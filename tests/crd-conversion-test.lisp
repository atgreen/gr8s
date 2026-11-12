;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify CRD conversion webhooks against a local TLS backend: writes store the
;;;; storage version, reads convert, lists batch, selectors read the requested
;;;; version, bad answers fail the request, and no webhook runs under the store lock.

(in-package #:gr8s/tests)
(def-suite crd-conversion :in gr8s)
(in-suite crd-conversion)

(defun crd-conversion-fixture (&key (storage "v1") webhook)
  "Build upstream's hostPort/host+port definition, converting through WEBHOOK when given."
  (flet ((schema (&rest fields)
           (gr8s.resources::core-object "openAPIV3Schema"
             (gr8s.resources::core-object "type" "object" "properties"
               (let ((properties (gr8s.resources::core-object)))
                 (dolist (field fields properties)
                   (setf (gethash field properties) (gr8s.resources::core-object "type" "string"))))))))
    (gr8s.resources::core-object
     "apiVersion" "apiextensions.k8s.io/v1" "kind" "CustomResourceDefinition"
     "metadata" (gr8s.resources::core-object "name" "hosts.stable.example.com")
     "spec" (gr8s.resources::core-object
             "group" "stable.example.com" "scope" "Namespaced"
             "names" (gr8s.resources::core-object "plural" "hosts" "kind" "Host")
             "conversion" (if webhook
                              (gr8s.resources::core-object "strategy" "Webhook" "webhook" webhook)
                              (gr8s.resources::core-object "strategy" "None"))
             "versions" (vector
                         (gr8s.resources::core-object "name" "v1" "served" t "storage" (equal storage "v1")
                                            "schema" (schema "hostPort")
                                            "selectableFields" (vector (gr8s.resources::core-object "jsonPath" ".hostPort")))
                         (gr8s.resources::core-object "name" "v2" "served" t "storage" (equal storage "v2")
                                            "schema" (schema "host" "port")
                                            "selectableFields" (vector (gr8s.resources::core-object "jsonPath" ".host")
                                                                       (gr8s.resources::core-object "jsonPath" ".port"))))))))

(defun crd-conversion-webhook-spec ()
  "Point a definition at the local backend's conversion path."
  (gr8s.resources::core-object "conversionReviewVersions" #("v1" "v1beta1")
                     "clientConfig" (gr8s.resources::core-object
                                     "url" (format nil "https://localhost:~D/crdconvert" *admission-test-port*)
                                     "caBundle" *admission-test-bundle*)))

(defun crd-conversion-convert (object desired)
  "Convert one object between hostPort and host+port as upstream's sample webhook does."
  (let ((copy (gr8s.resources::copy-core-object object)))
    (setf (gethash "apiVersion" copy) desired)
    (if (uiop:string-suffix-p desired "/v2")
        (let ((value (gethash "hostPort" copy)))
          (remhash "hostPort" copy)
          (when value
            (let ((colon (position #\: value)))
              (setf (gethash "host" copy) (subseq value 0 colon)
                    (gethash "port" copy) (if colon (subseq value (1+ colon)) "")))))
        (let ((host (gethash "host" copy)) (port (gethash "port" copy "")))
          (remhash "host" copy) (remhash "port" copy)
          (when host (setf (gethash "hostPort" copy) (format nil "~A:~A" host port)))))
    copy))

(defun crd-conversion-success (request)
  "Answer a ConversionReview REQUEST by converting all of its objects."
  (gr8s.resources::core-object "result" (gr8s.resources::core-object "status" "Success")
                     "convertedObjects" (map 'vector
                                             (lambda (object)
                                               (crd-conversion-convert object (gethash "desiredAPIVersion" request)))
                                             (gethash "objects" request))))

(defun crd-conversion-host (version name &rest fields)
  "Build a custom object at VERSION in namespace alpha."
  (let ((object (gr8s.resources::core-object "apiVersion" (format nil "stable.example.com/~A" version) "kind" "Host"
                                   "metadata" (gr8s.resources::core-object "name" name "namespace" "alpha"))))
    (loop for (key value) on fields by #'cddr do (setf (gethash key object) value))
    object))

(defun crd-conversion-path (version &optional name)
  "Name a Host collection or object at VERSION."
  (format nil "/apis/stable.example.com/~A/namespaces/alpha/hosts~@[/~A~]" version name))

(defun crd-conversion-create-definition (&rest arguments)
  "Establish the test definition."
  (check-core-status 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post
    :object (apply #'crd-conversion-fixture arguments)))

(test conversion-definitions-reject-unusable-webhooks
  (with-admission-api (store)
    (let ((path "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"))
      (flet ((refused (webhook)
               (check-core-status 422 path :method :post :object (crd-conversion-fixture :webhook webhook))))
        (let ((no-versions (crd-conversion-webhook-spec))) (remhash "conversionReviewVersions" no-versions) (refused no-versions))
        (let ((unknown (crd-conversion-webhook-spec)))
          (setf (gethash "conversionReviewVersions" unknown) #("v9"))
          (refused unknown))
        (let ((no-target (crd-conversion-webhook-spec)))
          (setf (gethash "clientConfig" no-target) (gr8s.resources::core-object))
          (refused no-target))
        (let ((both (crd-conversion-webhook-spec)))
          (setf (gethash "service" (gethash "clientConfig" both))
                (gr8s.resources::core-object "namespace" "alpha" "name" "hook"))
          (refused both)))
      (let ((none (crd-conversion-fixture)))
        (setf (gethash "webhook" (gethash "conversion" (gethash "spec" none))) (crd-conversion-webhook-spec))
        (check-core-status 422 path :method :post :object none))
      (let ((no-strategy (crd-conversion-fixture)))
        (setf (gethash "strategy" (gethash "conversion" (gethash "spec" no-strategy))) "Magic")
        (check-core-status 422 path :method :post :object no-strategy))
      (let ((defaulted (crd-conversion-fixture)))
        (remhash "conversion" (gethash "spec" defaulted))
        (let ((created (check-core-status 201 path :method :post :object defaulted)))
          (is (equal "None" (gethash "strategy" (gethash "conversion" (gethash "spec" created))))))))))

(test conversion-webhook-backs-reads-writes-and-mixed-lists
  (with-admission-api (store)
    (let ((reviews 0) (largest 0) (lock-free t) (called-path nil))
      (with-admission-handler (path request)
        (setf called-path path)
        (incf reviews)
        (setf largest (max largest (length (gethash "objects" request))))
        ;; The backend answers on its own thread, so this fails if the request holds the lock.
        (if (bt:acquire-lock (gr8s.store::pod-store-lock store) nil)
            (bt:release-lock (gr8s.store::pod-store-lock store))
            (setf lock-free nil))
        (crd-conversion-success request))
      (crd-conversion-create-definition :webhook (crd-conversion-webhook-spec))
      (let ((definition (check-core-status 200 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/hosts.stable.example.com")))
        (check-core-status 201 (crd-conversion-path "v1") :method :post
          :object (crd-conversion-host "v1" "one" "hostPort" "localhost:8080"))
        (is (zerop reviews))
        ;; Written at v1, read at v2.
        (let ((v2 (check-core-status 200 (crd-conversion-path "v2" "one"))))
          (is (equal "stable.example.com/v2" (gethash "apiVersion" v2)))
          (is (equal "localhost" (gethash "host" v2)))
          (is (equal "8080" (gethash "port" v2)))
          (is (not (nth-value 1 (gethash "hostPort" v2))))
          (is (plusp reviews)))
        ;; Written at v2, stored at the v1 storage version.
        (let ((created (check-core-status 201 (crd-conversion-path "v2") :method :post
                         :object (crd-conversion-host "v2" "two" "host" "example" "port" "443"))))
          (is (equal "stable.example.com/v2" (gethash "apiVersion" created)))
          (is (equal "example" (gethash "host" created))))
        (let ((stored (gr8s.resources::get-core-resource store "custom:stable.example.com/hosts" "alpha" "two")))
          (is (equal "stable.example.com/v1" (gethash "apiVersion" stored)))
          (is (equal "example:443" (gethash "hostPort" stored))))
        ;; An update at v2 keeps its identity and conversion.
        (let* ((current (check-core-status 200 (crd-conversion-path "v2" "two"))))
          (setf (gethash "port" current) "444")
          (let ((updated (check-core-status 200 (crd-conversion-path "v2" "two") :method :put :object current)))
            (is (equal "444" (gethash "port" updated)))))
        (let ((merged (check-core-status 200 (crd-conversion-path "v2" "two") :method :patch
                        :octets "{\"port\":\"445\"}" :content-type "application/merge-patch+json")))
          (is (equal "445" (gethash "port" merged))))
        (is (equal "example:445" (gethash "hostPort" (gr8s.resources::get-core-resource store "custom:stable.example.com/hosts" "alpha" "two"))))
        ;; A new storage version leaves a mixed collection, which one review converts.
        (setf (gethash "storage" (aref (gethash "versions" (gethash "spec" definition)) 0)) nil
              (gethash "storage" (aref (gethash "versions" (gethash "spec" definition)) 1)) t)
        (check-core-status 200 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/hosts.stable.example.com" :method :put :object definition)
        (check-core-status 201 (crd-conversion-path "v1") :method :post
          :object (crd-conversion-host "v1" "three" "hostPort" "localhost:8080"))
        (is (equal "stable.example.com/v2"
                   (gethash "apiVersion" (gr8s.resources::get-core-resource store "custom:stable.example.com/hosts" "alpha" "three"))))
        (let ((v1 (check-core-status 200 (crd-conversion-path "v1"))) (v2 (check-core-status 200 (crd-conversion-path "v2"))))
          (is (= 3 (length (gethash "items" v1))))
          (is (= 3 (length (gethash "items" v2))))
          (is (every (lambda (item) (equal "stable.example.com/v1" (gethash "apiVersion" item))) (gethash "items" v1)))
          (is (every (lambda (item) (gethash "hostPort" item)) (gethash "items" v1)))
          (is (every (lambda (item) (and (gethash "host" item) (equal "stable.example.com/v2" (gethash "apiVersion" item))))
                     (gethash "items" v2))))
        (is (equal "/crdconvert?timeout=30s" called-path))
        (is (>= largest 2))
        (is-true lock-free)))))

(test field-selectors-read-the-requested-version
  (with-admission-api (store)
    (with-admission-handler (path request) (crd-conversion-success request))
    (crd-conversion-create-definition :webhook (crd-conversion-webhook-spec))
    (check-core-status 201 (crd-conversion-path "v2") :method :post
      :object (crd-conversion-host "v2" "one" "host" "host1" "port" "80"))
    (check-core-status 201 (crd-conversion-path "v2") :method :post
      :object (crd-conversion-host "v2" "two" "host" "host1" "port" "8080"))
    (check-core-status 201 (crd-conversion-path "v2") :method :post
      :object (crd-conversion-host "v2" "three" "host" "host2" "port" ""))
    (flet ((names (version selector)
             (sort (map 'list (lambda (item) (gethash "name" (gethash "metadata" item)))
                        (gethash "items" (check-core-status 200 (crd-conversion-path version)
                                           :parameters (list (cons "fieldSelector" selector)))))
                   #'string<)))
      (is (equal '("one" "two") (names "v2" "host=host1")))
      (is (equal '("one") (names "v2" "host=host1,port=80")))
      (is (equal '("one") (names "v1" "hostPort=host1:80")))
      (is (equal '("two") (names "v1" "hostPort=host1:8080")))
      ;; A field v2 declares is not selectable at v1.
      (check-core-status 400 (crd-conversion-path "v1") :parameters '(("fieldSelector" . "host=host1"))))))

(test bad-conversion-answers-fail-the-request
  (with-admission-api (store)
    (crd-conversion-create-definition :webhook (crd-conversion-webhook-spec))
    (with-admission-handler (path request) (crd-conversion-success request))
    (check-core-status 201 (crd-conversion-path "v1") :method :post
      :object (crd-conversion-host "v1" "one" "hostPort" "a:1"))
    (flet ((fails (expected)
             (let ((status (check-core-status 500 (crd-conversion-path "v2" "one"))))
               (is (search expected (gethash "message" status)) "~A" (gethash "message" status)))))
      (with-admission-handler (path request)
        (gr8s.resources::core-object "result" (gr8s.resources::core-object "status" "Failure" "message" "no way")))
      (fails "no way")
      (with-admission-handler (path request)
        (gr8s.resources::core-object "result" (gr8s.resources::core-object "status" "Success") "convertedObjects" #()))
      (fails "returned 0 objects")
      (with-admission-handler (path request)
        (let ((answer (crd-conversion-success request)))
          (setf (gethash "apiVersion" (aref (gethash "convertedObjects" answer) 0)) "stable.example.com/v9")
          answer))
      (fails "invalid groupVersion")
      (with-admission-handler (path request)
        (let ((answer (crd-conversion-success request)))
          (setf (gethash "name" (gethash "metadata" (aref (gethash "convertedObjects" answer) 0))) "other")
          answer))
      (fails "same name"))
    ;; Only labels and annotations of the webhook's metadata survive.
    (with-admission-handler (path request)
      (let* ((answer (crd-conversion-success request))
             (metadata (gethash "metadata" (aref (gethash "convertedObjects" answer) 0))))
        (setf (gethash "labels" metadata) (gr8s.resources::core-object "added" "yes")
              (gethash "finalizers" metadata) #("example.com/invented"))
        answer))
    (let ((converted (check-core-status 200 (crd-conversion-path "v2" "one"))))
      (is (equal "yes" (gethash "added" (gethash "labels" (gethash "metadata" converted)))))
      (is (not (nth-value 1 (gethash "finalizers" (gethash "metadata" converted))))))))
