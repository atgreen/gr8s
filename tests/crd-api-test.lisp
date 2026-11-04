;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify genuine CRD establishment, store-scoped resource routes, structural
;;;; admission, version identity, finalizer cleanup and durable recovery.

(in-package #:gr8s/tests)
(def-suite crd-apis :in gr8s)
(in-suite crd-apis)

(defun crd-fixture (&key (group "widgets.example.test") (plural "widgets") (kind "Widget") (scope "Namespaced") (versions '("v1")))
  "Build an executable structural definition with a genuine status subresource."
  (gr8s::core-object "apiVersion" "apiextensions.k8s.io/v1" "kind" "CustomResourceDefinition"
    "metadata" (gr8s::core-object "name" (format nil "~A.~A" plural group))
    "spec" (gr8s::core-object "group" group "names" (gr8s::core-object "plural" plural "kind" kind)
      "scope" scope "versions"
      (coerce (loop for version in versions for index from 0 collect
                   (gr8s::core-object "name" version "served" t "storage" (zerop index)
                     "subresources" (gr8s::core-object "status" (gr8s::core-object))
                     "schema" (gr8s::core-object "openAPIV3Schema"
                       (gr8s::core-object "type" "object" "properties"
                         (gr8s::core-object "spec" (gr8s::core-object "type" "object" "properties"
                           (gr8s::core-object "count" (gr8s::core-object "type" "integer" "minimum" 1 "default" 2)))
                           "status" (gr8s::core-object "type" "object" "properties"
                             (gr8s::core-object "ready" (gr8s::core-object "type" "boolean")))))))) 'vector))))

(defun crd-instance (&optional (name "one") (group "widgets.example.test") (kind "Widget") (version "v1"))
  "Build a real custom object with an empty spec that receives declared defaults."
  (gr8s::core-object "apiVersion" (format nil "~A/~A" group version) "kind" kind
                    "metadata" (gr8s::core-object "name" name) "spec" (gr8s::core-object)))

(defmacro with-crd-api ((store path) &body body)
  "Use a distinct port so focused CRD tests can run beside unrelated suites."
  `(with-temporary-store (,store ,path)
     (let ((server (start-server :address "127.0.0.1" :port 18094 :store ,store :runtime (make-fake-runtime))))
       (unwind-protect (progn ,@body) (stop-server server)))))

(defun crd-api-request (expected path &key (method :get) object text content-type parameters)
  "Issue a real HTTP request and assert its actual Kubernetes response code."
  (multiple-value-bind (body status)
      (drakma:http-request (concatenate 'string "http://127.0.0.1:18094" path) :method method
                          :content-type (or content-type "application/json") :parameters parameters
                          :content (or text (when object (com.inuoe.jzon:stringify object))))
    (is (= expected status) "~A returned ~A: ~A" path status body)
    (com.inuoe.jzon:parse body)))

(test crd-establishment-installs-real-schema-backed-routes-and-status
  (with-crd-api (store path)
    (values store path)
    (let* ((definition (crd-api-request 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post :object (crd-fixture)))
           (established (find "Established" (gethash "conditions" (gethash "status" definition)) :test #'equal :key (lambda (condition) (gethash "type" condition))))
           (collection "/apis/widgets.example.test/v1/namespaces/alpha/widgets")
           (item (concatenate 'string collection "/one")))
      (is (equal "True" (gethash "status" established)))
      (crd-api-request 200 "/apis/widgets.example.test/v1")
      (let ((input (crd-instance)))
        (setf (gethash "unknown" input) t
              (gethash "extra" (gethash "spec" input)) t
              (gethash "status" input) (gr8s::core-object "ready" t))
        (let ((object (crd-api-request 201 collection :method :post :object input)))
          (is (= 2 (gethash "count" (gethash "spec" object))))
          (is (null (gethash "unknown" object)))
          (is (null (gethash "extra" (gethash "spec" object))))
          (is (null (gethash "status" object)))
          (setf (gethash "status" object) (gr8s::core-object "ready" t)
                (gethash "count" (gethash "spec" object)) 999)
          (let ((updated (crd-api-request 200 (concatenate 'string item "/status") :method :put :object object)))
            (is (= 2 (gethash "count" (gethash "spec" updated))))
            (is-true (gethash "ready" (gethash "status" updated))))
          (crd-api-request 409 (concatenate 'string item "/status") :method :put :object object)))
      (crd-api-request 422 item :method :patch :content-type "application/merge-patch+json" :object (gr8s::core-object "spec" (gr8s::core-object "count" 0)))
      (crd-api-request 404 "/apis/widgets.example.test/v1/namespaces/beta/widgets/one")
      (is (= 1 (length (gethash "items" (crd-api-request 200 "/apis/widgets.example.test/v1/widgets")))))
      (crd-api-request 200 item :method :delete)
      (crd-api-request 404 item))))

(test custom-identities-survive-restart-with-group-and-builtin-collisions
  (with-temporary-store (store path)
    (dolist (group '("first.example.test" "second.example.test"))
      (gr8s::create-core-resource store "customresourcedefinitions" (crd-fixture :group group :plural "configmaps" :kind "ConfigMap") nil)
      (let* ((*package* (find-package :gr8s/tests))
             (gr8s::*stored-resource-types* (append gr8s::*stored-resource-types* (gr8s::crd-resource-types store))))
        (gr8s::create-core-resource store (format nil "custom:~A/configmaps" group) (crd-instance "same" group "ConfigMap") "alpha")))
    (gr8s::create-core-resource store "configmaps" (gr8s::core-object "metadata" (gr8s::core-object "name" "same") "data" (gr8s::core-object "builtin" "true")) "alpha")
    (let* ((loaded (open-store path))
           (gr8s::*stored-resource-types* (append gr8s::*stored-resource-types* (gr8s::crd-resource-types loaded))))
      (dolist (group '("first.example.test" "second.example.test"))
        (let ((object (gr8s::get-core-resource loaded (format nil "custom:~A/configmaps" group) "alpha" "same")))
          (is (equal (format nil "~A/v1" group) (gethash "apiVersion" object)))
          (is (= 2 (gethash "count" (gethash "spec" object))))))
      (is (equal "true" (gethash "builtin" (gethash "data" (gr8s::get-core-resource loaded "configmaps" "alpha" "same"))))))))

(test custom-version-none-conversion-shares-uid-and-status-generation
  (with-crd-api (store path)
    (values store path)
    (crd-api-request 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post :object (crd-fixture :versions '("v1" "v2")))
    (let* ((v1 "/apis/widgets.example.test/v1/namespaces/alpha/widgets/one")
           (v2 "/apis/widgets.example.test/v2/namespaces/alpha/widgets/one")
           (created (crd-api-request 201 "/apis/widgets.example.test/v2/namespaces/alpha/widgets" :method :post :object (crd-instance "one" "widgets.example.test" "Widget" "v2")))
           (read (crd-api-request 200 v1)))
      (is (equal "widgets.example.test/v2" (gethash "apiVersion" created)))
      (is (equal "widgets.example.test/v1" (gethash "apiVersion" read)))
      (is (equal (gethash "uid" (gethash "metadata" created)) (gethash "uid" (gethash "metadata" read))))
      (let ((patched (crd-api-request 200 v2 :method :patch :content-type "application/merge-patch+json" :object (gr8s::core-object "spec" (gr8s::core-object "count" 3)))))
        (is (= 2 (gethash "generation" (gethash "metadata" patched)))))
      (is (= 3 (gethash "count" (gethash "spec" (crd-api-request 200 v1))))))))

(test crd-deletion-resumes-real-instance-cleanup-after-restart
  (with-temporary-store (store path)
    (let* ((definition (gr8s::create-core-resource store "customresourcedefinitions" (crd-fixture) nil))
           (resource (gr8s::crd-custom-key definition))
           (gr8s::*stored-resource-types* (append gr8s::*stored-resource-types* (gr8s::crd-resource-types store)))
           (input (crd-instance)))
      (setf (gethash "finalizers" (gethash "metadata" input)) #("example.test/cleanup"))
      (gr8s::create-core-resource store resource input "alpha")
      (gr8s::delete-core-resource store "customresourcedefinitions" nil "widgets.widgets.example.test")
      (let* ((loaded (open-store path))
             (metadata (gethash "metadata" (gr8s::get-core-resource loaded resource "alpha" "one"))))
        (is-true (gethash "deletionTimestamp" metadata))
        (is-true (gethash "deletionTimestamp" (gethash "metadata" (gr8s::get-core-resource loaded "customresourcedefinitions" nil "widgets.widgets.example.test"))))
        (gr8s::reconcile-crd-deletions loaded)
        (is (= 1 (length (gr8s::list-core-resources loaded resource "alpha"))))
        (gr8s::update-core-resource loaded resource "alpha" "one"
          (lambda (object) (setf (gethash "finalizers" (gethash "metadata" object)) #()) object))
        (gr8s::reconcile-crd-deletions loaded)
        (signals kubernetes-error (gr8s::get-core-resource loaded "customresourcedefinitions" nil "widgets.widgets.example.test"))
        (is (null (gr8s::crd-resource-types loaded)))))))

(test custom-watch-journal-and-failed-crd-checkpoint-preserve-real-state
  (with-temporary-store (store path)
    (gr8s::create-core-resource store "customresourcedefinitions" (crd-fixture) nil)
    (let* ((resource "custom:widgets.example.test/widgets")
           (gr8s::*stored-resource-types* (append gr8s::*stored-resource-types* (gr8s::crd-resource-types store)))
           (revision (gr8s::pod-store-resource-revision store)))
      (gr8s::create-core-resource store resource (crd-instance) "alpha")
      (let ((events (gr8s::template-watch-events store "alpha" "" "" revision :resource resource)))
        (is (equal "ADDED" (gethash "type" (first events)))))
      (let ((original (symbol-function 'gr8s::write-private-text-atomically)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s::write-private-text-atomically)
                     (lambda (&rest arguments) (declare (ignore arguments)) (error "injected storage failure")))
               (signals error (gr8s::delete-core-resource store "customresourcedefinitions" nil "widgets.widgets.example.test")))
          (setf (symbol-function 'gr8s::write-private-text-atomically) original)))
      (dolist (current (list store (open-store path)))
        (is (= 1 (length (gr8s::list-core-resources current resource "alpha"))))
        (is (null (gethash "deletionTimestamp" (gethash "metadata" (gr8s::get-core-resource current "customresourcedefinitions" nil "widgets.widgets.example.test")))))))))

(test custom-strict-field-validation-is-executable-and-published
  (with-crd-api (store path)
    (values store path)
    (crd-api-request 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post :object (crd-fixture))
    (let* ((collection "/apis/widgets.example.test/v1/namespaces/alpha/widgets")
           (input (crd-instance)))
      (setf (gethash "unexpected" (gethash "spec" input)) t)
      (crd-api-request 400 collection :method :post :object input :parameters '(("fieldValidation" . "Strict")))
      (crd-api-request 201 collection :method :post :object input :parameters '(("fieldValidation" . "Warn")))
      (crd-api-request 400 (concatenate 'string collection "/one") :method :patch :content-type "application/merge-patch+json"
                       :object (gr8s::core-object "metadata" (gr8s::core-object "unknown" t)) :parameters '(("fieldValidation" . "Strict")))
      (crd-api-request 400 collection :method :post :parameters '(("fieldValidation" . "Strict"))
                       :text "{\"apiVersion\":\"widgets.example.test/v1\",\"kind\":\"Widget\",\"metadata\":{\"name\":\"duplicate\"},\"spec\":{\"count\":2,\"count\":3}}")
      (let* ((document (crd-api-request 200 "/openapi/v3/apis/widgets.example.test/v1"))
             (operation (gethash "post" (gethash "/apis/widgets.example.test/v1/namespaces/{namespace}/widgets" (gethash "paths" document)))))
        (is (hash-table-p (gethash "x-kubernetes-group-version-kind" operation)))
        (is (find "fieldValidation" (gethash "parameters" operation) :test #'equal :key (lambda (entry) (gethash "name" entry))))))
    (let ((document (crd-api-request 200 "/openapi/v3/apis/apiextensions.k8s.io/v1")))
      (is (gethash "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" (gethash "paths" document))))))

(test crd-status-preserves-routes-and-requires-actual-storage-migration
  (with-crd-api (store path)
    (values path)
    (let* ((base "/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
           (item (concatenate 'string base "/widgets.widgets.example.test"))
           (status-url (concatenate 'string item "/status"))
           (definition (crd-api-request 201 base :method :post :object (crd-fixture :versions '("v1" "v2")))))
      (crd-api-request 201 "/apis/widgets.example.test/v1/namespaces/alpha/widgets" :method :post :object (crd-instance))
      (let ((versions (gethash "versions" (gethash "spec" definition))))
        (setf (gethash "storage" (aref versions 0)) nil
              (gethash "storage" (aref versions 1)) t))
      (crd-api-request 200 item :method :put :object definition)
      (let ((status (crd-api-request 200 status-url)))
        (setf (gethash "storedVersions" (gethash "status" status)) #("v2"))
        (crd-api-request 422 status-url :method :put :object status))
      (crd-api-request 200 "/apis/widgets.example.test/v2/namespaces/alpha/widgets/one"
                       :method :patch :content-type "application/merge-patch+json"
                       :object (gr8s::core-object "spec" (gr8s::core-object "count" 3)))
      (let ((status (crd-api-request 200 status-url)))
        (setf (gethash "storedVersions" (gethash "status" status)) #("v2")
              (gethash "group" (gethash "spec" status)) "must-not-change.example.test")
        (crd-api-request 200 status-url :method :put :object status)
        (crd-api-request 409 status-url :method :put :object status))
      (let* ((current (crd-api-request 200 item)) (versions (gethash "versions" (gethash "spec" current))))
        (is (equal "widgets.example.test" (gethash "group" (gethash "spec" current))))
        (setf (gethash "versions" (gethash "spec" current)) (vector (aref versions 1)))
        (crd-api-request 200 item :method :put :object current))
      (crd-api-request 404 "/apis/widgets.example.test/v1/namespaces/alpha/widgets/one")
      (is (equal "widgets.example.test/v2"
                 (gethash "apiVersion" (gr8s::get-core-resource store "custom:widgets.example.test/widgets" "alpha" "one")))))))

(test crd-status-cannot-claim-inert-establishment-and-collection-deletion-cleans-instances
  (with-crd-api (store path)
    (values store path)
    (let* ((base "/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
           (item (concatenate 'string base "/widgets.widgets.example.test"))
           (definition (crd-fixture)))
      (setf (gethash "labels" (gethash "metadata" definition)) (gr8s::core-object "cleanup" "selected"))
      (crd-api-request 201 base :method :post :object definition)
      (crd-api-request 201 base :method :post :object (crd-fixture :group "other.example.test"))
      (crd-api-request 201 "/apis/widgets.example.test/v1/namespaces/alpha/widgets" :method :post :object (crd-instance))
      (let* ((status-url (concatenate 'string item "/status"))
             (status (crd-api-request 200 status-url))
             (conditions (gethash "conditions" (gethash "status" status))))
        (setf (gethash "status" (find "Established" conditions :test #'equal :key (lambda (condition) (gethash "type" condition)))) "False")
        (crd-api-request 422 status-url :method :put :object status))
      (crd-api-request 200 base :method :delete :parameters '(("labelSelector" . "cleanup=selected")))
      (crd-api-request 404 item)
      (crd-api-request 404 "/apis/widgets.example.test/v1/namespaces/alpha/widgets/one")
      (crd-api-request 200 (concatenate 'string base "/widgets.other.example.test")))))

(test custom-gc-resolves-non-storage-owner-versions-and-exact-uids
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "customresourcedefinitions" (crd-fixture :versions '("v1" "v2")) nil)
    (let* ((gr8s::*stored-resource-types* (append gr8s::*stored-resource-types* (gr8s::crd-resource-types store)))
           (resource "custom:widgets.example.test/widgets")
           (owner (gr8s::create-core-resource store resource (crd-instance "owner") "alpha"))
           (child (crd-instance "child")))
      (setf (gethash "ownerReferences" (gethash "metadata" child))
            (vector (gr8s::core-object "apiVersion" "widgets.example.test/v2" "kind" "Widget" "name" "owner"
                                     "uid" (gethash "uid" (gethash "metadata" owner)))))
      (gr8s::create-core-resource store resource child "alpha")
      (gr8s::collect-orphaned-custom-resources store)
      (is (= 2 (length (gr8s::list-core-resources store resource "alpha"))))
      (gr8s::delete-core-resource store resource "alpha" "owner")
      (gr8s::create-core-resource store resource (crd-instance "owner") "alpha")
      (gr8s::collect-orphaned-custom-resources store)
      (signals kubernetes-error (gr8s::get-core-resource store resource "alpha" "child"))
      (is (= 1 (length (gr8s::list-core-resources store resource "alpha")))))))

(test custom-discovery-uses-kube-aware-version-priority
  (let* ((group (gr8s::crd-api-group "versions.example.test" '("v2alpha1" "v1beta2" "v1" "v10" "foo10" "foo1")))
         (versions (map 'list (lambda (entry) (gethash "version" entry)) (gethash "versions" group))))
    (is (equal '("v10" "v1" "v1beta2" "v2alpha1" "foo1" "foo10") versions))
    (is (equal "v10" (gethash "version" (gethash "preferredVersion" group))))))

(test custom-watch-cannot-follow-a-same-name-definition-replacement
  (with-crd-api (store path)
    (values path)
    (gr8s::create-core-resource store "customresourcedefinitions" (crd-fixture) nil)
    (sb-sys:with-deadline (:seconds 10)
      (multiple-value-bind (stream code)
          (drakma:http-request "http://127.0.0.1:18094/apis/widgets.example.test/v1/namespaces/alpha/widgets"
                               :want-stream t :parameters '(("watch" . "true") ("resourceVersion" . "0") ("timeoutSeconds" . "3")))
        (unwind-protect
             (progn
               (is (= 200 code))
               (gr8s::delete-core-resource store "customresourcedefinitions" nil "widgets.widgets.example.test")
               (gr8s::create-core-resource store "customresourcedefinitions" (crd-fixture) nil)
               (let ((event (read-template-watch-event stream)))
                 (is (equal "ERROR" (gethash "type" event)))
                 (is (= 410 (gethash "code" (gethash "object" event))))))
          (close stream))))))

(test custom-lists-and-continue-tokens-cannot-replay-a-previous-definition
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "customresourcedefinitions" (crd-fixture) nil)
    (let* ((resource "custom:widgets.example.test/widgets")
           (gr8s::*stored-resource-types* (append gr8s::*stored-resource-types* (gr8s::crd-resource-types store))))
      (gr8s::create-core-resource store resource (crd-instance "a") "alpha")
      (gr8s::create-core-resource store resource (crd-instance "b") "alpha")
      (let* ((page (gr8s::template-list-page store "alpha" "" "" :resource resource :limit 1))
             (metadata (gethash "metadata" page))
             (token (gethash "continue" metadata))
             (revision (gethash "resourceVersion" metadata)))
        (gr8s::delete-core-resource store "customresourcedefinitions" nil "widgets.widgets.example.test")
        (gr8s::create-core-resource store "customresourcedefinitions" (crd-fixture) nil)
        (is (= 410 (core-resource-status (lambda () (gr8s::template-list-page store "alpha" "" "" :resource resource :continuation token)))))
        (is (= 410 (core-resource-status (lambda () (gr8s::template-list-page store "alpha" "" "" :resource resource :resource-version revision :match "Exact")))))
        (is (zerop (length (gethash "items" (gr8s::template-list-page store "alpha" "" "" :resource resource)))))))))

(in-suite gr8s)
