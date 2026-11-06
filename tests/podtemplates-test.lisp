;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify stored templates with broad PodSpecs, real protobuf and HTTP CRUD,
;;;; strategic patch lists, revision-consistent pages across mutation/restart,
;;;; signed continuation expiry, selector transitions and streamed watches.

(in-package #:gr8s/tests)
(def-suite podtemplates :in gr8s)
(in-suite podtemplates)

(defun podtemplate-fixture (name)
  "Return a template with fields deliberately outside the native runtime subset."
  (let ((object (com.inuoe.jzon:parse
                 "{\"apiVersion\":\"v1\",\"kind\":\"PodTemplate\",\"metadata\":{\"name\":\"template\",\"labels\":{\"app\":\"web\"}},\"template\":{\"metadata\":{\"labels\":{\"app\":\"workload\"}},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"example.invalid/web:v1\",\"resources\":{\"requests\":{\"cpu\":\"250m\"}},\"readinessProbe\":{\"httpGet\":{\"path\":\"/ready\",\"port\":\"http\"}},\"env\":[{\"name\":\"KEEP\",\"value\":\"yes\"}]}],\"initContainers\":[{\"name\":\"init\",\"image\":\"example.invalid/init:v1\"}],\"nodeSelector\":{\"example.org/rack\":\"a\"}}}}")))
    (setf (gethash "name" (gethash "metadata" object)) name)
    object))

(defun template-main-container (object)
  "Read the main container from a PodTemplate response."
  (aref (gethash "containers" (gethash "spec" (gethash "template" object))) 0))

(test podtemplate-http-crud-discovery-and-strategic-merge
  (with-core-api (store path)
    (let* ((collection "/api/v1/namespaces/alpha/podtemplates")
           (item (concatenate 'string collection "/web"))
           (created (check-core-status 201 collection :method :post :object (podtemplate-fixture "web")))
           (uid (gethash "uid" (gethash "metadata" created))))
      (is (equal "250m" (gethash "cpu" (gethash "requests" (gethash "resources" (template-main-container created))))))
      (is (equal "http" (gethash "port" (gethash "httpGet" (gethash "readinessProbe" (template-main-container created))))))
      (is (equal "Always" (gethash "restartPolicy" (gethash "spec" (gethash "template" created)))))
      (is (null (gr8s:list-pods store)))
      (let* ((patch (com.inuoe.jzon:parse "{\"template\":{\"spec\":{\"containers\":[{\"name\":\"main\",\"env\":[{\"name\":\"NEW\",\"value\":\"value\"}]}]}}}"))
             (patched (check-core-status 200 item :method :patch :content-type "application/strategic-merge-patch+json" :object patch)))
        (is (= 2 (length (gethash "env" (template-main-container patched)))))
        (is (equal "example.invalid/web:v1" (gethash "image" (template-main-container patched)))))
      (check-core-status 409 item :method :put :object created)
      (let ((current (check-core-status 200 item)))
        (setf (gethash "annotations" (gethash "metadata" current)) (gr8s::core-object "updated" "yes"))
        (let ((updated (check-core-status 200 item :method :put :object current)))
          (is (equal uid (gethash "uid" (gethash "metadata" updated))))))
      (is (= 1 (length (gethash "items" (check-core-status 200 "/api/v1/podtemplates" :parameters '(("labelSelector" . "app=web")))))))
      (is (equal uid (gethash "uid" (gethash "metadata" (gr8s::get-core-resource (open-store path) "podtemplates" "alpha" "web")))))
      (let* ((resources (gethash "resources" (check-core-status 200 "/api/v1")))
             (descriptor (find "podtemplates" resources :test #'equal :key (lambda (item) (gethash "name" item)))))
        (is (find "deletecollection" (gethash "verbs" descriptor) :test #'equal))
        (is (find "watch" (gethash "verbs" descriptor) :test #'equal)))
      (let* ((api (check-core-status 200 "/openapi/v3/api/v1"))
             (schemas (gethash "schemas" (gethash "components" api))))
        (is (gethash "io.k8s.api.core.v1.PodTemplate" schemas))
        (is (gethash "delete" (gethash "/api/v1/namespaces/{namespace}/podtemplates" (gethash "paths" api)))))
      (check-core-status 200 collection :method :delete :parameters '(("dryRun" . "All") ("labelSelector" . "app=web")))
      (check-core-status 200 item)
      (gr8s::create-core-resource store "podtemplates" (podtemplate-fixture "web") "beta")
      (check-core-status 200 collection :method :delete :parameters '(("labelSelector" . "app=web")))
      (check-core-status 404 item)
      (is (= 1 (length (gr8s::list-core-resources store "podtemplates" "beta")))))))

(test podtemplate-protobuf-preserves-inline-fields-quantities-and-named-probe-ports
  (with-core-api (store path)
    (values path)
    (let* ((port (core-test-protobuf '((1 1) (3 "http"))))
           (http (core-test-protobuf (list (list 1 "/ready") (list 2 port))))
           (handler (core-test-protobuf (list (list 2 http))))
           (probe (core-test-protobuf (list (list 1 handler))))
           (quantity (core-test-protobuf '((1 "250m"))))
           (request (core-test-protobuf (list (list 1 "cpu") (list 2 quantity))))
           (resources (core-test-protobuf (list (list 2 request))))
           (container (core-test-protobuf (list (list 1 "main") (list 2 "web:v1") (list 8 resources) (list 11 probe))))
           (spec (core-test-protobuf (list (list 2 container) (list 3 "") (list 6 ""))))
           (template (core-test-protobuf (list (list 2 spec))))
           (input (core-test-protobuf-envelope "PodTemplate" (list (list 1 (core-test-protobuf '((1 "wire")))) (list 2 template))))
           (created (check-core-status 201 "/api/v1/namespaces/alpha/podtemplates" :method :post
                      :content-type "application/vnd.kubernetes.protobuf" :octets input)))
      (is (equal "http" (gethash "port" (gethash "httpGet" (gethash "readinessProbe" (template-main-container created))))))
      (is (equal "250m" (gethash "cpu" (gethash "requests" (gethash "resources" (template-main-container created))))))
      (is (null (gr8s:list-pods store)))
      (check-core-status 400 "/api/v1/namespaces/alpha/podtemplates" :method :post
                         :content-type "application/vnd.kubernetes.protobuf" :octets (subseq input 0 (1- (length input)))))))

(test template-pages-retain-a-snapshot-through-mutation-and-restart
  (with-temporary-store (store path)
    (let* ((now 1000) (gr8s::*podtemplate-clock* (lambda () now)))
      (dolist (name '("a" "b" "c")) (gr8s::create-core-resource store "podtemplates" (podtemplate-fixture name) "alpha"))
      (let* ((page (gr8s::template-list-page store "alpha" "" "" :limit 1))
             (token (gethash "continue" (gethash "metadata" page)))
             (rv (gethash "resourceVersion" (gethash "metadata" page))))
        (gr8s::update-core-resource store "podtemplates" "alpha" "b"
         (lambda (object) (setf (gethash "image" (template-main-container object)) "web:v2") object))
        (gr8s::delete-core-resource store "podtemplates" "alpha" "c")
        (gr8s::create-core-resource store "podtemplates" (podtemplate-fixture "aa") "alpha")
        (let* ((restored (open-store path))
               (next (gr8s::template-list-page restored "alpha" "" "" :limit 10 :continuation token)))
          (is (equal rv (gethash "resourceVersion" (gethash "metadata" next))))
          (is (equal '("b" "c") (map 'list (lambda (object) (gethash "name" (gethash "metadata" object))) (gethash "items" next))))
          (is (equal "example.invalid/web:v1" (gethash "image" (template-main-container (aref (gethash "items" next) 0))))))
        (is (= 400 (core-resource-status (lambda () (gr8s::template-list-page store "beta" "" "" :continuation token)))))
        (setf now 1400)
        (multiple-value-bind (expired code) (gr8s::template-list-page store "alpha" "" "" :continuation token)
          (is (= 410 code))
          (let* ((replacement (gethash "continue" (gethash "metadata" expired)))
                 (resumed (gr8s::template-list-page store "alpha" "" "" :continuation replacement :limit 1)))
            (is (not (equal rv (gethash "resourceVersion" (gethash "metadata" resumed)))))
            (is (equal "aa" (gethash "name" (gethash "metadata" (aref (gethash "items" resumed) 0)))))))))))

(test template-watch-selector-transitions-are-real-journal-events
  (with-temporary-store (store path)
    (values path)
    (let ((rv (gr8s::pod-store-resource-revision store)))
      (gr8s::create-core-resource store "podtemplates" (podtemplate-fixture "web") "alpha")
      (gr8s::update-core-resource store "podtemplates" "alpha" "web"
       (lambda (object) (setf (gethash "image" (template-main-container object)) "web:v2") object))
      (gr8s::update-core-resource store "podtemplates" "alpha" "web"
       (lambda (object) (setf (gethash "app" (gethash "labels" (gethash "metadata" object))) "other") object))
      (gr8s::delete-core-resource store "podtemplates" "alpha" "web")
      (multiple-value-bind (events watermark) (gr8s::template-watch-events store "alpha" "app=web" "" rv)
        (is (= 4 watermark))
        (is (equal '("ADDED" "MODIFIED" "DELETED") (mapcar (lambda (event) (gethash "type" event)) events)))
        (is (equal '("1" "2" "3") (mapcar (lambda (event) (gethash "resourceVersion" (gethash "metadata" (gethash "object" event)))) events)))))))

(defun read-template-watch-event (stream)
  "Read one JSON event from Drakma's actual HTTP response stream."
  (let ((line (if (subtypep (stream-element-type stream) 'character) (read-line stream)
                  (with-output-to-string (text)
                    (loop for byte = (read-byte stream) until (= byte 10) do (write-char (code-char byte) text))))))
    (com.inuoe.jzon:parse line)))

(test podtemplate-http-watch-streams-add-modify-and-delete
  (with-core-api (store path)
    (values path)
    (gr8s::create-core-resource store "podtemplates" (podtemplate-fixture "stream") "alpha")
    (sb-sys:with-deadline (:seconds 10)
      (multiple-value-bind (stream code)
          (drakma:http-request (core-api-url "/api/v1/namespaces/alpha/podtemplates")
                               :want-stream t :parameters '(("watch" . "true") ("resourceVersion" . "0") ("timeoutSeconds" . "2")))
        (unwind-protect
             (progn
               (is (= 200 code))
               (is (equal "ADDED" (gethash "type" (read-template-watch-event stream))))
               (gr8s::update-core-resource store "podtemplates" "alpha" "stream"
                (lambda (object) (setf (gethash "image" (template-main-container object)) "web:v2") object))
               (let ((event (read-template-watch-event stream)))
                 (is (equal "MODIFIED" (gethash "type" event)))
                 (is (equal "web:v2" (gethash "image" (template-main-container (gethash "object" event))))))
               (gr8s::delete-core-resource store "podtemplates" "alpha" "stream")
               (is (equal "DELETED" (gethash "type" (read-template-watch-event stream)))))
          (close stream))))))

(test podtemplate-dry-run-and-invalid-input-do-not-change-storage
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "podtemplates" (podtemplate-fixture "preview") "alpha" :dry-run t)
    (is (zerop (gr8s::pod-store-resource-revision store)))
    (is (null (gr8s::list-core-resources store "podtemplates")))
    (let ((bad (podtemplate-fixture "invalid")))
      (setf (gethash "imagePullPolicy" (template-main-container bad)) "Unsupported")
      (is (= 422 (core-resource-status (lambda () (gr8s::create-core-resource store "podtemplates" bad "alpha"))))))
    (let ((bad (podtemplate-fixture "invalid")))
      (setf (gethash "template" bad) 42)
      (is (= 422 (core-resource-status (lambda () (gr8s::create-core-resource store "podtemplates" bad "alpha"))))))
    (is (null (gr8s::list-core-resources store "podtemplates")))))

(test podtemplate-strategic-patch-supports-client-side-apply-order-and-replacement
  (with-core-api (store path)
    (values store path)
    (let ((collection "/api/v1/namespaces/alpha/podtemplates")
          (item "/api/v1/namespaces/alpha/podtemplates/ordered"))
      (check-core-status 201 collection :method :post :object (podtemplate-fixture "ordered"))
      (let* ((patch (com.inuoe.jzon:parse "{\"template\":{\"spec\":{\"$setElementOrder/containers\":[{\"name\":\"sidecar\"},{\"name\":\"main\"}],\"containers\":[{\"name\":\"sidecar\",\"image\":\"sidecar:v1\"}]}}}"))
             (result (check-core-status 200 item :method :patch :object patch :content-type "application/strategic-merge-patch+json")))
        (is (equal '("sidecar" "main")
                   (map 'list (lambda (container) (gethash "name" container))
                        (gethash "containers" (gethash "spec" (gethash "template" result)))))))
      (let* ((patch (com.inuoe.jzon:parse "{\"template\":{\"spec\":{\"containers\":[{\"$patch\":\"replace\"},{\"name\":\"replacement\",\"image\":\"web:v1\"}]}}}"))
             (result (check-core-status 200 item :method :patch :object patch :content-type "application/strategic-merge-patch+json")))
        (is (equal "replacement" (gethash "name" (template-main-container result))))))))

(test template-wire-timestamps-preserve-nanoseconds-and-reject-invalid-values
  (let ((gr8s::*core-protobuf-field-count* 0))
    (is (equal "1970-01-01T00:00:01.005000000Z"
               (gr8s::template-protobuf-message "k8s.io.apimachinery.pkg.apis.meta.v1.Time"
                                                (core-test-protobuf '((1 1) (2 5000000))))))
    (signals error (gr8s::template-protobuf-message "k8s.io.apimachinery.pkg.apis.meta.v1.Time"
                                                   (core-test-protobuf '((1 1) (2 1000000000)))))))

(test template-storage-limit-prevents-unreadable-persisted-objects
  (with-temporary-store (store path)
    (let ((object (podtemplate-fixture "oversized")))
      (setf (gethash "args" (template-main-container object)) (vector (make-string (* 2 1024 1024) :initial-element #\x)))
      (is (= 413 (core-resource-status (lambda () (gr8s::create-core-resource store "podtemplates" object "alpha")))))
      (is (null (gr8s::list-core-resources (open-store path) "podtemplates"))))))

(test strategic-merge-puts-entries-new-to-a-list-first
  (let* ((schema (gr8s::template-schema "io.k8s.api.core.v1.PodSpec"))
         (old (com.inuoe.jzon:parse "{\"containers\":[{\"name\":\"a\",\"image\":\"1\"},{\"name\":\"b\",\"image\":\"1\"}]}"))
         (names (lambda (patch)
                  (map 'list (lambda (container) (gethash "name" container))
                       (gethash "containers" (gr8s::template-strategic-merge (gr8s::copy-core-object old) (com.inuoe.jzon:parse patch) schema))))))
    ;; As upstream's merge does: a new entry leads, and existing ones keep their relative order.
    (is (equal '("new" "a" "b") (funcall names "{\"containers\":[{\"name\":\"new\",\"image\":\"2\"}]}")))
    (is (equal '("a" "b") (funcall names "{\"containers\":[{\"name\":\"b\",\"image\":\"2\"}]}")))
    (is (equal '("a" "b") (funcall names "{\"containers\":[{\"name\":\"a\",\"image\":\"2\"}]}")))
    (is (equal '("b") (funcall names "{\"containers\":[{\"name\":\"a\",\"$patch\":\"delete\"}]}")))))
