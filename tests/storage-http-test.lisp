;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise storage discovery, typed request bodies, status isolation and real
;;;; watches through HTTP, including controller-generated binding transitions.

(in-package #:gr8s/tests)
(def-suite storage-http :in gr8s)
(in-suite storage-http)

(defvar *storage-http-port* nil "The kernel-assigned port of the current WITH-STORAGE-HTTP server.")

(defun storage-http-request (path &key (method :get) object octets (content-type "application/json"))
  "Make one isolated HTTP request to the storage test server."
  (multiple-value-bind (body code)
      (drakma:http-request (format nil "http://127.0.0.1:~D~A" *storage-http-port* path) :method method
                          :content-type content-type :content (or octets (when object (com.inuoe.jzon:stringify object))))
    (values (com.inuoe.jzon:parse body) code)))

(defun storage-http-check (expected path &rest options)
  "Assert a Kubernetes status code while preserving the response object."
  (multiple-value-bind (body code) (apply #'storage-http-request path options)
    (is (= expected code) "~A: ~A" path body) body))

(defmacro with-storage-http ((store path) &body body)
  "Run an API-only storage test without acquiring any native runtime state."
  `(with-temporary-store (,store ,path)
     (let* ((server (start-server :address "127.0.0.1" :port 0 :store ,store :runtime (make-fake-runtime)))
            (*storage-http-port* (hunchentoot:acceptor-port server)))
       (unwind-protect (progn ,@body) (stop-server server)))))

(test storage-http-discovery-and-typed-protobuf-creation
  (with-storage-http (store path)
    (values store path)
    (let* ((discovery (storage-http-check 200 "/api/v1"))
           (names (map 'list (lambda (object) (gethash "name" object)) (gethash "resources" discovery))))
      (dolist (name '("persistentvolumes" "persistentvolumeclaims" "persistentvolumes/status" "persistentvolumeclaims/status"))
        (is-true (member name names :test #'equal))))
    (let ((storage (storage-http-check 200 "/apis/storage.k8s.io/v1")))
      (is (equal "storageclasses" (gethash "name" (aref (gethash "resources" storage) 0))))
      (is-false (gethash "namespaced" (aref (gethash "resources" storage) 0))))
    (let* ((schema (storage-http-check 200 "/openapi/v3/apis/storage.k8s.io/v1"))
           (definitions (gethash "schemas" (gethash "components" schema))))
      (is-true (gethash "io.k8s.api.storage.v1.StorageClass" definitions)))
    (let* ((metadata (core-test-protobuf '((1 "typed-class"))))
           (input (core-test-protobuf-envelope "StorageClass" (list (list 1 metadata) (list 2 "kubernetes.io/no-provisioner") (list 7 "WaitForFirstConsumer")) "storage.k8s.io/v1"))
           (created (storage-http-check 201 "/apis/storage.k8s.io/v1/storageclasses" :method :post
                                        :content-type "application/vnd.kubernetes.protobuf" :octets input)))
      (is (equal "WaitForFirstConsumer" (gethash "volumeBindingMode" created))))))

(test storage-status-writes-preserve-spec-and-ordinary-writes-preserve-status
  (with-storage-http (store path)
    (let* ((created (storage-http-check 201 "/api/v1/persistentvolumes" :method :post :object (storage-test-volume "provided" (merge-pathnames "backing/" path))))
           (old-source (gethash "hostPath" (gethash "spec" created)))
           (status-body (gr8s::copy-core-object created)))
      (setf (gethash "status" status-body) (gr8s::core-object "phase" "Available")
            (gethash "hostPath" (gethash "spec" status-body)) (gr8s::core-object "path" "/must-not-replace-source"))
      (storage-http-check 200 "/api/v1/persistentvolumes/provided/status" :method :put :object status-body)
      (let ((loaded (storage-http-check 200 "/api/v1/persistentvolumes/provided")))
        (is (gr8s::core-json-equal-p old-source (gethash "hostPath" (gethash "spec" loaded)))))
      (storage-http-check 200 "/api/v1/persistentvolumes/provided" :method :patch :content-type "application/merge-patch+json"
                          :object (gr8s::core-object "status" (gr8s::core-object "phase" "Bound")))
      (is (equal "Available" (storage-phase store "persistentvolumes" nil "provided")))
      (storage-http-check 409 "/api/v1/persistentvolumes/provided/status" :method :put :object status-body))))

(test storage-watch-reports-atomic-binding-and-survives-store-reopen
  (with-storage-http (store path)
    (let* ((claim (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default"))
           (revision (gethash "resourceVersion" (gethash "metadata" claim))))
      (sb-sys:with-deadline (:seconds 8)
        (multiple-value-bind (stream code)
            (drakma:http-request (format nil "http://127.0.0.1:~D/api/v1/namespaces/default/persistentvolumeclaims" *storage-http-port*)
                                 :want-stream t :parameters `(("watch" . "true") ("resourceVersion" . ,revision) ("timeoutSeconds" . "5")))
          (unwind-protect
               (progn
                 (is (= 200 code))
                 (gr8s::create-core-resource store "persistentvolumes" (storage-test-volume "provided" (merge-pathnames "backing/" path)) nil)
                 (gr8s::reconcile-storage-bindings store)
                 (let* ((event (read-template-watch-event stream)) (object (gethash "object" event)))
                   (is (equal "MODIFIED" (gethash "type" event)))
                   (is (equal "Bound" (gethash "phase" (gethash "status" object)))))
                 (is (equal "Bound" (storage-phase (open-store path) "persistentvolumeclaims" "default" "claim"))))
            (close stream)))))))

(in-suite gr8s)
