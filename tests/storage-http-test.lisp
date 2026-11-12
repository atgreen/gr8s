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

(defun storage-http-request (path &key (method :get) object octets (content-type "application/json") parameters)
  "Make one isolated HTTP request to the storage test server."
  (multiple-value-bind (body code)
      (drakma:http-request (format nil "http://127.0.0.1:~D~A" *storage-http-port* path) :method method :parameters parameters
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
           (status-body (gr8s.resources::copy-core-object created)))
      (setf (gethash "status" status-body) (gr8s.resources::core-object "phase" "Available")
            (gethash "hostPath" (gethash "spec" status-body)) (gr8s.resources::core-object "path" "/must-not-replace-source"))
      (storage-http-check 200 "/api/v1/persistentvolumes/provided/status" :method :put :object status-body)
      (let ((loaded (storage-http-check 200 "/api/v1/persistentvolumes/provided")))
        (is (gr8s.apiserver::core-json-equal-p old-source (gethash "hostPath" (gethash "spec" loaded)))))
      (storage-http-check 200 "/api/v1/persistentvolumes/provided" :method :patch :content-type "application/merge-patch+json"
                          :object (gr8s.resources::core-object "status" (gr8s.resources::core-object "phase" "Bound")))
      (is (equal "Available" (storage-phase store "persistentvolumes" nil "provided")))
      (storage-http-check 409 "/api/v1/persistentvolumes/provided/status" :method :put :object status-body))))

(test storage-watch-reports-atomic-binding-and-survives-store-reopen
  (with-storage-http (store path)
    (let* ((claim (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default"))
           (revision (gethash "resourceVersion" (gethash "metadata" claim))))
      (sb-sys:with-deadline (:seconds 8)
        (multiple-value-bind (stream code)
            (drakma:http-request (format nil "http://127.0.0.1:~D/api/v1/namespaces/default/persistentvolumeclaims" *storage-http-port*)
                                 :want-stream t :parameters `(("watch" . "true") ("resourceVersion" . ,revision) ("timeoutSeconds" . "5")))
          (unwind-protect
               (progn
                 (is (= 200 code))
                 (gr8s.resources::create-core-resource store "persistentvolumes" (storage-test-volume "provided" (merge-pathnames "backing/" path)) nil)
                 (gr8s.resources::reconcile-storage-bindings store)
                 (let* ((event (read-template-watch-event stream)) (object (gethash "object" event)))
                   (is (equal "MODIFIED" (gethash "type" event)))
                   (is (equal "Bound" (gethash "phase" (gethash "status" object)))))
                 (is (equal "Bound" (storage-phase (open-store path) "persistentvolumeclaims" "default" "claim"))))
            (close stream)))))))

(defun storage-protobuf-request (kind fields version)
  "Encode KIND as client-go does, with the empty metadata.name Go always sends."
  (core-test-protobuf-envelope kind fields version))

(test storage-protobuf-creation-honors-generate-name
  ;; client-go sends name "" next to generateName; the e2e lifecycle specs create
  ;; StorageClasses, PVs and PVCs exactly so.
  (with-storage-http (store path)
    (values store path)
    (flet ((generated-metadata (prefix) (core-test-protobuf (list (list 1 "") (list 2 prefix)))))
      (let ((class (storage-http-check
                    201 "/apis/storage.k8s.io/v1/storageclasses" :method :post :content-type "application/vnd.kubernetes.protobuf"
                    :octets (storage-protobuf-request "StorageClass" (list (list 1 (generated-metadata "e2e-")) (list 2 "e2e-fake-provisioner"))
                                                      "storage.k8s.io/v1"))))
        (is (uiop:string-prefix-p "e2e-" (gethash "name" (gethash "metadata" class))))
        (is (< 4 (length (gethash "name" (gethash "metadata" class)))))
        (storage-http-check 200 (format nil "/apis/storage.k8s.io/v1/storageclasses/~A" (gethash "name" (gethash "metadata" class)))))
      (let* ((quantity (core-test-protobuf '((1 "2Gi"))))
             (csi (core-test-protobuf '((1 "e2e-driver") (2 "e2e-conformance"))))
             (source (core-test-protobuf (list (list 22 csi))))
             (capacity (core-test-protobuf (list (list 1 "storage") (list 2 quantity))))
             (spec (core-test-protobuf (list (list 1 capacity) (list 2 source) (list 3 "ReadWriteOnce") (list 6 "pv-ns"))))
             (names (loop repeat 2
                          collect (gethash "name" (gethash "metadata"
                                                           (storage-http-check
                                                            201 "/api/v1/persistentvolumes" :method :post
                                                            :content-type "application/vnd.kubernetes.protobuf"
                                                            :octets (storage-protobuf-request "PersistentVolume" (list (list 1 (generated-metadata "pv-ns-")) (list 2 spec)) "v1")))))))
        (is (every (lambda (name) (uiop:string-prefix-p "pv-ns-" name)) names))
        (is (not (equal (first names) (second names)))))
      (let* ((requests (core-test-protobuf (list (list 1 "storage") (list 2 (core-test-protobuf '((1 "1Gi")))))))
             (spec (core-test-protobuf (list (list 1 "ReadWriteOnce") (list 2 (core-test-protobuf (list (list 2 requests)))) (list 5 "pv-ns"))))
             (claim (storage-http-check 201 "/api/v1/namespaces/default/persistentvolumeclaims" :method :post
                                        :content-type "application/vnd.kubernetes.protobuf"
                                        :octets (storage-protobuf-request "PersistentVolumeClaim" (list (list 1 (generated-metadata "pvc-")) (list 2 spec)) "v1")))
             (name (gethash "name" (gethash "metadata" claim))))
        (is (uiop:string-prefix-p "pvc-" name))
        (storage-http-check 200 (format nil "/api/v1/namespaces/default/persistentvolumeclaims/~A/status" name))))
    ;; Without either name, creation is refused rather than storing an empty name.
    (storage-http-check 422 "/apis/storage.k8s.io/v1/storageclasses" :method :post
                        :object (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "") "provisioner" "e2e-fake-provisioner"))
    (is (null (gr8s.model::dns-subdomain-p "")))))

(test csinodes-accept-no-drivers-and-serve-status
  (with-storage-http (store path)
    (values store path)
    ;; Go sends spec.drivers as null in JSON and leaves it out of protobuf.
    (let ((created (storage-http-check 201 "/apis/storage.k8s.io/v1/csinodes" :method :post
                                       :object (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "e2e-csinode-a")
                                                                  "spec" (gr8s.resources::core-object "drivers" 'null)))))
      (is (equalp #() (gethash "drivers" (gethash "spec" created)))))
    (storage-http-check 201 "/apis/storage.k8s.io/v1/csinodes" :method :post :content-type "application/vnd.kubernetes.protobuf"
                        :octets (storage-protobuf-request "CSINode" (list (list 1 (core-test-protobuf '((1 "e2e-csinode-b")))) (list 2 (core-test-protobuf nil)))
                                                          "storage.k8s.io/v1"))
    (storage-http-check 200 "/apis/storage.k8s.io/v1/csinodes/e2e-csinode-b" :method :patch :content-type "application/strategic-merge-patch+json"
                        :object (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "labels" (gr8s.resources::core-object "e2e-csinode-b" "patched"))))
    (is (= 1 (length (gethash "items" (storage-http-check 200 "/apis/storage.k8s.io/v1/csinodes" :parameters '(("labelSelector" . "e2e-csinode-b=patched")))))))
    (let* ((storage (storage-http-check 200 "/apis/storage.k8s.io/v1"))
           (names (map 'list (lambda (object) (gethash "name" object)) (gethash "resources" storage))))
      (dolist (name '("csinodes/status" "volumeattachments/status" "volumeattributesclasses"))
        (is-true (member name names :test #'equal) "~A is not discovered" name)))
    (is (equal "e2e-csinode-a" (gethash "name" (gethash "metadata" (storage-http-check 200 "/apis/storage.k8s.io/v1/csinodes/e2e-csinode-a/status")))))
    ;; storageHealth needs the alpha CSIVolumeHealth gate, so as in Kubernetes it is dropped.
    (let ((written (storage-http-check 200 "/apis/storage.k8s.io/v1/csinodes/e2e-csinode-a/status" :method :patch
                                       :content-type "application/merge-patch+json"
                                       :object (gr8s.resources::core-object "spec" (gr8s.resources::core-object "drivers" (vector (gr8s.resources::core-object "name" "x.example.test" "nodeID" "n")))
                                                                  "status" (gr8s.resources::core-object "storageHealth" (vector (gr8s.resources::core-object "name" "x.example.test")))))))
      (is (null (gethash "status" written)))
      (is (equalp #() (gethash "drivers" (gethash "spec" written)))))
    (storage-http-check 200 "/apis/storage.k8s.io/v1/csinodes" :method :delete
                        :parameters '(("labelSelector" . "e2e-csinode-b=patched")))
    (storage-http-check 404 "/apis/storage.k8s.io/v1/csinodes/e2e-csinode-b")))

(test volume-attributes-classes-follow-the-kubernetes-lifecycle
  (with-storage-http (store path)
    (values path)
    (let* ((metadata (core-test-protobuf (list (list 1 "") (list 2 "e2e-"))))
           (created (storage-http-check 201 "/apis/storage.k8s.io/v1/volumeattributesclasses" :method :post
                                        :content-type "application/vnd.kubernetes.protobuf"
                                        :octets (storage-protobuf-request
                                                 "VolumeAttributesClass"
                                                 (list (list 1 metadata) (list 2 "e2e-fake-csi-driver") (list 3 (core-test-protobuf '((1 "foo") (2 "bar")))))
                                                 "storage.k8s.io/v1")))
           (name (gethash "name" (gethash "metadata" created)))
           (item (format nil "/apis/storage.k8s.io/v1/volumeattributesclasses/~A" name)))
      (is (uiop:string-prefix-p "e2e-" name))
      (is (equal "bar" (gethash "foo" (gethash "parameters" created))))
      (is (equalp #("kubernetes.io/vac-protection") (gethash "finalizers" (gethash "metadata" created))))
      (storage-http-check 200 item :method :patch :content-type "application/strategic-merge-patch+json"
                          :object (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "labels" (gr8s.resources::core-object name "patched"))))
      (storage-http-check 422 item :method :patch :content-type "application/merge-patch+json"
                          :object (gr8s.resources::core-object "parameters" (gr8s.resources::core-object "foo" "baz")))
      (storage-http-check 422 item :method :patch :content-type "application/merge-patch+json"
                          :object (gr8s.resources::core-object "driverName" "other.example.test"))
      ;; A claim naming the class keeps it until the claim lets go, as vac-protection does.
      (let ((claim (storage-test-claim "uses-class")))
        (setf (gethash "volumeAttributesClassName" (gethash "spec" claim)) name)
        (gr8s.resources::create-core-resource store "persistentvolumeclaims" claim "default"))
      (storage-http-check 200 item :method :delete)
      (gr8s.resources::reconcile-storage-bindings store)
      (is-true (gethash "deletionTimestamp" (gethash "metadata" (storage-http-check 200 item))))
      (gr8s.resources::delete-core-resource store "persistentvolumeclaims" "default" "uses-class")
      (gr8s.resources::reconcile-storage-bindings store)
      (storage-http-check 404 item))
    (storage-http-check 422 "/apis/storage.k8s.io/v1/volumeattributesclasses" :method :post
                        :object (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "no-parameters") "driverName" "e2e-fake-csi-driver"))
    (storage-http-check 201 "/apis/storage.k8s.io/v1/volumeattributesclasses" :method :post
                        :object (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "plain" "labels" (gr8s.resources::core-object "plain" "updated"))
                                                   "driverName" "e2e-fake-csi-driver" "parameters" (gr8s.resources::core-object "foo" "bar")))
    (storage-http-check 200 "/apis/storage.k8s.io/v1/volumeattributesclasses" :method :delete
                        :parameters '(("labelSelector" . "plain=updated")))
    (is (zerop (length (gethash "items" (storage-http-check 200 "/apis/storage.k8s.io/v1/volumeattributesclasses")))))))

(in-suite gr8s)
