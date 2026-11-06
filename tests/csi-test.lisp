;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify the CSI APIs, external provisioning hand-off, attachment control, driver
;;;; registration and the publish lifecycle against a recording fake driver. A real
;;;; driver and its sidecars need a root test node: see docs/persistent-storage.md.

(in-package #:gr8s/tests)
(def-suite csi :in gr8s)
(in-suite csi)

(defun csi-test-driver-object (name &key (attach-required t attach-supplied) modes)
  (let ((spec (gr8s::core-object)))
    (when attach-supplied (setf (gethash "attachRequired" spec) attach-required))
    (when modes (setf (gethash "volumeLifecycleModes" spec) modes))
    (gr8s::core-object "apiVersion" "storage.k8s.io/v1" "kind" "CSIDriver"
                       "metadata" (gr8s::core-object "name" name) "spec" spec)))

(defun csi-test-volume (name &key (driver "csi.example.test") (handle "disk-1") (class "") claim-ref)
  (let ((volume (storage-test-volume name "/unused" :class class)))
    (remhash "hostPath" (gethash "spec" volume))
    (setf (gethash "csi" (gethash "spec" volume)) (gr8s::core-object "driver" driver "volumeHandle" handle))
    (when claim-ref (setf (gethash "claimRef" (gethash "spec" volume)) claim-ref))
    volume))

(test csi-api-objects-are-served-with-kubernetes-defaults-and-immutability
  (with-temporary-store (store path)
    (values path)
    (let* ((driver (gr8s::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test") nil))
           (spec (gethash "spec" driver)))
      (is (eq t (gethash "attachRequired" spec)))
      (is (equal "ReadWriteOnceWithFSType" (gethash "fsGroupPolicy" spec)))
      (is (equalp #("Persistent") (gethash "volumeLifecycleModes" spec))))
    (signals kubernetes-error
      (gr8s::update-core-resource store "csidrivers" nil "csi.example.test"
                                  (lambda (old)
                                    (let ((copy (gr8s::copy-core-object old)))
                                      (setf (gethash "attachRequired" (gethash "spec" copy)) nil)
                                      copy))))
    (signals kubernetes-error
      (gr8s::create-core-resource store "csidrivers" (csi-test-driver-object "not_a_driver!") nil))
    (signals kubernetes-error
      (gr8s::create-core-resource store "csidrivers"
                                  (csi-test-driver-object "other.example.test" :modes #("Sometimes")) nil))
    (is (gr8s::create-core-resource
         store "csinodes"
         (gr8s::core-object "metadata" (gr8s::core-object "name" "worker-a")
                            "spec" (gr8s::core-object "drivers" (vector (gr8s::core-object "name" "csi.example.test" "nodeID" "n1"))))
         nil))
    (signals kubernetes-error
      (gr8s::create-core-resource
       store "csinodes"
       (gr8s::core-object "metadata" (gr8s::core-object "name" "worker-b")
                          "spec" (gr8s::core-object "drivers" (vector (gr8s::core-object "name" "csi.example.test"))))
       nil))
    (is (gr8s::create-core-resource
         store "csistoragecapacities"
         (gr8s::core-object "metadata" (gr8s::core-object "name" "cap") "storageClassName" "fast" "capacity" "1Gi")
         "default"))))

(test leases-serve-leader-election-for-driver-sidecars
  (with-temporary-store (store path)
    (values path)
    (let ((lease (gr8s::create-core-resource
                  store "leases"
                  (gr8s::core-object "metadata" (gr8s::core-object "name" "external-provisioner")
                                     "spec" (gr8s::core-object "holderIdentity" "me" "leaseDurationSeconds" 15))
                  "kube-system")))
      (is (equal "coordination.k8s.io/v1" (gethash "apiVersion" lease))))
    (signals kubernetes-error
      (gr8s::create-core-resource store "leases"
                                  (gr8s::core-object "metadata" (gr8s::core-object "name" "bad")
                                                     "spec" (gr8s::core-object "unknownField" 1))
                                  "kube-system"))))

(test volume-attachment-status-belongs-to-the-attacher
  (with-temporary-store (store path)
    (values path)
    (let ((input (gr8s::core-object "metadata" (gr8s::core-object "name" "a1")
                                    "spec" (gr8s::core-object "attacher" "csi.example.test" "nodeName" "worker-a"
                                                              "source" (gr8s::core-object "persistentVolumeName" "pv"))
                                    "status" (gr8s::core-object "attached" t))))
      (is (null (gethash "status" (gr8s::create-core-resource store "volumeattachments" input nil))))
      ;; external-attacher adds its finalizer repeatedly before any status exists.
      (dotimes (attempt 2)
        (gr8s::update-core-resource store "volumeattachments" nil "a1"
                                    (lambda (old)
                                      (let ((copy (gr8s::copy-core-object old)))
                                        (setf (gethash "labels" (gethash "metadata" copy))
                                              (gr8s::core-object "attempt" (write-to-string attempt)))
                                        copy))))
      (is (null (gethash "status" (gr8s::get-core-resource store "volumeattachments" nil "a1"))))
      (signals kubernetes-error
        (gr8s::update-core-resource store "volumeattachments" nil "a1"
                                    (lambda (old)
                                      (let ((copy (gr8s::copy-core-object old)))
                                        (setf (gethash "nodeName" (gethash "spec" copy)) "worker-b")
                                        copy))))
      (let ((gr8s::*storage-status-write* t))
        (gr8s::update-core-resource store "volumeattachments" nil "a1"
                                    (lambda (old)
                                      (let ((copy (gr8s::copy-core-object old)))
                                        (setf (gethash "status" copy) (gr8s::core-object "attached" t))
                                        copy))))
      (is (eq t (gethash "attached" (gethash "status" (gr8s::get-core-resource store "volumeattachments" nil "a1"))))))))

(test claims-of-a-csi-class-are-handed-to-its-external-provisioner
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "storageclasses"
                                (provisioning-class "fast" "csi.example.test" "volumeBindingMode" "WaitForFirstConsumer") nil)
    (gr8s::create-core-resource store "storageclasses"
                                (provisioning-class "now" "csi.example.test") nil)
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "delayed" :class "fast") "default")
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "immediate" :class "now") "default")
    (gr8s::reconcile-storage-bindings store)
    (flet ((annotation (claim key)
             (gethash key (gethash "annotations" (gethash "metadata" (claim-object store claim)) (gr8s::core-object)))))
      (is (equal "csi.example.test" (annotation "immediate" gr8s::+external-provisioner-annotation+)))
      ;; A delayed claim isn't announced until its consumer has chosen a node.
      (is (null (annotation "delayed" gr8s::+external-provisioner-annotation+)))
      (ready-node store "worker-a" "a" "10.64.0.0/20")
      (let ((node (gr8s:schedule-pod store (create-pod store (storage-test-pod "consumer" "delayed")))))
        (is (equal "worker-a" (gr8s:node-record-name node))))
      (gr8s::reconcile-storage-bindings store)
      (is (equal "csi.example.test" (annotation "delayed" gr8s::+external-provisioner-annotation+)))
      (is (equal "worker-a" (annotation "delayed" gr8s::+selected-node-annotation+)))
      (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" "delayed")))
      (let ((revision (gr8s::pod-store-resource-revision store)))
        (is-false (gr8s::reconcile-storage-bindings store))
        (is (= revision (gr8s::pod-store-resource-revision store))))
      ;; The sidecar's volume reserves exactly this claim, which then binds to it.
      (let* ((claim (claim-object store "immediate"))
             (volume (csi-test-volume "pvc-sidecar" :class "now"
                                      :claim-ref (gr8s::core-object
                                                  "name" "immediate" "namespace" "default"
                                                  "uid" (gethash "uid" (gethash "metadata" claim))))))
        (setf (gethash "annotations" (gethash "metadata" volume))
              (gr8s::core-object gr8s::+provisioned-by-annotation+ "csi.example.test")
              (gethash "persistentVolumeReclaimPolicy" (gethash "spec" volume)) "Delete")
        (gr8s::create-core-resource store "persistentvolumes" volume nil))
      (gr8s::reconcile-storage-bindings store)
      (is (equal "pvc-sidecar" (claim-volume-name store "immediate")))
      ;; external-provisioner deletes a Released volume, so it must not report Failed.
      (gr8s::delete-core-resource store "persistentvolumeclaims" "default" "immediate")
      (gr8s::reconcile-storage-bindings store)
      (let ((volume (gr8s::get-core-resource store "persistentvolumes" nil "pvc-sidecar")))
        (is (equal "Released" (gethash "phase" (gethash "status" volume))))
        (is-false (gr8s::storage-volume-reclaimable-p volume))))))

(test no-provisioner-classes-still-wait-for-an-administrator
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "storageclasses"
                                (provisioning-class "manual" gr8s::+no-provisioner+ "volumeBindingMode" "WaitForFirstConsumer") nil)
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim" :class "manual") "default")
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (is (null (gr8s:schedule-pod store (create-pod store (storage-test-pod "consumer" "claim")))))))

(test attachments-follow-consumers-and-honor-the-driver
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (gr8s::create-core-resource store "persistentvolumes" (csi-test-volume "pv") nil)
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
    (gr8s::reconcile-storage-bindings store)
    (gr8s::reconcile-volume-attachments store)
    (is (null (gr8s::list-core-resources store "volumeattachments")))
    (let* ((pod (create-pod store (storage-test-pod "consumer" "claim")))
           (node (gr8s:schedule-pod store pod))
           (name (gr8s::volume-attachment-name "csi.example.test" "disk-1" "worker-a")))
      (is-true node)
      (gr8s::reconcile-volume-attachments store)
      (let* ((attachment (gr8s::get-core-resource store "volumeattachments" nil name))
             (spec (gethash "spec" attachment)))
        (is (equal "csi.example.test" (gethash "attacher" spec)))
        (is (equal "worker-a" (gethash "nodeName" spec)))
        (is (equal "pv" (gethash "persistentVolumeName" (gethash "source" spec)))))
      (gr8s::reconcile-volume-attachments store)
      (is (= 1 (length (gr8s::list-core-resources store "volumeattachments"))))
      ;; The attacher's finalizer keeps the object until it has actually detached.
      (gr8s::update-core-resource store "volumeattachments" nil name
                                  (lambda (old)
                                    (let ((copy (gr8s::copy-core-object old)))
                                      (setf (gethash "finalizers" (gethash "metadata" copy)) #("external-attacher/csi-example-test"))
                                      copy)))
      (gr8s::remove-pod store "default" "consumer")
      (gr8s::reconcile-volume-attachments store)
      (is-true (gethash "deletionTimestamp"
                        (gethash "metadata" (gr8s::get-core-resource store "volumeattachments" nil name))))))
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (gr8s::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test" :attach-required nil) nil)
    (gr8s::create-core-resource store "persistentvolumes" (csi-test-volume "pv") nil)
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
    (gr8s::reconcile-storage-bindings store)
    (gr8s:schedule-pod store (create-pod store (storage-test-pod "consumer" "claim")))
    (gr8s::reconcile-volume-attachments store)
    (is (null (gr8s::list-core-resources store "volumeattachments")))))

(test attachments-gr8s-did-not-create-are-left-alone
  ;; The VolumeAttachment conformance specs create attachments for PVs that don't exist.
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (let ((ours (gr8s::volume-attachment-name "csi.example.test" "gone" "worker-a")))
      (dolist (name (list "va-e2e-2xjx6" ours))
        (gr8s::create-core-resource
         store "volumeattachments"
         (gr8s::core-object "metadata" (gr8s::core-object "name" name)
                            "spec" (gr8s::core-object "attacher" "e2e-test.storage.k8s.io" "nodeName" "worker-a"
                                                      "source" (gr8s::core-object "persistentVolumeName" "pv-e2e-2xjx6")))
         nil))
      (is-true (gr8s::gr8s-volume-attachment-name-p ours))
      (is-false (gr8s::gr8s-volume-attachment-name-p "va-e2e-2xjx6"))
      (gr8s::reconcile-volume-attachments store)
      (is (equal '("va-e2e-2xjx6")
                 (mapcar (lambda (object) (gethash "name" (gethash "metadata" object)))
                         (gr8s::list-core-resources store "volumeattachments")))))))

(test csi-assignments-carry-only-what-their-own-volume-needs
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (gr8s::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test") nil)
    (gr8s::create-core-resource store "csidrivers" (csi-test-driver-object "other.example.test") nil)
    (let ((volume (csi-test-volume "pv")))
      (setf (gethash "nodePublishSecretRef" (gethash "csi" (gethash "spec" volume)))
            (gr8s::core-object "name" "creds" "namespace" "storage-system"))
      (gr8s::create-core-resource store "persistentvolumes" volume nil))
    (gr8s::create-core-resource store "secrets"
                                (gr8s::core-object "metadata" (gr8s::core-object "name" "creds" "namespace" "storage-system")
                                                   "data" (gr8s::core-object "key" "dmFsdWU="))
                                "storage-system")
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
    (gr8s::reconcile-storage-bindings store)
    (let ((pod (create-pod store (storage-test-pod "consumer" "claim"))))
      (gr8s:schedule-pod store pod)
      (gr8s::reconcile-volume-attachments store)
      (let* ((pod (get-pod store "default" "consumer"))
             (objects (gr8s::pod-persistent-resource-objects store pod))
             (kinds (mapcar (lambda (object) (gethash "kind" object)) objects)))
        (dolist (kind '("PersistentVolumeClaim" "PersistentVolume" "CSIDriver" "VolumeAttachment" "Secret"))
          (is (member kind kinds :test #'equal)))
        (is (= 5 (length objects)))
        (dolist (object objects)
          (unless (equal "Secret" (gethash "kind" object))
            (is-true (gr8s::assigned-storage-resource-p object pod objects))))
        (is-true (gr8s::csi-volume-secret-reference-p
                  (find "Secret" objects :key (lambda (object) (gethash "kind" object)) :test #'equal) objects))
        ;; A forged driver or another node's attachment is refused on arrival.
        (is-false (gr8s::assigned-storage-resource-p
                   (gr8s::get-core-resource store "csidrivers" nil "other.example.test") pod objects))
        (is-false (gr8s::assigned-storage-resource-p
                   (gr8s::core-object "kind" "VolumeAttachment" "metadata" (gr8s::core-object "name" "x")
                                      "spec" (gr8s::core-object "nodeName" "worker-b"
                                                                "source" (gr8s::core-object "persistentVolumeName" "pv")))
                   pod objects))
        (is-false (gr8s::csi-volume-secret-reference-p
                   (gr8s::core-object "metadata" (gr8s::core-object "name" "creds" "namespace" "elsewhere")) objects))))))

(test node-registrations-publish-a-csinode-only-when-they-change
  (with-temporary-store (store path)
    (values path)
    (flet ((registration (name id)
             (make-instance 'gr8s.node.v1::csi-driver-registration
                            :name name :node-id id :max-volumes 16
                            :topology (list (cons "topology.example.test/zone" "z1")))))
      (is (null (gr8s::update-node-csi-registrations store "worker-a" nil)))
      (is (null (gr8s::list-core-resources store "csinodes")))
      (gr8s::update-node-csi-registrations store "worker-a" (list (registration "csi.example.test" "n1")))
      (let* ((node (gr8s::get-core-resource store "csinodes" nil "worker-a"))
             (entry (aref (gethash "drivers" (gethash "spec" node)) 0)))
        (is (equal "n1" (gethash "nodeID" entry)))
        (is (equalp #("topology.example.test/zone") (gethash "topologyKeys" entry)))
        (is (= 16 (gethash "count" (gethash "allocatable" entry)))))
      (let ((revision (gr8s::pod-store-resource-revision store)))
        (gr8s::update-node-csi-registrations store "worker-a" (list (registration "csi.example.test" "n1")))
        (is (= revision (gr8s::pod-store-resource-revision store))))
      (gr8s::update-node-csi-registrations store "worker-a" nil)
      (is (zerop (length (gethash "drivers" (gethash "spec" (gr8s::get-core-resource store "csinodes" nil "worker-a")))))))))

;;; Pods

(defun csi-pod-json (volume &key (propagation "") (context ""))
  (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"c\",\"uid\":\"c-uid\"},\"spec\":{\"volumes\":[~A],\"containers\":[{\"name\":\"c\",\"image\":\"busybox\"~A,\"volumeMounts\":[{\"name\":\"v\",\"mountPath\":\"/v\"~A}]}]}}"
          volume context propagation))

(test pods-validate-inline-csi-and-mount-propagation
  (let ((good "{\"name\":\"v\",\"csi\":{\"driver\":\"csi.example.test\",\"readOnly\":true,\"volumeAttributes\":{\"a\":\"b\"}}}")
        (host "{\"name\":\"v\",\"hostPath\":{\"path\":\"/var/lib/kubelet\"}}"))
    (is (parse-pod (csi-pod-json good)))
    (signals kubernetes-error
      (parse-pod (csi-pod-json "{\"name\":\"v\",\"csi\":{\"driver\":\"Not Valid\"}}")))
    (signals kubernetes-error
      (parse-pod (csi-pod-json "{\"name\":\"v\",\"csi\":{\"driver\":\"csi.example.test\",\"other\":1}}")))
    (is (parse-pod (csi-pod-json host :propagation ",\"mountPropagation\":\"HostToContainer\"")))
    (signals kubernetes-error (parse-pod (csi-pod-json host :propagation ",\"mountPropagation\":\"Sideways\"")))
    ;; A container that shares mounts back to the host has to be privileged, as upstream requires.
    (signals kubernetes-error (parse-pod (csi-pod-json host :propagation ",\"mountPropagation\":\"Bidirectional\"")))
    (let ((pod (parse-pod (csi-pod-json host :propagation ",\"mountPropagation\":\"Bidirectional\""
                                             :context ",\"securityContext\":{\"privileged\":true}"))))
      (let ((mount (aref (gethash "volumeMounts" (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0)) 0)))
        (is (= gr8s.cri.v1::+mountpropagation-propagation_bidirectional+ (gr8s::container-mount-propagation mount)))))
    (is (= gr8s.cri.v1::+mountpropagation-propagation_private+
           (gr8s::container-mount-propagation (gr8s::core-object))))))

;;; Driver registration and the publish lifecycle

(defmacro with-fake-csi-driver ((calls directory &key (stage t) (type "CSIPlugin") (versions ''("1.0.0"))) &body body)
  "Run BODY with a kubelet root in DIRECTORY and every CSI call answered by a recording driver."
  (let ((table (gensym "TABLE")))
    `(let* ((,calls nil)
            (gr8s::*csi-kubelet-root* (namestring (uiop:ensure-directory-pathname (merge-pathnames "kubelet/" (truename ,directory)))))
            (gr8s::*csi-plugins* (make-hash-table :test #'equal))
            (,table (merge-pathnames "csi-mountinfo" ,directory))
            (gr8s::*pod-mount-table-path* ,table)
            (gr8s::*csi-call*
              (lambda (socket operation request)
                (push (list operation socket request) ,calls)
                (ecase operation
                  (:get-info (make-instance 'gr8s.pluginregistration.v1::plugin-info
                                            :type ,type :name "csi.example.test"
                                            :endpoint "/run/csi.sock" :supported-versions ,versions))
                  (:notify (make-instance 'gr8s.pluginregistration.v1::registration-status-response))
                  (:node-get-info (make-instance 'gr8s.csi.v1::node-get-info-response
                                                 :node-id "n1" :max-volumes-per-node 8))
                  (:node-capabilities
                   (make-instance 'gr8s.csi.v1::node-get-capabilities-response
                                  :capabilities (when ,stage
                                                  (list (make-instance 'gr8s.csi.v1::node-service-capability
                                                                       :rpc (make-instance 'gr8s.csi.v1::rpc :type 1))))))
                  ((:stage :unstage :publish :unpublish) t)))))
       (with-open-file (stream ,table :direction :output :if-exists :supersede)
         (format stream "22 1 0:21 / /proc rw - proc proc rw~%"))
       ,@body)))

(defun csi-operations (calls)
  (reverse (mapcar #'first calls)))

(defun make-registry-socket (root name)
  "Create a real socket file in the plugin registry, as node-driver-registrar does."
  (let ((path (format nil "~Aplugins_registry/~A" root name))
        (socket (make-instance 'sb-bsd-sockets:local-socket :type :stream)))
    (ensure-directories-exist path)
    (sb-bsd-sockets:socket-bind socket path)
    (values path socket)))

(test drivers-register-through-the-kubelet-plugin-registry
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-csi-driver (calls directory)
      (is (null (gr8s::csi-driver-registrations)))
      (gr8s::scan-csi-plugin-registry)
      (is (null calls))
      (multiple-value-bind (path socket) (make-registry-socket gr8s::*csi-kubelet-root* "csi.example.test-reg.sock")
        (unwind-protect
             (progn
               (gr8s::scan-csi-plugin-registry)
               (is (equal '(:get-info :node-get-info :node-capabilities :notify) (csi-operations calls)))
               (is (eq t (gr8s.pluginregistration.v1::plugin-registered (third (first calls)))))
               (let ((registration (first (gr8s::csi-driver-registrations))))
                 (is (equal "csi.example.test" (slot-value registration 'gr8s.node.v1::name)))
                 (is (equal "n1" (slot-value registration 'gr8s.node.v1::node-id)))
                 (is (= 8 (slot-value registration 'gr8s.node.v1::max-volumes))))
               (is-true (gr8s::csi-plugin-stage-unstage-p (gr8s::csi-plugin-for "csi.example.test")))
               ;; An unchanged socket isn't asked again.
               (let ((count (length calls)))
                 (gr8s::scan-csi-plugin-registry)
                 (is (= count (length calls)))))
          (sb-bsd-sockets:socket-close socket))
        (delete-file path)
        (gr8s::scan-csi-plugin-registry)
        (is (null (gr8s::csi-driver-registrations)))
        (signals runtime-error (gr8s::csi-plugin-for "csi.example.test"))))))

(test unusable-plugins-are-told-why-and-stay-unregistered
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (dolist (scenario '(("DRAPlugin" ("1.0.0")) ("CSIPlugin" ("0.3.0"))))
      (destructuring-bind (type versions) scenario
        (with-fake-csi-driver (calls directory :type type :versions versions)
          (multiple-value-bind (path socket)
              (make-registry-socket gr8s::*csi-kubelet-root* (format nil "~A-reg.sock" (string-downcase type)))
            (unwind-protect
                 (let ((*error-output* (make-broadcast-stream)))
                   (gr8s::scan-csi-plugin-registry)
                   (is (null (gr8s::csi-driver-registrations)))
                   (is (eq :notify (first (first calls))))
                   (is (not (gr8s.pluginregistration.v1::plugin-registered (third (first calls))))))
              (sb-bsd-sockets:socket-close socket)
              (delete-file path))))))))

(defun csi-register-fake ()
  (bt:with-lock-held (gr8s::*csi-plugins-lock*)
    (setf (gethash "csi.example.test" gr8s::*csi-plugins*)
          (gr8s::make-csi-plugin :name "csi.example.test" :endpoint "/run/csi.sock" :stage-unstage-p t))))

(defun csi-test-pod (name uid)
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"~A\",\"namespace\":\"default\",\"uid\":\"~A\"},\"spec\":{\"nodeName\":\"worker-a\",\"containers\":[{\"name\":\"c\",\"image\":\"busybox\"}]}}" name uid)))

(defun bound-csi-volume (&key (modes #("ReadWriteMany")))
  (gr8s::core-object
   "metadata" (gr8s::core-object "name" "pv")
   "spec" (gr8s::core-object "accessModes" modes "mountOptions" #("noatime")
                             "csi" (gr8s::core-object "driver" "csi.example.test" "volumeHandle" "disk-1" "fsType" "ext4"
                                                      "volumeAttributes" (gr8s::core-object "tier" "gold")))))

(test publishing-waits-for-attachment-then-stages-and-publishes
  (with-temporary-store (store directory)
    (with-fake-csi-driver (calls directory)
      (csi-register-fake)
      (let ((pod (csi-test-pod "first" "uid-1")) (volume (bound-csi-volume)))
        ;; No CSIDriver object means an attachment is required, as in Kubernetes.
        (signals runtime-error (gr8s::materialize-persistent-csi-volume store pod "data" volume))
        (is (null calls))
        (let ((name (gr8s::volume-attachment-name "csi.example.test" "disk-1" "worker-a")))
          (gr8s::create-core-resource
           store "volumeattachments"
           (gr8s::core-object "metadata" (gr8s::core-object "name" name)
                              "spec" (gr8s::core-object "attacher" "csi.example.test" "nodeName" "worker-a"
                                                        "source" (gr8s::core-object "persistentVolumeName" "pv")))
           nil)
          (signals runtime-error (gr8s::materialize-persistent-csi-volume store pod "data" volume))
          (let ((gr8s::*storage-status-write* t))
            (gr8s::update-core-resource
             store "volumeattachments" nil name
             (lambda (old)
               (let ((copy (gr8s::copy-core-object old)))
                 (setf (gethash "status" copy)
                       (gr8s::core-object "attached" t "attachmentMetadata" (gr8s::core-object "lun" "3")))
                 copy)))))
        (let ((path (gr8s::materialize-persistent-csi-volume store pod "data" volume)))
          (is (equal '(:stage :publish) (csi-operations calls)))
          (let* ((stage (third (second calls))) (publish (third (first calls)))
                 (capability (gr8s.csi.v1::volume-capability publish)))
            (is (equal "disk-1" (gr8s.csi.v1::volume-id publish)))
            (is (equal (gr8s.csi.v1::staging-target-path stage) (gr8s.csi.v1::staging-target-path publish)))
            (is (uiop:string-suffix-p (gr8s.csi.v1::staging-target-path publish) "/globalmount"))
            (is (equal (format nil "~Apods/uid-1/volumes/kubernetes.io~~csi/data/mount" gr8s::*csi-kubelet-root*)
                       (gr8s.csi.v1::target-path publish)))
            (is (equal (string-right-trim "/" (namestring path)) (gr8s.csi.v1::target-path publish)))
            (is (equal '(("lun" . "3")) (gr8s.csi.v1::publish-context publish)))
            (is (equal "gold" (cdr (assoc "tier" (gr8s.csi.v1::volume-context publish) :test #'equal))))
            (is (equal "first" (cdr (assoc "csi.storage.k8s.io/pod.name" (gr8s.csi.v1::volume-context publish) :test #'equal))))
            (is (eq :mount (gr8s.csi.v1::access-type-case capability)))
            (is (equal "ext4" (gr8s.csi.v1::fs-type (gr8s.csi.v1::mount capability))))
            (is (equal '("noatime") (gr8s.csi.v1::mount-flags (gr8s.csi.v1::mount capability))))
            (is (= 5 (gr8s.csi.v1::mode (gr8s.csi.v1::access-mode capability))))))))))

(test drivers-that-need-no-attachment-publish-at-once
  (with-temporary-store (store directory)
    (with-fake-csi-driver (calls directory)
      (setf (gethash "csi.example.test" gr8s::*csi-plugins*)
            (gr8s::make-csi-plugin :name "csi.example.test" :endpoint "/run/csi.sock" :stage-unstage-p nil))
      (gr8s::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test" :attach-required nil) nil)
      (gr8s::materialize-persistent-csi-volume store (csi-test-pod "first" "uid-1") "data" (bound-csi-volume))
      (is (equal '(:publish) (csi-operations calls))))))

(test the-last-pod-using-a-volume-unstages-it
  (with-temporary-store (store directory)
    (with-fake-csi-driver (calls directory)
      (csi-register-fake)
      (gr8s::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test" :attach-required nil) nil)
      (dolist (entry '(("first" "uid-1") ("second" "uid-2")))
        (gr8s::materialize-persistent-csi-volume store (apply #'csi-test-pod entry) "data" (bound-csi-volume)))
      (setf calls nil)
      (gr8s::cleanup-pod-csi-volumes "uid-1")
      (is (equal '(:unpublish) (csi-operations calls)))
      (is (equal (format nil "~Apods/uid-1/volumes/kubernetes.io~~csi/data/mount" gr8s::*csi-kubelet-root*)
                 (gr8s.csi.v1::target-path (third (first calls)))))
      (is (null (probe-file (format nil "~Apods/uid-1/" gr8s::*csi-kubelet-root*))))
      (setf calls nil)
      (gr8s::cleanup-pod-csi-volumes "uid-2")
      (is (equal '(:unpublish :unstage) (csi-operations calls)))
      ;; Nothing is left to do on a second pass.
      (setf calls nil)
      (gr8s::cleanup-pod-csi-volumes "uid-2")
      (is (null calls)))))

(test a-failed-unpublish-leaves-the-record-so-deletion-retries
  (with-temporary-store (store directory)
    (with-fake-csi-driver (calls directory)
      (csi-register-fake)
      (gr8s::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test" :attach-required nil) nil)
      (gr8s::materialize-persistent-csi-volume store (csi-test-pod "first" "uid-1") "data" (bound-csi-volume))
      ;; The driver is unavailable, so the volume can't be declared gone.
      (clrhash gr8s::*csi-plugins*)
      (signals runtime-error (gr8s::cleanup-pod-csi-volumes "uid-1"))
      (is (= 1 (length (gr8s::csi-volume-records))))
      (csi-register-fake)
      (gr8s::cleanup-pod-csi-volumes "uid-1")
      (is (zerop (length (gr8s::csi-volume-records)))))))

(test inline-volumes-require-a-driver-that-allows-them
  (with-temporary-store (store directory)
    (with-fake-csi-driver (calls directory)
      (csi-register-fake)
      (let* ((pod (csi-test-pod "first" "uid-1"))
             (volume (gr8s::core-object "name" "secrets"
                                        "csi" (gr8s::core-object "driver" "csi.example.test" "readOnly" t
                                                                 "volumeAttributes" (gr8s::core-object "a" "b")))))
        (signals runtime-error (gr8s::materialize-inline-csi-volume store pod volume))
        (gr8s::create-core-resource store "csidrivers"
                                    (csi-test-driver-object "csi.example.test" :modes #("Persistent")) nil)
        (signals runtime-error (gr8s::materialize-inline-csi-volume store pod volume)))
      (is (null calls)))
    (with-temporary-store (store second)
      (with-fake-csi-driver (calls second)
        (setf (gethash "csi.example.test" gr8s::*csi-plugins*)
              (gr8s::make-csi-plugin :name "csi.example.test" :endpoint "/run/csi.sock" :stage-unstage-p t))
        (gr8s::create-core-resource store "csidrivers"
                                    (csi-test-driver-object "csi.example.test" :modes #("Ephemeral")) nil)
        (multiple-value-bind (path readonly)
            (gr8s::materialize-inline-csi-volume
             store (csi-test-pod "first" "uid-1")
             (gr8s::core-object "name" "secrets"
                                "csi" (gr8s::core-object "driver" "csi.example.test" "readOnly" t)))
          (is-true path)
          (is (eq t readonly))
          ;; An inline volume has no separate lifetime to stage for, and no shared identity.
          (is (uiop:string-prefix-p "csi-" (gr8s.csi.v1::volume-id (third (first calls)))))
          (is (equal "true" (cdr (assoc "csi.storage.k8s.io/ephemeral"
                                        (gr8s.csi.v1::volume-context (third (first calls))) :test #'equal))))
          (is (eq t (gr8s.csi.v1::readonly (third (first calls))))))))))

(test csi-requests-use-the-specifications-field-numbers
  ;; Field 4 target_path, field 1 volume_id: a driver decodes these, so they must not drift.
  (let* ((request (make-instance 'gr8s.csi.v1::node-publish-volume-request
                                 :volume-id "v" :target-path "t" :readonly t))
         (bytes (ag-proto:serialize-to-bytes request)))
    (is (equalp #(#x0a 1 118 #x22 1 116 #x30 1) (coerce bytes 'vector))))
  (let ((bytes (ag-proto:serialize-to-bytes
                (make-instance 'gr8s.pluginregistration.v1::registration-status :plugin-registered t))))
    (is (equalp #(#x08 1) (coerce bytes 'vector)))))
