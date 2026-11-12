;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the CSI APIs, external provisioning hand-off, attachment control, driver
;;;; registration and the publish lifecycle against a recording fake driver. A real
;;;; driver and its sidecars need a root test node: see docs/persistent-storage.md.

(in-package #:gr8s/tests)
(def-suite csi :in gr8s)
(in-suite csi)

(defun csi-test-driver-object (name &key (attach-required t attach-supplied) modes)
  (let ((spec (gr8s.resources::core-object)))
    (when attach-supplied (setf (gethash "attachRequired" spec) attach-required))
    (when modes (setf (gethash "volumeLifecycleModes" spec) modes))
    (gr8s.resources::core-object "apiVersion" "storage.k8s.io/v1" "kind" "CSIDriver"
                       "metadata" (gr8s.resources::core-object "name" name) "spec" spec)))

(defun csi-test-volume (name &key (driver "csi.example.test") (handle "disk-1") (class "") claim-ref)
  (let ((volume (storage-test-volume name "/unused" :class class)))
    (remhash "hostPath" (gethash "spec" volume))
    (setf (gethash "csi" (gethash "spec" volume)) (gr8s.resources::core-object "driver" driver "volumeHandle" handle))
    (when claim-ref (setf (gethash "claimRef" (gethash "spec" volume)) claim-ref))
    volume))

(test csi-api-objects-are-served-with-kubernetes-defaults-and-immutability
  (with-temporary-store (store path)
    (values path)
    (let* ((driver (gr8s.resources::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test") nil))
           (spec (gethash "spec" driver)))
      (is (eq t (gethash "attachRequired" spec)))
      (is (equal "ReadWriteOnceWithFSType" (gethash "fsGroupPolicy" spec)))
      (is (equalp #("Persistent") (gethash "volumeLifecycleModes" spec))))
    (signals kubernetes-error
      (gr8s.resources::update-core-resource store "csidrivers" nil "csi.example.test"
                                  (lambda (old)
                                    (let ((copy (gr8s.resources::copy-core-object old)))
                                      (setf (gethash "attachRequired" (gethash "spec" copy)) nil)
                                      copy))))
    (signals kubernetes-error
      (gr8s.resources::create-core-resource store "csidrivers" (csi-test-driver-object "not_a_driver!") nil))
    (signals kubernetes-error
      (gr8s.resources::create-core-resource store "csidrivers"
                                  (csi-test-driver-object "other.example.test" :modes #("Sometimes")) nil))
    (is (gr8s.resources::create-core-resource
         store "csinodes"
         (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "worker-a")
                            "spec" (gr8s.resources::core-object "drivers" (vector (gr8s.resources::core-object "name" "csi.example.test" "nodeID" "n1"))))
         nil))
    (signals kubernetes-error
      (gr8s.resources::create-core-resource
       store "csinodes"
       (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "worker-b")
                          "spec" (gr8s.resources::core-object "drivers" (vector (gr8s.resources::core-object "name" "csi.example.test"))))
       nil))
    (is (gr8s.resources::create-core-resource
         store "csistoragecapacities"
         (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "cap") "storageClassName" "fast" "capacity" "1Gi")
         "default"))))

(test leases-serve-leader-election-for-driver-sidecars
  (with-temporary-store (store path)
    (values path)
    (let ((lease (gr8s.resources::create-core-resource
                  store "leases"
                  (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "external-provisioner")
                                     "spec" (gr8s.resources::core-object "holderIdentity" "me" "leaseDurationSeconds" 15))
                  "kube-system")))
      (is (equal "coordination.k8s.io/v1" (gethash "apiVersion" lease))))
    (signals kubernetes-error
      (gr8s.resources::create-core-resource store "leases"
                                  (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "bad")
                                                     "spec" (gr8s.resources::core-object "unknownField" 1))
                                  "kube-system"))))

(test volume-attachment-status-belongs-to-the-attacher
  (with-temporary-store (store path)
    (values path)
    (let ((input (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "a1")
                                    "spec" (gr8s.resources::core-object "attacher" "csi.example.test" "nodeName" "worker-a"
                                                              "source" (gr8s.resources::core-object "persistentVolumeName" "pv"))
                                    "status" (gr8s.resources::core-object "attached" t))))
      (is (null (gethash "status" (gr8s.resources::create-core-resource store "volumeattachments" input nil))))
      ;; external-attacher adds its finalizer repeatedly before any status exists.
      (dotimes (attempt 2)
        (gr8s.resources::update-core-resource store "volumeattachments" nil "a1"
                                    (lambda (old)
                                      (let ((copy (gr8s.resources::copy-core-object old)))
                                        (setf (gethash "labels" (gethash "metadata" copy))
                                              (gr8s.resources::core-object "attempt" (write-to-string attempt)))
                                        copy))))
      (is (null (gethash "status" (gr8s.resources::get-core-resource store "volumeattachments" nil "a1"))))
      (signals kubernetes-error
        (gr8s.resources::update-core-resource store "volumeattachments" nil "a1"
                                    (lambda (old)
                                      (let ((copy (gr8s.resources::copy-core-object old)))
                                        (setf (gethash "nodeName" (gethash "spec" copy)) "worker-b")
                                        copy))))
      (let ((gr8s.resources::*storage-status-write* t))
        (gr8s.resources::update-core-resource store "volumeattachments" nil "a1"
                                    (lambda (old)
                                      (let ((copy (gr8s.resources::copy-core-object old)))
                                        (setf (gethash "status" copy) (gr8s.resources::core-object "attached" t))
                                        copy))))
      (is (eq t (gethash "attached" (gethash "status" (gr8s.resources::get-core-resource store "volumeattachments" nil "a1"))))))))

(test claims-of-a-csi-class-are-handed-to-its-external-provisioner
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "storageclasses"
                                (provisioning-class "fast" "csi.example.test" "volumeBindingMode" "WaitForFirstConsumer") nil)
    (gr8s.resources::create-core-resource store "storageclasses"
                                (provisioning-class "now" "csi.example.test") nil)
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "delayed" :class "fast") "default")
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "immediate" :class "now") "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (flet ((annotation (claim key)
             (gethash key (gethash "annotations" (gethash "metadata" (claim-object store claim)) (gr8s.resources::core-object)))))
      (is (equal "csi.example.test" (annotation "immediate" gr8s.resources::+external-provisioner-annotation+)))
      ;; A delayed claim isn't announced until its consumer has chosen a node.
      (is (null (annotation "delayed" gr8s.resources::+external-provisioner-annotation+)))
      (ready-node store "worker-a" "a" "10.64.0.0/20")
      (let ((node (gr8s.controllers::schedule-pod store (create-pod store (storage-test-pod "consumer" "delayed")))))
        (is (equal "worker-a" (gr8s.model::node-record-name node))))
      (gr8s.resources::reconcile-storage-bindings store)
      (is (equal "csi.example.test" (annotation "delayed" gr8s.resources::+external-provisioner-annotation+)))
      (is (equal "worker-a" (annotation "delayed" gr8s.resources::+selected-node-annotation+)))
      (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" "delayed")))
      (let ((revision (gr8s.store::pod-store-resource-revision store)))
        (is-false (gr8s.resources::reconcile-storage-bindings store))
        (is (= revision (gr8s.store::pod-store-resource-revision store))))
      ;; The sidecar's volume reserves exactly this claim, which then binds to it.
      (let* ((claim (claim-object store "immediate"))
             (volume (csi-test-volume "pvc-sidecar" :class "now"
                                      :claim-ref (gr8s.resources::core-object
                                                  "name" "immediate" "namespace" "default"
                                                  "uid" (gethash "uid" (gethash "metadata" claim))))))
        (setf (gethash "annotations" (gethash "metadata" volume))
              (gr8s.resources::core-object gr8s.resources::+provisioned-by-annotation+ "csi.example.test")
              (gethash "persistentVolumeReclaimPolicy" (gethash "spec" volume)) "Delete")
        (gr8s.resources::create-core-resource store "persistentvolumes" volume nil))
      (gr8s.resources::reconcile-storage-bindings store)
      (is (equal "pvc-sidecar" (claim-volume-name store "immediate")))
      ;; external-provisioner deletes a Released volume, so it must not report Failed.
      (gr8s.resources::delete-core-resource store "persistentvolumeclaims" "default" "immediate")
      (gr8s.resources::reconcile-storage-bindings store)
      (let ((volume (gr8s.resources::get-core-resource store "persistentvolumes" nil "pvc-sidecar")))
        (is (equal "Released" (gethash "phase" (gethash "status" volume))))
        (is-false (gr8s.resources::storage-volume-reclaimable-p volume))))))

(test no-provisioner-classes-still-wait-for-an-administrator
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "storageclasses"
                                (provisioning-class "manual" gr8s.resources::+no-provisioner+ "volumeBindingMode" "WaitForFirstConsumer") nil)
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim" :class "manual") "default")
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (is (null (gr8s.controllers::schedule-pod store (create-pod store (storage-test-pod "consumer" "claim")))))))

(test attachments-follow-consumers-and-honor-the-driver
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (gr8s.resources::create-core-resource store "persistentvolumes" (csi-test-volume "pv") nil)
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (gr8s.resources::reconcile-volume-attachments store)
    (is (null (gr8s.resources::list-core-resources store "volumeattachments")))
    (let* ((pod (create-pod store (storage-test-pod "consumer" "claim")))
           (node (gr8s.controllers::schedule-pod store pod))
           (name (gr8s.resources::volume-attachment-name "csi.example.test" "disk-1" "worker-a")))
      (is-true node)
      (gr8s.resources::reconcile-volume-attachments store)
      (let* ((attachment (gr8s.resources::get-core-resource store "volumeattachments" nil name))
             (spec (gethash "spec" attachment)))
        (is (equal "csi.example.test" (gethash "attacher" spec)))
        (is (equal "worker-a" (gethash "nodeName" spec)))
        (is (equal "pv" (gethash "persistentVolumeName" (gethash "source" spec)))))
      (gr8s.resources::reconcile-volume-attachments store)
      (is (= 1 (length (gr8s.resources::list-core-resources store "volumeattachments"))))
      ;; The attacher's finalizer keeps the object until it has actually detached.
      (gr8s.resources::update-core-resource store "volumeattachments" nil name
                                  (lambda (old)
                                    (let ((copy (gr8s.resources::copy-core-object old)))
                                      (setf (gethash "finalizers" (gethash "metadata" copy)) #("external-attacher/csi-example-test"))
                                      copy)))
      (gr8s.store::remove-pod store "default" "consumer")
      (gr8s.resources::reconcile-volume-attachments store)
      (is-true (gethash "deletionTimestamp"
                        (gethash "metadata" (gr8s.resources::get-core-resource store "volumeattachments" nil name))))))
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (gr8s.resources::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test" :attach-required nil) nil)
    (gr8s.resources::create-core-resource store "persistentvolumes" (csi-test-volume "pv") nil)
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (gr8s.controllers::schedule-pod store (create-pod store (storage-test-pod "consumer" "claim")))
    (gr8s.resources::reconcile-volume-attachments store)
    (is (null (gr8s.resources::list-core-resources store "volumeattachments")))))

(test attachments-gr8s-did-not-create-are-left-alone
  ;; The VolumeAttachment conformance specs create attachments for PVs that don't exist.
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (let ((ours (gr8s.resources::volume-attachment-name "csi.example.test" "gone" "worker-a")))
      (dolist (name (list "va-e2e-2xjx6" ours))
        (gr8s.resources::create-core-resource
         store "volumeattachments"
         (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" name)
                            "spec" (gr8s.resources::core-object "attacher" "e2e-test.storage.k8s.io" "nodeName" "worker-a"
                                                      "source" (gr8s.resources::core-object "persistentVolumeName" "pv-e2e-2xjx6")))
         nil))
      (is-true (gr8s.resources::gr8s-volume-attachment-name-p ours))
      (is-false (gr8s.resources::gr8s-volume-attachment-name-p "va-e2e-2xjx6"))
      (gr8s.resources::reconcile-volume-attachments store)
      (is (equal '("va-e2e-2xjx6")
                 (mapcar (lambda (object) (gethash "name" (gethash "metadata" object)))
                         (gr8s.resources::list-core-resources store "volumeattachments")))))))

(test csi-assignments-carry-only-what-their-own-volume-needs
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (gr8s.resources::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test") nil)
    (gr8s.resources::create-core-resource store "csidrivers" (csi-test-driver-object "other.example.test") nil)
    (let ((volume (csi-test-volume "pv")))
      (setf (gethash "nodePublishSecretRef" (gethash "csi" (gethash "spec" volume)))
            (gr8s.resources::core-object "name" "creds" "namespace" "storage-system"))
      (gr8s.resources::create-core-resource store "persistentvolumes" volume nil))
    (gr8s.resources::create-core-resource store "secrets"
                                (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "creds" "namespace" "storage-system")
                                                   "data" (gr8s.resources::core-object "key" "dmFsdWU="))
                                "storage-system")
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (let ((pod (create-pod store (storage-test-pod "consumer" "claim"))))
      (gr8s.controllers::schedule-pod store pod)
      (gr8s.resources::reconcile-volume-attachments store)
      (let* ((pod (get-pod store "default" "consumer"))
             (objects (gr8s.kubelet::pod-persistent-resource-objects store pod))
             (kinds (mapcar (lambda (object) (gethash "kind" object)) objects)))
        (dolist (kind '("PersistentVolumeClaim" "PersistentVolume" "CSIDriver" "VolumeAttachment" "Secret"))
          (is (member kind kinds :test #'equal)))
        (is (= 5 (length objects)))
        (dolist (object objects)
          (unless (equal "Secret" (gethash "kind" object))
            (is-true (gr8s.kubelet::assigned-storage-resource-p object pod objects))))
        (is-true (gr8s.kubelet::csi-volume-secret-reference-p
                  (find "Secret" objects :key (lambda (object) (gethash "kind" object)) :test #'equal) objects))
        ;; A forged driver or another node's attachment is refused on arrival.
        (is-false (gr8s.kubelet::assigned-storage-resource-p
                   (gr8s.resources::get-core-resource store "csidrivers" nil "other.example.test") pod objects))
        (is-false (gr8s.kubelet::assigned-storage-resource-p
                   (gr8s.resources::core-object "kind" "VolumeAttachment" "metadata" (gr8s.resources::core-object "name" "x")
                                      "spec" (gr8s.resources::core-object "nodeName" "worker-b"
                                                                "source" (gr8s.resources::core-object "persistentVolumeName" "pv")))
                   pod objects))
        (is-false (gr8s.kubelet::csi-volume-secret-reference-p
                   (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "creds" "namespace" "elsewhere")) objects))))))

(test node-registrations-publish-a-csinode-only-when-they-change
  (with-temporary-store (store path)
    (values path)
    (flet ((registration (name id)
             (make-instance 'gr8s.node.v1::csi-driver-registration
                            :name name :node-id id :max-volumes 16
                            :topology (list (cons "topology.example.test/zone" "z1")))))
      (is (null (gr8s.resources::update-node-csi-registrations store "worker-a" nil)))
      (is (null (gr8s.resources::list-core-resources store "csinodes")))
      (gr8s.resources::update-node-csi-registrations store "worker-a" (list (registration "csi.example.test" "n1")))
      (let* ((node (gr8s.resources::get-core-resource store "csinodes" nil "worker-a"))
             (entry (aref (gethash "drivers" (gethash "spec" node)) 0)))
        (is (equal "n1" (gethash "nodeID" entry)))
        (is (equalp #("topology.example.test/zone") (gethash "topologyKeys" entry)))
        (is (= 16 (gethash "count" (gethash "allocatable" entry)))))
      (let ((revision (gr8s.store::pod-store-resource-revision store)))
        (gr8s.resources::update-node-csi-registrations store "worker-a" (list (registration "csi.example.test" "n1")))
        (is (= revision (gr8s.store::pod-store-resource-revision store))))
      (gr8s.resources::update-node-csi-registrations store "worker-a" nil)
      (is (zerop (length (gethash "drivers" (gethash "spec" (gr8s.resources::get-core-resource store "csinodes" nil "worker-a")))))))))

(test driver-topology-labels-its-node-as-a-kubelet-does
  ;; external-provisioner looks for a driver's topology keys on Node labels.
  (with-temporary-store (store path)
    (values path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (flet ((registration (name topology)
             (make-instance 'gr8s.node.v1::csi-driver-registration :name name :node-id "n1" :topology topology))
           (labels-of () (gr8s.model::node-record-labels (gr8s.controllers::get-node store "worker-a"))))
      (gr8s.resources::update-node-csi-registrations store "worker-a"
                                           (list (registration "csi.example.test" (list (cons "topology.example.test/node" "worker-a")))))
      (is (equal "worker-a" (gethash "topology.example.test/node" (labels-of))))
      (is (equal "worker-a" (gethash "topology.example.test/node"
                                     (gethash "labels" (gethash "metadata" (gr8s.resources::node-api-object (gr8s.controllers::get-node store "worker-a")))))))
      ;; A colliding value is reported, never written over the existing label.
      (gr8s.resources::update-node-csi-registrations store "worker-a"
                                           (list (registration "other.example.test" (list (cons "topology.example.test/node" "elsewhere")))))
      (is (equal "worker-a" (gethash "topology.example.test/node" (labels-of)))))))

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
        (is (= gr8s.cri.v1::+mountpropagation-propagation_bidirectional+ (gr8s.kubelet::container-mount-propagation mount)))))
    (is (= gr8s.cri.v1::+mountpropagation-propagation_private+
           (gr8s.kubelet::container-mount-propagation (gr8s.resources::core-object))))))

;;; Driver registration and the publish lifecycle

(defmacro with-fake-csi-driver ((calls directory &key (stage t) (type "CSIPlugin") (versions ''("1.0.0"))) &body body)
  "Run BODY with a kubelet root in DIRECTORY and every CSI call answered by a recording driver."
  (let ((table (gensym "TABLE")))
    `(let* ((,calls nil)
            (gr8s.kubelet::*csi-kubelet-root* (namestring (uiop:ensure-directory-pathname (merge-pathnames "kubelet/" (truename ,directory)))))
            (gr8s.kubelet::*csi-plugins* (make-hash-table :test #'equal))
            (,table (merge-pathnames "csi-mountinfo" ,directory))
            (gr8s.kubelet::*pod-mount-table-path* ,table)
            (gr8s.kubelet::*csi-call*
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
      (is (null (gr8s.kubelet::csi-driver-registrations)))
      (gr8s.kubelet::scan-csi-plugin-registry)
      (is (null calls))
      ;; Driver manifests mount these as hostPath type Directory, as on a kubelet node.
      (dolist (name '("pods/" "plugins/" "plugins_registry/"))
        (let ((path (format nil "~A~A" gr8s.kubelet::*csi-kubelet-root* name)))
          (is-true (uiop:directory-exists-p path) "~A" name)
          (is (= #o750 (logand #o7777 (sb-posix:stat-mode (sb-posix:stat path)))))))
      (multiple-value-bind (path socket) (make-registry-socket gr8s.kubelet::*csi-kubelet-root* "csi.example.test-reg.sock")
        (unwind-protect
             (progn
               (gr8s.kubelet::scan-csi-plugin-registry)
               (is (equal '(:get-info :node-get-info :node-capabilities :notify) (csi-operations calls)))
               (is (eq t (gr8s.pluginregistration.v1::plugin-registered (third (first calls)))))
               (let ((registration (first (gr8s.kubelet::csi-driver-registrations))))
                 (is (equal "csi.example.test" (slot-value registration 'gr8s.node.v1::name)))
                 (is (equal "n1" (slot-value registration 'gr8s.node.v1::node-id)))
                 (is (= 8 (slot-value registration 'gr8s.node.v1::max-volumes))))
               (is-true (gr8s.kubelet::csi-plugin-stage-unstage-p (gr8s.kubelet::csi-plugin-for "csi.example.test")))
               ;; An unchanged socket isn't asked again.
               (let ((count (length calls)))
                 (gr8s.kubelet::scan-csi-plugin-registry)
                 (is (= count (length calls)))))
          (sb-bsd-sockets:socket-close socket))
        (delete-file path)
        (gr8s.kubelet::scan-csi-plugin-registry)
        (is (null (gr8s.kubelet::csi-driver-registrations)))
        (signals runtime-error (gr8s.kubelet::csi-plugin-for "csi.example.test"))))))

(test unusable-plugins-are-told-why-and-stay-unregistered
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (dolist (scenario '(("OtherPlugin" ("1.0.0")) ("CSIPlugin" ("0.3.0"))))
      (destructuring-bind (type versions) scenario
        (with-fake-csi-driver (calls directory :type type :versions versions)
          (multiple-value-bind (path socket)
              (make-registry-socket gr8s.kubelet::*csi-kubelet-root* (format nil "~A-reg.sock" (string-downcase type)))
            (unwind-protect
                 (let ((*error-output* (make-broadcast-stream)))
                   (gr8s.kubelet::scan-csi-plugin-registry)
                   (is (null (gr8s.kubelet::csi-driver-registrations)))
                   (is (eq :notify (first (first calls))))
                   (is (not (gr8s.pluginregistration.v1::plugin-registered (third (first calls))))))
              (sb-bsd-sockets:socket-close socket)
              (delete-file path))))))))

(test dra-drivers-register-through-the-kubelet-plugin-registry
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (let* ((calls nil)
           (gr8s.kubelet::*csi-kubelet-root*
             (namestring (uiop:ensure-directory-pathname
                          (merge-pathnames "kubelet/" (truename directory)))))
           (gr8s.kubelet::*csi-plugins* (make-hash-table :test #'equal))
           (gr8s.kubelet::*dra-plugins* (make-hash-table :test #'equal))
           (gr8s.kubelet::*csi-call*
             (lambda (socket operation request)
               (push (list operation socket request) calls)
               (ecase operation
                 (:get-info
                  (make-instance 'gr8s.pluginregistration.v1::plugin-info
                                 :type "DRAPlugin" :name "devices.example.com"
                                 :endpoint "/run/dra.sock"
                                 :supported-versions '("v1.DRAPlugin")))
                 (:notify
                  (make-instance 'gr8s.pluginregistration.v1::registration-status-response))))))
      (declare (special gr8s.kubelet::*dra-plugins*))
      (multiple-value-bind (path socket)
          (make-registry-socket gr8s.kubelet::*csi-kubelet-root* "devices.example.com-reg.sock")
        (unwind-protect
             (progn
               (gr8s.kubelet::scan-csi-plugin-registry)
               (let ((plugin (gethash "devices.example.com" gr8s.kubelet::*dra-plugins*)))
                 (is-true plugin)
                 (when plugin
                   (is (equal "/run/dra.sock" (gr8s.kubelet::dra-plugin-endpoint plugin)))))
               (is (eq t (gr8s.pluginregistration.v1::plugin-registered
                          (third (first calls)))))
               (is (null (gr8s.kubelet::csi-driver-registrations))))
          (sb-bsd-sockets:socket-close socket)
          (delete-file path))))))

(test dra-prepares-allocated-claims-and-exposes-cdi-devices-to-the-container
  (with-temporary-store (store directory)
    (let* ((pod
             (parse-pod
              "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"consumer\",\"namespace\":\"default\",\"uid\":\"pod-uid\"},\"spec\":{\"nodeName\":\"worker-a\",\"resourceClaims\":[{\"name\":\"device\",\"resourceClaimName\":\"claim\"}],\"containers\":[{\"name\":\"app\",\"image\":\"busybox\",\"resources\":{\"claims\":[{\"name\":\"device\",\"request\":\"gpu\"}]}}]}}"))
           (second-pod
             (parse-pod
              "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"consumer-two\",\"namespace\":\"default\",\"uid\":\"pod-uid-2\"},\"spec\":{\"nodeName\":\"worker-a\",\"resourceClaims\":[{\"name\":\"device\",\"resourceClaimName\":\"claim\"}],\"containers\":[{\"name\":\"app\",\"image\":\"busybox\",\"resources\":{\"claims\":[{\"name\":\"device\",\"request\":\"gpu\"}]}}]}}"))
           (claim
             (gr8s.resources::core-object
              "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
              "metadata" (gr8s.resources::core-object "name" "claim" "namespace" "default"
                                               "uid" "claim-uid")
              "spec" (gr8s.resources::core-object "devices" (gr8s.resources::core-object))))
           (manager (gr8s.kubelet::make-dra-manager store directory))
           (calls nil)
           (gr8s.kubelet::*dra-plugins* (make-hash-table :test #'equal))
           (gr8s.kubelet::*dra-call*
             (lambda (plugin operation request)
               (push (list operation plugin request) calls)
               (ecase operation
                 (:prepare
                  (let ((uid (gr8s.dra.v1::uid
                              (first (gr8s.dra.v1::claims request)))))
                    (make-instance
                     'gr8s.dra.v1::node-prepare-resources-response
                     :claims
                     (list
                      (cons uid
                            (make-instance
                             'gr8s.dra.v1::node-prepare-resource-response
                             :devices
                             (list (make-instance 'gr8s.dra.v1::device
                                                  :request-names '("gpu")
                                                  :pool-name "pool" :device-name "gpu-0"
                                                  :cdi-device-ids '("vendor.example/gpu=0")))))))))
                 (:unprepare
                  (let ((uid (gr8s.dra.v1::uid
                              (first (gr8s.dra.v1::claims request)))))
                    (make-instance
                     'gr8s.dra.v1::node-unprepare-resources-response
                     :claims
                     (list (cons uid
                                 (make-instance
                                  'gr8s.dra.v1::node-unprepare-resource-response))))))))))
      (declare (special gr8s.kubelet::*dra-plugins* gr8s.kubelet::*dra-call*))
      (gr8s.resources::create-core-resource store "resourceclaims" claim "default")
      (let ((gr8s.resources::*typed-api-status-write* t))
        (gr8s.resources::update-core-resource
         store "resourceclaims" "default" "claim"
         (lambda (object)
           (setf (gethash "status" object)
                 (gr8s.resources::core-object
                  "allocation"
                  (gr8s.resources::core-object
                   "devices"
                   (gr8s.resources::core-object
                    "results"
                    (vector (gr8s.resources::core-object "request" "gpu"
                                                "driver" "devices.example.com"
                                                "pool" "pool" "device" "gpu-0"))))
                  "reservedFor"
                  (vector (gr8s.resources::core-object "resource" "pods" "name" "consumer"
                                              "uid" "pod-uid")
                          (gr8s.resources::core-object "resource" "pods" "name" "consumer-two"
                                              "uid" "pod-uid-2"))))
           object)))
      (setf (gethash "devices.example.com" gr8s.kubelet::*dra-plugins*)
            (gr8s.kubelet::make-dra-plugin :name "devices.example.com" :endpoint "/run/dra.sock"))
      (gr8s.kubelet::prepare-pod-dynamic-resources manager pod)
      (gr8s.kubelet::prepare-pod-dynamic-resources manager second-pod)
      (is (equal '(:prepare) (reverse (mapcar #'first calls))))
      (setf manager (gr8s.kubelet::make-dra-manager store directory))
      (let* ((request (third (first calls)))
             (requested-claim (first (gr8s.dra.v1::claims request))))
        (is (equal "default" (gr8s.dra.v1::namespace requested-claim)))
        (is (equal "claim" (gr8s.dra.v1::name requested-claim)))
        (is (equal (gethash "uid"
                            (gethash "metadata"
                                     (gr8s.resources::get-core-resource store "resourceclaims"
                                                              "default" "claim")))
                   (gr8s.dra.v1::uid requested-claim))))
      (let ((container (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0)))
        (is (equal '("vendor.example/gpu=0")
                   (gr8s.kubelet::container-dra-cdi-device-ids manager pod container)))
        (gr8s.kubelet::unprepare-pod-dynamic-resources manager pod)
        (is (equal '(:prepare) (reverse (mapcar #'first calls))))
        (is (equal '("vendor.example/gpu=0")
                   (gr8s.kubelet::container-dra-cdi-device-ids manager second-pod container)))
        (gr8s.kubelet::unprepare-pod-dynamic-resources manager second-pod)
        (is (equal '(:prepare :unprepare) (reverse (mapcar #'first calls))))
        (signals runtime-error
          (gr8s.kubelet::container-dra-cdi-device-ids manager pod container))))))

(test upstream-dra-driver-registers-publishes-prepares-and-unprepares
  (let ((driver (uiop:getenv "GR8S_TEST_DRA_DRIVER")))
    (if (or (null driver) (not (probe-file driver)))
        (skip "Set GR8S_TEST_DRA_DRIVER to Kubernetes' dra-test-driver binary")
        (with-temporary-store (store directory)
          (let* ((root (uiop:ensure-directory-pathname directory))
                 (gr8s.kubelet::*csi-kubelet-root*
                   (namestring (uiop:ensure-directory-pathname
                                (merge-pathnames "kubelet/" root))))
                 (gr8s.kubelet::*dra-plugins* (make-hash-table :test #'equal))
                 (kubeconfig (merge-pathnames "kubeconfig" root))
                 (log (merge-pathnames "dra-driver.log" root))
                 (server (start-server :address "127.0.0.1" :port 0 :store store
                                       :runtime (make-fake-runtime)))
                 (process nil)
                 (ready nil))
            (declare (special gr8s.kubelet::*dra-plugins*))
            (unwind-protect
                 (progn
                   (let ((node (make-test-node "worker-a" "node-a" "10.64.0.0/20")))
                     (gr8s.controllers::register-node store node)
                     (gr8s.controllers::mark-node-ready store "worker-a" 100))
                   (with-open-file (out kubeconfig :direction :output
                                                   :if-exists :supersede
                                                   :if-does-not-exist :create)
                     (format out
                             "apiVersion: v1~%kind: Config~%clusters:~%- name: gr8s~%  cluster: {server: ~S}~%contexts:~%- name: gr8s~%  context: {cluster: gr8s, user: gr8s}~%current-context: gr8s~%users:~%- name: gr8s~%  user: {}~%"
                             (format nil "http://127.0.0.1:~D"
                                     (hunchentoot:acceptor-port server))))
                   (gr8s.kubelet::ensure-csi-kubelet-directories)
                   (ensure-directories-exist
                    (uiop:ensure-directory-pathname
                     (gr8s.kubelet::csi-kubelet-path
                      "plugins/test-driver.cdi.k8s.io")))
                   (setf process
                         (uiop:launch-program
                          (list driver "--kubeconfig" (namestring kubeconfig)
                                "--drivername" "test-driver.cdi.k8s.io"
                                "kubelet-plugin" "--node-name" "worker-a"
                                "--num-devices" "1"
                                "--plugin-registration-path"
                                (gr8s.kubelet::csi-kubelet-path "plugins_registry")
                                "--datadir" (gr8s.kubelet::csi-kubelet-path "plugins")
                                "--cdi-dir" (namestring (merge-pathnames "cdi/" root)))
                          :output (namestring log) :error-output :output))
                   (setf ready
                         (wait-until
                          (lambda ()
                            (gr8s.kubelet::scan-csi-plugin-registry)
                            (and (gethash "test-driver.cdi.k8s.io" gr8s.kubelet::*dra-plugins*)
                                 (plusp (length
                                         (gr8s.resources::list-core-resources
                                          store "resourceslices" nil)))))
                          :timeout 30))
                   (is-true ready "External DRA driver did not become ready:~%~A"
                            (if (probe-file log)
                                (uiop:read-file-string log)
                                "driver produced no log"))
                   (when ready
                     (gr8s.resources::create-core-resource
                    store "deviceclasses"
                    (gr8s.resources::core-object
                     "apiVersion" "resource.k8s.io/v1" "kind" "DeviceClass"
                     "metadata" (gr8s.resources::core-object "name" "external")
                     "spec" (gr8s.resources::core-object "selectors" #()))
                    nil)
                   (gr8s.resources::create-core-resource
                    store "resourceclaims"
                    (gr8s.resources::core-object
                     "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
                     "metadata" (gr8s.resources::core-object "name" "external")
                     "spec" (gr8s.resources::core-object
                             "devices"
                             (gr8s.resources::core-object
                              "requests"
                              (vector
                               (gr8s.resources::core-object
                                "name" "device"
                                "exactly"
                                (gr8s.resources::core-object
                                 "deviceClassName" "external"
                                 "allocationMode" "ExactCount" "count" 1))))))
                    "default")
                   (let* ((pod
                            (create-pod
                             store
                             (parse-pod
                              (gr8s.resources::core-object
                               "apiVersion" "v1" "kind" "Pod"
                               "metadata" (gr8s.resources::core-object
                                           "name" "external" "namespace" "default")
                               "spec" (gr8s.resources::core-object
                                       "resourceClaims"
                                       (vector (gr8s.resources::core-object
                                                "name" "device"
                                                "resourceClaimName" "external"))
                                       "containers"
                                       (vector (gr8s.resources::core-object
                                                "name" "app" "image" "busybox"
                                                "resources"
                                                (gr8s.resources::core-object
                                                 "claims"
                                                 (vector (gr8s.resources::core-object
                                                          "name" "device"))))))))))
                          (node (gr8s.controllers::schedule-pod store pod))
                          (manager (gr8s.kubelet::make-dra-manager
                                    store (merge-pathnames "dra-state/" root)))
                          (claim-object
                            (gr8s.resources::get-core-resource
                             store "resourceclaims" "default" "external"))
                          (expected-cdi
                            (format nil
                                    "test-driver.cdi.k8s.io/test=claim-~A-device"
                                    (gethash "uid" (gethash "metadata" claim-object))))
                          (container (aref (gethash "containers"
                                                    (gethash "spec" (pod-to-object pod)))
                                           0)))
                     (is (equal "worker-a" (and node (gr8s.model::node-record-name node))))
                     (gr8s.kubelet::prepare-pod-dynamic-resources manager pod)
                     (is (equal (list expected-cdi)
                                (gr8s.kubelet::container-dra-cdi-device-ids
                                 manager pod container)))
                     (is-true (gr8s.kubelet::unprepare-pod-dynamic-resources manager pod)))))
              (when process
                (ignore-errors (uiop:terminate-process process))
                (ignore-errors (uiop:wait-process process)))
              (ignore-errors (gr8s.apiserver::stop-server server))))))))

(test dra-claims-are-projected-only-to-their-reserved-pod
  (with-temporary-store (store directory)
    (let* ((claim
             (gr8s.resources::create-core-resource
              store "resourceclaims"
              (gr8s.resources::core-object
               "apiVersion" "resource.k8s.io/v1" "kind" "ResourceClaim"
               "metadata" (gr8s.resources::core-object "name" "claim" "namespace" "default")
               "spec" (gr8s.resources::core-object "devices" (gr8s.resources::core-object)))
              "default"))
           (pod
             (create-pod
              store
              (parse-pod
               "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"consumer\",\"namespace\":\"default\"},\"spec\":{\"nodeName\":\"worker-a\",\"resourceClaims\":[{\"name\":\"device\",\"resourceClaimName\":\"claim\"}],\"containers\":[{\"name\":\"app\",\"image\":\"busybox\",\"resources\":{\"claims\":[{\"name\":\"device\",\"request\":\"gpu\"}]}}]}}")))
           (agent-store (open-store (merge-pathnames "agent/" directory))))
      (let ((gr8s.resources::*typed-api-status-write* t))
        (gr8s.resources::update-core-resource
         store "resourceclaims" "default" "claim"
         (lambda (object)
           (setf (gethash "status" object)
                 (gr8s.resources::core-object
                  "allocation" (gr8s.resources::core-object "devices" (gr8s.resources::core-object "results" #()))
                  "reservedFor"
                  (vector (gr8s.resources::core-object "resource" "pods" "name" (pod-name pod)
                                              "uid" (pod-uid pod)))))
           object)))
      (let* ((assignment (gr8s.controllers::pod-assignment pod store))
             (objects
               (mapcar (lambda (bytes)
                         (com.inuoe.jzon:parse
                          (trivial-utf-8:utf-8-bytes-to-string bytes)))
                       (slot-value assignment 'gr8s.node.v1::resource-objects-json))))
        (is (= 1 (count "ResourceClaim" objects :test #'equal
                        :key (lambda (object) (gethash "kind" object)))))
        (gr8s.kubelet::install-assigned-resource-objects agent-store (list assignment))
        (is (equal (gethash "uid" (gethash "metadata" claim))
                   (gethash "uid"
                            (gethash "metadata"
                                     (gr8s.resources::get-core-resource agent-store "resourceclaims"
                                                              "default" "claim")))))
        (let ((projected (find "ResourceClaim" objects :test #'equal
                               :key (lambda (object) (gethash "kind" object)))))
          (setf (gethash "uid"
                         (aref (gethash "reservedFor" (gethash "status" projected)) 0))
                "another-pod")
          (setf (slot-value assignment 'gr8s.node.v1::resource-objects-json)
                (list (trivial-utf-8:string-to-utf-8-bytes
                       (com.inuoe.jzon:stringify projected))))
          (signals kubernetes-error
            (gr8s.kubelet::assignment-resource-objects assignment)))))))

(test containerd-node-runtime-wires-the-dra-lifecycle
  (with-temporary-store (unused directory)
    (declare (ignore unused))
    (let* ((backend (gr8s.runtime.containerd::make-containerd-runtime
                     :socket-path (namestring (merge-pathnames "unused.sock" directory))
                     :log-root (merge-pathnames "logs/" directory)))
           (node (gr8s.agent::make-node-runtime (merge-pathnames "agent/" directory) backend nil))
           (pod (parse-pod
                 "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"plain\",\"namespace\":\"default\",\"uid\":\"plain-uid\"},\"spec\":{\"containers\":[{\"name\":\"app\",\"image\":\"busybox\"}]}}"))
           (container (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0)))
      (is (typep (gr8s.agent::node-runtime-dynamic-resource-manager node)
                 'gr8s.kubelet::dra-manager))
      (is-true (gr8s.runtime::runtime-prepare-pod-resources backend pod))
      (is-false (gr8s.runtime::runtime-container-cdi-device-ids backend pod container))
      (is-true (gr8s.runtime::runtime-unprepare-pod-resources backend pod)))))

(defun csi-register-fake ()
  (bt:with-lock-held (gr8s.kubelet::*csi-plugins-lock*)
    (setf (gethash "csi.example.test" gr8s.kubelet::*csi-plugins*)
          (gr8s.kubelet::make-csi-plugin :name "csi.example.test" :endpoint "/run/csi.sock" :stage-unstage-p t))))

(defun csi-test-pod (name uid)
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"~A\",\"namespace\":\"default\",\"uid\":\"~A\"},\"spec\":{\"nodeName\":\"worker-a\",\"containers\":[{\"name\":\"c\",\"image\":\"busybox\"}]}}" name uid)))

(defun bound-csi-volume (&key (modes #("ReadWriteMany")))
  (gr8s.resources::core-object
   "metadata" (gr8s.resources::core-object "name" "pv")
   "spec" (gr8s.resources::core-object "accessModes" modes "mountOptions" #("noatime")
                             "csi" (gr8s.resources::core-object "driver" "csi.example.test" "volumeHandle" "disk-1" "fsType" "ext4"
                                                      "volumeAttributes" (gr8s.resources::core-object "tier" "gold")))))

(test publishing-waits-for-attachment-then-stages-and-publishes
  (with-temporary-store (store directory)
    (with-fake-csi-driver (calls directory)
      (csi-register-fake)
      (let ((pod (csi-test-pod "first" "uid-1")) (volume (bound-csi-volume)))
        ;; No CSIDriver object means an attachment is required, as in Kubernetes.
        (signals runtime-error (gr8s.kubelet::materialize-persistent-csi-volume store pod "data" volume))
        (is (null calls))
        (let ((name (gr8s.resources::volume-attachment-name "csi.example.test" "disk-1" "worker-a")))
          (gr8s.resources::create-core-resource
           store "volumeattachments"
           (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" name)
                              "spec" (gr8s.resources::core-object "attacher" "csi.example.test" "nodeName" "worker-a"
                                                        "source" (gr8s.resources::core-object "persistentVolumeName" "pv")))
           nil)
          (signals runtime-error (gr8s.kubelet::materialize-persistent-csi-volume store pod "data" volume))
          (let ((gr8s.resources::*storage-status-write* t))
            (gr8s.resources::update-core-resource
             store "volumeattachments" nil name
             (lambda (old)
               (let ((copy (gr8s.resources::copy-core-object old)))
                 (setf (gethash "status" copy)
                       (gr8s.resources::core-object "attached" t "attachmentMetadata" (gr8s.resources::core-object "lun" "3")))
                 copy)))))
        (let ((path (gr8s.kubelet::materialize-persistent-csi-volume store pod "data" volume)))
          (is (equal '(:stage :publish) (csi-operations calls)))
          (let* ((stage (third (second calls))) (publish (third (first calls)))
                 (capability (gr8s.csi.v1::volume-capability publish)))
            (is (equal "disk-1" (gr8s.csi.v1::volume-id publish)))
            (is (equal (gr8s.csi.v1::staging-target-path stage) (gr8s.csi.v1::staging-target-path publish)))
            (is (uiop:string-suffix-p (gr8s.csi.v1::staging-target-path publish) "/globalmount"))
            (is (equal (format nil "~Apods/uid-1/volumes/kubernetes.io~~csi/data/mount" gr8s.kubelet::*csi-kubelet-root*)
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
      (setf (gethash "csi.example.test" gr8s.kubelet::*csi-plugins*)
            (gr8s.kubelet::make-csi-plugin :name "csi.example.test" :endpoint "/run/csi.sock" :stage-unstage-p nil))
      (gr8s.resources::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test" :attach-required nil) nil)
      (gr8s.kubelet::materialize-persistent-csi-volume store (csi-test-pod "first" "uid-1") "data" (bound-csi-volume))
      (is (equal '(:publish) (csi-operations calls))))))

(test the-last-pod-using-a-volume-unstages-it
  (with-temporary-store (store directory)
    (with-fake-csi-driver (calls directory)
      (csi-register-fake)
      (gr8s.resources::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test" :attach-required nil) nil)
      (dolist (entry '(("first" "uid-1") ("second" "uid-2")))
        (gr8s.kubelet::materialize-persistent-csi-volume store (apply #'csi-test-pod entry) "data" (bound-csi-volume)))
      (setf calls nil)
      (gr8s.kubelet::cleanup-pod-csi-volumes "uid-1")
      (is (equal '(:unpublish) (csi-operations calls)))
      (is (equal (format nil "~Apods/uid-1/volumes/kubernetes.io~~csi/data/mount" gr8s.kubelet::*csi-kubelet-root*)
                 (gr8s.csi.v1::target-path (third (first calls)))))
      (is (null (probe-file (format nil "~Apods/uid-1/" gr8s.kubelet::*csi-kubelet-root*))))
      (setf calls nil)
      (gr8s.kubelet::cleanup-pod-csi-volumes "uid-2")
      (is (equal '(:unpublish :unstage) (csi-operations calls)))
      ;; Nothing is left to do on a second pass.
      (setf calls nil)
      (gr8s.kubelet::cleanup-pod-csi-volumes "uid-2")
      (is (null calls)))))

(test a-failed-unpublish-leaves-the-record-so-deletion-retries
  (with-temporary-store (store directory)
    (with-fake-csi-driver (calls directory)
      (csi-register-fake)
      (gr8s.resources::create-core-resource store "csidrivers" (csi-test-driver-object "csi.example.test" :attach-required nil) nil)
      (gr8s.kubelet::materialize-persistent-csi-volume store (csi-test-pod "first" "uid-1") "data" (bound-csi-volume))
      ;; The driver is unavailable, so the volume can't be declared gone.
      (clrhash gr8s.kubelet::*csi-plugins*)
      (signals runtime-error (gr8s.kubelet::cleanup-pod-csi-volumes "uid-1"))
      (is (= 1 (length (gr8s.kubelet::csi-volume-records))))
      (csi-register-fake)
      (gr8s.kubelet::cleanup-pod-csi-volumes "uid-1")
      (is (zerop (length (gr8s.kubelet::csi-volume-records)))))))

(test inline-volumes-require-a-driver-that-allows-them
  (with-temporary-store (store directory)
    (with-fake-csi-driver (calls directory)
      (csi-register-fake)
      (let* ((pod (csi-test-pod "first" "uid-1"))
             (volume (gr8s.resources::core-object "name" "secrets"
                                        "csi" (gr8s.resources::core-object "driver" "csi.example.test" "readOnly" t
                                                                 "volumeAttributes" (gr8s.resources::core-object "a" "b")))))
        (signals runtime-error (gr8s.kubelet::materialize-inline-csi-volume store pod volume))
        (gr8s.resources::create-core-resource store "csidrivers"
                                    (csi-test-driver-object "csi.example.test" :modes #("Persistent")) nil)
        (signals runtime-error (gr8s.kubelet::materialize-inline-csi-volume store pod volume)))
      (is (null calls)))
    (with-temporary-store (store second)
      (with-fake-csi-driver (calls second)
        (setf (gethash "csi.example.test" gr8s.kubelet::*csi-plugins*)
              (gr8s.kubelet::make-csi-plugin :name "csi.example.test" :endpoint "/run/csi.sock" :stage-unstage-p t))
        (gr8s.resources::create-core-resource store "csidrivers"
                                    (csi-test-driver-object "csi.example.test" :modes #("Ephemeral")) nil)
        (multiple-value-bind (path readonly)
            (gr8s.kubelet::materialize-inline-csi-volume
             store (csi-test-pod "first" "uid-1")
             (gr8s.resources::core-object "name" "secrets"
                                "csi" (gr8s.resources::core-object "driver" "csi.example.test" "readOnly" t)))
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
