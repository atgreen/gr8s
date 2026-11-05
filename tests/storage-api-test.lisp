;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify real reservations, capacity/mode admission and Retain protection;
;;;; native filesystem tests separately prove the CRI paths contain actual data.

(in-package #:gr8s/tests)
(def-suite storage-apis :in gr8s)
(in-suite storage-apis)

(defun storage-test-volume (name path &key (capacity "2Gi") (class "") (modes #("ReadWriteOnce")))
  "Build a static hostPath PV whose directory is explicitly managed by its owner."
  (gr8s::core-object "apiVersion" "v1" "kind" "PersistentVolume" "metadata" (gr8s::core-object "name" name)
                     "spec" (gr8s::core-object "capacity" (gr8s::core-object "storage" capacity)
                                               "accessModes" modes "storageClassName" class
                                               "persistentVolumeReclaimPolicy" "Retain"
                                               "hostPath" (gr8s::core-object "path" (namestring path) "type" "DirectoryOrCreate"))))

(defun storage-test-claim (name &key (capacity "1Gi") (class "") (modes #("ReadWriteOnce")))
  "Build a filesystem PVC with explicit opt-out from default StorageClass assignment."
  (gr8s::core-object "apiVersion" "v1" "kind" "PersistentVolumeClaim" "metadata" (gr8s::core-object "name" name)
                     "spec" (gr8s::core-object "resources" (gr8s::core-object "requests" (gr8s::core-object "storage" capacity))
                                               "accessModes" modes "storageClassName" class)))

(defun storage-test-pod (name claim &optional node)
  "Create a runtime-valid Pod referencing exactly one claim."
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*)) (spec (gethash "spec" object))
         (container (aref (gethash "containers" spec) 0)))
    (setf (gethash "name" (gethash "metadata" object)) name
          (gethash "volumes" spec) (vector (gr8s::core-object "name" "data" "persistentVolumeClaim" (gr8s::core-object "claimName" claim)))
          (gethash "volumeMounts" container) (vector (gr8s::core-object "name" "data" "mountPath" "/data")))
    (when node (setf (gethash "nodeName" spec) node))
    (parse-pod object)))

(defun storage-phase (store resource namespace name)
  "Read the server's actual persisted storage phase."
  (gethash "phase" (gethash "status" (gr8s::get-core-resource store resource namespace name))))

(test storage-quantities-compare-exactly-and-invalid-capacities-fail
  (is (= 1073741824 (gr8s::storage-quantity "1Gi" "test")))
  (is (= 1500000000 (gr8s::storage-quantity "1.5G" "test")))
  (is (= 1/1000 (gr8s::storage-quantity "1m" "test")))
  (is (= 1000 (gr8s::storage-quantity "1e3" "test")))
  (dolist (bad '("0" "-1Gi" "1Bad" "1e99999" "NaN" "1.2.3" nil))
    (signals kubernetes-error (gr8s::storage-quantity bad "test"))))

(test static-volume-binding-is-two-sided-exclusive-and-survives-restart
  (with-temporary-store (store path)
    (gr8s::create-core-resource store "persistentvolumes" (storage-test-volume "large" (merge-pathnames "large/" path) :capacity "4Gi") nil)
    (gr8s::create-core-resource store "persistentvolumes" (storage-test-volume "small" (merge-pathnames "small/" path)) nil)
    (let* ((claim (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "first") "default"))
           (uid (gethash "uid" (gethash "metadata" claim))))
      (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" "first")))
      (is-true (gr8s::reconcile-storage-bindings store))
      (let* ((loaded (open-store path))
             (bound (gr8s::get-core-resource loaded "persistentvolumeclaims" "default" "first"))
             (volume (gr8s::get-core-resource loaded "persistentvolumes" nil "small")))
        (is (equal "small" (gethash "volumeName" (gethash "spec" bound))))
        (is (equal "Bound" (storage-phase loaded "persistentvolumeclaims" "default" "first")))
        (is (equal uid (gethash "uid" (gethash "claimRef" (gethash "spec" volume)))))
        (is (equal "2Gi" (gethash "storage" (gethash "capacity" (gethash "status" bound)))))))
    (let ((revision (gr8s::pod-store-resource-revision store)))
      (is-false (gr8s::reconcile-storage-bindings store))
      (is (= revision (gr8s::pod-store-resource-revision store))))
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "second") "default")
    (gr8s::reconcile-storage-bindings store)
    (is (equal "large" (gethash "volumeName" (gethash "spec" (gr8s::get-core-resource store "persistentvolumeclaims" "default" "second")))))))

(test capacity-class-and-access-modes-cannot-be-invented-by-the-binder
  (with-temporary-store (store path)
    (gr8s::create-core-resource store "persistentvolumes" (storage-test-volume "provided" (merge-pathnames "provided/" path)) nil)
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "too-large" :capacity "3Gi") "default")
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "wrong-class" :class "other") "default")
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "wrong-mode" :modes #("ReadWriteMany")) "default")
    (gr8s::reconcile-storage-bindings store)
    (dolist (name '("too-large" "wrong-class" "wrong-mode"))
      (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" name))))
    (is (equal "Available" (storage-phase store "persistentvolumes" nil "provided"))))
  (with-temporary-store (store path)
    (let ((volume (storage-test-volume "missing" (merge-pathnames "missing/" path))))
      (remhash "hostPath" (gethash "spec" volume))
      (setf (gethash "csi" (gethash "spec" volume)) (gr8s::core-object "driver" "example.test" "volumeHandle" "provided-by-admin"))
      (gr8s::create-core-resource store "persistentvolumes" volume nil))
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "waiting") "default")
    (gr8s::reconcile-storage-bindings store)
    (is (equal "Bound" (storage-phase store "persistentvolumeclaims" "default" "waiting")))))

(test storage-protection-preserves-in-use-claims-and-retained-data
  (with-temporary-store (store path)
    (let ((backing (merge-pathnames "provided/" path)))
      (ensure-directories-exist backing)
      (with-open-file (stream (merge-pathnames "keep" backing) :direction :output) (write-string "retained" stream))
      (gr8s::create-core-resource store "persistentvolumes" (storage-test-volume "provided" backing) nil)
      (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
      (gr8s::reconcile-storage-bindings store)
      (create-pod store (storage-test-pod "consumer" "claim"))
      (gr8s::delete-core-resource store "persistentvolumeclaims" "default" "claim")
      (is-true (gethash "deletionTimestamp" (gethash "metadata" (gr8s::get-core-resource store "persistentvolumeclaims" "default" "claim"))))
      (gr8s::reconcile-storage-bindings store)
      (is (equal "Bound" (storage-phase store "persistentvolumes" nil "provided")))
      (gr8s::remove-pod store "default" "consumer")
      (gr8s::reconcile-storage-bindings store)
      (signals kubernetes-error (gr8s::get-core-resource store "persistentvolumeclaims" "default" "claim"))
      (is (equal "Released" (storage-phase store "persistentvolumes" nil "provided")))
      (is (equal "retained" (uiop:read-file-string (merge-pathnames "keep" backing))))
      (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
      (gr8s::reconcile-storage-bindings store)
      (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" "claim"))))))

(test delayed-binding-follows-real-consumer-node-and-volume-affinity
  (with-temporary-store (store path)
    (let ((class (gr8s::core-object "metadata" (gr8s::core-object "name" "local") "provisioner" "kubernetes.io/no-provisioner"
                                   "volumeBindingMode" "WaitForFirstConsumer"))
          (volume (storage-test-volume "local-pv" (merge-pathnames "local/" path) :class "local")))
      (gr8s::create-core-resource store "storageclasses" class nil)
      (setf (gethash "nodeAffinity" (gethash "spec" volume))
            (gr8s::core-object "required" (gr8s::core-object "nodeSelectorTerms"
              (vector (gr8s::core-object "matchExpressions" (vector (gr8s::core-object "key" "kubernetes.io/hostname" "operator" "In" "values" #("worker-b"))))))))
      (gr8s::create-core-resource store "persistentvolumes" volume nil)
      (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim" :class "local") "default")
      (gr8s::reconcile-storage-bindings store)
      (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" "claim")))
      (dolist (entry '(("worker-a" "a" "10.64.0.0/20") ("worker-b" "b" "10.64.16.0/20")))
        (let ((node (apply #'make-test-node entry)))
          (gr8s:register-node store node) (gr8s:mark-node-ready store (first entry) 1)))
      (let* ((pod (create-pod store (storage-test-pod "consumer" "claim")))
             (node (gr8s:schedule-pod store pod)))
        (is (equal "worker-b" (gr8s:node-record-name node)))
        (gr8s::reconcile-storage-bindings store)
        (is (equal "Bound" (storage-phase store "persistentvolumeclaims" "default" "claim")))))))

(test pv-status-input-cannot-fabricate-binding-and-source-updates-are-immutable
  (with-temporary-store (store path)
    (let ((volume (storage-test-volume "provided" (merge-pathnames "provided/" path))))
      (setf (gethash "status" volume) (gr8s::core-object "phase" "Bound"))
      (gr8s::create-core-resource store "persistentvolumes" volume nil))
    (is (equal "Pending" (storage-phase store "persistentvolumes" nil "provided")))
    (signals kubernetes-error
      (gr8s::update-core-resource store "persistentvolumes" nil "provided"
        (lambda (object) (setf (gethash "path" (gethash "hostPath" (gethash "spec" object))) "/another-path") object)))))


(test assigned-pvc-mounts-use-real-retained-data-and-verified-uid-reservations
  (with-temporary-store (store path)
    (let* ((backing (merge-pathnames "backing/" path))
           (agent-store (open-store (merge-pathnames "agent/" path)))
           (runtime (gr8s::make-containerd-runtime :log-root (merge-pathnames "pod-logs/" path))))
      (ensure-directories-exist backing)
      (with-open-file (stream (merge-pathnames "original" backing) :direction :output) (write-string "real storage" stream))
      (gr8s::create-core-resource store "persistentvolumes" (storage-test-volume "provided" backing) nil)
      (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
      (gr8s::reconcile-storage-bindings store)
      (let* ((pod (create-pod store (storage-test-pod "consumer" "claim")))
             (assignment (gr8s::pod-assignment pod store)))
        (is (= 2 (length (slot-value assignment 'gr8s.node.v1::resource-objects-json))))
        (gr8s::install-assigned-resource-objects agent-store (list assignment))
        (setf (gr8s::containerd-runtime-resource-store runtime) agent-store)
        (let* ((mount (first (gr8s::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0))))
               (source (pathname (gr8s.cri.v1::host-path mount))))
          (is (equal (truename backing) (truename source)))
          (is (equal "real storage" (uiop:read-file-string (merge-pathnames "original" (uiop:ensure-directory-pathname source)))))
          (is-false (gr8s.cri.v1::readonly mount)))
        (let ((volume (gr8s::get-core-resource store "persistentvolumes" nil "provided")))
          (setf (gethash "uid" (gethash "claimRef" (gethash "spec" volume))) "another-claim")
          (let* ((claim (gr8s::get-core-resource store "persistentvolumeclaims" "default" "claim"))
                 (objects (list claim volume)))
            (setf (slot-value assignment 'gr8s.node.v1::resource-objects-json)
                  (mapcar (lambda (object) (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify object))) objects)))
          (signals kubernetes-error (gr8s::assignment-resource-objects assignment)))
        (is (equal "real storage" (uiop:read-file-string (merge-pathnames "original" backing))))))))

(test real-hostpath-type-checks-fail-before-cri-and-create-only-explicit-types
  (with-temporary-store (store path)
    (values store)
    (let ((directory (merge-pathnames "created/" path)) (file (merge-pathnames "created/file" path)))
      (gr8s::materialize-host-storage-source (gr8s::core-object "path" (namestring directory) "type" "DirectoryOrCreate"))
      (is-true (uiop:directory-exists-p directory))
      (gr8s::materialize-host-storage-source (gr8s::core-object "path" (namestring file) "type" "FileOrCreate"))
      (is-true (probe-file file))
      (signals gr8s::runtime-error (gr8s::materialize-host-storage-source (gr8s::core-object "path" (namestring directory) "type" "File")))
      (signals gr8s::runtime-error (gr8s::materialize-host-storage-source (gr8s::core-object "path" (namestring file) "type" "Directory")))
      (signals gr8s::runtime-error (gr8s::materialize-host-storage-source (gr8s::core-object "path" (namestring (merge-pathnames "absent/" path)) "type" "Directory"))))))

(test retroactive-default-class-respects-explicit-opt-out
  (with-temporary-store (store path)
    (let ((claim (storage-test-claim "implicit")))
      (remhash "storageClassName" (gethash "spec" claim))
      (gr8s::create-core-resource store "persistentvolumeclaims" claim "default"))
    (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "opt-out") "default")
    (gr8s::create-core-resource store "storageclasses"
      (gr8s::core-object "metadata" (gr8s::core-object "name" "default-class" "annotations"
                           (gr8s::core-object "storageclass.kubernetes.io/is-default-class" "true"))
                        "provisioner" "kubernetes.io/no-provisioner") nil)
    (gr8s::create-core-resource store "persistentvolumes"
      (storage-test-volume "provided" (merge-pathnames "provided/" path) :class "default-class") nil)
    (gr8s::reconcile-storage-bindings store)
    (let ((claim (gr8s::get-core-resource store "persistentvolumeclaims" "default" "implicit")))
      (is (equal "default-class" (gethash "storageClassName" (gethash "spec" claim))))
      (is (equal "Bound" (gethash "phase" (gethash "status" claim)))))
    (is (equal "" (gethash "storageClassName" (gethash "spec" (gr8s::get-core-resource store "persistentvolumeclaims" "default" "opt-out")))))
    (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" "opt-out")))))

(test unsupported-prebound-source-reserves-exact-uid-without-fabricating-a-mount
  (with-temporary-store (store path)
    (let* ((claim (storage-test-claim "claim"))
           (volume (storage-test-volume "unsupported" (merge-pathnames "unused/" path))))
      (setf (gethash "volumeName" (gethash "spec" claim)) "unsupported")
      (setf claim (gr8s::create-core-resource store "persistentvolumeclaims" claim "default"))
      (remhash "hostPath" (gethash "spec" volume))
      (setf (gethash "csi" (gethash "spec" volume)) (gr8s::core-object "driver" "example.test" "volumeHandle" "admin-volume")
            (gethash "claimRef" (gethash "spec" volume))
            (gr8s::core-object "name" "claim" "namespace" "default" "uid" (gethash "uid" (gethash "metadata" claim))))
      (gr8s::create-core-resource store "persistentvolumes" volume nil)
      (gr8s::reconcile-storage-bindings store)
      (is (equal "Bound" (storage-phase store "persistentvolumeclaims" "default" "claim")))
      (is (equal "Bound" (storage-phase store "persistentvolumes" nil "unsupported")))
      (let* ((bound (gr8s::get-core-resource store "persistentvolumes" nil "unsupported"))
             (runtime (gr8s::make-containerd-runtime :log-root (merge-pathnames "pod-logs/" path))))
        (is (equal (gethash "uid" (gethash "metadata" claim)) (gethash "uid" (gethash "claimRef" (gethash "spec" bound)))))
        (setf (gr8s::containerd-runtime-resource-store runtime) store)
        (signals gr8s::runtime-error
          (gr8s::materialize-persistent-claim-volume runtime (storage-test-pod "consumer" "claim")
             (gr8s::core-object "claimName" "claim")))))))

(test empty-storage-topology-term-matches-no-nodes
  (let ((node (make-test-node "worker-a" "a" "10.64.0.0/20")))
    (is-false (gr8s::storage-class-topology-matches-p
                (gr8s::core-object "allowedTopologies" (vector (gr8s::core-object))) node))))

(test rox-binding-does-not-override-explicit-pod-mount-flags
  (with-temporary-store (store path)
    (gr8s::create-core-resource store "persistentvolumes"
      (storage-test-volume "rox" (merge-pathnames "rox/" path) :modes #("ReadOnlyMany")) nil)
    (gr8s::create-core-resource store "persistentvolumeclaims"
      (storage-test-claim "claim" :modes #("ReadOnlyMany")) "default")
    (gr8s::reconcile-storage-bindings store)
    (let ((runtime (gr8s::make-containerd-runtime :log-root (merge-pathnames "pod-logs/" path))))
      (setf (gr8s::containerd-runtime-resource-store runtime) store)
      (dolist (flags '((nil nil nil) (t nil t) (nil t t)))
        (destructuring-bind (source-readonly mount-readonly expected) flags
          (let* ((object (pod-to-object (storage-test-pod "consumer" "claim")))
                 (spec (gethash "spec" object)) (container (aref (gethash "containers" spec) 0)))
            (setf (gethash "readOnly" (gethash "persistentVolumeClaim" (aref (gethash "volumes" spec) 0))) source-readonly
                  (gethash "readOnly" (aref (gethash "volumeMounts" container) 0)) mount-readonly)
            (let* ((pod (parse-pod object))
                   (mount (first (gr8s::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0)))))
              (is (eql expected (gr8s.cri.v1::readonly mount))))))))))

(in-suite gr8s)
