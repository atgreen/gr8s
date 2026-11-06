;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
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
      (signals gr8s::runtime-error (gr8s::materialize-host-storage-source (gr8s::core-object "path" (namestring (merge-pathnames "absent/" path)) "type" "Directory")))
      ;; Untyped, a missing source is left for the CRI runtime to create, as upstream StatefulSet tests expect.
      (let ((untyped (merge-pathnames "untyped/" path)))
        (is (equal (namestring untyped)
                   (namestring (gr8s::materialize-host-storage-source (gr8s::core-object "path" (namestring untyped))))))
        (is-false (uiop:directory-exists-p untyped)))
      ;; A local PV's directory must already exist.
      (signals gr8s::runtime-error
        (gr8s::materialize-host-storage-source (gr8s::core-object "path" (namestring (merge-pathnames "absent/" path))) :local t)))))

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

(test prebound-pairs-bind-as-given-and-unschedulable-pods-say-why
  ;; The SchedulerPredicates spec pre-binds a local PV whose class differs from the
  ;; claim's defaulted one, with node affinity naming nodes that don't exist.
  (with-temporary-store (store path)
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (gr8s::seed-default-storage-class store path :path (namestring (merge-pathnames "local-path" path)))
    (let ((volume (storage-test-volume "pv-prebound" (merge-pathnames "local/" path))))
      (remhash "hostPath" (gethash "spec" volume))
      (setf (gethash "local" (gethash "spec" volume)) (gr8s::core-object "path" "/tmp")
            (gethash "nodeAffinity" (gethash "spec" volume))
            (gr8s::core-object "required" (gr8s::core-object "nodeSelectorTerms"
                                           (vector (gr8s::core-object "matchExpressions"
                                                    (vector (gr8s::core-object "key" "kubernetes.io/hostname" "operator" "In"
                                                                               "values" #("worker-a" "absent-1" "absent-2")))))))
            (gethash "claimRef" (gethash "spec" volume)) (gr8s::core-object "name" "data" "namespace" "default"))
      (gr8s::create-core-resource store "persistentvolumes" volume nil))
    (let ((claim (storage-test-claim "data")))
      (remhash "storageClassName" (gethash "spec" claim))
      (setf (gethash "volumeName" (gethash "spec" claim)) "pv-prebound")
      (is (equal "local-path" (gethash "storageClassName" (gethash "spec" (gr8s::create-core-resource store "persistentvolumeclaims" claim "default"))))))
    (gr8s::reconcile-storage-bindings store)
    (is (equal "Bound" (storage-phase store "persistentvolumeclaims" "default" "data")))
    (is (equal "Bound" (storage-phase store "persistentvolumes" nil "pv-prebound")))
    (let ((pod (create-pod store (storage-test-pod "consumer" "data"))))
      (is (equal "worker-a" (gr8s::node-record-name (gr8s:schedule-pod store pod)))))
    ;; A missing claim is reported as the scheduler reports it.
    (let ((pod (create-pod store (storage-test-pod "orphan" "missing"))))
      (is (null (gr8s:schedule-pod store pod)))
      (is (equal "0/1 nodes are available: 1 persistentvolumeclaim \"missing\" not found."
                 (gr8s::with-store-lock (store) (gr8s::pod-unschedulable-message store pod)))))))


(test local-volumes-take-the-pods-fs-group-without-following-links
  (with-temporary-store (store path)
    (let* ((runtime (gr8s::%make-containerd-runtime :log-root (merge-pathnames "logs/" path) :resource-store store))
           (backing (merge-pathnames "local/" path)) (outside (merge-pathnames "outside" path))
           (gid (sb-posix:getgid)) (volume (storage-test-volume "local-pv" backing)))
      (ensure-directories-exist (merge-pathnames "nested/" backing))
      (dolist (file (list (merge-pathnames "file" backing) outside))
        (with-open-file (out file :direction :output) (write-string "x" out))
        (sb-posix:chmod (namestring file) #o600))
      (sb-posix:chmod (namestring backing) #o755)
      (sb-posix:chmod (namestring (merge-pathnames "nested/" backing)) #o755)
      (sb-posix:symlink (namestring outside) (namestring (merge-pathnames "escape" backing)))
      (remhash "hostPath" (gethash "spec" volume))
      (setf (gethash "local" (gethash "spec" volume)) (gr8s::core-object "path" (string-right-trim "/" (namestring backing)))
            (gethash "nodeAffinity" (gethash "spec" volume))
            (gr8s::core-object "required" (gr8s::core-object "nodeSelectorTerms"
                                           (vector (gr8s::core-object "matchExpressions"
                                                    (vector (gr8s::core-object "key" "kubernetes.io/hostname" "operator" "In" "values" #("worker-a"))))))))
      (gr8s::create-core-resource store "persistentvolumes" volume nil)
      (gr8s::create-core-resource store "persistentvolumeclaims" (storage-test-claim "data") "default")
      (gr8s::reconcile-storage-bindings store)
      (let* ((object (pod-to-object (storage-test-pod "consumer" "data" "worker-a"))))
        (setf (gethash "securityContext" (gethash "spec" object)) (gr8s::core-object "fsGroup" gid))
        (let* ((pod (create-pod store (parse-pod object)))
               (source (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0)))
          (flet ((mode (file) (logand #o7777 (sb-posix:stat-mode (sb-posix:lstat (namestring file))))))
            (gr8s::materialize-pod-volume runtime pod source)
            (is (= #o2775 (mode (string-right-trim "/" (namestring backing)))))
            (is (= #o2775 (mode (merge-pathnames "nested" backing))))
            (is (= #o660 (mode (merge-pathnames "file" backing))))
            (is (= gid (sb-posix:stat-gid (sb-posix:stat (namestring (merge-pathnames "file" backing))))))
            ;; The link is re-owned but never followed.
            (is (= #o600 (mode outside)))
            ;; OnRootMismatch leaves a matching root's contents alone.
            (sb-posix:chmod (namestring (merge-pathnames "file" backing)) #o600)
            (setf (gethash "fsGroupChangePolicy" (gethash "securityContext" (gethash "spec" (pod-to-object pod)))) "OnRootMismatch")
            (gr8s::materialize-pod-volume runtime pod source)
            (is (= #o600 (mode (merge-pathnames "file" backing))))))))))

(test volume-gid-annotations-join-the-containers-supplemental-groups
  ;; The PersistentVolumes NFS specs check that a container's groups include the PV's
  ;; pv.beta.kubernetes.io/gid, as a kubelet adds it.
  (with-temporary-store (store path)
    (flet ((volume (name gid)
             (let ((object (storage-test-volume name (merge-pathnames (format nil "~A/" name) path))))
               (setf (gethash "annotations" (gethash "metadata" object)) (gr8s::core-object "pv.beta.kubernetes.io/gid" gid))
               (gr8s::create-core-resource store "persistentvolumes" object nil)))
           (claim (name volume)
             (let ((object (storage-test-claim name)))
               (when volume (setf (gethash "volumeName" (gethash "spec" object)) volume))
               (gr8s::create-core-resource store "persistentvolumeclaims" object "default"))))
      (volume "annotated" "777") (claim "data" "annotated")
      (volume "garbled" "not-a-gid") (claim "other" "garbled")
      (claim "unbound" nil)
      (gr8s::reconcile-storage-bindings store)
      (let* ((object (pod-to-object (storage-test-pod "consumer" "data"))))
        (setf (gethash "volumes" (gethash "spec" object))
              (concatenate 'vector (gethash "volumes" (gethash "spec" object))
                           (vector (gr8s::core-object "name" "other" "persistentVolumeClaim" (gr8s::core-object "claimName" "other"))
                                   (gr8s::core-object "name" "unbound" "persistentVolumeClaim" (gr8s::core-object "claimName" "unbound"))))
              (gethash "securityContext" (gethash "spec" object)) (gr8s::core-object "supplementalGroups" #(5 777)))
        (let* ((pod (create-pod store (parse-pod object)))
               (groups (gr8s::pod-volume-supplemental-groups store pod)))
          (is (equal '(777) groups))
          (is (equal '(5 777)
                     (coerce (gr8s.cri.v1::supplemental-groups
                              (gr8s::containerd-pod-security-context pod (aref (pod-containers pod) 0) :volume-groups groups))
                             'list)))
          (is (equal '(5 777 1234)
                     (coerce (gr8s.cri.v1::supplemental-groups
                              (gr8s::containerd-pod-security-context pod (aref (pod-containers pod) 0) :volume-groups '(1234)))
                             'list))))))))
(in-suite gr8s)
