;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify dynamic local and NFS provisioning, NFS mounting through injected
;;;; mount calls, safe reclamation on a real filesystem, generic ephemeral volumes
;;;; and enforced emptyDir limits. Real kernel NFS mounts need a root test node:
;;;; see scripts/test-storage-dynamic-native.py.

(in-package #:gr8s/tests)
(def-suite storage-provisioning :in gr8s)
(in-suite storage-provisioning)

(defun provisioning-class (name provisioner &rest fields)
  "Build a StorageClass from alternating top-level FIELDS."
  (let ((class (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" name) "provisioner" provisioner)))
    (loop for (key value) on fields by #'cddr do (setf (gethash key class) value))
    class))

(defun local-path-class (path &optional (name "fast"))
  (provisioning-class name gr8s.resources::+local-path-provisioner+
                      "volumeBindingMode" "WaitForFirstConsumer"
                      "allowVolumeExpansion" t
                      "parameters" (gr8s.resources::core-object "path" (string-right-trim "/" (namestring path)))))

(defun nfs-class (&key (name "shared") (mount-options #("hard" "nconnect=2")) (on-delete "delete"))
  (provisioning-class name gr8s.resources::+nfs-provisioner+
                      "mountOptions" mount-options
                      "parameters" (gr8s.resources::core-object "server" "10.0.0.5" "share" "/export/k8s" "onDelete" on-delete)))

(defun ready-node (store name id cidr)
  (gr8s.controllers::register-node store (make-test-node name id cidr))
  (gr8s.controllers::mark-node-ready store name 1))

(defun claim-object (store name &optional (namespace "default"))
  (gr8s.resources::get-core-resource store "persistentvolumeclaims" namespace name))

(defun claim-volume-name (store name)
  (gethash "volumeName" (gethash "spec" (claim-object store name))))

(test local-path-waits-for-a-consumer-then-pins-a-volume-to-its-node
  (with-temporary-store (store path)
    (gr8s.resources::create-core-resource store "storageclasses" (local-path-class (merge-pathnames "volumes/" path)) nil)
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim" :class "fast") "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" "claim")))
    (is (null (gr8s.resources::list-core-resources store "persistentvolumes")))
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (let* ((pod (create-pod store (storage-test-pod "consumer" "claim")))
           (node (gr8s.controllers::schedule-pod store pod)))
      (is (equal "worker-a" (gr8s.model::node-record-name node)))
      (gr8s.resources::reconcile-storage-bindings store)
      (let* ((name (claim-volume-name store "claim"))
             (volume (gr8s.resources::get-core-resource store "persistentvolumes" nil name))
             (spec (gethash "spec" volume))
             (uid (gethash "uid" (gethash "metadata" (claim-object store "claim")))))
        (is (equal (format nil "pvc-~A" uid) name))
        (is (equal "Bound" (storage-phase store "persistentvolumeclaims" "default" "claim")))
        (is (equal "DirectoryOrCreate" (gethash "type" (gethash "hostPath" spec))))
        (is (uiop:string-suffix-p (gethash "path" (gethash "hostPath" spec)) (format nil "/volumes/~A" name)))
        (is (equal "Delete" (gethash "persistentVolumeReclaimPolicy" spec)))
        (is (not (gr8s.resources::storage-node-affinity-matches-p volume (make-test-node "worker-b" "b" "10.64.16.0/20"))))
        (is (gr8s.resources::storage-node-affinity-matches-p volume (gr8s.controllers::get-node store "worker-a")))
        (let ((revision (gr8s.store::pod-store-resource-revision store)))
          (is-false (gr8s.resources::reconcile-storage-bindings store))
          (is (= revision (gr8s.store::pod-store-resource-revision store))))))))

(test local-path-refuses-modes-one-directory-cannot-serve
  (with-temporary-store (store path)
    (gr8s.resources::create-core-resource store "storageclasses" (local-path-class (merge-pathnames "volumes/" path)) nil)
    (gr8s.resources::create-core-resource store "persistentvolumeclaims"
                                (storage-test-claim "wide" :class "fast" :modes #("ReadWriteMany")) "default")
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (is (null (gr8s.controllers::schedule-pod store (create-pod store (storage-test-pod "consumer" "wide")))))
    (gr8s.resources::reconcile-storage-bindings store)
    (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" "wide")))))

(test a-matching-static-volume-is-preferred-over-provisioning
  (with-temporary-store (store path)
    (gr8s.resources::create-core-resource store "storageclasses" (nfs-class) nil)
    (gr8s.resources::create-core-resource store "persistentvolumes"
                                (storage-test-volume "static" (merge-pathnames "static/" path) :class "shared") nil)
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim" :class "shared") "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (is (equal "static" (claim-volume-name store "claim")))))

(test nfs-classes-provision-shared-volumes-immediately
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "storageclasses" (nfs-class) nil)
    (gr8s.resources::create-core-resource store "persistentvolumeclaims"
                                (storage-test-claim "claim" :class "shared" :modes #("ReadWriteMany")) "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (let* ((name (claim-volume-name store "claim"))
           (volume (gr8s.resources::get-core-resource store "persistentvolumes" nil name))
           (spec (gethash "spec" volume))
           (annotations (gethash "annotations" (gethash "metadata" volume))))
      (is (equal "Bound" (storage-phase store "persistentvolumeclaims" "default" "claim")))
      (is (equal "10.0.0.5" (gethash "server" (gethash "nfs" spec))))
      (is (equal (format nil "/export/k8s/~A" name) (gethash "path" (gethash "nfs" spec))))
      (is (equalp #("hard" "nconnect=2") (gethash "mountOptions" spec)))
      (is (null (gethash "nodeAffinity" spec)))
      (is (equal "/export/k8s" (gethash gr8s.resources::+nfs-share-annotation+ annotations)))
      (is-true (gr8s.resources::storage-native-volume-p volume)))))

(test claims-a-provisioner-cannot-honor-stay-pending
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "storageclasses" (nfs-class) nil)
    (let ((block-claim (storage-test-claim "block" :class "shared"))
          (selected (storage-test-claim "selected" :class "shared")))
      (setf (gethash "volumeMode" (gethash "spec" block-claim)) "Block"
            (gethash "selector" (gethash "spec" selected))
            (gr8s.resources::core-object "matchLabels" (gr8s.resources::core-object "tier" "gold")))
      (gr8s.resources::create-core-resource store "persistentvolumeclaims" block-claim "default")
      (gr8s.resources::create-core-resource store "persistentvolumeclaims" selected "default"))
    (gr8s.resources::reconcile-storage-bindings store)
    (dolist (name '("block" "selected"))
      (is (equal "Pending" (storage-phase store "persistentvolumeclaims" "default" name))))
    (is (null (gr8s.resources::list-core-resources store "persistentvolumes")))))

(test built-in-classes-reject-what-they-cannot-honor
  (with-temporary-store (store path)
    (values path)
    (flet ((rejected (class)
             (signals kubernetes-error (gr8s.resources::create-core-resource store "storageclasses" class nil))))
      (rejected (provisioning-class "a" gr8s.resources::+nfs-provisioner+))
      (rejected (provisioning-class "b" gr8s.resources::+nfs-provisioner+
                                    "parameters" (gr8s.resources::core-object "server" "bad,server" "share" "/x")))
      (rejected (provisioning-class "c" gr8s.resources::+nfs-provisioner+
                                    "parameters" (gr8s.resources::core-object "server" "s" "share" "/../x")))
      (rejected (provisioning-class "d" gr8s.resources::+nfs-provisioner+
                                    "parameters" (gr8s.resources::core-object "server" "s" "share" "/x" "unknown" "y")))
      (rejected (nfs-class :mount-options #("sec=sys,exec=/bin/sh")))
      (rejected (nfs-class :on-delete "shred"))
      (rejected (provisioning-class "e" gr8s.resources::+local-path-provisioner+
                                    "parameters" (gr8s.resources::core-object "path" "relative")))
      (rejected (provisioning-class "f" gr8s.resources::+local-path-provisioner+ "mountOptions" #("noatime"))))
    ;; A third party's parameters remain its own business.
    (is (gr8s.resources::create-core-resource store "storageclasses"
                                    (provisioning-class "g" "example.test/driver"
                                                        "parameters" (gr8s.resources::core-object "anything" "goes"))
                                    nil))))

(test static-nfs-volumes-validate-their-source-and-options
  (with-temporary-store (store path)
    (values path)
    (flet ((volume (name server share &optional options)
             (let ((object (storage-test-volume name "/unused")))
               (remhash "hostPath" (gethash "spec" object))
               (setf (gethash "nfs" (gethash "spec" object)) (gr8s.resources::core-object "server" server "path" share))
               (when options (setf (gethash "mountOptions" (gethash "spec" object)) options))
               object)))
      (is (gr8s.resources::create-core-resource store "persistentvolumes"
                                      (volume "good" "nas.example.test" "/share" #("vers=4.1" "soft,timeo=30")) nil))
      (signals kubernetes-error
        (gr8s.resources::create-core-resource store "persistentvolumes" (volume "bad-server" "a b" "/share") nil))
      (signals kubernetes-error
        (gr8s.resources::create-core-resource store "persistentvolumes" (volume "bad-path" "nas" "share") nil))
      (signals kubernetes-error
        (gr8s.resources::create-core-resource store "persistentvolumes" (volume "bad-option" "nas" "/share" #("context=x")) nil))
      (signals kubernetes-error
        (gr8s.resources::create-core-resource store "persistentvolumes" (volume "bad-version" "nas" "/share" #("vers=9")) nil)))))

(test deleting-a-claim-releases-its-provisioned-volume-for-reclaim
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "storageclasses" (nfs-class) nil)
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim" :class "shared") "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (let ((name (claim-volume-name store "claim")))
      (gr8s.resources::delete-core-resource store "persistentvolumeclaims" "default" "claim")
      (gr8s.resources::reconcile-storage-bindings store)
      (let ((volume (gr8s.resources::get-core-resource store "persistentvolumes" nil name)))
        (is (equal "Released" (gethash "phase" (gethash "status" volume))))
        (is-true (gr8s.resources::storage-volume-reclaimable-p volume)))
      ;; With no Ready node the deletion waits, and nothing is removed.
      (let ((reclaimer (gr8s.resources::make-volume-reclaimer store nil))
            (*error-output* (make-broadcast-stream)))
        (gr8s.resources::volume-reclaimer-step reclaimer 1000)
        (is-false (cl-work-queue::retry-backoff-ready-p (gr8s.resources::volume-reclaimer-backoff reclaimer) name 1000))
        (is (gr8s.resources::get-core-resource store "persistentvolumes" nil name))))))

(test static-delete-policy-volumes-still-report-no-deleter
  (with-temporary-store (store path)
    (let ((volume (storage-test-volume "static" (merge-pathnames "static/" path))))
      (setf (gethash "persistentVolumeReclaimPolicy" (gethash "spec" volume)) "Delete")
      (gr8s.resources::create-core-resource store "persistentvolumes" volume nil))
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim") "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (gr8s.resources::delete-core-resource store "persistentvolumeclaims" "default" "claim")
    (gr8s.resources::reconcile-storage-bindings store)
    (is (equal "Failed" (storage-phase store "persistentvolumes" nil "static")))))

(test claims-grow-only-where-their-class-allows
  (with-temporary-store (store path)
    (gr8s.resources::create-core-resource store "storageclasses" (nfs-class) nil)
    (let ((class (nfs-class :name "growing")))
      (setf (gethash "allowVolumeExpansion" class) t)
      (gr8s.resources::create-core-resource store "storageclasses" class nil))
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "fixed" :class "shared") "default")
    (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "grows" :class "growing") "default")
    (gr8s.resources::reconcile-storage-bindings store)
    (flet ((resize (name capacity)
             (gr8s.resources::update-core-resource
              store "persistentvolumeclaims" "default" name
              (lambda (old)
                (let ((claim (gr8s.resources::copy-core-object old)))
                  (setf (gethash "storage" (gethash "requests" (gethash "resources" (gethash "spec" claim)))) capacity)
                  claim)))))
      (signals kubernetes-error (resize "fixed" "5Gi"))
      (resize "grows" "5Gi")
      (gr8s.resources::reconcile-storage-bindings store)
      (let ((claim (claim-object store "grows")))
        (is (equal "5Gi" (gethash "storage" (gethash "capacity" (gethash "status" claim)))))
        (is (equal "5Gi" (gethash "storage" (gethash "capacity"
                                                     (gethash "spec" (gr8s.resources::get-core-resource store "persistentvolumes" nil
                                                                                              (claim-volume-name store "grows")))))))))
    (values path)))

(test default-class-is-seeded-once-and-stays-deleted
  (with-temporary-store (store path)
    (gr8s.resources::seed-default-storage-class store path :path "/srv/volumes")
    (let ((class (gr8s.resources::get-core-resource store "storageclasses" nil "local-path")))
      (is (equal gr8s.resources::+local-path-provisioner+ (gethash "provisioner" class)))
      (is (equal "WaitForFirstConsumer" (gethash "volumeBindingMode" class)))
      (is (equal "/srv/volumes" (gethash "path" (gethash "parameters" class)))))
    (gr8s.resources::create-core-resource store "persistentvolumeclaims"
                                (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "defaulted")
                                                   "spec" (gr8s.resources::core-object "accessModes" #("ReadWriteOnce")
                                                                             "resources" (gr8s.resources::core-object "requests" (gr8s.resources::core-object "storage" "1Gi"))))
                                "default")
    (is (equal "local-path" (gethash "storageClassName" (gethash "spec" (claim-object store "defaulted")))))
    (gr8s.resources::delete-core-resource store "storageclasses" nil "local-path")
    (gr8s.resources::seed-default-storage-class store path :path "/srv/volumes")
    (signals kubernetes-error (gr8s.resources::get-core-resource store "storageclasses" nil "local-path"))))

(test mount-affinity-judges-only-what-an-agent-can-know
  (flet ((volume (&rest expressions)
           (gr8s.resources::core-object
            "spec" (gr8s.resources::core-object
                    "nodeAffinity"
                    (gr8s.resources::core-object
                     "required"
                     (gr8s.resources::core-object
                      "nodeSelectorTerms"
                      (vector (gr8s.resources::core-object "matchExpressions" (coerce expressions 'vector)))))))))
    ;; An agent has no Node labels, so a custom label must not fail a scheduled mount.
    (is-false (gr8s.resources::storage-node-affinity-excludes-node-name-p
               (volume (gr8s.resources::core-object "key" "disk" "operator" "In" "values" #("ssd"))) "worker-a"))
    (is-false (gr8s.resources::storage-node-affinity-excludes-node-name-p
               (volume (gr8s.resources::core-object "key" "kubernetes.io/hostname" "operator" "In" "values" #("worker-a"))) "worker-a"))
    (is-true (gr8s.resources::storage-node-affinity-excludes-node-name-p
              (volume (gr8s.resources::core-object "key" "kubernetes.io/hostname" "operator" "In" "values" #("worker-b"))) "worker-a"))))

;;; NFS mounting

(test nfs-mount-attempts-negotiate-versions-and-separate-flags
  (multiple-value-bind (attempts flags)
      (gr8s.kubelet::nfs-mount-attempts '("noatime" "ro" "hard" "timeo=30") "10.0.0.5")
    (is (equal '(("nfs4" . "vers=4.2,addr=10.0.0.5,hard,timeo=30")
                 ("nfs4" . "vers=4.1,addr=10.0.0.5,hard,timeo=30")
                 ("nfs4" . "vers=4.0,addr=10.0.0.5,hard,timeo=30")
                 ("nfs" . "vers=3,addr=10.0.0.5,nolock,hard,timeo=30"))
               attempts))
    ;; MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOATIME: the kernel NFS parser would reject these as text.
    (is (= (logior 1 2 4 #x400) flags)))
  (is (equal '(("nfs" . "vers=3,addr=10.0.0.5,nolock"))
             (gr8s.kubelet::nfs-mount-attempts '("nfsvers=3") "10.0.0.5")))
  (is (equal '(("nfs" . "vers=3,addr=10.0.0.5,lock"))
             (gr8s.kubelet::nfs-mount-attempts '("vers=3" "lock") "10.0.0.5")))
  (is (equal '(("nfs4" . "vers=4.1,addr=10.0.0.5"))
             (gr8s.kubelet::nfs-mount-attempts '("vers=4.1") "10.0.0.5"))))

(test nfs-mount-options-cannot-smuggle-other-options
  (dolist (token '("vers=4.1" "soft" "hard" "timeo=30" "sec=krb5p" "noatime" "ro" "nconnect=4" "proto=tcp"))
    (is-true (gr8s.kubelet::nfs-mount-option-valid-p token)))
  (dolist (token '("vers=9" "context=system_u" "timeo=" "bogus" "addr=1.2.3.4" "clientaddr=1.1.1.1" "port=1 2"))
    (is-false (gr8s.kubelet::nfs-mount-option-valid-p token)))
  (is (equal '("a" "b" "c") (gr8s.kubelet::nfs-mount-option-tokens #(" a , b" "c,,")))))

(defun nfs-test-pod ()
  (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"nfs\",\"uid\":\"nfs-uid\"},\"spec\":{\"volumes\":[{\"name\":\"data\",\"nfs\":{\"server\":\"10.0.0.5\",\"path\":\"/share\",\"readOnly\":true}}],\"containers\":[{\"name\":\"c\",\"image\":\"busybox\",\"volumeMounts\":[{\"name\":\"data\",\"mountPath\":\"/data\"}]}]}}"))

(defmacro with-fake-nfs ((calls directory &key (mount-result '(constantly 0))) &body body)
  "Run BODY recording NFS mount calls in CALLS, against a fake mount table in DIRECTORY."
  (let ((table (gensym "TABLE")) (lock (gensym "LOCK")) (mounted (gensym "MOUNTED")) (result (gensym "RESULT")))
    `(let* ((,calls nil) (,mounted nil) (,lock (bt:make-lock)) (,result ,mount-result)
            (,table (merge-pathnames "nfs-mountinfo" ,directory)))
       (flet ((write-table ()
                (with-open-file (stream ,table :direction :output :if-exists :supersede)
                  (format stream "22 1 0:21 / /proc rw - proc proc rw~%")
                  (dolist (target ,mounted)
                    (format stream "90 1 0:50 / ~A rw - nfs4 10.0.0.5:/share rw~%" target)))))
         (write-table)
         (let ((gr8s.kubelet::*pod-mount-table-path* ,table)
               (gr8s.kubelet::*nfs-mount-call*
                 (lambda (source target type flags data)
                   (bt:with-lock-held (,lock)
                     (push (list source target type flags data) ,calls)
                     (let ((code (funcall ,result source target type flags data)))
                       (when (zerop code) (push target ,mounted) (write-table))
                       code))))
               (gr8s.kubelet::*nfs-unmount-call*
                 (lambda (target flags)
                   (declare (ignore flags))
                   (bt:with-lock-held (,lock)
                     (setf ,mounted (remove target ,mounted :test #'equal))
                     (write-table)
                     0))))
           ,@body)))))

(test nfs-volumes-mount-once-without-touching-the-share
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-nfs (calls directory)
      (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
             (pod (nfs-test-pod))
             (volume (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0)))
        (multiple-value-bind (path readonly) (gr8s.kubelet::materialize-pod-volume runtime pod volume)
          (is (eq t readonly))
          (is (= 1 (length calls)))
          (destructuring-bind (source target type flags data) (first calls)
            (is (equal "10.0.0.5:/share" source))
            (is (equal "nfs4" type))
            (is (= (logior 1 2 4) flags))
            (is (equal "vers=4.2,addr=10.0.0.5" data))
            (is (equal (string-right-trim "/" (namestring path)) target))))
        ;; A restarted container reuses the live mount.
        (gr8s.kubelet::materialize-pod-volume runtime pod volume)
        (is (= 1 (length calls)))))))

(test nfs-mounts-fall-back-only-for-refused-versions
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-nfs (calls directory
                    :mount-result (lambda (source target type flags data)
                                    (declare (ignore source target type flags))
                                    (if (search "vers=4.0" data) 0 sb-posix:eprotonosupport)))
      (gr8s.kubelet::mount-nfs-filesystem "10.0.0.5" "/share" (namestring (merge-pathnames "t1" directory)) nil)
      (is (= 3 (length calls))))
    (with-fake-nfs (calls directory :mount-result (constantly sb-posix:eacces))
      (signals gr8s.kubelet::nfs-mount-error
        (gr8s.kubelet::mount-nfs-filesystem "10.0.0.5" "/share" (namestring (merge-pathnames "t2" directory)) nil))
      (is (= 1 (length calls))))
    ;; An fsid=0 export hides its v3 path from NFSv4, so ENOENT goes straight on to NFSv3.
    (with-fake-nfs (calls directory
                    :mount-result (lambda (source target type flags data)
                                    (declare (ignore source target flags data))
                                    (if (equal type "nfs") 0 sb-posix:enoent)))
      (gr8s.kubelet::mount-nfs-filesystem "10.0.0.5" "/exports" (namestring (merge-pathnames "t3" directory)) nil)
      (is (equal '("nfs" "nfs4") (mapcar #'third calls)))
      (is (search "vers=3" (fifth (first calls))))
      (is (search "nolock" (fifth (first calls)))))
    ;; A version the mount names is the only one tried.
    (with-fake-nfs (calls directory :mount-result (constantly sb-posix:enoent))
      (signals gr8s.kubelet::nfs-mount-error
        (gr8s.kubelet::mount-nfs-filesystem "10.0.0.5" "/missing" (namestring (merge-pathnames "t4" directory)) '("vers=4.1")))
      (is (= 1 (length calls))))))

(test a-provisioned-nfs-volume-creates-its-directory-on-first-use
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (let ((exists nil))
      (with-fake-nfs (calls directory
                      :mount-result (lambda (source target type flags data)
                                      (declare (ignore target type flags data))
                                      (cond ((equal source "10.0.0.5:/share") (setf exists t) 0)
                                            (exists 0)
                                            (t sb-posix:enoent))))
        (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
               (pod (nfs-test-pod))
               (path (gr8s.kubelet::materialize-pod-nfs-volume
                      runtime pod "data"
                      (gr8s.resources::core-object "server" "10.0.0.5" "path" "/share/pvc-abc") #("hard")
                      :share "/share")))
          ;; The missing directory is looked for over NFSv4 and then NFSv3, as mount.nfs does.
          (is (equal '(("10.0.0.5:/share/pvc-abc" "nfs4") ("10.0.0.5:/share/pvc-abc" "nfs")
                       ("10.0.0.5:/share" "nfs4") ("10.0.0.5:/share/pvc-abc" "nfs4"))
                     (mapcar (lambda (call) (list (first call) (third call))) (reverse calls))))
          (is (uiop:directory-pathname-p path))
          ;; The share is staged briefly and the volume's own directory now exists in it.
          (let ((staging (second (third (reverse calls)))))
            (is (probe-file (format nil "~A/pvc-abc/" staging)))))))))

(test a-blocked-nfs-server-delays-only-its-caller
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (let ((release nil) (attempts 0) (lock (bt:make-lock)))
      (with-fake-nfs (calls directory
                      :mount-result (lambda (&rest arguments)
                                      (declare (ignore arguments))
                                      (bt:with-lock-held (lock) (incf attempts))
                                      0))
        (let ((target (namestring (merge-pathnames "blocked" directory)))
              (gr8s.kubelet::*nfs-operation-wait-seconds* 0.05)
              (gr8s.kubelet::*nfs-mount-call*
                (let ((inner gr8s.kubelet::*nfs-mount-call*))
                  (lambda (&rest arguments)
                    (loop until release do (sleep 0.01))
                    (apply inner arguments)))))
          (signals runtime-error (gr8s.kubelet::mount-nfs-filesystem "10.0.0.5" "/share" target nil))
          ;; A retry joins the blocked mount instead of starting another.
          (signals runtime-error (gr8s.kubelet::mount-nfs-filesystem "10.0.0.5" "/share" target nil))
          (setf release t)
          (loop repeat 200
                until (bt:with-lock-held (lock) (= attempts 1))
                do (sleep 0.01))
          (gr8s.kubelet::mount-nfs-filesystem "10.0.0.5" "/share" target nil)
          (is (= 1 attempts))
          (is (= 1 (length calls))))))))

(test pod-termination-unmounts-nfs-and-keeps-the-share-contents
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-nfs (calls directory)
      (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
             (pod (nfs-test-pod))
             (volume (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0))
             (path (gr8s.kubelet::materialize-pod-volume runtime pod volume))
             (target (string-right-trim "/" (namestring path))))
        (is (gr8s.kubelet::pod-volume-nfs-mount-p target))
        (gr8s.kubelet::cleanup-pod-volumes runtime (pod-uid pod))
        (is (not (gr8s.kubelet::nfs-target-mounted-p target)))
        (is (null (probe-file path)))
        (is (= 1 (length calls)))))))

(test pod-volume-cleanup-refuses-to-delete-beneath-a-stuck-mount
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-nfs (calls directory)
      (let* ((runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
             (pod (nfs-test-pod))
             (volume (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0))
             (path (gr8s.kubelet::materialize-pod-volume runtime pod volume))
             (kept (merge-pathnames "data-on-the-share" path)))
        (with-open-file (stream kept :direction :output) (write-string "x" stream))
        (let ((gr8s.kubelet::*nfs-unmount-call* (lambda (target flags) (declare (ignore target flags)) 0)))
          (signals runtime-error (gr8s.kubelet::cleanup-pod-volumes runtime (pod-uid pod))))
        (is (probe-file kept))
        (is (= 1 (length calls)))))))

;;; Reclamation on a real filesystem

(defun provisioned-test-volume (name provisioner path &optional (on-delete "delete"))
  (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" name
                                                   "annotations" (gr8s.resources::core-object gr8s.resources::+provisioned-by-annotation+ provisioner
                                                                                    gr8s.resources::+on-delete-annotation+ on-delete))
                     "spec" (gr8s.resources::core-object "hostPath" (gr8s.resources::core-object "path" path))))

(test reclaim-removes-only-the-volume-and-never-follows-links
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (let* ((root (string-right-trim "/" (namestring (truename directory))))
           (outside (format nil "~A/outside/" root))
           (volume (format nil "~A/volumes/pvc-1/" root))
           (neighbor (format nil "~A/volumes/pvc-2/keep" root)))
      (ensure-directories-exist outside)
      (ensure-directories-exist (format nil "~Anested/" volume))
      (ensure-directories-exist neighbor)
      (with-open-file (stream (format nil "~Asecret" outside) :direction :output) (write-string "x" stream))
      (with-open-file (stream (format nil "~Anested/file" volume) :direction :output) (write-string "x" stream))
      ;; A tenant plants links to directories and files outside its volume.
      (sb-posix:symlink outside (format nil "~Alink-dir" volume))
      (sb-posix:symlink (format nil "~Asecret" outside) (format nil "~Anested/link-file" volume))
      (gr8s.resources::reclaim-provisioned-volume
       directory (provisioned-test-volume "pvc-1" gr8s.resources::+local-path-provisioner+
                                          (string-right-trim "/" volume)))
      (is (null (probe-file volume)))
      (is (probe-file (format nil "~Asecret" outside)))
      (is (probe-file (format nil "~A/volumes/pvc-2/" root)))
      ;; Reclaiming again finds nothing to do.
      (finishes (gr8s.resources::reclaim-provisioned-volume
                 directory (provisioned-test-volume "pvc-1" gr8s.resources::+local-path-provisioner+
                                                    (string-right-trim "/" volume)))))))

(test reclaim-refuses-paths-that-are-not-the-volumes-own-directory
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (flet ((refused (name path provisioner)
             (signals runtime-error
               (gr8s.resources::reclaim-provisioned-volume directory (provisioned-test-volume name provisioner path)))))
      (refused "pvc-1" "/etc" gr8s.resources::+local-path-provisioner+)
      (refused "pvc-1" "/var/lib/pvc-2" gr8s.resources::+local-path-provisioner+)
      (refused "etc" "/etc" gr8s.resources::+local-path-provisioner+)
      (refused "pvc-1" "/a/../pvc-1" gr8s.resources::+local-path-provisioner+)
      (refused "pvc-1" "/a/pvc-1" "example.test/driver"))))

(test reclaim-honors-retain-and-archive
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (let* ((root (string-right-trim "/" (namestring (truename directory))))
           (path (format nil "~A/volumes/pvc-1" root)))
      (ensure-directories-exist (format nil "~A/" path))
      (gr8s.resources::reclaim-provisioned-volume
       directory (provisioned-test-volume "pvc-1" gr8s.resources::+local-path-provisioner+ path "retain"))
      (is (probe-file (format nil "~A/" path)))
      (gr8s.resources::reclaim-provisioned-volume
       directory (provisioned-test-volume "pvc-1" gr8s.resources::+local-path-provisioner+ path "archive"))
      (is (null (probe-file (format nil "~A/" path))))
      (is (probe-file (format nil "~A/volumes/archived-pvc-1/" root))))))

(test reclaiming-an-nfs-volume-mounts-its-share-and-removes-its-directory
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (with-fake-nfs (calls directory
                    :mount-result (lambda (source target type flags data)
                                    (declare (ignore source type flags data))
                                    ;; The share holds this volume and a neighbor.
                                    (ensure-directories-exist (format nil "~A/pvc-1/inner/" target))
                                    (ensure-directories-exist (format nil "~A/pvc-2/" target))
                                    0))
      (let ((volume (gr8s.resources::core-object
                     "metadata" (gr8s.resources::core-object "name" "pvc-1"
                                                   "annotations" (gr8s.resources::core-object gr8s.resources::+provisioned-by-annotation+ gr8s.resources::+nfs-provisioner+
                                                                                    gr8s.resources::+nfs-share-annotation+ "/share"))
                     "spec" (gr8s.resources::core-object "nfs" (gr8s.resources::core-object "server" "10.0.0.5" "path" "/share/pvc-1")))))
        (gr8s.resources::reclaim-provisioned-volume directory volume)
        (destructuring-bind (source target &rest rest) (first calls)
          (declare (ignore rest))
          (is (equal "10.0.0.5:/share" source))
          (is (null (probe-file (format nil "~A/pvc-1/" target))))
          (is (probe-file (format nil "~A/pvc-2/" target)))
          (is (not (gr8s.kubelet::nfs-target-mounted-p target))))
        (setf (gethash "path" (gethash "nfs" (gethash "spec" volume))) "/other/pvc-1")
        (signals runtime-error (gr8s.resources::reclaim-provisioned-volume directory volume))))))

;;; Generic ephemeral volumes

(defun ephemeral-test-pod (name)
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"~A\"},\"spec\":{\"volumes\":[{\"name\":\"scratch\",\"ephemeral\":{\"volumeClaimTemplate\":{\"metadata\":{\"labels\":{\"a\":\"b\"}},\"spec\":{\"storageClassName\":\"shared\",\"accessModes\":[\"ReadWriteOnce\"],\"resources\":{\"requests\":{\"storage\":\"1Gi\"}}}}}}],\"containers\":[{\"name\":\"c\",\"image\":\"busybox\",\"volumeMounts\":[{\"name\":\"scratch\",\"mountPath\":\"/scratch\"}]}]}}" name)))

(test generic-ephemeral-volumes-get-an-owned-claim-that-binds-and-is-collected
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "storageclasses" (nfs-class) nil)
    (let ((pod (create-pod store (ephemeral-test-pod "worker"))))
      (is (equal '("worker-scratch") (gr8s.resources::storage-pod-claim-names pod)))
      (gr8s.resources::reconcile-storage-bindings store)
      (let* ((claim (claim-object store "worker-scratch"))
             (owner (aref (gethash "ownerReferences" (gethash "metadata" claim)) 0)))
        (is (equal (pod-uid pod) (gethash "uid" owner)))
        (is (equal "Pod" (gethash "kind" owner)))
        (is (equal "b" (gethash "a" (gethash "labels" (gethash "metadata" claim)))))
        (is-true (gr8s.kubelet::claim-owned-by-pod-p claim pod)))
      (gr8s.resources::reconcile-storage-bindings store)
      (is (equal "Bound" (storage-phase store "persistentvolumeclaims" "default" "worker-scratch")))
      ;; Once its Pod has gone the claim has no live owner and is collected.
      (is (not (gr8s.controllers::api-object-orphaned-p store (claim-object store "worker-scratch"))))
      (gr8s.store::remove-pod store "default" "worker")
      (is-true (gr8s.controllers::api-object-orphaned-p store (claim-object store "worker-scratch"))))))

(test generic-ephemeral-volumes-never-adopt-an-existing-claim
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "storageclasses" (nfs-class) nil)
    (let ((before (gr8s.resources::create-core-resource store "persistentvolumeclaims"
                                              (storage-test-claim "worker-scratch" :class "shared") "default"))
          (pod (create-pod store (ephemeral-test-pod "worker"))))
      (gr8s.resources::reconcile-storage-bindings store)
      (let ((claim (claim-object store "worker-scratch")))
        (is (equal (gethash "uid" (gethash "metadata" before)) (gethash "uid" (gethash "metadata" claim))))
        (is-false (gr8s.kubelet::claim-owned-by-pod-p claim pod))))))

(test pods-reject-malformed-nfs-and-ephemeral-volumes
  (flet ((pod (volume)
           (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"p\"},\"spec\":{\"volumes\":[~A],\"containers\":[{\"name\":\"c\",\"image\":\"busybox\"}]}}" volume)))
    (dolist (volume '("{\"name\":\"v\",\"nfs\":{\"server\":\"a,b\",\"path\":\"/x\"}}"
                      "{\"name\":\"v\",\"nfs\":{\"server\":\"s\",\"path\":\"x\"}}"
                      "{\"name\":\"v\",\"nfs\":{\"server\":\"s\",\"path\":\"/x\",\"readOnly\":7}}"
                      "{\"name\":\"v\",\"nfs\":{\"server\":\"s\",\"path\":\"/x\",\"other\":1}}"
                      "{\"name\":\"v\",\"ephemeral\":{}}"
                      "{\"name\":\"v\",\"ephemeral\":{\"volumeClaimTemplate\":{\"metadata\":{\"name\":\"x\"},\"spec\":{\"accessModes\":[\"ReadWriteOnce\"],\"resources\":{\"requests\":{\"storage\":\"1Gi\"}}}}}}"
                      "{\"name\":\"v\",\"ephemeral\":{\"volumeClaimTemplate\":{\"spec\":{\"accessModes\":[\"Sometimes\"],\"resources\":{\"requests\":{\"storage\":\"1Gi\"}}}}}}"))
      (signals kubernetes-error (parse-pod (pod volume))))
    (is (not (null (parse-pod (pod "{\"name\":\"v\",\"nfs\":{\"server\":\"nas.example.test\",\"path\":\"/x\"}}")))))))

;;; emptyDir limits

(defun empty-dir-test-pod (source &optional (resources ""))
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"e\",\"uid\":\"e-uid\"},\"spec\":{\"volumes\":[{\"name\":\"scratch\",\"emptyDir\":~A}],\"containers\":[{\"name\":\"c\",\"image\":\"busybox\"~A}]}}" source resources)))

(test disk-empty-dirs-are-evicted-when-they-outgrow-their-limit
  (let ((pod (empty-dir-test-pod "{\"sizeLimit\":\"1Mi\"}")))
    (is-true (gr8s.kubelet::pod-ephemeral-limit-p pod))
    (is (null (gr8s.kubelet::pod-empty-dir-violation pod (list (cons "scratch" 1024)))))
    (is (search "EmptyDir volume \"scratch\""
                (gr8s.kubelet::pod-empty-dir-violation pod (list (cons "scratch" (* 2 1024 1024)))))))
  ;; tmpfs enforces its own size, so only a disk-backed volume is measured.
  (let ((pod (empty-dir-test-pod "{\"medium\":\"Memory\",\"sizeLimit\":\"1Mi\"}")))
    (is-false (gr8s.kubelet::pod-ephemeral-limit-p pod))
    (is (null (gr8s.kubelet::pod-empty-dir-violation pod (list (cons "scratch" (* 2 1024 1024))))))))

(test memory-empty-dirs-are-sized-by-the-smaller-of-both-limits
  (let ((limits ",\"resources\":{\"limits\":{\"memory\":\"32Mi\"}}"))
    (is (= (* 32 1024 1024)
           (gr8s.kubelet::pod-memory-volume-bytes (empty-dir-test-pod "{\"medium\":\"Memory\",\"sizeLimit\":\"64Mi\"}" limits)
                                          (gr8s.resources::core-object "sizeLimit" "64Mi"))))
    (is (= (* 16 1024 1024)
           (gr8s.kubelet::pod-memory-volume-bytes (empty-dir-test-pod "{\"medium\":\"Memory\",\"sizeLimit\":\"16Mi\"}" limits)
                                          (gr8s.resources::core-object "sizeLimit" "16Mi"))))
    (is (= (* 32 1024 1024)
           (gr8s.kubelet::pod-memory-volume-bytes (empty-dir-test-pod "{\"medium\":\"Memory\"}" limits) (gr8s.resources::core-object)))))
  (is (null (gr8s.kubelet::pod-memory-volume-bytes (empty-dir-test-pod "{\"medium\":\"Memory\"}") (gr8s.resources::core-object)))))

;;; Across the real node protocol

(test released-volumes-are-reclaimed-through-the-remote-agent
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-remote" :name "worker-a" :pod-cidr "10.88.1.0/24"))
    (let* ((server (gr8s.apiserver::start-node-grpc-server store :host "127.0.0.1" :port 0))
           (node-runtime (gr8s.agent::make-node-runtime (merge-pathnames "worker-a/runtime/" path)
                                                  (make-fake-runtime) nil))
           (control (gr8s.agent::make-node-session-control))
           (agent-thread nil)
           (root (merge-pathnames "volumes/" path)))
      (unwind-protect
           (progn
             (gr8s.agent::start-node-runtime node-runtime)
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                       "worker-a" (merge-pathnames "worker-a/identity.json" path)
                       (lambda (snapshot) (gr8s.agent::reconcile-node-snapshot node-runtime snapshot))
                       :operation-handler
                       (lambda (variant payload emit)
                         (gr8s.agent::dispatch-node-operation node-runtime variant payload emit))
                       :status-provider
                       (lambda ()
                         (make-instance
                          'gr8s.node.v1::node-status
                          :csi-drivers (list (make-instance 'gr8s.node.v1::csi-driver-registration
                                                            :name "csi.example.test" :node-id "n1"))))
                       :reconnect-delay 0.01
                       :control control))
                    :name "gr8s remote reclaim test agent"))
             (is-true (wait-until (lambda () (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "worker-a")))
                                  :timeout 5))
             ;; The agent's driver report arrives through its status messages.
             (is-true (wait-until
                       (lambda ()
                         (handler-case (gr8s.resources::get-core-resource store "csinodes" nil "worker-a")
                           (kubernetes-error () nil)))
                       :timeout 10))
             (gr8s.resources::create-core-resource store "storageclasses" (local-path-class root) nil)
             (gr8s.resources::create-core-resource store "persistentvolumeclaims" (storage-test-claim "claim" :class "fast") "default")
             (gr8s.controllers::schedule-pod store (create-pod store (storage-test-pod "consumer" "claim")))
             (gr8s.resources::reconcile-storage-bindings store)
             (let* ((name (claim-volume-name store "claim"))
                    (backing (format nil "~A~A/" (namestring root) name))
                    (reclaimer (gr8s.resources::make-volume-reclaimer store server)))
               (ensure-directories-exist (format nil "~Ainner/" backing))
               (gr8s.store::remove-pod store "default" "consumer")
               (gr8s.resources::delete-core-resource store "persistentvolumeclaims" "default" "claim")
               (gr8s.resources::reconcile-storage-bindings store)
               (is-true (gr8s.resources::storage-volume-reclaimable-p (gr8s.resources::get-core-resource store "persistentvolumes" nil name)))
               (is-true (wait-until
                         (lambda ()
                           (gr8s.resources::volume-reclaimer-step reclaimer)
                           (handler-case (progn (gr8s.resources::get-core-resource store "persistentvolumes" nil name) nil)
                             (kubernetes-error () t)))
                         :timeout 10))
               (is (null (probe-file backing)))))
        (gr8s.agent::cancel-node-session control)
        (when agent-thread (ignore-errors (bt:join-thread agent-thread)))
        (gr8s.agent::stop-node-runtime node-runtime)
        (gr8s.apiserver::stop-node-grpc-server server)))))


(test ephemeral-claim-templates-accept-the-empty-name-go-sends
  ;; Go sends name "" and generateName "" in a template's metadata; only a real name is refused.
  (flet ((pod-with (metadata)
           (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"p\"},\"spec\":{\"volumes\":[{\"name\":\"scratch\",\"ephemeral\":{\"volumeClaimTemplate\":{\"metadata\":~A,\"spec\":{\"accessModes\":[\"ReadWriteOnce\"],\"resources\":{\"requests\":{\"storage\":\"1Gi\"}}}}}}],\"containers\":[{\"name\":\"c\",\"image\":\"busybox\"}]}}" metadata)))
    (is-true (parse-pod (pod-with "{\"name\":\"\",\"generateName\":\"\",\"labels\":{\"a\":\"b\"}}")))
    (signals kubernetes-error (parse-pod (pod-with "{\"name\":\"fixed\"}")))
    (signals kubernetes-error (parse-pod (pod-with "{\"generateName\":\"fixed-\"}")))))
(test nfs-reclaim-runs-only-on-a-node-its-class-allows
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((class (nfs-class)))
      (setf (gethash "allowedTopologies" class)
            (vector (gr8s.resources::core-object
                     "matchLabelExpressions"
                     (vector (gr8s.resources::core-object "key" "kubernetes.io/hostname" "values" #("worker-b"))))))
      (gr8s.resources::create-core-resource store "storageclasses" class nil))
    (ready-node store "worker-a" "a" "10.64.0.0/20")
    (ready-node store "worker-b" "b" "10.64.16.0/20")
    (let ((volume (gr8s.resources::core-object
                   "spec" (gr8s.resources::core-object
                           "storageClassName" "shared"
                           "nfs" (gr8s.resources::core-object "server" "10.0.0.5" "path" "/export/k8s/pvc-x")))))
      (is (equal "worker-b" (gr8s.model::node-record-name
                             (gr8s.resources::storage-volume-reclaim-node store volume))))
      (is (equal "worker-b" (gr8s.model::node-record-name
                             (gr8s.resources::storage-volume-reclaim-node store volume '("worker-b")))))
      (gr8s.controllers::mark-node-not-ready store "worker-b")
      (is (null (gr8s.resources::storage-volume-reclaim-node store volume))))))
