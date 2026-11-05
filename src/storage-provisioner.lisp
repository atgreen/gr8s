;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Provision node-local and NFS PersistentVolumes without a helper Pod or image.
;;;; The control plane only writes PV objects and asks an agent to reclaim one; each
;;;; agent creates and deletes the backing directories, since it owns the node.

(in-package #:gr8s)

(defparameter +local-path-provisioner+ "gr8s.io/local-path")
(defparameter +nfs-provisioner+ "gr8s.io/nfs")
(defparameter +no-provisioner+ "kubernetes.io/no-provisioner")
(defparameter +provisioned-by-annotation+ "pv.kubernetes.io/provisioned-by")
(defparameter +nfs-share-annotation+ "gr8s.io/nfs-share")
(defparameter +on-delete-annotation+ "gr8s.io/on-delete")
(defparameter +default-local-storage-path+ "/var/lib/gr8s/storage")
(defparameter +default-storage-class-name+ "local-path")

(defun storage-class-provisioner (class)
  "Return CLASS's provisioner name, or NIL when there is no class."
  (and class (gethash "provisioner" class)))

(defun builtin-provisioner-p (name)
  "Return whether gr8s itself provisions volumes for provisioner NAME."
  (member name (list +local-path-provisioner+ +nfs-provisioner+) :test #'equal))

(defun validate-builtin-storage-class (class)
  "Reject parameters a built-in provisioner would ignore or could not honor."
  (let ((provisioner (gethash "provisioner" class))
        (parameters (gethash "parameters" class (core-object))))
    (when (builtin-provisioner-p provisioner)
      (let ((allowed (if (equal provisioner +nfs-provisioner+)
                         '("server" "share" "onDelete") '("path" "onDelete"))))
        (maphash (lambda (key value)
                   (declare (ignore value))
                   (unless (member key allowed :test #'equal)
                     (core-resource-error 422 "Invalid" "~A does not accept parameter ~S" provisioner key)))
                 parameters))
      (storage-string-enum (gethash "onDelete" parameters "delete") '("delete" "retain" "archive")
                           "parameters.onDelete")
      (if (equal provisioner +nfs-provisioner+)
          (progn
            (validate-nfs-source (core-object "server" (gethash "server" parameters)
                                              "path" (gethash "share" parameters)))
            (validate-nfs-mount-options (gethash "mountOptions" class)))
          (progn
            (when (plusp (length (gethash "mountOptions" class #())))
              (core-resource-error 422 "Invalid" "~A does not support mountOptions" provisioner))
            (unless (storage-absolute-path-p (gethash "path" parameters +default-local-storage-path+))
              (core-resource-error 422 "Invalid" "parameters.path must be absolute without traversal")))))))

(defun storage-claim-provisionable-p (class claim)
  "Return whether CLASS's built-in provisioner can create a volume for CLAIM.
A node-local directory can't serve Pods on several nodes, so it refuses shared modes."
  (let ((spec (gethash "spec" claim)) (provisioner (storage-class-provisioner class)))
    (and (builtin-provisioner-p provisioner)
         (equal "Filesystem" (gethash "volumeMode" spec "Filesystem"))
         (not (gethash "volumeName" spec))
         (not (gethash "selector" spec))
         (not (gethash "dataSource" spec))
         (not (gethash "dataSourceRef" spec))
         (or (equal provisioner +nfs-provisioner+)
             (every (lambda (mode) (member mode '("ReadWriteOnce" "ReadWriteOncePod") :test #'equal))
                    (gethash "accessModes" spec))))))

(defun storage-class-node-bound-p (class)
  "Return whether CLASS creates storage on one node, and so must wait for a consumer's."
  (equal +local-path-provisioner+ (storage-class-provisioner class)))

(defun storage-provisioned-volume-name (claim)
  "Name a claim's volume after its UID, so a repeated pass can't create a second one."
  (format nil "pvc-~A" (gethash "uid" (gethash "metadata" claim))))

(defun storage-node-affinity-for (node-name)
  "Pin a volume to the node holding its directory."
  (core-object
   "required"
   (core-object
    "nodeSelectorTerms"
    (vector (core-object "matchExpressions"
                         (vector (core-object "key" "kubernetes.io/hostname" "operator" "In"
                                              "values" (vector node-name))))))))

(defun storage-provisioned-volume (store class claim node)
  "Build the admitted PV CLASS provides for CLAIM on NODE, or NIL while it can't be made."
  (when (and (storage-claim-provisionable-p class claim)
             (or node (not (storage-class-node-bound-p class))))
    (let* ((name (storage-provisioned-volume-name claim))
           (provisioner (storage-class-provisioner class))
           (parameters (gethash "parameters" class (core-object)))
           (spec (gethash "spec" claim))
           (annotations (core-object +provisioned-by-annotation+ provisioner
                                     +on-delete-annotation+ (gethash "onDelete" parameters "delete")))
           (volume (core-object
                    "capacity" (core-object "storage" (gethash "storage" (gethash "requests" (gethash "resources" spec))))
                    "accessModes" (copy-seq (gethash "accessModes" spec))
                    "storageClassName" (gethash "storageClassName" spec)
                    "volumeMode" "Filesystem"
                    "persistentVolumeReclaimPolicy" (gethash "reclaimPolicy" class "Delete"))))
      (if (equal provisioner +nfs-provisioner+)
          (let ((share (string-right-trim "/" (gethash "share" parameters))))
            (setf (gethash +nfs-share-annotation+ annotations) (if (zerop (length share)) "/" share)
                  (gethash "nfs" volume) (core-object "server" (gethash "server" parameters)
                                                      "path" (format nil "~A/~A" share name)))
            (when (plusp (length (gethash "mountOptions" class #())))
              (setf (gethash "mountOptions" volume) (copy-seq (gethash "mountOptions" class)))))
          (let ((root (string-right-trim "/" (gethash "path" parameters +default-local-storage-path+))))
            (setf (gethash "hostPath" volume) (core-object "path" (format nil "~A/~A" root name)
                                                           "type" "DirectoryOrCreate")
                  (gethash "nodeAffinity" volume) (storage-node-affinity-for (node-record-name node)))))
      (normalize-storage-resource
       "persistentvolumes"
       (core-object "apiVersion" "v1" "kind" "PersistentVolume"
                    "metadata" (core-object "name" name "annotations" annotations)
                    "spec" volume)
       nil name store))))

(defun storage-volume-reclaimable-p (volume)
  "Return whether a released VOLUME is one a built-in provisioner must now delete."
  (let ((metadata (gethash "metadata" volume)) (spec (gethash "spec" volume)))
    (and (equal "Released" (gethash "phase" (gethash "status" volume (core-object))))
         (equal "Delete" (gethash "persistentVolumeReclaimPolicy" spec))
         (builtin-provisioner-p (gethash +provisioned-by-annotation+ (gethash "annotations" metadata (core-object)))))))

(defun storage-volume-reclaim-node (store volume)
  "Choose the node that can reach VOLUME's data: its own, or for NFS any Ready one."
  (flet ((ready (node) (and node (node-record-ready-p node) node)))
    (if (gethash "nfs" (gethash "spec" volume))
        (find-if #'ready (list-nodes store))
        (let ((term (aref (gethash "nodeSelectorTerms"
                                   (gethash "required" (gethash "nodeAffinity" (gethash "spec" volume)))) 0)))
          (ready (get-node store (aref (gethash "values" (aref (gethash "matchExpressions" term) 0)) 0)))))))

(defun reclaim-volume-through-agent (node-server node volume)
  "Ask NODE's agent to remove VOLUME's backing directory, returning only once it has."
  (let* ((operation
           (request-node-operation
            node-server (node-record-name node)
            (make-instance
             'gr8s.node.v1::operation-request
             :operation-id (generate-uid)
             :kind gr8s.node.v1::+operationkind-operation_kind_reclaim_volume+
             :volume-json (trivial-utf-8:string-to-utf-8-bytes
                           (com.inuoe.jzon:stringify volume)))
            :timeout 300))
         (response (pending-node-operation-response operation)))
    (unless (= (slot-value response 'gr8s.node.v1::status)
               gr8s.node.v1::+operationstatus-operation_status_complete+)
      (error 'runtime-error :message (slot-value response 'gr8s.node.v1::error-message)))))

(defparameter +volume-reclaim-retry-seconds+ 30)

(defun reclaim-released-volumes (store node-server attempts)
  "Reclaim each released provisioned volume, then delete its PV; a failure waits and retries.
ATTEMPTS maps volume names to when each was last tried, so a dead node isn't asked constantly."
  (dolist (volume (list-core-resources store "persistentvolumes"))
    (when (storage-volume-reclaimable-p volume)
      (let ((name (storage-resource-name volume)) (now (get-universal-time)))
        (when (>= (- now (gethash name attempts 0)) +volume-reclaim-retry-seconds+)
          (setf (gethash name attempts) now)
          (handler-case
              (let ((node (storage-volume-reclaim-node store volume)))
                (unless node (error 'runtime-error :message "no Ready node can reach this volume"))
                (reclaim-volume-through-agent node-server node volume)
                (delete-core-resource store "persistentvolumes" nil name)
                (remhash name attempts))
            (error (condition)
              (format *error-output* "gr8s PersistentVolume ~A reclaim failed: ~A~%" name condition))))))))

(defun start-volume-reclaimer (store node-server stop-predicate)
  "Reclaim on a separate thread, since deleting a large volume must not stall reconciliation."
  (bt:make-thread
   (lambda ()
     (let ((attempts (make-hash-table :test #'equal)))
       (loop until (funcall stop-predicate)
             do (handler-case (reclaim-released-volumes store node-server attempts)
                  (error (condition)
                    (format *error-output* "gr8s volume reclaimer failed: ~A~%" condition)))
                (sleep 1))))
   :name "gr8s volume reclaimer"))

(defun seed-default-storage-class (store state-directory &key (path +default-local-storage-path+))
  "Create the default class once; a marker keeps an administrator's deletion in force."
  (let ((marker (merge-pathnames "storage/default-class-seeded"
                                 (uiop:ensure-directory-pathname state-directory))))
    (unless (probe-file marker)
      (handler-case
          (create-core-resource
           store "storageclasses"
           (core-object "apiVersion" "storage.k8s.io/v1" "kind" "StorageClass"
                        "metadata" (core-object
                                    "name" +default-storage-class-name+
                                    "annotations" (core-object "storageclass.kubernetes.io/is-default-class" "true"))
                        "provisioner" +local-path-provisioner+
                        "reclaimPolicy" "Delete"
                        "volumeBindingMode" "WaitForFirstConsumer"
                        "allowVolumeExpansion" t
                        "parameters" (core-object "path" path))
           nil)
        (kubernetes-error (condition)
          (unless (= 409 (kubernetes-error-status-code condition)) (error condition))))
      (ensure-directories-exist marker)
      (with-open-file (stream marker :direction :output :if-exists :supersede)
        (write-line "seeded" stream)))))

;;; Agent side

(defun reclaim-volume-directory (directory name on-delete)
  "Apply ON-DELETE to volume NAME, a child of DIRECTORY, so nothing else can be removed."
  (let ((path (format nil "~A/~A" (string-right-trim "/" directory) name)))
    (cond ((equal on-delete "retain") nil)
          ((equal on-delete "archive")
           (when (stat-host-storage-path path)
             (sb-posix:rename path (format nil "~A/archived-~A" (string-right-trim "/" directory) name))))
          (t (safe-delete-volume-tree path)))))

(defun storage-volume-owned-child-name (path name)
  "Return NAME when PATH is exactly a provisioned child called NAME, or signal otherwise.
The path comes from a stored object, so root must not trust it beyond this shape."
  (unless (and (uiop:string-prefix-p "pvc-" name)
               (storage-absolute-path-p path)
               (equal name (subseq path (1+ (or (position #\/ path :from-end t) -1)))))
    (error 'runtime-error :message "Volume path is not a provisioned directory"))
  name)

(defun reclaim-provisioned-volume (state-directory volume)
  "Remove a built-in provisioner's directory, or finish silently if it is already gone."
  (let* ((metadata (gethash "metadata" volume)) (spec (gethash "spec" volume))
         (name (gethash "name" metadata))
         (annotations (gethash "annotations" metadata (core-object)))
         (provisioner (gethash +provisioned-by-annotation+ annotations))
         (on-delete (gethash +on-delete-annotation+ annotations "delete")))
    (cond
      ((equal provisioner +local-path-provisioner+)
       (let ((path (gethash "path" (gethash "hostPath" spec))))
         (storage-volume-owned-child-name path name)
         (reclaim-volume-directory (subseq path 0 (position #\/ path :from-end t)) name on-delete)))
      ((equal provisioner +nfs-provisioner+)
       (let* ((source (gethash "nfs" spec))
              (path (gethash "path" source))
              (share (gethash +nfs-share-annotation+ annotations))
              (tokens (nfs-mount-option-tokens (gethash "mountOptions" spec)))
              (staging (merge-pathnames (format nil "nfs-reclaim/~A/" name)
                                        (uiop:ensure-directory-pathname state-directory)))
              (target (string-right-trim "/" (namestring staging))))
         (storage-volume-owned-child-name path name)
         (unless (equal (string-right-trim "/" share) (subseq path 0 (position #\/ path :from-end t)))
           (error 'runtime-error :message "Volume path is outside its NFS share"))
         (ensure-directories-exist staging)
         (unless (nfs-target-mounted-p target)
           (mount-nfs-filesystem (gethash "server" source) share target tokens :wait 60))
         (unwind-protect (reclaim-volume-directory target name on-delete)
           (unmount-nfs-filesystem target))
         (ignore-errors (sb-posix:rmdir target))))
      (t (error 'runtime-error :message "Volume was not provisioned by gr8s")))))
