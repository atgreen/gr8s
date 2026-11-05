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

(defparameter +local-reclaim-lane+ "local")

(defun volume-reclaim-lane (volume)
  "Name the lane VOLUME's deletion runs in: one for local disks and one per NFS server,
so a dead server can only hold up volumes on that server."
  (let ((source (gethash "nfs" (gethash "spec" volume))))
    (if source
        (format nil "nfs/~A" (gethash "server" source))
        +local-reclaim-lane+)))

(defun volume-reclaim-lane-limit (lane)
  "Return how many deletions one agent runs at once in LANE."
  (if (equal lane +local-reclaim-lane+) 4 2))

(defun make-volume-reclaim-queue ()
  "Make an agent's queue of volume deletions."
  (make-work-queue :name "volume reclaim" :lane-limit #'volume-reclaim-lane-limit))

(defparameter +volume-reclaim-dispatch-limit+ 8
  "How many requests per node and lane may be outstanding, so an agent's backlog stays small.")

(defstruct (volume-reclaim-request (:constructor make-volume-reclaim-request (operation node lane)))
  operation node lane)

(defstruct (volume-reclaimer (:constructor make-volume-reclaimer (store node-server)))
  store
  node-server
  (in-flight (make-hash-table :test #'equal))
  (backoff (make-retry-backoff)))

(defun volume-reclaim-failed (reclaimer name now message)
  "Record a failed attempt, and report it with when the next one will be."
  (format *error-output* "gr8s PersistentVolume ~A reclaim failed, retrying in ~Ds: ~A~%"
          name (retry-backoff-failed (volume-reclaimer-backoff reclaimer) name now) message))

(defun volume-reclaim-operation-failure (operation)
  "Return why a finished OPERATION failed, or NIL if the agent removed the volume."
  (let ((response (pending-node-operation-response operation)))
    (cond ((pending-node-operation-error operation))
          ((null response) "The agent gave no response")
          ((/= (slot-value response 'gr8s.node.v1::status)
               gr8s.node.v1::+operationstatus-operation_status_complete+)
           (slot-value response 'gr8s.node.v1::error-message)))))

(defun collect-finished-volume-reclaims (reclaimer now)
  "Delete the PV of each volume its agent has removed, and pace retries of the rest."
  (let ((in-flight (volume-reclaimer-in-flight reclaimer))
        (store (volume-reclaimer-store reclaimer)))
    (dolist (name (loop for name being the hash-keys of in-flight using (hash-value request)
                        when (pending-node-operation-done-p (volume-reclaim-request-operation request))
                          collect name))
      (let* ((operation (volume-reclaim-request-operation (gethash name in-flight)))
             (failure (volume-reclaim-operation-failure operation)))
        (release-node-operation (volume-reclaimer-node-server reclaimer) operation)
        (remhash name in-flight)
        (if failure
            (volume-reclaim-failed reclaimer name now failure)
            (handler-case
                (progn
                  (optional-delete-persistent-volume store name)
                  (retry-backoff-clear (volume-reclaimer-backoff reclaimer) name))
              (error (condition)
                (volume-reclaim-failed reclaimer name now condition))))))))

(defun optional-delete-persistent-volume (store name)
  "Delete a PV an administrator may already have removed."
  (handler-case (delete-core-resource store "persistentvolumes" nil name)
    (kubernetes-error (condition)
      (unless (= 404 (kubernetes-error-status-code condition)) (error condition)))))

(defun dispatch-volume-reclaim (reclaimer node volume)
  "Ask NODE's agent to remove VOLUME's directory, without waiting for it to finish."
  (make-volume-reclaim-request
   (queue-node-operation
    (volume-reclaimer-node-server reclaimer) (node-record-name node)
    (make-instance
     'gr8s.node.v1::operation-request
     :operation-id (generate-uid)
     :kind gr8s.node.v1::+operationkind-operation_kind_reclaim_volume+
     :volume-json (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify volume))))
   (node-record-name node)
   (volume-reclaim-lane volume)))

(defun dispatch-released-volumes (reclaimer now)
  "Request reclaim of each released volume that isn't running, backing off or over its limit.
A request stays in flight until its agent answers or its session ends, however long
that takes, so a slow deletion is never requested again on top of itself."
  (let ((in-flight (volume-reclaimer-in-flight reclaimer))
        (outstanding (make-hash-table :test #'equal)))
    (loop for request being the hash-values of in-flight
          do (incf (gethash (list (volume-reclaim-request-node request) (volume-reclaim-request-lane request))
                            outstanding 0)))
    (dolist (volume (list-core-resources (volume-reclaimer-store reclaimer) "persistentvolumes"))
      (let ((name (storage-resource-name volume)))
        (when (and (storage-volume-reclaimable-p volume)
                   (not (gethash name in-flight))
                   (retry-backoff-ready-p (volume-reclaimer-backoff reclaimer) name now))
          (handler-case
              (let ((node (storage-volume-reclaim-node (volume-reclaimer-store reclaimer) volume)))
                (unless node (error 'runtime-error :message "no Ready node can reach this volume"))
                (let ((slot (list (node-record-name node) (volume-reclaim-lane volume))))
                  (when (< (gethash slot outstanding 0) +volume-reclaim-dispatch-limit+)
                    (setf (gethash name in-flight) (dispatch-volume-reclaim reclaimer node volume))
                    (incf (gethash slot outstanding 0)))))
            (error (condition)
              (volume-reclaim-failed reclaimer name now condition))))))))

(defun volume-reclaimer-step (reclaimer &optional (now (get-universal-time)))
  "Run one pass: settle finished requests, then send what can now be sent."
  (collect-finished-volume-reclaims reclaimer now)
  (dispatch-released-volumes reclaimer now))

(defun start-volume-reclaimer (store node-server stop-predicate)
  "Run the reclaimer on one thread that never waits on an agent, so one slow volume holds up no other."
  (bt:make-thread
   (lambda ()
     (let ((reclaimer (make-volume-reclaimer store node-server)))
       (loop until (funcall stop-predicate)
             do (handler-case (volume-reclaimer-step reclaimer)
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
