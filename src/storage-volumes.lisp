;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Resolve authenticated PV/PVC assignments to real host filesystem paths.
;;;; Only a provisioned volume's own directory is created here; nothing is reformatted.
;;;; Source type and binding ownership are checked before CRI receives a mount.

(in-package #:gr8s)

(defun pod-persistent-resource-objects (store pod)
  "Project only a Pod's referenced claims and their exact bound volumes."
  (let ((result nil))
    (dolist (name (storage-pod-claim-names pod))
      (let ((claim (handler-case (get-core-resource store "persistentvolumeclaims" (pod-namespace pod) name)
                     (kubernetes-error (condition) (unless (= 404 (kubernetes-error-status-code condition)) (error condition))))))
        (when claim
          (push claim result)
          (let* ((volume-name (gethash "volumeName" (gethash "spec" claim)))
                 (volume (and volume-name
                              (handler-case (get-core-resource store "persistentvolumes" nil volume-name)
                                (kubernetes-error (condition) (unless (= 404 (kubernetes-error-status-code condition)) (error condition)))))))
            (when (and volume (storage-claim-ref-matches-p volume claim))
              (push volume result)
              (setf result (append (pod-csi-volume-objects store pod volume) result)))))))
    (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
          when (gethash "csi" volume)
            do (let ((driver (optional-core-resource store "csidrivers" nil (gethash "driver" (gethash "csi" volume)))))
                 (when driver (push driver result))))
    result))

(defun optional-core-resource (store resource namespace name)
  "Return one stored object, or NIL only for a genuine NotFound."
  (handler-case (get-core-resource store resource namespace name)
    (kubernetes-error (condition)
      (unless (= 404 (kubernetes-error-status-code condition)) (error condition)))))

(defun pod-csi-volume-objects (store pod volume)
  "Project what an agent needs to publish a bound CSI VOLUME for POD on its node."
  (let ((source (gethash "csi" (gethash "spec" volume))))
    (when source
      (let ((driver (gethash "driver" source)) (handle (gethash "volumeHandle" source)))
        (remove nil
                (append
                 (list (optional-core-resource store "csidrivers" nil driver)
                       (optional-core-resource store "volumeattachments" nil
                                               (volume-attachment-name driver handle (or (pod-node-name pod) ""))))
                 (loop for field in '("nodeStageSecretRef" "nodePublishSecretRef")
                       for reference = (gethash field source)
                       when reference
                         collect (optional-core-resource store "secrets" (gethash "namespace" reference)
                                                         (gethash "name" reference)))))))))

(defun csi-volume-secret-reference-p (secret projected)
  "Return whether a PV among PROJECTED names SECRET as one of its CSI secrets."
  (let ((metadata (gethash "metadata" secret)))
    (some (lambda (object)
            (let ((source (and (equal "PersistentVolume" (gethash "kind" object))
                               (gethash "csi" (gethash "spec" object)))))
              (and source
                   (some (lambda (field)
                           (let ((reference (gethash field source)))
                             (and reference
                                  (equal (gethash "name" metadata) (gethash "name" reference))
                                  (equal (gethash "namespace" metadata) (gethash "namespace" reference)))))
                         '("nodeStageSecretRef" "nodePublishSecretRef")))))
          projected)))

(defun assigned-storage-resource-p (object pod projected)
  "Reject unreferenced claims, forged PV reservations and cross-namespace projection."
  (let* ((metadata (gethash "metadata" object))
         (name (gethash "name" metadata)) (namespace (gethash "namespace" metadata)))
    (cond
      ((equal "CSIDriver" (gethash "kind" object))
       (or (some (lambda (volume)
                   (let ((source (gethash "csi" volume)))
                     (and source (equal name (gethash "driver" source)))))
                 (gethash "volumes" (gethash "spec" (pod-to-object pod)) #()))
           (some (lambda (other)
                   (let ((source (and (equal "PersistentVolume" (gethash "kind" other))
                                      (gethash "csi" (gethash "spec" other)))))
                     (and source (equal name (gethash "driver" source)))))
                 projected)))
      ((equal "VolumeAttachment" (gethash "kind" object))
       (and (equal (pod-node-name pod) (gethash "nodeName" (gethash "spec" object)))
            (some (lambda (other)
                    (and (equal "PersistentVolume" (gethash "kind" other))
                         (equal (storage-resource-name other)
                                (gethash "persistentVolumeName" (gethash "source" (gethash "spec" object))))))
                  projected)))
      ((equal "PersistentVolumeClaim" (gethash "kind" object))
       (and (equal namespace (pod-namespace pod)) (member name (storage-pod-claim-names pod) :test #'equal)))
      ((equal "PersistentVolume" (gethash "kind" object))
       (and (member namespace '(nil "") :test #'equal)
            (some (lambda (claim)
                    (and (equal "PersistentVolumeClaim" (gethash "kind" claim))
                         (equal (pod-namespace pod) (gethash "namespace" (gethash "metadata" claim)))
                         (member (storage-resource-name claim) (storage-pod-claim-names pod) :test #'equal)
                         (equal name (gethash "volumeName" (gethash "spec" claim)))
                         (storage-claim-ref-matches-p object claim))) projected))))))

(defun stat-host-storage-path (path)
  "Return the actual source stat, preserving failures other than a missing path."
  (handler-case (sb-posix:stat path)
    (sb-posix:syscall-error (condition)
      (unless (= sb-posix:enoent (sb-posix:syscall-errno condition)) (error condition)))))

(defun materialize-host-storage-source (source &key local)
  "Validate a real hostPath/local source and create only explicitly requested types."
  (let* ((path (gethash "path" source)) (type (if local "Directory" (gethash "type" source "")))
         (stat nil))
    (unless (storage-absolute-path-p path)
      (error 'runtime-error :message "Volume host path is not a safe absolute path"))
    (setf stat (stat-host-storage-path path))
    (unless stat
      (cond
        ((equal type "DirectoryOrCreate") (ensure-directories-exist (uiop:ensure-directory-pathname path)))
        ((equal type "FileOrCreate")
         ;; Kubernetes FileOrCreate does not create a missing parent directory.
         (handler-case
             (sb-posix:close (sb-posix:open path (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl) #o644))
           (sb-posix:syscall-error (condition)
             (unless (= sb-posix:eexist (sb-posix:syscall-errno condition)) (error condition))))))
      (setf stat (stat-host-storage-path path)))
    ;; An untyped hostPath is unchecked, as in Kubernetes: the CRI runtime creates a missing
    ;; source as a directory, so gr8s still creates only what a type asks for.
    (when (and (null stat) (not local) (equal type ""))
      (return-from materialize-host-storage-source (pathname path)))
    (unless stat (error 'runtime-error :message "Persistent storage source does not exist on this node"))
    (let* ((kind (logand (sb-posix:stat-mode stat) #o170000))
           (expected (cond ((member type '("Directory" "DirectoryOrCreate") :test #'equal) #o040000)
                           ((member type '("File" "FileOrCreate") :test #'equal) #o100000)
                           ((equal type "Socket") #o140000) ((equal type "CharDevice") #o020000)
                           ((equal type "BlockDevice") #o060000))))
      (when (and expected (/= expected kind))
        (error 'runtime-error :message (format nil "Volume source is not the requested hostPath type ~A" type))))
    (pathname path)))

(defun ensure-provisioned-local-directory (path)
  "Create a provisioned directory writable by whichever user a workload runs as."
  (unless (stat-host-storage-path path)
    (ensure-directories-exist (uiop:ensure-directory-pathname path))
    (sb-posix:chmod path #o777)))

(defun claim-owned-by-pod-p (claim pod)
  "Return whether POD owns CLAIM, as a generic ephemeral volume's claim must be."
  (some (lambda (owner) (and (equal "Pod" (gethash "kind" owner)) (equal (pod-uid pod) (gethash "uid" owner))))
        (gethash "ownerReferences" (gethash "metadata" claim) #())))

(defun materialize-persistent-claim-volume (runtime pod source &optional (volume-name (gethash "claimName" source)) require-owner)
  "Resolve a real filesystem PV only after checking exact claim UID ownership."
  (let* ((store (containerd-runtime-resource-store runtime))
         (claim (handler-case (get-core-resource store "persistentvolumeclaims" (pod-namespace pod) (gethash "claimName" source))
                  (kubernetes-error () (error 'runtime-error :message "PersistentVolumeClaim is not available to the assigned Pod"))))
         (bound-name (gethash "volumeName" (gethash "spec" claim)))
         (volume (and bound-name (handler-case (get-core-resource store "persistentvolumes" nil bound-name)
                                   (kubernetes-error () nil)))))
    (when (and require-owner (not (claim-owned-by-pod-p claim pod)))
      (error 'runtime-error :message "An existing PersistentVolumeClaim is not owned by this Pod's ephemeral volume"))
    (unless (and volume (storage-claim-ref-matches-p volume claim)
                 (equal "Bound" (gethash "phase" (gethash "status" claim (core-object))))
                 (equal "Bound" (gethash "phase" (gethash "status" volume (core-object)))))
      (error 'runtime-error :message "PersistentVolumeClaim has no valid bound volume on this node"))
    (unless (and (storage-native-volume-p volume)
                 (not (storage-node-affinity-excludes-node-name-p volume (or (pod-node-name pod) ""))))
      (error 'runtime-error :message "Persistent volume source, mode, mount options or node affinity is unavailable"))
    (let* ((spec (gethash "spec" volume)) (kind (storage-source-kind spec))
           (annotations (gethash "annotations" (gethash "metadata" volume) (core-object)))
           (provisioner (gethash +provisioned-by-annotation+ annotations))
           (claim-readonly (eq t (gethash "readOnly" source))))
      (when (equal kind "csi")
        (multiple-value-bind (path readonly) (materialize-persistent-csi-volume store pod volume-name volume)
          (return-from materialize-persistent-claim-volume (values path (or claim-readonly readonly)))))
      (if (equal kind "nfs")
          (values (materialize-pod-nfs-volume runtime pod volume-name (gethash "nfs" spec)
                                              (gethash "mountOptions" spec)
                                              :share (when (equal provisioner +nfs-provisioner+)
                                                       (gethash +nfs-share-annotation+ annotations)))
                  (or claim-readonly (eq t (gethash "readOnly" (gethash "nfs" spec)))))
          (progn
            (when (equal provisioner +local-path-provisioner+)
              (ensure-provisioned-local-directory (gethash "path" (gethash kind spec))))
            (values (materialize-host-storage-source (gethash kind spec) :local (equal kind "local"))
                    claim-readonly))))))
