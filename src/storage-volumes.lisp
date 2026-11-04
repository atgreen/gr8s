;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Resolve authenticated PV/PVC assignments to real host filesystem paths.
;;;; No backing storage is fabricated, reformatted or deleted by this layer.
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
            (when (and volume (storage-claim-ref-matches-p volume claim)) (push volume result))))))
    result))

(defun assigned-storage-resource-p (object pod projected)
  "Reject unreferenced claims, forged PV reservations and cross-namespace projection."
  (let* ((metadata (gethash "metadata" object))
         (name (gethash "name" metadata)) (namespace (gethash "namespace" metadata)))
    (cond
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
    (unless stat (error 'runtime-error :message "Persistent storage source does not exist on this node"))
    (let* ((kind (logand (sb-posix:stat-mode stat) #o170000))
           (expected (cond ((member type '("Directory" "DirectoryOrCreate") :test #'equal) #o040000)
                           ((member type '("File" "FileOrCreate") :test #'equal) #o100000)
                           ((equal type "Socket") #o140000) ((equal type "CharDevice") #o020000)
                           ((equal type "BlockDevice") #o060000))))
      (when (and expected (/= expected kind))
        (error 'runtime-error :message (format nil "Volume source is not the requested hostPath type ~A" type))))
    (pathname path)))

(defun materialize-persistent-claim-volume (runtime pod source)
  "Resolve a real filesystem PV only after checking exact claim UID ownership."
  (let* ((store (containerd-runtime-resource-store runtime))
         (claim (handler-case (get-core-resource store "persistentvolumeclaims" (pod-namespace pod) (gethash "claimName" source))
                  (kubernetes-error () (error 'runtime-error :message "PersistentVolumeClaim is not available to the assigned Pod"))))
         (volume-name (gethash "volumeName" (gethash "spec" claim)))
         (volume (and volume-name (handler-case (get-core-resource store "persistentvolumes" nil volume-name)
                                   (kubernetes-error () nil)))))
    (unless (and volume (storage-claim-ref-matches-p volume claim)
                 (equal "Bound" (gethash "phase" (gethash "status" claim (core-object))))
                 (equal "Bound" (gethash "phase" (gethash "status" volume (core-object)))))
      (error 'runtime-error :message "PersistentVolumeClaim has no valid bound volume on this node"))
    (unless (and (storage-native-volume-p volume)
                 (storage-node-affinity-matches-p volume (make-node-record :name (or (pod-node-name pod) ""))))
      (error 'runtime-error :message "Persistent volume source, mode, mount options or node affinity is unavailable"))
    (let* ((spec (gethash "spec" volume)) (kind (storage-source-kind spec)))
      (values (materialize-host-storage-source (gethash kind spec) :local (equal kind "local"))
              (eq t (gethash "readOnly" source))))))
