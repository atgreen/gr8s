;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Durable Pod observation checkpoints. These records belong to the store:
;;;; they preserve status and condition history across process restarts without
;;;; depending on the API presentation or reconciliation layers.

(in-package #:gr8s.store)

(defun pod-status-state-path (store uid)
  "Return UID's private status checkpoint pathname in STORE."
  (merge-pathnames (format nil "observations/~A.json" uid) (store-data-path store)))

(defun copy-pod-status-value (value)
  "Copy JSON status data before publishing it outside a store transaction."
  (when value (com.inuoe.jzon:parse (com.inuoe.jzon:stringify value))))

(defun public-pod-status-value (value)
  "Copy API status without private, node-authenticated networking identity."
  (let ((copy (copy-pod-status-value value)))
    (when (hash-table-p copy) (remhash "gr8sServiceTranslation" copy))
    copy))

(defun current-status-pod-p (store pod)
  "Check POD's UID and revision against STORE while its lock is held."
  (let ((current (gethash (pod-key (pod-namespace pod) (pod-name pod))
                          (pod-store-pods store))))
    (and current
         (equal (pod-uid pod) (pod-uid current))
         (equal (pod-resource-version pod) (pod-resource-version current)))))

(defun persist-pod-status-state
    (store pod &key
                 (finalization (gethash (pod-uid pod)
                                        (pod-store-pod-finalization-states store)))
                 (conditions (gethash (pod-uid pod)
                                      (pod-store-pod-condition-histories store)))
                 (status (gethash (pod-uid pod)
                                  (pod-store-pod-observed-statuses store)))
                 (resource-version
                   (gethash (pod-uid pod)
                            (pod-store-pod-observed-resource-versions store)))
                 (client (gethash (pod-uid pod)
                                  (pod-store-pod-client-statuses store))))
  "Atomically checkpoint POD's history and actual observation before updating memory."
  (when (pod-stage-active-p store)
    (stage-pod-write store pod :status t)
    (return-from persist-pod-status-state pod))
  (let* ((target (pod-status-state-path store (pod-uid pod)))
         (temporary
           (make-pathname :name (format nil "~A-~36R" (pathname-name target)
                                        (random (expt 36 10)))
                          :type "tmp" :defaults target))
         (record (make-hash-table :test #'equal)))
    (setf (gethash "formatVersion" record) 1
          (gethash "uid" record) (pod-uid pod)
          (gethash "namespace" record) (pod-namespace pod)
          (gethash "name" record) (pod-name pod)
          (gethash "conditions" record) (or conditions #()))
    (when finalization (setf (gethash "finalization" record) finalization))
    (when client (setf (gethash "clientStatus" record) client))
    (when status
      (setf (gethash "status" record) status
            (gethash "observedResourceVersion" record) resource-version))
    (ensure-directories-exist target)
    (unwind-protect
         (progn
           (with-open-file (stream temporary :direction :output
                                            :if-exists :supersede
                                            :if-does-not-exist :create)
             (com.inuoe.jzon:stringify record :stream stream))
           (uiop:rename-file-overwriting-target temporary target))
      (when (probe-file temporary) (delete-file temporary)))))

(defun terminal-status-p (status)
  "Return true when STATUS is a valid terminal Pod status checkpoint."
  (and (hash-table-p status)
       (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal)))

(defun load-pod-status-state (store)
  "Restore checkpoints only for the exact desired Pod identity still present on disk."
  (dolist (path (directory (merge-pathnames "observations/*.json"
                                            (store-data-path store))))
    (let* ((record (com.inuoe.jzon:parse path))
           (uid (gethash "uid" record))
           (pod (gethash (pod-key (gethash "namespace" record)
                                  (gethash "name" record))
                         (pod-store-pods store))))
      (unless (eql 1 (gethash "formatVersion" record))
        (error "Unsupported Pod observation checkpoint format in ~A" path))
      (if (and pod (equal uid (pod-uid pod)) (equal uid (pathname-name path)))
          (let ((status (gethash "status" record))
                (finalization (gethash "finalization" record))
                (conditions (gethash "conditions" record #()))
                (revision (gethash "observedResourceVersion" record)))
            (unless (and (vectorp conditions) (not (stringp conditions)))
              (error "Invalid Pod condition checkpoint in ~A" path))
            (setf (gethash uid (pod-store-pod-condition-histories store)) conditions)
            (when (gethash "clientStatus" record)
              (setf (gethash uid (pod-store-pod-client-statuses store))
                    (gethash "clientStatus" record)))
            (when finalization
              (unless (and (hash-table-p finalization)
                           (member (gethash "runtimeDeleted" finalization) '(t nil))
                           (or (null (gethash "status" finalization))
                               (terminal-status-p (gethash "status" finalization))))
                (error "Invalid Pod finalization checkpoint in ~A" path))
              (setf (gethash uid (pod-store-pod-finalization-states store)) finalization))
            (when status
              (unless (and (hash-table-p status) (stringp revision))
                (error "Invalid Pod observation checkpoint in ~A" path))
              (setf (gethash uid (pod-store-pod-observed-statuses store)) status
                    (gethash uid (pod-store-pod-observed-resource-versions store)) revision
                    (gethash uid (pod-store-pod-observed-phases store))
                    (gethash "phase" status "Unknown"))))
          (delete-file path))))
  store)
