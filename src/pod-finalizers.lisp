;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Validate Pod finalizers and retain exact-UID runtime deletion evidence while
;;;; API objects wait for their finalizers. Terminal observations and physical
;;;; cleanup completion are durable without acknowledging desired revisions.

(in-package #:gr8s)

(defun pod-finalizers (pod)
  "Read the Pod's validated finalizer names."
  (gethash "finalizers" (gethash "metadata" (pod-to-object pod)) #()))

(defun pod-finalizers-present-p (pod)
  "Distinguish API retention from the independent runtime shutdown intent."
  (plusp (length (pod-finalizers pod))))

(defun validate-pod-finalizers (metadata)
  "Validate qualified finalizer names, treating a JSON null list as empty."
  (let ((value (gethash "finalizers" metadata #())))
    (when (eq value 'null) (setf value #() (gethash "finalizers" metadata) value))
    (unless (and (vectorp value) (not (stringp value)) (every #'core-qualified-key-p value))
      (invalid-pod "metadata.finalizers must be an array of qualified names"))))

(defun validate-pod-finalizer-update (existing replacement)
  "Allow removals, but never add a finalizer after deletion has become irreversible."
  (when (gethash "deletionTimestamp" (gethash "metadata" (pod-to-object existing)))
    (loop for name across (pod-finalizers replacement)
          unless (find name (pod-finalizers existing) :test #'equal)
            do (invalid-pod "metadata.finalizers cannot add names after deletion begins"))))

(defun pod-terminal-status-p (status)
  "Recognize an actual terminal Pod observation without inferring an exit code."
  (and (hash-table-p status) (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal)))

(defun pod-finalization-state (store pod)
  "Read exact-UID finalization evidence without associating it with a newer desired revision."
  (with-store-lock (store)
    (copy-pod-status-value (gethash (pod-uid pod) (pod-store-pod-finalization-states store)))))

(defun save-pod-finalization-state (store pod status deleted)
  "Checkpoint real terminal status and runtime completion before retiring native metadata."
  (with-store-lock (store)
    (when (current-status-pod-p store pod)
      (let* ((old (gethash (pod-uid pod) (pod-store-pod-finalization-states store) (core-object)))
             (state (core-object "runtimeDeleted" (or deleted (gethash "runtimeDeleted" old)))))
        (when (or (pod-terminal-status-p status) (gethash "status" old))
          (setf (gethash "status" state) (copy-pod-status-value (if (pod-terminal-status-p status) status (gethash "status" old)))))
        (unless (equalp state old)
          (persist-pod-status-state store pod :finalization state)
          (setf (gethash (pod-uid pod) (pod-store-pod-finalization-states store)) state))
        state))))

(defun observe-finalizing-pod (reconciler pod)
  "Tolerate a concurrent CRI removal while reading actual terminal observations."
  (handler-case
      (let ((observed (runtime-observe (reconciler-runtime reconciler) (pod-uid pod))))
        (when observed (observed-status observed)))
    (runtime-error () nil)))

(defun converge-finalized-pod-deletion (reconciler pod)
  "Finish runtime shutdown while holding the API Pod until its last finalizer is removed."
  (let* ((store (reconciler-store reconciler)) (runtime (reconciler-runtime reconciler))
         (state (or (pod-finalization-state store pod) (core-object))) (before nil)
         (done (gethash "runtimeDeleted" state)))
    (unless done
      (setf before (observe-finalizing-pod reconciler pod))
      (when (pod-terminal-status-p before) (save-pod-finalization-state store pod before nil))
      (setf done (runtime-delete-pod runtime pod))
      (let ((after (observe-finalizing-pod reconciler pod)))
        (setf state (save-pod-finalization-state store pod (if (pod-terminal-status-p after) after before) done))))
    (cond
      ((and done (not (pod-finalizers-present-p pod)))
       (runtime-forget-pod-finalization runtime (pod-uid pod))
       (remove-pod store (pod-namespace pod) (pod-name pod) :uid (pod-uid pod))
       (pod-status "Succeeded" :reason "Deleted"))
      (t
       (let ((status (or (copy-pod-status-value (gethash "status" state)) before (pod-status "Unknown"))))
         (unless (pod-terminal-status-p status) (setf (gethash "reason" status) "Terminating"))
         status)))))
