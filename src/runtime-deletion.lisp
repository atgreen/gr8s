;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Run potentially long container shutdown outside the reconciler lock.
;;;; Each UID owns a cancellable job against its persisted absolute deadline.
;;;; Shortening cancels the old job's transports before starting a replacement;
;;;; runtime shutdown joins all owned jobs before containerd is stopped.

(in-package #:gr8s)

(defstruct deletion-job
  deadline thread error done cancelled
  cancellers)

(defstruct deletion-controller
  (jobs (make-hash-table :test #'equal))
  retired
  (lock (bt:make-lock "gr8s runtime deletion jobs")))

(defparameter *runtime-deletion-register-cancel* nil)

(defun register-runtime-deletion-cancel (cancel)
  "Register CANCEL with the current job, rejecting operations from superseded jobs."
  (when *runtime-deletion-register-cancel*
    (funcall *runtime-deletion-register-cancel* cancel)))

(defun cancel-deletion-job-under-lock (job)
  "Mark JOB cancelled under its controller lock and return its cleanup callbacks."
  (setf (deletion-job-cancelled job) t)
  (prog1 (deletion-job-cancellers job)
    (setf (deletion-job-cancellers job) nil)))

(defun run-deletion-cancellers (cancellers)
  "Close transports or processes owned by cancelled deletion operations."
  (dolist (cancel cancellers) (ignore-errors (funcall cancel))))

(defun run-runtime-deletion-job (controller job runtime pod)
  "Execute JOB and publish completion under CONTROLLER's lock."
  (let ((*runtime-deletion-register-cancel*
          (lambda (cancel)
            (bt:with-lock-held ((deletion-controller-lock controller))
              (when (deletion-job-cancelled job)
                (ignore-errors (funcall cancel))
                (error 'runtime-error :message "Pod deletion operation superseded"))
              (push cancel (deletion-job-cancellers job)))))
        (failure nil))
    (handler-case
        (runtime-terminate-pod runtime pod (deletion-job-deadline job))
      (error (condition) (setf failure condition)))
    (bt:with-lock-held ((deletion-controller-lock controller))
      (setf (deletion-job-error job) failure
            (deletion-job-done job) t
            (deletion-job-cancellers job) nil))))

(defun poll-runtime-pod-deletion (controller runtime pod)
  "Start or poll POD's shutdown without blocking the reconciliation worker."
  (let ((uid (pod-uid pod)) (deadline (pod-deletion-deadline pod))
        (cancellers nil) (new-job nil) (failure nil) (done nil))
    (bt:with-lock-held ((deletion-controller-lock controller))
      ;; Finished retired threads no longer need lifecycle tracking.
      (setf (deletion-controller-retired controller)
            (remove-if-not #'bt:thread-alive-p (deletion-controller-retired controller)))
      (let ((job (gethash uid (deletion-controller-jobs controller))))
        (when (and job (< deadline (deletion-job-deadline job)))
          (setf cancellers (cancel-deletion-job-under-lock job))
          (push (deletion-job-thread job) (deletion-controller-retired controller))
          (remhash uid (deletion-controller-jobs controller))
          (setf job nil))
        (cond
          ((and job (deletion-job-done job))
           (setf done t failure (deletion-job-error job))
           (remhash uid (deletion-controller-jobs controller)))
          ((null job)
           (setf new-job (make-deletion-job :deadline deadline)
                 (gethash uid (deletion-controller-jobs controller)) new-job)
           ;; Create under the lock so shutdown never sees an unowned thread.
           (setf (deletion-job-thread new-job)
                 (bt:make-thread
                  (lambda () (run-runtime-deletion-job controller new-job runtime pod))
                  :name (format nil "gr8s stop Pod ~A" uid)))))))
    (run-deletion-cancellers cancellers)
    (when failure
      (error 'runtime-error :message (princ-to-string failure)))
    done))

(defun cancel-runtime-pod-deletion (controller uid)
  "Cancel an existing UID job before an immediate replacement or cleanup."
  (let ((cancellers nil))
    (bt:with-lock-held ((deletion-controller-lock controller))
      (let ((job (gethash uid (deletion-controller-jobs controller))))
        (when job
          (setf cancellers (cancel-deletion-job-under-lock job))
          (push (deletion-job-thread job) (deletion-controller-retired controller))
          (remhash uid (deletion-controller-jobs controller)))))
    (run-deletion-cancellers cancellers)))

(defun stop-runtime-deletion-controller (controller)
  "Cancel and join every job owned by CONTROLLER before its runtime is stopped."
  (let ((threads nil) (cancellers nil))
    (bt:with-lock-held ((deletion-controller-lock controller))
      (maphash (lambda (uid job)
                 (declare (ignore uid))
                 (push (deletion-job-thread job) threads)
                 (setf cancellers (nconc (cancel-deletion-job-under-lock job) cancellers)))
               (deletion-controller-jobs controller))
      (setf threads (append threads (deletion-controller-retired controller))
            (deletion-controller-retired controller) nil)
      (clrhash (deletion-controller-jobs controller)))
    (run-deletion-cancellers cancellers)
    (dolist (thread threads)
      (unless (eq thread (bt:current-thread)) (bt:join-thread thread)))))
