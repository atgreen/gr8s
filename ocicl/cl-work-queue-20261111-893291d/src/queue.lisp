;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-work-queue)

(define-condition work-queue-stopped (error)
  ((name :initarg :name :reader work-queue-stopped-name))
  (:report (lambda (condition stream)
             (format stream "The ~A queue has stopped"
                     (work-queue-stopped-name condition)))))

(defstruct (work-lane (:constructor make-work-lane (name limit)))
  name limit (running 0) (pending nil))

(defstruct (work-job (:constructor make-work-job (key lane thunk callbacks)))
  key lane thunk callbacks)

(defstruct (work-queue (:constructor %make-work-queue (name lane-limit)))
  name
  lane-limit
  (lanes (make-hash-table :test #'equal))
  (jobs (make-hash-table :test #'equal))
  (lock (bt:make-lock "work queue"))
  (stopped nil))

(defun make-work-queue (&key (name "work") (lane-limit (constantly 1)))
  "Make a queue; LANE-LIMIT maps a lane's name to how many workers it may run at once."
  (%make-work-queue name lane-limit))

(defun run-work-job-callbacks (queue callbacks value condition)
  "Tell each waiter the result; one waiter's failure must not cost the lane its worker."
  (dolist (callback callbacks)
    (handler-case (funcall callback value condition)
      (error (failure)
        (format *error-output* "~A queue callback failed: ~A~%" (work-queue-name queue) failure)))))

(defun run-work-lane (queue lane)
  "Run LANE's pending jobs until none remain, then give up this worker's slot."
  (loop
    (let ((job (bt:with-lock-held ((work-queue-lock queue))
                 (or (pop (work-lane-pending lane))
                     (progn
                       (decf (work-lane-running lane))
                       ;; Lane names may describe transient external resources.
                       (when (zerop (work-lane-running lane))
                         (remhash (work-lane-name lane) (work-queue-lanes queue)))
                       (return))))))
      (multiple-value-bind (value condition)
          (handler-case (values (funcall (work-job-thunk job)) nil)
            (error (failure) (values nil failure)))
        ;; Removing the job and taking its waiters are one step, so a late request
        ;; either joins this result or starts a fresh job, and is never lost.
        (let ((callbacks (bt:with-lock-held ((work-queue-lock queue))
                           (remhash (work-job-key job) (work-queue-jobs queue))
                           (work-job-callbacks job))))
          (run-work-job-callbacks queue callbacks value condition))))))

(defun work-queue-submit (queue key lane-name thunk &key on-done)
  "Run THUNK in LANE-NAME unless KEY is already queued or running, in which case join it.
ON-DONE receives the value and any error, on a worker thread. Returns true for a new job."
  (bt:with-lock-held ((work-queue-lock queue))
    (when (work-queue-stopped queue)
      (error 'work-queue-stopped :name (work-queue-name queue)))
    (let ((existing (gethash key (work-queue-jobs queue))))
      (when existing
        (when on-done
          (setf (work-job-callbacks existing) (append (work-job-callbacks existing) (list on-done))))
        (return-from work-queue-submit nil)))
    (let* ((lane (or (gethash lane-name (work-queue-lanes queue))
                     (setf (gethash lane-name (work-queue-lanes queue))
                           (make-work-lane lane-name (funcall (work-queue-lane-limit queue) lane-name)))))
           (job (make-work-job key lane thunk (when on-done (list on-done)))))
      (setf (gethash key (work-queue-jobs queue)) job
            (work-lane-pending lane) (append (work-lane-pending lane) (list job)))
      (when (< (work-lane-running lane) (work-lane-limit lane))
        (incf (work-lane-running lane))
        (bt:make-thread (lambda () (run-work-lane queue lane))
                        :name (format nil "work queue ~A ~A" (work-queue-name queue) lane-name)))
      t)))

(defun work-queue-active-p (queue key)
  "Return whether a job for KEY is queued or running."
  (bt:with-lock-held ((work-queue-lock queue))
    (not (null (gethash key (work-queue-jobs queue))))))

(defun work-queue-running-workers (queue)
  "Return how many workers QUEUE has across all of its lanes."
  (bt:with-lock-held ((work-queue-lock queue))
    (loop for lane being the hash-values of (work-queue-lanes queue)
          sum (work-lane-running lane))))

(defun work-queue-wait (queue &key timeout)
  "Wait until QUEUE has no running workers. Return NIL if TIMEOUT seconds elapse."
  (let ((deadline (and timeout
                       (+ (get-internal-real-time)
                          (* timeout internal-time-units-per-second)))))
    (loop
      (when (zerop (work-queue-running-workers queue))
        (return t))
      (when (and deadline (>= (get-internal-real-time) deadline))
        (return nil))
      (sleep 0.005))))

(defun work-queue-stop (queue)
  "Refuse new work and fail what hasn't started. Running jobs are left to finish,
since they may be stuck in calls that nothing can interrupt."
  (let ((abandoned
          (bt:with-lock-held ((work-queue-lock queue))
            (setf (work-queue-stopped queue) t)
            (loop for lane being the hash-values of (work-queue-lanes queue)
                  nconc (loop for job in (shiftf (work-lane-pending lane) nil)
                              do (remhash (work-job-key job) (work-queue-jobs queue))
                              append (work-job-callbacks job))))))
    (run-work-job-callbacks queue abandoned nil
                            (make-condition 'work-queue-stopped :name (work-queue-name queue)))))

;;; Retry pacing

(defstruct (retry-backoff (:constructor make-retry-backoff (&key (initial 1) (maximum 300))))
  initial maximum (entries (make-hash-table :test #'equal)))

(defun retry-backoff-ready-p (backoff key now)
  "Return whether KEY may be tried at time NOW."
  (let ((entry (gethash key (retry-backoff-entries backoff))))
    (or (null entry) (>= now (cdr entry)))))

(defun retry-backoff-failed (backoff key now)
  "Record a failure of KEY at NOW, doubling its delay up to the maximum; return the delay."
  (let* ((entry (gethash key (retry-backoff-entries backoff)))
         (delay (if entry
                    (min (retry-backoff-maximum backoff) (* 2 (car entry)))
                    (retry-backoff-initial backoff))))
    (setf (gethash key (retry-backoff-entries backoff)) (cons delay (+ now delay)))
    delay))

(defun retry-backoff-clear (backoff key)
  "Forget KEY's failures after it succeeds."
  (remhash key (retry-backoff-entries backoff)))

