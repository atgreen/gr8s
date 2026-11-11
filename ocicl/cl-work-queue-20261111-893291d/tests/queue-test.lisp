;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-work-queue/tests)
(def-suite work-queues :in cl-work-queue)
(in-suite work-queues)

(defun wait-until (predicate &key (timeout 2))
  (loop with deadline = (+ (get-internal-real-time)
                           (* timeout internal-time-units-per-second))
        until (funcall predicate)
        when (>= (get-internal-real-time) deadline) do (return nil)
        do (sleep 0.005)
        finally (return t)))

(defmacro with-test-gate ((open-gate wait-gate) &body body)
  "Bind OPEN-GATE to release jobs blocked in WAIT-GATE, opening it however BODY exits."
  (let ((open (gensym "OPEN")))
    `(let ((,open nil))
       (flet ((,open-gate () (setf ,open t))
              (,wait-gate () (loop until ,open do (sleep 0.005))))
         (declare (ignorable #',open-gate #',wait-gate))
         (unwind-protect (progn ,@body)
           (setf ,open t))))))

(test lanes-never-exceed-their-limit-and-run-every-job
  (let* ((queue (cl-work-queue:make-work-queue :lane-limit (constantly 4)))
         (lock (bt:make-lock)) (running 0) (peak 0) (finished 0))
    (dotimes (index 300)
      (cl-work-queue:work-queue-submit
       queue index "local"
       (lambda ()
         (bt:with-lock-held (lock)
           (incf running)
           (setf peak (max peak running)))
         (sleep 0.001)
         (bt:with-lock-held (lock)
           (decf running)
           (incf finished)))))
    (is-true (wait-until (lambda () (bt:with-lock-held (lock) (= 300 finished))) :timeout 30))
    (is (<= peak 4))
    (is-true (wait-until (lambda () (zerop (cl-work-queue:work-queue-running-workers queue))) :timeout 5))
    ;; An idle lane leaves nothing behind.
    (is (zerop (hash-table-count (cl-work-queue::work-queue-lanes queue))))))

(test a-request-for-a-running-key-joins-it
  (with-test-gate (release wait)
    (let* ((queue (cl-work-queue:make-work-queue)) (runs 0) (answers nil) (lock (bt:make-lock)))
      (flet ((submit (tag)
               (cl-work-queue:work-queue-submit
                queue "pvc-1" "local"
                (lambda () (incf runs) (wait) :done)
                :on-done (lambda (value condition)
                           (declare (ignore condition))
                           (bt:with-lock-held (lock) (push (cons tag value) answers))))))
        (is-true (submit :first))
        (is-true (wait-until (lambda () (= 1 runs))))
        (is-false (submit :second))
        (is-true (cl-work-queue:work-queue-active-p queue "pvc-1"))
        (release)
        (is-true (wait-until (lambda () (bt:with-lock-held (lock) (= 2 (length answers))))))
        (is (= 1 runs))
        (is (equal '((:first . :done) (:second . :done)) (reverse answers)))
        (is-true (wait-until (lambda () (not (cl-work-queue:work-queue-active-p queue "pvc-1")))))
        ;; A finished key can run again.
        (is-true (submit :third))
        (is-true (wait-until (lambda () (= 2 runs))))))))

(test a-stuck-lane-holds-up-only-itself
  (with-test-gate (release wait)
    (let* ((queue (cl-work-queue:make-work-queue :lane-limit (constantly 2))) (done nil))
      (dotimes (index 5)
        (cl-work-queue:work-queue-submit queue (format nil "dead-~D" index) "nfs/dead" #'wait))
      (cl-work-queue:work-queue-submit queue "alive" "local" (lambda () (setf done t)))
      (is-true (wait-until (lambda () done)))
      ;; Two workers are stuck and three jobs wait behind them; no more threads appear.
      (is (= 2 (cl-work-queue:work-queue-running-workers queue)))
      (is-true (cl-work-queue:work-queue-active-p queue "dead-4"))
      (release)
      (is-true (wait-until (lambda () (not (cl-work-queue:work-queue-active-p queue "dead-4"))))))))

(test job-failures-reach-the-waiter-and-keep-the-worker
  (let* ((queue (cl-work-queue:make-work-queue)) (seen nil) (ran nil)
         (*error-output* (make-broadcast-stream)))
    (cl-work-queue:work-queue-submit queue "a" "local"
                             (lambda () (error "disk on fire"))
                             :on-done (lambda (value condition)
                                        (declare (ignore value))
                                        (setf seen condition)
                                        ;; A broken waiter must not cost the lane its worker.
                                        (error "waiter failed")))
    (cl-work-queue:work-queue-submit queue "b" "local" (lambda () (setf ran t)))
    (is-true (wait-until (lambda () (and seen ran))))
    (is (typep seen 'error))))

(test stopping-fails-waiting-jobs-and-refuses-new-ones
  (with-test-gate (release wait)
    (let* ((queue (cl-work-queue:make-work-queue)) (started nil) (ran nil) (seen nil))
      (cl-work-queue:work-queue-submit queue "running" "local" (lambda () (setf started t) (wait)))
      (is-true (wait-until (lambda () started)))
      (cl-work-queue:work-queue-submit queue "waiting" "local" (lambda () (setf ran t))
                               :on-done (lambda (value condition)
                                          (declare (ignore value))
                                          (setf seen condition)))
      (cl-work-queue:work-queue-stop queue)
      (is (typep seen 'cl-work-queue:work-queue-stopped))
      (signals cl-work-queue:work-queue-stopped (cl-work-queue:work-queue-submit queue "late" "local" (constantly nil)))
      (release)
      (is-true (wait-until (lambda () (zerop (cl-work-queue:work-queue-running-workers queue)))))
      (is (null ran)))))

(test wait-joins-running-workers-with-an-optional-timeout
  (with-test-gate (release wait)
    (let ((queue (cl-work-queue:make-work-queue))
          (started nil))
      (cl-work-queue:work-queue-submit
       queue "running" "local" (lambda () (setf started t) (wait)))
      (is-true (wait-until (lambda () started)))
      (is-false (cl-work-queue:work-queue-wait queue :timeout 0.01))
      (release)
      (is-true (cl-work-queue:work-queue-wait queue :timeout 2)))))

(test backoff-doubles-to-its-maximum-and-clears
  (let ((backoff (cl-work-queue:make-retry-backoff)))
    (is-true (cl-work-queue:retry-backoff-ready-p backoff "a" 100))
    (is (= 1 (cl-work-queue:retry-backoff-failed backoff "a" 100)))
    (is-false (cl-work-queue:retry-backoff-ready-p backoff "a" 100))
    (is-true (cl-work-queue:retry-backoff-ready-p backoff "a" 101))
    (is (equal '(2 4 8 16 32 64 128 256 300 300)
               (loop repeat 10 collect (cl-work-queue:retry-backoff-failed backoff "a" 101))))
    (cl-work-queue:retry-backoff-clear backoff "a")
    (is-true (cl-work-queue:retry-backoff-ready-p backoff "a" 101))
    (is (= 1 (cl-work-queue:retry-backoff-failed backoff "a" 101)))))

