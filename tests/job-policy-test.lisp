;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise pinned retry/reset timing, actual restart accounting, stable Job
;;;; conditions, and atomic durable controller state across reopen/write failure.

(in-package #:gr8s/tests)
(def-suite job-policy :in gr8s)
(in-suite job-policy)

(defun job-test-finish (seconds phase)
  "Construct an explicit terminal observation with its real test finish timestamp."
  (gr8s::core-object "phase" phase "containerStatuses"
                    (vector (gr8s::core-object "state" (gr8s::core-object "terminated"
                                          (gr8s::core-object "finishedAt" (gr8s::current-timestamp seconds)))))))

(test job-retries-use-pinned-exponential-delay-and-success-finish-order-reset
  (let* ((now 4000000000)
         (first (gr8s::next-job-backoff-state nil nil (list (job-test-finish now "Failed")))))
    (is (= (+ now 10) (gr8s::job-backoff-until first)))
    (let ((second (gr8s::next-job-backoff-state first nil (list (job-test-finish (+ now 10) "Failed")))))
      (is (= (+ now 30) (gr8s::job-backoff-until second))))
    (let ((reset (gr8s::next-job-backoff-state first (list (job-test-finish (+ now 20) "Succeeded")) nil)))
      (is (= 0 (gr8s::job-backoff-until reset))))
    (let ((mixed (gr8s::next-job-backoff-state first (list (job-test-finish (+ now 20) "Succeeded"))
                  (list (job-test-finish (+ now 10) "Failed") (job-test-finish (+ now 30) "Failed")))))
      (is (= 1 (gethash "failuresAfterLastSuccess" mixed)))
      (is (= (+ now 40) (gr8s::job-backoff-until mixed))))
    (let ((capped (gr8s::core-object "failuresAfterLastSuccess" 100 "lastFailureTime" now)))
      (is (= (+ now 360) (gr8s::job-backoff-until capped))))))

(test job-onfailure-limit-uses-actual-current-pending-running-init-and-main-restarts
  (let* ((pod (parse-pod *valid-pod-json*))
         (status (gr8s::core-object "phase" "Running" "containerStatuses"
                                   (vector (gr8s::core-object "restartCount" 2))
                                   "initContainerStatuses" (vector (gr8s::core-object "restartCount" 1)))))
    (is (= 3 (gr8s::job-onfailure-restarts (list (cons pod status)))))
    (setf (gethash "phase" status) "Failed")
    (is (= 0 (gr8s::job-onfailure-restarts (list (cons pod status)))))
    (setf (gethash "phase" status) "Pending"
          (gethash "deletionTimestamp" (gethash "metadata" (pod-to-object pod))) (gr8s::current-timestamp))
    (is (= 0 (gr8s::job-onfailure-restarts (list (cons pod status)))))))

(test job-condition-clock-does-not-advance-or-claim-success-without-the-goal
  (let* ((now 4000000000) (gr8s::*job-clock* (lambda () now))
         (status (gr8s::core-object))
         (spec (gr8s::core-object "completions" 2)))
    (is-false (gr8s::job-success-goal-met-p spec 0 0))
    (is-false (gr8s::job-success-goal-met-p spec 1 0))
    (is-true (gr8s::job-success-goal-met-p spec 2 0))
    (is-false (gr8s::job-terminal-condition status))
    (gr8s::set-job-condition status "Suspended" "True" "JobSuspended" "Actual suspension")
    (let ((before (gr8s::copy-core-object status)))
      (incf now 50)
      (gr8s::set-job-condition status "Suspended" "True" "JobSuspended" "Actual suspension")
      (is (gr8s::workload-equal-p before status)))
    (is-false (gr8s::job-terminal-condition status))
    (is-false (gr8s::job-success-goal-met-p (gr8s::core-object) 0 0))
    (is-false (gr8s::job-success-goal-met-p (gr8s::core-object) 1 1))
    (is-true (gr8s::job-success-goal-met-p (gr8s::core-object) 1 0))))

(test job-controller-retry-checkpoint-is-atomic-with-the-core-state-and-survives-reopen
  (with-temporary-store (store directory)
    (let ((states (gr8s::core-object "owner-uid" (gr8s::core-object "failuresAfterLastSuccess" 2 "lastFailureTime" 4000000000))))
      (gr8s::commit-core-resources store (gr8s::copy-core-resource-index store) 1 :job-controller-states states)
      (let* ((before (uiop:read-file-string (gr8s::core-resource-state-path store)))
             (persist (symbol-function 'gr8s::write-private-text-atomically))
             (next (gr8s::copy-core-object states)))
        (setf (gethash "failuresAfterLastSuccess" (gethash "owner-uid" next)) 3)
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s::write-private-text-atomically)
                     (lambda (&rest arguments) (declare (ignore arguments)) (error "Simulated full atomic snapshot failure")))
               (signals error
                 (gr8s::commit-core-resources store (gr8s::copy-core-resource-index store) 2 :job-controller-states next))
               (is (= 2 (gethash "failuresAfterLastSuccess" (gethash "owner-uid" (gr8s::pod-store-job-controller-states store)))))
               (is (= 1 (gr8s::pod-store-resource-revision store))))
          (setf (symbol-function 'gr8s::write-private-text-atomically) persist))
        (is (equal before (uiop:read-file-string (gr8s::core-resource-state-path store)))))
      (let* ((reopened (open-store directory))
             (record (gethash "owner-uid" (gr8s::pod-store-job-controller-states reopened))))
        (is (= 2 (gethash "failuresAfterLastSuccess" record)))
        (is (= 4000000000 (gethash "lastFailureTime" record)))))))
