;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise pinned retry/reset timing, actual restart accounting, stable Job
;;;; conditions, and atomic durable controller state across reopen/write failure.

(in-package #:gr8s/tests)
(def-suite job-policy :in gr8s)
(in-suite job-policy)

(defun job-test-finish (seconds phase)
  "Construct an explicit terminal observation with its real test finish timestamp."
  (gr8s.resources::core-object "phase" phase "containerStatuses"
                    (vector (gr8s.resources::core-object "state" (gr8s.resources::core-object "terminated"
                                          (gr8s.resources::core-object "finishedAt" (gr8s.store::current-timestamp seconds)))))))

(test job-retries-use-pinned-exponential-delay-and-success-finish-order-reset
  (let* ((now 4000000000)
         (first (gr8s.controllers::next-job-backoff-state nil nil (list (job-test-finish now "Failed")))))
    (is (= (+ now 10) (gr8s.controllers::job-backoff-until first)))
    (let ((second (gr8s.controllers::next-job-backoff-state first nil (list (job-test-finish (+ now 10) "Failed")))))
      (is (= (+ now 30) (gr8s.controllers::job-backoff-until second))))
    (let ((reset (gr8s.controllers::next-job-backoff-state first (list (job-test-finish (+ now 20) "Succeeded")) nil)))
      (is (= 0 (gr8s.controllers::job-backoff-until reset))))
    (let ((mixed (gr8s.controllers::next-job-backoff-state first (list (job-test-finish (+ now 20) "Succeeded"))
                  (list (job-test-finish (+ now 10) "Failed") (job-test-finish (+ now 30) "Failed")))))
      (is (= 1 (gethash "failuresAfterLastSuccess" mixed)))
      (is (= (+ now 40) (gr8s.controllers::job-backoff-until mixed))))
    (let ((capped (gr8s.resources::core-object "failuresAfterLastSuccess" 100 "lastFailureTime" now)))
      (is (= (+ now 360) (gr8s.controllers::job-backoff-until capped))))))

(test job-onfailure-limit-uses-actual-current-pending-running-init-and-main-restarts
  (let* ((pod (parse-pod *valid-pod-json*))
         (status (gr8s.resources::core-object "phase" "Running" "containerStatuses"
                                   (vector (gr8s.resources::core-object "restartCount" 2))
                                   "initContainerStatuses" (vector (gr8s.resources::core-object "restartCount" 1)))))
    (is (= 3 (gr8s.controllers::job-onfailure-restarts (list (cons pod status)))))
    (setf (gethash "phase" status) "Failed")
    (is (= 0 (gr8s.controllers::job-onfailure-restarts (list (cons pod status)))))
    (setf (gethash "phase" status) "Pending"
          (gethash "deletionTimestamp" (gethash "metadata" (pod-to-object pod))) (gr8s.store::current-timestamp))
    (is (= 0 (gr8s.controllers::job-onfailure-restarts (list (cons pod status)))))))

(test job-condition-clock-does-not-advance-or-claim-success-without-the-goal
  (let* ((now 4000000000) (gr8s.controllers::*job-clock* (lambda () now))
         (status (gr8s.resources::core-object))
         (spec (gr8s.resources::core-object "completions" 2)))
    (is-false (gr8s.controllers::job-success-goal-met-p spec 0 0))
    (is-false (gr8s.controllers::job-success-goal-met-p spec 1 0))
    (is-true (gr8s.controllers::job-success-goal-met-p spec 2 0))
    (is-false (gr8s.controllers::job-terminal-condition status))
    (gr8s.controllers::set-job-condition status "Suspended" "True" "JobSuspended" "Actual suspension")
    (let ((before (gr8s.resources::copy-core-object status)))
      (incf now 50)
      (gr8s.controllers::set-job-condition status "Suspended" "True" "JobSuspended" "Actual suspension")
      (is (gr8s.resources::workload-equal-p before status)))
    (is-false (gr8s.controllers::job-terminal-condition status))
    (is-false (gr8s.controllers::job-success-goal-met-p (gr8s.resources::core-object) 0 0))
    (is-false (gr8s.controllers::job-success-goal-met-p (gr8s.resources::core-object) 1 1))
    (is-true (gr8s.controllers::job-success-goal-met-p (gr8s.resources::core-object) 1 0))))

(test job-controller-retry-checkpoint-is-atomic-with-the-core-state-and-survives-reopen
  (with-temporary-store (store directory)
    (let ((states (gr8s.resources::core-object "owner-uid" (gr8s.resources::core-object "failuresAfterLastSuccess" 2 "lastFailureTime" 4000000000))))
      (gr8s.resources::commit-core-resources store (gr8s.resources::copy-core-resource-index store) 1 :job-controller-states states)
      (let* ((before (uiop:read-file-string (gr8s.resources::core-resource-state-path store)))
             (persist (symbol-function 'gr8s.security::write-private-text-atomically))
             (next (gr8s.resources::copy-core-object states)))
        (setf (gethash "failuresAfterLastSuccess" (gethash "owner-uid" next)) 3)
        ;; A failed checkpoint ...
        (setf (gr8s.store::pod-store-core-checkpoint-needed store) t)
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.security::write-private-text-atomically)
                     (lambda (&rest arguments) (declare (ignore arguments)) (error "Simulated full atomic snapshot failure")))
               (signals error
                 (gr8s.resources::commit-core-resources store (gr8s.resources::copy-core-resource-index store) 2 :job-controller-states next))
               (is (= 2 (gethash "failuresAfterLastSuccess" (gethash "owner-uid" (gr8s.store::pod-store-job-controller-states store)))))
               (is (= 1 (gr8s.store::pod-store-resource-revision store))))
          (setf (symbol-function 'gr8s.security::write-private-text-atomically) persist))
        (is (equal before (uiop:read-file-string (gr8s.resources::core-resource-state-path store))))
        ;; ... and a failed journal append change neither memory nor the durable state.
        (setf (gr8s.store::pod-store-core-checkpoint-needed store) nil)
        (ensure-directories-exist (uiop:ensure-directory-pathname (gr8s.resources::core-journal-path store)))
        (signals error
          (gr8s.resources::commit-core-resources store (gr8s.resources::copy-core-resource-index store) 2 :job-controller-states next))
        (is (= 2 (gethash "failuresAfterLastSuccess" (gethash "owner-uid" (gr8s.store::pod-store-job-controller-states store)))))
        (is (= 1 (gr8s.store::pod-store-resource-revision store)))
        (uiop:delete-directory-tree (uiop:ensure-directory-pathname (gr8s.resources::core-journal-path store)) :validate t)
        (is (equal before (uiop:read-file-string (gr8s.resources::core-resource-state-path store))))
        (is (null (probe-file (gr8s.resources::core-journal-path store)))))
      (let* ((reopened (open-store directory))
             (record (gethash "owner-uid" (gr8s.store::pod-store-job-controller-states reopened))))
        (is (= 2 (gethash "failuresAfterLastSuccess" record)))
        (is (= 4000000000 (gethash "lastFailureTime" record)))))))

(test job-finish-time-distinguishes-missing-state-from-invalid-state
  (let ((gr8s.controllers::*job-clock* (lambda () 4000000000)))
    (is (= 4000000000
           (gr8s.controllers::job-pod-finished-time
            (gr8s.resources::core-object "containerStatuses"
                                         (vector (gr8s.resources::core-object "name" "main"))))))
    (dolist (invalid-state (list nil 'null 42))
      (signals type-error
        (gr8s.controllers::job-pod-finished-time
         (gr8s.resources::core-object "containerStatuses"
                                      (vector (gr8s.resources::core-object "state" invalid-state))))))))
