;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise real Job-owned Pod creation/adoption and durable terminal UID
;;;; handoff before finalizer removal, including write failure, process reopen,
;;;; name reuse and preservation of user finalizers/healthy runtime identities.

(in-package #:gr8s/tests)
(def-suite job-controller :in gr8s)
(in-suite job-controller)

(defmacro with-job-controller-fixture ((store runtime reconciler directory) &body body)
  "Enable the private Job type only inside focused controller tests before public API wiring."
  `(let ((gr8s.resources::*stored-resource-types*
           (cons '("jobs" "Job" "batch/v1" t) gr8s.resources::*stored-resource-types*)))
     (with-temporary-store (,store ,directory)
       (let* ((,runtime (make-fake-runtime)) (,reconciler (make-reconciler ,store ,runtime)))
         ,@body))))

(defun create-controller-job (store &optional (name "work") (restart-policy "OnFailure"))
  "Create through production admission with a user finalizer on the Pod template."
  (let* ((input (batch-test-job name)) (template (gethash "template" (gethash "spec" input)))
         (metadata (gethash "metadata" template)))
    (setf (gethash "finalizers" metadata) #("example.com/user")
          (gethash "restartPolicy" (gethash "spec" template)) restart-policy)
    (gr8s.resources::create-core-resource store "jobs" input "alpha")))

(defun observe-job-pod-terminal (reconciler runtime pod phase exit-code finish-time)
  "Provide a concrete runtime exit observation without mutating the Job's controller status."
  (gr8s.kubelet::reconcile-pod reconciler (pod-namespace pod) (pod-name pod))
  (let* ((actual (gr8s.runtime::runtime-observe runtime (pod-uid pod)))
         (status (job-test-finish finish-time phase))
         (container (aref (gethash "containerStatuses" status) 0)))
    (setf (gethash "exitCode" (gethash "terminated" (gethash "state" container))) exit-code
          (gethash "name" container) "web"
          (gethash "containerID" container) (concatenate 'string "fake://" (pod-uid pod))
          (gr8s.runtime::runtime-pod-phase actual) phase (gr8s.runtime::runtime-pod-status actual) status)
    actual))

(defun current-job-status (store)
  "Read the actual durable Job status used by the controller tests."
  (gethash "status" (gr8s.resources::get-core-resource store "jobs" "alpha" "work")))

(defun current-job-pod (store pod)
  "Read the same named dependent and let each test verify its exact identity."
  (get-pod store (pod-namespace pod) (pod-name pod)))

(test job-creates-real-unique-uid-owned-tracked-pods
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignore directory))
    (let* ((job (create-controller-job store))
           (first (gr8s.controllers::create-job-pod store job))
           (second (gr8s.controllers::create-job-pod store job))
           (reference (gr8s.controllers::workload-controller-reference (pod-to-object first))))
      (is (= 2 (length (list-pods store "alpha"))))
      (is-false (equal (pod-uid first) (pod-uid second)))
      (is-true (gr8s.controllers::workload-owned-p (pod-to-object first) job))
      (is-true (gethash "blockOwnerDeletion" reference))
      (is-true (gr8s.controllers::job-pod-tracked-p first))
      (is (find "example.com/user" (gr8s.kubelet::pod-finalizers first) :test #'equal))
      (reconcile-all reconciler)
      (is (= 2 (gr8s.runtime::fake-runtime-ensure-count runtime))))))

(test job-terminal-accounting-does-not-release-tracking-before-durable-write
  (with-job-controller-fixture (store runtime reconciler directory)
    (let* ((job (create-controller-job store))
           (pod (gr8s.controllers::create-job-pod store job)))
      (gr8s.controllers::flush-job-terminal-accounting reconciler job (gr8s.controllers::job-observations reconciler job))
      (is (= 0 (gethash "succeeded" (current-job-status store) 0)))
      (is-false (gr8s.controllers::job-terminal-condition (current-job-status store)))
      (observe-job-pod-terminal reconciler runtime pod "Succeeded" 0 4000000000)
      (let ((terminal (gr8s.controllers::job-observations reconciler job)))
        (with-failing-core-writes ("Simulated Job checkpoint failure")
          (signals error (gr8s.controllers::flush-job-terminal-accounting reconciler job terminal))
          (is-true (gr8s.controllers::job-pod-tracked-p (current-job-pod store pod))))
        (gr8s.controllers::flush-job-terminal-accounting reconciler job terminal)
        (gr8s.controllers::flush-job-terminal-accounting reconciler job terminal)
        (let ((status (current-job-status store)) (retained (current-job-pod store pod)))
          (is (= 1 (gethash "succeeded" status)))
          (is (null (gr8s.controllers::job-uncounted-uids status "succeeded")))
          (is-false (gr8s.controllers::job-pod-tracked-p retained))
          (is (equalp #("example.com/user") (gr8s.kubelet::pod-finalizers retained))))
        (let* ((reopened (open-store directory))
               (fresh (make-reconciler reopened runtime))
               (current (gr8s.resources::get-core-resource reopened "jobs" "alpha" "work")))
          (gr8s.controllers::flush-job-terminal-accounting fresh current (gr8s.controllers::job-observations fresh current))
          (is (= 1 (gethash "succeeded" (current-job-status reopened)))))))))

(test job-reopen-recovers-a-committed-uncounted-failure-before-finalizer-removal
  (with-job-controller-fixture (store runtime reconciler directory)
    ;; Only Never leaves a Pod Failed; OnFailure restarts it in place.
    (let* ((job (create-controller-job store "work" "Never")) (pod (gr8s.controllers::create-job-pod store job)))
      (observe-job-pod-terminal reconciler runtime pod "Failed" 17 4000000000)
      (gr8s.controllers::account-job-observations reconciler job (gr8s.controllers::job-observations reconciler job))
      (let ((status (current-job-status store)))
        (is (= 0 (gethash "failed" status)))
        (is (equal (list (pod-uid pod)) (gr8s.controllers::job-uncounted-uids status "failed"))))
      (is-true (gr8s.controllers::job-pod-tracked-p (current-job-pod store pod)))
      (let* ((reopened (open-store directory))
             (fresh (make-reconciler reopened runtime))
             (current (gr8s.resources::get-core-resource reopened "jobs" "alpha" "work"))
             (uid (gethash "uid" (gethash "metadata" current))))
        (gr8s.controllers::flush-job-terminal-accounting fresh current (gr8s.controllers::job-observations fresh current))
        (let ((status (current-job-status reopened))
              (backoff (gethash uid (gr8s.store::pod-store-job-controller-states reopened))))
          (is (= 1 (gethash "failed" status)))
          (is (null (gr8s.controllers::job-uncounted-uids status "failed")))
          (is (= 1 (gethash "failuresAfterLastSuccess" backoff))))))))

(test stale-job-name-reuse-cannot-create-adopt-or-release-a-replacement-owner
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignore runtime directory))
    (let* ((old (create-controller-job store))
           (old-uid (gethash "uid" (gethash "metadata" old)))
           (pod (gr8s.controllers::create-job-pod store old)))
      (gr8s.resources::delete-core-resource store "jobs" "alpha" "work")
      (let* ((replacement (create-controller-job store))
             (new-uid (gethash "uid" (gethash "metadata" replacement))))
        (is-false (equal old-uid new-uid))
        (is-false (gr8s.controllers::create-job-pod store old))
        (is (null (gr8s.controllers::job-owned-pods reconciler replacement :claim t)))
        (is-false (gr8s.controllers::remove-accounted-job-finalizer store old pod :deleting t))
        (is-true (gr8s.controllers::job-pod-tracked-p (current-job-pod store pod)))))))

(defun job-with-spec (store &rest fields)
  "Create a Never-restart Job whose spec additionally has the FIELDS plist."
  (let* ((input (batch-test-job "work")) (spec (gethash "spec" input)))
    (setf (gethash "restartPolicy" (gethash "spec" (gethash "template" spec))) "Never")
    (loop for (key value) on fields by #'cddr do (setf (gethash key spec) value))
    (gr8s.resources::create-core-resource store "jobs" input "alpha")))

(defun job-now (store)
  "Read the current durable Job."
  (gr8s.resources::get-core-resource store "jobs" "alpha" "work"))

(defun finish-job-pods (reconciler runtime store phase &optional (exit-code 0))
  "Report every undeleted Pod of the namespace as having reached the terminal PHASE."
  (dolist (pod (list-pods store "alpha"))
    (unless (gr8s.kubelet::deletion-requested-p pod)
      (observe-job-pod-terminal reconciler runtime pod phase exit-code 3000000000))))

(test reconcile-creates-parallel-pods-and-reports-active
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable runtime directory))
    (job-with-spec store "parallelism" 2 "completions" 3)
    (gr8s.controllers::reconcile-jobs reconciler)
    (is (= 2 (length (list-pods store "alpha"))))
    (let ((status (gethash "status" (job-now store))))
      (is (= 2 (gethash "active" status)))
      (is (stringp (gethash "startTime" status)))
      (is-false (gr8s.controllers::job-terminal-condition status)))
    ;; Another pass with both Pods running changes nothing.
    (gr8s.controllers::reconcile-jobs reconciler)
    (is (= 2 (length (list-pods store "alpha"))))))

(test successful-pods-complete-the-job-and-release-tracking
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (job-with-spec store)
    (gr8s.controllers::reconcile-jobs reconciler)
    (finish-job-pods reconciler runtime store "Succeeded")
    (gr8s.controllers::reconcile-jobs reconciler)
    (gr8s.controllers::reconcile-jobs reconciler)
    (let ((status (gethash "status" (job-now store))))
      (is (= 1 (gethash "succeeded" status)))
      (is (= 0 (gethash "active" status)))
      (is (gr8s.controllers::job-condition-true-p status "Complete"))
      (is (gr8s.controllers::job-condition-true-p status "SuccessCriteriaMet"))
      (is (stringp (gethash "completionTime" status))))
    (dolist (pod (list-pods store "alpha"))
      (is-false (gr8s.controllers::job-pod-tracked-p pod)))
    ;; A finished Job never creates more Pods.
    (let ((count (length (list-pods store "alpha"))))
      (gr8s.controllers::reconcile-jobs reconciler)
      (is (= count (length (list-pods store "alpha")))))))

(test exceeding-the-backoff-limit-fails-the-job
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (job-with-spec store "backoffLimit" 0)
    (gr8s.controllers::reconcile-jobs reconciler)
    (finish-job-pods reconciler runtime store "Failed" 3)
    (gr8s.controllers::reconcile-jobs reconciler)
    (gr8s.controllers::reconcile-jobs reconciler)
    (let* ((status (gethash "status" (job-now store)))
           (condition (gr8s.controllers::job-terminal-condition status)))
      (is (equal "Failed" (gethash "type" condition)))
      (is (equal "BackoffLimitExceeded" (gethash "reason" condition)))
      (is (= 1 (gethash "failed" status))))))

(test failures-retry-only-after-the-backoff-delay
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    ;; The Pods finish at 3000000000, so the ten-second delay is still running.
    (let* ((now 3000000001) (gr8s.controllers::*job-clock* (lambda () now)))
      (job-with-spec store "backoffLimit" 5)
      (gr8s.controllers::reconcile-jobs reconciler)
      (finish-job-pods reconciler runtime store "Failed" 3)
      (gr8s.controllers::reconcile-jobs reconciler)
      (is (= 1 (length (list-pods store "alpha"))))
      (incf now 11)
      (gr8s.controllers::reconcile-jobs reconciler)
      (is (= 2 (length (list-pods store "alpha"))))
      (is-false (gr8s.controllers::job-terminal-condition (gethash "status" (job-now store)))))))

(test deadline-fails-the-job-and-removes-active-pods
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable runtime directory))
    (let* ((now 3000000000) (gr8s.controllers::*job-clock* (lambda () now)))
      (job-with-spec store "activeDeadlineSeconds" 30)
      (gr8s.controllers::reconcile-jobs reconciler)
      (is (= 1 (length (list-pods store "alpha"))))
      (incf now 31)
      (gr8s.controllers::reconcile-jobs reconciler)
      ;; The outcome is fixed at once, but Failed waits for the Pod to stop.
      (let ((status (gethash "status" (job-now store))))
        (is (equal "DeadlineExceeded" (gethash "reason" (gr8s.controllers::job-finishing-condition status))))
        (is-false (gr8s.controllers::job-terminal-condition status)))
      (gr8s.controllers::reconcile-jobs reconciler)
      (gr8s.controllers::reconcile-jobs reconciler)
      (let ((status (gethash "status" (job-now store))))
        (is (equal "DeadlineExceeded" (gethash "reason" (gr8s.controllers::job-terminal-condition status))))
        (is (= 1 (gethash "failed" status))))
      (dolist (pod (list-pods store "alpha"))
        (is-false (gr8s.controllers::job-pod-tracked-p pod))))))

(test suspension-removes-pods-and-resuming-recreates-them
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable runtime directory))
    (job-with-spec store "suspend" t)
    (gr8s.controllers::reconcile-jobs reconciler)
    (is (null (list-pods store "alpha")))
    (is (gr8s.controllers::job-condition-true-p (gethash "status" (job-now store)) "Suspended"))
    (gr8s.resources::update-core-resource store "jobs" "alpha" "work"
                                (lambda (current) (setf (gethash "suspend" (gethash "spec" current)) nil) current))
    (gr8s.controllers::reconcile-jobs reconciler)
    (is (= 1 (length (list-pods store "alpha"))))
    (is-false (gr8s.controllers::job-condition-true-p (gethash "status" (job-now store)) "Suspended"))))

(test deleted-jobs-release-their-pods-for-collection
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable runtime directory))
    (job-with-spec store)
    (gr8s.controllers::reconcile-jobs reconciler)
    (let ((pod (first (list-pods store "alpha"))))
      (is-true (gr8s.controllers::job-pod-tracked-p pod))
      (gr8s.resources::delete-core-resource store "jobs" "alpha" "work")
      (gr8s.controllers::reconcile-jobs reconciler)
      (is-false (gr8s.controllers::job-pod-tracked-p (get-pod store "alpha" (pod-name pod)))))))

(test status-writes-apply-metadata-but-never-the-spec
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable runtime reconciler directory))
    (let* ((job (job-with-spec store "parallelism" 2))
           (input (gr8s.resources::copy-core-object job))
           (metadata (gethash "metadata" input)))
      (setf (gethash "annotations" metadata) (gr8s.resources::core-object "patched" "true")
            (gethash "parallelism" (gethash "spec" input)) 9
            (gethash "status" input) (gr8s.resources::core-object "startTime" "2026-01-01T00:00:00Z"))
      (gr8s.apiserver::workload-update-status-request store "jobs" "alpha" "work" input nil)
      (let ((current (job-now store)))
        (is (equal "true" (gethash "patched" (gethash "annotations" (gethash "metadata" current)))))
        (is (equal "2026-01-01T00:00:00Z" (gethash "startTime" (gethash "status" current))))
        (is (= 2 (gethash "parallelism" (gethash "spec" current))))))))

(test job-collections-can-be-deleted-by-selector
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable runtime reconciler directory))
    (job-with-spec store)
    (is (gr8s.resources::batch-resource-p "jobs"))
    (is (= 1 (length (gr8s.resources::list-core-resources store "jobs" "alpha"))))))

