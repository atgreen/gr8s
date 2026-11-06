;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise Indexed Jobs through the production controller and a fake runtime:
;;;; index identity on Pods, per-index retries and failure sets, podFailurePolicy
;;;; actions, successPolicy rules, delayed terminal conditions and TTL collection.

(in-package #:gr8s/tests)
(def-suite job-indexed :in gr8s)
(in-suite job-indexed)

(defun reconcile-until-settled (reconciler &optional (passes 4))
  "Run enough controller passes for accounting, finalizer release and conditions to settle."
  (loop repeat passes do (gr8s::reconcile-jobs reconciler)))

(defun indexed-test-pods (store index)
  "List the Job Pods working on completion INDEX."
  (remove index (list-pods store "alpha") :test-not #'eql :key #'gr8s::job-pod-completion-index))

(defun finish-indexed-pod (reconciler runtime store index phase &optional (exit-code 0))
  "Report the live Pods of INDEX as having reached the terminal PHASE."
  (dolist (pod (indexed-test-pods store index))
    (unless (or (gr8s::deletion-requested-p pod) (not (gr8s::job-pod-tracked-p pod)))
      (observe-job-pod-terminal reconciler runtime pod phase exit-code 3000000000))))

(defun job-terminal-of (store)
  "Return the current Job's Complete or Failed condition."
  (gr8s::job-terminal-condition (gethash "status" (job-now store))))

(defun exit-code-policy (action &rest codes)
  "Build a podFailurePolicy applying ACTION to exit CODES."
  (gr8s::core-object "rules"
    (vector (gr8s::core-object "action" action
              "onExitCodes" (gr8s::core-object "operator" "In" "values" (coerce codes 'vector))))))

(test job-index-sets-round-trip-in-kubernetes-form
  (is (equal "1,3" (gr8s::format-job-indexes (gr8s::parse-job-indexes "1,3"))))
  (is (equal "0,1" (gr8s::format-job-indexes (gr8s::parse-job-indexes "0-1"))))
  (is (equal "0-2,5" (gr8s::format-job-indexes (gr8s::parse-job-indexes "2,0,1,5"))))
  (is (equal "" (gr8s::format-job-indexes nil)))
  (is (= 4 (gr8s::job-indexes-total (gr8s::parse-job-indexes "1,3-5"))))
  (is (equal '((0 . 2)) (gr8s::job-indexes-add 1 '((0 . 0) (2 . 2)))))
  (is (eq :invalid (nth-value 1 (gr8s::parse-job-indexes "4" 4))))
  (is (eq :invalid (nth-value 1 (gr8s::parse-job-indexes "3-1"))))
  (is (eq :invalid (nth-value 1 (gr8s::parse-job-indexes "a,1")))))

(test indexed-pods-carry-index-identity-and-hostname
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable runtime directory))
    (job-with-spec store "completionMode" "Indexed" "completions" 3 "parallelism" 2)
    (gr8s::reconcile-jobs reconciler)
    (is (= 2 (length (list-pods store "alpha"))))
    (let* ((pod (first (indexed-test-pods store 1))) (object (pod-to-object pod))
           (metadata (gethash "metadata" object)) (spec (gethash "spec" object))
           (env (gethash "env" (aref (gethash "containers" spec) 0)))
           (variable (find "JOB_COMPLETION_INDEX" env :test #'equal :key (lambda (entry) (gethash "name" entry)))))
      (is (equal "1" (gethash gr8s::+job-completion-index-key+ (gethash "annotations" metadata))))
      (is (equal "1" (gethash gr8s::+job-completion-index-key+ (gethash "labels" metadata))))
      (is (equal "work-1" (gethash "hostname" spec)))
      (is (uiop:string-prefix-p "work-1-" (pod-name pod)))
      (is (equal "metadata.labels['batch.kubernetes.io/job-completion-index']"
                 (gethash "fieldPath" (gethash "fieldRef" (gethash "valueFrom" variable))))))
    (is (null (indexed-test-pods store 2)))))

(test indexed-completion-tracks-each-index-once
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (job-with-spec store "completionMode" "Indexed" "completions" 3 "parallelism" 2)
    (gr8s::reconcile-jobs reconciler)
    (finish-indexed-pod reconciler runtime store 1 "Succeeded")
    (reconcile-until-settled reconciler)
    (let ((status (gethash "status" (job-now store))))
      (is (equal "1" (gethash "completedIndexes" status)))
      (is (= 1 (gethash "succeeded" status)))
      (is-false (gr8s::job-terminal-condition status)))
    ;; Index 2 starts next, and index 1 is not retried.
    (is (= 1 (length (indexed-test-pods store 2))))
    (is (= 1 (length (indexed-test-pods store 1))))
    (finish-indexed-pod reconciler runtime store 0 "Succeeded")
    (finish-indexed-pod reconciler runtime store 2 "Succeeded")
    (reconcile-until-settled reconciler)
    (let ((status (gethash "status" (job-now store))))
      (is (equal "0-2" (gethash "completedIndexes" status)))
      (is (= 3 (gethash "succeeded" status)))
      (is (equal "CompletionsReached" (gethash "reason" (gr8s::job-terminal-condition status))))
      (is (= 0 (gethash "active" status))))
    (dolist (pod (list-pods store "alpha")) (is-false (gr8s::job-pod-tracked-p pod)))))

(test per-index-limit-retries-one-index-and-records-the-failure-count
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (let* ((now 3000000001) (gr8s::*job-clock* (lambda () now)))
      (job-with-spec store "completionMode" "Indexed" "completions" 2 "parallelism" 2 "backoffLimitPerIndex" 1)
      (is (= 2147483647 (gethash "backoffLimit" (gethash "spec" (job-now store)))))
      (gr8s::reconcile-jobs reconciler)
      (flet ((failure-count (pod)
               (gethash gr8s::+job-index-failure-count-key+
                        (gethash "annotations" (gethash "metadata" (pod-to-object pod))))))
        (is (equal "0" (failure-count (first (indexed-test-pods store 1)))))
        (finish-indexed-pod reconciler runtime store 1 "Failed" 1)
        (reconcile-until-settled reconciler)
        ;; The retry waits out that index's own delay; index 0 keeps running.
        (is (= 1 (length (indexed-test-pods store 1))))
        (incf now 11)
        (reconcile-until-settled reconciler)
        (let ((pods (indexed-test-pods store 1)))
          (is (= 2 (length pods)))
          (is (equal '("0" "1") (sort (mapcar #'failure-count pods) #'string<)))))
      (finish-indexed-pod reconciler runtime store 1 "Failed" 1)
      (reconcile-until-settled reconciler)
      (let ((status (gethash "status" (job-now store))))
        (is (equal "1" (gethash "failedIndexes" status)))
        (is (= 2 (gethash "failed" status)))
        (is-false (gr8s::job-terminal-condition status)))
      ;; Other indexes still run, and the Job fails once all are decided.
      (finish-indexed-pod reconciler runtime store 0 "Succeeded")
      (reconcile-until-settled reconciler)
      (let* ((status (gethash "status" (job-now store))) (condition (gr8s::job-terminal-condition status)))
        (is (equal "Failed" (gethash "type" condition)))
        (is (equal "FailedIndexes" (gethash "reason" condition)))
        (is (equal "0" (gethash "completedIndexes" status)))
        (is (= 1 (gethash "succeeded" status)))))))

(test max-failed-indexes-stops-the-job-early
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (job-with-spec store "completionMode" "Indexed" "completions" 4 "parallelism" 1
                   "backoffLimitPerIndex" 0 "maxFailedIndexes" 0)
    (gr8s::reconcile-jobs reconciler)
    (finish-indexed-pod reconciler runtime store 0 "Failed" 1)
    (reconcile-until-settled reconciler)
    (let* ((status (gethash "status" (job-now store))) (condition (gr8s::job-terminal-condition status)))
      (is (equal "MaxFailedIndexesExceeded" (gethash "reason" condition)))
      (is (equal "0" (gethash "failedIndexes" status)))
      (is (= 1 (gethash "failed" status))))
    (is (= 1 (length (list-pods store "alpha"))))))

(test fail-job-rule-fails-the-job-and-terminal-condition-waits-for-pods
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (job-with-spec store "parallelism" 2 "completions" 4 "podFailurePolicy" (exit-code-policy "FailJob" 1))
    (is (equal "Failed" (gethash "podReplacementPolicy" (gethash "spec" (job-now store)))))
    (gr8s::reconcile-jobs reconciler)
    (let ((pods (list-pods store "alpha")))
      (observe-job-pod-terminal reconciler runtime (first pods) "Failed" 1 3000000000))
    (gr8s::reconcile-jobs reconciler)
    (let ((status (gethash "status" (job-now store))))
      (is (equal "PodFailurePolicy" (gethash "reason" (gr8s::job-finishing-condition status))))
      ;; The other Pod is still stopping, so Failed is not yet declared.
      (is-false (gr8s::job-terminal-condition status))
      (is (plusp (gethash "terminating" status))))
    (reconcile-until-settled reconciler)
    (let ((condition (job-terminal-of store)))
      (is (equal "Failed" (gethash "type" condition)))
      (is (equal "PodFailurePolicy" (gethash "reason" condition)))
      (is (search "matching FailJob rule at index 0" (gethash "message" condition))))))

(test exit-code-rules-skip-other-codes-and-honor-not-in
  (let* ((pod (parse-pod *valid-pod-json*))
         (status (gr8s::core-object "phase" "Failed" "containerStatuses"
                   (vector (gr8s::core-object "name" "web" "state"
                             (gr8s::core-object "terminated" (gr8s::core-object "exitCode" 42))))))
         (spec (gr8s::core-object "podFailurePolicy" (exit-code-policy "FailJob" 1))))
    (is-false (gr8s::job-pod-failure-action spec pod status))
    (setf (gethash "operator" (gethash "onExitCodes" (aref (gethash "rules" (gethash "podFailurePolicy" spec)) 0))) "NotIn")
    (is (equal "FailJob" (gr8s::job-pod-failure-action spec pod status)))))

(test ignore-rule-on-disruption-replaces-the-pod-without-counting
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (job-with-spec store "completionMode" "Indexed" "completions" 1 "parallelism" 1 "backoffLimit" 0
                   "podFailurePolicy"
                   (gr8s::core-object "rules"
                     (vector (gr8s::core-object "action" "Ignore" "onPodConditions"
                               (vector (gr8s::core-object "type" "DisruptionTarget" "status" "True"))))))
    (gr8s::reconcile-jobs reconciler)
    (let ((pod (first (indexed-test-pods store 0))))
      (gr8s::mark-pod-disruption-target store pod)
      (gr8s::delete-reconciled-pod reconciler "alpha" (pod-name pod) :uid (pod-uid pod))
      (reconcile-until-settled reconciler)
      (let ((status (gethash "status" (job-now store))))
        (is (= 0 (gethash "failed" status 0)))
        (is-false (gr8s::job-terminal-condition status)))
      (is-false (find (pod-uid pod) (list-pods store "alpha") :key #'pod-uid :test #'equal))
      (is (= 1 (length (indexed-test-pods store 0)))))))

(test fail-index-rule-fails-the-index-without-a-retry
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (job-with-spec store "completionMode" "Indexed" "completions" 2 "parallelism" 2 "backoffLimitPerIndex" 1
                   "podFailurePolicy" (exit-code-policy "FailIndex" 1))
    (gr8s::reconcile-jobs reconciler)
    (finish-indexed-pod reconciler runtime store 0 "Succeeded")
    (finish-indexed-pod reconciler runtime store 1 "Failed" 1)
    (reconcile-until-settled reconciler)
    (let ((status (gethash "status" (job-now store))))
      (is (equal "1" (gethash "failedIndexes" status)))
      (is (equal "0" (gethash "completedIndexes" status)))
      (is (= 1 (gethash "failed" status)))
      (is (= 1 (gethash "succeeded" status)))
      (is (equal "FailedIndexes" (gethash "reason" (gr8s::job-terminal-condition status)))))
    (is (= 2 (length (list-pods store "alpha"))))))

(test success-policy-completes-the-job-with-pending-indexes
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (job-with-spec store "completionMode" "Indexed" "completions" 5 "parallelism" 2
                   "successPolicy" (gr8s::core-object "rules" (vector (gr8s::core-object "succeededIndexes" "0"))))
    (gr8s::reconcile-jobs reconciler)
    (finish-indexed-pod reconciler runtime store 1 "Succeeded")
    (reconcile-until-settled reconciler)
    (is-false (job-terminal-of store))
    (finish-indexed-pod reconciler runtime store 0 "Succeeded")
    (reconcile-until-settled reconciler 6)
    (let* ((status (gethash "status" (job-now store))) (condition (gr8s::job-terminal-condition status)))
      (is (equal "Complete" (gethash "type" condition)))
      (is (equal "SuccessPolicy" (gethash "reason" condition)))
      (is (equal "SuccessPolicy" (gethash "reason" (gr8s::job-finishing-condition status))))
      (is (= 0 (gethash "active" status)))
      (is (= 0 (gethash "terminating" status))))))

(test success-policy-rule-matching
  (flet ((message (rule completed)
           (gr8s::job-success-policy-message
            (gr8s::core-object "completions" 5 "successPolicy" (gr8s::core-object "rules" (vector rule)))
            (gr8s::parse-job-indexes completed))))
    (is (message (gr8s::core-object "succeededCount" 1) "3"))
    (is-false (message (gr8s::core-object "succeededCount" 2) "3"))
    (is (message (gr8s::core-object "succeededIndexes" "1-2") "1,2,4"))
    (is-false (message (gr8s::core-object "succeededIndexes" "1-2") "1,4"))
    (is (message (gr8s::core-object "succeededIndexes" "1-3" "succeededCount" 2) "1,3"))
    (is-false (message (gr8s::core-object "succeededCount" 1) ""))))

(test job-admission-refuses-policies-it-cannot-honor
  (flet ((refused (&rest fields)
           (let* ((input (batch-test-job "work")) (spec (gethash "spec" input)))
             (setf (gethash "restartPolicy" (gethash "spec" (gethash "template" spec))) "Never")
             (loop for (key value) on fields by #'cddr do (setf (gethash key spec) value))
             (signals gr8s::kubernetes-error (normalize-test-job input)))))
    (refused "completionMode" "Other")
    (refused "completionMode" "Indexed" "parallelism" 1)
    (refused "backoffLimitPerIndex" 1)
    (refused "completions" 2 "maxFailedIndexes" 1)
    (refused "completionMode" "Indexed" "completions" 2 "backoffLimitPerIndex" 1 "maxFailedIndexes" 3)
    (refused "successPolicy" (gr8s::core-object "rules" (vector (gr8s::core-object "succeededCount" 1))))
    (refused "completionMode" "Indexed" "completions" 2
             "successPolicy" (gr8s::core-object "rules" (vector (gr8s::core-object "succeededIndexes" "2"))))
    (refused "completionMode" "Indexed" "completions" 2
             "successPolicy" (gr8s::core-object "rules" (vector (gr8s::core-object))))
    (refused "podFailurePolicy" (exit-code-policy "FailIndex" 1))
    (refused "podFailurePolicy" (exit-code-policy "Other" 1))
    (refused "podFailurePolicy" (exit-code-policy "FailJob" 0))
    (refused "podFailurePolicy" (exit-code-policy "FailJob" 2 1))
    (refused "podFailurePolicy" (exit-code-policy "FailJob" 1) "podReplacementPolicy" "TerminatingOrFailed")
    (refused "podFailurePolicy" (gr8s::core-object "rules" (vector (gr8s::core-object "action" "FailJob")))))
  ;; A name that cannot form every index's hostname, and a policy with restarts.
  (let ((input (batch-test-job (make-string 62 :initial-element #\a))))
    (setf (gethash "completionMode" (gethash "spec" input)) "Indexed"
          (gethash "completions" (gethash "spec" input)) 1)
    (signals gr8s::kubernetes-error (normalize-test-job input)))
  (let ((input (batch-test-job "work")))
    (setf (gethash "podFailurePolicy" (gethash "spec" input)) (exit-code-policy "FailJob" 1))
    (signals gr8s::kubernetes-error (normalize-test-job input))))

(test ttl-after-finished-deletes-the-job
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (let* ((now 3000000000) (gr8s::*job-clock* (lambda () now)))
      (job-with-spec store "ttlSecondsAfterFinished" 60)
      (gr8s::reconcile-jobs reconciler)
      (finish-job-pods reconciler runtime store "Succeeded")
      (reconcile-until-settled reconciler)
      (is (equal "Complete" (gethash "type" (job-terminal-of store))))
      (incf now 61)
      ;; The clock used for condition timestamps fixed when the Job finished.
      (reconcile-until-settled reconciler)
      (let ((job (ignore-errors (job-now store))))
        (is (or (null job) (gethash "deletionTimestamp" (gethash "metadata" job))))))))

(test job-managed-elsewhere-gets-no-pods-or-status-from-this-controller
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable runtime directory))
    (job-with-spec store "managedBy" "example.com/custom-job-controller")
    (reconcile-until-settled reconciler)
    (is (null (list-pods store "alpha")))
    (is (zerop (hash-table-count (gethash "status" (job-now store))))))
  (dolist (manager '("no-domain" "a/b/c" "/x" ""))
    (let ((input (batch-test-job)))
      (setf (gethash "managedBy" (gethash "spec" input)) manager)
      (signals gr8s::kubernetes-error (normalize-test-job input)))))

(defstruct (job-slow-delete-runtime (:include gr8s::fake-runtime)
                                    (:constructor make-job-slow-delete-runtime ()))
  "A runtime whose containers have not yet stopped when deletion is requested."
  (stopped nil))

(defmethod gr8s::runtime-delete-pod ((runtime job-slow-delete-runtime) pod)
  "Report shutdown as still running until the test says the containers stopped."
  (declare (ignorable pod))
  (and (job-slow-delete-runtime-stopped runtime) (call-next-method)))

(test replacement-policy-failed-waits-for-a-deleted-pod-to-stop
  (let ((gr8s::*stored-resource-types* (cons '("jobs" "Job" "batch/v1" t) gr8s::*stored-resource-types*)))
    (with-temporary-store (store directory)
      (declare (ignorable directory))
      (let* ((runtime (make-job-slow-delete-runtime)) (reconciler (make-reconciler store runtime))
             (now 3000000000) (gr8s::*job-clock* (lambda () now)))
        (job-with-spec store "completionMode" "Indexed" "completions" 1 "parallelism" 1 "podReplacementPolicy" "Failed")
        (gr8s::reconcile-jobs reconciler)
        (let ((pod (first (list-pods store "alpha"))))
          (gr8s::delete-reconciled-pod reconciler "alpha" (pod-name pod) :uid (pod-uid pod))
          (reconcile-until-settled reconciler)
          ;; Still stopping: not counted, and its index is not yet started again.
          (is (equal (list (pod-uid pod)) (mapcar #'pod-uid (list-pods store "alpha"))))
          (let ((status (gethash "status" (job-now store))))
            (is (= 1 (gethash "terminating" status)))
            (is (= 0 (gethash "failed" status 0))))
          (setf (job-slow-delete-runtime-stopped runtime) t)
          (reconcile-until-settled reconciler)
          (let ((status (gethash "status" (job-now store))))
            (is (= 1 (gethash "failed" status)))
            (is (= 0 (gethash "terminating" status))))
          ;; The counted failure delays the replacement like any other.
          (incf now 11)
          (reconcile-until-settled reconciler)
          (is (= 1 (length (remove (pod-uid pod) (list-pods store "alpha") :key #'pod-uid :test #'equal)))))))))

(test a-pod-finishing-after-accounting-waits-for-the-next-pass
  ;; podster-uqb.158: an index whose second failure landed between accounting and
  ;; Pod creation got a third Pod, so status.failed read 5 where upstream expects 4.
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (let* ((now 3000000001) (gr8s::*job-clock* (lambda () now))
           (original (symbol-function 'gr8s::flush-job-terminal-accounting)) (fail-next nil))
      (job-with-spec store "completionMode" "Indexed" "completions" 2 "parallelism" 2 "backoffLimitPerIndex" 1)
      (gr8s::reconcile-jobs reconciler)
      (finish-indexed-pod reconciler runtime store 1 "Failed" 1)
      (reconcile-until-settled reconciler)
      (incf now 11)
      (reconcile-until-settled reconciler)
      (is (= 2 (length (indexed-test-pods store 1))))
      (incf now 100)
      (unwind-protect
           (progn
             ;; The retry fails just after this pass has accounted its Pods.
             (setf fail-next t
                   (symbol-function 'gr8s::flush-job-terminal-accounting)
                   (lambda (reconciler job observations)
                     (prog1 (funcall original reconciler job observations)
                       (when fail-next
                         (setf fail-next nil)
                         (finish-indexed-pod reconciler runtime store 1 "Failed" 1)))))
             (gr8s::reconcile-jobs reconciler))
        (setf (symbol-function 'gr8s::flush-job-terminal-accounting) original))
      (is (= 2 (length (indexed-test-pods store 1))))
      (reconcile-until-settled reconciler)
      (let ((status (gethash "status" (job-now store))))
        (is (equal "1" (gethash "failedIndexes" status)))
        (is (= 2 (gethash "failed" status))))
      (is (= 2 (length (indexed-test-pods store 1)))))))

(test a-user-finalizer-holds-a-deleted-job-until-a-client-removes-it
  ;; Upstream's TTLAfterFinished spec puts a finalizer on its Job and removes it in cleanup.
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (let* ((now 3000000000) (gr8s::*job-clock* (lambda () now)))
      (job-with-spec store "ttlSecondsAfterFinished" 10)
      (gr8s::update-core-resource store "jobs" "alpha" "work"
        (lambda (job) (setf (gethash "finalizers" (gethash "metadata" job)) #("example.com/hold")) job))
      (gr8s::reconcile-jobs reconciler)
      (finish-job-pods reconciler runtime store "Succeeded")
      (reconcile-until-settled reconciler)
      (incf now 11)
      (reconcile-until-settled reconciler)
      (dotimes (pass 4) (gr8s::reconcile-workloads reconciler) (reconcile-all reconciler))
      (let ((metadata (gethash "metadata" (job-now store))))
        (is-true (gethash "deletionTimestamp" metadata))
        (is (equalp #("example.com/hold") (gethash "finalizers" metadata))))
      (gr8s::update-core-resource store "jobs" "alpha" "work"
        (lambda (job) (setf (gethash "finalizers" (gethash "metadata" job)) #()) job))
      (signals gr8s::kubernetes-error (job-now store))))
  ;; Background deletion is held the same way.
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable runtime reconciler directory))
    (job-with-spec store)
    (gr8s::update-core-resource store "jobs" "alpha" "work"
      (lambda (job) (setf (gethash "finalizers" (gethash "metadata" job)) #("example.com/hold")) job))
    (gr8s::delete-workload-resource store "jobs" "alpha" "work")
    (is-true (gethash "deletionTimestamp" (gethash "metadata" (job-now store))))
    (signals gr8s::kubernetes-error
      (gr8s::update-core-resource store "jobs" "alpha" "work"
        (lambda (job) (setf (gethash "finalizers" (gethash "metadata" job)) #("example.com/hold" "example.com/more")) job)))
    (gr8s::update-core-resource store "jobs" "alpha" "work"
      (lambda (job) (setf (gethash "finalizers" (gethash "metadata" job)) #()) job))
    (signals gr8s::kubernetes-error (job-now store))))

(test job-controller-records-pod-creation-and-completion-events
  (with-job-controller-fixture (store runtime reconciler directory)
    (declare (ignorable directory))
    (job-with-spec store)
    (gr8s::reconcile-jobs reconciler)
    (let ((pod (first (list-pods store "alpha"))))
      (finish-job-pods reconciler runtime store "Succeeded")
      (reconcile-until-settled reconciler)
      (let ((events (loop for event in (gr8s::list-core-resources store "events" "alpha")
                          when (equal "Job" (gethash "kind" (gethash "involvedObject" event)))
                            collect (cons (gethash "reason" event) (gethash "message" event)))))
        (is (member (cons "SuccessfulCreate" (format nil "Created pod: ~A" (pod-name pod))) events :test #'equal))
        (is (member (cons "Completed" "Job completed") events :test #'equal))
        (is (= 1 (count "Completed" events :key #'car :test #'equal)))))))
