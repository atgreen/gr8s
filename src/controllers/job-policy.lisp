;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Derive Job scheduling decisions from actual Pod observations: retry delays,
;;;; stable condition history, completion index sets, podFailurePolicy matching
;;;; and successPolicy rules. Durable accounting and real owned-Pod mutations
;;;; live in the controller.

(in-package #:gr8s.controllers)

(defparameter *job-clock* #'get-universal-time
  "Wall clock used for observed Job deadlines and durable retry timestamps.")

(defun job-terminal-condition (status)
  "Return only a true completed/failed Job decision, never infer completion from no Pods."
  (find-if (lambda (condition)
             (and (equal "True" (gethash "status" condition))
                  (member (gethash "type" condition) '("Complete" "Failed") :test #'equal)))
           (gethash "conditions" status #())))

(defun job-condition-true-p (status name)
  "Recognize a persisted Job condition using the pinned string-valued ConditionStatus."
  (find-if (lambda (condition) (and (equal name (gethash "type" condition))
                                  (equal "True" (gethash "status" condition))))
           (gethash "conditions" status #())))

(defun set-job-condition (status name value reason message)
  "Retain existing transition/probe timestamps unless a real condition changes."
  (let* ((conditions (gethash "conditions" status #()))
         (old (find name conditions :key (lambda (condition) (gethash "type" condition)) :test #'equal)))
    (unless (and old (equal value (gethash "status" old))
                 (equal reason (gethash "reason" old)) (equal message (gethash "message" old)))
      (let* ((now (current-timestamp (funcall *job-clock*)))
             (condition (core-object "type" name "status" value "reason" reason "message" message
                                     "lastProbeTime" now "lastTransitionTime"
                                     (if (and old (equal value (gethash "status" old)))
                                         (gethash "lastTransitionTime" old now) now))))
        (setf (gethash "conditions" status)
              (concatenate 'vector
                           (remove name conditions :key (lambda (entry) (gethash "type" entry)) :test #'equal)
                           (vector condition)))))
    status))

(defun job-pod-finished-time (status)
  "Use real CRI finish timestamps, falling back to observation time only for an already terminal Pod."
  (or (loop for field in '("containerStatuses" "initContainerStatuses")
            maximize (loop for container across (gethash field status #())
                           for terminated = (gethash "terminated" (gethash "state" container (core-object)))
                           for finished = (and terminated (gethash "finishedAt" terminated))
                           maximize (or (and finished (ignore-errors (pod-deletion-time finished))) 0))
            into latest
            finally (return (and (plusp latest) latest)))
      (funcall *job-clock*)))

(defun next-job-backoff-state (previous new-successes new-failures)
  "Match pinned Job backoff reset/order rules for newly accounted terminal Pod statuses."
  (let ((state (copy-core-object (or previous (core-object))))
        (success-times (mapcar #'job-pod-finished-time new-successes))
        (failure-times (mapcar #'job-pod-finished-time new-failures)))
    (cond
      ((null success-times)
       (when failure-times
         (incf (gethash "failuresAfterLastSuccess" state 0) (length failure-times))
         (setf (gethash "lastFailureTime" state) (reduce #'max failure-times))))
      (t
       (let ((failures-after (remove-if (lambda (time) (<= time (reduce #'max success-times))) failure-times)))
         (setf (gethash "failuresAfterLastSuccess" state) (length failures-after))
         (if failures-after (setf (gethash "lastFailureTime" state) (reduce #'max failures-after))
             (remhash "lastFailureTime" state)))))
    state))

(defun job-backoff-until (state)
  "Apply the pinned ten-second exponential retry delay, capped at six minutes."
  (let ((count (gethash "failuresAfterLastSuccess" state 0))
        (last (gethash "lastFailureTime" state)))
    (if (and last (plusp count))
        (+ last (min 360 (* 10 (expt 2 (min 6 (1- count))))))
        0)))

(defun job-active-observation-p (pod status)
  "Exclude deleting and actually terminal Pods from active parallelism."
  (and (not (deletion-requested-p pod))
       (not (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal))))

(defun job-onfailure-restarts (observations)
  "Sum actual init/main restart counts only for Pending/Running Job children."
  (loop for (pod . status) in observations
        when (and (not (deletion-requested-p pod))
                  (member (gethash "phase" status) '("Pending" "Running") :test #'equal))
          sum (loop for field in '("containerStatuses" "initContainerStatuses")
                    sum (loop for container across (gethash field status #())
                              sum (gethash "restartCount" container 0)))))

(defun job-success-goal-met-p (spec successes active)
  "Distinguish a fixed completion goal from a work queue requiring one genuine success."
  (multiple-value-bind (completions specified) (gethash "completions" spec)
    (if specified (>= successes completions) (and (plusp successes) (zerop active)))))

;;; Indexed completion: index sets are ordered, merged (first . last) intervals.

(defparameter +job-completion-index-key+ "batch.kubernetes.io/job-completion-index"
  "Pod annotation and label naming the completion index a Pod works on.")

(defparameter +job-index-failure-count-key+ "batch.kubernetes.io/job-index-failure-count"
  "Pod annotation recording how many failures its index has counted so far.")

(defparameter +job-index-ignored-failure-count-key+ "batch.kubernetes.io/job-index-ignored-failure-count"
  "Pod annotation recording how many failures of its index a policy ignored.")

(defun merge-job-index-intervals (intervals)
  "Sort INTERVALS and join those that overlap or touch."
  (let ((result nil))
    (dolist (interval (sort (copy-list intervals) #'< :key #'car) (nreverse result))
      (if (and result (<= (car interval) (1+ (cdar result))))
          (setf (car result) (cons (caar result) (max (cdar result) (cdr interval))))
          (push (cons (car interval) (cdr interval)) result)))))

(defun parse-job-indexes (text &optional limit)
  "Parse an index list such as 1,3-5; return NIL and :INVALID on malformed text or an index at or past LIMIT."
  (let ((intervals nil))
    (dolist (part (and (plusp (length text)) (uiop:split-string text :separator '(#\,)))
                  (merge-job-index-intervals intervals))
      (let* ((bounds (uiop:split-string part :separator '(#\-)))
             (numbers (mapcar (lambda (bound)
                                (and (plusp (length bound)) (every #'digit-char-p bound) (parse-integer bound)))
                              bounds)))
        (unless (and (<= 1 (length numbers) 2) (every #'identity numbers)
                     (<= (first numbers) (car (last numbers)))
                     (or (null limit) (< (car (last numbers)) limit)))
          (return (values nil :invalid)))
        (push (cons (first numbers) (car (last numbers))) intervals)))))

(defun job-indexes-below (intervals limit)
  "Return INTERVALS without the indexes at or past LIMIT, which a scaled-down Job no longer has."
  (loop for (first . last) in intervals
        when (< first limit) collect (cons first (min last (1- limit)))))

(defun format-job-indexes (intervals)
  "Write INTERVALS as Kubernetes does: two adjacent indexes stay comma separated."
  (format nil "~{~A~^,~}"
          (mapcar (lambda (interval)
                    (destructuring-bind (first . last) interval
                      (cond ((= first last) (format nil "~D" first))
                            ((= last (1+ first)) (format nil "~D,~D" first last))
                            (t (format nil "~D-~D" first last)))))
                  intervals)))

(defun job-indexes-total (intervals)
  "Count the indexes in INTERVALS."
  (loop for (first . last) in intervals sum (1+ (- last first))))

(defun job-indexes-member-p (index intervals)
  "Report whether INDEX is one of INTERVALS."
  (loop for (first . last) in intervals thereis (<= first index last)))

(defun job-indexes-add (index intervals)
  "Return INTERVALS with INDEX added."
  (merge-job-index-intervals (cons (cons index index) intervals)))

(defun job-indexes-overlap (left right)
  "Count the indexes present in both LEFT and RIGHT."
  (loop for (a . b) in left
        sum (loop for (c . d) in right
                  sum (max 0 (1+ (- (min b d) (max a c)))))))

(defun job-indexed-p (spec)
  "Recognize Indexed completion mode."
  (equal "Indexed" (gethash "completionMode" spec)))

(defun job-per-index-limit (spec)
  "Return backoffLimitPerIndex, or NIL when failures are counted for the whole Job."
  (gethash "backoffLimitPerIndex" spec))

(defun job-only-replace-failed-p (spec)
  "Wait for a deleted Pod to finish before replacing it, as Failed replacement requires."
  (equal "Failed" (gethash "podReplacementPolicy" spec)))

(defun job-pod-completion-index (pod)
  "Read POD's completion index annotation, or NIL when it has no valid one."
  (let* ((annotations (gethash "annotations" (gethash "metadata" (pod-to-object pod)) (core-object)))
         (text (gethash +job-completion-index-key+ annotations)))
    (and (stringp text) (plusp (length text)) (every #'digit-char-p text) (parse-integer text))))

(defun job-exit-code-rule-matches-p (requirement status)
  "Match a failed container's nonzero exit code, trying main containers before init containers."
  (let ((name (gethash "containerName" requirement))
        (values (coerce (gethash "values" requirement #()) 'list))
        (in (equal "In" (gethash "operator" requirement))))
    (when (eq name 'null) (setf name nil))
    (loop for field in '("containerStatuses" "initContainerStatuses")
          thereis (loop for container across (gethash field status #())
                        for terminated = (gethash "terminated" (gethash "state" container (core-object)))
                        for code = (and terminated (gethash "exitCode" terminated))
                        thereis (and code (/= 0 code)
                                     (or (null name) (equal name (gethash "name" container)))
                                     (if in (member code values) (not (member code values)))
                                     container)))))

(defun job-pod-condition-rule-matches-p (patterns status)
  "Match any observed Pod condition with the requested type and status."
  (loop for pattern across patterns
        thereis (loop for condition across (gethash "conditions" status #())
                      thereis (and (equal (gethash "type" pattern) (gethash "type" condition))
                                   (equal (gethash "status" pattern) (gethash "status" condition))))))

(defun job-pod-failure-action (spec pod status)
  "Apply the first matching podFailurePolicy rule; return its action and any Job failure message."
  (let ((policy (gethash "podFailurePolicy" spec)))
    (when policy
      (loop for rule across (gethash "rules" policy #()) for index from 0
            for exit-codes = (gethash "onExitCodes" rule)
            for conditions = (gethash "onPodConditions" rule)
            for container = (and exit-codes (not (eq exit-codes 'null))
                                 (job-exit-code-rule-matches-p exit-codes status))
            when (or container
                     (and (or (null exit-codes) (eq exit-codes 'null)) conditions (not (eq conditions 'null))
                          (job-pod-condition-rule-matches-p conditions status)))
              do (let ((action (gethash "action" rule)))
                   (return
                     (values action
                             (when (equal action "FailJob")
                               (if container
                                   (format nil "Container ~A for pod ~A/~A failed with exit code ~D matching ~A rule at index ~D"
                                           (gethash "name" container) (pod-namespace pod) (pod-name pod)
                                           (gethash "exitCode" (gethash "terminated" (gethash "state" container)))
                                           action index)
                                   (format nil "Pod ~A/~A has condition matching ~A rule at index ~D"
                                           (pod-namespace pod) (pod-name pod) action index))))))))))

(defun job-success-policy-message (spec completed)
  "Return a message when any successPolicy rule is met by the COMPLETED index intervals."
  (let ((policy (gethash "successPolicy" spec)) (completions (gethash "completions" spec)))
    (when (and policy completed)
      (loop for rule across (gethash "rules" policy #()) for position from 0
            for text = (gethash "succeededIndexes" rule)
            for count = (gethash "succeededCount" rule)
            for wanted = (if (stringp text) (parse-job-indexes text completions)
                             (list (cons 0 (1- completions))))
            for contained = (job-indexes-overlap wanted completed)
            when (if (integerp count) (>= contained count)
                     (= contained (job-indexes-total wanted)))
              do (return (format nil "Matched rules at index ~D" position))))))

(defun job-finishing-condition (status)
  "Return the interim condition that fixed this Job's outcome before its Pods stopped."
  (find-if (lambda (condition)
             (and (equal "True" (gethash "status" condition))
                  (member (gethash "type" condition) '("SuccessCriteriaMet" "FailureTarget") :test #'equal)))
           (gethash "conditions" status #())))

(defun job-index-record (state index)
  "Return the durable failure record of INDEX, creating it in STATE on first use."
  (let ((records (or (gethash "indexFailures" state)
                     (setf (gethash "indexFailures" state) (core-object))))
        (key (format nil "~D" index)))
    (or (gethash key records) (setf (gethash key records) (core-object)))))

(defun job-index-counts (state index)
  "Return the counted and ignored failures INDEX has seen, without changing STATE."
  (let* ((records (gethash "indexFailures" state))
         (record (and records (gethash (format nil "~D" index) records))))
    (if record
        (values (gethash "count" record 0) (gethash "ignored" record 0))
        (values 0 0))))

(defun job-index-backoff-until (state index)
  "Apply the Job retry delay to INDEX alone, from its own failure count."
  (let* ((records (gethash "indexFailures" state))
         (record (and records (gethash (format nil "~D" index) records))))
    (if record
        (job-backoff-until (core-object "failuresAfterLastSuccess" (gethash "count" record 0)
                                        "lastFailureTime" (gethash "last" record)))
        0)))
