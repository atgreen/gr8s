;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Derive NonIndexed Job scheduling decisions from actual Pod observations.
;;;; Preserve pinned retry delay/reset semantics and stable condition history;
;;;; durable accounting and real owned-Pod mutations live in the controller.

(in-package #:gr8s)

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
