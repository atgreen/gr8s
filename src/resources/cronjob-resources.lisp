;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Admit batch/v1 CronJobs: pinned defaults, a schedule and time zone that can
;;;; actually run, and a Job template that passes the same admission as a Job.
;;;; Controller-owned status survives ordinary writes.

(in-package #:gr8s.resources)

(defun cronjob-resource-p (resource)
  "Recognize the CronJob collection."
  (equal resource "cronjobs"))

(defun normalize-cronjob-template (spec namespace)
  "Check the Job template through Job admission, storing its defaulted spec."
  (let* ((template (require-object (gethash "jobTemplate" spec) "spec.jobTemplate"))
         (embedded (let ((value (gethash "metadata" template))) (if (member value '(nil null)) (core-object) value)))
         (job-spec (require-object (gethash "spec" template) "spec.jobTemplate.spec"))
         (kept (core-object)))
    (maphash (lambda (key value)
               (cond ((member key '("labels" "annotations") :test #'equal)
                      (unless (eq value 'null) (setf (gethash key kept) value)))
                     ((not (or (member value '(nil null "" 0)) (equal key "creationTimestamp")
                               (and (vectorp value) (zerop (length value)))))
                      (core-resource-error 422 "Invalid" "spec.jobTemplate.metadata.~A is not supported" key))))
             embedded)
    (when (or (eq t (gethash "manualSelector" job-spec))
              (not (member (gethash "selector" job-spec) '(nil null))))
      (core-resource-error 422 "Invalid" "spec.jobTemplate.spec cannot use a manual selector"))
    (let ((job (normalize-batch-resource
                (core-object "apiVersion" "batch/v1" "kind" "Job" "metadata" (let ((metadata (copy-core-object kept)))
                                                                                (setf (gethash "name" metadata) "cronjob-template")
                                                                                metadata)
                             "spec" job-spec)
                namespace "cronjob-template")))
      (setf (gethash "metadata" template) kept
            (gethash "spec" template) (gethash "spec" job)))))

(defun normalize-cronjob-resource (input namespace name)
  "Validate a CronJob that can really be scheduled; ordinary writes never submit status."
  (let* ((object (copy-core-object (require-object input "CronJob")))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (spec (require-object (gethash "spec" object) "spec")))
    (unless (and (equal "batch/v1" (gethash "apiVersion" object "batch/v1"))
                 (equal "CronJob" (gethash "kind" object "CronJob")))
      (core-resource-error 400 "BadRequest" "Expected batch/v1 CronJob"))
    (when (eq (gethash "finalizers" metadata) 'null) (setf (gethash "finalizers" metadata) #()))
    (validate-core-metadata metadata namespace name :allow-finalizers t)
    (when (> (length (gethash "name" metadata)) 52)
      (core-resource-error 422 "Invalid" "A CronJob name must be at most 52 characters, leaving room for its Jobs' suffix"))
    (setf (gethash "namespace" metadata) namespace (gethash "apiVersion" object) "batch/v1" (gethash "kind" object) "CronJob")
    (remhash "status" object)
    (validate-template-shape object (template-schema "io.k8s.api.batch.v1.CronJob") "CronJob")
    (reject-unsupported-fields spec '("schedule" "timeZone" "startingDeadlineSeconds" "concurrencyPolicy" "suspend"
                                      "jobTemplate" "successfulJobsHistoryLimit" "failedJobsHistoryLimit") "CronJob.spec")
    (handler-case
        (progn
          (parse-cron (gethash "schedule" spec))
          (dolist (field '("timeZone" "startingDeadlineSeconds"))
            (when (eq (gethash field spec) 'null) (remhash field spec)))
          (when (gethash "timeZone" spec) (load-cron-zone (gethash "timeZone" spec))))
      (invalid-cron-schedule (condition)
        (core-resource-error 422 "Invalid" "~A" condition)))
    (let ((deadline (gethash "startingDeadlineSeconds" spec)))
      (when (and deadline (not (typep deadline '(integer 0 9223372036854775807))))
        (core-resource-error 422 "Invalid" "CronJob.spec.startingDeadlineSeconds must be a nonnegative int64")))
    (when (member (gethash "concurrencyPolicy" spec) '(nil null "") :test #'equal)
      (setf (gethash "concurrencyPolicy" spec) "Allow"))
    (unless (member (gethash "concurrencyPolicy" spec) '("Allow" "Forbid" "Replace") :test #'equal)
      (core-resource-error 422 "Invalid" "CronJob.spec.concurrencyPolicy must be Allow, Forbid or Replace"))
    (setf (gethash "suspend" spec) (batch-boolean (gethash "suspend" spec) "CronJob.spec.suspend")
          (gethash "successfulJobsHistoryLimit" spec)
          (workload-int (gethash "successfulJobsHistoryLimit" spec) "CronJob.spec.successfulJobsHistoryLimit" 3)
          (gethash "failedJobsHistoryLimit" spec)
          (workload-int (gethash "failedJobsHistoryLimit" spec) "CronJob.spec.failedJobsHistoryLimit" 1))
    (normalize-cronjob-template spec namespace)
    object))

(defun prepare-cronjob-write (object existing)
  "Assign the generation and preserve controller status and any pending deletion."
  (let ((metadata (gethash "metadata" object)))
    (remhash "deletionTimestamp" metadata)
    (when existing
      (let ((pending (gethash "deletionTimestamp" (gethash "metadata" existing))))
        (when pending
          (setf (gethash "deletionTimestamp" metadata) pending)
          (loop for name across (gethash "finalizers" metadata #())
                unless (find name (gethash "finalizers" (gethash "metadata" existing) #()) :test #'equal)
                  do (core-resource-error 422 "Invalid" "CronJob finalizers cannot be added after deletion begins")))))
    (setf (gethash "generation" metadata)
          (if existing (+ (gethash "generation" (gethash "metadata" existing) 1)
                          (if (workload-equal-p (gethash "spec" object) (gethash "spec" existing)) 0 1)) 1)
          (gethash "status" object)
          (if existing (copy-core-object (gethash "status" existing (core-object))) (core-object)))
    object))
