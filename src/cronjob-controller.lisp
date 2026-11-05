;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Run CronJobs: create a Job, owned by exact UID, for the latest schedule time
;;;; not yet started, subject to suspend, deadline and concurrency policy; keep
;;;; the active list true to the Jobs that exist; trim finished-Job history. A
;;;; Job's name derives from its scheduled time, so a restart cannot start it twice.

(in-package #:gr8s)

(defparameter *cronjob-clock* #'get-universal-time
  "Wall clock that decides which schedule times have arrived.")

(defparameter +cronjob-scheduled-timestamp-key+ "batch.kubernetes.io/cronjob-scheduled-timestamp"
  "Job annotation recording the schedule time that started the Job.")

(defun record-cronjob-event (store cronjob type reason message &optional (key message))
  "Publish one Event about CRONJOB; KEY makes a repeat of the same occurrence a no-op."
  (let* ((metadata (workload-metadata cronjob)) (namespace (gethash "namespace" metadata))
         (now (current-timestamp (funcall *cronjob-clock*)))
         (digest (octets-to-hex (ironclad:digest-sequence
                                 :sha256 (trivial-utf-8:string-to-utf-8-bytes
                                          (format nil "~A/~A/~A" (gethash "uid" metadata) reason key)))))
         (name (format nil "~A.~A" (gethash "name" metadata) (string-downcase (subseq digest 0 16)))))
    (handler-case
        (create-core-resource store "events"
          (core-object "apiVersion" "v1" "kind" "Event" "metadata" (core-object "name" name)
                       "involvedObject" (core-object "apiVersion" "batch/v1" "kind" "CronJob" "namespace" namespace
                                                     "name" (gethash "name" metadata) "uid" (gethash "uid" metadata))
                       "reason" reason "message" message "type" type "count" 1
                       "firstTimestamp" now "lastTimestamp" now
                       "source" (core-object "component" "cronjob-controller")
                       "reportingComponent" "cronjob-controller")
          namespace)
      (kubernetes-error (condition)
        (unless (= 409 (kubernetes-error-status-code condition))
          (format *error-output* "gr8s cronjob Event publication failed: ~A~%" condition))))))

(defun cronjob-owned-jobs (store cronjob)
  "List the Jobs whose controller is this exact CronJob UID."
  (remove-if-not (lambda (job) (workload-owned-p job cronjob))
                 (list-core-resources store "jobs" (gethash "namespace" (workload-metadata cronjob)))))

(defun job-object-reference (job)
  "Build the status.active reference to JOB."
  (let ((metadata (workload-metadata job)))
    (core-object "apiVersion" "batch/v1" "kind" "Job" "namespace" (gethash "namespace" metadata)
                 "name" (gethash "name" metadata) "uid" (gethash "uid" metadata)
                 "resourceVersion" (gethash "resourceVersion" metadata))))

(defun cronjob-time (text)
  "Decode a stored UTC timestamp, or NIL when absent or written in another form."
  (and (stringp text) (ignore-errors (pod-deletion-time text))))

(defun reconcile-cronjob-children (store cronjob status jobs)
  "Bring the active list and last success time of STATUS into line with the Jobs that exist."
  (let ((active (coerce (gethash "active" status #()) 'list)))
    (dolist (job jobs)
      (let* ((metadata (workload-metadata job)) (uid (gethash "uid" metadata)) (name (gethash "name" metadata))
             (listed (find uid active :key (lambda (entry) (gethash "uid" entry)) :test #'equal))
             (terminal (job-terminal-condition (gethash "status" job (core-object)))))
        (cond
          ((and (not listed) (not terminal))
           (record-cronjob-event store cronjob "Warning" "UnexpectedJob"
                                 (format nil "Saw a job that the controller did not create or forgot: ~A" name) uid))
          ((and listed terminal)
           (setf active (remove listed active))
           (record-cronjob-event store cronjob "Normal" "SawCompletedJob"
                                 (format nil "Saw completed job: ~A, condition: ~A" name (gethash "type" terminal)) uid)))
        (when (and terminal (equal "Complete" (gethash "type" terminal)))
          (let ((finished (cronjob-time (gethash "completionTime" (gethash "status" job))))
                (recorded (cronjob-time (gethash "lastSuccessfulTime" status))))
            (when (and finished (or (null recorded) (> finished recorded)))
              (setf (gethash "lastSuccessfulTime" status) (gethash "completionTime" (gethash "status" job))))))))
    (dolist (entry active)
      (unless (find (gethash "uid" entry) jobs :key (lambda (job) (gethash "uid" (workload-metadata job))) :test #'equal)
        (setf active (remove entry active))
        (record-cronjob-event store cronjob "Warning" "MissingJob"
                              (format nil "Active job went missing: ~A" (gethash "name" entry)) (gethash "uid" entry))))
    (setf (gethash "active" status) (coerce active 'vector))
    (when (null active) (remhash "active" status))
    status))

(defun cronjob-job-input (cronjob scheduled zone)
  "Build the Job for SCHEDULED from CRONJOB's template, owned by its exact UID."
  (let* ((template (gethash "jobTemplate" (gethash "spec" cronjob)))
         (source (gethash "metadata" template (core-object)))
         (annotations (copy-core-object (gethash "annotations" source (core-object))))
         (metadata (core-object "name" (format nil "~A-~D" (gethash "name" (workload-metadata cronjob))
                                               (floor (- scheduled +unix-epoch-universal+) 60))
                                "annotations" annotations
                                "ownerReferences" (vector (job-owner-reference cronjob)))))
    (setf (gethash +cronjob-scheduled-timestamp-key+ annotations) (format-cron-time scheduled zone))
    (when (gethash "labels" source)
      (setf (gethash "labels" metadata) (copy-core-object (gethash "labels" source))))
    (core-object "apiVersion" "batch/v1" "kind" "Job" "metadata" metadata
                 "spec" (copy-core-object (gethash "spec" template)))))

(defun start-cronjob-job (store cronjob scheduled zone)
  "Create the Job for SCHEDULED, or find the one an interrupted earlier pass already created."
  (let* ((input (cronjob-job-input cronjob scheduled zone))
         (namespace (gethash "namespace" (workload-metadata cronjob)))
         (name (gethash "name" (gethash "metadata" input))))
    (handler-case
        (let ((job (with-controller-admission ("cronjob-controller")
                     (admitted-create-core-resource store "jobs" input namespace))))
          (record-cronjob-event store cronjob "Normal" "SuccessfulCreate" (format nil "Created job ~A" name))
          job)
      (kubernetes-error (condition)
        (unless (= 409 (kubernetes-error-status-code condition)) (error condition))
        (let ((existing (get-core-resource store "jobs" namespace name)))
          (and (workload-owned-p existing cronjob) existing))))))

(defun replace-active-cronjob-jobs (store cronjob status)
  "Delete the Jobs STATUS lists as active, leaving their Pods to background collection."
  (loop for entry across (gethash "active" status #())
        do (handler-case
               (when (controller-delete-allowed-p store "jobs" (gethash "namespace" entry) (gethash "name" entry)
                                                  "cronjob-controller")
                 (delete-workload-resource store "jobs" (gethash "namespace" entry) (gethash "name" entry)
                                           :uid (gethash "uid" entry) :policy "Background")
                 (record-cronjob-event store cronjob "Normal" "SuccessfulDelete"
                                       (format nil "Deleted job ~A" (gethash "name" entry))))
             (kubernetes-error (condition)
               (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))
  (remhash "active" status))

(defun cronjob-due-time (cronjob status schedule zone now)
  "Return the schedule time this CronJob should start now, or NIL when none is due or it is too late."
  (let* ((spec (gethash "spec" cronjob))
         (deadline (gethash "startingDeadlineSeconds" spec))
         (earliest (or (cronjob-time (gethash "lastScheduleTime" status))
                       (cronjob-time (gethash "creationTimestamp" (workload-metadata cronjob)))
                       now))
         (earliest (if deadline (max earliest (- now deadline)) earliest))
         (scheduled (most-recent-cron-time schedule earliest now zone)))
    (and scheduled (or (null deadline) (<= now (+ scheduled deadline))) scheduled)))

(defun clean-cronjob-history (store cronjob jobs)
  "Delete the oldest finished Jobs past each history limit."
  (let ((spec (gethash "spec" cronjob)))
    (flet ((trim (type limit)
             (let* ((finished (remove-if-not
                               (lambda (job)
                                 (let ((terminal (job-terminal-condition (gethash "status" job (core-object)))))
                                   (and terminal (equal type (gethash "type" terminal))
                                        (not (gethash "deletionTimestamp" (workload-metadata job))))))
                               jobs))
                    (ordered (stable-sort (copy-list finished) #'<
                                          :key (lambda (job)
                                                 (or (cronjob-time (gethash "startTime" (gethash "status" job)))
                                                     (cronjob-time (gethash "creationTimestamp" (workload-metadata job)))
                                                     0)))))
               (loop repeat (- (length ordered) limit)
                     for job in ordered
                     do (let ((metadata (workload-metadata job)))
                          (handler-case
                              (when (controller-delete-allowed-p store "jobs" (gethash "namespace" metadata) (gethash "name" metadata)
                                                                 "cronjob-controller")
                                (delete-workload-resource store "jobs" (gethash "namespace" metadata) (gethash "name" metadata)
                                                          :uid (gethash "uid" metadata) :policy "Background")
                                (record-cronjob-event store cronjob "Normal" "SuccessfulDelete"
                                                      (format nil "Deleted job ~A" (gethash "name" metadata))))
                            (kubernetes-error (condition)
                              (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition))))))))) 
      (trim "Complete" (gethash "successfulJobsHistoryLimit" spec 3))
      (trim "Failed" (gethash "failedJobsHistoryLimit" spec 1)))))

(defun reconcile-cronjob (store cronjob)
  "Run one CronJob pass: truthful status first, then any Job now due, then history."
  (let* ((spec (gethash "spec" cronjob)) (now (funcall *cronjob-clock*))
         (status (copy-core-object (gethash "status" cronjob (core-object))))
         (jobs (cronjob-owned-jobs store cronjob)))
    (reconcile-cronjob-children store cronjob status jobs)
    (handler-case
        (unless (eq t (gethash "suspend" spec))
          (let* ((schedule (parse-cron (gethash "schedule" spec)))
                 (zone (and (gethash "timeZone" spec) (load-cron-zone (gethash "timeZone" spec))))
                 (scheduled (cronjob-due-time cronjob status schedule zone now)))
            (when scheduled
              (let ((policy (gethash "concurrencyPolicy" spec))
                    (active (plusp (length (gethash "active" status #())))))
                (if (and active (equal policy "Forbid"))
                    (record-cronjob-event store cronjob "Normal" "JobAlreadyActive"
                                          "Not starting job because prior execution is running and concurrency policy is Forbid"
                                          (format nil "~D" scheduled))
                    (progn
                      (when (and active (equal policy "Replace"))
                        (replace-active-cronjob-jobs store cronjob status))
                      (let ((job (start-cronjob-job store cronjob scheduled zone)))
                        (when job
                          (unless (find (gethash "uid" (workload-metadata job)) (gethash "active" status #())
                                        :key (lambda (entry) (gethash "uid" entry)) :test #'equal)
                            (setf (gethash "active" status)
                                  (concatenate 'vector (gethash "active" status #()) (vector (job-object-reference job)))))
                          (setf (gethash "lastScheduleTime" status) (current-timestamp scheduled))))))))))
      (invalid-cron-schedule (condition)
        (record-cronjob-event store cronjob "Warning" "InvalidSchedule" (princ-to-string condition))))
    (update-workload-controller-status store "cronjobs" cronjob status)
    (clean-cronjob-history store cronjob jobs)))

(defun reconcile-cronjobs (reconciler)
  "Run one pass over all CronJobs, isolating each so one failure cannot stall the others."
  (let ((store (reconciler-store reconciler)))
    (dolist (cronjob (list-core-resources store "cronjobs"))
      (handler-case
          (unless (gethash "deletionTimestamp" (workload-metadata cronjob))
            (reconcile-cronjob store cronjob))
        (kubernetes-error (condition)
          (unless (member (kubernetes-error-status-code condition) '(404 409))
            (format *error-output* "gr8s cronjobs controller: ~A~%" condition)))
        (error (condition) (format *error-output* "gr8s cronjobs controller: ~A~%" condition))))))
