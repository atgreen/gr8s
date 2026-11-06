;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise CronJob admission, the HTTP surface and the schedule controller:
;;;; owned Jobs named for their schedule time, concurrency policies, suspension,
;;;; deadlines, active list recovery, history limits and restart idempotence.

(in-package #:gr8s/tests)
(def-suite cronjob :in gr8s)
(in-suite cronjob)

(defparameter *cronjob-test-start* (cron-at 2026 11 4 10 0)
  "A fixed creation time, on a minute boundary, for the controller tests.")

(defun cronjob-test-input (&rest fields)
  "Build a CronJob with a Never-restart Job template and additional spec FIELDS."
  (let* ((job (batch-test-job "ignored")) (job-spec (gethash "spec" job))
         (spec (gr8s::core-object "schedule" "*/1 * * * ?"
                                  "jobTemplate" (gr8s::core-object "spec" job-spec))))
    (setf (gethash "restartPolicy" (gethash "spec" (gethash "template" job-spec))) "Never")
    (loop for (key value) on fields by #'cddr do (setf (gethash key spec) value))
    (gr8s::core-object "apiVersion" "batch/v1" "kind" "CronJob" "metadata" (gr8s::core-object "name" "tick") "spec" spec)))

(defmacro with-cronjob-fixture ((store reconciler clock) &body body)
  "Run BODY with a fake runtime and a settable clock CLOCK, starting at the fixed creation time."
  (let ((directory (gensym "DIRECTORY")) (runtime (gensym "RUNTIME")))
    `(with-temporary-store (,store ,directory)
       (declare (ignorable ,directory))
       (let* ((,runtime (make-fake-runtime)) (,reconciler (make-reconciler ,store ,runtime))
              (,clock *cronjob-test-start*)
              (gr8s::*cronjob-clock* (lambda () ,clock)))
         (declare (ignorable ,reconciler))
         ,@body))))

(defun create-test-cronjob (store &rest fields)
  "Admit a CronJob through production create, created at the fixed test time."
  (let ((created (gr8s::create-core-resource store "cronjobs" (apply #'cronjob-test-input fields) "alpha")))
    (gr8s::with-store-lock (store)
      (let ((stored (gethash (gr8s::core-resource-key "cronjobs" "alpha" "tick") (gr8s::pod-store-resources store))))
        (setf (gethash "creationTimestamp" (gethash "metadata" stored)) (gr8s::current-timestamp *cronjob-test-start*))))
    created))

(defun cronjob-now (store)
  "Read the current durable CronJob."
  (gr8s::get-core-resource store "cronjobs" "alpha" "tick"))

(defun cronjob-pass (store)
  "Run one controller pass over the test CronJob."
  (gr8s::reconcile-cronjob store (cronjob-now store)))

(defun cronjob-job-names (store)
  "List the names of the test CronJob's Jobs."
  (mapcar (lambda (job) (gethash "name" (gethash "metadata" job))) (gr8s::list-core-resources store "jobs" "alpha")))

(defun cronjob-active-names (store)
  "List the Job names in the test CronJob's active list."
  (map 'list (lambda (entry) (gethash "name" entry))
       (gethash "active" (gethash "status" (cronjob-now store)) #())))

(defun finish-cronjob-job (store name type)
  "Mark the Job NAME finished with a Complete or Failed condition and matching times."
  (gr8s::commit-job-controller-update store (gr8s::get-core-resource store "jobs" "alpha" name)
    (lambda (status state)
      (gr8s::set-job-condition status type "True" "Test" "finished by test")
      (setf (gethash "startTime" status) (gr8s::current-timestamp *cronjob-test-start*))
      (when (equal type "Complete")
        (setf (gethash "completionTime" status) (gr8s::current-timestamp (+ *cronjob-test-start* 30))))
      (values status state))))

(defun cronjob-job-name-at (minutes)
  "Return the Job name for the schedule time MINUTES after the test start."
  (format nil "tick-~D" (floor (- (+ *cronjob-test-start* (* 60 minutes)) gr8s::+unix-epoch-universal+) 60)))

(test cronjob-defaults-and-admission-refusals
  (let* ((object (gr8s::normalize-cronjob-resource (cronjob-test-input) "alpha" nil)) (spec (gethash "spec" object)))
    (is (equal "Allow" (gethash "concurrencyPolicy" spec)))
    (is (= 3 (gethash "successfulJobsHistoryLimit" spec)))
    (is (= 1 (gethash "failedJobsHistoryLimit" spec)))
    (is-false (gethash "suspend" spec))
    (is (= 6 (gethash "backoffLimit" (gethash "spec" (gethash "jobTemplate" spec))))))
  (flet ((refused (&rest fields)
           (signals gr8s::kubernetes-error
             (gr8s::normalize-cronjob-resource (apply #'cronjob-test-input fields) "alpha" nil))))
    (refused "schedule" "not a schedule")
    (refused "schedule" "TZ=UTC * * * * *")
    (refused "timeZone" "bad-time-zone")
    (refused "concurrencyPolicy" "Sometimes")
    (refused "startingDeadlineSeconds" -1)
    (refused "successfulJobsHistoryLimit" -1)
    (refused "unknownField" 1))
  (let ((input (cronjob-test-input)))
    (setf (gethash "name" (gethash "metadata" input)) (make-string 53 :initial-element #\a))
    (signals gr8s::kubernetes-error (gr8s::normalize-cronjob-resource input "alpha" nil)))
  (let ((input (cronjob-test-input)))
    (setf (gethash "manualSelector" (gethash "spec" (gethash "jobTemplate" (gethash "spec" input)))) t)
    (signals gr8s::kubernetes-error (gr8s::normalize-cronjob-resource input "alpha" nil))))

(test nothing-starts-before-the-first-schedule-time
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store)
    (cronjob-pass store)
    (is (null (cronjob-job-names store)))
    (is (null (cronjob-active-names store)))))

(test due-schedule-creates-one-owned-annotated-job
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store)
    (incf clock 61)
    (cronjob-pass store)
    (cronjob-pass store)
    (is (equal (list (cronjob-job-name-at 1)) (cronjob-job-names store)))
    (is (equal (list (cronjob-job-name-at 1)) (cronjob-active-names store)))
    (let* ((job (gr8s::get-core-resource store "jobs" "alpha" (cronjob-job-name-at 1)))
           (status (gethash "status" (cronjob-now store)))
           (reference (aref (gethash "active" status) 0)))
      (is-true (gr8s::workload-owned-p job (cronjob-now store)))
      (is (equal "2026-11-04T10:01:00Z" (gethash "lastScheduleTime" status)))
      (is (equal "2026-11-04T10:01:00Z"
                 (gethash gr8s::+cronjob-scheduled-timestamp-key+ (gethash "annotations" (gethash "metadata" job)))))
      (is (equal "Job" (gethash "kind" reference)))
      (is (equal (gethash "uid" (gethash "metadata" job)) (gethash "uid" reference))))))

(test allow-policy-runs-jobs-side-by-side-and-catches-up-only-once
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store)
    (incf clock 61)
    (cronjob-pass store)
    (incf clock 60)
    (cronjob-pass store)
    (is (= 2 (length (cronjob-active-names store))))
    ;; After a long outage only the latest missed time starts.
    (incf clock 3600)
    (cronjob-pass store)
    (is (= 3 (length (cronjob-job-names store))))
    (is (find (cronjob-job-name-at 62) (cronjob-job-names store) :test #'equal))))

(test forbid-policy-holds-while-a-job-runs-and-starts-after
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store "concurrencyPolicy" "Forbid")
    (incf clock 61)
    (cronjob-pass store)
    (incf clock 60)
    (cronjob-pass store)
    (cronjob-pass store)
    (is (equal (list (cronjob-job-name-at 1)) (cronjob-active-names store)))
    (is (= 1 (length (cronjob-job-names store))))
    (finish-cronjob-job store (cronjob-job-name-at 1) "Complete")
    (cronjob-pass store)
    (is (equal (list (cronjob-job-name-at 2)) (cronjob-active-names store)))))

(test replace-policy-swaps-the-running-job
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store "concurrencyPolicy" "Replace")
    (incf clock 61)
    (cronjob-pass store)
    (incf clock 60)
    (cronjob-pass store)
    (is (equal (list (cronjob-job-name-at 2)) (cronjob-job-names store)))
    (is (equal (list (cronjob-job-name-at 2)) (cronjob-active-names store)))))

(test suspended-cronjob-starts-nothing-but-resumes-at-the-latest-time
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store "suspend" t)
    (incf clock 300)
    (cronjob-pass store)
    (is (null (cronjob-job-names store)))
    (gr8s::update-core-resource store "cronjobs" "alpha" "tick"
      (lambda (current) (setf (gethash "suspend" (gethash "spec" current)) nil) current))
    (cronjob-pass store)
    (is (equal (list (cronjob-job-name-at 5)) (cronjob-job-names store)))))

(test starting-deadline-skips-a-time-too-late-to-start
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store "schedule" "0 * * * *" "startingDeadlineSeconds" 30)
    (incf clock 3640)
    (cronjob-pass store)
    (is (null (cronjob-job-names store)))
    (decf clock 20)
    (cronjob-pass store)
    (is (= 1 (length (cronjob-job-names store))))))

(test completed-and-deleted-jobs-leave-the-active-list
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store "schedule" "0 0 1 1 *")
    (let ((cronjob (cronjob-now store)))
      (gr8s::start-cronjob-job store cronjob (+ *cronjob-test-start* 60) nil)
      (gr8s::start-cronjob-job store cronjob (+ *cronjob-test-start* 120) nil)
      (let ((status (gr8s::copy-core-object (gethash "status" cronjob (gr8s::core-object)))))
        (setf (gethash "active" status)
              (map 'vector #'gr8s::job-object-reference (gr8s::list-core-resources store "jobs" "alpha")))
        (gr8s::update-workload-controller-status store "cronjobs" cronjob status)))
    (finish-cronjob-job store (cronjob-job-name-at 1) "Complete")
    (gr8s::delete-core-resource store "jobs" "alpha" (cronjob-job-name-at 2))
    (cronjob-pass store)
    (let ((status (gethash "status" (cronjob-now store))))
      (is (null (cronjob-active-names store)))
      (is (equal "2026-11-04T10:00:30Z" (gethash "lastSuccessfulTime" status))))
    (let ((reasons (mapcar (lambda (event) (gethash "reason" event))
                           (gr8s::list-core-resources store "events" "alpha"))))
      (is (member "MissingJob" reasons :test #'equal))
      (is (member "SawCompletedJob" reasons :test #'equal))
      (is-false (member "UnexpectedJob" reasons :test #'equal)))))

(test history-limits-trim-the-oldest-finished-jobs
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store "successfulJobsHistoryLimit" 1 "failedJobsHistoryLimit" 0)
    (dolist (minutes '(1 2 3))
      (incf clock 60)
      (cronjob-pass store)
      (finish-cronjob-job store (cronjob-job-name-at minutes) (if (= minutes 3) "Failed" "Complete"))
      (incf clock 0))
    (cronjob-pass store)
    (cronjob-pass store)
    (is (equal (list (cronjob-job-name-at 2)) (cronjob-job-names store)))))

(test an-interrupted-pass-recovers-its-job-rather-than-duplicating-it
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store)
    (incf clock 61)
    ;; The earlier pass created the Job, then stopped before writing status.
    (gr8s::start-cronjob-job store (cronjob-now store) (+ *cronjob-test-start* 60) nil)
    (cronjob-pass store)
    (is (equal (list (cronjob-job-name-at 1)) (cronjob-job-names store)))
    (is (equal (list (cronjob-job-name-at 1)) (cronjob-active-names store)))))

(test foreign-job-with-the-scheduled-name-is-not-claimed
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store)
    (incf clock 61)
    (let ((foreign (batch-test-job (cronjob-job-name-at 1))))
      (gr8s::create-core-resource store "jobs" foreign "alpha"))
    (cronjob-pass store)
    (is (null (cronjob-active-names store)))
    (is (null (gethash "lastScheduleTime" (gethash "status" (cronjob-now store)))))))

(test foreground-deletion-waits-for-jobs-and-orphaning-detaches-them
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store)
    (incf clock 61)
    (cronjob-pass store)
    (gr8s::delete-workload-resource store "cronjobs" "alpha" "tick" :policy "Orphan")
    (gr8s::process-workload-deletions reconciler)
    (signals gr8s::kubernetes-error (cronjob-now store))
    (let ((job (first (gr8s::list-core-resources store "jobs" "alpha"))))
      (is (zerop (length (gethash "ownerReferences" (gethash "metadata" job) #()))))))
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store)
    (incf clock 61)
    (cronjob-pass store)
    (gr8s::delete-workload-resource store "cronjobs" "alpha" "tick" :policy "Foreground")
    (gr8s::process-workload-deletions reconciler)
    (is (gethash "deletionTimestamp" (gethash "metadata" (cronjob-now store))))
    (gr8s::process-workload-deletions reconciler)
    (gr8s::process-workload-deletions reconciler)
    (gr8s::process-workload-deletions reconciler)
    (is (null (gr8s::list-core-resources store "jobs" "alpha")))
    (signals gr8s::kubernetes-error (cronjob-now store))))

(test background-deletion-collects-the-owned-jobs
  (with-cronjob-fixture (store reconciler clock)
    (create-test-cronjob store)
    (incf clock 61)
    (cronjob-pass store)
    (gr8s::delete-workload-resource store "cronjobs" "alpha" "tick")
    (gr8s::collect-orphaned-api-objects reconciler)
    (is (null (gr8s::list-core-resources store "jobs" "alpha")))))

(test cronjob-http-surface-serves-crud-status-and-discovery
  (with-core-api (store path)
    (values path store)
    (let ((body (com.inuoe.jzon:stringify (cronjob-test-input))))
      (multiple-value-bind (object code)
          (core-api-request "/apis/batch/v1/namespaces/default/cronjobs" :method :post
                            :content-type "application/json" :octets (trivial-utf-8:string-to-utf-8-bytes body))
        (is (= 201 code))
        (is (= 1 (gethash "generation" (gethash "metadata" object))))))
    (multiple-value-bind (list code) (core-api-request "/apis/batch/v1/cronjobs")
      (is (= 200 code))
      (is (= 1 (length (gethash "items" list)))))
    (multiple-value-bind (object code)
        (core-api-request "/apis/batch/v1/namespaces/default/cronjobs/tick/status" :method :patch
                          :content-type "application/merge-patch+json"
                          :octets (trivial-utf-8:string-to-utf-8-bytes
                                   "{\"metadata\":{\"annotations\":{\"patchedstatus\":\"true\"}},\"status\":{\"lastScheduleTime\":\"2026-11-04T10:00:00Z\"}}"))
      (is (= 200 code))
      (is (equal "2026-11-04T10:00:00Z" (gethash "lastScheduleTime" (gethash "status" object))))
      (is (equal "true" (gethash "patchedstatus" (gethash "annotations" (gethash "metadata" object))))))
    (multiple-value-bind (object code) (core-api-request "/apis/batch/v1/namespaces/default/cronjobs/tick/status")
      (is (= 200 code))
      (is (stringp (gethash "uid" (gethash "metadata" object)))))
    ;; An ordinary write cannot change status.
    (multiple-value-bind (object code)
        (core-api-request "/apis/batch/v1/namespaces/default/cronjobs/tick" :method :patch
                          :content-type "application/merge-patch+json"
                          :octets (trivial-utf-8:string-to-utf-8-bytes
                                   "{\"status\":{\"lastScheduleTime\":\"2020-01-01T00:00:00Z\"}}"))
      (is (= 200 code))
      (is (equal "2026-11-04T10:00:00Z" (gethash "lastScheduleTime" (gethash "status" object)))))
    (let* ((discovery (core-api-request "/apis/batch/v1"))
           (names (map 'list (lambda (entry) (gethash "name" entry)) (gethash "resources" discovery))))
      (dolist (name '("jobs" "jobs/status" "cronjobs" "cronjobs/status"))
        (is (member name names :test #'equal))))
    (multiple-value-bind (ignored code)
        (core-api-request "/apis/batch/v1/namespaces/default/cronjobs/tick" :method :delete)
      (declare (ignore ignored))
      (is (= 200 code)))
    (is (= 404 (nth-value 1 (core-api-request "/apis/batch/v1/namespaces/default/cronjobs/tick"))))))
