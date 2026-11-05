;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Execute Jobs using real UID-owned Pods, in NonIndexed and Indexed modes.
;;;; Commit uncounted terminal identities, index sets and retry state before
;;;; releasing tracking finalizers; acknowledge finalizer removal before
;;;; increasing counters, so retries/reopen cannot count a Pod twice or invent
;;;; completion from missing runtime observations. An interim SuccessCriteriaMet
;;;; or FailureTarget condition fixes the outcome; Complete or Failed follows
;;;; only once every Pod has stopped.

(in-package #:gr8s)

(defun job-owner-reference (job)
  "Create the real blocking controller reference used by Job dependents."
  (let ((reference (workload-owner-reference job)))
    (setf (gethash "blockOwnerDeletion" reference) t)
    reference))

(defun job-pod-tracked-p (pod)
  "Read only the Job tracking finalizer, preserving unrelated user finalizers."
  (find +job-tracking-finalizer+ (pod-finalizers pod) :test #'equal))

(defun job-owned-pods (reconciler job &key claim)
  "Claim matching orphans and release mismatches with exact owner/dependent UID checks."
  (let* ((store (reconciler-store reconciler)) (metadata (workload-metadata job))
         (selector (gethash "selector" (gethash "spec" job))) (result nil))
    (dolist (pod (list-pods store (gethash "namespace" metadata)))
      (let* ((object (pod-to-object pod)) (owned (workload-owned-p object job))
             (matches (workload-selector-matches-p selector (gethash "labels" (workload-metadata object)))))
        (cond
          ((and claim owned (not matches))
           (change-controller-pod-owner store job pod nil :resource "jobs" :tracking-finalizer +job-tracking-finalizer+))
          ((and owned matches) (push pod result))
          ((and claim matches (not (deletion-requested-p pod)) (null (workload-controller-reference object)))
           (let ((adopted (change-controller-pod-owner store job pod t :resource "jobs"
                           :tracking-finalizer +job-tracking-finalizer+ :reference (job-owner-reference job))))
             (when adopted (push adopted result)))))))
    (nreverse result)))

(defun job-pod-name-prefix (job index)
  "Name a Pod after its Job, and its index if it has one, within the generated name limit."
  (let ((name (gethash "name" (workload-metadata job)))
        (suffix (if index (format nil "-~D-" index) "-")))
    (concatenate 'string (subseq name 0 (min (- 58 (length suffix)) (length name))) suffix)))

(defun add-job-index-environment (spec)
  "Expose the completion index to every container that does not define it itself."
  (dolist (field '("containers" "initContainers"))
    (loop for container across (gethash field spec #())
          for env = (let ((value (gethash "env" container))) (if (or (null value) (eq value 'null)) #() value))
          unless (find "JOB_COMPLETION_INDEX" env :key (lambda (entry) (gethash "name" entry)) :test #'equal)
            do (setf (gethash "env" container)
                     (concatenate 'vector env
                       (vector (core-object "name" "JOB_COMPLETION_INDEX" "valueFrom"
                                 (core-object "fieldRef"
                                   (core-object "fieldPath"
                                     (format nil "metadata.labels['~A']" +job-completion-index-key+)))))))))
  spec)

(defun apply-job-pod-index (job metadata spec index state)
  "Bind Pod METADATA and SPEC to completion INDEX, with its stable hostname and failure counts."
  (let ((annotations (or (gethash "annotations" metadata) (setf (gethash "annotations" metadata) (core-object))))
        (labels (or (gethash "labels" metadata) (setf (gethash "labels" metadata) (core-object))))
        (text (format nil "~D" index)))
    (setf (gethash +job-completion-index-key+ annotations) text
          (gethash +job-completion-index-key+ labels) text)
    (when (job-per-index-limit (gethash "spec" job))
      (multiple-value-bind (count ignored) (job-index-counts state index)
        (setf (gethash +job-index-failure-count-key+ annotations) (format nil "~D" count))
        (when (plusp ignored)
          (setf (gethash +job-index-ignored-failure-count-key+ annotations) (format nil "~D" ignored)))))
    (when (member (gethash "hostname" spec) '(nil null "") :test #'equal)
      (setf (gethash "hostname" spec) (format nil "~A-~D" (gethash "name" (workload-metadata job)) index)))
    (add-job-index-environment spec)))

(defun create-job-pod (store job &key index state)
  "Admit and persist a real tracked Pod only while the owner UID/generation still exists."
  (let* ((template (gethash "template" (gethash "spec" job)))
         (source (gethash "metadata" template)) (metadata (core-object))
         (spec (copy-core-object (gethash "spec" template)))
         (namespace (gethash "namespace" (workload-metadata job))))
    (dolist (key '("labels" "annotations" "finalizers"))
      (when (gethash key source) (setf (gethash key metadata) (copy-core-object (gethash key source)))))
    (setf (gethash "namespace" metadata) namespace
          (gethash "generateName" metadata) (job-pod-name-prefix job index)
          (gethash "ownerReferences" metadata) (vector (job-owner-reference job)))
    (when index (apply-job-pod-index job metadata spec index (or state (core-object))))
    (unless (find +job-tracking-finalizer+ (gethash "finalizers" metadata #()) :test #'equal)
      (setf (gethash "finalizers" metadata)
            (concatenate 'vector (gethash "finalizers" metadata #()) (vector +job-tracking-finalizer+))))
    (let ((pod (admit-controller-pod
                store (core-object "apiVersion" "v1" "kind" "Pod" "metadata" metadata "spec" spec) "job-controller")))
      (with-store-lock (store)
        (when (workload-current-unlocked store "jobs" job :generation t)
          (create-pod-unlocked store pod))))))

(defun job-observations (reconciler job &key claim)
  "Pair managed Pods with actual reconciliation observations, never fabricated success."
  (loop for pod in (job-owned-pods reconciler job :claim claim)
        collect (cons pod (workload-pod-status reconciler pod))))

(defun commit-job-controller-update (store job transform)
  "Atomically checkpoint observed status and retry state for the current owner UID/generation."
  (with-store-lock (store)
    (let ((current (workload-current-unlocked store "jobs" job :generation t :allow-deleting t)))
      (when current
        (let* ((uid (gethash "uid" (workload-metadata current)))
               (status (copy-core-object (gethash "status" current (core-object))))
               (previous (gethash uid (pod-store-job-controller-states store) (core-object))))
          (multiple-value-bind (new-status new-state) (funcall transform status (copy-core-object previous))
            (if (and (workload-equal-p new-status (gethash "status" current (core-object)))
                     (workload-equal-p new-state previous))
                (copy-core-object current)
                (let* ((copy (copy-core-object current)) (resources (copy-core-resource-index store))
                       (states (copy-core-object (pod-store-job-controller-states store)))
                       (revision (1+ (pod-store-resource-revision store))))
                  (setf (gethash "status" copy) new-status (gethash uid states) new-state)
                  (prepare-core-resource-metadata copy current revision)
                  (setf (gethash (core-resource-key "jobs" (gethash "namespace" (workload-metadata copy))
                                                  (gethash "name" (workload-metadata copy))) resources) copy)
                  (commit-core-resources store resources revision :job-controller-states states)
                  copy))))))))

(defun job-uncounted-uids (status kind)
  "Read a pending terminal UID set without treating absent status as completion."
  (coerce (gethash kind (gethash "uncountedTerminatedPods" status (core-object)) #()) 'list))

(defun set-job-uncounted-uids (status successes failures)
  "Write the actual pending terminal identities using pinned JobStatus field names."
  (let ((uncounted (core-object)))
    (when successes (setf (gethash "succeeded" uncounted) (coerce successes 'vector)))
    (when failures (setf (gethash "failed" uncounted) (coerce failures 'vector)))
    (setf (gethash "uncountedTerminatedPods" status) uncounted))
  status)

(defun job-releasable-uids (state)
  "Read Pods committed as needing no count, only release of their tracking finalizer."
  (coerce (gethash "releasablePods" state #()) 'list))

(defun record-job-index-failure (state index time ignored)
  "Add one failure of INDEX to its durable record and return its counted total."
  (let ((record (job-index-record state index)))
    (if ignored
        (incf (gethash "ignored" record 0))
        (setf (gethash "last" record) time))
    (if ignored
        (gethash "count" record 0)
        (incf (gethash "count" record 0)))))

(defun write-job-index-sets (status spec completed failed)
  "Publish index sets, deriving an Indexed Job's success count from its completed set."
  (when (job-indexed-p spec)
    (setf (gethash "succeeded" status) (job-indexes-total completed))
    (if completed
        (setf (gethash "completedIndexes" status) (format-job-indexes completed))
        (remhash "completedIndexes" status))
    (when (job-per-index-limit spec)
      (setf (gethash "failedIndexes" status) (format-job-indexes failed))))
  status)

(defun account-job-observations (reconciler job observations)
  "Commit terminal UID evidence before removal, then count only acknowledged tracking removal."
  (let* ((store (reconciler-store reconciler)) (spec (gethash "spec" job))
         (indexed (job-indexed-p spec)) (limit (job-per-index-limit spec))
         (completions (gethash "completions" spec 0)))
    (commit-job-controller-update store job
      (lambda (status state)
        (let* ((tracked
                 (loop for pod being the hash-values of (pod-store-pods store)
                       when (and (equal (pod-namespace pod) (gethash "namespace" (workload-metadata job)))
                                 (workload-owned-p (pod-to-object pod) job) (job-pod-tracked-p pod))
                         collect (pod-uid pod)))
               (successes (job-uncounted-uids status "succeeded"))
               (failures (job-uncounted-uids status "failed"))
               (releasable (remove-if-not (lambda (uid) (member uid tracked :test #'equal))
                                          (job-releasable-uids state)))
               ;; A scaled-down Indexed Job forgets indexes it no longer has.
               (completed (job-indexes-below (parse-job-indexes (gethash "completedIndexes" status ""))
                                             (or (gethash "completions" (gethash "spec" job)) most-positive-fixnum)))
               (failed-indexes (parse-job-indexes (gethash "failedIndexes" status "")))
               (new-successes nil) (new-failures nil))
          (dolist (pair (list (cons "succeeded" successes) (cons "failed" failures)))
            (incf (gethash (car pair) status 0)
                  (count-if-not (lambda (uid) (member uid tracked :test #'equal)) (cdr pair))))
          (setf successes (remove-if-not (lambda (uid) (member uid tracked :test #'equal)) successes)
                failures (remove-if-not (lambda (uid) (member uid tracked :test #'equal)) failures))
          (dolist (observation observations)
            (let* ((pod (car observation)) (observed (cdr observation)) (uid (pod-uid pod))
                   (current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store)))
                   (index (and indexed current (job-pod-completion-index current)))
                   (usable (and index (< index completions))))
              (when (and (< (+ (length successes) (length failures) (length releasable)) 500)
                         current (equal uid (pod-uid current))
                         (workload-owned-p (pod-to-object current) job) (job-pod-tracked-p current)
                         (not (member uid successes :test #'equal)) (not (member uid failures :test #'equal))
                         (not (member uid releasable :test #'equal)))
                (cond
                  ((equal "Succeeded" (gethash "phase" observed))
                   (cond ((not indexed) (push uid successes) (push observed new-successes))
                         (t (push uid releasable)
                            (when (and usable (not (job-indexes-member-p index completed))
                                       (not (job-indexes-member-p index failed-indexes)))
                              (setf completed (job-indexes-add index completed))
                              (push observed new-successes)))))
                  ((equal "Failed" (gethash "phase" observed))
                   (multiple-value-bind (action message) (job-pod-failure-action spec current observed)
                     (cond
                       ((and indexed (not usable)) (push uid releasable))
                       ((equal action "Ignore")
                        (push uid releasable)
                        (when (and indexed limit)
                          (record-job-index-failure state index (job-pod-finished-time observed) t)))
                       (t
                        (push uid failures) (push observed new-failures)
                        (when (and indexed limit)
                          (let ((count (record-job-index-failure state index (job-pod-finished-time observed) nil)))
                            (when (and (or (> count limit) (equal action "FailIndex"))
                                       (not (job-indexes-member-p index completed)))
                              (setf failed-indexes (job-indexes-add index failed-indexes)))))
                        (when (and message (not (job-finishing-condition status)))
                          (set-job-condition status "FailureTarget" "True" "PodFailurePolicy" message))))))))))
          (set-job-uncounted-uids status successes failures)
          (write-job-index-sets status spec completed failed-indexes)
          (let ((next (next-job-backoff-state state new-successes new-failures)))
            (if releasable
                (setf (gethash "releasablePods" next) (coerce releasable 'vector))
                (remhash "releasablePods" next))
            (values status next)))))))

(defun remove-accounted-job-finalizer (store job pod &key deleting)
  "Release only a committed terminal identity, or a deleting owner's own tracking finalizer."
  (with-store-lock (store)
    (let* ((owner (workload-current-unlocked store "jobs" job :allow-deleting t))
           (current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store))))
      (when (and owner current (equal (pod-uid current) (pod-uid pod))
                 (workload-owned-p (pod-to-object current) owner) (job-pod-tracked-p current)
                 (or (and deleting (or (gethash "deletionTimestamp" (workload-metadata owner))
                                       (deletion-requested-p current)))
                     (let ((status (gethash "status" owner))
                           (state (gethash (gethash "uid" (workload-metadata owner))
                                           (pod-store-job-controller-states store) (core-object))))
                       (or (member (pod-uid current) (job-uncounted-uids status "succeeded") :test #'equal)
                           (member (pod-uid current) (job-uncounted-uids status "failed") :test #'equal)
                           (member (pod-uid current) (job-releasable-uids state) :test #'equal)))))
        (let* ((object (copy-core-object (pod-to-object current))) (metadata (workload-metadata object)))
          (setf (gethash "finalizers" metadata) (remove +job-tracking-finalizer+ (pod-finalizers current) :test #'equal))
          (update-pod-unlocked store (parse-pod object) (pod-resource-version current)))))))

(defun flush-job-terminal-accounting (reconciler job observations)
  "Perform the durable-before-finalizer handoff and acknowledge removals without double counting."
  (let ((committed (account-job-observations reconciler job observations)))
    (when committed
      (dolist (pair observations)
        (remove-accounted-job-finalizer (reconciler-store reconciler) committed (car pair)))
      (account-job-observations reconciler committed observations))))

(defun job-pod-runtime-deleted-p (store pod)
  "Report that POD's containers are gone though finalizers still hold its API object."
  (gethash "runtimeDeleted" (or (pod-finalization-state store pod) (core-object))))

(defun job-reconcile-observations (reconciler job claim)
  "Observe Pods, deciding when one deleted before finishing counts as failed.
A Job that replaces only failed Pods waits for the Pod to stop, as a kubelet would report;
any other, and a Job already failing, counts it at once."
  (let* ((store (reconciler-store reconciler))
         (spec (gethash "spec" job))
         (finishing (job-finishing-condition (gethash "status" job (core-object))))
         (failing (and finishing (equal "FailureTarget" (gethash "type" finishing)))))
    (loop for (pod . status) in (job-observations reconciler job :claim claim)
          collect (cons pod
                        (if (and (deletion-requested-p pod)
                                 (not (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal))
                                 (or failing (not (job-only-replace-failed-p spec))
                                     (job-pod-runtime-deleted-p store pod)))
                            (let ((copy (copy-core-object status)))
                              (setf (gethash "phase" copy) "Failed")
                              copy)
                            status)))))

(defun delete-job-pods (reconciler job pods &key (release t))
  "Delete POD identities. RELEASE drops tracking so they are not counted; otherwise accounting decides."
  (let ((store (reconciler-store reconciler)))
    (dolist (pod pods)
      (handler-case
          (when (delete-controller-pod reconciler (pod-namespace pod) (pod-name pod) "job-controller" :uid (pod-uid pod))
            (when release
              (let ((current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store))))
                (when current (remove-accounted-job-finalizer store job current :deleting t)))))
        (kubernetes-error (condition)
          (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))))

(defun job-terminal-decision (spec status restarts start-time active)
  "Return the outcome this Job has reached, as a type, reason and message."
  (let* ((deadline (gethash "activeDeadlineSeconds" spec))
         (succeeded (gethash "succeeded" status 0))
         (failures (+ (gethash "failed" status 0) (length (job-uncounted-uids status "failed"))))
         (limit (gethash "backoffLimit" spec 6))
         (completed (parse-job-indexes (gethash "completedIndexes" status "")))
         (failed-indexes (parse-job-indexes (gethash "failedIndexes" status "")))
         (allowed-failures (gethash "maxFailedIndexes" spec))
         (finishing (job-finishing-condition status)))
    (cond
      (finishing
       (values (if (equal "FailureTarget" (gethash "type" finishing)) "Failed" "Complete")
               (gethash "reason" finishing) (gethash "message" finishing)))
      ;; Failed Pods may reach the limit, while restarts in place count against it as soon as they meet it.
      ((or (> failures limit) (if (zerop limit) (plusp restarts) (>= restarts limit)))
       (values "Failed" "BackoffLimitExceeded" "Job has reached the specified backoff limit"))
      ((and deadline start-time (>= (funcall *job-clock*) (+ start-time deadline)))
       (values "Failed" "DeadlineExceeded" "Job was active longer than specified deadline"))
      ((and allowed-failures (> (job-indexes-total failed-indexes) allowed-failures))
       (values "Failed" "MaxFailedIndexesExceeded" "Job has exceeded the specified maximal number of failed indexes"))
      ((and failed-indexes
            (>= (+ (job-indexes-total failed-indexes) (job-indexes-total completed)) (gethash "completions" spec 0)))
       (values "Failed" "FailedIndexes" "Job has failed indexes"))
      ((and (job-indexed-p spec) (job-success-policy-message spec completed))
       (values "Complete" "SuccessPolicy" (job-success-policy-message spec completed)))
      ((job-success-goal-met-p spec succeeded active)
       (values "Complete" "CompletionsReached" "Reached expected number of succeeded pods")))))

(defun job-pods-wanted (spec status active)
  "Return how many Pods should be active now, given work already finished."
  (let ((parallelism (gethash "parallelism" spec 1)) (succeeded (gethash "succeeded" status 0))
        (failed-indexes (job-indexes-total (parse-job-indexes (gethash "failedIndexes" status "")))))
    (multiple-value-bind (completions specified) (gethash "completions" spec)
      (cond (specified (max 0 (min parallelism (- completions succeeded failed-indexes))))
            ((plusp succeeded) active)
            (t parallelism)))))

(defun write-job-status (store job active ready terminating update)
  "Publish observed counts; UPDATE then applies any condition or timestamp change."
  (commit-job-controller-update store job
    (lambda (status state)
      (setf (gethash "active" status) active (gethash "ready" status) ready
            (gethash "terminating" status) terminating)
      (when update (funcall update status))
      (values status state))))

(defun job-terminating-observation-p (store pod status)
  "Count a deleted Pod until it reports a terminal phase or its containers are gone."
  (and (deletion-requested-p pod)
       (not (equal "Deleted" (gethash "reason" status)))
       (not (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal))
       (not (job-pod-runtime-deleted-p store pod))))

(defun job-pending-indexes (spec status state active-pods waiting-pods wanted)
  "Choose up to WANTED of the lowest indexes that have no Pod and are past their retry delay."
  (let ((completed (parse-job-indexes (gethash "completedIndexes" status "")))
        (failed (parse-job-indexes (gethash "failedIndexes" status "")))
        (busy (remove nil (mapcar #'job-pod-completion-index (append active-pods waiting-pods))))
        (per-index (job-per-index-limit spec)) (now (funcall *job-clock*)))
    (when (or per-index (>= now (job-backoff-until state)))
      (loop with found = 0
            for index from 0 below (gethash "completions" spec 0)
            while (< found wanted)
            when (and (not (job-indexes-member-p index completed)) (not (job-indexes-member-p index failed))
                      (not (member index busy))
                      (or (not per-index) (>= now (job-index-backoff-until state index))))
              collect index and do (incf found)))))

(defun job-surplus-indexed-pods (spec status active-pods)
  "Find active Pods without a usable index, duplicating one, or working on an index already decided."
  (let ((completed (parse-job-indexes (gethash "completedIndexes" status "")))
        (failed (parse-job-indexes (gethash "failedIndexes" status "")))
        (completions (gethash "completions" spec 0)) (seen nil) (surplus nil))
    (dolist (pod active-pods (nreverse surplus))
      (let ((index (job-pod-completion-index pod)))
        (if (or (null index) (>= index completions) (member index seen)
                (job-indexes-member-p index completed) (job-indexes-member-p index failed))
            (push pod surplus)
            (push index seen))))))

(defun finish-job (reconciler job type reason message active-pods terminating)
  "Record the outcome and stop active Pods; declare Complete or Failed only once all have stopped."
  (delete-job-pods reconciler job active-pods :release nil)
  (write-job-status (reconciler-store reconciler) job 0 0 (+ terminating (length active-pods))
    (lambda (next)
      (set-job-condition next (if (equal type "Complete") "SuccessCriteriaMet" "FailureTarget")
                         "True" reason message)
      (when (and (null active-pods) (zerop terminating)
                 (null (job-uncounted-uids next "succeeded")) (null (job-uncounted-uids next "failed")))
        (set-job-condition next type "True" reason message)
        (when (equal type "Complete")
          (setf (gethash "completionTime" next) (current-timestamp (funcall *job-clock*))))))))

(defun run-job-pods (reconciler job status active-pods waiting-pods ready terminating)
  "Move the number of active Pods toward what this Job still wants, then publish status."
  (let* ((store (reconciler-store reconciler)) (spec (gethash "spec" job))
         (state (gethash (gethash "uid" (workload-metadata job))
                         (pod-store-job-controller-states store) (core-object)))
         (surplus (when (job-indexed-p spec) (job-surplus-indexed-pods spec status active-pods)))
         (working (set-difference active-pods surplus))
         (wanted (job-pods-wanted spec status (length working)))
         (missing (- wanted (length working) (if (job-only-replace-failed-p spec) terminating 0)))
         (created 0))
    (when surplus (delete-job-pods reconciler job surplus))
    (cond
      ((> (length working) wanted)
       (let ((ordered (if (job-indexed-p spec)
                          (sort (copy-list working) #'> :key #'job-pod-completion-index)
                          working)))
         (delete-job-pods reconciler job (subseq ordered 0 (- (length working) wanted)))
         (setf working (subseq ordered (- (length working) wanted)))))
      ((and (plusp missing) (job-indexed-p spec))
       (dolist (index (job-pending-indexes spec status state working waiting-pods missing))
         (when (create-job-pod store job :index index :state state) (incf created))))
      ((and (plusp missing) (>= (funcall *job-clock*) (job-backoff-until state)))
       (loop repeat missing do (when (create-job-pod store job) (incf created)))))
    (write-job-status store job (+ (length working) created) ready terminating
      (lambda (next)
        (unless (gethash "startTime" next)
          (setf (gethash "startTime" next) (current-timestamp (funcall *job-clock*))))
        (when (job-condition-true-p next "Suspended")
          (set-job-condition next "Suspended" "False" "JobResumed" "Job resumed"))))))

(defun reconcile-job (reconciler job)
  "Drive one Job toward its goal from actual Pod observations and durable accounting."
  (let* ((store (reconciler-store reconciler))
         (metadata (workload-metadata job)) (namespace (gethash "namespace" metadata))
         (finished (job-terminal-condition (gethash "status" job (core-object)))))
    (let ((observations (job-reconcile-observations reconciler job (not finished))))
      (flush-job-terminal-accounting reconciler job observations)
      (let* ((job (handler-case (get-core-resource store "jobs" namespace (gethash "name" metadata))
                    (kubernetes-error (condition)
                      (when (= 404 (kubernetes-error-status-code condition))
                        (return-from reconcile-job nil))
                      (error condition))))
             (spec (gethash "spec" job))
             (status (gethash "status" job (core-object)))
             (observations (job-observations reconciler job))
             (active (remove-if-not (lambda (pair) (job-active-observation-p (car pair) (cdr pair))) observations))
             (active-pods (mapcar #'car active))
             (ready (count-if (lambda (pair) (pod-status-ready-p (cdr pair))) active))
             (waiting (remove-if-not (lambda (pair) (job-terminating-observation-p store (car pair) (cdr pair)))
                                     observations))
             (waiting-pods (mapcar #'car waiting))
             (terminating (length waiting))
             (start-text (gethash "startTime" status))
             (start-time (and start-text (pod-deletion-time start-text))))
        (cond
          (finished
           (delete-job-pods reconciler job active-pods)
           (write-job-status store job 0 0 terminating nil))
          ((and (eq t (gethash "suspend" spec)) (not (job-finishing-condition status)))
           (delete-job-pods reconciler job active-pods)
           (write-job-status store job 0 0 terminating
             (lambda (next)
               (remhash "startTime" next)
               (set-job-condition next "Suspended" "True" "JobSuspended" "Job suspended"))))
          (t
           (multiple-value-bind (type reason message)
               (job-terminal-decision spec status (job-onfailure-restarts observations) start-time
                                      (length active-pods))
             (if type
                 (finish-job reconciler job type reason message active-pods terminating)
                 (run-job-pods reconciler job status active-pods
                               (if (job-only-replace-failed-p spec) waiting-pods nil)
                               ready terminating)))))))))

(defun release-orphaned-job-pods (store)
  "Remove tracking from Pods whose Job UID no longer exists, so they can be collected."
  (with-store-lock (store)
    (let ((jobs (loop for key being the hash-keys of (pod-store-resources store) using (hash-value object)
                      when (equal "jobs" (first key))
                        collect (gethash "uid" (workload-metadata object)))))
      (dolist (pod (loop for pod being the hash-values of (pod-store-pods store) collect pod))
        (when (job-pod-tracked-p pod)
          (let* ((object (copy-core-object (pod-to-object pod)))
                 (owner (workload-controller-reference object)))
            (unless (and owner (member (gethash "uid" owner) jobs :test #'equal))
              (setf (gethash "finalizers" (workload-metadata object))
                    (remove +job-tracking-finalizer+ (pod-finalizers pod) :test #'equal))
              (update-pod-unlocked store (parse-pod object) (pod-resource-version pod)))))))))

(defun release-deleting-job-pods (reconciler)
  "Release tracking for Pods of a Job with a pending foreground or orphan deletion."
  (let ((store (reconciler-store reconciler)))
    (dolist (job (list-core-resources store "jobs"))
      (when (gethash "deletionTimestamp" (workload-metadata job))
        (dolist (pod (list-pods store (gethash "namespace" (workload-metadata job))))
          (when (and (workload-owned-p (pod-to-object pod) job) (job-pod-tracked-p pod))
            (remove-accounted-job-finalizer store job pod :deleting t)))))))

(defun job-managed-here-p (job)
  "Report whether this controller, not one named by spec.managedBy, runs JOB."
  (member (gethash "managedBy" (gethash "spec" job) "kubernetes.io/job-controller")
          '("kubernetes.io/job-controller") :test #'equal))

(defun collect-finished-job (store job)
  "Delete a finished Job once ttlSecondsAfterFinished has passed since it finished."
  (let* ((ttl (gethash "ttlSecondsAfterFinished" (gethash "spec" job)))
         (condition (job-terminal-condition (gethash "status" job (core-object))))
         (finished (and ttl condition (ignore-errors (pod-deletion-time (gethash "lastTransitionTime" condition))))))
    (when (and finished (>= (funcall *job-clock*) (+ finished ttl)))
      (let ((metadata (workload-metadata job)))
        (when (controller-delete-allowed-p store "jobs" (gethash "namespace" metadata) (gethash "name" metadata)
                                           "ttl-after-finished-controller")
          (delete-workload-resource store "jobs" (gethash "namespace" metadata) (gethash "name" metadata)
                                    :uid (gethash "uid" metadata) :policy "Foreground"))))))

(defun forget-deleted-job-states (store)
  "Drop retry and index records of Jobs that no longer exist, so they cannot accumulate."
  (with-store-lock (store)
    (let* ((states (pod-store-job-controller-states store))
           (live (loop for key being the hash-keys of (pod-store-resources store) using (hash-value object)
                       when (equal "jobs" (first key)) collect (gethash "uid" (workload-metadata object))))
           (stale (loop for uid being the hash-keys of states
                        unless (member uid live :test #'equal) collect uid)))
      (when stale
        (let ((next (copy-core-object states)))
          (dolist (uid stale) (remhash uid next))
          (commit-core-resources store (copy-core-resource-index store) (1+ (pod-store-resource-revision store))
                                 :job-controller-states next))))))

(defun reconcile-jobs (reconciler)
  "Run one pass over all Jobs, isolating each so one failure cannot stall the others."
  (let ((store (reconciler-store reconciler)))
    (release-orphaned-job-pods store)
    (release-deleting-job-pods reconciler)
    (forget-deleted-job-states store)
    (dolist (job (list-core-resources store "jobs"))
      (handler-case
          (unless (gethash "deletionTimestamp" (workload-metadata job))
            ;; A Job managed elsewhere is left to its controller until it finishes.
            (when (job-managed-here-p job) (reconcile-job reconciler job))
            (collect-finished-job store job))
        (kubernetes-error (condition)
          (unless (member (kubernetes-error-status-code condition) '(404 409))
            (format *error-output* "gr8s jobs controller: ~A~%" condition)))
        (error (condition) (format *error-output* "gr8s jobs controller: ~A~%" condition))))))
