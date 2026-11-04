;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Execute NonIndexed Jobs using real UID-owned Pods. Commit uncounted terminal
;;;; identities and retry state before releasing tracking finalizers; acknowledge
;;;; finalizer removal before increasing counters, so retries/reopen cannot count
;;;; a Pod twice or invent completion from missing runtime observations.
;;;; Indexed completion and Pod failure policies are refused at admission.

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

(defun create-job-pod (store job)
  "Admit and persist a real tracked Pod only while the owner UID/generation still exists."
  (let* ((template (gethash "template" (gethash "spec" job)))
         (source (gethash "metadata" template)) (metadata (core-object))
         (namespace (gethash "namespace" (workload-metadata job)))
         (prefix (concatenate 'string (gethash "name" (workload-metadata job)) "-")))
    (dolist (key '("labels" "annotations" "finalizers"))
      (when (gethash key source) (setf (gethash key metadata) (copy-core-object (gethash key source)))))
    (setf (gethash "namespace" metadata) namespace
          (gethash "generateName" metadata) (subseq prefix 0 (min 58 (length prefix)))
          (gethash "ownerReferences" metadata) (vector (job-owner-reference job)))
    (unless (find +job-tracking-finalizer+ (gethash "finalizers" metadata #()) :test #'equal)
      (setf (gethash "finalizers" metadata)
            (concatenate 'vector (gethash "finalizers" metadata #()) (vector +job-tracking-finalizer+))))
    (let ((pod (admit-in-cluster-pod store
                 (parse-pod (core-object "apiVersion" "v1" "kind" "Pod" "metadata" metadata
                                         "spec" (copy-core-object (gethash "spec" template))) :allow-generate-name t))))
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

(defun account-job-observations (reconciler job observations)
  "Commit terminal UID evidence before removal, then count only acknowledged tracking removal."
  (let ((store (reconciler-store reconciler)))
    (commit-job-controller-update store job
      (lambda (status state)
        (let* ((tracked
                 (loop for pod being the hash-values of (pod-store-pods store)
                       when (and (equal (pod-namespace pod) (gethash "namespace" (workload-metadata job)))
                                 (workload-owned-p (pod-to-object pod) job) (job-pod-tracked-p pod))
                         collect (pod-uid pod)))
               (successes (job-uncounted-uids status "succeeded"))
               (failures (job-uncounted-uids status "failed"))
               (new-successes nil) (new-failures nil))
          (dolist (pair (list (cons "succeeded" successes) (cons "failed" failures)))
            (incf (gethash (car pair) status 0)
                  (count-if-not (lambda (uid) (member uid tracked :test #'equal)) (cdr pair))))
          (setf successes (remove-if-not (lambda (uid) (member uid tracked :test #'equal)) successes)
                failures (remove-if-not (lambda (uid) (member uid tracked :test #'equal)) failures))
          (dolist (observation observations)
            (let* ((pod (car observation)) (observed (cdr observation)) (uid (pod-uid pod))
                   (current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store))))
              (when (and (< (+ (length successes) (length failures)) 500)
                         current (equal uid (pod-uid current))
                         (workload-owned-p (pod-to-object current) job) (job-pod-tracked-p current)
                         (not (member uid successes :test #'equal)) (not (member uid failures :test #'equal)))
                (cond ((equal "Succeeded" (gethash "phase" observed))
                       (push uid successes) (push observed new-successes))
                      ((equal "Failed" (gethash "phase" observed))
                       (push uid failures) (push observed new-failures))))))
          (set-job-uncounted-uids status successes failures)
          (values status (next-job-backoff-state state new-successes new-failures)))))))

(defun remove-accounted-job-finalizer (store job pod &key deleting)
  "Release only a committed terminal identity, or a deleting owner's own tracking finalizer."
  (with-store-lock (store)
    (let* ((owner (workload-current-unlocked store "jobs" job :allow-deleting t))
           (current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store))))
      (when (and owner current (equal (pod-uid current) (pod-uid pod))
                 (workload-owned-p (pod-to-object current) owner) (job-pod-tracked-p current)
                 (or (and deleting (or (gethash "deletionTimestamp" (workload-metadata owner))
                                       (deletion-requested-p current)))
                     (let ((status (gethash "status" owner)))
                       (or (member (pod-uid current) (job-uncounted-uids status "succeeded") :test #'equal)
                           (member (pod-uid current) (job-uncounted-uids status "failed") :test #'equal)))))
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

(defun job-reconcile-observations (reconciler job claim)
  "Observe Pods, counting one deleted before finishing as failed, as the Job controller does."
  (loop for (pod . status) in (job-observations reconciler job :claim claim)
        collect (cons pod
                      (if (and (deletion-requested-p pod)
                               (not (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal)))
                          (let ((copy (copy-core-object status)))
                            (setf (gethash "phase" copy) "Failed")
                            copy)
                          status))))

(defun delete-job-pods (reconciler job pods)
  "Delete POD identities and release tracking, since these will not be counted."
  (let ((store (reconciler-store reconciler)))
    (dolist (pod pods)
      (handler-case
          (progn
            (delete-reconciled-pod reconciler (pod-namespace pod) (pod-name pod) :uid (pod-uid pod))
            (let ((current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store))))
              (when current (remove-accounted-job-finalizer store job current :deleting t))))
        (kubernetes-error (condition)
          (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))))

(defun job-terminal-decision (spec status restarts start-time)
  "Return the reason this Job must fail or complete now, as a type, reason and message."
  (let ((deadline (gethash "activeDeadlineSeconds" spec))
        (succeeded (gethash "succeeded" status 0))
        (attempts (+ (gethash "failed" status 0) restarts)))
    (cond
      ((and deadline start-time (>= (funcall *job-clock*) (+ start-time deadline)))
       (values "Failed" "DeadlineExceeded" "Job was active longer than specified deadline"))
      ((> attempts (gethash "backoffLimit" spec 6))
       (values "Failed" "BackoffLimitExceeded" "Job has reached the specified backoff limit"))
      ((job-success-goal-met-p spec succeeded 0)
       (values "Complete" "CompletionsReached" "Reached expected number of succeeded pods")))))

(defun job-pods-wanted (spec status)
  "Return how many Pods should be active now, given work already succeeded."
  (let ((parallelism (gethash "parallelism" spec 1)) (succeeded (gethash "succeeded" status 0)))
    (multiple-value-bind (completions specified) (gethash "completions" spec)
      (cond (specified (max 0 (min parallelism (- completions succeeded))))
            ((plusp succeeded) 0)
            (t parallelism)))))

(defun write-job-status (store job active ready terminating update)
  "Publish observed counts; UPDATE then applies any condition or timestamp change."
  (commit-job-controller-update store job
    (lambda (status state)
      (setf (gethash "active" status) active (gethash "ready" status) ready
            (gethash "terminating" status) terminating)
      (when update (funcall update status))
      (values status state))))

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
             (terminating (count-if (lambda (pair) (deletion-requested-p (car pair))) observations))
             (start-text (gethash "startTime" status))
             (start-time (and start-text (pod-deletion-time start-text))))
        (cond
          (finished
           (delete-job-pods reconciler job active-pods)
           (write-job-status store job 0 0 terminating nil))
          ((eq t (gethash "suspend" spec))
           (delete-job-pods reconciler job active-pods)
           (write-job-status store job 0 0 terminating
             (lambda (next)
               (remhash "startTime" next)
               (set-job-condition next "Suspended" "True" "JobSuspended" "Job suspended"))))
          (t
           (multiple-value-bind (type reason message)
               (job-terminal-decision spec status (job-onfailure-restarts observations) start-time)
             (if type
                 (progn
                   (delete-job-pods reconciler job active-pods)
                   (write-job-status store job 0 0 terminating
                     (lambda (next)
                       (set-job-condition next (if (equal type "Complete") "SuccessCriteriaMet" "FailureTarget")
                                          "True" reason message)
                       (set-job-condition next type "True" reason message)
                       (when (equal type "Complete")
                         (setf (gethash "completionTime" next) (current-timestamp (funcall *job-clock*)))))))
                 (let* ((wanted (job-pods-wanted spec status))
                        (missing (- wanted (length active)))
                        (state (gethash (gethash "uid" (workload-metadata job))
                                        (pod-store-job-controller-states store) (core-object))))
                   (cond
                     ((minusp missing)
                      (delete-job-pods reconciler job (subseq active-pods 0 (- missing))))
                     ((and (plusp missing) (>= (funcall *job-clock*) (job-backoff-until state)))
                      (loop repeat missing do (create-job-pod store job))))
                   (write-job-status store job (+ (length active) (max 0 missing)) ready terminating
                     (lambda (next)
                       (unless (gethash "startTime" next)
                         (setf (gethash "startTime" next) (current-timestamp (funcall *job-clock*))))
                       (when (job-condition-true-p next "Suspended")
                         (set-job-condition next "Suspended" "False" "JobResumed" "Job resumed")))))))))))))

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

(defun reconcile-jobs (reconciler)
  "Run one pass over all Jobs, isolating each so one failure cannot stall the others."
  (let ((store (reconciler-store reconciler)))
    (release-orphaned-job-pods store)
    (release-deleting-job-pods reconciler)
    (dolist (job (list-core-resources store "jobs"))
      (handler-case
          (unless (gethash "deletionTimestamp" (workload-metadata job))
            (reconcile-job reconciler job))
        (kubernetes-error (condition)
          (unless (member (kubernetes-error-status-code condition) '(404 409))
            (format *error-output* "gr8s jobs controller: ~A~%" condition)))
        (error (condition) (format *error-output* "gr8s jobs controller: ~A~%" condition))))))

