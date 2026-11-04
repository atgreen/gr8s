;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Execute NonIndexed Jobs using real UID-owned Pods. Commit uncounted terminal
;;;; identities and retry state before releasing tracking finalizers; acknowledge
;;;; finalizer removal before increasing counters, so retries/reopen cannot count
;;;; a Pod twice or invent completion from missing runtime observations.

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
                 (or (and deleting (gethash "deletionTimestamp" (workload-metadata owner)))
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
