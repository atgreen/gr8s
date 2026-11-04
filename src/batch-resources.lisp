;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Admit executing batch/v1 Jobs through pinned Kubernetes wire/structural
;;;; schemas and defaults, automatic UID selectors and immutable templates.
;;;; Unsupported advanced policies are rejected rather than stored inertly.

(in-package #:gr8s)

(let ((addition (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/batch-v1.json"))))
  (dolist (section '("messages" "definitions"))
    (maphash (lambda (name value) (setf (gethash name (gethash section *podtemplate-schema*)) value))
             (gethash section addition))))

(defparameter +job-tracking-finalizer+ "batch.kubernetes.io/job-tracking"
  "Hold terminal Pod identities until real Job accounting is durable.")

(defun batch-resource-p (resource)
  "Recognize the implemented batch collection without advertising CronJobs."
  (equal resource "jobs"))

(defun batch-boolean (value context &optional default)
  "Apply a boolean default while preserving explicit false values."
  (when (eq value 'null) (setf value default))
  (unless (member value '(t nil)) (core-resource-error 422 "Invalid" "~A must be a boolean" context))
  value)

(defun normalize-batch-resource (input namespace name)
  "Validate genuine executable Job state; ordinary writes never submit runtime status."
  (let* ((object (copy-core-object (require-object input "Job")))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (spec (require-object (gethash "spec" object) "spec"))
         (template (require-object (gethash "template" spec) "spec.template"))
         (pod-spec (require-object (gethash "spec" template) "spec.template.spec")))
    (unless (and (equal "batch/v1" (gethash "apiVersion" object "batch/v1"))
                 (equal "Job" (gethash "kind" object "Job")))
      (core-resource-error 400 "BadRequest" "Expected batch/v1 Job"))
    (when (eq (gethash "finalizers" metadata) 'null) (setf (gethash "finalizers" metadata) #()))
    (validate-core-metadata metadata namespace name :allow-finalizers t)
    (setf (gethash "namespace" metadata) namespace (gethash "apiVersion" object) "batch/v1" (gethash "kind" object) "Job")
    (remhash "status" object)
    (validate-template-shape object (template-schema "io.k8s.api.batch.v1.Job") "Job")
    ;; Kubernetes nullable optional pointers do not request an unsupported
    ;; policy. Preserve explicit non-null requests for admission rejection.
    (dolist (field '("podFailurePolicy" "successPolicy" "backoffLimitPerIndex" "maxFailedIndexes"))
      (when (eq (gethash field spec) 'null) (remhash field spec)))
    (reject-unsupported-fields spec '("parallelism" "completions" "activeDeadlineSeconds" "backoffLimit" "selector"
                                       "manualSelector" "template" "ttlSecondsAfterFinished" "completionMode"
                                       "suspend" "podReplacementPolicy" "managedBy") "Job.spec")
    (when (and (member (gethash "parallelism" spec) '(nil null)) (member (gethash "completions" spec) '(nil null)))
      (setf (gethash "parallelism" spec) 1 (gethash "completions" spec) 1))
    (setf (gethash "parallelism" spec) (workload-int (gethash "parallelism" spec) "Job.spec.parallelism" 1)
          (gethash "backoffLimit" spec) (workload-int (gethash "backoffLimit" spec) "Job.spec.backoffLimit" 6))
    (dolist (field '("completions" "ttlSecondsAfterFinished"))
      (if (member (gethash field spec) '(nil null)) (remhash field spec)
          (setf (gethash field spec) (workload-int (gethash field spec) field))))
    (let ((deadline (gethash "activeDeadlineSeconds" spec)))
      (if (member deadline '(nil null)) (remhash "activeDeadlineSeconds" spec)
          (unless (typep deadline '(integer 1 9223372036854775807))
            (core-resource-error 422 "Invalid" "Job.spec.activeDeadlineSeconds must be a positive int64"))))
    (dolist (field '("suspend" "manualSelector"))
      (setf (gethash field spec) (batch-boolean (gethash field spec) field)))
    (when (member (gethash "completionMode" spec) '(nil null) :test #'equal)
      (setf (gethash "completionMode" spec) "NonIndexed"))
    (unless (equal "NonIndexed" (gethash "completionMode" spec))
      (core-resource-error 422 "Invalid" "Indexed Jobs require the executing index controller"))
    (when (member (gethash "podReplacementPolicy" spec) '(nil null) :test #'equal)
      (setf (gethash "podReplacementPolicy" spec) "TerminatingOrFailed"))
    (unless (member (gethash "podReplacementPolicy" spec) '("Failed" "TerminatingOrFailed") :test #'equal)
      (core-resource-error 422 "Invalid" "Invalid Job podReplacementPolicy"))
    (when (eq (gethash "managedBy" spec) 'null) (remhash "managedBy" spec))
    (when (and (gethash "managedBy" spec) (not (equal "kubernetes.io/job-controller" (gethash "managedBy" spec))))
      (core-resource-error 422 "Invalid" "External Job controllers are not implemented"))
    (let ((embedded (gethash "metadata" template)))
      (when (member embedded '(nil null)) (setf embedded (core-object)))
      (setf (gethash "metadata" template) embedded)
      (dolist (field '("labels" "annotations"))
        (when (eq (gethash field embedded) 'null) (remhash field embedded)))
      (when (eq (gethash "finalizers" embedded) 'null) (setf (gethash "finalizers" embedded) #()))
      (let ((check (copy-core-object embedded)))
        (setf (gethash "name" check) "template")
        (validate-core-metadata check namespace nil :allow-finalizers t))
      (when (and (or (null (gethash "labels" metadata)) (zerop (hash-table-count (gethash "labels" metadata))))
                 (gethash "labels" embedded))
        (setf (gethash "labels" metadata) (copy-core-object (gethash "labels" embedded))))
      (let ((selector (gethash "selector" spec)))
        (when (eq selector 'null) (remhash "selector" spec) (setf selector nil))
        (when (or selector (gethash "manualSelector" spec))
          (validate-workload-selector selector :allow-empty t)
          (unless (workload-selector-matches-p selector (gethash "labels" embedded))
            (core-resource-error 422 "Invalid" "Job selector does not match its Pod template")))))
    (unless (member (gethash "restartPolicy" pod-spec) '("Never" "OnFailure") :test #'equal)
      (core-resource-error 422 "Invalid" "Job Pod restartPolicy must be Never or OnFailure"))
    ;; Execute only Pod features that pass the same admission used at creation.
    ;; Only these fields reach created Pods. Typed requests also carry empty
    ;; server-owned template fields such as selfLink, which a Pod would refuse.
    (let ((embedded (core-object "name" "job-template" "namespace" namespace)))
      (dolist (field '("labels" "annotations" "finalizers"))
        (when (gethash field (gethash "metadata" template))
          (setf (gethash field embedded) (copy-core-object (gethash field (gethash "metadata" template))))))
      (let ((checked (parse-pod (core-object "apiVersion" "v1" "kind" "Pod" "metadata" embedded "spec" (copy-core-object pod-spec)))))
        (setf (gethash "spec" template) (copy-core-object (gethash "spec" (pod-to-object checked))))))
    object))

(defun prepare-batch-write (object existing)
  "Bind automatic selectors to the assigned UID and preserve controller-owned status."
  (let* ((metadata (gethash "metadata" object)) (spec (gethash "spec" object))
         (template (gethash "template" spec)) (embedded (gethash "metadata" template))
         (labels (gethash "labels" embedded (core-object))))
    (unless (gethash "manualSelector" spec)
      (let ((uid (gethash "uid" metadata)) (name (gethash "name" metadata)))
        (dolist (pair (list (cons "controller-uid" uid) (cons "batch.kubernetes.io/controller-uid" uid)
                            (cons "job-name" name) (cons "batch.kubernetes.io/job-name" name)))
          (when (and (gethash (car pair) labels) (not (equal (gethash (car pair) labels) (cdr pair))))
            (core-resource-error 422 "Invalid" "Job template has conflicting automatic ownership labels"))
          (setf (gethash (car pair) labels) (cdr pair)))
        (unless existing
          (let* ((selector (gethash "selector" spec (core-object)))
                 (matches (gethash "matchLabels" selector (core-object))))
            (unless (gethash "batch.kubernetes.io/controller-uid" matches)
              (setf (gethash "batch.kubernetes.io/controller-uid" matches) uid))
            (setf (gethash "matchLabels" selector) matches (gethash "selector" spec) selector)))))
    (setf (gethash "labels" embedded) labels)
    (validate-core-metadata (core-object "name" "job-template" "labels" labels) nil nil)
    (unless (workload-selector-matches-p (gethash "selector" spec) labels)
      (core-resource-error 422 "Invalid" "Job selector does not match UID-bound template labels"))
    (when (and existing (gethash "deletionTimestamp" (gethash "metadata" existing)))
      (loop for name across (gethash "finalizers" metadata #())
            unless (find name (gethash "finalizers" (gethash "metadata" existing) #()) :test #'equal)
              do (core-resource-error 422 "Invalid" "Job finalizers cannot be added after deletion begins")))
    (when existing
      (dolist (field '("selector" "template" "completions" "completionMode" "manualSelector" "managedBy"))
        (unless (workload-equal-p (gethash field spec) (gethash field (gethash "spec" existing)))
          (core-resource-error 422 "Invalid" "Job.spec.~A is immutable" field))))
    (remhash "deletionTimestamp" metadata)
    (when (and existing (gethash "deletionTimestamp" (gethash "metadata" existing)))
      (setf (gethash "deletionTimestamp" metadata) (gethash "deletionTimestamp" (gethash "metadata" existing))))
    (setf (gethash "generation" metadata)
          (if existing (+ (gethash "generation" (gethash "metadata" existing) 1)
                          (if (workload-equal-p spec (gethash "spec" existing)) 0 1)) 1)
          (gethash "status" object) (if existing (copy-core-object (gethash "status" existing (core-object))) (core-object)))
    object))

(defun decode-batch-protobuf (bytes)
  "Decode typed Job input with the pinned batch/v1 field numbers and omission rules."
  (let* ((object (template-protobuf-message "k8s.io.api.batch.v1.Job" bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) "batch/v1" (gethash "kind" object) "Job")
    object))
