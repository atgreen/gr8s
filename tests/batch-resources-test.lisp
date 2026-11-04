;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify pinned Job defaulting, automatic exact-UID ownership, immutable
;;;; templates, nullable policies and typed wire presence before API admission.

(in-package #:gr8s/tests)
(def-suite batch-resources :in gr8s)
(in-suite batch-resources)

(defun batch-test-job (&optional (name "work"))
  "Build an executing NonIndexed Job input around a supported Pod template."
  (let ((spec (gr8s::copy-core-object (gethash "spec" (pod-to-object (parse-pod *valid-pod-json*))))))
    (setf (gethash "restartPolicy" spec) "OnFailure")
    (gr8s::core-object "apiVersion" "batch/v1" "kind" "Job" "metadata" (gr8s::core-object "name" name)
                      "spec" (gr8s::core-object "template" (gr8s::core-object "metadata" (gr8s::core-object)
                                                                             "spec" spec)))))

(defun normalize-test-job (input)
  "Apply production Job admission without exposing an inert public collection."
  (gr8s::normalize-batch-resource input "default" nil))

(defun prepare-test-job (input &optional existing)
  "Simulate core metadata assignment before production automatic ownership binding."
  (let ((object (normalize-test-job input)))
    (setf (gethash "uid" (gethash "metadata" object)) "job-owner-uid")
    (gr8s::prepare-batch-write object existing)))

(test job-defaults-distinguish-fixed-completions-from-work-queues-and-zero-work
  (let ((spec (gethash "spec" (normalize-test-job (batch-test-job)))))
    (is (= 1 (gethash "parallelism" spec)))
    (is (= 1 (gethash "completions" spec)))
    (is (= 6 (gethash "backoffLimit" spec)))
    (is (equal "NonIndexed" (gethash "completionMode" spec)))
    (is-false (gethash "suspend" spec)))
  (let ((input (batch-test-job)))
    (setf (gethash "parallelism" (gethash "spec" input)) 2)
    (let ((spec (gethash "spec" (normalize-test-job input))))
      (is (= 2 (gethash "parallelism" spec)))
      (is-false (nth-value 1 (gethash "completions" spec)))))
  (let ((input (batch-test-job)))
    (setf (gethash "parallelism" (gethash "spec" input)) 0
          (gethash "completions" (gethash "spec" input)) 0
          (gethash "backoffLimit" (gethash "spec" input)) 0)
    (let ((spec (gethash "spec" (normalize-test-job input))))
      (is (= 0 (gethash "parallelism" spec)))
      (is (= 0 (gethash "completions" spec)))
      (is (= 0 (gethash "backoffLimit" spec))))))

(test jobs-reject-invalid-runtime-policy-and-accept-null-policies
  (dolist (pair '(("parallelism" -1) ("completions" -1) ("backoffLimit" -1)
                  ("activeDeadlineSeconds" 0) ("completionMode" "") ("completionMode" "Other")
                  ("podReplacementPolicy" "Invalid") ("suspend" "false")
                  ("backoffLimitPerIndex" 0) ("maxFailedIndexes" 0)))
    (let ((input (batch-test-job)))
      (setf (gethash (first pair) (gethash "spec" input)) (second pair))
      (signals gr8s:kubernetes-error (normalize-test-job input))))
  (let ((input (batch-test-job)))
    (setf (gethash "restartPolicy" (gethash "spec" (gethash "template" (gethash "spec" input)))) "Always")
    (signals gr8s:kubernetes-error (normalize-test-job input)))
  (dolist (field '("podFailurePolicy" "successPolicy" "backoffLimitPerIndex" "maxFailedIndexes"))
    (let ((input (batch-test-job)))
      (setf (gethash field (gethash "spec" input)) 'null)
      (is-false (nth-value 1 (gethash field (gethash "spec" (normalize-test-job input))))))))

(test job-automatic-selectors-bind-the-real-uid-and-template-is-immutable
  (let* ((created (prepare-test-job (batch-test-job)))
         (spec (gethash "spec" created))
         (labels (gethash "labels" (gethash "metadata" (gethash "template" spec))))
         (selector-labels (gethash "matchLabels" (gethash "selector" spec))))
    (is (equal "job-owner-uid" (gethash "batch.kubernetes.io/controller-uid" labels)))
    (is (equal "job-owner-uid" (gethash "controller-uid" labels)))
    (is (equal "work" (gethash "batch.kubernetes.io/job-name" labels)))
    (is (equal "job-owner-uid" (gethash "batch.kubernetes.io/controller-uid" selector-labels)))
    (is (= 1 (gethash "generation" (gethash "metadata" created))))
    (let* ((copy (gr8s::copy-core-object created))
           (updated (progn (setf (gethash "parallelism" (gethash "spec" copy)) 4)
                           (prepare-test-job copy created))))
      (is (= 2 (gethash "generation" (gethash "metadata" updated)))))
    (let* ((copy (gr8s::copy-core-object created))
           (pod-spec (gethash "spec" (gethash "template" (gethash "spec" copy))))
           (container (aref (gethash "containers" pod-spec) 0)))
      (setf (gethash "image" container) "different")
      (signals gr8s:kubernetes-error (prepare-test-job copy created)))))

(test job-manual-empty-selectors-do-not-weaken-apps-selector-validation
  (let ((input (batch-test-job)))
    (setf (gethash "manualSelector" (gethash "spec" input)) t
          (gethash "selector" (gethash "spec" input)) (gr8s::core-object))
    (is (hash-table-p (gethash "selector" (gethash "spec" (normalize-test-job input)))))
    (signals gr8s:kubernetes-error (gr8s::validate-workload-selector (gr8s::core-object)))))

(test job-protobuf-preserves-explicit-zero-counts-and-false-suspension
  (let* ((container (core-test-protobuf '((1 "main") (2 "busybox:1.36.1"))))
         (pod-spec (core-test-protobuf (list (list 2 container) (list 3 "Never"))))
         (template (core-test-protobuf (list (list 1 #()) (list 2 pod-spec))))
         (spec (core-test-protobuf (list (list 1 0) (list 2 0) (list 6 template) (list 7 0) (list 10 0))))
         (object (gr8s::decode-batch-protobuf
                  (core-test-protobuf (list (list 1 (core-test-protobuf '((1 "wire")))) (list 2 spec))))))
    (let ((normalized (gethash "spec" (normalize-test-job object))))
      (is (= 0 (gethash "parallelism" normalized)))
      (is (= 0 (gethash "completions" normalized)))
      (is (= 0 (gethash "backoffLimit" normalized)))
      (is-false (gethash "suspend" normalized)))))

(test typed-template-metadata-with-empty-server-fields-is-accepted
  ;; Protobuf decoding of ObjectMeta fills in fields such as an empty selfLink.
  (let* ((input (batch-test-job))
         (metadata (gethash "metadata" (gethash "template" (gethash "spec" input)))))
    (setf (gethash "selfLink" metadata) "" (gethash "uid" metadata) ""
          (gethash "labels" metadata) (gr8s::core-object "job" "work"))
    (let ((object (normalize-test-job input)))
      (is (equal "work" (gethash "job" (gethash "labels" (gethash "metadata" (gethash "template" (gethash "spec" object))))))))))

