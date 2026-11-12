;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify pinned Job defaulting, automatic exact-UID ownership, immutable
;;;; templates, nullable policies and typed wire presence before API admission.

(in-package #:gr8s/tests)
(def-suite batch-resources :in gr8s)
(in-suite batch-resources)

(defun batch-test-job (&optional (name "work"))
  "Build an executing NonIndexed Job input around a supported Pod template."
  (let ((spec (gr8s.resources::copy-core-object (gethash "spec" (pod-to-object (parse-pod *valid-pod-json*))))))
    (setf (gethash "restartPolicy" spec) "OnFailure")
    (gr8s.resources::core-object "apiVersion" "batch/v1" "kind" "Job" "metadata" (gr8s.resources::core-object "name" name)
                      "spec" (gr8s.resources::core-object "template" (gr8s.resources::core-object "metadata" (gr8s.resources::core-object)
                                                                             "spec" spec)))))

(defun normalize-test-job (input)
  "Apply production Job admission without exposing an inert public collection."
  (gr8s.resources::normalize-batch-resource input "default" nil))

(defun prepare-test-job (input &optional existing)
  "Simulate core metadata assignment before production automatic ownership binding."
  (let ((object (normalize-test-job input)))
    (setf (gethash "uid" (gethash "metadata" object)) "job-owner-uid")
    (gr8s.resources::prepare-batch-write object existing)))

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
      (signals gr8s.model::kubernetes-error (normalize-test-job input))))
  (let ((input (batch-test-job)))
    (setf (gethash "restartPolicy" (gethash "spec" (gethash "template" (gethash "spec" input)))) "Always")
    (signals gr8s.model::kubernetes-error (normalize-test-job input)))
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
    (let* ((copy (gr8s.resources::copy-core-object created))
           (updated (progn (setf (gethash "parallelism" (gethash "spec" copy)) 4)
                           (prepare-test-job copy created))))
      (is (= 2 (gethash "generation" (gethash "metadata" updated)))))
    (let* ((copy (gr8s.resources::copy-core-object created))
           (pod-spec (gethash "spec" (gethash "template" (gethash "spec" copy))))
           (container (aref (gethash "containers" pod-spec) 0)))
      (setf (gethash "image" container) "different")
      (signals gr8s.model::kubernetes-error (prepare-test-job copy created)))))

(test job-manual-empty-selectors-do-not-weaken-apps-selector-validation
  (let ((input (batch-test-job)))
    (setf (gethash "manualSelector" (gethash "spec" input)) t
          (gethash "selector" (gethash "spec" input)) (gr8s.resources::core-object))
    (is (hash-table-p (gethash "selector" (gethash "spec" (normalize-test-job input)))))
    (signals gr8s.model::kubernetes-error (gr8s.resources::validate-workload-selector (gr8s.resources::core-object)))))

(test job-protobuf-preserves-explicit-zero-counts-and-false-suspension
  (let* ((container (core-test-protobuf '((1 "main") (2 "busybox:1.36.1"))))
         (pod-spec (core-test-protobuf (list (list 2 container) (list 3 "Never"))))
         (template (core-test-protobuf (list (list 1 #()) (list 2 pod-spec))))
         (spec (core-test-protobuf (list (list 1 0) (list 2 0) (list 6 template) (list 7 0) (list 10 0))))
         (object (gr8s.resources::decode-batch-protobuf
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
          (gethash "labels" metadata) (gr8s.resources::core-object "job" "work"))
    (let ((object (normalize-test-job input)))
      (is (equal "work" (gethash "job" (gethash "labels" (gethash "metadata" (gethash "template" (gethash "spec" object))))))))))


(defun fidelity-job (name &rest spec-fields)
  "Build a one-container Job with SPEC-FIELDS set."
  (let ((spec (gr8s.resources::core-object
               "template" (gr8s.resources::core-object
                           "spec" (gr8s.resources::core-object "restartPolicy" "Never"
                                                     "containers" (vector (gr8s.resources::core-object "name" "main" "image" "busybox:1.36.1")))))))
    (loop for (key value) on spec-fields by #'cddr do (setf (gethash key spec) value))
    (gr8s.resources::core-object "apiVersion" "batch/v1" "kind" "Job" "metadata" (gr8s.resources::core-object "name" name) "spec" spec)))

(test indexed-jobs-scale-completions-only-in-tandem-with-parallelism
  (with-temporary-store (store path)
    (values path)
    (flet ((scale (name completions parallelism)
             (gr8s.resources::update-core-resource store "jobs" "alpha" name
               (lambda (object)
                 (setf (gethash "completions" (gethash "spec" object)) completions)
                 (when parallelism (setf (gethash "parallelism" (gethash "spec" object)) parallelism))
                 object))))
      (gr8s.resources::create-core-resource store "jobs" (fidelity-job "indexed" "completionMode" "Indexed" "completions" 4 "parallelism" 4) "alpha")
      (gr8s.resources::create-core-resource store "jobs" (fidelity-job "plain" "completions" 4 "parallelism" 4) "alpha")
      (is (= 2 (gethash "completions" (gethash "spec" (scale "indexed" 2 2)))))
      (signals kubernetes-error (scale "indexed" 3 nil))
      (signals kubernetes-error (scale "plain" 2 2)))))

(test suspended-jobs-accept-the-template-changes-kubernetes-allows
  (with-temporary-store (store path)
    (values path)
    (flet ((edit (name function)
             (gr8s.resources::update-core-resource store "jobs" "alpha" name
               (lambda (object)
                 (funcall function (gethash "template" (gethash "spec" object)))
                 object)))
           (resources (template)
             (setf (gethash "resources" (aref (gethash "containers" (gethash "spec" template)) 0))
                   (gr8s.resources::core-object "requests" (gr8s.resources::core-object "cpu" "100m"))))
           (selector (template)
             (setf (gethash "nodeSelector" (gethash "spec" template)) (gr8s.resources::core-object "zone" "a")))
           (image (template)
             (setf (gethash "image" (aref (gethash "containers" (gethash "spec" template)) 0)) "busybox:changed")))
      (gr8s.resources::create-core-resource store "jobs" (fidelity-job "held" "suspend" t) "alpha")
      (is-true (edit "held" #'resources))
      (is-true (edit "held" #'selector))
      (signals kubernetes-error (edit "held" #'image))
      (gr8s.resources::create-core-resource store "jobs" (fidelity-job "running") "alpha")
      (signals kubernetes-error (edit "running" #'resources))
      (signals kubernetes-error (edit "running" #'selector)))))

(test job-backoff-limit-counts-restarts-in-place-as-soon-as-they-meet-it
  (let ((spec (gr8s.resources::core-object "backoffLimit" 2 "completions" 1 "parallelism" 1)))
    (is (null (gr8s.controllers::job-terminal-decision spec (gr8s.resources::core-object) 1 nil 1)))
    (is (equal "Failed" (gr8s.controllers::job-terminal-decision spec (gr8s.resources::core-object) 2 nil 1)))
    ;; Failed Pods, by contrast, may reach the limit.
    (is (null (gr8s.controllers::job-terminal-decision spec (gr8s.resources::core-object "failed" 2) 0 nil 1)))
    (is (equal "Failed" (gr8s.controllers::job-terminal-decision spec (gr8s.resources::core-object "failed" 3) 0 nil 1))))
  (let ((spec (gr8s.resources::core-object "backoffLimit" 0 "completions" 1 "parallelism" 1)))
    (is (null (gr8s.controllers::job-terminal-decision spec (gr8s.resources::core-object) 0 nil 1)))
    (is (equal "Failed" (gr8s.controllers::job-terminal-decision spec (gr8s.resources::core-object) 1 nil 1)))))
