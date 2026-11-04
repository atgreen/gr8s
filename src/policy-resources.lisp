;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Admit policy/v1 PodDisruptionBudgets through pinned Kubernetes wire and
;;;; structural schemas. Budgets are mutable, their status is server-owned, and
;;;; their generation advances only when the spec really changes, which is how a
;;;; client can tell when the disruption controller has caught up.

(in-package #:gr8s)

(let ((addition (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/policy-v1.json"))))
  (dolist (section '("messages" "definitions"))
    (maphash (lambda (name value) (setf (gethash name (gethash section *podtemplate-schema*)) value))
             (gethash section addition))))

(defun policy-resource-p (resource)
  "Recognize the implemented policy collection."
  (equal resource "poddisruptionbudgets"))

(defun validate-disruption-limit (value field)
  "Require a nonnegative integer or a percentage of at most 100 in spec FIELD."
  (unless (or (typep value '(integer 0 2147483647))
              (and (stringp value) (cl-ppcre:scan "^[0-9]+%$" value)
                   (<= (parse-integer value :end (1- (length value))) 100)))
    (core-resource-error 422 "Invalid" "spec.~A must be a nonnegative integer or a percentage of at most 100%" field)))

(defun normalize-policy-resource (input namespace name)
  "Validate a PodDisruptionBudget's desired state; ordinary writes never carry its status."
  (let* ((object (copy-core-object (require-object input "PodDisruptionBudget")))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (spec (let ((value (gethash "spec" object)))
                 (if (member value '(nil null)) (core-object) (require-object value "spec")))))
    (unless (and (equal "policy/v1" (gethash "apiVersion" object "policy/v1"))
                 (equal "PodDisruptionBudget" (gethash "kind" object "PodDisruptionBudget")))
      (core-resource-error 400 "BadRequest" "Expected policy/v1 PodDisruptionBudget"))
    (validate-core-metadata metadata namespace name)
    (pod-generate-name-prefix metadata)
    (remhash "status" object)
    (setf (gethash "namespace" metadata) namespace (gethash "apiVersion" object) "policy/v1"
          (gethash "kind" object) "PodDisruptionBudget" (gethash "spec" object) spec)
    (validate-template-shape object (template-schema "io.k8s.api.policy.v1.PodDisruptionBudget") "PodDisruptionBudget")
    (dolist (field '("minAvailable" "maxUnavailable" "selector" "unhealthyPodEvictionPolicy"))
      (when (eq (gethash field spec) 'null) (remhash field spec)))
    (when (and (nth-value 1 (gethash "minAvailable" spec)) (nth-value 1 (gethash "maxUnavailable" spec)))
      (core-resource-error 422 "Invalid" "spec.minAvailable and spec.maxUnavailable cannot both be set"))
    (dolist (field '("minAvailable" "maxUnavailable"))
      (when (nth-value 1 (gethash field spec)) (validate-disruption-limit (gethash field spec) field)))
    ;; An absent selector selects nothing, and an empty one every Pod in the namespace.
    (when (gethash "selector" spec) (validate-workload-selector (gethash "selector" spec) :allow-empty t))
    (let ((policy (gethash "unhealthyPodEvictionPolicy" spec)))
      (when (equal policy "") (remhash "unhealthyPodEvictionPolicy" spec) (setf policy nil))
      (unless (member policy '(nil "IfHealthyBudget" "AlwaysAllow") :test #'equal)
        (core-resource-error 422 "Invalid" "spec.unhealthyPodEvictionPolicy must be IfHealthyBudget or AlwaysAllow")))
    object))

(defun prepare-policy-write (object existing)
  "Keep status server-owned and advance generation only when the spec really changed."
  (setf (gethash "status" object)
        (if existing (copy-core-object (gethash "status" existing (core-object)))
            (core-object "disruptionsAllowed" 0 "currentHealthy" 0 "desiredHealthy" 0 "expectedPods" 0))
        (gethash "generation" (gethash "metadata" object))
        (if existing (+ (gethash "generation" (gethash "metadata" existing) 1)
                        (if (workload-equal-p (gethash "spec" existing) (gethash "spec" object)) 0 1)) 1))
  object)

(defun validate-disruption-status (status)
  "Refuse a client status write with a negative count, as the Kubernetes API does."
  (dolist (field '("observedGeneration" "disruptionsAllowed" "currentHealthy" "desiredHealthy" "expectedPods"))
    (let ((value (gethash field status)))
      (when (and (integerp value) (minusp value))
        (core-resource-error 422 "Invalid" "status.~A must not be negative" field)))))

(defun decode-policy-protobuf (bytes)
  "Decode typed PodDisruptionBudget input with the pinned policy/v1 field numbers."
  (let* ((object (template-protobuf-message "k8s.io.api.policy.v1.PodDisruptionBudget" bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) "policy/v1" (gethash "kind" object) "PodDisruptionBudget")
    object))

(defun decode-eviction-protobuf (bytes)
  "Decode a typed Eviction, keeping only its identity and delete options."
  (let* ((fields (core-protobuf-fields bytes))
         (metadata (core-protobuf-value fields 1)) (options (core-protobuf-value fields 2))
         (object (core-object "apiVersion" "policy/v1" "kind" "Eviction"
                              "metadata" (if metadata (core-protobuf-metadata metadata) (core-object)))))
    (when options (setf (gethash "deleteOptions" object) (core-protobuf-delete-options options)))
    object))
