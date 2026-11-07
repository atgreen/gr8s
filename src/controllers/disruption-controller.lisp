;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Keep each PodDisruptionBudget's status true to the Pods it selects, with the
;;;; arithmetic of the Kubernetes disruption controller. Health is observed Pod
;;;; readiness, and a budget it cannot evaluate allows no disruptions at all.

(in-package #:gr8s.controllers)

(defparameter +disrupted-pod-timeout+ 120
  "Seconds an evicted Pod stays charged to its budget while it has not been deleted.")

(defun disruption-budget-pods (store budget)
  "Return the Pods BUDGET selects. An absent selector selects none, an empty one all."
  (let ((selector (gethash "selector" (gethash "spec" budget))))
    (when selector
      (remove-if-not (lambda (pod)
                       (workload-selector-matches-p selector (gethash "labels" (workload-metadata (pod-to-object pod)))))
                     (list-pods store (gethash "namespace" (workload-metadata budget)))))))

(defun disruption-owner-scale (store namespace reference)
  "Return the controller identity and declared scale behind an owner REFERENCE, or NIL if it has none.
A ReplicaSet managed by a Deployment answers for its Deployment, as upstream does."
  (let* ((kind (gethash "kind" reference)) (version (gethash "apiVersion" reference))
         (type (find-if (lambda (type) (and (equal kind (second type)) (equal version (third type))))
                        *stored-resource-types*))
         (owner (when (and type (member kind '("ReplicaSet" "Deployment" "StatefulSet" "ReplicationController") :test #'equal))
                  (handler-case (get-core-resource store (first type) namespace (gethash "name" reference))
                    (kubernetes-error (condition)
                      (if (= 404 (kubernetes-error-status-code condition)) nil (error condition)))))))
    (when (and owner (equal (gethash "uid" reference) (gethash "uid" (workload-metadata owner))))
      (let ((parent (and (equal kind "ReplicaSet") (workload-controller-reference owner))))
        (if (and parent (equal "Deployment" (gethash "kind" parent)))
            (disruption-owner-scale store namespace parent)
            (values (gethash "uid" (workload-metadata owner)) (gethash "replicas" (gethash "spec" owner) 1)))))))

(defun disruption-expected-scale (store budget pods)
  "Return the total scale of PODS' distinct controllers, ignoring Pods that have none.
Signal a Kubernetes error for a controller whose scale cannot be determined."
  (let ((scales (make-hash-table :test #'equal)))
    (dolist (pod pods)
      (let ((reference (workload-controller-reference (pod-to-object pod))))
        (when reference
          (multiple-value-bind (uid scale)
              (disruption-owner-scale store (gethash "namespace" (workload-metadata budget)) reference)
            (unless uid
              (core-resource-error 409 "Conflict" "found no controllers for pod ~S" (pod-name pod)))
            (setf (gethash uid scales) scale)))))
    (loop for scale being the hash-values of scales sum scale)))

(defun disruption-scaled-limit (value expected)
  "Resolve an integer or percentage limit against EXPECTED, rounding up as upstream does."
  (workload-rollout-count value expected :round-up t))

(defun disruption-expected-counts (store budget pods)
  "Return BUDGET's expected Pod count and its desired healthy count as two values."
  (let* ((spec (gethash "spec" budget)) (maximum (gethash "maxUnavailable" spec)) (minimum (gethash "minAvailable" spec)))
    (cond (maximum
           (let ((expected (disruption-expected-scale store budget pods)))
             (values expected (max 0 (- expected (disruption-scaled-limit maximum expected))))))
          ((integerp minimum) (values (length pods) minimum))
          (minimum
           (let ((expected (disruption-expected-scale store budget pods)))
             (values expected (disruption-scaled-limit minimum expected))))
          (t (values 0 0)))))

(defun disruption-live-disrupted-pods (budget pods now)
  "Keep the recorded evictions of Pods that exist, are undeleted and have not timed out."
  (let ((kept (core-object)) (recorded (gethash "disruptedPods" (gethash "status" budget (core-object)))))
    (when recorded
      (maphash (lambda (name time)
                 (let ((pod (find name pods :key #'pod-name :test #'equal))
                       (seconds (ignore-errors (pod-deletion-time time))))
                   (when (and pod (not (deletion-requested-p pod)) seconds
                              (<= now (+ seconds +disrupted-pod-timeout+)))
                     (setf (gethash name kept) time))))
               recorded))
    kept))

(defun disruption-healthy-count (reconciler pods disrupted)
  "Count undeleted, unevicted Pods whose readiness is actually observed."
  (count-if (lambda (pod)
              (and (not (deletion-requested-p pod))
                   (not (nth-value 1 (gethash (pod-name pod) disrupted)))
                   (pod-status-ready-p (workload-pod-status reconciler pod))))
            pods))

(defun disruption-allowed-condition (previous value reason message)
  "Build the DisruptionAllowed condition, keeping its transition time while its status holds."
  (let ((old (find "DisruptionAllowed" previous :test #'equal :key (lambda (condition) (gethash "type" condition)))))
    (core-object "type" "DisruptionAllowed" "status" value "reason" reason "message" message
                 "lastTransitionTime" (if (and old (equal value (gethash "status" old)))
                                          (gethash "lastTransitionTime" old)
                                          (current-timestamp (funcall *workload-clock*))))))

(defun publish-disruption-status (store budget status)
  "Commit STATUS unless BUDGET changed since it was read: an eviction may have spent the budget."
  (with-store-lock (store)
    (let* ((metadata (workload-metadata budget))
           (key (core-resource-key "poddisruptionbudgets" (gethash "namespace" metadata) (gethash "name" metadata)))
           (current (gethash key (pod-store-resources store))))
      (when (and current (equal (gethash "resourceVersion" metadata) (gethash "resourceVersion" (workload-metadata current)))
                 (not (workload-equal-p status (gethash "status" current))))
        (let ((copy (copy-core-object current)) (resources (copy-core-resource-index store))
              (revision (1+ (pod-store-resource-revision store))))
          (setf (gethash "status" copy) status)
          (prepare-core-resource-metadata copy current revision)
          (setf (gethash key resources) copy)
          (commit-core-resources store resources revision))))))

(defun reconcile-disruption-budget (reconciler budget)
  "Recompute BUDGET's status from its Pods, failing safe to no disruptions on any error."
  (let* ((store (reconciler-store reconciler)) (prior (gethash "status" budget (core-object)))
         (previous (gethash "conditions" prior #())) (pods (disruption-budget-pods store budget))
         (now (funcall *workload-clock*)))
    (handler-case
        (multiple-value-bind (expected desired) (disruption-expected-counts store budget pods)
          (let* ((disrupted (disruption-live-disrupted-pods budget pods now))
                 (healthy (disruption-healthy-count reconciler pods disrupted))
                 (allowed (if (plusp expected) (max 0 (- healthy desired)) 0)))
            (publish-disruption-status
             store budget
             (let ((status (core-object "observedGeneration" (gethash "generation" (workload-metadata budget))
                                        "disruptionsAllowed" allowed "currentHealthy" healthy
                                        "desiredHealthy" desired "expectedPods" expected
                                        "conditions"
                                        (vector (if (plusp allowed)
                                                    (disruption-allowed-condition previous "True" "SufficientPods" "")
                                                    (disruption-allowed-condition previous "False" "InsufficientPods" ""))))))
               (when (plusp (hash-table-count disrupted)) (setf (gethash "disruptedPods" status) disrupted))
               status))))
      (kubernetes-error (condition)
        (let ((status (copy-core-object prior)))
          (setf (gethash "disruptionsAllowed" status) 0
                (gethash "conditions" status)
                (vector (disruption-allowed-condition previous "False" "SyncFailed" (kubernetes-error-message condition))))
          (publish-disruption-status store budget status))))))

(defun reconcile-disruption-budgets (reconciler)
  "Run the disruption controller over every budget; one failure does not stop the others."
  (dolist (budget (list-core-resources (reconciler-store reconciler) "poddisruptionbudgets"))
    (handler-case (reconcile-disruption-budget reconciler budget)
      (error (condition) (format *error-output* "gr8s disruption controller: ~A~%" condition)))))
