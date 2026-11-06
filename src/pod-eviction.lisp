;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve the policy/v1 Eviction subresource of Pods, in upstream's decision order.
;;;; An eviction spends one unit of the Pod's disruption budget atomically with reading
;;;; it, so concurrent evictions can never overdraw, and is refused with a 429 naming
;;;; the DisruptionBudget cause when nothing is left to spend. It then marks a live Pod
;;;; with the DisruptionTarget condition and deletes it gracefully. Webhooks see the
;;;; Eviction's creation, not a deletion, as upstream's admission does.

(in-package #:gr8s)

(defparameter +max-disrupted-pods+ 2000
  "Most evicted Pods a budget tracks at once, as upstream limits it.")

(defun decode-eviction-protobuf (bytes)
  "Decode a typed policy/v1 Eviction's name and DeleteOptions."
  (unless (and (>= (length bytes) 4) (equalp (subseq bytes 0 4) #(107 56 115 0)))
    (core-resource-error 400 "BadRequest" "Invalid Eviction protobuf envelope"))
  (let* ((envelope (core-protobuf-fields (subseq bytes 4)))
         (raw (or (core-protobuf-value envelope 2)
                  (core-resource-error 400 "BadRequest" "Eviction protobuf has no object")))
         (fields (core-protobuf-fields raw))
         (metadata (core-protobuf-value fields 1))
         (options (core-protobuf-value fields 2))
         (object (core-object "metadata" (if metadata (core-protobuf-metadata metadata) (core-object)))))
    (when options (setf (gethash "deleteOptions" object) (core-protobuf-delete-options options)))
    object))

(defun eviction-request-object ()
  "Read the request's Eviction from JSON or Kubernetes protobuf."
  (let ((content-type (request-media-type)))
    (cond
      ((string= content-type "application/vnd.kubernetes.protobuf")
       (decode-eviction-protobuf (hunchentoot:raw-post-data :force-binary t)))
      ((member content-type '("" "application/json") :test #'string=)
       (require-object (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t)) "Eviction"))
      (t (core-resource-error 415 "UnsupportedMediaType" "Supported Eviction formats are JSON and Kubernetes protobuf")))))

(defun mark-pod-disruption-target (store pod)
  "Durably add the DisruptionTarget condition to POD's client-visible status conditions."
  (let* ((client (copy-pod-status-value
                  (or (with-store-lock (store) (gethash (pod-uid pod) (pod-store-pod-client-statuses store)))
                      (core-object))))
         (condition (core-object "type" "DisruptionTarget" "status" "True"
                                 "reason" "EvictionByEvictionAPI" "message" "Eviction API: evicting"
                                 "lastTransitionTime" (current-timestamp))))
    (setf (gethash "conditions" client)
          (concatenate 'vector
                       (remove "DisruptionTarget" (gethash "conditions" client #())
                               :key (lambda (entry) (gethash "type" entry)) :test #'equal)
                       (vector condition)))
    (save-pod-client-status store pod client)))

(defun pod-disruption-budgets (store pod)
  "Return the budgets selecting POD. A Pod without labels has none, as upstream decides."
  (let ((labels (gethash "labels" (workload-metadata (pod-to-object pod)))))
    (when (and labels (plusp (hash-table-count labels)))
      (remove-if-not (lambda (budget)
                       (let ((selector (gethash "selector" (gethash "spec" budget))))
                         (and selector (workload-selector-matches-p selector labels))))
                     (list-core-resources store "poddisruptionbudgets" (pod-namespace pod))))))

(defun eviction-budget-denied (message)
  "Refuse an eviction with HTTP 429 and the DisruptionBudget cause clients look for."
  (error 'kubernetes-error
         :status-code 429 :reason "TooManyRequests"
         :message "Cannot evict pod as it would violate the pod's disruption budget."
         :details (core-object "causes" (vector (core-object "reason" "DisruptionBudget" "message" message)))))

(defun spend-disruption-budget (store budget-name namespace pod-name dry-run)
  "Atomically charge one eviction of POD-NAME to the named budget, or signal why it may not happen."
  (with-store-lock (store)
    (let* ((key (core-resource-key "poddisruptionbudgets" namespace budget-name))
           (current (or (gethash key (pod-store-resources store))
                        (core-resource-error 409 "Conflict" "The disruption budget ~A has changed" budget-name)))
           (metadata (workload-metadata current)) (status (gethash "status" current (core-object)))
           (allowed (gethash "disruptionsAllowed" status 0)))
      (when (< (gethash "observedGeneration" status 0) (gethash "generation" metadata 1))
        (eviction-budget-denied (format nil "The disruption budget ~A is still being processed by the server." budget-name)))
      (when (minusp allowed)
        (core-resource-error 403 "Forbidden" "pdb disruptions allowed is negative"))
      (when (> (hash-table-count (gethash "disruptedPods" status (core-object))) +max-disrupted-pods+)
        (core-resource-error 403 "Forbidden" "DisruptedPods map too big - too many evictions not confirmed by PDB controller"))
      (when (zerop allowed)
        (eviction-budget-denied (format nil "The disruption budget ~A needs ~D healthy pods and has ~D currently"
                                                budget-name (gethash "desiredHealthy" status 0) (gethash "currentHealthy" status 0))))
      (unless dry-run
        (let* ((copy (copy-core-object current)) (updated (gethash "status" copy))
               (disrupted (gethash "disruptedPods" updated (core-object)))
               (resources (copy-core-resource-index store)) (revision (1+ (pod-store-resource-revision store))))
          (setf (gethash pod-name disrupted) (current-timestamp (funcall *workload-clock*))
                (gethash "disruptedPods" updated) disrupted
                (gethash "disruptionsAllowed" updated) (1- allowed))
          (prepare-core-resource-metadata copy current revision)
          (setf (gethash key resources) copy)
          (commit-core-resources store resources revision))))))

(defun admit-pod-eviction (store namespace name eviction dry-run)
  "Offer the Eviction's creation to the webhooks, which may refuse it."
  (let ((attributes (admission-attributes-for store "CREATE" "pods" namespace name
                                              :subresource "eviction" :kind "Eviction" :kind-api-version "policy/v1"
                                              :options (admission-request-options "CreateOptions")
                                              :dry-run dry-run :object eviction)))
    (when (admission-active-p store attributes)
      (setf (gethash "apiVersion" eviction) "policy/v1" (gethash "kind" eviction) "Eviction")
      (admission-mutate store attributes)
      (admission-validate store attributes))))

(defun pod-eviction-budget-check (store pod ready dry-run)
  "Charge POD's eviction to its budget, or signal why its budget refuses it."
  (let ((budgets (pod-disruption-budgets store pod)) (namespace (pod-namespace pod)))
    (when (> (length budgets) 1)
      (core-resource-error 500 "InternalError"
                           "This pod has more than one PodDisruptionBudget, which the eviction subresource does not support."))
    (when budgets
      (let* ((budget (first budgets)) (spec (gethash "spec" budget)) (status (gethash "status" budget (core-object)))
             (healthy (gethash "currentHealthy" status 0)) (desired (gethash "desiredHealthy" status 0)))
        ;; An unready Pod spends nothing when its budget allows evicting it anyway.
        (unless (and (not ready)
                     (or (equal "AlwaysAllow" (gethash "unhealthyPodEvictionPolicy" spec))
                         (and (>= healthy desired) (plusp desired))))
          (spend-disruption-budget store (gethash "name" (workload-metadata budget)) namespace (pod-name pod) dry-run))))))

(defun pod-eviction-response (store reconciler name namespace)
  "Evict the named Pod: check its budget, name the disruption on it, then delete it with the given options."
  (let* ((input (eviction-request-object))
         (metadata (require-object (gethash "metadata" input (core-object)) "metadata"))
         (options (let ((value (gethash "deleteOptions" input)))
                    (if (member value '(nil null)) (core-object) (require-object value "deleteOptions"))))
         (preconditions (let ((value (gethash "preconditions" options)))
                          (if (member value '(nil null)) (core-object) (require-object value "preconditions"))))
         (grace (gethash "gracePeriodSeconds" options))
         (preview (gethash "dryRun" options))
         (dry-run (or (core-resource-dry-run-p)
                      (and (vectorp preview) (not (stringp preview)) (plusp (length preview)))))
         (uid (gethash "uid" preconditions))
         (revision (gethash "resourceVersion" preconditions)))
    (unless (equal name (gethash "name" metadata))
      (core-resource-error 400 "BadRequest" "name in URL does not match name in Eviction object"))
    (when (eq t (gethash "ignoreStoreReadErrorWithClusterBreakingPotential" options))
      (core-resource-error 422 "Invalid" "deleteOptions.ignoreStoreReadErrorWithClusterBreakingPotential can not be set for pod eviction"))
    (admit-pod-eviction store namespace name input dry-run)
    (let* ((pod (get-pod store namespace name))
           (status (workload-pod-status reconciler pod))
           (phase (gethash "phase" status)))
      (when (or (and uid (not (eq uid 'null)) (not (equal uid (pod-uid pod))))
                (and revision (not (eq revision 'null)) (not (equal revision (pod-resource-version pod)))))
        (core-resource-error 409 "Conflict" "Pod no longer matches the eviction preconditions"))
      (unless (or (deletion-requested-p pod) (member phase '("Succeeded" "Failed" "Pending") :test #'equal))
        (pod-eviction-budget-check store pod (pod-status-ready-p status) dry-run))
      (unless dry-run
        (unless (or (deletion-requested-p pod)
                    (pod-terminal-status-p (with-store-lock (store)
                                             (gethash (pod-uid pod) (pod-store-pod-observed-statuses store)))))
          (mark-pod-disruption-target store pod)))
      (apply #'delete-reconciled-pod reconciler namespace name :uid (pod-uid pod) :dry-run dry-run
             (when (integerp grace) (list :grace-period grace))))
    (status-response "Success" "Created" "Eviction accepted" 201)))
