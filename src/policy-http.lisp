;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Expose policy/v1 discovery and the Pod eviction subresource. An eviction
;;;; spends one unit of the Pod's disruption budget atomically with reading it, so
;;;; concurrent evictions can never overdraw, and is refused with a 429 naming the
;;;; DisruptionBudget cause when nothing is left to spend.

(in-package #:gr8s)

(defparameter +max-disrupted-pods+ 2000
  "Most evicted Pods a budget tracks at once, as upstream limits it.")

(defun policy-api-group ()
  "Describe the implemented policy/v1 API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "policy"
               "versions" (vector (core-object "groupVersion" "policy/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "policy/v1" "version" "v1")))

(defun policy-resources-response ()
  "Advertise PodDisruptionBudgets and their separately authorized status subresource."
  (let ((resources (stored-resource-discovery "policy/v1")))
    (loop for resource across resources do (setf (gethash "shortNames" resource) #("pdb")))
    (json-response
     (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "policy/v1"
                  "resources" (concatenate 'vector resources
                                           (vector (core-object "name" "poddisruptionbudgets/status" "namespaced" t
                                                                "kind" "PodDisruptionBudget" "verbs" #("get" "patch" "update"))))))))

(defun add-policy-openapi-paths (paths)
  "Describe PodDisruptionBudget CRUD and status schemas for clients that discover them."
  (let* ((schema "io.k8s.api.policy.v1.PodDisruptionBudget")
         (collection "/apis/policy/v1/namespaces/{namespace}/poddisruptionbudgets")
         (item (concatenate 'string collection "/{name}")))
    (labels ((parameters (names)
               (coerce (loop for name in names
                             collect (core-object "name" name "in" "path" "required" t "schema" (core-object "type" "string"))) 'vector))
             (operation (action &optional body)
               (let ((result (core-object "operationId" (format nil "~APolicyV1NamespacedPodDisruptionBudget" action)
                                          "x-kubernetes-group-version-kind"
                                          (core-object "group" "policy" "version" "v1" "kind" "PodDisruptionBudget")
                                          "responses" (core-object "200" (core-object "description" "Success")))))
                 (when body
                   (setf (gethash "requestBody" result)
                         (core-object "required" t "content"
                                      (core-object "application/json" (core-object "schema" (reference-schema schema))))))
                 result)))
      (setf (gethash collection paths)
            (core-object "parameters" (parameters '("namespace")) "get" (operation "list")
                         "post" (operation "create" t) "delete" (operation "deleteCollection"))
            (gethash item paths)
            (core-object "parameters" (parameters '("namespace" "name")) "get" (operation "read")
                         "put" (operation "replace" t) "patch" (operation "patch" t) "delete" (operation "delete"))
            (gethash (concatenate 'string item "/status") paths)
            (core-object "parameters" (parameters '("namespace" "name")) "get" (operation "readStatus")
                         "put" (operation "replaceStatus" t) "patch" (operation "patchStatus" t)))))
  paths)

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

(defun eviction-request-options (name)
  "Decode the current Eviction request for Pod NAME and return its DeleteOptions."
  (let* ((eviction (core-resource-request-object "Eviction"))
         (metadata (gethash "metadata" eviction (core-object)))
         (options (gethash "deleteOptions" eviction)))
    (unless (equal name (gethash "name" metadata))
      (core-resource-error 400 "BadRequest" "name in URL does not match name in Eviction object"))
    (if (member options '(nil null)) (core-object) (require-object options "deleteOptions"))))

(defun evict-pod-unconditionally (store reconciler pod options dry-run)
  "Delete an evictable POD with the request's OPTIONS, first marking it DisruptionTarget."
  (let* ((preconditions (let ((value (gethash "preconditions" options)))
                          (if (member value '(nil null)) (core-object) value)))
         (uid (gethash "uid" preconditions)) (version (gethash "resourceVersion" preconditions))
         (grace (gethash "gracePeriodSeconds" options)))
    (when (or (and uid (not (eq uid 'null)) (not (equal uid (pod-uid pod))))
              (and version (not (eq version 'null)) (not (equal version (pod-resource-version pod)))))
      (core-resource-error 409 "Conflict" "Eviction preconditions do not match the Pod"))
    (admit-pod-delete store (pod-namespace pod) (pod-name pod) options)
    (unless dry-run
      (let* ((client (or (with-store-lock (store) (gethash (pod-uid pod) (pod-store-pod-client-statuses store)))
                         (core-object)))
             (updated (copy-core-object client))
             (conditions (remove "DisruptionTarget" (gethash "conditions" updated #())
                                 :test #'equal :key (lambda (condition) (gethash "type" condition)))))
        (setf (gethash "conditions" updated)
              (concatenate 'vector conditions
                           (vector (core-object "type" "DisruptionTarget" "status" "True"
                                                "reason" "EvictionByEvictionAPI" "message" "Eviction API: evicting"
                                                "lastTransitionTime" (current-timestamp (funcall *workload-clock*))))))
        (save-pod-client-status store pod updated)))
    (apply #'delete-reconciled-pod reconciler (pod-namespace pod) (pod-name pod)
           :uid (pod-uid pod) :dry-run dry-run
           (when (integerp grace) (list :grace-period grace)))))

(defun evict-pod-response (store reconciler name namespace)
  "Serve one Eviction with the upstream decision order and answer a bare Success Status."
  (let* ((options (eviction-request-options name))
         (preview (gethash "dryRun" options))
         (dry-run (or (core-resource-dry-run-p)
                      (and (vectorp preview) (not (stringp preview)) (plusp (length preview)))))
         (pod (get-pod store namespace name))
         (status (workload-pod-status reconciler pod))
         (phase (gethash "phase" status))
         (ready (pod-status-ready-p status)))
    (unless (or (deletion-requested-p pod) (member phase '("Succeeded" "Failed" "Pending") :test #'equal))
      (let ((budgets (pod-disruption-budgets store pod)))
        (when (> (length budgets) 1)
          (core-resource-error 500 "InternalError"
                               "This pod has more than one PodDisruptionBudget, which the eviction subresource does not support."))
        (when budgets
          (let* ((budget (first budgets)) (spec (gethash "spec" budget)) (budget-status (gethash "status" budget (core-object)))
                 (healthy (gethash "currentHealthy" budget-status 0)) (desired (gethash "desiredHealthy" budget-status 0)))
            ;; An unready Pod spends nothing when its budget allows evicting it anyway.
            (unless (and (not ready)
                         (or (equal "AlwaysAllow" (gethash "unhealthyPodEvictionPolicy" spec))
                             (and (>= healthy desired) (plusp desired))))
              (spend-disruption-budget store (gethash "name" (workload-metadata budget)) namespace name dry-run))))))
    (evict-pod-unconditionally store reconciler pod options dry-run)
    (json-response (core-object "apiVersion" "v1" "kind" "Status" "status" "Success" "metadata" (core-object)) 201)))
