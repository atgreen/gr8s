;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Decide whether a Pod's resource requests and node affinity fit a node, and
;;;; when none fits, which lower-priority Pods to preempt. Follows the upstream
;;;; default preemption plugin: remove every lower-priority Pod, reprieve as many
;;;; as still fit from the most important down, and reserve the node for the
;;;; preemptor while its victims terminate.

(in-package #:gr8s)

(defparameter +node-pod-capacity+ 110
  "The Pod count a node advertises, matching the kubelet default.")

(defun filesystem-capacity-bytes (path)
  "Return the size of the filesystem holding PATH, or NIL when it cannot be measured."
  (sb-alien:with-alien ((fields (array sb-alien:unsigned-long 32)))
    (when (zerop (sb-alien:alien-funcall
                  (sb-alien:extern-alien "statvfs" (function sb-alien:int sb-alien:c-string (* t)))
                  path (sb-alien:addr fields)))
      ;; f_frsize and f_blocks are the second and third words of struct statvfs.
      (* (sb-alien:deref fields 1) (sb-alien:deref fields 2)))))

(defun node-reported-capacity ()
  "Measure the CPU, memory and storage this node's agent reports to the scheduler."
  (let ((capacity (core-object "cpu" (write-to-string (node-allocatable-cpu))
                               "memory" (policy-value-string (node-allocatable-memory) :binary)
                               "pods" (write-to-string +node-pod-capacity+)))
        (storage (filesystem-capacity-bytes "/var/lib")))
    (when storage (setf (gethash "ephemeral-storage" capacity) (policy-value-string storage :binary)))
    capacity))

(defun node-reported-capacity-entries ()
  "Return the measured capacity as the protocol's map entries."
  (loop for name being the hash-keys of (node-reported-capacity) using (hash-value value)
        collect (cons name value)))

(defun node-capacity-from-entries (entries)
  "Return a capacity table from protocol map ENTRIES, or NIL when an older agent sent none."
  (when entries
    (let ((capacity (core-object)))
      (dolist (entry entries capacity)
        (setf (gethash (car entry) capacity) (cdr entry))))))

(defun pod-spec-priority (pod)
  "Return POD's admission-resolved integer priority."
  (gethash "priority" (gethash "spec" (pod-to-object pod)) 0))

(defun pod-preemption-allowed-p (pod)
  "Return whether POD's preemption policy lets it displace other Pods."
  (not (equal "Never" (gethash "preemptionPolicy" (gethash "spec" (pod-to-object pod))))))

(defun pod-requests-table (pod)
  "Return POD's exact effective requests, including overhead."
  (values (pod-spec-resource-totals (gethash "spec" (pod-to-object pod)))))

(defun node-allocatable-table (node)
  "Return NODE's exact allocatable amounts from its report and advertised extended resources."
  (let ((table (make-hash-table :test #'equal)))
    (dolist (source (list (node-record-capacity node) (node-record-extended-resources node)))
      (when source
        (maphash (lambda (name value) (setf (gethash name table) (policy-value value))) source)))
    table))

(defun node-charged-pods-unlocked (store node-name)
  "Return the Pods still occupying NODE-NAME, including ones shutting down."
  (loop for pod being the hash-values of (pod-store-pods store)
        when (and (equal node-name (pod-node-name pod))
                  (not (terminal-pod-phase-p (gethash (pod-uid pod) (pod-store-pod-observed-phases store)))))
          collect pod))

(defun nominated-pods-unlocked (store node-name pod)
  "Return other Pods reserving NODE-NAME that POD must not take resources from."
  (loop for other being the hash-values of (pod-store-pods store)
        when (and (not (equal (pod-uid other) (pod-uid pod)))
                  (null (pod-node-name other))
                  (equal node-name (gethash (pod-uid other) (pod-store-nominated-nodes store)))
                  (>= (pod-spec-priority other) (pod-spec-priority pod)))
          collect other))

(defun resource-fit-p (requests allocatable pods)
  "Return whether REQUESTS plus the list PODS fit ALLOCATABLE.
A node that has not reported CPU, memory or storage is unconstrained for that
resource; an extended resource it does not advertise has zero capacity."
  (let ((used (make-hash-table :test #'equal)))
    (dolist (pod pods)
      (maphash (lambda (name value) (incf (gethash name used 0) value)) (pod-requests-table pod)))
    (and (or (null (gethash "pods" allocatable))
             (<= (1+ (length pods)) (gethash "pods" allocatable)))
         (loop for name being the hash-keys of requests using (hash-value amount)
               always (or (zerop amount)
                          (multiple-value-bind (limit known) (gethash name allocatable)
                            (cond (known (<= (+ amount (gethash name used 0)) limit))
                                  ((extended-resource-name-p name) nil)
                                  (t t))))))))

(defun pod-fits-node-unlocked (store pod node)
  "Return whether POD fits NODE alongside its Pods and higher-priority reservations."
  (resource-fit-p (pod-requests-table pod) (node-allocatable-table node)
                  (append (node-charged-pods-unlocked store (node-record-name node))
                          (nominated-pods-unlocked store (node-record-name node) pod))))

(defun node-selector-term-matches-p (term node)
  "Evaluate one NodeSelectorTerm against NODE's labels and name; an empty term matches nothing."
  (let ((labels (storage-node-labels node))
        (expressions (gethash "matchExpressions" term #()))
        (fields (gethash "matchFields" term #())))
    (and (or (plusp (length expressions)) (plusp (length fields)))
         (loop for requirement across expressions
               always (storage-requirement-matches-p requirement (gethash (gethash "key" requirement) labels)))
         (loop for requirement across fields
               always (storage-requirement-matches-p requirement (node-record-name node))))))

(defun pod-node-affinity (pod)
  "Return POD's nodeAffinity object, if any."
  (let ((affinity (gethash "affinity" (gethash "spec" (pod-to-object pod)))))
    (and affinity (gethash "nodeAffinity" affinity))))

(defun pod-node-affinity-matches-p (pod node)
  "Return whether NODE satisfies POD's required node affinity."
  (let* ((affinity (pod-node-affinity pod))
         (required (and affinity (gethash "requiredDuringSchedulingIgnoredDuringExecution" affinity))))
    (or (null required)
        (some (lambda (term) (node-selector-term-matches-p term node))
              (gethash "nodeSelectorTerms" required #())))))

(defun pod-node-preference-score (pod node)
  "Sum the weights of POD's preferred node affinity terms NODE satisfies."
  (let* ((affinity (pod-node-affinity pod))
         (preferred (and affinity (gethash "preferredDuringSchedulingIgnoredDuringExecution" affinity))))
    (if preferred
        (loop for entry across preferred
              when (node-selector-term-matches-p (gethash "preference" entry) node)
                sum (gethash "weight" entry))
        0)))

(defun pod-node-placeable-p (store pod node)
  "Return whether NODE satisfies every POD placement constraint other than resources."
  (and (node-record-runtime-ready-p node)
       (pod-node-taints-allow-p pod node)
       (pod-node-selector-matches-p pod node)
       (pod-node-affinity-matches-p pod node)
       (null (pod-affinity-failure-unlocked store pod node))
       (pod-host-ports-free-p store pod node)
       (pod-node-storage-compatible-p store pod node)))

(defun pod-more-important-p (left right)
  "Order Pods by descending priority, then earliest creation, as the scheduler's reprieve does."
  (or (> (pod-spec-priority left) (pod-spec-priority right))
      (and (= (pod-spec-priority left) (pod-spec-priority right))
           (string< (gethash "creationTimestamp" (gethash "metadata" (pod-to-object left)) "")
                    (gethash "creationTimestamp" (gethash "metadata" (pod-to-object right)) "")))))

(defun node-preemption-victims-unlocked (store pod node)
  "Return the fewest lower-priority Pods to remove so POD fits NODE; second value is success."
  (let* ((priority (pod-spec-priority pod))
         (requests (pod-requests-table pod))
         (allocatable (node-allocatable-table node))
         (occupants (node-charged-pods-unlocked store (node-record-name node)))
         (removable (sort (remove-if-not (lambda (other)
                                           (and (< (pod-spec-priority other) priority)
                                                (not (deletion-requested-p other))))
                                         occupants)
                          #'pod-more-important-p))
         (kept (append (set-difference occupants removable)
                       (nominated-pods-unlocked store (node-record-name node) pod))))
    (unless (resource-fit-p requests allocatable kept)
      (return-from node-preemption-victims-unlocked (values nil nil)))
    (let ((victims nil))
      (dolist (candidate removable)
        (if (resource-fit-p requests allocatable (cons candidate kept))
            (push candidate kept)
            (push candidate victims)))
      (values (nreverse victims) t))))

(defun preemption-plan-better-p (left right)
  "Prefer sacrificing the lowest priorities, then the fewest Pods, then a stable node name."
  (flet ((score (plan)
           (let ((victims (cdr plan)))
             (list (if victims (reduce #'max (mapcar #'pod-spec-priority victims)) most-negative-fixnum)
                   (reduce #'+ (mapcar #'pod-spec-priority victims))
                   (length victims)))))
    (loop for a in (score left) for b in (score right)
          do (cond ((< a b) (return t)) ((> a b) (return nil)))
          finally (return (string< (node-record-name (car left)) (node-record-name (car right)))))))

(defun pod-awaiting-preemption-p (store pod)
  "Return whether POD already preempted on its nominated node and its victims are still terminating."
  (let ((nominated (gethash (pod-uid pod) (pod-store-nominated-nodes store))))
    (and nominated
         (some (lambda (other)
                 (and (deletion-requested-p other) (< (pod-spec-priority other) (pod-spec-priority pod))))
               (node-charged-pods-unlocked store nominated)))))

(defun choose-preemption-unlocked (store pod nodes)
  "Return the best (node . victims) plan for POD over the placeable NODES, or NIL."
  (when (and (pod-preemption-allowed-p pod) (not (pod-awaiting-preemption-p store pod)))
    (let ((plans (loop for node in nodes
                       for (victims possible) = (multiple-value-list (node-preemption-victims-unlocked store pod node))
                       when (and possible victims) collect (cons node victims))))
      (when plans (first (sort plans #'preemption-plan-better-p))))))

(defun preempt-pod (store victim)
  "Record why VICTIM is being removed, then begin its ordinary graceful deletion."
  (handler-case
      (let* ((existing (with-store-lock (store)
                         (gethash (pod-uid victim) (pod-store-pod-client-statuses store))))
             (client (if existing (copy-core-object existing) (core-object))))
        (setf (gethash "conditions" client)
              (concatenate 'vector
                           (remove "DisruptionTarget" (gethash "conditions" client #())
                                   :key (lambda (condition) (gethash "type" condition)) :test #'equal)
                           (vector (core-object "type" "DisruptionTarget" "status" "True"
                                                "reason" "PreemptionByScheduler"
                                                "message" "gr8s-scheduler: preempting to accommodate a higher priority pod"
                                                "lastTransitionTime" (current-timestamp)))))
        (save-pod-client-status store victim client)
        (mark-pod-deleting store (pod-namespace victim) (pod-name victim) :uid (pod-uid victim)))
    (kubernetes-error (condition)
      ;; The victim vanished or changed identity meanwhile, which frees the same resources.
      (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))
