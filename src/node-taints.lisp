;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Enforce Node taints and the unschedulable flag. The scheduler refuses a Pod
;;;; that does not tolerate a node's NoSchedule and NoExecute taints, and a
;;;; control-plane pass evicts running Pods that do not tolerate a NoExecute
;;;; taint, once any finite tolerationSeconds has passed since it was noticed.

(in-package #:gr8s)

(defun validate-node-taints (spec)
  "Validate and normalize SPEC's taints, requiring unique key and effect pairs."
  (when (eq (gethash "taints" spec) 'null) (remhash "taints" spec))
  (let ((taints (gethash "taints" spec #())) (seen nil))
    (unless (and (vectorp taints) (not (stringp taints)))
      (core-resource-error 422 "Invalid" "spec.taints must be an array"))
    (loop for taint across taints
          do (drop-null-fields (require-object taint "taint"))
             (reject-unsupported-fields taint '("key" "value" "effect" "timeAdded") "taint")
             (unless (core-qualified-key-p (gethash "key" taint))
               (core-resource-error 422 "Invalid" "spec.taints key ~S is invalid" (gethash "key" taint)))
             (unless (core-label-name-p (gethash "value" taint "") :empty t)
               (core-resource-error 422 "Invalid" "spec.taints value ~S is invalid" (gethash "value" taint)))
             (unless (member (gethash "effect" taint) '("NoSchedule" "PreferNoSchedule" "NoExecute") :test #'equal)
               (core-resource-error 422 "Invalid" "spec.taints effect ~S is invalid" (gethash "effect" taint)))
             (let ((identity (cons (gethash "key" taint) (gethash "effect" taint))))
               (when (member identity seen :test #'equal)
                 (core-resource-error 422 "Invalid" "spec.taints has a duplicate ~A:~A" (car identity) (cdr identity)))
               (push identity seen)))
    taints))

(defun toleration-matches-taint-p (toleration taint)
  "Apply Kubernetes' toleration rules to one taint."
  (let ((effect (gethash "effect" toleration ""))
        (key (gethash "key" toleration ""))
        (operator (gethash "operator" toleration "Equal")))
    (and (or (equal effect "") (equal effect (gethash "effect" taint)))
         (or (and (equal key "") (equal operator "Exists")) (equal key (gethash "key" taint)))
         (or (equal operator "Exists")
             (equal (gethash "value" toleration "") (gethash "value" taint ""))))))

(defun spec-tolerations (spec)
  "Return Pod SPEC's tolerations as a vector."
  (let ((tolerations (gethash "tolerations" spec)))
    (if (and tolerations (not (eq tolerations 'null))) tolerations #())))

(defun spec-tolerates-node-scheduling-p (spec node)
  "Return whether a Pod with SPEC may be placed on NODE, as far as its taints go."
  (let ((tolerations (spec-tolerations spec)))
    (every (lambda (taint)
             (or (equal "PreferNoSchedule" (gethash "effect" taint))
                 (some (lambda (toleration) (toleration-matches-taint-p toleration taint)) tolerations)))
           (node-record-taints node))))

(defun pod-node-taints-allow-p (pod node)
  "Return whether NODE's unschedulable flag and taints admit POD to the scheduler."
  (let ((spec (gethash "spec" (pod-to-object pod))))
    (and (not (node-record-unschedulable node))
         (spec-tolerates-node-scheduling-p spec node))))

(defun pod-no-execute-toleration-seconds (spec node)
  "Return how long a Pod with SPEC may stay on NODE: NIL forever, otherwise seconds, 0 for at once."
  (let ((tolerations (spec-tolerations spec)) (seconds nil))
    (loop for taint across (node-record-taints node)
          when (equal "NoExecute" (gethash "effect" taint))
            do (let ((matching (remove-if-not (lambda (toleration) (toleration-matches-taint-p toleration taint))
                                              tolerations)))
                 (when (zerop (length matching)) (return-from pod-no-execute-toleration-seconds 0))
                 (loop for toleration across matching
                       for limit = (gethash "tolerationSeconds" toleration)
                       when (integerp limit)
                         do (setf seconds (if seconds (min seconds (max 0 limit)) (max 0 limit))))))
    seconds))

(defun node-has-no-execute-taint-p (node)
  "Return whether NODE carries any NoExecute taint."
  (find "NoExecute" (node-record-taints node) :test #'equal :key (lambda (taint) (gethash "effect" taint))))

(defun reconcile-node-taint-evictions (reconciler &optional (now (funcall *pod-deletion-clock*)))
  "Evict Pods that NoExecute taints no longer allow, forgetting timers of Pods they no longer affect."
  (let* ((store (reconciler-store reconciler))
         (timers (reconciler-taint-timers reconciler))
         (live nil))
    (dolist (pod (list-pods store))
      (let ((node (and (pod-node-name pod) (with-store-lock (store) (get-node-unlocked store (pod-node-name pod))))))
        (when (and node (node-has-no-execute-taint-p node) (not (deletion-requested-p pod))
                   (not (member (with-store-lock (store) (gethash (pod-uid pod) (pod-store-pod-observed-phases store)))
                                '("Succeeded" "Failed") :test #'equal)))
          (let ((seconds (pod-no-execute-toleration-seconds (gethash "spec" (pod-to-object pod)) node)))
            (when seconds
              (let ((noticed (or (gethash (pod-uid pod) timers) (setf (gethash (pod-uid pod) timers) now))))
                (push (pod-uid pod) live)
                (when (>= now (+ noticed seconds))
                  (handler-case
                      (delete-controller-pod reconciler (pod-namespace pod) (pod-name pod) "node-lifecycle-controller" :uid (pod-uid pod))
                    (kubernetes-error (condition)
                      (unless (member (kubernetes-error-status-code condition) '(404 409))
                        (error condition)))))))))))
    (loop for uid in (loop for uid being the hash-keys of timers collect uid)
          unless (member uid live :test #'equal)
            do (remhash uid timers))))

(defun create-node-response (store)
  "Register a Node through the API. No agent stands behind it, so it can never run a Pod."
  (let* ((input (require-object (core-resource-request-object "Node") "Node"))
         (metadata (require-object (gethash "metadata" input) "metadata"))
         (spec (let ((value (gethash "spec" input))) (if (hash-table-p value) value (core-object))))
         (name (gethash "name" metadata))
         (status (gethash "status" input)))
    (unless (equal "Node" (gethash "kind" input "Node")) (core-resource-error 400 "BadRequest" "Expected v1 Node"))
    (unless (dns-subdomain-p name) (core-resource-error 422 "Invalid" "metadata.name must be a DNS subdomain"))
    (validate-core-metadata (core-object "name" "node"
                                         "labels" (or (gethash "labels" metadata) (core-object))
                                         "annotations" (or (gethash "annotations" metadata) (core-object)))
                            nil nil)
    (let ((taints (validate-node-taints spec))
          (node (make-node-record
                 :id (generate-uid) :name name :pod-cidr "" :api-only t :creation-timestamp (current-timestamp)
                 :labels (and (hash-table-p (gethash "labels" metadata)) (copy-core-object (gethash "labels" metadata)))
                 :annotations (and (hash-table-p (gethash "annotations" metadata)) (copy-core-object (gethash "annotations" metadata)))
                 :unschedulable (eq t (gethash "unschedulable" spec))
                 :api-status (and (hash-table-p status) (copy-core-object status)))))
      (setf (node-record-taints node) taints)
      (if (core-resource-dry-run-p)
          (json-response (node-api-object node) 201)
          (with-store-lock (store)
            (when (get-node-unlocked store name)
              (core-resource-error 409 "AlreadyExists" "nodes ~S already exists" name))
            (publish-node-change-unlocked store nil node)
            (setf (gethash name (pod-store-nodes store)) node)
            (note-node-desired-change store)   ; desired API write (8ia.4)
            (json-response (node-api-object node) 201))))))

(defun delete-node-response (store name)
  "Delete an API-registered Node; a node an agent runs on leaves by stopping that agent."
  (let ((node (get-node store name)))
    (unless (node-record-api-only node)
      (core-resource-error 409 "Conflict" "Node ~A is registered by its agent and cannot be deleted through the API" name))
    (unless (core-resource-dry-run-p)
      (with-store-lock (store) (remove-node-unlocked store node)))
    (json-response (node-api-object node))))
