;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Change what a running container was declared with, without replacing its
;;;; sandbox: the pods/resize subresource and in-place CPU and memory updates, or
;;;; a restart of just that container for a new image or a RestartContainer resize
;;;; policy. A container's status reports what was actually applied, so a resize
;;;; stays visibly in progress until the runtime has carried it out.

(in-package #:gr8s.kubelet)

(defun validate-container-resize-policy (container)
  "Validate CONTAINER's optional resizePolicy entries."
  (when (eq (gethash "resizePolicy" container) 'null) (remhash "resizePolicy" container))
  (let ((seen nil))
    (loop for entry across (optional-vector container "resizePolicy" "container")
          do (drop-null-fields (require-object entry "resizePolicy"))
             (reject-unsupported-fields entry '("resourceName" "restartPolicy") "resizePolicy")
             (unless (member (gethash "resourceName" entry) '("cpu" "memory") :test #'equal)
               (invalid-pod "resizePolicy.resourceName must be cpu or memory"))
             (unless (member (gethash "restartPolicy" entry) '("NotRequired" "RestartContainer") :test #'equal)
               (invalid-pod "resizePolicy.restartPolicy must be NotRequired or RestartContainer"))
             (when (member (gethash "resourceName" entry) seen :test #'equal)
               (invalid-pod "resizePolicy has a duplicate resource ~A" (gethash "resourceName" entry)))
             (push (gethash "resourceName" entry) seen))))

(defun resource-quantities-equal-p (left right)
  "Compare two JSON quantity lists semantically, as parsed amounts."
  (let ((left (or left (core-object))) (right (or right (core-object))))
    (and (= (hash-table-count left) (hash-table-count right))
         (loop for name being the hash-keys of left using (hash-value value)
               always (and (nth-value 1 (gethash name right))
                           (zerop (container-quantity-compare (parse-container-quantity value)
                                                              (parse-container-quantity (gethash name right)))))))))

(defun container-resources-equal-p (left right)
  "Compare two resource declarations semantically; absent and empty mean the same."
  (flet ((part (resources kind) (and resources (gethash kind resources))))
    (and (resource-quantities-equal-p (part left "requests") (part right "requests"))
         (resource-quantities-equal-p (part left "limits") (part right "limits")))))

(defun validate-container-resize (old new policy)
  "Refuse resource changes Kubernetes refuses for container declarations OLD and NEW."
  (let ((name (gethash "name" old)))
    (unless (equal (gethash "image" old) (gethash "image" new))
      (invalid-pod "pod resize may not change spec.containers[~A].image" name))
    (dolist (kind '("requests" "limits"))
      (let ((before (gethash kind (gethash "resources" old (core-object)) (core-object)))
            (after (gethash kind (gethash "resources" new (core-object)) (core-object))))
        (maphash (lambda (resource value)
                   (declare (ignorable value))
                   (when (and (member resource '("cpu" "memory") :test #'equal)
                              (equal kind "limits") (not (gethash resource after)))
                     (invalid-pod "resource limits cannot be removed from container ~A" name))
                   (unless (member resource '("cpu" "memory") :test #'equal)
                     (unless (equal (gethash resource before) (gethash resource after))
                       (invalid-pod "only cpu and memory resources are mutable; ~A of container ~A changed" resource name))))
                 before)
        (maphash (lambda (resource value)
                   (declare (ignorable value))
                   (unless (or (member resource '("cpu" "memory") :test #'equal)
                               (nth-value 1 (gethash resource before)))
                     (invalid-pod "only cpu and memory resources are mutable; ~A of container ~A changed" resource name)))
                 after)))
    (when (equal policy "Never")
      (loop for entry across (gethash "resizePolicy" new #())
            do (when (equal "RestartContainer" (gethash "restartPolicy" entry))
                 (invalid-pod "resizePolicy RestartContainer is not allowed with restartPolicy Never"))))))

(defun pod-resize-merged-object (pod input)
  "Return POD's object with only the resources and resize policies INPUT declares."
  (let* ((object (copy-json-object (pod-to-object pod)))
         (spec (gethash "spec" object))
         (requested (require-object (gethash "spec" input) "spec")))
    (loop for field in '("containers" "initContainers")
          do (let ((declared (gethash field spec #()))
                   (asked (gethash field requested #())))
               (unless (= (length declared) (length asked))
                 (invalid-pod "pod resize may not add or remove spec.~A" field))
               (loop for container across declared
                     for new = (find (gethash "name" container) asked :test #'equal
                                     :key (lambda (item) (gethash "name" item)))
                     do (unless new (invalid-pod "pod resize may not add or remove spec.~A" field))
                        (let ((resources (gethash "resources" new)))
                          (if (and resources (not (eq resources 'null)))
                              (setf (gethash "resources" container) (copy-json-object resources))
                              (remhash "resources" container)))
                        (normalize-container-resources container)
                        (let ((policy (gethash "resizePolicy" new)))
                          (if (and policy (not (eq policy 'null)))
                              (setf (gethash "resizePolicy" container) (copy-json-object policy))
                              (remhash "resizePolicy" container))))))
    object))

(defun validate-pod-resize (pod replacement)
  "Refuse a resize of ordinary init containers or one that would change the Pod's QoS class."
  (let ((old (gethash "spec" (pod-to-object pod)))
        (new (gethash "spec" (pod-to-object replacement))))
    (loop for before across (gethash "initContainers" old #())
          for after = (find (gethash "name" before) (gethash "initContainers" new #()) :test #'equal
                            :key (lambda (item) (gethash "name" item)))
          do (unless (or (equal "Always" (gethash "restartPolicy" before))
                         (container-resources-equal-p (gethash "resources" before) (gethash "resources" after)))
               (invalid-pod "only regular containers and sidecars can be resized")))
    (loop for field in '("containers" "initContainers")
          do (loop for before across (gethash field old #())
                   for after = (find (gethash "name" before) (gethash field new #()) :test #'equal
                                     :key (lambda (item) (gethash "name" item)))
                   do (validate-container-resize before after (pod-restart-policy pod))))
    (unless (equal (pod-spec-qos-class old) (pod-spec-qos-class new))
      (invalid-pod "Pod QoS is immutable: resizing would change it from ~A to ~A"
                   (pod-spec-qos-class old) (pod-spec-qos-class new)))))

(defun refuse-pod-resize-beyond-node (store pod replacement)
  "Refuse a resize its node could never hold, which a client can only learn about in time from here."
  (let ((node (and (pod-node-name pod)
                   (with-store-lock (store) (gethash (pod-node-name pod) (pod-store-nodes store))))))
    (when node
      (let ((allocatable (node-allocatable-table node)) (old (pod-requests-table pod)) (new (pod-requests-table replacement)))
        (dolist (resource '("cpu" "memory"))
          (multiple-value-bind (limit known) (gethash resource allocatable)
            (when (and known (> (gethash resource new 0) limit) (> (gethash resource new 0) (gethash resource old 0)))
              (let ((message (format nil "Pod resize rejected: node didn't have enough allocatable resources: ~A, requested: ~A, allocatable: ~A"
                                     resource (policy-value-string (gethash resource new)) (policy-value-string limit))))
                (error 'kubernetes-error
                       :status-code 403 :reason "Forbidden" :message message
                       :details (core-object "name" (pod-name pod) "kind" "pods"
                                             "causes" (vector (core-object "reason" "NodeCapacity" "message" message))))))))))))

(defun write-pod-resize-response (store reconciler name namespace method)
  "Declare new resources for POD's containers, and leave carrying them out to its node."
  (let* ((pod (get-pod store namespace name))
         (input (admit-subresource-write
                 store "pods" "resize" namespace name
                 (require-object (pod-ephemeral-write-input (pod-to-object pod) method) "Pod")
                 (pod-to-object pod) :dry-run (core-resource-dry-run-p)))
         (metadata (require-object (gethash "metadata" input) "metadata"))
         (expected (gethash "resourceVersion" metadata)))
    (when (and (gethash "name" metadata) (not (equal name (gethash "name" metadata))))
      (core-resource-error 400 "BadRequest" "metadata.name does not match request name"))
    (when (and (stringp expected) (plusp (length expected))
               (not (pod-revision-satisfied-p store expected (pod-resource-version pod))))
      (core-resource-error 409 "Conflict" "Pod resourceVersion has changed"))
    (let ((replacement (parse-pod (pod-resize-merged-object pod input))))
      (validate-pod-resize pod replacement)
      (refuse-pod-resize-beyond-node store pod replacement)
      (if (core-resource-dry-run-p)
          (json-response (pod-response-object replacement (reconcile-pod reconciler namespace name)))
          (let ((updated (let ((*pod-resize-update* t))
                           (update-pod store replacement (pod-resource-version pod)))))
            (json-response (pod-response-object updated (reconcile-written-pod reconciler updated))))))))

(defun container-resize-restart-required-p (container before after)
  "Return whether changing resources BEFORE to AFTER requires a restart under CONTAINER's policy."
  (flet ((changed-p (resource)
           (flet ((part (resources kind)
                    (let ((values (and resources (gethash kind resources))))
                      (and values (gethash resource values)))))
             (loop for kind in '("requests" "limits")
                   for left = (part before kind) for right = (part after kind)
                   thereis (not (or (and (null left) (null right))
                                    (and left right
                                         (zerop (container-quantity-compare (parse-container-quantity left)
                                                                            (parse-container-quantity right))))))))))
    (loop for entry across (gethash "resizePolicy" container #())
          thereis (and (equal "RestartContainer" (gethash "restartPolicy" entry))
                       (changed-p (gethash "resourceName" entry))))))

(defun record-container-applied-spec (state name object)
  "Remember the image and resources container NAME was just started with."
  (let ((entry (or (gethash name (gethash "containers" state)) (core-object))))
    (setf (gethash "appliedImage" entry) (gethash "image" object)
          (gethash "appliedResources" entry) (copy-core-object (or (gethash "resources" object) (core-object)))
          (gethash name (gethash "containers" state)) entry)))

(defun request-container-update-restart (pod state name container-id)
  "Durably ask for container NAME's exact attempt to stop and start again with its new declaration."
  (let ((entry (gethash name (gethash "containers" state))))
    (unless (equal container-id (gethash "containerID" (gethash "probeRestart" entry (core-object))))
      (setf (gethash "probeRestart" entry)
            (core-object "containerID" container-id "kind" "update" "message" "container declaration changed"
                         "deadline" (+ (funcall *container-lifecycle-clock*)
                                       (gethash "terminationGracePeriodSeconds" (gethash "spec" (pod-to-object pod)) 30)))))))

(defun cri-update-container-resources (socket-path container-id resources &key (timeout 30))
  "Apply RESOURCES to a running container's cgroup through CRI."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-update-container-resources
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::update-container-resources-request
                             :container-id container-id :linux resources)
              :timeout timeout)
           (declare (ignore response))
           (ensure-cri-status "UpdateContainerResources" status))
      (ag-grpc:channel-close channel))))

(defun pod-applied-requests (runtime pod)
  "Return POD's requests as its containers actually run them, which a pending resize has not changed."
  (let* ((state (load-container-lifecycle-state runtime (pod-uid pod)))
         (spec (copy-core-object (gethash "spec" (pod-to-object pod)))))
    (dolist (field '("initContainers" "containers"))
      (loop for object across (gethash field spec #())
            for entry = (gethash (gethash "name" object) (gethash "containers" state))
            for applied = (and entry (gethash "appliedResources" entry))
            when applied do (setf (gethash "resources" object) applied)))
    (values (pod-spec-resource-totals spec))))

(defun pod-resize-outranks-p (left right)
  "Return whether a pending resize of Pod LEFT goes before one of Pod RIGHT, by priority then QoS class."
  (flet ((qos-rank (pod)
           (position (pod-spec-qos-class (gethash "spec" (pod-to-object pod))) '("BestEffort" "Burstable" "Guaranteed")
                     :test #'equal)))
    (or (> (pod-spec-priority left) (pod-spec-priority right))
        (and (= (pod-spec-priority left) (pod-spec-priority right))
             (> (qos-rank left) (qos-rank right))))))

(defun pod-resize-verdict (desired applied used capacity)
  "Judge requests DESIRED against CAPACITY and the amounts other Pods have USED, as a kubelet does.
Return NIL when the resize may go ahead, or its pending reason and message. Giving back resources
always may, since waiting could not help."
  (flet ((amount (table name) (gethash name table 0)))
    (when (some (lambda (name) (> (amount desired name) (amount applied name))) '("cpu" "memory"))
      (dolist (name '("cpu" "memory"))
        (multiple-value-bind (limit known) (gethash name capacity)
          (when (and known (> (amount desired name) limit))
            (return-from pod-resize-verdict
              (values "Infeasible"
                      (format nil "Node didn't have enough capacity: ~A, requested: ~A, capacity: ~A"
                              name (policy-value-string (amount desired name)) (policy-value-string limit)))))))
      (dolist (name '("cpu" "memory"))
        (multiple-value-bind (limit known) (gethash name capacity)
          (when (and known (> (+ (amount desired name) (amount used name)) limit))
            (return-from pod-resize-verdict
              (values "Deferred"
                      (format nil "Node didn't have enough resource: ~A, requested: ~A, used: ~A, capacity: ~A"
                              name (policy-value-string (amount desired name)) (policy-value-string (amount used name))
                              (policy-value-string limit))))))))))

(defun pod-resize-judgement (runtime pod)
  "Return the pending reason and message of POD's declared resources on this node, if any."
  (let ((judge (gr8s.runtime.containerd:containerd-runtime-resource-resize-function runtime)))
    (when judge
      (multiple-value-bind (reason message) (funcall judge pod)
        (when reason (return-from pod-resize-judgement (values reason message))))))
  (let ((used (make-hash-table :test #'equal))
        (lister (containerd-runtime-pod-lister runtime)))
    (when lister
      (dolist (other (funcall lister))
        (unless (equal (pod-uid other) (pod-uid pod))
          ;; Another Pod's waiting increase only counts against this one if it goes first.
          (let ((amounts (if (pod-resize-outranks-p other pod)
                             (pod-requests-table other)
                             (pod-applied-requests runtime other))))
            (maphash (lambda (name value) (incf (gethash name used 0) value)) amounts)))))
    (let ((capacity (make-hash-table :test #'equal)))
      (maphash (lambda (name value) (setf (gethash name capacity) (policy-value value))) (node-reported-capacity))
      (pod-resize-verdict (pod-requests-table pod) (pod-applied-requests runtime pod) used capacity))))

(defun note-pod-resize-pending (state reason message)
  "Durably record why a resize waits, returning whether that changed anything observable."
  (let ((old (gethash "resizePending" state)))
    (cond ((and reason (not (and old (equal reason (gethash "reason" old)) (equal message (gethash "message" old)))))
           (setf (gethash "resizePending" state) (core-object "type" "PodResizePending" "status" "True"
                                                               "reason" reason "message" message))
           t)
          ((and old (null reason)) (remhash "resizePending" state) t))))

(defun reconcile-container-updates (runtime pod observed)
  "Carry out changed images and resources for POD's running containers, returning true on any change.
A node that cannot take a resize keeps the old resources and says why, as PodResizePending."
  (let* ((uid (pod-uid pod)) (state (load-container-lifecycle-state runtime uid)) (changed nil)
         (reason nil) (message nil) (judged nil))
    (dolist (object (pod-probed-container-objects pod))
      (let* ((name (gethash "name" object))
             (entry (gethash name (gethash "containers" state)))
             (status (find name (container-lifecycle-all-statuses observed) :test #'equal
                           :key (lambda (item) (gethash "name" item))))
             (running (and status entry (hash-table-p (gethash "state" status))
                           (gethash "running" (gethash "state" status))))
             (id (and running (subseq (gethash "containerID" status) (length "containerd://"))))
             (applied-image (and entry (gethash "appliedImage" entry)))
             (applied (and entry (gethash "appliedResources" entry)))
             (desired (or (gethash "resources" object) (core-object))))
        (when (and running id)
          (cond
            ;; Attempts from before these were recorded are taken as they are.
            ((null applied-image)
             (record-container-applied-spec state name object) (setf changed t))
            ((not (equal applied-image (gethash "image" object)))
             (request-container-update-restart pod state name id) (setf changed t))
            ((container-resources-equal-p applied desired))
            ((progn
               (unless judged
                 (multiple-value-setq (reason message) (pod-resize-judgement runtime pod))
                 (setf judged t))
               reason))
            ((container-resize-restart-required-p object applied desired)
             (request-container-update-restart pod state name id) (setf changed t))
            (t
             (cri-update-container-resources (containerd-runtime-socket-path runtime) id
                                             (gr8s.runtime.containerd:containerd-effective-container-resources runtime pod object))
             (setf (gethash "appliedResources" entry) (copy-core-object desired) changed t))))))
    (when (note-pod-resize-pending state reason message) (setf changed t))
    (when changed (save-container-lifecycle-state runtime uid state))
    changed))

(defun pod-resize-in-progress-p (pod status)
  "Return whether any running container's actual resources still differ from its declaration."
  (flet ((differs-p (object statuses)
           (let ((item (find (gethash "name" object) statuses :test #'equal
                             :key (lambda (entry) (and (hash-table-p entry) (gethash "name" entry))))))
             (and item (hash-table-p (gethash "state" item))
                  (gethash "running" (gethash "state" item))
                  (nth-value 1 (gethash "resources" item))
                  (not (container-resources-equal-p (gethash "resources" object) (gethash "resources" item)))))))
    (let ((spec (gethash "spec" (pod-to-object pod))))
      (or (some (lambda (object) (differs-p object (gethash "containerStatuses" status #())))
                (gethash "containers" spec #()))
          (some (lambda (object) (differs-p object (gethash "initContainerStatuses" status #())))
                (remove-if-not (lambda (object) (equal "Always" (gethash "restartPolicy" object)))
                               (gethash "initContainers" spec #())))))))
