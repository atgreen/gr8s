;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Change what a running container was declared with, without replacing its
;;;; sandbox: the pods/resize subresource and in-place CPU and memory updates, or
;;;; a restart of just that container for a new image or a RestartContainer resize
;;;; policy. A container's status reports what was actually applied, so a resize
;;;; stays visibly in progress until the runtime has carried it out.

(in-package #:gr8s)

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
      (if (core-resource-dry-run-p)
          (json-response (pod-response-object replacement (reconcile-pod reconciler namespace name)))
          (let ((updated (let ((*pod-resize-update* t))
                           (update-pod store replacement (pod-resource-version pod)))))
            (json-response (pod-response-object updated (reconcile-pod reconciler namespace name))))))))

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

(defun reconcile-container-updates (runtime pod observed)
  "Carry out changed images and resources for POD's running containers, returning true on any change."
  (let* ((uid (pod-uid pod)) (state (load-container-lifecycle-state runtime uid)) (changed nil))
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
            ((container-resize-restart-required-p object applied desired)
             (request-container-update-restart pod state name id) (setf changed t))
            (t
             (cri-update-container-resources (containerd-runtime-socket-path runtime) id
                                             (cri-linux-container-resources object))
             (setf (gethash "appliedResources" entry) (copy-core-object desired) changed t))))))
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
