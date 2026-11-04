;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Derive Kubernetes Pod conditions from real per-container observations.
;;;; Running or assignment alone never implies Ready. Stable condition status
;;;; retains its transition timestamp, including across process restarts; this
;;;; history does not advance the independently tracked agent-observed revision.

(in-package #:gr8s)

(defparameter *pod-condition-clock* #'get-universal-time)

(defun find-pod-condition (conditions type)
  "Find TYPE in a JSON Pod condition array, tolerating absence of the array."
  (when (and (vectorp conditions) (not (stringp conditions)))
    (find type conditions :test #'equal :key (lambda (condition) (gethash "type" condition)))))

(defun pod-status-ready-p (status)
  "Return true only for an explicit Ready=True condition in STATUS."
  (let ((condition (and status (find-pod-condition (gethash "conditions" status) "Ready"))))
    (and condition (equal "True" (gethash "status" condition)))))

(defun pod-container-readiness (pod status)
  "Return readiness status, reason and message for every declared regular container."
  (let ((phase (gethash "phase" status "Unknown"))
        (containers (gethash "containerStatuses" status))
        (unknown nil) (unready nil))
    (cond
      ((equal phase "Unknown")
       (return-from pod-container-readiness
         (values "Unknown" (if (equal "Terminating" (gethash "reason" status))
                               "UnknownContainerStatuses" "NodeStatusUnknown")
                 "Container readiness is unknown")))
      ((equal phase "Succeeded")
       (return-from pod-container-readiness (values "False" "PodCompleted" nil)))
      ((equal phase "Failed")
       (return-from pod-container-readiness (values "False" "PodFailed" nil))))
    (unless (pod-initialization-complete-p pod status)
      (return-from pod-container-readiness (values "False" "ContainersNotInitialized" nil)))
    (unless (and (vectorp containers) (not (stringp containers)) (plusp (length containers)))
      (return-from pod-container-readiness (values "False" "UnknownContainerStatuses" nil)))
    (loop for spec across (pod-containers pod)
          for name = (container-spec-name spec)
          for matches = (remove-if-not (lambda (item) (and (hash-table-p item) (equal name (gethash "name" item)))) containers)
          do (cond
               ((/= 1 (length matches)) (push name unknown))
               ((not (and (eq t (gethash "ready" (aref matches 0)))
                          (hash-table-p (gethash "state" (aref matches 0)))
                          (hash-table-p (gethash "running" (gethash "state" (aref matches 0))))))
                (push name unready))))
    (if (or unknown unready (not (equal phase "Running")) (not (pod-node-name pod)))
        (values "False" "ContainersNotReady"
                (format nil "containers with unknown status: [~{~A~^, ~}]; containers not ready: [~{~A~^, ~}]"
                        (nreverse unknown) (nreverse unready)))
        (values "True" nil nil))))

(defun pod-condition-transition-time (old incoming value now)
  "Keep the last timestamp while status is unchanged; never backdate a later transition."
  (let* ((previous (and old (gethash "lastTransitionTime" old)))
         (source (and incoming (gethash "lastTransitionTime" incoming)))
         (source-time (and source (ignore-errors (pod-deletion-time source))))
         (previous-time (and previous (ignore-errors (pod-deletion-time previous)))))
    (cond
      ((and previous-time (equal value (gethash "status" old))) previous)
      ((and source-time (equal value (gethash "status" incoming))
            (or (not previous-time) (>= source-time previous-time)) (<= source-time now)) source)
      (t (current-timestamp now)))))

(defun add-declared-container-statuses (pod status)
  "List every declared container of an assigned, unfinished Pod, as a kubelet does.
A container the agent has not reported yet is waiting. Clients cannot read an empty
list as 'nothing is running': Sonobuoy's worker takes it to mean all containers exited."
  (when (and (pod-node-name pod)
             (member (gethash "phase" status) '("Pending" "Running") :test #'equal))
    ;; Reports stay untouched, so readiness still sees any malformed or duplicate entry.
    (let ((reported (gethash "containerStatuses" status #())))
      (setf (gethash "containerStatuses" status)
            (concatenate
             'vector reported
             (loop for container across (pod-containers pod)
                   for name = (container-spec-name container)
                   unless (find name reported :test #'equal
                                :key (lambda (item) (and (hash-table-p item) (gethash "name" item))))
                     collect (core-object "name" name "image" (container-spec-image container)
                                          "imageID" "" "restartCount" 0 "ready" nil "started" nil
                                          "state" (core-object "waiting" (core-object "reason" "ContainerCreating"))))))))
  status)

(defun add-pod-status-conditions (store pod status)
  "Attach truthful conditions and checkpoint their history without acknowledging a revision."
  (add-declared-container-statuses pod status)
  (let* ((scheduled (not (null (pod-node-name pod))))
         (incoming (gethash "conditions" status))
         (generation (gethash "observedGeneration" status))
         (phase (gethash "phase" status "Unknown"))
         (now (funcall *pod-condition-clock*)))
    (multiple-value-bind (readiness reason message) (pod-container-readiness pod status)
      (with-store-lock (store)
        (let ((history (gethash (pod-uid pod) (pod-store-pod-condition-histories store)))
              (conditions nil))
          (labels ((condition (type value &optional reason message)
                     (let ((result (core-object "type" type "status" value
                                                "lastTransitionTime"
                                                (pod-condition-transition-time
                                                 (find-pod-condition history type)
                                                 (find-pod-condition incoming type) value now))))
                       (when generation (setf (gethash "observedGeneration" result) generation))
                       (when reason (setf (gethash "reason" result) reason))
                       (when message (setf (gethash "message" result) message))
                       (push result conditions))))
            (condition "PodScheduled" (if scheduled "True" "False")
                       (unless scheduled "Unschedulable")
                       (unless scheduled "Waiting for an available matching node"))
            (let ((initialized (and scheduled (pod-initialization-complete-p pod status)))
                  (incomplete (loop for spec across (pod-init-containers pod)
                                    unless (init-container-succeeded-p
                                            (find (container-spec-name spec) (gethash "initContainerStatuses" status)
                                                  :test #'equal :key (lambda (item) (gethash "name" item))))
                                      collect (container-spec-name spec))))
              (condition "Initialized" (if initialized "True" "False")
                         (cond ((not scheduled) "PodInitializing")
                               (incomplete "ContainersNotInitialized")
                               ((equal phase "Succeeded") "PodCompleted"))
                         (when incomplete
                           (format nil "containers with incomplete status: [~{~A~^ ~}]" incomplete))))
            (condition "ContainersReady" readiness reason message)
            (condition "Ready" readiness reason message))
          (setf conditions (coerce (nreverse conditions) 'vector)
                (gethash "conditions" status) conditions)
          (when (and (current-status-pod-p store pod) (not (equalp conditions history)))
            (persist-pod-status-state store pod :conditions conditions)
            (setf (gethash (pod-uid pod) (pod-store-pod-condition-histories store))
                  (copy-pod-status-value conditions)))
          (let ((nominated (and (not scheduled) (gethash (pod-uid pod) (pod-store-nominated-nodes store)))))
            (when nominated (setf (gethash "nominatedNodeName" status) nominated)))
          (add-pod-host-address store pod status)
          (apply-pod-client-status store pod status)
          (publish-pod-status-unlocked store pod status)))))
  status)
