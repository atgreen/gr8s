;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Convert actual node probe occurrences into ordinary Kubernetes Events only
;;;; after the node session validates Pod UID, assignment and desired revision.
;;;; Replayed cumulative counts do not create duplicate changes; all object
;;;; references and reporter identities come from authenticated server state.
;;;;
;;;; An occurrence that repeats, such as a probe failing every few seconds, has
;;;; its first few counts published at once and after that at most once a minute:
;;;; each publication is a write to every member of the control plane.

(in-package #:gr8s.resources)

(defparameter +container-lifecycle-event-reasons+
  '("Created" "Started" "Killing" "Failed" "FailedPostStartHook" "FailedPreStopHook"
    "BackOff" "FailedMount" "ErrImageNeverPull" "FailedToRetrieveImagePullSecret"
    "RestartingAllContainers")
  "The container occurrences a node reports besides its probes' results.")

(defparameter +pod-runtime-event-reasons+ '("Evicted")
  "The occurrences a node reports about a Pod as a whole, with no container to name.")

(defun node-runtime-event-reasons (kind)
  "Return the reasons a node may report for an Event of KIND."
  (cond ((equal kind "lifecycle") +container-lifecycle-event-reasons+)
        ((equal kind "pod") +pod-runtime-event-reasons+)
        (t '("Unhealthy" "ProbeWarning"))))

(defparameter *node-event-prompt-occurrences* 10
  "How many occurrences of one Event are each published as soon as they are reported.")

(defparameter *node-event-rewrite-seconds* 60
  "Once an Event has occurred more often than that, the least time between rewrites of it.")

(defun node-runtime-event-due-p (stored event)
  "True when EVENT, a node's cumulative record, should replace what STORED shows:
it has occurred again, and either it is still new or STORED is a minute behind."
  (let ((count (gethash "count" event)))
    (and (> count (gethash "count" stored 0))
         (or (<= count *node-event-prompt-occurrences*)
             (handler-case (>= (- (pod-deletion-time (gethash "lastTimestamp" event))
                                  (pod-deletion-time (gethash "lastTimestamp" stored)))
                               *node-event-rewrite-seconds*)
               (error () t))))))

(defun record-node-runtime-events (store pod node-name events)
  "Publish bounded same-Pod cumulative pages; ignore malformed or expired records."
  (when (and (vectorp events) (not (stringp events)))
    (loop for event across events for index below 4096
          for pod-level = (and (hash-table-p event) (equal "pod" (gethash "kind" event)))
          when (and (hash-table-p event) (stringp (gethash "id" event)) (<= 1 (length (gethash "id" event)) 128)
                    (member (gethash "kind" event) '("startupProbe" "readinessProbe" "livenessProbe" "lifecycle" "pod")
                            :test #'equal)
                    (member (gethash "reason" event) (node-runtime-event-reasons (gethash "kind" event)) :test #'equal)
                    (or pod-level
                        (find (gethash "container" event) (pod-all-containers pod) :test #'equal :key #'container-spec-name))
                    (typep (gethash "count" event) '(integer 1 2147483647))
                    (stringp (gethash "message" event))
                    (<= (length (trivial-utf-8:string-to-utf-8-bytes (gethash "message" event))) 1024)
                    (handler-case (< (funcall *event-clock*)
                                     (+ (pod-deletion-time (gethash "lastTimestamp" event)) *event-ttl-seconds*))
                      (error () nil)))
            do (handler-case
                   (block publication
                     (let* ((key (format nil "~A/~A" (pod-uid pod) (gethash "id" event)))
                            (name (concatenate 'string "probe-" (string-downcase (subseq (octets-to-hex (ironclad:digest-sequence :sha256 (trivial-utf-8:string-to-utf-8-bytes key))) 0 48))))
                            (existing (handler-case (get-core-resource store "events" (pod-namespace pod) name)
                                        (kubernetes-error (error) (unless (= 404 (kubernetes-error-status-code error)) (error error)) nil))))
                       (if existing
                           (when (and (equal (pod-uid pod) (gethash "uid" (gethash "involvedObject" existing)))
                                      (node-runtime-event-due-p existing event))
                             (update-core-resource store "events" (pod-namespace pod) name
                               (lambda (old)
                                 (unless (and (equal (pod-uid pod) (gethash "uid" (gethash "involvedObject" old)))
                                              (node-runtime-event-due-p old event))
                                   (return-from publication nil))
                                 (setf (gethash "count" old) (gethash "count" event)
                                       (gethash "lastTimestamp" old) (gethash "lastTimestamp" event)
                                       (gethash "message" old) (gethash "message" event)) old)))
                           (create-core-resource store "events"
                             (core-object "apiVersion" "v1" "kind" "Event" "metadata" (core-object "name" name)
                                          "involvedObject" (let ((object (core-object "apiVersion" "v1" "kind" "Pod"
                                                                                      "namespace" (pod-namespace pod)
                                                                                      "name" (pod-name pod) "uid" (pod-uid pod))))
                                                             ;; An Event about the whole Pod names no container.
                                                             (unless pod-level
                                                               (setf (gethash "fieldPath" object)
                                                                     (format nil "spec.containers{~A}" (gethash "container" event))))
                                                             object)
                                          "reason" (gethash "reason" event) "message" (gethash "message" event)
                                          "type" (if (equal "Normal" (gethash "type" event)) "Normal" "Warning")
                                          "count" (gethash "count" event) "firstTimestamp" (gethash "firstTimestamp" event)
                                          "lastTimestamp" (gethash "lastTimestamp" event)
                                          "source" (core-object "component" "kubelet" "host" node-name)
                                          "reportingComponent" "kubelet" "reportingInstance" node-name)
                             (pod-namespace pod)))))
                 (error (condition)
                   (format *error-output* "gr8s probe Event publication failed: ~A~%" condition)
                   ;; No quorum: each further write would wait out its own
                   ;; timeout. The node reports these cumulative records again.
                   (when (and (typep condition 'kubernetes-error)
                              (= 503 (kubernetes-error-status-code condition)))
                     (return)))))))
