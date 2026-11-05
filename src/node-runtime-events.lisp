;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Convert actual node probe occurrences into ordinary Kubernetes Events only
;;;; after the node session validates Pod UID, assignment and desired revision.
;;;; Replayed cumulative counts do not create duplicate changes; all object
;;;; references and reporter identities come from authenticated server state.

(in-package #:gr8s)

(defparameter +container-lifecycle-event-reasons+
  '("Created" "Started" "Killing" "Failed" "FailedPostStartHook" "FailedPreStopHook")
  "The container occurrences a node reports besides its probes' results.")

(defun record-node-runtime-events (store pod node-name events)
  "Publish bounded same-Pod cumulative pages; ignore malformed or expired records."
  (when (and (vectorp events) (not (stringp events)))
    (loop for event across events for index below 4096
          when (and (hash-table-p event) (stringp (gethash "id" event)) (<= 1 (length (gethash "id" event)) 128)
                    (member (gethash "kind" event) '("startupProbe" "readinessProbe" "livenessProbe" "lifecycle") :test #'equal)
                    (member (gethash "reason" event) (if (equal "lifecycle" (gethash "kind" event))
                                                         +container-lifecycle-event-reasons+
                                                         '("Unhealthy" "ProbeWarning"))
                            :test #'equal)
                    (find (gethash "container" event) (pod-all-containers pod) :test #'equal :key #'container-spec-name)
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
                                      (> (gethash "count" event) (gethash "count" existing 0)))
                             (update-core-resource store "events" (pod-namespace pod) name
                               (lambda (old)
                                 (unless (and (equal (pod-uid pod) (gethash "uid" (gethash "involvedObject" old)))
                                              (> (gethash "count" event) (gethash "count" old 0)))
                                   (return-from publication nil))
                                 (setf (gethash "count" old) (gethash "count" event)
                                       (gethash "lastTimestamp" old) (gethash "lastTimestamp" event)
                                       (gethash "message" old) (gethash "message" event)) old)))
                           (create-core-resource store "events"
                             (core-object "apiVersion" "v1" "kind" "Event" "metadata" (core-object "name" name)
                                          "involvedObject" (core-object "apiVersion" "v1" "kind" "Pod" "namespace" (pod-namespace pod)
                                                                        "name" (pod-name pod) "uid" (pod-uid pod)
                                                                        "fieldPath" (format nil "spec.containers{~A}" (gethash "container" event)))
                                          "reason" (gethash "reason" event) "message" (gethash "message" event)
                                          "type" (if (equal "Normal" (gethash "type" event)) "Normal" "Warning")
                                          "count" (gethash "count" event) "firstTimestamp" (gethash "firstTimestamp" event)
                                          "lastTimestamp" (gethash "lastTimestamp" event)
                                          "source" (core-object "component" "kubelet" "host" node-name)
                                          "reportingComponent" "kubelet" "reportingInstance" node-name)
                             (pod-namespace pod)))))
                 (error (condition) (format *error-output* "gr8s probe Event publication failed: ~A~%" condition))))))
