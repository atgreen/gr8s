;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve the policy/v1 Eviction subresource of Pods. An eviction marks a live
;;;; Pod with the DisruptionTarget condition and then deletes it gracefully.
;;;; gr8s has no PodDisruptionBudget API, so no budget can refuse an eviction.

(in-package #:gr8s)

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
  (let ((content-type (first (uiop:split-string (or (hunchentoot:header-in* :content-type) "") :separator '(#\;)))))
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

(defun pod-eviction-response (store reconciler name namespace)
  "Evict the named Pod: name the disruption on it, then delete it with the given options."
  (let* ((input (eviction-request-object))
         (metadata (require-object (gethash "metadata" input (core-object)) "metadata"))
         (options (gethash "deleteOptions" input))
         (preconditions (and options (not (eq options 'null)) (gethash "preconditions" options)))
         (grace (and options (not (eq options 'null)) (gethash "gracePeriodSeconds" options)))
         (preview (and options (not (eq options 'null)) (gethash "dryRun" options)))
         (dry-run (or (core-resource-dry-run-p)
                      (and (vectorp preview) (not (stringp preview)) (plusp (length preview)))))
         (pod (get-pod store namespace name))
         (uid (and preconditions (not (eq preconditions 'null)) (gethash "uid" preconditions)))
         (revision (and preconditions (not (eq preconditions 'null)) (gethash "resourceVersion" preconditions))))
    (unless (member (gethash "name" metadata name) (list name "") :test #'equal)
      (core-resource-error 400 "BadRequest" "Eviction name does not match the Pod in the request"))
    (when (and uid (not (equal uid (pod-uid pod))))
      (core-resource-error 409 "Conflict" "Pod UID no longer matches the eviction precondition"))
    (unless dry-run
      (unless (or (deletion-requested-p pod)
                  (pod-terminal-status-p (with-store-lock (store)
                                           (gethash (pod-uid pod) (pod-store-pod-observed-statuses store)))))
        (mark-pod-disruption-target store pod))
      (apply #'delete-reconciled-pod reconciler namespace name :uid (pod-uid pod) :resource-version revision
             (when (integerp grace) (list :grace-period grace))))
    (status-response "Success" "Created" "Eviction accepted" 201)))
