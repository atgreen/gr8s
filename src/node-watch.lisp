;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Give Nodes a revision for every change clients can see, and a bounded event
;;;; journal to watch them by. Node records live outside the durable resource store,
;;;; and their revisions come from the Pod revision counter, which already covers
;;;; Node writes. The journal is memory-only: resuming from before it returns 410
;;;; Gone, which Kubernetes clients answer by relisting.

(in-package #:gr8s)

(defparameter *node-watch-journal-limit* 1024
  "Retain at least this many recent Node events for resuming watches.")

(defparameter +node-selector-field-paths+ '("metadata.name" "spec.unschedulable")
  "The Node fields clients may name in field selectors.")

(defun next-node-revision-unlocked (store node)
  "Allocate a revision above NODE's own, which a fresh store's counter can trail."
  (let ((current (parse-integer (node-record-resource-version node))))
    (loop for revision = (next-pod-revision-unlocked store)
          when (> revision current) return revision)))

(defun record-node-watch-event-unlocked (store revision old new)
  "Append one transition to the journal, compacting once it doubles its retention."
  (push (list revision old new) (pod-store-node-watch-journal store))
  (when (> (incf (pod-store-node-watch-journal-length store)) (* 2 *node-watch-journal-limit*))
    (let ((retained (subseq (pod-store-node-watch-journal store) 0 *node-watch-journal-limit*)))
      ;; The oldest retained event must stay readable, so resume just before it.
      (setf (pod-store-node-watch-floor store) (1- (first (car (last retained))))
            (pod-store-node-watch-journal store) retained
            (pod-store-node-watch-journal-length store) *node-watch-journal-limit*))))

(defun publish-node-change-unlocked (store old node)
  "Persist NODE at a fresh revision and journal it, unless its API view still equals OLD.
OLD is NODE's view before the change, or NIL when NODE is new. Heartbeats change nothing a
client can see, so they cost neither a revision nor an event."
  (let ((new (node-api-object node)))
    (unless (and old (workload-equal-p old new))
      (let ((revision (next-node-revision-unlocked store node)))
        (setf (node-record-resource-version node) (write-to-string revision)
              (gethash "resourceVersion" (gethash "metadata" new)) (write-to-string revision))
        (persist-node store node)
        (record-node-watch-event-unlocked store revision old new)))
    node))

(defun remove-node-unlocked (store node)
  "Forget NODE durably and journal its final API view as a deletion at a fresh revision."
  (let ((old (node-api-object node))
        (path (node-path store node)))
    (when (probe-file path) (delete-file path))
    (remhash (node-record-name node) (pod-store-nodes store))
    (record-node-watch-event-unlocked store (next-node-revision-unlocked store node) old nil)
    (note-node-desired-change store)))

(defun check-node-watch-revision-unlocked (store revision)
  "Reject REVISION when its later events are gone or have not yet been issued."
  (when (< revision (pod-store-node-watch-floor store))
    (core-resource-error 410 "Expired" "too old resource version: ~D (~D)"
                         revision (pod-store-node-watch-floor store)))
  (when (> revision (pod-store-pod-revision store))
    (core-resource-error 504 "Timeout" "Requested resourceVersion is newer than storage")))

(defun node-selection-predicate (labels fields)
  "Return a test for Node API views matching the LABELS and FIELDS selectors."
  (let ((label-test (core-selector-predicate labels))
        (field-test (core-selector-predicate fields :fields t :field-paths +node-selector-field-paths+)))
    (lambda (object)
      (and (hash-table-p object) (funcall label-test object) (funcall field-test object)))))

(defun node-list-page (store labels fields &optional resource-version match)
  "Return the revision and current API views of the Nodes selected, read as one view."
  (let ((matches (node-selection-predicate labels fields))
        (requested (unless (member resource-version '(nil "" "0") :test #'equal)
                     (parse-integer resource-version))))
    (with-store-lock (store)
      (when requested (check-node-watch-revision-unlocked store requested))
      (core-object
       "apiVersion" "v1" "kind" "NodeList"
       "metadata" (core-object "resourceVersion"
                               (write-to-string (if (and requested (not (equal match "NotOlderThan")))
                                                    requested (pod-store-pod-revision store))))
       "items" (coerce (loop for node in (sort (loop for node being the hash-values of (pod-store-nodes store) collect node)
                                               #'string< :key #'node-record-name)
                             for view = (node-api-object node)
                             when (funcall matches view) collect view)
                       'vector)))))

(defun node-watch-events (store labels fields revision)
  "Read matching events after REVISION, oldest first, with the current watermark."
  ;; Commits replace the journal's head in one word, so an idle watch can skip the lock.
  ;; REVISION stays put: the counter can pass an event that is not yet in the journal.
  (let ((newest (first (pod-store-node-watch-journal store))))
    (when (or (null newest) (<= (first newest) revision))
      (return-from node-watch-events (values nil revision))))
  (let ((matches (node-selection-predicate labels fields)))
    (with-store-lock (store)
      (check-node-watch-revision-unlocked store revision)
      (values (revision-journal-events (pod-store-node-watch-journal store) revision matches)
              (pod-store-pod-revision store)))))

(defun node-watch-response (store)
  "Serve a Kubernetes JSON watch stream for Nodes."
  (podtemplate-watch-response
   store nil "nodes"
   :page-reader (lambda (labels fields resource-version match)
                  (node-list-page store labels fields resource-version match))
   :event-reader (lambda (labels fields revision)
                   (node-watch-events store labels fields revision))
   :bookmark-kind "Node" :bookmark-api-version "v1"))

(defun delete-node-collection-response (store)
  "Delete the selected API-registered Nodes, or none if an agent's Node is among them."
  (let* ((labels (or (hunchentoot:parameter "labelSelector") ""))
         (fields (or (hunchentoot:parameter "fieldSelector") ""))
         (matches (node-selection-predicate labels fields))
         (dry-run (core-resource-dry-run-p)))
    (json-response
     (with-store-lock (store)
       (let* ((selected (remove-if-not (lambda (node) (funcall matches (node-api-object node)))
                                       (sort (loop for node being the hash-values of (pod-store-nodes store) collect node)
                                             #'string< :key #'node-record-name)))
              (views (mapcar #'node-api-object selected)))
         (dolist (node selected)
           (unless (node-record-api-only node)
             (core-resource-error 409 "Conflict" "Node ~A is registered by its agent and cannot be deleted through the API"
                                  (node-record-name node))))
         (unless dry-run
           (dolist (node selected) (remove-node-unlocked store node)))
         (core-object "apiVersion" "v1" "kind" "NodeList"
                      "metadata" (core-object "resourceVersion" (write-to-string (pod-store-pod-revision store)))
                      "items" (coerce views 'vector)))))))
