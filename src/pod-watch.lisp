;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Give Pods one monotonic revision and a bounded event journal covering spec
;;;; writes, scheduling, deletion and observed status. Status-only revisions are
;;;; shown to clients but never replace the desired revision agents acknowledge.
;;;; The journal is memory-only: resuming from before it returns 410 Gone, which
;;;; Kubernetes clients answer by relisting.

(in-package #:gr8s)

(defparameter *pod-watch-journal-limit* 4096
  "Retain at least this many recent Pod events for resuming watches.")

(defparameter *pod-revision-reservation* 1024
  "Durably reserve this many revisions at once, so restarts never reuse a number.")

(defun pod-revision-ceiling-path (store)
  "Return STORE's durable revision ceiling.
It needs a file type, since atomic renames merge a missing one from the temporary file."
  (merge-pathnames "pod-revision.ceiling" (pod-store-path store)))

(defun load-pod-revision (store)
  "Resume above every revision that could have been issued before the last shutdown."
  (let* ((path (pod-revision-ceiling-path store))
         (ceiling (if (probe-file path) (parse-integer (uiop:read-file-string path)) 0))
         (revision (reduce #'max (loop for pod being the hash-values of (pod-store-pods store)
                                       collect (parse-integer (pod-resource-version pod)))
                           :initial-value ceiling)))
    (setf (pod-store-pod-revision store) revision
          (pod-store-pod-revision-ceiling store) revision
          (pod-store-pod-watch-floor store) revision)
    store))

(defun next-pod-revision-unlocked (store)
  "Allocate the next revision, durably reserving a new block before first use."
  (let ((next (1+ (pod-store-pod-revision store))))
    (when (> next (pod-store-pod-revision-ceiling store))
      (let ((ceiling (+ next *pod-revision-reservation*)))
        (write-private-text-atomically (pod-revision-ceiling-path store) (write-to-string ceiling))
        (setf (pod-store-pod-revision-ceiling store) ceiling)))
    (setf (pod-store-pod-revision store) next)))

(defun pod-revision-satisfied-p (store expected actual)
  "Accept EXPECTED when it was issued at or after ACTUAL, the Pod's last spec write.
Status-only revisions are newer than that write but do not make a client's spec stale."
  (or (equal expected actual)
      (let ((number (and (stringp expected) (plusp (length expected))
                         (every #'digit-char-p expected) (parse-integer expected))))
        (and number (>= number (parse-integer actual))
             (<= number (pod-store-pod-revision store))))))

(defun pod-selector-field-paths ()
  "Return the Pod fields clients may name in field selectors."
  '("metadata.name" "metadata.namespace" "spec.nodeName" "spec.serviceAccountName"
    "spec.restartPolicy" "status.phase" "status.podIP"))

(defun pod-published-view (store pod)
  "Return POD's API object using its last published status."
  (pod-response-object pod (or (gethash (pod-uid pod) (pod-store-pod-published-statuses store))
                               (pod-status "Pending"))))

(defun record-pod-watch-event-unlocked (store revision old new)
  "Append one transition to the journal, compacting once it doubles its retention."
  (push (list revision old new) (pod-store-pod-watch-journal store))
  (when (> (incf (pod-store-pod-watch-journal-length store)) (* 2 *pod-watch-journal-limit*))
    (let* ((retained (subseq (pod-store-pod-watch-journal store) 0 *pod-watch-journal-limit*)))
      ;; The oldest retained event must stay readable, so resume just before it.
      (setf (pod-store-pod-watch-floor store) (1- (first (car (last retained))))
            (pod-store-pod-watch-journal store) retained
            (pod-store-pod-watch-journal-length store) *pod-watch-journal-limit*))))

(defun publish-pod-spec-change-unlocked (store old pod)
  "Journal POD at its current revision; OLD is its prior API view, or NIL when created."
  (record-pod-watch-event-unlocked store (parse-integer (pod-resource-version pod))
                                   old (pod-published-view store pod)))

(defun publish-pod-status-unlocked (store pod status)
  "Journal STATUS when it differs from what clients last saw for the current Pod."
  (let ((current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store)))
        (uid (pod-uid pod)))
    (when (and current (equal uid (pod-uid current))
               (not (equalp status (gethash uid (pod-store-pod-published-statuses store)))))
      (let ((old (pod-published-view store current))
            (revision (next-pod-revision-unlocked store)))
        (setf (gethash uid (pod-store-pod-published-statuses store)) (copy-pod-status-value status)
              (pod-status-revision current) revision)
        (record-pod-watch-event-unlocked store revision old (pod-published-view store current))))))

(defun publish-pod-removal-unlocked (store pod)
  "Journal POD's final API view as a deletion at a fresh revision."
  (let ((old (pod-published-view store pod)))
    (record-pod-watch-event-unlocked store (next-pod-revision-unlocked store) old nil)
    (remhash (pod-uid pod) (pod-store-pod-published-statuses store))))

(defun check-pod-watch-revision-unlocked (store revision)
  "Reject REVISION when its later events are gone or have not yet been issued."
  (when (< revision (pod-store-pod-watch-floor store))
    (core-resource-error 410 "Expired" "too old resource version: ~D (~D)"
                         revision (pod-store-pod-watch-floor store)))
  (when (> revision (pod-store-pod-revision store))
    (core-resource-error 504 "Timeout" "Requested resourceVersion is newer than storage")))

(defun pod-watch-predicate (namespace labels fields)
  "Return a test for API views in NAMESPACE matching the LABELS and FIELDS selectors."
  (let ((label-test (core-selector-predicate labels))
        (field-test (core-selector-predicate fields :fields t :field-paths (pod-selector-field-paths))))
    (lambda (object)
      (and (hash-table-p object)
           (or (null namespace) (equal namespace (gethash "namespace" (gethash "metadata" object))))
           (funcall label-test object) (funcall field-test object)))))

(defun pod-watch-events (store namespace labels fields revision)
  "Read matching events after REVISION, oldest first, with the current watermark.
Selector transitions become ADDED and DELETED, as if the object entered or left a set."
  (let ((matches (pod-watch-predicate namespace labels fields)))
    (with-store-lock (store)
      (check-pod-watch-revision-unlocked store revision)
      (let ((events nil))
        (loop for (entry-revision old new) in (pod-store-pod-watch-journal store)
              while (> entry-revision revision)
              do (let ((before (funcall matches old)) (after (funcall matches new)))
                   (when (or before after)
                     (let ((object (copy-core-object (if after new old))))
                       (setf (gethash "resourceVersion" (gethash "metadata" object))
                             (write-to-string entry-revision))
                       (push (core-object "type" (cond ((and before after) "MODIFIED") (after "ADDED") (t "DELETED"))
                                          "object" object)
                             events)))))
        (values events (pod-store-pod-revision store))))))

(defun pod-watch-page (store namespace labels fields resource-version match)
  "Return the start revision and current API views for a new Pod watch."
  (let ((matches (pod-watch-predicate namespace labels fields))
        (requested (unless (member resource-version '(nil "" "0") :test #'equal)
                     (parse-integer resource-version))))
    (with-store-lock (store)
      (when requested (check-pod-watch-revision-unlocked store requested))
      (core-object
       "metadata" (core-object "resourceVersion"
                               (write-to-string (if (and requested (not (equal match "NotOlderThan")))
                                                    requested (pod-store-pod-revision store))))
       "items" (coerce (loop for pod being the hash-values of (pod-store-pods store)
                             for view = (pod-published-view store pod)
                             when (funcall matches view) collect view) 'vector)))))

(defun pod-watch-response (store namespace)
  "Serve a Kubernetes JSON watch stream for Pods in NAMESPACE, or all when NIL."
  (podtemplate-watch-response
   store namespace "pods"
   :page-reader (lambda (labels fields resource-version match)
                  (pod-watch-page store namespace labels fields resource-version match))
   :event-reader (lambda (labels fields revision)
                   (pod-watch-events store namespace labels fields revision))
   :bookmark-kind "Pod" :bookmark-api-version "v1"))
