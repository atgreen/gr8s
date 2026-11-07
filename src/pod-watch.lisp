;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Give Pods one monotonic revision and a bounded event journal covering spec
;;;; writes, scheduling, deletion and observed status. Status-only revisions are
;;;; shown to clients but never replace the desired revision agents acknowledge.
;;;; The journal is memory-only: resuming from before it ends the watch with a 410
;;;; Gone event, which Kubernetes clients answer by relisting.

(in-package #:gr8s)

(defparameter *pod-watch-journal-limit* 16384
  "The most Pod events kept for resuming watches, however recent.
Each holds two views of a Pod that nothing else does, which is what this limit bounds.")

(defparameter +pod-watch-journal-minimum+ 4096
  "Keep this many Pod events however old, for a cluster too quiet to fill the time window.")

(defparameter *pod-watch-journal-bytes* (* 96 1024 1024)
  "The most memory, by APPROXIMATE-HEAP-BYTES, that the Pod events may hold in all.
This wins over the count and the time window, which a burst of status changes could
otherwise fill with tens of kilobytes an event.")

(defparameter +revision-journal-trim-interval+ 1024
  "Events between looks for what has aged out of a journal, since each look walks it.")

(defun pod-revision-ceiling-path (store)
  "Return STORE's durable revision ceiling.
It needs a file type, since atomic renames merge a missing one from the temporary file."
  (merge-pathnames "pod-revision.ceiling" (pod-store-path store)))

(defun load-pod-revision (store)
  "Resume above every revision that could have been issued before the last shutdown."
  (let* ((path (pod-revision-ceiling-path store))
         (ceiling (if (probe-file path) (parse-integer (uiop:read-file-string path)) 0))
         (revision (reduce #'max (append
                                  (loop for pod being the hash-values of (pod-store-pods store)
                                        collect (parse-integer (pod-resource-version pod)))
                                  (loop for node being the hash-values of (pod-store-nodes store)
                                        collect (parse-integer (node-record-resource-version node))))
                           :initial-value ceiling)))
    (setf (pod-store-pod-revision store) revision
          (pod-store-pod-revision-ceiling store) revision
          (pod-store-pod-watch-floor store) revision
          (pod-store-node-watch-floor store) revision)
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

(defun trim-revision-journal (journal length bytes limit minimum byte-limit)
  "Return the newest of JOURNAL's LENGTH entries still worth keeping, their count, floor and bytes.
That is at most LIMIT entries and BYTE-LIMIT bytes, and otherwise MINIMUM (or LIMIT, if lower)
however old and the rest of the watch history window. Each entry is (revision old new time bytes).
Once over BYTE-LIMIT it keeps an eighth less, so a full journal is not walked for every event.
Returns NIL when nothing is due to go."
  (when (or (> length (* 2 limit)) (> bytes byte-limit)
            (zerop (mod length +revision-journal-trim-interval+)))
    (let* ((minimum (min minimum limit))
           (budget (if (> bytes byte-limit) (- byte-limit (floor byte-limit 8)) byte-limit))
           (now (funcall *podtemplate-clock*))
           (kept 0)
           (keep (or (loop for (nil nil nil time size) in journal
                           for count from 0
                           when (or (>= count limit)
                                    ;; Always keep the newest, so the floor is one an event follows.
                                    (and (plusp count) (> (+ kept size) budget))
                                    (and (>= count minimum) (> (- now time) *watch-history-seconds*)))
                             return count
                           do (incf kept size))
                     length)))
      (when (< keep length)
        (let ((retained (subseq journal 0 keep)))
          ;; The oldest retained event must stay readable, so resume just before it.
          (values retained keep (1- (first (car (last retained)))) kept))))))

(defun record-revision-journal-event (journal revision old new previous)
  "Return JOURNAL with a transition from OLD to NEW at REVISION, newest first.
The entry's fifth element is the memory it adds. PREVIOUS is the view the last event for
this object ended with: when OLD still equals it, the event shares it, not a second copy."
  (let ((shared (and old previous (core-json-equal-p old previous))))
    (cons (list revision (if shared previous old) new (funcall *podtemplate-clock*)
                (+ 64 (if (or shared (not (hash-table-p old))) 0 (approximate-heap-bytes old))
                   (if (hash-table-p new) (approximate-heap-bytes new) 0)))
          journal)))

(defun pod-watch-view-uid (view)
  "Return the UID of the Pod API VIEW, or NIL."
  (and (hash-table-p view) (gethash "uid" (gethash "metadata" view))))

(defun record-pod-watch-event-unlocked (store revision old new)
  "Append one transition to the journal, compacting what has fallen out of its retention.
A store without a journal only moves its floor, so a watch of it fails rather than misses events."
  (unless (pod-store-watch-journal-p store)
    (setf (pod-store-pod-watch-floor store) revision)
    (return-from record-pod-watch-event-unlocked nil))
  (let* ((uid (or (pod-watch-view-uid new) (pod-watch-view-uid old)))
         (views (pod-store-pod-watch-views store))
         (journal (record-revision-journal-event (pod-store-pod-watch-journal store) revision old new
                                                 (and uid (gethash uid views)))))
    (setf (pod-store-pod-watch-journal store) journal)
    (when uid
      (if new (setf (gethash uid views) new) (remhash uid views)))
    (multiple-value-bind (retained length floor bytes)
        (trim-revision-journal journal
                               (incf (pod-store-pod-watch-journal-length store))
                               (incf (pod-store-pod-watch-journal-bytes store) (fifth (first journal)))
                               *pod-watch-journal-limit* +pod-watch-journal-minimum+
                               *pod-watch-journal-bytes*)
      (when retained
        (setf (pod-store-pod-watch-floor store) floor
              (pod-store-pod-watch-journal store) retained
              (pod-store-pod-watch-journal-length store) length
              (pod-store-pod-watch-journal-bytes store) bytes)))))

(defun publish-pod-spec-change-unlocked (store old pod)
  "Journal POD at its current revision; OLD is its prior API view, or NIL when created."
  (record-pod-watch-event-unlocked store (parse-integer (pod-resource-version pod))
                                   old (and (pod-store-watch-journal-p store) (pod-published-view store pod))))

(defun publish-pod-status-unlocked (store pod status)
  "Journal STATUS when it differs from what clients last saw for the current Pod."
  (let ((current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store)))
        (uid (pod-uid pod)))
    (when (and current (equal uid (pod-uid current))
               (not (equalp status (gethash uid (pod-store-pod-published-statuses store)))))
      (let ((old (and (pod-store-watch-journal-p store) (pod-published-view store current)))
            (revision (next-pod-revision-unlocked store)))
        (setf (gethash uid (pod-store-pod-published-statuses store)) (copy-pod-status-value status)
              (pod-status-revision current) revision)
        (record-pod-watch-event-unlocked store revision old
                                         (and old (pod-published-view store current)))))))

(defun publish-pod-removal-unlocked (store pod)
  "Journal POD's final API view as a deletion at a fresh revision."
  (let ((old (and (pod-store-watch-journal-p store) (pod-published-view store pod))))
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

(defun revision-journal-events (journal revision matches)
  "Turn JOURNAL's entries after REVISION into watch events, oldest first.
Selector transitions become ADDED and DELETED, as if the object entered or left a set."
  (let ((events nil))
    (loop for (entry-revision old new) in journal
          while (> entry-revision revision)
          do (let ((before (funcall matches old)) (after (funcall matches new)))
               (when (or before after)
                 (let ((object (copy-core-object (if after new old))))
                   (setf (gethash "resourceVersion" (gethash "metadata" object))
                         (write-to-string entry-revision))
                   (push (core-object "type" (cond ((and before after) "MODIFIED") (after "ADDED") (t "DELETED"))
                                      "object" object)
                         events)))))
    events))

(defun pod-watch-events (store namespace labels fields revision)
  "Read matching events after REVISION, oldest first, with the current watermark."
  (let ((matches (pod-watch-predicate namespace labels fields)))
    (with-store-lock (store)
      (check-pod-watch-revision-unlocked store revision)
      (values (revision-journal-events (pod-store-pod-watch-journal store) revision matches)
              (pod-store-pod-revision store)))))

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
