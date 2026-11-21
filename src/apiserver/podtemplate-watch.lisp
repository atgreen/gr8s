;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Stream stored resource watch events from durable mutations, with revision
;;;; resumption, selector transitions, initial-event bookmarks and bounded
;;;; timeouts. Never hold the storage lock while writing to a slow client.

(in-package #:gr8s.apiserver)

(defun check-watch-store-access (store)
  "Let whatever has closed STORE have it. A checkpoint closes the store for a
moment and changes nothing a watch has read: the watch gives its lease up, waits
for the store to open, and goes on. It used to end here whenever a checkpoint
found it between two sends, and its client listed everything again (podster-0o5).
A restore replaces what the watch has read, so the watch ends."
  (when (gr8s.store::store-access-blocked-p store)
    (flet ((expired ()
             (core-resource-error 410 "Expired" "Application restore requires a fresh list/watch")))
      ;; Taking the lease again waits a checkpoint out and is refused by a restore.
      (handler-case (gr8s.store::call-with-store-request-suspended (lambda () nil))
        (kubernetes-error () (expired)))
      ;; A watch that holds no lease has nothing to give up, and waits as long.
      (loop with deadline = (+ (get-internal-real-time)
                               (* gr8s.store::*store-quiesce-patience-seconds* internal-time-units-per-second))
            while (gr8s.store::store-access-blocked-p store)
            do (unless (and (gr8s.store::pod-store-access-block-brief-p store)
                            (< (get-internal-real-time) deadline))
                 (expired))
               (sleep .05)))))

(defun template-watch-events (store namespace labels fields revision &key (resource "podtemplates"))
  "Read matching journal events after REVISION and the current storage watermark."
  (let ((label-test (core-selector-predicate labels)) (field-test (crd-field-selector-test resource fields)))
    (labels ((matches (object)
               (and (hash-table-p object)
                    (or (null namespace) (equal namespace (gethash "namespace" (gethash "metadata" object))))
                    (funcall label-test object) (funcall field-test object))))
      (template-watch-maintenance store)
      ;; Commits replace the revision in one word, so an idle watch can skip the
      ;; lock that every writer needs; a hundred such watches poll twenty times a second.
      (when (eql revision (pod-store-resource-revision store))
        (return-from template-watch-events (values nil revision)))
      (multiple-value-bind (entries watermark)
          (with-store-lock (store)
            (check-template-revision-unlocked store revision resource)
            (values (template-history-after store revision) (pod-store-resource-revision store)))
        (values
         (loop for entry in entries
               when (equal resource (gethash "resource" entry "podtemplates"))
                 append (let* ((old (gethash "old" entry)) (new (gethash "new" entry))
                               (before (matches old)) (after (matches new)))
                          (when (or before after)
                            (let ((object (copy-core-object (if after new old))))
                              (setf (gethash "resourceVersion" (gethash "metadata" object)) (write-to-string (gethash "revision" entry)))
                              (list (core-object "type" (cond ((and before after) "MODIFIED") (after "ADDED") (t "DELETED")) "object" object))))))
         watermark)))))

(defun template-watch-maintenance (store)
  "Let open watches expire Events and journal entries, at most once an interval."
  (let ((now (get-internal-real-time)))
    (when (>= (- now (pod-store-template-history-maintained-at store)) +template-watch-maintenance-interval+)
      (with-store-lock (store)
        (setf (pod-store-template-history-maintained-at store) now)
        (compact-template-history-unlocked store)))))

(defun podtemplate-watch-response (store namespace &optional (resource "podtemplates")
                                   &key page-reader event-reader
                                     (bookmark-kind (and (null page-reader) (core-resource-kind resource)))
                                     bookmark-api-version)
  "Serve a real Kubernetes JSON watch stream for a resource collection.
PAGE-READER and EVENT-READER replace the durable journal for separately stored resources."
  (let* ((*table-send-columns* t)
         (rv-text (or (hunchentoot:parameter "resourceVersion") ""))
         (send-initial-text (hunchentoot:parameter "sendInitialEvents"))
         (send-initial (true-parameter-p send-initial-text))
         (initial (if send-initial-text send-initial (member rv-text '("" "0") :test #'equal)))
         (labels (or (hunchentoot:parameter "labelSelector") ""))
         (fields (or (hunchentoot:parameter "fieldSelector") ""))
         (match (hunchentoot:parameter "resourceVersionMatch"))
         (timeout-text (hunchentoot:parameter "timeoutSeconds"))
         (timeout (if timeout-text (ignore-errors (parse-integer timeout-text :junk-allowed nil)) 300))
         (revision nil) (first-events nil) (expired nil))
    (unless (and timeout (<= 1 timeout 3600)) (core-resource-error 400 "BadRequest" "timeoutSeconds must be 1..3600"))
    (unless (or (equal rv-text "") (and (plusp (length rv-text)) (every #'digit-char-p rv-text)))
      (core-resource-error 400 "BadRequest" "Invalid resourceVersion"))
    (unless (member match '(nil "" "NotOlderThan") :test #'equal) (core-resource-error 400 "BadRequest" "Unsupported watch resourceVersionMatch"))
    ;; The same rules as upstream's validateWatchOptions, for what a WatchList client sends.
    (when (and send-initial-text (not (equal match "NotOlderThan")))
      (core-resource-error 400 "BadRequest" "sendInitialEvents requires setting resourceVersionMatch to NotOlderThan"))
    (when (and (member match '("NotOlderThan") :test #'equal) (not send-initial-text))
      (core-resource-error 400 "BadRequest" "resourceVersionMatch is forbidden for watch unless sendInitialEvents is provided"))
    ;; Initial events start from a state at least this new; without them, the watch
    ;; starts exactly at the revision given. No revision at all means the latest either way.
    ;; Too old a revision ends an established watch with an ERROR event, as upstream's
    ;; does. RetryWatcher gives up on that one, but retries a failed request every second.
    (handler-case
        (multiple-value-bind (page code)
            (let ((match (and initial (not (equal rv-text "")) match)))
              (if page-reader
                  (funcall page-reader labels fields rv-text match)
                  (template-list-page store namespace labels fields :resource-version rv-text :match match :resource resource)))
          (declare (ignore code))
          (setf revision (parse-integer (gethash "resourceVersion" (gethash "metadata" page))))
          (when initial
            (setf first-events (loop for object across (gethash "items" page) collect (core-object "type" "ADDED" "object" object)))))
      (kubernetes-error (condition)
        (unless (= 410 (kubernetes-error-status-code condition)) (error condition))
        (setf expired condition)))
    (setf (hunchentoot:content-type*) "application/json"
          (hunchentoot:header-out :cache-control) "no-cache")
    (let* ((out (hunchentoot:send-headers))
           (json-out (flexi-streams:make-flexi-stream out :external-format :utf-8))
           ;; Events wait here, newest first, for SEND-PENDING: a watch neither
           ;; serializes nor writes to its client while it holds its store lease. A
           ;; checkpoint waits for every lease, and a watch inside a socket write
           ;; cannot notice one, so a slow client would hold the store closed for as
           ;; long as it took to read.
           (pending nil)
           (deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second)))
           (last-bookmark (get-internal-real-time)))
      (labels ((write-event (event)
                 (push event pending))
               (send-pending (&optional even-if-empty)
                 (when (or pending even-if-empty)
                   (let ((events (nreverse pending)))
                     (setf pending nil)
                     (gr8s.store::call-with-store-request-suspended
                      (lambda ()
                        (dolist (event events)
                          (com.inuoe.jzon:stringify event :stream json-out)
                          (write-char #\Newline json-out))
                        (finish-output json-out)
                        (finish-output out))))))
               (emit (event)
                 (let ((view (crd-api-view (event-api-view event))))
                   (when (and *table-request* (not (equal "ERROR" (gethash "type" view))))
                     (setf (gethash "object" view) (table-representation (gethash "object" view))
                           *table-send-columns* nil))
                   (write-event view)))
               (bookmark (&optional initial-end)
                 ;; Carries no object to project, so the views that rewrite one would only mangle it.
                 (let ((metadata (core-object "resourceVersion" (write-to-string revision))))
                   (when initial-end (setf (gethash "annotations" metadata) (core-object "k8s.io/initial-events-end" "true")))
                   (write-event
                    (core-object "type" "BOOKMARK"
                                 "object" (watch-bookmark-representation
                                           (core-object "apiVersion" (cond (bookmark-api-version)
                                                                           (*crd-view-definition*
                                                                            (format nil "~A/~A" (gethash "group" (gethash "spec" *crd-view-definition*))
                                                                                    *crd-request-version*))
                                                                           (t *core-resource-view-version*))
                                                        "kind" bookmark-kind "metadata" metadata)))))))
        (handler-case
            (progn
              (check-watch-store-access store)
              (when expired (error expired))
              (dolist (event first-events) (emit event))
              (setf first-events nil)
              ;; client-go waits for this bookmark before trusting its initial state.
              (when (and send-initial (true-parameter-p (hunchentoot:parameter "allowWatchBookmarks"))) (bookmark t))
              ;; Flush headers even for an initially empty watch.
              (send-pending t)
              (loop while (and (< (get-internal-real-time) deadline)
                               (not (api-watch-client-departed-p)))
                    do (check-watch-store-access store)
                       (when (and *crd-view-definition*
                                  (not (crd-watch-definition-current-p store *crd-view-definition* *crd-request-version*)))
                         (core-resource-error 410 "Expired" "Custom definition identity or served version has changed"))
                       (multiple-value-bind (events watermark)
                           (if event-reader
                               (funcall event-reader labels fields revision)
                               (template-watch-events store namespace labels fields revision :resource resource))
                         (dolist (event events) (emit event))
                         (setf revision watermark))
                       (when (and (true-parameter-p (hunchentoot:parameter "allowWatchBookmarks"))
                                  (> (- (get-internal-real-time) last-bookmark) (* 20 internal-time-units-per-second)))
                         (bookmark) (setf last-bookmark (get-internal-real-time)))
                       (send-pending)
                       (sleep .05)))
          (kubernetes-error (condition)
            ;; The watch is over and reads the store no more: give the lease up for
            ;; good, so that sending this last event does not wait to take it back.
            (gr8s.store::release-store-request)
            ;; A Status has no object to project, so the views would only mangle it.
            (ignore-errors (write-event (core-object "type" "ERROR" "object"
                                         (core-object "apiVersion" "v1" "kind" "Status" "metadata" (core-object) "status" "Failure"
                                                      "code" (kubernetes-error-status-code condition)
                                                      "reason" (kubernetes-error-reason condition) "message" (kubernetes-error-message condition))))
                           (send-pending)))
          (stream-error () nil)
          (usocket:socket-error () nil))))
    nil))
