;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Stream stored resource watch events from durable mutations, with revision
;;;; resumption, selector transitions, initial-event bookmarks and bounded
;;;; timeouts. Never hold the storage lock while writing to a slow client.

(in-package #:gr8s)

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
                                     (bookmark-api-version (and (null page-reader) (core-resource-api-version resource))))
  "Serve a real Kubernetes JSON watch stream for a resource collection.
PAGE-READER and EVENT-READER replace the durable journal for separately stored resources."
  (let* ((rv-text (or (hunchentoot:parameter "resourceVersion") ""))
         (initial (or (member rv-text '("" "0") :test #'equal) (true-parameter-p (hunchentoot:parameter "sendInitialEvents"))))
         (labels (or (hunchentoot:parameter "labelSelector") ""))
         (fields (or (hunchentoot:parameter "fieldSelector") ""))
         (match (hunchentoot:parameter "resourceVersionMatch"))
         (timeout-text (hunchentoot:parameter "timeoutSeconds"))
         (timeout (if timeout-text (ignore-errors (parse-integer timeout-text :junk-allowed nil)) 300))
         (revision nil) (first-events nil))
    (unless (and timeout (<= 1 timeout 3600)) (core-resource-error 400 "BadRequest" "timeoutSeconds must be 1..3600"))
    (unless (or (equal rv-text "") (and (plusp (length rv-text)) (every #'digit-char-p rv-text)))
      (core-resource-error 400 "BadRequest" "Invalid resourceVersion"))
    (unless (member match '(nil "" "NotOlderThan") :test #'equal) (core-resource-error 400 "BadRequest" "Unsupported watch resourceVersionMatch"))
    (when (and (true-parameter-p (hunchentoot:parameter "sendInitialEvents")) (not (equal match "NotOlderThan")))
      (core-resource-error 400 "BadRequest" "sendInitialEvents requires NotOlderThan"))
    (multiple-value-bind (page code)
        (if page-reader
            (funcall page-reader labels fields rv-text match)
            (template-list-page store namespace labels fields :resource-version rv-text :match match :resource resource))
      (declare (ignore code))
      (setf revision (parse-integer (gethash "resourceVersion" (gethash "metadata" page))))
      (when initial
        (setf first-events (loop for object across (gethash "items" page) collect (core-object "type" "ADDED" "object" object)))))
    (setf (hunchentoot:content-type*) "application/json"
          (hunchentoot:header-out :cache-control) "no-cache")
    (let* ((out (hunchentoot:send-headers))
           (deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second)))
           (last-bookmark (get-internal-real-time)))
      (labels ((emit (event)
                 (write-sequence (trivial-utf-8:string-to-utf-8-bytes
                                  (concatenate 'string (com.inuoe.jzon:stringify (crd-api-view (event-api-view event))) (string #\Newline))) out)
                 (finish-output out))
               (bookmark (&optional initial-end)
                 (let ((metadata (core-object "resourceVersion" (write-to-string revision))))
                   (when initial-end (setf (gethash "annotations" metadata) (core-object "k8s.io/initial-events-end" "true")))
                   (emit (core-object "type" "BOOKMARK" "object" (core-object "apiVersion" bookmark-api-version "kind" bookmark-kind "metadata" metadata))))))
        (handler-case
            (progn
              (dolist (event first-events) (emit event))
              (when (true-parameter-p (hunchentoot:parameter "sendInitialEvents")) (bookmark t))
              ;; Flush headers even for an initially empty watch.
              (finish-output out)
              (loop while (< (get-internal-real-time) deadline)
                    do (when (and *crd-view-definition*
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
                       (sleep .05)))
          (kubernetes-error (condition)
            (ignore-errors (emit (core-object "type" "ERROR" "object"
                                  (core-object "apiVersion" "v1" "kind" "Status" "status" "Failure"
                                               "code" (kubernetes-error-status-code condition)
                                               "reason" (kubernetes-error-reason condition) "message" (kubernetes-error-message condition))))))
          (stream-error () nil)
          (usocket:socket-error () nil))))
    nil))
