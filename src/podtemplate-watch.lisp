;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Stream stored resource watch events from durable mutations, with revision
;;;; resumption, selector transitions, initial-event bookmarks and bounded
;;;; timeouts. Never hold the storage lock while writing to a slow client.

(in-package #:gr8s)

(defun template-watch-events (store namespace labels fields revision &key (resource "podtemplates"))
  "Read matching journal events after REVISION and the current storage watermark."
  (let ((label-test (core-selector-predicate labels)) (field-test (core-selector-predicate fields :fields t :field-paths (core-resource-field-paths resource))))
    (labels ((matches (object)
               (and (hash-table-p object)
                    (or (null namespace) (equal namespace (gethash "namespace" (gethash "metadata" object))))
                    (funcall label-test object) (funcall field-test object))))
      (with-store-lock (store)
        (compact-template-history-unlocked store)
        (template-index-at-revision-unlocked store revision resource)
        (values
         (loop for entry in (pod-store-template-history store)
               when (and (equal resource (gethash "resource" entry "podtemplates"))
                         (> (gethash "revision" entry) revision))
                 append (let* ((old (gethash "old" entry)) (new (gethash "new" entry))
                               (before (matches old)) (after (matches new)))
                          (when (or before after)
                            (let ((object (copy-core-object (if after new old))))
                              (setf (gethash "resourceVersion" (gethash "metadata" object)) (write-to-string (gethash "revision" entry)))
                              (list (core-object "type" (cond ((and before after) "MODIFIED") (after "ADDED") (t "DELETED")) "object" object))))))
         (pod-store-resource-revision store))))))

(defun podtemplate-watch-response (store namespace &optional (resource "podtemplates"))
  "Serve a real Kubernetes JSON watch stream for a durable resource collection."
  (let* ((rv-text (or (hunchentoot:parameter "resourceVersion") ""))
         (initial (or (equal rv-text "0") (true-parameter-p (hunchentoot:parameter "sendInitialEvents"))))
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
    (multiple-value-bind (page code) (template-list-page store namespace labels fields :resource-version rv-text :match match :resource resource)
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
                                  (concatenate 'string (com.inuoe.jzon:stringify (event-api-view event)) (string #\Newline))) out)
                 (finish-output out))
               (bookmark (&optional initial-end)
                 (let ((metadata (core-object "resourceVersion" (write-to-string revision))))
                   (when initial-end (setf (gethash "annotations" metadata) (core-object "k8s.io/initial-events-end" "true")))
                   (emit (core-object "type" "BOOKMARK" "object" (core-object "apiVersion" (core-resource-api-version resource) "kind" (core-resource-kind resource) "metadata" metadata))))))
        (handler-case
            (progn
              (dolist (event first-events) (emit event))
              (when (true-parameter-p (hunchentoot:parameter "sendInitialEvents")) (bookmark t))
              ;; Flush headers even for an initially empty watch.
              (finish-output out)
              (loop while (< (get-internal-real-time) deadline)
                    do (multiple-value-bind (events watermark) (template-watch-events store namespace labels fields revision :resource resource)
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
