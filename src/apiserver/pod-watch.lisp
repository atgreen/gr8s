;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Translate the store's bounded revision journal into Kubernetes ListWatch
;;;; pages and event streams, including namespace and selector filtering.

(in-package #:gr8s.apiserver)

(defun pod-selector-field-paths ()
  "Return the Pod fields clients may name in field selectors."
  '("metadata.name" "metadata.namespace" "spec.nodeName" "spec.serviceAccountName"
    "spec.restartPolicy" "status.phase" "status.podIP"))

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
        (field-test (core-selector-predicate fields :fields t
                                             :field-paths (pod-selector-field-paths))))
    (lambda (object)
      (and (hash-table-p object)
           (or (null namespace)
               (equal namespace
                      (gethash "namespace" (gethash "metadata" object))))
           (funcall label-test object)
           (funcall field-test object)))))

(defun revision-journal-events (journal revision matches)
  "Turn JOURNAL's entries after REVISION into watch events, oldest first.
Selector transitions become ADDED and DELETED, as if the object entered or left a set."
  (let ((events nil))
    (loop for (entry-revision old new) in journal
          while (> entry-revision revision)
          do (let ((before (funcall matches old))
                   (after (funcall matches new)))
               (when (or before after)
                 (let ((object (copy-core-object (if after new old))))
                   (setf (gethash "resourceVersion" (gethash "metadata" object))
                         (write-to-string entry-revision))
                   (push (core-object
                          "type" (cond ((and before after) "MODIFIED")
                                       (after "ADDED")
                                       (t "DELETED"))
                          "object" object)
                         events)))))
    events))

(defun pod-watch-events (store namespace labels fields revision)
  "Read matching events after REVISION, oldest first, with the current watermark."
  (let ((matches (pod-watch-predicate namespace labels fields)))
    (with-store-lock (store)
      (check-pod-watch-revision-unlocked store revision)
      (values (revision-journal-events
               (pod-store-pod-watch-journal store) revision matches)
              (pod-store-pod-revision store)))))

(defun pod-watch-page (store namespace labels fields resource-version match)
  "Return the start revision and current API views for a new Pod watch."
  (let ((matches (pod-watch-predicate namespace labels fields))
        (requested (unless (member resource-version '(nil "" "0") :test #'equal)
                     (parse-integer resource-version))))
    (with-store-lock (store)
      (when requested
        (check-pod-watch-revision-unlocked store requested))
      (core-object
       "metadata"
       (core-object
        "resourceVersion"
        (write-to-string
         (if (and requested (not (equal match "NotOlderThan")))
             requested
             (pod-store-pod-revision store))))
       "items"
       (coerce
        (loop for pod being the hash-values of (pod-store-pods store)
              for view = (pod-published-view store pod)
              when (funcall matches view)
                collect view)
        'vector)))))

(defun pod-watch-response (store namespace)
  "Serve a Kubernetes JSON watch stream for Pods in NAMESPACE, or all when NIL."
  (podtemplate-watch-response
   store namespace "pods"
   :page-reader (lambda (labels fields resource-version match)
                  (pod-watch-page store namespace labels fields
                                  resource-version match))
   :event-reader (lambda (labels fields revision)
                   (pod-watch-events store namespace labels fields revision))
   :bookmark-kind "Pod"
   :bookmark-api-version "v1"))
