;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Apply genuine namespace and owner-UID garbage collection to custom objects.
;;;; Owner lookup recognizes declared non-storage versions while keeping unknown
;;;; external kinds unresolved rather than guessing that their owners are absent.

(in-package #:gr8s)

(defun crd-referenced-owner-state (store namespace owner)
  "Resolve an exact custom owner UID across any declared version, or return NIL."
  (unless (let* ((version (gethash "apiVersion" owner "")) (separator (position #\/ version)))
            (and separator (find #\. version :end separator)))
    (return-from crd-referenced-owner-state nil))
  (with-store-lock (store)
    (loop for key being the hash-keys of (pod-store-resources store) using (hash-value definition)
          when (equal "customresourcedefinitions" (first key))
            do (let* ((spec (gethash "spec" definition)) (names (gethash "names" spec))
                      (prefix (concatenate 'string (gethash "group" spec) "/"))
                      (version (gethash "apiVersion" owner "")))
                 (when (and (equal (gethash "kind" owner) (gethash "kind" names))
                            (uiop:string-prefix-p prefix version)
                            (crd-version definition (subseq version (length prefix))))
                   (let* ((namespace (and (equal "Namespaced" (gethash "scope" spec)) namespace))
                          (object (gethash (core-resource-key (crd-custom-key definition) namespace (gethash "name" owner))
                                           (pod-store-resources store))))
                     (return (if (and object (equal (gethash "uid" owner) (gethash "uid" (gethash "metadata" object)))) :live :absent))))))))

(defun collect-orphaned-custom-resources (store)
  "Collect actual custom dependents using the same namespace/owner rules as core APIs."
  (let* ((types (crd-resource-types store)) (*stored-resource-types* (append *stored-resource-types* types)))
    (dolist (descriptor types)
      (let ((resource (first descriptor)))
        (dolist (object (list-core-resources store resource))
          (drop-dangling-owner-references store resource object)
          (when (api-object-orphaned-p store object)
            (let ((metadata (gethash "metadata" object)))
              (handler-case
                  (when (controller-delete-allowed-p store resource (gethash "namespace" metadata) (gethash "name" metadata)
                                                     "generic-garbage-collector")
                    (delete-core-resource store resource (gethash "namespace" metadata) (gethash "name" metadata) :uid (gethash "uid" metadata)))
                (kubernetes-error (condition)
                  (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))))))))
