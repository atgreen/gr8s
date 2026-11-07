;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Expose genuine CRD status writes without inventing establishment or storage
;;;; migration. Stored versions can be removed only after all actual instances
;;;; have left that version; route identity and desired schemas remain unchanged.

(in-package #:gr8s.apiserver)

(defun crd-server-condition-p (condition)
  "Identify conditions that describe actual installed routes or cleanup work."
  (member (gethash "type" condition) '("NamesAccepted" "Established" "Terminating") :test #'equal))

(defun validate-crd-status-write (store existing input)
  "Validate a status projection against actual schema installation and stored data."
  (let* ((status (copy-core-object (require-object input "status")))
         (old (gethash "status" existing)) (names (gethash "names" (gethash "spec" existing)))
         (storage-version (gethash "name" (crd-storage-version existing)))
         (resource (crd-custom-key existing)))
    (reject-unsupported-fields status '("acceptedNames" "conditions" "storedVersions") "CRD status")
    (when (and (gethash "acceptedNames" status) (not (crd-json-equal-p names (gethash "acceptedNames" status))))
      (crd-schema-error "status.acceptedNames" "cannot contradict established route names"))
    (setf (gethash "acceptedNames" status) (copy-core-object names))
    (unless (gethash "storedVersions" status) (setf (gethash "storedVersions" status) (copy-core-object (gethash "storedVersions" old))))
    (crd-check-string-array (gethash "storedVersions" status) "status.storedVersions" :nonempty t)
    (unless (find storage-version (gethash "storedVersions" status) :test #'equal)
      (crd-schema-error "status.storedVersions" "must include the current storage version"))
    (loop for version across (gethash "storedVersions" status)
          unless (crd-version existing version) do (crd-schema-error "status.storedVersions" "version is not declared"))
    (maphash (lambda (key object)
               (when (equal resource (first key))
                 (let ((version (car (last (uiop:split-string (gethash "apiVersion" object) :separator '(#\/))))))
                   (unless (find version (gethash "storedVersions" status) :test #'equal)
                     (crd-schema-error "status.storedVersions" "actual instances still use version ~A" version))))) (pod-store-resources store))
    (let ((conditions (gethash "conditions" status #())) (result nil))
      (unless (crd-array-p conditions) (crd-schema-error "status.conditions" "requires an array"))
      (loop for condition across conditions
            for type = (gethash "type" (require-object condition "condition") "")
            do (unless (or (stringp type) (eq type 'null)) (crd-schema-error "status.conditions" "condition type must be a string"))
               (reject-unsupported-fields condition '("type" "status" "reason" "message" "lastTransitionTime") "CRD condition")
               (unless (or (stringp (gethash "status" condition "")) (eq 'null (gethash "status" condition)))
                 (crd-schema-error "status.conditions" "condition status must be a string"))
               (dolist (field '("reason" "message"))
                 (when (gethash field condition) (unless (stringp (gethash field condition)) (crd-schema-error "status.conditions" "condition text must be a string"))))
               (when (gethash "lastTransitionTime" condition) (normalize-event-time (gethash "lastTransitionTime" condition)))
               (if (crd-server-condition-p condition)
                   (unless (find condition (gethash "conditions" old) :test #'crd-json-equal-p)
                     (crd-schema-error "status.conditions" "server conditions must reflect actual route/cleanup state"))
                   (push condition result)))
      (setf (gethash "conditions" status)
            (concatenate 'vector (remove-if-not #'crd-server-condition-p (gethash "conditions" old)) (coerce (nreverse result) 'vector))))
    status))

(defun write-crd-status (store name input dry-run)
  "Write only validated status after exact optimistic identity checks."
  (let ((metadata (require-object (gethash "metadata" input) "metadata")))
    (unless (and (equal +crd-api-version+ (gethash "apiVersion" input +crd-api-version+))
                 (equal "CustomResourceDefinition" (gethash "kind" input "CustomResourceDefinition")))
      (core-resource-error 400 "BadRequest" "Expected CRD status representation"))
    (when (and (gethash "name" metadata) (not (equal name (gethash "name" metadata)))) (core-resource-error 400 "BadRequest" "metadata.name differs from request"))
    (when (not (member (gethash "namespace" metadata) '(nil null "") :test #'equal)) (core-resource-error 400 "BadRequest" "CRD status is cluster scoped"))
    (with-store-lock (store)
      (let* ((existing (get-core-resource-unlocked store "customresourcedefinitions" nil name))
             (old-meta (gethash "metadata" existing)) (index (copy-core-resource-index store))
             (revision (1+ (pod-store-resource-revision store))) (copy (copy-core-object existing)))
        (unless (and (equal (gethash "resourceVersion" metadata) (gethash "resourceVersion" old-meta))
                     (or (not (gethash "uid" metadata)) (equal (gethash "uid" metadata) (gethash "uid" old-meta))))
          (core-resource-error 409 "Conflict" "CRD status resource version or UID has changed"))
        (setf (gethash "status" copy) (validate-crd-status-write store existing (gethash "status" input)))
        (when (crd-json-equal-p copy existing) (return-from write-crd-status copy))
        (prepare-core-resource-metadata copy existing revision)
        (setf (gethash (core-resource-key "customresourcedefinitions" nil name) index) copy)
        (unless dry-run (commit-core-resources store index revision))
        copy))))

(defun dispatch-crd-definition-status (store name method)
  "Serve CRD status reads and JSON writes independently of desired schema fields."
  (let ((old (get-core-resource store "customresourcedefinitions" nil name)))
    (cond ((eq method :get) (json-response old))
          ((member method '(:put :patch))
           (let* ((type (request-media-type))
                  (input (if (eq method :put) (core-resource-request-object "CustomResourceDefinition")
                             (let ((patch (crd-parse-json-content (hunchentoot:raw-post-data :force-text t))))
                               (cond ((equal type "application/merge-patch+json") (merge-json-object old patch))
                                     ((equal type "application/json-patch+json") (apply-core-json-patch old patch))
                                     (t (core-resource-error 415 "UnsupportedMediaType" "CRD status supports JSON/merge patches")))))))
             (json-response (write-crd-status store name
                                              (admit-subresource-write store "customresourcedefinitions" "status" nil name input old
                                                                       :dry-run (core-resource-dry-run-p))
                                              (core-resource-dry-run-p)))))
          (t (core-resource-error 405 "MethodNotAllowed" "Unsupported CRD status method")))))

(defun delete-crd-definition-collection (store labels fields dry-run)
  "Delete actual selector-matched definitions through their finalizer-aware lifecycle."
  (let ((label-test (core-selector-predicate labels)) (field-test (core-selector-predicate fields :fields t)))
    (dolist (definition (list-core-resources store "customresourcedefinitions"))
      (when (and (funcall label-test definition) (funcall field-test definition))
        (let ((metadata (gethash "metadata" definition)))
          (delete-core-resource store "customresourcedefinitions" nil (gethash "name" metadata) :uid (gethash "uid" metadata) :dry-run dry-run))))))
