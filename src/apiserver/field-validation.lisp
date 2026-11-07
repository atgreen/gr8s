;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Apply the fieldValidation request option to typed and custom objects:
;;;; Strict rejects unknown and duplicate fields, Warn reports them in Warning
;;;; headers and removes them, and Ignore removes them silently.

(in-package #:gr8s.apiserver)

(defun strip-field-path-root (path)
  "Report a field path from the object's root, without the walker's own root name."
  (if (uiop:string-prefix-p "resource." path) (subseq path (length "resource.")) path))

(defun add-warning-header (message)
  "Add one RFC 7234 warning, keeping any already on this response."
  (let ((warning (format nil "299 - ~A" (com.inuoe.jzon:stringify (subseq message 0 (min 1000 (length message))))))
        (existing (hunchentoot:header-out :warning)))
    (setf (hunchentoot:header-out :warning)
          (if existing (format nil "~A, ~A" existing warning) warning))))

(defun report-field-problems (problems &optional (prefix ""))
  "Fail on PROBLEMS under Strict or warn about each under Warn; Ignore says nothing."
  (when problems
    (cond ((equal *crd-field-validation* "Strict")
           (core-resource-error 400 "BadRequest" "~Astrict decoding error: ~{~A~^, ~}" prefix problems))
          ((equal *crd-field-validation* "Warn")
           (dolist (problem problems) (add-warning-header problem))))))

(defun unknown-field-problem (path)
  "Describe an unknown field as Kubernetes' strict decoder does."
  (format nil "unknown field ~S" (strip-field-path-root path)))

(defun duplicate-field-problem (path)
  "Describe a repeated field as Kubernetes' strict decoder does."
  (format nil "duplicate field ~S" (strip-field-path-root path)))

(defun typed-request-schema (kind)
  "Find the pinned definition of KIND in the requested version, when one exists."
  (let* ((version (or *core-resource-view-version* "v1"))
         (slash (position #\/ version))
         (group (if slash (subseq version 0 (or (position #\. version) slash)) "core"))
         (name (if (equal group "apiregistration")
                   (format nil "io.k8s.kube-aggregator.pkg.apis.apiregistration.v1.~A" kind)
                   (format nil "io.k8s.api.~A.~A.~A" group (if slash (subseq version (1+ slash)) version) kind))))
    (values (gethash name (gethash "definitions" *podtemplate-schema*)))))

(defun prune-typed-unknown-fields (value schema &optional (path "") (depth 0))
  "Remove fields a typed definition does not declare and return their paths, in order."
  (when (> depth 64) (core-resource-error 422 "Invalid" "Object nesting exceeds 64"))
  (let* ((schema (resolve-template-schema schema)) (properties (gethash "properties" schema))
         (extra (gethash "additionalProperties" schema)) (unknown nil))
    (cond
      ((hash-table-p value)
       (dolist (key (sort (loop for key being the hash-keys of value collect key) #'string<))
         (let ((child (or (and properties (gethash key properties)) (and (hash-table-p extra) extra)))
               (location (if (equal path "") key (concatenate 'string path "." key))))
           (cond (child (setf unknown (append unknown (prune-typed-unknown-fields (gethash key value) child location (1+ depth)))))
                 ((and properties (not (eq extra t)))
                  (setf unknown (append unknown (list location)))
                  (remhash key value))))))
      ((and (vectorp value) (not (stringp value)) (gethash "items" schema))
       (loop for item across value for index from 0
             do (setf unknown (append unknown (prune-typed-unknown-fields item (gethash "items" schema)
                                                                          (format nil "~A[~D]" path index) (1+ depth)))))))
    unknown))

(defun apply-typed-field-validation (object text kind)
  "Enforce fieldValidation on a decoded typed OBJECT read from JSON TEXT."
  (let ((schema (typed-request-schema kind)))
    (when (and schema (hash-table-p object))
      (let ((unknown (prune-typed-unknown-fields object schema))
            (duplicates (unless (equal "Ignore" *crd-field-validation*) (reverse (crd-json-duplicate-fields text)))))
        (report-field-problems (append (mapcar #'unknown-field-problem unknown)
                                       (mapcar #'duplicate-field-problem duplicates))
                               (format nil "~A in version ~S cannot be handled as a ~A: "
                                       kind (subseq (or *core-resource-view-version* "v1")
                                                    (let ((slash (position #\/ (or *core-resource-view-version* "v1"))))
                                                      (if slash (1+ slash) 0)))
                                       kind)))))
  object)

(defun crd-undeclared-fields (value schema &optional (path "") (root t) (depth 0))
  "List fields of a custom object its structural schema neither declares nor preserves."
  (when (> depth 64) (crd-schema-error "resource" "resource nesting exceeds 64"))
  (cond
    ((hash-table-p value)
     (let ((properties (gethash "properties" schema)) (additional (gethash "additionalProperties" schema))
           (embedded (or root (gethash "x-kubernetes-embedded-resource" schema)))
           (preserve (gethash "x-kubernetes-preserve-unknown-fields" schema)))
       (loop for key in (sort (loop for key being the hash-keys of value collect key) #'string<)
             for child = (gethash key value)
             for location = (format nil "~A.~A" path key)
             for sub = (or (and properties (gethash key properties)) (and (hash-table-p additional) additional))
             append (cond
                      ((and embedded (equal key "metadata"))
                       (mapcar (lambda (field) (format nil "~A.~A" path field))
                               (prune-typed-unknown-fields (copy-core-object child)
                                                           (template-schema "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta")
                                                           "metadata")))
                      ((and embedded (member key '("apiVersion" "kind") :test #'equal)) nil)
                      (sub (crd-undeclared-fields child sub location nil (1+ depth)))
                      ((or (eq t additional) preserve) nil)
                      (t (list location))))))
    ((crd-array-p value)
     (when (gethash "items" schema)
       (loop for child across value for index from 0
             append (crd-undeclared-fields child (gethash "items" schema) (format nil "~A[~D]" path index) nil (1+ depth)))))))
