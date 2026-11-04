;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Enforce Kubernetes structural invariants independently of value validation:
;;;; logical branches cannot introduce untyped fields, root metadata stays
;;;; implicit, and list identity/default schemas must be safe before serving.

(in-package #:gr8s)

(defun crd-int-or-string-union-p (branches)
  "Recognize the canonical upstream integer/string structural union."
  (and (crd-array-p branches) (= 2 (length branches))
       (loop for entry across branches for type in '("integer" "string")
             always (and (hash-table-p entry) (= 1 (hash-table-count entry)) (equal type (gethash "type" entry))))))

(defun validate-crd-logical-branch (branch base path &optional allow-int-union)
  "Forbid structural declarations inside logical constraints and require a base."
  (dolist (field '("type" "default" "additionalProperties" "title" "description" "nullable"
                   "x-kubernetes-preserve-unknown-fields" "x-kubernetes-embedded-resource" "x-kubernetes-int-or-string"
                   "x-kubernetes-list-type" "x-kubernetes-list-map-keys" "x-kubernetes-map-type"))
    (when (nth-value 1 (gethash field branch)) (crd-schema-error path "~A is not structural inside a logical branch" field)))
  (when (gethash "properties" branch)
    (maphash (lambda (key child)
               (let ((declared (gethash key (gethash "properties" base (core-object)))))
                 (unless (and declared (not (equal key "metadata")))
                   (crd-schema-error path "logical property ~A must have a structural declaration outside the branch" key))
                 (validate-crd-logical-branch child declared (format nil "~A.~A" path key)))) (gethash "properties" branch)))
  (when (gethash "items" branch)
    (unless (gethash "items" base) (crd-schema-error path "logical items require a structural items declaration"))
    (validate-crd-logical-branch (gethash "items" branch) (gethash "items" base) (concatenate 'string path ".items")))
  (loop for key across (gethash "required" branch #())
        unless (gethash key (gethash "properties" base (core-object)))
          do (crd-schema-error path "logical required field ~A has no structural declaration" key))
  (dolist (field '("allOf" "anyOf" "oneOf"))
    (unless (and allow-int-union (equal field "anyOf") (crd-int-or-string-union-p (gethash field branch)))
      (loop for child across (gethash field branch #()) do (validate-crd-logical-branch child base path))))
  (when (gethash "not" branch) (validate-crd-logical-branch (gethash "not" branch) base path)))

(defun validate-crd-structural-node (schema path &optional root)
  "Validate structural declarations before their routes can become Established."
  (let* ((properties (gethash "properties" schema)) (items (gethash "items" schema))
         (embedded (eq t (gethash "x-kubernetes-embedded-resource" schema)))
         (int-string (eq t (gethash "x-kubernetes-int-or-string" schema)))
         (list-type (gethash "x-kubernetes-list-type" schema)))
    (when (and root (not (equal "object" (gethash "type" schema)))) (crd-schema-error path "root must have object type"))
    (when (and (or root embedded) (nth-value 1 (gethash "additionalProperties" schema)))
      (crd-schema-error path "additionalProperties is forbidden at resource roots"))
    (when (and embedded (not (gethash "x-kubernetes-preserve-unknown-fields" schema))
               (or (null properties) (zerop (hash-table-count properties))))
      (crd-schema-error path "embedded resources need properties or preserved unknown fields"))
    (when int-string
      (when (or (gethash "type" schema) embedded (gethash "x-kubernetes-preserve-unknown-fields" schema))
        (crd-schema-error path "int-or-string requires an implicit type without resource/preservation extensions")))
    (when (or root embedded)
      (dolist (field '("apiVersion" "kind"))
        (let ((child (and properties (gethash field properties))))
          (when (and child (not (equal "string" (gethash "type" child)))) (crd-schema-error path "~A must have string type" field))))
      (let ((metadata (and properties (gethash "metadata" properties))))
        (when metadata
          (unless (equal "object" (gethash "type" metadata)) (crd-schema-error path "metadata requires object type"))
          (when root
            (reject-unsupported-fields metadata '("type" "properties") "root metadata schema")
            (when (gethash "properties" metadata)
              (reject-unsupported-fields (gethash "properties" metadata) '("name" "generateName") "root metadata properties"))))))
    (when properties
      (maphash (lambda (name child) (validate-crd-structural-node child (format nil "~A.~A" path name))) properties))
    (when items (validate-crd-structural-node items (concatenate 'string path ".items")))
    (when (hash-table-p (gethash "additionalProperties" schema))
      (validate-crd-structural-node (gethash "additionalProperties" schema) (concatenate 'string path ".additionalProperties")))
    (when (member list-type '("map" "set") :test #'equal)
      (when (gethash "nullable" items) (crd-schema-error path "map/set list items cannot be nullable")))
    (when (equal list-type "set")
      (when (or (and (equal "object" (gethash "type" items)) (not (equal "atomic" (gethash "x-kubernetes-map-type" items))))
                (and (equal "array" (gethash "type" items)) (not (equal "atomic" (gethash "x-kubernetes-list-type" items)))))
        (crd-schema-error path "set items require atomic collection types")))
    (when (equal list-type "map")
      (loop for key across (gethash "x-kubernetes-list-map-keys" schema)
            for child = (gethash key (gethash "properties" items))
            unless (and (not (gethash "nullable" child))
                        (or (find key (gethash "required" items #()) :test #'equal) (nth-value 1 (gethash "default" child))))
              do (crd-schema-error path "list key ~A must be required/defaulted and nonnullable" key)))
    (dolist (field '("allOf" "anyOf" "oneOf"))
      (unless (and int-string (equal field "anyOf") (crd-int-or-string-union-p (gethash field schema)))
        (loop for child across (gethash field schema #()) for index from 0
              do (validate-crd-logical-branch child schema path
                     (and int-string (equal field "allOf") (zerop index))))))
    (when (gethash "not" schema) (validate-crd-logical-branch (gethash "not" schema) schema path))
    (when (nth-value 1 (gethash "default" schema))
      (let ((*crd-apply-defaults* nil) (*crd-track-pruning* nil))
        (unless (crd-json-equal-p (gethash "default" schema) (crd-prepare-value (gethash "default" schema) schema))
          (crd-schema-error path "default contains unknown fields that would be pruned")))))
  schema)
