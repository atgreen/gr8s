;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Encode the OpenAPI v2 document as gnostic's protobuf Document, the only form
;;;; client-go's OpenAPISchema accepts. Field numbers follow gnostic's OpenAPIv2.proto.

(in-package #:gr8s.apiserver)

(defparameter +openapi-protobuf-media-type+ "application/com.github.proto-openapi.spec.v2.v1.0+protobuf"
  "Content type upstream answers the protobuf OpenAPI v2 document with.")

(defun openapi-protobuf-requested-p ()
  "Test whether the Accept header asks for the protobuf OpenAPI document."
  (let ((accept (or (hunchentoot:header-in* :accept) "")))
    (and (search "com.github.proto-openapi.spec.v2" accept) (search "protobuf" accept) t)))

(defun pb-varint (value out)
  "Write VALUE as a protobuf varint, two's complement when negative."
  (let ((value (if (minusp value) (+ value (expt 2 64)) value)))
    (loop
      (multiple-value-bind (rest low) (floor value 128)
        (if (zerop rest)
            (progn (vector-push-extend low out) (return))
            (progn (vector-push-extend (logior low 128) out) (setf value rest)))))))

(defun pb-buffer ()
  "Make an empty encoding buffer."
  (make-array 32 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))

(defun pb-bytes (number octets out)
  "Write a length-delimited field NUMBER."
  (pb-varint (+ (* number 8) 2) out)
  (pb-varint (length octets) out)
  (loop for octet across octets do (vector-push-extend octet out)))

(defun pb-string (number value out)
  "Write a string field unless absent or empty."
  (when (and (stringp value) (plusp (length value)))
    (pb-bytes number (trivial-utf-8:string-to-utf-8-bytes value) out)))

(defun pb-bool (number value out)
  "Write a bool field when true."
  (when (eq value t)
    (pb-varint (* number 8) out)
    (pb-varint 1 out)))

(defun pb-int (number value out)
  "Write an int64 field when a nonzero integer."
  (when (and (integerp value) (not (zerop value)))
    (pb-varint (* number 8) out)
    (pb-varint value out)))

(defun pb-double (number value out)
  "Write a double field when a number."
  (when (realp value)
    (pb-varint (+ (* number 8) 1) out)
    (let ((bits (sb-kernel:double-float-bits (coerce value 'double-float))))
      (let ((bits (ldb (byte 64 0) bits)))
        (dotimes (index 8) (vector-push-extend (ldb (byte 8 (* index 8)) bits) out))))))

(defmacro pb-message (number (out) &body body)
  "Write the fields BODY produces in OUT as the submessage field NUMBER of the enclosing OUT."
  (let ((outer (gensym "OUTER")))
    `(let ((,outer ,out))
       (let ((,out (pb-buffer)))
         ,@body
         (pb-bytes ,number ,out ,outer)))))

(defun pb-any (number value out)
  "Write a gnostic Any carrying VALUE as YAML, of which JSON is a subset."
  (pb-message number (out)
    (pb-string 2 (com.inuoe.jzon:stringify value) out)))

(defun pb-extensions (number object out)
  "Write OBJECT's x- fields as repeated NamedAny."
  (when (hash-table-p object)
    (maphash (lambda (key value)
               (when (uiop:string-prefix-p "x-" key)
                 (pb-message number (out)
                   (pb-string 1 key out)
                   (pb-any 2 value out))))
             object)))

(defun pb-sorted-pairs (object)
  "List OBJECT's entries by key, so the same document always encodes the same."
  (sort (loop for key being the hash-keys of object using (hash-value value) collect (cons key value))
        #'string< :key #'car))

(defun pb-schema-fields (schema out)
  "Write a Schema message's fields."
  (pb-string 1 (gethash "$ref" schema) out)
  (pb-string 2 (gethash "format" schema) out)
  (pb-string 3 (gethash "title" schema) out)
  (pb-string 4 (gethash "description" schema) out)
  (when (nth-value 1 (gethash "default" schema)) (pb-any 5 (gethash "default" schema) out))
  (pb-double 6 (gethash "multipleOf" schema) out)
  (pb-double 7 (gethash "maximum" schema) out)
  (pb-bool 8 (gethash "exclusiveMaximum" schema) out)
  (pb-double 9 (gethash "minimum" schema) out)
  (pb-bool 10 (gethash "exclusiveMinimum" schema) out)
  (pb-int 11 (gethash "maxLength" schema) out)
  (pb-int 12 (gethash "minLength" schema) out)
  (pb-string 13 (gethash "pattern" schema) out)
  (pb-int 14 (gethash "maxItems" schema) out)
  (pb-int 15 (gethash "minItems" schema) out)
  (pb-bool 16 (gethash "uniqueItems" schema) out)
  (pb-int 17 (gethash "maxProperties" schema) out)
  (pb-int 18 (gethash "minProperties" schema) out)
  (let ((required (gethash "required" schema)))
    (when (crd-array-p required)
      (loop for name across required do (pb-string 19 name out))))
  (let ((enum (gethash "enum" schema)))
    (when (crd-array-p enum)
      (loop for value across enum do (pb-any 20 value out))))
  (multiple-value-bind (additional present) (gethash "additionalProperties" schema)
    (when present
      (pb-message 21 (out)
        (cond ((hash-table-p additional)
               (pb-message 1 (out) (pb-schema-fields additional out)))
              ((eq additional t) (pb-bool 2 t out))
              (t (pb-varint (* 2 8) out) (pb-varint 0 out))))))
  (let ((type (gethash "type" schema)))
    (when (stringp type)
      (pb-message 22 (out) (pb-string 1 type out))))
  (let ((items (gethash "items" schema)))
    (when (hash-table-p items)
      (pb-message 23 (out)
        (pb-message 1 (out) (pb-schema-fields items out)))))
  (let ((branches (gethash "allOf" schema)))
    (when (crd-array-p branches)
      (loop for branch across branches
            do (pb-message 24 (out) (pb-schema-fields branch out)))))
  (let ((properties (gethash "properties" schema)))
    (when (hash-table-p properties)
      (pb-message 25 (out)
        (loop for (name . child) in (pb-sorted-pairs properties)
              do (pb-message 1 (out)
                   (pb-string 1 name out)
                   (pb-message 2 (out) (pb-schema-fields child out)))))))
  (pb-string 26 (gethash "discriminator" schema) out)
  (pb-bool 27 (gethash "readOnly" schema) out)
  (pb-extensions 31 schema out))

(defun pb-parameter (parameter out)
  "Write a ParametersItem for one operation parameter."
  (pb-message 1 (out)
    (if (equal "body" (gethash "in" parameter))
        (pb-message 1 (out)
          (pb-string 1 (gethash "description" parameter) out)
          (pb-string 2 (gethash "name" parameter) out)
          (pb-string 3 "body" out)
          (pb-bool 4 (gethash "required" parameter) out)
          (when (hash-table-p (gethash "schema" parameter))
            (pb-message 5 (out) (pb-schema-fields (gethash "schema" parameter) out))))
        (pb-message 2 (out)
          (let ((location (gethash "in" parameter)))
            (flet ((common (out)
                     (pb-bool 1 (gethash "required" parameter) out)
                     (pb-string 2 location out)
                     (pb-string 3 (gethash "description" parameter) out)
                     (pb-string 4 (gethash "name" parameter) out)))
              (cond
                ((equal location "query")
                 (pb-message 3 (out)
                   (common out)
                   (pb-string 6 (or (gethash "type" parameter) "string") out)))
                ((equal location "path")
                 (pb-message 4 (out)
                   (common out)
                   (pb-string 5 (or (gethash "type" parameter) "string") out)))
                ((equal location "header")
                 (pb-message 1 (out)
                   (common out)
                   (pb-string 5 (or (gethash "type" parameter) "string") out)))
                (t
                 (pb-message 2 (out)
                   (common out)
                   (pb-string 6 (or (gethash "type" parameter) "string") out))))))))))

(defun pb-operation (number operation out)
  "Write an Operation field NUMBER."
  (pb-message number (out)
    (pb-string 2 (gethash "summary" operation) out)
    (pb-string 3 (gethash "description" operation) out)
    (pb-string 5 (gethash "operationId" operation) out)
    (let ((produces (gethash "produces" operation)))
      (when (crd-array-p produces)
        (loop for value across produces do (pb-string 6 value out))))
    (let ((consumes (gethash "consumes" operation)))
      (when (crd-array-p consumes)
        (loop for value across consumes do (pb-string 7 value out))))
    (let ((parameters (gethash "parameters" operation)))
      (when (crd-array-p parameters)
        (loop for parameter across parameters
              do (pb-message 8 (out) (pb-parameter parameter out)))))
    (let ((responses (gethash "responses" operation)))
      (when (hash-table-p responses)
        (pb-message 9 (out)
          (loop for (code . response) in (pb-sorted-pairs responses)
                do (when (hash-table-p response)
                     (pb-message 1 (out)
                       (pb-string 1 code out)
                       (pb-message 2 (out)
                         (pb-message 1 (out)
                           (pb-string 1 (gethash "description" response) out)
                           (when (hash-table-p (gethash "schema" response))
                             (pb-message 2 (out)
                               (pb-message 1 (out)
                                 (pb-schema-fields (gethash "schema" response) out)))))))))))
      (pb-extensions 13 operation out))))

(defun pb-path-item (item out)
  "Write a PathItem's fields."
  (loop for (verb . number) in '(("get" . 2) ("put" . 3) ("post" . 4) ("delete" . 5) ("options" . 6) ("head" . 7) ("patch" . 8))
        do (when (hash-table-p (gethash verb item))
             (pb-operation number (gethash verb item) out)))
  (let ((parameters (gethash "parameters" item)))
    (when (crd-array-p parameters)
      (loop for parameter across parameters
            do (pb-message 9 (out) (pb-parameter parameter out)))))
  (pb-extensions 10 item out))

(defun openapi-v2-protobuf (document)
  "Encode an OpenAPI v2 DOCUMENT as gnostic's Document message."
  (let ((out (pb-buffer)))
    (pb-string 1 (gethash "swagger" document) out)
    (let ((info (gethash "info" document)))
      (when (hash-table-p info)
        (pb-message 2 (out)
          (pb-string 1 (gethash "title" info) out)
          (pb-string 2 (gethash "version" info) out)
          (pb-string 3 (gethash "description" info) out))))
    (let ((paths (gethash "paths" document)))
      (when (hash-table-p paths)
        (pb-message 8 (out)
          (loop for (path . item) in (pb-sorted-pairs paths)
                do (when (hash-table-p item)
                     (pb-message 2 (out)
                       (pb-string 1 path out)
                       (pb-message 2 (out) (pb-path-item item out))))))))
    (let ((definitions (gethash "definitions" document)))
      (when (hash-table-p definitions)
        (pb-message 9 (out)
          (loop for (name . schema) in (pb-sorted-pairs definitions)
                do (pb-message 1 (out)
                     (pb-string 1 name out)
                     (pb-message 2 (out) (pb-schema-fields schema out)))))))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun openapi-v2-response (store)
  "Answer /openapi/v2 as the protobuf client-go asks for, or as JSON."
  (let ((document (merge-aggregated-openapi-v2
                   store (crd-openapi-document store nil nil nil))))
    (if (openapi-protobuf-requested-p)
        (progn
          (setf (hunchentoot:content-type*) +openapi-protobuf-media-type+)
          (openapi-v2-protobuf document))
        (json-response document))))
