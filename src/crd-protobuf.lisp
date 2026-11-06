;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Decode genuine typed apiextensions protobuf requests using pinned schemas,
;;;; preserving raw JSON defaults, schema unions and Go JSON tag/omission rules.
;;;; Unstructured custom resources continue to require JSON, as upstream.

(in-package #:gr8s)

(defparameter *crd-wire-schema*
  (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/crd-wire-v1.json")))

(eval-when (:load-toplevel :execute)
  (maphash (lambda (name fields)
             (unless (gethash name (gethash "messages" *podtemplate-schema*))
               (setf (gethash name (gethash "messages" *podtemplate-schema*)) fields)))
           (gethash "messages" *crd-wire-schema*)))

(defun crd-protobuf-json-value (name object)
  "Restore JSON wrapper/union semantics instead of exposing protobuf scaffolding."
  (cond
    ((equal name "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSON")
     (let ((raw (gethash "raw" object)))
       (if (and raw (plusp (length raw))) (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string (ag-grpc:base64-decode raw))
                                   :max-string-length (* 2 1024 1024)) 'null)))
    ((equal name "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaPropsOrBool")
     (or (gethash "schema" object) (eq t (gethash "allows" object))))
    ((equal name "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaPropsOrArray")
     (or (gethash "schema" object) (gethash "jSONSchemas" object 'null)))
    ((equal name "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaPropsOrStringArray")
     (or (gethash "schema" object) (gethash "property" object #())))
    (t object)))

(defun decode-crd-protobuf (bytes)
  "Decode a real CRD payload with normal metadata preconditions and finalizers."
  (let* ((object (template-protobuf-message "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition" bytes))
         (metadata (gethash "metadata" object (core-object))))
    ;; ObjectMeta's non-pointer strings are written as zero values by Go's
    ;; protobuf marshaler although its JSON encoding omits those values.
    (dolist (field '("name" "generateName" "namespace" "uid" "resourceVersion" "selfLink" "clusterName"))
      (when (equal "" (gethash field metadata)) (remhash field metadata)))
    (setf (gethash "metadata" object) metadata
          (gethash "apiVersion" object) +crd-api-version+
          (gethash "kind" object) "CustomResourceDefinition")
    object))
