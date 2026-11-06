;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise pinned real CRD wire fields through the HTTP API, including Go's
;;;; zero-valued metadata, JSON defaults/enums, schema unions and double bounds.

(in-package #:gr8s/tests)
(def-suite crd-protobuf :in gr8s)
(in-suite crd-protobuf)

(defun crd-test-double-field (number value)
  "Encode an independent fixed64 wire field for numeric schema bounds."
  (let ((buffer (make-array 16 :element-type '(unsigned-byte 8) :fill-pointer 0 :adjustable t)))
    (ag-proto::write-field-tag number 1 buffer)
    (loop for byte in (ag-proto::encode-float64 value) do (vector-push-extend byte buffer))
    buffer))

(defun crd-test-wire-request ()
  "Build actual v1 field numbers, deliberately retaining Go protobuf zero metadata."
  (let* ((json-default (core-test-protobuf '((1 "2"))))
         (count-schema (concatenate '(vector (unsigned-byte 8))
                         (core-test-protobuf (list (list 5 "integer") (list 8 json-default)))
                         (crd-test-double-field 11 1.5d0)))
         (false-json (core-test-protobuf '((1 "false"))))
         (flag-schema (core-test-protobuf (list (list 5 "boolean") (list 8 false-json) (list 20 false-json))))
         (string-schema (core-test-protobuf '((5 "string") (14 0))))
         (map-schema (core-test-protobuf (list (list 5 "object") (list 30 (core-test-protobuf (list (list 1 1) (list 2 string-schema)))))))
         (array-schema (core-test-protobuf (list (list 5 "array") (list 24 (core-test-protobuf (list (list 1 string-schema)))))))
         (root (core-test-protobuf
                (list (list 5 "object")
                      (list 29 (core-test-protobuf (list (list 1 "count") (list 2 count-schema))))
                      (list 29 (core-test-protobuf (list (list 1 "flag") (list 2 flag-schema))))
                      (list 29 (core-test-protobuf (list (list 1 "attrs") (list 2 map-schema))))
                      (list 29 (core-test-protobuf (list (list 1 "names") (list 2 array-schema)))))))
         (version (core-test-protobuf (list (list 1 "v1") (list 2 1) (list 3 1) (list 4 (core-test-protobuf (list (list 1 root)))))))
         (names (core-test-protobuf '((1 "wirewidgets") (2 "") (4 "WireWidget") (5 ""))))
         (spec (core-test-protobuf (list (list 1 "wire.example.test") (list 3 names) (list 4 "Cluster") (list 7 version) (list 10 0))))
         (metadata (core-test-protobuf '((1 "wirewidgets.wire.example.test") (2 "") (3 "") (5 "") (6 "") (7 0)))))
    (core-test-protobuf-envelope "CustomResourceDefinition" (list (list 1 metadata) (list 2 spec)) "apiextensions.k8s.io/v1")))

(test typed-crd-wire-input-establishes-real-json-schema-and-defaults
  (with-crd-api (store path)
    (values store path)
    (multiple-value-bind (body code)
        (drakma:http-request (crd-api-url "/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
                            :method :post :content-type "application/vnd.kubernetes.protobuf" :content (crd-test-wire-request))
      (is (= 201 code) "~A" body)
      (let* ((object (com.inuoe.jzon:parse body))
             (schema (gethash "openAPIV3Schema" (gethash "schema" (aref (gethash "versions" (gethash "spec" object)) 0))))
             (properties (gethash "properties" schema)))
        (is (= 1.5d0 (gethash "minimum" (gethash "count" properties))))
        (is (= 2 (gethash "default" (gethash "count" properties))))
        (is-true (nth-value 1 (gethash "default" (gethash "flag" properties))))
        (is-false (gethash "default" (gethash "flag" properties)))
        (is (equal "string" (gethash "type" (gethash "additionalProperties" (gethash "attrs" properties)))))
        (is (equal "string" (gethash "type" (gethash "items" (gethash "names" properties)))))))
    (let ((created (crd-api-request 201 "/apis/wire.example.test/v1/wirewidgets" :method :post
                                   :object (gr8s::core-object "apiVersion" "wire.example.test/v1" "kind" "WireWidget"
                                                            "metadata" (gr8s::core-object "name" "one")))))
      (is (= 2 (gethash "count" created)))
      (is-true (nth-value 1 (gethash "flag" created))))
    (crd-api-request 422 "/apis/wire.example.test/v1/wirewidgets/one" :method :patch :content-type "application/merge-patch+json"
                     :object (gr8s::core-object "count" 1))))

(test typed-crd-union-and-nonfinite-boundaries-are-not-silently-reinterpreted
  (let* ((prefix "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.")
         (gr8s::*core-protobuf-field-count* 0))
    (is (equal "https://example.test/ref"
               (gethash "$ref" (gr8s::template-protobuf-message (concatenate 'string prefix "JSONSchemaProps")
                                 (core-test-protobuf '((3 "https://example.test/ref")))))))
    (is (eq 'null (gr8s::template-protobuf-message (concatenate 'string prefix "JSON") (core-test-protobuf (list (list 1 #()))))))
    (is-false (gr8s::template-protobuf-message (concatenate 'string prefix "JSONSchemaPropsOrBool") (core-test-protobuf '((1 0)))))
    (signals error
      (gr8s::template-protobuf-message (concatenate 'string prefix "JSONSchemaProps")
          (concatenate '(vector (unsigned-byte 8)) #(73) #(0 0 0 0 0 0 240 127))))))

(in-suite gr8s)
