;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise actual structural admission, defaulting, pruning and validation
;;;; independently of custom-resource HTTP routing and durable storage.

(in-package #:gr8s/tests)
(def-suite crd-schema :in gr8s)
(in-suite crd-schema)

(defun crd-test-schema ()
  "Build a small structural schema with typed defaults and a preserved subtree."
  (gr8s::core-object "type" "object" "required" #("spec") "properties"
    (gr8s::core-object "spec" (gr8s::core-object "type" "object" "required" #("count") "properties"
      (gr8s::core-object
        "count" (gr8s::core-object "type" "integer" "minimum" 1 "maximum" 4 "default" 2)
        "name" (gr8s::core-object "type" "string" "pattern" "^[a-z]+$" "minLength" 2 "maxLength" 8)
        "opaque" (gr8s::core-object "type" "object" "x-kubernetes-preserve-unknown-fields" t "properties"
                    (gr8s::core-object "typed" (gr8s::core-object "type" "object" "properties"
                        (gr8s::core-object "keep" (gr8s::core-object "type" "boolean"))))))))))

(test custom-schema-defaulting-pruning-and-validation-are-real
  (let* ((schema (gr8s::validate-crd-schema (crd-test-schema)))
         (input (gr8s::core-object "apiVersion" "sample.test/v1" "kind" "Widget" "metadata" (gr8s::core-object "name" "one")
                  "unknown" "pruned" "spec" (gr8s::core-object "count" 'null "name" "valid" "extra" t "opaque"
                    (gr8s::core-object "unknown" t "typed" (gr8s::core-object "keep" nil "drop" t)))))
         (output (gr8s::crd-prepare-value input schema t)))
    (gr8s::crd-validate-value output schema "resource")
    (is (equal "Widget" (gethash "kind" output)))
    (is (null (gethash "unknown" output)))
    (is (= 2 (gethash "count" (gethash "spec" output))))
    (is (null (gethash "extra" (gethash "spec" output))))
    (is-true (gethash "unknown" (gethash "opaque" (gethash "spec" output))))
    (is-false (gethash "drop" (gethash "typed" (gethash "opaque" (gethash "spec" output)))))
    (is-true (gethash "unknown" input))
    (dolist (bad '(0 5 "2" nil))
      (setf (gethash "count" (gethash "spec" output)) bad)
      (signals kubernetes-error (gr8s::crd-validate-value output schema "resource")))))

(test custom-schema-rejects-unsupported-validation-and-invalid-structure
  (dolist (schema (list (gr8s::core-object "type" "object" "x-kubernetes-validations" #())
                        (gr8s::core-object "type" "object" "$ref" "https://example.test/schema")
                        (gr8s::core-object "type" "string" "format" "invented")
                        (gr8s::core-object "type" "array")
                        (gr8s::core-object "type" "object" "properties" (gr8s::core-object "missing-type" (gr8s::core-object)))
                        (gr8s::core-object "type" "integer" "default" "not-an-integer")))
    (signals kubernetes-error (gr8s::validate-crd-schema schema))))

(test custom-schema-enforces-list-identity-nullability-and-logical-constraints
  (let* ((schema (gr8s::core-object "type" "array" "x-kubernetes-list-type" "map" "x-kubernetes-list-map-keys" #("key")
                   "items" (gr8s::core-object "type" "object" "required" #("key") "properties"
                            (gr8s::core-object "key" (gr8s::core-object "type" "string")))))
         (item (gr8s::core-object "key" "duplicate")))
    (gr8s::validate-crd-schema schema)
    (signals kubernetes-error (gr8s::crd-validate-value (vector item item) schema "list"))
    (gr8s::crd-validate-value (vector item (gr8s::core-object "key" "other")) schema "list"))
  (let ((schema (gr8s::core-object "type" "integer" "nullable" t "anyOf"
                  (vector (gr8s::core-object "minimum" 5) (gr8s::core-object "maximum" 1)))))
    (gr8s::validate-crd-schema schema)
    (is (eq 'null (gr8s::crd-validate-value 'null schema "nullable")))
    (is (= 7 (gr8s::crd-validate-value 7 schema "logical")))
    (signals kubernetes-error (gr8s::crd-validate-value 3 schema "logical"))))

(test custom-schema-false-values-have-real-enum-and-set-identity
  (let ((schema (gr8s::core-object "type" "boolean" "enum" #(nil))))
    (is-false (gr8s::crd-validate-value nil schema "false"))
    (signals kubernetes-error (gr8s::crd-validate-value t schema "false")))
  (signals kubernetes-error
    (gr8s::crd-validate-value #(nil nil) (gr8s::core-object "type" "array" "uniqueItems" t
                                     "items" (gr8s::core-object "type" "boolean")) "set")))

(in-suite gr8s)
