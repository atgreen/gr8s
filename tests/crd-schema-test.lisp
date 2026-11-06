;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
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
  (dolist (schema (list (gr8s::core-object "type" "object" "$ref" "https://example.test/schema")
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
    (gr8s::crd-validate-value (vector item (gr8s::core-object "key" "other")) schema "list")
    (is (vectorp (gr8s::crd-validate-value (vector (gr8s::core-object "key" "Case") (gr8s::core-object "key" "case")) schema "case-sensitive-list"))))
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

(test crd-structural-constraints-reject-inert-or-ambiguous-declarations
  (dolist (schema
           (list
            (gr8s::core-object "type" "object" "additionalProperties" t)
            (gr8s::core-object "type" "object" "anyOf" (vector (gr8s::core-object "type" "object")))
            (gr8s::core-object "type" "object" "allOf" (vector (gr8s::core-object "properties" (gr8s::core-object "undeclared" (gr8s::core-object "minLength" 1)))))
            (gr8s::core-object "type" "object" "properties" (gr8s::core-object "metadata" (gr8s::core-object "type" "object" "properties" (gr8s::core-object "labels" (gr8s::core-object "type" "object")))))
            (gr8s::core-object "type" "object" "properties" (gr8s::core-object "items" (gr8s::core-object "type" "array" "x-kubernetes-list-type" "set" "items" (gr8s::core-object "type" "object"))))
            (gr8s::core-object "type" "object" "properties" (gr8s::core-object "spec" (gr8s::core-object "type" "object" "default" (gr8s::core-object "unknown" t))))))
    (signals kubernetes-error (gr8s::validate-crd-structural-node schema "schema" t))))

(test embedded-resources-require-real-identities-and-prune-metadata
  (let* ((schema (gr8s::core-object "type" "object" "x-kubernetes-embedded-resource" t "x-kubernetes-preserve-unknown-fields" t))
         (input (gr8s::core-object "apiVersion" "v1" "kind" "Pod" "metadata" (gr8s::core-object "name" "nested" "unknown" t)
                                  "spec" (gr8s::core-object "preserved" t)))
         (output (gr8s::crd-prepare-value input schema)))
    (gr8s::validate-crd-schema schema)
    (gr8s::validate-crd-structural-node schema "embedded")
    (is (null (gethash "unknown" (gethash "metadata" output))))
    (is-true (gethash "preserved" (gethash "spec" output)))
    (gr8s::crd-validate-value output schema "embedded")
    (remhash "kind" output)
    (signals kubernetes-error (gr8s::crd-validate-value output schema "embedded"))))

;; Upstream's validateEmbeddedResource and ObjectMeta round trip.
(test embedded-resources-check-identity-forms-and-coerce-metadata
  (let ((schema (gr8s::core-object "type" "object" "x-kubernetes-embedded-resource" t "x-kubernetes-preserve-unknown-fields" t)))
    (flet ((refused (text expected)
             (let ((message (handler-case (progn (gr8s::crd-validate-value (com.inuoe.jzon:parse text) schema "resource.spec.tmpl") nil)
                              (kubernetes-error (condition) (gr8s::kubernetes-error-message condition)))))
               (is (and message (search expected message)) "~A: ~A" text message))))
      (refused "{\"kind\":\"Pod\"}" "spec.tmpl.apiVersion: Required value")
      (refused "{\"apiVersion\":\"v1\",\"kind\":5}" "spec.tmpl.kind: must be a string")
      (refused "{\"apiVersion\":\"v1\",\"kind\":\"\"}" "spec.tmpl.kind: must not be empty")
      (refused "{\"apiVersion\":\"v1\",\"kind\":\"a_b\"}" "spec.tmpl.kind: may have mixed case")
      (refused "{\"apiVersion\":\"v1\",\"kind\":\"9Lives\"}" "spec.tmpl.kind: may have mixed case")
      (refused "{\"apiVersion\":\"a/b/c\",\"kind\":\"X\"}" "unexpected GroupVersion string"))
    (gr8s::crd-validate-value (com.inuoe.jzon:parse "{\"apiVersion\":\"apps/v1\",\"kind\":\"StatefulSet\"}") schema "resource.spec.tmpl")
    ;; A zero creationTimestamp does not survive the ObjectMeta round trip; unknown fields are pruned.
    (let ((output (gr8s::crd-prepare-value
                   (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"a\",\"creationTimestamp\":null,\"foo\":1}}")
                   schema)))
      (is (equal '("name") (loop for key being the hash-keys of (gethash "metadata" output) collect key))))))

(test structural-int-or-string-and-declared-logical-validation-are-supported
  (let ((schema (gr8s::core-object "x-kubernetes-int-or-string" t "anyOf"
                   (vector (gr8s::core-object "type" "integer") (gr8s::core-object "type" "string")))))
    (gr8s::validate-crd-schema schema)
    (gr8s::validate-crd-structural-node schema "union")
    (is (= 3 (gr8s::crd-validate-value 3 schema "union")))
    (is (equal "3" (gr8s::crd-validate-value "3" schema "union"))))
  (let ((schema (gr8s::core-object "type" "object" "properties" (gr8s::core-object "count" (gr8s::core-object "type" "integer"))
                 "allOf" (vector (gr8s::core-object "properties" (gr8s::core-object "count" (gr8s::core-object "minimum" 2)))))))
    (gr8s::validate-crd-schema schema)
    (gr8s::validate-crd-structural-node schema "logical" t)
    (signals kubernetes-error (gr8s::crd-validate-value (gr8s::core-object "count" 1) schema "logical"))))

(test supported-regexps-retain-re2-anchor-and-ascii-class-semantics
  (let ((schema (gr8s::core-object "type" "string" "pattern" "^[a-z]+$")))
    (gr8s::validate-crd-schema schema)
    (signals kubernetes-error (gr8s::crd-validate-value (format nil "valid~%") schema "anchor")))
  (dolist (pattern '("(?=lookahead)" "\\1" "a{1001}"))
    (signals kubernetes-error (gr8s::validate-crd-schema (gr8s::core-object "type" "string" "pattern" pattern))))
  (let ((schema (gr8s::core-object "type" "string" "pattern" "^\\w+$")))
    (gr8s::validate-crd-schema schema)
    (is (equal "ascii_123" (gr8s::crd-validate-value "ascii_123" schema "ascii")))
    (signals kubernetes-error (gr8s::crd-validate-value "é" schema "ascii"))))

(in-suite gr8s)
