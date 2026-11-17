;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for Kubernetes resource semantics and admission.

(defpackage #:gr8s.resources
  (:use #:cl)
  ;; RE2-syntax regular expressions now come from the extracted cl-re2 library.
  (:import-from #:cl-re2
   #:re2-compile #:re2-search #:re2-match-p
   #:re2-syntax-error #:re2-syntax-error-message)
  (:shadow
   #:*raft-local-plane-resources*
   #:*stored-resource-types*
   #:copy-core-object
   #:copy-core-resource-index
   #:core-object
   #:core-resource-api-version
   #:core-resource-error
   #:core-resource-key
   #:core-resource-kind
   #:core-resource-namespaced-p
   #:create-core-resource
   #:delete-core-resource
   #:disable-secret-encryption
   #:enable-secret-encryption
   #:finalize-secret-encryption-key
   #:get-core-resource
   #:get-core-resource-unlocked
   #:install-secret-encryption-command
   #:install-core-state-blob
   #:install-core-state-delta
   #:list-core-resources
   #:load-core-resources
   #:normalize-core-resource
   #:prepare-secret-encryption-key
   #:promote-secret-encryption-key
   #:reencrypt-secrets
   #:secret-encryption-status
   #:stored-resource-type
   #:update-core-resource
   #:with-crd-deferred-conversions))

(defvar gr8s.resources::*internal-stored-resource-types* nil
  "Private consensus records, persisted with resources but not exposed through generic Kubernetes CRUD.")
;;; The CEL (Common Expression Language) engine now lives in the standalone
;;; cl-cel library (installed via ocicl).  gr8s drives it from several packages
;;; the way the in-tree engine was driven: admission policies, CRD validation and
;;; the DRA scheduler rebind the engine's dynamic variables (declared variables,
;;; variable and node type maps, step budget) around compile and evaluate calls
;;; and read its value constructors and parsers directly.  For those dynamic
;;; bindings to reach the library's code they must name the very symbols the
;;; library binds, so we re-home cl-cel's engine symbols -- its exported API and
;;; the internals gr8s reaches into -- into gr8s.resources and the gr8s
;;; composition package here, before any resources file that references them
;;; (some, such as store-snapshot-index and crd-formats, load early).
(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((symbols (mapcar (lambda (name)
                           (or (find-symbol name '#:cl-cel)
                               (error "cl-cel does not provide ~A, which gr8s requires." name)))
                         '("*CEL-AUTHORIZER-CHECK*"
                           "CEL-BUDGET-EXHAUSTED"
                           "CEL-CHECK"
                           "CEL-CHECK-ERROR"
                           "CEL-COMPILE-ERROR"
                           "*CEL-CONSTRUCTION-TYPES*"
                           "CEL-COST-EXCEEDED"
                           "*CEL-DECLARED-VARIABLES*"
                           "CEL-DURATION"
                           "CEL-ERROR-MESSAGE"
                           "CEL-ESTIMATED-COST"
                           "CEL-EVALUATE"
                           "+CEL-EVALUATION-BUDGET+"
                           "CEL-EVALUATION-ERROR"
                           "CEL-FAIL"
                           "CEL-LIST-P"
                           "CEL-MARK-LIST"
                           "CEL-MASKED-ADDRESS"
                           "+CEL-MATCH-CONDITIONS-BUDGET+"
                           "*CEL-NODE-TYPES*"
                           "CEL-OPAQUE"
                           "CEL-OPTIONAL"
                           "CEL-PARSE-CIDR"
                           "CEL-PARSE-DURATION"
                           "CEL-PARSE-EXPRESSION"
                           "CEL-PARSE-IP"
                           "CEL-PARSE-IPV4"
                           "CEL-PARSE-RFC3339"
                           "CEL-REFERENCES-VARIABLE-P"
                           "*CEL-REMAINING-STEPS*"
                           "*CEL-REQUEST-RESOURCE*"
                           "+CEL-RUNTIME-BUDGET+"
                           "*CEL-SHARED-BUDGET*"
                           "CEL-TIMESTAMP"
                           "CEL-TOKENIZE"
                           "CEL-TYPE-HEAD"
                           "CEL-TYPE-NAME"
                           "CEL-UNESCAPE-FIELD"
                           "*CEL-VARIABLE-TYPES*"
                           "COMPILE-CEL-CONDITION"
                           "COMPILE-CEL-EXPRESSION"
                           "EVALUATE-CEL-CONDITION"
                           "EVALUATE-CEL-VALUE"
                           "WITH-CEL-BUDGET"
                           "MAKE-CEL-TIMESTAMP"
                           "MAKE-CEL-DURATION"
                           "MAKE-CEL-OPTIONAL"
                           "MAKE-CEL-PARSER"))))
    (shadowing-import symbols '#:gr8s.resources)
    (export symbols '#:gr8s.resources)))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (export (intern "PARSE-YAML" '#:gr8s.resources) '#:gr8s.resources)
  (export (intern "STRINGIFY-TO-UTF-8-BYTES" '#:gr8s.resources) '#:gr8s.resources))
