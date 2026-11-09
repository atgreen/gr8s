;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for Kubernetes resource semantics and admission.

(defpackage #:gr8s.resources
  (:use #:cl #:gr8s)
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

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((resources (find-package '#:gr8s.resources))
        (composition (find-package '#:gr8s)))
    ;; These operations are referenced by persistence and HA code loaded before
    ;; their implementations.  Give those forward references their final owner.
    (dolist (name '("*RAFT-LOCAL-PLANE-RESOURCES*"
                    "*STORED-RESOURCE-TYPES*"
                    "COPY-CORE-OBJECT"
                    "COPY-CORE-RESOURCE-INDEX"
                    "CORE-OBJECT"
                    "CORE-RESOURCE-API-VERSION"
                    "CORE-RESOURCE-ERROR"
                    "CORE-RESOURCE-KEY"
                    "CORE-RESOURCE-KIND"
                    "CORE-RESOURCE-NAMESPACED-P"
                    "CREATE-CORE-RESOURCE"
                    "DELETE-CORE-RESOURCE"
                    "DISABLE-SECRET-ENCRYPTION"
                    "ENABLE-SECRET-ENCRYPTION"
                    "FINALIZE-SECRET-ENCRYPTION-KEY"
                    "GET-CORE-RESOURCE"
                    "GET-CORE-RESOURCE-UNLOCKED"
                    "INSTALL-SECRET-ENCRYPTION-COMMAND"
                    "INSTALL-CORE-STATE-BLOB"
                    "INSTALL-CORE-STATE-DELTA"
                    "LIST-CORE-RESOURCES"
                    "LOAD-CORE-RESOURCES"
                    "NORMALIZE-CORE-RESOURCE"
                    "PREPARE-SECRET-ENCRYPTION-KEY"
                    "PROMOTE-SECRET-ENCRYPTION-KEY"
                    "REENCRYPT-SECRETS"
                    "SECRET-ENCRYPTION-STATUS"
                    "STORED-RESOURCE-TYPE"
                    "UPDATE-CORE-RESOURCE"
                    "WITH-CRD-DEFERRED-CONVERSIONS"))
      (shadowing-import (find-symbol name resources) composition))))
