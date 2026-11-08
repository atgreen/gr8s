;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for Kubernetes domain values independent of persistence,
;;;; transport, runtime, and HTTP concerns.

(defpackage #:gr8s.model
  (:use #:cl)
  (:export
   #:*pod-resize-update*
   #:container-spec
   #:container-spec-args
   #:container-spec-command
   #:container-spec-env
   #:container-spec-image
   #:container-spec-name
   #:container-spec-ports
   #:copy-node-record
   #:default-container-termination-message
   #:dns-label-p
   #:dns-subdomain-p
   #:invalid-pod
   #:kubernetes-error
   #:kubernetes-error-details
   #:kubernetes-error-message
   #:kubernetes-error-reason
   #:kubernetes-error-status-code
   #:make-container-spec
   #:make-node-record
   #:make-pod
   #:make-pod-parser-policy
   #:node-record
   #:node-record-annotations
   #:node-record-api-only
   #:node-record-api-status
   #:node-record-capacity
   #:node-record-creation-timestamp
   #:node-record-extended-resources
   #:node-record-id
   #:node-record-kubelet-port
   #:node-record-labels
   #:node-record-last-heartbeat
   #:node-record-lease-deadline
   #:node-record-name
   #:node-record-pod-cidr
   #:node-record-ready-p
   #:node-record-resource-version
   #:node-record-runtime-down-message
   #:node-record-runtime-ready-p
   #:node-record-taints
   #:node-record-underlay-address
   #:node-record-wireguard-public-key
   #:node-record-unschedulable
   #:object-value
   #:optional-vector
   #:parse-container
   #:parse-environment
   #:parse-ephemeral-container
   #:parse-init-container
   #:parse-pod-ephemeral-containers
   #:parse-pod-with-policy
   #:parse-ports
   #:pod
   #:pod-all-containers
   #:pod-containers
   #:pod-ephemeral-containers
   #:pod-init-containers
   #:pod-name
   #:pod-namespace
   #:pod-node-name
   #:pod-object
   #:pod-parser-policy
   #:pod-parser-policy-container-validator
   #:pod-parser-policy-environment-reference-validator
   #:pod-parser-policy-metadata-validator
   #:pod-parser-policy-resource-validator
   #:pod-parser-policy-spec-validator
   #:pod-generate-name-prefix
   #:pod-resource-version
   #:pod-restart-policy
   #:pod-status-revision
   #:pod-uid
   #:pod-to-object
   #:reject-unsupported-fields
   #:require-dns-label
   #:require-dns-subdomain
   #:require-empty-object-if-present
   #:require-nonempty-string
   #:require-object
   #:require-string-vector
   #:validate-owner-references))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (do-external-symbols (symbol '#:gr8s.model)
    (shadowing-import symbol '#:gr8s))
  ;; Preserve only the historical public facade. Parser helpers remain an
  ;; explicit MODEL interface without broadening GR8S's public API.
  (dolist (name '("CONTAINER-SPEC-ARGS" "CONTAINER-SPEC-COMMAND"
                  "CONTAINER-SPEC-ENV" "CONTAINER-SPEC-IMAGE"
                  "CONTAINER-SPEC-NAME" "CONTAINER-SPEC-PORTS"
                  "KUBERNETES-ERROR" "KUBERNETES-ERROR-REASON"
                  "MAKE-NODE-RECORD" "NODE-RECORD-ID"
                  "NODE-RECORD-LAST-HEARTBEAT" "NODE-RECORD-NAME"
                  "NODE-RECORD-POD-CIDR" "NODE-RECORD-READY-P"
                  "POD-CONTAINERS" "POD-NAME" "POD-NODE-NAME"
                  "POD-NAMESPACE" "POD-RESTART-POLICY"
                  "POD-RESOURCE-VERSION" "POD-TO-OBJECT" "POD-UID"))
    (export (find-symbol name '#:gr8s.model) '#:gr8s)))
