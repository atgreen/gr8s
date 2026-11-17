;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Kubernetes-facing adapters for the Raft consensus and transport layers.

(defpackage #:gr8s.ha
  (:use #:cl #:gr8s.raft #:gr8s.raft.transport)
  (:export
   #:ha-control-plane
   #:ha-control-plane-leader-p
   #:ha-control-plane-leader-status
   #:ha-control-plane-member
   #:ha-control-plane-node-endpoints
   #:ha-control-plane-node-session-endpoints
   #:ha-control-plane-membership
   #:ha-control-plane-remove-member
   #:ha-control-plane-store
   #:ha-recovery-wait-report
   #:make-ha-control-plane
   #:make-raft-plane
   #:make-raft-resource-record
   #:make-raft-resource-store
   #:raft-consensus-resource-p
   #:raft-leader-redirect-url
   #:raft-local-plane-category-p
   #:raft-mutating-method-p
   #:raft-plane
   #:raft-plane-consensus-fn
   #:raft-plane-local-fn
   #:raft-plane-submit
   #:raft-resource-apply
   #:raft-resource-get
   #:raft-resource-record
   #:raft-resource-record-resource-version
   #:raft-resource-record-uid
   #:raft-resource-record-value
   #:raft-resource-store
   #:raft-resource-store-equal
   #:raft-resource-store-resources
   #:raft-resource-store-revision
   #:reset-control-plane-membership
   #:start-ha-control-plane
   #:stop-ha-control-plane))

;; Preserve the historical facade while source files migrate package by package.
