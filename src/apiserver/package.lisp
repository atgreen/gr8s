;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for HTTP, watch, OpenAPI, and streaming API adapters.

(defpackage #:gr8s.apiserver
  (:use #:cl)
  (:import-from #:gr8s.foundation
   #:+dns-pod-server-address+
   #:json-object
   #:node-steering-capacity-score
   #:rank-network-steering-candidates
   #:steering-bounded-integer)
  (:import-from #:gr8s.model
   #:kubernetes-error-status-code
   #:make-node-record
   #:node-record-all-pod-cidrs
   #:node-record-capacity
   #:node-record-id
   #:node-record-labels
   #:node-record-name
   #:node-record-pod-cidr
   #:node-record-ready-p
   #:node-record-ready-since
   #:node-record-underlay-address
   #:node-record-wireguard-endpoints
   #:node-record-wireguard-public-key
   #:node-record-wireguard-reflexive-observed-at
   #:pod-name
   #:pod-namespace
   #:pod-node-name
   #:pod-resource-version
   #:pod-to-object
   #:pod-uid)
  (:import-from #:gr8s.protocol
   #:+node-protocol-version+
   #:ensure-node-protocol-version
   #:make-server-envelope)
  (:shadow
   #:node-grpc-server
   #:node-grpc-server-port
   #:node-session-acknowledged-revision
   #:pending-node-operation-done-p
   #:pending-node-operation-error
   #:pending-node-operation-response
   #:publish-node-desired-state
   #:queue-node-operation
   #:release-node-operation
   #:route-http-request
   #:start-node-grpc-server
   #:start-agent-kubelet-server
   #:start-debug-server
   #:start-kubelet-server
   #:start-server
   #:stop-debug-server
   #:stop-node-grpc-server
   #:stop-kubelet-server
   #:stop-server)
  (:export
   #:node-grpc-server-port
   #:node-session-acknowledged-revision
   #:publish-node-desired-state
   #:start-node-grpc-server
   #:stop-node-grpc-server))
;;; The WireGuard overlay topology planner -- direct-peer adjacency and
;;; deterministic next-hop selection over an overlay-node graph -- now lives in
;;; the standalone cl-wireguard-overlay library (installed via ocicl).  gr8s
;;; feeds it overlay-nodes derived from Kubernetes node-records (see
;;; node-record->overlay-node) and keeps its own node-record locality helpers, so
;;; we re-home the library's topology API into gr8s.apiserver and the composition
;;; package here, before node-session.lisp loads.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((symbols (mapcar (lambda (name)
                           (or (find-symbol name '#:cl-wireguard-overlay)
                               (error "cl-wireguard-overlay does not provide ~A, which gr8s requires." name)))
                         (list
                          "COPY-OVERLAY-NODE"
                          "COPY-WIREGUARD-TOPOLOGY-PLAN"
                          "MAKE-OVERLAY-NODE"
                          "MAKE-WIREGUARD-TOPOLOGY-PLAN"
                          "OVERLAY-NODE"
                          "OVERLAY-NODE-NAME"
                          "OVERLAY-NODE-P"
                          "OVERLAY-NODE-REGION"
                          "OVERLAY-NODE-ZONE"
                          "PLAN-WIREGUARD-TOPOLOGY"
                          "WIREGUARD-TOPOLOGY-ADD-EDGE"
                          "WIREGUARD-TOPOLOGY-ADD-RING"
                          "WIREGUARD-TOPOLOGY-NEIGHBORS"
                          "WIREGUARD-TOPOLOGY-NEXT-HOP"
                          "WIREGUARD-TOPOLOGY-OBJECT"
                          "WIREGUARD-TOPOLOGY-PLAN"
                          "WIREGUARD-TOPOLOGY-PLAN-ADJACENCY"
                          "WIREGUARD-TOPOLOGY-PLAN-MODE"
                          "WIREGUARD-TOPOLOGY-PLAN-NODES"
                          "WIREGUARD-TOPOLOGY-PLAN-OBJECT"
                          "WIREGUARD-TOPOLOGY-PLAN-P"
                          "WIREGUARD-TOPOLOGY-PLAN-TRANSIT-NODES"
))))
    (shadowing-import symbols '#:gr8s.apiserver)
    (export symbols '#:gr8s.apiserver)))
