;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for Raft peer transport and dynamic cluster membership.

(defpackage #:gr8s.raft.transport
  (:use #:cl #:gr8s.raft)
  (:export
   #:configure-raft-node-operation-routing
   #:make-raft-member
   #:make-raft-peer-link
   #:octets->raft-message
   #:raft-apply-error
   #:raft-apply-error-underlying
   #:raft-cluster-add-member
   #:raft-cluster-address-book-members
   #:raft-cluster-call-join
   #:raft-cluster-init
   #:raft-cluster-install-join-handler
   #:raft-cluster-join
   #:raft-cluster-members
   #:raft-cluster-prepare-joiner
   #:raft-cluster-remove-member
   #:raft-link-drop
   #:raft-link-drop-relay
   #:raft-link-enqueue
   #:raft-link-relay-operation
   #:raft-link-sender-loop
   #:raft-link-stub
   #:raft-link-wait-batch
   #:raft-member
   #:raft-member-credentials
   #:raft-member-enable-dynamic-membership
   #:raft-member-forward-propose-sync
   #:raft-member-grpc-server
   #:raft-member-handle-join
   #:raft-member-host
   #:raft-member-join-handler
   #:raft-member-leader-api-url
   #:raft-member-leader-p
   #:raft-member-links
   #:raft-member-lock
   #:raft-member-node
   #:raft-member-open-link
   #:raft-member-operation-server
   #:raft-member-port
   #:raft-member-propose
   #:raft-member-propose-sync
   #:raft-member-reconcile-links
   #:raft-member-renewal-thread
   #:raft-member-route-node-operation
   #:raft-member-running
   #:raft-member-server-thread
   #:raft-member-set-peers
   #:raft-member-start
   #:raft-member-tick-loop
   #:raft-member-tick-thread
   #:raft-member-wait-applied
   #:raft-message->octets
   #:raft-peer-link
   #:raft-peer-link-changed
   #:raft-peer-link-channel
   #:raft-peer-link-host
   #:raft-peer-link-id
   #:raft-peer-link-items
   #:raft-peer-link-lock
   #:raft-peer-link-port
   #:raft-peer-link-relay-channel
   #:raft-peer-link-relay-lock
   #:raft-peer-link-relay-stub
   #:raft-peer-link-stub
   #:raft-peer-link-thread
   #:start-raft-member
   #:stop-raft-member))

;; GR8S remains a compatibility facade while callers move to the subsystem
;; package. Importing the exact symbols keeps existing GR8S:: references valid.
