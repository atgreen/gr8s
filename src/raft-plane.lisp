;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The consistency-plane split for the HA control plane (podster-c2d.5). Not
;;;; all cluster state needs linearizable consensus, and forcing it all through
;;;; one Raft log is exactly what makes monolithic etcd the scaling bottleneck.
;;;; gr8s already separates desired state (what the control plane decides) from
;;;; observed state (what agents report); this module makes that split explicit
;;;; at the datastore boundary:
;;;;
;;;;   * CONSENSUS plane -- durable API objects (the stored resource types):
;;;;     small, low-write, must be linearizable. These are proposed through Raft
;;;;     (podster-c2d.4) so every member converges.
;;;;   * LOCAL plane -- observed Pod status, endpoint telemetry, node
;;;;     heartbeats/leases, and expiring Events: high-churn, loss-tolerant, and
;;;;     reconstructable from the agents that report them. These bypass consensus
;;;;     (kept per-member / gossiped / re-derived), keeping the Raft log tiny.
;;;;
;;;; This module only classifies and routes; the leader-aware HTTP/controller
;;;; wiring that calls it is podster-c2d.7.

(in-package #:gr8s)

;; *RAFT-LOCAL-PLANE-RESOURCES* lives in core-resources.lisp (loaded before this
;; file) so the replication blob and INSTALL-CORE-STATE-BLOB can filter on it.

(defun raft-consensus-resource-p (resource)
  "True when writes to RESOURCE (a stored-resource plural like \"configmaps\")
   must go through Raft. Every stored resource type is consensus state except
   those explicitly placed on the local plane."
  (and (assoc resource *stored-resource-types* :test #'equal)
       (not (member resource *raft-local-plane-resources* :test #'equal))
       t))

;;; Observed/telemetry state is never an API resource write -- it arrives from
;;; agents as status/telemetry -- so it is local-plane by construction. These
;;; predicates name the categories for the routing layer and for documentation.
(defun raft-local-plane-category-p (category)
  "True for state categories that are always off-consensus."
  (member category '(:observed-status :endpoint-telemetry :node-heartbeat :node-lease)
          :test #'eq))

(defstruct raft-plane
  "Routes an operation to the consensus plane (Raft) or the local plane."
  consensus-fn                         ; (lambda (op) ...) propose through Raft, return result
  local-fn)                            ; (lambda (op) ...) apply locally, return result

(defun raft-plane-submit (plane resource op)
  "Route OP for RESOURCE to the consensus or local plane and return its result."
  (if (raft-consensus-resource-p resource)
      (funcall (raft-plane-consensus-fn plane) op)
      (funcall (raft-plane-local-fn plane) op)))

;;; ---------------------------------------------------------------------------
;;; Leader-aware HTTP (podster-c2d.7). Consensus writes must be served by the
;;; leader; a follower sends the client to the leader with a 307 so the method
;;; and body are preserved. Reads are served locally (a follower's replica is
;;; consistent as of its applied index). This is the pure routing decision; the
;;; HTTP layer wires it into its dispatch.

(defun raft-mutating-method-p (method)
  "True for HTTP methods that mutate state and so must reach the leader. METHOD
   is a keyword (:get :post ...) or a string; GET/HEAD/OPTIONS are reads."
  (let ((name (string-upcase (string method))))
    (not (member name '("GET" "HEAD" "OPTIONS") :test #'string=))))

(defun raft-leader-redirect-url (method request-uri self-leader-p leader-base-url)
  "The absolute URL a mutating request should be redirected to, or NIL to serve
   it here. Returns NIL on the leader, for a read, or when the leader is unknown
   (LEADER-BASE-URL NIL -- the caller then answers 503, since there is no leader
   to forward to). REQUEST-URI is the path+query; LEADER-BASE-URL is like
   \"https://10.0.0.2:6443\"."
  (when (and (not self-leader-p)
             (raft-mutating-method-p method)
             leader-base-url)
    (concatenate 'string
                 (string-right-trim "/" leader-base-url)
                 (if (and (plusp (length request-uri)) (char= (char request-uri 0) #\/))
                     request-uri
                     (concatenate 'string "/" request-uri)))))
