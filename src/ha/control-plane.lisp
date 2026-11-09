;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Tie a control-plane's durable store to a Raft member (podster-c2d.7.1): the
;;;; member replicates the consensus-plane state (c2d.7.2) and tells the rest of
;;;; the control plane who the leader is. 'gr8s serve' starts one of these only
;;;; in HA mode (--raft-* flags); without them the control plane runs exactly as
;;;; the single-node path always has, with no Raft member at all.
;;;;
;;;;   * The member's state machine installs replicated core-state blobs on the
;;;;     local store, so every member converges on the same desired state.
;;;;   * The store's consensus-commit-fn proposes each durable write through the
;;;;     member; on a follower the propose fails fast, which the HTTP layer turns
;;;;     into a redirect to the leader (c2d.7.3).
;;;;   * HA-CONTROL-PLANE-LEADER-P is the reconciliation worker's leader gate, so
;;;;     controllers run only on the leader (c2d.7.1).

(in-package #:gr8s.ha)

(defstruct ha-control-plane
  member
  store)

(defun start-ha-control-plane (store &key id (host "127.0.0.1") (port 0)
                                          init join-host join-port
                                          node-name token ca-pin pki api-url)
  "Start the control plane's Raft member bound to STORE and either found a new
   cluster (INIT) or join an existing one (JOIN-HOST/JOIN-PORT). Routes STORE's
   durable writes through the member and returns an HA-CONTROL-PLANE. Signals an
   error if a join does not succeed. With PKI, which 'gr8s serve' always supplies,
   members use mutual TLS under its Raft directory; a joiner enrolls with TOKEN,
   trusting CA-PIN. Without it they use plain gRPC, which only in-process tests do."
  ;; Enrollment can happen before any Pod needs a token. Founders must therefore
  ;; create the cluster key now so the first voter receives it with the other
  ;; shared private credentials.
  (when (and pki init) (gr8s::load-service-account-signing-key store))
  (let* ((member nil)
         (credentials
           (when pki
             (let ((root (gr8s::raft-tls-root pki)))
               (if init
                   (gr8s::ensure-raft-founder-credentials root id)
                   (gr8s::ensure-raft-joiner-credentials
                    root id join-host join-port
                    :node-name node-name :token token :ca-pin ca-pin
                    :node-root (gr8s::cluster-pki-root pki))))))
         (apply-fn (lambda (command)
                     (when (consp command)
                       (case (car command)
                         (:core-state (gr8s::install-core-state-blob store (second command)))
                         (:core-delta (gr8s::install-core-state-delta store (second command)))
                         ;; Install every committed state on every member. This is
                         ;; idempotent for a leader-local write and necessary when
                         ;; the leader committed a proposal forwarded by a follower.
                         (:pod-state (gr8s::install-pod-state-blob store (second command)))
                         (:pod-delta (gr8s::install-pod-state-delta store (second command)))
                         (:node-state (gr8s::install-node-state-blob store (second command)))
                         (:node-delta (gr8s::install-node-state-delta store (second command)))
                         ;; Enrollment is an operation rather than a follower-authored
                         ;; whole-index snapshot: allocation occurs at this exact log
                         ;; position against the same preceding state on every replica.
                         (:node-enrollment
                          (apply #'gr8s::install-node-enrollment-command
                                 store (second command))))))))
    (when credentials (setf (gr8s::raft-credentials-node-pki credentials) pki))
    (setf member (start-raft-member id :host host :port port :apply-fn apply-fn :credentials credentials
                                     :snapshot-directory (merge-pathnames "raft/transfers/" (gr8s::pod-store-path store))))
    (cond
      (init
       (raft-cluster-init member :api-url api-url)
       (raft-member-start member))
      (join-host
       ;; The member's server is already accepting appends; join (as a learner)
       ;; before driving the clock so it never self-elects a rival term.
       (unless (raft-cluster-join member join-host join-port
                                  :node-name node-name :token token :api-url api-url)
         (stop-raft-member member)
         (error "control plane ~A could not join the cluster at ~A:~D" id join-host join-port))
       (raft-member-start member))
      (t (stop-raft-member member)
         (error "start-ha-control-plane requires :init or :join-host")))
    ;; Durable writes now go through Raft: the leader proposes and commits; a
    ;; follower proposals are forwarded to the leader. TAG is :core-delta,
    ;; :pod-state, or :node-delta; each committed command applies on every replica.
    (setf (gr8s::pod-store-consensus-commit-fn store)
          (lambda (tag json)
            (multiple-value-bind (result committed)
                (if (raft-member-leader-p member)
                    (raft-member-propose-sync member (list tag json) :timeout 10)
                    (raft-member-forward-propose-sync member (list tag json) :timeout 10))
              ;; PROPOSE-SYNC returns T only on commit; a reason keyword
              ;; (:not-leader / :timeout) otherwise -- both truthy, so test for T.
              (unless (eq committed t)
                (gr8s::core-resource-error
                 503 "ServiceUnavailable"
                 "This control-plane member is not the Raft leader"))
              result)))
    (make-ha-control-plane :member member :store store)))

(defun ha-control-plane-leader-p (hcp)
  "True when this control-plane member currently holds Raft leadership."
  (and hcp (raft-member-leader-p (ha-control-plane-member hcp))))

(defun ha-control-plane-leader-status (hcp)
  "Return (values self-leader-p leader-api-url) for the HTTP leader-aware layer."
  (if hcp
      (values (raft-member-leader-p (ha-control-plane-member hcp))
              (raft-member-leader-api-url (ha-control-plane-member hcp)))
      (values t nil)))

(defun ha-control-plane-node-endpoints (hcp node-port)
  "Return every known control-plane node endpoint as (HOST PORT), with this
   member first. Raft and node gRPC use different ports but the same advertised
   host. A local agent must enroll locally because its one-time node token lives
   in this member's PKI store; subsequent follower writes are forwarded through
   Raft, and the remaining endpoints retain session failover coverage."
  (let ((member (ha-control-plane-member hcp)))
    (bt:with-lock-held ((raft-member-lock member))
      (let* ((node (raft-member-node member))
             (self (raft-node-id node))
             (members
               (sort
                (loop for id being the hash-keys of (raft-node-peer-addresses node)
                        using (hash-value address)
                      collect (cons id (list (first address) node-port)))
                #'string< :key #'car))
             (self-entry (assoc self members :test #'equal)))
        (mapcar #'cdr
                (if self-entry
                    (cons self-entry (remove self-entry members :test #'eq))
                    members))))))

(defun ha-control-plane-node-session-endpoints (hcp node-port)
  "Return control-plane node endpoints with the currently known Raft leader first.
Enrollment remains local-first because its token is member-local; after enrollment,
agents session with the leader so all observed readiness is visible to the active
API and controllers. Remaining members retain reconnect failover coverage."
  (let ((member (ha-control-plane-member hcp)))
    (bt:with-lock-held ((raft-member-lock member))
      (let* ((node (raft-member-node member))
             (leader (raft-node-leader-id node))
             (members
               (sort
                (loop for id being the hash-keys of (raft-node-peer-addresses node)
                        using (hash-value address)
                      collect (cons id (list (first address) node-port)))
                #'string< :key #'car))
             (leader-entry (and leader (assoc leader members :test #'equal))))
        (mapcar #'cdr
                (if leader-entry
                    (cons leader-entry (remove leader-entry members :test #'eq))
                    members))))))

(defun stop-ha-control-plane (hcp)
  "Tear down the HA control plane: detach the store's consensus commit hook so no
further writes are proposed to Raft, then stop the member. A no-op when HCP is NIL."
  (when hcp
    (setf (gr8s::pod-store-consensus-commit-fn
           (ha-control-plane-store hcp)) nil)
    (stop-raft-member (ha-control-plane-member hcp))))
