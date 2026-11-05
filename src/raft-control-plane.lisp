;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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

(in-package #:gr8s)

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
  (let* ((member nil)
         (credentials
           (when pki
             (let ((root (raft-tls-root pki)))
               (if init
                   (ensure-raft-founder-credentials root id)
                   (ensure-raft-joiner-credentials root id join-host join-port
                                                   :node-name node-name :token token :ca-pin ca-pin
                                                   :node-root (cluster-pki-root pki))))))
         (apply-fn (lambda (command)
                     (when (consp command)
                       (case (car command)
                         (:core-state (install-core-state-blob store (second command)))
                         ;; The leader already applied the Pod/node write locally
                         ;; before proposing; only followers install it (8ia.2/8ia.4).
                         ;; apply-fn runs under the member lock, so use the
                         ;; lock-free role predicate, not raft-member-leader-p
                         ;; (which would re-acquire the lock and deadlock).
                         (:pod-state (unless (raft-leader-p (raft-member-node member))
                                       (install-pod-state-blob store (second command))))
                         (:node-state (unless (raft-leader-p (raft-member-node member))
                                        (install-node-state-blob store (second command)))))))))
    (when credentials (setf (raft-credentials-node-pki credentials) pki))
    (setf member (start-raft-member id :host host :port port :apply-fn apply-fn :credentials credentials))
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
    ;; follower's propose returns :not-leader, surfaced to the HTTP layer. TAG is
    ;; :core-state or :pod-state; the proposed command installs on every replica.
    (setf (pod-store-consensus-commit-fn store)
          (lambda (tag json)
            (multiple-value-bind (result committed)
                (raft-member-propose-sync member (list tag json) :timeout 10)
              (declare (ignore result))
              ;; PROPOSE-SYNC returns T only on commit; a reason keyword
              ;; (:not-leader / :timeout) otherwise -- both truthy, so test for T.
              (unless (eq committed t)
                (core-resource-error 503 "ServiceUnavailable"
                                     "This control-plane member is not the Raft leader")))))
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

(defun stop-ha-control-plane (hcp)
  (when hcp
    (setf (pod-store-consensus-commit-fn (ha-control-plane-store hcp)) nil)
    (stop-raft-member (ha-control-plane-member hcp))))
