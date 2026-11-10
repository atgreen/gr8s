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
;;;;   * The store's consensus-commit-fn proposes durable writes through the member,
;;;;     forwarding follower-authored internal writes to the leader. The HTTP
;;;;     layer redirects ordinary follower mutation requests (c2d.7.3).
;;;;   * HA-CONTROL-PLANE-LEADER-P is the reconciliation worker's leader gate, so
;;;;     controllers run only on the leader (c2d.7.1).

(in-package #:gr8s.ha)

(defstruct ha-control-plane
  member store
  compaction-thread compaction-running
  (compaction-lock (bt:make-lock "gr8s HA compaction"))
  (compaction-changed (bt:make-condition-variable :name "gr8s HA compaction"))
  (compaction-bytes (* 16 1024 1024)) (compaction-entries 256) (compaction-interval 1)
  (compaction-count 0) (compaction-reaped 0) compaction-error)

(defun member-snapshot-artifact-matches-p (state index term digest)
  (and (gr8s.raft::raft-snapshot-envelope-p state)
       (eq t (getf (cddr state) :application-present))
       (handler-case (progn (gr8s.raft::raft-validate-snapshot-envelope state) t) (error () nil))
       (equal (getf (cddr state) :application)
              (list :gr8s-store-artifact 1 :index index :term term :sha256 digest))))

(defun make-member-generation-validator (member transfer-term expected-index expected-term expected-digest &key recover)
  "Bind a staged generation to the transfer/WAL identity and current member state.
The caller supplies the authenticated transfer's boundary/digest, not values read
back from the generation being checked. Invoke under MEMBER's lock, after outer
application ingress/writer barriers. This function neither persists nor adopts Raft state."
  (unless (and (member recover '(nil t))
               (typep transfer-term '(integer 0 #.most-positive-fixnum))
               (typep expected-index (if recover '(integer 0 #.most-positive-fixnum) '(integer 1 #.most-positive-fixnum)))
               (typep expected-term '(integer 0 #.most-positive-fixnum))
               (or (plusp expected-index) (zerop expected-term))
               (<= expected-term transfer-term)
               (stringp expected-digest) (= 64 (length expected-digest))
               (every (lambda (char) (find char "0123456789abcdef")) expected-digest))
    (error "Invalid expected application snapshot identity"))
  ;; Do not retain a caller-mutable digest string in the validation capability.
  (let ((digest (copy-seq expected-digest)))
    (lambda (descriptor store)
      (declare (ignore store))
      (unless (sb-thread:holding-mutex-p (raft-member-lock member))
        (error "Application snapshot validation requires the current member lock"))
      (unless (and (hash-table-p descriptor)
                   (eql expected-index (gethash "index" descriptor))
                   (eql expected-term (gethash "term" descriptor))
                   (equal digest (gethash "artifactSha256" descriptor)))
        (error "Staged generation differs from the expected application snapshot"))
      (let* ((node (raft-member-node member))
             (floor (max (raft-node-commit-index node) (raft-node-last-applied node)
                         (raft-node-snapshot-index node)))
             (floor-term (raft-log-term node floor))
             (pending (raft-node-snapshot-pending node)))
        (unless (and (<= (raft-node-snapshot-index node) (raft-node-last-applied node)
                          (raft-node-commit-index node) (raft-last-log-index node))
                     (or (= floor (raft-node-snapshot-index node)) (raft-log-entry node floor))
                     (<= expected-term (raft-node-current-term node))
                     floor-term (<= floor-term expected-term)
                     (>= expected-index floor))
          (error "Application snapshot is incompatible with the current member boundary"))
        (cond
          (pending
           (destructuring-bind (index term state entries) pending
             (declare (ignore entries))
             (unless (and (= index expected-index) (= term expected-term)
                          (member-snapshot-artifact-matches-p state expected-index expected-term digest))
               (error "Another durable application snapshot is pending"))))
          (recover
           (unless (and (= expected-index floor (raft-node-snapshot-index node))
                        (= expected-term (raft-node-snapshot-term node))
                        (member-snapshot-artifact-matches-p (raft-node-snapshot-state node) expected-index expected-term digest))
             (error "Recovery generation does not match the member's durable snapshot")))
          (t
           (unless (and (eq :follower (raft-node-role node))
                        (= transfer-term (raft-node-current-term node))
                        (> expected-index floor))
             (error "Application snapshot does not advance the committed/applied boundary")))))
      t)))

(defun make-store-raft-apply-function (store)
  "Use the same deterministic application dispatcher for new and recovered members."
  (lambda (command)
    (when (consp command)
      (case (car command)
        (:store-recovery-barrier :recovered)
        (:core-state (gr8s::install-core-state-blob store (second command)))
        (:core-delta (gr8s::install-core-state-delta store (second command)))
        (:secrets-encryption (gr8s::install-secret-encryption-command store (second command)))
        (:pod-state (gr8s::install-pod-state-blob store (second command)))
        (:pod-delta (gr8s::install-pod-state-delta store (second command)))
        (:node-state (gr8s::install-node-state-blob store (second command)))
        (:node-delta (gr8s::install-node-state-delta store (second command)))
        (:image-tracker
         (gr8s.image-distribution::tracker-apply-command (gr8s::pod-store-image-tracker store) (second command)))
        (:node-enrollment (apply #'gr8s::install-node-enrollment-command store (second command)))))))

(defun make-store-raft-commit-function (member)
  (lambda (tag json)
    (multiple-value-bind (result committed)
        (if (raft-member-leader-p member)
            (raft-member-propose-sync member (list tag json) :timeout 10)
            (raft-member-forward-propose-sync member (list tag json) :timeout 10))
      (unless (eq committed t)
        (if (eq committed :proposal-too-large)
            (gr8s::core-resource-error 413 "RequestEntityTooLarge" "Write exceeds the control-plane proposal byte limit")
            (gr8s::core-resource-error 503 "ServiceUnavailable"
                                      (if (eq committed :capacity)
                                          "Control-plane pending write capacity is full; retry after quorum recovers"
                                          "The control-plane write could not commit"))))
      result)))

(defun control-plane-store-bootstrap-role (store id init api-url)
  "Choose fresh/journaled bootstrap without resetting a published member WAL."
  (let* ((root (gr8s::pod-store-path store))
         (wal (merge-pathnames "raft/control-plane.log" root))
         (journal (merge-pathnames "raft/bootstrap.json" root))
         (role (if init :founder :learner))
         (wal-stat (gr8s.store::store-generation-stat wal)))
    (if (gr8s.store::store-generation-stat journal)
        (let* ((record (gr8s.store::read-private-generation-json journal))
               (published (equal "published" (gethash "phase" record)))
               (stored-role (gethash "role" record)))
          (unless (member stored-role '("founder" "learner") :test #'equal)
            (error "Invalid control-plane bootstrap role"))
          (gr8s.resources::validate-store-member-bootstrap
           record id (if published stored-role (if init "founder" "learner")) (or api-url ""))
          (if published
              (progn
                (unless wal-stat (error "Published control-plane WAL is missing"))
                nil)
              role))
        (progn
          (when wal-stat (error "Control-plane WAL has no bootstrap journal"))
          role))))

(defun start-ha-control-plane (store &key id (host "127.0.0.1") (port 0)
                                          init join-host join-port
                                          node-name token ca-pin pki api-url
                                          (compaction-bytes (* 16 1024 1024))
                                          (compaction-entries 256) (compaction-interval nil))
  "Start an artifact-backed durable Raft member before application ingress.
Fresh founders bootstrap one voter; fresh joiners bootstrap a learner. Restart
restores the durable membership and application baseline, without reinitializing
the cluster. Access stays gated until a current-term committed boundary applies."
  (unless (and (or init join-host) (not (and init join-host)))
    (error "start-ha-control-plane requires exactly one of :init or :join-host"))
  (validate-ha-compaction-options compaction-bytes compaction-entries compaction-interval)
  (let* ((bootstrap-role (control-plane-store-bootstrap-role store id init api-url))
         (member nil) (hcp nil) (completed nil)
         (credentials
           (when pki
             (when (and init bootstrap-role) (gr8s::load-service-account-signing-key store))
             (let ((root (gr8s::raft-tls-root pki)))
               (if init
                   (gr8s::ensure-raft-founder-credentials root id)
                   (gr8s::ensure-raft-joiner-credentials
                    root id join-host join-port
                    :node-name node-name :token token :ca-pin ca-pin
                    :node-root (gr8s::cluster-pki-root pki)))))))
    (when credentials (setf (gr8s::raft-credentials-node-pki credentials) pki))
    (unwind-protect
         (progn
           (setf member
                 (apply #'gr8s.resources::start-store-member-from-wal
                        store id (merge-pathnames "raft/control-plane.log" (gr8s::pod-store-path store))
                        :host host :port port :credentials credentials
                        :snapshot-directory (merge-pathnames "raft/transfers/" (gr8s::pod-store-path store))
                        (when bootstrap-role
                          (list :bootstrap-role bootstrap-role :bootstrap-api-url api-url))))
           (bt:with-lock-held ((raft-member-lock member))
             (setf (gr8s.raft::raft-node-uncommitted-byte-limit (raft-member-node member)) (* 16 1024 1024))
             (raft-member-enable-dynamic-membership member :pki pki))
           ;; Only a learner still awaiting admission needs Join. Recovered voters
           ;; reconnect using the durable address book, without enrollment tokens
           ;; or an accidental single-member configuration reset.
           (when (and join-host (eq :learner (gr8s.raft::raft-node-self-role (raft-member-node member))))
             (unless (raft-cluster-join member join-host join-port
                                       :node-name node-name :token token :api-url api-url)
               (error "control plane ~A could not join the cluster at ~A:~D" id join-host join-port)))
           (raft-member-start member)
           (setf hcp (make-ha-control-plane :member member :store store
                                           :compaction-bytes compaction-bytes
                                           :compaction-entries compaction-entries
                                           :compaction-interval compaction-interval))
           (when compaction-interval (start-ha-compaction-worker hcp))
           (setf completed t)
           hcp)
      (unless completed
        (when hcp (stop-ha-compaction-worker hcp))
        (when member (stop-raft-member member))))))

(defun ha-control-plane-leader-p (hcp)
  "True only for an elected leader whose recovered application is ready."
  (and hcp (not (gr8s.store::store-access-blocked-p (ha-control-plane-store hcp)))
       (raft-member-leader-p (ha-control-plane-member hcp))))

(defun ha-control-plane-leader-status (hcp)
  "Return leader routing only after this member's application recovery gate opens."
  (cond ((null hcp) (values t nil))
        ((gr8s.store::store-access-blocked-p (ha-control-plane-store hcp)) (values nil nil))
        (t (values (raft-member-leader-p (ha-control-plane-member hcp))
                   (raft-member-leader-api-url (ha-control-plane-member hcp))))))

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
  "Stop Raft and block application access, retaining the fail-closed commit hook."
  (when hcp
    (let ((store (ha-control-plane-store hcp)))
      ;; The hook stays attached to the stopped member. Even if another owner
      ;; later resumes access, shutdown cannot become local-only mutation.
      (stop-ha-compaction-worker hcp)
      (stop-raft-member (ha-control-plane-member hcp))
      (unless (gr8s.store::store-access-blocked-p store)
        (gr8s.store::quiesce-store-access store)))))
