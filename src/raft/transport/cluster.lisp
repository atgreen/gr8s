;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Cluster bootstrap over the ag-gRPC Raft transport (podster-c2d.6): form a
;;;; new cluster from a single member, and grow or shrink it at runtime. The
;;;; transport in raft-transport.lisp wires a FIXED peer set up front; this layer
;;;; makes membership dynamic by reconciling per-peer delivery links against the
;;;; Raft core's live configuration whenever it changes.
;;;;
;;;; Two things have to travel together for a member to join a running cluster:
;;;;   * the membership itself (handled by the Raft config change in raft.lisp),
;;;;     so the joiner is counted for quorum only once its entry commits; and
;;;;   * every member's network ADDRESS, so each one can open a link to reach the
;;;;     joiner (and the joiner can reply to the leader and vote). Addresses ride
;;;;     along in the config command's :addresses, so when the entry commits every
;;;;     member learns where the new peer lives and opens a link to it.
;;;;
;;;; The core calls back through ON-CONFIGURED after every membership change; we
;;;; point that at RAFT-MEMBER-RECONCILE-LINKS, which opens any missing links from
;;;; the address book. Links are only ever ADDED here: the core simply stops
;;;; sending to a member once it leaves the configuration, so a now-unused link
;;;; idles harmlessly rather than needing a careful teardown mid-change.

(in-package #:gr8s.raft.transport)

(defun raft-member-open-link (member id host port)
  "Open a peer link under the member lock, retaining its role during departure."
  (let* ((node (raft-member-node member))
         (role (or (gethash id (raft-node-roles node)) (gethash id (raft-node-pending-members node))))
         (existing (gethash id (raft-member-links member))))
    (if existing
        (when role (setf (raft-peer-link-role existing) role))
        (let ((link (make-raft-peer-link :id id :host host :port port :role (or role :voter))))
          (setf (gethash id (raft-member-links member)) link
                (raft-peer-link-thread link)
                (bt:make-thread (lambda () (raft-link-sender-loop member link))
                                :name (format nil "gr8s raft link ~A->~A" (raft-node-id node) id)))))))

(defun raft-member-reconcile-links (member)
  "Open a link to every member in the address book we can reach but do not yet
   have one for. Called by the core's ON-CONFIGURED hook (with the member lock
   held) after a membership change, and by the bootstrap entry points below."
  (let* ((node (raft-member-node member))
         (self (raft-node-id node)))
    (loop for id being the hash-keys of (raft-node-peer-addresses node) using (hash-value addr)
          unless (equal id self)
            do (raft-member-open-link member id (first addr) (second addr)))))

(defun raft-member-enable-dynamic-membership (member &key pki)
  "Point the core's config-change callback at link reconciliation, record self in
   the address book, and install the Join handler so this member can admit (or
   redirect) joiners once it becomes leader. Caller holds the member lock."
  (let ((node (raft-member-node member)))
    (setf (raft-node-on-configured node)
          (lambda (n) (declare (ignore n)) (raft-member-reconcile-links member))
          (gethash (raft-node-id node) (raft-node-peer-addresses node))
          (list (raft-member-host member) (raft-member-port member))))
  (raft-cluster-install-join-handler member :pki pki))

(defun raft-cluster-init (member &key (role :voter) pki api-url)
  "Form a brand-new cluster from MEMBER alone: it is the sole voter and, once
   RAFT-MEMBER-START drives its clock, elects itself leader. It also answers Join
   RPCs (authenticating with PKI when given) so other members can be admitted;
   additional members are brought in with RAFT-CLUSTER-JOIN or -ADD-MEMBER.
   API-URL is this member's HTTP API base URL, replicated for leader redirects."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-member-enable-dynamic-membership member :pki pki)
    (let ((node (raft-member-node member)))
      (when api-url (setf (gethash (raft-node-id node) (raft-node-api-urls node)) api-url))
      (raft-configure node (list (cons (raft-node-id node) role))))))

(defun raft-member-leader-api-url (member)
  "The HTTP API base URL of the current Raft leader, as this member knows it, or
   NIL (including when this member is itself the leader)."
  (bt:with-lock-held ((raft-member-lock member))
    (let* ((node (raft-member-node member))
           (leader (raft-node-leader-id node)))
      (when (and leader (not (equal leader (raft-node-id node))))
        (gethash leader (raft-node-api-urls node))))))

(defun raft-cluster-prepare-joiner (member seed-addresses &key pki)
  "Prepare a fresh MEMBER to join an existing cluster. SEED-ADDRESSES is an alist
   id->(host port) for the members it already knows (at least the leader), learned
   out of band through the join/token handshake. The joiner starts as a LEARNER so
   it never self-elects a rival single-node term while it waits to be admitted;
   the committed config promotes it to its real role. Links to the seeds are
   opened now so it can reply to the leader's first append before the add commits."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-member-enable-dynamic-membership member :pki pki)
    (let ((node (raft-member-node member)))
      (unless (member (gethash (raft-node-id node) (raft-node-roles node)) '(:voter :witness))
        (setf (raft-node-self-role node) :learner))
      (setf (raft-node-removed node) nil)
      (dolist (a seed-addresses)
        (setf (gethash (car a) (raft-node-peer-addresses node)) (cdr a)))
      (raft-member-reconcile-links member))))

(defun raft-cluster-admit-member (node id host port role &optional api-url)
  "Admit a requested voter as a learner. Caller holds the member lock."
  (unless (and (stringp id) (plusp (length id)) (stringp host) (plusp (length host))
               (typep port '(integer 1 65535)) (member role '(:voter :witness :learner)))
    (error "Invalid Raft admission endpoint or role"))
  (unless (raft-leader-p node) (return-from raft-cluster-admit-member (values nil :not-leader)))
  (let* ((existing (cdr (assoc id (raft-current-config node) :test #'equal)))
         (pending (gethash id (raft-node-pending-members node)))
         (address (gethash id (raft-node-peer-addresses node)))
         (target (if (eq role :voter) :learner role)))
    (when (or existing pending)
      (unless (and (equal address (list host port))
                   (or (null api-url) (equal api-url (gethash id (raft-node-api-urls node)))))
        (return-from raft-cluster-admit-member (values nil :identity-conflict)))
      (when (and existing
                 (or (eq existing role)
                     (and (eq role :voter) (eq existing :learner)
                          (eq :voter (gethash id (raft-node-promotion-intents node))))))
        (return-from raft-cluster-admit-member (values (raft-node-last-applied node) t)))
      (when pending
        (let* ((entry (loop for index from (1+ (raft-node-last-applied node)) to (raft-last-log-index node)
                            for command = (raft-entry-command (raft-log-entry node index))
                            when (and (consp command) (eq :raft-config (first command))) return command))
               (intent (cdr (assoc id (getf (cdr entry) :promotions) :test #'equal))))
          (return-from raft-cluster-admit-member
            (if (and (eq pending target) (eq intent (and (eq role :voter) :voter)))
                (values (raft-last-log-index node) t) (values nil :role-conflict)))))
      (unless (and (eq existing :learner) (eq role :voter))
        (return-from raft-cluster-admit-member (values nil :role-conflict))))
    (raft-propose-config node :add id :role target :address (list host port) :api-url api-url
                             :promotion-role (and (eq role :voter) :voter))))

(defun raft-cluster-add-member (member id host port &key (role :voter))
  "Admit a member; voters first catch up as learners without changing quorum."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-cluster-admit-member (raft-member-node member) id host port role)))

(defun raft-member-promote-learners (member)
  "Drive one bounded promotion step under the member lock, without blocking."
  (let ((node (raft-member-node member)))
    (when (and (raft-leader-p node)
               (or (plusp (hash-table-count (raft-node-promotion-intents node)))
                   (raft-config-change-in-flight-p node)))
      (cond
        ((/= (raft-node-current-term node) (raft-log-term node (raft-node-commit-index node)))
         ;; A retained current-term entry already supplies the barrier. Retrying
         ;; a disconnected quorum must not append another on each clock tick.
         (unless (= (raft-node-current-term node) (raft-last-log-term node))
           (raft-propose node '(:raft-barrier))))
        ((not (raft-config-change-in-flight-p node))
         (let ((id (first (sort (loop for id being the hash-keys of (raft-node-promotion-intents node)
                                     when (raft-peer-ready-for-promotion-p node id) collect id) #'string<))))
           (when id (raft-propose-config node :add id :role :voter))))))))

(defun raft-cluster-remove-member (member id)
  "Leader-side removal of member ID. Returns (values index t) once proposed, or
   (values nil reason)."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-propose-config (raft-member-node member) :remove id)))

(defun raft-cluster-members (member)
  "The current membership as an alist id->role, from this member's view."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-current-config (raft-member-node member))))

;;; ---------------------------------------------------------------------------
;;; Join handshake (podster-c2d.10): the network front for the add-member flow.

(defun raft-cluster-install-join-handler (member &key pki)
  "Make MEMBER answer Join RPCs (leader-side admission). A follower replies with
   the current leader's address so the joiner can retry there; the leader
   authenticates the joiner, proposes the add, and returns the member address book.
   A member using TLS requires the joiner's certificate; otherwise PKI, when given,
   validates a join token."
  (setf (raft-member-join-handler member)
        (lambda (request context) (raft-member-handle-join member request context :pki pki))))

(defun raft-member-handle-join (member request context &key pki)
  "Handle a Join RPC on MEMBER (see RAFT-CLUSTER-INSTALL-JOIN-HANDLER). Authenticates
   the joiner -- by its peer certificate when MEMBER uses TLS, else by validating its
   join token against PKI. A non-leader replies accepted=false with the last known
   leader's address so the joiner can retry there; the leader proposes the add-member
   config change and replies accepted=true with the member address book. Returns the
   JoinResponse."
  (let* ((node (raft-member-node member))
         (credentials (raft-member-credentials member))
         (id (gr8s.node.v1::member-id request))
         (host (gr8s.node.v1::host request))
         (port (gr8s.node.v1::port request))
         (role (cond ((string-equal "witness" (gr8s.node.v1::role request)) :witness)
                     ((string-equal "learner" (gr8s.node.v1::role request)) :learner)
                     ((member (gr8s.node.v1::role request) '("" "voter") :test #'string-equal) :voter)
                     (t (gr8s::pki-fail "invalid-member-role" "Unknown Raft join role"))))
         (node-name (gr8s.node.v1::node-name request))
         (token (gr8s.node.v1::join-token request))
         (api-url (gr8s.node.v1::api-url request)))
    (cond
      (credentials
       (unless (equal id (gr8s::authenticate-raft-peer credentials context))
         (gr8s::pki-fail
          "member-identity-mismatch"
          "Raft join for ~A used another member's certificate" id)))
      (pki (gr8s::validate-token pki token node-name)))
    (gr8s.server::validate-member-patch-admission member (gr8s.node.v1::patch-inventory-json request))
    (bt:with-lock-held ((raft-member-lock member))
      (if (not (raft-leader-p node))
          ;; Redirect: point the joiner at the leader we last heard from.
          (let* ((leader (raft-node-leader-id node))
                 (addr (and leader (gethash leader (raft-node-peer-addresses node)))))
            (make-instance 'gr8s.node.v1::join-response
                           :accepted nil
                           :leader-id (or leader "")
                           :leader-host (if addr (first addr) "")
                           :leader-port (if addr (second addr) 0)))
          (multiple-value-bind (index accepted)
              (raft-cluster-admit-member node id host port role (and (plusp (length api-url)) api-url))
            (declare (ignore index))
            (make-instance 'gr8s.node.v1::join-response
                           :accepted (eq t accepted)
                           :leader-id (raft-node-id node)
                           :members (raft-cluster-address-book-members node)))))))

(defun raft-cluster-address-book-members (node)
  "The current address book as a list of RaftMember proto messages."
  (loop for mid being the hash-keys of (raft-node-peer-addresses node) using (hash-value addr)
        collect (make-instance 'gr8s.node.v1::raft-member
                               :id mid :host (first addr) :port (second addr)
                               :role (string-downcase (symbol-name (or (gethash mid (raft-node-pending-members node)) (raft-member-role node mid)))))))

(defun raft-cluster-call-join (member host port &key node-name token (role :voter) api-url (timeout 5))
  "Dial HOST:PORT and send one Join request for MEMBER. Returns the JoinResponse."
  (let ((channel (gr8s::make-raft-channel
                  (raft-member-credentials member) host port timeout)))
    (unwind-protect
         (let* ((stub (gr8s.node.v1::make-raft-transport-stub channel))
                (request (make-instance 'gr8s.node.v1::join-request
                                        :member-id (raft-node-id (raft-member-node member))
                                        :host (raft-member-host member)
                                        :port (raft-member-port member)
                                        :role (string-downcase (symbol-name role))
                                        :node-name (or node-name "")
                                        :join-token (or token "")
                                        :api-url (or api-url "")
                                        :patch-inventory-json (if gr8s.patch:*manager*
                                                                  (gr8s.patch::octets (com.inuoe.jzon:stringify (gr8s.patch:inventory gr8s.patch:*manager*))) #()))))
           (values (gr8s.node.v1::raft-transport-join stub request :timeout timeout)))
      (ignore-errors (ag-grpc:channel-close channel)))))

(defun raft-cluster-join (member host port &key node-name token (role :voter) pki api-url
                                                (max-redirects 3) (timeout 5))
  "Join an existing cluster through its Join RPC at HOST:PORT (any member;
   followers redirect to the leader). MEMBER's gRPC server must already be
   running. On success, seeds the address book from the response so MEMBER can
   reach every peer, and returns T. Returns (values nil reason) otherwise."
  ;; Stay inert (a learner) through the round-trip so we never self-elect a
  ;; rival single-node term before the leader admits us.
  (bt:with-lock-held ((raft-member-lock member))
    (raft-member-enable-dynamic-membership member :pki pki)
    (let ((node (raft-member-node member)))
      (unless (member (gethash (raft-node-id node) (raft-node-roles node)) '(:voter :witness))
        (setf (raft-node-self-role node) :learner))))
  (loop with h = host and p = port
        for attempt from 0 to max-redirects
        for response = (raft-cluster-call-join member h p :node-name node-name
                                                          :token token :role role
                                                          :api-url api-url :timeout timeout)
        do (cond
             ((gr8s.node.v1::accepted response)
              (raft-cluster-prepare-joiner
               member
               (loop for m in (gr8s.node.v1::members response)
                     collect (cons (gr8s.node.v1::id m)
                                   (list (gr8s.node.v1::host m) (gr8s.node.v1::port m))))
               :pki pki)
              (return t))
             ((and (plusp (length (gr8s.node.v1::leader-host response)))
                   (< attempt max-redirects))
              (setf h (gr8s.node.v1::leader-host response)
                    p (gr8s.node.v1::leader-port response)))
             (t (return (values nil :no-leader))))))

(defun raft-member-propose-sync (member command &key (timeout 5))
  "Propose COMMAND on the leader and block until it commits, returning the
   state-machine result. The commit callback fires under the member lock (from
   the proposing or a delivery thread) and hands the result to this waiter
   through a separate mailbox lock, so there is no lock-order hazard. Returns
   (values result t index) on commit, (values nil :not-leader nil) if MEMBER is
   not the leader, or (values nil :timeout nil) if the entry does not commit in
   time."
  (let ((lock (bt:make-lock "gr8s raft propose-sync"))
        (cv (bt:make-condition-variable))
        (done nil) (result nil))
    (multiple-value-bind (index ok)
        (raft-member-propose member command
                             (lambda (r)
                               (bt:with-lock-held (lock)
                                 (setf result r done t)
                                 (bt:condition-notify cv))))
      (if (not ok)
          (values nil :not-leader nil)
          (bt:with-lock-held (lock)
            (let ((deadline (+ (get-internal-real-time)
                               (* timeout internal-time-units-per-second))))
              (loop until done
                    do (let ((remaining (/ (- deadline (get-internal-real-time))
                                           internal-time-units-per-second)))
                         (when (<= remaining 0) (return))
                         (bt:condition-wait cv lock :timeout remaining)))
              (if done
                  (values result t index)
                  (values nil :timeout nil))))))))
