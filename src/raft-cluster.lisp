;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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

(in-package #:gr8s)

(defun raft-member-open-link (member id host port)
  "Open and register a per-peer delivery link + sender thread (caller holds the
   member lock). Idempotent: a member that already has a link is left alone."
  (unless (gethash id (raft-member-links member))
    (let ((link (make-raft-peer-link :id id :host host :port port)))
      (setf (gethash id (raft-member-links member)) link
            (raft-peer-link-thread link)
            (bt:make-thread (lambda () (raft-link-sender-loop member link))
                            :name (format nil "gr8s raft link ~A->~A"
                                          (raft-node-id (raft-member-node member)) id))))))

(defun raft-member-reconcile-links (member)
  "Open a link to every member in the address book we can reach but do not yet
   have one for. Called by the core's ON-CONFIGURED hook (with the member lock
   held) after a membership change, and by the bootstrap entry points below."
  (let* ((node (raft-member-node member))
         (self (raft-node-id node)))
    (loop for id being the hash-keys of (raft-node-peer-addresses node) using (hash-value addr)
          unless (equal id self)
            do (raft-member-open-link member id (first addr) (second addr)))))

(defun raft-member-enable-dynamic-membership (member)
  "Point the core's config-change callback at link reconciliation and record
   self in the address book. Caller holds the member lock."
  (let ((node (raft-member-node member)))
    (setf (raft-node-on-configured node)
          (lambda (n) (declare (ignore n)) (raft-member-reconcile-links member))
          (gethash (raft-node-id node) (raft-node-peer-addresses node))
          (list (raft-member-host member) (raft-member-port member)))))

(defun raft-cluster-init (member &key (role :voter))
  "Form a brand-new cluster from MEMBER alone: it is the sole voter and, once
   RAFT-MEMBER-START drives its clock, elects itself leader. Additional members
   are brought in later with RAFT-CLUSTER-ADD-MEMBER."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-member-enable-dynamic-membership member)
    (raft-configure (raft-member-node member)
                    (list (cons (raft-node-id (raft-member-node member)) role)))))

(defun raft-cluster-prepare-joiner (member seed-addresses)
  "Prepare a fresh MEMBER to join an existing cluster. SEED-ADDRESSES is an alist
   id->(host port) for the members it already knows (at least the leader), learned
   out of band through the join/token handshake. The joiner starts as a LEARNER so
   it never self-elects a rival single-node term while it waits to be admitted;
   the committed config promotes it to its real role. Links to the seeds are
   opened now so it can reply to the leader's first append before the add commits."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-member-enable-dynamic-membership member)
    (let ((node (raft-member-node member)))
      (setf (raft-node-self-role node) :learner
            (raft-node-removed node) nil)
      (dolist (a seed-addresses)
        (setf (gethash (car a) (raft-node-peer-addresses node)) (cdr a)))
      (raft-member-reconcile-links member))))

(defun raft-cluster-add-member (member id host port &key (role :voter))
  "Leader-side admission of a new member ID at HOST:PORT (a voter or a witness).
   Records its address, opens a link to it, and proposes the single-member config
   change. Returns (values index t) once proposed, or (values nil reason) if this
   member is not the leader or a change is already in flight."
  (bt:with-lock-held ((raft-member-lock member))
    (let ((node (raft-member-node member)))
      (setf (gethash id (raft-node-peer-addresses node)) (list host port))
      (raft-propose-config node :add id :role role :address (list host port)))))

(defun raft-cluster-remove-member (member id)
  "Leader-side removal of member ID. Returns (values index t) once proposed, or
   (values nil reason)."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-propose-config (raft-member-node member) :remove id)))

(defun raft-cluster-members (member)
  "The current membership as an alist id->role, from this member's view."
  (bt:with-lock-held ((raft-member-lock member))
    (raft-current-config (raft-member-node member))))
