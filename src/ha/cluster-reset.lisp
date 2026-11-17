;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.ha)

;;; podster-0d9: a committed voter whose host is gone forever leaves the
;;; survivors without a quorum. No leader can be elected, so nothing commits --
;;; including the membership change that would remove the dead voter -- and a
;;; restarted member blocks in "waiting for committed application recovery"
;;; with the API never starting. `serve --cluster-reset` is the escape hatch:
;;; before any member or listener starts, it rewrites the durable membership to
;;; the sole local voter, the moral equivalent of k3s's --cluster-reset.

(defun raft-config-command-p (command)
  (and (consp command) (eq :raft-config (first command))))

(defun sole-voter-snapshot-state (state id)
  "STATE's snapshot envelope with ID as the only member, a voter. The
   application reference is untouched: the retained snapshot artifact on disk
   keeps backing the baseline. Other members' addresses and API URLs go with
   them, and no promotion intent survives."
  (let* ((plist (copy-list (cddr state)))
         (self-address (assoc id (getf plist :addresses) :test #'equal))
         (self-api-url (assoc id (getf plist :api-urls) :test #'equal)))
    (setf (getf plist :members) (list (cons id :voter))
          (getf plist :addresses) (when self-address (list self-address))
          (getf plist :api-urls) (when self-api-url (list self-api-url))
          (getf plist :promotions) nil)
    (list* (first state) (second state) plist)))

(defun reset-control-plane-membership (root id)
  "Rewrite the control-plane WAL under ROOT so ID is the sole voter, offline.
   The caller owns the state directory and no member is running. Committed
   entries and the application baseline are preserved; committed membership
   changes are neutralized to no-ops so replay cannot resurrect the old
   configuration, uncommitted entries (an in-flight membership change among
   them) are dropped, and the hard-state term is bumped past everything the
   lost members ever saw. Returns the removed member ids, NIL when ID was
   already alone. Idempotent."
  (let ((wal (merge-pathnames "raft/control-plane.log" root)))
    (unless (probe-file wal)
      (error "Cluster reset requires an existing control-plane WAL (~A); it cannot found a cluster" wal))
    (let ((storage (open-file-raft-storage wal)))
      (unwind-protect
           (let* ((recovered (load-raft-log wal :repair-storage storage))
                  (state (raft-recovered-snapshot-state recovered)))
             (unless (gr8s.raft::raft-snapshot-envelope-p state)
               (error "Cluster reset requires a snapshot-enveloped control-plane WAL"))
             (let* ((commit (raft-recovered-commit-index recovered))
                    (committed (remove-if (lambda (entry) (> (raft-entry-index entry) commit))
                                          (raft-recovered-entries recovered)))
                    ;; The durable membership is the LAST committed config
                    ;; change, falling back to the snapshot envelope's.
                    (last-config (find-if #'raft-config-command-p committed
                                          :key #'raft-entry-command :from-end t))
                    (members (if last-config
                                 (getf (rest (raft-entry-command last-config)) :members)
                                 (getf (cddr state) :members))))
               (unless (assoc id members :test #'equal)
                 (error "Member ~A is not in the durable membership (~{~A~^, ~})"
                        id (mapcar #'car members)))
               (let ((entries
                       (map 'vector
                            (lambda (entry)
                              (if (raft-config-command-p (raft-entry-command entry))
                                  (make-raft-entry :index (raft-entry-index entry)
                                                   :term (raft-entry-term entry)
                                                   :command '(:store-recovery-barrier))
                                  entry))
                            committed)))
                 ;; The WAL rewrite byte-copies any entry with a cached frame,
                 ;; which would resurrect the original membership commands at
                 ;; their unchanged index and term. Clearing the cache forces
                 ;; every entry through full re-serialization.
                 (clrhash (gr8s.raft::file-raft-storage-entry-frames storage))
                 (gr8s.raft::raft-storage-replace-snapshot
                  storage
                  (raft-recovered-snapshot-index recovered)
                  (raft-recovered-snapshot-term recovered)
                  (sole-voter-snapshot-state state id)
                  (1+ (max (raft-recovered-term recovered)
                           (raft-recovered-snapshot-term recovered)))
                  nil entries :commit-index commit)
                 (remove id (mapcar #'car members) :test #'equal))))
        (close-file-raft-storage storage)))))

(defun ha-recovery-wait-report (hcp)
  "Why committed application recovery is still waiting, as lines for the log:
   the quorum arithmetic, each durable member, and which peers this member has
   never heard from. Printed by the serve startup wait so a quorum lost forever
   is diagnosable from the journal alone (podster-0d9)."
  (let ((member (ha-control-plane-member hcp)))
    (bt:with-lock-held ((raft-member-lock member))
      (let* ((node (raft-member-node member))
             (id (raft-node-id node))
             (peers (raft-node-peers node))
             (descriptions
               (cons (format nil "~A (this member)" id)
                     (mapcar
                      (lambda (peer)
                        (let* ((address (gethash peer (raft-node-peer-addresses node)))
                               (link (gethash peer (gr8s.raft.transport::raft-member-links member)))
                               (heard (and link (plusp (gr8s.raft.transport::raft-peer-link-received-messages link)))))
                          (format nil "~A~@[ (~{~A~^:~})~]~:[, not heard from since startup~;, in contact~]"
                                  peer address heard)))
                      peers))))
        (format nil "gr8s HA: waiting for a quorum: ~D of ~D voting member~:P needed; ~{~A~^; ~}~
                     ~@[~%~A~]~
                     ~%gr8s HA: if the missing members are permanently gone, restart this member with --cluster-reset to continue alone"
                (raft-majority node) (raft-cluster-size node) descriptions
                (ha-catchup-transfer-line member node))))))

(defun ha-catchup-transfer-line (member node)
  "One journal line describing a joiner's snapshot catch-up, or NIL: progress
while chunks arrive, and -- the silent stall podster-84o is about -- an explicit
warning when an admitted learner has received nothing, whose usual cause is a
firewalled raft port on this member (see `gr8s doctor`)."
  (let ((receiver (gr8s.raft.transport::raft-member-snapshot-receiver member)))
    (cond
      (receiver
       (format nil "gr8s HA: application snapshot transfer: ~D~@[ of ~D~] bytes received, last chunk ~Ds ago"
               (gr8s.raft.transport::raft-snapshot-receiver-offset receiver)
               (let ((total (gr8s.raft.transport::raft-snapshot-receiver-total receiver)))
                 (and (integerp total) (plusp total) total))
               (round (- (get-internal-real-time)
                         (gr8s.raft.transport::raft-snapshot-receiver-activity receiver))
                      internal-time-units-per-second)))
      ((eq :learner (gr8s.raft::raft-node-self-role node))
       "gr8s HA: admitted, but no application snapshot bytes have arrived; check that this member's raft port is reachable from the leader ('gr8s doctor' checks the host firewall)"))))
