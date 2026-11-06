;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; A pure-Common-Lisp Raft consensus core for the gr8s HA control plane
;;;; (podster-c2d.1). It implements leader election, log replication, and
;;;; commit/apply per the Raft paper (§5), with the network transport and the
;;;; logical clock injected -- so the identical core runs under a deterministic
;;;; in-process simulator (tests: partitions, leader kills) and, later, under an
;;;; ag-gRPC transport adapter. No etcd, no external consensus.
;;;;
;;;; Indexing: the log is 1-based; index 0 is a sentinel with term 0. The
;;;; replicated state machine is supplied as APPLY-FN, invoked exactly once per
;;;; committed entry in log order; its result is handed back to the client that
;;;; proposed that entry (enabling linearizable compare-and-swap).

(in-package #:gr8s)

(defstruct raft-entry
  (term 0 :type fixnum)
  (index 0 :type fixnum)
  command)

(defstruct raft-node
  id                                    ; this member's id
  peers                                 ; list of the other members' ids
  (role :follower)                      ; :follower | :candidate | :leader
  (current-term 0 :type fixnum)
  (voted-for nil)
  (log (make-array 0 :adjustable t :fill-pointer 0))  ; vector of RAFT-ENTRY after snapshot-index
  (commit-index 0 :type fixnum)
  (last-applied 0 :type fixnum)
  ;; compaction: entries <= snapshot-index are discarded; snapshot-term is the
  ;; term of the last entry the snapshot includes. log[0] is index snapshot-index+1.
  (snapshot-index 0 :type fixnum)
  (snapshot-term 0 :type fixnum)
  leader-id
  ;; membership (podster-c2d.6). ROLES maps member-id -> :voter | :witness |
  ;; :learner; PEERS stays the quorum+replication set (voters+witnesses, so the
  ;; proven quorum/commit paths are unchanged for an all-voter cluster).
  ;; PENDING-MEMBERS are being added: replicated to, but not counted for quorum
  ;; until the config entry commits. A witness votes and counts for quorum but
  ;; never starts an election; a learner neither votes-weight nor leads.
  (roles (make-hash-table :test 'equal))
  (self-role :voter)
  (pending-members (make-hash-table :test 'equal))   ; id -> role
  ;; DEPARTING-MEMBERS are peers a committed config just dropped: the leader
  ;; keeps replicating the commit to them (id -> config-entry index) until they
  ;; apply it and learn they are removed, so they stop disrupting the new quorum.
  (departing-members (make-hash-table :test 'equal))
  (removed nil)
  ;; Transport glue (ignored by the deterministic in-process sim, where SEND-FN
  ;; routes by id). PEER-ADDRESSES maps member-id -> (host port), carried in the
  ;; config command so every member learns where to reach a joiner; ON-CONFIGURED
  ;; (if set) runs after a membership change so the transport can reconcile links.
  (peer-addresses (make-hash-table :test 'equal))
  ;; id -> HTTP API base URL, replicated in the config so every member can
  ;; redirect a write to the leader's API (podster-c2d.7.3).
  (api-urls (make-hash-table :test 'equal))
  on-configured
  ;; leader volatile
  (next-index (make-hash-table :test 'equal))
  (match-index (make-hash-table :test 'equal))
  ;; candidate volatile
  (votes (make-hash-table :test 'equal))
  ;; logical timers (ticks)
  (election-elapsed 0 :type fixnum)
  (heartbeat-elapsed 0 :type fixnum)
  (election-timeout 10 :type fixnum)
  (heartbeat-timeout 1 :type fixnum)
  ;; injectables
  send-fn                               ; (lambda (to message-plist))
  apply-fn                              ; (lambda (command) -> result)
  storage                               ; a RAFT-STORAGE for durable hard-state/log, or NIL
  snapshot-fn                           ; (lambda () -> opaque state-machine snapshot)
  restore-fn                            ; (lambda (snapshot)) restores the state machine
  (timeout-fn (lambda () 10))           ; -> next election timeout (randomized in prod)
  ;; leader: commit-index -> list of (client-callback . nil); resolved on apply
  (pending (make-hash-table :test 'eql)))

;;; ---------------------------------------------------------------------------
;;; Durable storage protocol (implemented by file-raft-storage in raft-log.lisp;
;;; NIL = volatile, used by the deterministic simulator). Raft requires
;;; currentTerm, votedFor and the log to survive a crash.

(defgeneric raft-storage-save-hard-state (storage term vote)
  (:method ((storage null) term vote) (declare (ignore term vote)) nil))
(defgeneric raft-storage-append-entry (storage entry)
  (:method ((storage null) entry) (declare (ignore entry)) nil))
(defgeneric raft-storage-truncate (storage index)
  (:method ((storage null) index) (declare (ignore index)) nil))
(defgeneric raft-storage-save-snapshot (storage index term state)
  (:method ((storage null) index term state) (declare (ignore index term state)) nil))

(defun raft-persist-hard-state (node)
  (raft-storage-save-hard-state (raft-node-storage node)
                                (raft-node-current-term node) (raft-node-voted-for node)))

;;; ---------------------------------------------------------------------------
;;; Log helpers (1-based, offset by snapshot-index for compaction).

(defun raft-log-length (node)
  "Absolute index of the last entry (snapshot-index + in-memory tail length)."
  (+ (raft-node-snapshot-index node) (fill-pointer (raft-node-log node))))

(defun raft-log-entry (node index)
  "The RAFT-ENTRY at absolute INDEX, or NIL if compacted/out of range."
  (let ((pos (- index (raft-node-snapshot-index node) 1)))
    (when (and (>= pos 0) (< pos (fill-pointer (raft-node-log node))))
      (aref (raft-node-log node) pos))))

(defun raft-log-term (node index)
  "Term of the entry at absolute INDEX; 0 at index 0; snapshot-term at/below the
   snapshot boundary."
  (cond ((zerop index) 0)
        ((= index (raft-node-snapshot-index node)) (raft-node-snapshot-term node))
        ((< index (raft-node-snapshot-index node)) (raft-node-snapshot-term node))
        (t (let ((e (raft-log-entry node index))) (if e (raft-entry-term e) 0)))))

(defun raft-last-log-index (node) (raft-log-length node))
(defun raft-last-log-term (node) (raft-log-term node (raft-log-length node)))

(defun raft-log-truncate (node index)
  "Drop every entry at absolute INDEX and beyond."
  (setf (fill-pointer (raft-node-log node))
        (max 0 (- index (raft-node-snapshot-index node) 1)))
  (raft-storage-truncate (raft-node-storage node) index))

(defun raft-log-append (node entry)
  (vector-push-extend entry (raft-node-log node))
  (setf (raft-entry-index entry) (raft-log-length node))
  (raft-storage-append-entry (raft-node-storage node) entry)
  entry)

;;; ---------------------------------------------------------------------------
;;; Snapshot / compaction.

(defun raft-compact (node upto)
  "Discard committed log entries at/below absolute index UPTO, folding them into
   the snapshot. UPTO must be <= commit-index. Persists the snapshot."
  (when (and (> upto (raft-node-snapshot-index node)) (<= upto (raft-node-commit-index node)))
    (let ((term (raft-log-term node upto))
          (drop (- upto (raft-node-snapshot-index node))))
      ;; shift the in-memory tail left by DROP entries
      (let* ((v (raft-node-log node)) (n (fill-pointer v)))
        (loop for i from drop below n do (setf (aref v (- i drop)) (aref v i)))
        (setf (fill-pointer v) (max 0 (- n drop))))
      (setf (raft-node-snapshot-index node) upto
            (raft-node-snapshot-term node) term)
      (raft-storage-save-snapshot (raft-node-storage node) upto term
                                  (and (raft-node-snapshot-fn node)
                                       (funcall (raft-node-snapshot-fn node)))))))

(defun raft-restore-snapshot (node index term state)
  "Install a snapshot into NODE (used on recovery and, later, InstallSnapshot):
   drop the log, set the snapshot boundary, and restore the state machine."
  (setf (fill-pointer (raft-node-log node)) 0
        (raft-node-snapshot-index node) index
        (raft-node-snapshot-term node) term
        (raft-node-last-applied node) (max (raft-node-last-applied node) index)
        (raft-node-commit-index node) (max (raft-node-commit-index node) index))
  (when (raft-node-restore-fn node) (funcall (raft-node-restore-fn node) state)))

(defun raft-majority (node)
  (1+ (floor (1+ (length (raft-node-peers node))) 2)))  ; floor((N+1)/2)+ -> strict majority of N

(defun raft-cluster-size (node) (1+ (length (raft-node-peers node))))

(defun raft-member-role (node id) (gethash id (raft-node-roles node) :voter))

(defun raft-replicate-ids (node)
  "Everyone the leader replicates to: quorum peers, members being added, and
   members being removed (until they apply the config and learn they are out)."
  (append (raft-node-peers node)
          (loop for id being the hash-keys of (raft-node-pending-members node) collect id)
          (loop for id being the hash-keys of (raft-node-departing-members node) collect id)))

(defun raft-configure (node members &optional (default-self-role :voter))
  "Set NODE's membership from MEMBERS, an alist (id . role) for the whole cluster
   (including self). PEERS becomes the voters+witnesses except self; self-role and
   the removed flag follow MEMBERS. Not required for an all-voter cluster that
   passed :peers to MAKE-RAFT-NODE -- it is for witnesses/learners/config change."
  (clrhash (raft-node-roles node))
  (dolist (m members) (setf (gethash (car m) (raft-node-roles node)) (cdr m)))
  (let ((self (assoc (raft-node-id node) members :test #'equal)))
    (setf (raft-node-self-role node) (if self (cdr self) default-self-role)
          (raft-node-removed node) (not self)
          (raft-node-peers node)
          (loop for (id . role) in members
                unless (equal id (raft-node-id node))
                  when (member role '(:voter :witness)) collect id))))

(defun raft-current-config (node)
  "The current membership as an alist (id . role), including self."
  (cons (cons (raft-node-id node) (raft-node-self-role node))
        (loop for id in (raft-node-peers node) collect (cons id (raft-member-role node id)))))

;;; ---------------------------------------------------------------------------
;;; Role transitions.

(defun raft-reset-election-timer (node)
  (setf (raft-node-election-elapsed node) 0
        (raft-node-election-timeout node) (funcall (raft-node-timeout-fn node))))

(defun raft-become-follower (node term &optional leader-id)
  (setf (raft-node-role node) :follower
        (raft-node-current-term node) term
        (raft-node-voted-for node) nil
        (raft-node-leader-id node) leader-id)
  (clrhash (raft-node-pending-members node))   ; abandon any in-flight add on leadership loss
  (clrhash (raft-node-departing-members node)) ; a new leader restarts removal delivery
  (raft-persist-hard-state node)
  (raft-reset-election-timer node))

(defun raft-send (node to message)
  (funcall (raft-node-send-fn node) to message))

(defun raft-broadcast (node message-fn)
  (dolist (peer (raft-node-peers node))
    (raft-send node peer (funcall message-fn peer))))

(defun raft-become-candidate (node)
  (setf (raft-node-role node) :candidate)
  (incf (raft-node-current-term node))
  (setf (raft-node-voted-for node) (raft-node-id node)
        (raft-node-leader-id node) nil)
  (raft-persist-hard-state node)
  (clrhash (raft-node-votes node))
  (setf (gethash (raft-node-id node) (raft-node-votes node)) t)
  (raft-reset-election-timer node)
  (raft-broadcast node
                  (lambda (peer)
                    (declare (ignore peer))
                    (list :type :request-vote
                          :term (raft-node-current-term node)
                          :from (raft-node-id node)
                          :last-log-index (raft-last-log-index node)
                          :last-log-term (raft-last-log-term node))))
  ;; A single-node cluster wins immediately.
  (raft-maybe-become-leader node))

(defun raft-maybe-become-leader (node)
  (when (and (eq (raft-node-role node) :candidate)
             (>= (hash-table-count (raft-node-votes node)) (raft-majority node)))
    (raft-become-leader node)))

(defun raft-become-leader (node)
  (setf (raft-node-role node) :leader
        (raft-node-leader-id node) (raft-node-id node))
  (clrhash (raft-node-next-index node))
  (clrhash (raft-node-match-index node))
  (dolist (peer (raft-replicate-ids node))
    (setf (gethash peer (raft-node-next-index node)) (1+ (raft-last-log-index node))
          (gethash peer (raft-node-match-index node)) 0))
  ;; Replicate immediately to assert leadership.
  (raft-broadcast-append node))

;;; ---------------------------------------------------------------------------
;;; Leader replication.

(defun raft-append-message (node peer)
  (let* ((next (gethash peer (raft-node-next-index node) (1+ (raft-last-log-index node))))
         (prev-index (1- next))
         (entries (loop for i from next to (raft-last-log-index node)
                        collect (raft-log-entry node i))))
    (list :type :append-entries
          :term (raft-node-current-term node)
          :from (raft-node-id node)
          :prev-log-index prev-index
          :prev-log-term (raft-log-term node prev-index)
          :entries entries
          :leader-commit (raft-node-commit-index node))))

(defun raft-broadcast-append (node)
  (setf (raft-node-heartbeat-elapsed node) 0)
  (dolist (peer (raft-replicate-ids node))
    (raft-send node peer (raft-append-message node peer)))
  ;; A departing member that already holds its removal entry has now also been
  ;; sent the commit for it (this append carries leader-commit), so it will apply
  ;; the change and learn it is out. Stop tracking it. If it has not yet stored
  ;; the entry (match below the removal index), keep sending until it does.
  (loop for peer being the hash-keys of (raft-node-departing-members node) using (hash-value at)
        when (>= (gethash peer (raft-node-match-index node) 0) at)
          collect peer into done
        finally (dolist (peer done) (remhash peer (raft-node-departing-members node)))))

(defun raft-advance-commit (node)
  "Leader: advance commit-index to the highest N replicated on a majority whose
   entry is from the current term (Raft §5.4.2)."
  (loop for n from (raft-last-log-index node) downto (1+ (raft-node-commit-index node))
        when (and (= (raft-log-term node n) (raft-node-current-term node))
                  (>= (1+ (loop for peer in (raft-node-peers node)
                                count (>= (gethash peer (raft-node-match-index node) 0) n)))
                      (raft-majority node)))
          do (setf (raft-node-commit-index node) n)
             (return)))

;;; ---------------------------------------------------------------------------
;;; Apply committed entries to the state machine.

(defun raft-apply-committed (node)
  (loop while (< (raft-node-last-applied node) (raft-node-commit-index node))
        do (incf (raft-node-last-applied node))
           (let* ((index (raft-node-last-applied node))
                  (entry (raft-log-entry node index))
                  (command (raft-entry-command entry))
                  (result
                    (if (and (consp command) (eq (car command) :raft-config))
                        ;; A membership change is applied to the config, not the
                        ;; user state machine. Every member applies it in log
                        ;; order, so all converge on the same membership.
                        (progn (raft-adopt-config node (getf (cdr command) :members)
                                                  (getf (cdr command) :addresses)
                                                  (getf (cdr command) :api-urls))
                               :configured)
                        (and (raft-node-apply-fn node) (funcall (raft-node-apply-fn node) command))))
                  (callback (gethash index (raft-node-pending node))))
             (when callback
               (remhash index (raft-node-pending node))
               (funcall callback result)))))

;;; ---------------------------------------------------------------------------
;;; Client proposal (leader only).

(defun raft-propose (node command &optional callback)
  "Leader appends COMMAND and replicates it. CALLBACK (if given) is invoked with
   the state-machine result once the entry commits. Returns (values index t) on
   the leader, or (values nil nil) otherwise so the caller can redirect."
  (if (eq (raft-node-role node) :leader)
      (let ((entry (raft-log-append node (make-raft-entry :term (raft-node-current-term node)
                                                          :command command))))
        (when callback (setf (gethash (raft-entry-index entry) (raft-node-pending node)) callback))
        (setf (gethash (raft-node-id node) (raft-node-match-index node)) (raft-entry-index entry))
        (raft-broadcast-append node)
        (raft-advance-commit node)
        (raft-apply-committed node)
        (values (raft-entry-index entry) t))
      (values nil nil)))

;;; ---------------------------------------------------------------------------
;;; Membership change (single-member, effective on commit).

(defun raft-adopt-config (node members &optional addresses api-urls)
  "Adopt a committed membership MEMBERS (alist id->role). Every member runs this
   in log order, so all converge. A member that finds itself gone steps down.
   ADDRESSES (alist id->(host port)) teaches the transport where to reach peers;
   API-URLS (alist id->url) teaches the HTTP layer where to redirect writes."
  (dolist (a addresses)
    (setf (gethash (car a) (raft-node-peer-addresses node)) (cdr a)))
  (dolist (a api-urls)
    (when (cdr a) (setf (gethash (car a) (raft-node-api-urls node)) (cdr a))))
  (let ((old-peers (raft-node-peers node))
        (leading (eq (raft-node-role node) :leader)))
    (raft-configure node members)
    (clrhash (raft-node-pending-members node))  ; any added member is now a real peer
    ;; Keep delivering this commit to peers the change just dropped, so they
    ;; apply it, mark themselves removed, and stop holding elections. (Only the
    ;; leader replicates; a departed member clears its own set when it steps.)
    (when leading
      (dolist (id old-peers)
        (unless (member id (raft-node-peers node) :test #'equal)
          (setf (gethash id (raft-node-departing-members node)) (raft-node-commit-index node))))))
  (when (raft-node-removed node)
    (clrhash (raft-node-departing-members node))
    (when (eq (raft-node-role node) :leader)
      (raft-become-follower node (raft-node-current-term node))))
  (when (raft-node-on-configured node)
    (funcall (raft-node-on-configured node) node)))

(defun raft-propose-config (node &key add remove (role :voter) address api-url callback)
  "Leader-only single-member change. ADD = a member id to add with ROLE (:voter
   or :witness) and ADDRESS = its (host port) so every member can reach it;
   REMOVE = a member id to drop (not self). Only one change may be in flight. The
   new member is replicated to immediately but is not counted for quorum until
   the config entry commits (effective-on-commit). Returns (values index t) when
   the change is proposed, else (values nil reason)."
  (cond
    ((not (eq (raft-node-role node) :leader)) (values nil :not-leader))
    ((plusp (hash-table-count (raft-node-pending-members node))) (values nil :change-in-flight))
    ((and remove (equal remove (raft-node-id node))) (values nil :cannot-remove-self))
    (t
     (let ((members (raft-current-config node)))
       (cond
         (add (setf members (cons (cons add role)
                                  (remove add members :key #'car :test #'equal)))
              (when address (setf (gethash add (raft-node-peer-addresses node)) address))
              (when api-url (setf (gethash add (raft-node-api-urls node)) api-url))
              ;; Replicate to the joiner now (not yet quorum) so it receives the
              ;; config entry that promotes it. The transport needs its link before
              ;; the append goes out, so reconcile immediately.
              (setf (gethash add (raft-node-pending-members node)) role
                    (gethash add (raft-node-next-index node)) (1+ (raft-last-log-index node))
                    (gethash add (raft-node-match-index node)) 0)
              (when (raft-node-on-configured node)
                (funcall (raft-node-on-configured node) node)))
         (remove (setf members (remove remove members :key #'car :test #'equal))))
       ;; Carry the whole address book (and API URLs) so a just-joined member
       ;; (and every other) learns where to reach each peer when this commits.
       (raft-propose node (list :raft-config :members members
                                :addresses (raft-config-addresses node)
                                :api-urls (raft-config-api-urls node))
                     callback)))))

(defun raft-config-addresses (node)
  "The current member address book as an alist id->(host port) for a config entry."
  (loop for id being the hash-keys of (raft-node-peer-addresses node) using (hash-value addr)
        collect (cons id addr)))

(defun raft-config-api-urls (node)
  "The current member API-URL book as an alist id->url for a config entry."
  (loop for id being the hash-keys of (raft-node-api-urls node) using (hash-value url)
        collect (cons id url)))

;;; ---------------------------------------------------------------------------
;;; Message handling.

(defun raft-step-down-if-stale (node term)
  "If TERM exceeds ours, adopt it and revert to follower. Returns T if stepped."
  (when (> term (raft-node-current-term node))
    (raft-become-follower node term)
    t))

(defun raft-handle-request-vote (node msg)
  (raft-step-down-if-stale node (getf msg :term))
  (let* ((term (getf msg :term))
         (candidate (getf msg :from))
         (up-to-date (or (> (getf msg :last-log-term) (raft-last-log-term node))
                         (and (= (getf msg :last-log-term) (raft-last-log-term node))
                              (>= (getf msg :last-log-index) (raft-last-log-index node)))))
         (grant (and (= term (raft-node-current-term node))
                     (member (raft-node-voted-for node) (list nil candidate) :test #'equal)
                     up-to-date)))
    (when grant
      (setf (raft-node-voted-for node) candidate)
      (raft-persist-hard-state node)
      (raft-reset-election-timer node))
    (raft-send node candidate
               (list :type :request-vote-reply :term (raft-node-current-term node)
                     :from (raft-node-id node) :granted grant))))

(defun raft-handle-request-vote-reply (node msg)
  (raft-step-down-if-stale node (getf msg :term))
  (when (and (eq (raft-node-role node) :candidate)
             (= (getf msg :term) (raft-node-current-term node))
             (getf msg :granted))
    (setf (gethash (getf msg :from) (raft-node-votes node)) t)
    (raft-maybe-become-leader node)))

(defun raft-handle-append-entries (node msg)
  (let ((term (getf msg :term)) (leader (getf msg :from)))
    (raft-step-down-if-stale node term)
    (cond
      ((< term (raft-node-current-term node))
       (raft-send node leader (list :type :append-entries-reply
                                    :term (raft-node-current-term node) :from (raft-node-id node)
                                    :success nil :match-index 0)))
      (t
       ;; Valid leader for our term.
       (when (eq (raft-node-role node) :candidate) (raft-become-follower node term leader))
       (setf (raft-node-leader-id node) leader)
       (raft-reset-election-timer node)
       (let ((prev-index (getf msg :prev-log-index))
             (prev-term (getf msg :prev-log-term)))
         (if (and (> prev-index 0)
                  (/= (raft-log-term node prev-index) prev-term))
             ;; Log mismatch: reject so the leader backs up.
             (raft-send node leader (list :type :append-entries-reply
                                          :term (raft-node-current-term node) :from (raft-node-id node)
                                          :success nil :match-index 0))
             (progn
               ;; Append/overwrite, skipping entries we already agree on.
               (loop for entry in (getf msg :entries)
                     for i from (1+ prev-index)
                     do (cond ((> i (raft-log-length node)) (raft-log-append node (copy-raft-entry entry)))
                              ((/= (raft-log-term node i) (raft-entry-term entry))
                               (raft-log-truncate node i)
                               (raft-log-append node (copy-raft-entry entry)))))
               (let ((last-new (+ prev-index (length (getf msg :entries)))))
                 (when (> (getf msg :leader-commit) (raft-node-commit-index node))
                   (setf (raft-node-commit-index node)
                         (min (getf msg :leader-commit) last-new)))
                 (raft-apply-committed node)
                 (raft-send node leader (list :type :append-entries-reply
                                              :term (raft-node-current-term node)
                                              :from (raft-node-id node)
                                              :success t :match-index last-new))))))))))

(defun raft-handle-append-entries-reply (node msg)
  (raft-step-down-if-stale node (getf msg :term))
  (when (and (eq (raft-node-role node) :leader)
             (= (getf msg :term) (raft-node-current-term node)))
    (let ((peer (getf msg :from)))
      (if (getf msg :success)
          (progn
            (setf (gethash peer (raft-node-match-index node)) (getf msg :match-index)
                  (gethash peer (raft-node-next-index node)) (1+ (getf msg :match-index)))
            (raft-advance-commit node)
            (raft-apply-committed node))
          ;; Back up and retry on the next replication round.
          (setf (gethash peer (raft-node-next-index node))
                (max 1 (1- (gethash peer (raft-node-next-index node) 1))))))))

(defun raft-handle-message (node msg)
  (ecase (getf msg :type)
    (:request-vote (raft-handle-request-vote node msg))
    (:request-vote-reply (raft-handle-request-vote-reply node msg))
    (:append-entries (raft-handle-append-entries node msg))
    (:append-entries-reply (raft-handle-append-entries-reply node msg))))

;;; ---------------------------------------------------------------------------
;;; Logical clock.

(defun raft-tick (node)
  "Advance one logical tick: voter candidates/followers may start an election,
   leaders send heartbeats. A witness or learner never starts an election (so it
   never becomes leader); a removed member does nothing."
  (unless (raft-node-removed node)
    (case (raft-node-role node)
      ((:follower :candidate)
       (when (eq (raft-node-self-role node) :voter)
         (when (>= (incf (raft-node-election-elapsed node)) (raft-node-election-timeout node))
           (raft-become-candidate node))))
      (:leader
       (when (>= (incf (raft-node-heartbeat-elapsed node)) (raft-node-heartbeat-timeout node))
         (raft-broadcast-append node))))))

(defun raft-leader-p (node) (eq (raft-node-role node) :leader))
