;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
  (dolist (peer (raft-node-peers node))
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
  (raft-broadcast node (lambda (peer) (raft-append-message node peer))))

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
                  (result (and (raft-node-apply-fn node)
                               (funcall (raft-node-apply-fn node) (raft-entry-command entry))))
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
  "Advance one logical tick: candidates/followers may start an election, leaders
   send heartbeats."
  (case (raft-node-role node)
    ((:follower :candidate)
     (when (>= (incf (raft-node-election-elapsed node)) (raft-node-election-timeout node))
       (raft-become-candidate node)))
    (:leader
     (when (>= (incf (raft-node-heartbeat-elapsed node)) (raft-node-heartbeat-timeout node))
       (raft-broadcast-append node)))))

(defun raft-leader-p (node) (eq (raft-node-role node) :leader))
