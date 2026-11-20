;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Linearizable reads (Raft ReadIndex, dissertation section 6.4).
;;;;
;;;; A member's own state is as old as the last entry it applied. A follower cut
;;;; off from the leader, or a leader that has been replaced without knowing it,
;;;; would answer a read from state that the rest of the cluster has moved past,
;;;; for as long as the partition lasts (podster-gxi).
;;;;
;;;; Kubernetes promises more: a GET or LIST that names no resourceVersion is
;;;; answered from a quorum read of etcd, and etcd answers such a read with
;;;; ReadIndex. The leader notes its commit index, confirms with one round of
;;;; heartbeats that a quorum still follows it, and the read is served once that
;;;; index has been applied. A follower asks the leader for the index and waits
;;;; until it has applied it too. A member that cannot reach a leader that a
;;;; quorum follows cannot answer, and says so.
;;;;
;;;; One round confirms every read that was already waiting when it began, so
;;;; the cost is one round of heartbeats per batch of reads, not per read.

(in-package #:gr8s.raft.transport)

(defun raft-read-seconds-until (deadline)
  (/ (- deadline (get-internal-real-time)) internal-time-units-per-second))

(defun raft-member-confirm-leadership (member deadline)
  "On the leader, wait for a quorum to confirm that it still leads and for this
member to apply everything committed before the call. Returns (values index T),
or (values NIL reason): :NOT-LEADER, :NOT-READY (a new leader that has not yet
committed an entry of its own term) or :TIMEOUT at DEADLINE (internal time)."
  (let ((lock (bt:make-lock "gr8s raft read confirmation"))
        (answered (bt:make-condition-variable))
        (done nil) (index nil))
    (multiple-value-bind (queued reason)
        (bt:with-lock-held ((raft-member-lock member))
          ;; The callback runs under the member lock, on this thread or on the
          ;; one that delivers the confirming reply.
          (raft-read-index (raft-member-node member)
                           (lambda (read-index)
                             (bt:with-lock-held (lock)
                               (setf done t index read-index)
                               (bt:condition-notify answered)))))
      (if (not queued)
          (values nil reason)
          (bt:with-lock-held (lock)
            (loop until done
                  do (let ((remaining (raft-read-seconds-until deadline)))
                       (when (<= remaining 0) (return))
                       (bt:condition-wait answered lock :timeout remaining)))
            (cond ((not done) (values nil :timeout))
                  (index (values index t))
                  (t (values nil :not-leader))))))))

(defun raft-read-gate-drop-leader (gate)
  (ignore-errors (when (raft-read-gate-channel gate) (ag-grpc:channel-close (raft-read-gate-channel gate))))
  (setf (raft-read-gate-channel gate) nil (raft-read-gate-stub gate) nil (raft-read-gate-leader gate) nil))

(defun raft-member-ask-leader-read-index (member)
  "On a follower, ask the leader this member last heard from for a read index.
Returns (values index T), or (values NIL reason). :UNSUPPORTED is a leader from
before this call existed, during a rolling upgrade."
  (let ((gate (raft-member-read-gate member)))
    (multiple-value-bind (leader address)
        (bt:with-lock-held ((raft-member-lock member))
          (let* ((node (raft-member-node member)) (leader (raft-node-leader-id node)))
            (values leader (and leader (gethash leader (raft-node-peer-addresses node))))))
      (unless (and leader address (not (equal leader (raft-node-id (raft-member-node member)))))
        (return-from raft-member-ask-leader-read-index (values nil :not-leader)))
      (unless (equal leader (raft-read-gate-leader gate))
        (raft-read-gate-drop-leader gate))
      (handler-case
          (progn
            (unless (raft-read-gate-stub gate)
              (let ((channel (gr8s.security::make-raft-channel
                              (raft-member-credentials member) (first address) (second address) 2)))
                (setf (raft-read-gate-channel gate) channel
                      (raft-read-gate-stub gate) (gr8s.node.v1::make-raft-transport-stub channel)
                      (raft-read-gate-leader gate) leader)))
            (let ((response (gr8s.node.v1::raft-transport-read-index
                             (raft-read-gate-stub gate)
                             (make-instance 'gr8s.node.v1::raft-read-index-request) :timeout 3)))
              (if (gr8s.node.v1::confirmed response)
                  (values (gr8s.node.v1::index response) t)
                  (values nil (or (find-symbol (string-upcase (gr8s.node.v1::reason response)) :keyword)
                                  :not-leader)))))
        (ag-grpc:grpc-status-error (condition)
          (if (eql ag-grpc:+grpc-status-unimplemented+ (ag-grpc:grpc-status-error-code condition))
              (values nil :unsupported)
              (progn (raft-read-gate-drop-leader gate) (values nil :timeout))))
        ((or error sb-ext:timeout) ()
          (raft-read-gate-drop-leader gate)
          (values nil :timeout))))))

(defun raft-member-read-round (member deadline)
  "Bring MEMBER's applied state up to everything committed before this call.
Returns T, or (values NIL reason) when no leader that a quorum follows could be
reached by DEADLINE. An election in progress is waited out, not reported."
  (loop
    (multiple-value-bind (index confirmed)
        (if (raft-member-leader-p member)
            (raft-member-confirm-leadership member deadline)
            (raft-member-ask-leader-read-index member))
      (cond ((eq confirmed t)
             (return (or (raft-member-wait-applied member index deadline) (values nil :timeout))))
            ;; A leader too old to answer cannot be asked; read as members did before.
            ((eq confirmed :unsupported) (return t))
            ((or (>= (get-internal-real-time) deadline) (not (raft-member-running member)))
             (return (values nil confirmed)))
            (t (sleep 0.02))))))

(defun raft-member-await-linearizable-read (member &key (timeout 5))
  "Return T once MEMBER's state holds every write committed before this call, so
that the caller may read it; or (values NIL reason) after TIMEOUT seconds without
a leader that a quorum follows.

A round that began before this call may have noted an index from before it, so
the caller needs the next round. Whoever finds no round running drives one; the
others wait for it."
  (let* ((gate (raft-member-read-gate member))
         (deadline (+ (get-internal-real-time) (round (* timeout internal-time-units-per-second))))
         (need nil))
    (loop
      (let ((drive nil))
        (bt:with-lock-held ((raft-read-gate-lock gate))
          (unless need (setf need (1+ (raft-read-gate-round gate))))
          (loop
            (cond ((>= (raft-read-gate-confirmed gate) need)
                   (return-from raft-member-await-linearizable-read t))
                  ((raft-read-gate-running gate)
                   (let ((remaining (raft-read-seconds-until deadline)))
                     (when (<= remaining 0)
                       (return-from raft-member-await-linearizable-read (values nil :timeout)))
                     (bt:condition-wait (raft-read-gate-changed gate) (raft-read-gate-lock gate)
                                        :timeout remaining)))
                  ((>= (raft-read-gate-round gate) need)
                   (return-from raft-member-await-linearizable-read
                     (values nil (or (raft-read-gate-refusal gate) :timeout))))
                  (t (setf (raft-read-gate-running gate) t
                           (raft-read-gate-round gate) need
                           drive t)
                     (return)))))
        (when drive
          (let ((confirmed nil) (reason :timeout))
            (unwind-protect
                 (multiple-value-setq (confirmed reason) (raft-member-read-round member deadline))
              (bt:with-lock-held ((raft-read-gate-lock gate))
                (setf (raft-read-gate-running gate) nil)
                (if confirmed
                    (setf (raft-read-gate-confirmed gate) need)
                    (setf (raft-read-gate-refusal gate) reason))
                (sb-thread:condition-broadcast (raft-read-gate-changed gate))))))))))

(defun raft-member-follows-a-leader-p (member)
  "True when MEMBER leads, or heard from a leader within its election timeout.
Costs no round trip: it tells a load balancer that a member is cut off, and is
not a licence to serve a read."
  (bt:with-lock-held ((raft-member-lock member))
    (let ((node (raft-member-node member)))
      (or (raft-leader-p node)
          (and (raft-node-leader-id node)
               (< (raft-node-leader-contact-elapsed node)
                  (raft-node-election-timeout node)))))))
