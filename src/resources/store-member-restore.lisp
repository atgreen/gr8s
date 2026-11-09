;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.resources)

(defun restore-member-store-artifact (member store reference)
  "Load a durable pending artifact under verified outer barriers and member mutex."
  (unless (and (gr8s.store::store-application-barriers-owned-p store)
               (sb-thread:holding-mutex-p (gr8s.raft.transport:raft-member-lock member)))
    (error "Application snapshot restore requires outer barriers before member lock"))
  (let* ((node (gr8s.raft.transport:raft-member-node member))
         (pending (gr8s.raft:raft-node-snapshot-pending node))
         (root (pod-store-path store))
         (path (checked-store-snapshot-artifact-path root reference)))
    (unless (and pending (equal reference (getf (cddr (third pending)) :application)))
      (error "Application restore does not match a durable pending snapshot"))
    (let* ((index (first pending)) (term (second pending)) (digest (eighth reference))
           (validate (gr8s.ha::make-member-generation-validator
                      member (gr8s.raft:raft-node-current-term node) index term digest))
           (existing (gr8s.store::read-store-restore-intent root))
           (descriptor nil))
      (if existing
          (setf descriptor existing)
          (multiple-value-bind (generation incoming)
              (materialize-store-snapshot
               root path digest :expected-index index :expected-term term
               :minimum-resource-revision (1+ (pod-store-resource-revision store))
               :minimum-pod-revision (1+ (max (pod-store-pod-revision store) (pod-store-pod-revision-ceiling store))))
            (declare (ignore generation))
            (setf descriptor incoming)))
      (gr8s.store::reload-store-application
       store (gethash "generation" descriptor) :call-with-member-lock #'funcall
       :validate-recovery validate
       ;; Pending state is published only after its WAL replacement completed.
       ;; Recheck it after loading before removing the application intent. The
       ;; dispatch barrier keeps access closed until Raft publication completes.
       :commit-recovery validate))))

(defun member-store-restore-may-resume-p (member)
  (let* ((node (gr8s.raft.transport:raft-member-node member))
         (storage (gr8s.raft:raft-node-storage node)))
    (and (null (gr8s.raft:raft-node-snapshot-pending node))
         (typep storage 'gr8s.raft::file-raft-storage)
         (let ((stream (gr8s.raft::file-raft-storage-stream storage)))
           (and stream (open-stream-p stream))))))

(defun configure-member-store-restore (member store &key (drain-timeout 30))
  "Install opt-in live artifact restore. Production startup/compaction remain separate.
A closure owns only gates it successfully quiesces. Failed durable installs keep
that gate blocked for a later ordinary RPC to retry under the same outer barriers."
  (let ((serial (bt:make-lock "gr8s application snapshot dispatch")) (owns-gate nil))
    (bt:with-lock-held ((gr8s.raft.transport:raft-member-lock member))
      (unless (member-store-restore-may-resume-p member)
        (error "Application restore requires an open durable WAL without a pending install"))
      (when (gr8s.raft.transport::raft-member-snapshot-barrier-pending member)
        (error "Cannot replace an unfinished application restore barrier"))
      (install-store-artifact-transport-unlocked member (pod-store-path store))
      (setf (gr8s.raft:raft-node-restore-fn (gr8s.raft.transport:raft-member-node member))
            (lambda (reference) (restore-member-store-artifact member store reference))
            (gr8s.raft.transport::raft-member-snapshot-barrier-fn member)
            (lambda (incoming message dispatch)
              (unless (eq incoming member) (error "Snapshot barrier belongs to another member"))
              (bt:with-lock-held (serial)
                (unless owns-gate
                  (gr8s.store::quiesce-store-access store :timeout drain-timeout)
                  (setf owns-gate t))
                (let ((completed nil))
                  (unwind-protect
                       (gr8s.store::call-with-store-application-barriers
                        store
                        (lambda ()
                          (bt:with-lock-held ((gr8s.raft.transport:raft-member-lock member))
                            (unless (or (not (eq :snapshot-chunk (getf message :type)))
                                        (eq :artifact-v1 (getf message :format)))
                              (error "Application snapshots require raw artifact transport")))
                          (funcall dispatch)
                          (setf completed t)))
                    ;; Resume only our own gate, after both application and Raft
                    ;; publication. On pre-WAL failure the old application can
                    ;; reopen; an uncertain/closed WAL or pending install cannot.
                    (when owns-gate
                      (bt:with-lock-held ((gr8s.raft.transport:raft-member-lock member))
                        (ignore-errors
                          (when (member-store-restore-may-resume-p member)
                            (gr8s.store::resume-store-access store)
                            (setf owns-gate nil)))
                        (setf (gr8s.raft.transport::raft-member-snapshot-barrier-pending member) owns-gate))))
                  (when (and completed owns-gate) (error "Application snapshot remains unavailable"))))))))
  member)
