;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.resources)

(defun restore-member-store-artifact (member store reference &key recover)
  "Restore a pending install or recovered WAL snapshot under verified barriers."
  (unless (and (gr8s.store::store-application-barriers-owned-p store)
               (sb-thread:holding-mutex-p (gr8s.raft.transport:raft-member-lock member)))
    (error "Application snapshot restore requires outer barriers before member lock"))
  (let* ((node (gr8s.raft.transport:raft-member-node member))
         (pending (gr8s.raft:raft-node-snapshot-pending node))
         (root (pod-store-path store))
         (path (checked-store-snapshot-artifact-path root reference)))
    (unless (if recover
                (and (not (gr8s.raft.transport:raft-member-running member)) (null pending)
                     (equal reference (getf (cddr (gr8s.raft:raft-node-snapshot-state node)) :application)))
                (and pending (equal reference (getf (cddr (third pending)) :application))))
      (error "Application restore does not match its durable WAL snapshot"))
    (let* ((index (if recover (gr8s.raft:raft-node-snapshot-index node) (first pending)))
           (term (if recover (gr8s.raft:raft-node-snapshot-term node) (second pending)))
           (digest (eighth reference))
           (validate (gr8s.ha::make-member-generation-validator
                      member (gr8s.raft:raft-node-current-term node) index term digest :recover recover))
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
       ;; Live pending state follows a completed WAL replacement; startup state
       ;; comes from the validated WAL. Recheck it before intent removal. The
       ;; dispatch barrier keeps access closed until Raft publication completes.
       :commit-recovery validate))))

(defun member-store-restore-may-resume-p (member)
  (let* ((node (gr8s.raft.transport:raft-member-node member))
         (storage (gr8s.raft:raft-node-storage node)))
    (and (null (gr8s.raft:raft-node-snapshot-pending node))
         (typep storage 'gr8s.raft::file-raft-storage)
         (let ((stream (gr8s.raft::file-raft-storage-stream storage)))
           (and stream (open-stream-p stream))))))

(defun member-store-current-term-applied-p (node index)
  (and (typep index '(integer 1 *)) (plusp (gr8s.raft:raft-node-current-term node))
       (<= index (gr8s.raft:raft-node-commit-index node) (gr8s.raft:raft-node-last-applied node))
       (= (gr8s.raft::raft-log-term node index) (gr8s.raft:raft-node-current-term node))))

(defun member-store-startup-synchronized-p (member message)
  "Require a committed current-term barrier, not merely a recovered log suffix."
  (let ((node (gr8s.raft.transport:raft-member-node member)))
    (or (and (eq :leader (gr8s.raft:raft-node-role node))
             (member-store-current-term-applied-p node (gr8s.raft:raft-node-commit-index node)))
        (and (eq :append-entries (getf message :type))
             (eql (getf message :term) (gr8s.raft:raft-node-current-term node))
             (equal (getf message :from) (gr8s.raft:raft-node-leader-id node))
             (member-store-current-term-applied-p node (getf message :leader-commit))))))

(defun configure-member-store-restore (member store &key (drain-timeout 30) startup)
  "Install live or pre-listener artifact restore barriers.
Production control-plane integration and compaction remain separate.
A closure owns only gates it successfully quiesces. Failed durable installs keep
that gate blocked for a later ordinary RPC to retry under the same outer barriers."
  (unless (member startup '(nil t)) (error "Invalid store startup mode"))
  (let ((serial (bt:make-lock "gr8s application snapshot dispatch"))
        (owns-gate startup) (startup-sync-required startup) (recovery-barrier-term nil))
    (bt:with-lock-held ((gr8s.raft.transport:raft-member-lock member))
      (if startup
          (progn
            (unless (and (gr8s.store::store-application-barriers-owned-p store)
                         (not (gr8s.raft.transport:raft-member-running member))
                         (null (gr8s.raft.transport:raft-member-grpc-server member))
                         (null (gr8s.raft:raft-node-storage (gr8s.raft.transport:raft-member-node member))))
              (error "Store startup must prepare barriers before recovery/listener startup"))
            (bt:with-lock-held ((pod-store-lock store)) (gr8s.store::require-store-reload-quiescence store)))
          (unless (member-store-restore-may-resume-p member)
            (error "Application restore requires an open durable WAL without a pending install")))
      (when (gr8s.raft.transport::raft-member-snapshot-barrier-pending member)
        (error "Cannot replace an unfinished application restore barrier"))
      (install-store-artifact-transport-unlocked member (pod-store-path store))
      (setf (gr8s.raft:raft-node-restore-fn (gr8s.raft.transport:raft-member-node member))
            (lambda (reference)
              (restore-member-store-artifact member store reference
               :recover (and startup-sync-required (not (gr8s.raft.transport:raft-member-running member)))))
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
                        (when (and startup-sync-required (member-store-startup-synchronized-p member message))
                          (setf startup-sync-required nil))
                        (ignore-errors
                          (when (and (not startup-sync-required) (member-store-restore-may-resume-p member))
                            (gr8s.store::resume-store-access store)
                            (setf owns-gate nil
                                  (gr8s.raft.transport::raft-member-startup-check-fn member) nil)))
                        (setf (gr8s.raft.transport::raft-member-snapshot-barrier-pending member) owns-gate))))
                  (when (and completed owns-gate (not startup-sync-required))
                    (error "Application snapshot remains unavailable"))))))
      (when startup
        (setf (gr8s.raft.transport::raft-member-snapshot-barrier-pending member) t
              (gr8s.raft.transport::raft-member-startup-check-fn member)
              (lambda (incoming)
                (when (or startup-sync-required (gr8s.raft.transport::raft-member-snapshot-barrier-pending incoming))
                  (when
                      (bt:with-lock-held ((gr8s.raft.transport:raft-member-lock incoming))
                        (let ((node (gr8s.raft.transport:raft-member-node incoming)))
                          ;; Election alone does not establish a commit barrier.
                          ;; Append one durable application no-op per recovery term.
                          (when (and startup-sync-required (eq :leader (gr8s.raft:raft-node-role node))
                                     (not (member-store-startup-synchronized-p incoming nil))
                                     (not (eql recovery-barrier-term (gr8s.raft:raft-node-current-term node))))
                            (let ((term (gr8s.raft:raft-node-current-term node))
                                  (index (1+ (gr8s.raft::raft-last-log-index node))))
                              (unwind-protect (gr8s.raft:raft-propose node '(:store-recovery-barrier))
                                ;; Apply may fail AFTER the barrier was durably
                                ;; appended. Remember that entry instead of
                                ;; appending another one on every tick.
                                (let ((entry (gr8s.raft::raft-log-entry node index)))
                                  (when (and entry (= term (gr8s.raft:raft-entry-term entry))
                                             (equal '(:store-recovery-barrier) (gr8s.raft:raft-entry-command entry)))
                                    (setf recovery-barrier-term term))))))
                          (when (and (eq :leader (gr8s.raft:raft-node-role node))
                                     (eql recovery-barrier-term (gr8s.raft:raft-node-current-term node)))
                            (gr8s.raft::raft-apply-committed node))
                          (member-store-startup-synchronized-p incoming nil)))
                    (funcall (gr8s.raft.transport::raft-member-snapshot-barrier-fn incoming)
                             incoming nil (lambda () nil)))))))))
  member)

(defun validate-store-member-recovered-baseline (store recovered)
  (declare (ignore store))
  (let* ((state (gr8s.raft::raft-recovered-snapshot-state recovered))
         (index (gr8s.raft::raft-recovered-snapshot-index recovered))
         (term (gr8s.raft::raft-recovered-snapshot-term recovered))
         (reference (and (gr8s.raft::raft-snapshot-envelope-p state) (getf (cddr state) :application))))
    (unless (and (consp reference)
                 (equal reference (store-snapshot-artifact-reference index term (eighth reference)))
                 (gr8s.ha::member-snapshot-artifact-matches-p state index term (eighth reference)))
      (error "Application WAL recovery requires a retained artifact baseline"))
    t))

(defun start-store-member-from-wal (store id wal &rest options)
  "Restore an artifact-backed WAL before listening. API access stays blocked until
current-term committed catch-up. Durable writes use the shared HA dispatcher;
the caller starts ticking and publishes its application endpoints.
Use :BOOTSTRAP-ROLE :FOUNDER or :LEARNER only for fresh/journaled bootstrap.
Production control-plane integration remains separate."
  (unless (or (pathnamep wal) (stringp wal)) (error "Invalid application WAL pathname"))
  (unless (evenp (length options)) (error "Invalid store member startup options"))
  (loop for key in options by #'cddr
        when (member key '(:storage :storage-path :prepare-fn :validate-recovery-fn :restore-fn :apply-fn))
          do (error "Store member startup owns ~S" key))
  (let ((bootstrap-role (getf options :bootstrap-role))
        (bootstrap-api-url (getf options :bootstrap-api-url)))
    (when (and bootstrap-api-url (null bootstrap-role))
      (error "Bootstrap API URL requires a fresh bootstrap role"))
    (setf options (loop for (key value) on options by #'cddr
                        unless (member key '(:bootstrap-role :bootstrap-api-url))
                          append (list key value)))
  (gr8s.store::quiesce-store-access store)
  (let ((member nil) (completed nil))
    (unwind-protect
         (gr8s.store::call-with-store-application-barriers
          store
          (lambda ()
            (when bootstrap-role
              (unless (equal (merge-pathnames wal)
                             (merge-pathnames "raft/control-plane.log" (pod-store-path store)))
                (error "Fresh application bootstrap must use its member-root WAL"))
              (bootstrap-store-member-wal store id :role bootstrap-role :api-url bootstrap-api-url))
            (setf member
                  (apply #'gr8s.raft.transport:start-raft-member id :storage-path wal
                         :apply-fn (gr8s.ha::make-store-raft-apply-function store)
                         :prepare-fn
                         (lambda (incoming)
                           (configure-member-store-restore incoming store :startup t)
                           (setf (pod-store-consensus-commit-fn store) (gr8s.ha::make-store-raft-commit-function incoming)))
                         :validate-recovery-fn
                         (lambda (incoming recovered)
                           (declare (ignore incoming))
                           (validate-store-member-recovered-baseline store recovered))
                         options))
            (bt:with-lock-held ((gr8s.raft.transport:raft-member-lock member))
              (gr8s.raft.transport:raft-member-enable-dynamic-membership member)
              (gr8s.raft.transport:raft-member-reconcile-links member))
            (setf completed t)
            member))
      (unless completed (when member (gr8s.raft.transport:stop-raft-member member)))))))
