;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.ha)

;;; Self-heal for the application-restore wedge (podster-7l9).
;;;
;;; When a snapshot-barrier restore quiesces the store but the cluster is left with no
;;; leader, nothing proposes the :store-recovery-barrier, so no member resumes and the
;;; store stays access-blocked forever -- the whole API returns 503 until a human
;;; restarts every member. The signature is unambiguous: the store is application-blocked
;;; AND Raft reports no leader, continuously. Either alone is normal (a checkpoint keeps
;;; its leader; an in-progress election is not store-blocked), so requiring both -- well
;;; past any legitimate checkpoint drain or snapshot install -- isolates the real wedge.
;;; The member then restarts itself (systemd Restart=always re-runs WAL recovery), which
;;; is exactly the manual fix; when every member is wedged they all do it and re-form.

(defparameter *ha-store-wedge-threshold-seconds* 180
  "How long the store may stay application-blocked with no elected leader before this
member restarts to break the podster-7l9 deadlock. Comfortably above any legitimate
drain/install, and both conditions must hold the whole time.")

(defun self-restart-exit ()
  "Exit so systemd (Restart=always) restarts us into a clean WAL recovery. Abrupt by
design: the store is already wedged, no writes are in flight, and the WAL is durable."
  (sb-ext:exit :code 1 :abort t))

(defun ha-store-wedge-condition-p (hcp)
  "True when this member's store is application-blocked AND Raft reports no leader -- the
podster-7l9 wedge signature."
  (let ((store (ha-control-plane-store hcp))
        (node (raft-member-node (ha-control-plane-member hcp))))
    (and (gr8s.store::store-access-blocked-p store)
         (null (gr8s.raft:raft-node-leader-id node)))))

(defun ha-store-wedge-advance (wedged-p seen-serving wedge-since now exit)
  "Pure wedge-watchdog step. WEDGED-P is whether the wedge condition holds now;
SEEN-SERVING whether the store has ever been observed serving since the worker started
(so initial startup recovery, which is store-blocked on purpose, is never mistaken for a
wedge); WEDGE-SINCE the internal-real-time the condition began, or NIL. Returns
(values seen-serving wedge-since), and calls EXIT once the condition has held past
*ha-store-wedge-threshold-seconds*."
  (cond
    ((not wedged-p) (values t nil))             ; serving: remember it, clear the timer
    ((not seen-serving) (values nil nil))       ; still in first-boot recovery: ignore
    ((null wedge-since) (values t now))         ; wedge just began
    ((>= (/ (- now wedge-since) internal-time-units-per-second)
         *ha-store-wedge-threshold-seconds*)
     (funcall exit)
     (values t wedge-since))
    (t (values t wedge-since))))

(defun ha-store-wedge-watch (hcp seen-serving wedge-since
                             &key (now (get-internal-real-time)) (exit #'self-restart-exit))
  "Run one wedge-watchdog step against HCP, logging on trigger. Returns the updated
(values seen-serving wedge-since)."
  (let ((wedged (ha-store-wedge-condition-p hcp)))
    (when (and wedged seen-serving wedge-since
               (>= (/ (- now wedge-since) internal-time-units-per-second)
                   *ha-store-wedge-threshold-seconds*))
      (format *error-output*
              "~&gr8s HA: store application-blocked with no leader for ~Ds ~
               (podster-7l9 wedge); restarting this member to recover from its WAL.~%"
              (round (/ (- now wedge-since) internal-time-units-per-second)))
      (finish-output *error-output*))
    (ha-store-wedge-advance wedged seen-serving wedge-since now exit)))

(defun maintain-ha-artifacts-once (hcp)
  "Claim one obsolete artifact under member ownership; unlink trash outside it."
  (let* ((member (ha-control-plane-member hcp))
         (root (gr8s.store::pod-store-path (ha-control-plane-store hcp)))
         (eligible nil) (removed 0))
    (when (sb-thread:holding-mutex-p (raft-member-lock member))
      (error "Artifact maintenance must start outside the member mutex"))
    (bt:with-lock-held ((raft-member-lock member))
      (let ((state (gr8s.raft:raft-node-snapshot-state (raft-member-node member))))
        (when (and (gr8s.resources::store-snapshot-artifact-owner-p member root)
                   (gr8s.raft::raft-snapshot-envelope-p state)
                   (getf (cddr state) :application))
          (setf eligible t)
          (gr8s.resources::claim-store-snapshot-artifacts-unlocked member root))))
    (when eligible
      (setf removed (gr8s.resources::reap-store-snapshot-artifact-trash root)))
    (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
      (incf (ha-control-plane-artifacts-reaped hcp) removed)
      (setf (ha-control-plane-artifact-maintenance-error hcp) nil))
    removed))

(defun reconcile-ha-advertised-api-url (hcp)
  "On the leader, make the cluster's record of this member's API URL match the URL
it now intends to advertise, so followers redirect clients to where the leader
actually is after it has roamed to a new address (podster-1ig). Leader-gated and
idempotent: a follower does nothing, and once the committed config matches, the
refresh is skipped. Returns the proposal outcome, or NIL when nothing was done."
  (let ((intended (ha-control-plane-advertised-api-url hcp)))
    (when (and intended (ha-control-plane-leader-p hcp))
      (multiple-value-bind (proposed reason)
          (raft-cluster-readvertise-api-url (ha-control-plane-member hcp) intended)
        (when (and (not proposed)
                   reason
                   (not (member reason '(:unchanged :not-leader :change-in-flight
                                         :not-ready :transferring))))
          (format *error-output* "~&gr8s HA could not re-advertise API URL ~A: ~A~%"
                  intended reason))
        (or proposed reason)))))

(defun maintain-ha-store-once (hcp)
  "Attempt generation and artifact cleanup independently of local checkpoints."
  (unwind-protect
       (let ((removed (gr8s.store::reap-retired-store-generations (ha-control-plane-store hcp))))
         (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
           (incf (ha-control-plane-generation-reaped-files hcp) removed)
           (setf (ha-control-plane-maintenance-error hcp) nil))
         removed)
    ;; A generation failure must not starve independent artifact reclamation,
    ;; an artifact error must not hide the original generation condition, and
    ;; neither must block the leader's API-URL re-advertisement.
    (handler-case (maintain-ha-artifacts-once hcp)
      (error (condition)
        (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
          (setf (ha-control-plane-artifact-maintenance-error hcp) (princ-to-string condition)))
        (format *error-output* "~&gr8s HA artifact maintenance failed: ~A~%" condition)))
    (handler-case (reconcile-ha-advertised-api-url hcp)
      (error (condition)
        (format *error-output* "~&gr8s HA API-URL re-advertisement failed: ~A~%" condition)))
    (handler-case (reconcile-ha-resource-revisions hcp)
      (error (condition)
        (format *error-output* "~&gr8s HA resource revision reconciliation failed: ~A~%" condition)))))

(defun reconcile-ha-resource-revisions (hcp)
  "Take this member's part in bringing the members to count revisions alike and
give each object one version: see GR8S.RESOURCES::RECONCILE-CORE-VERSIONS. A
member asks for a round once each time it starts."
  (let ((store (ha-control-plane-store hcp))
        (member (ha-control-plane-member hcp)))
    (multiple-value-bind (self voters leader-p ready)
        (bt:with-lock-held ((raft-member-lock member))
          (let ((node (raft-member-node member)))
            (values (raft-node-id node)
                    (loop for (id . role) in (raft-current-config node)
                          when (eq role :voter) collect id)
                    (raft-leader-p node)
                    ;; A learner cannot propose, and with no leader a proposal only waits.
                    (and (gr8s.raft::raft-node-leader-id node)
                         (not (eq :learner (gr8s.raft::raft-node-self-role node)))))))
      (when (and ready (gr8s.store::pod-store-consensus-commit-fn store))
        ;; A store that is installing a snapshot, or a write that cannot commit
        ;; yet, is tried again on the next pass.
        (handler-case
            (progn
              (gr8s.resources::reconcile-core-versions
               store self voters leader-p :ask (not (ha-control-plane-revision-advertised hcp)))
              (setf (ha-control-plane-revision-advertised hcp) t))
          (gr8s.model:kubernetes-error (condition)
            (unless (eql 503 (gr8s.model:kubernetes-error-status-code condition))
              (error condition))))))))

(defun start-ha-maintenance-worker (hcp &key (interval 1))
  "Run generation maintenance even when automatic Raft compaction is disabled."
  (unless (and (realp interval) (plusp interval)) (error "Invalid maintenance interval"))
  (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
    (when (ha-control-plane-maintenance-thread hcp) (error "Maintenance worker already exists"))
    (sb-sys:without-interrupts
     (setf (ha-control-plane-maintenance-running hcp) t
          (ha-control-plane-maintenance-thread hcp)
          (bt:make-thread
           (lambda ()
             (let ((seen-serving nil) (wedge-since nil))
               (loop
                 (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
                   (unless (ha-control-plane-maintenance-running hcp) (return))
                   (bt:condition-wait (ha-control-plane-maintenance-changed hcp)
                                      (ha-control-plane-maintenance-lock hcp)
                                      :timeout (float interval 1d0))
                   (unless (ha-control-plane-maintenance-running hcp) (return)))
                 (handler-case (maintain-ha-store-once hcp)
                   (error (condition)
                     (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
                       (setf (ha-control-plane-maintenance-error hcp) (princ-to-string condition)))
                     (format *error-output* "~&gr8s HA generation maintenance failed: ~A~%" condition)))
                 ;; Watch for the podster-7l9 wedge; a fault here must not kill the worker.
                 (handler-case
                     (multiple-value-setq (seen-serving wedge-since)
                       (ha-store-wedge-watch hcp seen-serving wedge-since))
                   (error (condition)
                     (format *error-output* "~&gr8s HA wedge watchdog error: ~A~%" condition))))))
           :name "gr8s HA generation maintenance"))))
  hcp)

(defun stop-ha-maintenance-worker (hcp)
  "Join before releasing member ownership or stopping Raft."
  (let ((thread nil))
    (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
      (setf (ha-control-plane-maintenance-running hcp) nil
            thread (ha-control-plane-maintenance-thread hcp))
      (bt:condition-notify (ha-control-plane-maintenance-changed hcp)))
    (when thread (bt:join-thread thread))
    (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
      (setf (ha-control-plane-maintenance-thread hcp) nil)))
  hcp)
