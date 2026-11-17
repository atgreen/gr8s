;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.ha)

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
        (format *error-output* "~&gr8s HA API-URL re-advertisement failed: ~A~%" condition)))))

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
                   (format *error-output* "~&gr8s HA generation maintenance failed: ~A~%" condition)))))
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
