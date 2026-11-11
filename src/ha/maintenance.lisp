;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.ha)

(defun maintain-ha-store-once (hcp)
  "Reclaim a batch independently of local checkpoint creation and Raft locks."
  (let ((removed (gr8s.store::reap-retired-store-generations (ha-control-plane-store hcp))))
    (bt:with-lock-held ((ha-control-plane-maintenance-lock hcp))
      (incf (ha-control-plane-generation-reaped-files hcp) removed)
      (setf (ha-control-plane-maintenance-error hcp) nil))
    removed))

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
