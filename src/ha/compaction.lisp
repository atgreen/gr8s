;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.ha)

(defun validate-ha-compaction-options (bytes entries interval)
  (unless (and (typep bytes '(integer 1 *)) (typep entries '(integer 1 *))
               (or (null interval) (and (realp interval) (plusp interval))))
    (error "Invalid HA compaction thresholds or interval")))

(defun ha-compaction-due-unlocked-p (hcp)
  "Check disk bytes and conservative retained-command weight under the member mutex."
  (let* ((member (ha-control-plane-member hcp)) (node (raft-member-node member))
         (storage (gr8s.raft.transport::raft-member-owned-storage member)))
    (unless (sb-thread:holding-mutex-p (raft-member-lock member))
      (error "Compaction trigger requires the member mutex"))
    (and (gr8s.raft.transport::raft-member-running member)
         (gr8s.resources::member-store-restore-may-resume-p member)
         (> (raft-node-last-applied node) (raft-node-snapshot-index node))
         (<= (raft-node-last-applied node) (raft-node-commit-index node))
         (or (>= (- (raft-node-last-applied node) (raft-node-snapshot-index node))
                 (ha-control-plane-compaction-entries hcp))
             ;; JSON-bearing Lisp strings may use four bytes per character even
             ;; when their UTF-8 WAL uses one. Stop scanning once the budget is
             ;; met; the existing wire weight also bounds those string payloads.
             (loop with bytes = 0
                   for entry across (gr8s.raft:raft-node-log node)
                   do (incf bytes (+ 128 (gr8s.raft::raft-command-wire-weight
                                         (gr8s.raft:raft-entry-command entry))))
                   when (>= bytes (ha-control-plane-compaction-bytes hcp)) return t)
             (>= (sb-posix:stat-size
                  (sb-posix:fstat (sb-sys:fd-stream-fd (gr8s.raft::file-raft-storage-stream storage))))
                 (ha-control-plane-compaction-bytes hcp))))))

(defun call-with-ha-compaction-measurement (hcp rows index function)
  "Record attempts, wall ticks and process GC ticks, including abnormal exits.
Rows contain count, wall total/max/last and process GC total/max/last. GC deltas
include other threads and overlapping measurements; they are not CPU attribution."
  (let ((started (get-internal-real-time)) (gc-started sb-ext:*gc-run-time*))
    (unwind-protect (funcall function)
      (let ((elapsed (max 0 (- (get-internal-real-time) started)))
            (gc (max 0 (- sb-ext:*gc-run-time* gc-started))))
        (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
          (let ((row (or (aref rows index)
                         (setf (aref rows index) (make-array 7 :initial-element 0)))))
            (incf (aref row 0))
            (incf (aref row 1) elapsed)
            (incf (aref row 4) gc)
            (setf (aref row 2) (max (aref row 2) elapsed)
                  (aref row 3) elapsed
                  (aref row 5) (max (aref row 5) gc)
                  (aref row 6) gc)))))))

(defun call-with-ha-compaction-phase (hcp phase function)
  (call-with-ha-compaction-measurement
   hcp (ha-control-plane-compaction-phase-times hcp)
   (or (position phase '(:freeze :capture :retain :publish))
       (error "Unknown compaction phase: ~S" phase)) function))

(defmacro with-ha-compaction-phase ((hcp phase) &body body)
  `(call-with-ha-compaction-phase ,hcp ,phase (lambda () ,@body)))

(defun call-with-ha-compaction-member-lock (hcp section function)
  "Measure the entire compactor critical section after acquiring the member lock.
Includes trigger checks, preparation, gate changes and reaping, as applicable;
excludes acquisition wait and the diagnostic counter update at section exit."
  (let ((index (or (position section '(:check :freeze :publish :resume))
                   (error "Unknown compaction member-lock section: ~S" section))))
    (bt:with-lock-held ((raft-member-lock (ha-control-plane-member hcp)))
      (call-with-ha-compaction-measurement
       hcp (ha-control-plane-compaction-member-lock-times hcp) index function))))

(defmacro with-ha-compaction-member-lock ((hcp section) &body body)
  `(call-with-ha-compaction-member-lock ,hcp ,section (lambda () ,@body)))

(defun compact-ha-store-once (hcp)
  "Allow only one frozen view per control plane, including manual callers."
  (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
    (when (ha-control-plane-compaction-in-flight hcp)
      (return-from compact-ha-store-once nil))
    (setf (ha-control-plane-compaction-in-flight hcp) t))
  (unwind-protect (compact-ha-store-once-exclusive hcp)
    (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
      (setf (ha-control-plane-compaction-in-flight hcp) nil))))

(defun compact-ha-store-once-exclusive (hcp)
  "Freeze under drained barriers; serialize/retain outside live locks and gates.
Drain again before WAL replacement so uncertain durability remains fail-closed."
  (let ((member (ha-control-plane-member hcp)) (store (ha-control-plane-store hcp))
        (owns-gate nil) (prepared nil) (view nil) (temporary nil))
    (when (or (gr8s.store::store-access-blocked-p store)
              (not (with-ha-compaction-member-lock (hcp :check)
                     (ha-compaction-due-unlocked-p hcp))))
      (return-from compact-ha-store-once-exclusive nil))
    (unwind-protect
         (progn
           (gr8s.store::quiesce-store-access store)
           (setf owns-gate t)
           (gr8s.store::call-with-store-application-barriers
            store
            (lambda ()
              (with-ha-compaction-member-lock (hcp :freeze)
                (when (ha-compaction-due-unlocked-p hcp)
                  (setf prepared (gr8s.raft::raft-prepare-compaction (raft-member-node member)))
                  (when prepared
                    (setf view (with-ha-compaction-phase (hcp :freeze)
                                (gr8s.resources::freeze-store-snapshot
                                 store (gr8s.raft::raft-prepared-compaction-index prepared)
                                 (gr8s.raft::raft-prepared-compaction-term prepared))))))
                (when (gr8s.resources::member-store-restore-may-resume-p member)
                  (gr8s.store::resume-store-access store)
                  (setf owns-gate nil)))))
           (unless (and prepared (not owns-gate))
             (return-from compact-ha-store-once-exclusive nil))
           (let* ((index (gr8s.raft::raft-prepared-compaction-index prepared))
                  (term (gr8s.raft::raft-prepared-compaction-term prepared))
                  (root (gr8s::pod-store-path store)))
             (setf temporary (merge-pathnames
                              (format nil "raft/capture-~A.jsonl" (gr8s.store:generate-uid)) root))
             (with-ha-compaction-phase (hcp :capture)
               (gr8s.resources::capture-frozen-store-snapshot view temporary))
             ;; Drop the private view before copying/validating the artifact.
             (setf view nil)
             (let* ((digest (ironclad:byte-array-to-hex-string (ironclad:digest-file :sha256 temporary)))
                    (reference (gr8s.resources::store-snapshot-artifact-reference index term digest)))
               (gr8s.resources::call-with-store-artifact-pin
                member reference
                (lambda ()
                  (with-ha-compaction-phase (hcp :retain)
                    (gr8s.resources::retain-store-snapshot-artifact root temporary index term digest))
                  (when (gr8s.store::store-access-blocked-p store)
                    (return-from compact-ha-store-once-exclusive nil))
                  (gr8s.store::quiesce-store-access store)
                  (setf owns-gate t)
                  (gr8s.store::call-with-store-application-barriers
                   store
                   (lambda ()
                     (with-ha-compaction-member-lock (hcp :publish)
                       (when (and (gr8s.raft.transport::raft-member-running member)
                                  (gr8s.resources::member-store-restore-may-resume-p member)
                                  (with-ha-compaction-phase (hcp :publish)
                                    (gr8s.raft::raft-commit-prepared-compaction
                                     (raft-member-node member) prepared reference)))
                         (let ((reaped (gr8s.resources::reap-store-snapshot-artifacts-unlocked member root)))
                           (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
                             (incf (ha-control-plane-compaction-count hcp))
                             (incf (ha-control-plane-compaction-reaped hcp) reaped)
                             (setf (ha-control-plane-compaction-error hcp) nil)))
                         t)))))))))
      (unwind-protect
           (when (and temporary (probe-file temporary)) (delete-file temporary))
        (when owns-gate
        ;; Hold the same outer-before-member order through gate reopening, so a
        ;; failed WAL replacement cannot permit standalone/unconfirmed writes.
        (gr8s.store::call-with-store-application-barriers
         store
         (lambda ()
           (with-ha-compaction-member-lock (hcp :resume)
             (when (gr8s.resources::member-store-restore-may-resume-p member)
               (gr8s.store::resume-store-access store))))))))))

(defun start-ha-compaction-worker (hcp)
  (validate-ha-compaction-options (ha-control-plane-compaction-bytes hcp)
                                  (ha-control-plane-compaction-entries hcp)
                                  (ha-control-plane-compaction-interval hcp))
  ;; Member before compaction lock, matching publication's counter updates.
  (bt:with-lock-held ((raft-member-lock (ha-control-plane-member hcp)))
   (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
    (when (ha-control-plane-compaction-thread hcp) (error "Compaction worker already exists"))
    (let* ((node (raft-member-node (ha-control-plane-member hcp)))
           (previous (gr8s.raft::raft-node-retained-byte-limit node))
           (previous-catchup (gr8s.raft::raft-node-catchup-byte-limit node))
           (installed-catchup (min (or previous-catchup (* 128 1024 1024)) (* 128 1024 1024)))
           (budget (max (* 32 1024 1024) (* 2 (ha-control-plane-compaction-bytes hcp))))
           (installed (if previous (min previous budget) budget)))
      (setf (ha-control-plane-compaction-retention-policy hcp) (cons previous installed)
            (ha-control-plane-compaction-catchup-policy hcp) (cons previous-catchup installed-catchup)
            (gr8s.raft::raft-node-catchup-byte-limit node) installed-catchup
            (gr8s.raft::raft-node-retained-byte-limit node) installed))
    (setf (ha-control-plane-compaction-running hcp) t
          (ha-control-plane-compaction-thread hcp)
          (bt:make-thread
           (lambda ()
             (loop
               (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
                 (unless (ha-control-plane-compaction-running hcp) (return))
                 (bt:condition-wait (ha-control-plane-compaction-changed hcp)
                                    (ha-control-plane-compaction-lock hcp)
                                    :timeout (float (ha-control-plane-compaction-interval hcp) 1d0))
                 (unless (ha-control-plane-compaction-running hcp) (return)))
               (handler-case (compact-ha-store-once hcp)
                 (error (condition)
                   (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
                     (setf (ha-control-plane-compaction-error hcp) (princ-to-string condition)))
                   (format *error-output* "~&gr8s HA compaction failed: ~A~%" condition)))))
           :name "gr8s HA compaction"))))
  hcp)

(defun stop-ha-compaction-worker (hcp)
  "Join before stopping Raft: draining requests may still need its clock."
  (let ((thread nil))
    (bt:with-lock-held ((ha-control-plane-compaction-lock hcp))
      (setf (ha-control-plane-compaction-running hcp) nil
            thread (ha-control-plane-compaction-thread hcp))
      (bt:condition-notify (ha-control-plane-compaction-changed hcp)))
    (when thread (bt:join-thread thread))
    (bt:with-lock-held ((raft-member-lock (ha-control-plane-member hcp)))
      (let* ((policy (ha-control-plane-compaction-catchup-policy hcp))
             (node (raft-member-node (ha-control-plane-member hcp))))
        (when policy
          (when (eql (gr8s.raft::raft-node-catchup-byte-limit node) (cdr policy))
            (setf (gr8s.raft::raft-node-catchup-byte-limit node) (car policy))
            (unless (car policy) (gr8s.raft::raft-storage-clear-catchup (gr8s.raft:raft-node-storage node))))
          (setf (ha-control-plane-compaction-catchup-policy hcp) nil)))
      (let ((policy (ha-control-plane-compaction-retention-policy hcp))
            (node (raft-member-node (ha-control-plane-member hcp))))
        (when policy
          (when (eql (gr8s.raft::raft-node-retained-byte-limit node) (cdr policy))
            (setf (gr8s.raft::raft-node-retained-byte-limit node) (car policy)))
          (setf (ha-control-plane-compaction-retention-policy hcp) nil))))
    (setf (ha-control-plane-compaction-thread hcp) nil))
  hcp)
