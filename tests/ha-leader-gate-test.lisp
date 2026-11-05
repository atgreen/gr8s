;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The HA controller leader gate (podster-c2d.7): the reconciliation worker
;;;; only drives controllers while this control plane holds leadership. A
;;;; follower's worker spins without reconciling anything, and starts the moment
;;;; it is promoted -- so exactly one member runs the controllers at a time.

(in-package #:gr8s/tests)
(def-suite ha-leader-gate :in gr8s)
(in-suite ha-leader-gate)

(test leader-gate-runs-controllers-only-while-leader
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime))
           (leader nil)                 ; promotion toggle, flipped by the test
           (passes 0)                   ; reconcile passes actually run
           (worker (gr8s::start-reconciliation-worker
                    reconciler
                    :interval 0.01
                    :leader-gate (lambda () leader)
                    :before-reconcile (lambda () (incf passes)))))
      (unwind-protect
           (progn
             ;; As a follower, the worker spins but reconciles nothing.
             (sleep 0.2)
             (is (zerop passes) "a follower runs no reconciliation passes")
             ;; Promote: controllers start driving.
             (setf leader t)
             (is (poll-until (lambda () (plusp passes)) :timeout 5)
                 "a promoted leader starts reconciling")
             ;; Demote: passes stop advancing again.
             (setf leader nil)
             (sleep 0.1)
             (let ((frozen passes))
               (sleep 0.2)
               (is (= frozen passes) "a demoted leader stops reconciling")))
        (gr8s::stop-reconciliation-worker worker)))))
