;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The controller reconciliation pass the server supervisor runs each cycle.

(in-package #:gr8s.server)

(defun run-controller-pass (worker)
  "One complete controller operation: the optional before-reconcile hook, then a
full reconcile of WORKER's reconciler."
  (when (reconciliation-worker-before-reconcile worker)
    (funcall (reconciliation-worker-before-reconcile worker)))
  (reconcile-all (reconciliation-worker-reconciler worker)
                 :observer (reconciliation-worker-observer worker)))
