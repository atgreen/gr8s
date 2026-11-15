;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The controller reconciliation pass the server supervisor runs each cycle.

(in-package #:gr8s.server)

(defun run-controller-pass (worker)
  "Run targeted Gateway publication or the full pass, sharing discovery encoding."
  (gr8s.kubelet::call-with-discovery-projection-cache
   (lambda ()
     (if (and (eq (reconciliation-worker-pass-scope worker) :gateway)
              (reconciliation-worker-gateway-reconcile worker))
         (funcall (reconciliation-worker-gateway-reconcile worker))
         (progn
           (when (reconciliation-worker-before-reconcile worker)
             (funcall (reconciliation-worker-before-reconcile worker)))
           (reconcile-all (reconciliation-worker-reconciler worker)
                          :observer (reconciliation-worker-observer worker)))))))
