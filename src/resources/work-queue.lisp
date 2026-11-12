;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The per-key serialized work queue and the exponential retry backoff now live
;;;; in the standalone cl-work-queue library (installed via ocicl).  gr8s consumes
;;;; them from two packages -- gr8s.resources (the volume reclaimer) and
;;;; gr8s.agent (the node runtime that stops and feeds the queue) -- so this shim
;;;; re-homes the library's public API into gr8s.resources and propagates it into
;;;; the gr8s composition package, exactly as resources/compat.lisp does for
;;;; symbols defined here directly.

(in-package #:gr8s.resources)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((symbols (list 'cl-work-queue:make-work-queue
                       'cl-work-queue:work-queue
                       'cl-work-queue:work-queue-active-p
                       'cl-work-queue:work-queue-running-workers
                       'cl-work-queue:work-queue-stop
                       'cl-work-queue:work-queue-stopped
                       'cl-work-queue:work-queue-submit
                       'cl-work-queue:work-queue-wait
                       'cl-work-queue:make-retry-backoff
                       'cl-work-queue:retry-backoff
                       'cl-work-queue:retry-backoff-clear
                       'cl-work-queue:retry-backoff-failed
                       'cl-work-queue:retry-backoff-ready-p
                       ;; The entries accessor is used by the reclaimer's pruning
                       ;; pass but is not part of the library's exported surface.
                       (find-symbol "RETRY-BACKOFF-ENTRIES" '#:cl-work-queue))))
    (import symbols '#:gr8s.resources)
    (export symbols '#:gr8s.resources)))
