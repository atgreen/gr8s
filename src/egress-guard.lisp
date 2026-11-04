;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; gr8s-facing entry point for the per-endpoint egress guard: JIT-compile the
;;;; Whistler program held in src/egress-guard-program.lisp, in-process, with no
;;;; ELF.  The CNI policy installer will build on this (podster-7q2.5b); for now
;;;; it is the compile step the migration and its tests share with the socket LB
;;;; via the generic compile-whistler-program helper in src/service-lb.lisp.

(in-package #:gr8s)

(defun compile-egress-guard ()
  "JIT-compile the per-endpoint egress guard. Returns (values map-specs
prog-specs), the same shape as compile-service-lb."
  (compile-whistler-program *egress-guard-map-forms* *egress-guard-program-forms*))
