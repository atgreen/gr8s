;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; CronJob schedule parsing, next/previous firing-time arithmetic and the TZif
;;;; timezone reader now live in the standalone cl-cronexpr library (installed via
;;;; ocicl).  gr8s uses them from gr8s.resources (CronJob resources, the CEL
;;;; library) and gr8s.controllers (the CronJob controller), so this shim
;;;; re-homes the library's public API into gr8s.resources and propagates it into
;;;; the gr8s composition package, as resources/compat.lisp does for symbols
;;;; defined here directly.

(in-package #:gr8s.resources)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((symbols (list 'cl-cronexpr:cron-schedule
                       'cl-cronexpr:parse-cron
                       'cl-cronexpr:next-cron-time
                       'cl-cronexpr:most-recent-cron-time
                       'cl-cronexpr:format-cron-time
                       'cl-cronexpr:invalid-cron-schedule
                       'cl-cronexpr:invalid-cron-schedule-text
                       'cl-cronexpr:cron-zone
                       'cl-cronexpr:make-cron-zone
                       'cl-cronexpr:load-cron-zone
                       'cl-cronexpr:cron-zone-offset
                       'cl-cronexpr:parse-tzif
                       'cl-cronexpr:extend-zone-transitions
                       'cl-cronexpr:+unix-epoch-universal+)))
    (import symbols '#:gr8s.resources)
    (export symbols '#:gr8s.resources)
    (shadowing-import symbols '#:gr8s)))
