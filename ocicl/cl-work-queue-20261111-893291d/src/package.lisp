;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(defpackage #:cl-work-queue
  (:use #:cl)
  (:export
   #:make-work-queue
   #:work-queue
   #:work-queue-active-p
   #:work-queue-running-workers
   #:work-queue-stop
   #:work-queue-stopped
   #:work-queue-submit
   #:work-queue-wait
   #:make-retry-backoff
   #:retry-backoff
   #:retry-backoff-clear
   #:retry-backoff-failed
   #:retry-backoff-ready-p))

