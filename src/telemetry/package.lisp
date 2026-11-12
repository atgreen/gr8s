;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for cluster telemetry helpers (Prometheus exposition).
;;;; Defined early so the stage-1 declarations can home its symbols before the
;;;; implementation in telemetry/cluster.lisp loads.

(defpackage #:gr8s.telemetry
  (:use #:cl))
