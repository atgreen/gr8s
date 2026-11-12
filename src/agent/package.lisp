;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for the per-node agent and its operation streams.

(defpackage #:gr8s.agent
  (:use #:cl)
  (:shadow
   #:cancel-node-session
   #:make-node-session-control
   #:node-runtime-wireguard-metrics-text
   #:node-session-cancelled-p
   #:run-node-session)
  (:export
   #:cancel-node-session
   #:make-node-session-control
   #:node-session-cancelled-p
   #:run-node-session))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (export (intern "NODE-RUNTIME-WIREGUARD-METRICS-TEXT" '#:gr8s.agent) '#:gr8s.agent))
