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
  (let ((agent (find-package '#:gr8s.agent))
        (composition (find-package '#:gr8s)))
    (dolist (name '("CANCEL-NODE-SESSION"
                    "MAKE-NODE-SESSION-CONTROL"
                    "NODE-RUNTIME-WIREGUARD-METRICS-TEXT"
                    "NODE-SESSION-CANCELLED-P"
                    "RUN-NODE-SESSION"))
      (let ((old (find-symbol name composition))
            (new (find-symbol name agent)))
        (dolist (user (package-used-by-list composition))
          (when (eq old (find-symbol name user))
            (shadowing-import new user)))
        (shadowing-import new composition)
        (export new agent)))
    (export (find-symbol "RUN-NODE-SESSION" agent) composition)))
