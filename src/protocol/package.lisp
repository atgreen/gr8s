;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for node and streaming wire protocols.

(defpackage #:gr8s.protocol
  (:use #:cl #:gr8s)
  (:shadow
   #:+node-protocol-version+
   #:connect-runtime-stream
   #:ensure-node-protocol-version
   #:make-agent-envelope
   #:make-server-envelope
   #:make-spdy-server
   #:make-unix-grpc-channel
   #:read-websocket-frame)
  (:export
   #:+node-protocol-version+
   #:connect-runtime-stream
   #:ensure-node-protocol-version
   #:make-agent-envelope
   #:make-server-envelope
   #:make-spdy-server
   #:make-unix-grpc-channel
   #:read-websocket-frame))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((protocol (find-package '#:gr8s.protocol))
        (composition (find-package '#:gr8s)))
    (dolist (name '("+NODE-PROTOCOL-VERSION+"
                    "CONNECT-RUNTIME-STREAM"
                    "ENSURE-NODE-PROTOCOL-VERSION"
                    "MAKE-AGENT-ENVELOPE"
                    "MAKE-SERVER-ENVELOPE"
                    "MAKE-SPDY-SERVER"
                    "MAKE-UNIX-GRPC-CHANNEL"
                    "READ-WEBSOCKET-FRAME"))
      (let ((old (find-symbol name composition))
            (new (find-symbol name protocol)))
        (dolist (user (package-used-by-list composition))
          (when (eq old (find-symbol name user))
            (shadowing-import new user)))
        (shadowing-import new composition)
        (export new protocol)))
    (dolist (name '("+NODE-PROTOCOL-VERSION+"
                    "ENSURE-NODE-PROTOCOL-VERSION"
                    "MAKE-AGENT-ENVELOPE"
                    "MAKE-SERVER-ENVELOPE"))
      (export (find-symbol name protocol) composition))))
