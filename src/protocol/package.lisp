;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for node and streaming wire protocols.

(defpackage #:gr8s.protocol
  (:use #:cl)
  (:shadow
   #:+node-protocol-version+
   #:connect-runtime-stream
   #:ensure-node-protocol-version
   #:make-agent-envelope
   #:make-server-envelope
   #:make-spdy-server
   #:make-unix-grpc-channel
   #:read-websocket-frame
   #:unsupported-node-protocol-version
   #:unsupported-node-protocol-version-received
   #:unsupported-node-protocol-version-supported)
  (:export
   #:+node-protocol-version+
   #:connect-runtime-stream
   #:ensure-node-protocol-version
   #:make-agent-envelope
   #:make-server-envelope
   #:make-spdy-server
   #:make-unix-grpc-channel
   #:read-websocket-frame
   #:unsupported-node-protocol-version
   #:unsupported-node-protocol-version-received
   #:unsupported-node-protocol-version-supported))
