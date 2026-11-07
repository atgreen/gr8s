;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for HTTP, watch, OpenAPI, and streaming API adapters.

(defpackage #:gr8s.apiserver
  (:use #:cl #:gr8s)
  (:shadow
   #:node-grpc-server
   #:node-grpc-server-port
   #:node-session-acknowledged-revision
   #:pending-node-operation-done-p
   #:pending-node-operation-error
   #:pending-node-operation-response
   #:publish-node-desired-state
   #:queue-node-operation
   #:release-node-operation
   #:route-http-request
   #:start-node-grpc-server
   #:start-agent-kubelet-server
   #:start-debug-server
   #:start-kubelet-server
   #:start-server
   #:stop-debug-server
   #:stop-node-grpc-server
   #:stop-kubelet-server
   #:stop-server)
  (:export
   #:node-grpc-server-port
   #:node-session-acknowledged-revision
   #:publish-node-desired-state
   #:start-node-grpc-server
   #:stop-node-grpc-server))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((apiserver (find-package '#:gr8s.apiserver))
        (composition (find-package '#:gr8s)))
    ;; Establish these identities before resource adapters and the node-session
    ;; implementation are read.  GR8S remains the compatibility facade.
    (dolist (name '("NODE-GRPC-SERVER"
                    "NODE-GRPC-SERVER-PORT"
                    "NODE-SESSION-ACKNOWLEDGED-REVISION"
                    "PENDING-NODE-OPERATION-DONE-P"
                    "PENDING-NODE-OPERATION-ERROR"
                    "PENDING-NODE-OPERATION-RESPONSE"
                    "PUBLISH-NODE-DESIRED-STATE"
                    "QUEUE-NODE-OPERATION"
                    "RELEASE-NODE-OPERATION"
                    "START-NODE-GRPC-SERVER"
                    "STOP-NODE-GRPC-SERVER"))
      (shadowing-import (find-symbol name apiserver) composition))
    (dolist (name '("NODE-GRPC-SERVER-PORT"
                    "NODE-SESSION-ACKNOWLEDGED-REVISION"
                    "PUBLISH-NODE-DESIRED-STATE"
                    "START-NODE-GRPC-SERVER"
                    "STOP-NODE-GRPC-SERVER"))
      (let ((symbol (find-symbol name apiserver)))
        (export symbol apiserver)
        (export symbol composition)))))
