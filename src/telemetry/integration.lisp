;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Explicit cross-module imports for GR8S.TELEMETRY.
;;;;
;;;; GR8S.TELEMETRY (:use #:cl) only; it imports exactly the sibling symbols the
;;;; cluster telemetry exposition references.  Loaded after the owning modules so
;;;; the control-plane-runtime class and node gRPC server accessors are defined.

(in-package #:gr8s.telemetry)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (dolist (spec '(("GR8S.APISERVER" "NODE-GRPC-SERVER-LOCK" "NODE-GRPC-SERVER-STATUSES"
                   "NODE-GRPC-SERVER-STORE")
                  ("GR8S.CONTROLLERS" "CONTROL-PLANE-RUNTIME" "CONTROL-PLANE-RUNTIME-NODE-SERVER"
                   "GET-NODE")
                  ("GR8S.MODEL" "NODE-RECORD-RUNTIME-READY-P")
                  ("GR8S.RUNTIME" "RUNTIME-NETWORK-METRICS")))
    (let ((pkg (find-package (first spec))))
      (unless pkg (error "GR8S.TELEMETRY imports from missing package ~A" (first spec)))
      (dolist (name (rest spec))
        (shadowing-import (intern name pkg) '#:gr8s.telemetry)))))
