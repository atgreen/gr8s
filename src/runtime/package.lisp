;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Implementation-independent container runtime protocol.

(defpackage #:gr8s.runtime
  (:use #:cl #:gr8s.model)
  (:export
   #:*running-pod-cancellation-deferred*
   #:*running-pod-cancellation-pending*
   #:*running-pod-convergence*
   #:+exec-output-window-bytes+
   #:+gr8s-container-label+
   #:+gr8s-host-network-label+
   #:+gr8s-managed-label+
   #:+gr8s-resource-version-label+
   #:+gr8s-spec-fingerprint-label+
   #:+gr8s-termination-file-label+
   #:+gr8s-termination-policy-label+
   #:+gr8s-uid-label+
   #:+port-forward-window-bytes+
   #:canonical-workload-json
   #:container-config-error
   #:container-image-pending
   #:container-image-pull-error
   #:copy-runtime-exec-result
   #:copy-runtime-pod
   #:fake-runtime
   #:fake-runtime-ensure-count
   #:fake-runtime-exec-result
   #:fake-runtime-exec-url
   #:fake-runtime-failure
   #:fake-runtime-last-exec
   #:fake-runtime-pods
   #:fail-if-requested
   #:make-fake-runtime
   #:make-runtime-exec-result
   #:make-runtime-pod
   #:pod-runtime-spec-fingerprint
   #:runtime-attach-url
   #:runtime-cancel-exec-session
   #:runtime-cancel-port-forward
   #:runtime-container-metrics
   #:runtime-resource-metrics
   #:runtime-delete
   #:runtime-delete-pod
   #:runtime-ensure
   #:runtime-prepare-pod-resources
   #:runtime-container-cdi-device-ids
   #:runtime-unprepare-pod-resources
   #:runtime-ephemeral-usage
   #:runtime-error
   #:runtime-error-message
   #:runtime-events
   #:runtime-exec-result
   #:runtime-exec-result-exit-code
   #:runtime-exec-result-stderr
   #:runtime-exec-result-stdout
   #:runtime-exec-session-exit-code
   #:runtime-exec-sync
   #:runtime-exec-url
   #:runtime-forget-pod-finalization
   #:runtime-logs
   #:runtime-network-metrics
   #:runtime-next-exec-session-output
   #:runtime-observe
   #:runtime-pod
   #:runtime-pod-container-details
   #:runtime-pod-logs
   #:runtime-pod-phase
   #:runtime-pod-pod-ip
   #:runtime-pod-pod-ips
   #:runtime-pod-resource-version
   #:runtime-pod-spec-fingerprint
   #:runtime-pod-status
   #:runtime-pod-uid
   #:runtime-port-forward-next
   #:runtime-port-forward-send
   #:runtime-port-forward-url
   #:runtime-reconcile-containers
   #:runtime-release-exec-session
   #:runtime-release-port-forward
   #:runtime-runs-containers-p
   #:runtime-send-exec-session-input
   #:runtime-start-attach-session
   #:runtime-start-exec-session
   #:runtime-start-port-forward
   #:runtime-terminate-pod
   #:runtime-unavailable
   #:runtime-unavailable-message
   #:set-fake-runtime-exec-result
   #:set-fake-runtime-exec-url
   #:set-fake-runtime-failure
   #:stop-runtime-deletions
   #:with-running-pod-cancellation-deferred))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (do-external-symbols (symbol '#:gr8s.runtime)
    (shadowing-import symbol '#:gr8s))
  (dolist (name '("FAKE-RUNTIME-ENSURE-COUNT" "MAKE-FAKE-RUNTIME"
                  "RUNTIME-DELETE" "RUNTIME-ENSURE" "RUNTIME-ERROR"
                  "RUNTIME-ERROR-MESSAGE" "RUNTIME-LOGS" "RUNTIME-OBSERVE"
                  "RUNTIME-POD-PHASE" "RUNTIME-POD-RESOURCE-VERSION"
                  "RUNTIME-POD-UID" "SET-FAKE-RUNTIME-FAILURE"))
    (export (find-symbol name '#:gr8s.runtime) '#:gr8s)))
