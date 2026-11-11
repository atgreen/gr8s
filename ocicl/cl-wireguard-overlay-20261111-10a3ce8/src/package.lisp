;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(defpackage #:cl-wireguard-overlay
  (:use #:cl)
  (:export
   #:overlay-node #:make-overlay-node #:overlay-node-name
   #:overlay-node-region #:overlay-node-zone
   #:wireguard-topology-plan #:wireguard-topology-plan-mode
   #:wireguard-topology-plan-object
   #:plan-wireguard-topology #:wireguard-topology-neighbors
   #:wireguard-topology-next-hop
   #:wireguard-path-observation #:make-wireguard-path-observation
   #:wireguard-path-observation-name #:wireguard-path-observation-safe-mtu
   #:wireguard-path-observation-handshake-age-seconds
   #:wireguard-path-observation-consecutive-successes
   #:wireguard-path-observation-consecutive-failures
   #:wireguard-path-observation-trial-latency-milliseconds
   #:wireguard-path-observation-mtu-upgrade-successes
   #:wireguard-path-telemetry #:make-wireguard-path-telemetry
   #:apply-wireguard-path-telemetry
   #:wireguard-peer-path-state #:make-wireguard-peer-path-state
   #:wireguard-path-trial-allowed-p #:wireguard-path-healthy-p
   #:wireguard-path-score #:select-wireguard-path
   #:discover-wireguard-path-mtu #:update-wireguard-path-mtu
   #:overlay-controller #:make-overlay-controller
   #:overlay-controller-selected-path #:reconcile-overlay-peer))
