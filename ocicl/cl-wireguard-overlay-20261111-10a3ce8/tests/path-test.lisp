;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-wireguard-overlay/tests)
(in-suite cl-wireguard-overlay)

(test fails-over-immediately-but-optimizes-conservatively
  (let* ((stale (make-wireguard-path-observation
                 :name "public" :handshake-age-seconds 1000
                 :consecutive-failures 2 :trial-latency-milliseconds 10))
         (private (make-wireguard-path-observation
                   :name "private" :handshake-age-seconds 2
                   :consecutive-successes 1 :trial-latency-milliseconds 20)))
    (multiple-value-bind (selected reason)
        (select-wireguard-path stale (list stale private))
      (is (eq private selected))
      (is (eq :current-unhealthy reason))))
  (let* ((current (make-wireguard-path-observation
                   :name "public" :handshake-age-seconds 3
                   :consecutive-successes 8 :trial-latency-milliseconds 100))
         (candidate (make-wireguard-path-observation
                     :name "private" :handshake-age-seconds 3
                     :consecutive-successes 2 :trial-latency-milliseconds 20)))
    (multiple-value-bind (selected reason)
        (select-wireguard-path current (list current candidate))
      (is (eq current selected))
      (is (eq :candidate-unproven reason)))
    (setf (wireguard-path-observation-consecutive-successes candidate) 3)
    (multiple-value-bind (selected reason)
        (select-wireguard-path current (list current candidate))
      (is (eq candidate selected))
      (is (eq :sustained-improvement reason)))))

(test direct-paths-precede-relays-while-healthy
  (let ((direct (make-wireguard-path-observation
                 :name "private" :handshake-age-seconds 1
                 :consecutive-successes 3 :trial-latency-milliseconds 100))
        (relay (make-wireguard-path-observation
                :name "relay" :handshake-age-seconds 1
                :consecutive-successes 10 :trial-latency-milliseconds 1)))
    (multiple-value-bind (selected reason)
        (select-wireguard-path direct (list relay direct))
      (is (eq direct selected))
      (is (eq :current-preferred reason)))))

(test discovers-and-hysteretically-updates-path-mtu
  (let ((probes 0))
    (multiple-value-bind (mtu reason)
        (discover-wireguard-path-mtu
         (lambda (size) (incf probes) (<= size 1280))
         :minimum 576 :maximum 1420)
      (is (= 1280 mtu))
      (is (eq :packet-size-black-hole reason))
      (is (< probes 12))))
  (let ((path (make-wireguard-path-observation :safe-mtu 1420)))
    (is (= 1280 (update-wireguard-path-mtu path 1280 :now 1)))
    (is (= 1280 (update-wireguard-path-mtu path 1400 :now 2)))
    (is (= 1280 (update-wireguard-path-mtu path 1400 :now 3)))
    (is (= 1400 (update-wireguard-path-mtu path 1400 :now 4)))))

(test passive-telemetry-is-bounded-and-cannot-create-health
  (let ((path (make-wireguard-path-observation
               :name "public" :handshake-age-seconds 999
               :consecutive-failures 2)))
    (apply-wireguard-path-telemetry
     path (make-wireguard-path-telemetry
           :rtt-microseconds -5 :tcp-samples -1 :retransmits 999999999999
           :active-flows 999999999999 :bytes 999999999999999
           :interval-milliseconds 0))
    (is-false (wireguard-path-healthy-p path))
    (is (plusp (wireguard-path-score path)))))
