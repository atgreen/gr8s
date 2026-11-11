;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-wireguard-overlay)

(defstruct wireguard-path-observation
  "One candidate endpoint's evidence, kept separate from the live kernel peer."
  name
  address
  (port 0)
  (latest-handshake-seconds 0)
  (handshake-age-seconds most-positive-fixnum)
  (transferred-bytes-delta 0)
  (transferred-bytes-total 0)
  trial-latency-milliseconds
  passive-rtt-microseconds
  (passive-tcp-samples 0)
  (passive-retransmits 0)
  passive-congestion-window
  (passive-active-flows 0)
  (passive-bytes-per-second 0)
  (safe-mtu 1420)
  (last-mtu-probe-at 0)
  (mtu-reason :initial)
  (mtu-changed-at 0)
  mtu-upgrade-candidate
  (mtu-upgrade-successes 0)
  (consecutive-successes 0)
  (consecutive-failures 0))

(defstruct wireguard-path-telemetry
  "One bounded userspace snapshot derived from passive transport observations."
  (rtt-microseconds 0)
  (tcp-samples 0)
  (retransmits 0)
  (congestion-window 0)
  (active-flows 0)
  (bytes 0)
  (interval-milliseconds 1))

(defun apply-wireguard-path-telemetry (observation telemetry)
  "Fold passive TELEMETRY into OBSERVATION without changing its safety state.
All values are clamped at this trust boundary: passive data may rank an already
verified path, but cannot alter handshakes, successes, or failures."
  (flet ((bounded (value ceiling)
           (min ceiling (max 0 (if (integerp value) value 0)))))
    (let ((interval (max 1 (bounded
                            (wireguard-path-telemetry-interval-milliseconds telemetry)
                            3600000))))
      (setf
       (wireguard-path-observation-passive-rtt-microseconds observation)
       (bounded (wireguard-path-telemetry-rtt-microseconds telemetry) 10000000)
       (wireguard-path-observation-passive-tcp-samples observation)
       (bounded (wireguard-path-telemetry-tcp-samples telemetry) 1000000000)
       (wireguard-path-observation-passive-retransmits observation)
       (bounded (wireguard-path-telemetry-retransmits telemetry) 1000000000)
       (wireguard-path-observation-passive-congestion-window observation)
       (bounded (wireguard-path-telemetry-congestion-window telemetry) 1000000)
       (wireguard-path-observation-passive-active-flows observation)
       (bounded (wireguard-path-telemetry-active-flows telemetry) 1000000)
       (wireguard-path-observation-passive-bytes-per-second observation)
       (min 1000000000000
            (floor (* 1000 (bounded (wireguard-path-telemetry-bytes telemetry)
                                    1000000000000))
                   interval)))))
  observation)

(defstruct wireguard-peer-path-state
  peer-id
  selected
  previous
  (reason :initial)
  (changed-at 0)
  (last-trial-at 0)
  (observations nil))

(defstruct wireguard-path-state
  (peers (make-hash-table :test #'equal))
  (history nil))

(defun discover-wireguard-path-mtu
    (probe &key (minimum 576) (maximum 1420))
  "Return the largest inner packet size PROBE verifies without fragmentation.
The search is logarithmically bounded. A failed minimum means the path itself is
unreachable; a lower-than-maximum result identifies a packet-size black hole."
  (unless (and (integerp minimum) (integerp maximum) (<= 576 minimum maximum 9000))
    (error "WireGuard MTU search bounds must satisfy 576 <= minimum <= maximum <= 9000"))
  (unless (funcall probe minimum)
    (return-from discover-wireguard-path-mtu (values nil :path-unreachable)))
  (let ((low minimum) (high maximum))
    (loop while (< low high)
          for candidate = (ceiling (+ low high) 2)
          do (if (funcall probe candidate)
                 (setf low candidate)
                 (setf high (1- candidate))))
    (values low (if (= low maximum) :maximum-verified
                    :packet-size-black-hole))))

(defun update-wireguard-path-mtu
    (observation discovered &key (upgrade-successes 3) (reason :probe-verified)
                                  (now 0))
  "Apply conservative MTU hysteresis: shrink now, grow after repeated proof."
  (unless (and (integerp discovered) (<= 576 discovered 9000))
    (error "Discovered WireGuard path MTU must be between 576 and 9000"))
  (let ((current (wireguard-path-observation-safe-mtu observation)))
    (cond
      ((< discovered current)
       (setf (wireguard-path-observation-safe-mtu observation) discovered
             (wireguard-path-observation-mtu-reason observation) reason
             (wireguard-path-observation-mtu-changed-at observation) now
             (wireguard-path-observation-mtu-upgrade-candidate observation) nil
             (wireguard-path-observation-mtu-upgrade-successes observation) 0))
      ((> discovered current)
       (if (eql discovered
                (wireguard-path-observation-mtu-upgrade-candidate observation))
           (incf (wireguard-path-observation-mtu-upgrade-successes observation))
           (setf (wireguard-path-observation-mtu-upgrade-candidate observation) discovered
                 (wireguard-path-observation-mtu-upgrade-successes observation) 1))
       (when (>= (wireguard-path-observation-mtu-upgrade-successes observation)
                 upgrade-successes)
         (setf (wireguard-path-observation-safe-mtu observation) discovered
               (wireguard-path-observation-mtu-reason observation) reason
               (wireguard-path-observation-mtu-changed-at observation) now
               (wireguard-path-observation-mtu-upgrade-candidate observation) nil
               (wireguard-path-observation-mtu-upgrade-successes observation) 0)))
      (t
       (setf (wireguard-path-observation-mtu-upgrade-candidate observation) nil
             (wireguard-path-observation-mtu-upgrade-successes observation) 0)))
    (wireguard-path-observation-safe-mtu observation)))


(defun wireguard-path-trial-allowed-p
    (peer now &key (minimum-interval-seconds 30))
  "Rate-limit trials for PEER without delaying unhealthy-path failover logic."
  (>= (- now (wireguard-peer-path-state-last-trial-at peer))
      minimum-interval-seconds))

(defun wireguard-path-healthy-p (observation &key (maximum-handshake-age 180))
  "Whether OBSERVATION is safe to retain or select without another trial."
  (and observation
       (<= (wireguard-path-observation-handshake-age-seconds observation)
           maximum-handshake-age)
       (< (wireguard-path-observation-consecutive-failures observation) 2)))

(defun wireguard-path-score (observation)
  "Return a lower-is-better path cost from handshake freshness, trial latency,
bulk byte progress, and failures. Success count gates optimization separately."
  (max
   1
   (+ (if (string= "relay" (wireguard-path-observation-name observation))
          100000 0)
      (or (wireguard-path-observation-trial-latency-milliseconds observation)
          1000)
      (* 2 (wireguard-path-observation-handshake-age-seconds observation))
      (* 1000 (wireguard-path-observation-consecutive-failures observation))
      ;; Passive TCP evidence is deliberately bounded and never participates
      ;; in WIREGUARD-PATH-HEALTHY-P. It can optimize among safe paths only.
      (min 2000 (floor (or (wireguard-path-observation-passive-rtt-microseconds
                            observation)
                           0)
                       1000))
      (let ((samples (wireguard-path-observation-passive-tcp-samples observation)))
        (if (plusp samples)
            (min 3000
                 (floor (* 10000
                           (wireguard-path-observation-passive-retransmits observation))
                        samples))
            0))
      (let ((window (wireguard-path-observation-passive-congestion-window observation)))
        (if (and window (plusp window))
            (min 1000 (floor 1000 window))
            0))
      (- (min 50
              (* 5
                 (integer-length
                  (wireguard-path-observation-transferred-bytes-delta
                   observation))))))))

(defun wireguard-path-less-p (left right)
  "Order every healthy direct path before a relay, then compare measured cost."
  (let ((left-relay (string= "relay" (wireguard-path-observation-name left)))
        (right-relay (string= "relay" (wireguard-path-observation-name right))))
    (if (eq left-relay right-relay)
        (< (wireguard-path-score left) (wireguard-path-score right))
        (not left-relay))))

(defun select-wireguard-path
    (current observations &key (minimum-successes 3)
                              (improvement-ratio 4/5)
                              (maximum-handshake-age 180))
  "Choose a path conservatively. Fail away from an unhealthy CURRENT at once;
otherwise require MINIMUM-SUCCESSES and at least twenty percent lower cost."
  (let* ((healthy
           (remove-if-not
            (lambda (observation)
              (wireguard-path-healthy-p
               observation :maximum-handshake-age maximum-handshake-age))
            observations))
         (best (first (sort (copy-list healthy) #'wireguard-path-less-p))))
    (cond
      ((not (wireguard-path-healthy-p
             current :maximum-handshake-age maximum-handshake-age))
       (if best (values best :current-unhealthy)
           (values current :no-healthy-alternative)))
      ((or (null best) (eq best current))
       (values current :current-preferred))
      ((< (wireguard-path-observation-consecutive-successes best)
          minimum-successes)
       (values current :candidate-unproven))
      ((<= (wireguard-path-score best)
           (* improvement-ratio (wireguard-path-score current)))
       (values best :sustained-improvement))
      (t (values current :current-preferred)))))

