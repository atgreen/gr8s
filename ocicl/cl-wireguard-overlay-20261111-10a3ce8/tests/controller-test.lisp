;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-wireguard-overlay/tests)
(in-suite cl-wireguard-overlay)

(test controller-observes-selects-and-applies-through-callbacks
  (let* ((direct (make-wireguard-path-observation
                  :name "direct" :handshake-age-seconds 1
                  :consecutive-successes 3 :trial-latency-milliseconds 20))
         (relay (make-wireguard-path-observation
                 :name "relay" :handshake-age-seconds 1
                 :consecutive-successes 3 :trial-latency-milliseconds 5))
         (observations (list direct relay))
         (applications nil)
         (controller
           (make-overlay-controller
            :observe (lambda (peer-id)
                       (is (string= "peer-a" peer-id))
                       observations)
            :apply (lambda (peer-id path reason)
                     (push (list peer-id path reason) applications)))))
    (multiple-value-bind (selected reason)
        (reconcile-overlay-peer controller "peer-a")
      (is (eq direct selected))
      (is (eq :current-unhealthy reason)))
    (is (= 1 (length applications)))
    (reconcile-overlay-peer controller "peer-a")
    (is (= 1 (length applications)))
    (setf (wireguard-path-observation-consecutive-failures direct) 2)
    (multiple-value-bind (selected reason)
        (reconcile-overlay-peer controller "peer-a")
      (is (eq relay selected))
      (is (eq :current-unhealthy reason)))
    (is (= 2 (length applications)))
    (is (eq relay (overlay-controller-selected-path controller "peer-a")))))
