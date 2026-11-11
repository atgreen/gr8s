;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(require "asdf")
(asdf:load-asd
 (merge-pathnames "../cl-wireguard-overlay.asd" *load-truename*))
(asdf:load-system "cl-wireguard-overlay")

(let* ((nodes
         (list
          (cl-wireguard-overlay:make-overlay-node
           :name "alpha" :region "east" :zone "east-a")
          (cl-wireguard-overlay:make-overlay-node
           :name "bravo" :region "east" :zone "east-b")
          (cl-wireguard-overlay:make-overlay-node
           :name "charlie" :region "west" :zone "west-a")))
       (plan (cl-wireguard-overlay:plan-wireguard-topology
              nodes :full-mesh-limit 2))
       (direct
         (cl-wireguard-overlay:make-wireguard-path-observation
          :name "direct" :address "198.51.100.8" :port 51820
          :handshake-age-seconds 8 :consecutive-successes 4
          :trial-latency-milliseconds 12))
       (relay
         (cl-wireguard-overlay:make-wireguard-path-observation
          :name "relay" :address "203.0.113.20" :port 51820
          :handshake-age-seconds 5 :consecutive-successes 5
          :trial-latency-milliseconds 20))
       (controller
         (cl-wireguard-overlay:make-overlay-controller
          :observe (lambda (peer-id)
                     (declare (ignore peer-id))
                     (list direct relay))
          :apply (lambda (peer-id path reason)
                   (format t "selected ~A for ~A (~A)~%"
                           (cl-wireguard-overlay:wireguard-path-observation-name
                            path)
                           peer-id reason)))))
  (format t "topology: ~A~%"
          (cl-wireguard-overlay:wireguard-topology-plan-mode plan))
  (format t "alpha to charlie: ~A~%"
          (cl-wireguard-overlay:wireguard-topology-next-hop
           plan "alpha" "charlie"))
  (cl-wireguard-overlay:reconcile-overlay-peer controller "peer-7"))
