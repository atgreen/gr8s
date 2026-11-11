;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-wireguard-overlay/tests)
(in-suite cl-wireguard-overlay)

(defun nodes (count &key (regions 1) (zones 1))
  (loop for index below count
        collect (make-overlay-node
                 :name (format nil "node-~2,'0D" index)
                 :region (format nil "r~D" (mod index regions))
                 :zone (format nil "z~D" (mod index zones)))))

(test keeps-small-overlays-direct
  (let* ((members (nodes 4))
         (plan (plan-wireguard-topology members :full-mesh-limit 8)))
    (is (eq :full-mesh (wireguard-topology-plan-mode plan)))
    (dolist (member members)
      (is (= 3 (length (wireguard-topology-neighbors
                        plan (overlay-node-name member))))))))

(test sparse-plans-are-deterministic-bounded-and-routable
  (let* ((members (nodes 18 :regions 2 :zones 6))
         (plan (plan-wireguard-topology members :full-mesh-limit 8))
         (again (plan-wireguard-topology (reverse members) :full-mesh-limit 8)))
    (is (eq :sparse (wireguard-topology-plan-mode plan)))
    (is (equal (wireguard-topology-plan-object plan)
               (wireguard-topology-plan-object again)))
    (dolist (source members)
      (let ((neighbors (wireguard-topology-neighbors plan (overlay-node-name source))))
        (is (<= (length neighbors) 6))
        (dolist (destination members)
          (unless (eq source destination)
            (let ((hop (wireguard-topology-next-hop
                        plan (overlay-node-name source) (overlay-node-name destination))))
              (is-true hop)
              (is (member hop neighbors :test #'string=)))))))))

(test non-transit-members-remain-reachable-leaves
  (let* ((members (nodes 10))
         (stable (mapcar #'overlay-node-name (rest members)))
         (leaf (overlay-node-name (first members)))
         (plan (plan-wireguard-topology members :full-mesh-limit 8
                                        :transit-node-names stable)))
    (is (<= (length (wireguard-topology-neighbors plan leaf)) 2))
    (dolist (source stable)
      (dolist (destination stable)
        (unless (string= source destination)
          (let ((hop (wireguard-topology-next-hop plan source destination)))
            (is-true hop)
            (is (not (string= leaf hop)))))))
    (is (wireguard-topology-next-hop plan (first stable) leaf))))
