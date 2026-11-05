;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Node desired-state replication (podster-8ia.4): a node's control-plane-
;;;; assigned podCIDR (and labels/taints) must survive leader failover, or a new
;;;; leader could hand the node a different CIDR than its agent is already using.
;;;; Heartbeat/lease state is observed and deliberately NOT replicated.

(in-package #:gr8s/tests)
(def-suite ha-node-cidr :in gr8s)
(in-suite ha-node-cidr)

(defun ha-node-cidr (store name)
  (let ((node (ignore-errors (gr8s:get-node store name))))
    (and node (gr8s:node-record-pod-cidr node))))

(test node-cidr-replicates-and-survives-failover
  (with-temporary-store (s1 p1)
    (with-temporary-store (s2 p2)
      (with-temporary-store (s3 p3)
        (declare (ignore p1 p2 p3))
        (let ((h1 nil) (h2 nil) (h3 nil))
          (unwind-protect
               (progn
                 (setf h1 (gr8s::start-ha-control-plane s1 :id "cp1" :init t))
                 (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p h1))))
                 (let ((lp (gr8s::raft-member-port (gr8s::ha-control-plane-member h1))))
                   (setf h2 (gr8s::start-ha-control-plane s2 :id "cp2" :join-host "127.0.0.1" :join-port lp))
                   (setf h3 (gr8s::start-ha-control-plane s3 :id "cp3" :join-host "127.0.0.1" :join-port lp)))
                 (is (poll-until
                      (lambda () (= 2 (length (gr8s::raft-node-peers
                                               (gr8s::raft-member-node (gr8s::ha-control-plane-member h1))))))
                      :timeout 15)
                     "both followers joined")
                 ;; Register a worker on the leader with an assigned podCIDR.
                 (gr8s:register-node
                  s1 (gr8s:make-node-record :id "node-1" :name "worker-a" :pod-cidr "10.88.0.0/20"))
                 (is (poll-until
                      (lambda () (every (lambda (s) (equal "10.88.0.0/20" (ha-node-cidr s "worker-a")))
                                        (list s1 s2 s3)))
                      :timeout 10)
                     "the assigned podCIDR replicates to every member")
                 ;; Kill the leader; a survivor keeps the CIDR assignment.
                 (gr8s::stop-ha-control-plane h1)
                 (setf h1 nil)
                 (is (poll-until (lambda () (or (gr8s::ha-control-plane-leader-p h2)
                                                (gr8s::ha-control-plane-leader-p h3)))
                                 :timeout 20)
                     "a survivor becomes leader")
                 (is (and (equal "10.88.0.0/20" (ha-node-cidr s2 "worker-a"))
                          (equal "10.88.0.0/20" (ha-node-cidr s3 "worker-a")))
                     "the podCIDR assignment is not lost on failover"))
            (dolist (h (list h1 h2 h3)) (when h (ignore-errors (gr8s::stop-ha-control-plane h))))))))))
