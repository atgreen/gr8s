;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The HA control-plane coordinator (podster-c2d.7.1) that 'gr8s serve' starts
;;;; in HA mode: one control plane founds the Raft cluster, another joins it, the
;;;; leader gate reflects real leadership (so controllers run on exactly one
;;;; member), and a durable write on the leader's store replicates to the joiner.

(in-package #:gr8s/tests)
(def-suite ha-control-plane :in gr8s)
(in-suite ha-control-plane)

(test ha-control-plane-founds-joins-gates-and-replicates
  (with-temporary-store (s1 p1)
    (with-temporary-store (s2 p2)
      (declare (ignore p1 p2))
      (let ((h1 nil) (h2 nil))
        (unwind-protect
             (progn
               ;; Found the cluster on member 1.
               (setf h1 (gr8s::start-ha-control-plane s1 :id "cp1" :init t))
               (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p h1)))
                   "the founding control plane becomes leader")
               ;; Member 2 joins, learning member 1's address from its member.
               (let ((leader-port (gr8s::raft-member-port (gr8s::ha-control-plane-member h1))))
                 (setf h2 (gr8s::start-ha-control-plane
                           s2 :id "cp2" :join-host "127.0.0.1" :join-port leader-port)))
               (is (poll-until
                    (lambda () (member "cp2" (gr8s::raft-node-peers
                                              (gr8s::raft-member-node (gr8s::ha-control-plane-member h1)))
                                       :test #'equal)))
                   "the joining control plane becomes a voting peer")
               ;; The leader gate is true on exactly one member.
               (is (gr8s::ha-control-plane-leader-p h1) "member 1 holds leadership")
               (is (not (gr8s::ha-control-plane-leader-p h2)) "member 2 is a follower")
               ;; A durable write on the leader's store replicates to the follower.
               (gr8s::create-core-resource s1 "configmaps"
                                           (configmap-input "cm1" "k" "v1") "default")
               (is (poll-until
                    (lambda () (and (equal "v1" (configmap-value s1 "cm1" "k"))
                                    (equal "v1" (configmap-value s2 "cm1" "k"))))
                    :timeout 10)
                   "the write replicates from the leader to the follower control plane")
               ;; Internal writers such as node enrollment and heartbeats run on
               ;; every member.  A follower forwards their consensus proposal to
               ;; the leader, and the committed state returns to every replica.
               (let ((original (symbol-function 'gr8s::install-core-state-delta)))
                 (unwind-protect
                      (progn
                        ;; A leader can acknowledge the forwarded proposal before
                        ;; its commit notification returns to the authoring follower.
                        ;; Make that local apply gap deterministic: the write must
                        ;; still not return until this follower can read its result.
                        (setf (symbol-function 'gr8s::install-core-state-delta)
                              (lambda (store json)
                                (when (eq store s2) (sleep 0.2))
                                (funcall original store json)))
                        (gr8s::create-core-resource s2 "configmaps"
                                                    (configmap-input "cm2" "k" "x") "default")
                        (is (equal "x" (configmap-value s2 "cm2" "k"))
                            "a forwarded write has read-after-write consistency locally")
                        (is (poll-until
                             (lambda () (equal "x" (configmap-value s1 "cm2" "k")))
                             :timeout 10)
                            "a durable follower write is forwarded through the leader"))
                   (setf (symbol-function 'gr8s::install-core-state-delta) original))))
          (gr8s::stop-ha-control-plane h2)
          (gr8s::stop-ha-control-plane h1))))))
