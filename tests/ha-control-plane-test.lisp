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

(test ha-control-plane-replicates-image-tracker-leases-and-swarms
  (with-temporary-store (s1 p1)
    (with-temporary-store (s2 p2)
      (declare (ignore p1 p2))
      (let ((h1 nil) (h2 nil))
        (unwind-protect
             (progn
               (setf h1 (gr8s::start-ha-control-plane s1 :id "tracker-cp1" :init t))
               (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p h1))))
               (setf h2
                     (gr8s::start-ha-control-plane
                      s2 :id "tracker-cp2" :join-host "127.0.0.1"
                      :join-port (gr8s::raft-member-port
                                  (gr8s::ha-control-plane-member h1))))
               (is (poll-until
                    (lambda ()
                      (member "tracker-cp2"
                              (gr8s::raft-node-peers
                               (gr8s::raft-member-node
                                (gr8s::ha-control-plane-member h1)))
                              :test #'equal))))
               (multiple-value-bind (digest torrent) (tracker-test-torrent)
                 (let* ((token (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 17))
                        (peer-id (bt-octets "-GR8001-AAAAAAAAAAAA"))
                        (commit (gr8s::pod-store-consensus-commit-fn s2))
                        (acquired
                          (funcall
                           commit :image-tracker
                           (gr8s.image-distribution::make-tracker-command
                            :action :acquire :digest digest :node-name "node-a"
                            :now 1000 :token token))))
                   (is (eq :granted (getf acquired :status))
                       "a follower returns the committed lease result")
                   (is (equalp token
                               (gr8s.image-distribution::tracker-result-octets
                                acquired :token)))
                   (dolist (store (list s1 s2))
                     (let ((view
                             (gr8s.image-distribution::tracker-lookup
                              (gr8s::pod-store-image-tracker store) digest "node-b"
                              :now 1000)))
                       (is (eq :waiting
                               (gr8s.image-distribution::tracker-view-status view)))
                       (is (string= "node-a"
                                    (gr8s.image-distribution::tracker-view-origin-node view)))))
                   (let ((renewed
                           (funcall
                            (gr8s::pod-store-consensus-commit-fn s1)
                            :image-tracker
                            (gr8s.image-distribution::make-tracker-command
                             :action :renew :digest digest :node-name "node-a"
                             :now 1001 :token token))))
                     (is (eq :ok (getf renewed :status)))
                     (is (= 1121 (getf renewed :expires-at))))
                   (let ((published
                           (funcall
                            commit :image-tracker
                            (gr8s.image-distribution::make-tracker-command
                             :action :publish :digest digest :node-name "node-a"
                             :now 1002 :token token
                             :metainfo (gr8s.image-distribution::blob-torrent-metainfo torrent)
                             :address "10.0.0.1" :port 6881 :peer-id peer-id))))
                     (is (eq :ok (getf published :status))))
                   (dolist (store (list s1 s2))
                     (let ((view
                             (gr8s.image-distribution::tracker-lookup
                              (gr8s::pod-store-image-tracker store) digest "node-b"
                              :now 1002)))
                       (is (eq :available
                               (gr8s.image-distribution::tracker-view-status view)))
                       (is (equalp (gr8s.image-distribution::blob-torrent-infohash torrent)
                                   (gr8s.image-distribution::tracker-view-infohash view)))
                       (is (string= "node-a"
                                    (gr8s.image-distribution::tracker-peer-node-name
                                     (first
                                      (gr8s.image-distribution::tracker-view-peers view)))))))
                   (funcall
                    (gr8s::pod-store-consensus-commit-fn s1)
                    :image-tracker
                    (gr8s.image-distribution::make-tracker-command
                     :action :announce :digest digest :node-name "node-b"
                     :now 1003 :address "10.0.0.2" :port 6882
                     :peer-id (bt-octets "-GR8001-BBBBBBBBBBBB") :complete-p t))
                   (is (poll-until
                        (lambda ()
                          (every
                           (lambda (store)
                             (= 2 (length
                                   (gr8s.image-distribution::tracker-view-peers
                                    (gr8s.image-distribution::tracker-lookup
                                     (gr8s::pod-store-image-tracker store)
                                     digest "node-c" :now 1003)))))
                           (list s1 s2))))
                       "the peer announcement converges on every member")
                   (funcall
                    commit :image-tracker
                    (gr8s.image-distribution::make-tracker-command
                     :action :withdraw :digest digest :node-name "node-b" :now 1004))
                   (dolist (store (list s1 s2))
                     (let ((peers
                             (gr8s.image-distribution::tracker-view-peers
                              (gr8s.image-distribution::tracker-lookup
                               (gr8s::pod-store-image-tracker store) digest "node-c"
                               :now 1004))))
                       (is (= 1 (length peers)))
                       (is (string= "node-a"
                                    (gr8s.image-distribution::tracker-peer-node-name
                                     (first peers))))))))
          (gr8s::stop-ha-control-plane h2)
          (gr8s::stop-ha-control-plane h1)))))))
