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

(defun race-ha-core-http-writes (left right left-server right-server method path left-body right-body)
  "Pause each member after authoring its command, then commit left before right."
  (let ((arrived (sb-thread:make-semaphore :count 0))
        (release-left (sb-thread:make-semaphore :count 0))
        (release-right (sb-thread:make-semaphore :count 0))
        (original-left (gr8s::pod-store-consensus-commit-fn left))
        (original-right (gr8s::pod-store-consensus-commit-fn right))
        (a nil) (b nil) (left-result nil) (right-result nil))
    (labels ((wrapper (original release)
               (lambda (tag payload)
                 (when (eq tag :core-delta)
                   (sb-thread:signal-semaphore arrived)
                   (unless (sb-thread:wait-on-semaphore release :timeout 30)
                     (error "Timed out waiting to commit concurrent core write")))
                 (funcall original tag payload)))
             (send (server body)
               (handler-case
                   (nth-value 1 (drakma:http-request
                                 (format nil "http://127.0.0.1:~D~A" (hunchentoot:acceptor-port server) path)
                                 :method method :content-type (if (eq method :post) "application/json" "application/merge-patch+json")
                                 :content body :proxy nil :redirect nil :connection-timeout 20))
                 (error (condition) (princ-to-string condition)))))
      (unwind-protect
           (progn
             (setf (gr8s::pod-store-consensus-commit-fn left) (wrapper original-left release-left)
                   (gr8s::pod-store-consensus-commit-fn right) (wrapper original-right release-right)
                   a (sb-thread:make-thread (lambda () (setf left-result (send left-server left-body))))
                   b (sb-thread:make-thread (lambda () (setf right-result (send right-server right-body)))))
             (assert (sb-thread:wait-on-semaphore arrived :timeout 15))
             (assert (sb-thread:wait-on-semaphore arrived :timeout 15))
             (sb-thread:signal-semaphore release-left)
             (assert (not (eq :timeout (sb-thread:join-thread a :timeout 15 :default :timeout))))
             (sb-thread:signal-semaphore release-right)
             (assert (not (eq :timeout (sb-thread:join-thread b :timeout 15 :default :timeout))))
             (list left-result right-result))
        (sb-thread:signal-semaphore release-left)
        (sb-thread:signal-semaphore release-right)
        (when a (sb-thread:join-thread a :timeout 20 :default nil))
        (when b (sb-thread:join-thread b :timeout 20 :default nil))
        (setf (gr8s::pod-store-consensus-commit-fn left) original-left
              (gr8s::pod-store-consensus-commit-fn right) original-right)))))

(test concurrent-http-core-writes-return-conflicts-through-real-raft-forwarding
  (with-temporary-store (left lp)
    (with-temporary-store (right rp)
      (declare (ignore lp rp))
      (let ((h1 nil) (h2 nil) (s1 nil) (s2 nil))
        (unwind-protect
             (progn
               (setf h1 (gr8s::start-ha-control-plane left :id "conflict-left" :init t))
               (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p h1))))
               (setf h2 (gr8s::start-ha-control-plane right :id "conflict-right"
                         :join-host "127.0.0.1"
                         :join-port (gr8s::raft-member-port (gr8s::ha-control-plane-member h1))))
               (is (poll-until (lambda () (member "conflict-right"
                          (gr8s::raft-node-peers (gr8s::raft-member-node (gr8s::ha-control-plane-member h1)))
                          :test #'equal))))
               ;; Admit writes on both test acceptors to exercise the same store
               ;; forwarding path used by internal writers on production followers.
               (setf s1 (gr8s::start-server :address "127.0.0.1" :port 0 :store left :runtime (make-fake-runtime))
                     s2 (gr8s::start-server :address "127.0.0.1" :port 0 :store right :runtime (make-fake-runtime)))
               (is (equal '(201 409)
                          (race-ha-core-http-writes left right s1 s2 :post
                           "/api/v1/namespaces/default/configmaps"
                           (com.inuoe.jzon:stringify (configmap-input "raced" "k" "created-left"))
                           (com.inuoe.jzon:stringify (configmap-input "raced" "k" "created-right")))))
               (is (equal "created-left" (configmap-value left "raced" "k")))
               (is (equal "created-left" (configmap-value right "raced" "k")))
               (is (equal '(200 409)
                          (race-ha-core-http-writes left right s1 s2 :patch
                           "/api/v1/namespaces/default/configmaps/raced"
                           "{\"data\":{\"k\":\"updated-left\"}}" "{\"data\":{\"k\":\"updated-right\"}}")))
               (is (equal "updated-left" (configmap-value left "raced" "k")))
               (is (equal "updated-left" (configmap-value right "raced" "k"))))
          (when s1 (gr8s::stop-server s1))
          (when s2 (gr8s::stop-server s2))
          (gr8s::stop-ha-control-plane h2)
          (gr8s::stop-ha-control-plane h1))))))

(test durable-control-plane-restarts-preserve-voters-and-do-not-rejoin
  (with-temporary-store (s1 p1)
    (with-temporary-store (s2 p2)
      (let ((h1 nil) (h2 nil) (port1 nil) (port2 nil) (journal nil)
            (key (merge-pathnames "pki/restart-sentinel.key" p1)))
        (gr8s.security::write-private-text-exclusively key "identity-must-survive")
        (unwind-protect
             (progn
               (setf h1 (gr8s::start-ha-control-plane s1 :id "durable-one" :init t))
               (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p h1)) :timeout 15))
               (setf port1 (gr8s::raft-member-port (gr8s::ha-control-plane-member h1))
                     h2 (gr8s::start-ha-control-plane s2 :id "durable-two" :join-host "127.0.0.1" :join-port port1)
                     port2 (gr8s::raft-member-port (gr8s::ha-control-plane-member h2)))
               (is (poll-until (lambda ()
                                (and (eq :voter (gr8s::raft-node-self-role (gr8s::raft-member-node (gr8s::ha-control-plane-member h2))))
                                     (not (gr8s.store::store-access-blocked-p s2)))) :timeout 20))
               (gr8s::create-core-resource s1 "configmaps" (configmap-input "durable" "k" "A") "default")
               (is (poll-until (lambda () (equal "A" (ignore-errors (configmap-value s2 "durable" "k")))) :timeout 15))
               (setf journal (uiop:read-file-string (merge-pathnames "raft/bootstrap.json" p1)))
               (is (null (gr8s.ha::control-plane-store-bootstrap-role s1 "durable-one" nil nil)))
               (gr8s::stop-ha-control-plane h2)
               (gr8s::stop-ha-control-plane h1)
               (is (= 503 (core-resource-status
                           (lambda () (gr8s::create-core-resource s1 "configmaps" (configmap-input "after-stop" "k" "unsafe") "default")))))
               (setf s1 (gr8s:open-store p1 :defer-restore-completion t)
                     s2 (gr8s:open-store p2 :defer-restore-completion t)
                     h1 (gr8s::start-ha-control-plane s1 :id "durable-one" :init t :port port1))
               ;; The founder must keep its two-voter quorum and remain gated
               ;; while its only peer is still down, rather than re-found alone.
               (is (= 2 (gr8s::raft-majority (gr8s::raft-member-node (gr8s::ha-control-plane-member h1)))))
               (is-true (gr8s.store::store-access-blocked-p s1))
               (is (not (gr8s::ha-control-plane-leader-p h1)))
               ;; A recovered voter must use the durable address book. An invalid
               ;; enrollment seed proves startup did not repeat Join.
               (setf h2 (gr8s::start-ha-control-plane s2 :id "durable-two" :port port2
                                                     :join-host "127.0.0.1" :join-port 1))
               (is (eq :voter (gr8s::raft-node-self-role (gr8s::raft-member-node (gr8s::ha-control-plane-member h2)))))
               (is (poll-until (lambda () (and (not (gr8s.store::store-access-blocked-p s1))
                                               (not (gr8s.store::store-access-blocked-p s2)))) :timeout 20))
               (is (equal "A" (configmap-value s1 "durable" "k")))
               (is (equal "A" (configmap-value s2 "durable" "k")))
               (is (equal journal (uiop:read-file-string (merge-pathnames "raft/bootstrap.json" p1))))
               (is (equal "identity-must-survive" (uiop:read-file-string key)))
               (let ((leader (if (gr8s::ha-control-plane-leader-p h1) s1 s2)))
                 (gr8s::create-core-resource leader "configmaps" (configmap-input "durable-after" "k" "B") "default"))
               (is (poll-until (lambda () (and (equal "B" (ignore-errors (configmap-value s1 "durable-after" "k")))
                                               (equal "B" (ignore-errors (configmap-value s2 "durable-after" "k"))))) :timeout 15)))
          (gr8s::stop-ha-control-plane h2)
          (gr8s::stop-ha-control-plane h1))))))

(test durable-control-plane-capture-requires-barriers-and-survives-restart
  (with-temporary-store (store root)
    (let ((ha nil) (port nil) (boundary nil))
      (unwind-protect
           (progn
             (setf ha (gr8s::start-ha-control-plane store :id "capture" :init t))
             (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p ha)) :timeout 15))
             (gr8s::create-core-resource store "configmaps" (configmap-input "captured" "k" "exact") "default")
             (let* ((member (gr8s::ha-control-plane-member ha)) (node (gr8s::raft-member-node member)))
               (setf port (gr8s::raft-member-port member))
               (bt:with-lock-held ((gr8s::raft-member-lock member))
                 (signals error (funcall (gr8s.raft:raft-node-snapshot-fn node))))
               (call-with-bootstrap-barriers
                store
                (lambda ()
                  (bt:with-lock-held ((gr8s::raft-member-lock member))
                    (setf boundary (gr8s::raft-node-last-applied node))
                    (gr8s::raft-compact node boundary)
                    (is (= boundary (gr8s::raft-node-snapshot-index node)))
                    (is-true (probe-file
                              (gr8s.resources::checked-store-snapshot-artifact-path
                               root (getf (cddr (gr8s::raft-node-snapshot-state node)) :application))))))))
             (gr8s::stop-ha-control-plane ha)
             (setf store (gr8s:open-store root :defer-restore-completion t)
                   ha (gr8s::start-ha-control-plane store :id "capture" :init t :port port))
             (is (= boundary (gr8s::raft-node-snapshot-index (gr8s::raft-member-node (gr8s::ha-control-plane-member ha)))))
             (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p ha)) :timeout 15))
             (is (equal "exact" (configmap-value store "captured" "k"))))
        (gr8s::stop-ha-control-plane ha)))))
