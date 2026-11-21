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

(test ha-health-metrics-report-prefix-and-peer-pressure-without-payloads
  (let* ((node (cl-raft::make-raft-node :id "metrics" :role :leader :current-term 3
                                    :snapshot-index 5 :commit-index 11 :last-applied 10
                                    :catchup-byte-limit 8192 :retained-byte-limit 4096 :uncommitted-weight-fn (constantly 100)
                                    :log (make-array 7 :adjustable t :fill-pointer 7
                                                     :initial-contents
                                                     (loop for index from 6 to 12 collect
                                                       (cl-raft::make-raft-entry :term 3 :index index
                                                                             :command "PRIVATE-PAYLOAD")))))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (link (gr8s.raft.transport::make-raft-peer-link :id "peer\"one"
                                                       :items (list '(:type :append-entries))
                                                       :active-items (list '(:type :install-snapshot))))
         (ha (gr8s.ha::make-ha-control-plane :member member :compaction-count 7
                                            :compaction-in-flight t :compaction-error "PRIVATE-ERROR")))
    (setf (gethash "peer\"one" (gr8s.raft.transport::raft-member-links member)) link
          (gethash "peer\"one" (cl-raft::raft-node-match-index node)) 8)
    (let ((text (gr8s.ha::ha-metrics-text ha)))
      (dolist (sample '("gr8s_raft_term 3" "gr8s_raft_is_leader 1" "gr8s_raft_commit_index 11"
                         "gr8s_raft_applied_index 10" "gr8s_raft_snapshot_index 5"
                         "gr8s_raft_apply_lag_entries 1" "gr8s_raft_retained_entries 7"
                         "gr8s_raft_uncommitted_entries 1" "gr8s_raft_retained_bytes 1596"
                         "gr8s_raft_retained_limit_bytes 4096" "gr8s_raft_catchup_cache_limit_bytes 8192"
                         "gr8s_raft_catchup_cache_bytes 0" "gr8s_raft_catchup_cache_segments 0"
                         "gr8s_raft_catchup_cache_error 0" "gr8s_compaction_completed_total 7"
                         "gr8s_compaction_in_flight 1" "gr8s_compaction_error 1"
                         "gr8s_raft_peer_replication_lag_entries{peer=\"peer\\\"one\"} 4"
                         "gr8s_raft_peer_outbox_messages{peer=\"peer\\\"one\"} 2"))
        (is (search sample text)))
      (is-false (search "PRIVATE" text))
      (is (= 11 (cl-raft::raft-node-commit-index node)))
      (is (= 7 (length (cl-raft::raft-node-log node)))))
    (setf (cl-raft::raft-node-role node) :follower
          (gr8s.raft::raft-node-retained-byte-limit node) nil)
    (let ((text (gr8s.ha::ha-metrics-text ha)))
      (is (search "gr8s_raft_is_leader 0" text))
      (is-false (search "gr8s_raft_peer_replication_lag_entries" text))
      (is-false (search "gr8s_raft_retained_limit_bytes" text)))))

(test ha-admission-preserves-full-size-secret-create-and-update
  (dolist (encrypted '(nil t))
    (with-temporary-store (store root)
      (let ((ha nil) (port nil))
        (unwind-protect
             (progn
               (when encrypted (gr8s.security::ensure-cluster-pki root))
               (setf ha (gr8s.ha::start-ha-control-plane store :id "large-secret" :init t))
               (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
               (when encrypted (gr8s.resources::enable-secret-encryption store))
               (let* ((bytes (make-array (* 1024 1024) :element-type '(unsigned-byte 8) :initial-element 17))
                      (one (ag-grpc:base64-encode bytes)))
                 (gr8s.resources::create-core-resource store "secrets"
                   (gr8s.resources::core-object "apiVersion" "v1" "kind" "Secret"
                     "metadata" (gr8s.resources::core-object "name" "large") "data" (gr8s.resources::core-object "value" one)) "default")
                 (setf (aref bytes 0) 18)
                 (let ((two (ag-grpc:base64-encode bytes)))
                   (gr8s.resources::update-core-resource store "secrets" "default" "large"
                     (lambda (object) (setf (gethash "value" (gethash "data" object)) two) object))
                   (is (equal two (gethash "value" (gethash "data"
                                    (gr8s.resources::get-core-resource store "secrets" "default" "large")))))
                   (setf port (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member ha)))
                   (gr8s.ha::stop-ha-control-plane ha)
                   (setf ha nil store (gr8s.store::open-store root :defer-restore-completion t)
                         ha (gr8s.ha::start-ha-control-plane store :id "large-secret" :init t :port port))
                   (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
                   (is (equal two (gethash "value" (gethash "data"
                                    (gr8s.resources::get-core-resource store "secrets" "default" "large"))))))))
          (gr8s.ha::stop-ha-control-plane ha))))))

(test proposal-capacity-refusals-propagate-through-sync-forwarding-and-store-hook
  (let* ((node (cl-raft::make-raft-node :id "a" :role :leader :peers '("b" "c")
                 :current-term 1 :uncommitted-byte-limit 4096
                 :send-fn (lambda (&rest args) (declare (ignore args)))))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (payload (make-string 500 :initial-element #\x))
         (commit (gr8s.ha::make-store-raft-commit-function member)))
    (gr8s.raft.transport::raft-member-propose member (list :core-delta payload))
    (multiple-value-bind (result reason index)
        (gr8s.raft.transport::raft-member-propose-sync member (list :core-delta payload))
      (is (null result)) (is (eq :capacity reason)) (is (null index)))
    (multiple-value-bind (result reason)
        (gr8s.raft.transport::raft-member-forward-propose-sync member (list :core-delta payload))
      (is (null result)) (is (eq :capacity reason)))
    (handler-case
        (progn (funcall commit :core-delta payload) (fail "Expected capacity refusal"))
      (gr8s.model::kubernetes-error (condition)
        (is (= 503 (gr8s.model::kubernetes-error-status-code condition)))))
    (handler-case
        (progn (funcall commit :core-delta (make-string 2000)) (fail "Expected size refusal"))
      (gr8s.model::kubernetes-error (condition)
        (is (= 413 (gr8s.model::kubernetes-error-status-code condition)))))
    (is (= 1 (cl-raft::raft-last-log-index node)))
    (is (zerop (hash-table-count (gr8s.raft::raft-node-pending node))))))

(test ha-control-plane-founds-joins-gates-and-replicates
  (with-temporary-store (s1 p1)
    (with-temporary-store (s2 p2)
      (declare (ignore p1 p2))
      (let ((h1 nil) (h2 nil))
        (unwind-protect
             (progn
               ;; Found the cluster on member 1.
               (setf h1 (gr8s.ha::start-ha-control-plane s1 :id "cp1" :init t))
               (is (= (* 16 1024 1024)
                      (gr8s.raft::raft-node-uncommitted-byte-limit
                       (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member h1)))))
               (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p h1)))
                   "the founding control plane becomes leader")
               ;; Member 2 joins, learning member 1's address from its member.
               (let ((leader-port (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member h1))))
                 (setf h2 (gr8s.ha::start-ha-control-plane
                           s2 :id "cp2" :join-host "127.0.0.1" :join-port leader-port)))
               (is (poll-until
                    (lambda () (member "cp2" (cl-raft::raft-node-peers
                                              (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member h1)))
                                       :test #'equal)))
                   "the joining control plane becomes a voting peer")
               ;; The leader gate is true on exactly one member.
               (is (gr8s.ha::ha-control-plane-leader-p h1) "member 1 holds leadership")
               (is (not (gr8s.ha::ha-control-plane-leader-p h2)) "member 2 is a follower")
               ;; A durable write on the leader's store replicates to the follower.
               (gr8s.resources::create-core-resource s1 "configmaps"
                                           (configmap-input "cm1" "k" "v1") "default")
               (is (poll-until
                    (lambda () (and (equal "v1" (configmap-value s1 "cm1" "k"))
                                    (equal "v1" (configmap-value s2 "cm1" "k"))))
                    :timeout 10)
                   "the write replicates from the leader to the follower control plane")
               ;; Internal writers such as node enrollment and heartbeats run on
               ;; every member.  A follower forwards their consensus proposal to
               ;; the leader, and the committed state returns to every replica.
               (let ((original (symbol-function 'gr8s.resources::install-core-state-delta)))
                 (unwind-protect
                      (progn
                        ;; A leader can acknowledge the forwarded proposal before
                        ;; its commit notification returns to the authoring follower.
                        ;; Make that local apply gap deterministic: the write must
                        ;; still not return until this follower can read its result.
                        (setf (symbol-function 'gr8s.resources::install-core-state-delta)
                              (lambda (store json)
                                (when (eq store s2) (sleep 0.2))
                                (funcall original store json)))
                        (gr8s.resources::create-core-resource s2 "configmaps"
                                                    (configmap-input "cm2" "k" "x") "default")
                        (is (equal "x" (configmap-value s2 "cm2" "k"))
                            "a forwarded write has read-after-write consistency locally")
                        (is (poll-until
                             (lambda () (equal "x" (configmap-value s1 "cm2" "k")))
                             :timeout 10)
                            "a durable follower write is forwarded through the leader"))
                   (setf (symbol-function 'gr8s.resources::install-core-state-delta) original))))
          (gr8s.ha::stop-ha-control-plane h2)
          (gr8s.ha::stop-ha-control-plane h1))))))

(test ha-control-plane-replicates-image-tracker-leases-and-swarms
  (with-temporary-store (s1 p1)
    (with-temporary-store (s2 p2)
      (declare (ignore p1 p2))
      (let ((h1 nil) (h2 nil))
        (unwind-protect
             (progn
               (setf h1 (gr8s.ha::start-ha-control-plane s1 :id "tracker-cp1" :init t))
               (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p h1))))
               (setf h2
                     (gr8s.ha::start-ha-control-plane
                      s2 :id "tracker-cp2" :join-host "127.0.0.1"
                      :join-port (gr8s.raft.transport::raft-member-port
                                  (gr8s.ha::ha-control-plane-member h1))))
               (is (poll-until
                    (lambda ()
                      (member "tracker-cp2"
                              (cl-raft::raft-node-peers
                               (gr8s.raft.transport::raft-member-node
                                (gr8s.ha::ha-control-plane-member h1)))
                              :test #'equal))))
               (multiple-value-bind (digest torrent) (tracker-test-torrent)
                 (let* ((token (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 17))
                        (peer-id (bt-octets "-GR8001-AAAAAAAAAAAA"))
                        (commit (gr8s.store::pod-store-consensus-commit-fn s2))
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
                              (gr8s.store::pod-store-image-tracker store) digest "node-b"
                              :now 1000)))
                       (is (eq :waiting
                               (gr8s.image-distribution::tracker-view-status view)))
                       (is (string= "node-a"
                                    (gr8s.image-distribution::tracker-view-origin-node view)))))
                   (let ((renewed
                           (funcall
                            (gr8s.store::pod-store-consensus-commit-fn s1)
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
                             :metainfo (gr8s.image-distribution::torrent-metainfo torrent)
                             :address "10.0.0.1" :port 6881 :peer-id peer-id))))
                     (is (eq :ok (getf published :status))))
                   (dolist (store (list s1 s2))
                     (let ((view
                             (gr8s.image-distribution::tracker-lookup
                              (gr8s.store::pod-store-image-tracker store) digest "node-b"
                              :now 1002)))
                       (is (eq :available
                               (gr8s.image-distribution::tracker-view-status view)))
                       (is (equalp (gr8s.image-distribution::torrent-infohash torrent)
                                   (gr8s.image-distribution::tracker-view-infohash view)))
                       (is (string= "node-a"
                                    (gr8s.image-distribution::tracker-peer-node-name
                                     (first
                                      (gr8s.image-distribution::tracker-view-peers view)))))))
                   (funcall
                    (gr8s.store::pod-store-consensus-commit-fn s1)
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
                                     (gr8s.store::pod-store-image-tracker store)
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
                               (gr8s.store::pod-store-image-tracker store) digest "node-c"
                               :now 1004))))
                       (is (= 1 (length peers)))
                       (is (string= "node-a"
                                    (gr8s.image-distribution::tracker-peer-node-name
                                     (first peers))))))))
          (gr8s.ha::stop-ha-control-plane h2)
          (gr8s.ha::stop-ha-control-plane h1)))))))

(defun race-ha-core-http-writes (left right left-server right-server method path left-body right-body)
  "Pause each member after authoring its command, then commit left before right."
  (let ((arrived (sb-thread:make-semaphore :count 0))
        (release-left (sb-thread:make-semaphore :count 0))
        (release-right (sb-thread:make-semaphore :count 0))
        (original-left (gr8s.store::pod-store-consensus-commit-fn left))
        (original-right (gr8s.store::pod-store-consensus-commit-fn right))
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
             (setf (gr8s.store::pod-store-consensus-commit-fn left) (wrapper original-left release-left)
                   (gr8s.store::pod-store-consensus-commit-fn right) (wrapper original-right release-right)
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
        (setf (gr8s.store::pod-store-consensus-commit-fn left) original-left
              (gr8s.store::pod-store-consensus-commit-fn right) original-right)))))

(test concurrent-http-core-writes-return-conflicts-through-real-raft-forwarding
  (with-temporary-store (left lp)
    (with-temporary-store (right rp)
      (declare (ignore lp rp))
      (let ((h1 nil) (h2 nil) (s1 nil) (s2 nil))
        (unwind-protect
             (progn
               (setf h1 (gr8s.ha::start-ha-control-plane left :id "conflict-left" :init t))
               (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p h1))))
               (setf h2 (gr8s.ha::start-ha-control-plane right :id "conflict-right"
                         :join-host "127.0.0.1"
                         :join-port (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member h1))))
               (is (poll-until (lambda () (member "conflict-right"
                          (cl-raft::raft-node-peers (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member h1)))
                          :test #'equal))))
               ;; Admit writes on both test acceptors to exercise the same store
               ;; forwarding path used by internal writers on production followers.
               (setf s1 (gr8s.apiserver::start-server :address "127.0.0.1" :port 0 :store left :runtime (make-fake-runtime))
                     s2 (gr8s.apiserver::start-server :address "127.0.0.1" :port 0 :store right :runtime (make-fake-runtime)))
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
          (when s1 (gr8s.apiserver::stop-server s1))
          (when s2 (gr8s.apiserver::stop-server s2))
          (gr8s.ha::stop-ha-control-plane h2)
          (gr8s.ha::stop-ha-control-plane h1))))))

(test stopped-control-plane-gate-can-be-handed-to-same-store-recovery
  (with-temporary-store (store root)
    (let ((ha nil) (port nil))
      (unwind-protect
           (progn
             (setf ha (gr8s.ha::start-ha-control-plane store :id "same-store" :init t))
             (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
             (setf port (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member ha)))
             (gr8s.resources::create-core-resource store "configmaps" (configmap-input "sentinel" "k" "preserved") "default")
             (gr8s.ha::stop-ha-control-plane ha)
             (is (gr8s.store::store-access-blocked-p store))
             ;; Only the owner of this stopped, drained fixture hands off its
             ;; gate. No requests or controllers enter during the transition.
             (gr8s.store::resume-store-access store)
             (let* ((node (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member ha)))
                    (index (cl-raft::raft-last-log-index node))
                    (wal (merge-pathnames "raft/control-plane.log" root))
                    (bytes (sb-posix:stat-size (sb-posix:stat (namestring wal)))))
               ;; Reopening the application gate cannot silently turn the
               ;; stopped member's consensus hook into a local-only writer.
               (signals error (funcall (gr8s.store::pod-store-consensus-commit-fn store) :core-delta "{}"))
               (is (= index (cl-raft::raft-last-log-index node)))
               (is (= bytes (sb-posix:stat-size (sb-posix:stat (namestring wal))))))
             (setf ha (gr8s.ha::start-ha-control-plane store :id "same-store" :init t :port port))
             (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
             (is (equal "preserved" (configmap-value store "sentinel" "k"))))
        (gr8s.ha::stop-ha-control-plane ha)))))

(test durable-control-plane-restarts-preserve-voters-and-do-not-rejoin
  (with-temporary-store (s1 p1)
    (with-temporary-store (s2 p2)
      (let ((h1 nil) (h2 nil) (port1 nil) (port2 nil) (journal nil)
            (key (merge-pathnames "pki/restart-sentinel.key" p1)))
        (gr8s.security::write-private-text-exclusively key "identity-must-survive")
        (unwind-protect
             (progn
               (setf h1 (gr8s.ha::start-ha-control-plane s1 :id "durable-one" :init t))
               (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p h1)) :timeout 15))
               (setf port1 (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member h1))
                     h2 (gr8s.ha::start-ha-control-plane s2 :id "durable-two" :join-host "127.0.0.1" :join-port port1)
                     port2 (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member h2)))
               (is (poll-until (lambda ()
                                (and (eq :voter (cl-raft::raft-node-self-role (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member h2))))
                                     (not (gr8s.store::store-access-blocked-p s2)))) :timeout 20))
               (gr8s.resources::create-core-resource s1 "configmaps" (configmap-input "durable" "k" "A") "default")
               (is (poll-until (lambda () (equal "A" (ignore-errors (configmap-value s2 "durable" "k")))) :timeout 15))
               (setf journal (uiop:read-file-string (merge-pathnames "raft/bootstrap.json" p1)))
               (is (null (gr8s.ha::control-plane-store-bootstrap-role s1 "durable-one" nil nil)))
               (gr8s.ha::stop-ha-control-plane h2)
               (gr8s.ha::stop-ha-control-plane h1)
               (is (= 503 (core-resource-status
                           (lambda () (gr8s.resources::create-core-resource s1 "configmaps" (configmap-input "after-stop" "k" "unsafe") "default")))))
               (setf s1 (gr8s.store::open-store p1 :defer-restore-completion t)
                     s2 (gr8s.store::open-store p2 :defer-restore-completion t)
                     h1 (gr8s.ha::start-ha-control-plane s1 :id "durable-one" :init t :port port1))
               ;; The founder must keep its two-voter quorum and remain gated
               ;; while its only peer is still down, rather than re-found alone.
               (is (= 2 (cl-raft::raft-majority (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member h1)))))
               (is-true (gr8s.store::store-access-blocked-p s1))
               (is (not (gr8s.ha::ha-control-plane-leader-p h1)))
               ;; A recovered voter must use the durable address book. An invalid
               ;; enrollment seed proves startup did not repeat Join.
               (setf h2 (gr8s.ha::start-ha-control-plane s2 :id "durable-two" :port port2
                                                     :join-host "127.0.0.1" :join-port 1))
               (is (eq :voter (cl-raft::raft-node-self-role (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member h2)))))
               (is (poll-until (lambda () (and (not (gr8s.store::store-access-blocked-p s1))
                                               (not (gr8s.store::store-access-blocked-p s2)))) :timeout 20))
               (is (equal "A" (configmap-value s1 "durable" "k")))
               (is (equal "A" (configmap-value s2 "durable" "k")))
               (is (equal journal (uiop:read-file-string (merge-pathnames "raft/bootstrap.json" p1))))
               (is (equal "identity-must-survive" (uiop:read-file-string key)))
               (let ((leader (if (gr8s.ha::ha-control-plane-leader-p h1) s1 s2)))
                 (gr8s.resources::create-core-resource leader "configmaps" (configmap-input "durable-after" "k" "B") "default"))
               (is (poll-until (lambda () (and (equal "B" (ignore-errors (configmap-value s1 "durable-after" "k")))
                                               (equal "B" (ignore-errors (configmap-value s2 "durable-after" "k"))))) :timeout 15)))
          (gr8s.ha::stop-ha-control-plane h2)
          (gr8s.ha::stop-ha-control-plane h1))))))

(test durable-control-plane-capture-requires-barriers-and-survives-restart
  (with-temporary-store (store root)
    (let ((ha nil) (port nil) (boundary nil))
      (unwind-protect
           (progn
             (setf ha (gr8s.ha::start-ha-control-plane store :id "capture" :init t))
             (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
             (gr8s.resources::create-core-resource store "configmaps" (configmap-input "captured" "k" "exact") "default")
             (let* ((member (gr8s.ha::ha-control-plane-member ha)) (node (gr8s.raft.transport::raft-member-node member)))
               (setf port (gr8s.raft.transport::raft-member-port member))
               (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
                 (signals error (funcall (gr8s.raft::raft-node-snapshot-fn node))))
               (call-with-bootstrap-barriers
                store
                (lambda ()
                  (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
                    (setf boundary (cl-raft::raft-node-last-applied node))
                    (cl-raft::raft-compact node boundary)
                    (is (= boundary (cl-raft::raft-node-snapshot-index node)))
                    (is-true (probe-file
                              (gr8s.resources::checked-store-snapshot-artifact-path
                               root (getf (cddr (cl-raft::raft-node-snapshot-state node)) :application))))))))
             (gr8s.ha::stop-ha-control-plane ha)
             (setf store (gr8s.store::open-store root :defer-restore-completion t)
                   ha (gr8s.ha::start-ha-control-plane store :id "capture" :init t :port port))
             (is (= boundary (cl-raft::raft-node-snapshot-index (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member ha)))))
             (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
             (is (equal "exact" (configmap-value store "captured" "k"))))
        (gr8s.ha::stop-ha-control-plane ha)))))

(in-suite ha-control-plane)
(test automatic-compaction-uses-bytes-reclaims-history-and-recovers
  (with-temporary-store (store root)
    (let ((ha nil) (port nil) (boundary nil))
      (labels ((count-checkpoints ()
                 (bt:with-lock-held ((gr8s.ha::ha-control-plane-compaction-lock ha))
                   (gr8s.ha::ha-control-plane-compaction-count ha)))
               (write-when-ready (name value)
                 (poll-until
                  (lambda ()
                    (handler-case
                        (progn (gr8s.resources::create-core-resource store "configmaps"
                                 (configmap-input name "k" value) "default") t)
                      (gr8s.model::kubernetes-error () nil))) :timeout 15)))
        (unwind-protect
             (progn
               (setf ha (gr8s.ha::start-ha-control-plane store :id "compact" :init t
                         :compaction-bytes 4096 :compaction-entries 100000 :compaction-interval 0.02))
               (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
               (setf port (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member ha)))
               (dotimes (i 3)
                 (let ((before (count-checkpoints)) (name (format nil "round-~D" i)))
                   (is (write-when-ready name (make-string 8192 :initial-element #\x)))
                   (is (poll-until (lambda () (> (count-checkpoints) before)) :timeout 15))
                   (is (poll-until (lambda () (not (gr8s.store::store-access-blocked-p store))) :timeout 15))))
               (let* ((member (gr8s.ha::ha-control-plane-member ha)) (node (gr8s.raft.transport::raft-member-node member)))
                 (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
                   (setf boundary (cl-raft::raft-node-snapshot-index node))
                   (is (= boundary (cl-raft::raft-node-last-applied node)))
                   (is (< (sb-posix:stat-size (sb-posix:stat (merge-pathnames "raft/control-plane.log" root))) 4096)))
                 ;; Reclamation is a joined maintenance task, independent of
                 ;; checkpoint publication. Preserve the same physical-file bound.
                 (is (poll-until
                      (lambda () (<= (length (uiop:directory-files (merge-pathnames "snapshot-artifacts/" root))) 2))
                      :timeout 15)))
               (gr8s.ha::stop-ha-control-plane ha)
               ;; The member writes on its own account too: a marker and a report
               ;; when it starts, by which the members compare their versions.
               ;; Those can pass the byte limit after the lines above, so the
               ;; boundary a restart must come back to is the one it stopped at.
               (setf boundary (cl-raft::raft-node-snapshot-index
                               (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member ha))))
               (is (null (gr8s.ha::ha-control-plane-compaction-thread ha)))
               (loop for row across (gr8s.ha::ha-control-plane-compaction-phase-times ha) do
                 (is (and row (plusp (aref row 0))))
                 (is (<= 0 (aref row 3) (aref row 2) (aref row 1))))
               (loop for row across (gr8s.ha::ha-control-plane-compaction-member-lock-times ha) do
                 (is (and row (plusp (aref row 0))))
                 (is (<= 0 (aref row 3) (aref row 2) (aref row 1)))
                 (is (<= 0 (aref row 6) (aref row 5) (aref row 4))))
               (setf store (gr8s.store::open-store root :defer-restore-completion t)
                     ha (gr8s.ha::start-ha-control-plane store :id "compact" :init t :port port))
               (is (= boundary (cl-raft::raft-node-snapshot-index (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member ha)))))
               (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
               (is (= 8192 (length (configmap-value store "round-2" "k")))))
          (gr8s.ha::stop-ha-control-plane ha))))))

(test compaction-capture-failure-reopens-only-its-own-gate
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((ha nil) (capture (symbol-function 'gr8s.resources::capture-frozen-store-snapshot)))
      (unwind-protect
           (progn
             (setf ha (gr8s.ha::start-ha-control-plane store :id "failure" :init t
                       :compaction-entries 1 :compaction-interval nil))
             (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
             (let* ((member (gr8s.ha::ha-control-plane-member ha)) (node (gr8s.raft.transport::raft-member-node member))
                    (boundary (cl-raft::raft-node-snapshot-index node)))
               (setf (symbol-function 'gr8s.resources::capture-frozen-store-snapshot)
                     (lambda (&rest arguments) (declare (ignore arguments)) (error "Injected capture failure")))
               (signals error (gr8s.ha::compact-ha-store-once ha))
               (is (not (gr8s.store::store-access-blocked-p store)))
               (is (= boundary (cl-raft::raft-node-snapshot-index node)))
               (setf (symbol-function 'gr8s.resources::capture-frozen-store-snapshot) capture)
               (gr8s.store::quiesce-store-access store)
               (is (null (gr8s.ha::compact-ha-store-once ha)))
               (is (gr8s.store::store-access-blocked-p store))
               (gr8s.store::resume-store-access store)
               (is (gr8s.ha::compact-ha-store-once ha))))
        (setf (symbol-function 'gr8s.resources::capture-frozen-store-snapshot) capture)
        (gr8s.ha::stop-ha-control-plane ha)))))

(test compaction-io-allows-live-writes-and-recovers-the-newer-suffix
  (with-temporary-store (store root)
    (let ((ha nil) (original (symbol-function 'gr8s.resources::capture-frozen-store-snapshot))
          (frozen-index nil) (seen nil))
      (unwind-protect
           (progn
             (setf ha (gr8s.ha::start-ha-control-plane store :id "async-capture" :init t
                       :compaction-entries 1 :compaction-interval nil))
             (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
             (setf (symbol-function 'gr8s.resources::capture-frozen-store-snapshot)
                   (lambda (view path)
                     (setf seen t frozen-index (gr8s.resources::frozen-store-snapshot-index view))
                     (is (not (gr8s.store::store-access-blocked-p store)))
                     (dolist (lock (list (gr8s.raft.transport::raft-member-lock (gr8s.ha::ha-control-plane-member ha))
                                        (gr8s.store::pod-store-lock store)
                                        (gr8s.store::pod-store-workload-lock store)
                                        (gr8s.store::pod-store-credential-lock store)
                                        (gr8s.store::pod-store-consensus-write-lock store)))
                       (is (not (sb-thread:holding-mutex-p lock))))
                     (is (null (gr8s.ha::compact-ha-store-once ha)))
                     ;; A normal write commits after freezing, before encoding.
                     (gr8s.resources::create-core-resource store "configmaps" (configmap-input "during-capture" "k" "later") "default")
                     (funcall original view path)))
             (is (gr8s.ha::compact-ha-store-once ha))
             (is (eq t seen))
             (let ((member (gr8s.ha::ha-control-plane-member ha)))
               (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
                 (is (= frozen-index (cl-raft::raft-node-snapshot-index (gr8s.raft.transport::raft-member-node member))))
                 (is (> (gr8s.raft::raft-node-last-applied (gr8s.raft.transport::raft-member-node member)) frozen-index))
                 (is (null (gr8s.raft.transport::raft-member-artifact-pins member)))))
             (is (not (gr8s.ha::ha-control-plane-compaction-in-flight ha)))
             (setf (symbol-function 'gr8s.resources::capture-frozen-store-snapshot) original)
             (gr8s.ha::stop-ha-control-plane ha)
             (setf ha nil)
             (let ((reopened (gr8s.store::open-store root)))
               (setf ha (gr8s.ha::start-ha-control-plane reopened :id "async-capture" :init t
                         :compaction-interval nil))
               (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
               (is (equal "later" (gethash "k" (gethash "data"
                      (gr8s.resources::get-core-resource reopened "configmaps" "default" "during-capture")))))))
        (setf (symbol-function 'gr8s.resources::capture-frozen-store-snapshot) original)
        (when ha (gr8s.ha::stop-ha-control-plane ha))))))

(test uncertain-checkpoint-storage-failure-keeps-application-gated
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((ha nil) (original (symbol-function 'gr8s.raft::raft-storage-replace-snapshot)))
      (unwind-protect
           (progn
             (setf ha (gr8s.ha::start-ha-control-plane store :id "uncertain" :init t
                       :compaction-entries 1 :compaction-interval nil))
             (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
             (let ((storage (gr8s.raft::raft-node-storage
                             (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member ha)))))
               (setf (symbol-function 'gr8s.raft::raft-storage-replace-snapshot)
                     (lambda (&rest arguments)
                       (declare (ignore arguments))
                       (gr8s.raft::close-file-raft-storage storage)
                       (error "Injected uncertain checkpoint durability")))
               (signals error (gr8s.ha::compact-ha-store-once ha))
               (is (gr8s.store::store-access-blocked-p store))
               (signals gr8s.model::kubernetes-error
                 (gr8s.resources::create-core-resource store "configmaps" (configmap-input "blocked" "k" "v") "default"))))
        (setf (symbol-function 'gr8s.raft::raft-storage-replace-snapshot) original)
        (gr8s.ha::stop-ha-control-plane ha)))))

(test compaction-worker-shutdown-wakes-its-long-interval
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((ha nil))
      (unwind-protect
           (progn
             (setf ha (gr8s.ha::start-ha-control-plane store :id "worker-stop" :init t :compaction-interval 3600))
             (is (bt:thread-alive-p (gr8s.ha::ha-control-plane-compaction-thread ha)))
             (is (= (* 32 1024 1024)
                    (gr8s.raft::raft-node-retained-byte-limit
                     (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member ha)))))
             (let ((started (get-internal-real-time)))
               (gr8s.ha::stop-ha-compaction-worker ha)
               (is (< (- (get-internal-real-time) started) (* 5 internal-time-units-per-second))))
             (is (null (gr8s.ha::ha-control-plane-compaction-thread ha)))
             (is (null (gr8s.raft::raft-node-retained-byte-limit
                        (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member ha))))))
        (gr8s.ha::stop-ha-control-plane ha)))))

(test compaction-budget-includes-retained-command-weight-before-wal-threshold
  (with-temporary-store (store root)
    (let ((ha nil))
      (unwind-protect
           (progn
             (setf ha (gr8s.ha::start-ha-control-plane store :id "heap-budget" :init t
                       :compaction-bytes 65536 :compaction-entries 100000 :compaction-interval nil))
             (is (= (* 16 1024 1024)
                    (gr8s.raft::raft-node-uncommitted-byte-limit
                     (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member ha)))))
             (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p ha)) :timeout 15))
             (gr8s.resources::create-core-resource store "configmaps"
               (configmap-input "wide" "k" (make-string 16384 :initial-element #\x)) "default")
             (is (< (sb-posix:stat-size (sb-posix:stat (merge-pathnames "raft/control-plane.log" root))) 65536))
             (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock (gr8s.ha::ha-control-plane-member ha)))
               (is (gr8s.ha::ha-compaction-due-unlocked-p ha)))
             (is (gr8s.ha::compact-ha-store-once ha))
             (is (not (gr8s.store::store-access-blocked-p store))))
        (gr8s.ha::stop-ha-control-plane ha)))))

(test a-joiner-can-be-replayed-well-past-a-snapshot-before-its-log-is-full
  ;; podster-kiw: a wiped member rejoining a cluster that was taking writes was
  ;; sent snapshot after snapshot. Its retained-log budget held about 450 entries,
  ;; it cannot checkpoint until it has caught up, and the leader committed more
  ;; than that in the time one snapshot took to send and install.
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((ha nil))
      (unwind-protect
           (progn
             ;; The checkpoint worker installs the budget, as it does under serve.
             (setf ha (gr8s.ha::start-ha-control-plane store :id "budget" :init t :compaction-interval 3600))
             (let* ((node (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member ha)))
                    (limit (gr8s.raft::raft-node-retained-byte-limit node))
                    (command (list :node-delta (make-string 1000 :initial-element #\x)))
                    (proposal (+ 128 (funcall (gr8s.raft::raft-node-uncommitted-weight-fn node) command)))
                    (retained (+ 128 (funcall (gr8s.raft::raft-node-retained-weight-fn node) command))))
               (is (integerp limit))
               (is (> proposal 65536) "a proposal still reserves for its waiting client")
               (is (< retained 8192) "an entry retained from replication is charged its own size")
               ;; Two checkpoints' worth of entries went by during one snapshot
               ;; in the reproduction; leave room for a great deal more.
               (is (> (floor limit retained) 5000))))
        (when ha (gr8s.ha::stop-ha-control-plane ha))))))

(test compaction-worker-restores-disk-cache-policy-without-overwriting-external-changes
  (with-temporary-store (store root)
    (values root)
    (dolist (previous '(nil 1024))
      (let* ((node (gr8s.raft::make-raft-node :catchup-byte-limit previous))
             (member (gr8s.raft.transport::make-raft-member :node node))
             (ha (gr8s.ha::make-ha-control-plane :member member :store store :compaction-interval 3600)))
        (unwind-protect
             (progn
               (gr8s.ha::start-ha-compaction-worker ha)
               (is (= (or previous (* 128 1024 1024)) (gr8s.raft::raft-node-catchup-byte-limit node)))
               (gr8s.ha::stop-ha-compaction-worker ha)
               (is (eql previous (gr8s.raft::raft-node-catchup-byte-limit node)))
               (gr8s.ha::start-ha-compaction-worker ha)
               (setf (gr8s.raft::raft-node-catchup-byte-limit node) 2048)
               (gr8s.ha::stop-ha-compaction-worker ha)
               (is (= 2048 (gr8s.raft::raft-node-catchup-byte-limit node))))
          (gr8s.ha::stop-ha-compaction-worker ha))))))

(test stopping-compaction-worker-releases-its-populated-disk-cache
  (with-temporary-store (store root)
    (let* ((storage (cl-raft::open-file-raft-storage (merge-pathnames "cache.log" root)))
           (node (make-disk-catchup-test-node storage))
           (member (gr8s.raft.transport::make-raft-member :node node))
           (ha (gr8s.ha::make-ha-control-plane :member member :store store :compaction-interval 3600)))
      (setf (gr8s.raft::raft-node-catchup-byte-limit node) nil)
      (unwind-protect
           (progn
             (gr8s.ha::start-ha-compaction-worker ha)
             (let ((fd
                     (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
                       (gr8s.raft::raft-compact node 3)
                       (is (= 1 (nth-value 1 (gr8s.raft::raft-storage-catchup-usage storage))))
                       (gr8s.raft::raft-catchup-segment-fd
                        (first (gr8s.raft::file-raft-storage-catchup-segments storage))))))
               (gr8s.ha::stop-ha-compaction-worker ha)
               (is (null (gr8s.raft::raft-node-catchup-byte-limit node)))
               (is (zerop (gr8s.raft::raft-storage-catchup-usage storage)))
               (is (zerop (nth-value 1 (gr8s.raft::raft-storage-catchup-usage storage))))
               (signals sb-posix:syscall-error (sb-posix:fstat fd))
               ;; Worker stop releases the optional cache, leaving the WAL open.
               (is (open-stream-p (gr8s.raft::file-raft-storage-stream storage)))))
        (gr8s.ha::stop-ha-compaction-worker ha)
        (cl-raft::close-file-raft-storage storage)))))


(test compaction-phase-measurements-preserve-results-errors-and-nonlocal-exits
  (let* ((member (gr8s.raft.transport::make-raft-member :node (cl-raft::make-raft-node)))
         (ha (gr8s.ha::make-ha-control-plane :member member)))
    (is (equal '(1 2) (multiple-value-list
                       (gr8s.ha::with-ha-compaction-phase (ha :capture) (values 1 2)))))
    (signals simple-error (gr8s.ha::with-ha-compaction-phase (ha :capture) (error "expected")))
    (is (eq :escaped (catch 'phase-exit
                      (gr8s.ha::with-ha-compaction-phase (ha :capture) (throw 'phase-exit :escaped)))))
    (let ((row (aref (gr8s.ha::ha-control-plane-compaction-phase-times ha) 1)))
      (is (= 3 (aref row 0)))
      (is (<= 0 (aref row 3) (aref row 2) (aref row 1))))
    (signals simple-error (gr8s.ha::with-ha-compaction-phase (ha :unknown) (fail "Invalid phase ran")))
    (let ((text (gr8s.ha::ha-metrics-text ha)))
      (is (search "gr8s_compaction_phase_observations_total{phase=\"capture\"} 3" text))
      (is (search "gr8s_compaction_phase_observations_total{phase=\"publish\"} 0" text))
      (dolist (suffix '("duration_seconds_total" "duration_seconds_max" "duration_seconds_last"))
        (is (search (concatenate 'string "gr8s_compaction_phase_" suffix "{phase=\"capture\"}") text))))))

(test compaction-member-lock-measurements-preserve-locking-and-control-flow
  (let* ((member (gr8s.raft.transport::make-raft-member :node (cl-raft::make-raft-node)))
         (ha (gr8s.ha::make-ha-control-plane :member member))
         (lock (gr8s.raft.transport::raft-member-lock member)))
    (is (equal '(1 2)
               (multiple-value-list
                (gr8s.ha::with-ha-compaction-member-lock (ha :publish)
                  (is (sb-thread:holding-mutex-p lock))
                  (values 1 2)))))
    (signals simple-error
      (gr8s.ha::with-ha-compaction-member-lock (ha :publish) (error "expected")))
    (is (eq :escaped
            (catch 'lock-exit
              (gr8s.ha::with-ha-compaction-member-lock (ha :publish)
                (throw 'lock-exit :escaped)))))
    (is (not (sb-thread:holding-mutex-p lock)))
    (signals simple-error
      (gr8s.ha::with-ha-compaction-member-lock (ha :unknown) (fail "Invalid section ran")))
    (let ((row (aref (gr8s.ha::ha-control-plane-compaction-member-lock-times ha) 2)))
      (is (= 3 (aref row 0)))
      (is (<= 0 (aref row 3) (aref row 2) (aref row 1)))
      (is (<= 0 (aref row 6) (aref row 5) (aref row 4))))
    (let ((text (gr8s.ha::ha-metrics-text ha)))
      (is (search "gr8s_compaction_member_lock_observations_total{section=\"publish\"} 3" text))
      (is (search "gr8s_compaction_member_lock_observations_total{section=\"check\"} 0" text))
      (dolist (prefix '("gr8s_compaction_phase_" "gr8s_compaction_member_lock_"))
        (dolist (suffix '("gc_seconds_total" "gc_seconds_max" "gc_seconds_last"))
          (is (search (concatenate 'string prefix suffix "{") text)))))))

(test compaction-gc-deltas-accumulate-on-normal-and-abnormal-exits
  (let* ((member (gr8s.raft.transport::make-raft-member :node (cl-raft::make-raft-node)))
         (ha (gr8s.ha::make-ha-control-plane :member member))
         ;; A thread-local counter binding gives exact, deterministic deltas;
         ;; no global GC hooks or other threads' counters are modified.
         (sb-ext:*gc-run-time* 0))
    (gr8s.ha::with-ha-compaction-phase (ha :capture) (incf sb-ext:*gc-run-time* 7))
    (signals simple-error
      (gr8s.ha::with-ha-compaction-phase (ha :capture)
        (incf sb-ext:*gc-run-time* 11) (error "expected")))
    (let ((row (aref (gr8s.ha::ha-control-plane-compaction-phase-times ha) 1)))
      (is (= 2 (aref row 0)))
      (is (= 18 (aref row 4)))
      (is (= 11 (aref row 5)))
      (is (= 11 (aref row 6))))))

(test peer-receive-metrics-omit-unobserved-and-old-term-ages-and-removed-members
  (let* ((node (cl-raft::make-raft-node :id "local" :peers '("peer") :current-term 3))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (link (gr8s.raft.transport::make-raft-peer-link :id "peer"))
         (ha (gr8s.ha::make-ha-control-plane :member member)))
    (setf (gethash "peer" (gr8s.raft.transport::raft-member-links member)) link)
    (let ((text (gr8s.ha::ha-metrics-text ha)))
      (is (search "gr8s_raft_peer_received_messages_total{peer=\"peer\"} 0" text))
      (is (search "gr8s_raft_peer_receive_observed{peer=\"peer\"} 0" text))
      (is-false (search "gr8s_raft_peer_last_receive_age_seconds{" text)))
    (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
      (gr8s.raft.transport::raft-member-note-receive-unlocked
       member '(:type :append-entries :term 3 :from "peer")))
    (let ((text (gr8s.ha::ha-metrics-text ha)))
      (is (search "gr8s_raft_peer_received_messages_total{peer=\"peer\"} 1" text))
      (is (search "gr8s_raft_peer_receive_observed{peer=\"peer\"} 1" text))
      (is (search "gr8s_raft_peer_last_receive_age_seconds{peer=\"peer\"}" text)))
    (bt:with-lock-held ((gr8s.raft.transport::raft-peer-link-lock link))
      (setf (gr8s.raft.transport::raft-peer-link-last-receive-ticks link)
            (- (get-internal-real-time) (* 2 internal-time-units-per-second))))
    (let* ((prefix "gr8s_raft_peer_last_receive_age_seconds{peer=\"peer\"} ")
           (line (find-if (lambda (line) (uiop:string-prefix-p prefix line))
                          (uiop:split-string (gr8s.ha::ha-metrics-text ha) :separator '(#\Newline))))
           (*read-eval* nil))
      (is-true line)
      (when line (is (>= (read-from-string (subseq line (length prefix))) 2))))
    (setf (cl-raft::raft-node-current-term node) 4)
    (let ((text (gr8s.ha::ha-metrics-text ha)))
      (is (search "gr8s_raft_peer_receive_observed{peer=\"peer\"} 0" text))
      (is-false (search "gr8s_raft_peer_last_receive_age_seconds{" text)))
    (setf (cl-raft::raft-node-peers node) nil)
    (let ((text (gr8s.ha::ha-metrics-text ha)))
      (is-false (search "gr8s_raft_peer_received_messages_total{" text))
      (is-false (search "gr8s_raft_peer_receive_observed{" text)))))

(test generation-maintenance-runs-without-compaction-and-stop-joins-active-cleanup
  (with-temporary-store (store root)
    (destructuring-bind (old new staged) (make-retirement-test-generations root)
      (declare (ignore staged))
      (gr8s.security::write-private-text-exclusively
       (merge-pathnames "pod-revision.ceiling" (gr8s.store::store-generation-root root old)) "7")
      (set-test-generation-current store new)
      (let* ((member (gr8s.raft.transport::make-raft-member :node (gr8s.raft::make-raft-node :id "maintenance")))
             (hcp (gr8s.ha::make-ha-control-plane :store store :member member :compaction-interval nil))
             (original (symbol-function 'gr8s.store::reap-retired-store-generations))
             (entered (bt:make-semaphore)) (release (bt:make-semaphore)) (stopped (bt:make-semaphore))
             (stopper nil) (locked nil))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.store::reap-retired-store-generations)
                     (lambda (target &rest args)
                       (setf locked (or (sb-thread:holding-mutex-p (gr8s.store::pod-store-lock target))
                                        (sb-thread:holding-mutex-p (gr8s.raft.transport::raft-member-lock member))))
                       (bt:signal-semaphore entered)
                       (bt:wait-on-semaphore release)
                       (apply original target args)))
               (gr8s.ha::start-ha-maintenance-worker hcp :interval 0.01)
               (is-true (bt:wait-on-semaphore entered :timeout 10))
               (is-false locked)
               (is-false (gr8s.ha::ha-control-plane-compaction-thread hcp))
               (is-false (gr8s.raft::raft-node-retained-byte-limit (gr8s.raft.transport::raft-member-node member)))
               (is (search "gr8s_generation_reclamation_worker_up 1" (gr8s.ha::ha-metrics-text hcp)))
               (setf stopper (bt:make-thread (lambda ()
                                              (gr8s.ha::stop-ha-maintenance-worker hcp)
                                              (bt:signal-semaphore stopped))))
               (is-false (bt:wait-on-semaphore stopped :timeout 0.05))
               (bt:signal-semaphore release)
               (is-true (bt:wait-on-semaphore stopped :timeout 10))
               (bt:join-thread stopper)
               (setf stopper nil)
               (is-false (probe-file (gr8s.store::store-generation-root root old)))
               (is (search "gr8s_generation_reaped_files_total 1" (gr8s.ha::ha-metrics-text hcp)))
               (is (search "gr8s_generation_reclamation_worker_up 0" (gr8s.ha::ha-metrics-text hcp))))
          (bt:signal-semaphore release)
          (when stopper (bt:join-thread stopper))
          (gr8s.ha::stop-ha-maintenance-worker hcp)
          (setf (symbol-function 'gr8s.store::reap-retired-store-generations) original))))))

(test generation-maintenance-retries-errors-and-clears-error-metrics
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((member (gr8s.raft.transport::make-raft-member :node (gr8s.raft::make-raft-node :id "retry")))
           (hcp (gr8s.ha::make-ha-control-plane :store store :member member))
           (original (symbol-function 'gr8s.store::reap-retired-store-generations))
           (retry (bt:make-semaphore)) (release (bt:make-semaphore)) (calls 0))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.store::reap-retired-store-generations)
                   (lambda (target &rest args)
                     (if (= 1 (incf calls)) (error "PRIVATE injected maintenance error")
                         (progn
                           (when (= calls 2)
                             (bt:signal-semaphore retry)
                             (bt:wait-on-semaphore release))
                           (apply original target args)))))
             (gr8s.ha::start-ha-maintenance-worker hcp :interval 0.01)
             (is-true (bt:wait-on-semaphore retry :timeout 10))
             (let ((text (gr8s.ha::ha-metrics-text hcp)))
               (is (search "gr8s_generation_reclamation_error 1" text))
               (is-false (search "PRIVATE" text)))
             (bt:signal-semaphore release)
             (loop with deadline = (+ (get-internal-real-time) (* 10 internal-time-units-per-second))
                   while (and (search "gr8s_generation_reclamation_error 1" (gr8s.ha::ha-metrics-text hcp))
                              (< (get-internal-real-time) deadline)) do (sleep 0.01))
             (is (search "gr8s_generation_reclamation_error 0" (gr8s.ha::ha-metrics-text hcp))))
        (bt:signal-semaphore release)
        (gr8s.ha::stop-ha-maintenance-worker hcp)
        (setf (symbol-function 'gr8s.store::reap-retired-store-generations) original)))))

(test ha-store-wedge-advance-restarts-only-on-a-sustained-leaderless-block
  ;; podster-7l9: self-heal fires only when the store is blocked AND leaderless, has
  ;; served before (so first-boot recovery is exempt), and the condition has held past
  ;; the threshold. Anything else leaves the member running.
  (let* ((unit internal-time-units-per-second)
         (now (* 1000 unit))
         (exited nil))
    (flet ((ex () (setf exited t)))
      ;; Not wedged -> mark as having served, clear any timer, never exit.
      (multiple-value-bind (seen since) (gr8s.ha::ha-store-wedge-advance nil nil 123 now #'ex)
        (is (eq t seen)) (is (null since)) (is (not exited)))
      ;; Wedged but never served yet (first-boot recovery) -> ignored.
      (multiple-value-bind (seen since) (gr8s.ha::ha-store-wedge-advance t nil nil now #'ex)
        (is (null seen)) (is (null since)) (is (not exited)))
      ;; Wedge begins (served before) -> start the timer, do not exit.
      (multiple-value-bind (seen since) (gr8s.ha::ha-store-wedge-advance t t nil now #'ex)
        (is (eq t seen)) (is (= now since)) (is (not exited)))
      ;; Wedge held, but under threshold -> keep waiting.
      (let ((since (- now (* (1- gr8s.ha::*ha-store-wedge-threshold-seconds*) unit))))
        (multiple-value-bind (s w) (gr8s.ha::ha-store-wedge-advance t t since now #'ex)
          (declare (ignore s)) (is (= since w)) (is (not exited))))
      ;; Wedge held past threshold -> restart.
      (let ((since (- now (* (+ 5 gr8s.ha::*ha-store-wedge-threshold-seconds*) unit))))
        (gr8s.ha::ha-store-wedge-advance t t since now #'ex)
        (is (eq t exited))))))
