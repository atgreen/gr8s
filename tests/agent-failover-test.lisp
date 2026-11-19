;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Agent reconnect across control-plane failover (podster-c2d.7.4): given more
;;;; than one control-plane endpoint, the node agent rotates through them on each
;;;; reconnect, so when the member it was talking to is gone it finds a live one
;;;; (the new leader) and resumes its session.

(in-package #:gr8s/tests)
(def-suite agent-failover :in gr8s)
(in-suite agent-failover)

(test parse-agent-servers-splits-a-comma-list
  (is (equal '(("127.0.0.1" 7443)) (gr8s.server::parse-agent-servers "127.0.0.1:7443")))
  (is (equal '(("10.0.0.1" 7443) ("10.0.0.2" 7443))
             (gr8s.server::parse-agent-servers "10.0.0.1:7443, 10.0.0.2:7443"))))

(test ha-node-endpoints-put-the-local-member-first
  (let* ((node (cl-raft::make-raft-node :id "cp2" :leader-id "cp1"))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (hcp (gr8s.ha::make-ha-control-plane :member member)))
    (setf (gethash "cp1" (cl-raft::raft-node-peer-addresses node)) '("10.0.0.1" 7444)
          (gethash "cp2" (cl-raft::raft-node-peer-addresses node)) '("10.0.0.2" 7444)
          (gethash "cp3" (cl-raft::raft-node-peer-addresses node)) '("10.0.0.3" 7444))
    (is (equal '(("10.0.0.2" 7443)
                 ("10.0.0.1" 7443)
                 ("10.0.0.3" 7443))
               (gr8s.ha::ha-control-plane-node-endpoints hcp 7443)))))

(test ha-node-session-endpoints-put-the-known-leader-first
  (let* ((node (cl-raft::make-raft-node :id "cp2" :leader-id "cp1"))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (hcp (gr8s.ha::make-ha-control-plane :member member)))
    (setf (gethash "cp1" (cl-raft::raft-node-peer-addresses node)) '("10.0.0.1" 7444)
          (gethash "cp2" (cl-raft::raft-node-peer-addresses node)) '("10.0.0.2" 7444)
          (gethash "cp3" (cl-raft::raft-node-peer-addresses node)) '("10.0.0.3" 7444))
    (is (equal '(("10.0.0.1" 7443)
                 ("10.0.0.2" 7443)
                 ("10.0.0.3" 7443))
               (gr8s.ha::ha-control-plane-node-session-endpoints hcp 7443)))))

(test agent-rotates-to-a-live-control-plane-endpoint
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-1" :name "worker-a" :pod-cidr "10.88.0.0/20"))
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2))
           (good-port (gr8s.apiserver::node-grpc-server-port server))
           ;; A port with nothing listening: the first endpoint the agent tries.
           (dead-port (let ((s (make-instance 'hunchentoot:easy-acceptor :address "127.0.0.1" :port 0)))
                        (hunchentoot:start s)
                        (prog1 (hunchentoot:acceptor-port s) (hunchentoot:stop s))))
           (applied nil)
           (control (gr8s.agent::make-node-session-control))
           (agent-thread nil))
      (unwind-protect
           (progn
             (gr8s.apiserver::publish-node-desired-state server "worker-a" (empty-desired-snapshot))
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" dead-port "worker-a" identity-path
                       (lambda (snapshot)
                         (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
                       :endpoints (list (list "127.0.0.1" dead-port)
                                        (list "127.0.0.1" good-port))
                       :reconnect-delay 0.05 :control control))
                    :name "gr8s failover test agent"))
             (is-true (wait-until (lambda () applied) :timeout 10)
                      "the agent reaches the live endpoint after the dead one")
             (is (member 1 applied) "it applied the desired-state revision from the live member"))
        (gr8s.agent::cancel-node-session control)
        (when agent-thread (ignore-errors (bt:join-thread agent-thread)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test ha-node-endpoints-leave-out-witnesses
  ;; A witness votes but serves no nodes: an agent sent to its address waits out
  ;; a connect timeout before it can try a member that would admit it.
  (let* ((node (cl-raft::make-raft-node :id "cp1" :leader-id "cp1"))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (hcp (gr8s.ha::make-ha-control-plane :member member)))
    (loop for (id role address) in '(("cp1" :voter "10.0.0.1") ("cp2" :voter "10.0.0.2")
                                     ("wit" :witness "10.0.0.9"))
          do (setf (gethash id (cl-raft::raft-node-peer-addresses node)) (list address 7444)
                   (gethash id (cl-raft::raft-node-roles node)) role))
    (is (equal '(("10.0.0.1" 7443) ("10.0.0.2" 7443))
               (gr8s.ha::ha-control-plane-node-endpoints hcp 7443)))
    (is (equal '(("10.0.0.1" 7443) ("10.0.0.2" 7443))
               (gr8s.ha::ha-control-plane-node-session-endpoints hcp 7443)))))

(test a-checkpoint-does-not-turn-node-sessions-away
  (with-temporary-store (store path)
    (values path)
    (let* ((node (cl-raft::make-raft-node :id "cp1" :role :leader))
           (member (gr8s.raft.transport::make-raft-member :node node))
           (hcp (gr8s.ha::make-ha-control-plane :member member :store store)))
      (is-true (gr8s.ha::ha-control-plane-admits-node-sessions-p hcp))
      (unwind-protect
           (progn
             (gr8s.store::quiesce-store-access store)
             (is-false (gr8s.ha::ha-control-plane-admits-node-sessions-p hcp)
                       "a store blocked for a restore admits no sessions")
             (setf (gr8s.ha::ha-control-plane-compaction-quiescing hcp) t)
             (is-true (gr8s.ha::ha-control-plane-admits-node-sessions-p hcp)
                      "a store quiesced by this leader's own checkpoint still does")
             (setf (cl-raft::raft-node-role node) :follower)
             (is-false (gr8s.ha::ha-control-plane-admits-node-sessions-p hcp)))
        (setf (gr8s.store::pod-store-access-blocked store) nil)))))

(test a-refusal-names-where-the-session-can-go
  (let ((targets '(("10.0.0.2" 7443)))
        (refusal (make-condition 'gr8s.apiserver::node-session-refused
                                 :expected :hello :message "not the leader"
                                 :endpoints '("10.0.0.1:7443" "bogus" "10.0.0.2:7443"))))
    (is (equal '(("10.0.0.1" 7443) ("10.0.0.2" 7443))
               (gr8s.agent::node-session-targets-after-refusal targets refusal))
        "the members it named go first; a malformed one is ignored")
    (is (null (gr8s.agent::node-session-targets-after-refusal
               targets (make-condition 'gr8s.apiserver::node-session-refused
                                       :expected :hello :message "version" :endpoints nil))))))

(test agent-follows-a-refusal-to-the-member-that-admits-it
  ;; The agent knows one --server, and that member is not the leader: it has
  ;; never held a session, so only the refusal can tell it where the leader is.
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-1" :name "worker-a" :pod-cidr "10.88.0.0/20"))
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (leader (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2))
           (leader-port (gr8s.apiserver::node-grpc-server-port leader))
           (follower (gr8s.apiserver::start-node-grpc-server
                      store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2
                      :session-admission-fn (constantly nil)
                      :session-endpoints-fn (lambda () (list (list "127.0.0.1" leader-port)))))
           (follower-port (gr8s.apiserver::node-grpc-server-port follower))
           (applied nil)
           (control (gr8s.agent::make-node-session-control))
           (agent-thread nil))
      (unwind-protect
           (progn
             (gr8s.apiserver::publish-node-desired-state leader "worker-a" (empty-desired-snapshot))
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" follower-port "worker-a" identity-path
                       (lambda (snapshot)
                         (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
                       :reconnect-delay 0.05 :control control))
                    :name "gr8s redirect test agent"))
             (is-true (wait-until (lambda () applied) :timeout 10)
                      "the agent reaches the leader the follower named"))
        (gr8s.agent::cancel-node-session control)
        (when agent-thread (ignore-errors (bt:join-thread agent-thread)))
        (gr8s.apiserver::stop-node-grpc-server follower)
        (gr8s.apiserver::stop-node-grpc-server leader)))))

(test a-report-waits-for-the-store-a-checkpoint-closed
  (let ((calls 0))
    (is (eq :handled
            (gr8s.apiserver::call-once-store-is-available
             (lambda ()
               (when (< (incf calls) 3)
                 (error 'kubernetes-error :status-code 503 :reason "ServiceUnavailable"
                                          :message "Application restore is blocking store access"))
               :handled)
             :pause 0.01)))
    (is (= 3 calls)))
  (signals kubernetes-error
    (gr8s.apiserver::call-once-store-is-available
     (lambda () (error 'kubernetes-error :status-code 409 :reason "Conflict" :message "no")))
    "any other failure is not waited on")
  (signals kubernetes-error
    (gr8s.apiserver::call-once-store-is-available
     (lambda () (error 'kubernetes-error :status-code 503 :reason "ServiceUnavailable" :message "still"))
     :patience 0.05 :pause 0.01)))

(test a-lease-is-judged-only-by-a-member-that-could-hear-the-heartbeats
  ;; Not at all while it cannot record them (a follower, a closed store) ...
  (is-false (gr8s.apiserver::node-leases-judgeable-p nil 100 15))
  ;; ... and not until it has been listening for a whole lease: a new leader, or
  ;; one whose store a long checkpoint just reopened.
  (is-false (gr8s.apiserver::node-leases-judgeable-p 90 100 15))
  (is-true (gr8s.apiserver::node-leases-judgeable-p 85 100 15))
  (with-temporary-store (store path)
    (values path)
    (let ((admitted t)
          (server (gr8s.apiserver::start-node-grpc-server
                   store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 15)))
      (unwind-protect
           (progn
             (setf (gr8s.apiserver::node-grpc-server-session-admission-fn server)
                   (lambda () admitted))
             (is (= 100 (gr8s.apiserver::node-heartbeats-recordable-since server nil 100)))
             (is (= 100 (gr8s.apiserver::node-heartbeats-recordable-since server 100 107)))
             (setf admitted nil)
             (is (null (gr8s.apiserver::node-heartbeats-recordable-since server 100 108))
                 "a member that stops admitting sessions starts over when it resumes"))
        (gr8s.apiserver::stop-node-grpc-server server)))))
