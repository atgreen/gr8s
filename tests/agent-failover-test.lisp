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
  (is (equal '(("127.0.0.1" 7443)) (gr8s::parse-agent-servers "127.0.0.1:7443")))
  (is (equal '(("10.0.0.1" 7443) ("10.0.0.2" 7443))
             (gr8s::parse-agent-servers "10.0.0.1:7443, 10.0.0.2:7443"))))

(test ha-node-endpoints-put-the-local-member-first
  (let* ((node (gr8s::make-raft-node :id "cp2" :leader-id "cp1"))
         (member (gr8s::make-raft-member :node node))
         (hcp (gr8s::make-ha-control-plane :member member)))
    (setf (gethash "cp1" (gr8s::raft-node-peer-addresses node)) '("10.0.0.1" 7444)
          (gethash "cp2" (gr8s::raft-node-peer-addresses node)) '("10.0.0.2" 7444)
          (gethash "cp3" (gr8s::raft-node-peer-addresses node)) '("10.0.0.3" 7444))
    (is (equal '(("10.0.0.2" 7443)
                 ("10.0.0.1" 7443)
                 ("10.0.0.3" 7443))
               (gr8s::ha-control-plane-node-endpoints hcp 7443)))))

(test ha-node-session-endpoints-put-the-known-leader-first
  (let* ((node (gr8s::make-raft-node :id "cp2" :leader-id "cp1"))
         (member (gr8s::make-raft-member :node node))
         (hcp (gr8s::make-ha-control-plane :member member)))
    (setf (gethash "cp1" (gr8s::raft-node-peer-addresses node)) '("10.0.0.1" 7444)
          (gethash "cp2" (gr8s::raft-node-peer-addresses node)) '("10.0.0.2" 7444)
          (gethash "cp3" (gr8s::raft-node-peer-addresses node)) '("10.0.0.3" 7444))
    (is (equal '(("10.0.0.1" 7443)
                 ("10.0.0.2" 7443)
                 ("10.0.0.3" 7443))
               (gr8s::ha-control-plane-node-session-endpoints hcp 7443)))))

(test agent-rotates-to-a-live-control-plane-endpoint
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-1" :name "worker-a" :pod-cidr "10.88.0.0/20"))
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2))
           (good-port (gr8s:node-grpc-server-port server))
           ;; A port with nothing listening: the first endpoint the agent tries.
           (dead-port (let ((s (make-instance 'hunchentoot:easy-acceptor :address "127.0.0.1" :port 0)))
                        (hunchentoot:start s)
                        (prog1 (hunchentoot:acceptor-port s) (hunchentoot:stop s))))
           (applied nil)
           (control (gr8s::make-node-session-control))
           (agent-thread nil))
      (unwind-protect
           (progn
             (gr8s:publish-node-desired-state server "worker-a" (empty-desired-snapshot))
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
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
        (gr8s::cancel-node-session control)
        (when agent-thread (ignore-errors (bt:join-thread agent-thread)))
        (gr8s:stop-node-grpc-server server)))))
