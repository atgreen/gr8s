;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The Join RPC handshake (podster-c2d.10) end to end over real ag-gRPC: a
;;;; founding member admits a voter and a witness through RaftTransport.Join, a
;;;; join aimed at a follower is redirected to the leader, and the witness counts
;;;; toward quorum without ever leading. This is the network front the
;;;; 'gr8s witness' command (podster-c2d.9) and HA 'gr8s serve' build on.

(in-package #:gr8s/tests)
(def-suite raft-join :in gr8s)
(in-suite raft-join)

(defun join-member (id &key store)
  "A member whose state machine is STORE (a raft-resource-store) if given, else a
   no-op (as a witness needs no state)."
  (gr8s.raft.transport::start-raft-member
   id :apply-fn (if store
                    (lambda (c) (gr8s.ha::raft-resource-apply store c))
                    (lambda (c) (declare (ignore c)) nil))))

(test raft-join-admits-voters-and-a-witness-with-redirect
  (let* ((store-a (gr8s.ha::make-raft-resource-store))
         (store-b (gr8s.ha::make-raft-resource-store))
         (a (join-member "a" :store store-a))
         (b (join-member "b" :store store-b))
         (w (join-member "w"))
         (all (list a b w)))
    (unwind-protect
         (progn
           ;; "a" founds the cluster and elects itself.
           (gr8s.raft.transport::raft-cluster-init a)
           (gr8s.raft.transport::raft-member-start a)
           (is (poll-until (lambda () (gr8s.raft.transport::raft-member-leader-p a))))

           ;; "b" joins as a voter straight through the leader.
           (gr8s.raft.transport::raft-member-start b)
           (is-true (gr8s.raft.transport::raft-cluster-join b (gr8s.raft.transport::raft-member-host a) (gr8s.raft.transport::raft-member-port a))
                    "the leader admits b over the Join RPC")
           (is (poll-until
                (lambda () (member "b" (cl-raft::raft-node-peers (gr8s.raft.transport::raft-member-node a)) :test #'equal)))
               "b becomes a voting peer")

           ;; "w" aims its join at the follower b; the handshake is redirected to a.
           (gr8s.raft.transport::raft-member-start w)
           (is-true (gr8s.raft.transport::raft-cluster-join w (gr8s.raft.transport::raft-member-host b) (gr8s.raft.transport::raft-member-port b)
                                             :role :witness)
                    "a join aimed at a follower is redirected to the leader and admitted")
           (is (poll-until
                (lambda () (member "w" (cl-raft::raft-node-peers (gr8s.raft.transport::raft-member-node a)) :test #'equal)))
               "the witness joins the configuration")
           (is (poll-until
                (lambda () (eq :witness (cl-raft::raft-node-self-role (gr8s.raft.transport::raft-member-node w)))))
               "the witness takes the witness role")

           ;; A write replicates to both data-bearing members, and the witness
           ;; never becomes leader.
           (let ((leader (find-if #'gr8s.raft.transport::raft-member-leader-p all)))
             (gr8s.raft.transport::raft-member-propose-sync leader '(:put "cm/x" "v1" :expected nil :uid "u1")))
           (is (poll-until
                (lambda () (and (let ((r (gr8s.ha::raft-resource-get store-a "cm/x"))) (and r (equal "v1" (gr8s.ha::raft-resource-record-value r))))
                                (let ((r (gr8s.ha::raft-resource-get store-b "cm/x"))) (and r (equal "v1" (gr8s.ha::raft-resource-record-value r)))))))
               "the write replicates to both voters")
           (is (not (gr8s.raft.transport::raft-member-leader-p w)) "the witness never leads"))
      (dolist (m all) (ignore-errors (gr8s.raft.transport::stop-raft-member m))))))

;;; podster-ddc: a refused admission names its reason on both sides -- the
;;; leader's journal and the JoinResponse -- instead of a bare "could not join".

(test join-refusal-carries-its-reason
  (let* ((node (cl-raft::make-raft-node :id "leader"
                                        :send-fn (lambda (&rest args) (declare (ignore args)))))
         (member (gr8s.raft.transport::make-raft-member :node node)))
    (gr8s.raft::raft-configure node '(("leader" . :voter)))
    (setf (gr8s.raft::raft-node-role node) :leader
          ;; Another membership change is still in flight, so admission refuses.
          (gethash "pending" (gr8s.raft::raft-node-pending-members node)) :learner)
    (let* ((request (make-instance 'gr8s.node.v1::join-request
                                   :member-id "joiner" :host "10.0.0.9" :port 7000
                                   :role "voter" :node-name "joiner"
                                   :join-token "" :api-url ""))
           (complaints (make-string-output-stream))
           (response (let ((*error-output* complaints))
                       (gr8s.raft.transport::raft-member-handle-join member request nil))))
      (is (not (gr8s.node.v1::accepted response)))
      (is (equal "change-in-flight" (gr8s.node.v1::reason response))
          "the response carries the refusal reason for the joiner's log")
      (is (search "refusing join of joiner" (get-output-stream-string complaints))
          "the leader journals the refusal with its reason"))))

(test joiner-surfaces-the-leaders-refusal-reason
  (let* ((node (cl-raft::make-raft-node :id "joiner"
                                        :send-fn (lambda (&rest args) (declare (ignore args)))))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (original (symbol-function 'gr8s.raft.transport::raft-cluster-call-join)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.raft.transport::raft-cluster-call-join)
                 (lambda (&rest args) (declare (ignore args))
                   (make-instance 'gr8s.node.v1::join-response
                                  :accepted nil :leader-id "leader"
                                  :reason "change-in-flight")))
           (multiple-value-bind (joined reason)
               (gr8s.raft.transport::raft-cluster-join member "192.0.2.1" 7000)
             (is (null joined))
             (is (equal "change-in-flight" reason)))
           ;; An old leader that sends no reason still reports something.
           (setf (symbol-function 'gr8s.raft.transport::raft-cluster-call-join)
                 (lambda (&rest args) (declare (ignore args))
                   (make-instance 'gr8s.node.v1::join-response
                                  :accepted nil :leader-id "")))
           (multiple-value-bind (joined reason)
               (gr8s.raft.transport::raft-cluster-join member "192.0.2.1" 7000)
             (is (null joined))
             (is (equal "no-leader" reason))))
      (setf (symbol-function 'gr8s.raft.transport::raft-cluster-call-join) original))))
