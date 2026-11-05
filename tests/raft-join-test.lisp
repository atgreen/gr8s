;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
  (gr8s::start-raft-member
   id :apply-fn (if store
                    (lambda (c) (gr8s::raft-resource-apply store c))
                    (lambda (c) (declare (ignore c)) nil))))

(test raft-join-admits-voters-and-a-witness-with-redirect
  (let* ((store-a (gr8s::make-raft-resource-store))
         (store-b (gr8s::make-raft-resource-store))
         (a (join-member "a" :store store-a))
         (b (join-member "b" :store store-b))
         (w (join-member "w"))
         (all (list a b w)))
    (unwind-protect
         (progn
           ;; "a" founds the cluster and elects itself.
           (gr8s::raft-cluster-init a)
           (gr8s::raft-member-start a)
           (is (poll-until (lambda () (gr8s::raft-member-leader-p a))))

           ;; "b" joins as a voter straight through the leader.
           (gr8s::raft-member-start b)
           (is-true (gr8s::raft-cluster-join b (gr8s::raft-member-host a) (gr8s::raft-member-port a))
                    "the leader admits b over the Join RPC")
           (is (poll-until
                (lambda () (member "b" (gr8s::raft-node-peers (gr8s::raft-member-node a)) :test #'equal)))
               "b becomes a voting peer")

           ;; "w" aims its join at the follower b; the handshake is redirected to a.
           (gr8s::raft-member-start w)
           (is-true (gr8s::raft-cluster-join w (gr8s::raft-member-host b) (gr8s::raft-member-port b)
                                             :role :witness)
                    "a join aimed at a follower is redirected to the leader and admitted")
           (is (poll-until
                (lambda () (member "w" (gr8s::raft-node-peers (gr8s::raft-member-node a)) :test #'equal)))
               "the witness joins the configuration")
           (is (poll-until
                (lambda () (eq :witness (gr8s::raft-node-self-role (gr8s::raft-member-node w)))))
               "the witness takes the witness role")

           ;; A write replicates to both data-bearing members, and the witness
           ;; never becomes leader.
           (let ((leader (find-if #'gr8s::raft-member-leader-p all)))
             (gr8s::raft-member-propose-sync leader '(:put "cm/x" "v1" :expected nil :uid "u1")))
           (is (poll-until
                (lambda () (and (let ((r (gr8s::raft-resource-get store-a "cm/x"))) (and r (equal "v1" (gr8s::raft-resource-record-value r))))
                                (let ((r (gr8s::raft-resource-get store-b "cm/x"))) (and r (equal "v1" (gr8s::raft-resource-record-value r)))))))
               "the write replicates to both voters")
           (is (not (gr8s::raft-member-leader-p w)) "the witness never leads"))
      (dolist (m all) (ignore-errors (gr8s::stop-raft-member m))))))
