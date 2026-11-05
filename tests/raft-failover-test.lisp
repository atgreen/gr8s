;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The epic's headline, proven end to end (podster-c2d.7/.8): a Raft-replicated
;;;; desired-state store running over the real ag-gRPC transport survives the
;;;; loss of its leader. Three members each apply committed commands to their own
;;;; raft-resource-store (the linearizable CAS state machine from c2d.4); a write
;;;; on the leader replicates to every replica; killing the leader elects a new
;;;; one from the survivors, and writes keep committing with no loss of the data
;;;; that was already acknowledged.

(in-package #:gr8s/tests)
(def-suite raft-failover :in gr8s)
(in-suite raft-failover)

(defun start-resource-member (id)
  "A member whose state machine is a raft-resource-store; returns (values member
   store) so the test can inspect the replica directly."
  (let ((store (gr8s::make-raft-resource-store)))
    (values (gr8s::start-raft-member id :apply-fn (lambda (c) (gr8s::raft-resource-apply store c)))
            store)))

(defun resource-value (store key)
  (let ((rec (gr8s::raft-resource-get store key)))
    (and rec (gr8s::raft-resource-record-value rec))))

(test raft-replicated-store-survives-leader-failover
  (let* ((ids '("a" "b" "c"))
         (pairs (mapcar (lambda (id)
                          (multiple-value-bind (m s) (start-resource-member id)
                            (list id m s)))
                        ids))
         (member-of (lambda (id) (second (assoc id pairs :test #'equal))))
         (store-of (lambda (id) (third (assoc id pairs :test #'equal))))
         (members (mapcar #'second pairs))
         (live members))
    (unwind-protect
         (progn
           ;; All-voter cluster over real gRPC.
           (dolist (p pairs)
             (gr8s::raft-member-set-peers
              (second p)
              (loop for q in pairs unless (equal (first q) (first p))
                    collect (list (first q) (gr8s::raft-member-host (second q))
                                  (gr8s::raft-member-port (second q))))))
           (dolist (m members) (gr8s::raft-member-start m))
           (is (poll-until (lambda () (= 1 (count-if #'gr8s::raft-member-leader-p members))))
               "a single leader emerges")

           ;; A create replicates to every replica.
           (let ((leader (find-if #'gr8s::raft-member-leader-p members)))
             (multiple-value-bind (result ok)
                 (gr8s::raft-member-propose-sync leader '(:put "cm/a" "v1" :expected nil :uid "u1"))
               (is-true ok "the create commits on the leader")
               (is (eq :ok (first result)) "the state machine accepts the create")))
           (is (poll-until
                (lambda () (every (lambda (p) (equal "v1" (resource-value (third p) "cm/a"))) pairs)))
               "the create replicates to all three replicas")

           ;; Kill the leader; a survivor takes over.
           (let ((old-leader (find-if #'gr8s::raft-member-leader-p members)))
             (gr8s::stop-raft-member old-leader)
             (setf live (remove old-leader live))
             (is (poll-until (lambda () (= 1 (count-if #'gr8s::raft-member-leader-p live))) :timeout 15)
                 "the survivors elect a new leader after the old one is lost")

             ;; The new leader still has the acknowledged data, and new writes commit.
             (let ((new-leader (find-if #'gr8s::raft-member-leader-p live)))
               (is (not (null new-leader)))
               (is (equal "v1" (resource-value (funcall store-of
                                                         (car (find new-leader pairs :key #'second)))
                                               "cm/a"))
                   "the new leader retained the committed create")
               (multiple-value-bind (result ok)
                   (gr8s::raft-member-propose-sync new-leader
                                                   '(:put "cm/b" "v2" :expected nil :uid "u2") :timeout 10)
                 (is-true ok "a write commits under the new leader")
                 (is (eq :ok (first result))))
               (is (poll-until
                    (lambda () (every (lambda (m) (equal "v2" (resource-value
                                                               (funcall store-of
                                                                        (car (find m pairs :key #'second)))
                                                               "cm/b")))
                                      live))
                    :timeout 10)
                   "the post-failover write replicates to every survivor"))))
      (dolist (m live) (ignore-errors (gr8s::stop-raft-member m))))))
