;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise cluster bootstrap over the real ag-gRPC transport (podster-c2d.6):
;;;; a single member forms a cluster and elects itself, two more join a running
;;;; cluster and start replicating, and a member can then be removed and the
;;;; survivors keep committing. This proves the dynamic-membership link
;;;; reconciliation (src/raft-cluster.lisp) end to end, not just in the sim.

(in-package #:gr8s/tests)
(def-suite raft-cluster :in gr8s)
(in-suite raft-cluster)

(defun make-cluster-member (id kvs)
  (gr8s.raft.transport::start-raft-member
   id :apply-fn (let ((kv (cdr (assoc id kvs :test #'equal))))
                  (lambda (command) (raft-kv-apply kv command)))))

(defun member-address (member)
  (list (gr8s.raft.transport::raft-member-host member) (gr8s.raft.transport::raft-member-port member)))

(test raft-cluster-bootstraps-grows-and-shrinks
  (let* ((ids '("a" "b" "c"))
         (kvs (mapcar (lambda (id) (cons id (make-hash-table :test 'equal))) ids))
         (a (make-cluster-member "a" kvs))
         (b (make-cluster-member "b" kvs))
         (c (make-cluster-member "c" kvs))
         (all (list a b c)))
    (unwind-protect
         (progn
           ;; "a" forms the cluster and elects itself.
           (gr8s.raft.transport::raft-cluster-init a)
           (gr8s.raft.transport::raft-member-start a)
           (is (poll-until (lambda () (gr8s.raft.transport::raft-member-leader-p a)))
               "the founding member elects itself leader")

           ;; "b" joins: it learns the leader's address out of band (the token
           ;; handshake), then the leader admits it.
           (gr8s.raft.transport::raft-cluster-prepare-joiner b (list (cons "a" (member-address a))))
           (gr8s.raft.transport::raft-member-start b)
           (is (gr8s.raft.transport::raft-cluster-add-member a "b" (gr8s.raft.transport::raft-member-host b) (gr8s.raft.transport::raft-member-port b))
               "the leader proposes adding b")
           (is (poll-until
                (lambda () (member "b" (cl-raft::raft-node-peers (gr8s.raft.transport::raft-member-node a)) :test #'equal)))
               "b becomes a voting peer once its config entry commits")

           ;; "c" joins the now two-member cluster.
           (gr8s.raft.transport::raft-cluster-prepare-joiner c (list (cons "a" (member-address a))))
           (gr8s.raft.transport::raft-member-start c)
           (is (gr8s.raft.transport::raft-cluster-add-member a "c" (gr8s.raft.transport::raft-member-host c) (gr8s.raft.transport::raft-member-port c)))
           (is (poll-until
                (lambda () (member "c" (cl-raft::raft-node-peers (gr8s.raft.transport::raft-member-node a)) :test #'equal)))
               "c becomes a voting peer")

           ;; A write now replicates to all three state machines.
           (gr8s.raft.transport::raft-member-propose a '(:set "k" "v1"))
           (is (poll-until
                (lambda () (every (lambda (kv) (equal "v1" (gethash "k" (cdr kv)))) kvs)))
               "the 3-member cluster replicates a write to every member")

           ;; A repeated Join must not temporarily demote an established voter.
           (let ((last (cl-raft::raft-last-log-index (gr8s.raft.transport::raft-member-node a))))
             (is (gr8s.raft.transport::raft-cluster-join b (gr8s.raft.transport::raft-member-host a) (gr8s.raft.transport::raft-member-port a)))
             (is (eq :voter (cl-raft::raft-node-self-role (gr8s.raft.transport::raft-member-node b))))
             (is (eq :voter (cl-raft::raft-member-role (gr8s.raft.transport::raft-member-node a) "b")))
             (is (= last (cl-raft::raft-last-log-index (gr8s.raft.transport::raft-member-node a)))))

           ;; Remove "c"; the surviving two keep committing.
           (is (gr8s.raft.transport::raft-cluster-remove-member a "c"))
           (is (poll-until
                (lambda () (not (member "c" (cl-raft::raft-node-peers (gr8s.raft.transport::raft-member-node a)) :test #'equal))))
               "c leaves the configuration")
           (is (poll-until (lambda () (cl-raft::raft-node-removed (gr8s.raft.transport::raft-member-node c))))
               "the removed member learns it is out and stops participating")
           (gr8s.raft.transport::raft-member-propose a '(:set "k" "v2"))
           (is (poll-until
                (lambda () (and (equal "v2" (gethash "k" (cdr (assoc "a" kvs :test #'equal))))
                                (equal "v2" (gethash "k" (cdr (assoc "b" kvs :test #'equal)))))))
               "the surviving two-member cluster still commits"))
      (dolist (m all) (ignore-errors (gr8s.raft.transport::stop-raft-member m))))))

(defun learner-test-join (member id port &optional (role "voter"))
  (gr8s.raft.transport::raft-member-handle-join
   member (make-instance 'gr8s.node.v1::join-request :member-id id :host "127.0.0.1" :port port :role role) nil))

(test join-keeps-unreachable-voters-out-of-quorum-until-applied
  (let ((sim (make-rsim '("a" "l") '(("a" . 3) ("l" . 9)))))
    (cl-raft::raft-configure (rsim-node sim "a") '(("a" . :voter)))
    (cl-raft::raft-configure (rsim-node sim "l") '(("a" . :voter) ("l" . :learner)))
    (rsim-run sim 8)
    (let* ((node (rsim-node sim "a"))
           (member (gr8s.raft.transport::make-raft-member :node node)))
      (setf (rsim-groups sim) '(("a") ("l")))
      (is-true (gr8s.node.v1::accepted (learner-test-join member "l" 19002)))
      (is (eq :learner (cl-raft::raft-member-role node "l")))
      (is (eq :voter (gethash "l" (gr8s.raft::raft-node-promotion-intents node))))
      (dotimes (i 20)
        (cl-raft::raft-propose node (list :set "ongoing" i))
        (gr8s.raft.transport::raft-member-promote-learners member)
        (rsim-drain sim))
      (is (= 19 (gethash "ongoing" (rsim-kv sim "a"))))
      (is (= 1 (cl-raft::raft-cluster-size node)))
      (let ((last (cl-raft::raft-last-log-index node)))
        (dotimes (i 5) (is-true (gr8s.node.v1::accepted (learner-test-join member "l" 19002))))
        (is (= last (cl-raft::raft-last-log-index node)))
        (is (not (gr8s.node.v1::accepted (learner-test-join member "l" 19003))))
        (is (= last (cl-raft::raft-last-log-index node))))
      (setf (rsim-groups sim) nil)
      (rsim-run sim 4)
      (gr8s.raft.transport::raft-member-promote-learners member)
      (rsim-run sim 4)
      (is (eq :voter (cl-raft::raft-member-role node "l")))
      (is (null (gethash "l" (gr8s.raft::raft-node-promotion-intents node))))
      (is (= 19 (gethash "ongoing" (rsim-kv sim "l"))))
      (let ((last (cl-raft::raft-last-log-index node)))
        (is-true (gr8s.node.v1::accepted (learner-test-join member "l" 19002)))
        (is (= last (cl-raft::raft-last-log-index node)))
        (is (eq :voter (cl-raft::raft-member-role node "l")))))))

(test join-honors-uncommitted-admission-and-rejects-overlapping-change
  (let ((sim (make-rsim '("a" "b" "c") '(("a" . 3) ("b" . 7) ("c" . 9)))))
    (rsim-run sim 8)
    (let* ((node (rsim-node sim "a")) (member (gr8s.raft.transport::make-raft-member :node node)))
      (setf (rsim-groups sim) '(("a") ("b" "c")))
      (is-true (gr8s.node.v1::accepted (learner-test-join member "l" 19002)))
      (let ((last (cl-raft::raft-last-log-index node)))
        (is-true (gr8s.node.v1::accepted (learner-test-join member "l" 19002)))
        (is (not (gr8s.node.v1::accepted (learner-test-join member "other" 19003))))
        (is (null (gethash "other" (cl-raft::raft-node-peer-addresses node))))
        (is (= last (cl-raft::raft-last-log-index node))))
      (is (null (gethash "l" (gr8s.raft::raft-node-promotion-intents node)))))))

(test removal-and-prior-term-config-block-overlap-with-bounded-handoff-barrier
  (let ((sim (make-rsim '("a" "b" "c") '(("a" . 3) ("b" . 7) ("c" . 9)))))
    (rsim-run sim 8)
    (let* ((node (rsim-node sim "a")) (member (gr8s.raft.transport::make-raft-member :node node)))
      (setf (rsim-groups sim) '(("a") ("b" "c")))
      (multiple-value-bind (index accepted) (cl-raft::raft-propose-config node :remove "b")
        (is (integerp index)) (is (eq t accepted)))
      (is (zerop (hash-table-count (cl-raft::raft-node-pending-members node))))
      (is-true (gr8s.raft::raft-config-change-in-flight-p node))
      (multiple-value-bind (index reason) (cl-raft::raft-propose-config node :add "l" :role :learner)
        (is (null index)) (is (eq :change-in-flight reason)))
      (incf (cl-raft::raft-node-current-term node))
      (cl-raft::raft-become-leader node)
      (gr8s.raft.transport::raft-member-promote-learners member)
      (let ((last (cl-raft::raft-last-log-index node)))
        (is (equal '(:raft-barrier) (cl-raft::raft-entry-command (cl-raft::raft-log-entry node last))))
        (dotimes (i 50) (gr8s.raft.transport::raft-member-promote-learners member))
        (is (= last (cl-raft::raft-last-log-index node))))
      (setf (rsim-groups sim) nil)
      (rsim-drain sim)
      (rsim-run sim 4)
      (is (not (gr8s.raft::raft-config-change-in-flight-p node)))
      (is (= (cl-raft::raft-node-current-term node)
             (cl-raft::raft-log-term node (cl-raft::raft-node-commit-index node))))
      (is (not (member "b" (cl-raft::raft-node-peers node) :test #'equal))))))
