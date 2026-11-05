;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
  (gr8s::start-raft-member
   id :apply-fn (let ((kv (cdr (assoc id kvs :test #'equal))))
                  (lambda (command) (raft-kv-apply kv command)))))

(defun member-address (member)
  (list (gr8s::raft-member-host member) (gr8s::raft-member-port member)))

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
           (gr8s::raft-cluster-init a)
           (gr8s::raft-member-start a)
           (is (poll-until (lambda () (gr8s::raft-member-leader-p a)))
               "the founding member elects itself leader")

           ;; "b" joins: it learns the leader's address out of band (the token
           ;; handshake), then the leader admits it.
           (gr8s::raft-cluster-prepare-joiner b (list (cons "a" (member-address a))))
           (gr8s::raft-member-start b)
           (is (gr8s::raft-cluster-add-member a "b" (gr8s::raft-member-host b) (gr8s::raft-member-port b))
               "the leader proposes adding b")
           (is (poll-until
                (lambda () (member "b" (gr8s::raft-node-peers (gr8s::raft-member-node a)) :test #'equal)))
               "b becomes a voting peer once its config entry commits")

           ;; "c" joins the now two-member cluster.
           (gr8s::raft-cluster-prepare-joiner c (list (cons "a" (member-address a))))
           (gr8s::raft-member-start c)
           (is (gr8s::raft-cluster-add-member a "c" (gr8s::raft-member-host c) (gr8s::raft-member-port c)))
           (is (poll-until
                (lambda () (member "c" (gr8s::raft-node-peers (gr8s::raft-member-node a)) :test #'equal)))
               "c becomes a voting peer")

           ;; A write now replicates to all three state machines.
           (gr8s::raft-member-propose a '(:set "k" "v1"))
           (is (poll-until
                (lambda () (every (lambda (kv) (equal "v1" (gethash "k" (cdr kv)))) kvs)))
               "the 3-member cluster replicates a write to every member")

           ;; Remove "c"; the surviving two keep committing.
           (is (gr8s::raft-cluster-remove-member a "c"))
           (is (poll-until
                (lambda () (not (member "c" (gr8s::raft-node-peers (gr8s::raft-member-node a)) :test #'equal))))
               "c leaves the configuration")
           (is (poll-until (lambda () (gr8s::raft-node-removed (gr8s::raft-member-node c))))
               "the removed member learns it is out and stops participating")
           (gr8s::raft-member-propose a '(:set "k" "v2"))
           (is (poll-until
                (lambda () (and (equal "v2" (gethash "k" (cdr (assoc "a" kvs :test #'equal))))
                                (equal "v2" (gethash "k" (cdr (assoc "b" kvs :test #'equal)))))))
               "the surviving two-member cluster still commits"))
      (dolist (m all) (ignore-errors (gr8s::stop-raft-member m))))))
