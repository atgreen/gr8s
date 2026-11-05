;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise Raft membership changes (src/raft.lisp, podster-c2d.6) over the
;;;; deterministic simulator: a witness votes and counts toward quorum but never
;;;; leads, a member can be added to a running cluster (and then replicates), and
;;;; a member can be removed (the cluster keeps committing under the new quorum).

(in-package #:gr8s/tests)
(def-suite raft-membership :in gr8s)
(in-suite raft-membership)

(defun configure-cluster (sim members)
  (dolist (entry (rsim-nodes sim)) (gr8s::raft-configure (cdr entry) members)))

(test raft-witness-votes-but-never-leads
  (let ((sim (make-rsim '("v1" "v2" "w") '(("v1" . 5) ("v2" . 7) ("w" . 3)))))  ; witness has the shortest timer
    (configure-cluster sim '(("v1" . :voter) ("v2" . :voter) ("w" . :witness)))
    (let ((witness-ever-leader nil))
      (dotimes (i 20)
        (rsim-tick sim)
        (when (gr8s::raft-leader-p (rsim-node sim "w")) (setf witness-ever-leader t)))
      (is (not witness-ever-leader) "the witness never becomes leader despite the shortest timeout")
      (is (= 1 (count-if #'gr8s::raft-leader-p (mapcar #'cdr (rsim-nodes sim)))))
      (is (equal "v1" (first (rsim-leaders sim)))))               ; the voter with the shorter timer leads
    ;; Partition v2 away: v1 + witness are a 2-of-3 majority and still commit,
    ;; which only holds if the witness counts toward quorum.
    (setf (rsim-groups sim) '(("v1" "w") ("v2")))
    (gr8s::raft-propose (rsim-node sim "v1") '(:set "k" "quorum-ok"))
    (rsim-run sim 8)
    (is (equal "quorum-ok" (gethash "k" (rsim-kv sim "v1"))) "committed with only v1 + witness")))

(test raft-add-member-grows-the-cluster
  (let ((sim (make-rsim '("a" "b" "c" "d") '(("a" . 3) ("b" . 5) ("c" . 7) ("d" . 4)))))
    (dolist (id '("a" "b" "c"))
      (gr8s::raft-configure (rsim-node sim id) '(("a" . :voter) ("b" . :voter) ("c" . :voter))))
    ;; d joins as a learner that knows the cluster but never disrupts it.
    (gr8s::raft-configure (rsim-node sim "d")
                          '(("a" . :voter) ("b" . :voter) ("c" . :voter) ("d" . :learner)))
    (rsim-run sim 8)
    (is (equal "a" (first (rsim-leaders sim))))
    (gr8s::raft-propose-config (rsim-node sim "a") :add "d" :role :voter)
    (rsim-run sim 12)
    (dolist (id '("a" "b" "c"))
      (is (member "d" (gr8s::raft-node-peers (rsim-node sim id)) :test #'equal) "~A sees d as a peer" id))
    (is (eq :voter (gr8s::raft-node-self-role (rsim-node sim "d"))))
    (is (not (gr8s::raft-node-removed (rsim-node sim "d"))))
    ;; A new value now replicates to all four.
    (gr8s::raft-propose (rsim-node sim "a") '(:set "m" "4node"))
    (rsim-run sim 8)
    (dolist (id '("a" "b" "c" "d"))
      (is (equal "4node" (gethash "m" (rsim-kv sim id))) "~A replicated the 4-node write" id))))

(test raft-remove-member-shrinks-the-cluster
  (let ((sim (make-rsim '("a" "b" "c") '(("a" . 3) ("b" . 5) ("c" . 7)))))
    (configure-cluster sim '(("a" . :voter) ("b" . :voter) ("c" . :voter)))
    (rsim-run sim 8)
    (is (equal "a" (first (rsim-leaders sim))))
    (gr8s::raft-propose-config (rsim-node sim "a") :remove "c")
    (rsim-run sim 12)
    (is (not (member "c" (gr8s::raft-node-peers (rsim-node sim "a")) :test #'equal)))
    (is (not (member "c" (gr8s::raft-node-peers (rsim-node sim "b")) :test #'equal)))
    (is (gr8s::raft-node-removed (rsim-node sim "c")))
    ;; The surviving two-member cluster still commits.
    (gr8s::raft-propose (rsim-node sim "a") '(:set "p" "2node"))
    (rsim-run sim 8)
    (is (equal "2node" (gethash "p" (rsim-kv sim "a"))))
    (is (equal "2node" (gethash "p" (rsim-kv sim "b"))))))
