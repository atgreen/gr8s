;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise the pure-Lisp Raft core (src/raft.lisp) under a deterministic
;;;; in-process simulator: leader election, log replication + apply, linearizable
;;;; compare-and-swap, leader failover across a partition, and the safety
;;;; guarantee that a partitioned minority leader cannot commit.

(in-package #:gr8s/tests)
(def-suite raft :in gr8s)
(in-suite raft)

;;; A versioned key/value state machine with compare-and-swap. Commands:
;;;   (:set key val)              -> val
;;;   (:cas key expected new)     -> :ok | :conflict   (expected NIL means "absent")
(defun raft-kv-apply (kv command)
  (ecase (first command)
    (:set (setf (gethash (second command) kv) (third command)))
    (:cas (if (equal (gethash (second command) kv) (third command))
              (progn (setf (gethash (second command) kv) (fourth command)) :ok)
              :conflict))))

(defstruct (rsim (:constructor %make-rsim)) nodes kvs (queue '()) (groups nil))

(defun rsim-node (sim id) (cdr (assoc id (rsim-nodes sim) :test #'equal)))
(defun rsim-kv (sim id) (cdr (assoc id (rsim-kvs sim) :test #'equal)))

(defun rsim-deliverable (sim from to)
  (let ((groups (rsim-groups sim)))
    (or (null groups)
        (loop for g in groups
                thereis (and (member from g :test #'equal) (member to g :test #'equal))))))

(defun rsim-drain (sim &optional (max 200000))
  (loop for steps from 0 below max
        while (rsim-queue sim)
        do (destructuring-bind (to . msg) (pop (rsim-queue sim))
             (when (rsim-deliverable sim (getf msg :from) to)
               (gr8s::raft-handle-message (rsim-node sim to) msg)))))

(defun rsim-tick (sim)
  (dolist (entry (rsim-nodes sim)) (gr8s::raft-tick (cdr entry)))
  (rsim-drain sim))

(defun rsim-run (sim ticks) (dotimes (i ticks) (rsim-tick sim)))

(defun make-rsim (ids timeouts)
  "IDS is a list of member ids; TIMEOUTS an alist id->election-timeout (distinct,
   to make elections deterministic). Each node gets its own KV state machine."
  (let ((sim (%make-rsim)))
    (dolist (id ids)
      (let* ((kv (make-hash-table :test 'equal))
             (to (cdr (assoc id timeouts :test #'equal)))
             (node (gr8s::make-raft-node
                    :id id :peers (remove id ids :test #'equal)
                    :heartbeat-timeout 1
                    :timeout-fn (let ((v to)) (lambda () v))
                    :send-fn (lambda (dest message)
                               (setf (rsim-queue sim)
                                     (nconc (rsim-queue sim) (list (cons dest message)))))
                    :apply-fn (let ((k kv)) (lambda (command) (raft-kv-apply k command))))))
        (gr8s::raft-reset-election-timer node)
        (push (cons id node) (rsim-nodes sim))
        (push (cons id kv) (rsim-kvs sim))))
    sim))

(defun rsim-leaders (sim)
  (loop for (id . node) in (rsim-nodes sim)
        when (gr8s::raft-leader-p node) collect id))

(defun three-node-sim ()
  (make-rsim '("a" "b" "c") '(("a" . 3) ("b" . 5) ("c" . 7))))

(test raft-elects-a-single-leader
  (let ((sim (three-node-sim)))
    (rsim-run sim 8)
    (is (equal '("a") (rsim-leaders sim)))                       ; lowest timeout wins, exactly one
    (let ((terms (loop for (id . n) in (rsim-nodes sim) collect (gr8s::raft-node-current-term n))))
      (is (apply #'= terms))                                     ; all on the same term
      (is (plusp (first terms))))
    (dolist (id '("b" "c"))
      (is (equal "a" (gr8s::raft-node-leader-id (rsim-node sim id)))))))

(test raft-replicates-and-applies
  (let ((sim (three-node-sim)))
    (rsim-run sim 8)
    (gr8s::raft-propose (rsim-node sim "a") '(:set "x" 1))
    (gr8s::raft-propose (rsim-node sim "a") '(:set "x" 2))
    (rsim-run sim 6)
    (dolist (id '("a" "b" "c"))
      (is (= 2 (gethash "x" (rsim-kv sim id))) "node ~A has x=2" id)
      (is (= 2 (gr8s::raft-node-commit-index (rsim-node sim id)))))))

(test raft-linearizable-compare-and-swap
  (let ((sim (three-node-sim)) (r1 nil) (r2 nil))
    (rsim-run sim 8)
    (gr8s::raft-propose (rsim-node sim "a") '(:cas "y" nil "A") (lambda (r) (setf r1 r)))
    (gr8s::raft-propose (rsim-node sim "a") '(:cas "y" nil "B") (lambda (r) (setf r2 r)))
    (rsim-run sim 6)
    ;; Exactly one CAS wins; the serialized order makes it deterministic.
    (is (eq :ok r1))
    (is (eq :conflict r2))
    (dolist (id '("a" "b" "c"))
      (is (equal "A" (gethash "y" (rsim-kv sim id))) "node ~A converged to y=A" id))))

(test raft-leader-failover-preserves-committed-and-drops-uncommitted
  (let ((sim (three-node-sim)) (minority-cb nil))
    (rsim-run sim 8)
    (is (equal '("a") (rsim-leaders sim)))
    ;; Commit an entry under leader a, replicated everywhere.
    (gr8s::raft-propose (rsim-node sim "a") '(:set "k" "v1"))
    (rsim-run sim 6)
    (dolist (id '("a" "b" "c")) (is (equal "v1" (gethash "k" (rsim-kv sim id)))))
    ;; Partition a away from the majority {b,c}.
    (setf (rsim-groups sim) '(("a") ("b" "c")))
    ;; a is now a minority leader: a proposal here must NOT commit.
    (gr8s::raft-propose (rsim-node sim "a") '(:set "k" "vX") (lambda (r) (setf minority-cb r)))
    (rsim-run sim 10)
    (is (null minority-cb) "minority leader must not commit")
    ;; The majority side elects a new leader and makes progress.
    (let ((new-leaders (remove "a" (rsim-leaders sim) :test #'equal)))
      (is (= 1 (length new-leaders)))
      (let ((b (rsim-node sim (first new-leaders))))
        (gr8s::raft-propose b '(:set "k" "v2"))
        (rsim-run sim 8)
        ;; Majority side committed v2.
        (dolist (id (second (rsim-groups sim)))
          (is (equal "v2" (gethash "k" (rsim-kv sim id)))))))
    ;; Heal: a learns of the higher term, steps down, and converges; its
    ;; uncommitted vX is discarded.
    (setf (rsim-groups sim) nil)
    (rsim-run sim 12)
    (is (= 1 (length (rsim-leaders sim))) "exactly one leader after heal")
    (dolist (id '("a" "b" "c"))
      (is (equal "v2" (gethash "k" (rsim-kv sim id))) "node ~A converged to k=v2" id))
    (let ((terms (loop for (id . n) in (rsim-nodes sim) collect (gr8s::raft-node-current-term n))))
      (is (apply #'= terms) "all members on one term after heal"))))

(test raft-single-node-self-elects
  (let ((sim (make-rsim '("solo") '(("solo" . 3)))))
    (rsim-run sim 4)
    (is (gr8s::raft-leader-p (rsim-node sim "solo")))
    (gr8s::raft-propose (rsim-node sim "solo") '(:set "z" 9))
    (rsim-run sim 1)
    (is (= 9 (gethash "z" (rsim-kv sim "solo"))))))
