;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the replicated desired-state store state machine (src/raft-store.lisp)
;;;; over the deterministic Raft simulator: a create + compare-and-swap updates
;;;; replicate identically to every member, linearizable CAS admits exactly one
;;;; of two conflicting updates, the pre-assigned UID is deterministic across
;;;; members, and delete honors the resourceVersion precondition.

(in-package #:gr8s/tests)
(def-suite raft-store :in gr8s)
(in-suite raft-store)

(defun make-store-sim ()
  (make-rsim '("a" "b" "c") '(("a" . 3) ("b" . 5) ("c" . 7))
             :state-factory (lambda () (gr8s.ha::make-raft-resource-store))
             :apply-maker (lambda (state) (lambda (command) (gr8s.ha::raft-resource-apply state command)))))

(defun store-records-agree (sim key)
  (let ((a (rsim-kv sim "a")))
    (and (gr8s.ha::raft-resource-store-equal a (rsim-kv sim "b"))
         (gr8s.ha::raft-resource-store-equal a (rsim-kv sim "c"))
         (gr8s.ha::raft-resource-get a key))))

(test raft-store-replicates-deterministically-with-linearizable-cas
  (let ((sim (make-store-sim)) (create nil) (u1 nil) (u2 nil))
    (rsim-run sim 8)
    (let ((leader (rsim-node sim "a")))
      ;; Create x with a leader-assigned UID.
      (cl-raft::raft-propose leader '(:put "x" "v0" :expected nil :uid "uid-123")
                          (lambda (r) (setf create r)))
      (rsim-run sim 6)
      (is (eq :ok (first create)))
      (let ((rv (second create)))
        ;; Two conflicting CAS updates at the same expected resourceVersion.
        (cl-raft::raft-propose leader (list :put "x" "vA" :expected rv :uid "ignored")
                            (lambda (r) (setf u1 r)))
        (cl-raft::raft-propose leader (list :put "x" "vB" :expected rv :uid "ignored")
                            (lambda (r) (setf u2 r)))
        (rsim-run sim 6)
        (is (eq :ok (first u1)))               ; the serialized-first update wins
        (is (eq :conflict (first u2)))         ; the stale CAS is rejected
        (let ((rec (store-records-agree sim "x")))
          (is (not (null rec)) "all three replicas converged")
          (is (equal "uid-123" (gr8s.ha::raft-resource-record-uid rec)))  ; deterministic UID
          (is (equal "vA" (gr8s.ha::raft-resource-record-value rec)))
          (is (> (gr8s.ha::raft-resource-record-resource-version rec) rv)))))))

(test raft-store-delete-honors-resource-version
  (let ((sim (make-store-sim)) (create nil) (bad nil) (good nil))
    (rsim-run sim 8)
    (let ((leader (rsim-node sim "a")))
      (cl-raft::raft-propose leader '(:put "y" "v0" :expected nil :uid "uid-y")
                          (lambda (r) (setf create r)))
      (rsim-run sim 6)
      (let ((rv (second create)))
        ;; Delete with the wrong precondition is refused.
        (cl-raft::raft-propose leader (list :delete "y" :expected (+ rv 99))
                            (lambda (r) (setf bad r)))
        (rsim-run sim 4)
        (is (eq :conflict (first bad)))
        (is (not (null (gr8s.ha::raft-resource-get (rsim-kv sim "a") "y"))))
        ;; Delete with the matching precondition succeeds and replicates.
        (cl-raft::raft-propose leader (list :delete "y" :expected rv)
                            (lambda (r) (setf good r)))
        (rsim-run sim 6)
        (is (eq :ok (first good)))
        (is (gr8s.ha::raft-resource-store-equal (rsim-kv sim "a") (rsim-kv sim "b")))
        (is (gr8s.ha::raft-resource-store-equal (rsim-kv sim "a") (rsim-kv sim "c")))
        (dolist (id '("a" "b" "c"))
          (is (null (gr8s.ha::raft-resource-get (rsim-kv sim id) "y"))))))))
