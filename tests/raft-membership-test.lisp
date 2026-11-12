;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise Raft membership changes (src/raft/core.lisp, podster-c2d.6) over the
;;;; deterministic simulator: a witness votes and counts toward quorum but never
;;;; leads, a member can be added to a running cluster (and then replicates), and
;;;; a member can be removed (the cluster keeps committing under the new quorum).

(in-package #:gr8s/tests)
(def-suite raft-membership :in gr8s)
(in-suite raft-membership)

(defun configure-cluster (sim members)
  (dolist (entry (rsim-nodes sim)) (cl-raft::raft-configure (cdr entry) members)))

(test raft-witness-votes-but-never-leads
  (let ((sim (make-rsim '("v1" "v2" "w") '(("v1" . 5) ("v2" . 7) ("w" . 3)))))  ; witness has the shortest timer
    (configure-cluster sim '(("v1" . :voter) ("v2" . :voter) ("w" . :witness)))
    (let ((witness-ever-leader nil))
      (dotimes (i 20)
        (rsim-tick sim)
        (when (cl-raft::raft-leader-p (rsim-node sim "w")) (setf witness-ever-leader t)))
      (is (not witness-ever-leader) "the witness never becomes leader despite the shortest timeout")
      (is (= 1 (count-if #'cl-raft::raft-leader-p (mapcar #'cdr (rsim-nodes sim)))))
      (is (equal "v1" (first (rsim-leaders sim)))))               ; the voter with the shorter timer leads
    ;; Partition v2 away: v1 + witness are a 2-of-3 majority and still commit,
    ;; which only holds if the witness counts toward quorum.
    (setf (rsim-groups sim) '(("v1" "w") ("v2")))
    (cl-raft::raft-propose (rsim-node sim "v1") '(:set "k" "quorum-ok"))
    (rsim-run sim 8)
    (is (equal "quorum-ok" (gethash "k" (rsim-kv sim "v1"))) "committed with only v1 + witness")))

(test raft-add-member-grows-the-cluster
  (let ((sim (make-rsim '("a" "b" "c" "d") '(("a" . 3) ("b" . 5) ("c" . 7) ("d" . 4)))))
    (dolist (id '("a" "b" "c"))
      (cl-raft::raft-configure (rsim-node sim id) '(("a" . :voter) ("b" . :voter) ("c" . :voter))))
    ;; d joins as a learner that knows the cluster but never disrupts it.
    (cl-raft::raft-configure (rsim-node sim "d")
                          '(("a" . :voter) ("b" . :voter) ("c" . :voter) ("d" . :learner)))
    (rsim-run sim 8)
    (is (equal "a" (first (rsim-leaders sim))))
    (cl-raft::raft-propose-config (rsim-node sim "a") :add "d" :role :voter)
    (rsim-run sim 12)
    (dolist (id '("a" "b" "c"))
      (is (member "d" (cl-raft::raft-node-peers (rsim-node sim id)) :test #'equal) "~A sees d as a peer" id))
    (is (eq :voter (cl-raft::raft-node-self-role (rsim-node sim "d"))))
    (is (not (cl-raft::raft-node-removed (rsim-node sim "d"))))
    ;; A new value now replicates to all four.
    (cl-raft::raft-propose (rsim-node sim "a") '(:set "m" "4node"))
    (rsim-run sim 8)
    (dolist (id '("a" "b" "c" "d"))
      (is (equal "4node" (gethash "m" (rsim-kv sim id))) "~A replicated the 4-node write" id))))

(test raft-remove-member-shrinks-the-cluster
  (let ((sim (make-rsim '("a" "b" "c") '(("a" . 3) ("b" . 5) ("c" . 7)))))
    (configure-cluster sim '(("a" . :voter) ("b" . :voter) ("c" . :voter)))
    (rsim-run sim 8)
    (is (equal "a" (first (rsim-leaders sim))))
    (cl-raft::raft-propose-config (rsim-node sim "a") :remove "c")
    (rsim-run sim 12)
    (is (not (member "c" (cl-raft::raft-node-peers (rsim-node sim "a")) :test #'equal)))
    (is (not (member "c" (cl-raft::raft-node-peers (rsim-node sim "b")) :test #'equal)))
    (is (cl-raft::raft-node-removed (rsim-node sim "c")))
    ;; The surviving two-member cluster still commits.
    (cl-raft::raft-propose (rsim-node sim "a") '(:set "p" "2node"))
    (rsim-run sim 8)
    (is (equal "2node" (gethash "p" (rsim-kv sim "a"))))
    (is (equal "2node" (gethash "p" (rsim-kv sim "b"))))))

(test learner-promotion-requires-a-current-term-applied-receipt
  (let ((sim (make-rsim '("a" "l") '(("a" . 3) ("l" . 9)))))
    (configure-cluster sim '(("a" . :voter) ("l" . :learner)))
    (rsim-run sim 8)
    (let ((leader (rsim-node sim "a")))
      (multiple-value-bind (index reason) (cl-raft::raft-propose-config leader :add "l" :role :voter)
        (is (null index)) (is (eq :learner-not-ready reason)))
      (cl-raft::raft-propose leader '(:set "barrier" "committed"))
      (rsim-run sim 3)
      (is-true (gr8s.raft::raft-peer-ready-for-promotion-p leader "l"))
      (let* ((boundary (cl-raft::raft-node-commit-index leader))
             (term (cl-raft::raft-node-current-term leader))
             (reply (list :type :append-entries-reply :from "l" :term term :success t :match-index boundary)))
        ;; A legacy peer's log match does not prove application catch-up.
        (clrhash (gr8s.raft::raft-node-peer-applied leader))
        (cl-raft::raft-handle-message leader reply)
        (is (not (gr8s.raft::raft-peer-ready-for-promotion-p leader "l")))
        (dolist (bad (list -1 (1+ boundary) "1"))
          (cl-raft::raft-handle-message leader (append (list :applied-index bad) reply))
          (is (not (gr8s.raft::raft-peer-ready-for-promotion-p leader "l"))))
        (cl-raft::raft-handle-message leader (append (list :applied-index boundary :term (1- term)) reply))
        (is (not (gr8s.raft::raft-peer-ready-for-promotion-p leader "l")))
        (cl-raft::raft-handle-message leader (append (list :applied-index boundary :success nil) reply))
        (is (not (gr8s.raft::raft-peer-ready-for-promotion-p leader "l")))
        (cl-raft::raft-handle-message leader (append (list :applied-index boundary :from "outsider") reply))
        (is (null (gethash "outsider" (gr8s.raft::raft-node-peer-applied leader))))
        (cl-raft::raft-handle-message leader (append (list :applied-index boundary) reply))
        (is-true (gr8s.raft::raft-peer-ready-for-promotion-p leader "l"))
        ;; A newly committed write makes the old applied receipt insufficient.
        (cl-raft::raft-propose leader '(:set "later" "committed"))
        (is (not (gr8s.raft::raft-peer-ready-for-promotion-p leader "l")))
        (rsim-run sim 3)
        (is-true (gr8s.raft::raft-peer-ready-for-promotion-p leader "l"))
        (multiple-value-bind (index accepted) (cl-raft::raft-propose-config leader :add "l" :role :voter)
          (is (integerp index)) (is (eq t accepted)))
        (rsim-run sim 3)
        (is (eq :voter (cl-raft::raft-member-role leader "l")))))))

(test failed-application-never-acknowledges-applied-progress
  (let* ((sent nil)
         (node (cl-raft::make-raft-node :id "l" :peers '("a")
                 :apply-fn (lambda (command) (declare (ignore command)) (error "injected apply failure"))
                 :send-fn (lambda (to msg) (declare (ignore to)) (push msg sent))))
         (message (list :type :append-entries :from "a" :term 1 :prev-log-index 0 :prev-log-term 0
                        :leader-commit 1 :entries (list (cl-raft::make-raft-entry :index 1 :term 1 :command '(:set "k" "v"))))))
    (signals error (cl-raft::raft-handle-message node message))
    (is (zerop (cl-raft::raft-node-last-applied node)))
    (is (null sent))
    (setf (cl-raft::raft-node-apply-fn node) (lambda (command) (declare (ignore command)) :applied))
    (cl-raft::raft-handle-message node message)
    (is (eq t (getf (first sent) :success)))
    (is (= 1 (getf (first sent) :applied-index)))
    (is (= 1 (cl-raft::raft-node-last-applied node)))))

(test leadership-change-clears-learner-applied-evidence
  (let ((sim (make-rsim '("a" "l") '(("a" . 3) ("l" . 9)))))
    (configure-cluster sim '(("a" . :voter) ("l" . :learner)))
    (rsim-run sim 8)
    (let ((leader (rsim-node sim "a")))
      (cl-raft::raft-propose leader '(:set "k" "v"))
      (rsim-run sim 3)
      (is-true (gr8s.raft::raft-peer-ready-for-promotion-p leader "l"))
      (cl-raft::raft-become-leader leader)
      (is (zerop (hash-table-count (gr8s.raft::raft-node-peer-applied leader))))
      (is (not (gr8s.raft::raft-peer-ready-for-promotion-p leader "l")))
      (rsim-drain sim)
      (is-true (gr8s.raft::raft-peer-ready-for-promotion-p leader "l"))
      ;; Even a fresh receipt cannot substitute for a current-term commit.
      (incf (cl-raft::raft-node-current-term leader))
      (cl-raft::raft-become-leader leader)
      (rsim-drain sim)
      (is (not (gr8s.raft::raft-peer-ready-for-promotion-p leader "l")))
      (cl-raft::raft-propose leader '(:set "new-term" "barrier"))
      (rsim-run sim 3)
      (is-true (gr8s.raft::raft-peer-ready-for-promotion-p leader "l")))))

(test learner-promotion-intent-is-committed-with-membership
  (let ((sim (make-rsim '("a" "b" "c" "l") '(("a" . 3) ("b" . 7) ("c" . 9) ("l" . 11)))))
    (dolist (id '("a" "b" "c"))
      (cl-raft::raft-configure (rsim-node sim id) '(("a" . :voter) ("b" . :voter) ("c" . :voter))))
    (cl-raft::raft-configure (rsim-node sim "l") '(("a" . :voter) ("b" . :voter) ("c" . :voter) ("l" . :learner)))
    (rsim-run sim 8)
    (let ((leader (rsim-node sim "a")))
      (setf (rsim-groups sim) '(("a") ("b" "c" "l")))
      (multiple-value-bind (index accepted)
          (cl-raft::raft-propose-config leader :add "l" :role :learner :promotion-role :voter)
        (is (integerp index)) (is (eq t accepted)))
      (rsim-drain sim)
      (is (null (gethash "l" (gr8s.raft::raft-node-promotion-intents leader))))
      (is (null (gethash "l" (cl-raft::raft-node-roles leader))))
      (setf (rsim-groups sim) nil)
      (rsim-run sim 3)
      (dolist (id '("a" "b" "c" "l"))
        (is (eq :voter (gethash "l" (gr8s.raft::raft-node-promotion-intents (rsim-node sim id)))))
        (is (eq :learner (gethash "l" (cl-raft::raft-node-roles (rsim-node sim id))))))
      ;; An unrelated membership entry must carry the outstanding intent.
      (cl-raft::raft-propose-config leader :add "b" :role :voter)
      (rsim-run sim 3)
      (is (eq :voter (gethash "l" (gr8s.raft::raft-node-promotion-intents leader))))
      (is-true (gr8s.raft::raft-peer-ready-for-promotion-p leader "l"))
      (cl-raft::raft-propose-config leader :add "l" :role :voter)
      (rsim-run sim 3)
      (is (eq :voter (cl-raft::raft-member-role leader "l")))
      (is (null (gethash "l" (gr8s.raft::raft-node-promotion-intents leader)))))))

(test learner-promotion-intent-survives-wal-replay-and-checkpoint
  (dolist (checkpoint '(nil t))
    (with-raft-temp-dir (path)
      (let* ((storage (cl-raft::open-file-raft-storage path))
             (node (make-standalone-node :storage storage :snapshot/restore t)))
        (unwind-protect
             (progn
               (cl-raft::raft-become-candidate node)
               (cl-raft::raft-propose-config node :add "l" :role :learner :promotion-role :voter)
               (cl-raft::raft-propose node '(:set "k" "preserved"))
               (is (eq :voter (gethash "l" (gr8s.raft::raft-node-promotion-intents node))))
               (when checkpoint (cl-raft::raft-compact node (cl-raft::raft-node-last-applied node))))
          (cl-raft::close-file-raft-storage storage)))
      (multiple-value-bind (restored kv) (make-standalone-node :snapshot/restore t)
        (unwind-protect
             (progn
               (cl-raft::recover-raft-node restored path)
               (when checkpoint
                 (is (eq :voter (gethash "l" (gr8s.raft::raft-node-promotion-intents restored)))))
               ;; Recovered suffixes require a confirmed commit before application.
               (setf (cl-raft::raft-node-commit-index restored) (cl-raft::raft-last-log-index restored))
               (cl-raft::raft-apply-committed restored)
               (is (equal "preserved" (gethash "k" kv)))
               (is (eq :learner (cl-raft::raft-member-role restored "l")))
               (is (eq :voter (gethash "l" (gr8s.raft::raft-node-promotion-intents restored))))
               (is (zerop (hash-table-count (gr8s.raft::raft-node-peer-applied restored))))
               (is (not (gr8s.raft::raft-peer-ready-for-promotion-p restored "l")))
               (cl-raft::raft-become-candidate restored)
               (cl-raft::raft-propose-config restored :remove "l")
               (is (null (gethash "l" (gr8s.raft::raft-node-promotion-intents restored)))))
          (when (cl-raft::raft-node-storage restored)
            (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage restored))))))))

(test invalid-promotion-intent-cannot-mutate-config-or-restore-application
  (let ((node (make-standalone-node)) (restored nil))
    (cl-raft::raft-configure node '(("n1" . :voter) ("l" . :learner)))
    (dolist (bad '((("n1" . :voter)) (("missing" . :voter)) (("l" . :witness)) (("l" . :voter) ("l" . :voter))))
      (signals error (cl-raft::raft-adopt-config node '(("n1" . :voter) ("l" . :learner))
                                            '(("n1" "changed" 1234)) nil bad))
      (is (null (gethash "n1" (cl-raft::raft-node-peer-addresses node))))
      (setf (cl-raft::raft-node-restore-fn node) (lambda (state) (declare (ignore state)) (setf restored t)))
      (signals error (gr8s.raft::raft-restore-snapshot-contents
                      node (list :cl-raft-snapshot 1 :application-present t :application nil
                                 :members '(("n1" . :voter) ("l" . :learner)) :promotions bad)))
      (is (not restored)))
    (signals error (cl-raft::raft-propose-config node :add "l" :role :voter :promotion-role :voter))))
