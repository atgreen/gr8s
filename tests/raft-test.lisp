;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the pure-Lisp Raft core (src/raft/core.lisp) under a deterministic
;;;; in-process simulator: leader election, log replication + apply, linearizable
;;;; compare-and-swap, leader failover across a partition, and the safety
;;;; guarantee that a partitioned minority leader cannot commit.

(in-package #:gr8s/tests)
(def-suite raft :in gr8s)
(in-suite raft)

(test raft-core-has-an-explicit-package-boundary
  (let ((package (find-package "GR8S.RAFT")))
    (is (not (null package)))
    (dolist (name '("MAKE-RAFT-NODE" "RAFT-HANDLE-MESSAGE" "RAFT-TICK"
                    "RAFT-PROPOSE" "OPEN-FILE-RAFT-STORAGE" "RECOVER-RAFT-NODE"))
      (multiple-value-bind (symbol status) (and package (find-symbol name package))
        (is (not (null symbol)) "~A is present in GR8S.RAFT" name)
        (is (eq :external status) "~A is exported from GR8S.RAFT" name)))))

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

(defun make-rsim (ids timeouts
                  &key (state-factory (lambda () (make-hash-table :test 'equal)))
                       (apply-maker (lambda (state) (lambda (command) (raft-kv-apply state command)))))
  "IDS is a list of member ids; TIMEOUTS an alist id->election-timeout (distinct,
   to make elections deterministic). Each node gets its own state machine built
   from STATE-FACTORY + APPLY-MAKER (default: a KV hash)."
  (let ((sim (%make-rsim)))
    (dolist (id ids)
      (let* ((state (funcall state-factory))
             (to (cdr (assoc id timeouts :test #'equal)))
             (node (gr8s::make-raft-node
                    :id id :peers (remove id ids :test #'equal)
                    :heartbeat-timeout 1
                    :timeout-fn (let ((v to)) (lambda () v))
                    :send-fn (lambda (dest message)
                               (setf (rsim-queue sim)
                                     (nconc (rsim-queue sim) (list (cons dest message)))))
                    :apply-fn (funcall apply-maker state))))
        (gr8s::raft-reset-election-timer node)
        (push (cons id node) (rsim-nodes sim))
        (push (cons id state) (rsim-kvs sim))))
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

;;; ---------------------------------------------------------------------------
;;; Durability + compaction (podster-c2d.2).

(defun make-standalone-node (&key kv storage snapshot/restore)
  "A single raft-node with a no-op transport and a KV state machine."
  (let ((kv (or kv (make-hash-table :test 'equal))))
    (values
     (gr8s::make-raft-node
      :id "n1" :peers nil
      :send-fn (lambda (to msg) (declare (ignore to msg)))
      :apply-fn (lambda (command) (raft-kv-apply kv command))
      :storage storage
      :snapshot-fn (when snapshot/restore
                     (lambda () (loop for k being the hash-keys of kv using (hash-value v)
                                      collect (cons k v))))
      :restore-fn (when snapshot/restore
                    (lambda (state) (clrhash kv) (loop for (k . v) in state do (setf (gethash k kv) v)))))
     kv)))

(defmacro with-raft-temp-dir ((path) &body body)
  `(let ((,path (namestring (merge-pathnames (format nil "gr8s-raft-~36R/wal" (random (expt 36 10)))
                                             (uiop:temporary-directory)))))
     (unwind-protect (progn ,@body)
       (ignore-errors (uiop:delete-directory-tree
                       (uiop:pathname-directory-pathname ,path) :validate t :if-does-not-exist :ignore)))))

(test raft-compaction-trims-log-and-preserves-access
  (let ((node (make-standalone-node)))
    (dotimes (i 5) (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command (list :set "x" i))))
    (setf (gr8s::raft-node-commit-index node) 5)
    (is (= 5 (gr8s::raft-last-log-index node)))
    (gr8s::raft-compact node 3)
    (is (= 3 (gr8s::raft-node-snapshot-index node)))
    (is (= 1 (gr8s::raft-node-snapshot-term node)))
    (is (= 5 (gr8s::raft-last-log-index node)))            ; absolute length unchanged by compaction
    (is (null (gr8s::raft-log-entry node 2)))              ; compacted away
    (is (null (gr8s::raft-log-entry node 3)))              ; == snapshot boundary
    (is (= 1 (gr8s::raft-log-term node 3)))                ; term still answerable at the boundary
    (let ((e4 (gr8s::raft-log-entry node 4)))
      (is (not (null e4)))                                 ; tail intact
      (is (= 4 (gr8s::raft-entry-index e4))))))

(test raft-crash-recovery-restores-hard-state-and-log
  (with-raft-temp-dir (path)
    ;; Write a WAL: hard state + three log entries, then "crash" (close).
    (multiple-value-bind (node kv) (make-standalone-node :storage (gr8s::open-file-raft-storage path))
      (declare (ignore kv))
      (setf (gr8s::raft-node-current-term node) 7 (gr8s::raft-node-voted-for node) "peer-b")
      (gr8s::raft-persist-hard-state node)
      (gr8s::raft-log-append node (gr8s::make-raft-entry :term 7 :command '(:set "a" 1)))
      (gr8s::raft-log-append node (gr8s::make-raft-entry :term 7 :command '(:set "b" 2)))
      (gr8s::raft-log-append node (gr8s::make-raft-entry :term 7 :command '(:set "a" 3)))
      (gr8s::close-file-raft-storage (gr8s::raft-node-storage node)))
    ;; Recover a fresh node from the same WAL.
    (let ((node2 (make-standalone-node)))
      (gr8s::recover-raft-node node2 path)
      (is (= 7 (gr8s::raft-node-current-term node2)))
      (is (equal "peer-b" (gr8s::raft-node-voted-for node2)))
      (is (= 3 (gr8s::raft-last-log-index node2)))
      (is (equal '(:set "a" 3) (gr8s::raft-entry-command (gr8s::raft-log-entry node2 3))))
      (is (= 7 (gr8s::raft-log-term node2 2)))
      (gr8s::close-file-raft-storage (gr8s::raft-node-storage node2)))))

(test raft-recovery-restores-snapshot-state
  (with-raft-temp-dir (path)
    (multiple-value-bind (node kv) (make-standalone-node :storage (gr8s::open-file-raft-storage path)
                                                         :snapshot/restore t)
      (dotimes (i 5) (gr8s::raft-log-append node (gr8s::make-raft-entry :term 2 :command (list :set "x" i))))
      (setf (gr8s::raft-node-commit-index node) 3)
      (gr8s::raft-apply-committed node)                    ; only the prefix through entry 3 is applied
      (is (= 2 (gethash "x" kv)))
      (gr8s::raft-compact node 3)                          ; persists snapshot image of kv
      (gr8s::close-file-raft-storage (gr8s::raft-node-storage node)))
    ;; Recover: snapshot image restores the state machine; the tail survives.
    (multiple-value-bind (node2 kv2) (make-standalone-node :snapshot/restore t)
      (gr8s::recover-raft-node node2 path)
      (is (= 2 (gethash "x" kv2)) "state machine restored from snapshot")
      (is (= 3 (gr8s::raft-node-snapshot-index node2)))
      (is (= 5 (gr8s::raft-last-log-index node2)))         ; entries 4,5 survived compaction
      (is (not (null (gr8s::raft-log-entry node2 4))))
      (is (= 3 (gr8s::raft-node-last-applied node2)))      ; applied up to the snapshot boundary
      (setf (gr8s::raft-node-commit-index node2) 5)
      (gr8s::raft-apply-committed node2)
      (is (= 4 (gethash "x" kv2)) "tail is applied once after the exact prefix snapshot")
      (gr8s::close-file-raft-storage (gr8s::raft-node-storage node2)))))

(test raft-single-node-self-elects
  (let ((sim (make-rsim '("solo") '(("solo" . 3)))))
    (rsim-run sim 4)
    (is (gr8s::raft-leader-p (rsim-node sim "solo")))
    (gr8s::raft-propose (rsim-node sim "solo") '(:set "z" 9))
    (rsim-run sim 1)
    (is (= 9 (gethash "z" (rsim-kv sim "solo"))))))

(in-suite raft)
(defclass failing-raft-storage ()
  ((operation :initarg :operation :accessor failing-raft-operation)))
(defmethod gr8s.raft:raft-storage-append-entry ((storage failing-raft-storage) entry)
  (declare (ignore entry))
  (when (eq :append (failing-raft-operation storage)) (error "Injected append failure")))
(defmethod gr8s.raft:raft-storage-truncate ((storage failing-raft-storage) index)
  (declare (ignore index))
  (when (eq :truncate (failing-raft-operation storage)) (error "Injected truncate failure")))
(defmethod gr8s.raft:raft-storage-save-snapshot ((storage failing-raft-storage) index term state)
  (declare (ignore index term state))
  (when (eq :snapshot (failing-raft-operation storage)) (error "Injected snapshot failure")))

(test raft-failed-storage-keeps-log-and-compaction-boundary
  (let* ((storage (make-instance 'failing-raft-storage :operation nil))
         (node (make-standalone-node :storage storage)))
    (dotimes (i 5)
      (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command (list :set "x" i))))
    (setf (failing-raft-operation storage) :append)
    (signals error (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command '(:set "x" 99))))
    (is (= 5 (gr8s::raft-last-log-index node)))
    (setf (failing-raft-operation storage) :truncate)
    (signals error (gr8s::raft-log-truncate node 4))
    (is (= 5 (gr8s::raft-last-log-index node)))
    (is (equal '(:set "x" 4) (gr8s::raft-entry-command (gr8s::raft-log-entry node 5))))
    (setf (failing-raft-operation storage) :snapshot
          (gr8s::raft-node-commit-index node) 3)
    (signals error (gr8s::raft-compact node 3))
    (is (= 0 (gr8s::raft-node-snapshot-index node)))
    (is (= 5 (gr8s::raft-last-log-index node)))
    (is (equal '(:set "x" 0) (gr8s::raft-entry-command (gr8s::raft-log-entry node 1))))))

(test raft-truncation-and-compaction-release-backing-array-references
  (let ((node (make-standalone-node)))
    (dotimes (i 8)
      (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command (list :set "x" i))))
    (gr8s::raft-log-truncate node 6)
    (let ((log (gr8s::raft-node-log node)))
      (loop for i from 5 below 8 do (is (null (aref log i)))))
    (setf (gr8s::raft-node-commit-index node) 3)
    (gr8s::raft-compact node 3)
    (is (= 2 (fill-pointer (gr8s::raft-node-log node))))
    (is (= 4 (gr8s::raft-entry-index (gr8s::raft-log-entry node 4))))
    (let ((log (gr8s::raft-node-log node)))
      (loop for i from 2 below 8 do (is (null (aref log i)))))
    (signals error (gr8s::raft-log-truncate node 3))))

(test raft-snapshot-refuses-to-label-current-state-as-an-older-prefix
  (multiple-value-bind (node kv) (make-standalone-node :snapshot/restore t)
    (declare (ignore kv))
    (dotimes (i 5)
      (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command (list :set "x" i))))
    (setf (gr8s::raft-node-commit-index node) 5)
    (gr8s::raft-apply-committed node)
    (signals error (gr8s::raft-compact node 3))
    (is (= 0 (gr8s::raft-node-snapshot-index node)))
    (gr8s::raft-compact node 5)
    (is (= 5 (gr8s::raft-node-snapshot-index node)))
    (is (= 0 (fill-pointer (gr8s::raft-node-log node))))))
(test raft-catch-up-batches-are-bounded-and-cover-the-complete-log
  (let ((node (make-standalone-node)))
    (setf (gr8s.raft::raft-node-append-entry-limit node) 3
          (gr8s.raft::raft-node-append-byte-budget node) 10000)
    (dotimes (i 20)
      (gr8s::raft-log-append node
       (gr8s::make-raft-entry :term 1 :command (list :set "x" (make-string 100 :initial-element #\x)))))
    (let ((seen nil))
      (loop with next = 1 while (<= next 20) do
        (setf (gethash "peer" (gr8s::raft-node-next-index node)) next)
        (let* ((message (gr8s::raft-append-message node "peer"))
               (entries (getf message :entries)))
          (is (= (1- next) (getf message :prev-log-index)))
          (is (<= 1 (length entries) 3))
          (setf seen (append seen (mapcar #'gr8s::raft-entry-index entries)))
          (incf next (length entries))))
      (is (equal (loop for i from 1 to 20 collect i) seen)))
    ;; The byte budget independently limits batches below the entry-count limit.
    (setf (gethash "peer" (gr8s::raft-node-next-index node)) 1
          (gr8s.raft::raft-node-append-byte-budget node) 1200)
    (is (= 1 (length (getf (gr8s::raft-append-message node "peer") :entries))))
    ;; A single oversized entry makes progress without dragging its suffix along.
    (setf (gethash "peer" (gr8s::raft-node-next-index node)) 1
          (gr8s.raft::raft-node-append-byte-budget node) 1)
    (is (= 1 (length (getf (gr8s::raft-append-message node "peer") :entries))))))

(test raft-restoring-new-snapshot-releases-old-tail-and-ignores-stale-state
  (multiple-value-bind (node kv) (make-standalone-node :snapshot/restore t)
    (dotimes (i 5)
      (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command (list :set "x" i))))
    (gr8s::raft-restore-snapshot node 8 2 '(("x" . 80)))
    (is (= 80 (gethash "x" kv)))
    (is (= 8 (gr8s::raft-node-last-applied node)))
    (loop for i below 5 do (is (null (aref (gr8s::raft-node-log node) i))))
    (is (null (gr8s::raft-restore-snapshot node 7 1 '(("x" . 70)))))
    (is (= 80 (gethash "x" kv)))))
(test raft-partitioned-follower-catches-up-through-bounded-batches
  (let ((sim (three-node-sim)))
    (dolist (entry (rsim-nodes sim))
      (setf (gr8s.raft::raft-node-append-entry-limit (cdr entry)) 2))
    (rsim-run sim 8)
    (setf (rsim-groups sim) '(("a" "b") ("c")))
    (dotimes (i 50)
      (gr8s::raft-propose (rsim-node sim "a") (list :set "counter" i))
      (rsim-run sim 1))
    (is (= 49 (gethash "counter" (rsim-kv sim "a"))))
    (is (null (gethash "counter" (rsim-kv sim "c"))))
    (setf (rsim-groups sim) nil)
    (rsim-run sim 40)
    (dolist (id '("a" "b" "c"))
      (is (= 49 (gethash "counter" (rsim-kv sim id))))
      (is (= 50 (gr8s::raft-node-commit-index (rsim-node sim id)))))))
(test raft-failed-application-retries-before-advancing-or-calling-the-client
  (let ((attempts 0) (effects nil) (callbacks 0)
        (node (make-standalone-node)))
    (setf (gr8s::raft-node-apply-fn node)
          (lambda (command)
            (when (= 1 (incf attempts)) (error "Transient datastore failure"))
            (push command effects) :ok))
    (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command '(:set "x" 1)))
    (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command '(:set "x" 2)))
    (setf (gr8s::raft-node-commit-index node) 2
          (gethash 1 (gr8s::raft-node-pending node)) (lambda (result) (declare (ignore result)) (incf callbacks)))
    (signals error (gr8s::raft-apply-committed node))
    (is (= 0 (gr8s::raft-node-last-applied node)))
    (is (= 0 callbacks))
    (gr8s::raft-apply-committed node)
    (is (= 2 (gr8s::raft-node-last-applied node)))
    (is (= 3 attempts))
    (is (= 1 callbacks))
    (is (equal '((:set "x" 1) (:set "x" 2)) (reverse effects)))))

(test raft-failed-client-callback-does-not-repeat-an-applied-command
  (let ((effects 0) (node (make-standalone-node)))
    (setf (gr8s::raft-node-apply-fn node) (lambda (command) (declare (ignore command)) (incf effects)))
    (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command '(:set "x" 1)))
    (setf (gr8s::raft-node-commit-index node) 1
          (gethash 1 (gr8s::raft-node-pending node))
          (lambda (result) (declare (ignore result)) (error "Client disconnected")))
    (signals error (gr8s::raft-apply-committed node))
    (is (= 1 (gr8s::raft-node-last-applied node)))
    (gr8s::raft-apply-committed node)
    (is (= 1 effects))))
(in-suite gr8s)

(in-suite raft)

(defmethod gr8s.raft:raft-storage-save-hard-state ((storage failing-raft-storage) term vote)
  (declare (ignore term vote))
  (when (eq :hard (failing-raft-operation storage)) (error "Injected hard-state failure")))

(test raft-same-term-stepdown-retains-durable-vote
  (with-raft-temp-dir (path)
    (let* ((storage (gr8s::open-file-raft-storage path))
           (node (make-standalone-node :storage storage))
           (replies nil))
      (unwind-protect
           (progn
             (gr8s::raft-become-candidate node)
             ;; A standalone candidate elected itself; model a candidate still
             ;; waiting on its peers when another leader's heartbeat arrives.
             (setf (gr8s::raft-node-role node) :candidate
                   (gr8s::raft-node-send-fn node)
                   (lambda (to message) (declare (ignore to)) (push message replies)))
             (gr8s::raft-handle-message node
               (list :type :append-entries :from "leader" :term 1
                     :prev-log-index 0 :prev-log-term 0 :entries nil :leader-commit 0))
             (is (eq :follower (gr8s::raft-node-role node)))
             (is (equal "n1" (gr8s::raft-node-voted-for node)))
             (gr8s::raft-handle-message node
               (list :type :request-vote :from "other" :term 1 :last-log-index 0 :last-log-term 0))
             (is (not (getf (first replies) :granted)))
             (gr8s::close-file-raft-storage storage)
             (let ((recovered (gr8s::load-raft-log path)))
               (is (= 1 (gr8s::raft-recovered-term recovered)))
               (is (equal "n1" (gr8s::raft-recovered-vote recovered)))))
        (gr8s::close-file-raft-storage storage)))))

(test raft-hard-state-failure-does-not-publish-transitions-or-replies
  (let* ((storage (make-instance 'failing-raft-storage :operation :hard))
         (node (make-standalone-node :storage storage))
         (replies nil))
    (setf (gr8s::raft-node-current-term node) 3
          (gr8s::raft-node-voted-for node) "first"
          (gr8s::raft-node-send-fn node)
          (lambda (to message) (declare (ignore to)) (push message replies)))
    (signals error (gr8s::raft-become-candidate node))
    (is (= 3 (gr8s::raft-node-current-term node)))
    (is (equal "first" (gr8s::raft-node-voted-for node)))
    (is (eq :follower (gr8s::raft-node-role node)))
    (setf (gr8s::raft-node-role node) :leader)
    (signals error (gr8s::raft-become-follower node 4 "new-leader"))
    (is (= 3 (gr8s::raft-node-current-term node)))
    (is (equal "first" (gr8s::raft-node-voted-for node)))
    (is (eq :leader (gr8s::raft-node-role node)))
    (setf (gr8s::raft-node-role node) :follower
          (gr8s::raft-node-voted-for node) nil)
    (signals error
      (gr8s::raft-handle-message node
        (list :type :request-vote :from "other" :term 3 :last-log-index 0 :last-log-term 0)))
    (is (null (gr8s::raft-node-voted-for node)))
    (is (null replies))))

(test raft-higher-term-stepdown-clears-vote-only-after-persistence
  (let* ((storage (make-instance 'failing-raft-storage :operation nil))
         (node (make-standalone-node :storage storage)))
    (setf (gr8s::raft-node-current-term node) 4
          (gr8s::raft-node-voted-for node) "old")
    (gr8s::raft-become-follower node 5 "leader")
    (is (= 5 (gr8s::raft-node-current-term node)))
    (is (null (gr8s::raft-node-voted-for node)))
    (is (equal "leader" (gr8s::raft-node-leader-id node)))))

(defclass checkpoint-failing-raft-storage (gr8s.raft:file-raft-storage)
  ((phase :initarg :phase :accessor checkpoint-failure-phase)))

(defmethod gr8s.raft::file-raft-checkpoint-sync :before
    ((storage checkpoint-failing-raft-storage) phase fd)
  (declare (ignore fd))
  (when (eq phase (checkpoint-failure-phase storage))
    (error "Injected checkpoint ~A fsync failure" phase)))

(defun raft-wal-size (path)
  (with-open-file (stream path :element-type '(unsigned-byte 8)) (file-length stream)))

(test raft-file-checkpoints-reclaim-history-and-retain-exact-tail
  (with-raft-temp-dir (path)
    (let* ((storage (gr8s::open-file-raft-storage path))
           (node (make-standalone-node :storage storage :snapshot/restore t)))
      (unwind-protect
           (progn
             (setf (gr8s::raft-node-current-term node) 7 (gr8s::raft-node-voted-for node) "peer")
             (gr8s::raft-persist-hard-state node)
             (dotimes (round 5)
               (dotimes (i 20)
                 (gr8s::raft-log-append node
                   (gr8s::make-raft-entry :term 7 :command
                     (list :set "x" (list round i (make-string 8192 :initial-element #\x))))))
               (let* ((boundary (- (gr8s::raft-last-log-index node) 2))
                      (before (raft-wal-size path)))
                 (setf (gr8s::raft-node-commit-index node) boundary)
                 (gr8s::raft-apply-committed node)
                 (gr8s::raft-compact node boundary)
                 (is (< (raft-wal-size path) (/ before 3)))
                 (is (< (raft-wal-size path) 26000))
                 (let ((recovered (gr8s::load-raft-log path)))
                   (is (= 7 (gr8s::raft-recovered-term recovered)))
                   (is (equal "peer" (gr8s::raft-recovered-vote recovered)))
                   (is (= boundary (gr8s::raft-recovered-snapshot-index recovered)))
                   (is (equal (list (1+ boundary) (+ boundary 2))
                              (mapcar #'gr8s::raft-entry-index (gr8s::raft-recovered-entries recovered)))))))
             (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat path)))))
             ;; Exercise truncation and replacement after checkpointing; writes
             ;; must reach the renamed inode rather than the discarded stream.
             (gr8s::raft-log-truncate node 100)
             (gr8s::raft-log-append node (gr8s::make-raft-entry :term 8 :command '(:set "x" "replacement")))
             (gr8s::close-file-raft-storage storage)
             (multiple-value-bind (node2 kv2) (make-standalone-node :snapshot/restore t)
               (unwind-protect
                    (progn
                      (gr8s::recover-raft-node node2 path)
                      (is (= 98 (gr8s::raft-node-last-applied node2)))
                      (is (= 100 (gr8s::raft-last-log-index node2)))
                      (is (= 8 (gr8s::raft-log-term node2 100)))
                      (setf (gr8s::raft-node-commit-index node2) 100)
                      (gr8s::raft-apply-committed node2)
                      (is (equal "replacement" (gethash "x" kv2))))
                 (gr8s::close-file-raft-storage (gr8s::raft-node-storage node2)))))
        (gr8s::close-file-raft-storage storage)))))

(test raft-checkpoint-pre-rename-failure-keeps-old-wal-and-removes-temporary
  (with-raft-temp-dir (path)
    (let* ((storage (change-class (gr8s::open-file-raft-storage path)
                                  'checkpoint-failing-raft-storage :phase :file))
           (node (make-standalone-node :storage storage :snapshot/restore t)))
      (unwind-protect
           (progn
             (dotimes (i 5)
               (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command (list :set "x" i))))
             (setf (gr8s::raft-node-commit-index node) 3)
             (gr8s::raft-apply-committed node)
             (let ((before (uiop:read-file-string path)))
               (signals error (gr8s::raft-compact node 3))
               (is (equal before (uiop:read-file-string path))))
             (is (= 0 (gr8s::raft-node-snapshot-index node)))
             (is (= 5 (gr8s::raft-last-log-index node)))
             (is (null (directory (format nil "~A.checkpoint-*" path))))
             (setf (checkpoint-failure-phase storage) nil)
             (gr8s::raft-compact node 3)
             (is (= 3 (gr8s::raft-recovered-snapshot-index (gr8s::load-raft-log path)))))
        (gr8s::close-file-raft-storage storage)))))

(test raft-checkpoint-post-rename-failure-requires-recovery
  (with-raft-temp-dir (path)
    (let* ((storage (change-class (gr8s::open-file-raft-storage path)
                                  'checkpoint-failing-raft-storage :phase :directory))
           (node (make-standalone-node :storage storage :snapshot/restore t)))
      (unwind-protect
           (progn
             (dotimes (i 5)
               (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command (list :set "x" i))))
             (setf (gr8s::raft-node-commit-index node) 3)
             (gr8s::raft-apply-committed node)
             (signals error (gr8s::raft-compact node 3))
             (is (= 0 (gr8s::raft-node-snapshot-index node)))
             (is (= 5 (gr8s::raft-last-log-index node)))
             (is (null (gr8s::file-raft-storage-stream storage)))
             (let ((before (uiop:read-file-string path)))
               (signals error (gr8s.raft:raft-storage-save-hard-state storage 2 "other"))
               (signals error (gr8s::raft-compact node 3))
               (is (equal before (uiop:read-file-string path))))
             (is (null (directory (format nil "~A.checkpoint-*" path))))
             (multiple-value-bind (node2 kv2) (make-standalone-node :snapshot/restore t)
               (unwind-protect
                    (progn
                      (gr8s::recover-raft-node node2 path)
                      (is (= 3 (gr8s::raft-node-snapshot-index node2)))
                      (is (= 5 (gr8s::raft-last-log-index node2)))
                      (is (= 2 (gethash "x" kv2))))
                 (gr8s::close-file-raft-storage (gr8s::raft-node-storage node2)))))
        (gr8s::close-file-raft-storage storage)))))

(test raft-checkpoint-unreadable-state-does-not-replace-valid-wal
  (with-raft-temp-dir (path)
    (let* ((storage (gr8s::open-file-raft-storage path))
           (node (make-standalone-node :storage storage)))
      (unwind-protect
           (progn
             (gr8s::raft-log-append node (gr8s::make-raft-entry :term 1 :command '(:set "x" 1)))
             (setf (gr8s::raft-node-commit-index node) 1
                   (gr8s::raft-node-last-applied node) 1
                   (gr8s::raft-node-snapshot-fn node) (lambda () (make-hash-table)))
             (let ((before (uiop:read-file-string path)))
               (signals print-not-readable (gr8s::raft-compact node 1))
               (is (equal before (uiop:read-file-string path))))
             (is (= 0 (gr8s::raft-node-snapshot-index node)))
             (is (null (directory (format nil "~A.checkpoint-*" path))))
             (gr8s.raft:raft-storage-save-hard-state storage 2 "peer")
             (is (= 2 (gr8s::raft-recovered-term (gr8s::load-raft-log path)))))
        (gr8s::close-file-raft-storage storage)))))

(defvar *raft-wal-reader-evaluated* nil)

(test raft-wal-recovery-never-evaluates-reader-forms
  (with-raft-temp-dir (path)
    (ensure-directories-exist path)
    (with-open-file (stream path :direction :output :if-does-not-exist :create)
      (write-string "#.(progn (setf gr8s/tests::*raft-wal-reader-evaluated* t) '(:hard 1 nil))" stream))
    (let ((*raft-wal-reader-evaluated* nil) (*read-eval* t))
      (signals reader-error (gr8s::load-raft-log path))
      (is (null *raft-wal-reader-evaluated*)))))

(in-suite gr8s)
