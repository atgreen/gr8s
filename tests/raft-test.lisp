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
               (cl-raft::raft-handle-message (rsim-node sim to) msg)))))

(defun rsim-tick (sim)
  (dolist (entry (rsim-nodes sim)) (cl-raft::raft-tick (cdr entry)))
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
             (node (cl-raft::make-raft-node
                    :id id :peers (remove id ids :test #'equal)
                    :heartbeat-timeout 1
                    :timeout-fn (let ((v to)) (lambda () v))
                    :send-fn (lambda (dest message)
                               (setf (rsim-queue sim)
                                     (nconc (rsim-queue sim) (list (cons dest message)))))
                    :apply-fn (funcall apply-maker state))))
        (cl-raft::raft-reset-election-timer node)
        (push (cons id node) (rsim-nodes sim))
        (push (cons id state) (rsim-kvs sim))))
    sim))

(defun rsim-leaders (sim)
  (loop for (id . node) in (rsim-nodes sim)
        when (cl-raft::raft-leader-p node) collect id))

(defun three-node-sim ()
  (make-rsim '("a" "b" "c") '(("a" . 3) ("b" . 5) ("c" . 7))))

(test raft-elects-a-single-leader
  (let ((sim (three-node-sim)))
    (rsim-run sim 8)
    (is (equal '("a") (rsim-leaders sim)))                       ; lowest timeout wins, exactly one
    (let ((terms (loop for (id . n) in (rsim-nodes sim) collect (cl-raft::raft-node-current-term n))))
      (is (apply #'= terms))                                     ; all on the same term
      (is (plusp (first terms))))
    (dolist (id '("b" "c"))
      (is (equal "a" (cl-raft::raft-node-leader-id (rsim-node sim id)))))))

(test raft-replicates-and-applies
  (let ((sim (three-node-sim)))
    (rsim-run sim 8)
    (cl-raft::raft-propose (rsim-node sim "a") '(:set "x" 1))
    (cl-raft::raft-propose (rsim-node sim "a") '(:set "x" 2))
    (rsim-run sim 6)
    (dolist (id '("a" "b" "c"))
      (is (= 2 (gethash "x" (rsim-kv sim id))) "node ~A has x=2" id)
      ;; Commit index covers the leader's election barrier plus both proposals.
      (is (= 3 (cl-raft::raft-node-commit-index (rsim-node sim id)))))))

(test raft-linearizable-compare-and-swap
  (let ((sim (three-node-sim)) (r1 nil) (r2 nil))
    (rsim-run sim 8)
    (cl-raft::raft-propose (rsim-node sim "a") '(:cas "y" nil "A") (lambda (r) (setf r1 r)))
    (cl-raft::raft-propose (rsim-node sim "a") '(:cas "y" nil "B") (lambda (r) (setf r2 r)))
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
    (cl-raft::raft-propose (rsim-node sim "a") '(:set "k" "v1"))
    (rsim-run sim 6)
    (dolist (id '("a" "b" "c")) (is (equal "v1" (gethash "k" (rsim-kv sim id)))))
    ;; Partition a away from the majority {b,c}.
    (setf (rsim-groups sim) '(("a") ("b" "c")))
    ;; a is now a minority leader: a proposal here must NOT commit.
    (cl-raft::raft-propose (rsim-node sim "a") '(:set "k" "vX") (lambda (r) (setf minority-cb r)))
    (rsim-run sim 10)
    (is (null minority-cb) "minority leader must not commit")
    ;; The majority side elects a new leader and makes progress.
    (let ((new-leaders (remove "a" (rsim-leaders sim) :test #'equal)))
      (is (= 1 (length new-leaders)))
      (let ((b (rsim-node sim (first new-leaders))))
        (cl-raft::raft-propose b '(:set "k" "v2"))
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
    (let ((terms (loop for (id . n) in (rsim-nodes sim) collect (cl-raft::raft-node-current-term n))))
      (is (apply #'= terms) "all members on one term after heal"))))

;;; ---------------------------------------------------------------------------
;;; Durability + compaction (podster-c2d.2).

(defun make-standalone-node (&key kv storage snapshot/restore)
  "A single raft-node with a no-op transport and a KV state machine."
  (let ((kv (or kv (make-hash-table :test 'equal))))
    (values
     (cl-raft::make-raft-node
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
    (dotimes (i 5) (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command (list :set "x" i))))
    (setf (cl-raft::raft-node-commit-index node) 5)
    (is (= 5 (cl-raft::raft-last-log-index node)))
    (cl-raft::raft-compact node 3)
    (is (= 3 (cl-raft::raft-node-snapshot-index node)))
    (is (= 1 (cl-raft::raft-node-snapshot-term node)))
    (is (= 5 (cl-raft::raft-last-log-index node)))            ; absolute length unchanged by compaction
    (is (null (cl-raft::raft-log-entry node 2)))              ; compacted away
    (is (null (cl-raft::raft-log-entry node 3)))              ; == snapshot boundary
    (is (= 1 (cl-raft::raft-log-term node 3)))                ; term still answerable at the boundary
    (let ((e4 (cl-raft::raft-log-entry node 4)))
      (is (not (null e4)))                                 ; tail intact
      (is (= 4 (cl-raft::raft-entry-index e4))))))

(test raft-crash-recovery-restores-hard-state-and-log
  (with-raft-temp-dir (path)
    ;; Write a WAL: hard state + three log entries, then "crash" (close).
    (multiple-value-bind (node kv) (make-standalone-node :storage (cl-raft::open-file-raft-storage path))
      (declare (ignore kv))
      (setf (cl-raft::raft-node-current-term node) 7 (cl-raft::raft-node-voted-for node) "peer-b")
      (cl-raft::raft-persist-hard-state node)
      (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 7 :command '(:set "a" 1)))
      (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 7 :command '(:set "b" 2)))
      (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 7 :command '(:set "a" 3)))
      (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage node)))
    ;; Recover a fresh node from the same WAL.
    (let ((node2 (make-standalone-node)))
      (cl-raft::recover-raft-node node2 path)
      (is (= 7 (cl-raft::raft-node-current-term node2)))
      (is (equal "peer-b" (cl-raft::raft-node-voted-for node2)))
      (is (= 3 (cl-raft::raft-last-log-index node2)))
      (is (equal '(:set "a" 3) (cl-raft::raft-entry-command (cl-raft::raft-log-entry node2 3))))
      (is (= 7 (cl-raft::raft-log-term node2 2)))
      (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage node2)))))

(test raft-recovery-restores-snapshot-state
  (with-raft-temp-dir (path)
    (multiple-value-bind (node kv) (make-standalone-node :storage (cl-raft::open-file-raft-storage path)
                                                         :snapshot/restore t)
      (dotimes (i 5) (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 2 :command (list :set "x" i))))
      (setf (cl-raft::raft-node-commit-index node) 3)
      (cl-raft::raft-apply-committed node)                    ; only the prefix through entry 3 is applied
      (is (= 2 (gethash "x" kv)))
      (cl-raft::raft-compact node 3)                          ; persists snapshot image of kv
      (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage node)))
    ;; Recover: snapshot image restores the state machine; the tail survives.
    (multiple-value-bind (node2 kv2) (make-standalone-node :snapshot/restore t)
      (cl-raft::recover-raft-node node2 path)
      (is (= 2 (gethash "x" kv2)) "state machine restored from snapshot")
      (is (= 3 (cl-raft::raft-node-snapshot-index node2)))
      (is (= 5 (cl-raft::raft-last-log-index node2)))         ; entries 4,5 survived compaction
      (is (not (null (cl-raft::raft-log-entry node2 4))))
      (is (= 3 (cl-raft::raft-node-last-applied node2)))      ; applied up to the snapshot boundary
      (setf (cl-raft::raft-node-commit-index node2) 5)
      (cl-raft::raft-apply-committed node2)
      (is (= 4 (gethash "x" kv2)) "tail is applied once after the exact prefix snapshot")
      (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage node2)))))

(test raft-single-node-self-elects
  (let ((sim (make-rsim '("solo") '(("solo" . 3)))))
    (rsim-run sim 4)
    (is (cl-raft::raft-leader-p (rsim-node sim "solo")))
    (cl-raft::raft-propose (rsim-node sim "solo") '(:set "z" 9))
    (rsim-run sim 1)
    (is (= 9 (gethash "z" (rsim-kv sim "solo"))))))

(in-suite raft)
(defclass failing-raft-storage ()
  ((operation :initarg :operation :accessor failing-raft-operation)))
(defmethod gr8s.raft::raft-storage-append-entry ((storage failing-raft-storage) entry)
  (declare (ignore entry))
  (when (eq :append (failing-raft-operation storage)) (error "Injected append failure")))
(defmethod gr8s.raft::raft-storage-truncate ((storage failing-raft-storage) index)
  (declare (ignore index))
  (when (eq :truncate (failing-raft-operation storage)) (error "Injected truncate failure")))
(defmethod gr8s.raft::raft-storage-save-snapshot ((storage failing-raft-storage) index term state)
  (declare (ignore index term state))
  (when (eq :snapshot (failing-raft-operation storage)) (error "Injected snapshot failure")))

(test raft-failed-storage-keeps-log-and-compaction-boundary
  (let* ((storage (make-instance 'failing-raft-storage :operation nil))
         (node (make-standalone-node :storage storage)))
    (dotimes (i 5)
      (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command (list :set "x" i))))
    (setf (failing-raft-operation storage) :append)
    (signals error (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command '(:set "x" 99))))
    (is (= 5 (cl-raft::raft-last-log-index node)))
    (setf (failing-raft-operation storage) :truncate)
    (signals error (cl-raft::raft-log-truncate node 4))
    (is (= 5 (cl-raft::raft-last-log-index node)))
    (is (equal '(:set "x" 4) (cl-raft::raft-entry-command (cl-raft::raft-log-entry node 5))))
    (setf (failing-raft-operation storage) :snapshot
          (cl-raft::raft-node-commit-index node) 3)
    (signals error (cl-raft::raft-compact node 3))
    (is (= 0 (cl-raft::raft-node-snapshot-index node)))
    (is (= 5 (cl-raft::raft-last-log-index node)))
    (is (equal '(:set "x" 0) (cl-raft::raft-entry-command (cl-raft::raft-log-entry node 1))))))

(test raft-truncation-and-compaction-release-backing-array-references
  (let ((node (make-standalone-node)))
    (dotimes (i 8)
      (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command (list :set "x" i))))
    (cl-raft::raft-log-truncate node 6)
    (let ((log (cl-raft::raft-node-log node)))
      (loop for i from 5 below 8 do (is (null (aref log i)))))
    (setf (cl-raft::raft-node-commit-index node) 3)
    (cl-raft::raft-compact node 3)
    (is (= 2 (fill-pointer (cl-raft::raft-node-log node))))
    (is (= 4 (cl-raft::raft-entry-index (cl-raft::raft-log-entry node 4))))
    (let ((log (cl-raft::raft-node-log node)))
      (loop for i from 2 below 8 do (is (null (aref log i)))))
    (signals error (cl-raft::raft-log-truncate node 3))))

(test raft-snapshot-refuses-to-label-current-state-as-an-older-prefix
  (multiple-value-bind (node kv) (make-standalone-node :snapshot/restore t)
    (declare (ignore kv))
    (dotimes (i 5)
      (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command (list :set "x" i))))
    (setf (cl-raft::raft-node-commit-index node) 5)
    (cl-raft::raft-apply-committed node)
    (signals error (cl-raft::raft-compact node 3))
    (is (= 0 (cl-raft::raft-node-snapshot-index node)))
    (cl-raft::raft-compact node 5)
    (is (= 5 (cl-raft::raft-node-snapshot-index node)))
    (is (= 0 (fill-pointer (cl-raft::raft-node-log node))))))
(test raft-catch-up-batches-are-bounded-and-cover-the-complete-log
  (let ((node (make-standalone-node)))
    (setf (gr8s.raft::raft-node-append-entry-limit node) 3
          (gr8s.raft::raft-node-append-byte-budget node) 10000)
    (dotimes (i 20)
      (cl-raft::raft-log-append node
       (cl-raft::make-raft-entry :term 1 :command (list :set "x" (make-string 100 :initial-element #\x)))))
    (let ((seen nil))
      (loop with next = 1 while (<= next 20) do
        (setf (gethash "peer" (cl-raft::raft-node-next-index node)) next)
        (let* ((message (cl-raft::raft-append-message node "peer"))
               (entries (getf message :entries)))
          (is (= (1- next) (getf message :prev-log-index)))
          (is (<= 1 (length entries) 3))
          (setf seen (append seen (mapcar #'cl-raft::raft-entry-index entries)))
          (incf next (length entries))))
      (is (equal (loop for i from 1 to 20 collect i) seen)))
    ;; The byte budget independently limits batches below the entry-count limit.
    (setf (gethash "peer" (cl-raft::raft-node-next-index node)) 1
          (gr8s.raft::raft-node-append-byte-budget node) 1200)
    (is (= 1 (length (getf (cl-raft::raft-append-message node "peer") :entries))))
    ;; A single oversized entry makes progress without dragging its suffix along.
    (setf (gethash "peer" (cl-raft::raft-node-next-index node)) 1
          (gr8s.raft::raft-node-append-byte-budget node) 1)
    (is (= 1 (length (getf (cl-raft::raft-append-message node "peer") :entries))))))

(test raft-restoring-new-snapshot-releases-old-tail-and-ignores-stale-state
  (multiple-value-bind (node kv) (make-standalone-node :snapshot/restore t)
    (dotimes (i 5)
      (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command (list :set "x" i))))
    (cl-raft::raft-restore-snapshot node 8 2 '(("x" . 80)))
    (is (= 80 (gethash "x" kv)))
    (is (= 8 (cl-raft::raft-node-last-applied node)))
    (loop for i below 5 do (is (null (aref (cl-raft::raft-node-log node) i))))
    (is (null (cl-raft::raft-restore-snapshot node 7 1 '(("x" . 70)))))
    (is (= 80 (gethash "x" kv)))))
(test raft-partitioned-follower-catches-up-through-bounded-batches
  (let ((sim (three-node-sim)))
    (dolist (entry (rsim-nodes sim))
      (setf (gr8s.raft::raft-node-append-entry-limit (cdr entry)) 2))
    (rsim-run sim 8)
    (setf (rsim-groups sim) '(("a" "b") ("c")))
    (dotimes (i 50)
      (cl-raft::raft-propose (rsim-node sim "a") (list :set "counter" i))
      (rsim-run sim 1))
    (is (= 49 (gethash "counter" (rsim-kv sim "a"))))
    (is (null (gethash "counter" (rsim-kv sim "c"))))
    (setf (rsim-groups sim) nil)
    (rsim-run sim 40)
    (dolist (id '("a" "b" "c"))
      (is (= 49 (gethash "counter" (rsim-kv sim id))))
      ;; Commit index covers the leader's election barrier plus all 50 proposals.
      (is (= 51 (cl-raft::raft-node-commit-index (rsim-node sim id)))))))
(test raft-failed-application-retries-before-advancing-or-calling-the-client
  (let ((attempts 0) (effects nil) (callbacks 0)
        (node (make-standalone-node)))
    (setf (cl-raft::raft-node-apply-fn node)
          (lambda (command)
            (when (= 1 (incf attempts)) (error "Transient datastore failure"))
            (push command effects) :ok))
    (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command '(:set "x" 1)))
    (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command '(:set "x" 2)))
    (setf (cl-raft::raft-node-commit-index node) 2
          ;; Pending callbacks are keyed (term . callback) so a stale entry replaced
          ;; at the same index is dropped rather than resolved; entry 1 has term 1.
          (gethash 1 (cl-raft::raft-node-pending node)) (cons 1 (lambda (result) (declare (ignore result)) (incf callbacks))))
    (signals error (cl-raft::raft-apply-committed node))
    (is (= 0 (cl-raft::raft-node-last-applied node)))
    (is (= 0 callbacks))
    (cl-raft::raft-apply-committed node)
    (is (= 2 (cl-raft::raft-node-last-applied node)))
    (is (= 3 attempts))
    (is (= 1 callbacks))
    (is (equal '((:set "x" 1) (:set "x" 2)) (reverse effects)))))

(test raft-failed-client-callback-does-not-repeat-an-applied-command
  (let ((effects 0) (node (make-standalone-node)))
    (setf (cl-raft::raft-node-apply-fn node) (lambda (command) (declare (ignore command)) (incf effects)))
    (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command '(:set "x" 1)))
    (setf (cl-raft::raft-node-commit-index node) 1
          (gethash 1 (cl-raft::raft-node-pending node))
          (lambda (result) (declare (ignore result)) (error "Client disconnected")))
    (signals error (cl-raft::raft-apply-committed node))
    (is (= 1 (cl-raft::raft-node-last-applied node)))
    (cl-raft::raft-apply-committed node)
    (is (= 1 effects))))
(test uncommitted-admission-starts-at-the-commit-offset-after-compaction
  (let* ((command (list :set "key" (make-string 500 :initial-element #\x)))
         (node (cl-raft::make-raft-node :id "a" :peers '("b" "c") :role :leader :current-term 1
                 :snapshot-index 100 :snapshot-term 1 :commit-index 101 :last-applied 101
                 :uncommitted-byte-limit 4096
                 :log (make-array 2 :adjustable t :fill-pointer 2
                         :initial-contents (list (cl-raft::make-raft-entry :index 101 :term 1 :command command)
                                                 (cl-raft::make-raft-entry :index 102 :term 1 :command command)))
                 :send-fn (lambda (&rest args) (declare (ignore args))))))
    (is (eq :capacity (nth-value 2 (cl-raft::raft-propose node command))))
    (setf (cl-raft::raft-node-commit-index node) 102 (cl-raft::raft-node-last-applied node) 102)
    (is-true (nth-value 1 (cl-raft::raft-propose node command)))
    (is (eq :capacity (nth-value 2 (cl-raft::raft-propose node command))))))

(test retained-byte-admission-counts-committed-prefix-and-recovers-after-compaction
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((path (merge-pathnames "retained.log" root))
           (storage (cl-raft::open-file-raft-storage path))
           (node (gr8s.raft::make-raft-node :id "retained" :role :leader :current-term 1 :storage storage
                   :uncommitted-byte-limit 4096 :retained-byte-limit 512
                   :uncommitted-weight-fn (constantly 128)))
           (callback nil))
      (unwind-protect
           (progn
             (is-true (nth-value 1 (gr8s.raft::raft-propose node '(:first))))
             (is-true (nth-value 1 (gr8s.raft::raft-propose node '(:second))))
             (is (= 2 (gr8s.raft::raft-node-commit-index node)))
             (let ((before (length (gr8s.raft::raft-node-log node)))
                   (bytes (sb-posix:stat-size (sb-posix:stat path))))
               (is (eq :capacity (nth-value 2 (gr8s.raft::raft-propose node '(:third)
                                              (lambda (value) (declare (ignore value)) (setf callback t))))))
               (is (= before (length (gr8s.raft::raft-node-log node))))
               (is (= bytes (sb-posix:stat-size (sb-posix:stat path))))
               (is (null callback))
               (is (zerop (hash-table-count (gr8s.raft::raft-node-pending node)))))
             (is-true (nth-value 1 (gr8s.raft::raft-propose node '(:raft-barrier))))
             (gr8s.raft::raft-compact node (gr8s.raft::raft-node-last-applied node))
             (is-true (nth-value 1 (gr8s.raft::raft-propose node '(:third))))
             (is (= 4 (gr8s.raft::raft-node-commit-index node))))
        (cl-raft::close-file-raft-storage storage)))))

(test replicated-retention-refusal-commits-certified-prefix-and-retries-after-compaction
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((path (merge-pathnames "follower-retained.log" root))
           (storage (cl-raft::open-file-raft-storage path))
           (replies nil)
           (node (gr8s.raft::make-raft-node
                  :id "follower" :current-term 1 :storage storage :retained-byte-limit 512
                  :uncommitted-weight-fn (constantly 128)
                  :send-fn (lambda (target message) (declare (ignore target)) (push message replies)))))
      (flet ((send (previous entries committed)
               (gr8s.raft::raft-handle-append-entries
                node (list :term 1 :from "leader" :prev-log-index previous
                           :prev-log-term (if (zerop previous) 0 1)
                           :leader-commit committed :entries entries)))
             (entry (command) (gr8s.raft::make-raft-entry :term 1 :command command)))
        (unwind-protect
             (progn
               (cl-raft::raft-persist-hard-state node)
               (send 0 (list (entry '(:first)) (entry '(:second))) 0)
               (is (getf (first replies) :success))
               (is (= 2 (length (gr8s.raft::raft-node-log node))))
               (is (zerop (gr8s.raft::raft-node-commit-index node)))
               (send 2 (list (entry '(:third))) 2)
               (is (not (getf (first replies) :success)))
               (is (= 3 (getf (first replies) :next-index)))
               (is (= 2 (gr8s.raft::raft-node-commit-index node)))
               (is (= 2 (gr8s.raft::raft-node-last-applied node)))
               (is (= 2 (length (gr8s.raft::raft-node-log node))))
               (let ((durable (gr8s.raft::load-raft-log path)))
                 (is (= 2 (gr8s.raft::raft-recovered-commit-index durable)))
                 (is (= 2 (length (gr8s.raft::raft-recovered-entries durable)))))
               (let ((bytes (sb-posix:stat-size (sb-posix:stat path))))
                 (send 2 (list (entry '(:third))) 3)
                 (is (= bytes (sb-posix:stat-size (sb-posix:stat path)))))
               (gr8s.raft::raft-compact node 2)
               (send 2 (list (entry '(:third))) 3)
               (is (getf (first replies) :success))
               (is (= 3 (gr8s.raft::raft-node-commit-index node)))
               ;; Matching retransmissions do not consume the budget twice.
               (setf (gr8s.raft::raft-node-retained-byte-limit node) 1)
               (send 2 (list (entry '(:third))) 3)
               (is (getf (first replies) :success))
               (is (= 1 (length (gr8s.raft::raft-node-log node))))
               ;; Recovery traffic may establish a commit even over budget.
               (send 3 (list (entry '(:raft-barrier))) 4)
               (is (getf (first replies) :success))
               (is (= 4 (gr8s.raft::raft-node-last-applied node))))
          (cl-raft::close-file-raft-storage storage))))))

(test replicated-retention-replacement-reuses-uncommitted-tail-budget
  (let ((node (gr8s.raft::make-raft-node :id "follower" :current-term 1
                :retained-byte-limit 512 :uncommitted-weight-fn (constantly 128)
                :send-fn (lambda (&rest arguments) (declare (ignore arguments))))))
    (gr8s.raft::raft-handle-append-entries
     node (list :term 1 :from "leader" :prev-log-index 0 :prev-log-term 0 :leader-commit 0
                :entries (list (gr8s.raft::make-raft-entry :term 1 :command '(:first))
                               (gr8s.raft::make-raft-entry :term 1 :command '(:old-tail)))))
    (gr8s.raft::raft-handle-append-entries
     node (list :term 2 :from "new-leader" :prev-log-index 1 :prev-log-term 1 :leader-commit 1
                :entries (list (gr8s.raft::make-raft-entry :term 2 :command '(:replacement)))))
    (is (= 2 (length (gr8s.raft::raft-node-log node))))
    (is (= 2 (gr8s.raft::raft-log-term node 2)))
    (is (= 1 (gr8s.raft::raft-node-commit-index node)))
    (signals error
      (gr8s.raft::raft-handle-append-entries
       node (list :term 3 :from "bad-leader" :prev-log-index 0 :prev-log-term 0 :leader-commit 2
                  :entries (list (gr8s.raft::make-raft-entry :term 3 :command '(:overwrite))))))
    (is (= 1 (gr8s.raft::raft-log-term node 1)))))

(test uncommitted-byte-admission-rejects-before-persisting-and-recovers-after-commit
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((path (merge-pathnames "admission.log" root))
           (storage (cl-raft::open-file-raft-storage path))
           (callbacks 0)
           (node (cl-raft::make-raft-node :id "a" :peers '("b" "c") :role :leader
                   :current-term 1 :storage storage :send-fn (lambda (&rest args) (declare (ignore args)))
                   :apply-fn (lambda (command) (declare (ignore command)) :applied)
                   :uncommitted-byte-limit 4096))
           (command (list :set "key" (make-string 500 :initial-element #\x))))
      (unwind-protect
           (progn
             (is-true (nth-value 1 (cl-raft::raft-propose node command (lambda (value)
                                                                   (declare (ignore value))
                                                                   (incf callbacks)))))
             (let ((bytes (sb-posix:stat-size (sb-posix:stat path))))
               (dotimes (i 200)
                 (multiple-value-bind (index accepted reason)
                     (cl-raft::raft-propose node command (lambda (value) (declare (ignore value)) (incf callbacks)))
                   (is (null index)) (is (null accepted)) (is (eq :capacity reason))))
               (is (= bytes (sb-posix:stat-size (sb-posix:stat path)))))
             (is (= 1 (cl-raft::raft-last-log-index node)))
             (is (= 1 (hash-table-count (gr8s.raft::raft-node-pending node))))
             (is (zerop callbacks))
             (is (eq :proposal-too-large
                     (nth-value 2 (cl-raft::raft-propose node (list :set "key" (make-string 2000))))))
             ;; The full application budget must not prevent protocol recovery.
             ;; A recovered legacy tail can exceed the configured budget.
             (setf (gr8s.raft::raft-node-uncommitted-byte-limit node) 1)
             (is-true (nth-value 1 (cl-raft::raft-propose-config node :add "d" :role :learner)))
             (is-true (nth-value 1 (cl-raft::raft-propose node '(:raft-barrier))))
             (is-true (nth-value 1 (cl-raft::raft-propose node '(:store-recovery-barrier))))
             (setf (gethash "b" (cl-raft::raft-node-match-index node)) (cl-raft::raft-last-log-index node))
             (cl-raft::raft-advance-commit node)
             (cl-raft::raft-apply-committed node)
             (is (= 1 callbacks))
             (is (zerop (hash-table-count (gr8s.raft::raft-node-pending node))))
             ;; Committed entries still in the log do not consume admission.
             (setf (gr8s.raft::raft-node-uncommitted-byte-limit node) 4096)
             (is-true (nth-value 1 (cl-raft::raft-propose node command))))
        (cl-raft::close-file-raft-storage storage)))))

(in-suite gr8s)

(in-suite raft)

(defmethod gr8s.raft::raft-storage-save-hard-state ((storage failing-raft-storage) term vote)
  (declare (ignore term vote))
  (when (eq :hard (failing-raft-operation storage)) (error "Injected hard-state failure")))

(test raft-same-term-stepdown-retains-durable-vote
  (with-raft-temp-dir (path)
    (let* ((storage (cl-raft::open-file-raft-storage path))
           (node (make-standalone-node :storage storage))
           (replies nil))
      (unwind-protect
           (progn
             (cl-raft::raft-become-candidate node)
             ;; A standalone candidate elected itself; model a candidate still
             ;; waiting on its peers when another leader's heartbeat arrives.
             (setf (cl-raft::raft-node-role node) :candidate
                   (cl-raft::raft-node-send-fn node)
                   (lambda (to message) (declare (ignore to)) (push message replies)))
             (cl-raft::raft-handle-message node
               (list :type :append-entries :from "leader" :term 1
                     :prev-log-index 0 :prev-log-term 0 :entries nil :leader-commit 0))
             (is (eq :follower (cl-raft::raft-node-role node)))
             (is (equal "n1" (cl-raft::raft-node-voted-for node)))
             (cl-raft::raft-handle-message node
               (list :type :request-vote :from "other" :term 1 :last-log-index 0 :last-log-term 0))
             (is (not (getf (first replies) :granted)))
             (cl-raft::close-file-raft-storage storage)
             (let ((recovered (cl-raft::load-raft-log path)))
               (is (= 1 (cl-raft::raft-recovered-term recovered)))
               (is (equal "n1" (cl-raft::raft-recovered-vote recovered)))))
        (cl-raft::close-file-raft-storage storage)))))

(test raft-hard-state-failure-does-not-publish-transitions-or-replies
  (let* ((storage (make-instance 'failing-raft-storage :operation :hard))
         (node (make-standalone-node :storage storage))
         (replies nil))
    (setf (cl-raft::raft-node-current-term node) 3
          (cl-raft::raft-node-voted-for node) "first"
          (cl-raft::raft-node-send-fn node)
          (lambda (to message) (declare (ignore to)) (push message replies)))
    (signals error (cl-raft::raft-become-candidate node))
    (is (= 3 (cl-raft::raft-node-current-term node)))
    (is (equal "first" (cl-raft::raft-node-voted-for node)))
    (is (eq :follower (cl-raft::raft-node-role node)))
    (setf (cl-raft::raft-node-role node) :leader)
    (signals error (cl-raft::raft-become-follower node 4 "new-leader"))
    (is (= 3 (cl-raft::raft-node-current-term node)))
    (is (equal "first" (cl-raft::raft-node-voted-for node)))
    (is (eq :leader (cl-raft::raft-node-role node)))
    (setf (cl-raft::raft-node-role node) :follower
          (cl-raft::raft-node-voted-for node) nil)
    (signals error
      (cl-raft::raft-handle-message node
        (list :type :request-vote :from "other" :term 3 :last-log-index 0 :last-log-term 0)))
    (is (null (cl-raft::raft-node-voted-for node)))
    (is (null replies))))

(test raft-higher-term-stepdown-clears-vote-only-after-persistence
  (let* ((storage (make-instance 'failing-raft-storage :operation nil))
         (node (make-standalone-node :storage storage)))
    (setf (cl-raft::raft-node-current-term node) 4
          (cl-raft::raft-node-voted-for node) "old")
    (cl-raft::raft-become-follower node 5 "leader")
    (is (= 5 (cl-raft::raft-node-current-term node)))
    (is (null (cl-raft::raft-node-voted-for node)))
    (is (equal "leader" (cl-raft::raft-node-leader-id node)))))

(defclass checkpoint-failing-raft-storage (gr8s.raft::file-raft-storage)
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
    (let* ((storage (cl-raft::open-file-raft-storage path))
           (node (make-standalone-node :storage storage :snapshot/restore t)))
      (unwind-protect
           (progn
             (setf (cl-raft::raft-node-current-term node) 7 (cl-raft::raft-node-voted-for node) "peer")
             (cl-raft::raft-persist-hard-state node)
             (dotimes (round 5)
               (dotimes (i 20)
                 (cl-raft::raft-log-append node
                   (cl-raft::make-raft-entry :term 7 :command
                     (list :set "x" (list round i (make-string 8192 :initial-element #\x))))))
               (let* ((boundary (- (cl-raft::raft-last-log-index node) 2))
                      (before (raft-wal-size path)))
                 (setf (cl-raft::raft-node-commit-index node) boundary)
                 (cl-raft::raft-apply-committed node)
                 (cl-raft::raft-compact node boundary)
                 (is (< (raft-wal-size path) (/ before 3)))
                 (is (< (raft-wal-size path) 26000))
                 (let ((recovered (cl-raft::load-raft-log path)))
                   (is (= 7 (cl-raft::raft-recovered-term recovered)))
                   (is (equal "peer" (cl-raft::raft-recovered-vote recovered)))
                   (is (= boundary (cl-raft::raft-recovered-snapshot-index recovered)))
                   (is (equal (list (1+ boundary) (+ boundary 2))
                              (mapcar #'cl-raft::raft-entry-index (cl-raft::raft-recovered-entries recovered)))))))
             (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat path)))))
             ;; Exercise truncation and replacement after checkpointing; writes
             ;; must reach the renamed inode rather than the discarded stream.
             (cl-raft::raft-log-truncate node 100)
             (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 8 :command '(:set "x" "replacement")))
             (cl-raft::close-file-raft-storage storage)
             (multiple-value-bind (node2 kv2) (make-standalone-node :snapshot/restore t)
               (unwind-protect
                    (progn
                      (cl-raft::recover-raft-node node2 path)
                      (is (= 98 (cl-raft::raft-node-last-applied node2)))
                      (is (= 100 (cl-raft::raft-last-log-index node2)))
                      (is (= 8 (cl-raft::raft-log-term node2 100)))
                      (setf (cl-raft::raft-node-commit-index node2) 100)
                      (cl-raft::raft-apply-committed node2)
                      (is (equal "replacement" (gethash "x" kv2))))
                 (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage node2)))))
        (cl-raft::close-file-raft-storage storage)))))

(test raft-checkpoint-pre-rename-failure-keeps-old-wal-and-removes-temporary
  (with-raft-temp-dir (path)
    (let* ((storage (change-class (cl-raft::open-file-raft-storage path)
                                  'checkpoint-failing-raft-storage :phase :file))
           (node (make-standalone-node :storage storage :snapshot/restore t)))
      (unwind-protect
           (progn
             (dotimes (i 5)
               (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command (list :set "x" i))))
             (setf (cl-raft::raft-node-commit-index node) 3)
             (cl-raft::raft-apply-committed node)
             (let ((before (uiop:read-file-string path)))
               (signals error (cl-raft::raft-compact node 3))
               (is (equal before (uiop:read-file-string path))))
             (is (= 0 (cl-raft::raft-node-snapshot-index node)))
             (is (= 5 (cl-raft::raft-last-log-index node)))
             (is (null (directory (format nil "~A.checkpoint-*" path))))
             (setf (checkpoint-failure-phase storage) nil)
             (cl-raft::raft-compact node 3)
             (is (= 3 (cl-raft::raft-recovered-snapshot-index (cl-raft::load-raft-log path)))))
        (cl-raft::close-file-raft-storage storage)))))

(test raft-checkpoint-post-rename-failure-requires-recovery
  (with-raft-temp-dir (path)
    (let* ((storage (change-class (cl-raft::open-file-raft-storage path)
                                  'checkpoint-failing-raft-storage :phase :directory))
           (node (make-standalone-node :storage storage :snapshot/restore t)))
      (unwind-protect
           (progn
             (dotimes (i 5)
               (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command (list :set "x" i))))
             (setf (cl-raft::raft-node-commit-index node) 3)
             (cl-raft::raft-apply-committed node)
             (signals error (cl-raft::raft-compact node 3))
             (is (= 0 (cl-raft::raft-node-snapshot-index node)))
             (is (= 5 (cl-raft::raft-last-log-index node)))
             (is (null (cl-raft::file-raft-storage-stream storage)))
             (let ((before (uiop:read-file-string path)))
               (signals error (gr8s.raft::raft-storage-save-hard-state storage 2 "other"))
               (signals error (cl-raft::raft-compact node 3))
               (is (equal before (uiop:read-file-string path))))
             (is (null (directory (format nil "~A.checkpoint-*" path))))
             ;; An uncertain checkpoint keeps the lease until explicit close.
             (signals error (cl-raft::open-file-raft-storage path))
             (cl-raft::close-file-raft-storage storage)
             (multiple-value-bind (node2 kv2) (make-standalone-node :snapshot/restore t)
               (unwind-protect
                    (progn
                      (cl-raft::recover-raft-node node2 path)
                      (is (= 3 (cl-raft::raft-node-snapshot-index node2)))
                      (is (= 5 (cl-raft::raft-last-log-index node2)))
                      (is (= 2 (gethash "x" kv2))))
                 (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage node2)))))
        (cl-raft::close-file-raft-storage storage)))))

(test raft-checkpoint-unreadable-state-does-not-replace-valid-wal
  (with-raft-temp-dir (path)
    (let* ((storage (cl-raft::open-file-raft-storage path))
           (node (make-standalone-node :storage storage)))
      (unwind-protect
           (progn
             (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command '(:set "x" 1)))
             (setf (cl-raft::raft-node-commit-index node) 1
                   (cl-raft::raft-node-last-applied node) 1
                   (cl-raft::raft-node-snapshot-fn node) (lambda () (make-hash-table)))
             (let ((before (uiop:read-file-string path)))
               (signals print-not-readable (cl-raft::raft-compact node 1))
               (is (equal before (uiop:read-file-string path))))
             (is (= 0 (cl-raft::raft-node-snapshot-index node)))
             (is (null (directory (format nil "~A.checkpoint-*" path))))
             (gr8s.raft::raft-storage-save-hard-state storage 2 "peer")
             (is (= 2 (cl-raft::raft-recovered-term (cl-raft::load-raft-log path)))))
        (cl-raft::close-file-raft-storage storage)))))

(defvar *raft-wal-reader-evaluated* nil)

(test raft-wal-recovery-never-evaluates-reader-forms
  (with-raft-temp-dir (path)
    (ensure-directories-exist path)
    (with-open-file (stream path :direction :output :if-does-not-exist :create)
      (write-string "#.(progn (setf gr8s/tests::*raft-wal-reader-evaluated* t) '(:hard 1 nil))" stream))
    (let ((*raft-wal-reader-evaluated* nil) (*read-eval* t))
      (signals reader-error (cl-raft::load-raft-log path))
      (is (null *raft-wal-reader-evaluated*)))))

(in-suite gr8s)

(in-suite raft)

(test raft-wal-owner-excludes-second-open-before-recovery-or-restore
  (with-raft-temp-dir (path)
    (let ((owner (cl-raft::open-file-raft-storage path)))
      (unwind-protect
           (progn
             (gr8s.raft::raft-storage-save-hard-state owner 7 "first")
             (let ((before (uiop:read-file-string path)) (validated nil) (restored nil)
                   (node (cl-raft::make-raft-node :id "second")))
               (setf (cl-raft::raft-node-restore-fn node) (lambda (state) (declare (ignore state)) (setf restored t)))
               (signals error (cl-raft::open-file-raft-storage path))
               (signals error (cl-raft::recover-raft-node node path :validate-fn
                                (lambda (state) (declare (ignore state)) (setf validated t))))
               (is (null validated))
               (is (null restored))
               (is (= 0 (cl-raft::raft-node-current-term node)))
               (is (equal before (uiop:read-file-string path)))
               (is (= 7 (cl-raft::raft-recovered-term (cl-raft::load-raft-log path))))))
        (cl-raft::close-file-raft-storage owner))
      (cl-raft::close-file-raft-storage owner)
      (let ((next (cl-raft::open-file-raft-storage path)))
        (unwind-protect
             (progn (gr8s.raft::raft-storage-save-hard-state next 8 "next")
                    (is (= 8 (cl-raft::raft-recovered-term (cl-raft::load-raft-log path)))))
          (cl-raft::close-file-raft-storage next))))))

(test raft-wal-owner-survives-checkpoint-inode-replacement
  (with-raft-temp-dir (path)
    (let* ((owner (cl-raft::open-file-raft-storage path))
           (node (make-standalone-node :storage owner :snapshot/restore t)))
      (unwind-protect
           (progn
             (dotimes (i 3)
               (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command (list :set "x" i))))
             (setf (cl-raft::raft-node-commit-index node) 3)
             (cl-raft::raft-apply-committed node)
             (let ((inode (sb-posix:stat-ino (sb-posix:stat path))))
               (cl-raft::raft-compact node 3)
               (is (/= inode (sb-posix:stat-ino (sb-posix:stat path)))))
             (signals error (cl-raft::open-file-raft-storage path))
             (is (= 3 (cl-raft::raft-recovered-snapshot-index (cl-raft::load-raft-log path)))))
        (cl-raft::close-file-raft-storage owner)))))

(test raft-wal-recovery-failures-release-ownership
  (with-raft-temp-dir (path)
    (let ((owner (cl-raft::open-file-raft-storage path)))
      (gr8s.raft::raft-storage-save-snapshot owner 3 1 '(:state))
      (cl-raft::close-file-raft-storage owner))
    (dolist (phase '(:validation :restore))
      (let ((node (cl-raft::make-raft-node :id "failed")))
        (setf (cl-raft::raft-node-restore-fn node)
              (lambda (state) (declare (ignore state)) (error "Injected restore failure")))
        (signals error (cl-raft::recover-raft-node node path :validate-fn
                         (lambda (state) (declare (ignore state)) (if (eq phase :validation) nil t))))
        (is (null (cl-raft::raft-node-storage node)))
        (let ((next (cl-raft::open-file-raft-storage path)))
          (is (not (null next)))
          (cl-raft::close-file-raft-storage next))))))

(test raft-wal-process-lease-is-released-by-sigkill
  (with-raft-temp-dir (path)
    (ensure-directories-exist path)
    (let* ((ready (concatenate 'string (namestring path) ".ready"))
           (log (concatenate 'string (namestring path) ".child.log"))
           (script (namestring (merge-pathnames "scripts/raft-wal-owner-test-child.lisp"
                                                (asdf:system-source-directory :gr8s))))
           (process (sb-ext:run-program "sbcl"
                     (list "--dynamic-space-size" "384" "--noinform" "--non-interactive"
                           "--load" script "--" (namestring path) ready)
                     :search t :wait nil :input nil :output log :error :output)))
      (unwind-protect
           (progn
             (poll-until (lambda () (or (probe-file ready) (not (sb-ext:process-alive-p process)))) :timeout 60)
             (unless (probe-file ready) (error "WAL ownership child failed: ~A" (uiop:read-file-string log)))
             (signals error (cl-raft::open-file-raft-storage path))
             (is (= 17 (cl-raft::raft-recovered-term (cl-raft::load-raft-log path))))
             (sb-ext:process-kill process sb-posix:sigkill)
             (sb-ext:process-wait process)
             (is (eq :signaled (sb-ext:process-status process)))
             (let ((owner (cl-raft::open-file-raft-storage path)))
               (unwind-protect
                    (progn (gr8s.raft::raft-storage-save-hard-state owner 18 "parent")
                           (is (= 18 (cl-raft::raft-recovered-term (cl-raft::load-raft-log path)))))
                 (cl-raft::close-file-raft-storage owner))))
        (when (sb-ext:process-alive-p process)
          (sb-ext:process-kill process sb-posix:sigkill)
          (sb-ext:process-wait process))
        (sb-ext:process-close process)))))

(test raft-member-leaves-external-storage-owned-by-caller
  (with-raft-temp-dir (path)
    (let* ((storage (cl-raft::open-file-raft-storage path))
           (member (gr8s.raft.transport::start-raft-member "external" :storage storage :initial-role :witness)))
      (unwind-protect
           (progn
             (gr8s.raft.transport::stop-raft-member member)
             (is (open-stream-p (gr8s.raft::file-raft-storage-stream storage)))
             (signals error (cl-raft::open-file-raft-storage path))
             (gr8s.raft::raft-storage-save-hard-state storage 3 "caller")
             (is (= 3 (cl-raft::raft-recovered-term (cl-raft::load-raft-log path)))))
        (gr8s.raft.transport::stop-raft-member member)
        (cl-raft::close-file-raft-storage storage)))))

(in-suite gr8s)

(in-suite raft)

(defun raft-test-record-octets (form)
  (trivial-utf-8:string-to-utf-8-bytes
   (with-output-to-string (out) (gr8s.raft::raft-wal-write-frame form out))))

(defun raft-test-write-octets (path octets &optional (end (length octets)))
  (ensure-directories-exist path)
  (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                           :if-exists :supersede :if-does-not-exist :create)
    (write-sequence octets out :end end)))

(test raft-framed-wal-recovers-every-short-tail-byte-boundary
  (with-raft-temp-dir (path)
    (let* ((baseline (concatenate '(vector (unsigned-byte 8))
                      (raft-test-record-octets '(:hard 17 "acknowledged"))
                      (raft-test-record-octets '(:entry 1 17 (:set "x" "kept"))))))
      (dolist (pending (list '(:hard 18 "unacknowledged")
                            (list :entry 2 18 (list :set "x" (format nil "éλ😀~%payload")))
                            '(:truncate 1)))
        (let* ((tail (raft-test-record-octets pending))
               (complete (concatenate '(vector (unsigned-byte 8)) baseline tail)))
          (loop for cut from 1 below (length tail)
                do (raft-test-write-octets path complete (+ (length baseline) cut))
                   (let ((size (raft-wal-size path)))
                     (signals error (cl-raft::load-raft-log path))
                     (is (= size (raft-wal-size path))))
                   (let ((node (cl-raft::make-raft-node :id "recover")))
                     (unwind-protect
                          (progn
                            (cl-raft::recover-raft-node node path)
                            (is (= 17 (cl-raft::raft-node-current-term node)))
                            (is (= 1 (cl-raft::raft-last-log-index node)))
                            (is (equal '(:set "x" "kept")
                                       (cl-raft::raft-entry-command (cl-raft::raft-log-entry node 1))))
                            (is (= (length baseline) (raft-wal-size path)))
                            (gr8s.raft::raft-storage-save-hard-state (cl-raft::raft-node-storage node) 19 "after-repair")
                            (is (= 19 (cl-raft::raft-recovered-term (cl-raft::load-raft-log path)))))
                       (when (cl-raft::raft-node-storage node)
                         (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage node)))))))))))

(test raft-framed-wal-rejects-complete-corruption-without-truncation
  (with-raft-temp-dir (path)
    (let* ((first (raft-test-record-octets '(:hard 17 "first")))
           (second (raft-test-record-octets '(:entry 1 17 (:set "x" "second")))))
      (dolist (position '(0 10 27 92 157 164))
        (let ((damaged (concatenate '(vector (unsigned-byte 8)) first second)))
          (setf (aref damaged position) (if (= (aref damaged position) (char-code #\0)) (char-code #\1) (char-code #\0)))
          (raft-test-write-octets path damaged)
          (signals error (cl-raft::load-raft-log path))
          (let ((node (cl-raft::make-raft-node :id "bad")))
            (signals error (cl-raft::recover-raft-node node path))
            (is (null (cl-raft::raft-node-storage node))))
          (is (= (length damaged) (raft-wal-size path)))
          (with-open-file (in path :element-type '(unsigned-byte 8))
            (let ((after (make-array (length damaged) :element-type '(unsigned-byte 8))))
              (read-sequence after in)
              (is (equalp damaged after)))))))))

(test raft-framed-wal-supports-legacy-prefix-and-fails-closed-on-legacy-torn-tail
  (with-raft-temp-dir (path)
    (ensure-directories-exist path)
    (with-open-file (out path :direction :output :if-does-not-exist :create)
      (write-line "(:hard 7 \"legacy\")" out))
    (let ((storage (cl-raft::open-file-raft-storage path)))
      (unwind-protect
           (gr8s.raft::raft-storage-append-entry storage
             (cl-raft::make-raft-entry :index 1 :term 7 :command (list :set "x" (format nil "éλ😀~%kept"))))
        (cl-raft::close-file-raft-storage storage)))
    (let ((recovered (cl-raft::load-raft-log path)))
      (is (= 7 (cl-raft::raft-recovered-term recovered)))
      (is (equal (list :set "x" (format nil "éλ😀~%kept"))
                 (cl-raft::raft-entry-command (first (cl-raft::raft-recovered-entries recovered))))))
    (with-open-file (out path :direction :output :if-exists :append)
      (write-string "(:hard 8 \"partial" out))
    (let ((before (raft-wal-size path)) (node (cl-raft::make-raft-node :id "legacy")))
      (signals end-of-file (cl-raft::recover-raft-node node path))
      (is (= before (raft-wal-size path)))
      (is (null (cl-raft::raft-node-storage node))))))

(in-suite gr8s)

(in-suite raft)

(test raft-short-payload-with-later-valid-frame-fails-closed
  (with-raft-temp-dir (path)
    (let* ((first (raft-test-record-octets (list :entry 1 1 (make-string 1000 :initial-element #\x))))
           (later (raft-test-record-octets '(:hard 2 "acknowledged-later")))
           (damaged (concatenate '(vector (unsigned-byte 8)) (subseq first 0 180) later)))
      (raft-test-write-octets path damaged)
      (let ((node (cl-raft::make-raft-node :id "interior")))
        (signals error (cl-raft::recover-raft-node node path))
        (is (null (cl-raft::raft-node-storage node))))
      (is (= (length damaged) (raft-wal-size path))))))

(defclass repair-observing-raft-storage (gr8s.raft::file-raft-storage)
  ((failure :initarg :failure :initform nil :reader repair-sync-failure)
   (sizes :initform nil :accessor repair-sync-sizes)))

(defmethod gr8s.raft::file-raft-tail-sync ((storage repair-observing-raft-storage) fd)
  (push (sb-posix:stat-size (sb-posix:fstat fd)) (repair-sync-sizes storage))
  (when (repair-sync-failure storage) (error "Injected tail repair fsync failure"))
  (call-next-method))

(test raft-tail-repair-syncs-truncation-and-seals-on-sync-failure
  (with-raft-temp-dir (path)
    (let* ((baseline (raft-test-record-octets '(:hard 17 "kept")))
           (tail (raft-test-record-octets '(:hard 18 "pending")))
           (damaged (concatenate '(vector (unsigned-byte 8)) baseline (subseq tail 0 170))))
      (dolist (failure '(nil t))
        (raft-test-write-octets path damaged)
        (let ((storage (change-class (cl-raft::open-file-raft-storage path)
                                    'repair-observing-raft-storage :failure failure)))
          (unwind-protect
               (progn
                 (if failure
                     (progn
                       (signals error (cl-raft::load-raft-log path :repair-storage storage))
                       (is (null (gr8s.raft::file-raft-storage-stream storage)))
                       (signals error (gr8s.raft::raft-storage-save-hard-state storage 19 "blocked")))
                     (progn
                       (is (= 17 (cl-raft::raft-recovered-term (cl-raft::load-raft-log path :repair-storage storage))))
                       (gr8s.raft::raft-storage-save-hard-state storage 19 "after-sync")
                       (is (= 19 (cl-raft::raft-recovered-term (cl-raft::load-raft-log path))))))
                 (is (equal (list (length baseline)) (repair-sync-sizes storage)))
                 (signals error (cl-raft::open-file-raft-storage path)))
            (cl-raft::close-file-raft-storage storage)))))))

(test raft-torn-write-survives-repeated-sigkill-and-repair
  (with-raft-temp-dir (path)
    (raft-test-write-octets path (raft-test-record-octets '(:hard 17 "acknowledged")))
    (let* ((script (namestring (merge-pathnames "scripts/raft-wal-torn-test-child.lisp"
                                                (asdf:system-source-directory :gr8s))))
           (ready (concatenate 'string (namestring path) ".ready"))
           (log (concatenate 'string (namestring path) ".child.log"))
           (process nil) (expected 17))
      (unwind-protect
           (dotimes (cycle 3)
             (when (probe-file ready) (delete-file ready))
             (let ((before (raft-wal-size path)))
               (setf process (sb-ext:run-program "sbcl"
                              (list "--dynamic-space-size" "384" "--noinform" "--non-interactive"
                                    "--load" script "--" (namestring path) ready)
                              :search t :wait nil :input nil :output log :if-output-exists :supersede :error :output))
               (poll-until (lambda () (or (probe-file ready) (not (sb-ext:process-alive-p process)))) :timeout 60)
               (unless (probe-file ready) (error "Torn-write child failed:~%~A" (uiop:read-file-string log)))
               (is (sb-ext:process-alive-p process))
               (signals error (cl-raft::open-file-raft-storage path))
               (signals error (cl-raft::load-raft-log path))
               (sb-ext:process-kill process sb-posix:sigkill)
               (sb-ext:process-wait process)
               (is (eq :signaled (sb-ext:process-status process)))
               (sb-ext:process-close process)
               (setf process nil)
               (let ((node (cl-raft::make-raft-node :id "after-crash")))
                 (unwind-protect
                      (progn
                        (cl-raft::recover-raft-node node path)
                        (is (= expected (cl-raft::raft-node-current-term node)))
                        (is (= before (raft-wal-size path)))
                        (setf expected (+ 20 cycle))
                        (gr8s.raft::raft-storage-save-hard-state (cl-raft::raft-node-storage node) expected "new-acknowledgment")
                        (is (= expected (cl-raft::raft-recovered-term (cl-raft::load-raft-log path)))))
                   (when (cl-raft::raft-node-storage node)
                     (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage node)))))))
        (when process
          (when (sb-ext:process-alive-p process)
            (sb-ext:process-kill process sb-posix:sigkill)
            (sb-ext:process-wait process))
          (sb-ext:process-close process))))))

(in-suite gr8s)

(in-suite raft)

(defclass unstable-wal-print-object () ((calls :initform 0 :accessor unstable-wal-print-calls)))
(defmethod print-object ((object unstable-wal-print-object) stream)
  (write-string (if (= 1 (incf (unstable-wal-print-calls object))) ":FIRST" ":OTHER") stream))

(test raft-wal-frames-a-record-from-one-printing
  ;; A frame's length and digest come from the same text that is written, so a
  ;; record that prints differently every time still gets a frame that passes
  ;; its own checksum. The writer once printed twice and sealed the log when
  ;; the two disagreed.
  (with-raft-temp-dir (path)
    (let ((storage (cl-raft::open-file-raft-storage path))
          (unstable (make-instance 'unstable-wal-print-object)))
      (unwind-protect
           (progn
             (gr8s.raft::raft-storage-append-entry
              storage (cl-raft::make-raft-entry :index 1 :term 1 :command unstable))
             (is (= 1 (unstable-wal-print-calls unstable)))
             (is (not (null (gr8s.raft::file-raft-storage-stream storage))) "the log stays open")
             (gr8s.raft::raft-storage-save-hard-state storage 2 "accepted"))
        (cl-raft::close-file-raft-storage storage))
      (let ((recovered (cl-raft::load-raft-log path)))
        (is (= 2 (cl-raft::raft-recovered-term recovered)))
        (is (eq :first (cl-raft::raft-entry-command (first (cl-raft::raft-recovered-entries recovered)))))))))

(test raft-wal-framing-binds-the-printer-and-reader-radix-and-package
  (with-raft-temp-dir (path)
    (let ((*print-base* 16) (*read-base* 16) (*print-case* :downcase)
          (storage (cl-raft::open-file-raft-storage path)))
      (unwind-protect
           (progn
             (gr8s.raft::raft-storage-save-hard-state storage 26 "base")
             (gr8s.raft::raft-storage-append-entry storage
               (cl-raft::make-raft-entry :index 1 :term 26 :command 'gr8s.raft::wal-test-symbol))
             (let ((recovered (cl-raft::load-raft-log path)))
               (is (= 26 (cl-raft::raft-recovered-term recovered)))
               (is (eq 'gr8s.raft::wal-test-symbol
                       (cl-raft::raft-entry-command (first (cl-raft::raft-recovered-entries recovered)))))))
        (cl-raft::close-file-raft-storage storage)))))

(test raft-wal-later-frame-detection-spans-the-read-buffer-boundary
  (with-raft-temp-dir (path)
    (let* ((first (raft-test-record-octets (list :entry 1 1 (make-string 80000 :initial-element #\x))))
           (later (raft-test-record-octets '(:hard 2 "later")))
           (cut (+ gr8s.raft::+raft-wal-header-length+ 65530))
           (damaged (concatenate '(vector (unsigned-byte 8)) (subseq first 0 cut) later)))
      (raft-test-write-octets path damaged)
      (signals error (cl-raft::recover-raft-node (cl-raft::make-raft-node :id "cross-boundary") path))
      (is (= (length damaged) (raft-wal-size path))))))

(in-suite gr8s)

(in-suite raft)

(test raft-wal-malformed-records-cannot-masquerade-as-eof-or-repair-status
  (with-raft-temp-dir (path)
    (dolist (form '(:eof :torn nil 42 "invalid" (:hard) (:hard -1 nil)
                   (:hard 2 nil :extra) (:entry 0 1 :bad-index) (:snapshot 1 -1 nil)))
      (dolist (framed '(nil t))
        (let* ((record (if framed (raft-test-record-octets form)
                           (trivial-utf-8:string-to-utf-8-bytes (format nil "~S~%" form))))
               (bytes (concatenate '(vector (unsigned-byte 8)) record
                                   (raft-test-record-octets '(:hard 9 "later")))))
          (raft-test-write-octets path bytes)
          (signals error (cl-raft::load-raft-log path))
          (let ((node (cl-raft::make-raft-node :id "malformed")))
            (signals error (cl-raft::recover-raft-node node path))
            (is (null (cl-raft::raft-node-storage node))))
          (is (= (length bytes) (raft-wal-size path))))))))

(in-suite gr8s)

(in-suite raft)

(test raft-missing-term-zero-prefix-never-matches-an-absent-entry
  (let ((replies nil))
    (multiple-value-bind (node kv) (make-standalone-node)
      (setf (cl-raft::raft-node-send-fn node) (lambda (to message) (declare (ignore to)) (push message replies)))
      (cl-raft::raft-handle-append-entries node
       (list :term 1 :from "leader" :prev-log-index 1 :prev-log-term 0 :leader-commit 2
             :entries (list (cl-raft::make-raft-entry :index 2 :term 1 :command '(:set "x" "gap")))))
      (is (= 0 (cl-raft::raft-last-log-index node)))
      (is (= 0 (cl-raft::raft-node-commit-index node)))
      (is (= 0 (cl-raft::raft-node-last-applied node)))
      (is (null (gethash "x" kv)))
      (is (null (getf (first replies) :success)))
      (cl-raft::raft-handle-append-entries node
       (list :term 1 :from "leader" :prev-log-index 0 :prev-log-term 0 :leader-commit 1
             :entries (list (cl-raft::make-raft-entry :index 1 :term 1 :command '(:set "x" "contiguous")))))
      (is (= 1 (cl-raft::raft-last-log-index node)))
      (is (= 1 (cl-raft::raft-node-commit-index node)))
      (is (= 1 (cl-raft::raft-node-last-applied node)))
      (is (equal "contiguous" (gethash "x" kv)))
      (is-true (getf (first replies) :success)))))

(in-suite gr8s)

(in-suite raft)

(defmethod gr8s.raft::raft-storage-save-commit-index ((storage failing-raft-storage) index)
  (declare (ignore index))
  (when (eq :commit (failing-raft-operation storage)) (error "Injected commit boundary failure")))

(test raft-recovery-restores-committed-membership-without-applying-uncommitted-removal
  (with-raft-temp-dir (path)
    (let* ((storage (cl-raft::open-file-raft-storage path))
           (node (cl-raft::make-raft-node :id "one" :storage storage :current-term 1 :role :leader
                                    :send-fn (lambda (&rest args) (declare (ignore args)))))
           (recovered (cl-raft::make-raft-node :id "one")))
      (unwind-protect
           (progn
             (cl-raft::raft-configure node '(("one" . :voter)))
             (gr8s.raft::raft-storage-save-hard-state storage 1 "one")
             (cl-raft::raft-propose node '(:raft-config :members (("one" . :voter) ("two" . :voter))
                                                  :addresses (("one" "127.0.0.1" 7101) ("two" "127.0.0.1" 7102))))
             (is (= 1 (cl-raft::raft-node-commit-index node)))
             (cl-raft::raft-propose node '(:raft-config :members (("one" . :voter))))
             (is (= 1 (cl-raft::raft-node-commit-index node)))
             (cl-raft::close-file-raft-storage storage)
             (cl-raft::recover-raft-node recovered path)
             (is (= 2 (cl-raft::raft-majority recovered)))
             (is (= 1 (cl-raft::raft-node-commit-index recovered) (cl-raft::raft-node-last-applied recovered)))
             (is (= 2 (cl-raft::raft-last-log-index recovered)))
             (is (eq :voter (gethash "two" (cl-raft::raft-node-roles recovered))))
             (is (equal '("127.0.0.1" 7102) (gethash "two" (cl-raft::raft-node-peer-addresses recovered)))))
        (cl-raft::close-file-raft-storage storage)
        (when (cl-raft::raft-node-storage recovered)
          (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage recovered)))))))

(test raft-failed-commit-persistence-does-not-publish-apply-or-acknowledge
  (let* ((storage (make-instance 'failing-raft-storage :operation :commit))
         (applies 0) (callbacks 0)
         (node (cl-raft::make-raft-node :id "solo" :storage storage :current-term 1 :role :leader
                                   :apply-fn (lambda (command) (declare (ignore command)) (incf applies)))))
    (signals error (cl-raft::raft-propose node :value (lambda (value) (declare (ignore value)) (incf callbacks))))
    (is (= 0 (cl-raft::raft-node-commit-index node) (cl-raft::raft-node-last-applied node) applies callbacks))
    (is (= 1 (cl-raft::raft-last-log-index node)))
    (setf (failing-raft-operation storage) nil)
    (cl-raft::raft-advance-commit node)
    (cl-raft::raft-apply-committed node)
    (cl-raft::raft-apply-committed node)
    (is (= 1 (cl-raft::raft-node-commit-index node) (cl-raft::raft-node-last-applied node) applies callbacks))))

(test raft-wal-rejects-commit-regression-missing-prefix-and-committed-overwrite
  (dolist (records '(((:entry 1 1 :a) (:commit 1) (:commit 0))
                     ((:entry 1 1 :a) (:commit 2))
                     ((:entry 1 1 :a) (:commit 1) (:truncate 1))
                     ((:entry 1 1 :a) (:commit 1) (:entry 1 2 :b))))
    (with-raft-temp-dir (path)
      (let ((storage (cl-raft::open-file-raft-storage path)))
        (unwind-protect (dolist (record records) (gr8s.raft::file-raft-write storage record))
          (cl-raft::close-file-raft-storage storage)))
      (signals error (cl-raft::load-raft-log path)))))

(test raft-checkpoint-preserves-proven-commit-beyond-the-snapshot
  (with-raft-temp-dir (path)
    (let* ((storage (cl-raft::open-file-raft-storage path))
           (node (cl-raft::make-raft-node :id "solo" :storage storage :current-term 1 :role :leader))
           (recovered (cl-raft::make-raft-node :id "solo")))
      (unwind-protect
           (progn
             (dotimes (i 3)
               (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command (list :value i))))
             (gr8s.raft::raft-set-commit-index node 3)
             ;; Model a committed suffix awaiting application after boundary1.
             ;; This fixture has no application state, so its snapshot is exact.
             (setf (cl-raft::raft-node-last-applied node) 1)
             (cl-raft::raft-compact node 1)
             (cl-raft::close-file-raft-storage storage)
             (let ((saved (cl-raft::load-raft-log path)))
               (is (= 1 (cl-raft::raft-recovered-snapshot-index saved)))
               (is (= 3 (gr8s.raft::raft-recovered-commit-index saved))))
             (cl-raft::recover-raft-node recovered path)
             (is (= 3 (cl-raft::raft-node-commit-index recovered) (cl-raft::raft-node-last-applied recovered)))
             (is (= 3 (cl-raft::raft-last-log-index recovered))))
        (cl-raft::close-file-raft-storage storage)
        (when (cl-raft::raft-node-storage recovered)
          (cl-raft::close-file-raft-storage (cl-raft::raft-node-storage recovered)))))))

(test raft-recovery-refuses-ambiguous-legacy-configuration-tails
  (with-raft-temp-dir (path)
    (let ((storage (cl-raft::open-file-raft-storage path)) (node (cl-raft::make-raft-node :id "one")))
      (unwind-protect
           (progn
             (gr8s.raft::file-raft-write storage '(:hard 1 "one"))
             (gr8s.raft::file-raft-write storage '(:entry 1 1 (:raft-config :members (("one" . :voter) ("two" . :voter)))))
             (cl-raft::close-file-raft-storage storage)
             (signals error (cl-raft::recover-raft-node node path))
             (is (zerop (cl-raft::raft-last-log-index node))))
        (cl-raft::close-file-raft-storage storage)))))

(test raft-old-matching-heartbeat-cannot-regress-the-commit-boundary
  (let ((node (cl-raft::make-raft-node :id "follower" :current-term 1
                                   :send-fn (lambda (&rest args) (declare (ignore args))))))
    (dotimes (i 2) (cl-raft::raft-log-append node (cl-raft::make-raft-entry :term 1 :command i)))
    (setf (cl-raft::raft-node-commit-index node) 2 (cl-raft::raft-node-last-applied node) 2)
    (cl-raft::raft-handle-append-entries node
      '(:term 1 :from "leader" :prev-log-index 0 :prev-log-term 0 :entries nil :leader-commit 3))
    (is (= 2 (cl-raft::raft-node-commit-index node) (cl-raft::raft-node-last-applied node)))
    (is (= 2 (cl-raft::raft-last-log-index node)))))

(in-suite gr8s)

(in-suite raft)

(defun make-disk-catchup-test-node (storage)
  (let ((node (gr8s.raft::make-raft-node
   :id "leader" :role :leader :current-term 2 :storage storage
   :catchup-byte-limit (* 8 1024 1024) :append-entry-limit 1
   :commit-index 3 :last-applied 3
   :log (make-array 3 :adjustable t :fill-pointer 3
                     :initial-contents
                     (loop for index from 1 to 3 collect
                       (gr8s.raft::make-raft-entry :index index :term (if (= index 1) 1 2)
                                                  :command (list :payload index)))))))
    (gr8s.raft::raft-persist-hard-state node)
    (map nil (lambda (entry) (gr8s.raft::raft-storage-append-entry storage entry)) (gr8s.raft::raft-node-log node))
    (gr8s.raft::raft-storage-save-commit-index storage 3)
    node))

(test disk-catchup-replicates-through-multiple-compactions-without-live-prefix
  (with-temporary-store (store root)
    (values store)
    (let* ((storage (cl-raft::open-file-raft-storage (merge-pathnames "cache.log" root)))
           (node (make-disk-catchup-test-node storage))
           (follower (gr8s.raft::make-raft-node :id "follower"
                                                :send-fn (lambda (&rest args) (declare (ignore args)))))
           (files (length (uiop:directory-files root))))
      (unwind-protect
           (progn
             (gr8s.raft::raft-compact node 3)
             (is-true (nth-value 1 (gr8s.raft::raft-propose node '(:payload 4))))
             (is-true (nth-value 1 (gr8s.raft::raft-propose node '(:payload 5))))
             (gr8s.raft::raft-compact node 5)
             (is (zerop (length (gr8s.raft::raft-node-log node))))
             (is (= 2 (nth-value 1 (gr8s.raft::raft-storage-catchup-usage storage))))
             (is (= files (length (uiop:directory-files root))))
             (loop for next from 1 to 5 do
               (setf (gethash "follower" (gr8s.raft::raft-node-next-index node)) next)
               (let ((message (gr8s.raft::raft-append-message node "follower")))
                 (is (eq :append-entries (getf message :type)))
                 (is (= 1 (length (getf message :entries))))
                 (is (= (1- next) (getf message :prev-log-index)))
                 (is (= (cond ((= next 1) 0) ((= next 2) 1) (t 2)) (getf message :prev-log-term)))
                 (gr8s.raft::raft-handle-append-entries follower message)))
             (is (= 5 (gr8s.raft::raft-node-commit-index follower)))
             (is (= 5 (gr8s.raft::raft-node-last-applied follower)))
             (is (equal '((:payload 1) (:payload 2) (:payload 3) (:payload 4) (:payload 5))
                        (map 'list #'gr8s.raft::raft-entry-command (gr8s.raft::raft-node-log follower)))))
        (cl-raft::close-file-raft-storage storage)))))

(test disk-catchup-eviction-and-close-release-anonymous-descriptors
  (with-temporary-store (store root)
    (values store)
    (let* ((storage (cl-raft::open-file-raft-storage (merge-pathnames "cache.log" root)))
           (node (make-disk-catchup-test-node storage)))
      (unwind-protect
           (progn
             (gr8s.raft::raft-compact node 3)
             (let* ((segment (first (gr8s.raft::file-raft-storage-catchup-segments storage)))
                    (fd (gr8s.raft::raft-catchup-segment-fd segment))
                    (stat (sb-posix:fstat fd)))
               (is (zerop (sb-posix:stat-nlink stat)))
               (is (= #o600 (logand #o777 (sb-posix:stat-mode stat))))
               (is (logtest 1 (cffi:foreign-funcall "fcntl" :int fd :int 1 :int)))
               (gr8s.raft::raft-catchup-evict storage 1 1)
               (signals sb-posix:syscall-error (sb-posix:fstat fd)))
             (is (zerop (gr8s.raft::raft-storage-catchup-usage storage)))
             (setf (gethash "follower" (gr8s.raft::raft-node-next-index node)) 1)
             (is (eq :install-snapshot (getf (gr8s.raft::raft-append-message node "follower") :type)))
             (gr8s.raft::raft-propose node '(:payload 4))
             (gr8s.raft::raft-compact node 4)
             (let ((fd (gr8s.raft::raft-catchup-segment-fd
                        (first (gr8s.raft::file-raft-storage-catchup-segments storage)))))
               (cl-raft::close-file-raft-storage storage)
               (signals sb-posix:syscall-error (sb-posix:fstat fd))))
        (cl-raft::close-file-raft-storage storage)))))

(test corrupt-disk-catchup-falls-back-to-snapshot-without-changing-durable-state
  (with-temporary-store (store root)
    (values store)
    (let* ((path (merge-pathnames "cache.log" root))
           (storage (cl-raft::open-file-raft-storage path))
           (node (make-disk-catchup-test-node storage)))
      (unwind-protect
           (progn
             (gr8s.raft::raft-compact node 3)
             (let ((fd (gr8s.raft::raft-catchup-segment-fd
                        (first (gr8s.raft::file-raft-storage-catchup-segments storage)))))
               (with-open-file (out (format nil "/proc/self/fd/~D" fd) :direction :output :if-exists :overwrite)
                 (write-char #\! out)))
             (setf (gethash "follower" (gr8s.raft::raft-node-next-index node)) 1)
             (is (eq :install-snapshot (getf (gr8s.raft::raft-append-message node "follower") :type)))
             (is (not (null (gr8s.raft::file-raft-storage-catchup-error storage))))
             (is (zerop (gr8s.raft::raft-storage-catchup-usage storage)))
             (is (= 3 (gr8s.raft::raft-recovered-commit-index (gr8s.raft::load-raft-log path))))
             (is (= 3 (gr8s.raft::raft-node-last-applied node))))
        (cl-raft::close-file-raft-storage storage)))))

(test failed-checkpoint-cannot-publish-an-unadopted-disk-cache-boundary
  (with-temporary-store (store root)
    (values store)
    (let* ((path (merge-pathnames "cache.log" root))
           (storage (cl-raft::open-file-raft-storage path))
           (node (make-disk-catchup-test-node storage)))
      (unwind-protect
           (progn
             (change-class storage 'checkpoint-failing-raft-storage :phase :file)
             (let ((bytes (raft-wal-size path)))
               (signals error (gr8s.raft::raft-compact node 3))
               (is (= bytes (raft-wal-size path))))
             (is (zerop (gr8s.raft::raft-node-snapshot-index node)))
             (is (null (gr8s.raft::raft-storage-read-catchup storage node 1)))
             (is (= 3 (gr8s.raft::raft-recovered-commit-index (gr8s.raft::load-raft-log path))))
             (setf (checkpoint-failure-phase storage) nil)
             (gr8s.raft::raft-compact node 3)
             (is (not (null (gr8s.raft::raft-storage-read-catchup storage node 1)))))
        (cl-raft::close-file-raft-storage storage)))))

(test disk-catchup-budget-and-opt-out-preserve-snapshot-fallback
  (with-temporary-store (store root)
    (values store)
    (let* ((storage (cl-raft::open-file-raft-storage (merge-pathnames "cache.log" root)))
           (node (make-disk-catchup-test-node storage)))
      (unwind-protect
           (progn
             (setf (gr8s.raft::raft-node-catchup-byte-limit node) 1)
             (gr8s.raft::raft-compact node 3)
             (is (zerop (gr8s.raft::raft-storage-catchup-usage storage)))
             (setf (gethash "follower" (gr8s.raft::raft-node-next-index node)) 1)
             (is (eq :install-snapshot (getf (gr8s.raft::raft-append-message node "follower") :type)))
             (setf (gr8s.raft::raft-node-catchup-byte-limit node) 65536)
             (gr8s.raft::raft-propose node '(:payload 4))
             (gr8s.raft::raft-compact node 4)
             (setf (gethash "follower" (gr8s.raft::raft-node-next-index node)) 4
                   (gr8s.raft::raft-node-append-entry-limit node) 64
                   (gr8s.raft::raft-node-append-byte-budget node) 1)
             (let ((message (gr8s.raft::raft-append-message node "follower")))
               (is (eq :append-entries (getf message :type)))
               (is (= 1 (length (getf message :entries)))))
             (setf (gr8s.raft::raft-node-catchup-byte-limit node) nil)
             (is (eq :install-snapshot (getf (gr8s.raft::raft-append-message node "follower") :type))))
        (cl-raft::close-file-raft-storage storage)))))

(test disk-catchup-reader-never-evaluates-reader-forms
  (with-temporary-store (store root)
    (values store)
    (let* ((storage (cl-raft::open-file-raft-storage (merge-pathnames "cache.log" root)))
           (node (make-disk-catchup-test-node storage))
           (*raft-wal-reader-evaluated* nil) (*read-eval* t))
      (unwind-protect
           (progn
             (gr8s.raft::raft-compact node 3)
             (let ((fd (gr8s.raft::raft-catchup-segment-fd
                        (first (gr8s.raft::file-raft-storage-catchup-segments storage)))))
               (with-open-file (out (format nil "/proc/self/fd/~D" fd) :direction :output :if-exists :overwrite)
                 (write-string "#.(progn (setf gr8s/tests::*raft-wal-reader-evaluated* t) '(:snapshot 0 0 nil))" out)))
             (setf (gethash "follower" (gr8s.raft::raft-node-next-index node)) 1)
             (is (eq :install-snapshot (getf (gr8s.raft::raft-append-message node "follower") :type)))
             (is-false *raft-wal-reader-evaluated*)
             (is (zerop (gr8s.raft::raft-storage-catchup-usage storage))))
        (cl-raft::close-file-raft-storage storage)))))

(test disk-catchup-copies-unicode-frames-after-checkpoint-and-recovery-without-printing-payloads
  (with-temporary-store (store root)
    (values store)
    (let* ((path (merge-pathnames "frames.log" root))
           (storage (cl-raft::open-file-raft-storage path))
           (node (make-disk-catchup-test-node storage))
           (text (concatenate 'string "λ😀" (make-string 70000 :initial-element #\x)))
           (original (symbol-function 'gr8s.raft::raft-wal-form-metrics)))
      (unwind-protect
           (progn
             ;; Keep an uncommitted Unicode suffix while checkpointing the
             ;; exact applied boundary; arbitrary older application capture is
             ;; deliberately rejected by the core.
             (let ((entry (gr8s.raft::make-raft-entry :index 4 :term 2 :command (list :payload text))))
               (gr8s.raft::raft-storage-append-entry storage entry)
               (vector-push-extend entry (gr8s.raft::raft-node-log node)))
             (is (= 3 (gr8s.raft::raft-node-last-applied node)))
             ;; Neither archived prefix nor retained checkpoint suffix may print
             ;; an entry when its durable frame is available.
             (setf (symbol-function 'gr8s.raft::raft-wal-form-metrics)
                   (lambda (form &optional output)
                     (when (eq :entry (first form)) (error "Copied entry was reserialized"))
                     (funcall original form output)))
             (gr8s.raft::raft-compact node 3)
             (is (= 1 (hash-table-count (gr8s.raft::file-raft-storage-entry-frames storage))))
             (cl-raft::close-file-raft-storage storage)
             (setf node (gr8s.raft::make-raft-node :id "recovered" :catchup-byte-limit (* 8 1024 1024)))
             (gr8s.raft::recover-raft-node node path)
             (setf storage (gr8s.raft::raft-node-storage node))
             (gr8s.raft::raft-storage-save-commit-index storage 4)
             (setf (gr8s.raft::raft-node-commit-index node) 4)
             (gr8s.raft::raft-apply-committed node)
             (is (= 1 (hash-table-count (gr8s.raft::file-raft-storage-entry-frames storage))))
             (is (plusp (gr8s.raft::raft-catchup-framed-prefix-size storage node 4)))
             (gr8s.raft::raft-compact node 4)
             (let ((batch (gr8s.raft::raft-storage-read-catchup storage node 4)))
               (is (not (null batch)))
               (is (= 2 (car batch)))
               (is (equal (list (list :payload text))
                          (mapcar #'gr8s.raft::raft-entry-command (cdr batch)))))
             (is (zerop (hash-table-count (gr8s.raft::file-raft-storage-entry-frames storage)))))
        (setf (symbol-function 'gr8s.raft::raft-wal-form-metrics) original)
        (cl-raft::close-file-raft-storage storage)))))

(test disk-catchup-frame-index-follows-truncation-and-reopened-append-offsets
  (with-temporary-store (store root)
    (values store)
    (let* ((path (merge-pathnames "frames.log" root))
           (storage (cl-raft::open-file-raft-storage path))
           (node nil))
      (unwind-protect
           (progn
             (gr8s.raft::raft-storage-save-hard-state storage 3 nil)
             (loop for i from 1 to 3 do
               (gr8s.raft::raft-storage-append-entry storage
                 (gr8s.raft::make-raft-entry :index i :term 2 :command (list :old i))))
             (gr8s.raft::raft-storage-save-commit-index storage 1)
             (gr8s.raft::raft-storage-truncate storage 2)
             (is (= 1 (hash-table-count (gr8s.raft::file-raft-storage-entry-frames storage))))
             (cl-raft::close-file-raft-storage storage)
             ;; Exercise O_APPEND reopening without recovery first: its initial
             ;; OS offset is zero, but the new frame belongs at the existing EOF.
             (let ((old-size (raft-wal-size path)))
               (setf storage (cl-raft::open-file-raft-storage path))
               (gr8s.raft::raft-storage-append-entry storage
                 (gr8s.raft::make-raft-entry :index 2 :term 3 :command '(:new "λ")))
               (is (= old-size (aref (gethash 2 (gr8s.raft::file-raft-storage-entry-frames storage)) 1))))
             (gr8s.raft::raft-storage-save-commit-index storage 2)
             (cl-raft::close-file-raft-storage storage)
             (setf node (gr8s.raft::make-raft-node :id "recovered" :catchup-byte-limit 65536))
             (gr8s.raft::recover-raft-node node path)
             (setf storage (gr8s.raft::raft-node-storage node))
             (is (= 2 (hash-table-count (gr8s.raft::file-raft-storage-entry-frames storage))))
             (is (null (gethash 3 (gr8s.raft::file-raft-storage-entry-frames storage))))
             (gr8s.raft::raft-compact node 2)
             (let ((batch (gr8s.raft::raft-storage-read-catchup storage node 1)))
               (is (equal '((:old 1) (:new "λ")) (mapcar #'gr8s.raft::raft-entry-command (cdr batch))))))
        (cl-raft::close-file-raft-storage storage)))))

(test failed-checkpoint-preserves-frame-offset-index-and-missing-index-falls-back
  (with-temporary-store (store root)
    (values store)
    (let* ((storage (cl-raft::open-file-raft-storage (merge-pathnames "frames.log" root)))
           (node (make-disk-catchup-test-node storage))
           (frames (gr8s.raft::file-raft-storage-entry-frames storage)))
      (unwind-protect
           (progn
             (change-class storage 'checkpoint-failing-raft-storage :phase :file)
             (signals error (gr8s.raft::raft-compact node 3))
             (is (eq frames (gr8s.raft::file-raft-storage-entry-frames storage)))
             (is (= 3 (hash-table-count frames)))
             (setf (checkpoint-failure-phase storage) nil)
             (clrhash frames)
             (is (null (gr8s.raft::raft-catchup-framed-prefix-size storage node 3)))
             (gr8s.raft::raft-compact node 3)
             (is (not (null (gr8s.raft::raft-storage-read-catchup storage node 1)))))
        (cl-raft::close-file-raft-storage storage)))))


(test checkpoint-mixes-copied-and-serialized-unicode-entries-and-remains-appendable
  (with-temporary-store (store root)
    (values store)
    (let* ((path (merge-pathnames "mixed.log" root))
           (storage (cl-raft::open-file-raft-storage path))
           (node (make-disk-catchup-test-node storage)))
      (unwind-protect
           (progn
             (loop for index from 4 to 5
                   for command in '((:unicode "λ😀") (:copied "日本語"))
                   for entry = (gr8s.raft::make-raft-entry :index index :term 2 :command command)
                   do (gr8s.raft::raft-storage-append-entry storage entry)
                      (vector-push-extend entry (gr8s.raft::raft-node-log node)))
             ;; The first suffix entry must use the legacy/missing-index
             ;; serializer, followed by raw binary copying and a text trailer.
             (remhash 4 (gr8s.raft::file-raft-storage-entry-frames storage))
             (gr8s.raft::raft-compact node 3)
             (let ((entry (gr8s.raft::make-raft-entry :index 6 :term 2 :command '(:after "é"))))
               (gr8s.raft::raft-storage-append-entry storage entry)
               (vector-push-extend entry (gr8s.raft::raft-node-log node)))
             (gr8s.raft::raft-storage-save-commit-index storage 6)
             (let ((loaded (gr8s.raft::load-raft-log path)))
               (is (= 6 (gr8s.raft::raft-recovered-commit-index loaded)))
               (is (equal '((:unicode "λ😀") (:copied "日本語") (:after "é"))
                          (mapcar #'gr8s.raft::raft-entry-command (gr8s.raft::raft-recovered-entries loaded)))))
             (is (= 3 (hash-table-count (gr8s.raft::file-raft-storage-entry-frames storage))))
             (setf (gr8s.raft::raft-node-commit-index node) 6)
             (gr8s.raft::raft-apply-committed node)
             (gr8s.raft::raft-compact node 6)
             (is (equal '((:unicode "λ😀") (:copied "日本語") (:after "é"))
                        (loop for next from 4 to 6 append
                          (mapcar #'gr8s.raft::raft-entry-command
                                  (cdr (gr8s.raft::raft-storage-read-catchup storage node next)))))))
        (cl-raft::close-file-raft-storage storage)))))

(test capacity-limited-cached-peer-installs-checkpoint-without-growing-budget
  (with-temporary-store (store root)
    (values store)
    (let* ((storage (cl-raft::open-file-raft-storage (merge-pathnames "capacity-cache.log" root)))
           (leader (make-disk-catchup-test-node storage))
           (replies nil)
           (follower (gr8s.raft::make-raft-node
                      :id "follower" :current-term 2 :retained-byte-limit 512
                      :uncommitted-weight-fn (constantly 128)
                      :send-fn (lambda (target message) (declare (ignore target))
                                 (push message replies)))))
      (unwind-protect
           (progn
             (gr8s.raft::raft-configure leader '(("leader" . :voter) ("follower" . :voter)))
             (gr8s.raft::raft-compact leader 3)
             (setf (gethash "follower" (gr8s.raft::raft-node-next-index leader)) 1)
             (dotimes (i 2)
               (values i)
               (gr8s.raft::raft-handle-message follower
                 (gr8s.raft::raft-append-message leader "follower"))
               (is (getf (first replies) :success))
               (gr8s.raft::raft-handle-message leader (first replies)))
             (is (= 2 (gr8s.raft::raft-node-last-applied follower)))
             (gr8s.raft::raft-handle-message follower
               (gr8s.raft::raft-append-message leader "follower"))
             (is (not (getf (first replies) :success)))
             (is (getf (first replies) :capacity-limited))
             (is (= 2 (gr8s.raft::raft-node-last-applied follower)))
             (gr8s.raft::raft-handle-message leader (first replies))
             (let ((message (gr8s.raft::raft-append-message leader "follower")))
               (is (eq :install-snapshot (getf message :type)))
               ;; Heartbeat retries must retain the snapshot preference.
               (is (eq :install-snapshot
                       (getf (gr8s.raft::raft-append-message leader "follower") :type)))
               (gr8s.raft::raft-handle-message follower message))
             (is (= 3 (gr8s.raft::raft-node-last-applied follower)))
             (is (= 512 (gr8s.raft::raft-node-retained-byte-limit follower)))
             (is (zerop (length (gr8s.raft::raft-node-log follower))))
             (gr8s.raft::raft-handle-message leader (first replies))
             (is (not (gethash "follower" (gr8s.raft::raft-node-peer-snapshot-required leader))))
             (is (= 4 (gethash "follower" (gr8s.raft::raft-node-next-index leader)))))
        (cl-raft::close-file-raft-storage storage)))))

(test snapshot-capacity-hints-are-current-term-member-scoped-and-reset
  (let ((node (gr8s.raft::make-raft-node
               :id "leader" :peers '("peer") :role :leader :current-term 2
               :snapshot-index 4 :snapshot-term 2 :commit-index 4 :last-applied 4)))
    (flet ((reply (peer term &optional (capacity t))
             (gr8s.raft::raft-handle-append-entries-reply node
               (list :from peer :term term :success nil :next-index 2 :capacity-limited capacity))))
      (reply "peer" 1)
      (reply "outsider" 2)
      (reply "peer" 2 nil)
      (is (zerop (hash-table-count (gr8s.raft::raft-node-peer-snapshot-required node))))
      (reply "peer" 2)
      (is (= 1 (hash-table-count (gr8s.raft::raft-node-peer-snapshot-required node))))
      (gr8s.raft::raft-configure node '(("leader" . :voter) ("peer" . :voter)))
      (is (zerop (hash-table-count (gr8s.raft::raft-node-peer-snapshot-required node))))
      (reply "peer" 2)
      (setf (gr8s.raft::raft-node-peers node) nil)
      (gr8s.raft::raft-become-leader node)
      (is (zerop (hash-table-count (gr8s.raft::raft-node-peer-snapshot-required node)))))))

(test delayed-append-ack-cannot-undo-newer-snapshot-or-log-progress
  (let ((node (gr8s.raft::make-raft-node
               :id "leader" :peers '("peer") :role :leader :current-term 3
               :snapshot-index 10 :snapshot-term 2 :commit-index 10 :last-applied 10
               :log (make-array 5 :adjustable t :fill-pointer 5
                                :initial-contents
                                (loop for index from 11 to 15 collect
                                  (gr8s.raft::make-raft-entry :index index :term 3 :command '(:noop)))))))
    (setf (gethash "leader" (gr8s.raft::raft-node-match-index node)) 15)
    (gr8s.raft::raft-handle-install-snapshot-reply
     node '(:from "peer" :term 3 :success t :match-index 10))
    (gr8s.raft::raft-handle-append-entries-reply
     node '(:from "peer" :term 3 :success t :match-index 6 :applied-index 6))
    (is (= 10 (gethash "peer" (gr8s.raft::raft-node-match-index node))))
    (is (= 11 (gethash "peer" (gr8s.raft::raft-node-next-index node))))
    (gr8s.raft::raft-handle-append-entries-reply
     node '(:from "peer" :term 3 :success t :match-index 14 :applied-index 14))
    (gr8s.raft::raft-handle-append-entries-reply
     node '(:from "peer" :term 3 :success t :match-index 12 :applied-index 12))
    (is (= 14 (gethash "peer" (gr8s.raft::raft-node-match-index node))))
    (is (= 15 (gethash "peer" (gr8s.raft::raft-node-next-index node))))
    ;; Applied proof must use this reply's match, not the newer remembered match.
    (gr8s.raft::raft-handle-append-entries-reply
     node '(:from "peer" :term 3 :success t :match-index 12 :applied-index 15))
    (is (= 14 (cdr (gethash "peer" (gr8s.raft::raft-node-peer-applied node)))))
    (gr8s.raft::raft-handle-append-entries-reply
     node '(:from "peer" :term 3 :success nil :next-index 2 :capacity-limited t))
    (is (= 15 (gethash "peer" (gr8s.raft::raft-node-next-index node))))
    (is-false (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node)))))

(test append-acknowledgements-require-current-peer-and-bounded-index
  (let ((node (gr8s.raft::make-raft-node :id "leader" :peers '("peer") :role :leader
                                      :current-term 3 :snapshot-index 10 :snapshot-term 3
                                      :commit-index 10 :last-applied 10)))
    (setf (gethash "peer" (gr8s.raft::raft-node-match-index node)) 10
          (gethash "peer" (gr8s.raft::raft-node-next-index node)) 11)
    (dolist (index '(11 -1 nil "10"))
      (finishes (gr8s.raft::raft-handle-append-entries-reply
                 node (list :from "peer" :term 3 :success t :match-index index)))
      (is (= 10 (gethash "peer" (gr8s.raft::raft-node-match-index node))))
      (is (= 11 (gethash "peer" (gr8s.raft::raft-node-next-index node)))))
    (dolist (success '(nil t))
      (gr8s.raft::raft-handle-append-entries-reply
       node (list :from "outsider" :term 3 :success success :match-index 10 :next-index 2)))
    (is-false (gethash "outsider" (gr8s.raft::raft-node-match-index node)))
    (is-false (gethash "outsider" (gr8s.raft::raft-node-next-index node)))
    (gr8s.raft::raft-handle-append-entries-reply
     node '(:from "peer" :term 2 :success t :match-index 1))
    (is (= 10 (gethash "peer" (gr8s.raft::raft-node-match-index node))))))

(test capacity-recovery-ack-does-not-chase-newer-checkpoints
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((storage (cl-raft::open-file-raft-storage (merge-pathnames "moving-checkpoint.log" root)))
           (leader (make-disk-catchup-test-node storage))
           (replies nil)
           (follower (gr8s.raft::make-raft-node
                      :id "follower" :current-term 2 :retained-byte-limit 512
                      :uncommitted-weight-fn (constantly 128)
                      :send-fn (lambda (target message) (declare (ignore target)) (push message replies)))))
      (unwind-protect
           (progn
             (gr8s.raft::raft-configure leader '(("leader" . :voter) ("follower" . :voter)))
             (setf (gethash "follower" (gr8s.raft::raft-node-match-index leader)) 2
                   (gethash "follower" (gr8s.raft::raft-node-next-index leader)) 3)
             (gr8s.raft::raft-compact leader 3)
             (gr8s.raft::raft-handle-append-entries-reply
              leader '(:from "follower" :term 2 :success nil :capacity-limited t :next-index 3))
             (let ((image (gr8s.raft::raft-append-message leader "follower")))
               (is (eq :install-snapshot (getf image :type)))
               (is (= 3 (getf image :last-index)))
               (gr8s.raft::raft-handle-message follower image)
               ;; The leader advances while this image's receipt is in flight.
               (let ((entry (gr8s.raft::make-raft-entry :index 4 :term 2 :command '(:payload 4))))
                 (gr8s.raft::raft-storage-append-entry storage entry)
                 (vector-push-extend entry (gr8s.raft::raft-node-log leader)))
               (gr8s.raft::raft-storage-save-commit-index storage 4)
               (setf (gr8s.raft::raft-node-commit-index leader) 4
                     (gr8s.raft::raft-node-last-applied leader) 4)
               (gr8s.raft::raft-compact leader 4)
               (gr8s.raft::raft-handle-install-snapshot-reply
                leader '(:from "follower" :term 2 :success t :match-index 2))
               (is-true (gethash "follower" (gr8s.raft::raft-node-peer-snapshot-required leader)))
               (gr8s.raft::raft-handle-message leader (first replies)))
             (is-false (gethash "follower" (gr8s.raft::raft-node-peer-snapshot-required leader)))
             ;; An older capacity refusal cannot revoke this recovered prefix.
             (gr8s.raft::raft-handle-append-entries-reply
              leader '(:from "follower" :term 2 :success nil :capacity-limited t :next-index 3))
             (is-false (gethash "follower" (gr8s.raft::raft-node-peer-snapshot-required leader)))
             (let ((tail (gr8s.raft::raft-append-message leader "follower")))
               (is (eq :append-entries (getf tail :type)))
               (when (eq :append-entries (getf tail :type))
                 (is (= 3 (getf tail :prev-log-index)))
                 (is (= 4 (gr8s.raft::raft-entry-index (first (getf tail :entries))))))
               (gr8s.raft::raft-handle-message follower tail)
               (is (= 4 (gr8s.raft::raft-node-last-applied follower)))
               (is (= 512 (gr8s.raft::raft-node-retained-byte-limit follower)))))
        (cl-raft::close-file-raft-storage storage)))))

(test newer-capacity-refusal-retains-its-own-recovery-boundary
  (let ((node (gr8s.raft::make-raft-node :id "leader" :peers '("peer") :role :leader :current-term 2
                                      :snapshot-index 3 :snapshot-term 2 :commit-index 3 :last-applied 3)))
    (setf (gethash "peer" (gr8s.raft::raft-node-match-index node)) 1
          (gethash "peer" (gr8s.raft::raft-node-next-index node)) 2)
    (flet ((refuse (index)
             (gr8s.raft::raft-handle-append-entries-reply
              node (list :from "peer" :term 2 :success nil :capacity-limited t :next-index index)))
           (ack (index)
             (gr8s.raft::raft-handle-install-snapshot-reply
              node (list :from "peer" :term 2 :success t :match-index index))))
      (refuse 2)
      (ack 2)
      (is-false (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node)))
      (refuse 3)
      (is-true (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node)))
      (ack 2)
      (is-true (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node)))
      (ack 3)
      (is-false (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node))))))

(test legacy-capacity-markers-use-pre-reply-progress-during-live-redefinition
  (let ((node (gr8s.raft::make-raft-node :id "leader" :peers '("peer") :role :leader :current-term 2
                                      :snapshot-index 4 :snapshot-term 2 :commit-index 4 :last-applied 4)))
    (flet ((seed ()
             (setf (gethash "peer" (gr8s.raft::raft-node-match-index node)) 2
                   (gethash "peer" (gr8s.raft::raft-node-next-index node)) 3
                   (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node)) t)))
      (seed)
      (gr8s.raft::raft-handle-install-snapshot-reply node '(:from "peer" :term 2 :success t :match-index 3))
      (is-false (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node)))
      (seed)
      (gr8s.raft::raft-handle-append-entries-reply node '(:from "peer" :term 2 :success t :match-index 3 :applied-index 3))
      (is-false (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node)))
      (seed)
      (setf (gethash "peer" (gr8s.raft::raft-node-match-index node)) 1)
      (gr8s.raft::raft-handle-append-entries-reply node '(:from "peer" :term 2 :success nil :capacity-limited t :next-index 2))
      (gr8s.raft::raft-handle-install-snapshot-reply node '(:from "peer" :term 2 :success t :match-index 2))
      (is-true (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node)))
      (gr8s.raft::raft-handle-install-snapshot-reply node '(:from "peer" :term 2 :success t :match-index 3))
      (is-false (gethash "peer" (gr8s.raft::raft-node-peer-snapshot-required node))))))
