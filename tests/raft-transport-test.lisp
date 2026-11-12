;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the ag-gRPC Raft transport (src/raft-transport.lisp): the wire
;;;; encoding round-trips a message (including log entries), and three real
;;;; members over real gRPC elect a leader and replicate a proposal to every
;;;; state machine.

(in-package #:gr8s/tests)
(def-suite raft-transport :in gr8s)
(in-suite raft-transport)

(test raft-transport-has-an-explicit-package-boundary
  (let ((package (find-package "GR8S.RAFT.TRANSPORT")))
    (is (not (null package)))
    (dolist (name '("START-RAFT-MEMBER" "STOP-RAFT-MEMBER"
                    "RAFT-MEMBER-START" "RAFT-MEMBER-PROPOSE"
                    "RAFT-CLUSTER-INIT" "RAFT-CLUSTER-JOIN"))
      (multiple-value-bind (symbol status) (and package (find-symbol name package))
        (is (not (null symbol)) "~A is present in GR8S.RAFT.TRANSPORT" name)
        (is (eq :external status)
            "~A is exported from GR8S.RAFT.TRANSPORT" name)))))

(test raft-transport-serialization-round-trips
  (let* ((entries (list (cl-raft::make-raft-entry :index 4 :term 2 :command '(:set "x" 7))
                        (cl-raft::make-raft-entry :index 5 :term 2 :command '(:cas "y" nil "Z"))))
         (msg (list :type :append-entries :term 2 :from "b"
                    :prev-log-index 3 :prev-log-term 1 :entries entries :leader-commit 3))
         (back (gr8s.raft.transport::octets->raft-message (gr8s.raft.transport::raft-message->octets msg))))
    (is (eq :append-entries (getf back :type)))
    (is (= 2 (getf back :term)))
    (is (equal "b" (getf back :from)))
    (is (= 3 (getf back :prev-log-index)))
    (is (= 2 (length (getf back :entries))))
    (let ((e (second (getf back :entries))))
      (is (= 5 (cl-raft::raft-entry-index e)))
      (is (= 2 (cl-raft::raft-entry-term e)))
      (is (equal '(:cas "y" nil "Z") (cl-raft::raft-entry-command e))))))

(test raft-link-coalesces-unsent-append-retries
  (let* ((link (gr8s.raft.transport::make-raft-peer-link :id "b"))
         (vote (list :type :request-vote :term 2 :from "a"))
         (old-append (list :type :append-entries :term 2 :from "a"
                           :prev-log-index 3 :entries nil :leader-commit 3))
         (new-append (list :type :append-entries :term 2 :from "a"
                           :prev-log-index 3 :entries nil :leader-commit 4)))
    (gr8s.raft.transport::raft-link-enqueue link vote)
    (gr8s.raft.transport::raft-link-enqueue link old-append)
    (gr8s.raft.transport::raft-link-enqueue link new-append)
    (let ((items (gr8s.raft.transport::raft-peer-link-items link)))
      (is (= 2 (length items)) "a disconnected peer retains at most one unsent AppendEntries")
      (is (eq :request-vote (getf (first items) :type)))
      (is (eq :append-entries (getf (second items) :type)))
      (is (= 4 (getf (second items) :leader-commit))
          "the newest AppendEntries supersedes the stale retry"))))

(test idle-raft-link-waits-until-enqueue-signals-it
  (let* ((member (gr8s.raft.transport::make-raft-member :running t))
         (link (gr8s.raft.transport::make-raft-peer-link :id "b"))
         (message (list :type :request-vote :term 2 :from "a"))
         (done nil)
         (batch nil)
         (thread
           (bt:make-thread
            (lambda ()
              (setf batch (gr8s.raft.transport::raft-link-wait-batch member link)
                    done t)))))
    (unwind-protect
         (progn
           (sleep 0.05)
           (is-false done "an empty peer link blocks instead of polling")
           (gr8s.raft.transport::raft-link-enqueue link message)
           (is (poll-until (lambda () done) :timeout 1))
           (is (equal (list message) batch)))
      (setf (gr8s.raft.transport::raft-member-running member) nil)
      (bt:with-lock-held ((gr8s.raft.transport::raft-peer-link-lock link))
        (bt:condition-notify (gr8s.raft.transport::raft-peer-link-changed link)))
      (when (bt:thread-alive-p thread) (bt:join-thread thread)))))

(defun poll-until (predicate &key (timeout 10) (interval 0.05))
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (loop (when (funcall predicate) (return t))
          (when (> (get-internal-real-time) deadline) (return nil))
          (sleep interval))))

(test raft-transport-elects-and-replicates-over-grpc
  (let* ((ids '("a" "b" "c"))
         (kvs (mapcar (lambda (id) (cons id (make-hash-table :test 'equal))) ids))
         (members (mapcar
                   (lambda (id)
                     (cons id
                           (gr8s.raft.transport::start-raft-member
                            id :apply-fn (let ((kv (cdr (assoc id kvs :test #'equal))))
                                           (lambda (command) (raft-kv-apply kv command))))))
                   ids))
         (member-list (mapcar #'cdr members)))
    (unwind-protect
         (progn
           ;; Wire every member to the other two, then start the clocks.
           (dolist (entry members)
             (let ((self (car entry)))
               (gr8s.raft.transport::raft-member-set-peers
                (cdr entry)
                (loop for other in members
                      unless (equal (car other) self)
                        collect (list (car other) (gr8s.raft.transport::raft-member-host (cdr other))
                                      (gr8s.raft.transport::raft-member-port (cdr other)))))))
           (dolist (m member-list) (gr8s.raft.transport::raft-member-start m))
           ;; A single leader emerges.
           (is (poll-until (lambda () (= 1 (count-if #'gr8s.raft.transport::raft-member-leader-p member-list)))))
           (let ((leader (find-if #'gr8s.raft.transport::raft-member-leader-p member-list)))
             (is (not (null leader)))
             ;; Propose on the leader; it replicates to every state machine.
             (gr8s.raft.transport::raft-member-propose leader '(:set "k" "v1"))
             (is (poll-until
                  (lambda ()
                    (every (lambda (kv) (equal "v1" (gethash "k" (cdr kv)))) kvs))))
             (dolist (kv kvs)
               (is (equal "v1" (gethash "k" (cdr kv))) "member ~A replicated k=v1" (car kv)))))
      (dolist (m member-list) (ignore-errors (gr8s.raft.transport::stop-raft-member m))))))

(in-suite raft-transport)
(test snapshot-roots-cover-dequeued-batches-and-release-after-delivery
  (dolist (failure '(nil t))
    (let* ((member (gr8s.raft.transport::make-raft-member :running t))
           (link (gr8s.raft.transport::make-raft-peer-link :id "peer"))
           (old (list :type :install-snapshot :state :old))
           (new (list :type :install-snapshot :state :new))
           (stub-original (symbol-function 'gr8s.raft.transport::raft-link-stub))
           (send-original (symbol-function 'gr8s.raft.transport::raft-link-send-snapshot)))
      (setf (gethash "peer" (gr8s.raft.transport::raft-member-links member)) link)
      (flet ((roots () (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
                        (gr8s.raft.transport::raft-member-snapshot-messages-unlocked member))))
        (unwind-protect
             (progn
               (signals error (gr8s.raft.transport::raft-member-snapshot-messages-unlocked member))
               (gr8s.raft.transport::raft-link-enqueue link old)
               (is (equal (list old) (roots)))
               (setf (symbol-function 'gr8s.raft.transport::raft-link-stub) (lambda (&rest args) (declare (ignore args)) :stub)
                     (symbol-function 'gr8s.raft.transport::raft-link-send-snapshot)
                     (lambda (incoming stub message &key recipient-role)
                       (declare (ignore stub recipient-role))
                       (is (eq incoming member))
                       (is (eq message old))
                       (is (null (gr8s.raft.transport::raft-peer-link-items link)))
                       (is (equal (list old) (roots)))
                       (gr8s.raft.transport::raft-link-enqueue link new)
                       (is (= 2 (length (roots))))
                       (setf (gr8s.raft.transport::raft-member-running member) nil)
                       (when failure (error "Injected snapshot delivery failure"))))
               (gr8s.raft.transport::raft-link-sender-loop member link)
               (is (null (gr8s.raft.transport::raft-peer-link-active-items link)))
               (is (equal (list new) (roots))))
          (setf (symbol-function 'gr8s.raft.transport::raft-link-stub) stub-original
                (symbol-function 'gr8s.raft.transport::raft-link-send-snapshot) send-original))))))

(test peer-receive-observation-follows-normal-current-term-dispatch
  (let* ((node (cl-raft::make-raft-node :id "local" :peers '("peer") :current-term 3
                                   :send-fn (lambda (&rest args) (declare (ignore args)))))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (link (gr8s.raft.transport::make-raft-peer-link :id "peer"))
         (message (list :type :append-entries :term 3 :from "peer" :prev-log-index 0
                        :prev-log-term 0 :entries nil :leader-commit 0)))
    (setf (gethash "peer" (gr8s.raft.transport::raft-member-links member)) link)
    (gr8s.raft.transport::raft-member-dispatch-message member message)
    (is (= 1 (gr8s.raft.transport::raft-peer-link-received-messages link)))
    (is (= 3 (gr8s.raft.transport::raft-peer-link-last-receive-term link)))
    (is (integerp (gr8s.raft.transport::raft-peer-link-last-receive-ticks link)))
    (let ((stale (copy-list message)))
      (setf (getf stale :term) 2)
      (gr8s.raft.transport::raft-member-dispatch-message member stale))
    (signals error
      (gr8s.raft.transport::raft-member-dispatch-message member '(:type :unknown :term 3 :from "peer")))
    (is (= 1 (gr8s.raft.transport::raft-peer-link-received-messages link)))
    ;; A retained physical link for a removed member must not keep producing
    ;; observations. Learners remain current configured members.
    (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
      (gr8s.raft::raft-configure node '(("local" . :voter) ("peer" . :learner)))
      (gr8s.raft.transport::raft-member-note-receive-unlocked member message)
      (is (= 2 (gr8s.raft.transport::raft-peer-link-received-messages link)))
      (gr8s.raft::raft-configure node '(("local" . :voter)))
      (gr8s.raft.transport::raft-member-note-receive-unlocked member message)
      (is (= 2 (gr8s.raft.transport::raft-peer-link-received-messages link)))
      (gr8s.raft.transport::raft-member-note-receive-unlocked
       member '(:type :append-entries :term 3 :from "unconfigured")))
    (is (= 1 (hash-table-count (gr8s.raft.transport::raft-member-links member))))))
