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

;;; podster-5vz.15: a committed-entry apply failure (RAFT-APPLY-ERROR, signalled
;;; by MAKE-STORE-RAFT-APPLY-FUNCTION) must never crash the thread that applies
;;; it. The library leaves LAST-APPLIED un-advanced on a signalling apply, so the
;;; entry retries; these threads (the gRPC Deliver handler and the gRPC/local
;;; propose paths) must survive. Only the typed condition is contained -- any
;;; other error still propagates. These unit tests stub RAFT-HANDLE-MESSAGE /
;;; RAFT-MEMBER-PROPOSE to force the apply outcome without a real committed log.

(test follower-dispatch-contains-apply-error-but-not-other-errors
  (let* ((node (cl-raft::make-raft-node :id "local" :peers '("peer") :current-term 3
                                        :send-fn (lambda (&rest args) (declare (ignore args)))))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (message (list :type :append-entries :term 3 :from "peer" :prev-log-index 0
                        :prev-log-term 0 :entries nil :leader-commit 0))
         (handle (symbol-function 'gr8s.raft.transport::raft-handle-message)))
    (unwind-protect
         (progn
           ;; A failing apply on the follower's Deliver thread is contained: no
           ;; reply (NIL), the thread lives, and the leader re-sends for retry.
           (setf (symbol-function 'gr8s.raft.transport::raft-handle-message)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (error 'gr8s.raft.transport:raft-apply-error
                          :underlying (make-condition 'simple-error
                                                      :format-control "injected apply failure"))))
           (let ((result :unset))
             (finishes (setf result (gr8s.raft.transport::raft-member-dispatch-message member message)))
             (is (null result) "a contained apply error dispatches to NIL (no reply)"))
           ;; Any non-apply error from the same path still propagates.
           (setf (symbol-function 'gr8s.raft.transport::raft-handle-message)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (error "unrelated handler failure")))
           (signals error
             (gr8s.raft.transport::raft-member-dispatch-message member message)))
      (setf (symbol-function 'gr8s.raft.transport::raft-handle-message) handle))))

(test propose-sync-reports-apply-failure-instead-of-crashing
  (let* ((node (cl-raft::make-raft-node :id "solo" :peers nil :current-term 1
                                        :send-fn (lambda (&rest args) (declare (ignore args)))))
         (member (gr8s.raft.transport::make-raft-member :node node))
         (propose (symbol-function 'gr8s.raft.transport::raft-member-propose)))
    (unwind-protect
         (progn
           ;; A single-voter leader applies inline inside RAFT-MEMBER-PROPOSE; a
           ;; failing apply must surface as a retriable :apply-failed non-commit
           ;; rather than unwind out of the proposing thread.
           (setf (symbol-function 'gr8s.raft.transport::raft-member-propose)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (error 'gr8s.raft.transport:raft-apply-error
                          :underlying (make-condition 'simple-error
                                                      :format-control "injected inline apply failure"))))
           (multiple-value-bind (result committed index)
               (gr8s.raft.transport::raft-member-propose-sync member '(:noop))
             (is (null result))
             (is (eq :apply-failed committed)
                 "an inline apply failure is reported as a retriable non-commit")
             (is (null index))))
      (setf (symbol-function 'gr8s.raft.transport::raft-member-propose) propose))))

;;; podster-2pm: a systemctl stop once hung forever in STOP-RAFT-MEMBER's
;;; JOIN-THREAD (unreachable peer mid-config-change) until systemd SIGABRT'd the
;;; process. Shutdown must finish within its deadline no matter what a worker
;;; thread is doing: a thread that will not exit is abandoned with a warning,
;;; never waited on indefinitely.

(test stop-raft-member-abandons-a-stuck-worker-thread
  (let* ((member (gr8s.raft.transport::make-raft-member :running t))
         (release nil)
         (stuck (bt:make-thread
                 (lambda () (loop until release do (sleep 0.05)))
                 :name "gr8s test stuck raft worker")))
    (setf (gr8s.raft.transport::raft-member-tick-thread member) stuck)
    (unwind-protect
         (let ((start (get-internal-real-time))
               (warned nil))
           (handler-bind ((warning (lambda (w) (setf warned t) (muffle-warning w))))
             (gr8s.raft.transport::stop-raft-member member :timeout 0.5))
           (let ((elapsed (/ (- (get-internal-real-time) start)
                             internal-time-units-per-second)))
             (is (< elapsed 5)
                 "stop returned in ~,1F seconds despite a thread that never exits" elapsed))
           (is-true warned "abandoning a worker thread is reported")
           (is-true (bt:thread-alive-p stuck)
                    "the stuck thread is abandoned, not killed"))
      (setf release t)
      (when (bt:thread-alive-p stuck) (bt:join-thread stuck)))))

(test stop-raft-member-joins-cooperative-workers-without-warning
  (let* ((member (gr8s.raft.transport::make-raft-member :running t))
         (worker (bt:make-thread
                  (lambda ()
                    (loop while (gr8s.raft.transport::raft-member-running member)
                          do (sleep 0.01)))
                  :name "gr8s test cooperative raft worker")))
    (setf (gr8s.raft.transport::raft-member-tick-thread member) worker)
    (let ((warned nil))
      (handler-bind ((warning (lambda (w) (setf warned t) (muffle-warning w))))
        (gr8s.raft.transport::stop-raft-member member))
      (is-false warned "a cooperative shutdown stays silent")
      (is-false (bt:thread-alive-p worker)))))

(test the-raft-clock-says-when-it-ran-late-and-where-the-time-went
  ;; A clock thread that stops for longer than the election timeout costs the
  ;; leader its place, and nothing used to say so.
  (is (null (gr8s.raft.transport::raft-clock-lateness-report 1/20 0.05 0.0 0.01 0.0))
      "an ordinary pass is not reported")
  (is (null (gr8s.raft.transport::raft-clock-lateness-report 1/20 0.05 0.2 0.2 0.0)))
  (let ((report (gr8s.raft.transport::raft-clock-lateness-report 1/20 0.05 0.3 5.7 0.4)))
    (is (search "6.0s late" report))
    (is (search "the tick 5.7s" report) "the slow part is named")
    (is (search "the member lock 0.3s" report))
    (is (search "0.4s of that pass in GC" report))
    (is (null (search "held by" report)) "no holder is claimed when none was seen"))
  (is (search "the member lock 2.5s to get (held by gr8s ha compaction, grpc worker)"
              (gr8s.raft.transport::raft-clock-lateness-report
               1/20 0.05 2.5 0.0 0.0 '("gr8s ha compaction" "grpc worker")))
      "whoever held the lock is named")
  (is (search "sleep took 3.0s"
              (gr8s.raft.transport::raft-clock-lateness-report 1/20 3.0 0.0 0.0 2.9))
      "a stop-the-world stall shows up as a sleep that overran"))

(test a-change-of-raft-standing-is-reported-once
  (is (null (gr8s.raft.transport::raft-standing-report "cp1" '(:leader 3 "cp1") '(:leader 3 "cp1"))))
  (is (equal "gr8s raft: cp1 is now follower in term 4, leader cp2 (was leader in term 3, leader cp1)"
             (gr8s.raft.transport::raft-standing-report "cp1" '(:leader 3 "cp1") '(:follower 4 "cp2"))))
  (is (equal "gr8s raft: cp1 is now candidate in term 5, leader unknown (was follower in term 4, leader cp2)"
             (gr8s.raft.transport::raft-standing-report "cp1" '(:follower 4 "cp2") '(:candidate 5 nil))))
  (is (equal "gr8s raft: cp1 is now follower in term 1, leader unknown"
             (gr8s.raft.transport::raft-standing-report "cp1" nil '(:follower 1 nil)))
      "the first report has nothing to compare with")
  (let ((node (cl-raft::make-raft-node :id "cp1" :role :leader :leader-id "cp1")))
    (is (equal '(:leader 0 "cp1") (gr8s.raft.transport::raft-standing node)))))

(test the-clock-names-who-held-the-member-lock
  (let* ((member (gr8s.raft.transport::make-raft-member))
         (holding (bt:make-semaphore)) (release (bt:make-semaphore))
         (holder (bt:make-thread
                  (lambda ()
                    (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
                      (bt:signal-semaphore holding)
                      (bt:wait-on-semaphore release :timeout 10)))
                  :name "slow lock holder")))
    (is-true (bt:wait-on-semaphore holding :timeout 5))
    (let ((releaser (bt:make-thread (lambda () (sleep 0.6) (bt:signal-semaphore release)))))
      (is (equal '("slow lock holder")
                 (gr8s.raft.transport::grab-member-lock-noting-holders member)))
      (sb-thread:release-mutex (gr8s.raft.transport::raft-member-lock member))
      (bt:join-thread releaser))
    (bt:join-thread holder)
    ;; An uncontended lock is taken at once and names nobody.
    (is (null (gr8s.raft.transport::grab-member-lock-noting-holders member)))
    (sb-thread:release-mutex (gr8s.raft.transport::raft-member-lock member))))

(test a-failed-snapshot-transfer-is-reported-but-not-on-every-retry
  ;; podster-kiw: a joiner waited for recovery for ten minutes while neither its
  ;; journal nor the leader's mentioned a transfer.
  (let ((failure (make-condition 'simple-error :format-control "Artifact source checksum mismatch")))
    (let ((report (gr8s.raft.transport::raft-snapshot-send-failure-report "gr8s2" failure nil)))
      (is (search "snapshot transfer to gr8s2 failed" report))
      (is (search "Artifact source checksum mismatch" report)))
    (is (search "failed at byte 65536 of 4000000 and"
                (gr8s.raft.transport::raft-snapshot-send-failure-report "gr8s2" failure nil '(65536 4000000))))
    (is (search "after sending all 4000000 bytes, waiting for it to be installed"
                (gr8s.raft.transport::raft-snapshot-send-failure-report "gr8s2" failure nil '(4000000 4000000))))
    (is (null (gr8s.raft.transport::raft-snapshot-send-failure-report "gr8s2" failure 2)))
    (is (stringp (gr8s.raft.transport::raft-snapshot-send-failure-report
                  "gr8s2" failure gr8s.raft.transport::*raft-snapshot-failure-report-seconds*)))))
