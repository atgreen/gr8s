;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The 'gr8s witness' command (podster-c2d.9): a headless Raft voting member
;;;; that joins an existing cluster as a quorum tie-breaker. The command runs
;;;; RUN-WITNESS against a real leader and we confirm, from the leader's view,
;;;; that the witness joined in the witness role.

(in-package #:gr8s/tests)
(def-suite witness-command :in gr8s)
(in-suite witness-command)

(test witness-command-joins-a-cluster-as-a-voting-tie-breaker
  (with-raft-temp-dir (walpath)
    (let* ((state (namestring (uiop:pathname-directory-pathname walpath)))
           (credentials (gr8s.security::ensure-raft-founder-credentials
                         (merge-pathnames "leader/" (uiop:pathname-directory-pathname walpath)) "a"))
           (raft-pki (gr8s.security::raft-credentials-pki credentials))
           (a (gr8s.raft.transport::start-raft-member "a" :credentials credentials))
           (orphan-member (gr8s.raft.transport::make-raft-member :node (cl-raft::make-raft-node :id "orphan")
                            :snapshot-directory (merge-pathnames "raft/" (uiop:ensure-directory-pathname state))))
           (orphan-root nil)
           (boundary nil)
           (stop nil)
           (witness-thread nil))
      (unwind-protect
           (progn
             (gr8s.raft.transport::raft-cluster-init a)
             (gr8s.raft.transport::raft-member-start a)
             (is (poll-until (lambda () (gr8s.raft.transport::raft-member-leader-p a))))
             (setf orphan-root (gr8s.raft.transport::raft-member-snapshot-root-unlocked orphan-member))
             (gr8s.raft.transport::raft-snapshot-create-file (merge-pathnames "in-orphan.snapshot" orphan-root))
             (sb-posix:close (gr8s.raft.transport::raft-member-snapshot-owner-fd orphan-member))
             (setf (gr8s.raft.transport::raft-member-snapshot-owner-fd orphan-member) nil
                   (gr8s.raft.transport::raft-member-snapshot-root orphan-member) nil)
             (multiple-value-bind (value committed) (gr8s.raft.transport::raft-member-propose-sync a '(:noop))
               (declare (ignore value)) (is (eq t committed)))
             (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock a))
               (setf boundary (cl-raft::raft-node-last-applied (gr8s.raft.transport::raft-member-node a)))
               (cl-raft::raft-compact (gr8s.raft.transport::raft-member-node a) boundary))
             ;; Run the command exactly as the CLI dispatcher would, but with a
             ;; test-controlled stop predicate instead of the signal flag.
             (setf witness-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s.server::run-witness
                       (list :member-id "w1" :node-name "w1"
                             :join (format nil "127.0.0.1:~D" (gr8s.raft.transport::raft-member-port a))
                             :listen "127.0.0.1" :port 0
                             :token (gr8s.security::create-join-token raft-pki "w1" :role :witness)
                             :ca-pin (gr8s.security::cluster-pki-ca-fingerprint raft-pki)
                             :state-directory state)
                       :stop-predicate (lambda () stop)))
                    :name "gr8s test witness"))
             (is (poll-until
                  (lambda () (member "w1" (cl-raft::raft-node-peers (gr8s.raft.transport::raft-member-node a)) :test #'equal))
                  :timeout 15)
                 "the witness command joins the cluster")
             (is (eq :witness (cl-raft::raft-member-role (gr8s.raft.transport::raft-member-node a) "w1"))
                 "it joins in the witness role, counting toward quorum without leading")
             (is (poll-until
                  (lambda () (>= (gethash "w1" (cl-raft::raft-node-match-index (gr8s.raft.transport::raft-member-node a)) 0) (1+ boundary)))
                  :timeout 20) "the actual witness command installs the snapshot and membership tail")
             (is (not (probe-file orphan-root)))
             (let ((root (merge-pathnames "raft/" (uiop:ensure-directory-pathname state))))
               (is (= boundary (cl-raft::raft-recovered-snapshot-index
                                (cl-raft::load-raft-log (merge-pathnames "witness.log" root)))))
               (is (probe-file (gr8s.security::raft-member-certificate-path root)))
               (is (null (probe-file (gr8s.security::raft-ca-key-path root)))
                   "a witness never leads or admits members, so it doesn't get the CA key")
               (is (= #o600 (logand #o777 (sb-posix:stat-mode
                                           (sb-posix:stat (namestring (merge-pathnames "witness.log" root)))))))))
        (setf stop t)
        (when witness-thread (ignore-errors (bt:join-thread witness-thread)))
        (gr8s.raft.transport::raft-member-close-snapshot-root orphan-member)
        (ignore-errors (gr8s.raft.transport::stop-raft-member a))))))

(defun send-witness-vote-request (member term candidate)
  (let ((channel (gr8s.security::make-raft-channel nil "127.0.0.1" (gr8s.raft.transport::raft-member-port member) 2)))
    (unwind-protect
         (gr8s.raft.transport::raft-link-deliver-message
          (gr8s.node.v1::make-raft-transport-stub channel)
          (list :type :request-vote :term term :from candidate
                :last-log-index 1 :last-log-term 17))
      (ag-grpc:channel-close channel))))

(test recovered-witness-does-not-double-vote-after-repeated-restarts
  (with-raft-temp-dir (path)
    (let ((storage (cl-raft::open-file-raft-storage path)))
      (gr8s.raft::raft-storage-save-hard-state storage 17 "candidate-a")
      (gr8s.raft::raft-storage-append-entry storage (cl-raft::make-raft-entry :index 1 :term 17 :command '(:noop)))
      (gr8s.raft::close-file-raft-storage storage))
    (let ((first (gr8s.raft.transport::start-raft-member "recovered-witness" :storage-path path :initial-role :witness))
          (stream nil))
      (unwind-protect
           (let ((node (gr8s.raft.transport::raft-member-node first)))
             (setf stream (gr8s.raft::file-raft-storage-stream (gr8s.raft::raft-node-storage node)))
             (is (= 17 (cl-raft::raft-node-current-term node)))
             (is (equal "candidate-a" (cl-raft::raft-node-voted-for node)))
             (is (= 1 (cl-raft::raft-last-log-index node)))
             (send-witness-vote-request first 17 "candidate-b")
             (is (equal "candidate-a" (cl-raft::raft-node-voted-for node)))
             (send-witness-vote-request first 18 "candidate-b")
             (is (equal "candidate-b" (cl-raft::raft-node-voted-for node))))
        (gr8s.raft.transport::stop-raft-member first))
      (is-false (open-stream-p stream)))
    (dotimes (attempt 2)
      (let ((member (gr8s.raft.transport::start-raft-member "recovered-witness" :storage-path path :initial-role :witness)))
        (unwind-protect
             (let ((node (gr8s.raft.transport::raft-member-node member)))
               (is (= 18 (cl-raft::raft-node-current-term node)))
               (is (equal "candidate-b" (cl-raft::raft-node-voted-for node)))
               (is (= 1 (cl-raft::raft-last-log-index node)))
               (send-witness-vote-request member 18 "candidate-c")
               (is (equal "candidate-b" (cl-raft::raft-node-voted-for node)))
               (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
                 (dotimes (tick 100) (cl-raft::raft-tick node)))
               (is (eq :follower (cl-raft::raft-node-role node)))
               (is (= 18 (cl-raft::raft-node-current-term node))))
          (gr8s.raft.transport::stop-raft-member member))))))

(test witness-command-reopens-its-wal-and-rejoins-with-existing-credentials
  (with-raft-temp-dir (walpath)
    (let* ((state (uiop:pathname-directory-pathname walpath))
           (credentials (gr8s.security::ensure-raft-founder-credentials (merge-pathnames "leader/" state) "leader"))
           (pki (gr8s.security::raft-credentials-pki credentials))
           (leader (gr8s.raft.transport::start-raft-member "leader" :credentials credentials))
           (options nil) (thread nil) (stop nil) (outcome nil) (previous-index 0))
      (unwind-protect
           (progn
             (gr8s.raft.transport::raft-cluster-init leader)
             (gr8s.raft.transport::raft-member-start leader)
             (is (poll-until (lambda () (gr8s.raft.transport::raft-member-leader-p leader))))
             (setf options (list :member-id "restart-witness" :node-name "restart-witness"
                           :join (format nil "127.0.0.1:~D" (gr8s.raft.transport::raft-member-port leader))
                           :listen "127.0.0.1" :port 0 :state-directory (namestring state)
                           :token (gr8s.security::create-join-token pki "restart-witness" :role :witness)
                           :ca-pin (gr8s.security::cluster-pki-ca-fingerprint pki)))
             (dotimes (cycle 2)
               (setf stop nil outcome nil
                     thread (bt:make-thread
                             (lambda ()
                               (setf outcome (handler-case
                                                 (gr8s.server::run-witness options :stop-predicate (lambda () stop))
                                               (error (condition) (princ-to-string condition)))))
                             :name "gr8s restart witness command"))
               (is (poll-until
                    (lambda () (eq :witness (gethash "restart-witness"
                                 (cl-raft::raft-node-roles (gr8s.raft.transport::raft-member-node leader)))))
                    :timeout 20))
               ;; The new index needs this cycle's live witness acknowledgement;
               ;; match-index from the previous incarnation cannot commit it.
               (multiple-value-bind (value committed index)
                   (gr8s.raft.transport::raft-member-propose-sync leader (list :noop cycle) :timeout 20)
                 (declare (ignore value))
                 (unless (eq t committed)
                   (error "Witness restart cycle ~D failed to commit: ~S; command outcome: ~S" cycle committed outcome))
                 (is (eq t committed))
                 (is (> index previous-index))
                 (setf previous-index index))
               (setf (getf options :port)
                     (second (gethash "restart-witness"
                                      (cl-raft::raft-node-peer-addresses (gr8s.raft.transport::raft-member-node leader)))))
               (setf stop t)
               (bt:join-thread thread)
               (setf thread nil)
               (is (eql 0 outcome))
               (let ((recovered (cl-raft::load-raft-log (merge-pathnames "raft/witness.log" state))))
                 (is (plusp (cl-raft::raft-recovered-term recovered)))
                 (is (>= (cl-raft::raft-entry-index (car (last (cl-raft::raft-recovered-entries recovered))))
                         previous-index)))
               ;; Rejoin uses the saved member certificate, not a new token.
               (setf (getf options :token) nil)))
        (setf stop t)
        (when thread (ignore-errors (bt:join-thread thread)))
        (gr8s.raft.transport::stop-raft-member leader)))))

(test witness-hard-state-survives-repeated-sigkill-process-restarts
  (with-raft-temp-dir (path)
    (let* ((root (uiop:pathname-directory-pathname path))
           (script (merge-pathnames "witness-child.lisp" root))
           (ready (merge-pathnames "witness-ready.txt" root))
           (process nil))
      (ensure-directories-exist script)
      (with-open-file (out script :direction :output :if-does-not-exist :create)
        (format out "(require :asdf)~%(asdf:load-asd ~S)~%(asdf:load-system :gr8s)~%"
                (namestring (merge-pathnames "gr8s.asd" (asdf:system-source-directory :gr8s))))
        (format out "(let ((member (gr8s.raft.transport::start-raft-member ~S :storage-path ~S :initial-role :witness)))~%"
                "crash-witness" (namestring path))
        (format out "(gr8s.security::write-private-text-atomically ~S (write-to-string (gr8s.raft.transport::raft-member-port member)))~%"
                (namestring ready))
        (write-line "(loop (sleep 1)))" out))
      (unwind-protect
           (dotimes (cycle 3)
             (when (probe-file ready) (delete-file ready))
             (let ((log (merge-pathnames (format nil "witness-child-~D.log" cycle) root)))
               (setf process (sb-ext:run-program "sbcl"
                              (list "--noinform" "--no-sysinit" "--no-userinit"
                            "--load" (namestring (merge-pathnames "scripts/bootstrap.lisp"
                                                                (asdf:system-source-directory :gr8s)))
                            "--non-interactive" "--load" (namestring script))
                              :search t :wait nil :input nil :output log :error :output))
               (poll-until (lambda () (or (probe-file ready) (not (sb-ext:process-alive-p process)))) :timeout 60)
               (unless (probe-file ready)
                 (error "Witness child failed to start:~%~A" (uiop:read-file-string log))))
             (let ((remote (gr8s.raft.transport::make-raft-member :port (parse-integer (uiop:read-file-string ready)))))
               (send-witness-vote-request remote (if (= cycle 2) 21 20)
                                          (if (zerop cycle) "candidate-a" "candidate-b")))
             (let ((recovered (cl-raft::load-raft-log path)))
               (is (= (if (= cycle 2) 21 20) (cl-raft::raft-recovered-term recovered)))
               (is (equal (if (= cycle 2) "candidate-b" "candidate-a")
                          (cl-raft::raft-recovered-vote recovered))))
             (sb-ext:process-kill process 9)
             (sb-ext:process-wait process)
             (is (eq :signaled (sb-ext:process-status process)))
             (sb-ext:process-close process)
             (setf process nil))
        (when process
          (when (sb-ext:process-alive-p process)
            (sb-ext:process-kill process 9)
            (sb-ext:process-wait process))
          (sb-ext:process-close process))))))
