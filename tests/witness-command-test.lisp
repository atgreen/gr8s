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
           (credentials (gr8s::ensure-raft-founder-credentials
                         (merge-pathnames "leader/" (uiop:pathname-directory-pathname walpath)) "a"))
           (raft-pki (gr8s::raft-credentials-pki credentials))
           (a (gr8s::start-raft-member "a" :credentials credentials))
           (orphan-member (gr8s::make-raft-member :node (gr8s::make-raft-node :id "orphan")
                            :snapshot-directory (merge-pathnames "raft/" (uiop:ensure-directory-pathname state))))
           (orphan-root nil)
           (boundary nil)
           (stop nil)
           (witness-thread nil))
      (unwind-protect
           (progn
             (gr8s::raft-cluster-init a)
             (gr8s::raft-member-start a)
             (is (poll-until (lambda () (gr8s::raft-member-leader-p a))))
             (setf orphan-root (gr8s.raft.transport::raft-member-snapshot-root-unlocked orphan-member))
             (gr8s.raft.transport::raft-snapshot-create-file (merge-pathnames "in-orphan.snapshot" orphan-root))
             (sb-posix:close (gr8s.raft.transport::raft-member-snapshot-owner-fd orphan-member))
             (setf (gr8s.raft.transport::raft-member-snapshot-owner-fd orphan-member) nil
                   (gr8s.raft.transport::raft-member-snapshot-root orphan-member) nil)
             (multiple-value-bind (value committed) (gr8s::raft-member-propose-sync a '(:noop))
               (declare (ignore value)) (is (eq t committed)))
             (bt:with-lock-held ((gr8s::raft-member-lock a))
               (setf boundary (gr8s::raft-node-last-applied (gr8s::raft-member-node a)))
               (gr8s::raft-compact (gr8s::raft-member-node a) boundary))
             ;; Run the command exactly as the CLI dispatcher would, but with a
             ;; test-controlled stop predicate instead of the signal flag.
             (setf witness-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s::run-witness
                       (list :member-id "w1" :node-name "w1"
                             :join (format nil "127.0.0.1:~D" (gr8s::raft-member-port a))
                             :listen "127.0.0.1" :port 0
                             :token (gr8s:create-join-token raft-pki "w1" :role :witness)
                             :ca-pin (gr8s::cluster-pki-ca-fingerprint raft-pki)
                             :state-directory state)
                       :stop-predicate (lambda () stop)))
                    :name "gr8s test witness"))
             (is (poll-until
                  (lambda () (member "w1" (gr8s::raft-node-peers (gr8s::raft-member-node a)) :test #'equal))
                  :timeout 15)
                 "the witness command joins the cluster")
             (is (eq :witness (gr8s::raft-member-role (gr8s::raft-member-node a) "w1"))
                 "it joins in the witness role, counting toward quorum without leading")
             (is (poll-until
                  (lambda () (>= (gethash "w1" (gr8s::raft-node-match-index (gr8s::raft-member-node a)) 0) (1+ boundary)))
                  :timeout 20) "the actual witness command installs the snapshot and membership tail")
             (is (not (probe-file orphan-root)))
             (let ((root (merge-pathnames "raft/" (uiop:ensure-directory-pathname state))))
               (is (= boundary (gr8s::raft-recovered-snapshot-index
                                (gr8s::load-raft-log (merge-pathnames "witness.log" root)))))
               (is (probe-file (gr8s::raft-member-certificate-path root)))
               (is (null (probe-file (gr8s::raft-ca-key-path root)))
                   "a witness never leads or admits members, so it doesn't get the CA key")
               (is (= #o600 (logand #o777 (sb-posix:stat-mode
                                           (sb-posix:stat (namestring (merge-pathnames "witness.log" root)))))))))
        (setf stop t)
        (when witness-thread (ignore-errors (bt:join-thread witness-thread)))
        (gr8s.raft.transport::raft-member-close-snapshot-root orphan-member)
        (ignore-errors (gr8s::stop-raft-member a))))))
