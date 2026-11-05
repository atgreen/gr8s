;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
           (a (gr8s::start-raft-member "a" :apply-fn (lambda (c) (declare (ignore c)) nil)
                                           :credentials credentials))
           (stop nil)
           (witness-thread nil))
      (unwind-protect
           (progn
             (gr8s::raft-cluster-init a)
             (gr8s::raft-member-start a)
             (is (poll-until (lambda () (gr8s::raft-member-leader-p a))))
             ;; Run the command exactly as the CLI dispatcher would, but with a
             ;; test-controlled stop predicate instead of the signal flag.
             (setf witness-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s::run-witness
                       (list :member-id "w1" :node-name "w1"
                             :join (format nil "127.0.0.1:~D" (gr8s::raft-member-port a))
                             :listen "127.0.0.1" :port 0
                             :token (gr8s:create-join-token raft-pki "w1")
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
             (let ((root (merge-pathnames "raft/" (uiop:ensure-directory-pathname state))))
               (is (probe-file (gr8s::raft-member-certificate-path root)))
               (is (null (probe-file (gr8s::raft-ca-key-path root)))
                   "a witness never leads or admits members, so it doesn't get the CA key")
               (is (= #o600 (logand #o777 (sb-posix:stat-mode
                                           (sb-posix:stat (namestring (merge-pathnames "witness.log" root)))))))))
        (setf stop t)
        (when witness-thread (ignore-errors (bt:join-thread witness-thread)))
        (ignore-errors (gr8s::stop-raft-member a))))))
