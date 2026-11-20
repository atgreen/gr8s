;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; A witness stores log entries it cannot read (podster-00c), hands them to the
;;;; surviving voter when the leader fails (podster-f15), and is given no other
;;;; way into the cluster's state.

(in-package #:gr8s/tests)
(def-suite raft-seal :in gr8s)
(in-suite raft-seal)

(defun seal-test-key (&optional (secret "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDrNmQ0cluster0ca0key0for0tests0only
-----END EC PRIVATE KEY-----
"))
  (gr8s.raft.transport::make-raft-seal-key secret))

(test a-sealed-command-opens-only-at-its-own-place-under-its-own-key
  (let* ((key (seal-test-key))
         (command '(:core-delta :resource "secrets" :name "db" :data "hunter2"))
         (sealed (gr8s.raft.transport::raft-seal-command key 7 3 command)))
    (is (eq :sealed (first sealed)))
    (is (not (search "hunter2" (prin1-to-string sealed))))
    (is (equal command (gr8s.raft.transport::raft-unseal-command key 7 3 sealed)))
    (is (not (equal sealed (gr8s.raft.transport::raft-seal-command key 7 3 command)))
        "each seal has its own nonce")
    (flet ((refused (key index term sealed)
             (handler-case (progn (gr8s.raft.transport::raft-unseal-command key index term sealed) nil)
               (gr8s.raft.transport::raft-seal-error (condition) (princ-to-string condition)))))
      (is (search "does not verify" (refused key 8 3 sealed)) "another index")
      (is (search "does not verify" (refused key 7 4 sealed)) "another term")
      (is (search "does not verify"
                  (refused key 7 3 (list :sealed (second sealed)
                                         (let ((text (copy-seq (third sealed))))
                                           (setf (char text 20) (if (char= #\A (char text 20)) #\B #\A))
                                           text))))
          "an altered seal")
      (is (search "was sealed under key" (refused (seal-test-key "another cluster's CA key") 7 3 sealed)))
      (is (search "not a sealed command" (refused key 7 3 command))))
    (is (equal (gr8s.raft.transport::raft-seal-key-id key)
               (gr8s.raft.transport::raft-seal-key-id
                (seal-test-key (format nil "-----BEGIN EC PRIVATE KEY-----~C~CMHcCAQEEIDrNmQ0cluster0ca0key0for0tests0only~%-----END EC PRIVATE KEY-----"
                                       #\Return #\Newline))))
        "the same key file with other line endings derives the same key")))

(test a-witness-is-sent-data-sealed-and-membership-readable
  (let* ((key (seal-test-key))
         (config '(:raft-config :members (("a" . :voter) ("w" . :witness))))
         (data '(:pod-delta :name "p"))
         (message (list :type :append-entries :term 2 :from "a" :prev-log-index 4 :prev-log-term 2
                        :entries (list (cl-raft:make-raft-entry :index 5 :term 2 :command config)
                                       (cl-raft:make-raft-entry :index 6 :term 2 :command '(:raft-barrier))
                                       (cl-raft:make-raft-entry :index 7 :term 2 :command data))
                        :leader-commit 4))
         (sealed (gr8s.raft.transport::raft-seal-message key message))
         (commands (mapcar #'cl-raft:raft-entry-command (getf sealed :entries))))
    (is (equal config (first commands)))
    (is (equal '(:raft-barrier) (second commands)))
    (is (eq :sealed (first (third commands))))
    (is (equal data (cl-raft:raft-entry-command (third (getf message :entries))))
        "the leader's own message is untouched")
    (is (eq sealed (gr8s.raft.transport::raft-seal-message key sealed)) "sealing twice changes nothing")
    (let ((heartbeat (list :type :append-entries :term 2 :from "a" :entries nil)))
      (is (eq heartbeat (gr8s.raft.transport::raft-seal-message key heartbeat))))
    ;; A witness has no key and keeps what it is given.
    (is (eq sealed (gr8s.raft.transport::raft-open-message nil sealed nil)))
    ;; A voter opens it, from a voter or from a witness...
    (is (equal data (cl-raft:raft-entry-command
                     (third (getf (gr8s.raft.transport::raft-open-message key sealed nil) :entries)))))
    (let ((relayed (list :type :append-entries :from "w" :term 3
                         :entries (rest (getf sealed :entries)))))
      (is (equal (list '(:raft-barrier) data)
                 (mapcar #'cl-raft:raft-entry-command
                         (getf (gr8s.raft.transport::raft-open-message key relayed t) :entries)))))
    ;; ...but takes from a witness nothing a voter did not seal, except a barrier:
    ;; not data in the clear, and not a membership change.
    (signals gr8s.raft.transport::raft-seal-error
      (gr8s.raft.transport::raft-open-message key message t))
    (signals gr8s.raft.transport::raft-seal-error
      (gr8s.raft.transport::raft-open-message key sealed t))
    (signals gr8s.raft.transport::raft-seal-error
      (gr8s.raft.transport::raft-open-message
       key (list :type :append-entries :from "w" :term 2
                 :entries (list (cl-raft:make-raft-entry :index 5 :term 2 :command config)))
       t))
    (is (gr8s.raft.transport::raft-open-message
         key (list :type :append-entries :from "w" :term 2
                   :entries (list (cl-raft:make-raft-entry :index 5 :term 2 :command '(:raft-barrier))))
         t))
    (is (eq message (gr8s.raft.transport::raft-open-message key message nil))
        "a voter's unsealed entries are a voter's")))

(defun call-with-two-voters-and-a-witness (function)
  "Call FUNCTION with members a (leading) and b, witness w, and the voters' stores."
  (let* ((key (seal-test-key))
         (kvs (list (cons "a" (make-hash-table :test 'equal)) (cons "b" (make-hash-table :test 'equal))))
         (voter (lambda (id)
                  (gr8s.raft.transport::start-raft-member
                   id :seal-key key
                      :apply-fn (let ((kv (cdr (assoc id kvs :test #'equal))))
                                  (lambda (command) (raft-kv-apply kv command))))))
         (a (funcall voter "a")) (b (funcall voter "b"))
         (w (gr8s.raft.transport::start-raft-member "w" :initial-role :witness))
         (all (list a b w)))
    (unwind-protect
         (progn
           (gr8s.raft.transport::raft-cluster-init a)
           (gr8s.raft.transport::raft-member-start a)
           (poll-until (lambda () (gr8s.raft.transport::raft-member-leader-p a)))
           (gr8s.raft.transport::raft-member-start b)
           (gr8s.raft.transport::raft-cluster-join b (gr8s.raft.transport::raft-member-host a)
                                                   (gr8s.raft.transport::raft-member-port a))
           (poll-until (lambda () (eq :voter (cl-raft::raft-node-self-role (gr8s.raft.transport::raft-member-node b)))))
           (gr8s.raft.transport::raft-member-start w)
           (poll-until (lambda ()
                         (gr8s.raft.transport::raft-cluster-join
                          w (gr8s.raft.transport::raft-member-host a) (gr8s.raft.transport::raft-member-port a)
                          :role :witness)))
           (poll-until (lambda () (eq :witness (cl-raft::raft-node-self-role (gr8s.raft.transport::raft-member-node w)))))
           (funcall function a b w kvs))
      (dolist (member all) (ignore-errors (gr8s.raft.transport::stop-raft-member member))))))

(defun seal-test-log-commands (member)
  (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
    (map 'list #'cl-raft:raft-entry-command (cl-raft::raft-node-log (gr8s.raft.transport::raft-member-node member)))))

(test a-witness-stores-what-it-cannot-read
  (call-with-two-voters-and-a-witness
   (lambda (a b w kvs)
     (is (eq t (nth-value 1 (gr8s.raft.transport::raft-member-propose-sync a '(:set "token" "hunter2")))))
     (is (poll-until (lambda () (equal "hunter2" (gethash "token" (cdr (assoc "b" kvs :test #'equal)))))))
     (is (poll-until (lambda ()
                       (= (cl-raft::raft-last-log-index (gr8s.raft.transport::raft-member-node w))
                          (cl-raft::raft-last-log-index (gr8s.raft.transport::raft-member-node a))))))
     (is (member '(:set "token" "hunter2") (seal-test-log-commands b) :test #'equal)
         "a voter's log holds the write")
     (let ((held (seal-test-log-commands w)))
       (is (not (search "hunter2" (prin1-to-string held))) "the witness's does not")
       (is (find :sealed held :key (lambda (command) (and (consp command) (first command)))))
       (is (every (lambda (command)
                    (member (and (consp command) (first command)) '(:sealed :raft-config :raft-barrier)))
                  held)
           "it holds sealed commands, membership changes and barriers, and nothing else")))))

(test a-witness-hands-the-surviving-voter-the-writes-it-lacks
  ;; podster-f15, over the real transport: the leader and the witness commit a
  ;; write the other voter never received, and then the leader dies.
  (call-with-two-voters-and-a-witness
   (lambda (a b w kvs)
     (let ((links (gr8s.raft.transport::raft-member-links a)))
       (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock a)) (remhash "b" links)))
     (is (eq t (nth-value 1 (gr8s.raft.transport::raft-member-propose-sync a '(:set "k" "acknowledged")))))
     (is (null (gethash "k" (cdr (assoc "b" kvs :test #'equal)))) "b never received it")
     (gr8s.raft.transport::stop-raft-member a)
     (is (poll-until (lambda () (gr8s.raft.transport::raft-member-leader-p b)) :timeout 30)
         "the surviving voter becomes leader")
     (is (poll-until (lambda () (equal "acknowledged" (gethash "k" (cdr (assoc "b" kvs :test #'equal)))))
                     :timeout 10)
         "holding the write the client was told is saved")
     (is (not (gr8s.raft.transport::raft-member-leader-p w)))
     (is (eq t (nth-value 1 (gr8s.raft.transport::raft-member-propose-sync b '(:set "k2" "after")))))
     (is (equal "after" (gethash "k2" (cdr (assoc "b" kvs :test #'equal))))))))

(test only-a-voter-may-write-or-reach-a-node-through-another-member
  (call-with-two-voters-and-a-witness
   (lambda (a b w kvs)
     (declare (ignore b w kvs))
     (flet ((refused (peer)
              (handler-case (progn (gr8s.raft.transport::raft-member-require-key-holder a peer "propose a write") nil)
                (gr8s.security::pki-error (condition) (gr8s.security::pki-error-reason condition)))))
       (is (null (refused "b")))
       (is (equal "member-role-forbidden" (refused "w")))
       (is (equal "member-role-forbidden" (refused "stranger")))
       (is (null (refused nil)) "a member running without credentials authenticates nobody")))))
