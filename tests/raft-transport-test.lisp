;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise the ag-gRPC Raft transport (src/raft-transport.lisp): the wire
;;;; encoding round-trips a message (including log entries), and three real
;;;; members over real gRPC elect a leader and replicate a proposal to every
;;;; state machine.

(in-package #:gr8s/tests)
(def-suite raft-transport :in gr8s)
(in-suite raft-transport)

(test raft-transport-serialization-round-trips
  (let* ((entries (list (gr8s::make-raft-entry :index 4 :term 2 :command '(:set "x" 7))
                        (gr8s::make-raft-entry :index 5 :term 2 :command '(:cas "y" nil "Z"))))
         (msg (list :type :append-entries :term 2 :from "b"
                    :prev-log-index 3 :prev-log-term 1 :entries entries :leader-commit 3))
         (back (gr8s::octets->raft-message (gr8s::raft-message->octets msg))))
    (is (eq :append-entries (getf back :type)))
    (is (= 2 (getf back :term)))
    (is (equal "b" (getf back :from)))
    (is (= 3 (getf back :prev-log-index)))
    (is (= 2 (length (getf back :entries))))
    (let ((e (second (getf back :entries))))
      (is (= 5 (gr8s::raft-entry-index e)))
      (is (= 2 (gr8s::raft-entry-term e)))
      (is (equal '(:cas "y" nil "Z") (gr8s::raft-entry-command e))))))

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
                           (gr8s::start-raft-member
                            id :apply-fn (let ((kv (cdr (assoc id kvs :test #'equal))))
                                           (lambda (command) (raft-kv-apply kv command))))))
                   ids))
         (member-list (mapcar #'cdr members)))
    (unwind-protect
         (progn
           ;; Wire every member to the other two, then start the clocks.
           (dolist (entry members)
             (let ((self (car entry)))
               (gr8s::raft-member-set-peers
                (cdr entry)
                (loop for other in members
                      unless (equal (car other) self)
                        collect (list (car other) (gr8s::raft-member-host (cdr other))
                                      (gr8s::raft-member-port (cdr other)))))))
           (dolist (m member-list) (gr8s::raft-member-start m))
           ;; A single leader emerges.
           (is (poll-until (lambda () (= 1 (count-if #'gr8s::raft-member-leader-p member-list)))))
           (let ((leader (find-if #'gr8s::raft-member-leader-p member-list)))
             (is (not (null leader)))
             ;; Propose on the leader; it replicates to every state machine.
             (gr8s::raft-member-propose leader '(:set "k" "v1"))
             (is (poll-until
                  (lambda ()
                    (every (lambda (kv) (equal "v1" (gethash "k" (cdr kv)))) kvs))))
             (dolist (kv kvs)
               (is (equal "v1" (gethash "k" (cdr kv))) "member ~A replicated k=v1" (car kv)))))
      (dolist (m member-list) (ignore-errors (gr8s::stop-raft-member m))))))
