;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Linearizable reads (podster-gxi): a member answers a read that must be
;;;; current only after a leader that a quorum follows has told it how far to
;;;; catch up, and refuses when it can reach no such leader.

(in-package #:gr8s/tests)
(def-suite raft-read :in gr8s)
(in-suite raft-read)

(defun read-test-node (member) (gr8s.raft.transport::raft-member-node member))

(defun read-test-membership-settled-p (members)
  "True once every member is a voter and has applied the leader's whole log. A
membership entry carries the members' addresses, so one still in flight would
undo a test's change to a member's address book."
  (flet ((observe (member function)
           (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
             (funcall function (read-test-node member)))))
    (let ((last (observe (first members)
                         (lambda (leader)
                           (and (zerop (hash-table-count (cl-raft::raft-node-promotion-intents leader)))
                                (every (lambda (member)
                                         (eq :voter (gethash (cl-raft::raft-node-id (read-test-node member))
                                                             (cl-raft::raft-node-roles leader))))
                                       members)
                                (cl-raft::raft-last-log-index leader))))))
      (and last
           (every (lambda (member)
                    (observe member (lambda (node) (= last (cl-raft::raft-node-last-applied node)))))
                  members)))))

(defun call-with-read-test-cluster (function)
  "Call FUNCTION with three joined members (the first leads) and their stores."
  (let* ((ids '("a" "b" "c"))
         (kvs (mapcar (lambda (id) (cons id (make-hash-table :test 'equal))) ids))
         (members (mapcar (lambda (id) (make-cluster-member id kvs)) ids))
         (a (first members)))
    (unwind-protect
         (progn
           (gr8s.raft.transport::raft-cluster-init a)
           (gr8s.raft.transport::raft-member-start a)
           (poll-until (lambda () (gr8s.raft.transport::raft-member-leader-p a)))
           (dolist (joiner (rest members))
             (gr8s.raft.transport::raft-cluster-prepare-joiner joiner (list (cons "a" (member-address a))))
             (gr8s.raft.transport::raft-member-start joiner)
             (let ((id (cl-raft::raft-node-id (read-test-node joiner))))
               (poll-until (lambda ()
                             (gr8s.raft.transport::raft-cluster-add-member
                              a id (gr8s.raft.transport::raft-member-host joiner)
                              (gr8s.raft.transport::raft-member-port joiner))))
               (poll-until (lambda () (eq :voter (cl-raft::raft-node-self-role (read-test-node joiner)))))))
           (gr8s.raft.transport::raft-member-propose a '(:set "k" "before"))
           (poll-until (lambda () (every (lambda (kv) (equal "before" (gethash "k" (cdr kv)))) kvs)))
           (poll-until (lambda () (read-test-membership-settled-p members)))
           (funcall function members kvs))
      (dolist (member members) (ignore-errors (gr8s.raft.transport::stop-raft-member member))))))

(defun read-test-cut-replication (from to)
  "Stop FROM's replication to TO, returning a function that restores it."
  (let* ((links (gr8s.raft.transport::raft-member-links from))
         (id (cl-raft::raft-node-id (read-test-node to)))
         (link (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock from))
                 (prog1 (gethash id links) (remhash id links)))))
    (lambda ()
      (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock from))
        (setf (gethash id links) link)))))

(test a-follower-reads-only-what-the-leader-says-is-current
  (call-with-read-test-cluster
   (lambda (members kvs)
     (destructuring-bind (a b c) members
       (declare (ignore c))
       (is (eq t (gr8s.raft.transport::raft-member-await-linearizable-read b :timeout 5)))
       ;; b stops receiving entries; a and c go on committing.
       (let ((restore (read-test-cut-replication a b)))
         (gr8s.raft.transport::raft-member-propose a '(:set "k" "during"))
         (is (poll-until (lambda () (equal "during" (gethash "k" (cdr (assoc "c" kvs :test #'equal)))))))
         (is (equal "before" (gethash "k" (cdr (assoc "b" kvs :test #'equal))))
             "b's own state is now out of date")
         (is (equal '(nil :timeout)
                    (multiple-value-list
                     (gr8s.raft.transport::raft-member-await-linearizable-read b :timeout 1)))
             "and b knows it: the leader's index is ahead of what b has applied")
         (funcall restore))
       (is (eq t (gr8s.raft.transport::raft-member-await-linearizable-read b :timeout 10)))
       (is (equal "during" (gethash "k" (cdr (assoc "b" kvs :test #'equal))))
           "once the read is allowed, b has the write")))))

(test a-member-that-cannot-reach-a-leader-refuses-a-read
  (call-with-read-test-cluster
   (lambda (members kvs)
     (declare (ignore kvs))
     (destructuring-bind (a b c) members
       ;; b can no longer reach the leader at all.
       (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock b))
         (setf (gethash "a" (cl-raft::raft-node-peer-addresses (read-test-node b))) (list "127.0.0.1" 1)))
       (gr8s.raft.transport::raft-read-gate-drop-leader (gr8s.raft.transport::raft-member-read-gate b))
       (is (null (gr8s.raft.transport::raft-member-await-linearizable-read b :timeout 1)))
       ;; A leader that has lost its quorum cannot confirm that it still leads.
       (gr8s.raft.transport::stop-raft-member b)
       (gr8s.raft.transport::stop-raft-member c)
       (is (null (gr8s.raft.transport::raft-member-await-linearizable-read a :timeout 1)))
       (is (poll-until (lambda () (not (gr8s.raft.transport::raft-member-follows-a-leader-p a))) :timeout 10)
           "and after an election timeout it reports that it has lost the leader")))))

(test one-confirmation-round-serves-every-read-that-was-waiting
  (call-with-read-test-cluster
   (lambda (members kvs)
     (declare (ignore kvs))
     (let* ((a (first members))
            (gate (gr8s.raft.transport::raft-member-read-gate a))
            (before (gr8s.raft.transport::raft-read-gate-round gate))
            (answers (make-array 40 :initial-element nil))
            (threads nil))
       ;; The first reader drives a round and stops at the member lock; the rest
       ;; arrive while it runs, so all of them need the round after it.
       (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock a))
         (setf threads
               (loop for i below 40
                     collect (let ((i i))
                               (bt:make-thread
                                (lambda ()
                                  (setf (aref answers i)
                                        (gr8s.raft.transport::raft-member-await-linearizable-read a :timeout 10)))))))
         (sleep 0.5))
       (mapc #'bt:join-thread threads)
       (is (every (lambda (answer) (eq t answer)) answers))
       (is (= 2 (- (gr8s.raft.transport::raft-read-gate-round gate) before))
           "forty reads cost two rounds of heartbeats, not forty")))))

(test a-sole-member-reads-at-once
  (let* ((kvs (list (cons "solo" (make-hash-table :test 'equal))))
         (solo (make-cluster-member "solo" kvs)))
    (unwind-protect
         (progn
           (gr8s.raft.transport::raft-cluster-init solo)
           (gr8s.raft.transport::raft-member-start solo)
           (is (poll-until (lambda () (gr8s.raft.transport::raft-member-leader-p solo))))
           (is (eq t (gr8s.raft.transport::raft-member-await-linearizable-read solo :timeout 5)))
           (is (gr8s.raft.transport::raft-member-follows-a-leader-p solo)))
      (ignore-errors (gr8s.raft.transport::stop-raft-member solo)))))

(test only-a-read-that-names-no-version-must-be-current
  (flet ((gated (path &optional version (method :get))
           (gr8s.apiserver::linearizable-read-request-p method path version)))
    (is (gated "/api/v1/namespaces/default/configmaps/marker"))
    (is (gated "/api/v1/pods"))
    (is (gated "/apis/apps/v1/namespaces/default/deployments" ""))
    (is (not (gated "/api/v1/pods" "0")) "any version will do")
    (is (not (gated "/api/v1/pods" "1234")) "the caller named the version it has seen")
    (is (not (gated "/api/v1/pods" nil :post)))
    (is (not (gated "/api/v1")) "discovery")
    (is (not (gated "/apis/apps/v1")))
    (is (not (gated "/apis")))
    (is (not (gated "/version")))
    (is (not (gated "/openapi/v2")))
    (is (not (gated "/apis/gr8s.io/v1/controlplanemembers"))
        "an operator must be able to look at a member that is cut off")))

(test a-member-that-has-lost-the-leader-refuses-current-reads-and-is-not-ready
  (with-temporary-store (store path)
   (let* ((cut-off t)
         (server (gr8s.apiserver::start-server
                  :address "127.0.0.1" :port 0 :store store :runtime (make-fake-runtime)
                  :linearizable-read-fn (lambda () (if cut-off (values nil :not-leader) t))
                  :follows-a-leader-fn (lambda () (not cut-off)))))
    (flet ((fetch (path)
             (multiple-value-bind (body status headers)
                 (drakma:http-request (format nil "http://127.0.0.1:~D~A" (hunchentoot:acceptor-port server) path)
                                      :redirect nil)
               (values status
                       (if (stringp body) body (babel:octets-to-string body :encoding :utf-8))
                       headers))))
      (unwind-protect
           (progn
             (multiple-value-bind (status body headers) (fetch "/api/v1/namespaces/default/configmaps")
               (is (= 503 status))
               (is (equal "1" (cdr (assoc :retry-after headers))))
               (let ((object (com.inuoe.jzon:parse body)))
                 (is (equal "Status" (gethash "kind" object)))
                 (is (equal "ServiceUnavailable" (gethash "reason" object)))
                 (is (search "resourceVersion=0" (gethash "message" object)))))
             (is (= 200 (fetch "/api/v1/namespaces/default/configmaps?resourceVersion=0"))
                 "a caller that accepts old state still gets this member's own")
             (is (= 200 (fetch "/livez")) "it is alive")
             (multiple-value-bind (status body) (fetch "/readyz")
               (is (= 503 status) "and not ready, so a load balancer stops sending to it")
               (is (search "etcd" body)))
             (is (search "[-]etcd failed" (nth-value 1 (fetch "/readyz?verbose"))))
             (is (= 200 (fetch "/readyz?exclude=etcd")))
             (setf cut-off nil)
             (is (= 200 (fetch "/api/v1/namespaces/default/configmaps")))
             (is (= 200 (fetch "/readyz"))))
        (gr8s.apiserver::stop-server server))))))
