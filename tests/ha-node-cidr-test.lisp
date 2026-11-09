;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Node desired-state replication (podster-8ia.4): a node's control-plane-
;;;; assigned podCIDR (and labels/taints) must survive leader failover, or a new
;;;; leader could hand the node a different CIDR than its agent is already using.
;;;; Heartbeat churn stays local, but readiness transitions replicate so every
;;;; control-plane member serves the same Node API view.

(in-package #:gr8s/tests)
(def-suite ha-node-cidr :in gr8s)
(in-suite ha-node-cidr)

(defun ha-node-cidr (store name)
  (let ((node (ignore-errors (gr8s:get-node store name))))
    (and node (gr8s:node-record-pod-cidr node))))

(defun ha-node-ready-p (store name)
  (let ((node (ignore-errors (gr8s:get-node store name))))
    (and node (gr8s::node-record-ready-p node))))

(defun seed-ha-readiness-nodes (store)
  (gr8s:register-node
   store (gr8s:make-node-record :id "node-a" :name "worker-a"
                                :pod-cidr "10.88.0.0/20"))
  (gr8s:register-node
   store (gr8s:make-node-record :id "node-b" :name "worker-b"
                                :pod-cidr "10.88.16.0/20")))

(defun apply-ha-node-command (store command)
  (case (first command)
    (:node-state (gr8s::install-node-state-blob store (second command)))
    (:node-delta (gr8s::install-node-state-delta store (second command)))
    (t (error "Unsupported HA node command ~S" (first command)))))

(test stale-member-readiness-commands-preserve-unrelated-nodes
  ;; Two agents report their own readiness through different control-plane
  ;; members, each of which can still have a stale view of the other Node. Raft
  ;; order must merge the two key-level transitions instead of letting the later
  ;; whole-index snapshot turn the first Node NotReady again (podster-aqq).
  (with-temporary-store (left left-path)
    (with-temporary-store (right right-path)
      (with-temporary-store (replica replica-path)
        (declare (ignore left-path right-path replica-path))
        (dolist (store (list left right replica)) (seed-ha-readiness-nodes store))
        (let ((left-command nil) (right-command nil))
          (setf (gr8s::pod-store-consensus-commit-fn left)
                (lambda (tag payload) (setf left-command (list tag payload)))
                (gr8s::pod-store-consensus-commit-fn right)
                (lambda (tag payload) (setf right-command (list tag payload))))
          (let ((now (get-universal-time)))
            (gr8s::mark-node-ready left "worker-a" now)
            (gr8s::mark-node-ready right "worker-b" now))
          (apply-ha-node-command replica left-command)
          (apply-ha-node-command replica right-command)
          (is (ha-node-ready-p replica "worker-a")
              "the later stale member command preserves worker-a readiness")
          (is (ha-node-ready-p replica "worker-b")
              "the later member's worker-b readiness commits too"))))))

(test heartbeat-renewal-reaches-members-without-the-agent-session
  ;; Every control-plane member runs a lease-expiry monitor, while an agent's
  ;; stream belongs to only one member. Renewals must therefore advance the
  ;; replicated deadline; otherwise a follower expires a healthy Node from its
  ;; stale first-heartbeat deadline and commits NotReady (podster-aqq).
  (with-temporary-store (session-owner owner-path)
    (with-temporary-store (other-member member-path)
      (declare (ignore owner-path member-path))
      (seed-ha-readiness-nodes session-owner)
      (seed-ha-readiness-nodes other-member)
      (setf (gr8s::pod-store-consensus-commit-fn session-owner)
            (lambda (tag payload)
              (apply-ha-node-command other-member (list tag payload))))
      (let ((now (get-universal-time)))
        (gr8s::mark-node-ready session-owner "worker-a" now :lease-duration 15)
        (is (ha-node-ready-p other-member "worker-a"))
        ;; A beat ten seconds later extends the true deadline to NOW+25. At
        ;; NOW+16 the original deadline is stale but the renewed one is not.
        (gr8s::mark-node-ready session-owner "worker-a" (+ now 10) :lease-duration 15)
        (gr8s::expire-node-heartbeats other-member (+ now 1) :now (+ now 16))
        (is (ha-node-ready-p other-member "worker-a")
            "a member without the stream sees the renewed lease deadline")))))

(test node-cidr-replicates-and-survives-failover
  (with-temporary-store (s1 p1)
    (with-temporary-store (s2 p2)
      (with-temporary-store (s3 p3)
        (declare (ignore p1 p2 p3))
        (let ((h1 nil) (h2 nil) (h3 nil))
          (unwind-protect
               (progn
                 (setf h1 (gr8s::start-ha-control-plane s1 :id "cp1" :init t))
                 (is (poll-until (lambda () (gr8s::ha-control-plane-leader-p h1))))
                 (let ((lp (gr8s::raft-member-port (gr8s::ha-control-plane-member h1))))
                   (setf h2 (gr8s::start-ha-control-plane s2 :id "cp2" :join-host "127.0.0.1" :join-port lp))
                   (setf h3 (gr8s::start-ha-control-plane s3 :id "cp3" :join-host "127.0.0.1" :join-port lp)))
                 (is (poll-until
                      (lambda () (= 2 (length (gr8s::raft-node-peers
                                               (gr8s::raft-member-node (gr8s::ha-control-plane-member h1))))))
                      :timeout 15)
                     "both followers joined")
                 ;; Register a worker on the leader with an assigned podCIDR.
                 (gr8s:register-node
                  s1 (gr8s:make-node-record :id "node-1" :name "worker-a" :pod-cidr "10.88.0.0/20"))
                 (is (poll-until
                      (lambda () (every (lambda (s) (equal "10.88.0.0/20" (ha-node-cidr s "worker-a")))
                                        (list s1 s2 s3)))
                      :timeout 10)
                     "the assigned podCIDR replicates to every member")
                 ;; Heartbeats do not flood Raft, but the client-visible readiness
                 ;; transition must reach followers serving their own local APIs.
                 (gr8s::mark-node-ready s1 "worker-a" (get-universal-time))
                 (is (poll-until
                      (lambda () (every (lambda (s) (ha-node-ready-p s "worker-a"))
                                        (list s1 s2 s3)))
                      :timeout 10)
                     "the Ready transition replicates to every member")
                 (gr8s::mark-node-not-ready s1 "worker-a")
                 (is (poll-until
                      (lambda () (every (lambda (s) (not (ha-node-ready-p s "worker-a")))
                                        (list s1 s2 s3)))
                      :timeout 10)
                     "the NotReady transition replicates to every member")
                 ;; Kill the leader; a survivor keeps the CIDR assignment.
                 (gr8s::stop-ha-control-plane h1)
                 (setf h1 nil)
                 (is (poll-until (lambda () (or (gr8s::ha-control-plane-leader-p h2)
                                                (gr8s::ha-control-plane-leader-p h3)))
                                 :timeout 20)
                     "a survivor becomes leader")
                 (is (and (equal "10.88.0.0/20" (ha-node-cidr s2 "worker-a"))
                          (equal "10.88.0.0/20" (ha-node-cidr s3 "worker-a")))
                     "the podCIDR assignment is not lost on failover"))
            (dolist (h (list h1 h2 h3)) (when h (ignore-errors (gr8s::stop-ha-control-plane h))))))))))

(test enrollment-retry-finishes-failed-node-persistence
  (with-temporary-store (store path)
    (let ((original (symbol-function 'gr8s::persist-node)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::persist-node)
                   (lambda (&rest arguments)
                     (declare (ignore arguments))
                     (error "Injected enrollment persistence failure")))
             (signals error
               (gr8s::install-node-enrollment-command
                store "enrollment-id" "enrolled-worker" "10.88.0.0/16" 20
                "2026-11-09T00:00:00Z")))
        (setf (symbol-function 'gr8s::persist-node) original)))
    (let* ((node (gr8s:get-node store "enrolled-worker"))
           (revision (gr8s::node-record-resource-version node))
           (cidr (gr8s:node-record-pod-cidr node)))
      (is (null (probe-file (gr8s::node-path store node))))
      (is (eq node
              (gr8s::install-node-enrollment-command
               store "enrollment-id" "enrolled-worker" "10.88.0.0/16" 20
               "2026-11-09T00:00:00Z")))
      (is (probe-file (gr8s::node-path store node)))
      (let ((reopened (gr8s:open-store path)))
        (is (equal cidr (ha-node-cidr reopened "enrolled-worker")))
        (is (equal revision
                   (gr8s::node-record-resource-version
                    (gr8s:get-node reopened "enrolled-worker")))))
      (gr8s::install-node-enrollment-command
       store "enrollment-id" "enrolled-worker" "10.88.0.0/16" 20
       "2026-11-09T00:00:00Z")
      (is (equal revision (gr8s::node-record-resource-version node))))))

(test failed-node-consensus-restores-committed-state
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (let* ((original (gr8s:get-node store "worker-a"))
           (file (uiop:read-file-string (gr8s::node-path store original)))
           (revision (gr8s::pod-store-pod-revision store))
           (journal (gr8s::pod-store-node-watch-journal store)))
      (setf (gr8s::pod-store-consensus-commit-fn store)
            (lambda (tag payload)
              (declare (ignore payload))
              (is (eq :node-delta tag))
              (is (eq original (gethash "worker-a" (gr8s::pod-store-nodes store))))
              (is (equal file (uiop:read-file-string (gr8s::node-path store original))))
              (is (= revision (gr8s::pod-store-pod-revision store)))
              (is (eq journal (gr8s::pod-store-node-watch-journal store)))
              (error "Injected consensus failure")))
      (signals error (gr8s::mark-node-ready store "worker-a" (get-universal-time)))
      (is (null (gr8s::node-record-ready-p original)))
      (signals error
        (gr8s::with-store-lock (store) (gr8s::remove-node-unlocked store original)))
      (is (probe-file (gr8s::node-path store original)))
      (signals error
        (gr8s:register-node store (gr8s:make-node-record
                                  :id "new-worker" :name "new-worker" :pod-cidr "10.88.32.0/20")))
      (is (null (gethash "new-worker" (gr8s::pod-store-nodes store)))))))

(test committed-node-deltas-publish-on-every-replica
  (with-temporary-store (store path)
    (with-temporary-store (replica replica-path)
      (declare (ignore path replica-path))
      (dolist (s (list store replica)) (seed-ha-readiness-nodes s))
      (setf (gr8s::pod-store-consensus-commit-fn store)
            (lambda (tag payload)
              (is (eq :node-delta tag))
              (dolist (s (list store replica)) (gr8s::install-node-state-delta s payload))))
      (let ((before (gr8s::pod-store-node-watch-journal-length store)))
        (gr8s::mark-node-ready store "worker-a" (get-universal-time))
        (dolist (s (list store replica))
          (is (ha-node-ready-p s "worker-a"))
          (is (= (1+ before) (gr8s::pod-store-node-watch-journal-length s))))
        ;; Lease-only renewals persist and replicate without a client event.
        (gr8s::mark-node-ready store "worker-a" (1+ (get-universal-time)))
        (is (= (1+ before) (gr8s::pod-store-node-watch-journal-length store)))
        (gr8s::note-node-runtime-health store "worker-a" "runtime unavailable")
        (dolist (s (list store replica))
          (is (equal "runtime unavailable"
                     (gr8s::node-record-runtime-down-message (gr8s:get-node s "worker-a")))))
        (let ((node (gr8s:get-node store "worker-b")))
          (gr8s::with-store-lock (store) (gr8s::remove-node-unlocked store node)))
        (dolist (s (list store replica))
          (is (null (gethash "worker-b" (gr8s::pod-store-nodes s)))))))))

(test node-staging-unwinds-before-consensus-on-body-error
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (let ((original (gr8s:get-node store "worker-a")))
      (setf (gr8s::pod-store-consensus-commit-fn store)
            (lambda (&rest arguments)
              (declare (ignore arguments))
              (fail "A failed transaction body must not propose")))
      (signals error
        (gr8s::with-store-lock (store)
          (setf (gr8s::node-record-underlay-address
                 (gr8s::get-node-unlocked store "worker-a")) "192.0.2.10")
          (error "Abort private mutation")))
      (is (eq original (gethash "worker-a" (gr8s::pod-store-nodes store))))
      (is (equal "" (gr8s::node-record-underlay-address original))))))
