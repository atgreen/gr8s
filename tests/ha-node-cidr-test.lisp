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
  (let ((node (ignore-errors (gr8s.controllers::get-node store name))))
    (and node (gr8s.model::node-record-pod-cidr node))))

(defun ha-node-ready-p (store name)
  (let ((node (ignore-errors (gr8s.controllers::get-node store name))))
    (and node (gr8s.model::node-record-ready-p node))))

(defun seed-ha-readiness-nodes (store)
  (gr8s.controllers::register-node
   store (gr8s.model::make-node-record :id "node-a" :name "worker-a"
                                :pod-cidr "10.88.0.0/20"))
  (gr8s.controllers::register-node
   store (gr8s.model::make-node-record :id "node-b" :name "worker-b"
                                :pod-cidr "10.88.16.0/20")))

(defun apply-ha-node-command (store command)
  (case (first command)
    (:node-state (gr8s.store::install-node-state-blob store (second command)))
    (:node-delta (gr8s.store::install-node-state-delta store (second command)))
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
          (setf (gr8s.store::pod-store-consensus-commit-fn left)
                (lambda (tag payload) (setf left-command (list tag payload)))
                (gr8s.store::pod-store-consensus-commit-fn right)
                (lambda (tag payload) (setf right-command (list tag payload))))
          (let ((now (get-universal-time)))
            (gr8s.controllers::mark-node-ready left "worker-a" now)
            (gr8s.controllers::mark-node-ready right "worker-b" now))
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
      (setf (gr8s.store::pod-store-consensus-commit-fn session-owner)
            (lambda (tag payload)
              (apply-ha-node-command other-member (list tag payload))
              (apply-ha-node-command session-owner (list tag payload))))
      (let ((now (get-universal-time)))
        (gr8s.controllers::mark-node-ready session-owner "worker-a" now :lease-duration 15)
        (is (ha-node-ready-p other-member "worker-a"))
        ;; A beat ten seconds later extends the true deadline to NOW+25. At
        ;; NOW+16 the original deadline is stale but the renewed one is not.
        (gr8s.controllers::mark-node-ready session-owner "worker-a" (+ now 10) :lease-duration 15)
        (gr8s.controllers::expire-node-heartbeats other-member (+ now 1) :now (+ now 16))
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
                 (setf h1 (gr8s.ha::start-ha-control-plane s1 :id "cp1" :init t))
                 (is (poll-until (lambda () (gr8s.ha::ha-control-plane-leader-p h1))))
                 (let ((lp (gr8s.raft.transport::raft-member-port (gr8s.ha::ha-control-plane-member h1))))
                   (setf h2 (gr8s.ha::start-ha-control-plane s2 :id "cp2" :join-host "127.0.0.1" :join-port lp))
                   (setf h3 (gr8s.ha::start-ha-control-plane s3 :id "cp3" :join-host "127.0.0.1" :join-port lp)))
                 (is (poll-until
                      (lambda () (= 2 (length (cl-raft::raft-node-peers
                                               (gr8s.raft.transport::raft-member-node (gr8s.ha::ha-control-plane-member h1))))))
                      :timeout 15)
                     "both followers joined")
                 ;; Register a worker on the leader with an assigned podCIDR.
                 (gr8s.controllers::register-node
                  s1 (gr8s.model::make-node-record :id "node-1" :name "worker-a" :pod-cidr "10.88.0.0/20"))
                 (is (poll-until
                      (lambda () (every (lambda (s) (equal "10.88.0.0/20" (ha-node-cidr s "worker-a")))
                                        (list s1 s2 s3)))
                      :timeout 10)
                     "the assigned podCIDR replicates to every member")
                 ;; Heartbeats do not flood Raft, but the client-visible readiness
                 ;; transition must reach followers serving their own local APIs.
                 (gr8s.controllers::mark-node-ready s1 "worker-a" (get-universal-time))
                 (is (poll-until
                      (lambda () (every (lambda (s) (ha-node-ready-p s "worker-a"))
                                        (list s1 s2 s3)))
                      :timeout 10)
                     "the Ready transition replicates to every member")
                 (gr8s.controllers::mark-node-not-ready s1 "worker-a")
                 (is (poll-until
                      (lambda () (every (lambda (s) (not (ha-node-ready-p s "worker-a")))
                                        (list s1 s2 s3)))
                      :timeout 10)
                     "the NotReady transition replicates to every member")
                 (let ((stale (capture-ha-node-write
                               s2 (lambda () (gr8s.controllers::update-node-kubelet-port s2 "worker-a" 10250)))))
                   (gr8s.controllers::update-node-underlay-address s1 "worker-a" "192.0.2.10")
                   (multiple-value-bind (result committed)
                       (gr8s.raft.transport::raft-member-forward-propose-sync
                        (gr8s.ha::ha-control-plane-member h2) (list :node-delta stale))
                     (is (eq t committed))
                     (is (equal '(:node-conflict) result))))
                 ;; Kill the leader; a survivor keeps the CIDR assignment.
                 (gr8s.ha::stop-ha-control-plane h1)
                 (setf h1 nil)
                 (is (poll-until (lambda () (or (gr8s.ha::ha-control-plane-leader-p h2)
                                                (gr8s.ha::ha-control-plane-leader-p h3)))
                                 :timeout 20)
                     "a survivor becomes leader")
                 (is (and (equal "10.88.0.0/20" (ha-node-cidr s2 "worker-a"))
                          (equal "10.88.0.0/20" (ha-node-cidr s3 "worker-a")))
                     "the podCIDR assignment is not lost on failover"))
            (dolist (h (list h1 h2 h3)) (when h (ignore-errors (gr8s.ha::stop-ha-control-plane h))))))))))

(test enrollment-retry-finishes-failed-node-persistence
  (with-temporary-store (store path)
    (let ((original (symbol-function 'gr8s.store::persist-node)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.store::persist-node)
                   (lambda (&rest arguments)
                     (declare (ignore arguments))
                     (error "Injected enrollment persistence failure")))
             (signals error
               (gr8s.controllers::install-node-enrollment-command
                store "enrollment-id" "enrolled-worker" "10.88.0.0/16" 20
                "2026-11-09T00:00:00Z")))
        (setf (symbol-function 'gr8s.store::persist-node) original)))
    (let* ((node (gr8s.controllers::get-node store "enrolled-worker"))
           (revision (gr8s.model::node-record-resource-version node))
           (cidr (gr8s.model::node-record-pod-cidr node)))
      (is (null (probe-file (gr8s.store::node-path store node))))
      (is (eq node
              (gr8s.controllers::install-node-enrollment-command
               store "enrollment-id" "enrolled-worker" "10.88.0.0/16" 20
               "2026-11-09T00:00:00Z")))
      (is (probe-file (gr8s.store::node-path store node)))
      (let ((reopened (gr8s.store::open-store path)))
        (is (equal cidr (ha-node-cidr reopened "enrolled-worker")))
        (is (equal revision
                   (gr8s.model::node-record-resource-version
                    (gr8s.controllers::get-node reopened "enrolled-worker")))))
      (gr8s.controllers::install-node-enrollment-command
       store "enrollment-id" "enrolled-worker" "10.88.0.0/16" 20
       "2026-11-09T00:00:00Z")
      (is (equal revision (gr8s.model::node-record-resource-version node))))))

(test failed-node-consensus-restores-committed-state
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (let* ((original (gr8s.controllers::get-node store "worker-a"))
           (file (uiop:read-file-string (gr8s.store::node-path store original)))
           (revision (gr8s.store::pod-store-pod-revision store))
           (journal (gr8s.store::pod-store-node-watch-journal store)))
      (setf (gr8s.store::pod-store-consensus-commit-fn store)
            (lambda (tag payload)
              (declare (ignore payload))
              (is (eq :node-delta tag))
              (is (eq original (gethash "worker-a" (gr8s.store::pod-store-nodes store))))
              (is (equal file (uiop:read-file-string (gr8s.store::node-path store original))))
              (is (= revision (gr8s.store::pod-store-pod-revision store)))
              (is (eq journal (gr8s.store::pod-store-node-watch-journal store)))
              (error "Injected consensus failure")))
      (signals error (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time)))
      (is (null (gr8s.model::node-record-ready-p original)))
      (signals error
        (gr8s.store::with-store-lock (store) (gr8s.apiserver::remove-node-unlocked store original)))
      (is (probe-file (gr8s.store::node-path store original)))
      (signals error
        (gr8s.controllers::register-node store (gr8s.model::make-node-record
                                  :id "new-worker" :name "new-worker" :pod-cidr "10.88.32.0/20")))
      (is (null (gethash "new-worker" (gr8s.store::pod-store-nodes store)))))))

(test committed-node-deltas-publish-on-every-replica
  (with-temporary-store (store path)
    (with-temporary-store (replica replica-path)
      (declare (ignore path replica-path))
      (dolist (s (list store replica)) (seed-ha-readiness-nodes s))
      (setf (gr8s.store::pod-store-consensus-commit-fn store)
            (lambda (tag payload)
              (is (eq :node-delta tag))
              (dolist (s (list store replica)) (gr8s.store::install-node-state-delta s payload))))
      (let ((before (gr8s.store::pod-store-node-watch-journal-length store)))
        (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time))
        (dolist (s (list store replica))
          (is (ha-node-ready-p s "worker-a"))
          (is (= (1+ before) (gr8s.store::pod-store-node-watch-journal-length s))))
        ;; Lease-only renewals persist and replicate without a client event.
        (gr8s.controllers::mark-node-ready store "worker-a" (1+ (get-universal-time)))
        (is (= (1+ before) (gr8s.store::pod-store-node-watch-journal-length store)))
        (gr8s.controllers::note-node-runtime-health store "worker-a" "runtime unavailable")
        (dolist (s (list store replica))
          (is (equal "runtime unavailable"
                     (gr8s.model::node-record-runtime-down-message (gr8s.controllers::get-node s "worker-a")))))
        (let ((node (gr8s.controllers::get-node store "worker-b")))
          (gr8s.store::with-store-lock (store) (gr8s.apiserver::remove-node-unlocked store node)))
        (dolist (s (list store replica))
          (is (null (gethash "worker-b" (gr8s.store::pod-store-nodes s)))))))))

(test node-staging-unwinds-before-consensus-on-body-error
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (let ((original (gr8s.controllers::get-node store "worker-a")))
      (setf (gr8s.store::pod-store-consensus-commit-fn store)
            (lambda (&rest arguments)
              (declare (ignore arguments))
              (fail "A failed transaction body must not propose")))
      (signals error
        (gr8s.store::with-store-lock (store)
          (setf (gr8s.model::node-record-underlay-address
                 (gr8s.controllers::get-node-unlocked store "worker-a")) "192.0.2.10")
          (error "Abort private mutation")))
      (is (eq original (gethash "worker-a" (gr8s.store::pod-store-nodes store))))
      (is (equal "" (gr8s.model::node-record-underlay-address original))))))

(defun capture-ha-node-write (store function)
  (let ((original (gr8s.store::pod-store-consensus-commit-fn store)) (payload nil))
    (unwind-protect
         (progn
           (setf (gr8s.store::pod-store-consensus-commit-fn store)
                 (lambda (tag json)
                   (unless (eq tag :node-delta) (error "Unexpected command"))
                   (setf payload json)))
           (funcall function)
           payload)
      (setf (gr8s.store::pod-store-consensus-commit-fn store) original))))

(test stale-same-node-writes-conflict-without-changing-state
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (let ((first (capture-ha-node-write store
                  (lambda () (gr8s.controllers::update-node-underlay-address store "worker-a" "192.0.2.10"))))
          (stale (capture-ha-node-write store
                  (lambda () (gr8s.controllers::update-node-kubelet-port store "worker-a" 10250)))))
      (is (eq :node-ok (first (gr8s.store::install-node-state-delta store first))))
      (let ((revision (gr8s.store::pod-store-pod-revision store))
            (events (gr8s.store::pod-store-node-watch-journal-length store)))
        (is (equal '(:node-conflict) (gr8s.store::install-node-state-delta store stale)))
        (is (= revision (gr8s.store::pod-store-pod-revision store)))
        (is (= events (gr8s.store::pod-store-node-watch-journal-length store)))
        (is (= 0 (gr8s.model::node-record-kubelet-port (gr8s.controllers::get-node store "worker-a"))))
        ;; Retrying a successful command neither allocates another revision nor emits an event.
        (is (eq :node-ok (first (gr8s.store::install-node-state-delta store first))))
        (is (= revision (gr8s.store::pod-store-pod-revision store)))
        (is (= events (gr8s.store::pod-store-node-watch-journal-length store)))))))

(test node-commit-revisions-order-independent-key-writes
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (let ((a (capture-ha-node-write store
               (lambda () (gr8s.controllers::update-node-kubelet-port store "worker-a" 10250))))
          (b (capture-ha-node-write store
               (lambda () (gr8s.controllers::update-node-kubelet-port store "worker-b" 10251)))))
      (gr8s.store::install-node-state-delta store a)
      (gr8s.store::install-node-state-delta store b)
      (let ((av (parse-integer (gr8s.model::node-record-resource-version (gr8s.controllers::get-node store "worker-a"))))
            (bv (parse-integer (gr8s.model::node-record-resource-version (gr8s.controllers::get-node store "worker-b")))))
        (is (< av bv))
        (is (= bv (gr8s.store::pod-store-pod-revision store)))
        (let ((node (gr8s.controllers::get-node store "worker-a")))
          (setf (gr8s.store::pod-store-consensus-commit-fn store)
                (lambda (tag json)
                  (declare (ignore tag))
                  ;; Model another committed object's revision before this apply.
                  (incf (gr8s.store::pod-store-pod-revision store) 5)
                  (gr8s.store::install-node-state-delta store json)))
          (let ((returned (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time))))
            (is (not (eq node returned)))
            (is (equal (gr8s.model::node-record-resource-version returned)
                       (gr8s.model::node-record-resource-version (gr8s.controllers::get-node store "worker-a"))))))))))

(test node-conflict-result-becomes-an-api-conflict
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (setf (gr8s.store::pod-store-consensus-commit-fn store)
          (lambda (&rest arguments) (declare (ignore arguments)) (list :node-conflict)))
    (handler-case
        (progn (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time))
               (fail "Expected a conflict"))
      (gr8s.model::kubernetes-error (condition)
        (is (= 409 (gr8s.model::kubernetes-error-status-code condition)))))))

(test committed-node-lease-parsing-does-not-use-replica-wall-time
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (let ((payload (capture-ha-node-write store
                     (lambda () (gr8s.controllers::mark-node-ready store "worker-a" 1 :lease-duration 15)))))
      (gr8s.store::install-node-state-delta store payload)
      (is (ha-node-ready-p store "worker-a")
          "Raft apply reproduces committed readiness even after its deadline")
      (gr8s.controllers::expire-node-heartbeats store 2 :now 17)
      (is (not (ha-node-ready-p store "worker-a"))
          "the explicit expiry transition changes readiness"))))

(test failed-node-apply-persistence-does-not-consume-commit-revision
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (let ((payload (capture-ha-node-write store
                     (lambda () (gr8s.controllers::update-node-kubelet-port store "worker-a" 10250))))
          (revision (gr8s.store::pod-store-pod-revision store))
          (original (symbol-function 'gr8s.store::persist-node)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.store::persist-node)
                   (lambda (&rest arguments) (declare (ignore arguments)) (error "Injected apply failure")))
             (signals error (gr8s.store::install-node-state-delta store payload)))
        (setf (symbol-function 'gr8s.store::persist-node) original))
      (is (= revision (gr8s.store::pod-store-pod-revision store)))
      (is (= 0 (gr8s.model::node-record-kubelet-port (gr8s.controllers::get-node store "worker-a"))))
      (gr8s.store::install-node-state-delta store payload)
      (is (= (1+ revision) (gr8s.store::pod-store-pod-revision store))))))

(test heartbeat-monitor-survives-conflicts-and-unavailable-consensus
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((server (gr8s.apiserver::%make-node-grpc-server :store store))
          (calls 0)
          (original (symbol-function 'gr8s.apiserver::reconcile-node-heartbeats)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.apiserver::reconcile-node-heartbeats)
                   (lambda (s now)
                     (declare (ignore now))
                     (incf calls)
                     (case calls
                       (1 (error 'gr8s.model::kubernetes-error :status-code 409 :reason "Conflict" :message "Lease renewed"))
                       (2 (error 'gr8s.model::kubernetes-error :status-code 503 :reason "ServiceUnavailable" :message "No leader"))
                       (t (setf (gr8s.apiserver::node-grpc-server-stopping-p s) t)))))
             (gr8s.apiserver::monitor-node-heartbeats server)
             (is (= 3 calls)))
        (setf (symbol-function 'gr8s.apiserver::reconcile-node-heartbeats) original)))))

(test committed-node-writes-reject-cross-node-underlay-collisions
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (let ((a (capture-ha-node-write store
               (lambda () (gr8s.controllers::update-node-underlay-address store "worker-a" "192.0.2.10"))))
          (b (capture-ha-node-write store
               (lambda () (gr8s.controllers::update-node-underlay-address store "worker-b" "192.0.2.10")))))
      (is (eq :node-ok (first (gr8s.store::install-node-state-delta store a))))
      (let ((revision (gr8s.store::pod-store-pod-revision store))
            (events (gr8s.store::pod-store-node-watch-journal-length store)))
        (is (equal '(:node-conflict) (gr8s.store::install-node-state-delta store b)))
        (is (= revision (gr8s.store::pod-store-pod-revision store)))
        (is (= events (gr8s.store::pod-store-node-watch-journal-length store)))
        (is (equal "" (gr8s.model::node-record-underlay-address (gr8s.controllers::get-node store "worker-b"))))))))

(test committed-node-registration-rejects-cross-node-identity-and-cidr-collisions
  (dolist (collision '(:identity :cidr))
    (with-temporary-store (store path)
      (declare (ignore path))
      (let ((a (capture-ha-node-write store
                 (lambda () (gr8s.controllers::register-node store
                              (gr8s.model::make-node-record :id "node-a" :name "worker-a" :pod-cidr "10.88.0.0/20")))))
            (b (capture-ha-node-write store
                 (lambda () (gr8s.controllers::register-node store
                              (gr8s.model::make-node-record :id (if (eq collision :identity) "node-a" "node-b")
                                                     :name "worker-b"
                                                     :pod-cidr (if (eq collision :cidr) "10.88.0.0/20" "10.88.16.0/20")))))))
        (is (eq :node-ok (first (gr8s.store::install-node-state-delta store a))))
        (let ((revision (gr8s.store::pod-store-pod-revision store))
              (events (gr8s.store::pod-store-node-watch-journal-length store)))
          (is (equal '(:node-conflict) (gr8s.store::install-node-state-delta store b)))
          (is (= revision (gr8s.store::pod-store-pod-revision store)))
          (is (= events (gr8s.store::pod-store-node-watch-journal-length store)))
          (is (null (gethash "worker-b" (gr8s.store::pod-store-nodes store)))))))))

(test node-claim-conflicts-agree-on-replicas-and-survive-reopen
  (with-temporary-store (left left-root)
    (with-temporary-store (right right-root)
      (let ((a (capture-ha-node-write left
                 (lambda () (gr8s.controllers::register-node left
                              (gr8s.model::make-node-record :id "a" :name "a" :pod-cidr "10.88.0.0/20"
                                                     :underlay-address "192.0.2.20")))))
            (b (capture-ha-node-write left
                 (lambda () (gr8s.controllers::register-node left
                              (gr8s.model::make-node-record :id "b" :name "b" :pod-cidr "10.88.16.0/20"
                                                     :underlay-address "192.0.2.20"))))))
        (dolist (store (list left right))
          (is (eq :node-ok (first (gr8s.store::install-node-state-delta store a))))
          (is (equal '(:node-conflict) (gr8s.store::install-node-state-delta store b))))
        (dolist (root (list left-root right-root))
          (let ((reopened (gr8s.store::open-store root)))
            (is (equal "192.0.2.20" (gr8s.model::node-record-underlay-address (gr8s.controllers::get-node reopened "a"))))
            (is (null (gethash "b" (gr8s.store::pod-store-nodes reopened))))))))))

(test node-claim-transfer-validates-the-entire-final-delta-before-writing
  (with-temporary-store (store root)
    (declare (ignore root))
    (seed-ha-readiness-nodes store)
    (gr8s.controllers::update-node-underlay-address store "worker-a" "192.0.2.30")
    (let* ((release (com.inuoe.jzon:parse
                     (capture-ha-node-write store
                       (lambda () (gr8s.controllers::update-node-underlay-address store "worker-a" "")))))
           (claim (com.inuoe.jzon:parse
                   (capture-ha-node-write store
                     (lambda () (gr8s.controllers::update-node-underlay-address store "worker-b" "192.0.2.31")))))
           (claim-change (aref (gethash "changes" claim) 0))
           (release-change (aref (gethash "changes" release) 0)))
      (setf (gethash "underlayAddress" (gethash "object" claim-change)) "192.0.2.30")
      ;; A conflicting batch must not publish an earlier unrelated update.
      (let ((bad (com.inuoe.jzon:parse (com.inuoe.jzon:stringify release-change))))
        (setf (gethash "underlayAddress" (gethash "object" bad)) "192.0.2.30"
              (gethash "kubeletPort" (gethash "object" bad)) 10250
              (gethash "changes" claim) (vector bad claim-change))
        (is (equal '(:node-conflict) (gr8s.store::install-node-state-delta store (com.inuoe.jzon:stringify claim))))
        (is (= 0 (gr8s.model::node-record-kubelet-port (gr8s.controllers::get-node store "worker-a")))))
      ;; Order the new claimant first: checking intermediate states would fail.
      (setf (gethash "changes" claim) (vector claim-change release-change))
      (is (eq :node-ok (first (gr8s.store::install-node-state-delta store (com.inuoe.jzon:stringify claim)))))
      (is (equal "" (gr8s.model::node-record-underlay-address (gr8s.controllers::get-node store "worker-a"))))
      (is (equal "192.0.2.30" (gr8s.model::node-record-underlay-address (gr8s.controllers::get-node store "worker-b")))))))

(test committed-node-claims-include-secondary-pod-cidrs
  (with-temporary-store (store root)
    (declare (ignore root))
    (let ((a (capture-ha-node-write store
               (lambda () (gr8s.controllers::register-node store
                            (gr8s.model::make-node-record :id "a" :name "a" :pod-cidr "10.88.0.0/20"
                                                   :pod-cidrs #("10.88.0.0/20" "fd88::/64"))))))
          (b (capture-ha-node-write store
               (lambda () (gr8s.controllers::register-node store
                            (gr8s.model::make-node-record :id "b" :name "b" :pod-cidr "10.88.16.0/20"
                                                   :pod-cidrs #("10.88.16.0/20" "fd88::/64")))))))
      (is (eq :node-ok (first (gr8s.store::install-node-state-delta store a))))
      (is (equal '(:node-conflict) (gr8s.store::install-node-state-delta store b))))))
