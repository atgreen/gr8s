;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The durable (consensus-plane) resource store routed through Raft
;;;; (podster-c2d.7.2), proven over the real ag-gRPC transport. A ConfigMap
;;;; created/updated on the leader's store replicates to every member's store;
;;;; killing the leader elects a new one that still holds the data and keeps
;;;; accepting writes. This exercises the WITH-CORE-WRITE seam in core-resources:
;;;; the committed state blob is proposed on the leader and installed on every
;;;; replica via INSTALL-CORE-STATE-BLOB.

(in-package #:gr8s/tests)
(def-suite ha-store :in gr8s)
(in-suite ha-store)

(defun configmap-input (name key value)
  (com.inuoe.jzon:parse
   (format nil "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"~A\",\"namespace\":\"default\"},\"data\":{\"~A\":\"~A\"}}"
           name key value)))

(defun configmap-value (store name key)
  (let ((object (ignore-errors (gr8s.resources::get-core-resource store "configmaps" "default" name))))
    (and object (gethash key (gethash "data" object)))))

(defun ha-secret-input (name value)
  (gr8s.resources::core-object
   "apiVersion" "v1" "kind" "Secret"
   "metadata" (gr8s.resources::core-object "name" name "namespace" "default")
   "data" (gr8s.resources::core-object "password" value)))

(defun ha-secret-value (store name)
  (let ((object (gr8s.resources::get-core-resource store "secrets" "default" name)))
    (and object (gethash "password" (gethash "data" object)))))

(defun apply-ha-core-command (store command)
  "Apply one captured HA core command to STORE, as the Raft state machine does."
  (case (first command)
    (:core-state (gr8s.resources::install-core-state-blob store (second command)))
    (:core-delta (gr8s.resources::install-core-state-delta store (second command)))
    (:secrets-encryption
     (gr8s.resources::install-secret-encryption-command store (second command)))
    (t (error "Unsupported HA core command ~S" (first command)))))

(test secret-encryption-and-key-rotation-replicate-without-plaintext
  (with-temporary-store (leader leader-path)
    (with-temporary-store (follower follower-path)
      ;; HA members share the cluster CA identity from which encryption keys are
      ;; derived, but never replicate the derived keys themselves.
      (gr8s.security::ensure-cluster-pki leader-path)
      (ensure-directories-exist (merge-pathnames "pki/cluster-ca.key" follower-path))
      (uiop:copy-file (merge-pathnames "pki/cluster-ca.key" leader-path)
                      (merge-pathnames "pki/cluster-ca.key" follower-path))
      (let ((commands '()))
        (setf (gr8s.store::pod-store-consensus-commit-fn leader)
              (lambda (tag payload)
                (push (list tag payload) commands)
                (apply-ha-core-command leader (list tag payload))
                (apply-ha-core-command follower (list tag payload))))
        (gr8s.resources::enable-secret-encryption leader)
        (gr8s.resources::create-core-resource
         leader "secrets" (ha-secret-input "credentials" "cmFmdC1zZW50aW5lbA==")
         "default")
        (is (equal "cmFmdC1zZW50aW5lbA=="
                   (ha-secret-value follower "credentials")))
        (is (null (search "cmFmdC1zZW50aW5lbA=="
                          (second (find :core-delta commands :key #'first))))
            "the Raft delta contains only ciphertext")
        (let ((next-key (gr8s.resources::prepare-secret-encryption-key leader)))
          (gr8s.resources::promote-secret-encryption-key leader)
          (gr8s.resources::reencrypt-secrets leader)
          (gr8s.resources::finalize-secret-encryption-key leader)
          (is (equal next-key
                     (gethash "activeKeyId"
                              (gr8s.resources::secret-encryption-status follower))))
          (is (equal "cmFmdC1zZW50aW5lbA=="
                     (ha-secret-value follower "credentials")))
          (is (= 1 (length (gethash "keys"
                                    (gr8s.resources::secret-encryption-status follower))))))))))

(test stale-member-core-commands-preserve-unrelated-commits
  ;; Two members can prepare writes from the same committed base before either
  ;; sees the other's log entry. Applying those entries in Raft order must merge
  ;; their key-level effects; a later stale whole-index snapshot must not erase
  ;; the earlier acknowledged key (podster-7bw).
  (with-temporary-store (left left-path)
    (with-temporary-store (right right-path)
      (with-temporary-store (replica replica-path)
        (declare (ignore left-path right-path replica-path))
        (let ((left-command nil) (right-command nil))
          (setf (gr8s.store::pod-store-consensus-commit-fn left)
                (lambda (tag payload) (setf left-command (list tag payload)))
                (gr8s.store::pod-store-consensus-commit-fn right)
                (lambda (tag payload) (setf right-command (list tag payload))))
          (gr8s.resources::create-core-resource left "configmaps"
                                      (configmap-input "from-left" "k" "left") "default")
          (gr8s.resources::create-core-resource right "configmaps"
                                      (configmap-input "from-right" "k" "right") "default")
          (apply-ha-core-command replica left-command)
          (apply-ha-core-command replica right-command)
          (is (equal "left" (configmap-value replica "from-left" "k"))
              "the later stale member command preserves the earlier committed key")
          (is (equal "right" (configmap-value replica "from-right" "k"))
              "the later member's own key is committed too"))))))

(test leader-installs-its-own-synchronously-committed-delta
  ;; The real Raft proposer may synchronously invoke this member's apply callback
  ;; before WITH-STORE-LOCK has unwound its dynamic *CORE-WRITE-ACTIVE* binding.
  ;; Applying a committed delta must publish it locally, not mistake it for a new
  ;; author-side transaction and stash it for a second proposal (podster-7bw).
  (with-temporary-store (store path)
    (declare (ignore path))
    (setf (gr8s.store::pod-store-consensus-commit-fn store)
          (lambda (tag payload)
            (apply-ha-core-command store (list tag payload))))
    (gr8s.resources::create-core-resource store "configmaps"
                                (configmap-input "leader-local" "k" "committed")
                                "default")
    (is (equal "committed" (configmap-value store "leader-local" "k"))
        "the proposing leader publishes its own committed delta")))

(defun ha-member-for-store (id store)
  "A member whose state machine installs replicated core-state blobs on STORE."
  (gr8s.raft.transport::start-raft-member
   id :apply-fn (lambda (command)
                  (when (consp command)
                    (case (car command)
                      (:core-state (gr8s.resources::install-core-state-blob store (second command)))
                      (:core-delta (gr8s.resources::install-core-state-delta store (second command)))
                      (:secrets-encryption
                       (gr8s.resources::install-secret-encryption-command store (second command)))
                      (:pod-state (gr8s.store::install-pod-state-blob store (second command)))
                      (:pod-delta (gr8s.store::install-pod-state-delta store (second command)))
                      (:node-state (gr8s.store::install-node-state-blob store (second command)))
                      (:node-delta (gr8s.store::install-node-state-delta store (second command))))))))

(defun wire-ha-store (store member)
  "Make STORE's durable writes replicate through MEMBER's Raft log."
  (setf (gr8s.store::pod-store-consensus-commit-fn store)
        (lambda (tag json)
          (multiple-value-bind (result committed)
              (gr8s.raft.transport::raft-member-propose-sync member (list tag json) :timeout 10)
            (declare (ignore result))
            (unless (eq committed t) (error "core write did not commit (not leader)"))))))

(defun store-of-member (member a sa b sb c sc)
  (cond ((eq member a) sa) ((eq member b) sb) ((eq member c) sc)))

(test ha-core-writes-replicate-and-survive-failover
  (with-temporary-store (sa pa)
    (with-temporary-store (sb pb)
      (with-temporary-store (sc pc)
        (declare (ignore pa pb pc))
        (let* ((a (ha-member-for-store "a" sa))
               (b (ha-member-for-store "b" sb))
               (c (ha-member-for-store "c" sc))
               (members (list a b c))
               (live members))
          (unwind-protect
               (progn
                 (dolist (self (list (list "a" a) (list "b" b) (list "c" c)))
                   (gr8s.raft.transport::raft-member-set-peers
                    (second self)
                    (loop for other in (list (list "a" a) (list "b" b) (list "c" c))
                          unless (equal (first other) (first self))
                            collect (list (first other) (gr8s.raft.transport::raft-member-host (second other))
                                          (gr8s.raft.transport::raft-member-port (second other))))))
                 (dolist (m members) (gr8s.raft.transport::raft-member-start m))
                 (is (poll-until (lambda () (= 1 (count-if #'gr8s.raft.transport::raft-member-leader-p members)))))
                 (wire-ha-store sa a) (wire-ha-store sb b) (wire-ha-store sc c)

                 ;; Create on the leader's store; it replicates to all three.
                 (let* ((leader (find-if #'gr8s.raft.transport::raft-member-leader-p members))
                        (leader-store (store-of-member leader a sa b sb c sc)))
                   (gr8s.resources::create-core-resource leader-store "configmaps"
                                               (configmap-input "cm1" "k" "v1") "default")
                   (is (poll-until
                        (lambda () (every (lambda (s) (equal "v1" (configmap-value s "cm1" "k")))
                                          (list sa sb sc))))
                       "the create replicates to every member's store")

                   ;; Update on the leader; the new value replicates too.
                   (gr8s.resources::update-core-resource
                    leader-store "configmaps" "default" "cm1"
                    (lambda (object) (setf (gethash "k" (gethash "data" object)) "v2") object))
                   (is (poll-until
                        (lambda () (every (lambda (s) (equal "v2" (configmap-value s "cm1" "k")))
                                          (list sa sb sc))))
                       "the update replicates to every member's store"))

                 ;; Kill the leader; a survivor takes over with the data intact.
                 (let ((old-leader (find-if #'gr8s.raft.transport::raft-member-leader-p members)))
                   (gr8s.raft.transport::stop-raft-member old-leader)
                   (setf live (remove old-leader live))
                   (is (poll-until (lambda () (= 1 (count-if #'gr8s.raft.transport::raft-member-leader-p live))) :timeout 15)
                       "the survivors elect a new leader")
                   (let* ((new-leader (find-if #'gr8s.raft.transport::raft-member-leader-p live))
                          (new-store (store-of-member new-leader a sa b sb c sc)))
                     (is (equal "v2" (configmap-value new-store "cm1" "k"))
                         "the new leader kept the committed ConfigMap")
                     ;; A new write commits under the new leader and replicates to the survivors.
                     (gr8s.resources::create-core-resource new-store "configmaps"
                                                 (configmap-input "cm2" "k" "w1") "default")
                     (is (poll-until
                          (lambda () (every (lambda (m)
                                              (equal "w1" (configmap-value
                                                           (store-of-member m a sa b sb c sc) "cm2" "k")))
                                            live))
                          :timeout 10)
                         "the post-failover create replicates to every survivor")
                     ;; A delete also replicates to every survivor's store.
                     (gr8s.resources::delete-core-resource new-store "configmaps" "default" "cm1")
                     (is (poll-until
                          (lambda () (every (lambda (m)
                                              (null (configmap-value
                                                     (store-of-member m a sa b sb c sc) "cm1" "k")))
                                            live))
                          :timeout 10)
                         "a delete replicates to every survivor's store"))))
            (dolist (m live) (ignore-errors (gr8s.raft.transport::stop-raft-member m)))))))))

(defun capture-ha-core-write (store function)
  (let ((original (gr8s.store::pod-store-consensus-commit-fn store)) (command nil))
    (unwind-protect
         (progn
           (setf (gr8s.store::pod-store-consensus-commit-fn store)
                 (lambda (tag payload) (setf command (list tag payload)) nil))
           (funcall function)
           command)
      (setf (gr8s.store::pod-store-consensus-commit-fn store) original))))

(test concurrent-core-writers-conflict-without-partial-publication
  (with-temporary-store (left lp)
    (with-temporary-store (right rp)
      (declare (ignore lp rp))
      (let ((seed (capture-ha-core-write
                   left (lambda () (gr8s.resources::create-core-resource left "configmaps"
                                    (configmap-input "shared" "k" "base") "default")))))
        (dolist (store (list left right)) (apply-ha-core-command store seed)))
      ;; A restored/local-event-heavy member may expose a different RV for the
      ;; same replicated object. Conditions must not compare those local clocks.
      (setf (gr8s.store::pod-store-resource-revision right) 10000)
      (setf (gethash "resourceVersion" (gethash "metadata"
                     (gethash '("configmaps" "default" "shared") (gr8s.store::pod-store-resources right)))) "10000")
      (let* ((winner (capture-ha-core-write left
                       (lambda () (gr8s.resources::update-core-resource left "configmaps" "default" "shared"
                         (lambda (object) (setf (gethash "k" (gethash "data" object)) "winner") object)))))
             (loser (capture-ha-core-write right
                      (lambda () (gr8s.resources::update-core-resource right "configmaps" "default" "shared"
                        (lambda (object) (setf (gethash "k" (gethash "data" object)) "loser") object))))))
        (dolist (store (list left right))
          (apply-ha-core-command store winner)
          (let ((revision (gr8s.store::pod-store-resource-revision store))
                (history (gr8s.store::pod-store-template-history store)))
            (is (equal '(:core-conflict) (apply-ha-core-command store loser)))
            (is (= revision (gr8s.store::pod-store-resource-revision store)))
            (is (eq history (gr8s.store::pod-store-template-history store)))
            (is (equal "winner" (configmap-value store "shared" "k")))))))))

(test stale-delete-cannot-remove-a-recreated-core-object
  (with-temporary-store (store root)
    (declare (ignore root))
    (gr8s.resources::create-core-resource store "configmaps" (configmap-input "aba" "k" "same") "default")
    (let ((stale (capture-ha-core-write store
                   (lambda () (gr8s.resources::delete-core-resource store "configmaps" "default" "aba")))))
      (gr8s.resources::delete-core-resource store "configmaps" "default" "aba")
      (gr8s.resources::create-core-resource store "configmaps" (configmap-input "aba" "k" "same") "default")
      (is (equal '(:core-conflict) (apply-ha-core-command store stale)))
      (is (equal "same" (configmap-value store "aba" "k"))))))

(test core-map-conflicts-reject-the-whole-transaction
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((resources (gr8s.resources::copy-core-resource-index store))
           (jobs (gr8s.resources::core-object "job" (gr8s.resources::core-object "finished" 1)))
           (payload (gr8s.resources::core-state-delta-json
                     store resources 1 (gr8s.store::pod-store-workload-deletions store) jobs)))
      (setf (gethash "job" (gr8s.store::pod-store-job-controller-states store))
            (gr8s.resources::core-object "finished" 2))
      (is (equal '(:core-conflict) (gr8s.resources::install-core-state-delta store payload)))
      (is (= 2 (gethash "finished" (gethash "job" (gr8s.store::pod-store-job-controller-states store)))))
      (is (= 0 (gr8s.store::pod-store-resource-revision store))))))

(test encrypted-core-preconditions-preserve-secrecy-and-reject-stale-policy
  (with-temporary-store (store root)
    (declare (ignore root))
    (gr8s.resources::enable-secret-encryption store)
    (gr8s.resources::create-core-resource store "secrets" (ha-secret-input "guarded" "c2VjcmV0LW9sZA==") "default")
    (let ((command (capture-ha-core-write store
                     (lambda () (gr8s.resources::update-core-resource store "secrets" "default" "guarded"
                       (lambda (object)
                         (setf (gethash "password" (gethash "data" object)) "c2VjcmV0LW5ldw==") object))))))
      (is (null (search "c2VjcmV0LW9sZA==" (second command))))
      (is (null (search "c2VjcmV0LW5ldw==" (second command))))
      (gr8s.resources::prepare-secret-encryption-key store)
      (let ((config (gr8s.store::pod-store-secret-encryption-config store)))
        (is (equal '(:core-conflict) (apply-ha-core-command store command)))
        (is (eq config (gr8s.store::pod-store-secret-encryption-config store)))
        (is (equal "c2VjcmV0LW9sZA==" (ha-secret-value store "guarded")))))))

(test a-core-key-conflict-rejects-all-other-effects-in-the-same-delta
  (with-temporary-store (store root)
    (declare (ignore root))
    (dolist (name '("first" "second"))
      (gr8s.resources::create-core-resource store "configmaps" (configmap-input name "k" "base") "default"))
    (let ((resources (gr8s.resources::copy-core-resource-index store)))
      (dolist (name '("first" "second"))
        (let* ((key (list "configmaps" "default" name))
               (object (gr8s.resources::copy-core-object (gethash key resources))))
          (setf (gethash "k" (gethash "data" object)) "staged"
                (gethash key resources) object)))
      (let ((payload (gr8s.resources::core-state-delta-json
                      store resources 4 (gr8s.store::pod-store-workload-deletions store)
                      (gr8s.store::pod-store-job-controller-states store))))
        (gr8s.resources::update-core-resource store "configmaps" "default" "second"
          (lambda (object) (setf (gethash "k" (gethash "data" object)) "winner") object))
        (let ((revision (gr8s.store::pod-store-resource-revision store)))
          (is (equal '(:core-conflict) (gr8s.resources::install-core-state-delta store payload)))
          (is (= revision (gr8s.store::pod-store-resource-revision store)))
          (is (equal "base" (configmap-value store "first" "k")))
          (is (equal "winner" (configmap-value store "second" "k"))))))))

(test encrypted-prior-object-conditions-apply-and-survive-reopen
  (with-temporary-store (store root)
    (gr8s.resources::enable-secret-encryption store)
    (gr8s.resources::create-core-resource store "secrets" (ha-secret-input "updated" "b2xk") "default")
    (let ((command (capture-ha-core-write store
                     (lambda () (gr8s.resources::update-core-resource store "secrets" "default" "updated"
                       (lambda (object) (setf (gethash "password" (gethash "data" object)) "bmV3") object))))))
      (is (equal '(:core-ok) (apply-ha-core-command store command)))
      (is (equal "bmV3" (ha-secret-value store "updated")))
      (is (equal "bmV3" (ha-secret-value (gr8s.store::open-store root) "updated"))))))

(test replicated-core-conditions-include-status-and-case-sensitive-content
  (let* ((before (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "uid" "same-uid" "resourceVersion" "1")
                                  "spec" (gr8s.resources::core-object "mode" "Active")
                                  "status" (gr8s.resources::core-object "ready" 1)))
         (after (gr8s.resources::copy-core-object before)))
    (setf (gethash "resourceVersion" (gethash "metadata" after)) "10000")
    (is-true (gr8s.resources::core-replicated-state-equal-p before after))
    (setf (gethash "ready" (gethash "status" after)) 2)
    (is-false (gr8s.resources::core-replicated-state-equal-p before after))
    (setf (gethash "ready" (gethash "status" after)) 1
          (gethash "mode" (gethash "spec" after)) "active")
    (is-false (gr8s.resources::core-replicated-state-equal-p before after))))

;;; podster-uvs: the node-delta CAS compared whole replicated objects including
;;; the lease clock (lastHeartbeat/leaseDeadline/readySince), which renews every
;;; few seconds on the session-owning member. A write racing a heartbeat then
;;; got member-dependent conflict verdicts: some replicas silently skipped the
;;; committed delta, the stores forked, and every later delta from the forked
;;; side conflicted forever (the observed livelock: leader stale + NotReady,
;;; author fresh + Ready, handshakes refused ~1/s). The verdict must depend
;;; only on stable state, and a skipped committed delta must be journaled.

(test node-state-comparison-ignores-the-volatile-lease-clock
  (with-temporary-store (store path)
    (declare (ignorable path))
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record
            :id "n1" :name "n1" :pod-cidr "10.88.1.0/24"
            :underlay-address "192.0.2.10"))
    (let* ((node (gethash "n1" (gr8s.store::pod-store-nodes store)))
           (base (gr8s.store::node-replicated-object node))
           (heartbeat-moved (gr8s.store::copy-pod-status-value base))
           (stable-changed (gr8s.store::copy-pod-status-value base)))
      (setf (gethash "lastHeartbeat" heartbeat-moved) 4003900000
            (gethash "leaseDeadline" heartbeat-moved) 4003900015
            (gethash "readySince" heartbeat-moved) 4003899000
            (gethash "resourceVersion" heartbeat-moved) "9999")
      (is (gr8s.store::node-object-same-state-p base heartbeat-moved)
          "a moved lease clock is not a state difference")
      (setf (gethash "annotations" stable-changed)
            (gr8s.resources::core-object "example/a" "1"))
      (is (not (gr8s.store::node-object-same-state-p base stable-changed))
          "a real (stable) change still differs"))))

(test racing-write-with-stale-lease-clock-applies-identically
  ;; Two replicas at the same baseline apply the same committed delta whose
  ;; expected image has an older heartbeat than current (the author built it
  ;; before an interleaved heartbeat delta landed). Both must INSTALL it --
  ;; and end byte-identical -- rather than skip it on whichever member's
  ;; clock happened to differ.
  (flet ((replica ()
           (let ((store (gr8s.store::open-store
                         (uiop:ensure-directory-pathname
                          (sb-posix:mkdtemp
                           (namestring (merge-pathnames "gr8s-replica-XXXXXX"
                                                        (uiop:temporary-directory))))))))
             (gr8s.controllers::register-node
              store (gr8s.model::make-node-record
                     :id "n1" :name "n1" :pod-cidr "10.88.1.0/24"
                     :underlay-address "192.0.2.10"))
             ;; Current state: a fresh heartbeat has already applied.
             (let ((node (gethash "n1" (gr8s.store::pod-store-nodes store))))
               (setf (gr8s.model::node-record-ready-p node) t
                     (gr8s.model::node-record-last-heartbeat node) 4003900110
                     (gr8s.model::node-record-lease-deadline node) 4003900125))
             store)))
    (let* ((a (replica)) (b (replica))
           (current (gr8s.store::node-replicated-object
                     (gethash "n1" (gr8s.store::pod-store-nodes a))))
           (expected (gr8s.store::copy-pod-status-value current))
           (object (gr8s.store::copy-pod-status-value current)))
      ;; The author's images carry the OLDER clock it saw...
      (dolist (image (list expected object))
        (setf (gethash "lastHeartbeat" image) 4003900100
              (gethash "leaseDeadline" image) 4003900115))
      ;; ...and the write's real payload: an annotation.
      (setf (gethash "annotations" object) (gr8s.resources::core-object "example/a" "1")
            (gethash "resourceVersion" object) "4200")
      (let ((delta (com.inuoe.jzon:stringify
                    (gr8s.resources::core-object
                     "version" 2 "resourceVersion" "4200"
                     "changes" (vector (gr8s.resources::core-object
                                        "name" "n1" "expected" expected "object" object))))))
        (let ((result-a (gr8s.store::install-node-state-delta a delta))
              (result-b (gr8s.store::install-node-state-delta b delta)))
          (is (eq :node-ok (first result-a))
              "a lease-clock difference alone must not refuse a committed delta")
          (is (equal (first result-a) (first result-b))
              "every replica reaches the same verdict")
          (let ((view-a (gr8s.store::node-replicated-object (gethash "n1" (gr8s.store::pod-store-nodes a))))
                (view-b (gr8s.store::node-replicated-object (gethash "n1" (gr8s.store::pod-store-nodes b)))))
            (is (gr8s.store::json-value-equal-p view-a view-b)
                "replicas converge")
            (is (gethash "annotations" view-a)
                "the write's payload was installed")))))))

(test a-real-node-conflict-is-journaled-when-skipped
  (with-temporary-store (store path)
    (declare (ignorable path))
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record
            :id "n1" :name "n1" :pod-cidr "10.88.1.0/24"
            :underlay-address "192.0.2.10"))
    (let* ((current (gr8s.store::node-replicated-object
                     (gethash "n1" (gr8s.store::pod-store-nodes store))))
           (expected (gr8s.store::copy-pod-status-value current))
           (object (gr8s.store::copy-pod-status-value current)))
      ;; A genuinely stale basis: expected names labels current never had.
      (setf (gethash "labels" expected) (gr8s.resources::core-object "stale" "basis")
            (gethash "labels" object) (gr8s.resources::core-object "new" "value"))
      (let* ((delta (com.inuoe.jzon:stringify
                     (gr8s.resources::core-object
                      "version" 2 "resourceVersion" "4300"
                      "changes" (vector (gr8s.resources::core-object
                                         "name" "n1" "expected" expected "object" object)))))
             (complaints (make-string-output-stream))
             (result (let ((*error-output* complaints))
                       (gr8s.store::install-node-state-delta store delta))))
        (is (equal '(:node-conflict) result))
        (is (search "n1" (get-output-stream-string complaints))
            "a skipped committed delta is journaled, not silent")))))
