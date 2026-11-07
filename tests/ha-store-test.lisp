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
  (let ((object (ignore-errors (gr8s::get-core-resource store "configmaps" "default" name))))
    (and object (gethash key (gethash "data" object)))))

(defun apply-ha-core-command (store command)
  "Apply one captured HA core command to STORE, as the Raft state machine does."
  (case (first command)
    (:core-state (gr8s::install-core-state-blob store (second command)))
    (:core-delta (gr8s::install-core-state-delta store (second command)))
    (t (error "Unsupported HA core command ~S" (first command)))))

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
          (setf (gr8s::pod-store-consensus-commit-fn left)
                (lambda (tag payload) (setf left-command (list tag payload)))
                (gr8s::pod-store-consensus-commit-fn right)
                (lambda (tag payload) (setf right-command (list tag payload))))
          (gr8s::create-core-resource left "configmaps"
                                      (configmap-input "from-left" "k" "left") "default")
          (gr8s::create-core-resource right "configmaps"
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
    (setf (gr8s::pod-store-consensus-commit-fn store)
          (lambda (tag payload)
            (apply-ha-core-command store (list tag payload))))
    (gr8s::create-core-resource store "configmaps"
                                (configmap-input "leader-local" "k" "committed")
                                "default")
    (is (equal "committed" (configmap-value store "leader-local" "k"))
        "the proposing leader publishes its own committed delta")))

(defun ha-member-for-store (id store)
  "A member whose state machine installs replicated core-state blobs on STORE."
  (gr8s::start-raft-member
   id :apply-fn (lambda (command)
                  (when (consp command)
                    (case (car command)
                      (:core-state (gr8s::install-core-state-blob store (second command)))
                      (:core-delta (gr8s::install-core-state-delta store (second command)))
                      (:pod-state (gr8s::install-pod-state-blob store (second command)))
                      (:node-state (gr8s::install-node-state-blob store (second command)))
                      (:node-delta (gr8s::install-node-state-delta store (second command))))))))

(defun wire-ha-store (store member)
  "Make STORE's durable writes replicate through MEMBER's Raft log."
  (setf (gr8s::pod-store-consensus-commit-fn store)
        (lambda (tag json)
          (multiple-value-bind (result committed)
              (gr8s::raft-member-propose-sync member (list tag json) :timeout 10)
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
                   (gr8s::raft-member-set-peers
                    (second self)
                    (loop for other in (list (list "a" a) (list "b" b) (list "c" c))
                          unless (equal (first other) (first self))
                            collect (list (first other) (gr8s::raft-member-host (second other))
                                          (gr8s::raft-member-port (second other))))))
                 (dolist (m members) (gr8s::raft-member-start m))
                 (is (poll-until (lambda () (= 1 (count-if #'gr8s::raft-member-leader-p members)))))
                 (wire-ha-store sa a) (wire-ha-store sb b) (wire-ha-store sc c)

                 ;; Create on the leader's store; it replicates to all three.
                 (let* ((leader (find-if #'gr8s::raft-member-leader-p members))
                        (leader-store (store-of-member leader a sa b sb c sc)))
                   (gr8s::create-core-resource leader-store "configmaps"
                                               (configmap-input "cm1" "k" "v1") "default")
                   (is (poll-until
                        (lambda () (every (lambda (s) (equal "v1" (configmap-value s "cm1" "k")))
                                          (list sa sb sc))))
                       "the create replicates to every member's store")

                   ;; Update on the leader; the new value replicates too.
                   (gr8s::update-core-resource
                    leader-store "configmaps" "default" "cm1"
                    (lambda (object) (setf (gethash "k" (gethash "data" object)) "v2") object))
                   (is (poll-until
                        (lambda () (every (lambda (s) (equal "v2" (configmap-value s "cm1" "k")))
                                          (list sa sb sc))))
                       "the update replicates to every member's store"))

                 ;; Kill the leader; a survivor takes over with the data intact.
                 (let ((old-leader (find-if #'gr8s::raft-member-leader-p members)))
                   (gr8s::stop-raft-member old-leader)
                   (setf live (remove old-leader live))
                   (is (poll-until (lambda () (= 1 (count-if #'gr8s::raft-member-leader-p live))) :timeout 15)
                       "the survivors elect a new leader")
                   (let* ((new-leader (find-if #'gr8s::raft-member-leader-p live))
                          (new-store (store-of-member new-leader a sa b sb c sc)))
                     (is (equal "v2" (configmap-value new-store "cm1" "k"))
                         "the new leader kept the committed ConfigMap")
                     ;; A new write commits under the new leader and replicates to the survivors.
                     (gr8s::create-core-resource new-store "configmaps"
                                                 (configmap-input "cm2" "k" "w1") "default")
                     (is (poll-until
                          (lambda () (every (lambda (m)
                                              (equal "w1" (configmap-value
                                                           (store-of-member m a sa b sb c sc) "cm2" "k")))
                                            live))
                          :timeout 10)
                         "the post-failover create replicates to every survivor")
                     ;; A delete also replicates to every survivor's store.
                     (gr8s::delete-core-resource new-store "configmaps" "default" "cm1")
                     (is (poll-until
                          (lambda () (every (lambda (m)
                                              (null (configmap-value
                                                     (store-of-member m a sa b sb c sc) "cm1" "k")))
                                            live))
                          :timeout 10)
                         "a delete replicates to every survivor's store"))))
            (dolist (m live) (ignore-errors (gr8s::stop-raft-member m)))))))))
