;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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

(defun ha-member-for-store (id store)
  "A member whose state machine installs replicated core-state blobs on STORE."
  (gr8s::start-raft-member
   id :apply-fn (lambda (command)
                  (when (consp command)
                    (case (car command)
                      (:core-state (gr8s::install-core-state-blob store (second command)))
                      (:pod-state (gr8s::install-pod-state-blob store (second command))))))))

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
