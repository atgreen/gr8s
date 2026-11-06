;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Controller writes made through COMMIT-CORE-RESOURCES directly (not the
;;;; create/update/delete API path) now replicate through Raft too
;;;; (podster-8ia.1), because WITH-STORE-LOCK is itself HA-aware. A ReplicaSet's
;;;; controller status, written on the leader by UPDATE-WORKLOAD-CONTROLLER-STATUS,
;;;; replicates to every member and survives leader failover.

(in-package #:gr8s/tests)
(def-suite ha-controller-write :in gr8s)
(in-suite ha-controller-write)

(defun ha-replicaset-fixture (name)
  (gr8s::core-object
   "apiVersion" "apps/v1" "kind" "ReplicaSet" "metadata" (gr8s::core-object "name" name)
   "spec" (gr8s::core-object
           "replicas" 1 "selector" (gr8s::core-object "matchLabels" (gr8s::core-object "app" name))
           "template" (gr8s::core-object
                       "metadata" (gr8s::core-object "labels" (gr8s::core-object "app" name))
                       "spec" (gr8s::core-object
                               "containers" (vector (gr8s::core-object "name" "main" "image" "busybox")))))))

(defun ha-replicaset-status-replicas (store name)
  (let ((rs (ignore-errors (gr8s::get-core-resource store "replicasets" "default" name))))
    (and rs (gethash "replicas" (gethash "status" rs (gr8s::core-object))))))

(test controller-status-write-replicates-and-survives-failover
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
                     "both followers joined (leader sees 2 peers)")
                 ;; Create the ReplicaSet (API path) on the leader.
                 (let ((owner (gr8s::create-core-resource s1 "replicasets"
                                                          (ha-replicaset-fixture "workers") "default")))
                   ;; A controller status write via the DIRECT commit path.
                   (gr8s::update-workload-controller-status
                    s1 "replicasets" owner (gr8s::core-object "replicas" 1 "readyReplicas" 1)))
                 ;; The controller-written status replicated to every member.
                 (is (poll-until
                      (lambda () (every (lambda (s) (eql 1 (ha-replicaset-status-replicas s "workers")))
                                        (list s1 s2 s3)))
                      :timeout 10)
                     "the controller status replicates to every member's store")
                 ;; Kill the leader; the survivors keep the controller-written status.
                 (gr8s::stop-ha-control-plane h1)
                 (setf h1 nil)
                 (is (poll-until (lambda () (or (gr8s::ha-control-plane-leader-p h2)
                                                (gr8s::ha-control-plane-leader-p h3)))
                                 :timeout 20)
                     "a survivor becomes leader")
                 (is (and (eql 1 (ha-replicaset-status-replicas s2 "workers"))
                          (eql 1 (ha-replicaset-status-replicas s3 "workers")))
                     "the controller status is not lost on failover"))
            (dolist (h (list h1 h2 h3)) (when h (ignore-errors (gr8s::stop-ha-control-plane h))))))))))
