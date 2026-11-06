;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Pod desired-state replication (podster-8ia.2): Pods live outside the
;;;; core-resource index, so c2d.7.2 did not replicate them -- on failover a new
;;;; leader would regenerate Pods with fresh identities while the old ones ran.
;;;; Now a Pod created on the leader replicates to every member and survives
;;;; leader loss with its identity (UID) intact.

(in-package #:gr8s/tests)
(def-suite ha-pod-failover :in gr8s)
(in-suite ha-pod-failover)

(defun ha-make-pod (store name)
  (gr8s::create-pod
   store
   (gr8s:parse-pod
    (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"~A\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"busybox\"}]}}"
            name))))

(defun ha-pod-uid (store name)
  (let ((pod (ignore-errors (gr8s:get-pod store "default" name))))
    (and pod (gr8s:pod-uid pod))))

(test pod-desired-state-replicates-and-survives-failover
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
                 ;; Create a Pod on the leader; capture its server-assigned UID.
                 (let ((uid (gr8s:pod-uid (ha-make-pod s1 "p1"))))
                   (is (stringp uid))
                   ;; It replicates to every member with the SAME identity.
                   (is (poll-until
                        (lambda () (every (lambda (s) (equal uid (ha-pod-uid s "p1"))) (list s1 s2 s3)))
                        :timeout 10)
                       "the Pod replicates to every member with its UID intact")
                   ;; Kill the leader; a survivor still has the Pod, same UID.
                   (gr8s::stop-ha-control-plane h1)
                   (setf h1 nil)
                   (is (poll-until (lambda () (or (gr8s::ha-control-plane-leader-p h2)
                                                  (gr8s::ha-control-plane-leader-p h3)))
                                   :timeout 20)
                       "a survivor becomes leader")
                   (is (and (equal uid (ha-pod-uid s2 "p1"))
                            (equal uid (ha-pod-uid s3 "p1")))
                       "the Pod (and its identity) is not lost on failover")))
            (dolist (h (list h1 h2 h3)) (when h (ignore-errors (gr8s::stop-ha-control-plane h))))))))))
