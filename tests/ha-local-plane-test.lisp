;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Local-plane resources stay off the Raft log (podster-8ia.3). An Event written
;;;; on the leader is NOT replicated (each member keeps its own, self-expiring
;;;; events), while a ConfigMap written in the same cluster still replicates to
;;;; every member -- and the leader keeps its Event across that consensus write
;;;; (install preserves local-plane resources rather than dropping them).

(in-package #:gr8s/tests)
(def-suite ha-local-plane :in gr8s)
(in-suite ha-local-plane)

(defun ha-event-input (name)
  (gr8s::core-object
   "apiVersion" "v1" "kind" "Event"
   "metadata" (gr8s::core-object "name" name)
   "involvedObject" (gr8s::core-object "namespace" "default" "kind" "Pod" "name" "worker")
   "eventTime" "2017-09-19T14:42:36.000000Z"
   "message" "Observed" "reason" "Test" "action" "Observe" "type" "Normal"
   "reportingComponent" "test" "reportingInstance" "n1" "count" 1))

(defun ha-has-event (store name)
  (and (ignore-errors (gr8s::get-core-resource store "events" "default" name)) t))

(test events-stay-local-while-consensus-resources-replicate
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
                      :timeout 15))
                 ;; Write an Event (local plane) then a ConfigMap (consensus) on the leader.
                 (gr8s::create-core-resource s1 "events" (ha-event-input "e1") "default")
                 (is (ha-has-event s1 "e1") "the leader holds the event locally")
                 (gr8s::create-core-resource s1 "configmaps" (configmap-input "cm1" "k" "v1") "default")
                 ;; The ConfigMap replicates everywhere...
                 (is (poll-until
                      (lambda () (every (lambda (s) (equal "v1" (configmap-value s "cm1" "k")))
                                        (list s1 s2 s3)))
                      :timeout 10)
                     "the ConfigMap replicates to every member")
                 ;; ...the leader still has its event (install preserved it)...
                 (is (ha-has-event s1 "e1") "the leader keeps its event across the consensus write")
                 ;; ...and the event never reached the followers.
                 (sleep 0.5)
                 (is (not (ha-has-event s2 "e1")) "the event did not replicate to follower cp2")
                 (is (not (ha-has-event s3 "e1")) "the event did not replicate to follower cp3"))
            (dolist (h (list h1 h2 h3)) (when h (ignore-errors (gr8s::stop-ha-control-plane h))))))))))

(test event-delete-collection-stays-on-the-local-plane
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((control-plane nil))
      (unwind-protect
           (progn
             (setf control-plane
                   (gr8s::start-ha-control-plane store :id "cp1" :init t))
             (is (poll-until
                  (lambda () (gr8s::ha-control-plane-leader-p control-plane))))
             (let* ((event (ha-event-input "selected"))
                    (metadata (gethash "metadata" event)))
               (setf (gethash "labels" metadata)
                     (gr8s::core-object "testevent-set" "true"))
               (gr8s::create-core-resource store "events" event "default"))
             (is (ha-has-event store "selected"))
             (gr8s::delete-template-collection
              store "default" "testevent-set=true" "" :resource "events")
             (is-false (ha-has-event store "selected")))
        (when control-plane
          (ignore-errors (gr8s::stop-ha-control-plane control-plane)))))))
