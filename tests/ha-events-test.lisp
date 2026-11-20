;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Every member of an HA control plane shows the same Events (podster-xm5). An
;;;; Event is written through Raft like any other object, wherever it is written,
;;;; so a client sees it through whichever API server it asks. Each member expires
;;;; its own copy, and a member whose copy differs takes the next write as it is.

(in-package #:gr8s/tests)
(def-suite ha-events :in gr8s)
(in-suite ha-events)

(defun ha-event-input (name)
  (gr8s.resources::core-object
   "apiVersion" "v1" "kind" "Event"
   "metadata" (gr8s.resources::core-object "name" name)
   "involvedObject" (gr8s.resources::core-object "namespace" "default" "kind" "Pod" "name" "worker")
   "eventTime" "2017-09-19T14:42:36.000000Z"
   "message" "Observed" "reason" "Test" "action" "Observe" "type" "Normal"
   "reportingComponent" "test" "reportingInstance" "n1" "count" 1))

(defun ha-event (store name)
  (ignore-errors (gr8s.resources::get-core-resource store "events" "default" name)))

(defun ha-has-event (store name)
  (and (ha-event store name) t))

(defun ha-event-count (store name)
  (let ((event (ha-event store name)))
    (and event (gethash "count" event))))

(defun ha-expire-events (store seconds-from-now)
  "Run STORE's own Event expiry as it will run SECONDS-FROM-NOW."
  (let ((gr8s.resources::*event-clock* (lambda () (+ (get-universal-time) seconds-from-now))))
    (bt:with-lock-held ((gr8s.store::pod-store-lock store))
      (gr8s.resources::expire-core-events-unlocked store))))

(defun call-with-ha-event-cluster (function)
  "Call FUNCTION with the stores of a leader and two followers."
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
                      :timeout 15))
                 (funcall function s1 s2 s3))
            (dolist (h (list h1 h2 h3)) (when h (ignore-errors (gr8s.ha::stop-ha-control-plane h))))))))))

(test an-event-is-visible-through-every-member
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (gr8s.resources::create-core-resource s1 "events" (ha-event-input "on-leader") "default")
     (is (poll-until (lambda () (every (lambda (s) (ha-has-event s "on-leader")) (list s1 s2 s3))) :timeout 10)
         "an Event written on the leader reaches both followers")
     ;; A node's status report, which carries its kubelet's Events, may arrive at a follower.
     (gr8s.resources::create-core-resource s2 "events" (ha-event-input "on-follower") "default")
     (is (poll-until (lambda () (every (lambda (s) (ha-has-event s "on-follower")) (list s1 s2 s3))) :timeout 10)
         "an Event written on a follower reaches the leader and the other follower")
     (gr8s.resources::update-core-resource s1 "events" "default" "on-leader"
                                           (lambda (event) (setf (gethash "count" event) 2) event))
     (is (poll-until (lambda () (every (lambda (s) (eql 2 (ha-event-count s "on-leader"))) (list s1 s2 s3))) :timeout 10)
         "and so does a change to it")
     (gr8s.resources::delete-core-resource s1 "events" "default" "on-follower")
     (is (poll-until (lambda () (notany (lambda (s) (ha-has-event s "on-follower")) (list s1 s2 s3))) :timeout 10)
         "and its deletion"))))

(test each-member-expires-its-own-copy-of-an-event
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (gr8s.resources::create-core-resource s1 "events" (ha-event-input "old") "default")
     (is (poll-until (lambda () (every (lambda (s) (ha-has-event s "old")) (list s1 s2 s3))) :timeout 10))
     (dolist (store (list s1 s2 s3))
       (ha-expire-events store (- gr8s.resources::*event-ttl-seconds* 60))
       (is (ha-has-event store "old") "an Event lasts its hour on every member")
       (ha-expire-events store (+ gr8s.resources::*event-ttl-seconds* 60))
       (is-false (ha-has-event store "old") "and then each member drops its copy"))
     ;; Expiry proposed nothing, and left the members able to agree on what follows.
     (gr8s.resources::create-core-resource s1 "configmaps" (configmap-input "after" "k" "v") "default")
     (is (poll-until (lambda () (every (lambda (s) (equal "v" (configmap-value s "after" "k"))) (list s1 s2 s3)))
                     :timeout 10)))))

(test a-member-without-an-event-takes-the-next-write-of-it
  ;; Members expire by their own clocks, and before Events were replicated each
  ;; held different ones. A write that names a previous value a member does not
  ;; hold must not be refused there, or that member would never show the Event.
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (gr8s.resources::create-core-resource s1 "events" (ha-event-input "counted") "default")
     (is (poll-until (lambda () (every (lambda (s) (ha-has-event s "counted")) (list s1 s2 s3))) :timeout 10))
     (ha-expire-events s2 (+ gr8s.resources::*event-ttl-seconds* 60))
     (is-false (ha-has-event s2 "counted"))
     (gr8s.resources::update-core-resource s1 "events" "default" "counted"
                                           (lambda (event) (setf (gethash "count" event) 7) event))
     (is (poll-until (lambda () (every (lambda (s) (eql 7 (ha-event-count s "counted"))) (list s1 s2 s3))) :timeout 10)
         "the member that had dropped the Event holds it again")
     (gr8s.resources::delete-core-resource s1 "events" "default" "counted")
     (ha-expire-events s3 0)
     (gr8s.resources::create-core-resource s1 "events" (ha-event-input "counted") "default")
     (gr8s.resources::delete-core-resource s1 "events" "default" "counted")
     (is (poll-until (lambda () (notany (lambda (s) (ha-has-event s "counted")) (list s1 s2 s3))) :timeout 10)
         "and a deletion is taken by every member too"))))

(test deleting-a-collection-of-events-reaches-every-member
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (let* ((event (ha-event-input "selected"))
            (metadata (gethash "metadata" event)))
       (setf (gethash "labels" metadata) (gr8s.resources::core-object "testevent-set" "true"))
       (gr8s.resources::create-core-resource s1 "events" event "default"))
     (gr8s.resources::create-core-resource s1 "events" (ha-event-input "kept") "default")
     (is (poll-until (lambda () (every (lambda (s) (and (ha-has-event s "selected") (ha-has-event s "kept")))
                                       (list s1 s2 s3)))
                     :timeout 10))
     (gr8s.resources::delete-template-collection s1 "default" "testevent-set=true" "" :resource "events")
     (is (poll-until (lambda () (notany (lambda (s) (ha-has-event s "selected")) (list s1 s2 s3))) :timeout 10))
     (is (every (lambda (s) (ha-has-event s "kept")) (list s1 s2 s3))))))
