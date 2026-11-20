;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Every member of an HA control plane shows the same Events (podster-xm5). An
;;;; Event is written through Raft like any other object, wherever it is written,
;;;; so a client sees it through whichever API server it asks. It leaves every
;;;; member in the same write, an hour after its author's time, and a member whose
;;;; copy differs takes the next write as it is. Nothing a member does alone takes
;;;; a revision, so every member gives an object the same resourceVersion
;;;; (podster-gts).

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

(defun ha-drop-event (store name)
  "Make STORE lack an Event the other members hold, as after a snapshot."
  (bt:with-lock-held ((gr8s.store::pod-store-lock store))
    (remhash (gr8s.resources::core-resource-key "events" "default" name)
             (gr8s.store::pod-store-resources store))))

(defun ha-write-at (store seconds-from-now name)
  "Write a ConfigMap through STORE as its author's clock will read SECONDS-FROM-NOW."
  (let ((gr8s.resources::*event-clock* (lambda () (+ (get-universal-time) seconds-from-now))))
    (gr8s.resources::create-core-resource store "configmaps" (configmap-input name "k" "v") "default")))

(defun ha-revisions (stores)
  (mapcar #'gr8s.store::pod-store-resource-revision stores))

(defun ha-configmap-version (store name)
  (let ((object (ignore-errors (gr8s.resources::get-core-resource store "configmaps" "default" name))))
    (and object (gethash "resourceVersion" (gethash "metadata" object)))))

(defun ha-members-agree-p (stores name)
  "Whether STORES count alike and give ConfigMap NAME one resourceVersion."
  (and (apply #'= (ha-revisions stores))
       (ha-configmap-version (first stores) name)
       (every (lambda (store) (equal (ha-configmap-version (first stores) name) (ha-configmap-version store name)))
              stores)))

(defun ha-versions-alike-p (stores)
  "Whether STORES count alike and hold one version of every object."
  (and (apply #'= (ha-revisions stores))
       (let ((digests (mapcar (lambda (store)
                                (bt:with-lock-held ((gr8s.store::pod-store-lock store))
                                  (gr8s.resources::core-versions-digest (gr8s.store::pod-store-resources store))))
                              stores)))
         (every (lambda (digest) (equal digest (first digests))) digests))))

(defun ha-plant-own-numbering (store name &key (lead 500))
  "Give STORE a revision LEAD ahead and a version of its own for ConfigMap NAME, as an old member had."
  (bt:with-lock-held ((gr8s.store::pod-store-lock store))
    (let* ((index (gr8s.resources::copy-core-resource-index store))
           (key (gr8s.resources::core-resource-key "configmaps" "default" name))
           (ahead (+ lead (gr8s.store::pod-store-resource-revision store)))
           (gr8s.store::*unreplicated-write* t)
           (copy (gr8s.resources::copy-core-object (gethash key index))))
      (setf (gethash "resourceVersion" (gethash "metadata" copy)) (format nil "~D" (+ ahead 7))
            (gethash key index) copy)
      (gr8s.resources::commit-core-resources store index ahead))))

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

(test an-event-leaves-every-member-in-the-same-write
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (gr8s.resources::create-core-resource s1 "events" (ha-event-input "old") "default")
     (is (poll-until (lambda () (every (lambda (s) (ha-has-event s "old")) (list s1 s2 s3))) :timeout 10))
     (ha-write-at s1 (- gr8s.resources::*event-ttl-seconds* 60) "early")
     (is (poll-until (lambda () (every (lambda (s) (ha-configmap-version s "early")) (list s1 s2 s3))) :timeout 10))
     (is (every (lambda (s) (ha-has-event s "old")) (list s1 s2 s3)) "an Event lasts its hour on every member")
     ;; The write may come from any member; its time is what every member uses.
     (ha-write-at s2 (+ gr8s.resources::*event-ttl-seconds* 60) "late")
     (is (poll-until (lambda () (notany (lambda (s) (ha-has-event s "old")) (list s1 s2 s3))) :timeout 10)
         "and then leaves all of them")
     (is (poll-until (lambda () (ha-members-agree-p (list s1 s2 s3) "late")) :timeout 10)
         "at one revision, so the members still count alike"))))

(test nothing-a-member-does-alone-takes-a-revision
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (gr8s.resources::create-core-resource s1 "configmaps" (configmap-input "first" "k" "v") "default")
     (is (poll-until (lambda () (ha-members-agree-p (list s1 s2 s3) "first")) :timeout 10))
     ;; A watch or a list trims one member's history; a read asks it to expire Events.
     (bt:with-lock-held ((gr8s.store::pod-store-lock s2))
       (gr8s.resources::compact-template-history-unlocked s2 :checkpoint t)
       (let ((gr8s.resources::*event-clock*
               (lambda () (+ (get-universal-time) gr8s.resources::*event-ttl-seconds* 60))))
         (gr8s.resources::expire-core-events-unlocked s2)))
     (gr8s.resources::list-core-resources s3 "events")
     (gr8s.resources::create-core-resource s1 "configmaps" (configmap-input "second" "k" "v") "default")
     (is (poll-until (lambda () (ha-members-agree-p (list s1 s2 s3) "second")) :timeout 10)
         "the next object has one resourceVersion on every member")
     ;; So what a client read through a follower it can update through the leader.
     (let ((read (gr8s.resources::get-core-resource s2 "configmaps" "default" "second")))
       (finishes
         (gr8s.resources::update-core-resource
          s1 "configmaps" "default" "second"
          (lambda (current)
            (is (equal (gethash "resourceVersion" (gethash "metadata" read))
                       (gethash "resourceVersion" (gethash "metadata" current))))
            current)))))))

(test a-member-left-behind-takes-the-numbering-and-reissues-its-versions
  ;; Older versions let each member count for itself. After an upgrade the
  ;; members must come to agree without being rebuilt.
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (gr8s.resources::create-core-resource s1 "configmaps" (configmap-input "held" "k" "v") "default")
     (is (poll-until (lambda () (ha-members-agree-p (list s1 s2 s3) "held")) :timeout 10))
     ;; Give one follower a revision and a version of its own, as an old one had.
     (bt:with-lock-held ((gr8s.store::pod-store-lock s2))
       (let ((index (gr8s.resources::copy-core-resource-index s2))
             (key (gr8s.resources::core-resource-key "configmaps" "default" "held"))
             (ahead (+ 500 (gr8s.store::pod-store-resource-revision s2)))
             (gr8s.store::*unreplicated-write* t))
         (let ((copy (gr8s.resources::copy-core-object (gethash key index))))
           (setf (gethash "resourceVersion" (gethash "metadata" copy)) (write-to-string ahead)
                 (gethash key index) copy))
         (gr8s.resources::commit-core-resources s2 index ahead)))
     (is-false (ha-members-agree-p (list s1 s2 s3) "held"))
     (gr8s.resources::propose-core-version-mark s2)
     (is (poll-until (lambda () (ha-versions-alike-p (list s1 s2 s3))) :timeout 20)
         "the members that were behind take the higher numbering, and every object one version")
     (is (ha-members-agree-p (list s1 s2 s3) "held"))
     (is (> (parse-integer (ha-configmap-version s1 "held")) 500)))))

(test a-member-without-an-event-takes-the-next-write-of-it
  ;; A member that installed a snapshot holds its own Events, and before Events
  ;; were replicated each member held different ones. A write that names a previous value a member does not
  ;; hold must not be refused there, or that member would never show the Event.
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (gr8s.resources::create-core-resource s1 "events" (ha-event-input "counted") "default")
     (is (poll-until (lambda () (every (lambda (s) (ha-has-event s "counted")) (list s1 s2 s3))) :timeout 10))
     (ha-drop-event s2 "counted")
     (is-false (ha-has-event s2 "counted"))
     (gr8s.resources::update-core-resource s1 "events" "default" "counted"
                                           (lambda (event) (setf (gethash "count" event) 7) event))
     (is (poll-until (lambda () (every (lambda (s) (eql 7 (ha-event-count s "counted"))) (list s1 s2 s3))) :timeout 10)
         "the member that had dropped the Event holds it again")
     (gr8s.resources::delete-core-resource s1 "events" "default" "counted")
     (ha-drop-event s3 "counted")
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

(test a-version-this-server-has-not-reached-is-answered-as-too-large
  ;; client-go lists again without a resourceVersion only when it recognises
  ;; this cause; any other 504 it repeats until its informer gives up.
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((condition (handler-case
                         (progn (gr8s.resources::template-list-page store "default" nil nil :resource "configmaps"
                                                                    :resource-version "999999" :match "NotOlderThan")
                                nil)
                       (gr8s.model:kubernetes-error (condition) condition))))
      (is (eql 504 (gr8s.model:kubernetes-error-status-code condition)))
      (is (equal "Timeout" (gr8s.model:kubernetes-error-reason condition)))
      (let ((details (gr8s.model:kubernetes-error-details condition)))
        (is (eql 1 (gethash "retryAfterSeconds" details)))
        (is (equal "ResourceVersionTooLarge" (gethash "reason" (aref (gethash "causes" details) 0))))))))

(test objects-too-large-to-send-together-are-renumbered-too
  ;; Ten CustomResourceDefinitions are megabytes. Rewriting a hundred objects in
  ;; one write could exceed what a write may hold, and then never happened
  ;; (podster-b5d). Renumbering names the objects and does not carry them.
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (let ((large (make-string (* 500 1024) :initial-element #\x)))
       (dotimes (i 12)
         (gr8s.resources::create-core-resource s1 "configmaps" (configmap-input (format nil "large-~2,'0D" i) "k" large)
                                               "default")))
     (is (poll-until (lambda () (ha-members-agree-p (list s1 s2 s3) "large-11")) :timeout 30))
     (ha-plant-own-numbering s2 "large-07")
     (is-false (ha-versions-alike-p (list s1 s2 s3)))
     (gr8s.resources::propose-core-version-mark s2)
     (is (poll-until (lambda () (ha-versions-alike-p (list s1 s2 s3))) :timeout 40)
         "every object takes one version, however much the objects hold together"))))

(test a-follower-that-counted-ahead-is-followed-while-writes-go-on
  ;; The follower is not the author of the writes that go on, and what it says of
  ;; its revision is applied after other writes have been. The members compare
  ;; what they held at one place in the log, so that does not matter (podster-b5d).
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (gr8s.resources::create-core-resource s1 "configmaps" (configmap-input "held" "k" "v") "default")
     (is (poll-until (lambda () (ha-members-agree-p (list s1 s2 s3) "held")) :timeout 10))
     (ha-plant-own-numbering s2 "held")
     (let* ((stop nil)
            (writer (bt:make-thread
                     (lambda ()
                       (loop for i from 0 until stop
                             do (ignore-errors
                                 (gr8s.resources::create-core-resource
                                  s1 "configmaps" (configmap-input (format nil "busy-~D" i) "k" "v") "default")))))))
       (unwind-protect
            (progn
              (sleep 0.5)
              (gr8s.resources::propose-core-version-mark s2)
              (is (poll-until (lambda () (apply #'= (ha-revisions (list s1 s2 s3)))) :timeout 20)
                  "the members count alike while the writes go on"))
         (setf stop t)
         (bt:join-thread writer)))
     (is (poll-until (lambda () (ha-versions-alike-p (list s1 s2 s3))) :timeout 30)
         "and every object has one version")
     (is (> (parse-integer (ha-configmap-version s1 "held")) 500)))))

(test members-that-count-alike-and-hold-different-versions-renumber
  ;; What an upgrade can leave: the revisions agree, and objects written before
  ;; they did still have a version on each member (podster-b5d).
  (call-with-ha-event-cluster
   (lambda (s1 s2 s3)
     (gr8s.resources::create-core-resource s1 "configmaps" (configmap-input "held" "k" "v") "default")
     (is (poll-until (lambda () (ha-versions-alike-p (list s1 s2 s3))) :timeout 10))
     (ha-plant-own-numbering s3 "held" :lead 0)
     (is (apply #'= (ha-revisions (list s1 s2 s3))))
     (is-false (ha-versions-alike-p (list s1 s2 s3)))
     (gr8s.resources::propose-core-version-mark s2)
     (is (poll-until (lambda () (ha-versions-alike-p (list s1 s2 s3))) :timeout 20))
     ;; Once they agree, another round changes nothing.
     (let ((version (ha-configmap-version s1 "held")))
       (gr8s.resources::propose-core-version-mark s1)
       (sleep 4)
       (is (equal version (ha-configmap-version s1 "held")))
       (is (ha-versions-alike-p (list s1 s2 s3)))))))
