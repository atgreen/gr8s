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
  (gr8s.store::create-pod
   store
   (gr8s.kubelet::parse-pod
    (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"~A\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"busybox\"}]}}"
            name))))

(defun ha-pod-uid (store name)
  (let ((pod (ignore-errors (gr8s.store::get-pod store "default" name))))
    (and pod (gr8s.model::pod-uid pod))))

(defun ha-pod-node-name (store name)
  (let ((pod (ignore-errors (gr8s.store::get-pod store "default" name))))
    (and pod (gr8s.model::pod-node-name pod))))

(test replicated-pod-state-advances-the-follower-watch-journal
  ;; A follower may serve an in-cluster ListWatch.  Installing a replicated Pod
  ;; snapshot must therefore publish the same revisions and resumable events as
  ;; the authoring member, not merely replace the object visible to ordinary GETs.
  (with-temporary-store (source source-path)
    (with-temporary-store (follower follower-path)
      (declare (ignore source-path follower-path))
      (let ((pod (ha-make-pod source "watched")))
        (gr8s.store::install-pod-state-blob follower (gr8s.store::pod-state-json source))
        (let ((events (gr8s.apiserver::pod-watch-events follower "default" "" "" 0)))
          (is (equal '("ADDED") (mapcar (lambda (event) (gethash "type" event)) events))
              "the replicated create is resumable on the follower: ~S"
              (list :events (mapcar (lambda (event) (gethash "type" event)) events)
                    :journal (mapcar (lambda (entry)
                                       (list (first entry)
                                             (and (second entry) t)
                                             (and (third entry) t)))
                                     (gr8s.store::pod-store-pod-watch-journal follower))
                    :revision (gr8s.store::pod-store-pod-revision follower)
                    :floor (gr8s.store::pod-store-pod-watch-floor follower))))
        (let ((checkpoint (gr8s.store::pod-store-pod-revision follower)))
          (gr8s.controllers::update-pod-observed-status
           source pod
           (gr8s.resources::core-object
            "phase" "Running"
            "containerStatuses"
            (vector (gr8s.resources::core-object
                     "name" "main" "ready" t
                     "state" (gr8s.resources::core-object "running" (gr8s.resources::core-object))))))
          (gr8s.store::install-pod-state-blob follower (gr8s.store::pod-state-json source))
          (let* ((events (gr8s.apiserver::pod-watch-events follower "default" "" "" checkpoint))
                 (latest (car (last events))))
            (is (equal '("MODIFIED")
                       (mapcar (lambda (event) (gethash "type" event)) events))
                "the replicated observation is resumable on the follower")
            (is (equal "Running"
                       (and latest (gethash "phase" (gethash "status" (gethash "object" latest)))))
                "the replayed event carries the replicated status")
            (is (> (gr8s.store::pod-store-pod-revision follower) checkpoint)
                "the follower watermark advances with the replicated revision")))
        (let ((checkpoint (gr8s.store::pod-store-pod-revision follower)))
          (gr8s.store::delete-pod source "default" "watched")
          (gr8s.store::install-pod-state-blob follower (gr8s.store::pod-state-json source))
          (let ((events (gr8s.apiserver::pod-watch-events follower "default" "" "" checkpoint)))
            (is (equal '("DELETED")
                       (mapcar (lambda (event) (gethash "type" event)) events))
                "the replicated deletion is resumable on the follower")))))))

(test pod-deletion-replicates-the-revision-allocated-for-its-watch-event
  (with-temporary-store (source source-path)
    (declare (ignore source-path))
    (ha-make-pod source "deleted")
    (let ((payload nil))
      (setf (gr8s.store::pod-store-consensus-commit-fn source)
            (lambda (kind json)
              (when (eq kind :pod-delta)
                (setf payload json)
                (gr8s.store::install-pod-state-delta source json))))
      (gr8s.store::delete-pod source "default" "deleted")
      (let ((state (and payload (com.inuoe.jzon:parse payload))))
        (is (not (null state)) "the deletion emits a Pod state command")
        (is (equal (write-to-string (gr8s.store::pod-store-pod-revision source))
                   (and state (gethash "resourceVersion" state)))
            "the command includes the deletion event's revision")))))

(test stale-replicated-pod-state-cannot-undo-a-newer-deletion
  ;; Agent observations replicate a complete Pod snapshot.  One prepared before
  ;; a concurrent API deletion may be committed afterward, but it must not
  ;; resurrect the older desired object by erasing its deletion timestamp.
  (with-temporary-store (source source-path)
    (with-temporary-store (follower follower-path)
      (declare (ignore source-path follower-path))
      (ha-make-pod source "deleted")
      (let ((stale (gr8s.store::pod-state-json source)))
        (gr8s.store::mark-pod-deleting source "default" "deleted" :grace-period 30)
        (gr8s.store::install-pod-state-blob follower (gr8s.store::pod-state-json source))
        (let* ((deleting (gr8s.store::get-pod follower "default" "deleted"))
               (revision (gr8s.model::pod-resource-version deleting)))
          (is-true (gethash "deletionTimestamp"
                            (gethash "metadata" (gr8s.model::pod-to-object deleting))))
          (gr8s.store::install-pod-state-blob follower stale)
          (let ((current (gr8s.store::get-pod follower "default" "deleted")))
            (is (equal revision (gr8s.model::pod-resource-version current))
                "an older snapshot cannot replace newer desired state")
            (is-true (gethash "deletionTimestamp"
                              (gethash "metadata" (gr8s.model::pod-to-object current))))))))))

(test replicated-pod-events-advance-past-a-followers-newer-local-watermark
  ;; Different members own different agent sessions and may allocate revisions
  ;; concurrently.  A replicated transition must be newer than every revision
  ;; this follower has already returned from LIST, even when its source number
  ;; collides with or trails the follower's local watermark.
  (with-temporary-store (source source-path)
    (with-temporary-store (follower follower-path)
      (declare (ignore source-path follower-path))
      (let ((pod (ha-make-pod source "watched")))
        (dotimes (index 3)
          (ha-make-pod follower (format nil "local-~D" index)))
        (let ((checkpoint (gr8s.store::pod-store-pod-revision follower)))
          (gr8s.store::install-pod-state-blob follower (gr8s.store::pod-state-json source))
          (multiple-value-bind (events watermark)
              (gr8s.apiserver::pod-watch-events
               follower "default" "" "metadata.name=watched" checkpoint)
            (is (equal '("ADDED")
                       (mapcar (lambda (event) (gethash "type" event)) events))
                "a colliding replicated create remains visible after the LIST checkpoint")
            (is (> watermark checkpoint)
                "the follower assigns a watermark newer than one it already served")))
        (let ((checkpoint (gr8s.store::pod-store-pod-revision follower)))
          (gr8s.controllers::update-pod-observed-status
           source pod (gr8s.resources::core-object "phase" "Running"))
          (gr8s.store::install-pod-state-blob follower (gr8s.store::pod-state-json source))
          (let ((events (gr8s.apiserver::pod-watch-events
                         follower "default" "" "metadata.name=watched" checkpoint)))
            (is (equal '("MODIFIED")
                       (mapcar (lambda (event) (gethash "type" event)) events))
                "a trailing replicated status revision remains resumable")))))))

(test ha-pod-write-response-retries-a-transient-local-not-found
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((pod (gr8s.kubelet::parse-pod
                 "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"lagged\",\"namespace\":\"default\",\"uid\":\"uid-1\"},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"busybox\"}]}}"))
           (reconciler (gr8s.kubelet::make-reconciler store (gr8s.runtime::make-fake-runtime)))
           (attempts 0))
      ;; The presence of a consensus hook identifies the HA retry case.
      (setf (gr8s.store::pod-store-consensus-commit-fn store) (lambda (&rest ignored) (declare (ignore ignored))))
      (let ((status
              (gr8s.kubelet::reconcile-written-pod
               reconciler pod
               :reconcile
               (lambda (ignored-reconciler ignored-namespace ignored-name)
                 (declare (ignore ignored-reconciler ignored-namespace ignored-name))
                 (if (= 1 (incf attempts))
                     (gr8s.resources::core-resource-error 404 "NotFound" "replicated Pod not installed yet")
                     (gr8s.kubelet::pod-status "Pending"))))))
        (is (= 2 attempts))
        (is (equal "Pending" (gethash "phase" status)))))))

(test ha-pod-create-http-response-retries-a-transient-local-not-found
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((original (symbol-function 'gr8s.kubelet::reconcile-pod))
          (server nil)
          (attempts 0))
      ;; A committed HA create may become visible to the Raft state machine just
      ;; before the member's Pod index installs that committed view.  Exercise the
      ;; HTTP call site, not only RECONCILE-WRITTEN-POD in isolation.
      (setf (gr8s.store::pod-store-consensus-commit-fn store)
            (lambda (kind json)
              (case kind
                (:pod-delta (gr8s.store::install-pod-state-delta store json))
                (:core-delta (gr8s.resources::install-core-state-delta store json)))))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kubelet::reconcile-pod)
                   (lambda (reconciler namespace name)
                     (if (= 1 (incf attempts))
                         (gr8s.resources::core-resource-error
                          404 "NotFound" "committed Pod view is still installing")
                         (funcall original reconciler namespace name))))
             (setf server
                   (start-http-test-server
                    :store store :runtime (make-fake-runtime)))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods"
                          :method :post
                          :content *valid-pod-json*
                          :content-type "application/json")
               (is (= 201 status) "~A" body)
               (is (= 2 attempts))
               (is (string= "hello"
                            (gethash "name"
                                     (gethash "metadata"
                                              (response-object body)))))))
        (setf (symbol-function 'gr8s.kubelet::reconcile-pod) original)
        (when server (stop-server server))))))

(test pod-desired-state-replicates-and-survives-failover
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
                 ;; Create a Pod on the leader; capture its server-assigned UID.
                 (let ((uid (gr8s.model::pod-uid (ha-make-pod s1 "p1"))))
                   (is (stringp uid))
                   ;; It replicates to every member with the SAME identity.
                   (is (poll-until
                        (lambda () (every (lambda (s) (equal uid (ha-pod-uid s "p1"))) (list s1 s2 s3)))
                        :timeout 10)
                       "the Pod replicates to every member with its UID intact")
                   ;; Scheduling is a desired-state write too. A follower serving a
                   ;; Pod GET must know the assignment before the selected node's
                   ;; agent happens to install its local assignment snapshot.
                   (gr8s.store::with-store-lock (s1)
                     (gr8s.controllers::persist-pod-assignment
                      s1 (gr8s.store::get-pod-unlocked s1 "default" "p1") "worker-a"))
                   (is (poll-until
                        (lambda () (every (lambda (s) (equal "worker-a" (ha-pod-node-name s "p1")))
                                          (list s1 s2 s3)))
                        :timeout 10)
                       "the Pod assignment replicates to every member")
                   ;; Agent observations are client-visible API state. A Pod GET
                   ;; against any follower must see the same phase and containers.
                   (let ((status (gr8s.resources::core-object
                                  "phase" "Running"
                                  "containerStatuses"
                                  (vector (gr8s.resources::core-object
                                           "name" "main" "ready" t
                                           "state" (gr8s.resources::core-object "running" (gr8s.resources::core-object)))))))
                     (gr8s.controllers::update-pod-observed-status s1 (gr8s.store::get-pod s1 "default" "p1") status)
                     (is (poll-until
                          (lambda ()
                            (every (lambda (s)
                                     (let* ((pod (gr8s.store::get-pod s "default" "p1"))
                                            (observed (gr8s.controllers::pod-observed-status s pod)))
                                       (and observed (equal "Running" (gethash "phase" observed))
                                            (= 1 (length (gethash "containerStatuses" observed #()))))))
                                   (list s1 s2 s3)))
                          :timeout 10)
                         "the Pod observation replicates to every member"))
                   ;; A follower write returns only after that follower has applied
                   ;; the commit; the same HTTP request immediately reconciles it.
                   (let ((original (symbol-function 'gr8s.store::install-pod-state-delta)))
                     (unwind-protect
                          (progn
                            ;; Make the follower's post-commit apply lag deterministic.
                            (setf (symbol-function 'gr8s.store::install-pod-state-delta)
                                  (lambda (store json)
                                    (when (eq store s2) (sleep 0.2))
                                    (funcall original store json)))
                            (let ((follower-uid (gr8s.model::pod-uid (ha-make-pod s2 "from-follower"))))
                              (is (equal follower-uid (ha-pod-uid s2 "from-follower"))
                                  "a forwarded write has read-after-write consistency locally")))
                       (setf (symbol-function 'gr8s.store::install-pod-state-delta) original)))
                   ;; A stale proposal may commit as a rejected application
                   ;; transaction. The follower must receive that result over RPC.
                   (let* ((original (gr8s.store::pod-store-consensus-commit-fn s2))
                          (stale nil)
                          (pod (gr8s.store::get-pod s2 "default" "p1"))
                          (object (gr8s.store::copy-pod-status-value (gr8s.model::pod-to-object pod))))
                     (unwind-protect
                          (progn
                            (setf (gr8s.store::pod-store-consensus-commit-fn s2)
                                  (lambda (kind json) (when (eq kind :pod-delta) (setf stale json))))
                            (setf (gethash "labels" (gethash "metadata" object)) (gr8s.resources::core-object "proposal" "stale"))
                            (gr8s.store::update-pod s2 (gr8s.kubelet::parse-pod object) (gr8s.model::pod-resource-version pod)))
                       (setf (gr8s.store::pod-store-consensus-commit-fn s2) original))
                     (let* ((current (gr8s.store::get-pod s1 "default" "p1"))
                            (fresh (gr8s.store::copy-pod-status-value (gr8s.model::pod-to-object current))))
                       (setf (gethash "labels" (gethash "metadata" fresh)) (gr8s.resources::core-object "proposal" "fresh"))
                       (gr8s.store::update-pod s1 (gr8s.kubelet::parse-pod fresh) (gr8s.model::pod-resource-version current)))
                     (multiple-value-bind (result committed)
                         (gr8s.raft.transport::raft-member-forward-propose-sync
                          (gr8s.ha::ha-control-plane-member h2) (list :pod-delta stale))
                       (is (eq t committed))
                       (is (equal '(:pod-conflict) result))))
                   ;; Kill the leader; a survivor still has the Pod, same UID.
                   (is (poll-until (lambda () (every-member-sees-voters-p (list h1 h2 h3) 3)) :timeout 20)
                       "both joiners vote before the leader is stopped")
                   (gr8s.ha::stop-ha-control-plane h1)
                   (setf h1 nil)
                   (is (poll-until (lambda () (or (gr8s.ha::ha-control-plane-leader-p h2)
                                                  (gr8s.ha::ha-control-plane-leader-p h3)))
                                   :timeout 20)
                       "a survivor becomes leader")
                   (is (and (equal uid (ha-pod-uid s2 "p1"))
                            (equal uid (ha-pod-uid s3 "p1")))
                       "the Pod (and its identity) is not lost on failover")))
            (dolist (h (list h1 h2 h3)) (when h (ignore-errors (gr8s.ha::stop-ha-control-plane h))))))))))

;;; podster-eb0: every member shows a Pod and a Node at one resourceVersion, and
;;; a member that restarts shows them at the versions it showed before.

(defun ha-pod-and-node-versions (store)
  "The revision STORE counts Pods and Nodes by, and each version it shows, by name."
  (bt:with-lock-held ((gr8s.store::pod-store-lock store))
    (list (gr8s.store::pod-store-pod-revision store)
          (sort (append
                 (loop for pod being the hash-values of (gr8s.store::pod-store-pods store)
                       collect (cons (format nil "pod/~A" (gr8s.model::pod-name pod))
                                     (gr8s.resources::pod-shown-version pod)))
                 (loop for node being the hash-values of (gr8s.store::pod-store-nodes store)
                       collect (cons (format nil "node/~A" (gr8s.model::node-record-name node))
                                     (parse-integer (gr8s.model::node-record-resource-version node)))))
                #'string< :key #'car))))

(defun ha-run-a-pod (store name node)
  "Create Pod NAME through STORE, assign it to NODE and report it running."
  (ha-make-pod store name)
  (gr8s.store::with-store-lock (store)
    (gr8s.controllers::persist-pod-assignment store (gr8s.store::get-pod-unlocked store "default" name) node))
  (gr8s.controllers::update-pod-observed-status
   store (gr8s.store::get-pod store "default" name)
   (gr8s.resources::core-object
    "phase" "Running"
    "containerStatuses" (vector (gr8s.resources::core-object
                                 "name" "main" "ready" t
                                 "state" (gr8s.resources::core-object "running" (gr8s.resources::core-object)))))))

(test a-member-that-restarts-shows-pods-and-nodes-at-the-versions-it-showed
  (call-with-two-restartable-members
   (lambda (s1 restart second)
     (seed-ha-readiness-nodes s1)
     (dolist (name '("p1" "p2" "p3")) (ha-run-a-pod s1 name "worker-a"))
     (gr8s.controllers::mark-node-ready s1 "worker-a" (get-universal-time))
     (is (poll-until (lambda () (equal (ha-pod-and-node-versions s1) (ha-pod-and-node-versions (funcall second))))
                     :timeout 15)
         "the members show every Pod and Node at one version: ~S and ~S"
         (ha-pod-and-node-versions s1) (ha-pod-and-node-versions (funcall second)))
     (let ((before (ha-pod-and-node-versions s1)))
       (is (= 5 (length (second before))))
       (dotimes (restarts 2)
         (let ((s2 (funcall restart)))
           (is (equal before (ha-pod-and-node-versions s2))
               "the restarted member shows what it showed: ~S, not ~S" before (ha-pod-and-node-versions s2))
           (is (equal before (ha-pod-and-node-versions s1)))))
       ;; And what is written afterwards has one version on both.
       (ha-run-a-pod s1 "p4" "worker-b")
       (is (poll-until (lambda () (equal (ha-pod-and-node-versions s1) (ha-pod-and-node-versions (funcall second))))
                       :timeout 15)
           "a Pod written after the restart has one version too: ~S and ~S"
           (ha-pod-and-node-versions s1) (ha-pod-and-node-versions (funcall second)))))))

(test recovered-pod-and-node-versions-are-checked-against-what-the-member-showed
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (ha-run-a-pod store "p1" "worker-a")
    (let* ((shown (ha-pod-and-node-versions store))
           (revision (first shown)))
      (flet ((check (expectation &rest arguments)
               (bt:with-lock-held ((gr8s.store::pod-store-lock store))
                 (setf (gr8s.store::pod-store-pod-recovery-expectation store) expectation)
                 (apply #'gr8s.resources::check-recovered-pod-versions store arguments)
                 (gr8s.store::pod-store-pod-recovery-expectation store)))
             (digest ()
               (bt:with-lock-held ((gr8s.store::pod-store-lock store))
                 (gr8s.resources::pod-versions-digest store))))
        ;; The replay has not come to where the member stopped: nothing is decided.
        (is (check (cons (+ revision 5) (digest))))
        (is (equal shown (ha-pod-and-node-versions store)))
        ;; It has come there, showing what the member showed.
        (is (null (check (cons revision (digest)))))
        (is (equal shown (ha-pod-and-node-versions store)))
        ;; It is over, and never came there: one revision above all the member
        ;; gave out or had reserved, for every Node and every Pod's publication.
        (let ((reserved (gr8s.store::pod-store-pod-revision-ceiling store)))
          (is (null (check (cons (+ revision 40) (digest)) :replayed t)))
          (let* ((now (ha-pod-and-node-versions store))
                 (fresh (first now)))
            (is (> fresh (max reserved (+ revision 40))))
            (is (every (lambda (entry) (= fresh (cdr entry))) (second now))
                "every Pod and Node shows the new revision: ~S" now)
            (is (= fresh (gr8s.store::pod-store-pod-revision-epoch-floor store))
                "and a version from before is refused")
            (is (= fresh (gr8s.store::pod-store-pod-watch-floor store)))
            ;; The Pod can be read and updated at the version it now shows.
            (let ((pod (gr8s.store::get-pod store "default" "p1")))
              (is (equal "worker-a" (gr8s.model::pod-node-name pod)))
              (finishes (gr8s.controllers::update-pod-observed-status
                         store pod (gr8s.resources::core-object "phase" "Succeeded"))))))))))

(test the-members-renumber-pods-and-nodes-that-they-show-at-different-versions
  ;; A Pod that is steady is not published again, so members that came to show it
  ;; at different versions go on doing so. The round has them renumber.
  (call-with-two-restartable-members
   (lambda (s1 restart second)
     (declare (ignore restart))
     (let ((s2 (funcall second)))
       (seed-ha-readiness-nodes s1)
       (dolist (name '("p1" "p2" "p3")) (ha-run-a-pod s1 name "worker-a"))
       (is (poll-until (lambda () (equal (ha-pod-and-node-versions s1) (ha-pod-and-node-versions s2))) :timeout 15))
       ;; Let the rounds that the members' start began come to their end.
       (sleep 4)
       ;; One member numbers its Pods and Nodes by itself, as a restart once did.
       (bt:with-lock-held ((gr8s.store::pod-store-lock s2))
         (gr8s.resources::renumber-pods-and-nodes-unlocked
          s2 (+ 40 (gr8s.store::pod-store-pod-revision s2))))
       (let ((apart (first (ha-pod-and-node-versions s2))))
         (is-false (equal (ha-pod-and-node-versions s1) (ha-pod-and-node-versions s2)))
         (gr8s.resources::propose-core-version-mark s1)
         (is (poll-until (lambda () (equal (ha-pod-and-node-versions s1) (ha-pod-and-node-versions s2))) :timeout 30)
             "both show every Pod and Node at one version: ~S and ~S"
             (ha-pod-and-node-versions s1) (ha-pod-and-node-versions s2))
         (is (> (first (ha-pod-and-node-versions s1)) apart)
             "at a revision above what either had given out")
         ;; The round that follows finds them alike and leaves them.
         (sleep 5)
         (let ((settled (ha-pod-and-node-versions s1)))
           (is (equal settled (ha-pod-and-node-versions s2)))
           (gr8s.resources::propose-core-version-mark s2)
           (sleep 5)
           (is (equal settled (ha-pod-and-node-versions s1)) "another round changes nothing")
           (is (equal settled (ha-pod-and-node-versions s2)))
           (is (<= (gr8s.store::pod-store-core-pod-renumber-rounds s1) 1) "one renumbering was enough"))
         ;; A Pod can be read and changed at the version it now shows, and the
         ;; change has one version on both members.
         (finishes (gr8s.controllers::update-pod-observed-status
                    s1 (gr8s.store::get-pod s1 "default" "p2") (gr8s.resources::core-object "phase" "Succeeded")))
         (is (poll-until (lambda () (equal (ha-pod-and-node-versions s1) (ha-pod-and-node-versions s2))) :timeout 15)
             "a change after the renumbering has one version on both: ~S and ~S"
             (ha-pod-and-node-versions s1) (ha-pod-and-node-versions s2)))))))

(test pods-are-renumbered-only-when-every-voter-reports-them-and-not-without-end
  (with-temporary-store (store path)
    (declare (ignore path))
    (seed-ha-readiness-nodes store)
    (ha-run-a-pod store "p1" "worker-a")
    (let ((renumberings 0))
      ;; One member that commits what it proposes at once, and counts the renumberings.
      (setf (gr8s.store::pod-store-consensus-commit-fn store)
            (lambda (tag payload)
              (when (and (eq tag :core-delta) (search "versionPodRenumber" payload)) (incf renumberings))
              (ecase tag
                (:core-delta (gr8s.resources::install-core-state-delta store payload))
                (:pod-delta (gr8s.store::install-pod-state-delta store payload))
                (:node-delta (gr8s.store::install-node-state-delta store payload)))))
      (flet ((round-with (other)
               "Start a round, report as this member, and have voter b report OTHER of its Pods."
               (gr8s.resources::reconcile-core-versions store "a" '("a") t :ask t)
               (let ((mark (first (gr8s.store::pod-store-core-version-marks store))))
                 (setf (gethash "b" (gr8s.resources::core-version-mark-reports mark))
                       (append (list (gr8s.resources::core-version-mark-revision mark)
                                     (gr8s.resources::core-version-mark-digest mark))
                               (funcall other mark))))
               (gr8s.resources::reconcile-core-versions store "a" '("a" "b") t)))
        ;; A voter that runs an older version says nothing of its Pods.
        (round-with (lambda (mark) (declare (ignore mark)) (list nil nil)))
        (is (zerop renumberings) "nothing is renumbered while a voter has not reported its Pods")
        ;; A voter that shows what this member shows.
        (round-with (lambda (mark) (list (gr8s.resources::core-version-mark-pod-revision mark)
                                         (gr8s.resources::core-version-mark-pod-digest mark))))
        (is (zerop renumberings) "nor when the voters agree")
        ;; A voter that counted ahead and shows other versions, time after time.
        (let ((before (first (ha-pod-and-node-versions store))))
          (dotimes (attempt 6)
            (round-with (lambda (mark) (list (+ 500 (gr8s.resources::core-version-mark-pod-revision mark)) "other versions"))))
          (is (= 3 renumberings) "it renumbers, and gives up after three times: ~D" renumberings)
          (let ((now (ha-pod-and-node-versions store)))
            (is (> (first now) (+ before 500 1024)) "above what the voter reported, with room to spare")
            (is (every (lambda (entry) (= (cdr entry) (cdr (first (second now))))) (second now))
                "every Pod and Node shows one revision: ~S" now)))))))

;;; podster-lgi: a member decides for itself that a Node's lease has run out
;;; only where nothing else can tell it. A member of a control plane is told.

(test a-member-that-was-down-past-a-lease-shows-nodes-as-the-others-do
  ;; On the lab a restarted follower differed from the leader two seconds after it
  ;; started. It had loaded every Node as not ready, because the leases had run
  ;; out by its clock while it was down. The next heartbeat was then a change of
  ;; readiness for it alone: it gave the Node a version that no other member did,
  ;; and from then on it numbered by itself.
  (call-with-two-restartable-members
   (lambda (s1 restart second)
     (seed-ha-readiness-nodes s1)
     (ha-run-a-pod s1 "p1" "worker-a")
     ;; A lease that has run out already, as one has by the time a member is back.
     (let ((then (- (get-universal-time) 600)))
       (gr8s.controllers::mark-node-ready s1 "worker-a" then)
       (gr8s.controllers::mark-node-ready s1 "worker-b" then)
       (is (poll-until (lambda () (equal (ha-pod-and-node-versions s1) (ha-pod-and-node-versions (funcall second))))
                       :timeout 15))
       (sleep 4)
       ;; The member takes a snapshot while the Nodes are ready, as a running
       ;; member does every few hundred writes. It starts again from that.
       (let ((handle (funcall second :handle)))
         (setf (gr8s.ha::ha-control-plane-compaction-entries handle) 1)
         (is (poll-until
              (lambda ()
                (gr8s.ha::compact-ha-store-once handle)
                (let ((node (gr8s.raft.transport::raft-member-node (gr8s.ha:ha-control-plane-member handle))))
                  (= (cl-raft::raft-node-snapshot-index node) (cl-raft::raft-node-last-applied node))))
              :timeout 15)
             "the second member holds a snapshot of all it has applied"))
       (let* ((before (ha-pod-and-node-versions s1))
              (s2 (funcall restart)))
         (is (ha-node-ready-p s2 "worker-a")
             "the restarted member holds the Node as the control plane does: ready")
         (is (equal before (ha-pod-and-node-versions s2)))
         ;; The agent's next heartbeat renews the lease. It changes nothing a client sees.
         (gr8s.controllers::mark-node-ready s1 "worker-a" (+ then 5))
         (gr8s.controllers::mark-node-ready s1 "worker-b" (+ then 5))
         (sleep 3)
         (is (equal before (ha-pod-and-node-versions s1)) "a renewed lease takes no revision on the leader")
         (is (equal before (ha-pod-and-node-versions s2))
             "nor on the member that restarted: ~S, not ~S" before (ha-pod-and-node-versions s2))
         (is (zerop (gr8s.store::pod-store-core-pod-renumber-rounds s1)) "so nothing had to be renumbered"))))))
