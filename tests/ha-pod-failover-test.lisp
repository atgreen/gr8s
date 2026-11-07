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

(defun ha-pod-node-name (store name)
  (let ((pod (ignore-errors (gr8s:get-pod store "default" name))))
    (and pod (gr8s:pod-node-name pod))))

(test replicated-pod-state-advances-the-follower-watch-journal
  ;; A follower may serve an in-cluster ListWatch.  Installing a replicated Pod
  ;; snapshot must therefore publish the same revisions and resumable events as
  ;; the authoring member, not merely replace the object visible to ordinary GETs.
  (with-temporary-store (source source-path)
    (with-temporary-store (follower follower-path)
      (declare (ignore source-path follower-path))
      (let ((pod (ha-make-pod source "watched")))
        (gr8s::install-pod-state-blob follower (gr8s::pod-state-json source))
        (let ((events (gr8s::pod-watch-events follower "default" "" "" 0)))
          (is (equal '("ADDED") (mapcar (lambda (event) (gethash "type" event)) events))
              "the replicated create is resumable on the follower: ~S"
              (list :events (mapcar (lambda (event) (gethash "type" event)) events)
                    :journal (mapcar (lambda (entry)
                                       (list (first entry)
                                             (and (second entry) t)
                                             (and (third entry) t)))
                                     (gr8s::pod-store-pod-watch-journal follower))
                    :revision (gr8s::pod-store-pod-revision follower)
                    :floor (gr8s::pod-store-pod-watch-floor follower))))
        (let ((checkpoint (gr8s::pod-store-pod-revision follower)))
          (gr8s::update-pod-observed-status
           source pod
           (gr8s::core-object
            "phase" "Running"
            "containerStatuses"
            (vector (gr8s::core-object
                     "name" "main" "ready" t
                     "state" (gr8s::core-object "running" (gr8s::core-object))))))
          (gr8s::install-pod-state-blob follower (gr8s::pod-state-json source))
          (let* ((events (gr8s::pod-watch-events follower "default" "" "" checkpoint))
                 (latest (car (last events))))
            (is (equal '("MODIFIED")
                       (mapcar (lambda (event) (gethash "type" event)) events))
                "the replicated observation is resumable on the follower")
            (is (equal "Running"
                       (and latest (gethash "phase" (gethash "status" (gethash "object" latest)))))
                "the replayed event carries the replicated status")
            (is (> (gr8s::pod-store-pod-revision follower) checkpoint)
                "the follower watermark advances with the replicated revision")))
        (let ((checkpoint (gr8s::pod-store-pod-revision follower)))
          (gr8s::delete-pod source "default" "watched")
          (gr8s::install-pod-state-blob follower (gr8s::pod-state-json source))
          (let ((events (gr8s::pod-watch-events follower "default" "" "" checkpoint)))
            (is (equal '("DELETED")
                       (mapcar (lambda (event) (gethash "type" event)) events))
                "the replicated deletion is resumable on the follower")))))))

(test pod-deletion-replicates-the-revision-allocated-for-its-watch-event
  (with-temporary-store (source source-path)
    (declare (ignore source-path))
    (ha-make-pod source "deleted")
    (let ((payload nil))
      (setf (gr8s::pod-store-consensus-commit-fn source)
            (lambda (kind json)
              (when (eq kind :pod-state) (setf payload json))))
      (gr8s::delete-pod source "default" "deleted")
      (let ((state (and payload (com.inuoe.jzon:parse payload))))
        (is (not (null state)) "the deletion emits a Pod state command")
        (is (equal (write-to-string (gr8s::pod-store-pod-revision source))
                   (and state (gethash "resourceVersion" state)))
            "the command includes the deletion event's revision")))))

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
        (let ((checkpoint (gr8s::pod-store-pod-revision follower)))
          (gr8s::install-pod-state-blob follower (gr8s::pod-state-json source))
          (multiple-value-bind (events watermark)
              (gr8s::pod-watch-events
               follower "default" "" "metadata.name=watched" checkpoint)
            (is (equal '("ADDED")
                       (mapcar (lambda (event) (gethash "type" event)) events))
                "a colliding replicated create remains visible after the LIST checkpoint")
            (is (> watermark checkpoint)
                "the follower assigns a watermark newer than one it already served")))
        (let ((checkpoint (gr8s::pod-store-pod-revision follower)))
          (gr8s::update-pod-observed-status
           source pod (gr8s::core-object "phase" "Running"))
          (gr8s::install-pod-state-blob follower (gr8s::pod-state-json source))
          (let ((events (gr8s::pod-watch-events
                         follower "default" "" "metadata.name=watched" checkpoint)))
            (is (equal '("MODIFIED")
                       (mapcar (lambda (event) (gethash "type" event)) events))
                "a trailing replicated status revision remains resumable")))))))

(test ha-pod-write-response-retries-a-transient-local-not-found
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((pod (gr8s:parse-pod
                 "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"lagged\",\"namespace\":\"default\",\"uid\":\"uid-1\"},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"busybox\"}]}}"))
           (reconciler (gr8s:make-reconciler store (gr8s:make-fake-runtime)))
           (attempts 0))
      ;; The presence of a consensus hook identifies the HA retry case.
      (setf (gr8s::pod-store-consensus-commit-fn store) (lambda (&rest ignored) (declare (ignore ignored))))
      (let ((status
              (gr8s::reconcile-written-pod
               reconciler pod
               :reconcile
               (lambda (ignored-reconciler ignored-namespace ignored-name)
                 (declare (ignore ignored-reconciler ignored-namespace ignored-name))
                 (if (= 1 (incf attempts))
                     (gr8s::core-resource-error 404 "NotFound" "replicated Pod not installed yet")
                     (gr8s::pod-status "Pending"))))))
        (is (= 2 attempts))
        (is (equal "Pending" (gethash "phase" status)))))))

(test ha-pod-create-http-response-retries-a-transient-local-not-found
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((original (symbol-function 'gr8s::reconcile-pod))
          (server nil)
          (attempts 0))
      ;; A committed HA create may become visible to the Raft state machine just
      ;; before the member's Pod index installs that committed view.  Exercise the
      ;; HTTP call site, not only RECONCILE-WRITTEN-POD in isolation.
      (setf (gr8s::pod-store-consensus-commit-fn store)
            (lambda (&rest ignored) (declare (ignore ignored))))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::reconcile-pod)
                   (lambda (reconciler namespace name)
                     (if (= 1 (incf attempts))
                         (gr8s::core-resource-error
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
        (setf (symbol-function 'gr8s::reconcile-pod) original)
        (when server (stop-server server))))))

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
                   ;; Scheduling is a desired-state write too. A follower serving a
                   ;; Pod GET must know the assignment before the selected node's
                   ;; agent happens to install its local assignment snapshot.
                   (gr8s::with-store-lock (s1)
                     (gr8s::persist-pod-assignment
                      s1 (gr8s::get-pod-unlocked s1 "default" "p1") "worker-a"))
                   (is (poll-until
                        (lambda () (every (lambda (s) (equal "worker-a" (ha-pod-node-name s "p1")))
                                          (list s1 s2 s3)))
                        :timeout 10)
                       "the Pod assignment replicates to every member")
                   ;; Agent observations are client-visible API state. A Pod GET
                   ;; against any follower must see the same phase and containers.
                   (let ((status (gr8s::core-object
                                  "phase" "Running"
                                  "containerStatuses"
                                  (vector (gr8s::core-object
                                           "name" "main" "ready" t
                                           "state" (gr8s::core-object "running" (gr8s::core-object)))))))
                     (gr8s::update-pod-observed-status s1 (gr8s:get-pod s1 "default" "p1") status)
                     (is (poll-until
                          (lambda ()
                            (every (lambda (s)
                                     (let* ((pod (gr8s:get-pod s "default" "p1"))
                                            (observed (gr8s::pod-observed-status s pod)))
                                       (and observed (equal "Running" (gethash "phase" observed))
                                            (= 1 (length (gethash "containerStatuses" observed #()))))))
                                   (list s1 s2 s3)))
                          :timeout 10)
                         "the Pod observation replicates to every member"))
                   ;; A follower write returns only after that follower has applied
                   ;; the commit; the same HTTP request immediately reconciles it.
                   (let ((original (symbol-function 'gr8s::install-pod-state-blob)))
                     (unwind-protect
                          (progn
                            ;; Make the follower's post-commit apply lag deterministic.
                            (setf (symbol-function 'gr8s::install-pod-state-blob)
                                  (lambda (store json)
                                    (when (eq store s2) (sleep 0.2))
                                    (funcall original store json)))
                            (let ((follower-uid (gr8s:pod-uid (ha-make-pod s2 "from-follower"))))
                              (is (equal follower-uid (ha-pod-uid s2 "from-follower"))
                                  "a forwarded write has read-after-write consistency locally")))
                       (setf (symbol-function 'gr8s::install-pod-state-blob) original)))
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
