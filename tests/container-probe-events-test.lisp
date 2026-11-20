;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise cumulative probe Event delivery across real target retirement,
;;;; exact Pod UID wire validation, durable native reconstruction and fair
;;;; bounded pages. Expiry and capacity bound retained history while repeated
;;;; counts do not churn the API journal or leak transport fields into status.

(in-package #:gr8s/tests)
(def-suite container-probe-events :in gr8s)
(in-suite container-probe-events)

(defun event-outbox-pod (store &optional (count 1))
  "Create an assigned Pod with COUNT independently named containers."
  (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
    (setf (gethash "nodeName" (gethash "spec" object)) "probe-node"
          (gethash "containers" (gethash "spec" object))
          (coerce (loop for index below count collect (gr8s.resources::core-object "name" (format nil "c~D" index) "image" "busybox")) 'vector))
    (create-pod store (parse-pod object))))

(defun event-outbox-target (manager pod name now &key (attempt "attempt0"))
  "Attach one measured failing readiness attempt without starting worker threads."
  (let* ((worker (gr8s.kubelet::make-container-probe-worker :kind "readinessProbe"
                  :spec (checked-probe "{\"exec\":{\"command\":[\"false\"]}}")))
         (target (gr8s.kubelet::make-container-probe-target :uid (pod-uid pod) :name name :id attempt :workers (list worker))))
    (gr8s.kubelet::record-container-probe-result worker nil "actual failed occurrence" now)
    (setf (gethash (gr8s.kubelet::probe-target-key target) (gr8s.kubelet::container-probe-manager-targets manager)) target)
    target))

(defun deliver-probe-event-page (store pod page &optional (node "probe-node"))
  "Pass a real encoded node envelope through assigned UID/RV validation."
  (let* ((status (gr8s.resources::core-object "phase" "Running"))
         (message (gr8s.agent::pod-observed-status-message pod status page))
         (envelope (gr8s.protocol::make-agent-envelope :status (make-instance 'gr8s.node.v1::node-status :pods (list message))))
         (wire (ag-proto:serialize-to-bytes envelope))
         (decoded (ag-proto:deserialize-from-bytes 'gr8s.node.v1::agent-envelope wire)))
    (gr8s.apiserver::handle-node-agent-envelope (gr8s.apiserver::%make-node-grpc-server :store store) node decoded)
    (is-false (gethash "gr8sRuntimeEvents" status))))

(test retired-attempt-event-survives-wire-publication-and-native-reconstruction
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.resources::*event-clock* (lambda () now))
           (pod (event-outbox-pod store)) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
           (manager (gr8s.kubelet::make-container-probe-manager :clock (lambda () now)))
           (target (event-outbox-target manager pod "c0" now)))
      (setf (gr8s.runtime.containerd::containerd-runtime-probes runtime) manager)
      (gr8s.kubelet::checkpoint-container-probes runtime pod manager)
      (gr8s.kubelet::retire-container-probe-targets manager (constantly t))
      (is-false (gethash (gr8s.kubelet::probe-target-key target) (gr8s.kubelet::container-probe-manager-targets manager)))
      (is (= 1 (length (gr8s.runtime::runtime-events runtime (pod-uid pod)))))
      (let ((reopened (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
        (setf (gr8s.runtime.containerd::containerd-runtime-probes reopened) (gr8s.kubelet::make-container-probe-manager :clock (lambda () now)))
        (let ((page (gr8s.runtime::runtime-events reopened (pod-uid pod))))
          (is (= 1 (length page)))
          (deliver-probe-event-page store pod page "other-node")
          (is (null (gr8s.resources::list-core-resources store "events" "default")))
          (deliver-probe-event-page store pod page)
          (is (= 1 (length (gr8s.resources::list-core-resources store "events" "default"))))))
      (is-false (gethash "gr8sRuntimeEvents" (gethash (pod-uid pod) (gr8s.store::pod-store-pod-observed-statuses store))))
      ;; A CID replacement retains the original occurrence but owns fresh probe
      ;; state. A new UID never inherits the old UID's retained event records.
      (event-outbox-target manager pod "c0" now :attempt "attempt1")
      (is (= 2 (length (gr8s.runtime::runtime-events runtime (pod-uid pod)))))
      (is-false (gr8s.runtime::runtime-events runtime "replacement-pod-uid"))
      (let ((old-page (gr8s.runtime::runtime-events runtime (pod-uid pod))))
        (gr8s.store::remove-pod store (pod-namespace pod) (pod-name pod))
        (let ((replacement (event-outbox-pod store)))
          (is (not (equal (pod-uid pod) (pod-uid replacement))))
          (deliver-probe-event-page store pod old-page)
          (is (= 1 (length (gr8s.resources::list-core-resources store "events" "default"))))
          (is-false (gethash (pod-uid replacement) (gr8s.store::pod-store-pod-observed-statuses store))))))))

(test large-pod-events-use-fair-pages-and-replays-do-not-churn-api-history
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.resources::*event-clock* (lambda () now))
           (pod (event-outbox-pod store 130)) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
           (manager (gr8s.kubelet::make-container-probe-manager :clock (lambda () now))))
      (setf (gr8s.runtime.containerd::containerd-runtime-probes runtime) manager)
      (loop for container across (pod-containers pod) do (event-outbox-target manager pod (container-spec-name container) now))
      (dotimes (page 3)
        (let ((events (gr8s.runtime::runtime-events runtime (pod-uid pod))))
          (is (= 64 (length events))) (deliver-probe-event-page store pod events)))
      (is (= 130 (length (gr8s.resources::list-core-resources store "events" "default"))))
      (let ((revision (gr8s.store::pod-store-resource-revision store)))
        (dotimes (page 4) (deliver-probe-event-page store pod (gr8s.runtime::runtime-events runtime (pod-uid pod))))
        (is (= revision (gr8s.store::pod-store-resource-revision store))))
      (gr8s.kubelet::retire-container-probe-targets manager (constantly t))
      (gr8s.kubelet::checkpoint-container-probes runtime pod manager)
      (setf runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)
            (gr8s.runtime.containerd::containerd-runtime-probes runtime) (gr8s.kubelet::make-container-probe-manager :clock (lambda () now)))
      (let ((seen (make-hash-table :test #'equal)))
        (dotimes (page 3)
          (loop for event across (gr8s.runtime::runtime-events runtime (pod-uid pod)) do (setf (gethash (gethash "id" event) seen) t)))
        (is (= 130 (hash-table-count seen)))))))

(test receiver-accepts-valid-oversize-pages-without-dropping-entire-batch
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.resources::*event-clock* (lambda () now))
           (pod (event-outbox-pod store 65)) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
           (manager (gr8s.kubelet::make-container-probe-manager :clock (lambda () now))))
      (setf (gr8s.runtime.containerd::containerd-runtime-probes runtime) manager)
      (loop for container across (pod-containers pod) do (event-outbox-target manager pod (container-spec-name container) now))
      (let ((records (gr8s.kubelet::collect-container-probe-events manager (pod-uid pod) nil)))
        (deliver-probe-event-page store pod (coerce (loop for event being the hash-values of records collect event) 'vector)))
      (is (= 65 (length (gr8s.resources::list-core-resources store "events" "default")))))))

(test probe-outbox-coalesces-expires-and-evicts-oldest-before-unbounded-growth
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.resources::*event-clock* (lambda () now))
           (gr8s.kubelet::*container-probe-event-capacity* 2)
           (pod (event-outbox-pod store 3)) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
           (manager (gr8s.kubelet::make-container-probe-manager :clock (lambda () now)))
           (old (event-outbox-target manager pod "c0" now)))
      (setf (gr8s.runtime.containerd::containerd-runtime-probes runtime) manager)
      (incf now) (event-outbox-target manager pod "c1" now)
      (incf now) (event-outbox-target manager pod "c2" now)
      (let ((page (gr8s.runtime::runtime-events runtime (pod-uid pod))))
        (is (= 2 (length page)))
        (is-false (find "c0" page :test #'equal :key (lambda (event) (gethash "container" event)))))
      (let ((worker (first (gr8s.kubelet::container-probe-target-workers old))))
        (incf now) (gr8s.kubelet::record-container-probe-result worker nil "second real occurrence" now))
      (let* ((page (gr8s.runtime::runtime-events runtime (pod-uid pod)))
             (coalesced (find "c0" page :test #'equal :key (lambda (event) (gethash "container" event)))))
        (is (= 2 (length page))) (is (= 2 (gethash "count" coalesced)))
        (deliver-probe-event-page store pod page)
        (incf now gr8s.resources::*event-ttl-seconds*)
        (is-false (gr8s.runtime::runtime-events runtime (pod-uid pod)))
        (is (= 0 (hash-table-count (gr8s.kubelet::container-probe-manager-event-outbox manager))))
        (is (= 0 (hash-table-count (gr8s.kubelet::container-probe-manager-event-cursors manager))))
        (is (null (gr8s.resources::list-core-resources store "events" "default"))))
      ;; Even a delayed old peer page cannot recreate expired API Events.
      (let ((record (gr8s.resources::copy-core-object (gethash "Unhealthy" (gr8s.kubelet::container-probe-worker-events (first (gr8s.kubelet::container-probe-target-workers old)))))))
        (setf (gethash "container" record) "c0" (gethash "kind" record) "readinessProbe")
        (deliver-probe-event-page store pod (vector record))
        (is (null (gr8s.resources::list-core-resources store "events" "default")))))))

(test concurrent-cumulative-replays-commit-one-event-count-update
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s.resources::*event-clock* (lambda () now))
           (pod (event-outbox-pod store)) (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory))
           (manager (gr8s.kubelet::make-container-probe-manager :clock (lambda () now)))
           (target (event-outbox-target manager pod "c0" now))
           (entered (bt:make-semaphore)) (release (bt:make-semaphore))
           (original (symbol-function 'gr8s.resources::get-core-resource)) (threads nil))
      (setf (gr8s.runtime.containerd::containerd-runtime-probes runtime) manager)
      (gr8s.resources::record-node-runtime-events store pod "probe-node" (gr8s.runtime::runtime-events runtime (pod-uid pod)))
      (incf now)
      (gr8s.kubelet::record-container-probe-result (first (gr8s.kubelet::container-probe-target-workers target)) nil "second occurrence" now)
      (let ((page (gr8s.runtime::runtime-events runtime (pod-uid pod)))
            (revision (gr8s.store::pod-store-resource-revision store)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.resources::get-core-resource)
                     (lambda (&rest arguments)
                       (let ((result (apply original arguments)))
                         (bt:signal-semaphore entered) (bt:wait-on-semaphore release) result)))
               (dotimes (index 2)
                 (push (bt:make-thread (lambda ()
                                        (let ((gr8s.resources::*event-clock* (lambda () now)))
                                          (gr8s.resources::record-node-runtime-events store pod "probe-node" page)))) threads))
               (is (bt:wait-on-semaphore entered :timeout 3))
               (is (bt:wait-on-semaphore entered :timeout 3))
               (bt:signal-semaphore release :count 2)
               (mapc #'bt:join-thread threads)
               (is (= (1+ revision) (gr8s.store::pod-store-resource-revision store)))
               (is (= 2 (gethash "count" (first (gr8s.resources::list-core-resources store "events" "default"))))))
          (setf (symbol-function 'gr8s.resources::get-core-resource) original)
          (bt:signal-semaphore release :count 2)
          (mapc #'bt:join-thread threads))))))

(defun repeated-probe-event (pod count at)
  "One readiness failure of POD's first container, seen COUNT times, the last at universal time AT."
  (vector (gr8s.resources::core-object
           "id" "repeated" "kind" "readinessProbe" "container" "c0" "reason" "Unhealthy"
           "message" (format nil "Readiness probe failed: attempt ~D" count) "count" count
           "firstTimestamp" (gr8s.store::current-timestamp 4000000000)
           "lastTimestamp" (gr8s.store::current-timestamp at))))

(test a-probe-that-keeps-failing-rewrites-its-event-at-most-once-a-minute
  ;; A probe that fails every few seconds reports a higher count each time. Every
  ;; rewrite of the Event is a write to the whole control plane.
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((now 4000000000) (gr8s.resources::*event-clock* (lambda () now))
           (pod (event-outbox-pod store)))
      (flet ((report (count)
               (gr8s.resources::record-node-runtime-events store pod "probe-node" (repeated-probe-event pod count now)))
             (stored ()
               (let ((events (gr8s.resources::list-core-resources store "events" "default")))
                 (and (= 1 (length events)) (elt events 0)))))
        (loop for count from 1 to 10
              do (incf now 5) (report count)
                 (is (eql count (gethash "count" (stored))) "the first failures are each shown at once"))
        (let ((revision (gr8s.store::pod-store-resource-revision store)))
          (loop for count from 11 to 21
                do (incf now 5) (report count))
          (is (eql 10 (gethash "count" (stored))) "after those, 55 seconds of failures write nothing")
          (is (= revision (gr8s.store::pod-store-resource-revision store))))
        (incf now 5) (report 22)
        (is (eql 22 (gethash "count" (stored))) "and a minute after the last write the count is brought up to date")
        (is (search "attempt 22" (gethash "message" (stored))))
        (incf now 5) (report 23)
        (is (eql 22 (gethash "count" (stored))))))))

(test a-page-of-events-stops-at-the-first-one-the-control-plane-cannot-commit
  ;; Without a quorum each write waits out its timeout. A node's status report
  ;; must not wait that long once for every Event it carries; the node reports
  ;; the same cumulative records again.
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((now 4000000000) (gr8s.resources::*event-clock* (lambda () now))
           (pod (event-outbox-pod store 3)) (proposals 0)
           (page (coerce (loop for container in '("c0" "c1" "c2")
                               collect (let ((event (elt (repeated-probe-event pod 1 now) 0)))
                                         (setf (gethash "id" event) container (gethash "container" event) container)
                                         event))
                         'vector)))
      (setf (gr8s.store::pod-store-consensus-commit-fn store)
            (lambda (tag json)
              (declare (ignore tag json))
              (incf proposals)
              (gr8s.resources::core-resource-error 503 "ServiceUnavailable" "The control-plane write could not commit")))
      (gr8s.resources::record-node-runtime-events store pod "probe-node" page)
      (is (= 1 proposals))
      (setf (gr8s.store::pod-store-consensus-commit-fn store) nil)
      (is (null (gr8s.resources::list-core-resources store "events" "default")))
      (gr8s.resources::record-node-runtime-events store pod "probe-node" page)
      (is (= 3 (length (gr8s.resources::list-core-resources store "events" "default")))))))
