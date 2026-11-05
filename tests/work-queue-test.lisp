;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify lanes, deduplication and backoff, then show that many volumes and a hung
;;;; server stay within their limits in both the control plane and the agent.

(in-package #:gr8s/tests)
(def-suite work-queues :in gr8s)
(in-suite work-queues)

(defmacro with-test-gate ((open-gate wait-gate) &body body)
  "Bind OPEN-GATE to release jobs blocked in WAIT-GATE, opening it however BODY exits."
  (let ((open (gensym "OPEN")))
    `(let ((,open nil))
       (flet ((,open-gate () (setf ,open t))
              (,wait-gate () (loop until ,open do (sleep 0.005))))
         (declare (ignorable #',open-gate #',wait-gate))
         (unwind-protect (progn ,@body)
           (setf ,open t))))))

(test lanes-never-exceed-their-limit-and-run-every-job
  (let* ((queue (gr8s::make-work-queue :lane-limit (constantly 4)))
         (lock (bt:make-lock)) (running 0) (peak 0) (finished 0))
    (dotimes (index 300)
      (gr8s::work-queue-submit
       queue index "local"
       (lambda ()
         (bt:with-lock-held (lock)
           (incf running)
           (setf peak (max peak running)))
         (sleep 0.001)
         (bt:with-lock-held (lock)
           (decf running)
           (incf finished)))))
    (is-true (wait-until (lambda () (bt:with-lock-held (lock) (= 300 finished))) :timeout 30))
    (is (<= peak 4))
    (is-true (wait-until (lambda () (zerop (gr8s::work-queue-running-workers queue))) :timeout 5))
    ;; An idle lane leaves nothing behind.
    (is (zerop (hash-table-count (gr8s::work-queue-lanes queue))))))

(test a-request-for-a-running-key-joins-it
  (with-test-gate (release wait)
    (let* ((queue (gr8s::make-work-queue)) (runs 0) (answers nil) (lock (bt:make-lock)))
      (flet ((submit (tag)
               (gr8s::work-queue-submit
                queue "pvc-1" "local"
                (lambda () (incf runs) (wait) :done)
                :on-done (lambda (value condition)
                           (declare (ignore condition))
                           (bt:with-lock-held (lock) (push (cons tag value) answers))))))
        (is-true (submit :first))
        (is-true (wait-until (lambda () (= 1 runs))))
        (is-false (submit :second))
        (is-true (gr8s::work-queue-active-p queue "pvc-1"))
        (release)
        (is-true (wait-until (lambda () (bt:with-lock-held (lock) (= 2 (length answers))))))
        (is (= 1 runs))
        (is (equal '((:first . :done) (:second . :done)) (reverse answers)))
        (is-true (wait-until (lambda () (not (gr8s::work-queue-active-p queue "pvc-1")))))
        ;; A finished key can run again.
        (is-true (submit :third))
        (is-true (wait-until (lambda () (= 2 runs))))))))

(test a-stuck-lane-holds-up-only-itself
  (with-test-gate (release wait)
    (let* ((queue (gr8s::make-work-queue :lane-limit (constantly 2))) (done nil))
      (dotimes (index 5)
        (gr8s::work-queue-submit queue (format nil "dead-~D" index) "nfs/dead" #'wait))
      (gr8s::work-queue-submit queue "alive" "local" (lambda () (setf done t)))
      (is-true (wait-until (lambda () done)))
      ;; Two workers are stuck and three jobs wait behind them; no more threads appear.
      (is (= 2 (gr8s::work-queue-running-workers queue)))
      (is-true (gr8s::work-queue-active-p queue "dead-4"))
      (release)
      (is-true (wait-until (lambda () (not (gr8s::work-queue-active-p queue "dead-4"))))))))

(test job-failures-reach-the-waiter-and-keep-the-worker
  (let* ((queue (gr8s::make-work-queue)) (seen nil) (ran nil)
         (*error-output* (make-broadcast-stream)))
    (gr8s::work-queue-submit queue "a" "local"
                             (lambda () (error 'runtime-error :message "disk on fire"))
                             :on-done (lambda (value condition)
                                        (declare (ignore value))
                                        (setf seen condition)
                                        ;; A broken waiter must not cost the lane its worker.
                                        (error "waiter failed")))
    (gr8s::work-queue-submit queue "b" "local" (lambda () (setf ran t)))
    (is-true (wait-until (lambda () (and seen ran))))
    (is (typep seen 'runtime-error))))

(test stopping-fails-waiting-jobs-and-refuses-new-ones
  (with-test-gate (release wait)
    (let* ((queue (gr8s::make-work-queue)) (started nil) (ran nil) (seen nil))
      (gr8s::work-queue-submit queue "running" "local" (lambda () (setf started t) (wait)))
      (is-true (wait-until (lambda () started)))
      (gr8s::work-queue-submit queue "waiting" "local" (lambda () (setf ran t))
                               :on-done (lambda (value condition)
                                          (declare (ignore value))
                                          (setf seen condition)))
      (gr8s::work-queue-stop queue)
      (is (typep seen 'runtime-error))
      (signals runtime-error (gr8s::work-queue-submit queue "late" "local" (constantly nil)))
      (release)
      (is-true (wait-until (lambda () (zerop (gr8s::work-queue-running-workers queue)))))
      (is (null ran)))))

(test backoff-doubles-to-its-maximum-and-clears
  (let ((backoff (gr8s::make-retry-backoff)))
    (is-true (gr8s::retry-backoff-ready-p backoff "a" 100))
    (is (= 1 (gr8s::retry-backoff-failed backoff "a" 100)))
    (is-false (gr8s::retry-backoff-ready-p backoff "a" 100))
    (is-true (gr8s::retry-backoff-ready-p backoff "a" 101))
    (is (equal '(2 4 8 16 32 64 128 256 300 300)
               (loop repeat 10 collect (gr8s::retry-backoff-failed backoff "a" 101))))
    (gr8s::retry-backoff-clear backoff "a")
    (is-true (gr8s::retry-backoff-ready-p backoff "a" 101))
    (is (= 1 (gr8s::retry-backoff-failed backoff "a" 101)))))

;;; The control plane

(defun released-local-volume (store index)
  "Store a provisioned local volume whose claim has gone, on worker-a."
  (let* ((name (format nil "pvc-local-~D" index))
         (volume (storage-test-volume name (format nil "/volumes/~A" name))))
    (setf (gethash "annotations" (gethash "metadata" volume))
          (gr8s::core-object gr8s::+provisioned-by-annotation+ gr8s::+local-path-provisioner+)
          (gethash "persistentVolumeReclaimPolicy" (gethash "spec" volume)) "Delete"
          (gethash "claimRef" (gethash "spec" volume))
          (gr8s::core-object "name" "gone" "namespace" "default" "uid" (format nil "uid-~A" name))
          (gethash "nodeAffinity" (gethash "spec" volume)) (gr8s::storage-node-affinity-for "worker-a"))
    (gr8s::create-core-resource store "persistentvolumes" volume nil)))

(defun released-nfs-volume (store index server)
  "Store a provisioned NFS volume whose claim has gone."
  (let* ((name (format nil "pvc-nfs-~D" index))
         (volume (storage-test-volume name "/unused")))
    (remhash "hostPath" (gethash "spec" volume))
    (setf (gethash "annotations" (gethash "metadata" volume))
          (gr8s::core-object gr8s::+provisioned-by-annotation+ gr8s::+nfs-provisioner+
                             gr8s::+nfs-share-annotation+ "/share")
          (gethash "persistentVolumeReclaimPolicy" (gethash "spec" volume)) "Delete"
          (gethash "nfs" (gethash "spec" volume)) (gr8s::core-object "server" server "path" (format nil "/share/~A" name))
          (gethash "claimRef" (gethash "spec" volume))
          (gr8s::core-object "name" "gone" "namespace" "default" "uid" (format nil "uid-~A" name)))
    (gr8s::create-core-resource store "persistentvolumes" volume nil)))

(defmacro with-test-reclaimer ((reclaimer store path) &body body)
  "Run BODY with a reclaimer on a real node server whose worker-a has no session,
so requests wait until the test finishes them."
  (let ((server (gensym "SERVER")))
    `(with-temporary-store (,store ,path)
       (values ,path)
       (gr8s:register-node ,store (make-test-node "worker-a" "a" "10.64.0.0/20"))
       ;; A heartbeat far ahead of any clock, since the server expires silent nodes.
       (gr8s:mark-node-ready ,store "worker-a" (expt 10 11))
       (let* ((,server (gr8s:start-node-grpc-server ,store :host "127.0.0.1" :port 0))
              (,reclaimer (gr8s::make-volume-reclaimer ,store ,server))
              (*error-output* (make-broadcast-stream)))
         (unwind-protect (progn ,@body)
           (gr8s:stop-node-grpc-server ,server))))))

(defun in-flight-names (reclaimer)
  (loop for name being the hash-keys of (gr8s::volume-reclaimer-in-flight reclaimer) collect name))

(defun finish-reclaim (reclaimer name &key error)
  "Answer the outstanding request for NAME as an agent or a closed session would."
  (let ((operation (gr8s::volume-reclaim-request-operation
                    (gethash name (gr8s::volume-reclaimer-in-flight reclaimer)))))
    (gr8s::finish-node-operation
     operation
     :error error
     :response (unless error
                 (make-instance 'gr8s.node.v1::operation-response
                                :status gr8s.node.v1::+operationstatus-operation_status_complete+)))))

(test many-volumes-are-sent-in-limited-batches-without-repeats
  (with-test-reclaimer (reclaimer store path)
    (dotimes (index 20) (released-local-volume store index))
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (let ((first-batch (in-flight-names reclaimer)))
      (is (= gr8s::+volume-reclaim-dispatch-limit+ (length first-batch)))
      ;; A pass while they're still running sends nothing, however long they take.
      (gr8s::volume-reclaimer-step reclaimer 5000)
      (is (null (set-exclusive-or first-batch (in-flight-names reclaimer) :test #'equal)))
      (dolist (name first-batch) (finish-reclaim reclaimer name))
      (gr8s::volume-reclaimer-step reclaimer 5001)
      (dolist (name first-batch)
        (signals kubernetes-error (gr8s::get-core-resource store "persistentvolumes" nil name)))
      (is (= gr8s::+volume-reclaim-dispatch-limit+ (length (in-flight-names reclaimer))))
      (is (null (intersection first-batch (in-flight-names reclaimer) :test #'equal))))))

(test a-dead-nfs-server-does-not-hold-up-local-volumes-or-other-servers
  (with-test-reclaimer (reclaimer store path)
    (dotimes (index 12) (released-nfs-volume store index "dead.example.test"))
    (released-nfs-volume store 100 "alive.example.test")
    (released-local-volume store 0)
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (let ((names (in-flight-names reclaimer)))
      (is (member "pvc-local-0" names :test #'equal))
      (is (member "pvc-nfs-100" names :test #'equal))
      (is (= 8 (count-if (lambda (name) (and (uiop:string-prefix-p "pvc-nfs-" name)
                                             (not (equal name "pvc-nfs-100"))))
                         names))))
    ;; With the dead lane still full, new local work goes straight through.
    (finish-reclaim reclaimer "pvc-local-0")
    (released-local-volume store 1)
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1001)
    (is (member "pvc-local-1" (in-flight-names reclaimer) :test #'equal))))

(test failed-reclaims-back-off-and-a-closed-session-counts-as-failure
  (with-test-reclaimer (reclaimer store path)
    (released-local-volume store 0)
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (finish-reclaim reclaimer "pvc-local-0" :error "Node session closed")
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (is (null (in-flight-names reclaimer)))
    (is (gr8s::get-core-resource store "persistentvolumes" nil "pvc-local-0"))
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (is (null (in-flight-names reclaimer)))
    (gr8s::volume-reclaimer-step reclaimer 1001)
    (is (= 1 (length (in-flight-names reclaimer))))
    (finish-reclaim reclaimer "pvc-local-0" :error "still failing")
    (gr8s::volume-reclaimer-step reclaimer 1001)
    (gr8s::volume-reclaimer-step reclaimer 1002)
    (is (null (in-flight-names reclaimer)))
    (gr8s::volume-reclaimer-step reclaimer 1003)
    (is (= 1 (length (in-flight-names reclaimer))))
    (finish-reclaim reclaimer "pvc-local-0")
    (gr8s::volume-reclaimer-step reclaimer 1004)
    (signals kubernetes-error (gr8s::get-core-resource store "persistentvolumes" nil "pvc-local-0"))
    (is (zerop (hash-table-count (gr8s::retry-backoff-entries (gr8s::volume-reclaimer-backoff reclaimer)))))))

(test an-administrators-deletion-during-reclaim-is-not-a-failure
  (with-test-reclaimer (reclaimer store path)
    (released-local-volume store 0)
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (gr8s::delete-core-resource store "persistentvolumes" nil "pvc-local-0")
    (finish-reclaim reclaimer "pvc-local-0")
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (is (null (in-flight-names reclaimer)))
    (is (zerop (hash-table-count (gr8s::retry-backoff-entries (gr8s::volume-reclaimer-backoff reclaimer)))))))

;;; Reporting

(defun volume-events (store name)
  "Return the Events about PV NAME."
  (remove-if-not (lambda (event) (equal name (gethash "name" (gethash "involvedObject" event))))
                 (gr8s::list-core-resources store "events" "default")))

(defun volume-event (store name reason)
  (find reason (volume-events store name) :key (lambda (event) (gethash "reason" event)) :test #'equal))

(defun ready-second-node (store)
  (gr8s:register-node store (make-test-node "worker-b" "b" "10.64.16.0/20"))
  (gr8s:mark-node-ready store "worker-b" (expt 10 11)))

(defun in-flight-node (reclaimer name)
  (gr8s::volume-reclaim-request-node (gethash name (gr8s::volume-reclaimer-in-flight reclaimer))))

(test failures-raise-a-counted-warning-event-on-the-volume
  (with-test-reclaimer (reclaimer store path)
    (released-local-volume store 0)
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (is (null (volume-events store "pvc-local-0")))
    (finish-reclaim reclaimer "pvc-local-0" :error "Permission denied")
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (let ((event (volume-event store "pvc-local-0" "VolumeFailedDelete")))
      (is-true event)
      (is (equal "Warning" (gethash "type" event)))
      (is (= 1 (gethash "count" event)))
      (is (search "Permission denied" (gethash "message" event)))
      (is (search "retrying in 1s" (gethash "message" event)))
      (is (equal "PersistentVolume" (gethash "kind" (gethash "involvedObject" event)))))
    (gr8s::volume-reclaimer-step reclaimer 1001)
    (finish-reclaim reclaimer "pvc-local-0" :error "Still denied")
    (gr8s::volume-reclaimer-step reclaimer 1001)
    (let ((event (volume-event store "pvc-local-0" "VolumeFailedDelete")))
      (is (= 2 (gethash "count" event)))
      (is (search "Still denied" (gethash "message" event)))
      (is (search "retrying in 2s" (gethash "message" event))))
    (is (= 1 (length (volume-events store "pvc-local-0"))))))

(test long-failure-messages-still-produce-an-event
  (with-test-reclaimer (reclaimer store path)
    (released-local-volume store 0)
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (finish-reclaim reclaimer "pvc-local-0" :error (make-string 5000 :initial-element #\x))
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (is-true (volume-event store "pvc-local-0" "VolumeFailedDelete"))))

(test an-unanswered-request-is-reported-once-and-never-resent
  (with-test-reclaimer (reclaimer store path)
    (released-local-volume store 0)
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (let ((request (gethash "pvc-local-0" (gr8s::volume-reclaimer-in-flight reclaimer))))
      (gr8s::volume-reclaimer-step reclaimer 1299)
      (is (null (volume-event store "pvc-local-0" "VolumeReclaimStalled")))
      (gr8s::volume-reclaimer-step reclaimer 1300)
      (let ((event (volume-event store "pvc-local-0" "VolumeReclaimStalled")))
        (is-true event)
        (is (= 1 (gethash "count" event)))
        (is (search "worker-a" (gethash "message" event)))
        (is (search "300 seconds" (gethash "message" event))))
      (gr8s::volume-reclaimer-step reclaimer 9000)
      (is (= 1 (gethash "count" (volume-event store "pvc-local-0" "VolumeReclaimStalled"))))
      (is (eq request (gethash "pvc-local-0" (gr8s::volume-reclaimer-in-flight reclaimer))))
      (is (zerop (gr8s::volume-reclaimer-failures reclaimer))))))

(test metrics-report-failures-backlog-and-the-oldest-request
  (with-test-reclaimer (reclaimer store path)
    (dotimes (index 10) (released-local-volume store index))
    (released-nfs-volume store 0 "nas.example.test")
    (gr8s::reconcile-storage-bindings store)
    (is (null (gr8s::volume-reclaimer-metrics reclaimer)))
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (gr8s::volume-reclaimer-step reclaimer 1042)
    (let ((text (gr8s::volume-reclaimer-metrics reclaimer)))
      (is (search (format nil "gr8s_volume_reclaim_failures_total 0~%") text))
      ;; Two of the local volumes are over the limit of eight, so they're still waiting.
      (is (search (format nil "gr8s_volume_reclaim_waiting 2~%") text))
      (is (search (format nil "gr8s_volume_reclaim_oldest_outstanding_seconds 42~%") text))
      (is (search (format nil "gr8s_volume_reclaim_outstanding{node=\"worker-a\",lane=\"local\"} 8~%") text))
      (is (search (format nil "gr8s_volume_reclaim_outstanding{node=\"worker-a\",lane=\"nfs/nas.example.test\"} 1~%") text)))
    (finish-reclaim reclaimer "pvc-nfs-0" :error "boom")
    (gr8s::volume-reclaimer-step reclaimer 1043)
    (is (search (format nil "gr8s_volume_reclaim_failures_total 1~%") (gr8s::volume-reclaimer-metrics reclaimer)))
    ;; /metrics reads the running reclaimer, and is empty before there is one.
    (let ((gr8s::*active-volume-reclaimer* nil))
      (is (equal "" (gr8s::volume-reclaim-metrics-text))))
    (let ((gr8s::*active-volume-reclaimer* reclaimer))
      (is (search "gr8s_volume_reclaim_waiting" (gr8s::volume-reclaim-metrics-text))))))

(test retry-state-is-dropped-once-a-volume-is-gone
  (with-test-reclaimer (reclaimer store path)
    (released-nfs-volume store 0 "nas.example.test")
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (finish-reclaim reclaimer "pvc-nfs-0" :error "boom")
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (is (gethash "pvc-nfs-0" (gr8s::volume-reclaimer-failed-nodes reclaimer)))
    (gr8s::delete-core-resource store "persistentvolumes" nil "pvc-nfs-0")
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (is (zerop (hash-table-count (gr8s::volume-reclaimer-failed-nodes reclaimer))))
    (is (zerop (hash-table-count (gr8s::retry-backoff-entries (gr8s::volume-reclaimer-backoff reclaimer)))))))

;;; Choosing another node

(test a-failed-nfs-deletion-tries-the-other-ready-nodes-in-turn
  (with-test-reclaimer (reclaimer store path)
    (ready-second-node store)
    (released-nfs-volume store 0 "nas.example.test")
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (is (equal "worker-a" (in-flight-node reclaimer "pvc-nfs-0")))
    (finish-reclaim reclaimer "pvc-nfs-0" :error "stale file handle")
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (gr8s::volume-reclaimer-step reclaimer 1001)
    (is (equal "worker-b" (in-flight-node reclaimer "pvc-nfs-0")))
    ;; Every node has now failed, so a new round starts at the first.
    (finish-reclaim reclaimer "pvc-nfs-0" :error "stale file handle")
    (gr8s::volume-reclaimer-step reclaimer 1001)
    (gr8s::volume-reclaimer-step reclaimer 1003)
    (is (equal "worker-a" (in-flight-node reclaimer "pvc-nfs-0")))
    (finish-reclaim reclaimer "pvc-nfs-0" :error "stale file handle")
    (gr8s::volume-reclaimer-step reclaimer 1003)
    (gr8s::volume-reclaimer-step reclaimer 1007)
    (is (equal "worker-b" (in-flight-node reclaimer "pvc-nfs-0")))
    ;; Success ends it, and the next volume starts fresh.
    (finish-reclaim reclaimer "pvc-nfs-0")
    (gr8s::volume-reclaimer-step reclaimer 1007)
    (signals kubernetes-error (gr8s::get-core-resource store "persistentvolumes" nil "pvc-nfs-0"))
    (is (zerop (hash-table-count (gr8s::volume-reclaimer-failed-nodes reclaimer))))))

(test a-retry-skips-a-node-that-is-no-longer-ready
  (with-test-reclaimer (reclaimer store path)
    (ready-second-node store)
    (released-nfs-volume store 0 "nas.example.test")
    (gr8s::reconcile-storage-bindings store)
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (finish-reclaim reclaimer "pvc-nfs-0" :error "session closed")
    (gr8s::mark-node-not-ready store "worker-b")
    (gr8s::volume-reclaimer-step reclaimer 1000)
    (gr8s::volume-reclaimer-step reclaimer 1001)
    ;; Only worker-a is Ready, so it's tried again even though it has already failed.
    (is (equal "worker-a" (in-flight-node reclaimer "pvc-nfs-0")))))

(test local-volumes-only-ever-go-to-their-own-node
  (with-test-reclaimer (reclaimer store path)
    (ready-second-node store)
    (released-local-volume store 0)
    (gr8s::reconcile-storage-bindings store)
    (dolist (now '(1000 1001 1003))
      (gr8s::volume-reclaimer-step reclaimer now)
      (is (equal "worker-a" (in-flight-node reclaimer "pvc-local-0")))
      (finish-reclaim reclaimer "pvc-local-0" :error "disk error")
      (gr8s::volume-reclaimer-step reclaimer now))))

;;; The agent

(defun reclaim-request (volume)
  (make-instance 'gr8s.node.v1::operation-request
                 :operation-id (gr8s::generate-uid)
                 :kind gr8s.node.v1::+operationkind-operation_kind_reclaim_volume+
                 :volume-json (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify volume))))

(defun agent-test-volume (name &optional server)
  (let ((spec (gr8s::core-object)))
    (if server
        (setf (gethash "nfs" spec) (gr8s::core-object "server" server "path" (format nil "/share/~A" name)))
        (setf (gethash "hostPath" spec) (gr8s::core-object "path" (format nil "/volumes/~A" name))))
    (gr8s::core-object "metadata" (gr8s::core-object "name" name) "spec" spec)))

(test three-hundred-agent-requests-use-a-handful-of-threads
  (with-temporary-store (store path)
    (values store)
    (with-test-gate (release wait)
      (let* ((node-runtime (gr8s::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
             (lock (bt:make-lock)) (active 0) (peak 0) (runs 0) (answers 0)
             (gr8s::*reclaim-volume-call*
               (lambda (directory volume)
                 (declare (ignore directory volume))
                 (bt:with-lock-held (lock) (incf active) (incf runs) (setf peak (max peak active)))
                 (wait)
                 (bt:with-lock-held (lock) (decf active))))
             (threads-before (length (sb-thread:list-all-threads))))
        (flet ((emit (variant message)
                 (declare (ignore message))
                 (when (eq variant :operation-response)
                   (bt:with-lock-held (lock) (incf answers)))))
          (dotimes (index 300)
            (gr8s::dispatch-node-operation
             node-runtime :operation-request
             (reclaim-request (agent-test-volume (format nil "pvc-~D" index)))
             #'emit))
          (is-true (wait-until (lambda () (bt:with-lock-held (lock) (= 4 active)))))
          ;; The workers are the only threads this added, not 300 of them.
          (is (<= (- (length (sb-thread:list-all-threads)) threads-before) 4))
          (is (= 4 (gr8s::work-queue-running-workers (gr8s::node-runtime-reclaim-queue node-runtime))))
          (release)
          (is-true (wait-until (lambda () (bt:with-lock-held (lock) (= 300 answers))) :timeout 30))
          (is (= 300 runs))
          (is (= 4 peak)))))))

(test a-repeated-agent-request-joins-the-deletion-and-is-answered-too
  (with-temporary-store (store path)
    (values store)
    (with-test-gate (release wait)
      (let* ((node-runtime (gr8s::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
             (lock (bt:make-lock)) (runs 0) (answers nil)
             (gr8s::*reclaim-volume-call*
               (lambda (directory volume)
                 (declare (ignore directory volume))
                 (bt:with-lock-held (lock) (incf runs))
                 (wait))))
        (flet ((request ()
                 (let ((message (reclaim-request (agent-test-volume "pvc-1"))))
                   (gr8s::dispatch-node-operation
                    node-runtime :operation-request message
                    (lambda (variant response)
                      (when (eq variant :operation-response)
                        (bt:with-lock-held (lock)
                          (push (slot-value response 'gr8s.node.v1::operation-id) answers)))))
                   (slot-value message 'gr8s.node.v1::operation-id))))
          (let ((first (request)))
            (is-true (wait-until (lambda () (bt:with-lock-held (lock) (= 1 runs)))))
            (let ((second (request)))
              (release)
              (is-true (wait-until (lambda () (bt:with-lock-held (lock) (= 2 (length answers))))))
              (is (= 1 runs))
              (is (null (set-exclusive-or (list first second) answers :test #'equal))))))))))

(test a-hung-nfs-server-leaves-agent-local-deletions-running
  (with-temporary-store (store path)
    (values store)
    (with-test-gate (release wait)
      (let* ((node-runtime (gr8s::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
             (done nil)
             (gr8s::*reclaim-volume-call*
               (lambda (directory volume)
                 (declare (ignore directory))
                 (if (gethash "nfs" (gethash "spec" volume))
                     (wait)
                     (setf done t)))))
        (dotimes (index 5)
          (gr8s::dispatch-node-operation
           node-runtime :operation-request
           (reclaim-request (agent-test-volume (format nil "pvc-~D" index) "dead.example.test"))
           (constantly nil)))
        (gr8s::dispatch-node-operation
         node-runtime :operation-request (reclaim-request (agent-test-volume "pvc-local")) (constantly nil))
        (is-true (wait-until (lambda () done)))
        (is (= 2 (gr8s::work-queue-running-workers (gr8s::node-runtime-reclaim-queue node-runtime))))
        (release)))))

(test agent-failures-come-back-as-failed-responses
  (with-temporary-store (store path)
    (values store)
    (let* ((node-runtime (gr8s::make-node-runtime (merge-pathnames "agent/" path) (make-fake-runtime) nil))
           (response nil)
           (gr8s::*reclaim-volume-call*
             (lambda (directory volume)
               (declare (ignore directory volume))
               (error 'runtime-error :message "Permission denied"))))
      (gr8s::dispatch-node-operation
       node-runtime :operation-request (reclaim-request (agent-test-volume "pvc-1"))
       (lambda (variant message)
         (when (eq variant :operation-response) (setf response message))))
      (is-true (wait-until (lambda () response)))
      (is (= (slot-value response 'gr8s.node.v1::status)
             gr8s.node.v1::+operationstatus-operation_status_failed+))
      (is (search "Permission denied" (slot-value response 'gr8s.node.v1::error-message))))))

(test the-agent-reclaim-lanes-separate-local-disks-and-each-server
  (is (equal "local" (gr8s::volume-reclaim-lane (agent-test-volume "pvc-1"))))
  (is (equal "nfs/a.example.test" (gr8s::volume-reclaim-lane (agent-test-volume "pvc-1" "a.example.test"))))
  (is (= 4 (gr8s::volume-reclaim-lane-limit "local")))
  (is (= 2 (gr8s::volume-reclaim-lane-limit "nfs/a.example.test"))))
