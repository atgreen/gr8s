;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify real container-derived readiness, terminal and unavailable states,
;;;; stable persisted transition history, observation/revision separation,
;;;; replacement UID isolation and transaction rollback on checkpoint failure.

(in-package #:gr8s/tests)
(in-suite gr8s)

(defun condition-status-for-test (status type)
  "Find the requested condition in a generated Pod status."
  (gr8s::find-pod-condition (gethash "conditions" status) type))

(defun running-status-for-test (&rest names)
  "Translate concrete native CRI container observations into a running Pod status."
  (gr8s::core-object
   "phase" "Running" "observedGeneration" 1
   "containerStatuses"
   (map 'vector
        (lambda (name)
          (gr8s::containerd-container-status-object
           (gr8s::make-cri-container-info :id (concatenate 'string "container-" name)
                                         :name name :attempt 0 :image "busybox:1.36.1"
                                         :state gr8s.cri.v1::+containerstate-container_running+
                                         :started-at 1793729722000000000)))
        names)))

(test pod-readiness-requires-all-declared-native-containers
  (with-temporary-store (store path)
    (let ((pod (create-pod store (grace-pod))))
      (let ((unknown (gr8s::add-pod-status-conditions store pod (gr8s::pod-status "Running"))))
        (is (equal "False" (gethash "status" (condition-status-for-test unknown "Ready")))))
      (let ((ready (gr8s::add-pod-status-conditions store pod (running-status-for-test "web"))))
        (dolist (type '("PodScheduled" "Initialized" "ContainersReady" "Ready"))
          (is (equal "True" (gethash "status" (condition-status-for-test ready type)))))
        (is (gr8s::pod-status-ready-p ready)))
      (dolist (status (list (running-status-for-test "other") (running-status-for-test "web" "web")))
        (is (not (gr8s::pod-status-ready-p (gr8s::add-pod-status-conditions store pod status)))))
      (let ((unready (running-status-for-test "web")))
        (setf (gethash "ready" (aref (gethash "containerStatuses" unready) 0)) nil)
        (is (not (gr8s::pod-status-ready-p (gr8s::add-pod-status-conditions store pod unready)))))
      (let ((waiting (running-status-for-test "web")))
        (setf (gethash "state" (aref (gethash "containerStatuses" waiting) 0)) (gr8s::core-object "waiting" (gr8s::core-object)))
        (is (not (gr8s::pod-status-ready-p (gr8s::add-pod-status-conditions store pod waiting))))))))

(test one-ready-container-cannot-make-a-multicontainer-pod-ready
  (with-temporary-store (store path)
    (let* ((input (gr8s::copy-json-object (pod-to-object (grace-pod))))
           (spec (gethash "spec" input))
           (first (aref (gethash "containers" spec) 0))
           (second (gr8s::copy-json-object first)))
      (setf (gethash "name" second) "side"
            (gethash "containers" spec) (vector first second))
      (let ((pod (create-pod store (parse-pod input))))
        (is (not (gr8s::pod-status-ready-p (gr8s::add-pod-status-conditions store pod (running-status-for-test "web")))))
        (is (gr8s::pod-status-ready-p (gr8s::add-pod-status-conditions store pod (running-status-for-test "web" "side"))))))))

(test pod-conditions-preserve-transition-times-across-reasons-revisions-and-restarts
  (with-temporary-store (store path)
    (let* ((now 4000000000) (gr8s::*pod-condition-clock* (lambda () now))
           (pod (create-pod store (grace-pod)))
           (pending (gr8s::add-pod-status-conditions store pod (gr8s::pod-status "Pending")))
           (initial-time (gethash "lastTransitionTime" (condition-status-for-test pending "Ready"))))
      (incf now 10)
      (let ((reason-only (gr8s::add-pod-status-conditions store pod (gr8s::pod-status "Pending" :reason "RuntimeError"))))
        (is (equal initial-time (gethash "lastTransitionTime" (condition-status-for-test reason-only "Ready")))))
      (let* ((ready (gr8s::add-pod-status-conditions store pod (running-status-for-test "web")))
             (ready-time (gethash "lastTransitionTime" (condition-status-for-test ready "Ready"))))
        (is (not (equal initial-time ready-time)))
        ;; Rendering history must never masquerade as an agent acknowledgement.
        (is (equal "" (gr8s::pod-observed-resource-version store pod)))
        (is (null (gr8s::pod-observed-status (open-store path) pod)))
        (gr8s::update-pod-observed-status store pod ready)
        (let ((replacement (parse-pod (gr8s::copy-json-object (pod-to-object pod)))))
          (setf (gethash "annotations" (gethash "metadata" (pod-to-object replacement)))
                (gr8s::core-object "progress" "still running")
                pod (update-pod store replacement (pod-resource-version pod))))
        (incf now 10)
        (let* ((reopened (open-store path))
               (after-restart (gr8s::add-pod-status-conditions reopened pod (running-status-for-test "web"))))
          (is (equal "2" (pod-resource-version pod)))
          (is (equal "1" (gr8s::pod-observed-resource-version reopened pod)))
          (is (equal ready-time (gethash "lastTransitionTime" (condition-status-for-test after-restart "Ready")))))
        (let ((unknown (gr8s::copy-pod-status-value ready)))
          (setf (gethash "phase" unknown) "Unknown")
          (gr8s::add-pod-status-conditions store pod unknown)
          (is (equal "Unknown" (gethash "status" (condition-status-for-test unknown "Ready"))))
          (is (equal "NodeStatusUnknown" (gethash "reason" (condition-status-for-test unknown "Ready"))))
          (is (equal (gr8s::current-timestamp now) (gethash "lastTransitionTime" (condition-status-for-test unknown "Ready")))))
        (incf now 10)
        ;; An old agent timestamp cannot backdate recovery after node loss.
        (let ((recovered (gr8s::add-pod-status-conditions store pod ready)))
          (is (equal (gr8s::current-timestamp now)
                     (gethash "lastTransitionTime" (condition-status-for-test recovered "Ready")))))))))

(test terminal-and-unscheduled-pods-never-report-ready
  (with-temporary-store (store path)
    (let ((pod (create-pod store (parse-pod *valid-pod-json*))))
      (let ((observed (gr8s::add-pod-status-conditions store pod (running-status-for-test "web"))))
        (is (not (gr8s::pod-status-ready-p observed)))
        (is (equal "False" (gethash "status" (condition-status-for-test observed "PodScheduled")))))
      (delete-pod store "default" "hello"))
    (let ((pod (create-pod store (grace-pod))))
      (dolist (phase '("Succeeded" "Failed"))
        (let ((observed (running-status-for-test "web")))
          (setf (gethash "phase" observed) phase)
          (gr8s::add-pod-status-conditions store pod observed)
          (is (not (gr8s::pod-status-ready-p observed)))
          (is (equal "True" (gethash "status" (condition-status-for-test observed "Initialized"))))
          (is (equal (if (equal phase "Succeeded") "PodCompleted" "PodFailed")
                     (gethash "reason" (condition-status-for-test observed "Ready")))))))))

(test stale-status-checkpoints-cannot-revive-a-replacement-pod
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (grace-pod)))
           (old-uid (pod-uid pod))
           (checkpoint (gr8s::pod-status-state-path store old-uid))
           (status (gr8s::add-pod-status-conditions store pod (running-status-for-test "web"))))
      (gr8s::update-pod-observed-status store pod status)
      (let ((bytes (uiop:read-file-string checkpoint)))
        (delete-pod store "default" "hello")
        (is (not (probe-file checkpoint)))
        (let ((replacement (create-pod store (grace-pod))))
          ;; Simulate a crash leaving an orphan checkpoint after desired removal.
          (with-open-file (out checkpoint :direction :output :if-exists :supersede :if-does-not-exist :create)
            (write-string bytes out))
          (gr8s::update-pod-observed-status store pod status)
          (let ((reopened (open-store path)))
            (is (equal (pod-uid replacement) (pod-uid (get-pod reopened "default" "hello"))))
            (is (null (gr8s::pod-observed-status reopened replacement)))
            (is (equal "" (gr8s::pod-observed-resource-version reopened replacement)))
            (is (not (probe-file checkpoint)))))))))

(test status-checkpoint-failure-does-not-publish-partial-memory-state
  (with-temporary-store (store path)
    (let ((pod (create-pod store (grace-pod)))
          (blocker (merge-pathnames "observations" path)))
      (with-open-file (out blocker :direction :output :if-exists :supersede :if-does-not-exist :create)
        (write-string "not a directory" out))
      (signals file-error
        (gr8s::add-pod-status-conditions store pod (running-status-for-test "web")))
      (is (null (gethash (pod-uid pod) (gr8s::pod-store-pod-condition-histories store))))
      (signals file-error
        (gr8s::update-pod-observed-status store pod (running-status-for-test "web")))
      (is (null (gr8s::pod-observed-status store pod)))
      (is (equal "" (gr8s::pod-observed-resource-version store pod))))))

(test node-leases-survive-restart-only-while-the-granted-deadline-is-valid
  (with-temporary-store (store path)
    (let ((now (get-universal-time)))
      (gr8s::register-node store (make-test-node "worker-a" "node-a" "10.88.0.0/24"))
      (gr8s::mark-node-ready store "worker-a" now :lease-duration 60)
      (let ((restored (gr8s::get-node (open-store path) "worker-a")))
        (is (gr8s::node-record-ready-p restored))
        (is (= now (gr8s::node-record-last-heartbeat restored)))
        (is (= (+ now 60) (gr8s::node-record-lease-deadline restored))))
      ;; A changed server timeout cannot retroactively shorten a granted lease.
      (is (null (gr8s::expire-node-heartbeats store (+ now 50) :now (+ now 30))))
      (is (= 1 (length (gr8s::expire-node-heartbeats store now :now (+ now 61)))))
      (is (not (gr8s::node-record-ready-p (gr8s::get-node (open-store path) "worker-a"))))
      (gr8s::mark-node-ready store "worker-a" (- now 100) :lease-duration 1)
      (is (not (gr8s::node-record-ready-p (gr8s::get-node (open-store path) "worker-a"))))
      (gr8s::mark-node-ready store "worker-a" now :lease-duration 60)
      (gr8s::mark-node-not-ready store "worker-a")
      (is (not (gr8s::node-record-ready-p (gr8s::get-node (open-store path) "worker-a")))))))

(test node-heartbeats-checkpoint-the-servers-configured-lease-duration
  (with-temporary-store (store path)
    (gr8s::register-node store (make-test-node "worker-a" "node-a" "10.88.0.0/24"))
    (let ((server (gr8s::%make-node-grpc-server :store store :heartbeat-timeout-seconds 47)))
      (gr8s::handle-node-agent-envelope
       server "worker-a" (gr8s::make-agent-envelope :heartbeat (make-instance 'gr8s.node.v1::heartbeat)))
      (let ((node (gr8s::get-node (open-store path) "worker-a")))
        (is (gr8s::node-record-ready-p node))
        (is (= 47 (- (gr8s::node-record-lease-deadline node) (gr8s::node-record-last-heartbeat node))))))))

(test prepublished-snapshot-cannot-strand-an-agent-ahead-of-a-restarted-server
  (with-temporary-store (store path)
    (gr8s::register-node store (gr8s::make-node-record :name "worker-a" :id "node-a" :pod-cidr "10.88.0.0/24"))
    (let* ((server (gr8s::start-node-grpc-server store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "ahead/identity.json" path))
           (applied nil))
      (unwind-protect
           (progn
             (gr8s::persist-agent-identity identity-path (gr8s::make-agent-identity "worker-a" :node-id "node-a" :revision 64))
             (is (= 1 (gr8s::publish-node-desired-state server "worker-a" (empty-desired-snapshot))))
             (is (gr8s::same-node-snapshot-topology-p
                  (gr8s::current-node-snapshot server "worker-a")
                  (gr8s::attach-node-topology server "worker-a" (gr8s::node-desired-state-snapshot store "worker-a"))))
             (gr8s::run-node-session
              "127.0.0.1" (gr8s::node-grpc-server-port server) "worker-a" identity-path
              (lambda (snapshot) (push (slot-value snapshot 'gr8s.node.v1::revision) applied) nil)
              :max-sessions 1 :reconnect-delay .01)
             (is (equal '(65) applied))
             (is (= 65 (gethash "lastAppliedRevision" (com.inuoe.jzon:parse identity-path))))
             (is (= 65 (gr8s::node-session-acknowledged-revision server "worker-a"))))
        (gr8s::stop-node-grpc-server server)))))
