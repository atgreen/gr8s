;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise real asynchronous probe ownership and deterministic scheduling,
;;;; startup/threshold state, restart policy and durable stop intent against
;;;; controlled CRI observations. Preserve sibling and sandbox identity and
;;;; reject stale results on deletion or an actual attempt replacement.

(in-package #:gr8s/tests)
(in-suite container-probes)

(defun probe-test-side-container (pod)
  "Read the side container's authoritative declaration in a private test Pod."
  (aref (gethash "containers" (gethash "spec" (gr8s::pod-to-object pod))) 1))

(defun probe-test-target (manager pod)
  "Find the current side target under its UID/name ownership."
  (gethash (list (pod-uid pod) "side") (gr8s::container-probe-manager-targets manager)))

(defun probe-test-worker (target kind)
  "Read a specific independent kind's worker from the target."
  (find kind (gr8s::container-probe-target-workers target) :test #'equal :key #'gr8s::container-probe-worker-kind))

(test probe-readiness-obeys-initial-delay-period-and-consecutive-thresholds
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (answers '(t t nil nil)) (calls 0)
           (manager (gr8s::make-container-probe-manager :clock (lambda () now)
                      :executor (lambda (&rest args) (declare (ignore args)) (incf calls) (values (pop answers) "measured")))))
      (setf (gr8s::containerd-runtime-probes runtime) manager
            (gethash "readinessProbe" (probe-test-side-container pod))
            (checked-probe "{\"exec\":{\"command\":[\"ready\"]},\"initialDelaySeconds\":2,\"periodSeconds\":1,\"successThreshold\":2,\"failureThreshold\":2}"))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
        (let* ((observed (runtime-observe runtime (pod-uid pod))))
          (gr8s::sync-container-probe-targets runtime pod observed :start-workers nil)
          (let* ((target (probe-test-target manager pod)) (worker (probe-test-worker target "readinessProbe")))
            (gr8s::step-container-probe manager runtime target worker) (is (= 0 calls))
            (is-false (gethash "ready" (lifecycle-side-status (gr8s::apply-container-probe-observation runtime observed))))
            (incf now 2) (gr8s::step-container-probe manager runtime target worker) (is (= 1 calls))
            (is-false (gr8s::container-probe-worker-result worker))
            (gr8s::step-container-probe manager runtime target worker) (is (= 1 calls))
            (incf now) (gr8s::step-container-probe manager runtime target worker) (is-true (gr8s::container-probe-worker-result worker))
            (incf now) (gr8s::step-container-probe manager runtime target worker) (is-true (gr8s::container-probe-worker-result worker))
            (incf now) (gr8s::step-container-probe manager runtime target worker) (is-false (gr8s::container-probe-worker-result worker))
            (is (= 4 calls))))))))

(test startup-suppresses-other-probes-and-stops-executing-after-success
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (calls nil) (startup-runs 0)
           (manager (gr8s::make-container-probe-manager :clock (lambda () now)
                     :executor (lambda (runtime container id ip probe)
                                 (declare (ignore runtime container id ip))
                                 (let ((name (aref (gethash "command" (gethash "exec" probe)) 0)))
                                   (push name calls) (values (if (equal name "startup") (> (incf startup-runs) 1) t) "actual result"))))))
      (setf (gr8s::containerd-runtime-probes runtime) manager)
      (dolist (pair '(("startupProbe" . "startup") ("readinessProbe" . "ready") ("livenessProbe" . "live")))
        (setf (gethash (car pair) (probe-test-side-container pod))
              (checked-probe (format nil "{\"exec\":{\"command\":[\"~A\"]},\"periodSeconds\":1}" (cdr pair)) (car pair))))
      (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                           (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
        (let ((observed (runtime-observe runtime (pod-uid pod))))
          (gr8s::sync-container-probe-targets runtime pod observed :start-workers nil)
          (let* ((target (probe-test-target manager pod)) (startup (probe-test-worker target "startupProbe")))
            (dolist (kind '("readinessProbe" "livenessProbe")) (gr8s::step-container-probe manager runtime target (probe-test-worker target kind)))
            (is (null calls))
            (is-false (gethash "started" (lifecycle-side-status (gr8s::apply-container-probe-observation runtime observed))))
            (gr8s::step-container-probe manager runtime target startup) (is-false (gr8s::probe-target-started-p target))
            (incf now) (gr8s::step-container-probe manager runtime target startup) (is-true (gr8s::probe-target-started-p target))
            (dolist (kind '("readinessProbe" "livenessProbe")) (gr8s::step-container-probe manager runtime target (probe-test-worker target kind)))
            (is (equal '("live" "ready" "startup" "startup") calls))
            (incf now 10) (gr8s::step-container-probe manager runtime target startup) (is (= 2 startup-runs))
            (gr8s::checkpoint-container-probes runtime pod manager)
            (setf (gr8s::containerd-runtime-probes runtime) (gr8s::make-container-probe-manager :clock (lambda () now)))
            (let ((reopened (runtime-observe runtime (pod-uid pod))))
              (is-true (gethash "started" (lifecycle-side-status reopened)))
              (is-true (gethash "ready" (lifecycle-side-status reopened))))))))))

(test failed-probe-restarts-onfailure-zero-exit-without-touching-healthy-sibling
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (manager (gr8s::make-container-probe-manager :clock (lambda () now)
                      :executor (lambda (runtime container id ip probe)
                                  (declare (ignore runtime container ip probe)) (values (not (equal id "side-0")) "measured"))))
           (side (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
      (setf (gr8s::containerd-runtime-probes runtime) manager
            (gethash "livenessProbe" (probe-test-side-container pod))
            (checked-probe "{\"exec\":{\"command\":[\"live\"]},\"failureThreshold\":1,\"terminationGracePeriodSeconds\":7}" "livenessProbe"))
      (unwind-protect
           (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now) side))
             (let ((observed (runtime-observe runtime (pod-uid pod))))
               (gr8s::sync-container-probe-targets runtime pod observed :start-workers nil)
               (let ((target (probe-test-target manager pod)))
                 (gr8s::step-container-probe manager runtime target (probe-test-worker target "livenessProbe")))
               (let* ((state (gr8s::checkpoint-container-probes runtime pod manager))
                      (request (gethash "probeRestart" (gethash "side" (gethash "containers" state)))))
                 (is (equal "side-0" (gethash "containerID" request)))
                 (is (= (+ now 7) (gethash "deadline" request)))))
             ;; A process can handle TERM and exit successfully; the recorded
             ;; probe kill still requires OnFailure replacement, with real exit0.
             (setf (gr8s::cri-container-info-state side) gr8s.cri.v1::+containerstate-container_exited+
                   (gr8s::cri-container-info-exit-code side) 0
                   (gr8s::cri-container-info-finished-at side) (* (- now 2208988800) 1000000000))
             (let ((after (gr8s::runtime-reconcile-containers runtime pod (runtime-observe runtime (pod-uid pod)))))
               (is (= 1 (gethash "restartCount" (lifecycle-side-status after))))
               (is (equal "containerd://main-0" (gethash "containerID" (find "main" (gethash "containerStatuses" (gr8s::runtime-pod-status after)) :test #'equal :key (lambda (s) (gethash "name" s))))))
               (is (= 0 (gethash "exitCode" (gethash "terminated" (gethash "lastState" (lifecycle-side-status after))))))
               (is (find '(:create "side" 1 "same-sandbox") (lifecycle-cri-fixture-calls fixture) :test #'equal))
               (is-false (gethash "probeRestart" (gethash "side" (gethash "containers" (gr8s::load-container-lifecycle-state runtime (pod-uid pod))))))))
        (gr8s::stop-container-probes runtime)))))

(test deletion-cancels-blocked-probe-without-publishing-a-late-success
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (entered (bt:make-semaphore)) (unwound nil)
           (manager (gr8s::make-container-probe-manager :clock (lambda () now)
                      :executor (lambda (&rest args)
                                  (declare (ignore args))
                                  (unwind-protect (progn (bt:signal-semaphore entered) (sleep 1000) (values t "late"))
                                    (setf unwound t))))))
      (setf (gr8s::containerd-runtime-probes runtime) manager
            (gethash "readinessProbe" (probe-test-side-container pod)) (checked-probe "{\"exec\":{\"command\":[\"blocked\"]}}"))
      (unwind-protect
           (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                                (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
             (gr8s::sync-container-probe-targets runtime pod (runtime-observe runtime (pod-uid pod)))
             (is (bt:wait-on-semaphore entered :timeout 2))
             (let ((target (probe-test-target manager pod)) (start (get-internal-real-time)))
               (gr8s::stop-container-probes runtime (pod-uid pod))
               (is (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 1))
               (is-true unwound)
               (is-false (probe-test-target manager pod))
               (is-false (gr8s::container-probe-worker-result (probe-test-worker target "readinessProbe")))
               (is-true (gr8s::container-probe-worker-finished-p (probe-test-worker target "readinessProbe")))))
        (gr8s::stop-container-probes runtime)))))

(test failed-probe-stop-reuses-absolute-deadline-after-runtime-reconstruction
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (manager (gr8s::make-container-probe-manager :clock (lambda () now)
                      :executor (lambda (&rest args) (declare (ignore args)) (values nil "measured failure"))))
           (calls nil) (original (symbol-function 'gr8s::cri-stop-container)))
      (setf (gr8s::containerd-runtime-probes runtime) manager
            (gethash "livenessProbe" (probe-test-side-container pod))
            (checked-probe "{\"exec\":{\"command\":[\"live\"]},\"failureThreshold\":1,\"terminationGracePeriodSeconds\":7}" "livenessProbe"))
      (unwind-protect
           (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                                (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
             (let ((observed (runtime-observe runtime (pod-uid pod))))
               (gr8s::sync-container-probe-targets runtime pod observed :start-workers nil)
               (let ((target (probe-test-target manager pod)))
                 (gr8s::step-container-probe manager runtime target (probe-test-worker target "livenessProbe")))
               (gr8s::checkpoint-container-probes runtime pod manager)
               (incf now 2.5d0)
               (setf runtime (gr8s::make-containerd-runtime :log-root directory)
                     manager (gr8s::make-container-probe-manager :clock (lambda () now))
                     (gr8s::containerd-runtime-probes runtime) manager
                     (symbol-function 'gr8s::cri-stop-container)
                     (lambda (socket id &key grace-period)
                       (declare (ignore socket)) (push (list id grace-period) calls)))
               (gr8s::ensure-container-probe-stops runtime pod observed manager (gr8s::load-container-lifecycle-state runtime (pod-uid pod)))
               (is-true (wait-until (lambda () calls)))
               (is (equal '(("side-0" 5)) calls))
               (is (= 4000000007 (gethash "deadline" (gethash "probeRestart" (gethash "side" (gethash "containers" (gr8s::load-container-lifecycle-state runtime (pod-uid pod))))))))
               (is (gethash "running" (gethash "state" (lifecycle-side-status (runtime-observe runtime (pod-uid pod))))))))
        (gr8s::stop-container-probes runtime)
        (setf (symbol-function 'gr8s::cri-stop-container) original)))))

(test never-policy-does-not-restart-a-successful-probe-kill-after-history-collection
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (gr8s::*container-lifecycle-clock* (lambda () now))
           (pod (lifecycle-pod store "Never")) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (manager (gr8s::make-container-probe-manager :clock (lambda () now)
                      :executor (lambda (&rest args) (declare (ignore args)) (values nil "failed startup"))))
           (side (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
      (setf (gr8s::containerd-runtime-probes runtime) manager
            (gethash "startupProbe" (probe-test-side-container pod))
            (checked-probe "{\"exec\":{\"command\":[\"startup\"]},\"failureThreshold\":1}" "startupProbe"))
      (unwind-protect
           (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now) side))
             (let ((observed (runtime-observe runtime (pod-uid pod))))
               (gr8s::sync-container-probe-targets runtime pod observed :start-workers nil)
               (gr8s::checkpoint-container-lifecycle-observation runtime (pod-uid pod) observed)
               (let ((target (probe-test-target manager pod)))
                 (gr8s::step-container-probe manager runtime target (probe-test-worker target "startupProbe")))
               (gr8s::checkpoint-container-probes runtime pod manager))
             (setf (lifecycle-cri-fixture-infos fixture) (remove side (lifecycle-cri-fixture-infos fixture)))
             (runtime-ensure runtime pod)
             (is (not (find :create (lifecycle-cri-fixture-calls fixture) :key #'first)))
             (is-false (gethash "ready" (lifecycle-side-status (runtime-observe runtime (pod-uid pod))))))
        (gr8s::stop-container-probes runtime)))))

(test node-probe-events-are-real-counted-replay-safe-and-bound-to-assigned-pod
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((input (com.inuoe.jzon:parse *valid-pod-json*))
           (server (gr8s::%make-node-grpc-server :store store))
           (now 4000000000) (gr8s::*event-clock* (lambda () now))
           (event (gr8s::core-object "id" "real-occurrence" "kind" "readinessProbe" "container" "web" "reason" "Unhealthy"
                                    "message" "Readiness probe failed: measured exit7" "count" 1
                                    "firstTimestamp" (gr8s::current-timestamp now) "lastTimestamp" (gr8s::current-timestamp now))))
      (setf (gethash "nodeName" (gethash "spec" input)) "probe-node")
      (let* ((pod (create-pod store (parse-pod input)))
             (status (gr8s::core-object "phase" "Running"))
             (message (gr8s::pod-observed-status-message pod status (vector event)))
             (envelope (gr8s:make-agent-envelope :status (make-instance 'gr8s.node.v1::node-status :pods (list message)))))
        (gr8s::handle-node-agent-envelope server "other-node" envelope)
        (is (null (gr8s::list-core-resources store "events" "default")))
        (gr8s::handle-node-agent-envelope server "probe-node" envelope)
        (let* ((events (gr8s::list-core-resources store "events" "default")) (first (first events))
               (revision (gr8s::pod-store-resource-revision store)))
          (is (= 1 (length events)))
          (is (= 1 (gethash "count" first)))
          (is (equal (pod-uid pod) (gethash "uid" (gethash "involvedObject" first))))
          (is (equal "probe-node" (gethash "host" (gethash "source" first))))
          (is-false (gethash "gr8sRuntimeEvents" (gethash (pod-uid pod) (gr8s::pod-store-pod-observed-statuses store))))
          (is-false (gethash "gr8sRuntimeEvents" status))
          (gr8s::handle-node-agent-envelope server "probe-node" envelope)
          (is (= revision (gr8s::pod-store-resource-revision store)))
          (setf (gethash "count" event) 2)
          (gr8s::handle-node-agent-envelope server "probe-node"
            (gr8s:make-agent-envelope :status (make-instance 'gr8s.node.v1::node-status :pods (list (gr8s::pod-observed-status-message pod status (vector event))))))
          (is (= 2 (gethash "count" (first (gr8s::list-core-resources store "events" "default")))))
          (setf (slot-value message 'gr8s.node.v1::uid) "reused-old-uid")
          (gr8s::handle-node-agent-envelope server "probe-node" envelope)
          (is (= 1 (length (gr8s::list-core-resources store "events" "default")))))))))

(test probe-operation-serious-timeout-does-not-kill-its-worker
  (with-temporary-store (store directory)
    (let* ((now 4000000000) (pod (lifecycle-pod store)) (runtime (gr8s::make-containerd-runtime :log-root directory))
           (calls 0) (entered (bt:make-semaphore))
           (manager (gr8s::make-container-probe-manager :clock (lambda () now)
                      :executor (lambda (&rest args)
                                  (declare (ignore args))
                                  (when (= 1 (incf calls)) (bt:signal-semaphore entered) (error 'sb-ext:timeout))
                                  (values t "actually recovered")))))
      (setf (gr8s::containerd-runtime-probes runtime) manager
            (gethash "readinessProbe" (probe-test-side-container pod)) (checked-probe "{\"exec\":{\"command\":[\"ready\"]},\"periodSeconds\":1}"))
      (unwind-protect
           (with-lifecycle-cri (fixture pod (list (lifecycle-info "main" 0 gr8s.cri.v1::+containerstate-container_running+ now)
                                                (lifecycle-info "side" 0 gr8s.cri.v1::+containerstate-container_running+ now)))
             (gr8s::sync-container-probe-targets runtime pod (runtime-observe runtime (pod-uid pod)))
             (is (bt:wait-on-semaphore entered :timeout 2))
             (let ((worker (probe-test-worker (probe-test-target manager pod) "readinessProbe")))
               (is-false (gr8s::container-probe-worker-result worker))
               (incf now)
               (is-true (wait-until (lambda () (gr8s::container-probe-worker-result worker))))
               (is (bt:thread-alive-p (gr8s::container-probe-worker-thread worker)))
               (is (= 2 calls))))
        (gr8s::stop-container-probes runtime)))))

(test probe-stop-serious-timeout-remains-a-retryable-recorded-job
  (let* ((runtime (gr8s::make-containerd-runtime)) (manager (gr8s::make-container-probe-manager))
         (job (gr8s::make-container-probe-stop-job :uid "actual-uid" :id "actual-id" :deadline 0))
         (original (symbol-function 'gr8s::cri-stop-container)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s::cri-stop-container) (lambda (&rest args) (declare (ignore args)) (error 'sb-ext:timeout)))
           (gr8s::run-container-probe-stop runtime manager job)
           (is-true (gr8s::container-probe-stop-job-finished-p job))
           (is (typep (gr8s::container-probe-stop-job-failure job) 'sb-ext:timeout)))
      (setf (symbol-function 'gr8s::cri-stop-container) original))))
