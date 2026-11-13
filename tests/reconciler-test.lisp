(in-package #:gr8s/tests)

(in-suite gr8s)

(test runtime-protocol-has-an-explicit-package-boundary
  (let ((package (find-package "GR8S.RUNTIME")))
    (is (not (null package)))
    (dolist (name '("RUNTIME-ENSURE" "RUNTIME-OBSERVE" "RUNTIME-DELETE"
                    "RUNTIME-POD" "RUNTIME-ERROR" "MAKE-FAKE-RUNTIME"))
      (multiple-value-bind (symbol status) (and package (find-symbol name package))
        (is (not (null symbol)) "~A is present in GR8S.RUNTIME" name)
        (is (eq :external status) "~A is exported from GR8S.RUNTIME" name)
        (is (eq symbol (find-symbol name "GR8S"))
            "GR8S preserves ~A's runtime protocol symbol identity" name)))))

(test observed-runtime-status-publishes-every-pod-address
  (let* ((status (gr8s.kubelet::observed-status
                  (gr8s.runtime::make-runtime-pod
                   :pod-ip "10.88.1.2" :pod-ips #("10.88.1.2" "fd88::2"))))
         (addresses (gethash "podIPs" status)))
    (is (string= "10.88.1.2" (gethash "podIP" status)))
    (is (equalp #("10.88.1.2" "fd88::2")
                (map 'vector (lambda (item) (gethash "ip" item)) addresses)))))

(test control-plane-runtime-retains-every-agent-observed-pod-address
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (status (gr8s.resources::core-object
                    "phase" "Running" "podIP" "10.88.1.2"
                    "podIPs" (vector (gr8s.resources::core-object "ip" "10.88.1.2")
                                     (gr8s.resources::core-object "ip" "fd88::2")))))
      (gr8s.kubelet::save-pod-observation store pod status)
      (let ((observed (gr8s.controllers::control-plane-observation
                       (gr8s.controllers::make-control-plane-runtime store nil) pod)))
        (is (equalp #("10.88.1.2" "fd88::2")
                    (gr8s.runtime::runtime-pod-pod-ips observed)))))))

(test reconciliation-is-idempotent-and-replaces-changed-pods
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (is (string= "Running"
                   (gethash "phase" (reconcile-pod reconciler "default" "hello"))))
      (is (= 1 (fake-runtime-ensure-count runtime)))
      (reconcile-pod reconciler "default" "hello")
      (is (= 1 (fake-runtime-ensure-count runtime)))
      (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
        (setf (gethash "command" (aref (gethash "containers" (gethash "spec" object)) 0)) #("changed"))
        (update-pod store (parse-pod object) "1"))
      (reconcile-pod reconciler "default" "hello")
      (is (= 2 (fake-runtime-ensure-count runtime)))
      (is (string= (pod-resource-version (get-pod store "default" "hello"))
                   (runtime-pod-resource-version
                    (runtime-observe runtime (pod-uid pod))))))))

(test deletion-converges-before-removing-desired-state
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (reconcile-pod reconciler "default" "hello")
      (let ((foreign (create-pod store
                                 (parse-pod
                                  "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"foreign\"},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"busybox\"}]}}"))))
        (reconcile-pod reconciler "default" "foreign")
        (mark-pod-deleting store "default" "hello")
        (reconcile-pod reconciler "default" "hello")
        (is (null (runtime-observe runtime (pod-uid pod))))
        (is (runtime-observe runtime (pod-uid foreign)))
        (signals kubernetes-error (get-pod store "default" "hello"))))))

(test deletion-request-is-serialized-with-background-reconciliation
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime))
           (finished nil)
           (thread nil))
      (reconcile-pod reconciler "default" "hello")
      (bt:with-lock-held ((gr8s.kubelet::reconciler-lock reconciler))
        (setf thread
              (bt:make-thread
               (lambda ()
                 (gr8s.kubelet::delete-reconciled-pod
                  reconciler "default" "hello")
                 (setf finished t))))
        (sleep 0.02)
        (is (not finished)))
      (bt:join-thread thread)
      (is (eq t finished))
      (signals kubernetes-error
        (get-pod store "default" "hello")))))

(test retryable-runtime-failures-become-pending-status
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (set-fake-runtime-failure runtime "temporary runtime failure")
      (let ((status (reconcile-pod reconciler "default" "hello")))
        (is (string= "Pending" (gethash "phase" status)))
        (is (string= "RuntimeError" (gethash "reason" status))))
      (is (string= "Running"
                   (gethash "phase"
                            (reconcile-pod reconciler "default" "hello")))))))

(test reconcile-all-visits-every-desired-pod
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (is (= 1 (length (reconcile-all reconciler))))
      (is (= 1 (fake-runtime-ensure-count runtime))))))

(test always-restart-policy-reconverges-an-exited-runtime-pod
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (reconcile-pod reconciler "default" "hello")
      (setf (runtime-pod-phase (runtime-observe runtime (pod-uid pod)))
            "Succeeded")
      (reconcile-pod reconciler "default" "hello")
      (is (= 2 (fake-runtime-ensure-count runtime))))))

(test restart-policy-distinguishes-success-failure-and-running-containers
  (dolist (scenario '(("Always" "Failed" 2) ("Always" "Succeeded" 2)
                      ("Always" "Running" 1) ("OnFailure" "Failed" 2)
                      ("OnFailure" "Succeeded" 1) ("Never" "Failed" 1)
                      ("Never" "Succeeded" 1)))
    (destructuring-bind (policy phase count) scenario
      (with-temporary-store (store path)
        (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
               (runtime (make-fake-runtime))
               (reconciler (make-reconciler store runtime)))
          (setf (gethash "restartPolicy" (gethash "spec" object)) policy)
          (let ((pod (create-pod store (parse-pod object))))
            (reconcile-pod reconciler "default" "hello")
            (setf (runtime-pod-phase (runtime-observe runtime (pod-uid pod))) phase)
            (reconcile-pod reconciler "default" "hello")
            (is (= count (fake-runtime-ensure-count runtime)) "~A after ~A" policy phase)))))))

(defstruct (pending-create-runtime (:include gr8s.runtime::fake-runtime)
                                   (:constructor make-pending-create-runtime ()))
  "Model an asynchronous backend whose accepted first creation is still Pending.")

(defmethod gr8s.runtime::runtime-ensure :around ((runtime pending-create-runtime) pod)
  "Return Pending after recording the real fake-backend creation count."
  (let ((observed (call-next-method)))
    (setf (runtime-pod-phase observed) "Pending")
    observed))

(test pending-initial-creation-is-not-immediately-created-again
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-pending-create-runtime))
           (status (reconcile-pod (make-reconciler store runtime) "default" "hello")))
      (is (equal "Pending" (gethash "phase" status)))
      (is (= 1 (fake-runtime-ensure-count runtime))))))

(test log-reads-are-serialized-with-reconciliation
  (let* ((runtime (make-fake-runtime))
         (reconciler (make-reconciler nil runtime))
         (finished nil)
         (thread nil))
    (bt:with-lock-held ((gr8s.kubelet::reconciler-lock reconciler))
      (setf thread
            (bt:make-thread
             (lambda ()
               (reconciler-logs reconciler "uid" "main")
               (setf finished t))))
      (sleep 0.02)
      (is (not finished)))
    (bt:join-thread thread)
    (is (eq t finished))))

(test node-log-reads-do-not-wait-for-reconciliation
  ;; A node operation waits seconds for its agent; every Pod read and write would wait with it.
  (with-temporary-store (store path)
    (values path)
    (let* ((server (gr8s.apiserver::start-node-grpc-server store :host "127.0.0.1" :port 0))
           (reconciler (make-reconciler store (gr8s.controllers::make-control-plane-runtime store server)))
           (finished nil)
           (thread nil))
      (unwind-protect
           (bt:with-lock-held ((gr8s.kubelet::reconciler-lock reconciler))
             (setf thread
                   (bt:make-thread
                    (lambda ()
                      (handler-case (reconciler-logs reconciler "absent-uid" "main")
                        (runtime-error () nil))
                      (setf finished t))))
             (is-true (wait-until (lambda () finished) :timeout 5)))
        (when thread (bt:join-thread thread))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test fake-runtime-exec-records-the-complete-stream-request
  (let ((runtime (make-fake-runtime)))
    (gr8s.runtime::set-fake-runtime-exec-url
     runtime "http://127.0.0.1:1234/exec/token")
    (is (string= "http://127.0.0.1:1234/exec/token"
                 (gr8s.runtime::runtime-exec-url
                  runtime "pod-uid" "main" '("sh" "-i")
                  :stdin t :stdout t :stderr nil :tty t)))
    (is (equal '("pod-uid" "main" ("sh" "-i") t t nil t)
               (gr8s.runtime::fake-runtime-last-exec runtime)))))

(test metadata-only-pod-updates-adopt-observed-containers-without-restarting
  (with-temporary-store (store directory)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s.kubelet::reconcile-pod reconciler "default" "hello")
      (let* ((observed (runtime-observe runtime (pod-uid pod)))
             (object (gr8s.resources::copy-core-object (pod-to-object pod))))
        (setf (gethash "annotations" (gethash "metadata" object)) (gr8s.resources::core-object "progress" "running"))
        (let ((updated (gr8s.store::update-pod store (parse-pod object) (pod-resource-version pod))))
          (gr8s.kubelet::reconcile-pod reconciler "default" "hello")
          (is (= 1 (fake-runtime-ensure-count runtime)))
          (is (eq observed (runtime-observe runtime (pod-uid pod))))
          (is (equal (pod-resource-version updated) (gr8s.runtime::runtime-pod-resource-version observed)))
          ;; A fresh reconciler/store view can still adopt the runtime's durable
          ;; workload identity, instead of relying on a process-local RV cache.
          (gr8s.kubelet::reconcile-pod (make-reconciler (open-store directory) runtime) "default" "hello")
          (is (= 1 (fake-runtime-ensure-count runtime)))
          (let ((changed (gr8s.resources::copy-core-object (pod-to-object updated))))
            (setf (gethash "command" (aref (gethash "containers" (gethash "spec" changed)) 0)) #("changed"))
            (gr8s.store::update-pod store (parse-pod changed) (pod-resource-version updated))
            (gr8s.kubelet::reconcile-pod reconciler "default" "hello")
            (is (= 2 (fake-runtime-ensure-count runtime)))))))))

(test runtime-fingerprints-ignore-object-order-but-preserve-array-order
  (let* ((pod (parse-pod *valid-pod-json*)) (object (gr8s.resources::copy-core-object (pod-to-object pod)))
         (spec (gethash "spec" object)) (reordered (make-hash-table :test #'equal)))
    (dolist (key (reverse (loop for key being the hash-keys of spec collect key)))
      (setf (gethash key reordered) (gethash key spec)))
    (setf (gethash "spec" object) reordered)
    (is (equal (gr8s.runtime::pod-runtime-spec-fingerprint pod) (gr8s.runtime::pod-runtime-spec-fingerprint (parse-pod object))))
    (setf (gethash "command" (aref (gethash "containers" reordered) 0)) #("-c" "sh"))
    (is (not (equal (gr8s.runtime::pod-runtime-spec-fingerprint pod) (gr8s.runtime::pod-runtime-spec-fingerprint (parse-pod object)))))))

(test control-plane-publishes-pod-updates-until-the-agent-observes-the-new-version
  (with-temporary-store (store directory)
    (values directory)
    (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (runtime (gr8s.controllers::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s.kubelet::reconcile-pod reconciler "default" "hello")
      (gr8s.controllers::update-pod-observed-status store pod (gr8s.resources::core-object "phase" "Running"))
      (let* ((old-version (pod-resource-version pod))
             (old-revision (slot-value (gr8s.apiserver::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision))
             (object (gr8s.resources::copy-core-object (pod-to-object pod))))
        (setf (gethash "annotations" (gethash "metadata" object)) (gr8s.resources::core-object "progress" "new"))
        (let ((updated (gr8s.store::update-pod store (parse-pod object) old-version)))
          (is (equal old-version (gr8s.runtime::runtime-pod-resource-version (runtime-observe runtime (pod-uid updated)))))
          (gr8s.kubelet::reconcile-pod reconciler "default" "hello")
          (let* ((snapshot (gr8s.apiserver::current-node-snapshot server "worker-a"))
                 (assignment (first (slot-value snapshot 'gr8s.node.v1::pods))))
            (is (> (slot-value snapshot 'gr8s.node.v1::revision) old-revision))
            (is (equal (pod-resource-version updated) (slot-value assignment 'gr8s.node.v1::resource-version)))))))))

;; Reads of a Pod the agent has not reported go through runtime-ensure, so they run once
;; per Pod per request. A full snapshot there made listing N Pending Pods cost N^2 JSON.
(test reads-of-an-assigned-pod-build-no-snapshot-but-the-worker-tick-still-delivers-changes
  (with-temporary-store (store directory)
    (values directory)
    (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time))
    (gr8s.resources::create-core-resource store "configmaps"
      (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "settings")
                         "data" (gr8s.resources::core-object "key" "one"))
      "default")
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (runtime (gr8s.controllers::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime))
           (object (com.inuoe.jzon:parse *valid-pod-json*))
           (builds 0))
      (setf (gethash "volumes" (gethash "spec" object))
            (vector (gr8s.resources::core-object "name" "settings"
                                       "configMap" (gr8s.resources::core-object "name" "settings"))))
      (create-pod store (parse-pod (com.inuoe.jzon:stringify object)))
      (sb-int:encapsulate 'gr8s.controllers::node-desired-state-snapshot 'count-builds
                          (lambda (function &rest arguments)
                            (incf builds)
                            (apply function arguments)))
      (unwind-protect
           (progn
             (gr8s.kubelet::reconcile-pod reconciler "default" "hello")
             (is (= 1 builds) "the first read schedules the Pod and publishes it")
             (let ((revision (slot-value (gr8s.apiserver::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))
               (dotimes (iteration 20)
                 (gr8s.kubelet::reconcile-pod reconciler "default" "hello"))
               (is (= 1 builds) "later reads find the Pod's revision already published")
               (gr8s.resources::update-core-resource store "configmaps" "default" "settings"
                 (lambda (settings)
                   (setf (gethash "data" settings) (gr8s.resources::core-object "key" "two"))
                   settings))
               (gr8s.controllers::publish-service-discovery-snapshots runtime)
               (let* ((snapshot (gr8s.apiserver::current-node-snapshot server "worker-a"))
                      (assignment (first (slot-value snapshot 'gr8s.node.v1::pods))))
                 (is (> (slot-value snapshot 'gr8s.node.v1::revision) revision))
                 (is (some (lambda (octets) (search "two" (trivial-utf-8:utf-8-bytes-to-string octets)))
                           (slot-value assignment 'gr8s.node.v1::resource-objects-json))))))
        (sb-int:unencapsulate 'gr8s.controllers::node-desired-state-snapshot 'count-builds)))))

(test pending-agent-work-does-not-flood-identical-desired-state-snapshots
  (with-temporary-store (store directory)
    (values directory)
    (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (runtime (gr8s.controllers::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime)))
      (create-pod store (parse-pod *valid-pod-json*))
      (gr8s.kubelet::reconcile-pod reconciler "default" "hello")
      (let ((revision (slot-value (gr8s.apiserver::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))
        (dotimes (iteration 20)
          (gr8s.kubelet::reconcile-pod reconciler "default" "hello"))
        (is (= revision (slot-value (gr8s.apiserver::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))))))

;; podster-uqb.114: cancelling a creation interrupted its thread with an ERROR. If the
;; thread was already signalling, with the handler that expects the cancellation
;; unbound for a handler test or a handler function, that ERROR found no handler.
(defstruct (blocking-create-runtime (:include gr8s.runtime::fake-runtime)
                                    (:constructor make-blocking-create-runtime (create)))
  "Run CREATE in place of the fake backend's creation."
  create)

(defmethod gr8s.runtime::runtime-ensure ((runtime blocking-create-runtime) pod)
  (declare (ignore pod))
  (funcall (blocking-create-runtime-create runtime)))

(defun superseded-reconcile-pod (reconciler)
  "Reconcile the test Pod, answering :SUPERSEDED when cancellation reaches the caller."
  (handler-case (gr8s.kubelet::reconcile-pod reconciler "default" "hello")
    (gr8s.kubelet::pod-reconciliation-superseded () :superseded)))

(test cancelling-creation-during-a-signal-still-supersedes-it
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((signalling (bt:make-semaphore))
           (cleaned-up nil)
           (reconciler (make-reconciler store (make-blocking-create-runtime
                                               (lambda ()
                                                 (unwind-protect (error "read failed")
                                                   (setf cleaned-up t))))))
           (thread (bt:make-thread
                    (lambda ()
                      ;; The read error's handler runs outside the caller's handler for
                      ;; the cancellation, which is unbound while it runs.
                      (handler-bind ((error (lambda (condition)
                                              (declare (ignore condition))
                                              (bt:signal-semaphore signalling)
                                              (sleep 3600))))
                        (superseded-reconcile-pod reconciler)))
                    :name "gr8s cancelled creation test")))
      (is-true (bt:wait-on-semaphore signalling :timeout 10))
      (gr8s.kubelet::prioritize-reconciler-deletions reconciler '("other-uid"))
      (is (eq :superseded (bt:join-thread thread)))
      (is-true cleaned-up)
      (is (null (gr8s.kubelet::reconciler-active-convergence reconciler))))))

(test cancelling-creation-passes-handlers-that-recover-from-errors
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((blocked (bt:make-semaphore))
           (swallowed nil)
           (reconciler (make-reconciler store (make-blocking-create-runtime
                                               (lambda ()
                                                 (handler-case (progn (bt:signal-semaphore blocked) (sleep 3600))
                                                   (serious-condition () (setf swallowed t)))))))
           (thread (bt:make-thread (lambda () (superseded-reconcile-pod reconciler)))))
      (is-true (bt:wait-on-semaphore blocked :timeout 10))
      (gr8s.kubelet::prioritize-reconciler-deletions reconciler '("other-uid"))
      (is (eq :superseded (bt:join-thread thread)))
      (is-false swallowed))))

(test a-late-creation-cancellation-is-ignored
  (let* ((left (bt:make-semaphore))
         (received (bt:make-semaphore))
         (reconciler (make-reconciler nil (make-fake-runtime)))
         (thread nil))
    (setf thread (bt:make-thread
                  (lambda ()
                    ;; The operation's catch has gone, as after its creation finished.
                    (bt:signal-semaphore left)
                    (bt:wait-on-semaphore received)
                    :finished)))
    (setf (gr8s.kubelet::reconciler-active-convergence reconciler)
          (gr8s.kubelet::make-running-pod-convergence :thread thread :uid "finished-uid"))
    (bt:wait-on-semaphore left)
    (gr8s.kubelet::cancel-running-pod-convergence reconciler)
    (bt:signal-semaphore received)
    (is (eq :finished (bt:join-thread thread)))))

;; podster-uqb.123: a deletion that never finishes stops every later creation on the
;; node without any other report.
(test creation-held-by-an-unfinished-deletion-is-reported
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (deleting (let ((input (com.inuoe.jzon:parse *valid-pod-json*)))
                       (setf (gethash "name" (gethash "metadata" input)) "deleting")
                       (create-pod store (parse-pod input))))
           (reconciler (make-reconciler store (make-fake-runtime)))
           (dumps 0)
           (output (make-string-output-stream)))
      (declare (ignore pod))
      (gr8s.kubelet::prioritize-reconciler-deletions reconciler (list (pod-uid deleting)))
      (let ((gr8s.kubelet::*held-creation-report-seconds* 0)
            (gr8s.kubelet::*held-creation-dump* (lambda () (incf dumps)))
            (*error-output* output))
        (is (eq :superseded (superseded-reconcile-pod reconciler)))
        (is (eq :superseded (superseded-reconcile-pod reconciler))))
      (let ((text (get-output-stream-string output)))
        (is (search (format nil "unfinished deletions of ~A" (pod-uid deleting)) text))
        (is (= 2 (count #\Newline text))))
      (is (= 1 dumps))
      (gr8s.kubelet::finish-reconciler-urgent-deletion reconciler (pod-uid deleting))
      (is (null (gr8s.kubelet::reconciler-urgent-since reconciler)))
      (is (equal "Running" (gethash "phase" (gr8s.kubelet::reconcile-pod reconciler "default" "hello")))))))

;; podster-uqb.123: cancelling StartContainer halfway left a running task that CRI
;; reported as exited, so the Pod's deletion, and every creation after it, never ended.
(test cancelling-creation-lets-a-deferred-step-finish-first
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((entered (bt:make-semaphore))
           (release (bt:make-semaphore))
           (finished nil)
           (after nil)
           (reconciler (make-reconciler store (make-blocking-create-runtime
                                               (lambda ()
                                                 (gr8s.runtime::with-running-pod-cancellation-deferred
                                                   (bt:signal-semaphore entered)
                                                   (bt:wait-on-semaphore release)
                                                   (setf finished t))
                                                 (setf after t)))))
           (thread (bt:make-thread (lambda () (superseded-reconcile-pod reconciler)))))
      (is-true (bt:wait-on-semaphore entered :timeout 10))
      (gr8s.kubelet::prioritize-reconciler-deletions reconciler '("other-uid"))
      (sleep 0.2)
      (is (bt:thread-alive-p thread))
      (bt:signal-semaphore release)
      (is (eq :superseded (bt:join-thread thread)))
      (is-true finished)
      (is-false after))))

(test a-deferred-step-outside-creation-runs-normally
  (is (eq :done (gr8s.runtime::with-running-pod-cancellation-deferred :done))))

(defstruct (outage-fake-runtime (:include gr8s.runtime::fake-runtime)
                                (:constructor make-outage-fake-runtime ()))
  down-message)

(defmethod gr8s.runtime::runtime-unavailable-message ((runtime outage-fake-runtime))
  (outage-fake-runtime-down-message runtime))

(test runtime-outage-pauses-pod-synchronization-and-keeps-observations
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-outage-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (let ((status (reconcile-pod reconciler "default" "hello")))
        (is (string= "Running" (gethash "phase" status)))
        (gr8s.kubelet::save-pod-observation store pod status))
      (is (= 1 (fake-runtime-ensure-count runtime)))
      (setf (outage-fake-runtime-down-message runtime) "container runtime is down: test")
      ;; A changed Pod is not started against a dead runtime, and its last
      ;; observation stands instead of a fabricated Pending/RuntimeError.
      (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
        (setf (gethash "command" (aref (gethash "containers" (gethash "spec" object)) 0)) #("changed"))
        (update-pod store (parse-pod object) "1"))
      (let ((status (reconcile-pod reconciler "default" "hello")))
        (is (string= "Running" (gethash "phase" status)))
        (is (not (equal "RuntimeError" (gethash "reason" status)))))
      (is (null (reconcile-all reconciler)))
      (is (= 1 (fake-runtime-ensure-count runtime)))
      ;; It converges once the runtime is back.
      (setf (outage-fake-runtime-down-message runtime) nil)
      (is (string= "Running" (gethash "phase" (reconcile-pod reconciler "default" "hello"))))
      (is (= 2 (fake-runtime-ensure-count runtime))))))

(test runtime-outage-reports-unobserved-pods-pending-on-the-runtime
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-outage-fake-runtime))
           (reconciler (make-reconciler store runtime)))
      (setf (outage-fake-runtime-down-message runtime) "container runtime is down: test")
      (let ((status (reconcile-pod reconciler "default" "hello")))
        (is (string= "Pending" (gethash "phase" status)))
        (is (string= "ContainerRuntimeUnavailable" (gethash "reason" status))))
      (is (= 0 (fake-runtime-ensure-count runtime))))))

(test memory-eviction-selects-least-critical-pod-first
  (flet ((make-pod (name qos-json priority)
           (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"~A\"},\"spec\":{\"priority\":~D,\"containers\":[{\"name\":\"c\",\"image\":\"busybox\",\"resources\":~A}]}}"
                              name priority qos-json))))
    (let ((best-hi (make-pod "be-hi" "{}" 100))
          (best-lo (make-pod "be-lo" "{}" 0))
          (burst (make-pod "burst" "{\"requests\":{\"memory\":\"50Mi\"}}" 0))
          (guaranteed (make-pod "guar" "{\"requests\":{\"cpu\":\"1\",\"memory\":\"64Mi\"},\"limits\":{\"cpu\":\"1\",\"memory\":\"64Mi\"}}" 0)))
      ;; BestEffort is evicted before Burstable; within a class the lower priority first.
      (is (equal "be-lo" (pod-name (gr8s.kubelet::select-memory-eviction-pod
                                    (list burst best-hi best-lo guaranteed)))))
      (is (equal "burst" (pod-name (gr8s.kubelet::select-memory-eviction-pod (list burst guaranteed)))))
      ;; Only Guaranteed Pods remain: nothing is evicted for memory pressure alone.
      (is (null (gr8s.kubelet::select-memory-eviction-pod (list guaranteed)))))))

(test memory-soft-eviction-waits-for-the-grace-period
  "The hard threshold evicts at once; the soft threshold evicts only after memory
has stayed below it for the grace period, and a recovery resets the timer."
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (clock 0)
           (gr8s.kubelet::*node-pressure-clock-fn* (lambda () clock))
           (soft gr8s.kubelet::+memory-soft-eviction-threshold-bytes+)
           (hard gr8s.kubelet::+memory-eviction-threshold-bytes+)
           (grace-ticks (* gr8s.kubelet::+memory-soft-eviction-grace-seconds+
                           internal-time-units-per-second)))
      ;; Comfortably above the soft threshold: no eviction, timer stays clear.
      (is (null (gr8s.kubelet::node-memory-eviction-threshold reconciler (* 2 soft))))
      (is (null (gr8s.kubelet::reconciler-memory-soft-pressure-since reconciler)))
      ;; Below soft (above hard): the first pass starts the grace timer, no eviction.
      (is (null (gr8s.kubelet::node-memory-eviction-threshold reconciler (1- soft))))
      (is (gr8s.kubelet::reconciler-memory-soft-pressure-since reconciler))
      ;; Still within the grace window: still no eviction.
      (setf clock (1- grace-ticks))
      (is (null (gr8s.kubelet::node-memory-eviction-threshold reconciler (1- soft))))
      ;; Grace elapsed while still crossed: the soft threshold now evicts.
      (setf clock grace-ticks)
      (is (eql soft (gr8s.kubelet::node-memory-eviction-threshold reconciler (1- soft))))
      ;; Recovery above the soft threshold clears the timer.
      (is (null (gr8s.kubelet::node-memory-eviction-threshold reconciler (* 2 soft))))
      (is (null (gr8s.kubelet::reconciler-memory-soft-pressure-since reconciler)))
      ;; Below the hard threshold evicts immediately, regardless of grace.
      (is (eql hard (gr8s.kubelet::node-memory-eviction-threshold reconciler (1- hard)))))))
