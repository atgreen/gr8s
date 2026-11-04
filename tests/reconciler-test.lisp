(in-package #:gr8s/tests)

(in-suite gr8s)

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
        (setf (gethash "image" (aref (gethash "containers" (gethash "spec" object)) 0)) "busybox:changed")
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
      (bt:with-lock-held ((gr8s::reconciler-lock reconciler))
        (setf thread
              (bt:make-thread
               (lambda ()
                 (gr8s::delete-reconciled-pod
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

(defstruct (pending-create-runtime (:include gr8s::fake-runtime)
                                   (:constructor make-pending-create-runtime ()))
  "Model an asynchronous backend whose accepted first creation is still Pending.")

(defmethod gr8s::runtime-ensure :around ((runtime pending-create-runtime) pod)
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
    (bt:with-lock-held ((gr8s::reconciler-lock reconciler))
      (setf thread
            (bt:make-thread
             (lambda ()
               (reconciler-logs reconciler "uid" "main")
               (setf finished t))))
      (sleep 0.02)
      (is (not finished)))
    (bt:join-thread thread)
    (is (eq t finished))))

(test fake-runtime-exec-records-the-complete-stream-request
  (let ((runtime (make-fake-runtime)))
    (gr8s::set-fake-runtime-exec-url
     runtime "http://127.0.0.1:1234/exec/token")
    (is (string= "http://127.0.0.1:1234/exec/token"
                 (gr8s::runtime-exec-url
                  runtime "pod-uid" "main" '("sh" "-i")
                  :stdin t :stdout t :stderr nil :tty t)))
    (is (equal '("pod-uid" "main" ("sh" "-i") t t nil t)
               (gr8s::fake-runtime-last-exec runtime)))))

(test metadata-only-pod-updates-adopt-observed-containers-without-restarting
  (with-temporary-store (store directory)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s::reconcile-pod reconciler "default" "hello")
      (let* ((observed (runtime-observe runtime (pod-uid pod)))
             (object (gr8s::copy-core-object (pod-to-object pod))))
        (setf (gethash "annotations" (gethash "metadata" object)) (gr8s::core-object "progress" "running"))
        (let ((updated (gr8s::update-pod store (parse-pod object) (pod-resource-version pod))))
          (gr8s::reconcile-pod reconciler "default" "hello")
          (is (= 1 (fake-runtime-ensure-count runtime)))
          (is (eq observed (runtime-observe runtime (pod-uid pod))))
          (is (equal (pod-resource-version updated) (gr8s::runtime-pod-resource-version observed)))
          ;; A fresh reconciler/store view can still adopt the runtime's durable
          ;; workload identity, instead of relying on a process-local RV cache.
          (gr8s::reconcile-pod (make-reconciler (open-store directory) runtime) "default" "hello")
          (is (= 1 (fake-runtime-ensure-count runtime)))
          (let ((changed (gr8s::copy-core-object (pod-to-object updated))))
            (setf (gethash "image" (aref (gethash "containers" (gethash "spec" changed)) 0)) "busybox:changed")
            (gr8s::update-pod store (parse-pod changed) (pod-resource-version updated))
            (gr8s::reconcile-pod reconciler "default" "hello")
            (is (= 2 (fake-runtime-ensure-count runtime)))))))))

(test runtime-fingerprints-ignore-object-order-but-preserve-array-order
  (let* ((pod (parse-pod *valid-pod-json*)) (object (gr8s::copy-core-object (pod-to-object pod)))
         (spec (gethash "spec" object)) (reordered (make-hash-table :test #'equal)))
    (dolist (key (reverse (loop for key being the hash-keys of spec collect key)))
      (setf (gethash key reordered) (gethash key spec)))
    (setf (gethash "spec" object) reordered)
    (is (equal (gr8s::pod-runtime-spec-fingerprint pod) (gr8s::pod-runtime-spec-fingerprint (parse-pod object))))
    (setf (gethash "command" (aref (gethash "containers" reordered) 0)) #("-c" "sh"))
    (is (not (equal (gr8s::pod-runtime-spec-fingerprint pod) (gr8s::pod-runtime-spec-fingerprint (parse-pod object)))))))

(test control-plane-publishes-pod-updates-until-the-agent-observes-the-new-version
  (with-temporary-store (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (let* ((server (gr8s::%make-node-grpc-server :store store))
           (runtime (gr8s::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s::reconcile-pod reconciler "default" "hello")
      (gr8s::update-pod-observed-status store pod (gr8s::core-object "phase" "Running"))
      (let* ((old-version (pod-resource-version pod))
             (old-revision (slot-value (gr8s::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision))
             (object (gr8s::copy-core-object (pod-to-object pod))))
        (setf (gethash "annotations" (gethash "metadata" object)) (gr8s::core-object "progress" "new"))
        (let ((updated (gr8s::update-pod store (parse-pod object) old-version)))
          (is (equal old-version (gr8s::runtime-pod-resource-version (runtime-observe runtime (pod-uid updated)))))
          (gr8s::reconcile-pod reconciler "default" "hello")
          (let* ((snapshot (gr8s::current-node-snapshot server "worker-a"))
                 (assignment (first (slot-value snapshot 'gr8s.node.v1::pods))))
            (is (> (slot-value snapshot 'gr8s.node.v1::revision) old-revision))
            (is (equal (pod-resource-version updated) (slot-value assignment 'gr8s.node.v1::resource-version)))))))))

(test pending-agent-work-does-not-flood-identical-desired-state-snapshots
  (with-temporary-store (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (let* ((server (gr8s::%make-node-grpc-server :store store))
           (runtime (gr8s::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime)))
      (create-pod store (parse-pod *valid-pod-json*))
      (gr8s::reconcile-pod reconciler "default" "hello")
      (let ((revision (slot-value (gr8s::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))
        (dotimes (iteration 20)
          (gr8s::reconcile-pod reconciler "default" "hello"))
        (is (= revision (slot-value (gr8s::current-node-snapshot server "worker-a") 'gr8s.node.v1::revision)))))))
