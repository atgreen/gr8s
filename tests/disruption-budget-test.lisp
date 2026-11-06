;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify PodDisruptionBudget admission and status subresource, the disruption
;;;; controller's arithmetic over observed Pods, and the eviction subresource's
;;;; decision order over real HTTP, including typed protobuf requests.

(in-package #:gr8s/tests)
(def-suite disruption-budgets :in gr8s)
(in-suite disruption-budgets)

(defun budget-fixture (name &key min max (selector (gr8s::core-object "matchLabels" (gr8s::core-object "foo" "bar"))) policy)
  "Build a PodDisruptionBudget with the given limits."
  (let ((spec (gr8s::core-object)))
    (when min (setf (gethash "minAvailable" spec) min))
    (when max (setf (gethash "maxUnavailable" spec) max))
    (when selector (setf (gethash "selector" spec) selector))
    (when policy (setf (gethash "unhealthyPodEvictionPolicy" spec) policy))
    (gr8s::core-object "apiVersion" "policy/v1" "kind" "PodDisruptionBudget"
                       "metadata" (gr8s::core-object "name" name) "spec" spec)))

(defun budget-test-pod (store name &key (labels (gr8s::core-object "foo" "bar")) owner (restart "Always"))
  "Create a Pod in the test namespace with LABELS, an optional controller OWNER and a RESTART policy."
  (let ((metadata (gr8s::core-object "name" name "namespace" "alpha" "labels" labels)))
    (when owner
      (setf (gethash "ownerReferences" metadata) (vector (gr8s::workload-owner-reference owner))))
    (create-pod store (parse-pod (gr8s::core-object
                                  "apiVersion" "v1" "kind" "Pod" "metadata" metadata
                                  "spec" (gr8s::core-object "nodeName" "gr8s-local" "terminationGracePeriodSeconds" 0
                                                            "restartPolicy" restart
                                                            "containers" (vector (gr8s::core-object "name" "main" "image" "busybox:1.36.1"))))))))

(defun budget-status (store name)
  "Read the budget's durable status in the test namespace."
  (gethash "status" (gr8s::get-core-resource store "poddisruptionbudgets" "alpha" name)))

(defmacro with-budget-cluster ((store runtime reconciler) &body body)
  "Run BODY with a store, a fake runtime and its reconciler."
  `(with-temporary-store (,store path)
     (declare (ignorable path))
     (let* ((,runtime (make-fake-runtime)) (,reconciler (make-reconciler ,store ,runtime)))
       ,@body)))

(defmacro with-budget-api ((store runtime reconciler) &body body)
  "Run BODY with a fake cluster served over HTTP on a kernel-assigned port."
  `(with-budget-cluster (,store ,runtime ,reconciler)
     (let* ((server (start-server :address "127.0.0.1" :port 0 :store ,store :runtime ,runtime :reconciler ,reconciler))
            (*core-api-port* (hunchentoot:acceptor-port server)))
       (unwind-protect (progn ,@body) (stop-server server)))))

(defun settle-budgets (reconciler runtime store)
  "Make every Pod observably ready and run the controllers."
  (reconcile-all reconciler)
  (mark-workload-pods-ready store runtime)
  (reconcile-all reconciler)
  (gr8s::reconcile-workloads reconciler))

(defun eviction-body (name &optional options)
  "Build an Eviction for Pod NAME."
  (let ((object (gr8s::core-object "apiVersion" "policy/v1" "kind" "Eviction" "metadata" (gr8s::core-object "name" name "namespace" "alpha"))))
    (when options (setf (gethash "deleteOptions" object) options))
    object))

(test budget-admission-validates-limits-and-keeps-generation-honest
  (with-temporary-store (store path)
    (values path)
    (dolist (bad (list (budget-fixture "bad" :min 1 :max 1)
                       (budget-fixture "bad" :min "101%")
                       (budget-fixture "bad" :max -1)
                       (budget-fixture "bad" :min "many")
                       (budget-fixture "bad" :min 1 :policy "Sometimes")))
      (signals gr8s::kubernetes-error (gr8s::create-core-resource store "poddisruptionbudgets" bad "alpha")))
    (let* ((input (budget-fixture "foo" :min "1%"))
           (created (progn (setf (gethash "status" input) (gr8s::core-object "disruptionsAllowed" 9))
                           (gr8s::create-core-resource store "poddisruptionbudgets" input "alpha"))))
      (is (= 1 (gethash "generation" (gethash "metadata" created))))
      (is (zerop (gethash "disruptionsAllowed" (gethash "status" created))))
      (flet ((update (change)
               (gr8s::update-core-resource store "poddisruptionbudgets" "alpha" "foo"
                 (lambda (object) (funcall change object) object))))
        (let ((same (update (lambda (object) (setf (gethash "labels" (gethash "metadata" object)) (gr8s::core-object "a" "b"))))))
          (is (= 1 (gethash "generation" (gethash "metadata" same)))))
        (let ((changed (update (lambda (object) (setf (gethash "minAvailable" (gethash "spec" object)) "2%")))))
          (is (= 2 (gethash "generation" (gethash "metadata" changed))))
          (is (equal "2%" (gethash "minAvailable" (gethash "spec" changed)))))))))

(test budget-api-serves-crud-status-discovery-and-protobuf
  (with-core-api (store path)
    (values path)
    (let* ((collection "/apis/policy/v1/namespaces/alpha/poddisruptionbudgets")
           (item (concatenate 'string collection "/foo")))
      (is (find "policy/v1" (gethash "versions" (check-core-status 200 "/apis/policy"))
                :test #'equal :key (lambda (version) (gethash "groupVersion" version))))
      (let ((names (map 'list (lambda (resource) (gethash "name" resource))
                        (gethash "resources" (check-core-status 200 "/apis/policy/v1")))))
        (is (member "poddisruptionbudgets" names :test #'equal))
        (is (member "poddisruptionbudgets/status" names :test #'equal)))
      (is (find "pods/eviction" (gethash "resources" (check-core-status 200 "/api/v1"))
                :test #'equal :key (lambda (resource) (gethash "name" resource))))
      (check-core-status 200 "/openapi/v3/apis/policy/v1")
      ;; Typed create: a percentage is a string IntOrString, which is type 1.
      (let* ((labels (core-test-protobuf '((1 "foo") (2 "bar"))))
             (selector (core-test-protobuf (list (list 1 labels))))
             (limit (core-test-protobuf '((1 1) (3 "1%"))))
             (spec (core-test-protobuf (list (list 1 limit) (list 2 selector))))
             (input (core-test-protobuf-envelope "PodDisruptionBudget"
                      (list (list 1 (core-test-protobuf '((1 "foo")))) (list 2 spec)) "policy/v1"))
             (created (check-core-status 201 collection :method :post
                                         :content-type "application/vnd.kubernetes.protobuf" :octets input)))
        (is (equal "1%" (gethash "minAvailable" (gethash "spec" created)))))
      (let ((patched (check-core-status 200 item :method :patch :content-type "application/merge-patch+json"
                                        :object (gr8s::core-object "spec" (gr8s::core-object "minAvailable" "3%")))))
        (is (equal "3%" (gethash "minAvailable" (gethash "spec" patched)))))
      ;; Status writes are visible through status and ordinary reads and never touch the spec.
      (let* ((status-url (concatenate 'string item "/status"))
             (current (check-core-status 200 status-url))
             (generation (gethash "generation" (gethash "metadata" current))))
        (setf (gethash "disruptedPods" (gethash "status" current)) (gr8s::core-object "pod-0" "2026-11-04T12:00:00Z")
              (gethash "minAvailable" (gethash "spec" current)) "50%")
        (let ((written (check-core-status 200 status-url :method :put :object current)))
          (is (equal "2026-11-04T12:00:00Z" (gethash "pod-0" (gethash "disruptedPods" (gethash "status" written)))))
          (is (equal "3%" (gethash "minAvailable" (gethash "spec" written))))
          (is (= generation (gethash "generation" (gethash "metadata" written)))))
        (let ((patched (check-core-status 200 status-url :method :patch :content-type "application/merge-patch+json"
                                          :object (gr8s::core-object "status" (gr8s::core-object "disruptedPods" 'null)))))
          (is-false (gethash "disruptedPods" (gethash "status" patched)))))
      (check-core-status 200 item)
      (is (= 1 (length (gethash "items" (check-core-status 200 "/apis/policy/v1/poddisruptionbudgets")))))
      (check-core-status 200 collection :method :delete)
      (is (zerop (length (gethash "items" (check-core-status 200 collection))))))
    (is (null (gr8s::list-core-resources store "poddisruptionbudgets" "alpha")))))

(test disruption-controller-computes-absolute-limits-from-observed-pods
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "foo" :min 1) "alpha")
    (gr8s::reconcile-workloads reconciler)
    (let ((status (budget-status store "foo")))
      (is (= 1 (gethash "observedGeneration" status)))
      (is (zerop (gethash "disruptionsAllowed" status)))
      (is (equal "InsufficientPods" (gethash "reason" (aref (gethash "conditions" status) 0)))))
    ;; Assigned but not ready Pods count toward what is expected and not toward health.
    (dotimes (index 3) (budget-test-pod store (format nil "pod-~D" index)))
    (gr8s::reconcile-workloads reconciler)
    (let ((status (budget-status store "foo")))
      (is (= 3 (gethash "expectedPods" status)))
      (is (zerop (gethash "currentHealthy" status)))
      (is (= 1 (gethash "desiredHealthy" status)))
      (is (zerop (gethash "disruptionsAllowed" status))))
    (settle-budgets reconciler runtime store)
    (let ((status (budget-status store "foo")))
      (is (= 3 (gethash "currentHealthy" status)))
      (is (= 2 (gethash "disruptionsAllowed" status)))
      (is (equal "SufficientPods" (gethash "reason" (aref (gethash "conditions" status) 0)))))))

(test disruption-controller-scales-percentages-against-the-controller
  (with-budget-cluster (store runtime reconciler)
    (let* ((rs (gr8s::create-core-resource store "replicasets" (workload-fixture "ReplicaSet" "foo" 10) "alpha"))
           (labels (gr8s::core-object "app" "foo")))
      (gr8s::create-core-resource store "poddisruptionbudgets"
                                  (budget-fixture "up" :min "90%" :selector (gr8s::core-object "matchLabels" (gr8s::copy-core-object labels))) "alpha")
      (dotimes (index 2) (budget-test-pod store (format nil "pod-~D" index) :labels (gr8s::copy-core-object labels) :owner rs))
      (gr8s::reconcile-disruption-budgets reconciler)
      (let ((status (budget-status store "up")))
        (is (= 10 (gethash "expectedPods" status)))
        (is (= 9 (gethash "desiredHealthy" status)))))))

(test disruption-controller-subtracts-max-unavailable-and-rounds-up
  (with-budget-cluster (store runtime reconciler)
    (let ((rs (gr8s::create-core-resource store "replicasets" (workload-fixture "ReplicaSet" "foo" 10) "alpha")))
      (gr8s::create-core-resource store "poddisruptionbudgets"
                                  (budget-fixture "down" :max "11%" :selector (gr8s::core-object "matchLabels" (gr8s::core-object "app" "foo"))) "alpha")
      (budget-test-pod store "pod-0" :labels (gr8s::core-object "app" "foo") :owner rs)
      (gr8s::reconcile-disruption-budgets reconciler)
      (let ((status (budget-status store "down")))
        (is (= 10 (gethash "expectedPods" status)))
        ;; 11% of 10 rounds up to 2 unavailable.
        (is (= 8 (gethash "desiredHealthy" status)))))))

(test disruption-controller-fails-safe-for-a-controller-without-scale
  (with-budget-cluster (store runtime reconciler)
    (let* ((owner (gr8s::core-object "apiVersion" "apps/v1" "kind" "ReplicaSet"
                                     "metadata" (gr8s::core-object "name" "gone" "uid" "missing-uid"))))
      (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "foo" :max 1) "alpha")
      (budget-test-pod store "pod-0" :owner owner)
      (gr8s::reconcile-disruption-budgets reconciler)
      (let* ((status (budget-status store "foo")) (condition (aref (gethash "conditions" status) 0)))
        (is (zerop (gethash "disruptionsAllowed" status)))
        (is (equal "SyncFailed" (gethash "reason" condition)))
        (is (search "found no controllers" (gethash "message" condition)))))))

(test disruption-controller-ignores-pods-with-no-controller-for-scale
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "foo" :max 1) "alpha")
    (budget-test-pod store "pod-0")
    (gr8s::reconcile-disruption-budgets reconciler)
    (let ((status (budget-status store "foo")))
      (is (zerop (gethash "expectedPods" status)))
      (is (equal "InsufficientPods" (gethash "reason" (aref (gethash "conditions" status) 0)))))))

(test disruption-controller-keeps-recent-evictions-and-drops-expired-ones
  (with-budget-cluster (store runtime reconciler)
    (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "foo" :min 1) "alpha")
    (dotimes (index 3) (budget-test-pod store (format nil "pod-~D" index)))
    (settle-budgets reconciler runtime store)
    (let ((now (get-universal-time)))
      (gr8s::update-core-resource store "poddisruptionbudgets" "alpha" "foo" #'identity)
      (let* ((key (gr8s::core-resource-key "poddisruptionbudgets" "alpha" "foo"))
             (object (gethash key (gr8s::pod-store-resources store))))
        (setf (gethash "disruptedPods" (gethash "status" object))
              (gr8s::core-object "pod-0" (gr8s::current-timestamp now)
                                 "pod-1" (gr8s::current-timestamp (- now 3600))
                                 "absent" (gr8s::current-timestamp now)))
        (setf (gethash "resourceVersion" (gethash "metadata" object)) "stale-for-test"))
      (gr8s::reconcile-disruption-budgets reconciler)
      (let* ((status (budget-status store "foo")) (disrupted (gethash "disruptedPods" status)))
        (is (= 1 (hash-table-count disrupted)))
        (is (gethash "pod-0" disrupted))
        (is (= 2 (gethash "currentHealthy" status)))
        (is (= 1 (gethash "disruptionsAllowed" status)))))))

(test disruption-status-never-overwrites-a-newer-budget
  (with-budget-cluster (store runtime reconciler)
    (let ((stale (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "foo" :min 1) "alpha")))
      (gr8s::reconcile-workloads reconciler)
      (let ((version (gethash "resourceVersion" (gethash "metadata" (gr8s::get-core-resource store "poddisruptionbudgets" "alpha" "foo")))))
        (gr8s::publish-disruption-status store stale (gr8s::core-object "disruptionsAllowed" 7))
        (is (equal version (gethash "resourceVersion" (gethash "metadata" (gr8s::get-core-resource store "poddisruptionbudgets" "alpha" "foo")))))
        (is (zerop (gethash "disruptionsAllowed" (budget-status store "foo"))))))))

(test eviction-without-a-budget-deletes-the-pod
  (with-budget-api (store runtime reconciler)
    (budget-test-pod store "pod-0")
    (settle-budgets reconciler runtime store)
    (let ((url "/api/v1/namespaces/alpha/pods/pod-0/eviction"))
      (check-core-status 400 url :method :post :object (eviction-body "other"))
      (check-core-status 404 "/api/v1/namespaces/alpha/pods/absent/eviction" :method :post :object (eviction-body "absent"))
      (let ((answer (check-core-status 201 url :method :post :object (eviction-body "pod-0"))))
        (is (equal "Success" (gethash "status" answer))))
      (signals gr8s::kubernetes-error (get-pod store "alpha" "pod-0")))))

(test eviction-honors-its-preconditions-and-dry-run
  (with-budget-api (store runtime reconciler)
    (budget-test-pod store "pod-0")
    (settle-budgets reconciler runtime store)
    (let ((url "/api/v1/namespaces/alpha/pods/pod-0/eviction"))
      (check-core-status 409 url :method :post
                         :object (eviction-body "pod-0" (gr8s::core-object "preconditions" (gr8s::core-object "uid" "other"))))
      (is (get-pod store "alpha" "pod-0"))
      (check-core-status 201 url :method :post
                         :object (eviction-body "pod-0" (gr8s::core-object "dryRun" #("All"))))
      (is-false (gr8s::deletion-requested-p (get-pod store "alpha" "pod-0"))))))

(test eviction-spends-the-budget-and-is-refused-with-the-disruption-cause
  (with-budget-api (store runtime reconciler)
    (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "foo" :min 2) "alpha")
    (dotimes (index 3) (budget-test-pod store (format nil "pod-~D" index)))
    (settle-budgets reconciler runtime store)
    (is (= 1 (gethash "disruptionsAllowed" (budget-status store "foo"))))
    (check-core-status 201 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post :object (eviction-body "pod-0"))
    ;; Spent atomically, before any controller pass could notice the deletion.
    (is (zerop (gethash "disruptionsAllowed" (budget-status store "foo"))))
    (is (gethash "pod-0" (gethash "disruptedPods" (budget-status store "foo"))))
    (let* ((denied (check-core-status 429 "/api/v1/namespaces/alpha/pods/pod-1/eviction" :method :post :object (eviction-body "pod-1")))
           (cause (aref (gethash "causes" (gethash "details" denied)) 0)))
      (is (equal "DisruptionBudget" (gethash "reason" cause)))
      (is (search "needs 2 healthy pods and has" (gethash "message" cause))))
    (is-false (gr8s::deletion-requested-p (get-pod store "alpha" "pod-1")))))

(test eviction-waits-for-the-controller-to-observe-a-changed-budget
  (with-budget-api (store runtime reconciler)
    (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "foo" :min 3) "alpha")
    (dotimes (index 3) (budget-test-pod store (format nil "pod-~D" index)))
    (settle-budgets reconciler runtime store)
    (check-core-status 429 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post :object (eviction-body "pod-0"))
    (gr8s::update-core-resource store "poddisruptionbudgets" "alpha" "foo"
      (lambda (object) (setf (gethash "minAvailable" (gethash "spec" object)) 2) object))
    ;; The stale status still shows the old allowance, so the change must be observed first.
    (let ((denied (check-core-status 429 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post :object (eviction-body "pod-0"))))
      (is (search "still being processed" (gethash "message" (aref (gethash "causes" (gethash "details" denied)) 0)))))
    (gr8s::reconcile-workloads reconciler)
    (check-core-status 201 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post :object (eviction-body "pod-0"))))

(test eviction-of-a-pod-under-two-budgets-is-refused
  (with-budget-api (store runtime reconciler)
    (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "one" :min 0) "alpha")
    (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "two" :min 0) "alpha")
    (budget-test-pod store "pod-0")
    (settle-budgets reconciler runtime store)
    (let ((answer (check-core-status 500 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post :object (eviction-body "pod-0"))))
      (is (search "more than one PodDisruptionBudget" (gethash "message" answer))))))

(test eviction-of-an-unready-pod-follows-the-unhealthy-policy
  (flet ((attempt (policy healthy-first expected-code)
           (with-budget-api (store runtime reconciler)
             (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "foo" :max 0 :policy policy) "alpha")
             (let ((ready (budget-test-pod store "pod-ready" :labels (gr8s::core-object "other" "x")))
                   (selected (budget-test-pod store "pod-0")))
               (declare (ignore ready))
               (reconcile-all reconciler)
               (when healthy-first (mark-workload-pods-ready store runtime))
               (let ((observed (gr8s::runtime-observe runtime (pod-uid selected))))
                 (when (and observed (not healthy-first))
                   (setf (gr8s::runtime-pod-status observed)
                         (gr8s::core-object "phase" "Running" "containerStatuses"
                                            (vector (gr8s::core-object "name" "main" "ready" nil
                                                                       "state" (gr8s::core-object "running" (gr8s::core-object))))))))
               (reconcile-all reconciler)
               (gr8s::reconcile-workloads reconciler)
               (is (string= "Running" (gethash "phase" (gr8s::workload-pod-status reconciler selected))))
               (check-core-status expected-code "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post :object (eviction-body "pod-0"))))))
    (attempt nil t 429)
    (attempt nil nil 429)
    (attempt "AlwaysAllow" nil 201)
    (attempt "AlwaysAllow" t 429)))

(test eviction-of-a-pod-not-running-skips-the-budget
  (dolist (phase '("Pending" "Failed" "Succeeded"))
    (with-budget-api (store runtime reconciler)
      (gr8s::create-core-resource store "poddisruptionbudgets" (budget-fixture "foo" :min 5) "alpha")
      (let ((pod (budget-test-pod store "pod-0" :restart "Never")))
        (reconcile-all reconciler)
        (setf (gr8s::runtime-pod-phase (gr8s::runtime-observe runtime (pod-uid pod))) phase)
        (gr8s::reconcile-workloads reconciler)
        (is (equal phase (gethash "phase" (gr8s::workload-pod-status reconciler pod)))))
      (check-core-status 201 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post :object (eviction-body "pod-0")))))

(test eviction-asks-webhooks-about-its-creation-not-a-deletion
  (with-budget-api (store runtime reconciler)
    (budget-test-pod store "pod-0")
    (settle-budgets reconciler runtime store)
    (let ((seen nil))
      (let ((original (fdefinition 'gr8s::admission-active-p)))
        (unwind-protect
             (progn
               (setf (fdefinition 'gr8s::admission-active-p)
                     (lambda (active-store attributes)
                       (push (list (gr8s::admission-operation attributes) (gr8s::admission-subresource attributes)) seen)
                       (funcall original active-store attributes)))
               (check-core-status 201 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post :object (eviction-body "pod-0")))
          (setf (fdefinition 'gr8s::admission-active-p) original)))
      (is (equal '(("CREATE" "eviction")) seen)))))

(test typed-eviction-carries-its-delete-options
  (with-budget-api (store runtime reconciler)
    (budget-test-pod store "pod-0")
    (settle-budgets reconciler runtime store)
    (let* ((options (core-test-protobuf '((1 0))))
           (input (core-test-protobuf-envelope "Eviction"
                    (list (list 1 (core-test-protobuf '((1 "pod-0") (3 "alpha")))) (list 2 options)) "policy/v1")))
      (check-core-status 201 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post
                         :content-type "application/vnd.kubernetes.protobuf" :octets input)
      (signals gr8s::kubernetes-error (get-pod store "alpha" "pod-0")))))

(test eviction-records-the-disruption-target-condition
  (with-budget-api (store runtime reconciler)
    (let* ((input (gr8s::core-object
                   "apiVersion" "v1" "kind" "Pod"
                   "metadata" (gr8s::core-object "name" "pod-0" "namespace" "alpha" "finalizers" #("example.com/hold"))
                   "spec" (gr8s::core-object "nodeName" "gr8s-local"
                                             "containers" (vector (gr8s::core-object "name" "main" "image" "busybox:1.36.1")))))
           (pod (create-pod store (parse-pod input))))
      (settle-budgets reconciler runtime store)
      (check-core-status 201 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post
                         :object (eviction-body "pod-0" (gr8s::core-object "dryRun" #("All"))))
      (is-false (gr8s::with-store-lock (store) (gethash (pod-uid pod) (gr8s::pod-store-pod-client-statuses store))))
      ;; The finalizer keeps the deleted Pod readable, so its condition can be seen.
      (check-core-status 201 "/api/v1/namespaces/alpha/pods/pod-0/eviction" :method :post :object (eviction-body "pod-0"))
      (let* ((status (gethash "status" (check-core-status 200 "/api/v1/namespaces/alpha/pods/pod-0")))
             (condition (find "DisruptionTarget" (gethash "conditions" status) :test #'equal
                              :key (lambda (entry) (gethash "type" entry)))))
        (is (equal "True" (gethash "status" condition)))
        (is (equal "EvictionByEvictionAPI" (gethash "reason" condition)))))))
