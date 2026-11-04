;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify real workload mutations, ownership, scaling, rollouts, observed
;;;; readiness, durable recovery and JSON/protobuf HTTP subresources.

(in-package #:gr8s/tests)
(def-suite workloads :in gr8s)
(in-suite workloads)

(defun workload-fixture (kind name &optional (replicas 2))
  "Build an executable workload with a selector and distinctive template."
  (gr8s::core-object
   "apiVersion" "apps/v1" "kind" kind "metadata" (gr8s::core-object "name" name)
   "spec" (gr8s::core-object
           "replicas" replicas "selector" (gr8s::core-object "matchLabels" (gr8s::core-object "app" name))
           "template" (gr8s::core-object "metadata" (gr8s::core-object "labels" (gr8s::core-object "app" name))
                       "spec" (gr8s::core-object "nodeName" "gr8s-local" "restartPolicy" "Always"
                               "terminationGracePeriodSeconds" 0
                               "containers" (vector (gr8s::core-object "name" "main" "image" "busybox:1.36.1"
                                                     "command" #("sh" "-c" "sleep 300"))))))))

(defun workload-status (store resource name)
  "Read durable controller status in the test namespace."
  (gethash "status" (gr8s::get-core-resource store resource "alpha" name)))

(defun mark-workload-pods-ready (store runtime)
  "Provide actual fake-runtime container observations rather than modifying controller status."
  (dolist (pod (list-pods store "alpha"))
    (let ((observation (gr8s::runtime-observe runtime (pod-uid pod))))
      (when observation
        (setf (gr8s::runtime-pod-status observation)
              (gr8s::core-object "phase" "Running" "containerStatuses"
                                (vector (gr8s::core-object "name" "main" "containerID" (pod-uid pod)
                                                          "ready" t "state" (gr8s::core-object "running" (gr8s::core-object))))))))))

(defun run-workload-passes (reconciler &optional (count 3))
  "Advance controller and actual Pod reconciliation without fabricating ready status."
  (dotimes (index count)
    (gr8s::collect-orphaned-api-objects reconciler)
    (gr8s::reconcile-workloads reconciler)
    (reconcile-all reconciler)))

(defun change-workload-image (store resource name image)
  "Update the actual Pod template used for a subsequent rollout."
  (gr8s::update-core-resource store resource "alpha" name
    (lambda (object)
      (setf (gethash "image" (aref (gethash "containers" (gethash "spec" (gethash "template" (gethash "spec" object)))) 0)) image)
      object)))

(test workload-admission-defaults-generations-and-immutable-selectors
  (with-temporary-store (store path)
    (let* ((created (gr8s::create-core-resource store "deployments" (workload-fixture "Deployment" "web") "alpha"))
           (spec (gethash "spec" created)))
      (is (= 1 (gethash "generation" (gethash "metadata" created))))
      (is (equal "RollingUpdate" (gethash "type" (gethash "strategy" spec))))
      (is (equal "25%" (gethash "maxSurge" (gethash "rollingUpdate" (gethash "strategy" spec)))))
      (is (= 600 (gethash "progressDeadlineSeconds" spec)))
      (is (null (list-pods store)))
      (let ((updated (gr8s::update-core-resource store "deployments" "alpha" "web"
                       (lambda (object) (setf (gethash "labels" (gethash "metadata" object)) (gr8s::core-object "edited" "yes")) object))))
        (is (= 1 (gethash "generation" (gethash "metadata" updated)))))
      (gr8s::update-core-resource store "deployments" "alpha" "web"
        (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 3) object))
      (is (= 2 (gethash "generation" (gethash "metadata" (gr8s::get-core-resource store "deployments" "alpha" "web")))))
      (signals kubernetes-error
        (gr8s::update-core-resource store "deployments" "alpha" "web"
          (lambda (object)
            (setf (gethash "selector" (gethash "spec" object)) (gr8s::core-object "matchLabels" (gr8s::core-object "app" "different")))
            object))))))

(test replica-set-creates-scales-and-recovers-real-pod-identities
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "replicasets" (workload-fixture "ReplicaSet" "workers" 3) "alpha")
      (run-workload-passes reconciler)
      (is (= 3 (length (list-pods store "alpha"))))
      (is (= 0 (gethash "readyReplicas" (workload-status store "replicasets" "workers"))))
      (mark-workload-pods-ready store runtime)
      (run-workload-passes reconciler)
      (is (= 3 (gethash "readyReplicas" (workload-status store "replicasets" "workers"))))
      (let ((uids (sort (mapcar #'pod-uid (list-pods store "alpha")) #'string<))
            (revision (gr8s::pod-store-resource-revision store)))
        (run-workload-passes reconciler)
        (is (= revision (gr8s::pod-store-resource-revision store)))
        (let* ((reopened (open-store path)) (restored (make-reconciler reopened runtime)))
          (run-workload-passes restored)
          (is (equal uids (sort (mapcar #'pod-uid (list-pods reopened "alpha")) #'string<)))))
      (gr8s::update-core-resource store "replicasets" "alpha" "workers"
        (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 1) object))
      (run-workload-passes reconciler)
      (is (= 1 (length (list-pods store "alpha"))))
      (is (= 1 (gethash "replicas" (workload-status store "replicasets" "workers")))))))

(test replica-set-adopts-orphans-releases-mismatches-and-rejects-stale-owner-uids
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (owner (gr8s::create-core-resource store "replicasets" (workload-fixture "ReplicaSet" "workers" 1) "alpha"))
           (pod-input (gr8s::core-object "apiVersion" "v1" "kind" "Pod"
                       "metadata" (gr8s::core-object "name" "orphan" "namespace" "alpha" "labels" (gr8s::core-object "app" "workers"))
                       "spec" (gr8s::copy-core-object (gethash "spec" (gethash "template" (gethash "spec" owner))))))
           (pod (create-pod store (parse-pod pod-input))) (uid (pod-uid pod)))
      (run-workload-passes reconciler)
      (is (= 1 (length (list-pods store "alpha"))))
      (is (gr8s::workload-owned-p (pod-to-object (get-pod store "alpha" "orphan")) owner))
      (is (equal uid (pod-uid (get-pod store "alpha" "orphan"))))
      (let* ((current (get-pod store "alpha" "orphan")) (replacement (gr8s::copy-core-object (pod-to-object current))))
        (setf (gethash "labels" (gethash "metadata" replacement)) (gr8s::core-object "app" "unmatched"))
        (update-pod store (parse-pod replacement) (pod-resource-version current)))
      (run-workload-passes reconciler)
      (is (null (gr8s::workload-controller-reference (pod-to-object (get-pod store "alpha" "orphan")))))
      (is (= 2 (length (list-pods store "alpha"))))
      (gr8s::delete-core-resource store "replicasets" "alpha" "workers")
      (let ((replacement (gr8s::create-core-resource store "replicasets" (workload-fixture "ReplicaSet" "workers" 0) "alpha")))
        (is (not (equal (gethash "uid" (gethash "metadata" owner)) (gethash "uid" (gethash "metadata" replacement)))))
        (is (null (gr8s::create-replica-set-pod store owner)))))))

(test deployment-rollout-scales-real-replica-sets-and-cleans-revisions
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "deployments" (workload-fixture "Deployment" "web" 2) "alpha")
      (run-workload-passes reconciler)
      (mark-workload-pods-ready store runtime)
      (run-workload-passes reconciler)
      (is (= 2 (gethash "availableReplicas" (workload-status store "deployments" "web"))))
      (let ((old-uids (mapcar #'pod-uid (list-pods store "alpha"))))
        (change-workload-image store "deployments" "web" "busybox:1.37.0")
        (gr8s::update-core-resource store "deployments" "alpha" "web"
          (lambda (object) (setf (gethash "revisionHistoryLimit" (gethash "spec" object)) 0) object))
        (dotimes (iteration 8)
          (run-workload-passes reconciler 1)
          (is (<= (length (list-pods store "alpha")) 3))
          (mark-workload-pods-ready store runtime))
        (run-workload-passes reconciler)
        (is (= 2 (gethash "updatedReplicas" (workload-status store "deployments" "web"))))
        (is (= 2 (gethash "availableReplicas" (workload-status store "deployments" "web"))))
        (is (notany (lambda (pod) (member (pod-uid pod) old-uids :test #'equal)) (list-pods store "alpha")))
        (is (= 1 (length (gr8s::list-core-resources store "replicasets" "alpha"))))))))

(test deployment-recreate-and-background-deletion-preserve-controller-ownership
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (input (workload-fixture "Deployment" "web" 1)))
      (setf (gethash "strategy" (gethash "spec" input)) (gr8s::core-object "type" "Recreate"))
      (gr8s::create-core-resource store "deployments" input "alpha")
      (run-workload-passes reconciler)
      (mark-workload-pods-ready store runtime)
      (run-workload-passes reconciler)
      (let ((old (pod-uid (first (list-pods store "alpha")))))
        (change-workload-image store "deployments" "web" "busybox:1.37.0")
        (run-workload-passes reconciler 1)
        (is (null (list-pods store "alpha")))
        (run-workload-passes reconciler)
        (is (= 1 (length (list-pods store "alpha"))))
        (is (not (equal old (pod-uid (first (list-pods store "alpha")))))))
      (gr8s::delete-core-resource store "deployments" "alpha" "web")
      (run-workload-passes reconciler)
      (is (null (list-pods store "alpha")))
      (is (null (gr8s::list-core-resources store "replicasets" "alpha"))))))

(test workload-http-discovery-scale-status-and-strategic-merge
  (with-core-api (store path)
    (let* ((collection "/apis/apps/v1/namespaces/alpha/deployments") (item (concatenate 'string collection "/web"))
           (created (check-core-status 201 collection :method :post :object (workload-fixture "Deployment" "web" 2))))
      (is (equal "apps/v1" (gethash "groupVersion" (check-core-status 200 "/apis/apps/v1"))))
      (let ((scale (check-core-status 200 (concatenate 'string item "/scale"))))
        (is (= 2 (gethash "replicas" (gethash "spec" scale))))
        (is (= 0 (gethash "replicas" (gethash "status" scale))))
        (setf (gethash "replicas" (gethash "spec" scale)) 3)
        (check-core-status 200 (concatenate 'string item "/scale") :method :put :object scale))
      (let ((patched (check-core-status 200 (concatenate 'string item "/scale") :method :patch
                       :content-type "application/merge-patch+json" :object (gr8s::core-object "spec" (gr8s::core-object "replicas" 1)))))
        (is (= 1 (gethash "replicas" (gethash "spec" patched)))))
      (check-core-status 409 item :method :put :object created)
      (let ((status-object (check-core-status 200 item)))
        (setf (gethash "status" status-object) (gr8s::core-object "replicas" 0 "observedGeneration" 3)
              (gethash "replicas" (gethash "spec" status-object)) 99)
        (check-core-status 200 (concatenate 'string item "/status") :method :put :object status-object)
        (is (= 1 (gethash "replicas" (gethash "spec" (check-core-status 200 item))))))
      (let ((patched (check-core-status 200 item :method :patch :content-type "application/strategic-merge-patch+json"
                        :object (com.inuoe.jzon:parse "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"main\",\"env\":[{\"name\":\"MODE\",\"value\":\"new\"}]}]}}}}"))))
        (is (equal "busybox:1.36.1" (gethash "image" (aref (gethash "containers" (gethash "spec" (gethash "template" (gethash "spec" patched)))) 0)))))
      (let* ((openapi (check-core-status 200 "/openapi/v3/apis/apps/v1"))
             (schemas (gethash "schemas" (gethash "components" openapi))))
        (is (gethash "io.k8s.api.apps.v1.Deployment" schemas))
        (is (gethash "/apis/apps/v1/namespaces/{namespace}/deployments/{name}/scale" (gethash "paths" openapi))))
      (check-core-status 200 collection :method :delete)
      (is (null (gr8s::list-core-resources store "deployments" "alpha"))))))

(test workload-ready-duration-pause-and-progress-deadline-are-observed
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (now (get-universal-time)) (gr8s::*workload-clock* (lambda () now))
           (gr8s::*pod-condition-clock* (lambda () now))
           (input (workload-fixture "Deployment" "web" 1)))
      (setf (gethash "minReadySeconds" (gethash "spec" input)) 10
            (gethash "progressDeadlineSeconds" (gethash "spec" input)) 20)
      (gr8s::create-core-resource store "deployments" input "alpha")
      (run-workload-passes reconciler)
      (mark-workload-pods-ready store runtime)
      (run-workload-passes reconciler)
      (is (= 1 (gethash "readyReplicas" (workload-status store "deployments" "web"))))
      (is (= 0 (gethash "availableReplicas" (workload-status store "deployments" "web"))))
      (incf now 10)
      (run-workload-passes reconciler)
      (is (= 1 (gethash "availableReplicas" (workload-status store "deployments" "web"))))
      (gr8s::update-core-resource store "deployments" "alpha" "web"
        (lambda (object) (setf (gethash "paused" (gethash "spec" object)) t) object))
      (change-workload-image store "deployments" "web" "busybox:1.37.0")
      (run-workload-passes reconciler)
      (is (= 1 (length (gr8s::list-core-resources store "replicasets" "alpha"))))
      (gr8s::update-core-resource store "deployments" "alpha" "web"
        (lambda (object) (setf (gethash "paused" (gethash "spec" object)) nil) object))
      (run-workload-passes reconciler)
      (incf now 21)
      (run-workload-passes reconciler)
      (let* ((conditions (gethash "conditions" (workload-status store "deployments" "web")))
             (progress (find "Progressing" conditions :test #'equal :key (lambda (item) (gethash "type" item)))))
        (is (equal "ProgressDeadlineExceeded" (gethash "reason" progress)))
        (let ((stamp (gethash "lastTransitionTime" progress)))
          (run-workload-passes reconciler)
          (is (equal stamp (gethash "lastTransitionTime"
                             (find "Progressing" (gethash "conditions" (workload-status store "deployments" "web"))
                                   :test #'equal :key (lambda (item) (gethash "type" item)))))))))))

(test freshly-paused-workload-observes-generation-without-starting-pods
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (input (workload-fixture "Deployment" "paused" 1)))
      (setf (gethash "paused" (gethash "spec" input)) t)
      (gr8s::create-core-resource store "deployments" input "alpha")
      (run-workload-passes reconciler)
      (is (null (list-pods store)))
      (is (null (gr8s::list-core-resources store "replicasets" "alpha")))
      (is (= 1 (gethash "observedGeneration" (workload-status store "deployments" "paused")))))))

(test workload-protobuf-retains-explicit-zero-replicas-and-scale-version
  (with-core-api (store path)
    (let* ((labels (core-test-protobuf '((1 "app") (2 "wire"))))
           (selector (core-test-protobuf (list (list 1 labels))))
           (template-meta (core-test-protobuf (list (list 3 "") (list 11 labels))))
           (container (core-test-protobuf '((1 "main") (2 "busybox:1.36.1"))))
           (pod-spec (core-test-protobuf (list (list 2 container))))
           (template (core-test-protobuf (list (list 1 template-meta) (list 2 pod-spec))))
           (spec (core-test-protobuf (list (list 1 0) (list 2 selector) (list 3 template))))
           (input (core-test-protobuf-envelope "Deployment"
                    (list (list 1 (core-test-protobuf '((1 "wire")))) (list 2 spec)) "apps/v1"))
           (collection "/apis/apps/v1/namespaces/alpha/deployments")
           (created (check-core-status 201 collection :method :post :content-type "application/vnd.kubernetes.protobuf" :octets input)))
      (is (= 0 (gethash "replicas" (gethash "spec" created))))
      (check-core-status 400 collection :method :post :content-type "application/vnd.kubernetes.protobuf"
                         :octets (core-test-protobuf-envelope "Deployment" (list (list 1 #()) (list 2 spec)) "v1"))
      (let* ((metadata (core-test-protobuf (list (list 1 "wire") (list 6 (gethash "resourceVersion" (gethash "metadata" created))))))
             (scale (core-test-protobuf-envelope "Scale" (list (list 1 metadata) (list 2 (core-test-protobuf '((1 2))))) "autoscaling/v1"))
             (updated (check-core-status 200 (concatenate 'string collection "/wire/scale") :method :put
                        :content-type "application/vnd.kubernetes.protobuf" :octets scale)))
        (is (= 2 (gethash "replicas" (gethash "spec" updated))))
        (is (= 2 (gethash "replicas" (gethash "spec" (gr8s::get-core-resource store "deployments" "alpha" "wire")))))))))

(test foreground-workload-deletion-checkpoints-and-finishes-after-children-on-restart
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (owner (gr8s::create-core-resource store "deployments" (workload-fixture "Deployment" "web") "alpha")))
      (run-workload-passes reconciler)
      (is (= 2 (length (list-pods store "alpha"))))
      (gr8s::delete-workload-resource store "deployments" "alpha" "web" :policy "Foreground")
      (is (gethash "deletionTimestamp" (gethash "metadata" (gr8s::get-core-resource store "deployments" "alpha" "web"))))
      (let* ((reopened (open-store path)) (recovered (make-reconciler reopened runtime)))
        (is (= 1 (hash-table-count (gr8s::pod-store-workload-deletions reopened))))
        (run-workload-passes recovered 1)
        (is (null (gr8s::create-replica-set-pod reopened
                    (first (gr8s::list-core-resources reopened "replicasets" "alpha")))))
        (is (gethash "deletionTimestamp" (gethash "metadata" (gr8s::get-core-resource reopened "deployments" "alpha" "web"))))
        (run-workload-passes recovered 4)
        (is (null (list-pods reopened "alpha")))
        (is (null (gr8s::list-core-resources reopened "replicasets" "alpha")))
        (is (null (gr8s::list-core-resources reopened "deployments" "alpha")))
        (is (zerop (hash-table-count (gr8s::pod-store-workload-deletions reopened)))))
      (is (null (gr8s::workload-current-unlocked (open-store path) "deployments" owner))))))

(test workload-orphaning-detaches-controller-reference-without-restarting-children
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "deployments" (workload-fixture "Deployment" "web") "alpha")
      (run-workload-passes reconciler)
      (let ((uids (sort (mapcar #'pod-uid (list-pods store "alpha")) #'string<)))
        (gr8s::delete-workload-resource store "deployments" "alpha" "web" :policy "Orphan")
        (run-workload-passes reconciler)
        (is (null (gr8s::list-core-resources store "deployments" "alpha")))
        (let ((set (first (gr8s::list-core-resources store "replicasets" "alpha"))))
          (is (null (gr8s::workload-controller-reference set)))
          (gr8s::delete-workload-resource store "replicasets" "alpha" (gethash "name" (gethash "metadata" set)) :policy "Orphan"))
        (let* ((reopened (open-store path)) (recovered (make-reconciler reopened runtime)))
          (run-workload-passes recovered)
          (is (equal uids (sort (mapcar #'pod-uid (list-pods reopened "alpha")) #'string<)))
          (is (every (lambda (pod) (null (gr8s::workload-controller-reference (pod-to-object pod)))) (list-pods reopened "alpha"))))))))

(test foreground-deletion-does-not-publish-a-failed-checkpoint
  (with-temporary-store (store path)
    (gr8s::create-core-resource store "replicasets" (workload-fixture "ReplicaSet" "web") "alpha")
    (let ((original (symbol-function 'gr8s::write-private-text-atomically)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::write-private-text-atomically)
                   (lambda (&rest arguments) (declare (ignore arguments)) (error "injected disk failure")))
             (signals error (gr8s::delete-workload-resource store "replicasets" "alpha" "web" :policy "Foreground")))
        (setf (symbol-function 'gr8s::write-private-text-atomically) original)))
    (dolist (current (list store (open-store path)))
      (is (zerop (hash-table-count (gr8s::pod-store-workload-deletions current))))
      (is (not (gethash "deletionTimestamp" (gethash "metadata" (gr8s::get-core-resource current "replicasets" "alpha" "web"))))))))

(test workload-http-validates-and-checkpoints-foreground-delete-options
  (with-core-api (store path)
    (let* ((collection "/apis/apps/v1/namespaces/alpha/replicasets")
           (item (concatenate 'string collection "/web"))
           (created (check-core-status 201 collection :method :post :object (workload-fixture "ReplicaSet" "web" 0)))
           (metadata (gethash "metadata" created)))
      (check-core-status 422 item :method :delete :object (gr8s::core-object "propagationPolicy" "Invalid"))
      (check-core-status 200 item :method :delete :parameters '(("dryRun" . "All"))
                         :object (gr8s::core-object "propagationPolicy" "Foreground"))
      (is (zerop (hash-table-count (gr8s::pod-store-workload-deletions store))))
      (let* ((preconditions (core-test-protobuf (list (list 1 (gethash "uid" metadata))
                                                     (list 2 (gethash "resourceVersion" metadata)))))
             (options (core-test-protobuf-envelope "DeleteOptions" (list (list 2 preconditions) (list 4 "Foreground")) "apps/v1")))
        (check-core-status 200 item :method :delete :content-type "application/vnd.kubernetes.protobuf" :octets options))
      (is (gethash "deletionTimestamp" (gethash "metadata" (check-core-status 200 item))))
      (gr8s::reconcile-workloads (make-reconciler store (make-fake-runtime)))
      (check-core-status 404 item))))

(test unsupported-workload-pod-features-report-real-replica-failure
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (input (workload-fixture "ReplicaSet" "web" 1)))
      (setf (gethash "readinessProbe" (aref (gethash "containers" (gethash "spec" (gethash "template" (gethash "spec" input)))) 0))
            (gr8s::core-object "exec" (gr8s::core-object "command" #("false"))))
      (gr8s::create-core-resource store "replicasets" input "alpha")
      (run-workload-passes reconciler)
      (is (null (list-pods store)))
      (let* ((status (workload-status store "replicasets" "web")) (failure (aref (gethash "conditions" status) 0)))
        (is (= 0 (gethash "replicas" status)))
        (is (= 0 (gethash "readyReplicas" status)))
        (is (equal "ReplicaFailure" (gethash "type" failure)))
        (is (equal "FailedCreate" (gethash "reason" failure)))
        (is (search "readinessProbe" (gethash "message" failure)))))))

(test generated-workload-names-are-bounded-and-collisions-do-not-replace-existing-owners
  (with-temporary-store (store path)
    (let* ((input (workload-fixture "Deployment" "web" 0)) (metadata (gethash "metadata" input)))
      (setf (gethash "name" metadata) "" (gethash "generateName" metadata) (make-string 200 :initial-element #\a))
      (let* ((created (gr8s::create-core-resource store "deployments" input "alpha"))
             (name (gethash "name" (gethash "metadata" created))))
        (is (= 63 (length name)))
        (is (equal name (gethash "name" (gethash "metadata" (gr8s::get-core-resource (open-store path) "deployments" "alpha" name))))))
      (gr8s::create-core-resource store "deployments" (workload-fixture "Deployment" "collision" 0) "alpha")
      (let ((calls 0)
            (gr8s::*pod-name-generator* (lambda (prefix) (declare (ignore prefix)) "collision")))
        (declare (ignore calls))
        (signals kubernetes-error (gr8s::create-core-resource store "deployments" input "alpha")))
      (is (= 2 (length (gr8s::list-core-resources store "deployments" "alpha")))))))

(test zero-surge-rounded-percentage-rollouts-make-progress
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (input (workload-fixture "Deployment" "web" 1)))
      (setf (gethash "strategy" (gethash "spec" input))
            (gr8s::core-object "type" "RollingUpdate" "rollingUpdate" (gr8s::core-object "maxSurge" 0 "maxUnavailable" "25%")))
      (gr8s::create-core-resource store "deployments" input "alpha")
      (run-workload-passes reconciler)
      (mark-workload-pods-ready store runtime)
      (run-workload-passes reconciler)
      (let ((old (pod-uid (first (list-pods store "alpha")))))
        (change-workload-image store "deployments" "web" "busybox:1.37.0")
        (dotimes (iteration 6)
          (run-workload-passes reconciler 1)
          (mark-workload-pods-ready store runtime))
        (run-workload-passes reconciler)
        (is (= 1 (gethash "updatedReplicas" (workload-status store "deployments" "web"))))
        (is (not (equal old (pod-uid (first (list-pods store "alpha"))))))))))

(test deployment-releases-mismatched-replica-set-and-rehashes-name-collisions
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "deployments" (workload-fixture "Deployment" "web" 1) "alpha")
      (run-workload-passes reconciler)
      (let* ((old (first (gr8s::list-core-resources store "replicasets" "alpha"))) (name (gethash "name" (gethash "metadata" old))))
        (gr8s::update-core-resource store "replicasets" "alpha" name
          (lambda (object) (setf (gethash "app" (gethash "labels" (gethash "metadata" object))) "someone-else") object))
        (run-workload-passes reconciler)
        (is (null (gr8s::workload-controller-reference (gr8s::get-core-resource store "replicasets" "alpha" name))))
        (is (= 2 (length (gr8s::list-core-resources store "replicasets" "alpha"))))
        (is (= 1 (gethash "collisionCount" (workload-status store "deployments" "web"))))
        (let* ((reopened (open-store path)) (restored (make-reconciler reopened runtime)))
          (run-workload-passes restored)
          (is (= 2 (length (gr8s::list-core-resources reopened "replicasets" "alpha"))))
          (is (= 1 (gethash "collisionCount" (workload-status reopened "deployments" "web")))))))))

(test pod-list-survives-disappearing-and-replaced-snapshot-identities-over-http
  (with-core-api (store path)
    (dolist (replace '(nil t))
      (let* ((input (gr8s::copy-core-object (gr8s::core-object "apiVersion" "v1" "kind" "Pod"
                        "metadata" (gr8s::core-object "name" "racing" "namespace" "alpha")
                        "spec" (gethash "spec" (gethash "template" (gethash "spec" (workload-fixture "ReplicaSet" "web" 0)))))))
             (old (create-pod store (parse-pod input))) (original (symbol-function 'gr8s:list-pods)) (intercept t))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s:list-pods)
                     (lambda (actual &optional namespace)
                       (let ((snapshot (funcall original actual namespace)))
                         (when (and intercept (eq actual store))
                           (setf intercept nil)
                           (gr8s::remove-pod store "alpha" "racing")
                           (when replace (create-pod store (parse-pod (gr8s::copy-core-object input)))))
                         snapshot)))
               (let ((listed (check-core-status 200 "/api/v1/namespaces/alpha/pods")))
                 (is (zerop (length (gethash "items" listed)))))
               (when replace
                 (is (not (equal (pod-uid old) (pod-uid (get-pod store "alpha" "racing")))))))
          (setf (symbol-function 'gr8s:list-pods) original))
        (when replace (gr8s::remove-pod store "alpha" "racing"))))))

(test deployment-adopts-an-unannotated-matching-revision-as-initial-revision-one
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (input (workload-fixture "Deployment" "web" 1))
           (rs (workload-fixture "ReplicaSet" "existing" 1)))
      (setf (gethash "labels" (gethash "metadata" rs)) (gr8s::core-object "app" "web")
            (gethash "selector" (gethash "spec" rs)) (gr8s::copy-core-object (gethash "selector" (gethash "spec" input)))
            (gethash "template" (gethash "spec" rs)) (gr8s::copy-core-object (gethash "template" (gethash "spec" input))))
      (gr8s::create-core-resource store "replicasets" rs "alpha")
      (gr8s::create-core-resource store "deployments" input "alpha")
      (run-workload-passes reconciler)
      (let ((sets (gr8s::list-core-resources store "replicasets" "alpha")))
        (is (= 1 (length sets)))
        (is (= 1 (gr8s::deployment-revision (first sets))))
        (is (equal "1" (gethash "deployment.kubernetes.io/revision"
                               (gethash "annotations" (gethash "metadata" (gr8s::get-core-resource store "deployments" "alpha" "web"))))))))))

(test deployment-proportionally-scales-a-stalled-and-paused-rollout
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (input (workload-fixture "Deployment" "web" 10)))
      (setf (gethash "strategy" (gethash "spec" input))
            (gr8s::core-object "type" "RollingUpdate" "rollingUpdate" (gr8s::core-object "maxSurge" 3 "maxUnavailable" 2)))
      (gr8s::create-core-resource store "deployments" input "alpha")
      (run-workload-passes reconciler)
      (mark-workload-pods-ready store runtime)
      (run-workload-passes reconciler)
      (change-workload-image store "deployments" "web" "nonexistent:404")
      (run-workload-passes reconciler 6)
      (let* ((sets (sort (gr8s::list-core-resources store "replicasets" "alpha") #'< :key #'gr8s::deployment-revision))
             (old-name (gethash "name" (gethash "metadata" (first sets))))
             (new-name (gethash "name" (gethash "metadata" (second sets)))))
        (is (= 8 (gethash "replicas" (gethash "spec" (first sets)))))
        (is (= 5 (gethash "replicas" (gethash "spec" (second sets)))))
        (gr8s::update-core-resource store "deployments" "alpha" "web"
          (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 30) object))
        (run-workload-passes reconciler 5)
        (is (= 20 (gethash "replicas" (gethash "spec" (gr8s::get-core-resource store "replicasets" "alpha" old-name)))))
        (is (= 13 (gethash "replicas" (gethash "spec" (gr8s::get-core-resource store "replicasets" "alpha" new-name)))))
        (gr8s::update-core-resource store "deployments" "alpha" "web"
          (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 13
                                  (gethash "paused" (gethash "spec" object)) t) object))
        (run-workload-passes reconciler 3)
        (is (= 10 (gethash "replicas" (gethash "spec" (gr8s::get-core-resource store "replicasets" "alpha" old-name)))))
        (is (= 6 (gethash "replicas" (gethash "spec" (gr8s::get-core-resource store "replicasets" "alpha" new-name)))))))))

(test deployment-allows-large-surge-but-bounds-unavailable-percentage
  (with-temporary-store (store path)
    (let ((input (workload-fixture "Deployment" "web" 1)))
      (setf (gethash "strategy" (gethash "spec" input))
            (gr8s::core-object "type" "RollingUpdate" "rollingUpdate"
                               (gr8s::core-object "maxSurge" "200%" "maxUnavailable" "100%")))
      (is (equal "200%" (gethash "maxSurge" (gethash "rollingUpdate" (gethash "strategy"
        (gethash "spec" (gr8s::create-core-resource store "deployments" input "alpha")))))))
      (setf (gethash "maxUnavailable" (gethash "rollingUpdate" (gethash "strategy" (gethash "spec" input)))) "101%")
      (signals kubernetes-error
        (gr8s::create-core-resource store "deployments" input "alpha")))))

(test workload-scale-allows-an-explicitly-empty-resource-version
  (with-core-api (store path)
    (let* ((collection "/apis/apps/v1/namespaces/alpha/deployments")
           (endpoint (concatenate 'string collection "/web/scale")))
      (check-core-status 201 collection :method :post :object (workload-fixture "Deployment" "web" 1))
      (let ((scale (check-core-status 200 endpoint)))
        (setf (gethash "resourceVersion" (gethash "metadata" scale)) ""
              (gethash "replicas" (gethash "spec" scale)) 2)
        (is (= 2 (gethash "replicas" (gethash "spec" (check-core-status 200 endpoint :method :put :object scale)))))
        (setf (gethash "resourceVersion" (gethash "metadata" scale)) "stale")
        (check-core-status 409 endpoint :method :put :object scale)))))
