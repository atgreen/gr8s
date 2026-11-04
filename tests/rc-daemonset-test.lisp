;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify ReplicationController and DaemonSet admission and controllers,
;;;; ControllerRevision history, Node label writes, terminal Pod status writes
;;;; and foreground deletion through multiple owners and dependency cycles.

(in-package #:gr8s/tests)
(def-suite rc-daemonset :in gr8s)
(in-suite rc-daemonset)

(defun rc-fixture (name &optional (replicas 2))
  "Build a ReplicationController leaving its selector to default from the template."
  (gr8s::core-object
   "apiVersion" "v1" "kind" "ReplicationController" "metadata" (gr8s::core-object "name" name)
   "spec" (gr8s::core-object
           "replicas" replicas
           "template" (gr8s::core-object
                       "metadata" (gr8s::core-object "labels" (gr8s::core-object "app" name))
                       "spec" (gr8s::core-object "nodeName" "gr8s-local" "terminationGracePeriodSeconds" 0
                               "containers" (vector (gr8s::core-object "name" "main" "image" "busybox:1.36.1")))))))

(defun daemonset-fixture (name &key node-selector strategy)
  "Build a DaemonSet shaped like upstream's e2e fixture, with its empty security contexts."
  (let ((pod-spec (gr8s::core-object
                   "securityContext" (gr8s::core-object) "terminationGracePeriodSeconds" 0
                   "containers" (vector (gr8s::core-object "name" "app" "image" "agnhost:2.56"
                                                           "securityContext" (gr8s::core-object)
                                                           "ports" (vector (gr8s::core-object "containerPort" 9376)))))))
    (when node-selector (setf (gethash "nodeSelector" pod-spec) node-selector))
    (let ((object (gr8s::core-object
                   "apiVersion" "apps/v1" "kind" "DaemonSet"
                   "metadata" (gr8s::core-object "name" name "labels" (gr8s::core-object "daemonset-name" name))
                   "spec" (gr8s::core-object
                           "selector" (gr8s::core-object "matchLabels" (gr8s::core-object "daemonset-name" name))
                           "template" (gr8s::core-object
                                       "metadata" (gr8s::core-object "labels" (gr8s::core-object "daemonset-name" name))
                                       "spec" pod-spec)))))
      (when strategy (setf (gethash "updateStrategy" (gethash "spec" object)) strategy))
      object)))

(defun register-test-nodes (store &rest names)
  "Register NAMES as ready workers with distinct Pod networks."
  (loop for name in names for index from 0
        do (gr8s:register-node store (gr8s:make-node-record :id (format nil "id-~A" name) :name name
                                                           :pod-cidr (format nil "10.88.~D.0/24" index)))
           (gr8s:mark-node-ready store name (get-universal-time))))

(defun mark-all-pods-ready (store runtime namespace)
  "Report every Pod in NAMESPACE running and ready through the fake runtime."
  (dolist (pod (list-pods store namespace))
    (let ((observation (gr8s::runtime-observe runtime (pod-uid pod))))
      (when observation
        (setf (gr8s::runtime-pod-status observation)
              (gr8s::core-object "phase" "Running" "containerStatuses"
                                (vector (gr8s::core-object "name" (gethash "name" (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0))
                                                           "containerID" (pod-uid pod) "ready" t
                                                           "state" (gr8s::core-object "running" (gr8s::core-object))))))))))

(defun live-pods (store namespace)
  "List NAMESPACE's Pods that have no deletion in progress."
  (remove-if #'gr8s::deletion-requested-p (list-pods store namespace)))

(test replication-controller-defaults-selector-and-labels-from-its-template
  (with-temporary-store (store path)
    (let* ((created (gr8s::create-core-resource store "replicationcontrollers" (rc-fixture "web") "alpha"))
           (spec (gethash "spec" created)))
      (is (equal "web" (gethash "app" (gethash "selector" spec))))
      (is (equal "web" (gethash "app" (gethash "labels" (gethash "metadata" created)))))
      (is (= 1 (gethash "generation" (gethash "metadata" created))))
      (is (= 0 (gethash "minReadySeconds" spec))))
    (let ((missing (rc-fixture "bad")))
      (remhash "template" (gethash "spec" missing))
      (signals kubernetes-error (gr8s::create-core-resource store "replicationcontrollers" missing "alpha")))
    (let ((mismatch (rc-fixture "bad")))
      (setf (gethash "selector" (gethash "spec" mismatch)) (gr8s::core-object "app" "other"))
      (signals kubernetes-error (gr8s::create-core-resource store "replicationcontrollers" mismatch "alpha")))
    (let ((unrunnable (rc-fixture "bad")))
      (setf (gethash "affinity" (gethash "spec" (gethash "template" (gethash "spec" unrunnable)))) (gr8s::core-object))
      (signals kubernetes-error (gr8s::create-core-resource store "replicationcontrollers" unrunnable "alpha")))))

(test replication-controller-selector-may-change-after-creation
  (with-temporary-store (store path)
    (gr8s::create-core-resource store "replicationcontrollers" (rc-fixture "web" 0) "alpha")
    (let ((updated (gr8s::update-core-resource store "replicationcontrollers" "alpha" "web"
                     (lambda (object)
                       (setf (gethash "tier" (gethash "labels" (gethash "metadata" (gethash "template" (gethash "spec" object))))) "front"
                             (gethash "selector" (gethash "spec" object)) (gr8s::core-object "tier" "front"))
                       object))))
      (is (equal "front" (gethash "tier" (gethash "selector" (gethash "spec" updated))))))))

(test replication-controller-scales-adopts-and-releases-real-pods
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (orphan (create-pod store (parse-pod (gr8s::core-object
                                                 "apiVersion" "v1" "kind" "Pod"
                                                 "metadata" (gr8s::core-object "name" "orphan" "namespace" "alpha" "labels" (gr8s::core-object "app" "web"))
                                                 "spec" (gr8s::core-object "nodeName" "gr8s-local"
                                                         "containers" (vector (gr8s::core-object "name" "main" "image" "busybox:1.36.1")))))))
           (owner (gr8s::create-core-resource store "replicationcontrollers" (rc-fixture "web" 2) "alpha")))
      (run-workload-passes reconciler)
      (is (= 2 (length (list-pods store "alpha"))))
      (is (gr8s::workload-owned-p (pod-to-object (get-pod store "alpha" "orphan")) owner))
      (is (equal (pod-uid orphan) (pod-uid (get-pod store "alpha" "orphan"))))
      (let ((reference (gr8s::workload-controller-reference (pod-to-object (get-pod store "alpha" "orphan")))))
        (is (equal "v1" (gethash "apiVersion" reference)))
        (is (equal "ReplicationController" (gethash "kind" reference)))
        (is (eq t (gethash "blockOwnerDeletion" reference))))
      (mark-all-pods-ready store runtime "alpha")
      (run-workload-passes reconciler)
      (let ((status (workload-status store "replicationcontrollers" "web")))
        (is (= 2 (gethash "replicas" status)))
        (is (= 2 (gethash "readyReplicas" status)))
        (is (= 2 (gethash "availableReplicas" status)))
        (is (= 1 (gethash "observedGeneration" status))))
      (let* ((current (get-pod store "alpha" "orphan")) (replacement (gr8s::copy-core-object (pod-to-object current))))
        (setf (gethash "labels" (gethash "metadata" replacement)) (gr8s::core-object "app" "unmatched"))
        (update-pod store (parse-pod replacement) (pod-resource-version current)))
      (run-workload-passes reconciler)
      (is (null (gr8s::workload-controller-reference (pod-to-object (get-pod store "alpha" "orphan")))))
      (is (= 2 (count-if (lambda (pod) (gr8s::workload-owned-p (pod-to-object pod) owner)) (live-pods store "alpha")))))))

(test replication-controller-surfaces-and-clears-a-replica-failure
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "replicationcontrollers" (rc-fixture "web" 1) "alpha")
      (let ((original (symbol-function 'gr8s::admit-in-cluster-pod)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s::admit-in-cluster-pod)
                     (lambda (&rest arguments) (declare (ignore arguments)) (error "quota exceeded")))
               (gr8s::reconcile-workloads reconciler))
          (setf (symbol-function 'gr8s::admit-in-cluster-pod) original)))
      (let ((condition (aref (gethash "conditions" (workload-status store "replicationcontrollers" "web")) 0)))
        (is (equal "ReplicaFailure" (gethash "type" condition)))
        (is (null (nth-value 1 (gethash "lastUpdateTime" condition)))))
      (gr8s::reconcile-workloads reconciler)
      (is (null (gethash "conditions" (workload-status store "replicationcontrollers" "web")))))))

(test replication-controller-http-serves-scale-status-discovery-and-orphans-by-default
  (with-core-api (store path)
    (let* ((collection "/api/v1/namespaces/alpha/replicationcontrollers")
           (item (concatenate 'string collection "/web"))
           (reconciler (make-reconciler store (make-fake-runtime))))
      (check-core-status 201 collection :method :post :object (rc-fixture "web" 1))
      (let ((names (map 'list (lambda (resource) (gethash "name" resource))
                        (gethash "resources" (check-core-status 200 "/api/v1")))))
        (dolist (name '("replicationcontrollers" "replicationcontrollers/scale" "replicationcontrollers/status"))
          (is (member name names :test #'equal))))
      (let ((scale (check-core-status 200 (concatenate 'string item "/scale"))))
        (is (equal "Scale" (gethash "kind" scale)))
        (is (= 1 (gethash "replicas" (gethash "spec" scale))))
        (is (equal "app=web" (gethash "selector" (gethash "status" scale))))
        (setf (gethash "replicas" (gethash "spec" scale)) 3
              (gethash "resourceVersion" (gethash "metadata" scale)) "")
        (check-core-status 200 (concatenate 'string item "/scale") :method :put :object scale))
      (is (= 3 (gethash "replicas" (gethash "spec" (check-core-status 200 item)))))
      (check-core-status 200 (concatenate 'string item "/status") :method :patch
                         :content-type "application/strategic-merge-patch+json"
                         :object (gr8s::core-object "status" (gr8s::core-object "readyReplicas" 0)))
      (gr8s::reconcile-workloads reconciler)
      (is (= 3 (length (list-pods store "alpha"))))
      (let ((uids (sort (mapcar #'pod-uid (list-pods store "alpha")) #'string<)))
        (check-core-status 200 item :method :delete)
        (is (gethash "deletionTimestamp" (gethash "metadata" (check-core-status 200 item))))
        (gr8s::reconcile-workloads reconciler)
        (check-core-status 404 item)
        (is (equal uids (sort (mapcar #'pod-uid (list-pods store "alpha")) #'string<)))
        (is (every (lambda (pod) (null (gr8s::workload-controller-reference (pod-to-object pod))))
                   (list-pods store "alpha")))))))

(test daemonset-admission-defaults-its-strategy-and-refuses-surge
  (with-temporary-store (store path)
    (let* ((created (gr8s::create-core-resource store "daemonsets" (daemonset-fixture "ds") "alpha"))
           (spec (gethash "spec" created)) (strategy (gethash "updateStrategy" spec)))
      (is (equal "RollingUpdate" (gethash "type" strategy)))
      (is (= 1 (gethash "maxUnavailable" (gethash "rollingUpdate" strategy))))
      (is (= 10 (gethash "revisionHistoryLimit" spec)))
      (is (null (nth-value 1 (gethash "replicas" spec))))
      (is (= 0 (gethash "numberReady" (gethash "status" created)))))
    (signals kubernetes-error
      (gr8s::create-core-resource
       store "daemonsets"
       (daemonset-fixture "surge" :strategy (gr8s::core-object "type" "RollingUpdate" "rollingUpdate"
                                                               (gr8s::core-object "maxUnavailable" 0 "maxSurge" 1)))
       "alpha"))
    (signals kubernetes-error
      (gr8s::create-core-resource store "daemonsets"
                                  (daemonset-fixture "bad" :strategy (gr8s::core-object "type" "Sometimes")) "alpha"))))

(test daemonset-revision-data-is-the-json-a-typed-client-marshals
  ;; Upstream's daemon.Match compares these bytes with what a Go client derives.
  (let* ((daemonset (daemonset-fixture "ds"))
         (template (gethash "template" (gethash "spec" daemonset)))
         (pod-spec (gethash "spec" template)))
    (setf (gethash "dnsPolicy" pod-spec) "ClusterFirst" (gethash "restartPolicy" pod-spec) "Always"
          (gethash "args" (aref (gethash "containers" pod-spec) 0)) #()
          (gethash "creationTimestamp" (gethash "metadata" template)) 'null
          ;; A typed client's protobuf carries these zero values.
          (gethash "name" (gethash "metadata" template)) ""
          (gethash "uid" (gethash "metadata" template)) ""
          (gethash "generation" (gethash "metadata" template)) 0
          (gethash "nodeSelector" pod-spec) (gr8s::core-object))
    (is (equal (concatenate 'string
                 "{\"spec\":{\"template\":{\"$patch\":\"replace\",\"metadata\":{\"labels\":{\"daemonset-name\":\"ds\"}},"
                 "\"spec\":{\"containers\":[{\"image\":\"agnhost:2.56\",\"name\":\"app\","
                 "\"ports\":[{\"containerPort\":9376}],\"resources\":{},\"securityContext\":{}}],"
                 "\"dnsPolicy\":\"ClusterFirst\",\"restartPolicy\":\"Always\",\"securityContext\":{},"
                 "\"terminationGracePeriodSeconds\":0}}}}")
               (com.inuoe.jzon:stringify (gr8s::daemonset-revision-data daemonset))))
    ;; The order survives storage, and a copy of it, which clients then read back.
    (is (equal (com.inuoe.jzon:stringify (gr8s::daemonset-revision-data daemonset))
               (com.inuoe.jzon:stringify (gr8s::copy-core-object (gr8s::daemonset-revision-data daemonset)))))))

(test daemonset-runs-one-pod-per-selected-node-and-follows-node-labels
  (with-temporary-store (store path)
    (register-test-nodes store "node-a" "node-b")
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "daemonsets"
                                  (daemonset-fixture "ds" :node-selector (gr8s::core-object "color" "blue")) "alpha")
      (run-workload-passes reconciler)
      (is (null (list-pods store "alpha")))
      (is (= 0 (gethash "desiredNumberScheduled" (workload-status store "daemonsets" "ds"))))
      (setf (gr8s::node-record-labels (gr8s:get-node store "node-a")) (gr8s::core-object "color" "blue"))
      (run-workload-passes reconciler)
      (is (equal '("node-a") (mapcar #'gr8s::pod-node-name (live-pods store "alpha"))))
      (mark-all-pods-ready store runtime "alpha")
      (run-workload-passes reconciler)
      (let ((status (workload-status store "daemonsets" "ds")))
        (is (= 1 (gethash "desiredNumberScheduled" status)))
        (is (= 1 (gethash "currentNumberScheduled" status)))
        (is (= 1 (gethash "numberReady" status)))
        (is (= 1 (gethash "numberAvailable" status)))
        (is (= 1 (gethash "updatedNumberScheduled" status)))
        (is (= 0 (gethash "numberUnavailable" status))))
      (setf (gr8s::node-record-labels (gr8s:get-node store "node-a")) (gr8s::core-object "color" "green"))
      (run-workload-passes reconciler)
      (is (null (live-pods store "alpha")))
      (is (= 0 (gethash "desiredNumberScheduled" (workload-status store "daemonsets" "ds")))))))

(test daemonset-replaces-deleted-and-failed-pods-and-removes-extras
  (with-temporary-store (store path)
    (register-test-nodes store "node-a")
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (owner (gr8s::create-core-resource store "daemonsets" (daemonset-fixture "ds") "alpha")))
      (run-workload-passes reconciler)
      (let ((first-pod (first (live-pods store "alpha"))))
        (is (= 1 (length (live-pods store "alpha"))))
        (is (gr8s::workload-owned-p (pod-to-object first-pod) owner))
        (is (equal "node-a" (gr8s::pod-node-name first-pod)))
        (gr8s::delete-reconciled-pod reconciler "alpha" (pod-name first-pod) :uid (pod-uid first-pod))
        (run-workload-passes reconciler 4)
        (is (= 1 (length (live-pods store "alpha"))))
        (is (not (equal (pod-uid first-pod) (pod-uid (first (live-pods store "alpha")))))))
      (let ((pod (first (live-pods store "alpha"))))
        (gr8s::save-pod-client-status store pod (gr8s::core-object "phase" "Failed"))
        (is (equal "Failed" (gethash "phase" (gr8s::workload-pod-status reconciler pod))))
        (run-workload-passes reconciler 4)
        (is (= 1 (length (live-pods store "alpha"))))
        (is (not (equal (pod-uid pod) (pod-uid (first (live-pods store "alpha"))))))))))

(test daemonset-rolls-within-max-unavailable-and-records-history
  (with-temporary-store (store path)
    (register-test-nodes store "node-a" "node-b")
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "daemonsets" (daemonset-fixture "ds") "alpha")
      (run-workload-passes reconciler)
      (mark-all-pods-ready store runtime "alpha")
      (run-workload-passes reconciler)
      (let* ((revisions (gr8s::list-core-resources store "controllerrevisions" "alpha"))
             (first-revision (first revisions)))
        (is (= 1 (length revisions)))
        (is (= 1 (gethash "revision" first-revision)))
        (is (every (lambda (pod) (equal (gethash "controller-revision-hash" (gethash "labels" (gethash "metadata" (pod-to-object pod))))
                                        (gr8s::daemonset-revision-label first-revision)))
                   (live-pods store "alpha")))
        (let ((before (mapcar #'pod-uid (live-pods store "alpha"))))
          (gr8s::update-core-resource store "daemonsets" "alpha" "ds"
            (lambda (object)
              (setf (gethash "image" (aref (gethash "containers" (gethash "spec" (gethash "template" (gethash "spec" object)))) 0)) "agnhost:2.55")
              object))
          (gr8s::reconcile-workloads reconciler)
          ;; Both old Pods are available, and only one may go at a time.
          (is (= 1 (count-if (lambda (pod) (member (pod-uid pod) before :test #'equal)) (live-pods store "alpha"))))
          (is (= 2 (length (gr8s::list-core-resources store "controllerrevisions" "alpha"))))
          (dotimes (index 8)
            (mark-all-pods-ready store runtime "alpha")
            (run-workload-passes reconciler 2))
          (is (= 2 (length (live-pods store "alpha"))))
          (is (null (intersection before (mapcar #'pod-uid (live-pods store "alpha")) :test #'equal)))
          (is (every (lambda (pod) (equal "agnhost:2.55" (gethash "image" (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0))))
                     (live-pods store "alpha")))
          (is (= 2 (gethash "updatedNumberScheduled" (workload-status store "daemonsets" "ds"))))
          (is (= 2 (reduce #'max (gr8s::list-core-resources store "controllerrevisions" "alpha")
                           :key (lambda (revision) (gethash "revision" revision))))))))))

(test daemonset-on-delete-keeps-pods-until-they-are-deleted
  (with-temporary-store (store path)
    (register-test-nodes store "node-a")
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "daemonsets"
                                  (daemonset-fixture "ds" :strategy (gr8s::core-object "type" "OnDelete")) "alpha")
      (run-workload-passes reconciler)
      (let ((uid (pod-uid (first (live-pods store "alpha")))))
        (gr8s::update-core-resource store "daemonsets" "alpha" "ds"
          (lambda (object)
            (setf (gethash "image" (aref (gethash "containers" (gethash "spec" (gethash "template" (gethash "spec" object)))) 0)) "agnhost:2.55")
            object))
        (run-workload-passes reconciler)
        (is (equal uid (pod-uid (first (live-pods store "alpha")))))
        (is (= 2 (length (gr8s::list-core-resources store "controllerrevisions" "alpha"))))
        (is (= 0 (gethash "updatedNumberScheduled" (workload-status store "daemonsets" "ds"))))))))

(test daemonset-history-keeps-a-client-duplicate-and-does-not-restart-pods-for-it
  (with-temporary-store (store path)
    (register-test-nodes store "node-a")
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (owner (gr8s::create-core-resource store "daemonsets" (daemonset-fixture "ds") "alpha")))
      (run-workload-passes reconciler)
      (let* ((uid (pod-uid (first (live-pods store "alpha"))))
             (initial (first (gr8s::list-core-resources store "controllerrevisions" "alpha")))
             (labels (gr8s::copy-core-object (gethash "labels" (gethash "metadata" initial)))))
        (setf (gethash "controller-revision-hash" labels) "clientmade")
        (gr8s::create-core-resource
         store "controllerrevisions"
         (gr8s::core-object "apiVersion" "apps/v1" "kind" "ControllerRevision"
                            "metadata" (gr8s::core-object "name" "ds-clientmade" "labels" labels
                                                          "ownerReferences" (vector (gr8s::workload-owner-reference owner)))
                            "data" (gr8s::copy-core-object (gethash "data" initial)) "revision" 2)
         "alpha")
        (run-workload-passes reconciler)
        (is (= 2 (length (gr8s::list-core-resources store "controllerrevisions" "alpha"))))
        (is (equal uid (pod-uid (first (live-pods store "alpha")))))
        (is (= 1 (gethash "updatedNumberScheduled" (workload-status store "daemonsets" "ds"))))
        (signals kubernetes-error
          (gr8s::update-core-resource store "controllerrevisions" "alpha" "ds-clientmade"
            (lambda (object) (setf (gethash "data" object) (gr8s::core-object "changed" t)) object)))))))

(test daemonset-counts-a-revision-name-collision-and-recovers
  (with-temporary-store (store path)
    (register-test-nodes store "node-a")
    (let* ((reconciler (make-reconciler store (make-fake-runtime)))
           (owner (gr8s::create-core-resource store "daemonsets" (daemonset-fixture "ds") "alpha"))
           (hash (gr8s::daemonset-revision-hash (gr8s::daemonset-revision-data owner) 0)))
      (gr8s::create-core-resource
       store "controllerrevisions"
       (gr8s::core-object "apiVersion" "apps/v1" "kind" "ControllerRevision" "revision" 1
                          "metadata" (gr8s::core-object "name" (format nil "ds-~A" hash) "labels" (gr8s::core-object "other" "thing"))
                          "data" (gr8s::core-object "unrelated" t))
       "alpha")
      (run-workload-passes reconciler 2)
      (is (= 1 (gethash "collisionCount" (workload-status store "daemonsets" "ds"))))
      (is (= 2 (length (gr8s::list-core-resources store "controllerrevisions" "alpha"))))
      (is (= 1 (length (live-pods store "alpha")))))))

(test daemonset-foreground-deletion-removes-pods-and-revisions-first
  (with-temporary-store (store path)
    (register-test-nodes store "node-a")
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)))
      (gr8s::create-core-resource store "daemonsets" (daemonset-fixture "ds") "alpha")
      (run-workload-passes reconciler)
      (gr8s::delete-workload-resource store "daemonsets" "alpha" "ds" :policy "Foreground")
      (is (gethash "deletionTimestamp" (gethash "metadata" (gr8s::get-core-resource store "daemonsets" "alpha" "ds"))))
      (run-workload-passes reconciler 6)
      (is (null (list-pods store "alpha")))
      (is (null (gr8s::list-core-resources store "controllerrevisions" "alpha")))
      (is (null (gr8s::list-core-resources store "daemonsets" "alpha"))))))

(test foreground-deletion-keeps-a-dependent-another-owner-still-holds
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (leaving (gr8s::create-core-resource store "replicationcontrollers" (rc-fixture "leaving" 2) "alpha"))
           (staying (gr8s::create-core-resource store "replicationcontrollers" (rc-fixture "staying" 0) "alpha")))
      (run-workload-passes reconciler)
      (let* ((pod (first (list-pods store "alpha"))) (object (gr8s::copy-core-object (pod-to-object pod)))
             (metadata (gethash "metadata" object)))
        (setf (gethash "ownerReferences" metadata)
              (concatenate 'vector (gethash "ownerReferences" metadata)
                           (vector (gr8s::core-object "apiVersion" "v1" "kind" "ReplicationController" "name" "staying"
                                                      "uid" (gethash "uid" (gethash "metadata" staying))))))
        (update-pod store (parse-pod object) (pod-resource-version pod))
        (gr8s::delete-workload-resource store "replicationcontrollers" "alpha" "leaving"
                                        :uid (gethash "uid" (gethash "metadata" leaving)) :policy "Foreground")
        (run-workload-passes reconciler 6)
        (signals kubernetes-error (gr8s::get-core-resource store "replicationcontrollers" "alpha" "leaving"))
        (let ((remaining (list-pods store "alpha")))
          (is (= 1 (length remaining)))
          (is (equal (pod-uid pod) (pod-uid (first remaining))))
          (is (not (gr8s::deletion-requested-p (first remaining))))
          (is (= 1 (length (gethash "ownerReferences" (gethash "metadata" (pod-to-object (first remaining))))))))))))

(test foreground-pod-deletion-resolves-a-dependency-cycle
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (pods (loop for name in '("pod1" "pod2" "pod3")
                       collect (create-pod store (parse-pod (gr8s::core-object
                                                             "apiVersion" "v1" "kind" "Pod"
                                                             "metadata" (gr8s::core-object "name" name "namespace" "alpha")
                                                             "spec" (gr8s::core-object "nodeName" "gr8s-local" "terminationGracePeriodSeconds" 0
                                                                     "containers" (vector (gr8s::core-object "name" "main" "image" "busybox:1.36.1")))))))))
      (loop for pod in pods for owner in (list (third pods) (first pods) (second pods))
            do (let* ((object (gr8s::copy-core-object (pod-to-object (get-pod store "alpha" (pod-name pod))))))
                 (setf (gethash "ownerReferences" (gethash "metadata" object))
                       (vector (gr8s::core-object "apiVersion" "v1" "kind" "Pod" "name" (pod-name owner) "uid" (pod-uid owner)
                                                  "controller" t "blockOwnerDeletion" t)))
                 (update-pod store (parse-pod object) (pod-resource-version (get-pod store "alpha" (pod-name pod))))))
      (is (gr8s::hold-pod-for-foreground-deletion store "alpha" "pod1" (pod-uid (first pods))))
      (is (not (gr8s::deletion-requested-p (get-pod store "alpha" "pod1"))))
      (run-workload-passes reconciler 8)
      (is (null (list-pods store "alpha")))
      (is (zerop (hash-table-count (gr8s::pod-store-workload-deletions store)))))))

(test node-labels-are-written-durably-and-unenforceable-changes-refused
  (with-core-api (store path)
    (register-test-nodes store "node-a")
    (let* ((item "/api/v1/nodes/node-a") (node (check-core-status 200 item))
           (labels (gethash "labels" (gethash "metadata" node))))
      (is (equal "node-a" (gethash "kubernetes.io/hostname" labels)))
      (setf (gethash "daemonset-color" labels) "blue")
      (let ((updated (check-core-status 200 item :method :put :object node)))
        (is (equal "blue" (gethash "daemonset-color" (gethash "labels" (gethash "metadata" updated))))))
      (is (equal "blue" (gethash "daemonset-color" (gr8s::node-labels (gr8s:get-node (open-store path) "node-a")))))
      ;; The old resourceVersion no longer applies.
      (check-core-status 409 item :method :put :object node)
      (let ((patch (gr8s::core-object "metadata" (gr8s::core-object "labels" (gr8s::core-object "daemonset-color" "green")))))
        (check-core-status 200 item :method :patch :content-type "application/merge-patch+json" :object patch))
      (is (equal "green" (gethash "daemonset-color" (gr8s::node-labels (gr8s:get-node store "node-a")))))
      (check-core-status 422 item :method :patch :content-type "application/merge-patch+json"
                         :object (gr8s::core-object "spec" (gr8s::core-object "unschedulable" t)))
      (check-core-status 422 item :method :patch :content-type "application/merge-patch+json"
                         :object (gr8s::core-object "spec" (gr8s::core-object "taints" (vector (gr8s::core-object "key" "a" "effect" "NoSchedule")))))
      (check-core-status 422 item :method :patch :content-type "application/merge-patch+json"
                         :object (gr8s::core-object "metadata" (gr8s::core-object "labels" (gr8s::core-object "kubernetes.io/os" "plan9")))))))

(test controller-revision-http-lifecycle-and-daemonset-patch-tolerates-unknown-fields
  (with-core-api (store path)
    (let* ((daemonsets "/apis/apps/v1/namespaces/alpha/daemonsets")
           (revisions "/apis/apps/v1/namespaces/alpha/controllerrevisions")
           (revision (gr8s::core-object "metadata" (gr8s::core-object "name" "one" "labels" (gr8s::core-object "keep" "me"))
                                        "data" (gr8s::core-object "b" 1 "a" 2) "revision" 1)))
      (check-core-status 201 daemonsets :method :post :object (daemonset-fixture "ds"))
      (let ((names (map 'list (lambda (resource) (gethash "name" resource))
                        (gethash "resources" (check-core-status 200 "/apis/apps/v1")))))
        (is (member "daemonsets/status" names :test #'equal))
        (is (member "controllerrevisions" names :test #'equal))
        (is (not (member "daemonsets/scale" names :test #'equal))))
      (check-core-status 404 (concatenate 'string daemonsets "/ds/scale"))
      (check-core-status 201 revisions :method :post :object revision)
      ;; Kubernetes keeps a revision's data bytes exactly as written.
      (is (search "\"data\":{\"b\":1,\"a\":2}"
                  (com.inuoe.jzon:stringify (gr8s::get-core-resource store "controllerrevisions" "alpha" "one"))))
      (check-core-status 200 (concatenate 'string revisions "/one") :method :patch
                         :content-type "application/strategic-merge-patch+json"
                         :object (gr8s::core-object "metadata" (gr8s::core-object "labels" (gr8s::core-object "patched" "yes"))))
      (check-core-status 200 revisions :method :delete :parameters '(("labelSelector" . "patched=yes")))
      (check-core-status 404 (concatenate 'string revisions "/one"))
      ;; Upstream's ControllerRevision spec sends a misplaced top-level field.
      (let ((patched (check-core-status 200 (concatenate 'string daemonsets "/ds") :method :patch
                                        :content-type "application/strategic-merge-patch+json"
                                        :object (gr8s::core-object "spec" (gr8s::core-object "minReadySeconds" 1)
                                                                   "updateStrategy" (gr8s::core-object "type" "RollingUpdate")))))
        (is (= 1 (gethash "minReadySeconds" (gethash "spec" patched))))
        (is (null (nth-value 1 (gethash "updateStrategy" patched)))))
      (check-core-status 422 (concatenate 'string daemonsets "/ds") :method :patch
                         :parameters '(("fieldValidation" . "Strict"))
                         :content-type "application/strategic-merge-patch+json"
                         :object (gr8s::core-object "updateStrategy" (gr8s::core-object "type" "RollingUpdate"))))))

(test authenticated-accounts-may-read-openapi-documents
  ;; kubectl fetches these to validate manifests, whatever its account may do otherwise.
  (dolist (path '("/openapi/v2" "/openapi/v3" "/openapi/v3/api/v1" "/openapi/v3/apis/apps/v1"))
    (is (gr8s::authenticated-discovery-request-p path :get)))
  (is (not (gr8s::authenticated-discovery-request-p "/openapi/v3/api/v1" :post)))
  (is (not (gr8s::authenticated-discovery-request-p "/openapi/secrets" :get))))
