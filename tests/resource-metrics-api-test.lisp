;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the native metrics.k8s.io API objects built from the same node
;;;; statistics that back the kubelet resource metrics and HPA controller.

(in-package #:gr8s/tests)

(def-suite resource-metrics-api :in gr8s)
(in-suite resource-metrics-api)

(defun resource-metrics-test-summary ()
  "Return one node summary with one two-container Pod."
  (gr8s::core-object
   "node" (gr8s::core-object
           "nodeName" "node-a"
           "cpu" (gr8s::core-object "time" "2026-11-07T18:00:00Z" "usageNanoCores" 750000000)
           "memory" (gr8s::core-object "time" "2026-11-07T18:00:00Z" "workingSetBytes" 314572800))
   "pods" (vector
           (gr8s::core-object
            "podRef" (gr8s::core-object "namespace" "alpha" "name" "web" "uid" "uid-web")
            "containers" (vector
                          (gr8s::core-object
                           "name" "app"
                           "cpu" (gr8s::core-object "time" "2026-11-07T18:00:01Z"
                                                    "usageNanoCores" 250000000
                                                    "usageCoreNanoSeconds" 9000000000)
                           "memory" (gr8s::core-object "time" "2026-11-07T18:00:01Z"
                                                       "workingSetBytes" 104857600))
                          (gr8s::core-object
                           "name" "sidecar"
                           "cpu" (gr8s::core-object "time" "2026-11-07T18:00:02Z"
                                                    "usageNanoCores" 50000000
                                                    "usageCoreNanoSeconds" 3000000000)
                           "memory" (gr8s::core-object "time" "2026-11-07T18:00:02Z"
                                                       "workingSetBytes" 20971520)))))))

(test node-and-pod-metrics-use-standard-resource-quantities
  (let* ((summary (resource-metrics-test-summary))
         (node (gr8s.apiserver::node-metrics-from-summary summary))
         (pod (first (coerce (gr8s.apiserver::pod-metrics-from-summary summary) 'list))))
    (is (equal "metrics.k8s.io/v1beta1" (gethash "apiVersion" node)))
    (is (equal "NodeMetrics" (gethash "kind" node)))
    (is (equal "node-a" (gr8s::table-get node "metadata" "name")))
    (is (equal "750000000n" (gr8s::table-get node "usage" "cpu")))
    (is (equal "314572800" (gr8s::table-get node "usage" "memory")))
    (is (equal "10s" (gethash "window" node)))
    (is (equal "PodMetrics" (gethash "kind" pod)))
    (is (equal "alpha" (gr8s::table-get pod "metadata" "namespace")))
    (is (equal '("app" "sidecar")
               (map 'list (lambda (container) (gethash "name" container))
                    (gethash "containers" pod))))
    (is (equal "250000000n" (gr8s::table-get (aref (gethash "containers" pod) 0) "usage" "cpu")))
    (is (equal "104857600" (gr8s::table-get (aref (gethash "containers" pod) 0) "usage" "memory")))
    ;; The newest container sample timestamps the Pod, as metrics-server does.
    (is (equal "2026-11-07T18:00:02Z" (gethash "timestamp" pod)))))

(test a-node-summary-still-feeds-the-existing-hpa-sampler
  (let* ((summary (resource-metrics-test-summary))
         (metrics (gr8s.apiserver::container-metrics-from-summary summary))
         (containers (gethash "uid-web" metrics)))
    (is (= 9000000000 (gr8s::table-get containers "app" "cpu")))
    (is (= 104857600 (gr8s::table-get containers "app" "memory")))
    (is (= 3000000000 (gr8s::table-get containers "sidecar" "cpu")))))

(test resource-metrics-discovery-is-a-native-read-only-api
  (let* ((group (gr8s.apiserver::resource-metrics-api-group))
         (discovery (gr8s.apiserver::resource-metrics-discovery-object))
         (resources (gethash "resources" discovery)))
    (is (equal "metrics.k8s.io" (gethash "name" group)))
    (is (equal "v1beta1" (gr8s::table-get group "preferredVersion" "version")))
    (is (equal '("nodes" "pods")
               (map 'list (lambda (resource) (gethash "name" resource)) resources)))
    (is (every (lambda (resource)
                 (equalp #("get" "list") (gethash "verbs" resource)))
               resources))))

(test resource-metrics-list-get-and-select-like-kubernetes-resources
  (with-temporary-store (store path)
    (values path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-a" :name "node-a" :pod-cidr "10.88.0.0/24"
                                  :labels (gr8s::core-object "zone" "east")))
    (let ((summaries (vector (resource-metrics-test-summary))))
      (flet ((request (path &key labels fields)
               (gr8s.apiserver::resource-metrics-object
                store summaries path :get :label-selector labels :field-selector fields)))
        (is (= 1 (length (gethash "items" (request "/apis/metrics.k8s.io/v1beta1/nodes")))))
        (is (equal "node-a" (gr8s::table-get
                             (request "/apis/metrics.k8s.io/v1beta1/nodes/node-a")
                             "metadata" "name")))
        (is (= 0 (length (gethash "items"
                                  (request "/apis/metrics.k8s.io/v1beta1/nodes" :labels "zone=west")))))
        (is (= 1 (length (gethash "items"
                                  (request "/apis/metrics.k8s.io/v1beta1/nodes" :labels "zone=east")))))
        (is (= 0 (length (gethash "items"
                                  (request "/apis/metrics.k8s.io/v1beta1/nodes"
                                           :fields "metadata.name=other")))))
        (is (= 1 (length (gethash "items"
                                  (request "/apis/metrics.k8s.io/v1beta1/namespaces/alpha/pods")))))
        (is (equal "web" (gr8s::table-get
                          (request "/apis/metrics.k8s.io/v1beta1/namespaces/alpha/pods/web")
                          "metadata" "name")))
        (is (= 1 (length (gethash "items"
                                  (request "/apis/metrics.k8s.io/v1beta1/pods")))))))))

(test native-resource-metrics-routes-are-discoverable-and-authorized-as-resources
  (with-core-api (store path)
    (values store path)
    (let ((groups (check-core-status 200 "/apis")))
      (is (find "metrics.k8s.io" (gethash "groups" groups)
                :test #'equal :key (lambda (group) (gethash "name" group)))))
    (is (equal "metrics.k8s.io"
               (gethash "name" (check-core-status 200 "/apis/metrics.k8s.io"))))
    (is (equal "metrics.k8s.io/v1beta1"
               (gethash "groupVersion"
                        (check-core-status 200 "/apis/metrics.k8s.io/v1beta1"))))
    (is (equal "NodeMetricsList"
               (gethash "kind"
                        (check-core-status 200 "/apis/metrics.k8s.io/v1beta1/nodes"))))
    (is (equal "PodMetricsList"
               (gethash "kind"
                        (check-core-status 200 "/apis/metrics.k8s.io/v1beta1/pods"))))
    (is (= 404 (nth-value 1 (core-api-request
                              "/apis/metrics.k8s.io/v1beta1/namespaces/alpha/pods/missing")))))
  (is (equal '("list" "metrics.k8s.io" "nodes" nil nil)
             (multiple-value-list
              (gr8s::kubernetes-authorization-target
               "/apis/metrics.k8s.io/v1beta1/nodes" :get))))
  (is (equal '("get" "metrics.k8s.io" "pods" "web" "alpha")
             (multiple-value-list
              (gr8s::kubernetes-authorization-target
               "/apis/metrics.k8s.io/v1beta1/namespaces/alpha/pods/web" :get)))))
