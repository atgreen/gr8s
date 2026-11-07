;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve Kubernetes resource metrics from the node summaries gr8s already
;;;; collects, without deploying or proxying a metrics-server Pod.

(in-package #:gr8s.apiserver)

(defparameter +resource-metrics-version+ "metrics.k8s.io/v1beta1")
(defparameter +resource-metrics-window+ "10s")

(defun resource-metrics-api-group ()
  "Describe the native metrics.k8s.io group."
  (let ((version (core-object "groupVersion" +resource-metrics-version+ "version" "v1beta1")))
    (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "metrics.k8s.io"
                 "versions" (vector version) "preferredVersion" version
                 "serverAddressByClientCIDRs" #())))

(defun resource-metrics-discovery-object ()
  "Describe the read-only NodeMetrics and PodMetrics resources."
  (core-object
   "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" +resource-metrics-version+
   "resources"
   (vector
    (core-object "name" "nodes" "singularName" "" "namespaced" nil
                 "kind" "NodeMetrics" "verbs" #("get" "list"))
    (core-object "name" "pods" "singularName" "" "namespaced" t
                 "kind" "PodMetrics" "verbs" #("get" "list")))))

(defun resource-metrics-quantity (value suffix)
  "Render integer VALUE as a Kubernetes resource.Quantity with SUFFIX."
  (and value (format nil "~D~A" value suffix)))

(defun usage-resource-list (cpu memory)
  "Build the ResourceList represented by CPU and MEMORY summary objects."
  (let ((usage (core-object)))
    (when cpu
      (let ((value (gethash "usageNanoCores" cpu)))
        (when value (setf (gethash "cpu" usage) (resource-metrics-quantity value "n")))))
    (when memory
      (let ((value (gethash "workingSetBytes" memory)))
        (when value (setf (gethash "memory" usage) (resource-metrics-quantity value "")))))
    usage))

(defun usage-timestamp (&rest measurements)
  "Return the newest timestamp among non-NIL summary MEASUREMENTS."
  (let ((times (remove nil (mapcar (lambda (measurement)
                                     (and measurement (gethash "time" measurement)))
                                   measurements))))
    (if times (reduce (lambda (left right) (if (string< left right) right left)) times) "")))

(defun node-metrics-from-summary (summary)
  "Translate one kubelet stats SUMMARY into a metrics.k8s.io NodeMetrics."
  (let* ((node (gethash "node" summary))
         (cpu (and node (gethash "cpu" node)))
         (memory (and node (gethash "memory" node))))
    (when node
      (core-object
       "apiVersion" +resource-metrics-version+ "kind" "NodeMetrics"
       "metadata" (core-object "name" (gethash "nodeName" node))
       "timestamp" (usage-timestamp cpu memory)
       "window" +resource-metrics-window+
       "usage" (usage-resource-list cpu memory)))))

(defun pod-container-metrics (container)
  "Translate one container from a kubelet stats summary into ContainerMetrics."
  (let ((cpu (gethash "cpu" container)) (memory (gethash "memory" container)))
    (core-object "name" (gethash "name" container)
                 "usage" (usage-resource-list cpu memory))))

(defun pod-metrics-from-summary (summary)
  "Translate one kubelet stats SUMMARY into its vector of PodMetrics."
  (map 'vector
       (lambda (pod)
         (let* ((reference (gethash "podRef" pod))
                (containers (gethash "containers" pod #()))
                (measurements
                  (loop for container across containers
                        append (list (gethash "cpu" container) (gethash "memory" container)))))
           (core-object
            "apiVersion" +resource-metrics-version+ "kind" "PodMetrics"
            "metadata" (core-object "name" (gethash "name" reference)
                                    "namespace" (gethash "namespace" reference))
            "timestamp" (apply #'usage-timestamp measurements)
            "window" +resource-metrics-window+
            "containers" (map 'vector #'pod-container-metrics containers))))
       (gethash "pods" summary #())))

(defun container-metrics-from-summary (summary)
  "Adapt SUMMARY to the cumulative per-container map the HPA sampler consumes."
  (let ((metrics (make-hash-table :test #'equal)))
    (loop for pod across (gethash "pods" summary #())
          for reference = (gethash "podRef" pod)
          for uid = (gethash "uid" reference)
          for containers = (make-hash-table :test #'equal)
          when uid
            do (loop for container across (gethash "containers" pod #())
                     for cpu = (gethash "cpu" container)
                     for memory = (gethash "memory" container)
                     do (setf (gethash (gethash "name" container) containers)
                              (core-object "cpu" (or (and cpu (gethash "usageCoreNanoSeconds" cpu)) 0)
                                           "memory" (or (and memory (gethash "workingSetBytes" memory)) 0))))
               (setf (gethash uid metrics) containers))
    metrics))

(defun metrics-source-labels (store metrics)
  "Return labels of the Node or Pod represented by METRICS in STORE."
  (let* ((metadata (gethash "metadata" metrics))
         (name (gethash "name" metadata))
         (namespace (gethash "namespace" metadata)))
    (cond
      (namespace
       (let ((pod (ignore-errors (get-pod store namespace name))))
         (and pod (pod-object-labels (pod-to-object pod)))))
      (t
       (let ((node (find name (list-nodes store) :key #'node-record-name :test #'equal)))
         (and node (node-record-labels node)))))))

(defun decorate-resource-metrics (store metrics)
  "Copy METRICS and attach its source resource labels for selector semantics."
  (let* ((copy (copy-core-object metrics))
         (metadata (copy-core-object (gethash "metadata" copy)))
         (labels (metrics-source-labels store metrics)))
    (when labels (setf (gethash "labels" metadata) (copy-core-object labels)))
    (setf (gethash "metadata" copy) metadata)
    copy))

(defun select-resource-metrics (objects label-selector field-selector)
  "Filter OBJECTS by Kubernetes label and metadata field selectors."
  (let ((labels (core-selector-predicate label-selector))
        (fields (core-selector-predicate field-selector :fields t)))
    (remove-if-not (lambda (object) (and (funcall labels object) (funcall fields object))) objects)))

(defun resource-metrics-objects (store summaries resource)
  "Build decorated RESOURCE metrics from every node SUMMARY."
  (let ((objects
          (if (equal resource "nodes")
              (loop for summary across summaries
                    for metrics = (node-metrics-from-summary summary)
                    when metrics collect metrics)
              (loop for summary across summaries
                    append (coerce (pod-metrics-from-summary summary) 'list)))))
    (mapcar (lambda (metrics) (decorate-resource-metrics store metrics)) objects)))

(defun metrics-list-object (resource items)
  "Wrap ITEMS in the appropriate resource metrics list."
  (core-object "apiVersion" +resource-metrics-version+
               "kind" (if (equal resource "nodes") "NodeMetricsList" "PodMetricsList")
               "metadata" (core-object) "items" (coerce items 'vector)))

(defun resource-metrics-object
    (store summaries path method &key label-selector field-selector)
  "Answer one native resource-metrics PATH as a Kubernetes object."
  (unless (member method '(:get :head))
    (core-resource-error 405 "MethodNotAllowed" "Resource metrics are read-only"))
  (let* ((parts (remove "" (uiop:split-string path :separator '(#\/)) :test #'equal))
         (tail (nthcdr 3 parts))
         (namespaced (equal "namespaces" (first tail)))
         (namespace (and namespaced (second tail)))
         (resource (if namespaced (third tail) (first tail)))
         (name (if namespaced (fourth tail) (second tail))))
    (unless (member resource '("nodes" "pods") :test #'equal)
      (core-resource-error 404 "NotFound" "Resource metrics route not found"))
    (when (and namespaced (not (equal resource "pods")))
      (core-resource-error 404 "NotFound" "Only PodMetrics are namespaced"))
    (let* ((objects (resource-metrics-objects store summaries resource))
           (scoped (if namespace
                       (remove namespace objects :test-not #'equal
                               :key (lambda (object) (table-get object "metadata" "namespace")))
                       objects))
           (selected (select-resource-metrics scoped label-selector field-selector)))
      (if name
          (or (find name selected :test #'equal
                    :key (lambda (object) (table-get object "metadata" "name")))
              (core-resource-error 404 "NotFound" "~A.metrics.k8s.io ~S not found" resource name))
          (metrics-list-object resource selected)))))
