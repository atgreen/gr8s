;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Scale the targets of HorizontalPodAutoscalers from what containers actually use.
;;;; When an aggregated server provides the resource metrics API, as metrics-server
;;;; does, usage is read from its PodMetrics as upstream's controller reads it.
;;;; Otherwise nodes report CRI statistics, from which CPU rates are derived between
;;;; samples, so Resource and ContainerResource metrics work with no metrics server. There is no
;;;; custom or external metrics API, so those metric types report a failed
;;;; ScalingActive condition rather than scale on nothing. The replica arithmetic,
;;;; stabilization and rate policies follow the upstream controller.

(in-package #:gr8s)

(defparameter *hpa-sync-period* 15
  "Seconds between evaluations of one autoscaler, the upstream controller's default.")

(defparameter *hpa-sample-period* 5
  "Seconds between metric samples, so a CPU rate exists soon after an autoscaler appears.")

(defparameter *hpa-tolerance* 1/10
  "How far a usage ratio may stray from 1 before the replica count changes.")

(defparameter *hpa-cpu-initialization-period* 300
  "Seconds after a Pod starts during which only a ready Pod's CPU counts.")

(defparameter *hpa-initial-readiness-delay* 30
  "Seconds after a Pod starts during which turning unready is not taken for failing later.")

(defstruct hpa-state
  "What the controller remembers between passes; losing it on restart only restarts the windows."
  (samples (make-hash-table :test #'equal))
  (last-sample 0)
  (last-sync (make-hash-table :test #'equal))
  (recommendations (make-hash-table :test #'equal))
  (scale-up-events (make-hash-table :test #'equal))
  (scale-down-events (make-hash-table :test #'equal)))

(defvar *hpa-states* (make-hash-table :test #'eq :weakness :key :synchronized t)
  "Controller memory by store.")

(defun hpa-state-for (store)
  "Return STORE's controller memory, creating it on first use."
  (or (gethash store *hpa-states*) (setf (gethash store *hpa-states*) (make-hpa-state))))

;;; Samples

(defun record-hpa-samples (state metrics now)
  "Keep each container's recent samples from METRICS: uid to container to cpu seconds and memory."
  (maphash
   (lambda (uid containers)
     (maphash
      (lambda (name sample)
        (let ((key (cons uid name)))
          (push (list now (/ (gethash "cpu" sample 0) 1000000000) (gethash "memory" sample 0))
                (gethash key (hpa-state-samples state)))))
      containers))
   metrics)
  ;; Containers that stopped reporting age out with everything older than a useful window.
  (let ((oldest (- now 60)))
    (loop for key being the hash-keys of (hpa-state-samples state) using (hash-value samples)
          do (let ((kept (remove-if (lambda (sample) (< (first sample) oldest)) samples)))
               (if kept
                   (setf (gethash key (hpa-state-samples state)) kept)
                   (remhash key (hpa-state-samples state))))))
  (setf (hpa-state-last-sample state) now))

(defun hpa-container-usage (state uid container)
  "Return CONTAINER's CPU rate in cores and working set in bytes, or NIL before two samples exist.
The rate spans at least ten seconds where it can, and a counter that went back means a new attempt."
  (let* ((samples (gethash (cons uid container) (hpa-state-samples state))) (newest (first samples)))
    (when (cdr samples)
      (let* ((older (or (find-if (lambda (sample) (>= (- (first newest) (first sample)) 10)) samples)
                        (car (last samples))))
             (elapsed (- (first newest) (first older))) (used (- (second newest) (second older))))
        (when (and (plusp elapsed) (not (minusp used)))
          (values (/ used elapsed) (third newest)))))))

(defparameter +resource-metrics-apiservice+ "v1beta1.metrics.k8s.io"
  "The APIService through which a metrics server provides PodMetrics.")

(defvar *hpa-pod-metrics* nil
  "While one autoscaler is evaluated from the resource metrics API, its namespace's PodMetrics:
a table of Pod name to a table of container name to (cpu-cores . memory-bytes), or a string
saying why they could not be read. NIL means usage comes from the controller's own samples.")

(defun hpa-resource-metrics-apiservice (store)
  "Return the APIService of an aggregated resource metrics API, or NIL when none is registered."
  (let ((apiservice (stored-apiservice store +resource-metrics-apiservice+)))
    (and apiservice (apiservice-service apiservice) apiservice)))

(defun aggregated-api-get (store apiservice target)
  "GET TARGET from APIService's server as the controller manager and return the parsed object."
  (let ((aggregator (gethash store *aggregators*)) (socket nil))
    (unless (and aggregator (apiservice-available-p apiservice))
      (error "the server is currently unable to handle the request"))
    (unwind-protect
         (multiple-value-bind (connected stream) (aggregator-connect store apiservice aggregator)
           (setf socket connected)
           (let ((service (apiservice-service apiservice)))
             (sb-sys:with-deadline (:seconds 10)
               (aggregator-write-request
                stream :get target (format nil "~A.~A.svc:~D" (gethash "name" service) (gethash "namespace" service)
                                           (gethash "port" service))
                '(("Accept" . "application/json") ("User-Agent" . "kube-controller-manager/gr8s")
                  ("X-Remote-User" . "system:kube-controller-manager") ("X-Remote-Group" . "system:masters")
                  ("X-Remote-Group" . "system:authenticated"))
                #())
               (multiple-value-bind (code body) (admission-read-http-response stream)
                 (unless (<= 200 code 299)
                   (error "the server responded with HTTP ~D" code))
                 (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string body))))))
      (when socket (ignore-errors (usocket:socket-close socket))))))

(defun pod-metrics-usage-table (list)
  "Index a PodMetricsList by Pod name, each a table of container name to (cpu-cores . memory-bytes)."
  (let ((pods (make-hash-table :test #'equal)))
    (loop for item across (gethash "items" list #())
          for containers = (make-hash-table :test #'equal)
          do (loop for container across (gethash "containers" item #())
                   for usage = (gethash "usage" container (core-object))
                   do (setf (gethash (gethash "name" container) containers)
                            (cons (policy-value (gethash "cpu" usage "0")) (policy-value (gethash "memory" usage "0")))))
             (setf (gethash (table-get item "metadata" "name") pods) containers))
    pods))

(defun hpa-fetch-pod-metrics (store namespace)
  "Read NAMESPACE's PodMetrics from the resource metrics API, or the reason they can't be read."
  (let ((apiservice (hpa-resource-metrics-apiservice store)))
    (handler-case
        (let ((table (pod-metrics-usage-table
                      (aggregated-api-get store apiservice
                                          (format nil "/apis/metrics.k8s.io/v1beta1/namespaces/~A/pods" namespace)))))
          (if (plusp (hash-table-count table)) table "no metrics returned from resource metrics API"))
      ((or error sb-sys:deadline-timeout) (condition)
        (format nil "unable to fetch metrics from resource metrics API: ~A (get pods.metrics.k8s.io)"
                (remove #\Newline (princ-to-string condition)))))))

(defvar *hpa-pod-metrics-reader* 'hpa-fetch-pod-metrics
  "The function that reads a namespace's PodMetrics, given the store and namespace.")

(defun hpa-pod-usage (state pod resource container)
  "Return POD's use of RESOURCE, CPU in cores and memory in bytes, or NIL when any container lacks a measure."
  (let ((total 0)
        (reported (and (hash-table-p *hpa-pod-metrics*) (gethash (pod-name pod) *hpa-pod-metrics*))))
    (when (and (hash-table-p *hpa-pod-metrics*) (null reported))
      (return-from hpa-pod-usage nil))
    (loop for spec across (pod-containers pod)
          for name = (container-spec-name spec)
          do (when (or (null container) (equal name container))
               (multiple-value-bind (cpu memory)
                   (if reported
                       (let ((usage (gethash name reported))) (values (car usage) (cdr usage)))
                       (hpa-container-usage state (pod-uid pod) name))
                 (unless cpu (return-from hpa-pod-usage nil))
                 (incf total (if (equal resource "cpu") cpu memory)))))
    total))

(defun hpa-pod-request (pod resource container)
  "Return what POD's containers request of RESOURCE, or NIL when one requests none."
  (let ((total 0))
    (loop for object across (gethash "containers" (gethash "spec" (pod-to-object pod)))
          do (when (or (null container) (equal (gethash "name" object) container))
               (let ((request (gethash resource (container-resource-map object "requests"))))
                 (unless request (return-from hpa-pod-request nil))
                 (incf total (if (rationalp request) request (policy-value request))))))
    total))

;;; Replica arithmetic

(defun hpa-replica-count (current ready ratio-of-metrics metrics missing unready fallback)
  "Return the replicas a target should have, as the upstream replica calculator decides.
METRICS is an alist of (pod . usage) for READY Pods. MISSING and UNREADY list other Pods, and
FALLBACK gives what a missing Pod is assumed to use when scaling down."
  (let* ((ratio (funcall ratio-of-metrics metrics))
         (scale-up-with-unready (and unready (> ratio 1))))
    (when (and (not scale-up-with-unready) (null missing))
      (return-from hpa-replica-count
        (if (<= (abs (- 1 ratio)) *hpa-tolerance*) current (ceiling (* ratio ready)))))
    (let ((adjusted (copy-alist metrics)))
      (cond ((< ratio 1) (dolist (pod missing) (push (cons pod (funcall fallback pod)) adjusted)))
            ((> ratio 1) (dolist (pod missing) (push (cons pod 0) adjusted))))
      (when scale-up-with-unready
        (dolist (pod unready) (push (cons pod 0) adjusted)))
      (let ((new (funcall ratio-of-metrics adjusted)))
        (if (or (<= (abs (- 1 new)) *hpa-tolerance*)
                (and (< ratio 1) (> new 1))
                (and (> ratio 1) (< new 1)))
            current
            (let ((replicas (ceiling (* new (length adjusted)))))
              (if (or (and (< new 1) (> replicas current))
                      (and (> new 1) (< replicas current)))
                  current
                  replicas)))))))

(defun hpa-pod-unready-for-cpu-p (status now)
  "Decide whether POD's CPU should be left out, as a Pod that has not settled since it started."
  (let* ((ready (find-pod-condition (gethash "conditions" status) "Ready"))
         (start (ignore-errors (pod-deletion-time (gethash "startTime" status))))
         (changed (and ready (ignore-errors (pod-deletion-time (gethash "lastTransitionTime" ready)))))
         (true (and ready (equal "True" (gethash "status" ready)))))
    (cond ((or (null ready) (null start)) t)
          ((< now (+ start *hpa-cpu-initialization-period*)) (not true))
          (t (and (not true) changed (< changed (+ start *hpa-initial-readiness-delay*)))))))

(defun hpa-group-pods (reconciler state pods resource container now)
  "Sort POD into usable measures and the unready and missing Pods the calculation treats apart."
  (let ((metrics nil) (unready nil) (missing nil))
    (dolist (pod pods)
      (let ((status (workload-pod-status reconciler pod)))
        (cond
          ((or (deletion-requested-p pod) (equal "Failed" (gethash "phase" status))))
          ((equal "Pending" (gethash "phase" status)) (push pod unready))
          (t
           (let ((usage (hpa-pod-usage state pod resource container)))
             (cond ((null usage) (push pod missing))
                   ((and (equal resource "cpu") (hpa-pod-unready-for-cpu-p status now)) (push pod unready))
                   (t (push (cons pod usage) metrics))))))))
    (values metrics unready missing)))

(define-condition hpa-metric-failure (error)
  ((reason :initarg :reason :reader hpa-metric-failure-reason)
   (message :initarg :message :reader hpa-metric-failure-message)))

(defun hpa-metric-failure (reason control &rest arguments)
  "Give up on one metric, for the reason ScalingActive will report."
  (error 'hpa-metric-failure :reason reason :message (apply #'format nil control arguments)))

(defun hpa-resource-proposal (reconciler state metric current pods now)
  "Return the replicas one Resource or ContainerResource METRIC asks for and its currentMetrics entry."
  (let* ((type (gethash "type" metric))
         (container-metric (equal "ContainerResource" type))
         (source (gethash (if container-metric "containerResource" "resource") metric))
         (resource (gethash "name" source)) (target (gethash "target" source))
         (container (and container-metric (gethash "container" source)))
         (failure (if container-metric "FailedGetContainerResourceMetric" "FailedGetResourceMetric")))
    (unless pods (hpa-metric-failure failure "no pods returned by selector while calculating replica count"))
    (unless (member resource '("cpu" "memory") :test #'equal)
      (hpa-metric-failure failure "no metrics are measured for resource ~A" resource))
    (when (stringp *hpa-pod-metrics*)
      (hpa-metric-failure failure "unable to get metrics for resource ~A: ~A" resource *hpa-pod-metrics*))
    (multiple-value-bind (metrics unready missing) (hpa-group-pods reconciler state pods resource container now)
      (unless metrics
        (hpa-metric-failure failure "did not receive metrics for targeted pods (pods might be unready)"))
      (let* ((ready (length metrics))
             (utilization (gethash "averageUtilization" target))
             (value (and (not utilization) (policy-value (gethash "averageValue" target))))
             (requests (when utilization
                         (let ((table (make-hash-table :test #'eq)))
                           (dolist (pod pods table)
                             (setf (gethash pod table)
                                   (or (hpa-pod-request pod resource container)
                                       (hpa-metric-failure failure "missing request for ~A in container of pod ~A"
                                                           resource (pod-name pod))))))))
             (ratio (if utilization
                        (lambda (entries)
                          (let ((request (loop for (pod) in entries sum (gethash pod requests)))
                                (usage (loop for (nil . amount) in entries sum amount)))
                            (if (plusp request) (/ (* 100 (/ usage request)) utilization) 0)))
                        (lambda (entries)
                          (/ (/ (loop for (nil . amount) in entries sum amount) (length entries)) value))))
             (fallback (if utilization
                           (lambda (pod) (/ (* (gethash pod requests) (min 100 utilization)) 100))
                           (lambda (pod) (declare (ignore pod)) value)))
             (replicas (hpa-replica-count current ready ratio metrics missing unready fallback))
             (average (/ (loop for (nil . amount) in metrics sum amount) ready))
             (measured (if (equal resource "cpu")
                           (policy-value-string average)
                           (policy-value-string (ceiling average) :binary)))
             (observed (core-object "averageValue" measured)))
        (when utilization
          (setf (gethash "averageUtilization" observed)
                (ceiling (* 100 (/ (loop for (nil . amount) in metrics sum amount)
                                   (loop for (pod) in metrics sum (gethash pod requests)))))))
        (values replicas
                (core-object "type" type
                             (if container-metric "containerResource" "resource")
                             (let ((entry (core-object "name" resource "current" observed)))
                               (when container (setf (gethash "container" entry) container))
                               entry)))))))

;;; Stabilization and rate policies

(defun hpa-default-rules (direction)
  "Return the scaling rules Kubernetes applies in DIRECTION, :UP or :DOWN, without any behavior."
  (if (eq direction :up)
      (core-object "stabilizationWindowSeconds" 0 "selectPolicy" "Max"
                   "policies" (vector (core-object "type" "Pods" "value" 4 "periodSeconds" 15)
                                      (core-object "type" "Percent" "value" 100 "periodSeconds" 15)))
      (core-object "stabilizationWindowSeconds" 300 "selectPolicy" "Max"
                   "policies" (vector (core-object "type" "Percent" "value" 100 "periodSeconds" 15)))))

(defun hpa-scaling-rules (spec direction)
  "Return SPEC's scaling rules in DIRECTION with anything it leaves out defaulted."
  (let* ((behavior (gethash "behavior" spec))
         (rules (and behavior (gethash (if (eq direction :up) "scaleUp" "scaleDown") behavior)))
         (defaults (hpa-default-rules direction)))
    (if (null rules)
        defaults
        (let ((merged (copy-core-object defaults)))
          (dolist (field '("stabilizationWindowSeconds" "selectPolicy" "policies") merged)
            (when (nth-value 1 (gethash field rules))
              (setf (gethash field merged) (gethash field rules))))))))

(defun hpa-replicas-changed-in (events period now)
  "Sum the changes among EVENTS, each (time . count), within the last PERIOD seconds."
  (loop for (time . count) in events when (> time (- now period)) sum count))

(defun hpa-rate-limit (rules direction current up-events down-events now)
  "Return the furthest RULES let the replicas move from CURRENT in DIRECTION, given recent EVENTS."
  (if (equal "Disabled" (gethash "selectPolicy" rules))
      current
      (let* ((lowest-change (equal "Min" (gethash "selectPolicy" rules)))
             (proposals
               (map 'list
                    (lambda (policy)
                      (let* ((period (gethash "periodSeconds" policy)) (value (gethash "value" policy))
                             (start (+ (- current (hpa-replicas-changed-in up-events period now))
                                       (hpa-replicas-changed-in down-events period now))))
                        (if (eq direction :up)
                            (if (equal "Pods" (gethash "type" policy))
                                (+ start value)
                                (ceiling (* start (+ 1 (/ value 100)))))
                            (if (equal "Pods" (gethash "type" policy))
                                (- start value)
                                (floor (* start (- 1 (/ value 100))))))))
                    (gethash "policies" rules #()))))
        (if (eq direction :up)
            (reduce (if lowest-change #'min #'max) proposals)
            (reduce (if lowest-change #'max #'min) proposals)))))

(defun hpa-stabilized (recommendations proposed current up-window down-window now)
  "Return the recommendation after the windows: up to the lowest recent one, down to the highest."
  (let ((up proposed) (down proposed))
    (loop for (time . replicas) in recommendations
          do (when (> time (- now up-window)) (setf up (min up replicas)))
             (when (> time (- now down-window)) (setf down (max down replicas))))
    (let ((result current))
      (when (< result up) (setf result up))
      (when (> result down) (setf result down))
      result)))

(defun hpa-normalize-replicas (state key spec current proposed now)
  "Apply stabilization and rate limits to PROPOSED, returning the replicas and why they stopped there."
  (let* ((up-rules (hpa-scaling-rules spec :up)) (down-rules (hpa-scaling-rules spec :down))
         (up-window (gethash "stabilizationWindowSeconds" up-rules))
         (down-window (gethash "stabilizationWindowSeconds" down-rules))
         (history (gethash key (hpa-state-recommendations state)))
         (stabilized (hpa-stabilized history proposed current up-window down-window now))
         (up-events (gethash key (hpa-state-scale-up-events state)))
         (down-events (gethash key (hpa-state-scale-down-events state)))
         (minimum (gethash "minReplicas" spec 1)) (maximum (gethash "maxReplicas" spec)))
    (setf (gethash key (hpa-state-recommendations state))
          (cons (cons now proposed)
                (remove-if (lambda (entry) (<= (car entry) (- now (max up-window down-window)))) history)))
    (cond
      ((> stabilized current)
       (let* ((limit (max current (hpa-rate-limit up-rules :up current up-events down-events now)))
              (allowed (min maximum limit)))
         (if (> stabilized allowed)
             (if (< limit maximum)
                 (values allowed "ScaleUpLimit" "the desired replica count is increasing faster than the maximum scale rate")
                 (values allowed "TooManyReplicas" "the desired replica count is more than the maximum replica count"))
             (values stabilized "DesiredWithinRange" "the desired count is within the acceptable range"))))
      ((< stabilized current)
       (let* ((limit (min current (hpa-rate-limit down-rules :down current up-events down-events now)))
              (allowed (max minimum limit)))
         (if (< stabilized allowed)
             (if (> limit minimum)
                 (values allowed "ScaleDownLimit" "the desired replica count is decreasing faster than the maximum scale rate")
                 (values allowed "TooFewReplicas" "the desired replica count is less than the minimum replica count"))
             (values stabilized "DesiredWithinRange" "the desired count is within the acceptable range"))))
      (t (values stabilized "DesiredWithinRange" "the desired count is within the acceptable range")))))

(defun record-hpa-scale-event (state key from to now)
  "Remember a change of replicas so the rate policies can see it, forgetting what no policy could."
  (let* ((table (if (> to from) (hpa-state-scale-up-events state) (hpa-state-scale-down-events state)))
         (keep-since (- now 1800)))
    (setf (gethash key table)
          (cons (cons now (abs (- to from)))
                (remove-if (lambda (event) (<= (car event) keep-since)) (gethash key table))))))

;;; Status

(defun hpa-conditions (previous entries now)
  "Merge ENTRIES, each (type status reason message), keeping transition times of unchanged statuses."
  (let ((merged (map 'list #'identity previous)))
    (dolist (entry entries)
      (destructuring-bind (type status reason message) entry
        (let* ((old (find type merged :test #'equal :key (lambda (condition) (gethash "type" condition))))
               (same (and old (equal status (gethash "status" old)))))
          (setf merged (remove old merged))
          (setf merged
                (append merged
                        (list (core-object "type" type "status" status "reason" reason "message" message
                                           "lastTransitionTime"
                                           (if same (gethash "lastTransitionTime" old) (current-timestamp now)))))))))
    (coerce merged 'vector)))

(defun write-hpa-status (store hpa current desired metrics entries now scaled)
  "Publish an evaluation's observations through the same owner-checked path as other controllers."
  (let* ((previous (gethash "status" hpa (core-object)))
         (status (core-object "currentReplicas" current "desiredReplicas" desired
                              "observedGeneration" (gethash "generation" (workload-metadata hpa))
                              "currentMetrics" (coerce metrics 'vector)
                              "conditions" (hpa-conditions (gethash "conditions" previous #()) entries now))))
    (cond (scaled (setf (gethash "lastScaleTime" status) (current-timestamp now)))
          ((gethash "lastScaleTime" previous)
           (setf (gethash "lastScaleTime" status) (gethash "lastScaleTime" previous))))
    (update-workload-controller-status store "horizontalpodautoscalers" hpa status)))

;;; The controller

(defun hpa-target-resource (ref)
  "Return the stored collection SCALE-TARGET-REF names, if this server can scale it."
  (let ((type (find-if (lambda (type) (and (equal (gethash "kind" ref) (second type))
                                           (equal (gethash "apiVersion" ref) (third type))))
                       *stored-resource-types*)))
    (and type (member (first type) '("deployments" "replicasets" "replicationcontrollers" "statefulsets") :test #'equal)
         (first type))))

(defun hpa-custom-target (store ref namespace)
  "Resolve SCALE-TARGET-REF to a custom resource whose version serves the scale subresource.
Return its definition, the Scale its paths describe, and the scale paths of the stored version."
  (let* ((api-version (gethash "apiVersion" ref ""))
         (slash (position #\/ api-version))
         (group (and slash (subseq api-version 0 slash)))
         (version (and slash (subseq api-version (1+ slash))))
         (definition (and group
                          (find-if (lambda (definition)
                                     (let ((spec (gethash "spec" definition)))
                                       (and (equal group (gethash "group" spec))
                                            (equal (gethash "kind" ref) (gethash "kind" (gethash "names" spec))))))
                                   (list-core-resources store "customresourcedefinitions"))))
         (served (and definition (crd-version definition version :served t)))
         (scale (and served (gethash "scale" (gethash "subresources" served (core-object))))))
    (when (hash-table-p scale)
      (let ((object (handler-case (get-core-resource store (crd-custom-key definition) namespace (gethash "name" ref))
                      (kubernetes-error () nil))))
        (when object
          (let ((*crd-view-definition* definition) (*crd-request-version* version))
            (values definition
                    (crd-scale-view (crd-api-view object) definition)
                    (gethash "scale" (gethash "subresources" (crd-storage-version definition) (core-object))))))))))

(defun hpa-selected-pods (store selector namespace)
  "Return the Pods in NAMESPACE whose labels match the label selector string SELECTOR."
  (let ((predicate (core-selector-predicate selector)))
    (remove-if-not (lambda (pod) (funcall predicate (pod-to-object pod))) (list-pods store namespace))))

(defun hpa-target-pods (store target namespace)
  "Return the Pods TARGET's selector chooses."
  (let ((selector (workload-spec-selector target)))
    (remove-if-not (lambda (pod)
                     (workload-selector-matches-p selector (pod-object-labels (pod-to-object pod))))
                   (list-pods store namespace))))

(defun hpa-evaluate-metrics (reconciler state spec current pods now)
  "Return the largest replicas any metric asks for, currentMetrics, and the first failure's reason and message."
  (let ((proposal nil) (observed nil) (failure nil) (failed nil)
        (*hpa-pod-metrics*
          (and pods (hpa-resource-metrics-apiservice (reconciler-store reconciler))
               (some (lambda (metric) (member (gethash "type" metric) '("Resource" "ContainerResource") :test #'equal))
                     (gethash "metrics" spec #()))
               (funcall *hpa-pod-metrics-reader* (reconciler-store reconciler) (pod-namespace (first pods))))))
    (loop for metric across (gethash "metrics" spec #())
          do (handler-case
                 (let ((type (gethash "type" metric)))
                   (unless (member type '("Resource" "ContainerResource") :test #'equal)
                     (hpa-metric-failure (format nil "FailedGet~AMetric" type)
                                         "this cluster has no custom or external metrics API for a ~A metric" type))
                   (multiple-value-bind (replicas entry) (hpa-resource-proposal reconciler state metric current pods now)
                     (setf proposal (max (or proposal 0) replicas))
                     (push entry observed)))
               (hpa-metric-failure (condition)
                 (setf failed t)
                 (unless failure
                   (setf failure (cons (hpa-metric-failure-reason condition) (hpa-metric-failure-message condition)))))))
    ;; With a metric unknown it may want more than the others, so nothing scales down.
    (when (and failed proposal) (setf proposal (max proposal current)))
    (values proposal (nreverse observed) (car failure) (cdr failure))))

(defun sync-horizontal-pod-autoscaler (reconciler state hpa now)
  "Evaluate one autoscaler: read its target, weigh its metrics, scale, and report what happened."
  (let* ((store (reconciler-store reconciler)) (spec (gethash "spec" hpa)) (metadata (workload-metadata hpa))
         (namespace (gethash "namespace" metadata)) (key (gethash "uid" metadata))
         (ref (gethash "scaleTargetRef" spec)) (resource (hpa-target-resource ref))
         (minimum (gethash "minReplicas" spec 1)) (maximum (gethash "maxReplicas" spec))
         (target (when resource
                   (handler-case (get-core-resource store resource namespace (gethash "name" ref))
                     (kubernetes-error () nil))))
         (definition nil) (custom-scale nil) (scale-paths nil))
    ;; Anything else is read and scaled through its scale subresource, as upstream's controller does.
    (unless resource
      (multiple-value-setq (definition custom-scale scale-paths) (hpa-custom-target store ref namespace))
      (when custom-scale
        (setf target custom-scale resource (crd-custom-key definition))))
    (unless target
      (write-hpa-status store hpa 0 (gethash "desiredReplicas" (gethash "status" hpa (core-object)) 0) nil
                        (list (list "AbleToScale" "False" "FailedGetScale"
                                    (format nil "the HPA controller was unable to get the target's current scale: ~A ~A"
                                            (gethash "kind" ref) (gethash "name" ref))))
                        now nil)
      (return-from sync-horizontal-pod-autoscaler nil))
    (let* ((current (gethash "replicas" (gethash "spec" target) 0))
           (observed (gethash "replicas" (gethash "status" target (core-object)) 0))
           (desired current) (metrics nil) (entries nil)
           (able (list "AbleToScale" "True" "SucceededGetScale" "the HPA controller was able to get the target's current scale")))
      (cond
        ((and (zerop current) (plusp minimum))
         (setf desired 0)
         (push (list "ScalingActive" "False" "ScalingDisabled"
                     "scaling is disabled since the replica count of the target is zero")
               entries))
        ((> current maximum)
         (setf desired maximum)
         (push (list "ScalingLimited" "True" "TooManyReplicas" "the desired replica count is more than the maximum replica count") entries))
        ((< current minimum)
         (setf desired minimum)
         (push (list "ScalingLimited" "True" "TooFewReplicas" "the desired replica count is less than the minimum replica count") entries))
        ((and custom-scale (zerop (length (gethash "selector" (gethash "status" custom-scale) ""))))
         (push (list "ScalingActive" "False" "InvalidSelector" "selector is required") entries))
        (t
         (multiple-value-bind (proposal observed-metrics reason message)
             (hpa-evaluate-metrics reconciler state spec current
                                   (if custom-scale
                                       (hpa-selected-pods store (gethash "selector" (gethash "status" custom-scale) "") namespace)
                                       (hpa-target-pods store target namespace))
                                   now)
           (setf metrics observed-metrics)
           (if proposal
               (push (if reason
                         (list "ScalingActive" "False" reason message)
                         (list "ScalingActive" "True" "ValidMetricFound"
                               "the HPA was able to successfully calculate a replica count from the metrics"))
                     entries)
               (push (list "ScalingActive" "False" (or reason "FailedComputeMetricsReplicas")
                           (or message "the HPA has no metrics to evaluate"))
                     entries))
           (when proposal
             (multiple-value-bind (replicas limited why) (hpa-normalize-replicas state key spec current proposal now)
               (setf desired replicas)
               (push (list "ScalingLimited" (if (equal limited "DesiredWithinRange") "False" "True") limited why) entries))))))
      (let ((scaled (/= desired current)))
        (when scaled
          (setf able (list "AbleToScale" "True" "SucceededRescale"
                           (format nil "the HPA controller was able to update the target scale to ~D" desired)))
          (if custom-scale
              (update-owned-workload store resource target
                (lambda (object) (crd-write-json-path object (gethash "specReplicasPath" scale-paths) desired)))
              (update-owned-workload store resource target
                (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) desired) object)))
          (record-hpa-scale-event state key current desired now))
        (write-hpa-status store hpa observed desired metrics (cons able (reverse entries)) now scaled)))))

(defun reconcile-horizontal-pod-autoscalers (reconciler)
  "Sample what containers use while any autoscaler exists, and evaluate each one when it is due."
  (let* ((store (reconciler-store reconciler))
         (autoscalers (list-core-resources store "horizontalpodautoscalers")))
    (when autoscalers
      (let ((state (hpa-state-for store)) (now (funcall *workload-clock*)))
        ;; With a resource metrics API, its server measures usage instead.
        (when (and (>= (- now (hpa-state-last-sample state)) *hpa-sample-period*)
                   (not (hpa-resource-metrics-apiservice store)))
          (record-hpa-samples state (runtime-container-metrics (reconciler-runtime reconciler)) now))
        (dolist (hpa autoscalers)
          (let ((uid (gethash "uid" (workload-metadata hpa))))
            (when (>= (- now (gethash uid (hpa-state-last-sync state) 0)) *hpa-sync-period*)
              (setf (gethash uid (hpa-state-last-sync state)) now)
              (handler-case (sync-horizontal-pod-autoscaler reconciler state hpa now)
                (kubernetes-error (condition)
                  (unless (member (kubernetes-error-status-code condition) '(404 409))
                    (format *error-output* "gr8s HPA controller: ~A~%" condition)))
                (error (condition) (format *error-output* "gr8s HPA controller: ~A~%" condition))))))))))
