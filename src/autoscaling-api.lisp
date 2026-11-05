;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve HorizontalPodAutoscalers in autoscaling/v1 and v2 from one stored v2
;;;; form, and describe the built-in API versions as read-only APIServices.
;;;; No controller acts on an autoscaler yet, so its status stays empty and the
;;;; target's replica count never changes; aggregation of external API servers is
;;;; not implemented, which is why APIServices cannot be written.

(in-package #:gr8s)

(eval-when (:load-toplevel :execute)
  (setf *stored-resource-types*
        (append (remove "horizontalpodautoscalers" *stored-resource-types* :key #'first :test #'equal)
                '(("horizontalpodautoscalers" "HorizontalPodAutoscaler" "autoscaling/v2" t)))))

(defparameter +hpa-v2-spec-fields+ '("scaleTargetRef" "minReplicas" "maxReplicas" "metrics" "behavior")
  "Fields of an autoscaling/v2 spec.")

(defparameter +hpa-v1-spec-fields+ '("scaleTargetRef" "minReplicas" "maxReplicas" "targetCPUUtilizationPercentage")
  "Fields of an autoscaling/v1 spec.")

(defun hpa-resource-p (resource)
  "Recognize the stored autoscaler collection."
  (equal resource "horizontalpodautoscalers"))

(defun hpa-cpu-metric (utilization)
  "Express a v1 CPU utilization target as a v2 metric."
  (core-object "type" "Resource"
               "resource" (core-object "name" "cpu"
                                       "target" (core-object "type" "Utilization" "averageUtilization" utilization))))

(defun hpa-metric-cpu-utilization (metric)
  "Return METRIC's CPU utilization target, or NIL when it has another form."
  (let* ((resource (and (hash-table-p metric) (equal "Resource" (gethash "type" metric)) (gethash "resource" metric)))
         (target (and (hash-table-p resource) (equal "cpu" (gethash "name" resource)) (gethash "target" resource))))
    (and (hash-table-p target) (equal "Utilization" (gethash "type" target)) (gethash "averageUtilization" target))))

(defun hpa-v2-from-v1 (object)
  "Convert a v1 autoscaler's spec to its stored v2 form in place."
  (let* ((spec (gethash "spec" object)) (utilization (gethash "targetCPUUtilizationPercentage" spec)))
    (remhash "targetCPUUtilizationPercentage" spec)
    (when (integerp utilization)
      (setf (gethash "metrics" spec) (vector (hpa-cpu-metric utilization))))
    object))

(defun hpa-v1-view (object)
  "Project a stored autoscaler into autoscaling/v1, which can express only a CPU target."
  (let* ((copy (copy-core-object object)) (spec (gethash "spec" copy))
         (utilization (some #'hpa-metric-cpu-utilization (gethash "metrics" spec #()))))
    (dolist (field '("metrics" "behavior")) (remhash field spec))
    (when utilization (setf (gethash "targetCPUUtilizationPercentage" spec) utilization))
    (setf (gethash "apiVersion" copy) "autoscaling/v1")
    copy))

(defun hpa-api-view (input)
  "Project autoscalers, lists and watch envelopes into autoscaling/v1."
  (cond
    ((not (hash-table-p input)) input)
    ((equal "HorizontalPodAutoscaler" (gethash "kind" input)) (hpa-v1-view input))
    ((equal "HorizontalPodAutoscalerList" (gethash "kind" input))
     (let ((object (copy-core-object input)))
       (setf (gethash "apiVersion" object) "autoscaling/v1"
             (gethash "items" object) (map 'vector #'hpa-api-view (gethash "items" input)))
       object))
    ((gethash "object" input)
     (let ((object (copy-core-object input)))
       (setf (gethash "object" object) (hpa-api-view (gethash "object" input)))
       object))
    (t input)))

(defun hpa-replica-bound (spec field minimum)
  "Require FIELD of SPEC, when present, to be a 32-bit count of at least MINIMUM."
  (multiple-value-bind (value present) (gethash field spec)
    (when (and present (not (typep value `(integer ,minimum ,(1- (expt 2 31))))))
      (core-resource-error 422 "Invalid" "spec.~A: must be an integer of at least ~D" field minimum))
    value))

(defun validate-hpa-spec (spec)
  "Check what Kubernetes requires of an autoscaler's target and replica range."
  (let ((target (gethash "scaleTargetRef" spec)))
    (unless (hash-table-p target)
      (core-resource-error 422 "Invalid" "spec.scaleTargetRef: Required value"))
    (dolist (field '("kind" "name"))
      (unless (and (stringp (gethash field target)) (plusp (length (gethash field target))))
        (core-resource-error 422 "Invalid" "spec.scaleTargetRef.~A: Required value" field))))
  (unless (nth-value 1 (gethash "maxReplicas" spec))
    (core-resource-error 422 "Invalid" "spec.maxReplicas: Required value"))
  (let ((minimum (hpa-replica-bound spec "minReplicas" 0))
        (maximum (hpa-replica-bound spec "maxReplicas" 1)))
    (when (and (integerp minimum) (> minimum maximum))
      (core-resource-error 422 "Invalid" "spec.maxReplicas: must be greater than or equal to minReplicas")))
  (let ((metrics (gethash "metrics" spec)))
    (when metrics
      (unless (and (crd-array-p metrics) (every #'hash-table-p metrics))
        (core-resource-error 422 "Invalid" "spec.metrics: must be an array of objects"))
      (loop for metric across metrics for index from 0
            unless (member (gethash "type" metric) '("Object" "Pods" "Resource" "ContainerResource" "External") :test #'equal)
              do (core-resource-error 422 "Invalid" "spec.metrics[~D].type: Unsupported value" index)))))

(defun normalize-hpa-resource (input namespace name store)
  "Validate an autoscaler in either version, store it as v2 and keep status server-owned."
  (let* ((object (copy-core-object (require-object input "HorizontalPodAutoscaler")))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (version (or *core-resource-view-version* "autoscaling/v2"))
         (v1 (equal version "autoscaling/v1"))
         (spec (require-object (gethash "spec" object) "spec"))
         (existing (and store name (gethash (core-resource-key "horizontalpodautoscalers" namespace name) (pod-store-resources store)))))
    (unless (and (equal version (gethash "apiVersion" object version))
                 (equal "HorizontalPodAutoscaler" (gethash "kind" object "HorizontalPodAutoscaler")))
      (core-resource-error 400 "BadRequest" "Expected ~A HorizontalPodAutoscaler" version))
    (validate-core-metadata metadata namespace name)
    (pod-generate-name-prefix metadata)
    (let ((unknown (loop for key being the hash-keys of spec
                         unless (member key (if v1 +hpa-v1-spec-fields+ +hpa-v2-spec-fields+) :test #'equal)
                           collect key)))
      (report-field-problems (mapcar (lambda (key) (format nil "unknown field \"spec.~A\"" key)) unknown))
      (dolist (key unknown) (remhash key spec)))
    (when v1 (hpa-v2-from-v1 object))
    (unless (nth-value 1 (gethash "minReplicas" spec)) (setf (gethash "minReplicas" spec) 1))
    (unless (gethash "metrics" spec) (setf (gethash "metrics" spec) (vector (hpa-cpu-metric 80))))
    (validate-hpa-spec spec)
    (setf (gethash "apiVersion" object) "autoscaling/v2"
          (gethash "kind" object) "HorizontalPodAutoscaler"
          (gethash "namespace" metadata) namespace
          (gethash "generation" metadata)
          (cond ((null existing) 1)
                ((crd-json-equal-p spec (gethash "spec" existing)) (gethash "generation" (gethash "metadata" existing) 1))
                (t (1+ (gethash "generation" (gethash "metadata" existing) 1)))))
    (remhash "status" object)
    (setf (gethash "status" object)
          (if existing (copy-core-object (gethash "status" existing (core-object))) (core-object "currentReplicas" 0 "desiredReplicas" 0)))
    object))

(defun autoscaling-api-group ()
  "Describe the autoscaling group, preferring v2 as Kubernetes does."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "autoscaling"
               "versions" (vector (core-object "groupVersion" "autoscaling/v2" "version" "v2")
                                  (core-object "groupVersion" "autoscaling/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "autoscaling/v2" "version" "v2")))

(defun autoscaling-discovery-response (version)
  "Advertise the autoscaler collection in VERSION, v1 or v2."
  (let ((resources (stored-resource-discovery "autoscaling/v2")))
    (loop for resource across resources do (setf (gethash "shortNames" resource) #("hpa")))
    (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList"
                                "groupVersion" (format nil "autoscaling/~A" version)
                                "resources" resources))))

(defun apiservice-api-group ()
  "Describe the apiregistration.k8s.io group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "apiregistration.k8s.io"
               "versions" (vector (core-object "groupVersion" "apiregistration.k8s.io/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "apiregistration.k8s.io/v1" "version" "v1")))

(defun apiservice-discovery-response ()
  "Advertise APIServices as read-only, since nothing can be registered."
  (json-response
   (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "apiregistration.k8s.io/v1"
                "resources" (vector (core-object "name" "apiservices" "singularName" "apiservice" "namespaced" nil
                                                 "kind" "APIService" "categories" #("api-extensions")
                                                 "verbs" #("get" "list"))))))

(defun local-apiservices (store)
  "Describe each API version this server serves itself as an available local APIService."
  (let* ((groups (gethash "groups" (com.inuoe.jzon:parse (api-groups-response store))))
         (versions (cons (cons "" "v1")
                         (loop for group across groups
                               append (loop for version across (gethash "versions" group)
                                            collect (cons (gethash "name" group) (gethash "version" version)))))))
    (loop for (group . version) in versions
          for name = (if (equal group "") version (format nil "~A.~A" version group))
          collect (core-object "apiVersion" "apiregistration.k8s.io/v1" "kind" "APIService"
                               "metadata" (core-object "name" name)
                               "spec" (core-object "group" group "version" version
                                                   "groupPriorityMinimum" 1000 "versionPriority" 100)
                               "status" (core-object "conditions"
                                                     (vector (core-object "type" "Available" "status" "True" "reason" "Local"
                                                                          "message" "Local APIServices are always available")))))))

(defun apiservice-route (path)
  "Recognize the APIService collection and items, returning the name if any and T."
  (let ((prefix "/apis/apiregistration.k8s.io/v1/apiservices"))
    (cond ((equal path prefix) (values nil t))
          ((uiop:string-prefix-p (concatenate 'string prefix "/") path)
           (values (subseq path (1+ (length prefix))) t)))))

(defun apiservice-response (store name method)
  "Serve reads of local APIServices and refuse registration, which needs an aggregator."
  (unless (eq method :get)
    (core-resource-error 405 "MethodNotAllowed" "API aggregation is not implemented, so APIServices are read-only"))
  (let ((services (local-apiservices store)))
    (if name
        (json-response (or (find name services :test #'equal :key (lambda (service) (gethash "name" (gethash "metadata" service))))
                           (core-resource-error 404 "NotFound" "apiservices.apiregistration.k8s.io ~S not found" name)))
        (json-response (core-object "apiVersion" "apiregistration.k8s.io/v1" "kind" "APIServiceList"
                                    "metadata" (core-object "resourceVersion" (write-to-string (pod-store-resource-revision store)))
                                    "items" (coerce services 'vector))))))
