;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify the autoscaler's replica arithmetic, stabilization and rate policies, and
;;;; that it scales a real ReplicaSet from reported container usage and reports honest
;;;; conditions for metrics this cluster cannot measure.

(in-package #:gr8s/tests)

(def-suite hpa-controller :in gr8s)
(in-suite hpa-controller)

(test hpa-replica-count-follows-the-upstream-calculation
  (flet ((ratio (entries) (/ (loop for (nil . usage) in entries sum usage) (length entries) 50)))
    ;; Twice the target on two ready Pods means four.
    (is (= 4 (gr8s::hpa-replica-count 2 2 #'ratio '((a . 100) (b . 100)) nil nil (constantly 50))))
    ;; Close enough to the target changes nothing.
    (is (= 2 (gr8s::hpa-replica-count 2 2 #'ratio '((a . 52) (b . 52)) nil nil (constantly 50))))
    ;; A scale-up does not count a Pod that has not reported, as if it used nothing.
    (is (= 3 (gr8s::hpa-replica-count 3 2 #'ratio '((a . 75) (b . 75)) '(c) nil (constantly 50))))
    ;; An unready Pod counts as idle on the way up, which can cancel a small rise.
    (is (= 3 (gr8s::hpa-replica-count 3 2 #'ratio '((a . 60) (b . 60)) nil '(c) (constantly 50))))
    ;; A scale-down assumes a silent Pod is at its fallback, keeping the change cautious.
    (is (= 3 (gr8s::hpa-replica-count 3 2 #'ratio '((a . 25) (b . 25)) '(c) nil (constantly 100))))))

(test hpa-stabilization-holds-back-a-flapping-recommendation
  (let ((history '((100 . 5) (90 . 8))))
    ;; Scaling down is held to the highest recent recommendation.
    (is (= 8 (gr8s::hpa-stabilized history 3 8 0 300 110)))
    ;; Out of the window, the lower recommendation stands.
    (is (= 3 (gr8s::hpa-stabilized history 3 8 0 5 200)))
    ;; A scale-up waits for the lowest recommendation in its window.
    (is (= 5 (gr8s::hpa-stabilized history 10 4 60 0 110)))
    (is (= 10 (gr8s::hpa-stabilized history 10 4 0 0 110)))))

(test hpa-rate-policies-limit-how-far-one-period-moves
  (flet ((rules (select &rest policies)
           (gr8s::core-object "selectPolicy" select
                              "policies" (map 'vector (lambda (policy)
                                                        (gr8s::core-object "type" (first policy) "value" (second policy)
                                                                           "periodSeconds" 60))
                                              policies))))
    (is (= 6 (gr8s::hpa-rate-limit (rules "Max" '("Pods" 1) '("Percent" 100)) :up 3 nil nil 100)))
    (is (= 4 (gr8s::hpa-rate-limit (rules "Min" '("Pods" 1) '("Percent" 100)) :up 3 nil nil 100)))
    ;; What this period already added uses up the allowance.
    (is (= 5 (gr8s::hpa-rate-limit (rules "Max" '("Pods" 1)) :up 5 '((90 . 1)) nil 100)))
    (is (= 6 (gr8s::hpa-rate-limit (rules "Max" '("Pods" 1)) :up 5 '((10 . 1)) nil 100)))
    (is (= 4 (gr8s::hpa-rate-limit (rules "Max" '("Percent" 50)) :down 8 nil nil 100)))
    (is (= 7 (gr8s::hpa-rate-limit (rules "Min" '("Pods" 1) '("Percent" 50)) :down 8 nil nil 100)))
    (is (= 8 (gr8s::hpa-rate-limit (rules "Disabled" '("Pods" 1)) :up 8 nil nil 100)))))

(defun hpa-test-replicaset (replicas &optional (cpu "100m"))
  "Build a ReplicaSet of Pods that each request CPU."
  (gr8s::core-object
   "apiVersion" "apps/v1" "kind" "ReplicaSet" "metadata" (gr8s::core-object "name" "web")
   "spec" (gr8s::core-object
           "replicas" replicas
           "selector" (gr8s::core-object "matchLabels" (gr8s::core-object "app" "web"))
           "template" (gr8s::core-object
                       "metadata" (gr8s::core-object "labels" (gr8s::core-object "app" "web"))
                       "spec" (gr8s::core-object
                               "nodeName" "gr8s-local"
                               "containers" (vector (gr8s::core-object
                                                     "name" "main" "image" "busybox:1.36.1"
                                                     "resources" (gr8s::core-object
                                                                  "requests" (gr8s::core-object "cpu" cpu)))))))))

(defun hpa-test-autoscaler (&rest fields)
  "Build an autoscaler of the ReplicaSet web with FIELDS in its spec."
  (let ((spec (gr8s::core-object
               "scaleTargetRef" (gr8s::core-object "apiVersion" "apps/v1" "kind" "ReplicaSet" "name" "web")
               "minReplicas" 1 "maxReplicas" 5
               "metrics" (vector (gr8s::hpa-cpu-metric 50)))))
    (loop for (key value) on fields by #'cddr do (setf (gethash key spec) value))
    (gr8s::core-object "apiVersion" "autoscaling/v2" "kind" "HorizontalPodAutoscaler"
                       "metadata" (gr8s::core-object "name" "web") "spec" spec)))

(defun hpa-test-condition (store type)
  "Return the autoscaler's condition TYPE."
  (find type (gethash "conditions" (gethash "status" (gr8s::get-core-resource store "horizontalpodautoscalers" "alpha" "web")) #())
        :test #'equal :key (lambda (condition) (gethash "type" condition))))

(defun hpa-test-usage (state store cpu-seconds time)
  "Feed one sample in which every Pod has used CPU-SECONDS of CPU in all."
  (let ((metrics (make-hash-table :test #'equal)))
    (dolist (pod (list-pods store "alpha"))
      (let ((containers (make-hash-table :test #'equal)))
        (setf (gethash "main" containers)
              (gr8s::core-object "cpu" (* cpu-seconds 1000000000) "memory" 1000)
              (gethash (pod-uid pod) metrics) containers)))
    (gr8s::record-hpa-samples state metrics time)))

(test hpa-scales-a-real-replicaset-from-reported-usage
  (with-temporary-store (store path)
    (values path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (state (gr8s::hpa-state-for store)) (now 1000000)
           (gr8s::*workload-clock* (lambda () now)))
      (gr8s::create-core-resource store "replicasets" (hpa-test-replicaset 1) "alpha")
      (gr8s::create-core-resource store "horizontalpodautoscalers" (hpa-test-autoscaler) "alpha")
      (run-workload-passes reconciler 2)
      (mark-workload-pods-ready store runtime)
      (let* ((hpa (first (gr8s::list-core-resources store "horizontalpodautoscalers" "alpha")))
             (sync (lambda ()
                     (gr8s::sync-horizontal-pod-autoscaler
                      reconciler state (gr8s::get-core-resource store "horizontalpodautoscalers" "alpha" "web") now))))
        (values hpa)
        ;; With no measures yet the autoscaler says so and leaves the target alone.
        (funcall sync)
        (is (equal "False" (gethash "status" (hpa-test-condition store "ScalingActive"))))
        (is (equal "FailedGetResourceMetric" (gethash "reason" (hpa-test-condition store "ScalingActive"))))
        (is (= 1 (gethash "replicas" (gethash "spec" (gr8s::get-core-resource store "replicasets" "alpha" "web")))))
        ;; 200m on a 100m request at a 50% target asks for four Pods.
        (hpa-test-usage state store 0 now)
        (incf now 15)
        (hpa-test-usage state store 3 now)
        (funcall sync)
        (is (equal "ValidMetricFound" (gethash "reason" (hpa-test-condition store "ScalingActive"))))
        (is (= 4 (gethash "replicas" (gethash "spec" (gr8s::get-core-resource store "replicasets" "alpha" "web")))))
        (let ((status (gethash "status" (gr8s::get-core-resource store "horizontalpodautoscalers" "alpha" "web"))))
          (is (= 4 (gethash "desiredReplicas" status)))
          (is (gethash "lastScaleTime" status))
          (is (= 200 (gethash "averageUtilization"
                              (gethash "current" (gethash "resource" (aref (gethash "currentMetrics" status) 0)))))))))))

(test hpa-reads-the-resource-metrics-api-when-one-is-registered
  (with-temporary-store (store path)
    (values path)
    (let* ((runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (state (gr8s::hpa-state-for store)) (now 1000000) (answer nil) (asked nil)
           (gr8s::*workload-clock* (lambda () now))
           (gr8s::*hpa-pod-metrics-reader* (lambda (store namespace)
                                             (declare (ignore store))
                                             (push namespace asked)
                                             answer)))
      (gr8s::create-core-resource store "replicasets" (hpa-test-replicaset 1) "alpha")
      (gr8s::create-core-resource store "horizontalpodautoscalers" (hpa-test-autoscaler) "alpha")
      (gr8s::create-core-resource
       store "apiservices"
       (com.inuoe.jzon:parse "{\"apiVersion\":\"apiregistration.k8s.io/v1\",\"kind\":\"APIService\",
          \"metadata\":{\"name\":\"v1beta1.metrics.k8s.io\"},
          \"spec\":{\"group\":\"metrics.k8s.io\",\"version\":\"v1beta1\",\"insecureSkipTLSVerify\":true,
                  \"groupPriorityMinimum\":100,\"versionPriority\":100,
                  \"service\":{\"namespace\":\"kube-system\",\"name\":\"metrics-server\",\"port\":443}}}")
       nil)
      (run-workload-passes reconciler 2)
      (mark-workload-pods-ready store runtime)
      (flet ((sync ()
               (gr8s::sync-horizontal-pod-autoscaler
                reconciler state (gr8s::get-core-resource store "horizontalpodautoscalers" "alpha" "web") now)))
        ;; An unreachable metrics server is the reason given, as upstream's controller gives it.
        (setf answer "unable to fetch metrics from resource metrics API: the server is currently unable to handle the request")
        (sync)
        (is (equal "FailedGetResourceMetric" (gethash "reason" (hpa-test-condition store "ScalingActive"))))
        (is (search "unable to get metrics for resource cpu: unable to fetch metrics from resource metrics API"
                    (gethash "message" (hpa-test-condition store "ScalingActive"))))
        (is (equal '("alpha") asked))
        ;; Its PodMetrics, 200m on a 100m request at a 50% target, ask for four Pods.
        (setf answer (gr8s::pod-metrics-usage-table
                      (gr8s::core-object
                       "items" (map 'vector (lambda (pod)
                                             (gr8s::core-object
                                              "metadata" (gr8s::core-object "name" (pod-name pod) "namespace" "alpha")
                                              "timestamp" "2026-11-05T00:00:00Z" "window" "15s"
                                              "containers" (vector (gr8s::core-object
                                                                    "name" "main"
                                                                    "usage" (gr8s::core-object "cpu" "200000000n"
                                                                                               "memory" "1024Ki")))))
                                    (list-pods store "alpha")))))
        (incf now 15)
        (sync)
        (is (equal "ValidMetricFound" (gethash "reason" (hpa-test-condition store "ScalingActive"))))
        (is (= 4 (gethash "replicas" (gethash "spec" (gr8s::get-core-resource store "replicasets" "alpha" "web")))))
        ;; The controller takes no samples of its own meanwhile.
        (is (zerop (hash-table-count (gr8s::hpa-state-samples state))))))))

(test hpa-reports-metrics-it-cannot-measure-and-disabled-targets
  (with-temporary-store (store path)
    (values path)
    (let* ((reconciler (make-reconciler store (make-fake-runtime))) (state (gr8s::hpa-state-for store)))
      (gr8s::create-core-resource store "replicasets" (hpa-test-replicaset 1) "alpha")
      (gr8s::create-core-resource
       store "horizontalpodautoscalers"
       (hpa-test-autoscaler "metrics" (vector (gr8s::core-object
                                               "type" "External"
                                               "external" (gr8s::core-object
                                                           "metric" (gr8s::core-object "name" "queue")
                                                           "target" (gr8s::core-object "type" "Value" "value" "1")))))
       "alpha")
      (flet ((sync ()
               (gr8s::sync-horizontal-pod-autoscaler
                reconciler state (gr8s::get-core-resource store "horizontalpodautoscalers" "alpha" "web") 2000000)))
        (sync)
        (is (equal "FailedGetExternalMetric" (gethash "reason" (hpa-test-condition store "ScalingActive"))))
        (is (= 1 (gethash "replicas" (gethash "spec" (gr8s::get-core-resource store "replicasets" "alpha" "web")))))
        (gr8s::update-core-resource store "replicasets" "alpha" "web"
          (lambda (object) (setf (gethash "replicas" (gethash "spec" object)) 0) object))
        (sync)
        (is (equal "ScalingDisabled" (gethash "reason" (hpa-test-condition store "ScalingActive"))))
        (gr8s::delete-core-resource store "replicasets" "alpha" "web")
        (sync)
        (is (equal "FailedGetScale" (gethash "reason" (hpa-test-condition store "AbleToScale"))))))))

(test hpa-decodes-from-kubernetes-protobuf
  (let* ((reference (core-test-protobuf '((1 "ReplicaSet") (2 "web") (3 "apps/v1"))))
         (target (core-test-protobuf (list (list 1 "Utilization") (list 4 50))))
         (source (core-test-protobuf (list (list 1 "cpu") (list 2 target))))
         (metric (core-test-protobuf (list (list 1 "Resource") (list 4 source))))
         (spec (core-test-protobuf (list (list 1 reference) (list 2 1) (list 3 5) (list 4 metric))))
         (metadata (core-test-protobuf '((1 "web"))))
         (input (core-test-protobuf-envelope "HorizontalPodAutoscaler" (list (list 1 metadata) (list 2 spec))
                                             "autoscaling/v2"))
         (object (gr8s::decode-core-resource-protobuf input "HorizontalPodAutoscaler"))
         (decoded (gethash "spec" object)))
    (is (equal "web" (gethash "name" (gethash "metadata" object))))
    (is (equal "ReplicaSet" (gethash "kind" (gethash "scaleTargetRef" decoded))))
    (is (= 5 (gethash "maxReplicas" decoded)))
    (is (= 50 (gr8s::hpa-metric-cpu-utilization (aref (gethash "metrics" decoded) 0))))))

(test hpa-status-subresource-is-served-in-both-versions
  ;; Upstream serves horizontalpodautoscalers/status in autoscaling/v1 and v2; the
  ;; 1.37 discovery fixture lists it, and status writers (the controller, kubectl)
  ;; must not be able to change the spec through it.
  (with-core-api (store directory)
    (values store directory)
    (dolist (version '("v1" "v2"))
      (let ((entry (discovery-entry (check-core-status 200 (format nil "/apis/autoscaling/~A" version))
                                    "horizontalpodautoscalers/status")))
        (is (hash-table-p entry) "~A lacks horizontalpodautoscalers/status" version)
        (is (equal '("get" "patch" "update") (coerce (gethash "verbs" entry) 'list)))))
    (check-core-status 201 "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers" :method :post
      :object (gr8s::core-object "apiVersion" "autoscaling/v2" "kind" "HorizontalPodAutoscaler"
                                 "metadata" (gr8s::core-object "name" "web")
                                 "spec" (gr8s::core-object "scaleTargetRef" (gr8s::core-object "apiVersion" "apps/v1" "kind" "ReplicaSet" "name" "web")
                                                           "maxReplicas" 5)))
    (let* ((v2 "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers/web/status")
           (v1 "/apis/autoscaling/v1/namespaces/default/horizontalpodautoscalers/web/status")
           (read (check-core-status 200 v2)))
      (is (equal "autoscaling/v2" (gethash "apiVersion" read)))
      ;; A status PUT changes the status and ignores a changed spec.
      (setf (gethash "desiredReplicas" (gethash "status" read)) 3
            (gethash "maxReplicas" (gethash "spec" read)) 9
            (gethash "conditions" (gethash "status" read))
            (vector (gr8s::core-object "type" "AbleToScale" "status" "True" "reason" "Test"
                                       "lastTransitionTime" "2026-01-01T00:00:00Z")))
      (let ((written (check-core-status 200 v2 :method :put :object read)))
        (is (= 3 (gethash "desiredReplicas" (gethash "status" written))))
        (is (= 5 (gethash "maxReplicas" (gethash "spec" written)))))
      ;; A stale write conflicts.
      (check-core-status 409 v2 :method :put :object read)
      ;; v1 shows and patches the same status, keeping the conditions it cannot express.
      (let ((patched (check-core-status 200 v1 :method :patch :content-type "application/merge-patch+json"
                                        :object (gr8s::core-object "status" (gr8s::core-object "currentReplicas" 2
                                                                                               "currentCPUUtilizationPercentage" 40)))))
        (is (equal "autoscaling/v1" (gethash "apiVersion" patched)))
        (is (= 40 (gethash "currentCPUUtilizationPercentage" (gethash "status" patched)))))
      (let ((stored (check-core-status 200 v2)))
        (is (= 2 (gethash "currentReplicas" (gethash "status" stored))))
        (is (= 1 (length (gethash "conditions" (gethash "status" stored)))))
        (is (= 40 (gethash "averageUtilization"
                           (gethash "current" (gethash "resource" (aref (gethash "currentMetrics" (gethash "status" stored)) 0)))))))
      (let ((patched (check-core-status 200 v2 :method :patch :content-type "application/json-patch+json"
                                        :object (vector (gr8s::core-object "op" "replace" "path" "/status/desiredReplicas" "value" 4)))))
        (is (= 4 (gethash "desiredReplicas" (gethash "status" patched))))))))

(test hpa-targets-print-as-kubectl-shows-them
  (flet ((targets (spec-metrics current &optional extra)
           (gr8s::table-hpa-targets
            (gr8s::core-object "spec" (let ((spec (gr8s::core-object "metrics" spec-metrics)))
                                        (loop for (key value) on extra by #'cddr do (setf (gethash key spec) value))
                                        spec)
                               "status" (gr8s::core-object "currentMetrics" current)))))
    (let ((cpu (gr8s::hpa-cpu-metric 50))
          (memory (gr8s::core-object "type" "Resource"
                                     "resource" (gr8s::core-object "name" "memory"
                                                                   "target" (gr8s::core-object "type" "AverageValue"
                                                                                               "averageValue" "64Mi"))))
          (external (gr8s::core-object "type" "External"
                                       "external" (gr8s::core-object "metric" (gr8s::core-object "name" "queue")
                                                                     "target" (gr8s::core-object "type" "Value" "value" "1")))))
      (is (equal "cpu: <unknown>/50%" (targets (vector cpu) #())))
      (is (equal "cpu: 286%/50%"
                 (targets (vector cpu)
                          (vector (gr8s::core-object "type" "Resource"
                                                     "resource" (gr8s::core-object "name" "cpu"
                                                                                   "current" (gr8s::core-object "averageUtilization" 286
                                                                                                                "averageValue" "285m")))))))
      (is (equal "cpu: <unknown>/50%, memory: <unknown>/64Mi" (targets (vector cpu memory) #())))
      (is (equal "cpu: <unknown>/50%, memory: <unknown>/64Mi + 1 more..." (targets (vector cpu memory external) #())))
      (is (equal "<unknown>/1" (targets (vector external) #())))
      (is (equal "<none>" (targets #() #())))
      ;; autoscaling/v1 objects carry only a CPU target.
      (is (equal "cpu: 30%/80%"
                 (gr8s::table-hpa-targets (gr8s::core-object "spec" (gr8s::core-object "targetCPUUtilizationPercentage" 80)
                                                             "status" (gr8s::core-object "currentCPUUtilizationPercentage" 30))))))))
