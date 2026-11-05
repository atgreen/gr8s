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
