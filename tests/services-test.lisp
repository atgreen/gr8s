;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify durable Service IP allocation and immutable identities, namespace-
;;;; scoped endpoint selection, and real TCP forwarding including client half-close.

(in-package #:gr8s/tests)
(def-suite services :in gr8s)
(in-suite services)

(defun service-test-object (name &optional (target 80))
  "Create a simple selector-based TCP ClusterIP Service request."
  (gr8s::core-object "apiVersion" "v1" "kind" "Service"
                     "metadata" (gr8s::core-object "name" name)
                     "spec" (gr8s::core-object "selector" (gr8s::core-object "app" "web")
                                               "ports" (vector (gr8s::core-object "port" 8080 "targetPort" target)))))

(test services-allocate-durably-without-consuming-dry-run-addresses
  (with-temporary-store (store directory)
    (let* ((one (gr8s::create-core-resource store "services" (service-test-object "one") "alpha"))
           (two (gr8s::create-core-resource store "services" (service-test-object "two") "beta")))
      (is (equal "10.96.0.10" (gethash "clusterIP" (gethash "spec" one))))
      (is (equal "10.96.0.11" (gethash "clusterIP" (gethash "spec" two))))
      (let ((reopened (open-store directory)))
        (let* ((preview (gr8s::create-core-resource reopened "services" (service-test-object "preview") "alpha" :dry-run t))
               (three (gr8s::create-core-resource reopened "services" (service-test-object "three") "alpha")))
          (is (equal "10.96.0.12" (gethash "clusterIP" (gethash "spec" preview))))
          (is (equal "10.96.0.12" (gethash "clusterIP" (gethash "spec" three))))
          (is (= 3 (length (gr8s::list-core-resources reopened "services"))))))
      (let ((duplicate (service-test-object "duplicate")))
        (setf (gethash "clusterIP" (gethash "spec" duplicate)) "10.96.0.10")
        (signals kubernetes-error (gr8s::create-core-resource store "services" duplicate "alpha")))
      (signals kubernetes-error
        (gr8s::update-core-resource store "services" "alpha" "one"
          (lambda (object) (setf (gethash "clusterIP" (gethash "spec" object)) "10.96.0.20") object)))
      (is (equal "10.96.0.10" (gethash "clusterIP" (gethash "spec" (gr8s::get-core-resource store "services" "alpha" "one"))))))))

(test services-resolve-only-live-matching-pods-in-their-namespace
  (with-temporary-store (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "worker-id" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" (get-universal-time))
    (let ((service (gr8s::create-core-resource store "services" (service-test-object "web" "http") "alpha")))
      (dolist (namespace '("alpha" "beta"))
        (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
               (metadata (gethash "metadata" object))
               (container (aref (gethash "containers" (gethash "spec" object)) 0)))
          (setf (gethash "namespace" metadata) namespace
                (gethash "labels" metadata) (gr8s::core-object "app" "web")
                (gethash "ports" container) (vector (gr8s::core-object "name" "http" "containerPort" 7777)))
          (let ((pod (create-pod store (parse-pod object))))
            (gr8s::persist-pod-assignment store pod "worker-a")
            (gr8s::update-pod-observed-status store pod
             (gr8s::core-object "phase" "Running" "podIP" "192.0.2.5"
                                "conditions" (vector (gr8s::core-object "type" "Ready" "status" "True")))))))
      (let ((port (aref (gethash "ports" (gethash "spec" service)) 0)))
        (is (equal '(("192.0.2.5" 7777)) (gr8s::service-pod-endpoints store service port)))
        (let* ((pod (get-pod store "alpha" "hello"))
               (status (gr8s::copy-core-object (gr8s::pod-observed-status store pod))))
          (setf (gethash "status" (aref (gethash "conditions" status) 0)) "False")
          (gr8s::update-pod-observed-status store pod status)
          (is (null (gr8s::service-pod-endpoints store service port)))
          (setf (gethash "status" (aref (gethash "conditions" status) 0)) "True")
          (gr8s::update-pod-observed-status store pod status))
        (gr8s::mark-pod-deleting store "alpha" "hello")
        (is (null (gr8s::service-pod-endpoints store service port)))))))
