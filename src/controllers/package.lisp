;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for control-plane reconciliation loops.

(defpackage #:gr8s.controllers
  (:use #:cl)
  (:shadow
   #:+pod-certificate-request-beta-version+
   #:control-plane-runtime
   #:make-control-plane-runtime
   #:make-gateway-controller
   #:make-service-lb-controller
   #:reconcile-certificates
   #:reconcile-cronjobs
   #:reconcile-daemonset
   #:reconcile-disruption-budgets
   #:reconcile-endpoints
   #:reconcile-endpointslices
   #:reconcile-horizontal-pod-autoscalers
   #:reconcile-ingress-status
   #:reconcile-jobs
   #:reconcile-pod-certificate-requests
   #:reconcile-service-ip-addresses
   #:reconcile-service-load-balancer-status
   #:reconcile-statefulset
   #:reconcile-workloads
   #:schedule-pod
   #:scheduler-metrics-text
   #:stop-gateway-controller
   #:update-node-wireguard-endpoints
   #:update-node-wireguard-public-key)
  (:export
   #:+pod-certificate-request-beta-version+
   #:control-plane-runtime
   #:make-control-plane-runtime
   #:make-gateway-controller
   #:make-service-lb-controller
   #:service-lb-risk-published-p
   #:reconcile-certificates
   #:reconcile-cronjobs
   #:reconcile-daemonset
   #:reconcile-disruption-budgets
   #:reconcile-endpoints
   #:reconcile-endpointslices
   #:reconcile-horizontal-pod-autoscalers
   #:reconcile-ingress-status
   #:reconcile-jobs
   #:reconcile-pod-certificate-requests
   #:reconcile-service-ip-addresses
   #:reconcile-service-load-balancer-status
   #:reconcile-statefulset
   #:reconcile-workloads
   #:schedule-pod
   #:scheduler-metrics-text
   #:stop-gateway-controller
   #:update-node-wireguard-endpoints
   #:update-node-wireguard-public-key))
(defparameter gr8s.controllers:+pod-certificate-request-beta-version+
  "certificates.k8s.io/v1beta1"
  "The beta version still served beside v1 for older node clients.")
