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

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((controllers (find-package '#:gr8s.controllers))
        (composition (find-package '#:gr8s)))
    (dolist (name '("+POD-CERTIFICATE-REQUEST-BETA-VERSION+"
                    "CONTROL-PLANE-RUNTIME"
                    "MAKE-CONTROL-PLANE-RUNTIME"
                    "MAKE-GATEWAY-CONTROLLER"
                    "MAKE-SERVICE-LB-CONTROLLER"
                    "RECONCILE-CERTIFICATES"
                    "RECONCILE-CRONJOBS"
                    "RECONCILE-DAEMONSET"
                    "RECONCILE-DISRUPTION-BUDGETS"
                    "RECONCILE-ENDPOINTS"
                    "RECONCILE-ENDPOINTSLICES"
                    "RECONCILE-HORIZONTAL-POD-AUTOSCALERS"
                    "RECONCILE-INGRESS-STATUS"
                    "RECONCILE-JOBS"
                    "RECONCILE-POD-CERTIFICATE-REQUESTS"
                    "RECONCILE-SERVICE-IP-ADDRESSES"
                    "RECONCILE-SERVICE-LOAD-BALANCER-STATUS"
                    "RECONCILE-STATEFULSET"
                    "RECONCILE-WORKLOADS"
                    "SCHEDULE-POD"
                    "SCHEDULER-METRICS-TEXT"
                    "STOP-GATEWAY-CONTROLLER"
                    "UPDATE-NODE-WIREGUARD-ENDPOINTS"
                    "UPDATE-NODE-WIREGUARD-PUBLIC-KEY"))
      (multiple-value-bind (old old-status)
          (find-symbol name composition)
        (declare (ignore old))
        (let ((new (find-symbol name controllers)))
          (shadowing-import new composition)
          (export new controllers)
          (when (eq :external old-status)
            (export new composition)))))))

(defparameter gr8s.controllers:+pod-certificate-request-beta-version+
  "certificates.k8s.io/v1beta1"
  "The beta version still served beside v1 for older node clients.")
