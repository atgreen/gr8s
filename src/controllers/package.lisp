;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for control-plane reconciliation loops.

(defpackage #:gr8s.controllers
  (:use #:cl #:gr8s)
  (:shadow
   #:make-gateway-controller
   #:make-service-lb-controller
   #:reconcile-certificates
   #:reconcile-cronjobs
   #:reconcile-daemonset
   #:reconcile-disruption-budgets
   #:reconcile-endpoints
   #:reconcile-endpointslices
   #:reconcile-horizontal-pod-autoscalers
   #:reconcile-jobs
   #:reconcile-service-ip-addresses
   #:reconcile-statefulset
   #:reconcile-workloads
   #:stop-gateway-controller))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((controllers (find-package '#:gr8s.controllers))
        (composition (find-package '#:gr8s)))
    (dolist (name '("MAKE-GATEWAY-CONTROLLER"
                    "MAKE-SERVICE-LB-CONTROLLER"
                    "RECONCILE-CERTIFICATES"
                    "RECONCILE-CRONJOBS"
                    "RECONCILE-DAEMONSET"
                    "RECONCILE-DISRUPTION-BUDGETS"
                    "RECONCILE-ENDPOINTS"
                    "RECONCILE-ENDPOINTSLICES"
                    "RECONCILE-HORIZONTAL-POD-AUTOSCALERS"
                    "RECONCILE-JOBS"
                    "RECONCILE-SERVICE-IP-ADDRESSES"
                    "RECONCILE-STATEFULSET"
                    "RECONCILE-WORKLOADS"
                    "STOP-GATEWAY-CONTROLLER"))
      (shadowing-import (find-symbol name controllers) composition))))
