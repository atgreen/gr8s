;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Temporary imports from layers not yet extracted from the composition package.

(in-package #:gr8s.apiserver)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((apiserver (find-package '#:gr8s.apiserver))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol composition)
      (when (and (not (member (symbol-package symbol)
                              (list (find-package '#:cl)
                                    (find-package '#:keyword)
                                    apiserver))))
        (multiple-value-bind (present status)
            (find-symbol (symbol-name symbol) apiserver)
          (declare (ignore status))
          (when (or (null present) (eq present symbol))
            (import symbol apiserver)))))
    ;; Routing delegates these subresources and discovery fragments to
    ;; controller modules loaded after the HTTP surface.
    (dolist (name '("*WORKLOAD-CLOCK*"
                    "ADD-BUDGET-OPENAPI-PATHS"
                    "ADD-ENDPOINTSLICE-OPENAPI-PATHS"
                    "ADD-WORKLOAD-OPENAPI-PATHS"
                    "BATCH-API-GROUP"
                    "BATCH-RESOURCES-RESPONSE"
                    "BUDGET-API-GROUP"
                    "BUDGET-RESOURCES-RESPONSE"
                    "CERT-MANAGER-API-GROUP"
                    "CERT-MANAGER-DISCOVERY-RESPONSE"
                    "CORE-DELETION-HELD-P"
                    "DELETE-WORKLOAD-COLLECTION"
                    "DELETE-WORKLOAD-RESOURCE"
                    "DISPATCH-WORKLOAD-SUBRESOURCE"
                    "ENDPOINTSLICE-API-GROUP"
                    "ENDPOINTSLICE-DISCOVERY-RESPONSE"
                    "GATEWAY-API-GROUP"
                    "GATEWAY-DISCOVERY-RESPONSE"
                    "GATEWAY-METRICS-TEXT"
                    "HOLD-POD-FOR-FOREGROUND-DELETION"
                    "PARSE-AGENT-SERVER"
                    "SERVICE-POD-ENDPOINTS"
                    "WORKLOAD-API-GROUP"
                    "WORKLOAD-DELETION-POLICY"
                    "WORKLOAD-POD-STATUS"
                    "WORKLOAD-RESOURCES-RESPONSE"
                    "WORKLOAD-SUBRESOURCE-ROUTE"
                    "WORKLOAD-UPDATE-STATUS-REQUEST"))
      (let ((dependency (intern name composition)))
        (multiple-value-bind (present status) (find-symbol name apiserver)
          (declare (ignore status))
          (when (and present (not (eq present dependency)))
            (unintern present apiserver)))
        (import dependency apiserver)))))
