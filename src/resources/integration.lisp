;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Temporary imports from layers not yet extracted from the composition package.

(in-package #:gr8s.resources)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((resources (find-package '#:gr8s.resources))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol composition)
      (when (and (not (member (symbol-package symbol)
                              (list (find-package '#:cl)
                                    (find-package '#:keyword)
                                    resources))))
        (multiple-value-bind (present status)
            (find-symbol (symbol-name symbol) resources)
          (declare (ignore status))
          (when (or (null present) (eq present symbol))
            (import symbol resources)))))
    ;; Resource semantics invoke these adapters, which are implemented by the
    ;; later API-server, controller, storage, and node-session layers.
    (dolist (name '("ADMISSION-ACTIVE-P"
                    "ADMISSION-ATTRIBUTES-FOR"
                    "ADMISSION-CALL-FAILURE"
                    "ADMISSION-CALL-FAILURE-MESSAGE"
                    "ADMISSION-CALL-WEBHOOK"
                    "ADMISSION-POLICY-STATUS-AFTER-CHECK"
                    "APISERVICE-BY-NAME"
                    "APPLY-DEFAULT-MANAGER"
                    "APPLY-FIELD-MANAGER"
                    "APPLY-FORCE-P"
                    "APPLY-MERGE"
                    "APPLY-READ-CONFIGURATION"
                    "APPLY-STATUS-CONFIGURATION"
                    "APPLY-TRACK-WRITE"
                    "CONTROLLER-CREATE-CORE-RESOURCE"
                    "CONTROLLER-DELETE-ALLOWED-P"
                    "CONTROLLER-UPDATE-CORE-RESOURCE"
                    "CORE-RESOURCE-ROUTE"
                    "CORE-SELECTOR-PREDICATE"
                    "CORE-SELECTOR-TERMS"
                    "CRD-API-VIEW"
                    "CRD-REPORT-PRUNED-FIELDS"
                    "DECODE-CSR-PROTOBUF"
                    "DECODE-POD-STATUS-PROTOBUF"
                    "DEFAULT-LOCAL-APISERVICE-STATUS"
                    "DELETE-CONTROLLER-POD"
                    "ENDPOINTSLICE-CANONICAL-JSON"
                    "ENSURE-EXTENSION-APISERVER-RBAC"
                    "HPA-API-VIEW"
                    "HPA-RESOURCE-P"
                    "HPA-V1-VIEW"
                    "JOB-INDEXES-TOTAL"
                    "MOUNT-NFS-FILESYSTEM"
                    "NFS-MOUNT-OPTION-TOKENS"
                    "NFS-TARGET-MOUNTED-P"
                    "NODE-ALLOCATABLE-CPU"
                    "NODE-ALLOCATABLE-MEMORY"
                    "NODE-LIST-PAGE"
                    "NODE-REPORTED-ADDRESS"
                    "NODE-WATCH-RESPONSE"
                    "NORMALIZE-HPA-RESOURCE"
                    "NORMALIZE-POD-CERTIFICATE-REQUEST"
                    "NORMALIZE-SERVICE-RESOURCE"
                    "OBJECT-NAME"
                    "OPTIONAL-CORE-RESOURCE"
                    "PARSE-JOB-INDEXES"
                    "PENDING-NODE-OPERATION-DONE-P"
                    "PENDING-NODE-OPERATION-ERROR"
                    "PENDING-NODE-OPERATION-RESPONSE"
                    "POD-CERTIFICATE-REQUEST-API-VIEW"
                    "POD-CERTIFICATE-REQUEST-PATH-VERSION"
                    "POD-CERTIFICATE-REQUEST-VIEW"
                    "POD-FS-GROUP"
                    "POLICY-API-GROUP"
                    "PREPARE-SERVICE-IP-ADDRESS-WRITES"
                    "PROMETHEUS-LABEL"
                    "QUEUE-NODE-OPERATION"
                    "RECONCILER-TAINT-TIMERS"
                    "REFERENCE-SCHEMA"
                    "REFUSE-BUILTIN-APISERVICE"
                    "RELEASE-NODE-OPERATION"
                    "REMOVE-NODE-UNLOCKED"
                    "REQUEST-MEDIA-TYPE"
                    "SAFE-DELETE-VOLUME-TREE"
                    "SAVE-POD-CLIENT-STATUS"
                    "SERVICE-EXTERNAL-NAME-P"
                    "STAT-HOST-STORAGE-PATH"
                    "STATEFULSET-CLAIM-OBJECT"
                    "STATEFULSET-POD-OBJECT"
                    "STATEFULSET-START-ORDINAL"
                    "STRIP-FIELD-PATH-ROOT"
                    "TABLE-JSON-PATH-STEPS"
                    "TRUE-PARAMETER-P"
                    "UNMOUNT-NFS-FILESYSTEM"
                    "VALIDATE-APISERVICE"
                    "VALIDATE-NFS-MOUNT-OPTIONS"
                    "WORKLOAD-METADATA"
                    "WORKLOAD-TEMPLATE-POD-OBJECT"))
      (let ((dependency
              (if (member name '("PENDING-NODE-OPERATION-DONE-P"
                                 "PENDING-NODE-OPERATION-ERROR"
                                 "PENDING-NODE-OPERATION-RESPONSE"
                                 "QUEUE-NODE-OPERATION"
                                 "RELEASE-NODE-OPERATION")
                          :test #'equal)
                  (intern name (find-package '#:gr8s.apiserver))
                  (intern name composition))))
        (multiple-value-bind (present status) (find-symbol name resources)
          (declare (ignore status))
          (when (and present (not (eq present dependency)))
            (unintern present resources)))
        (import dependency resources)))))
