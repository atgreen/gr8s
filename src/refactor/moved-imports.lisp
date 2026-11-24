;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Remaining implementation imports, including cycles, for files that reached
;;;; their sibling symbols through the GR8S composition package.
;;;;
;;;; The scheduler, node-agent pod pool, kubelet pod/runtime helpers, and the
;;;; control-plane node-session / extension surfaces now live in their owning
;;;; module packages; this file shadowing-imports exactly the sibling symbols
;;;; their bodies reference. Stable foundation, model, protocol, runtime, and
;;;; library dependencies are declared in each consumer package.
;;;; INTERN (not FIND-SYMBOL) forward-declares collaborators defined later.  Loaded after every
;;;; module package boundary exists and before the first such file compiles.

(in-package #:cl-user)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (dolist (spec '(
                  ;; GR8S.AGENT
                  ("GR8S.AGENT" "GR8S.CONTROLLERS" "+DEFAULT-CLUSTER-POD-CIDR+"
                   "+DEFAULT-NODE-POD-PREFIX+" "FORMAT-POD-ADDRESS" "LIST-NODES"
                   "NORMALIZE-POD-POOL-GEOMETRY" "PARSE-POD-CIDR" "POD-CIDRS-OVERLAP-P")

                  ("GR8S.AGENT" "GR8S.NETWORK" "+NODE-VXLAN-INTERFACE+"
                   "+NODE-WIREGUARD-INTERFACE+" "CNI-CONTEXT-CONTAINER-ID" "INVALID-CNI"
                   "MAKE-CNI-CONTEXT" "NETWORK-LINK-KIND-P" "NETWORK-LINK-UNTAGGED-P"
                   "NODE-IPAM-ALLOCATIONS" "NODE-VXLAN-OWNER" "NODE-WIREGUARD-OWNER"
                   "OPEN-NODE-IPAM" "READ-IP-HOST-ROUTES" "ROUTED-CNI-HOST-NAME"
                   "ROUTED-CNI-OWNER" "ROUTED-VETH-MAC" "SAFE-CNI-CONTAINER-ID-P"
                   "VXLAN-ROUTER-ADDRESS" "VXLAN-ROUTER-MAC")
                  ("GR8S.AGENT" "GR8S.SECURITY" "WRITE-PRIVATE-TEXT-ATOMICALLY")
                  ;; GR8S.APISERVER
                  ("GR8S.APISERVER" "GR8S.CONTROLLERS" "+DEFAULT-CLUSTER-POD-CIDR+"
                   "+DEFAULT-NODE-POD-PREFIX+" "ALLOCATE-NODE-POD-CIDRS"
                   "CANONICAL-NODE-UNDERLAY-ADDRESS" "EXPIRE-NODE-HEARTBEATS" "GET-NODE"
                   "LIST-NODES" "MARK-NODE-READY" "NORMALIZE-POD-POOL-GEOMETRY"
                   "NOTE-NODE-PRESSURE" "NOTE-NODE-RUNTIME-HEALTH"
                   "RECORD-NODE-CERTIFICATE-ISSUER" "REGISTER-NODE"
                   "UPDATE-NODE-CAPACITY" "UPDATE-NODE-EXTENDED-RESOURCES"
                   "UPDATE-NODE-KUBELET-PORT" "UPDATE-NODE-AGENT-INFO" "UPDATE-NODE-UNDERLAY-ADDRESS"
                   "UPDATE-NODE-WIREGUARD-ENDPOINTS" "UPDATE-NODE-WIREGUARD-PUBLIC-KEY")
                  ("GR8S.APISERVER" "GR8S.KUBELET" "DELETION-REQUESTED-P"
                   "EXTENDED-RESOURCE-NAME-P" "SAVE-POD-FINALIZATION-STATE"
                   "SAVE-POD-OBSERVATION")

                  ("GR8S.APISERVER" "GR8S.RESOURCES" "CORE-OBJECT" "GET-CORE-RESOURCE"
                   "MINT-SERVICE-ACCOUNT-TOKEN" "NODE-CAPACITY-FROM-ENTRIES"
                   "NOTE-NODE-HEARTBEAT-LEASE" "RECORD-NODE-RUNTIME-EVENTS"
                   "UPDATE-NODE-CSI-REGISTRATIONS")
                  ("GR8S.APISERVER" "GR8S.SECURITY" "AUTHENTICATE-NODE-PEER"
                   "CLUSTER-PKI-CA-CERTIFICATE-PATH" "CLUSTER-PKI-CA-FINGERPRINT"
                   "CLUSTER-PKI-TRUST-CERTIFICATES" "ENROLL-NODE-CSR"
                   "ENSURE-NODE-SERVER-CREDENTIALS" "NODE-CERTIFICATE-ISSUER-FINGERPRINT"
                   "NODE-CERTIFICATE-NEEDS-ACTIVE-CA-RENEWAL-P" "NODE-SERVER-TLS-OPTIONS"
                   "PKI-ASCII-OCTETS" "RENEW-AUTHENTICATED-NODE-CSR")
                  ("GR8S.APISERVER" "GR8S.STORE" "CURRENT-TIMESTAMP" "GENERATE-UID" "GET-POD"
                   "POD-STORE-CONSENSUS-COMMIT-FN" "POD-STORE-IMAGE-TRACKER"
                   "POD-STORE-RESOURCE-REVISION")
                  ;; GR8S.CONTROLLERS
                  ("GR8S.CONTROLLERS" "GR8S.APISERVER" "PUBLISH-NODE-CHANGE-UNLOCKED"
                   "TABLE-GET")
                  ("GR8S.CONTROLLERS" "GR8S.KUBELET" "DELETION-REQUESTED-P" "POD-DELETION-TIME"
                   "POD-FOR-THIS-SCHEDULER-P" "POD-SCHEDULING-GATED-P" "SAVE-POD-OBSERVATION")
                  ("GR8S.CONTROLLERS" "GR8S.RESOURCES" "CHOOSE-PREEMPTION-UNLOCKED"
                   "COMMIT-CORE-RESOURCES" "COPY-CORE-OBJECT" "COPY-CORE-RESOURCE-INDEX"
                   "CORE-OBJECT" "CORE-RESOURCE-KEY" "CREATE-CORE-RESOURCE" "GET-CORE-RESOURCE"
                   "NODE-API-OBJECT" "NODE-SELECTOR-TERM-MATCHES-P"
                   "POD-AFFINITY-PREFERENCE-SCORE-UNLOCKED" "POD-AWAITING-PREEMPTION-P"
                   "POD-FITS-NODE-UNLOCKED" "POD-NODE-PLACEABLE-P" "POD-NODE-PREFERENCE-SCORE"
                   "POD-TOPOLOGY-SPREAD-PENALTY-UNLOCKED" "POD-UNSCHEDULABLE-MESSAGE"
                   "PREEMPT-POD" "UPDATE-CORE-RESOURCE")
                  ("GR8S.CONTROLLERS" "GR8S.SECURITY" "OCTETS-TO-HEX")
                  ("GR8S.CONTROLLERS" "GR8S.STORE" "COPY-POD-STATUS-VALUE" "CURRENT-TIMESTAMP"
                   "GENERATE-UID" "INDEX-POD" "NEXT-POD-REVISION-UNLOCKED"
                   "NOTE-NODE-DESIRED-CHANGE" "NOTE-NODE-STATE-CHANGE" "NOTE-POD-DESIRED-CHANGE"
                   "PERSIST-NODE" "PERSIST-POD" "POD-PUBLISHED-VIEW"
                   "POD-STORE-CONSENSUS-COMMIT-FN" "POD-STORE-LOCK" "POD-STORE-NODES"
                   "POD-STORE-NOMINATED-NODES" "POD-STORE-POD-CLIENT-STATUSES"
                   "POD-STORE-POD-OBSERVED-PHASES" "POD-STORE-POD-OBSERVED-RESOURCE-VERSIONS"
                   "POD-STORE-POD-OBSERVED-STATUSES" "POD-STORE-PODS"
                   "POD-STORE-RESOURCE-REVISION" "POD-STORE-RESOURCES"
                   "POD-STORE-SCHEDULING-NOTES" "PUBLISH-POD-SPEC-CHANGE-UNLOCKED"
                   "STAGE-NODE-WRITE" "WITH-STORE-LOCK")
                  ;; GR8S.KUBELET
                  ("GR8S.KUBELET" "GR8S.APISERVER" "ADD-POD-HOST-ADDRESS"
                   "ADMIT-SUBRESOURCE-WRITE" "APPLY-CORE-JSON-PATCH" "APPLY-POD-CLIENT-STATUS"
                   "APPLY-POD-PATCHED-OBJECT" "COPY-JSON-OBJECT" "CORE-JSON-EQUAL-P"
                   "CORE-RESOURCE-DRY-RUN-P" "CORE-RESOURCE-REQUEST-OBJECT" "JSON-RESPONSE"
                   "MERGE-JSON-OBJECT" "POD-RESPONSE-OBJECT")
                  ("GR8S.KUBELET" "GR8S.CONTROLLERS" "PARSE-IPV4-INTEGER")
                  ("GR8S.KUBELET" "GR8S.RESOURCES" "APPLY-POD-LEVEL-RESOURCES"
                   "CONTAINER-RESOURCE-MAP" "COPY-CORE-OBJECT" "CORE-DATA-KEY-P"
                   "CORE-LABEL-NAME-P" "CORE-OBJECT" "CORE-QUALIFIED-KEY-P"
                   "CORE-RESOURCE-ERROR" "CSI-DRIVER-NAME-VALID-P" "NATIVE-NODE-ARCHITECTURE"
                   "POD-LEVEL-REQUIREMENTS-QOS" "POD-UNSCHEDULABLE-MESSAGE"
                   "STORAGE-NODE-LABELS" "STORAGE-QUANTITY" "TEMPLATE-SCHEMA"
                   "TEMPLATE-STRATEGIC-MERGE" "VALIDATE-CORE-STRING-MAP"
                   "VALIDATE-HOST-STORAGE-SOURCE" "VALIDATE-POD-AFFINITY-GROUP"
                   "VALIDATE-POD-LEVEL-RESOURCES" "VALIDATE-STORAGE-ACCESS-MODES"
                   "VALIDATE-TOPOLOGY-SPREAD-CONSTRAINTS")
                  ("GR8S.KUBELET" "GR8S.RUNTIME.CONTAINERD" "CONTAINERD-OWNED-SANDBOX"
                   "CONTAINERD-POD-LOG-DIRECTORY" "CONTAINERD-RUNTIME-LOG-ROOT")
                  ("GR8S.KUBELET" "GR8S.SECURITY" "WRITE-PRIVATE-TEXT-ATOMICALLY")
                  ("GR8S.KUBELET" "GR8S.STORE" "COPY-POD-STATUS-VALUE" "CURRENT-STATUS-POD-P"
                   "CURRENT-TIMESTAMP" "GET-POD" "NOTE-POD-STATE-CHANGE"
                   "PERSIST-POD-STATUS-STATE" "POD-STORE-NOMINATED-NODES"
                   "POD-STORE-POD-CLIENT-STATUSES" "POD-STORE-POD-CONDITION-HISTORIES"
                   "POD-STORE-POD-FINALIZATION-STATES" "POD-STORE-POD-OBSERVED-PHASES"
                   "POD-STORE-POD-OBSERVED-RESOURCE-VERSIONS" "POD-STORE-POD-OBSERVED-STATUSES"
                   "PUBLISH-POD-STATUS-UNLOCKED" "REMOVE-POD" "UPDATE-POD" "WITH-STORE-LOCK")
                  ;; GR8S.RUNTIME
                  ("GR8S.RUNTIME" "GR8S.SERVER" "MAIN")
                  ;; Quoted condition-class and type references the undefined-function
                  ;; scan did not see (e.g. (error 'kubernetes-error ...)).  They must be
                  ;; imported before the moved file compiles; otherwise a later
                  ;; integration shadowing-import replaces -- and so uninterns -- the
                  ;; fresh symbol the file captured, leaving a dangling #:SYMBOL that no
                  ;; longer names the condition class.
                  ("GR8S.AGENT" "GR8S.NETWORK" "CNI-ERROR")


                  ("GR8S.NETWORK" "GR8S.CONTROLLERS" "SERVICE-AFFINITY-TIMEOUT"
                   "SERVICE-LOAD-BALANCER-IDENTITY" "SERVICE-LOAD-BALANCER-PORT-OWNERS"
                   "SERVICE-NODE-ZONE" "SERVICE-PORT-BACKENDS" "SERVICE-PROXIED-P"
                   "SERVICE-SLICE-ENDPOINT-RECORDS" "TERMINAL-POD-PHASE-P")
                  ("GR8S.NETWORK" "GR8S.KUBELET" "POD-HOST-NETWORK-P")
                  ("GR8S.NETWORK" "GR8S.RESOURCES" "LIST-CORE-RESOURCES")
                  ("GR8S.NETWORK" "GR8S.STORE" "LIST-PODS")
                  ))
    (destructuring-bind (into from &rest names) spec
      (let ((ipkg (find-package into)) (fpkg (find-package from)))
        (unless ipkg (error "moved-imports: missing target package ~A" into))
        (unless fpkg (error "moved-imports: missing source package ~A" from))
        (dolist (name names)
          (shadowing-import (intern name fpkg) ipkg))))))
