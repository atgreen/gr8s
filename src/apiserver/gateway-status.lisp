;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Reconcile Gateway status from desired configuration and authenticated,
;;;; current node observations. A delivered snapshot is not listener readiness.

(in-package #:gr8s.apiserver)

(defun note-node-gateway-status (server node-name status session)
  "Accept complete observations only from NODE-NAME's current connection."
  (when (slot-value status 'gr8s.node.v1::gateway-report-present)
    (bt:with-lock-held ((node-grpc-server-lock server))
      (when (and session (not (node-agent-session-evicted-p session))
                 (eq session (gethash node-name (node-grpc-server-sessions server))))
        (setf (gethash node-name (node-grpc-server-gateway-reports server))
              (list session (funcall (node-grpc-server-clock server))
                    (slot-value status 'gr8s.node.v1::gateways)))))))

(defun gateway-live-node-observations (server now)
  "Copy fresh inventories from ready nodes, excluding replaced connections."
  (let ((nodes (list-nodes (node-grpc-server-store server))))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (loop for node in nodes
            for name = (node-record-name node)
            for session = (gethash name (node-grpc-server-sessions server))
            for report = (gethash name (node-grpc-server-gateway-reports server))
            when (and (gr8s.model:node-record-runtime-ready-p node)
                      (gr8s.model:node-record-lease-deadline node)
                      (> (gr8s.model:node-record-lease-deadline node) now)
                      session (not (node-agent-session-evicted-p session))
                      report (eq session (first report))
                      (<= 0 (- now (second report))
                          (or (node-grpc-server-heartbeat-timeout-seconds server) 30)))
              collect (cons node (copy-list (third report)))))))

(defun gateway-observation-matches-p (observation gateway)
  "Require the exact object incarnation, spec generation, and full listener set."
  (let* ((metadata (gethash "metadata" gateway))
         (listeners (gethash "listeners" (gethash "spec" gateway)))
         (reported (slot-value observation 'gr8s.node.v1::listeners)))
    (and (equal (gethash "namespace" metadata) (slot-value observation 'gr8s.node.v1::namespace))
         (equal (gethash "name" metadata) (slot-value observation 'gr8s.node.v1::name))
         (equal (gethash "uid" metadata) (slot-value observation 'gr8s.node.v1::uid))
         (= (gethash "generation" metadata 1) (slot-value observation 'gr8s.node.v1::generation))
         (= (length listeners) (length reported))
         (every (lambda (listener)
                  (= 1 (count (gethash "name" listener) reported :test #'equal
                              :key (lambda (item) (slot-value item 'gr8s.node.v1::name)))))
                listeners))))

(defun gateway-current-node-observations (gateway live-nodes)
  "Return only unambiguous observations of GATEWAY's current configuration."
  (loop for (node . inventory) in live-nodes
        for matches = (remove-if-not (lambda (item) (gateway-observation-matches-p item gateway)) inventory)
        when (= 1 (length matches)) collect (cons node (first matches))))

(defun gateway-reported-listener (observation name)
  (find name (slot-value observation 'gr8s.node.v1::listeners) :test #'equal
        :key (lambda (item) (slot-value item 'gr8s.node.v1::name))))

(defun gateway-status-condition (old type state reason message generation)
  "Keep transition times stable until a condition's truth value changes."
  (let ((previous (find type old :test #'equal :key (lambda (item) (gethash "type" item)))))
    (core-object "type" type "status" state "reason" reason "message" message
                 "observedGeneration" generation
                 "lastTransitionTime"
                 (if (and previous (equal state (gethash "status" previous)))
                     (gethash "lastTransitionTime" previous) (current-timestamp)))))

(defun gateway-protocol-route-kinds (protocol)
  (cond ((member protocol '("HTTP" "HTTPS") :test #'equal) '("HTTPRoute"))
        ((equal protocol "TCP") '("TCPRoute"))
        ((equal protocol "TLS") '("TLSRoute"))))

(defun gateway-listener-route-kinds-valid-p (listener)
  "Every explicitly requested kind must be implemented for this protocol."
  (let ((supported (gateway-protocol-route-kinds (gethash "protocol" listener))))
    (every (lambda (ref)
             (and (equal "gateway.networking.k8s.io" (gethash "group" ref "gateway.networking.k8s.io"))
                  (member (gethash "kind" ref) supported :test #'equal)))
           (gethash "kinds" (gethash "allowedRoutes" listener (core-object))))))

(defun gateway-listener-supported-kinds (listener)
  "Advertise only implemented route kinds allowed by this listener."
  (let* ((supported (gateway-protocol-route-kinds (gethash "protocol" listener)))
         (allowed (gethash "kinds" (gethash "allowedRoutes" listener (core-object)))))
    (coerce (loop for kind in supported
                  when (or (null allowed)
                           (some (lambda (ref)
                                   (and (equal "gateway.networking.k8s.io"
                                               (gethash "group" ref "gateway.networking.k8s.io"))
                                        (equal kind (gethash "kind" ref)))) allowed))
                    collect (core-object "group" "gateway.networking.k8s.io" "kind" kind))
            'vector)))

(defun gateway-listener-allows-namespace-p (store gateway listener namespace)
  (let* ((policy (gethash "namespaces" (gethash "allowedRoutes" listener (core-object)) (core-object)))
         (from (gethash "from" policy "Same")))
    (cond ((equal from "All") t)
          ((equal from "Same") (equal namespace (gethash "namespace" (gethash "metadata" gateway))))
          ((equal from "Selector")
           (let ((object (ignore-errors (get-core-resource store "namespaces" nil namespace)))
                 (selector (gethash "selector" policy)))
             (and object selector
                  (gr8s.resources::workload-selector-matches-p
                   selector (gethash "labels" (gethash "metadata" object)))))))))

(defun gateway-listener-attached-routes (store gateway listener kinds)
  "Count each selected Route once, independent of backend validity or readiness."
  (let ((metadata (gethash "metadata" gateway))
        ;; Committed indexes and their rows are immutable. Counting does not
        ;; need the private deep copies returned by the public list API.
        (resources (gr8s.store::with-store-lock (store) (pod-store-resources store))))
    (loop for kind across kinds
          for resource = (cond ((equal (gethash "kind" kind) "HTTPRoute") "httproutes")
                               ((equal (gethash "kind" kind) "TCPRoute") "tcproutes")
                               (t "tlsroutes"))
          sum (loop for key being the hash-keys of resources using (hash-value route)
                    count (and (equal resource (first key))
                               (gateway-listener-allows-namespace-p
                                store gateway listener (gethash "namespace" (gethash "metadata" route)))
                               (gr8s.controllers::gateway-route-attaches-p
                                route (gethash "namespace" metadata) (gethash "name" metadata)
                                (gethash "name" listener) (gethash "port" listener)))))))

(defun gateway-listener-tls-reference-resolved-p (store gateway listener)
  "HTTPS requires a same-namespace TLS Secret with both certificate and key."
  (if (not (equal "HTTPS" (gethash "protocol" listener))) t
      (let* ((namespace (gethash "namespace" (gethash "metadata" gateway)))
             (ref (gr8s.controllers::gateway-listener-tls-ref namespace listener))
             (secret (and ref (equal namespace (car ref))
                          (ignore-errors (get-core-resource store "secrets" (car ref) (cdr ref)))))
             (data (and secret (gethash "data" secret))))
        (and secret (equal "kubernetes.io/tls" (gethash "type" secret))
             (stringp (gethash "tls.crt" data)) (plusp (length (gethash "tls.crt" data)))
             (stringp (gethash "tls.key" data)) (plusp (length (gethash "tls.key" data)))))))

(defun gateway-listener-resolved-refs-p (store gateway listener)
  (and (gateway-listener-route-kinds-valid-p listener)
       (gateway-listener-tls-reference-resolved-p store gateway listener)))

(defun gateway-listener-status-object (store gateway listener observations old)
  (let* ((name (gethash "name" listener))
         (generation (gethash "generation" (gethash "metadata" gateway) 1))
         (supported (member (gethash "protocol" listener) '("HTTP" "HTTPS" "TCP" "TLS") :test #'equal))
         (resolved (gateway-listener-resolved-refs-p store gateway listener))
         (programmed (and supported resolved
                          (some (lambda (entry)
                                  (let ((report (gateway-reported-listener (cdr entry) name)))
                                    (and report (slot-value report 'gr8s.node.v1::programmed)))) observations)))
         (kinds (gateway-listener-supported-kinds listener))
         (conditions (gethash "conditions" old #())))
    (core-object
     "name" name "supportedKinds" kinds
     "attachedRoutes" (gateway-listener-attached-routes store gateway listener kinds)
     "conditions"
     (vector (gateway-status-condition conditions "Accepted" (if supported "True" "False")
                                       (if supported "Accepted" "UnsupportedProtocol")
                                       (if supported "Listener configuration accepted" "Listener protocol is unsupported") generation)
             (gateway-status-condition conditions "ResolvedRefs" (if resolved "True" "False")
                                       (cond (resolved "ResolvedRefs")
                                             ((not (gateway-listener-route-kinds-valid-p listener)) "InvalidRouteKinds")
                                             (t "InvalidCertificateRef"))
                                       (if resolved "Listener references resolved" "Listener references are unavailable or unsupported") generation)
             (gateway-status-condition conditions "Programmed" (if programmed "True" "False")
                                       (if programmed "Programmed" "Pending")
                                       (if programmed "A current node reports this listener running"
                                           "Waiting for a current node to start this listener") generation)))))

(defun gateway-requested-address-p (gateway address)
  (let ((requested (gethash "addresses" (gethash "spec" gateway))))
    (or (null requested) (zerop (length requested))
        (some (lambda (entry)
                (and (equal "IPAddress" (gethash "type" entry "IPAddress"))
                     (equal address (gethash "value" entry)))) requested))))

(defun gateway-status-object (store gateway observations)
  (let* ((old (gethash "status" gateway (core-object)))
         (generation (gethash "generation" (gethash "metadata" gateway) 1))
         (listeners (gethash "listeners" (gethash "spec" gateway)))
         (accepted (every (lambda (listener)
                            (member (gethash "protocol" listener) '("HTTP" "HTTPS" "TCP" "TLS") :test #'equal)) listeners))
         (addresses
           (sort (remove-duplicates
                  (loop for (node . observation) in observations
                        for address = (node-reported-address node)
                        when (and accepted (stringp address) (plusp (length address))
                                  (gateway-requested-address-p gateway address)
                                  (every (lambda (listener)
                                           (and (gateway-listener-resolved-refs-p store gateway listener)
                                                (slot-value (gateway-reported-listener observation (gethash "name" listener))
                                                            'gr8s.node.v1::programmed))) listeners))
                          collect address)
                  :test #'equal) #'string<))
         (programmed (not (null addresses)))
         (conditions (gethash "conditions" old #())))
    (core-object
     "addresses" (map 'vector (lambda (address) (core-object "type" "IPAddress" "value" address)) addresses)
     "conditions" (vector
                   (gateway-status-condition conditions "Accepted" (if accepted "True" "False")
                                             (if accepted "Accepted" "UnsupportedProtocol")
                                             (if accepted "Gateway configuration accepted" "Gateway has an unsupported listener") generation)
                   (gateway-status-condition conditions "Programmed" (if programmed "True" "False")
                                             (if programmed "Programmed" "Pending")
                                             (if programmed "Current nodes are serving the Gateway"
                                                 "Waiting for current listener observations and a usable address") generation))
     "listeners" (map 'vector
                      (lambda (listener)
                        (gateway-listener-status-object
                         store gateway listener observations
                         (or (find (gethash "name" listener) (gethash "listeners" old #()) :test #'equal
                                   :key (lambda (item) (gethash "name" item))) (core-object)))) listeners))))

(defun write-gateway-controller-status (store resource object status)
  "Write changed status only while this UID and spec generation remain current."
  (unless (core-json-equal-p status (gethash "status" object (core-object)))
    (let* ((metadata (gethash "metadata" object))
           (gr8s.resources::*typed-api-status-write* t))
      (update-core-resource
       store resource (gethash "namespace" metadata) (gethash "name" metadata)
       (lambda (current)
         (let ((now (gethash "metadata" current)))
           (when (and (equal (gethash "uid" metadata) (gethash "uid" now))
                      (= (gethash "generation" metadata 1) (gethash "generation" now 1)))
             (setf (gethash "status" current) (copy-core-object status))))
         current)))))

(defun gateway-status-or-invalid (store gateway observations)
  "One malformed legacy configuration must not starve other Gateways."
  (handler-case (gateway-status-object store gateway observations)
    (error (condition)
      (declare (ignore condition))
      (let* ((old (gethash "status" gateway (core-object)))
             (conditions (gethash "conditions" old #()))
             (generation (gethash "generation" (gethash "metadata" gateway) 1)))
        (core-object
         "addresses" #() "listeners" #()
         "conditions"
         (vector (gateway-status-condition conditions "Accepted" "False" "Invalid"
                                           "Gateway configuration cannot be resolved" generation)
                 (gateway-status-condition conditions "Programmed" "False" "Pending"
                                           "Gateway configuration cannot be resolved" generation)))))))

(defun reconcile-gateway-status (server)
  "Publish controller-owned class and Gateway status on the leader's pass."
  (let* ((store (node-grpc-server-store server))
         (live (gateway-live-node-observations server (funcall (node-grpc-server-clock server)))))
    (dolist (class (list-core-resources store "gatewayclasses"))
      (when (equal gr8s.controllers::*gateway-controller-name* (gethash "controllerName" (gethash "spec" class)))
        (write-gateway-controller-status
         store "gatewayclasses" class
         (core-object "conditions"
                      (vector (gateway-status-condition
                               (gethash "conditions" (gethash "status" class (core-object)) #())
                               "Accepted" "True" "Accepted" "GatewayClass is managed by gr8s"
                               (gethash "generation" (gethash "metadata" class) 1)))))))
    (dolist (gateway (list-core-resources store "gateways"))
      (when (gr8s.controllers::gateway-controlled-p store gateway)
        (write-gateway-controller-status
         store "gateways" gateway
         (gateway-status-or-invalid store gateway (gateway-current-node-observations gateway live))))))
  nil)
