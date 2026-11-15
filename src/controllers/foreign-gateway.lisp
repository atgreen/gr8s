;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The Gateway API implementation on a foreign cluster (podster-982.5,
;;;; docs/design-foreign-cluster-networking.md).
;;;;
;;;; The existing gateway controller already reads everything it needs --
;;;; GatewayClasses, Gateways, routes, Secrets, Services, EndpointSlices --
;;;; through the desired-state seam, so on a foreign cluster it runs unchanged
;;;; over the agent's FOREIGN-RESOURCE-VIEW.  This file composes it into the
;;;; CNI agent's convergence loop, and adds the once-per-cluster work every
;;;; node must not repeat: whichever agent holds the coordination.k8s.io Lease
;;;; writes GatewayClass/Gateway/HTTPRoute status and provisions one
;;;; LoadBalancer Service per Gateway fronting the per-node listeners
;;;; (Cilium-style addressing).  Status is written only when it would change,
;;;; since a write wakes every watcher -- including our own nudge loop.

(in-package #:gr8s.controllers)

(defun foreign-gateway-vector (value)
  "A JSON array as a vector; an absent or JSON-null field is empty.
jzon parses null as the symbol NULL, which defeats GETHASH defaults."
  (if (vectorp value) value #()))

(defun foreign-gateway-now ()
  (gr8s.kube-client::rfc3339-micro (get-universal-time)))

(defun foreign-gateway-condition (type status reason &key generation existing)
  "A metav1 Condition, keeping EXISTING's lastTransitionTime while unchanged."
  (let ((previous (and existing
                       (find type (coerce existing 'list) :test #'equal
                             :key (lambda (entry) (gethash "type" entry)))))
        (condition (make-hash-table :test 'equal)))
    (setf (gethash "type" condition) type
          (gethash "status" condition) status
          (gethash "reason" condition) reason
          (gethash "message" condition) ""
          (gethash "lastTransitionTime" condition)
          (if (and previous (equal status (gethash "status" previous)))
              (gethash "lastTransitionTime" previous)
              (foreign-gateway-now)))
    (when generation (setf (gethash "observedGeneration" condition) generation))
    condition))

(defun foreign-gateway-node-addresses (view)
  "Every node's InternalIP: the per-node listeners answer on all of them."
  (loop for node in (list-core-resources view "nodes")
        append (loop for entry across (foreign-gateway-vector
                                        (gethash "addresses"
                                                 (gethash "status" node
                                                          (make-hash-table :test 'equal))))
                     when (equal "InternalIP" (gethash "type" entry))
                       collect (gethash "address" entry))))

(defun foreign-gateway-put-status (cluster group version resource namespace name status)
  "Write STATUS through the status subresource unless it is already current.
Returns quietly on write conflicts; the next pass retries."
  (handler-case
      (let* ((path (gr8s.kube-client:resource-path group version resource
                                                   :namespace namespace :name name))
             (current (gr8s.kube-client:kube-get cluster path)))
        (unless (equalp status (gethash "status" current))
          (setf (gethash "status" current) status)
          (handler-case
              (gr8s.kube-client:kube-replace
               cluster (gr8s.kube-client:resource-path group version resource
                                                       :namespace namespace :name name
                                                       :subresource "status")
               current)
            (gr8s.kube-client:kube-error (condition)
              ;; A server without the status subresource for this collection
              ;; (gr8s's own serves these resources whole) takes a plain PUT.
              (unless (eql 404 (gr8s.kube-client:kube-error-status condition))
                (error condition))
              (gr8s.kube-client:kube-replace cluster path current)))))
    (gr8s.kube-client:kube-error (condition)
      ;; A write conflict retries next pass; anything else deserves a line.
      (unless (eql 409 (gr8s.kube-client:kube-error-status condition))
        (format *error-output* "~&gr8s gateway status write ~A/~A: ~A~%"
                resource name condition)))))

(defun foreign-gateway-route-parents (route)
  (coerce (foreign-gateway-vector
           (gethash "parentRefs" (gethash "spec" route (make-hash-table :test 'equal))))
          'list))

(defun foreign-gateway-attached-routes (gateway routes)
  "The HTTPRoutes whose parentRefs attach to GATEWAY."
  (let* ((metadata (gethash "metadata" gateway))
         (name (gethash "name" metadata))
         (namespace (gethash "namespace" metadata)))
    (loop for route in routes
          when (loop for parent in (foreign-gateway-route-parents route)
                       thereis (and (equal name (gethash "name" parent))
                                    (equal namespace
                                           (or (gethash "namespace" parent)
                                               (gethash "namespace" (gethash "metadata" route))))))
            collect route)))

(defun foreign-gateway-publish-class-status (view cluster)
  (dolist (class (list-core-resources view "gatewayclasses"))
    (when (equal *gateway-controller-name*
                 (gethash "controllerName" (gethash "spec" class)))
      (let ((status (make-hash-table :test 'equal))
            (metadata (gethash "metadata" class)))
        (setf (gethash "conditions" status)
              (vector (foreign-gateway-condition
                       "Accepted" "True" "Accepted"
                       :generation (gethash "generation" metadata)
                       :existing (gethash "conditions"
                                          (gethash "status" class
                                                   (make-hash-table :test 'equal))))))
        (foreign-gateway-put-status cluster "gateway.networking.k8s.io" "v1"
                                    "gatewayclasses" nil (gethash "name" metadata)
                                    status)))))

(defun foreign-gateway-listener-supported-kinds (protocol)
  "The RouteGroupKinds gr8s serves on a listener of PROTOCOL."
  (mapcar (lambda (name)
            (let ((kind (make-hash-table :test 'equal)))
              (setf (gethash "group" kind) "gateway.networking.k8s.io"
                    (gethash "kind" kind) name)
              kind))
          (cond ((member protocol '("HTTP" "HTTPS") :test #'equal) '("HTTPRoute" "GRPCRoute"))
                ((equal protocol "TCP") '("TCPRoute"))
                ((equal protocol "TLS") '("TLSRoute"))
                (t '()))))

(defun foreign-gateway-listener-route-kinds (listener)
  "The listener's resolved supportedKinds and whether every allowedRoutes kind
is among them.  Returns (values supported-kind-objects all-allowed-supported-p)."
  (let* ((protocol (gethash "protocol" listener))
         (supported (foreign-gateway-listener-supported-kinds protocol))
         (supported-names (mapcar (lambda (k) (gethash "kind" k)) supported))
         (allowed (gethash "kinds"
                           (gethash "allowedRoutes" listener (make-hash-table :test 'equal)))))
    (if (and (vectorp allowed) (plusp (length allowed)))
        ;; Only the allowed kinds gr8s actually serves are supported; an allowed
        ;; kind it does not serve makes the listener's refs unresolved.
        (let ((intersection
                (loop for entry across allowed
                      for name = (gethash "kind" entry)
                      when (member name supported-names :test #'equal)
                        collect (let ((k (make-hash-table :test 'equal)))
                                  (setf (gethash "group" k)
                                        (or (gethash "group" entry) "gateway.networking.k8s.io")
                                        (gethash "kind" k) name)
                                  k))))
          (values intersection (= (length intersection) (length allowed))))
        (values supported t))))

(defun foreign-gateway-service-name (gateway-name)
  (concatenate 'string "gr8s-gateway-" gateway-name))

(defun foreign-gateway-provision-service (cluster gateway)
  "Ensure the LoadBalancer Service fronting GATEWAY's per-node listeners.
Selectorless: the listeners answer on every node's host network."
  (let* ((metadata (gethash "metadata" gateway))
         (namespace (gethash "namespace" metadata))
         (name (foreign-gateway-service-name (gethash "name" metadata)))
         (path (gr8s.kube-client:resource-path nil "v1" "services"
                                               :namespace namespace :name name)))
    (handler-case (progn (gr8s.kube-client:kube-get cluster path) nil)
      (gr8s.kube-client:kube-error (condition)
        (when (eql 404 (gr8s.kube-client:kube-error-status condition))
          (let ((service (make-hash-table :test 'equal))
                (service-metadata (make-hash-table :test 'equal))
                (spec (make-hash-table :test 'equal)))
            (setf (gethash "name" service-metadata) name
                  (gethash "namespace" service-metadata) namespace
                  (gethash "apiVersion" service) "v1"
                  (gethash "kind" service) "Service"
                  (gethash "metadata" service) service-metadata
                  (gethash "type" spec) "LoadBalancer"
                  (gethash "ports" spec)
                  (coerce
                   (loop for listener across (foreign-gateway-vector
                                              (gethash "listeners" (gethash "spec" gateway)))
                         collect (let ((port (make-hash-table :test 'equal)))
                                   (setf (gethash "name" port) (gethash "name" listener)
                                         (gethash "port" port) (gethash "port" listener)
                                         (gethash "protocol" port) "TCP")
                                   port))
                   'vector)
                  (gethash "spec" service) spec)
            (handler-case
                (gr8s.kube-client:kube-create
                 cluster (gr8s.kube-client:resource-path nil "v1" "services"
                                                         :namespace namespace)
                 service)
              (gr8s.kube-client:kube-error () nil))))))))

(defun foreign-gateway-publish-gateway-status (cluster gateway routes addresses)
  (let* ((metadata (gethash "metadata" gateway))
         (generation (gethash "generation" metadata))
         (existing-status (gethash "status" gateway (make-hash-table :test 'equal)))
         (attached (foreign-gateway-attached-routes gateway routes))
         (status (make-hash-table :test 'equal)))
    (setf (gethash "addresses" status)
          (coerce (loop for address in addresses
                        collect (let ((entry (make-hash-table :test 'equal)))
                                  (setf (gethash "type" entry) "IPAddress"
                                        (gethash "value" entry) address)
                                  entry))
                  'vector)
          (gethash "conditions" status)
          (vector (foreign-gateway-condition "Accepted" "True" "Accepted"
                                             :generation generation
                                             :existing (gethash "conditions" existing-status))
                  (foreign-gateway-condition "Programmed" "True" "Programmed"
                                             :generation generation
                                             :existing (gethash "conditions" existing-status)))
          (gethash "listeners" status)
          (coerce
           (loop for listener across (foreign-gateway-vector
                                      (gethash "listeners" (gethash "spec" gateway)))
                 collect
                 (let ((entry (make-hash-table :test 'equal))
                       (existing-listener
                         (find (gethash "name" listener)
                               (coerce (gethash "listeners" existing-status #()) 'list)
                               :test #'equal
                               :key (lambda (candidate) (gethash "name" candidate)))))
                   (multiple-value-bind (supported-kinds kinds-ok)
                       (foreign-gateway-listener-route-kinds listener)
                     (setf (gethash "name" entry) (gethash "name" listener)
                           (gethash "supportedKinds" entry) (coerce supported-kinds 'vector)
                           (gethash "attachedRoutes" entry) (length attached)
                           (gethash "conditions" entry)
                           ;; The spec requires Accepted, Programmed and
                           ;; ResolvedRefs; ResolvedRefs is False with reason
                           ;; InvalidRouteKinds when an allowedRoutes kind is one
                           ;; this listener's protocol does not serve.
                           (vector (foreign-gateway-condition
                                    "Accepted" "True" "Accepted"
                                    :generation generation
                                    :existing (and existing-listener
                                                   (gethash "conditions" existing-listener)))
                                   (foreign-gateway-condition
                                    "Programmed" "True" "Programmed"
                                    :generation generation
                                    :existing (and existing-listener
                                                   (gethash "conditions" existing-listener)))
                                   (foreign-gateway-condition
                                    "ResolvedRefs" (if kinds-ok "True" "False")
                                    (if kinds-ok "ResolvedRefs" "InvalidRouteKinds")
                                    :generation generation
                                    :existing (and existing-listener
                                                   (gethash "conditions" existing-listener))))))
                   entry))
           'vector))
    (foreign-gateway-put-status cluster "gateway.networking.k8s.io" "v1" "gateways"
                                (gethash "namespace" metadata) (gethash "name" metadata)
                                status)))

(defun foreign-gateway-publish-route-status (cluster route gateways)
  (let* ((metadata (gethash "metadata" route))
         (namespace (gethash "namespace" metadata))
         (existing (gethash "status" route (make-hash-table :test 'equal)))
         (parents
           (loop for parent in (foreign-gateway-route-parents route)
                 for gateway = (find-if
                                (lambda (candidate)
                                  (let ((gw-metadata (gethash "metadata" candidate)))
                                    (and (equal (gethash "name" parent)
                                                (gethash "name" gw-metadata))
                                         (equal (or (gethash "namespace" parent) namespace)
                                                (gethash "namespace" gw-metadata)))))
                                gateways)
                 when gateway
                   collect (let ((entry (make-hash-table :test 'equal))
                                 (existing-parent
                                   (find (gethash "name" parent)
                                         (coerce (foreign-gateway-vector
                                                  (gethash "parents" existing)) 'list)
                                         :test #'equal
                                         :key (lambda (candidate)
                                                (gethash "name"
                                                         (gethash "parentRef" candidate
                                                                  (make-hash-table :test 'equal)))))))
                             (setf (gethash "parentRef" entry) parent
                                   (gethash "controllerName" entry) *gateway-controller-name*
                                   (gethash "conditions" entry)
                                   ;; observedGeneration must track the route's
                                   ;; metadata.generation, which the conformance
                                   ;; suite waits to see on every condition.
                                   (vector (foreign-gateway-condition
                                            "Accepted" "True" "Accepted"
                                            :generation (gethash "generation" metadata)
                                            :existing (and existing-parent
                                                           (gethash "conditions" existing-parent)))
                                           (foreign-gateway-condition
                                            "ResolvedRefs" "True" "ResolvedRefs"
                                            :generation (gethash "generation" metadata)
                                            :existing (and existing-parent
                                                           (gethash "conditions" existing-parent)))))
                             entry))))
    (when parents
      (let ((status (make-hash-table :test 'equal)))
        (setf (gethash "parents" status) (coerce parents 'vector))
        (foreign-gateway-put-status cluster "gateway.networking.k8s.io" "v1" "httproutes"
                                    namespace (gethash "name" metadata) status)))))

(defun foreign-gateway-publish (view cluster)
  "The lease-holder's pass: statuses and per-Gateway LoadBalancer Services."
  (let* ((gateways (remove-if-not (lambda (gateway) (gateway-controlled-p view gateway))
                                  (list-core-resources view "gateways")))
         (routes (list-core-resources view "httproutes"))
         (addresses (foreign-gateway-node-addresses view)))
    (foreign-gateway-publish-class-status view cluster)
    (dolist (gateway gateways)
      (foreign-gateway-provision-service cluster gateway)
      (foreign-gateway-publish-gateway-status cluster gateway
                                              (foreign-gateway-attached-routes gateway routes)
                                              addresses))
    (dolist (route routes)
      (foreign-gateway-publish-route-status cluster route gateways))))

(defun start-foreign-gateway (view &key cert-dir resolver cluster node-name
                                        (lease-namespace "kube-system"))
  "A Gateway controller over the foreign VIEW, for the CNI agent's loop.
Returns (values CONVERGER STOPPER).  CONVERGER reconciles the HTTP and L4
listener plans; with CLUSTER and NODE-NAME it also contends for the
gr8s-gateway Lease, and the holder writes Gateway API statuses and provisions
the per-Gateway LoadBalancer Services.  RESOLVER overrides backend resolution
(tests)."
  (let ((controller (make-gateway-controller
                     view :cert-dir cert-dir :resolver resolver
                     ;; A foreign Gateway advertises the node addresses, so its
                     ;; listeners bind every interface -- unlike the native node,
                     ;; where sk_lookup steers the VIP to a loopback listener.
                     :start-fn (lambda (port router resolver tls)
                                 (start-gateway-listener :address "0.0.0.0" :port port
                                                         :router router :resolver resolver
                                                         :tls tls))
                     :l4-start-fn (lambda (port mode dispatcher resolver)
                                    (start-l4-listener :address "0.0.0.0" :port port
                                                       :mode mode :dispatcher dispatcher
                                                       :resolver resolver))))
        (leader nil) (stopping nil) (lease-thread nil) (status-thread nil)
        (listener-thread nil))
    ;; Converge the listener plans on their own responsive cadence rather than
    ;; behind the agent's shared nudge loop, where a burst of unrelated object
    ;; churn delayed a new Gateway's listener from binding for tens of seconds.
    (setf listener-thread
          (bt:make-thread
           (lambda ()
             (loop until stopping do
               (handler-case
                   (progn (converge-gateway-listeners controller)
                          (converge-gateway-l4-listeners controller))
                 (error (condition)
                   (format *error-output* "~&gr8s gateway listener convergence failed: ~A~%"
                           condition)))
               (sleep 1)))
           :name "gr8s gateway listeners"))
    (when (and cluster node-name)
      (setf lease-thread
            (bt:make-thread
             (lambda ()
               (gr8s.kube-client:run-lease-leader
                cluster "gr8s-gateway" node-name
                :namespace lease-namespace
                :lease-seconds 15 :renew-seconds 5
                :on-gained (lambda () (setf leader t))
                :on-lost (lambda () (setf leader nil))
                :stop-predicate (lambda () stopping)))
             :name "gr8s gateway lease"))
      ;; Status writes and Service provisioning make slow cluster-wide API
      ;; calls; run them on their own cadence so they never delay the fast,
      ;; local listener convergence below (a blocked status pass otherwise left
      ;; the node's listeners unbound for tens of seconds).
      (setf status-thread
            (bt:make-thread
             (lambda ()
               (loop until stopping do
                 (when leader
                   (handler-case (foreign-gateway-publish view cluster)
                     (error (condition)
                       (format *error-output* "~&gr8s gateway status pass failed: ~A~%"
                               condition))))
                 (sleep 2)))
             :name "gr8s gateway status")))
    (values
     ;; Listener convergence runs in its own thread above; the agent loop's
     ;; converger need do nothing, but converge once more so a nudge still
     ;; takes effect immediately rather than waiting for the next tick.
     (lambda ()
       (ignore-errors (converge-gateway-listeners controller))
       (ignore-errors (converge-gateway-l4-listeners controller)))
     (lambda ()
       (setf stopping t)
       (when listener-thread (ignore-errors (bt:join-thread listener-thread)))
       (when lease-thread (ignore-errors (bt:join-thread lease-thread)))
       (when status-thread (ignore-errors (bt:join-thread status-thread)))
       (stop-gateway-controller controller)))))
