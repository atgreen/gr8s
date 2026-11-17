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
;;;; LoadBalancer Service per Gateway fronting the per-node listeners.
;;;; Status is written only when it would change,
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
                      when (and (equal (or (gethash "group" entry) "gateway.networking.k8s.io")
                                       "gateway.networking.k8s.io")
                                (member name supported-names :test #'equal))
                        collect (let ((k (make-hash-table :test 'equal)))
                                  (setf (gethash "group" k)
                                        (or (gethash "group" entry) "gateway.networking.k8s.io")
                                        (gethash "kind" k) name)
                                  k))))
          (values intersection (= (length intersection) (length allowed))))
        (values supported t))))

(defun foreign-gateway-service-name (gateway-name)
  "Gateway names allow DNS subdomains; Service names require a 63-byte label."
  (let ((name (concatenate 'string "gr8s-gateway-" gateway-name)))
    (if (and (<= (length name) 63) (not (find #\. name)))
        name
        (let ((digest (ironclad:byte-array-to-hex-string
                       (ironclad:digest-sequence
                        :sha256 (trivial-utf-8:string-to-utf-8-bytes name)))))
          (concatenate 'string
                       (substitute #\- #\. (subseq name 0 (min 50 (length name))))
                       "-" (subseq digest 0 12))))))

(defun foreign-gateway-owner-reference (object)
  (let ((metadata (gethash "metadata" object)))
    (gr8s.resources::core-object
     "apiVersion" (gethash "apiVersion" object) "kind" (gethash "kind" object)
     "name" (gethash "name" metadata) "uid" (gethash "uid" metadata) "controller" t)))

(defun foreign-gateway-owned-by-p (object owner)
  (let ((expected (foreign-gateway-owner-reference owner)))
    (some (lambda (reference)
            (and (eq t (gethash "controller" reference))
                 (every (lambda (field) (equal (gethash field reference) (gethash field expected)))
                        '("apiVersion" "kind" "name" "uid"))))
          (foreign-gateway-vector (gethash "ownerReferences" (gethash "metadata" object))))))

(defun foreign-gateway-get (cluster path)
  (handler-case (gr8s.kube-client:kube-get cluster path)
    (gr8s.kube-client:kube-error (condition)
      (unless (eql 404 (gr8s.kube-client:kube-error-status condition)) (error condition)))))

(defun foreign-gateway-service-ports (gateway &optional existing)
  "One stable Service port per public TCP port, even with many hostname listeners."
  (let ((seen (make-hash-table)) (ports nil))
    (loop for listener across (foreign-gateway-vector (gethash "listeners" (gethash "spec" gateway)))
          for number = (gethash "port" listener)
          when (and (member (gethash "protocol" listener) '("HTTP" "HTTPS" "TCP" "TLS") :test #'equal)
                    (not (gethash number seen)))
            do (let* ((old (find number (foreign-gateway-vector existing)
                                :key (lambda (entry) (gethash "port" entry))))
                      (port (if old (gr8s.resources::copy-core-object old) (make-hash-table :test #'equal))))
                 (setf (gethash number seen) t
                       (gethash "name" port) (format nil "p-~D" number)
                       (gethash "port" port) number (gethash "targetPort" port) number
                       (gethash "protocol" port) "TCP")
                 (push port ports)))
    (coerce (sort ports #'< :key (lambda (entry) (gethash "port" entry))) 'vector)))

(defun foreign-gateway-provision-service (cluster gateway)
  "Reconcile the Gateway-owned selectorless Service without adopting name collisions."
  (when (zerop (length (foreign-gateway-service-ports gateway)))
    (return-from foreign-gateway-provision-service nil))
  (let* ((metadata (gethash "metadata" gateway))
         (namespace (gethash "namespace" metadata))
         (name (foreign-gateway-service-name (gethash "name" metadata)))
         (collection (gr8s.kube-client:resource-path nil "v1" "services" :namespace namespace))
         (path (gr8s.kube-client:resource-path nil "v1" "services" :namespace namespace :name name))
         (current (foreign-gateway-get cluster path)))
    (when (and current (not (foreign-gateway-owned-by-p current gateway)))
      (error "Refusing unrelated Service ~A/~A for Gateway ~A" namespace name (gethash "uid" metadata)))
    (let* ((service (or current
                        (gr8s.resources::core-object
                         "apiVersion" "v1" "kind" "Service"
                         "metadata" (gr8s.resources::core-object
                                     "name" name "namespace" namespace
                                     "ownerReferences" (vector (foreign-gateway-owner-reference gateway)))
                         "spec" (gr8s.resources::core-object "type" "LoadBalancer"))))
           (spec (gethash "spec" service))
           (ports (foreign-gateway-service-ports gateway (gethash "ports" spec)))
           (changed (or (not (equalp ports (gethash "ports" spec)))
                        (not (equal "LoadBalancer" (gethash "type" spec)))
                        (nth-value 1 (gethash "selector" spec)))))
      (setf (gethash "ports" spec) ports (gethash "type" spec) "LoadBalancer")
      (remhash "selector" spec)
      (cond ((null current) (gr8s.kube-client:kube-create cluster collection service))
            (changed (gr8s.kube-client:kube-replace cluster path service))
            (t service)))))

(defun foreign-gateway-service-addresses (service)
  "Prefer allocated LB IPs; ClusterIP remains reachable inside the cluster."
  (let ((external
          (loop for entry across (foreign-gateway-vector
                                   (gethash "ingress" (gethash "loadBalancer"
                                     (gethash "status" service (make-hash-table)) (make-hash-table))))
                for address = (gethash "ip" entry) when address collect address)))
    (or external
        (let ((address (gethash "clusterIP" (gethash "spec" service))))
          (when (and (stringp address) (not (equal "None" address))) (list address))))))

(defun foreign-gateway-listener-tls-error (view namespace listener)
  "Return the unresolved TLS reference reason for a terminating listener."
  (when (or (equal (gethash "protocol" listener) "HTTPS")
            (and (equal (gethash "protocol" listener) "TLS")
                 (equal (gethash "mode" (gethash "tls" listener (make-hash-table))) "Terminate")))
    (multiple-value-bind (reference error-reason)
        (gateway-listener-tls-ref namespace listener view)
      (or error-reason
          (let* ((secret (and view reference
                              (ignore-errors (get-core-resource view "secrets" (car reference) (cdr reference)))))
                 (data (and secret (gethash "data" secret))))
            (unless (and data (gethash "tls.crt" data) (gethash "tls.key" data)
                         (gateway-tls-material-valid-p (gethash "tls.crt" data) (gethash "tls.key" data)))
              "InvalidCertificateRef"))))))

(defun foreign-gateway-publish-gateway-status (cluster gateway routes addresses &optional view)
  (let* ((metadata (gethash "metadata" gateway))
         (generation (gethash "generation" metadata))
         (listeners (coerce (foreign-gateway-vector (gethash "listeners" (gethash "spec" gateway))) 'list))
         (supported-count (count-if (lambda (listener)
                                     (foreign-gateway-listener-supported-kinds (gethash "protocol" listener))) listeners))
         (usable-count (count-if (lambda (listener)
                                  (and (foreign-gateway-listener-supported-kinds (gethash "protocol" listener))
                                       (not (foreign-gateway-listener-tls-error
                                             view (gethash "namespace" metadata) listener)))) listeners))
         (existing-status (gethash "status" gateway (make-hash-table :test 'equal)))
         (status (make-hash-table :test 'equal)))
    (setf (gethash "addresses" status)
          (coerce (loop for address in addresses
                        collect (let ((entry (make-hash-table :test 'equal)))
                                  (setf (gethash "type" entry) "IPAddress"
                                        (gethash "value" entry) address)
                                  entry))
                  'vector)
          (gethash "conditions" status)
          (vector (foreign-gateway-condition "Accepted" (if (plusp supported-count) "True" "False")
                                             (if (= supported-count (length listeners)) "Accepted" "ListenersNotValid")
                                             :generation generation
                                             :existing (gethash "conditions" existing-status))
                  (foreign-gateway-condition "Programmed" (if (plusp usable-count) "True" "False")
                                             (if (plusp usable-count) "Programmed" "Invalid")
                                             :generation generation
                                             :existing (gethash "conditions" existing-status)))
          (gethash "listeners" status)
          (coerce
           (loop for listener across (foreign-gateway-vector
                                      (gethash "listeners" (gethash "spec" gateway)))
                 collect
                 (let ((protocol-ok (foreign-gateway-listener-supported-kinds
                                     (gethash "protocol" listener)))
                       (tls-error (foreign-gateway-listener-tls-error
                                   view (gethash "namespace" metadata) listener))
                       (entry (make-hash-table :test 'equal))
                       (existing-listener
                         (find (gethash "name" listener)
                               (coerce (gethash "listeners" existing-status #()) 'list)
                               :test #'equal
                               :key (lambda (candidate) (gethash "name" candidate)))))
                   (multiple-value-bind (supported-kinds kinds-ok)
                       (foreign-gateway-listener-route-kinds listener)
                     (setf (gethash "name" entry) (gethash "name" listener)
                           (gethash "supportedKinds" entry) (coerce supported-kinds 'vector)
                           (gethash "attachedRoutes" entry)
                           (count-if (lambda (route)
                                       (and protocol-ok
                                            (gateway-route-attaches-p
                                             route (gethash "namespace" metadata) (gethash "name" metadata)
                                             (gethash "name" listener) (gethash "port" listener))
                                            (gateway-listener-route-hostnames route listener)
                                            (gateway-listener-allows-route-p view route (gethash "namespace" metadata) listener))) routes)
                           (gethash "conditions" entry)
                           ;; The spec requires Accepted, Programmed and
                           ;; ResolvedRefs; ResolvedRefs is False with reason
                           ;; InvalidRouteKinds when an allowedRoutes kind is one
                           ;; this listener's protocol does not serve.
                           (vector (foreign-gateway-condition
                                    "Accepted" (if protocol-ok "True" "False")
                                    (if protocol-ok "Accepted" "UnsupportedProtocol")
                                    :generation generation
                                    :existing (and existing-listener
                                                   (gethash "conditions" existing-listener)))
                                   (foreign-gateway-condition
                                    "Programmed" (if (and protocol-ok (not tls-error)) "True" "False")
                                    (if (and protocol-ok (not tls-error)) "Programmed" "Invalid")
                                    :generation generation
                                    :existing (and existing-listener
                                                   (gethash "conditions" existing-listener)))
                                   (foreign-gateway-condition
                                    "ResolvedRefs" (if (and kinds-ok (not tls-error)) "True" "False")
                                    (or tls-error (if kinds-ok "ResolvedRefs" "InvalidRouteKinds"))
                                    :generation generation
                                    :existing (and existing-listener
                                                   (gethash "conditions" existing-listener))))))
                   entry))
           'vector))
    (foreign-gateway-put-status cluster "gateway.networking.k8s.io" "v1" "gateways"
                                (gethash "namespace" metadata) (gethash "name" metadata)
                                status)))

(defun gateway-route-parent-acceptance (view route gateway parent)
  "Accepted reason for this particular parentRef, using dataplane admission rules."
  (let* ((metadata (gethash "metadata" gateway))
         (namespace (gethash "namespace" metadata))
         (route-namespace (gethash "namespace" (gethash "metadata" route)))
         (listeners
           (remove-if-not
            (lambda (listener)
              (gateway-parent-matches-p parent route-namespace namespace (gethash "name" metadata)
                                        (gethash "name" listener) (gethash "port" listener)))
            (coerce (gethash "listeners" (gethash "spec" gateway) #()) 'list)))
         (allowed
           (remove-if-not
            (lambda (listener)
              (and (member (gethash "protocol" listener) '("HTTP" "HTTPS") :test #'equal)
                   (gateway-listener-allows-route-p view route namespace listener))) listeners)))
    (cond ((null listeners) "NoMatchingParent")
          ((null allowed) "NotAllowedByListeners")
          ((notany (lambda (listener) (gateway-listener-route-hostnames route listener)) allowed)
           "NoMatchingListenerHostname")
          (t "Accepted"))))

(defun gateway-route-backend-reference-error (view route)
  "First invalid backend reason, shared with the forwarding resolver."
  (let ((namespace (gethash "namespace" (gethash "metadata" route))))
    (loop for rule across (gethash "rules" (gethash "spec" route) #())
          thereis (loop for reference across (gethash "backendRefs" rule #())
                        thereis (gateway-backend-reference-error
                                 view (gw-parse-backend reference namespace))))))

(defun foreign-gateway-publish-route-status (cluster route gateways &optional view)
  (let* ((metadata (gethash "metadata" route))
         (namespace (gethash "namespace" metadata))
         (backend-error (gateway-route-backend-reference-error view route))
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
                   collect (let ((reason (gateway-route-parent-acceptance view route gateway parent))
                                 (entry (make-hash-table :test 'equal))
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
                                            "Accepted" (if (equal reason "Accepted") "True" "False") reason
                                            :generation (gethash "generation" metadata)
                                            :existing (and existing-parent
                                                           (gethash "conditions" existing-parent)))
                                           (foreign-gateway-condition
                                            "ResolvedRefs" (if backend-error "False" "True")
                                            (or backend-error "ResolvedRefs")
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
         (routes (list-core-resources view "httproutes")))
    (foreign-gateway-publish-class-status view cluster)
    (dolist (gateway gateways)
      (handler-case
          (let ((service (foreign-gateway-provision-service cluster gateway)))
            (foreign-gateway-publish-gateway-status cluster gateway
                                                  (foreign-gateway-attached-routes gateway routes)
                                                  (when service (foreign-gateway-service-addresses service)) view))
        (error (condition)
          (let ((metadata (gethash "metadata" gateway)))
            (format *error-output* "~&gr8s Gateway ~A/~A publication failed: ~A~%"
                    (gethash "namespace" metadata) (gethash "name" metadata) condition)))))
    (dolist (route routes)
      (foreign-gateway-publish-route-status cluster route gateways view))))

(defstruct foreign-gateway-view source gateway-key)

(defun foreign-gateway-key (gateway)
  (let ((metadata (gethash "metadata" gateway)))
    (list (gethash "namespace" metadata) (gethash "name" metadata)
          (gethash "uid" metadata))))

(defmethod list-core-resources ((view foreign-gateway-view) resource &optional namespace)
  "Keep Gateway and Ingress routing domains separate; share backend discovery."
  (multiple-value-bind (objects revision)
      (list-core-resources (foreign-gateway-view-source view) resource namespace)
    (values
     (cond ((equal resource "gateways")
            (remove-if-not (lambda (gateway)
                             (equal (foreign-gateway-view-gateway-key view)
                                    (foreign-gateway-key gateway))) objects))
           ((and (equal resource "ingresses") (foreign-gateway-view-gateway-key view)) nil)
           (t objects))
     revision)))

(defmethod get-core-resource ((view foreign-gateway-view) resource namespace name)
  (get-core-resource (foreign-gateway-view-source view) resource namespace name))

(defstruct foreign-gateway-controllers view resolver cert-dir ingress leases
  (gateways (make-hash-table :test #'equal)))

(defun make-foreign-gateway-listener-controller (view resolver cert-dir &key private port-fn)
  (flet ((bind-port (port)
           (cond (port-fn (funcall port-fn port))
                 (private 0)
                 ((<= +foreign-gateway-first-port+ port +foreign-gateway-last-port+)
                  (error "Ingress port ~D overlaps dedicated Gateway listener ports" port))
                 (t port))))
  (make-gateway-controller
   view :resolver resolver :cert-dir cert-dir
   :start-fn (lambda (port router resolver tls)
               (start-gateway-listener :address "0.0.0.0" :port (bind-port port)
                                       :router router :resolver resolver :tls tls))
   :l4-start-fn (lambda (port mode dispatcher resolver)
                  (start-l4-listener :address "0.0.0.0" :port (bind-port port)
                                     :mode mode :dispatcher dispatcher :resolver resolver)))))

(defun retire-foreign-gateway-obsolete-l4-listeners (controller gateway)
  "Free an old TCP/TLS socket before HTTP tries to bind the same durable lease."
  (let* ((running (gateway-controller-l4-listeners controller))
         (desired (loop for listener across (foreign-gateway-vector
                                             (gethash "listeners" (gethash "spec" gateway)))
                        when (member (gethash "protocol" listener) '("TCP" "TLS") :test #'equal)
                          collect (gethash "port" listener))))
    (dolist (port (loop for port being the hash-keys of running
                       unless (member port desired) collect port))
      (funcall (gateway-controller-unregister-fn controller) port)
      (funcall (gateway-controller-l4-stop-fn controller) (cdr (gethash port running)))
      (remhash port running))))

(defun converge-foreign-gateway-listeners (controllers)
  "Each Gateway UID owns its routing tables and private node sockets."
  (let* ((view (foreign-gateway-controllers-view controllers))
         (running (foreign-gateway-controllers-gateways controllers))
         (desired (make-hash-table :test #'equal)))
    (dolist (gateway (list-core-resources view "gateways"))
      (when (gateway-controlled-p view gateway)
        (let* ((key (foreign-gateway-key gateway))
               (controller (or (gethash key running)
                               (setf (gethash key running)
                                     (make-foreign-gateway-listener-controller
                                      (make-foreign-gateway-view :source view :gateway-key key)
                                      (foreign-gateway-controllers-resolver controllers)
                                      (foreign-gateway-controllers-cert-dir controllers)
                                      :private t
                                      :port-fn (when (foreign-gateway-controllers-leases controllers)
                                                 (lambda (port)
                                                   (foreign-gateway-port-for
                                                    (foreign-gateway-controllers-leases controllers)
                                                    key port))))))))
          (setf (gethash key desired) t)
          (handler-case
              (progn
                (retire-foreign-gateway-obsolete-l4-listeners controller gateway)
                (converge-gateway-listeners controller)
                (converge-gateway-l4-listeners controller))
            (error (condition)
              (format *error-output* "~&gr8s Gateway ~A/~A listener convergence failed: ~A~%"
                      (first key) (second key) condition))))))
    (dolist (key (loop for key being the hash-keys of running
                      unless (gethash key desired) collect key))
      (stop-gateway-controller (gethash key running))
      (remhash key running))
    ;; Preserve the existing Ingress entry point without merging its routes
    ;; into any Gateway's Service-addressed listeners.
    (converge-gateway-listeners (foreign-gateway-controllers-ingress controllers))
    (converge-gateway-l4-listeners (foreign-gateway-controllers-ingress controllers))))

(defun stop-foreign-gateway-listeners (controllers)
  (maphash (lambda (key controller) (declare (ignore key)) (stop-gateway-controller controller))
           (foreign-gateway-controllers-gateways controllers))
  (clrhash (foreign-gateway-controllers-gateways controllers))
  (stop-gateway-controller (foreign-gateway-controllers-ingress controllers)))

(defun start-foreign-gateway (view &key cert-dir resolver cluster node-name
                                        (lease-namespace "kube-system"))
  "A Gateway controller over the foreign VIEW, for the CNI agent's loop.
Returns (values CONVERGER STOPPER).  CONVERGER reconciles the HTTP and L4
listener plans; with CLUSTER and NODE-NAME it also contends for the
gr8s-gateway Lease, and the holder writes Gateway API statuses and provisions
the per-Gateway LoadBalancer Services.  RESOLVER overrides backend resolution
(tests)."
  (when (and cluster node-name)
    (validate-foreign-gateway-port-range
     (uiop:read-file-string "/proc/sys/net/ipv4/ip_local_port_range")))
  (let ((controllers
          (make-foreign-gateway-controllers
           :view view :resolver resolver :cert-dir cert-dir
           :leases (when (and cluster node-name)
                     (unless cert-dir
                       (error "Foreign Gateway listeners require a persistent certificate/state directory"))
                     (make-foreign-gateway-port-leases
                      :cluster cluster :node-name node-name :namespace lease-namespace
                      :identity-path (merge-pathnames "port-ledger.uid"
                                                      (uiop:ensure-directory-pathname cert-dir))))
           :ingress (make-foreign-gateway-listener-controller
                     (make-foreign-gateway-view :source view) resolver cert-dir)))
        (leader nil) (stopping nil) (lease-thread nil) (status-thread nil)
        (listener-thread nil)
        (convergence-lock (bt:make-lock "gr8s foreign Gateway convergence")))
    ;; Converge the listener plans on their own responsive cadence rather than
    ;; behind the agent's shared nudge loop, where a burst of unrelated object
    ;; churn delayed a new Gateway's listener from binding for tens of seconds.
    (setf listener-thread
          (bt:make-thread
           (lambda ()
             (loop until stopping do
               (handler-case
                   (bt:with-lock-held (convergence-lock)
                     (converge-foreign-gateway-listeners controllers))
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
                 (handler-case
                     (foreign-gateway-publish-local-endpoints
                      view cluster node-name
                      (bt:with-lock-held (convergence-lock)
                        (foreign-gateway-listener-snapshots controllers)))
                   (error (condition)
                     (format *error-output* "~&gr8s gateway endpoint publication failed: ~A~%" condition)))
                 (sleep 2)))
             :name "gr8s gateway status")))
    (values
     ;; Listener convergence runs in its own thread above; the agent loop's
     ;; converger need do nothing, but converge once more so a nudge still
     ;; takes effect immediately rather than waiting for the next tick. Both
     ;; entry points serialize the whole HTTP/L4 pass over this controller.
     (lambda ()
       (bt:with-lock-held (convergence-lock)
         (unless stopping
           (ignore-errors (converge-foreign-gateway-listeners controllers)))))
     (lambda ()
       (setf stopping t)
       (when listener-thread (ignore-errors (bt:join-thread listener-thread)))
       (when lease-thread (ignore-errors (bt:join-thread lease-thread)))
       (when status-thread (ignore-errors (bt:join-thread status-thread)))
       (when (and cluster node-name)
         (handler-case (foreign-gateway-withdraw-local-endpoints cluster node-name)
           (error (condition)
             (format *error-output* "~&gr8s Gateway endpoint withdrawal failed: ~A~%" condition))))
       (bt:with-lock-held (convergence-lock)
         (stop-foreign-gateway-listeners controllers))))))
