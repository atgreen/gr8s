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

(defun foreign-gateway-put-status (cluster group version resource namespace name status
                                   &key expected-uid expected-generation route-controller)
  "Write STATUS through the status subresource unless it is already current.
Returns quietly on write conflicts; the next pass retries."
  (handler-case
      (let* ((path (gr8s.kube-client:resource-path group version resource
                                                   :namespace namespace :name name))
             (current (gr8s.kube-client:kube-get cluster path)))
        (when (or (and expected-uid
                       (not (equal expected-uid (gethash "uid" (gethash "metadata" current)))))
                  (and expected-generation
                       (not (eql expected-generation (gethash "generation" (gethash "metadata" current))))))
          (return-from foreign-gateway-put-status nil))
        (when route-controller
          (let* ((latest (gethash "status" current (make-hash-table :test 'equal)))
                 (merged (gr8s.resources::copy-core-object latest)))
            (setf (gethash "parents" merged)
                  (coerce
                   (append
                    (remove-if (lambda (entry) (equal route-controller (gethash "controllerName" entry)))
                               (coerce (gethash "parents" latest #()) 'list))
                    (remove-if-not (lambda (entry) (equal route-controller (gethash "controllerName" entry)))
                                   (coerce (gethash "parents" status #()) 'list))) 'vector)
                  status merged)))
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
              (gr8s.kube-client:kube-replace cluster path current))))
        t)
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

(defun foreign-gateway-listener-route-kinds
    (listener &optional (supported (foreign-gateway-listener-supported-kinds (gethash "protocol" listener))))
  "The listener's resolved supportedKinds and whether every allowedRoutes kind
is among them.  Returns (values supported-kind-objects all-allowed-supported-p)."
  (let* ((supported-names (mapcar (lambda (k) (gethash "kind" k)) supported))
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

(defun foreign-gateway-service-ports (gateway &optional existing view)
  "One stable Service port per public TCP port, even with many hostname listeners."
  (let ((seen (make-hash-table)) (ports nil))
    (loop for entry in (gateway-listener-entries
                       view gateway (when view (list-core-resources view "listenersets")))
          for listener = (gateway-listener-entry-listener entry)
          for number = (gethash "port" listener)
          when (and (null (gateway-listener-entry-error entry))
                    (member (gethash "protocol" listener) '("HTTP" "HTTPS" "TCP" "TLS") :test #'equal)
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

(defun foreign-gateway-provision-service (cluster gateway &optional view)
  "Reconcile the Gateway-owned selectorless Service without adopting name collisions."
  (when (zerop (length (foreign-gateway-service-ports gateway nil view)))
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
           (ports (foreign-gateway-service-ports gateway (gethash "ports" spec) view))
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

(defun foreign-gateway-listener-tls-error (view namespace listener
                                         &optional (source-kind "Gateway")
                                           (source-group "gateway.networking.k8s.io"))
  "Return the unresolved TLS reference reason for a terminating listener."
  (when (or (equal (gethash "protocol" listener) "HTTPS")
            (and (equal (gethash "protocol" listener) "TLS")
                 (equal (gethash "mode" (gethash "tls" listener (make-hash-table))) "Terminate")))
    (multiple-value-bind (reference error-reason)
        (gateway-listener-tls-ref namespace listener view source-kind source-group)
      (or error-reason
          (let* ((secret (and view reference
                              (ignore-errors (get-core-resource view "secrets" (car reference) (cdr reference)))))
                 (data (and secret (gethash "data" secret))))
            (unless (and data (gethash "tls.crt" data) (gethash "tls.key" data)
                         (gateway-tls-material-valid-p (gethash "tls.crt" data) (gethash "tls.key" data)))
              "InvalidCertificateRef"))))))

(defun foreign-listenerset-route-attached-p (view owner listener route admitted definitions)
  "Count structural attachments for XListenerSet, accepted parents for stable API.
Use the same current acceptance decision as route status, not prior API status."
  (let* ((metadata (gethash "metadata" owner))
         (namespace (gethash "namespace" metadata))
         (kind (gethash "kind" owner "ListenerSet")))
    (and (gateway-listener-allows-route-p view route namespace listener)
         (some (lambda (parent)
                 (and (gateway-parent-matches-p
                       parent (gethash "namespace" (gethash "metadata" route))
                       namespace (gethash "name" metadata)
                       (gethash "name" listener) (gethash "port" listener)
                       kind (gateway-listener-owner-group owner))
                      (or (equal kind "XListenerSet")
                          (and admitted
                               (equal "Accepted" (gateway-route-parent-acceptance
                                                  view route owner parent definitions))))))
               (gethash "parentRefs" (gethash "spec" route) #())))))

(defun foreign-listenerset-status (view owner gateway entries routes programmed-p)
  "Describe a ListenerSet. PROGRAMMED-P must test an actually installed entry."
  (let* ((metadata (gethash "metadata" owner))
         (generation (gethash "generation" metadata))
         (namespace (gethash "namespace" metadata))
         (group (gateway-listener-owner-group owner))
         (kind (gethash "kind" owner "ListenerSet"))
         (owner-key (list group kind namespace (gethash "name" metadata)))
         (definitions (loop for entry in entries
                            when (and (equal owner-key (gateway-listener-owner-key entry))
                                      (null (gateway-listener-entry-error entry)))
                              collect (gateway-listener-entry-listener entry)))
         (parent-accepted (and gateway (gateway-controlled-p view gateway)))
         (admitted (and parent-accepted (gateway-listenerset-admitted-p view gateway owner)))
         (existing (gethash "status" owner (make-hash-table :test 'equal)))
         (accepted-count 0) (programmed-count 0) (invalid-count 0) (unsupported-port nil)
         (statuses nil))
    (labels ((condition (type value reason prior)
               (foreign-gateway-condition type (if value "True" "False") reason
                                          :generation generation :existing (gethash "conditions" prior))))
      (loop for listener across (gethash "listeners" (gethash "spec" owner) #())
            for name = (gethash "name" listener)
            for entry = (or (find-if (lambda (entry)
                                      (and (equal owner-key (gateway-listener-owner-key entry))
                                           (equal name (gethash "name" (gateway-listener-entry-listener entry))))) entries)
                            (make-gateway-listener-entry :gateway gateway :owner owner :listener listener))
            for prior = (or (find name (gethash "listeners" existing #())
                                 :key (lambda (status) (gethash "name" status)) :test #'equal)
                            (make-hash-table :test 'equal))
            for conflict = (gateway-listener-entry-conflict entry)
            for port-ok = (gateway-listener-port-supported-p listener)
            for supported = (member (gethash "protocol" listener) '("HTTP" "HTTPS") :test #'equal)
            for tls-error = (foreign-gateway-listener-tls-error view namespace listener kind group)
            for accepted = (and admitted supported port-ok (null conflict))
            do (multiple-value-bind (kinds kinds-ok)
                   (foreign-gateway-listener-route-kinds
                    listener (when supported
                               (list (gr8s.resources::core-object
                                      "group" "gateway.networking.k8s.io" "kind" "HTTPRoute"))))
                 (let* ((refs-error (or tls-error (unless kinds-ok "InvalidRouteKinds")))
                        (programmed (and accepted (not refs-error) (funcall programmed-p entry))))
                   (when accepted (incf accepted-count))
                   (when programmed (incf programmed-count))
                   (unless port-ok (setf unsupported-port t))
                   (when (or (not supported) (not port-ok) conflict refs-error) (incf invalid-count))
                   ;; The experimental schema requires a positive status port.
                   ;; Omit unbound dynamic entries rather than inventing a port.
                   (unless (and (equal kind "XListenerSet") (not port-ok))
                   (push
                    (gr8s.resources::core-object
                     "name" name "supportedKinds" (if supported (coerce kinds 'vector) #())
                     "attachedRoutes"
                     (count-if
                      (lambda (route)
                        (foreign-listenerset-route-attached-p
                         view owner listener route admitted definitions)) routes)
                     "conditions"
                     (vector
                      (condition "Accepted" accepted
                                 (cond ((not admitted) "NotAllowed") ((not port-ok) "UnsupportedPort")
                                       ((not supported) "UnsupportedProtocol")
                                       (conflict conflict) (t "Accepted")) prior)
                      (condition "Conflicted" conflict (or conflict "NoConflicts") prior)
                      (condition "ResolvedRefs" (null refs-error) (or refs-error "ResolvedRefs") prior)
                      (condition "Programmed" programmed
                                 (cond (programmed "Programmed") ((or (not accepted) refs-error) "Invalid")
                                       (t "Pending")) prior))) statuses)
                   (when (equal kind "XListenerSet")
                     (setf (gethash "port" (first statuses)) (gethash "port" listener)))))))
      (let* ((accepted (and admitted (plusp accepted-count)))
             (accepted-reason (cond ((not parent-accepted) "ParentNotAccepted")
                                    ((not admitted) "NotAllowed")
                                    ((and (not accepted) unsupported-port) "UnsupportedPort")
                                    ((or (not accepted) (plusp invalid-count)) "ListenersNotValid")
                                    (t "Accepted")))
             (programmed (and accepted (plusp programmed-count))))
        (gr8s.resources::core-object
         "listeners" (coerce (nreverse statuses) 'vector)
         "conditions"
         (vector (condition "Accepted" accepted accepted-reason existing)
                 (condition "Programmed" programmed
                            (cond (programmed "Programmed") ((not parent-accepted) "ParentNotProgrammed")
                                  ((not admitted) "Invalid") ((plusp invalid-count) "ListenersNotValid")
                                  (t "Pending")) existing)))))))

(defun foreign-gateway-condition-true-p (status type)
  (let ((condition (find type (gethash "conditions" status #())
                         :key (lambda (entry) (gethash "type" entry)) :test #'equal)))
    (and condition (equal "True" (gethash "status" condition)))))

(defun foreign-gateway-publish-gateway-status (cluster gateway routes addresses
                                             &optional view listener-set-statuses
                                               (programmed-p (constantly nil)))
  (let* ((metadata (gethash "metadata" gateway))
         (generation (gethash "generation" metadata))
         (listeners (coerce (foreign-gateway-vector (gethash "listeners" (gethash "spec" gateway))) 'list))
         (installed-listeners
           (remove-if-not
            (lambda (listener)
              (funcall programmed-p
                       (make-gateway-listener-entry :gateway gateway :owner gateway :listener listener)
                       view))
            listeners))
         (supported-count (count-if (lambda (listener)
                                     (foreign-gateway-listener-supported-kinds (gethash "protocol" listener))) listeners))
         (usable-count (count-if (lambda (listener)
                                  (and (member listener installed-listeners :test #'eq)
                                       (foreign-gateway-listener-supported-kinds (gethash "protocol" listener))
                                       (not (foreign-gateway-listener-tls-error
                                             view (gethash "namespace" metadata) listener)))) listeners))
         (attached-sets (count-if (lambda (status) (foreign-gateway-condition-true-p status "Accepted"))
                                 listener-set-statuses))
         (programmed-sets (count-if (lambda (status)
                                     (and (foreign-gateway-condition-true-p status "Accepted")
                                          (foreign-gateway-condition-true-p status "Programmed"))) listener-set-statuses))
         (accepted (or (plusp supported-count) (plusp attached-sets)))
         (programmed (or (plusp usable-count) (plusp programmed-sets)))
         (existing-status (gethash "status" gateway (make-hash-table :test 'equal)))
         (status (make-hash-table :test 'equal)))
    (setf (gethash "attachedListenerSets" status) attached-sets
          (gethash "addresses" status)
          (coerce (loop for address in addresses
                        collect (let ((entry (make-hash-table :test 'equal)))
                                  (setf (gethash "type" entry) "IPAddress"
                                        (gethash "value" entry) address)
                                  entry))
                  'vector)
          (gethash "conditions" status)
          (vector (foreign-gateway-condition "Accepted" (if accepted "True" "False")
                                             (if (and accepted (= supported-count (length listeners))) "Accepted" "ListenersNotValid")
                                             :generation generation
                                             :existing (gethash "conditions" existing-status))
                  (foreign-gateway-condition "Programmed" (if programmed "True" "False")
                                             (cond (programmed "Programmed") (accepted "Pending") (t "Invalid"))
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
                                    "Programmed" (if (and protocol-ok (not tls-error)
                                                          (member listener installed-listeners :test #'eq))
                                                     "True" "False")
                                    (cond ((or (not protocol-ok) tls-error) "Invalid")
                                          ((member listener installed-listeners :test #'eq) "Programmed")
                                          (t "Pending"))
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
                                status :expected-uid (gethash "uid" metadata)
                                :expected-generation generation)))

(defun gateway-route-parent-acceptance (view route gateway parent &optional (definitions nil definitions-p))
  "Accepted reason for this particular parentRef, using dataplane admission rules."
  (let* ((metadata (gethash "metadata" gateway))
         (namespace (gethash "namespace" metadata))
         (route-namespace (gethash "namespace" (gethash "metadata" route)))
         (listeners
           (remove-if-not
            (lambda (listener)
              (gateway-parent-matches-p parent route-namespace namespace (gethash "name" metadata)
                                        (gethash "name" listener) (gethash "port" listener)
                                        (gethash "kind" gateway "Gateway") (gateway-listener-owner-group gateway)))
            (if definitions-p definitions
                (coerce (gethash "listeners" (gethash "spec" gateway) #()) 'list))))
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

(defun foreign-route-parent-key (parent namespace)
  (list (gethash "group" parent "gateway.networking.k8s.io")
        (gethash "kind" parent "Gateway") (gethash "namespace" parent namespace)
        (gethash "name" parent)))

(defun foreign-route-parent-status-key (parent namespace)
  (append (foreign-route-parent-key parent namespace)
          (list (gethash "sectionName" parent) (gethash "port" parent))))

(defun foreign-route-owner-index (view gateways)
  "Index controlled owners and winning logical listeners once per status pass."
  (let ((index (make-hash-table :test 'equal))
        (sets (when view (list-core-resources view "listenersets"))))
    (dolist (gateway gateways)
      (setf (gethash (gateway-listener-owner-key (make-gateway-listener-entry :owner gateway)) index)
            (list gateway gateway nil)))
    (dolist (owner sets)
      (let* ((parent (gethash "parentRef" (gethash "spec" owner)))
             (record (gethash (foreign-route-parent-key parent (gethash "namespace" (gethash "metadata" owner))) index)))
        (when (and record (equal "Gateway" (gethash "kind" (first record) "Gateway")))
          (setf (gethash (gateway-listener-owner-key (make-gateway-listener-entry :owner owner)) index)
                (list owner (first record) nil)))))
    (dolist (gateway gateways)
      (dolist (entry (gateway-listener-entries view gateway sets))
        (let ((record (gethash (gateway-listener-owner-key entry) index)))
          (when (and record (null (gateway-listener-entry-error entry)))
            (push (gateway-listener-entry-listener entry) (third record))))))
    index))

(defun foreign-gateway-publish-route-status (cluster route gateways &optional view owner-index)
  (let* ((metadata (gethash "metadata" route))
         (namespace (gethash "namespace" metadata))
         (backend-error (gateway-route-backend-reference-error view route))
         (existing (gethash "status" route (make-hash-table :test 'equal)))
         (previous (coerce (gethash "parents" existing #()) 'list))
         (index (or owner-index (foreign-route-owner-index view gateways)))
         (ours nil))
    (dolist (parent (foreign-gateway-route-parents route))
      (let ((record (gethash (foreign-route-parent-key parent namespace) index)))
        (when record
          (destructuring-bind (owner gateway definitions) record
            (let* ((reason (if (or (eq owner gateway) (gateway-listenerset-admitted-p view gateway owner))
                               (gateway-route-parent-acceptance view route owner parent definitions)
                               "NotAllowedByListeners"))
                   (key (foreign-route-parent-status-key parent namespace))
                   (prior (find-if (lambda (entry)
                                     (and (equal *gateway-controller-name* (gethash "controllerName" entry))
                                          (equal key (foreign-route-parent-status-key (gethash "parentRef" entry) namespace))))
                                   previous)))
              (push (gr8s.resources::core-object
                     "parentRef" parent "controllerName" *gateway-controller-name*
                     "conditions"
                     (vector (foreign-gateway-condition
                              "Accepted" (if (equal reason "Accepted") "True" "False") reason
                              :generation (gethash "generation" metadata)
                              :existing (and prior (gethash "conditions" prior)))
                             (foreign-gateway-condition
                              "ResolvedRefs" (if backend-error "False" "True") (or backend-error "ResolvedRefs")
                              :generation (gethash "generation" metadata)
                              :existing (and prior (gethash "conditions" prior))))) ours))))))
    (when (or ours (some (lambda (entry) (equal *gateway-controller-name* (gethash "controllerName" entry))) previous))
      (let ((status (gr8s.resources::copy-core-object existing)))
        (setf (gethash "parents" status)
              (coerce (append (remove-if (lambda (entry) (equal *gateway-controller-name* (gethash "controllerName" entry))) previous)
                              (nreverse ours)) 'vector))
        (foreign-gateway-put-status cluster "gateway.networking.k8s.io" "v1" "httproutes"
                                    namespace (gethash "name" metadata) status
                                    :expected-uid (gethash "uid" metadata)
                                    :expected-generation (gethash "generation" metadata)
                                    :route-controller *gateway-controller-name*)))))

(defun foreign-gateway-publish-listenersets (view cluster routes programmed-p)
  "Publish each selected API's ListenerSets without conflating owner identities."
  (let ((sets (list-core-resources view "listenersets"))
        (published-by-gateway (make-hash-table :test 'equal))
        (gateways (make-hash-table :test 'equal))
        (entries-by-gateway (make-hash-table :test 'equal))
        (routes-by-parent (gateway-route-parent-index routes)))
    (dolist (gateway (list-core-resources view "gateways"))
      (let ((metadata (gethash "metadata" gateway)))
        (setf (gethash (list (gethash "namespace" metadata) (gethash "name" metadata)) gateways) gateway)))
    (dolist (owner sets published-by-gateway)
      (let* ((metadata (gethash "metadata" owner))
             (namespace (gethash "namespace" metadata))
             (parent (gethash "parentRef" (gethash "spec" owner)))
             (parent-key (list (gethash "namespace" parent namespace) (gethash "name" parent)))
             (gateway (gethash parent-key gateways)))
        ;; A Gateway owned by another implementation also owns its child status.
        (when (or (null gateway) (gateway-controlled-p view gateway))
          (handler-case
              (let* ((owner-key (gateway-listener-owner-key (make-gateway-listener-entry :owner owner)))
                     (entry-index
                       (when gateway
                         (or (gethash parent-key entries-by-gateway)
                             (setf (gethash parent-key entries-by-gateway)
                                   (let ((index (make-hash-table :test 'equal)))
                                     (dolist (entry (gateway-listener-entries view gateway sets) index)
                                       (push entry (gethash (gateway-listener-owner-key entry) index))))))))
                     (status (foreign-listenerset-status
                              view owner gateway (and entry-index (gethash owner-key entry-index))
                              (gethash owner-key routes-by-parent)
                              (lambda (entry) (funcall programmed-p entry view))))
                     (api (gethash "apiVersion" owner))
                     (slash (position #\/ api)))
                (when (foreign-gateway-put-status
                 cluster (subseq api 0 slash) (subseq api (1+ slash))
                 (if (equal "XListenerSet" (gethash "kind" owner)) "xlistenersets" "listenersets")
                 namespace (gethash "name" metadata) status
                 :expected-uid (gethash "uid" metadata)
                 :expected-generation (gethash "generation" metadata))
                  (when gateway
                    (push status (gethash (foreign-gateway-key gateway) published-by-gateway)))))
            (error (condition)
              (format *error-output* "~&gr8s ListenerSet ~A/~A status publication failed: ~A~%"
                      namespace (gethash "name" metadata) condition))))))))

(defun foreign-gateway-publish (view cluster &optional (programmed-p (constantly nil)))
  "The lease-holder's pass: statuses and per-Gateway LoadBalancer Services."
  (let* ((gateways (remove-if-not (lambda (gateway) (gateway-controlled-p view gateway))
                                  (list-core-resources view "gateways")))
         (routes (list-core-resources view "httproutes"))
         (route-owners (foreign-route-owner-index view gateways))
         (listener-set-statuses (foreign-gateway-publish-listenersets view cluster routes programmed-p)))
    (foreign-gateway-publish-class-status view cluster)
    (dolist (gateway gateways)
      (handler-case
          (let ((service (foreign-gateway-provision-service cluster gateway view)))
            (foreign-gateway-publish-gateway-status cluster gateway
                                                  (foreign-gateway-attached-routes gateway routes)
                                                  (when service (foreign-gateway-service-addresses service)) view
                                                  (gethash (foreign-gateway-key gateway) listener-set-statuses)
                                                  programmed-p))
        (error (condition)
          (let ((metadata (gethash "metadata" gateway)))
            (format *error-output* "~&gr8s Gateway ~A/~A publication failed: ~A~%"
                    (gethash "namespace" metadata) (gethash "name" metadata) condition)))))
    (dolist (route routes)
      (foreign-gateway-publish-route-status cluster route gateways view route-owners))))

(defstruct foreign-gateway-view source gateway-key)

(defun foreign-gateway-key (gateway)
  (let ((metadata (gethash "metadata" gateway)))
    (list (gethash "namespace" metadata) (gethash "name" metadata)
          (gethash "uid" metadata))))

(defmethod list-core-resources ((view foreign-gateway-view) resource &optional namespace)
  "Keep Gateway and Ingress routing domains separate; share backend discovery."
  (let ((source (foreign-gateway-view-source view))
        (key (foreign-gateway-view-gateway-key view)))
    (when (and key (equal resource "listenersets")
               (typep source 'gr8s.resources::foreign-resource-snapshot))
      (return-from list-core-resources
        (values (remove-if-not
                 (lambda (owner) (or (null namespace)
                                     (equal namespace (gethash "namespace" (gethash "metadata" owner)))))
                 (gr8s.resources::foreign-snapshot-gateway-listenersets source key))
                (write-to-string (gr8s.resources::foreign-resource-snapshot-revision source))))))
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

(defmethod gateway-parent-route-reader ((view foreign-gateway-view))
  (gateway-parent-route-reader (foreign-gateway-view-source view)))

(defstruct foreign-gateway-controllers view resolver cert-dir ingress leases
  snapshot revision retry-full-p
  (gateways (make-hash-table :test #'equal)))

(defun foreign-gateway-installed-predicate (controllers)
  "Capture under the convergence lock; subsequent API writes need no such lock."
  (let ((captured (make-hash-table :test 'equal)))
    (maphash
     (lambda (key controller)
       (let ((snapshot (copy-gateway-controller controller)))
         (setf (gateway-controller-listeners snapshot)
               (alexandria:copy-hash-table (gateway-controller-listeners controller))
               (gateway-controller-l4-listeners snapshot)
               (alexandria:copy-hash-table (gateway-controller-l4-listeners controller))
               (gateway-controller-installed-listeners snapshot)
               (alexandria:copy-hash-table (gateway-controller-installed-listeners controller))
               (gethash key captured) snapshot)))
     (foreign-gateway-controllers-gateways controllers))
    (lambda (entry view)
      (let* ((gateway (gateway-listener-entry-gateway entry))
             (controller (and gateway (gethash (foreign-gateway-key gateway) captured))))
        (and controller (gateway-listener-entry-programmed-p controller entry view))))))

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

(defun reconcile-foreign-gateway-listeners
    (controllers &optional (view (foreign-gateway-controllers-view controllers))
                           (gateway-keys nil selected-p) reuse-tls-bindings-p)
  "Each Gateway UID owns its routing tables and private node sockets."
  (let* ((running (foreign-gateway-controllers-gateways controllers))
         (success t)
         (desired (make-hash-table :test #'equal)))
    (dolist (gateway (if selected-p
                        (loop for key in gateway-keys
                              for object = (ignore-errors
                                             (get-core-resource view "gateways" (first key) (second key)))
                              when (and object (equal key (foreign-gateway-key object))) collect object)
                        (list-core-resources view "gateways")))
      (when (gateway-controlled-p view gateway)
        (let* ((key (foreign-gateway-key gateway))
               (controller (or (gethash key running)
                               (setf (gethash key running)
                                     (make-foreign-gateway-listener-controller
                                      (make-foreign-gateway-view :source view :gateway-key key)
                                      (or (foreign-gateway-controllers-resolver controllers)
                                          (make-service-backend-resolver
                                           (foreign-gateway-controllers-view controllers)))
                                      (foreign-gateway-controllers-cert-dir controllers)
                                      :private t
                                      :port-fn (when (foreign-gateway-controllers-leases controllers)
                                                 (lambda (port)
                                                   (foreign-gateway-port-for
                                                    (foreign-gateway-controllers-leases controllers)
                                                    key port))))))))
          (setf (gethash key desired) t)
          (setf (gateway-controller-store controller)
                (make-foreign-gateway-view :source view :gateway-key key))
          (handler-case
              (progn
                (retire-foreign-gateway-obsolete-l4-listeners controller gateway)
                (if reuse-tls-bindings-p
                    (converge-gateway-listeners controller :reuse-tls-bindings-p t)
                    (converge-gateway-listeners controller))
                (converge-gateway-l4-listeners controller))
            (error (condition)
              (setf success nil)
              (format *error-output* "~&gr8s Gateway ~A/~A listener convergence failed: ~A~%"
                      (first key) (second key) condition))))))
    (dolist (key (loop for key being the hash-keys of running
                      when (and (or (not selected-p) (member key gateway-keys :test #'equal))
                                (not (gethash key desired))) collect key))
      (stop-gateway-controller (gethash key running))
      (remhash key running))
    ;; Preserve the existing Ingress entry point without merging its routes
    ;; into any Gateway's Service-addressed listeners.
    (unless selected-p
      (setf (gateway-controller-store (foreign-gateway-controllers-ingress controllers))
            (make-foreign-gateway-view :source view))
      (converge-gateway-listeners (foreign-gateway-controllers-ingress controllers))
      (converge-gateway-l4-listeners (foreign-gateway-controllers-ingress controllers)))
    success))

(defun foreign-listenerset-parent-key (view owner)
  "Resolve a valid parent identity, including the Gateway incarnation."
  (when owner
    (let* ((parent (gethash "parentRef" (gethash "spec" owner)))
           (namespace (or (and parent (gethash "namespace" parent))
                          (gethash "namespace" (gethash "metadata" owner))))
           (gateway (and parent
                         (equal (gethash "group" parent "gateway.networking.k8s.io")
                                "gateway.networking.k8s.io")
                         (equal (gethash "kind" parent "Gateway") "Gateway")
                         (ignore-errors
                           (get-core-resource view "gateways" namespace (gethash "name" parent))))))
      (when gateway (foreign-gateway-key gateway)))))

(defun foreign-listenerset-changed-parents (before snapshot changes)
  "Include both sides of moves and deletion, without scanning unrelated Gateways."
  (let ((keys nil))
    (dolist (change changes keys)
      (let ((old (ignore-errors (apply #'get-core-resource before (car change)))))
        (dolist (key (list (foreign-listenerset-parent-key before old)
                          (foreign-listenerset-parent-key snapshot (cdr change))))
          (when key (pushnew key keys :test #'equal)))))))

(defparameter +foreign-gateway-planning-resources+
  '("gateways" "gatewayclasses" "listenersets" "httproutes"
    "grpcroutes" "tcproutes" "tlsroutes" "ingresses" "ingressclasses"
    "namespaces" "secrets" "referencegrants"))

(defun foreign-gateway-configuration-object (object)
  "Ignore API bookkeeping while preserving case-sensitive routing configuration."
  (when object
    (let* ((copy (gr8s.resources::copy-core-object object))
           (metadata (gethash "metadata" copy)))
      (remhash "status" copy)
      (when metadata
        (remhash "resourceVersion" metadata)
        (remhash "managedFields" metadata))
      copy)))

(defun foreign-gateway-secret-used-p (controllers key)
  (or (gethash (rest key) (gateway-controller-secret-ports (foreign-gateway-controllers-ingress controllers)))
      (loop for controller being the hash-values of (foreign-gateway-controllers-gateways controllers)
            thereis (gethash (rest key) (gateway-controller-secret-ports controller)))))

(defun foreign-gateway-rotate-secrets (controllers snapshot changes)
  "Update shared TLS bindings, or request full reconciliation for unsupported cases."
  (let ((keys (mapcar #'car changes)))
    (flet ((update (controller key)
             (setf (gateway-controller-store controller)
                   (make-foreign-gateway-view :source snapshot :gateway-key key))
             (unless (converge-gateway-secret-changes controller keys)
               (return-from foreign-gateway-rotate-secrets nil))))
      (maphash (lambda (key controller) (update controller key))
               (foreign-gateway-controllers-gateways controllers))
      (update (foreign-gateway-controllers-ingress controllers) nil))
    t))

(defun foreign-namespace-selector-changed-p (selector old new)
  (labels ((matches (selector object)
             (and object
                  (not (null (gr8s.resources::workload-selector-matches-p
                              selector (gethash "labels" (gethash "metadata" object))))))))
    (not (eq (matches selector old) (matches selector new)))))

(defun foreign-gateway-namespace-affects-admission-p (view old new)
  "Namespace metadata matters only when a listener selector changes admission."
  (flet ((changed (selector) (foreign-namespace-selector-changed-p selector old new)))
    (if (typep view 'gr8s.resources::foreign-resource-snapshot)
        (fset:do-map (owner selectors (gr8s.resources::foreign-resource-snapshot-namespace-selectors view))
          (declare (ignore owner))
          (when (some #'changed selectors)
            (return-from foreign-gateway-namespace-affects-admission-p t)))
        (loop for resource in '("gateways" "listenersets")
              thereis (loop for owner in (list-core-resources view resource)
                            thereis (some #'changed
                                          (gr8s.resources::foreign-owner-namespace-selectors resource owner)))))))

(defun foreign-namespace-changed-parents (before snapshot changes)
  "Select Gateway incarnations whose indexed selectors change their match."
  (let ((keys nil)
        (objects (mapcar (lambda (change)
                           (cons (ignore-errors (apply #'get-core-resource before (car change)))
                                 (cdr change))) changes)))
    (fset:do-map (owner selectors (gr8s.resources::foreign-resource-snapshot-namespace-selectors snapshot))
      (when (some (lambda (selector)
                    (some (lambda (pair) (foreign-namespace-selector-changed-p selector (car pair) (cdr pair)))
                          objects)) selectors)
        (let* ((object (apply #'get-core-resource snapshot owner))
               (key (if (equal "gateways" (first owner))
                        (foreign-gateway-key object)
                        (foreign-listenerset-parent-key snapshot object))))
          (when key (pushnew key keys :test #'equal)))))
    keys))

(defun converge-foreign-gateway-snapshot (controllers snapshot revision changes full)
  "Acknowledge a captured revision only after publication; failures force recovery."
  (let* ((before (foreign-gateway-controllers-snapshot controllers))
         (rebuild (or full (null before) (foreign-gateway-controllers-retry-full-p controllers)))
         (deltas (unless rebuild
                   (remove-if
                    (lambda (change)
                      (or (not (member (caar change) +foreign-gateway-planning-resources+ :test #'equal))
                          (and (equal "secrets" (caar change))
                               (not (foreign-gateway-secret-used-p controllers (car change))))
                          (let ((old (ignore-errors (apply #'get-core-resource before (car change)))))
                            ;; Secret resourceVersion participates in installed-state evidence.
                            (or (and (equal "namespaces" (caar change))
                                     (not (foreign-gateway-namespace-affects-admission-p snapshot old (cdr change))))
                                (gr8s.resources::core-json-equal-p
                                 (if (equal "secrets" (caar change)) old (foreign-gateway-configuration-object old))
                                 (if (equal "secrets" (caar change)) (cdr change)
                                     (foreign-gateway-configuration-object (cdr change)))))))) changes)))
         (success nil))
    (unwind-protect
         (handler-case
             (setf success
                   (cond
                     ((and (not rebuild) (null deltas)) t)
                     ((and (not rebuild)
                           (every (lambda (change) (equal "listenersets" (caar change))) deltas))
                      (reconcile-foreign-gateway-listeners
                       controllers snapshot
                       (foreign-listenerset-changed-parents before snapshot deltas) t))
                     ((and (not rebuild)
                           (typep snapshot 'gr8s.resources::foreign-resource-snapshot)
                           (every (lambda (change) (equal "namespaces" (caar change))) deltas))
                      (reconcile-foreign-gateway-listeners
                       controllers snapshot (foreign-namespace-changed-parents before snapshot deltas)))
                     ((and (not rebuild)
                           (every (lambda (change) (equal "secrets" (caar change))) deltas))
                      (or (foreign-gateway-rotate-secrets controllers snapshot deltas)
                          (reconcile-foreign-gateway-listeners controllers snapshot)))
                     ((and (not rebuild)
                           (every (lambda (change) (equal "httproutes" (caar change))) deltas))
                      (maphash
                       (lambda (key controller)
                         (let ((old (gateway-controller-store controller)))
                           (setf (gateway-controller-store controller)
                                 (make-foreign-gateway-view :source snapshot :gateway-key key))
                           (handler-case (converge-gateway-http-route-changes controller old deltas)
                             (error (condition)
                               (ignore-errors (stop-gateway-controller controller))
                               (error condition)))))
                       (foreign-gateway-controllers-gateways controllers))
                      t)
                     (t (reconcile-foreign-gateway-listeners controllers snapshot))))
           (error (condition)
             (format *error-output* "~&gr8s Gateway snapshot publication failed: ~A~%" condition)
             nil))
      (setf (foreign-gateway-controllers-retry-full-p controllers) (not success))
      (when success
        (setf (foreign-gateway-controllers-snapshot controllers) snapshot
              (foreign-gateway-controllers-revision controllers) revision)))
    success))

(defun converge-foreign-gateway-listeners (controllers)
  (let ((view (foreign-gateway-controllers-view controllers)))
    (if (typep view 'gr8s.resources::foreign-resource-view)
        (progn
          ;; Start every planning input before capturing the first coherent view.
          ;; Subsequent calls check watch health and retry discovery of optional APIs.
          (dolist (resource +foreign-gateway-planning-resources+)
            (let ((informer (gr8s.resources::foreign-view-informer view resource)))
              (when (and informer (not (gr8s.kube-client:informer-synced-p informer)))
                (error "Gateway input ~A has not synchronized" resource))))
          (multiple-value-bind (snapshot revision changes full)
              (gr8s.resources::foreign-view-snapshot view (foreign-gateway-controllers-revision controllers))
            (converge-foreign-gateway-snapshot controllers snapshot revision changes full)))
        (reconcile-foreign-gateway-listeners controllers))))

(defun stop-foreign-gateway-listeners (controllers)
  (maphash (lambda (key controller) (declare (ignore key)) (stop-gateway-controller controller))
           (foreign-gateway-controllers-gateways controllers))
  (clrhash (foreign-gateway-controllers-gateways controllers))
  (setf (foreign-gateway-controllers-snapshot controllers) nil
        (foreign-gateway-controllers-revision controllers) nil
        (foreign-gateway-controllers-retry-full-p controllers) nil)
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
                   (handler-case (foreign-gateway-publish
                                  view cluster
                                  (bt:with-lock-held (convergence-lock)
                                    (foreign-gateway-installed-predicate controllers)))
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
