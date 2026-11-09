;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Converge desired ClusterIP Service state into the socket load balancer's
;;;; BPF maps.  Each reconcile computes the full desired table from the live
;;;; Services and their backends (service-port-backends, which reads
;;;; EndpointSlices as kube-proxy does: traffic policies, terminating fallback
;;;; and topology hints), diffs it against what was last applied, and writes
;;;; only when something changed.  Backends are packed into consecutive slots in
;;;; a deterministic order so the plan is stable across ticks.
;;;;
;;;; The plan computation is pure (no kernel, no store coupling), and every map
;;;; operation is injected, so convergence is tested without privileges.

(in-package #:gr8s.controllers)

(defun service-proxied-p (service)
  "True unless SERVICE carries a label telling kube-proxy to leave it alone: a
service-proxy-name, which names another proxy, or headless."
  (let ((labels (gethash "labels" (gethash "metadata" service))))
    (not (and (hash-table-p labels)
              (or (nth-value 1 (gethash "service.kubernetes.io/service-proxy-name" labels))
                  (nth-value 1 (gethash "service.kubernetes.io/headless" labels)))))))

(defun service-lb-eligible-p (service)
  "True for a Service the socket LB should load-balance: a selector/endpoint
ClusterIP Service with a real virtual address.  ExternalName, headless (None),
the API Service (10.96.0.1, served by the real HTTPS listener), and a Service
labelled for another proxy are excluded."
  (let ((address (gethash "clusterIP" (gethash "spec" service))))
    (and (not (service-external-name-p service))
         (service-proxied-p service)
         (stringp address)
         (not (equal address "None"))
         (not (equal address "10.96.0.1")))))

(defun service-cluster-addresses (service)
  "Return every real ClusterIP of SERVICE in API order, including both families."
  (let* ((spec (gethash "spec" service))
         (addresses (gethash "clusterIPs" spec)))
    (if (and (vectorp addresses) (plusp (length addresses)))
        (coerce addresses 'list)
        (list (gethash "clusterIP" spec)))))

(defun service-address-family-key (address)
  "Return :IPV4 or :IPV6 for ADDRESS."
  (if (find #\: address) :ipv6 :ipv4))

(defun service-address-family-matches-p (left right)
  "True when LEFT and RIGHT are addresses from the same IP family."
  (eq (service-address-family-key left) (service-address-family-key right)))

(defun service-external-addresses (service)
  "The addresses besides the ClusterIP that SERVICE answers on: its externalIPs and the
load balancer ingress addresses, except ones whose ipMode Proxy says the balancer proxies itself."
  (let* ((spec (gethash "spec" service))
         (status (gethash "status" service))
         (balancer (and (hash-table-p status) (gethash "loadBalancer" status)))
         (ingress (and (hash-table-p balancer) (gethash "ingress" balancer))))
    (remove-duplicates
     (remove-if-not
      (lambda (address)
        (and (stringp address)
             (ignore-errors (network-address-wire-values address) t)))
      (append (coerce (gethash "externalIPs" spec #()) 'list)
              (when (vectorp ingress)
                (loop for entry across ingress
                      when (and (hash-table-p entry) (not (equal "Proxy" (gethash "ipMode" entry))))
                        collect (gethash "ip" entry)))))
     :test #'equal :from-end t)))

(defun service-load-balancer-ingress (store)
  "Return the ready node addresses published by the embedded ServiceLB controller."
  (coerce
   (loop for node in (list-nodes store)
         ;; The in-process local agent deliberately has no configured
         ;; underlay address. NODE-REPORTED-ADDRESS is also what the Node API
         ;; publishes as InternalIP, discovering the host's primary address
         ;; for that local-node case.
         for address = (node-reported-address node)
         when (and (node-record-runtime-ready-p node)
                   (stringp address) (plusp (length address)))
           collect (core-object "ip" address "ipMode" "Proxy"))
   'vector))

(defun gr8s-load-balancer-service-p (service)
  "True when the embedded controller, rather than a named external controller, owns SERVICE."
  (let ((spec (gethash "spec" service)))
    (and (equal "LoadBalancer" (gethash "type" spec))
         (member (gethash "loadBalancerClass" spec) '(nil "") :test #'equal))))

(defun service-load-balancer-identity (service)
  "Return SERVICE's stable namespace/name identity."
  (let ((metadata (gethash "metadata" service)))
    (format nil "~A/~A" (gethash "namespace" metadata "default")
            (gethash "name" metadata))))

(defun service-load-balancer-listener-keys (service)
  "Return the protocol/Service-port listeners SERVICE needs on every advertised node."
  (remove-duplicates
   (loop for port across (gethash "ports" (gethash "spec" service) #())
         collect (cons (gethash "protocol" port "TCP") (gethash "port" port)))
   :test #'equal))

(defun service-load-balancer-port-owners (services)
  "Return the identities of unclassed LoadBalancer SERVICES that own all their node listeners.
Ownership is deterministic by namespace/name. A Service with any colliding port
gets no listener or advertised ingress, matching an unschedulable Klipper
ServiceLB Pod instead of silently routing the shared port to an arbitrary Service."
  (let ((claimed (make-hash-table :test #'equal))
        (owners (make-hash-table :test #'equal)))
    (dolist (service (stable-sort (remove-if-not #'gr8s-load-balancer-service-p
                                                  (copy-list services))
                                  #'string< :key #'service-load-balancer-identity)
             owners)
      (let ((keys (service-load-balancer-listener-keys service)))
        (unless (some (lambda (key) (gethash key claimed)) keys)
          (setf (gethash (service-load-balancer-identity service) owners) t)
          (dolist (key keys)
            (setf (gethash key claimed) t)))))))

(defun reconcile-service-load-balancer-status (store)
  "Publish ready node addresses for every unclassed LoadBalancer Service.
Services naming another loadBalancerClass remain entirely under that controller's ownership."
  (let* ((services (list-core-resources store "services"))
         (owners (service-load-balancer-port-owners services))
         (ingress (service-load-balancer-ingress store)))
    (dolist (service services)
      (when (gr8s-load-balancer-service-p service)
        (let* ((metadata (gethash "metadata" service))
               (namespace (gethash "namespace" metadata))
               (name (gethash "name" metadata))
               (desired (core-object "loadBalancer"
                                     (if (and (gethash (service-load-balancer-identity service) owners)
                                              (plusp (length ingress)))
                                         (core-object "ingress" ingress)
                                         (core-object)))))
          (unless (core-json-equal-p desired (gethash "status" service (core-object)))
            (let ((*networking-status-write* t))
              (update-core-resource
               store "services" namespace name
               (lambda (current)
                 (when (equal (gethash "uid" metadata)
                              (gethash "uid" (gethash "metadata" current)))
                   (setf (gethash "status" current) (copy-core-object desired)))
                 current))))))))
  nil)

(defun service-affinity-timeout (service)
  "Return the seconds a ClientIP-affinity SERVICE keeps a client on one backend, or NIL."
  (let ((spec (gethash "spec" service)))
    (when (equal "ClientIP" (gethash "sessionAffinity" spec))
      (let* ((config (gethash "sessionAffinityConfig" spec))
             (client (and (hash-table-p config) (gethash "clientIP" config))))
        (or (and (hash-table-p client) (gethash "timeoutSeconds" client)) 10800)))))

(defun service-lb-plan (services endpoints-of)
  "Pack SERVICES into load-balancer map entries.
ENDPOINTS-OF is a function of (service port-object) returning two lists of (address
target-port) pairs: the backends for the ClusterIP, and those for the Service's
external IPs and load balancer addresses, which only this node's own clients reach
through the socket hook; and, as a third value, true when the port has no endpoints
anywhere, so connections to it are refused rather than left to time out.  Returns four values: the service entries (VIP key . value
conses), the backend entries (slot key . value conses), the total slot count, and the
affinity index entries (index key . offset conses).
Backends occupy consecutive slots from 0, assigned in a deterministic Service/port
order; a port's external addresses share its ClusterIP's slots when the backends match."
  (let ((service-entries nil) (backend-entries nil) (index-entries nil) (slot 0))
    (dolist (service (stable-sort (remove-if-not #'service-lb-eligible-p (copy-list services))
                                  #'string< :key (lambda (s) (gethash "clusterIP" (gethash "spec" s)))))
      (let ((addresses (service-cluster-addresses service))
            (external-addresses (service-external-addresses service))
            (timeout (service-affinity-timeout service)))
        (loop for port across (gethash "ports" (gethash "spec" service))
              for number = (gethash "port" port)
              for protocol = (gethash "protocol" port "TCP")
              do (multiple-value-bind (internal external none) (funcall endpoints-of service port)
                   (flet ((ordered (endpoints)
                            ;; Sorted so a client's backend offset means the same thing on every plan.
                            (sort (mapcar (lambda (endpoint) (cons (first endpoint) (second endpoint))) endpoints)
                                  #'string< :key #'prin1-to-string)))
                     (let ((placed nil))
                       (flet ((place (vip backends)
                                (let ((shared (assoc backends placed :test #'equal)))
                                  (multiple-value-bind (vip-key service-value packed indexed)
                                      (service-lb-entries vip number (if shared (cdr shared) slot) backends
                                                          :protocol protocol :affinity-timeout timeout
                                                          :refuse none)
                                    (push (cons vip-key service-value) service-entries)
                                    (dolist (entry indexed) (push entry index-entries))
                                    (unless shared
                                      (push (cons backends slot) placed)
                                      (dolist (entry packed) (push entry backend-entries))
                                      (incf slot (length backends)))))))
                         (dolist (address addresses)
                           (let ((family-backends
                                   (remove-if-not
                                    (lambda (endpoint)
                                      (service-address-family-matches-p address (first endpoint)))
                                    internal)))
                             (place address (ordered family-backends))))
                         (dolist (vip external-addresses)
                           (place vip
                                  (ordered
                                   (remove-if-not
                                    (lambda (endpoint)
                                      (service-address-family-matches-p vip (first endpoint)))
                                    external)))))))))))
    (values (nreverse service-entries) (nreverse backend-entries) slot (nreverse index-entries))))

(defstruct (service-lb-controller (:constructor %make-service-lb-controller
                                      (store dataplane node-name endpoint-steerer)))
  "Drives the socket LB maps from the durable store's Service/endpoint state."
  store
  dataplane
  node-name                    ; this node, for traffic policies and topology hints
  endpoint-steerer             ; bounded network-quality/locality selector
  (applied-service-keys nil)   ; VIP key byte-vectors currently in the service map
  (applied-slot-count 0)       ; highest backend slot currently populated
  (applied-index-keys nil)     ; affinity index keys currently in the index map
  (applied-signature nil))     ; last applied plan, for no-op skipping

(defun make-service-lb-controller (store dataplane &optional node-name &key endpoint-steerer)
  "Drive DATAPLANE's maps from STORE for the node NODE-NAME."
  (%make-service-lb-controller store dataplane node-name endpoint-steerer))

(defun service-lb-entry-family (entry kind)
  "Infer ENTRY's address family from the byte width of its KIND-specific key or value."
  (let ((size (length (ecase kind
                        (:service (car entry))
                        (:backend (cdr entry))
                        (:index (car entry))))))
    (ecase kind
      (:service (ecase size (8 :ipv4) (20 :ipv6)))
      (:backend (ecase size (8 :ipv4) (20 :ipv6)))
      (:index (ecase size (16 :ipv4) (40 :ipv6))))))

(defun service-lb-family-map (dataplane family kind)
  "Return DATAPLANE's FAMILY map for KIND."
  (ecase kind
    (:service (service-lb-service-table dataplane family))
    (:backend (service-lb-backend-table dataplane family))
    (:index (service-lb-map dataplane (ecase family
                                       (:ipv4 "gr8s_backend_index_v4")
                                       (:ipv6 "gr8s_backend_index_v6"))))))

(defun service-lb-delete-if-present (delete map key)
  "An absent key already satisfies withdrawal, including after a partial retry."
  (handler-case (funcall delete map key)
    (whistler/loader:bpf-error (condition)
      (unless (= sb-posix:enoent (whistler/loader::bpf-error-errno condition))
        (error condition)))))

(defun converge-service-lb-controller
    (controller
     &key (update #'whistler/loader:map-update)
          (delete #'whistler/loader:map-delete)
          (list-services
           (lambda () (list-core-resources (service-lb-controller-store controller) "services")))
          (endpoints-of
           (let* ((store (service-lb-controller-store controller))
                  (node-name (service-lb-controller-node-name controller))
                  (zone (service-node-zone store node-name)))
             (lambda (service port)
               (multiple-value-bind (internal external local-origin ready-local any)
                   (service-port-backends store service port :node-name node-name :zone zone)
                 (declare (ignore external ready-local))
                 (let ((steer (service-lb-controller-endpoint-steerer controller)))
                   (values (if steer (funcall steer internal) internal)
                           (if steer (funcall steer local-origin) local-origin)
                           (not any))))))))
  "Recompute the desired LB table and apply the difference to the maps.
Writes every backend before the service that references it (so the program never
reads a VIP whose slots are missing), then removes freed backend slots and
withdrawn VIPs.  A plan identical to the last applied one writes nothing."
  (multiple-value-bind (service-entries backend-entries slot-count index-entries)
      (service-lb-plan (funcall list-services) endpoints-of)
    (let ((signature (list service-entries backend-entries index-entries)))
      (unless (equalp signature (service-lb-controller-applied-signature controller))
        (let* ((dataplane (service-lb-controller-dataplane controller))
               (new-keys (mapcar #'car service-entries))
               (new-index-keys (mapcar #'car index-entries)))
          ;; Add/update first: backends and where each now sits, then the services that point at them.
          (dolist (entry backend-entries)
            (funcall update
                     (service-lb-family-map dataplane (service-lb-entry-family entry :backend) :backend)
                     (car entry) (cdr entry)))
          (dolist (entry index-entries)
            (let ((map (service-lb-family-map dataplane
                                              (service-lb-entry-family entry :index) :index)))
              (when map (funcall update map (car entry) (cdr entry)))))
          (dolist (entry service-entries)
            (funcall update
                     (service-lb-family-map dataplane (service-lb-entry-family entry :service) :service)
                     (car entry) (cdr entry)))
          ;; Remove withdrawn VIPs and freed backend slots.
          (dolist (old (service-lb-controller-applied-service-keys controller))
            (unless (member old new-keys :test #'equalp)
              (service-lb-delete-if-present delete
                       (service-lb-family-map dataplane
                                              (if (= 8 (length old)) :ipv4 :ipv6) :service)
                       old)))
          (loop for slot from slot-count below (service-lb-controller-applied-slot-count controller)
                do (dolist (family '(:ipv4 :ipv6))
                     (let ((map (service-lb-family-map dataplane family :backend)))
                       (when map (service-lb-delete-if-present delete map (service-lb-backend-key slot))))))
          (dolist (old (service-lb-controller-applied-index-keys controller))
            (unless (member old new-index-keys :test #'equalp)
              (let ((map (service-lb-family-map dataplane
                                                (if (= 16 (length old)) :ipv4 :ipv6) :index)))
                (when map (service-lb-delete-if-present delete map old)))))
          (setf (service-lb-controller-applied-index-keys controller) new-index-keys
                (service-lb-controller-applied-service-keys controller) new-keys
                (service-lb-controller-applied-slot-count controller) slot-count
                (service-lb-controller-applied-signature controller) signature)))))
  nil)
