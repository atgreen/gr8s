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

(defun service-external-addresses (service)
  "The addresses besides the ClusterIP that SERVICE answers on: its externalIPs and the IPv4
load balancer ingress addresses, except ones whose ipMode Proxy says the balancer proxies itself."
  (let* ((spec (gethash "spec" service))
         (status (gethash "status" service))
         (balancer (and (hash-table-p status) (gethash "loadBalancer" status)))
         (ingress (and (hash-table-p balancer) (gethash "ingress" balancer))))
    (remove-duplicates
     (remove-if-not
      (lambda (address) (and (stringp address) (not (find #\: address)) (ignore-errors (parse-ipv4-integer address))))
      (append (coerce (gethash "externalIPs" spec #()) 'list)
              (when (vectorp ingress)
                (loop for entry across ingress
                      when (and (hash-table-p entry) (not (equal "Proxy" (gethash "ipMode" entry))))
                        collect (gethash "ip" entry)))))
     :test #'equal :from-end t)))

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
      (let ((address (gethash "clusterIP" (gethash "spec" service)))
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
                         (place address (ordered internal))
                         (dolist (vip external-addresses)
                           (place vip (ordered external))))))))))
    (values (nreverse service-entries) (nreverse backend-entries) slot (nreverse index-entries))))

(defstruct (service-lb-controller (:constructor %make-service-lb-controller (store dataplane node-name)))
  "Drives the socket LB maps from the durable store's Service/endpoint state."
  store
  dataplane
  node-name                    ; this node, for traffic policies and topology hints
  (applied-service-keys nil)   ; VIP key byte-vectors currently in the service map
  (applied-slot-count 0)       ; highest backend slot currently populated
  (applied-index-keys nil)     ; affinity index keys currently in the index map
  (applied-signature nil))     ; last applied plan, for no-op skipping

(defun make-service-lb-controller (store dataplane &optional node-name)
  "Drive DATAPLANE's maps from STORE for the node NODE-NAME."
  (%make-service-lb-controller store dataplane node-name))

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
                 (values internal local-origin (not any)))))))
  "Recompute the desired LB table and apply the difference to the maps.
Writes every backend before the service that references it (so the program never
reads a VIP whose slots are missing), then removes freed backend slots and
withdrawn VIPs.  A plan identical to the last applied one writes nothing."
  (multiple-value-bind (service-entries backend-entries slot-count index-entries)
      (service-lb-plan (funcall list-services) endpoints-of)
    (let ((signature (list service-entries backend-entries index-entries)))
      (unless (equalp signature (service-lb-controller-applied-signature controller))
        (let* ((dataplane (service-lb-controller-dataplane controller))
               (service-map (service-lb-service-table dataplane))
               (backend-map (service-lb-backend-table dataplane))
               (index-map (service-lb-map dataplane "gr8s_backend_index_v4"))
               (new-keys (mapcar #'car service-entries))
               (new-index-keys (mapcar #'car index-entries)))
          ;; Add/update first: backends and where each now sits, then the services that point at them.
          (dolist (entry backend-entries) (funcall update backend-map (car entry) (cdr entry)))
          (when index-map
            (dolist (entry index-entries) (funcall update index-map (car entry) (cdr entry))))
          (dolist (entry service-entries) (funcall update service-map (car entry) (cdr entry)))
          ;; Remove withdrawn VIPs and freed backend slots.
          (dolist (old (service-lb-controller-applied-service-keys controller))
            (unless (member old new-keys :test #'equalp)
              (funcall delete service-map old)))
          (loop for slot from slot-count below (service-lb-controller-applied-slot-count controller)
                do (funcall delete backend-map (service-lb-backend-key slot)))
          (when index-map
            (dolist (old (service-lb-controller-applied-index-keys controller))
              (unless (member old new-index-keys :test #'equalp)
                (funcall delete index-map old))))
          (setf (service-lb-controller-applied-index-keys controller) (and index-map new-index-keys)
                (service-lb-controller-applied-service-keys controller) new-keys
                (service-lb-controller-applied-slot-count controller) slot-count
                (service-lb-controller-applied-signature controller) signature)))))
  nil)
