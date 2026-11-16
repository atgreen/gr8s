;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The foreign-cluster network services agent (podster-982.3, podster-982.14,
;;;; docs/design-foreign-cluster-networking.md).
;;;;
;;;; On a cluster whose kubelet and container runtime are not gr8s's, this agent
;;;; owns only the network slice of a node, as independently selectable
;;;; features over one shared FOREIGN-RESOURCE-VIEW.  The CNI feature serves
;;;; the gr8s CNI plugin's Unix socket, allocates Pod addresses from the node's
;;;; own podCIDR, wires routed veths, reconciles the overlay fabric, and keeps
;;;; every local Pod's Whistler NetworkPolicy guard maps fed from the cluster's
;;;; NetworkPolicies, Namespaces and Pods.  The service LB and Gateway features
;;;; arrive as EXTRA-FACTORY layers sharing the view and convergence loop; they
;;;; run with or without the CNI, since they only need Pod IPs the host can
;;;; reach, however they were assigned.  It never creates, deletes or observes
;;;; Pods; the foreign kubelet owns their lifecycle.

(in-package #:gr8s.network)

(defstruct (foreign-net-agent (:constructor %make-foreign-net-agent))
  "One node's foreign-cluster network services and their convergence loop."
  ;; CNI is a feature, not the essence: NIL skips the CNI socket, IPAM,
  ;; overlay fabric, NetworkPolicy guards and hostPort relays, leaving the
  ;; extra layers (service LB, Gateway) to drive the loop alone.
  (cni t)
  view node-name ipam bpf-root server cluster
  (lock (bt:make-lock "gr8s foreign net agent"))
  (wake (bt:make-condition-variable :name "gr8s foreign net agent wake"))
  (pending t) (running t)
  converge-thread policy-converger policy-writer
  ;; The last applied fabric intent, so peer retirement knows what to undo.
  last-network fabric-reconciler (mtu 1450)
  ;; WireGuard overlay: this node's durable public key (octets) and the shared
  ;; UDP listen port, published and discovered as peer Node annotations.
  (overlay-backend "vxlan") wireguard-public-key (wireguard-listen-port 51820)
  (host-port-forwarders (make-hash-table :test #'equal))
  ;; A higher layer's convergence and teardown, run with the agent's: the
  ;; Gateway controller lives above this module, so it arrives as functions.
  extra-converger extra-stopper)

(defun foreign-node-pod-cidrs (node)
  "NODE's podCIDRs, from the plural field when present, else the singular."
  (let* ((spec (gethash "spec" node))
         (plural (and spec (gethash "podCIDRs" spec)))
         (single (and spec (gethash "podCIDR" spec))))
    (or (and (vectorp plural) (plusp (length plural)) (coerce plural 'list))
        (and (stringp single) (plusp (length single)) (list single))
        (invalid-cni "node ~A has no spec.podCIDR yet"
                     (gethash "name" (gethash "metadata" node))))))

(defun foreign-agent-wait-for-node (view node-name stop-predicate)
  "Return NODE-NAME's Node object once it exists and carries a podCIDR."
  (loop
    (when (funcall stop-predicate) (return nil))
    (let ((node (handler-case
                    (gr8s.resources::get-core-resource view "nodes" nil node-name)
                  (error () nil))))
      (when (and node (ignore-errors (foreign-node-pod-cidrs node)))
        (return node)))
    (sleep 1)))

(defun foreign-agent-nudge (agent)
  (bt:with-lock-held ((foreign-net-agent-lock agent))
    (setf (foreign-net-agent-pending agent) t)
    (bt:condition-notify (foreign-net-agent-wake agent))))

(defun foreign-node-internal-address (node)
  (loop for entry across (let ((addresses
                                 (gethash "addresses"
                                          (gethash "status" node
                                                   (make-hash-table :test 'equal)))))
                           ;; jzon parses JSON null as the symbol NULL, which
                           ;; defeats the GETHASH default.
                           (if (vectorp addresses) addresses #()))
        when (equal "InternalIP" (gethash "type" entry))
          return (gethash "address" entry)))

(defun foreign-node-network (view node-name &key (mtu 1450))
  "Project the watched Nodes into the VXLAN reconciler's network intent: this
node's underlay address, and one route per peer Node carrying its podCIDRs --
the multi-node fabric, driven by the same objects every kubelet reports."
  (let ((local "") (local-cidrs nil) (routes '()))
    (dolist (node (gr8s.resources::list-core-resources view "nodes"))
      (let* ((metadata (gethash "metadata" node))
             (name (gethash "name" metadata))
             (address (foreign-node-internal-address node))
             (cidrs (ignore-errors (foreign-node-pod-cidrs node))))
        (cond ((equal name node-name)
               (when address (setf local address))
               (setf local-cidrs cidrs))
              ((and address cidrs)
               (push (json-object "nodeID" name
                                  "podCIDR" (first cidrs)
                                  "podCIDRs" (coerce cidrs 'vector)
                                  "underlayAddress" address)
                     routes)))))
    (json-object "underlayAddress" local
                 "nodePodCIDR" (or (first local-cidrs) "")
                 "nodePodCIDRs" (coerce local-cidrs 'vector)
                 ;; The VNI every gr8s node fabric uses.
                 "vni" 42
                 "mtu" mtu
                 "routes" (coerce (nreverse routes) 'vector))))

(defparameter +wireguard-public-key-annotation+ "gr8s.io/wireguard-public-key"
  "The Node annotation each gr8s agent publishes its WireGuard public key under,
so peers can discover it from the host cluster API -- the foreign-cluster analog
of the native node-session gRPC key exchange.")

(defun foreign-node-wireguard-public-key (node)
  "NODE's advertised WireGuard public key (base64), or NIL if it has not
published one yet (it then simply stays out of the encrypted fabric)."
  (let* ((metadata (gethash "metadata" node))
         (annotations (and metadata (gethash "annotations" metadata))))
    (when (hash-table-p annotations)
      (let ((key (gethash +wireguard-public-key-annotation+ annotations)))
        (when (and (stringp key) (plusp (length key))) key)))))

(defun foreign-node-wireguard-network (view node-name &key (mtu 1450) (listen-port 51820))
  "Project the watched Nodes into the WireGuard reconciler's intent.  Like
FOREIGN-NODE-NETWORK, but each peer route also carries the peer's published
WireGuard public key and the shared listen port; a peer that has not yet
advertised a key is skipped until it does.  Only Pod-CIDR destinations route
through the tunnel, so node and API-server traffic stays unencrypted and the
agent can still bootstrap against the host cluster (the pod-only encryption
model)."
  (let ((local "") (local-cidrs nil) (routes '()))
    (dolist (node (gr8s.resources::list-core-resources view "nodes"))
      (let* ((metadata (gethash "metadata" node))
             (name (gethash "name" metadata))
             (address (foreign-node-internal-address node))
             (cidrs (ignore-errors (foreign-node-pod-cidrs node))))
        (cond ((equal name node-name)
               (when address (setf local address))
               (setf local-cidrs cidrs))
              ((and address cidrs)
               (let ((public-key (foreign-node-wireguard-public-key node)))
                 (when public-key
                   (push (json-object "nodeID" name
                                      "podCIDR" (first cidrs)
                                      "podCIDRs" (coerce cidrs 'vector)
                                      "underlayAddress" address
                                      "wireguardPublicKey" public-key
                                      "wireguardListenPort" listen-port)
                         routes)))))))
    (json-object "overlayBackend" "wireguard"
                 "underlayAddress" local
                 "nodePodCIDR" (or (first local-cidrs) "")
                 "nodePodCIDRs" (coerce local-cidrs 'vector)
                 "wireguardListenPort" listen-port
                 "mtu" mtu
                 "routes" (coerce (nreverse routes) 'vector))))

(defun foreign-agent-publish-wireguard-identity (agent)
  "Publish this node's WireGuard public key as a Node annotation, idempotently:
patch only when the live annotation differs from this node's key, so a steady
state produces no API writes and no watch churn."
  (let* ((node-name (foreign-net-agent-node-name agent))
         (public-key (foreign-net-agent-wireguard-public-key agent))
         (encoded (ag-grpc:base64-encode public-key))
         (node (ignore-errors
                 (gr8s.resources::get-core-resource
                  (foreign-net-agent-view agent) "nodes" nil node-name))))
    (when (and node (not (equal encoded (foreign-node-wireguard-public-key node))))
      (gr8s.kube-client:kube-patch
       (foreign-net-agent-cluster agent)
       (gr8s.kube-client:resource-path "" "v1" "nodes" :name node-name)
       (json-object "metadata"
                    (json-object "annotations"
                                 (json-object +wireguard-public-key-annotation+ encoded)))))))

(defun foreign-agent-fabric-intent (agent view)
  "Project this node's fabric intent for the selected overlay backend."
  (if (string= (foreign-net-agent-overlay-backend agent) "wireguard")
      (foreign-node-wireguard-network
       view (foreign-net-agent-node-name agent)
       :mtu (foreign-net-agent-mtu agent)
       :listen-port (foreign-net-agent-wireguard-listen-port agent))
      (foreign-node-network view (foreign-net-agent-node-name agent)
                            :mtu (foreign-net-agent-mtu agent))))

(defun foreign-agent-converge-fabric (agent)
  "Reconcile the overlay fabric when the projected intent changed.  Only once a
peer exists (or existed) does the overlay device appear; a lone node keeps its
host networking untouched.  In WireGuard mode this node first advertises its
public key so peers can authenticate it."
  (let ((view (foreign-net-agent-view agent))
        (previous (foreign-net-agent-last-network agent)))
    (when (string= (foreign-net-agent-overlay-backend agent) "wireguard")
      (foreign-agent-publish-wireguard-identity agent))
    (let ((network (foreign-agent-fabric-intent agent view)))
      (when (and (not (equalp network previous))
                 (or (plusp (length (gethash "routes" network)))
                     (and previous (plusp (length (gethash "routes" previous))))))
        (funcall (foreign-net-agent-fabric-reconciler agent)
                 network (when previous (list previous)))
        (setf (foreign-net-agent-last-network agent) network)))))

(defun foreign-agent-endpoints (agent)
  "Every local Pod endpoint (SANDBOX INTERFACE ADDRESS) the agent's IPAM holds."
  (let ((ipam (foreign-net-agent-ipam agent)))
    (bt:with-lock-held ((node-ipam-lock ipam))
      (loop for key being the hash-keys of (node-ipam-allocations ipam)
              using (hash-value addresses)
            collect (list (car key) (cdr key) (first addresses))))))

(defun foreign-agent-converge (agent)
  "Write every local Pod's resolved NetworkPolicy into its pinned guard maps."
  (let* ((view (foreign-net-agent-view agent))
         (root (foreign-net-agent-bpf-root agent))
         ;; Resolve selectors against the cluster's Pods and Namespaces first,
         ;; exactly as the control plane does before projecting to gr8s nodes:
         ;; a raw policy's peers carry no addresses the guards could match.
         (specs (network-policy-specs-from-objects
                 (network-policy-projection view)))
         (ip-map (pod-ip-identity-map view)))
    (funcall (foreign-net-agent-policy-converger agent)
             specs (foreign-agent-endpoints agent)
             :pod-finder (lambda (address) (gethash address ip-map))
             :directory-fn (lambda (sandbox) (nth-value 2 (cni-pin-paths root sandbox)))
             :writer (foreign-net-agent-policy-writer agent))))

(defun foreign-agent-converge-loop (agent)
  (loop while (foreign-net-agent-running agent)
        do (bt:with-lock-held ((foreign-net-agent-lock agent))
             (loop until (or (foreign-net-agent-pending agent)
                             (not (foreign-net-agent-running agent)))
                   do (bt:condition-wait (foreign-net-agent-wake agent)
                                         (foreign-net-agent-lock agent)))
             (setf (foreign-net-agent-pending agent) nil))
           (when (foreign-net-agent-running agent)
             (when (foreign-net-agent-cni agent)
               (handler-case (foreign-agent-converge-fabric agent)
                 (error (condition)
                   (format *error-output* "~&gr8s foreign net agent: fabric convergence failed: ~A~%"
                           condition)))
               (handler-case (foreign-agent-converge agent)
                 (error (condition)
                   (format *error-output* "~&gr8s foreign net agent: policy convergence failed: ~A~%"
                           condition)))
               (handler-case
                   (converge-host-port-forwarders
                    (foreign-net-agent-host-port-forwarders agent)
                    (foreign-net-agent-view agent)
                    :node-name (foreign-net-agent-node-name agent))
                 (error (condition)
                   (format *error-output* "~&gr8s foreign net agent: host port convergence failed: ~A~%"
                           condition))))
             (let ((extra (foreign-net-agent-extra-converger agent)))
               (when extra
                 (handler-case (funcall extra)
                   (error (condition)
                     (format *error-output* "~&gr8s foreign net agent: gateway convergence failed: ~A~%"
                             condition))))))))

(defun start-foreign-net-agent
    (cluster &key (cni t) node-name state-directory bpf-root socket-path
                  (mtu 1450) operations-factory
                  (policy-converger #'converge-pod-network-policies)
                  (policy-writer #'write-pod-network-policy)
                  fabric-reconciler
                  (overlay-backend "vxlan")
                  wireguard-private-key wireguard-public-key (wireguard-listen-port 51820)
                  extra-factory
                  (stop-predicate (constantly nil)))
  "Start the foreign-cluster network services agent against CLUSTER and return
it.  With CNI (the default) it serves CNI requests on SOCKET-PATH with
addresses from this node's podCIDR, reconciles the overlay fabric, and
converges NetworkPolicy into the guard maps under BPF-ROOT; with CNI NIL it
skips all of that -- it does not wait for a podCIDR -- and runs only the
EXTRA-FACTORY layers over the view.  OPERATIONS-FACTORY receives the agent's
IPAM and returns the CNI operations, overriding the routed dataplane (tests);
POLICY-CONVERGER and POLICY-WRITER override the map writes.  EXTRA-FACTORY
receives the agent's resource view and returns (values CONVERGER STOPPER) for
higher layers -- the service LB and Gateway controllers -- that share the view
and the convergence loop."
  (when (and cni (string= overlay-backend "wireguard"))
    (unless (and wireguard-private-key wireguard-public-key)
      (error "WireGuard overlay backend requires a node key pair")))
  ;; Default the datapath reconciler per backend, keeping the caller's override
  ;; (tests) intact. The WireGuard reconciler needs the private key, wrapped so
  ;; the convergence loop keeps the uniform (network previous) fabric contract.
  (unless fabric-reconciler
    (setf fabric-reconciler
          (if (string= overlay-backend "wireguard")
              (lambda (network previous)
                (reconcile-node-overlay-network network previous wireguard-private-key))
              #'reconcile-node-vxlan-network)))
  (let* ((agent (%make-foreign-net-agent
                 :cni cni
                 :node-name node-name :bpf-root bpf-root :cluster cluster
                 :policy-converger policy-converger :policy-writer policy-writer
                 :fabric-reconciler fabric-reconciler :mtu mtu
                 :overlay-backend overlay-backend
                 :wireguard-public-key wireguard-public-key
                 :wireguard-listen-port wireguard-listen-port))
         (view (gr8s.resources::make-foreign-resource-view
                cluster
                ;; Every followed resource feeds either policy or the gateway
                ;; plan; convergence is cheap and idempotent, so any change
                ;; nudges one pass rather than maintaining a resource roster.
                :on-change (lambda (resource change key object)
                             (declare (ignore resource change key object))
                             (foreign-agent-nudge agent)))))
    (setf (foreign-net-agent-view agent) view)
    (when extra-factory
      (multiple-value-bind (converger stopper) (funcall extra-factory view)
        (setf (foreign-net-agent-extra-converger agent) converger
              (foreign-net-agent-extra-stopper agent) stopper)))
    (let ((node (when cni
                  (foreign-agent-wait-for-node view node-name stop-predicate))))
      (when (and cni (not node))
        (gr8s.resources::stop-foreign-resource-view view)
        (return-from start-foreign-net-agent nil))
      (handler-case
          (progn
            (when cni
              (setf (foreign-net-agent-ipam agent)
                    (open-node-ipam (uiop:ensure-directory-pathname state-directory)
                                    (foreign-node-pod-cidrs node))
                    (foreign-net-agent-server agent)
                    (let ((operations
                            (if operations-factory
                                (funcall operations-factory (foreign-net-agent-ipam agent))
                                (make-routed-cni-operations
                                 (foreign-net-agent-ipam agent)
                                 :node-id node-name :mtu mtu
                                 ;; The socket LB pins its Service maps here; the
                                 ;; per-Pod SCTP classifiers read them to steer
                                 ;; SCTP, which the connect4 socket LB cannot.
                                 :sctp-nat-pin-directory
                                 (when bpf-root
                                   (namestring (merge-pathnames
                                                "service-lb/"
                                                (uiop:ensure-directory-pathname bpf-root))))))))
                      (start-agent-cni-server
                       socket-path
                       (lambda (request)
                         ;; gr8s is the sole plugin here -- it creates the
                         ;; interface itself, so no prevResult can exist.
                         (prog1 (handle-agent-cni-request request :operations operations
                                                                  :chained nil)
                           ;; A new or departed endpoint changes which guards exist.
                           (foreign-agent-nudge agent)))))))
            (setf (foreign-net-agent-converge-thread agent)
                  (bt:make-thread (lambda () (foreign-agent-converge-loop agent))
                                  :name "gr8s foreign net agent policy"))
            agent)
        (error (condition)
          (stop-foreign-net-agent agent)
          (error condition))))))

(defun stop-foreign-net-agent (agent)
  "Stop AGENT's CNI server, convergence loop and informers."
  (bt:with-lock-held ((foreign-net-agent-lock agent))
    (setf (foreign-net-agent-running agent) nil)
    (bt:condition-notify (foreign-net-agent-wake agent)))
  (let ((server (foreign-net-agent-server agent)))
    (when server (ignore-errors (stop-agent-cni-server server))))
  (let ((thread (foreign-net-agent-converge-thread agent)))
    (when (and thread (bt:thread-alive-p thread))
      (ignore-errors (bt:join-thread thread))))
  (ignore-errors (stop-host-port-forwarders (foreign-net-agent-host-port-forwarders agent)))
  (let ((stopper (foreign-net-agent-extra-stopper agent)))
    (when stopper (ignore-errors (funcall stopper))))
  (let ((view (foreign-net-agent-view agent)))
    (when view (ignore-errors (gr8s.resources::stop-foreign-resource-view view))))
  nil)

(defun run-foreign-net-agent (cluster &rest options &key stop-predicate &allow-other-keys)
  "Run the foreign net agent until STOP-PREDICATE returns true."
  (let ((agent (apply #'start-foreign-net-agent cluster options)))
    (when agent
      (unwind-protect
           (loop until (funcall stop-predicate) do (sleep 1))
        (stop-foreign-net-agent agent)))))
