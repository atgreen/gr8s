;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The node agent's runtime: gr8s's kubelet-equivalent that runs one Node's assigned
;;;; Pods and reports their observed status back to the control plane.
;;;;
;;;; A NODE-RUNTIME owns the agent's lifecycle on a single node -- its threads, its
;;;; local desired-state store, the container runtime, IPAM and the VXLAN overlay --
;;;; and turns control-plane snapshots into reality: it installs assigned Pods, applies
;;;; the node's network and its Service/NetworkPolicy/Gateway dataplane, and streams
;;;; back observed status and endpoint telemetry. Two invariants run through the file.
;;;; First, snapshot application is revision-fenced: RECEIVED-REVISION together with the
;;;; arrival and apply locks ensure an obsolete snapshot can neither create a Pod nor
;;;; acknowledge a revision, so a slow apply racing a newer one does no harm. Second,
;;;; deletion intent is made durable before any CRI call and a withdrawal is only
;;;; acknowledged once it cannot be lost, so a crash never resurrects a Pod the server
;;;; has withdrawn. The dataplane convergences (Service LB, node ports, NetworkPolicy,
;;;; Gateway, host ports) are deliberately fail-soft: a transient error is logged, not
;;;; allowed to abort the rest of a snapshot. Node operations -- logs, metrics, volume
;;;; reclaim, port-forward and interactive exec/attach -- are dispatched here, with
;;;; exec/attach streamed on their own threads through the runtime's streaming server
;;;; so one session's reader is never held by a running command.

(in-package #:gr8s.agent)

(defstruct (node-runtime (:constructor %make-node-runtime))
  state-directory
  (node-name nil)   ; the Node this agent runs, for Service traffic policies
  (node-id "")     ; accepted durable ServerHello identity, fences node replacement
  runtime
  manager
  dynamic-resource-manager
  device-plugin-manager
  resource-manager
  pod-resources-server
  dns-forward-rules
  network
  network-reconciler
  ;; Authenticated WireGuard endpoint observations and last-known-good choices.
  wireguard-path-state
  wireguard-path-state-path
  wireguard-path-telemetry
  ;; (Pod CIDR, interface, UDP port) admitted to firewalld during this process
  ;; lifetime. Cached snapshots repeat the same network, so do not spawn
  ;; firewall-cmd for each one; retaining all three fields also makes a backend
  ;; transition withdraw the rules it supersedes.
  overlay-firewall-identity
  ipam
  cni-operations
  ;; Durable endpoints created by an operator-owned primary CNI before the
  ;; optional gr8s policy plugin. Keyed by (container-id . interface-name).
  (external-cni-endpoints (make-hash-table :test #'equal))
  (external-cni-endpoints-lock (bt:make-lock "gr8s external CNI endpoints"))
  (observed-statuses (make-hash-table :test #'equal))
  (assigned-versions (make-hash-table :test #'equal))
  (observed-lock (bt:make-lock "gr8s node observations"))
  (network-lock (bt:make-lock "gr8s node network"))
  store
  reconciler
  worker
  thread
  error
  (state :stopped)
  (stop-requested nil)
  (operations (make-hash-table :test #'equal))
  (operations-lock (bt:make-lock "gr8s node runtime operations"))
  (reclaim-queue (make-volume-reclaim-queue))
  (lock (bt:make-lock "gr8s node runtime"))
  (state-changed (bt:make-condition-variable :name "gr8s node runtime state"))
  (apply-lock (bt:make-lock "gr8s node snapshot application"))
  (received-revision -1)
  (arrival-lock (bt:make-lock "gr8s node snapshot arrival"))
  ;; In-kernel ClusterIP socket load balancer, owned by the agent (which holds
  ;; the bpffs and the Pod cgroups). NIL when unavailable (falls back to the
  ;; control-plane userspace proxy).
  service-lb
  service-lb-controller
  (service-risk-ready-revision nil) ; current snapshot's local v2 risk map was read back
  (service-selection-ready-revision nil) ; grant-matched Service tables converged
  (service-selection-grant-digest nil) ; last fully approved selection in this agent process
  ;; Listening host ports by (ip . port); see pod-host-ports.lisp.
  (host-port-forwarders (make-hash-table :test #'equal))
  ;; Listening Service node ports by (protocol ip . port), likewise.
  (node-port-forwarders (make-hash-table :test #'equal))
  (health-check-servers (make-hash-table))
  ;; Gateway API L7 proxy listeners, reconciled from stored Gateway/HTTPRoute
  ;; objects. NIL until the first reconcile creates it.
  gateway-controller
  ;; sk_lookup attachment that exposes loopback Gateway/Ingress listeners on
  ;; their destination ports without opening host-wide listening sockets.
  gateway-steering)

(defun node-runtime-local-risk-ready-p (node-runtime)
  "True only while the latest received snapshot has a read-back-complete local
v2 backend risk map. Remote node acknowledgement is a separate requirement."
  (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
    (let ((ready (node-runtime-service-risk-ready-revision node-runtime)))
      (and (node-runtime-service-lb node-runtime)
           (service-lb-map (node-runtime-service-lb node-runtime) "gr8s_nat_risk_v2")
           (integerp ready) (>= ready 0)
           (= ready (node-runtime-received-revision node-runtime))))))

(defun ensure-node-snapshot-service-risk-ready
    (node-runtime &key (owner-lookup #'whistler/loader:map-lookup)
                       (owner-next-key #'whistler/loader:map-get-next-key))
  "Withhold a v2 snapshot ACK until risk and trusted owner rows are read back.
The snapshot worker retries NODE-SNAPSHOT-INCOMPLETE without losing Pod work."
  (let* ((dataplane (node-runtime-service-lb node-runtime))
         (risk (and dataplane (service-lb-map dataplane "gr8s_nat_risk_v2"))))
    (when risk
      (unless (node-runtime-local-risk-ready-p node-runtime)
        (error 'node-snapshot-incomplete
               :message "v2 Service risk inventory is not published for the current snapshot"))
      (let ((owners (service-lb-map dataplane "gr8s_nat_id_v2"))
            (network (node-runtime-network node-runtime)))
        (unless (and network
                     (gr8s.network::service-nat-identities-published-p
                      owners (gethash "serviceTranslations" network #())
                      :lookup owner-lookup :next-key owner-next-key))
          (error 'node-snapshot-incomplete
                 :message "v2 Service owner inventory is not published for the current snapshot"))))))

(defun snapshot-service-receiver-pairs (snapshot)
  (mapcar (lambda (proof)
            (cons (slot-value proof 'gr8s.node.v1::pod-uid)
                  (slot-value proof 'gr8s.node.v1::incarnation)))
          (slot-value snapshot 'gr8s.node.v1::service-receivers)))

(defun publish-node-snapshot-service-receivers (node-runtime snapshot)
  "Converge remote receiver bits before this snapshot may enable selectors.
Local receiver bits belong to CNI attachment and are never set here."
  (let* ((dataplane (node-runtime-service-lb node-runtime))
         (owners (and dataplane (service-lb-map dataplane "gr8s_nat_id_v2")))
         (network (node-runtime-network node-runtime)))
    (when (and (slot-value snapshot 'gr8s.node.v1::service-receivers)
               (null owners))
      (error 'node-snapshot-incomplete
             :message "v2 Service receiver map is unavailable"))
    (when owners
      (unless network
        (error 'node-snapshot-incomplete :message "v2 Service owner assignment is unavailable"))
      (handler-case
          (bt:with-lock-held (gr8s.network::*service-nat-owner-lifecycle-lock*)
            (gr8s.network::publish-service-nat-receiver-readiness
             owners (gethash "serviceTranslations" network #())
             (snapshot-service-receiver-pairs snapshot)
             (node-runtime-node-id node-runtime)))
        (error (condition)
          (error 'node-snapshot-incomplete
                 :message (format nil "v2 Service receiver publication failed: ~A" condition)))))))

(defun ensure-node-snapshot-service-receivers-ready
    (node-runtime snapshot &key (lookup #'whistler/loader:map-lookup))
  "Withhold ACK and selection until the snapshot's remote receiver bits are
read back, including exact local CNI readiness for any listed local owner."
  (let* ((dataplane (node-runtime-service-lb node-runtime))
         (owners (and dataplane (service-lb-map dataplane "gr8s_nat_id_v2")))
         (network (node-runtime-network node-runtime)))
    (when (and (slot-value snapshot 'gr8s.node.v1::service-receivers)
               (null owners))
      (error 'node-snapshot-incomplete
             :message "v2 Service receiver map is unavailable"))
    (when owners
      (unless (and network
                   (handler-case
                       (gr8s.network::service-nat-receiver-readiness-published-p
                        owners (gethash "serviceTranslations" network #())
                        (snapshot-service-receiver-pairs snapshot)
                        (node-runtime-node-id node-runtime) :lookup lookup)
                     (error () nil)))
        (error 'node-snapshot-incomplete
               :message "v2 Service receiver inventory is not published for the current snapshot")))))

(defun node-snapshot-service-risk-granted-p (snapshot)
  "Validate a nonempty grant against this snapshot's exact discovery bytes."
  (let ((grant (slot-value snapshot 'gr8s.node.v1::service-risk-grant-digest)))
    (unless (zerop (length grant))
      (unless (and (= 32 (length grant))
                   (equalp grant
                           (gr8s.protocol::service-risk-projection-digest
                            (slot-value snapshot
                                        'gr8s.node.v1::service-discovery-objects-json))))
        (error 'node-snapshot-incomplete
               :message "v2 Service grant does not match the current discovery projection"))
      t)))

(defun node-snapshot-service-grant-mode (node-runtime snapshot)
  "Classify a current grant or a server-retained previous grant.
A retained digest is useful only in the agent process that applied it before;
after restart an unknown old digest cannot authorize pinned selectors."
  (let* ((grant (slot-value snapshot 'gr8s.node.v1::service-risk-grant-digest))
         (network (slot-value snapshot 'gr8s.node.v1::network))
         (owners (and network
                      (slot-value network 'gr8s.node.v1::service-translations)))
         (receivers (slot-value snapshot 'gr8s.node.v1::service-receivers)))
    (cond ((zerop (length grant)) nil)
          ((/= 32 (length grant))
           (error 'node-snapshot-incomplete
                  :message "v2 Service grant has an invalid digest length"))
          ((and (equalp grant
                        (gr8s.protocol::service-risk-projection-digest
                         (slot-value snapshot
                                     'gr8s.node.v1::service-discovery-objects-json)))
                network (= (length owners) (length receivers)))
           :current)
          ((and network
                (equalp grant (node-runtime-service-selection-grant-digest node-runtime)))
           :retained)
          (t nil))))

(defun node-runtime-local-selection-ready-p (node-runtime)
  (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
    (let ((ready (node-runtime-service-selection-ready-revision node-runtime)))
      (and (integerp ready) (>= ready 0)
           (= ready (node-runtime-received-revision node-runtime))))))

(defun ensure-node-snapshot-service-selection-ready (node-runtime snapshot)
  "Do not ACK a granted snapshot until its Service tables were converged."
  (when (eq :current (node-snapshot-service-grant-mode node-runtime snapshot))
    (unless (and (node-runtime-local-risk-ready-p node-runtime)
                 (node-runtime-local-selection-ready-p node-runtime))
      (error 'node-snapshot-incomplete
             :message "v2 Service selection is not published for the current grant"))))

(defun converge-node-runtime-service-lb (node-runtime &key (publish-services-p nil supplied-p))
  "Keep v2 in the risk-only phase until this revision's grant was applied.
The v1 socket LB remains active; a validated grant can release v2 tables."
  (let ((controller (node-runtime-service-lb-controller node-runtime))
        (dataplane (node-runtime-service-lb node-runtime)))
    (when controller
      (converge-service-lb-controller
       controller :publish-services-p
       (if supplied-p publish-services-p
           (or (not (and dataplane (service-lb-map dataplane "gr8s_nat_risk_v2")))
               (node-runtime-local-selection-ready-p node-runtime)))))))

(defun node-runtime-external-cni-endpoints-path (node-runtime)
  "Return the durable external-CNI endpoint registry path for NODE-RUNTIME."
  (merge-pathnames "external-cni-endpoints.json"
                   (node-runtime-state-directory node-runtime)))

(defun node-runtime-external-cni-endpoint-list (node-runtime)
  "Return external endpoints as sorted (container-id interface-name address) rows."
  (bt:with-lock-held ((node-runtime-external-cni-endpoints-lock node-runtime))
    (sort
     (loop for key being the hash-keys of (node-runtime-external-cni-endpoints node-runtime)
             using (hash-value address)
           collect (list (car key) (cdr key) address))
     #'string< :key (lambda (row) (format nil "~A/~A" (first row) (second row))))))

(defun persist-node-runtime-external-cni-endpoints (node-runtime)
  "Atomically persist NODE-RUNTIME's external endpoint registry. Caller holds its lock."
  (write-private-text-atomically
   (node-runtime-external-cni-endpoints-path node-runtime)
   (com.inuoe.jzon:stringify
    (json-object
     "version" 1
     "endpoints"
     (coerce
      (sort
       (loop for key being the hash-keys of (node-runtime-external-cni-endpoints node-runtime)
               using (hash-value address)
             collect (json-object "containerID" (car key)
                                  "interfaceName" (cdr key)
                                  "address" address))
       #'string< :key (lambda (entry)
                        (format nil "~A/~A" (gethash "containerID" entry)
                                (gethash "interfaceName" entry))))
      'vector)))))

(defun load-node-runtime-external-cni-endpoints (node-runtime)
  "Load NODE-RUNTIME's durable external endpoint registry, if present."
  (let ((path (node-runtime-external-cni-endpoints-path node-runtime)))
    (when (probe-file path)
      (let* ((object (com.inuoe.jzon:parse (uiop:read-file-string path)))
             (entries (and (hash-table-p object) (gethash "endpoints" object))))
        (unless (and (= 1 (gethash "version" object 0)) (vectorp entries))
          (error "invalid external CNI endpoint registry"))
        (loop for entry across entries
              for container = (and (hash-table-p entry) (gethash "containerID" entry))
              for interface = (and (hash-table-p entry) (gethash "interfaceName" entry))
              for address = (and (hash-table-p entry) (gethash "address" entry))
              do (unless (and (safe-cni-container-id-p container)
                              (stringp interface) (plusp (length interface))
                              (ignore-errors (gr8s.controllers::parse-ipv4-integer address)))
                   (error "invalid external CNI endpoint registry entry"))
                 (setf (gethash (cons container interface)
                                (node-runtime-external-cni-endpoints node-runtime))
                       address)))))
  node-runtime)

(defun update-node-runtime-external-cni-endpoint
    (node-runtime command container interface &optional address)
  "Persist a successful external chained ADD or DEL in NODE-RUNTIME's registry."
  (when (member command '("ADD" "DEL") :test #'string=)
    (let ((key (cons container interface)))
      (bt:with-lock-held ((node-runtime-external-cni-endpoints-lock node-runtime))
        (let ((old (gethash key (node-runtime-external-cni-endpoints node-runtime)))
              (present (nth-value 1 (gethash key (node-runtime-external-cni-endpoints node-runtime)))))
          (if (string= command "ADD")
              (setf (gethash key (node-runtime-external-cni-endpoints node-runtime)) address)
              (remhash key (node-runtime-external-cni-endpoints node-runtime)))
          (handler-case
              (persist-node-runtime-external-cni-endpoints node-runtime)
            (error (condition)
              (if present
                  (setf (gethash key (node-runtime-external-cni-endpoints node-runtime)) old)
                  (remhash key (node-runtime-external-cni-endpoints node-runtime)))
              (error condition)))))))
  nil)

(defun make-node-runtime (state-directory runtime manager
                          &key wireguard-private-key
                               (network-reconciler
                                 (when manager
                                   (lambda (network previous-networks)
                                     (reconcile-node-overlay-network
                                      network previous-networks
                                      wireguard-private-key))))
                               dns-forward-rules (cpu-manager-policy "none") reserved-cpus
                               (topology-manager-policy "none"))
  "Build and return a NODE-RUNTIME for STATE-DIRECTORY, opening its local desired-state
store (watch journal disabled, since the control plane serves every watch) and wiring in
RUNTIME and MANAGER. Replays any persisted node network -- applied or pending -- and
rebuilds the urgent-cleanup fence from the Pods already on disk, so a restart resumes
mid-deletion work even with the control plane unavailable. Starts no thread;
START-NODE-RUNTIME does that."
  (let* ((directory (uiop:ensure-directory-pathname state-directory))
         (store (open-store (merge-pathnames "desired/" directory)))
         (dynamic-resource-manager
           (when (containerd-runtime-p runtime)
             (gr8s.kubelet::make-dra-manager store directory))))
    ;; The control plane serves every watch; a journal here would only repeat its own.
    (setf (pod-store-watch-journal-p store) nil)
    (when (containerd-runtime-p runtime)
      (setf (containerd-runtime-resource-store runtime) store))
    (let ((node-runtime
            (%make-node-runtime
             :state-directory directory :runtime runtime :manager manager
             :dynamic-resource-manager dynamic-resource-manager
             :dns-forward-rules dns-forward-rules
             :network-reconciler network-reconciler
             :wireguard-path-state-path (merge-pathnames "wireguard-paths.json" directory)
             :wireguard-path-state
             (handler-case
                 (load-wireguard-path-state (merge-pathnames "wireguard-paths.json" directory))
               (error (condition)
                 (format *error-output* "gr8s: ignoring invalid WireGuard path state: ~A~%"
                         condition)
                 (make-wireguard-path-state)))
             :store store :reconciler (make-reconciler store runtime))))
      (when (and manager (containerd-runtime-p runtime))
        (setf (gr8s.runtime.containerd:containerd-runtime-kubelet-root runtime)
              (uiop:ensure-directory-pathname gr8s.kubelet::*csi-kubelet-root*))
        (let ((devices (gr8s.kubelet::make-device-plugin-manager directory)))
          (setf (node-runtime-device-plugin-manager node-runtime) devices
                (gr8s.runtime.containerd:containerd-runtime-device-plugin-allocation-function runtime)
                (lambda (pod container)
                  (gr8s.kubelet::node-pod-device-config (node-runtime-resource-manager node-runtime) pod container))
                (gr8s.runtime.containerd:containerd-runtime-device-plugin-release-function runtime)
                (lambda (pod) (gr8s.kubelet::release-plugin-devices devices pod)))
          (let ((resources (gr8s.kubelet::make-node-resource-manager
                            directory :policy cpu-manager-policy :topology-policy topology-manager-policy
                            :reserved-cpus reserved-cpus :devices devices :runtime runtime :store store
                            :cpu-state-path (merge-pathnames "cpu_manager_state" (gr8s.runtime.containerd:containerd-runtime-kubelet-root runtime)))))
            (setf (node-runtime-resource-manager node-runtime) resources
                  (gr8s.runtime.containerd:containerd-runtime-resource-prepare-function runtime)
                  (lambda (pod) (gr8s.kubelet::prepare-node-pod-resources resources pod))
                  (gr8s.runtime.containerd:containerd-runtime-resource-config-function runtime)
                  (lambda (pod container config)
                    (bt:with-lock-held ((gr8s.kubelet::node-resource-manager-lock resources))
                      (gr8s.kubelet::node-container-resources resources pod container config)))
                  (gr8s.runtime.containerd:containerd-runtime-resource-release-function runtime)
                  (lambda (pod) (gr8s.kubelet::release-node-pod-resources resources pod))
                  (gr8s.runtime.containerd:containerd-runtime-resource-resize-function runtime)
                  (lambda (pod) (gr8s.kubelet::node-resource-resize-verdict resources pod))))))
      (when dynamic-resource-manager
        (setf (gr8s.runtime.containerd:containerd-runtime-dynamic-resource-prepare-function runtime)
              (lambda (pod)
                (gr8s.kubelet::prepare-pod-dynamic-resources dynamic-resource-manager pod))
              (gr8s.runtime.containerd:containerd-runtime-dynamic-resource-cdi-device-function runtime)
              (lambda (pod container)
                (gr8s.kubelet::container-dra-cdi-device-ids
                 dynamic-resource-manager pod container))
              (gr8s.runtime.containerd:containerd-runtime-dynamic-resource-unprepare-function runtime)
              (lambda (pod)
                (gr8s.kubelet::unprepare-pod-dynamic-resources dynamic-resource-manager pod))))
      (when (and manager (string= "external" (managed-containerd-cni-mode manager)))
        (load-node-runtime-external-cni-endpoints node-runtime))
      (let ((applied (read-node-network-file (node-runtime-network-path node-runtime)))
            (pending (read-node-network-file (node-runtime-network-pending-path node-runtime))))
        (when (or (null manager)
                  (string= "native" (managed-containerd-cni-mode manager)))
          (when applied
            (validate-node-network-object applied)
            (setf (node-runtime-network node-runtime) applied))
          (when (or pending applied)
            (configure-node-runtime-network node-runtime (or pending applied)
                                            :persist (not (null pending))))))
      (dolist (pod (list-pods store))
        (setf (gethash (pod-uid pod) (node-runtime-assigned-versions node-runtime))
              (pod-resource-version pod))
        ;; Rebuild the finite cleanup admission fence before the background
        ;; reconciler starts, including when the control plane is unavailable.
        (when (pod-runtime-cleanup-pending-p store pod)
          (let ((reconciler (node-runtime-reconciler node-runtime)))
            (setf (gethash (pod-uid pod) (reconciler-urgent-deletions reconciler)) t)
            (note-urgent-deletions-changed reconciler))))
      node-runtime)))

(defun node-runtime-network-path (node-runtime)
  "Pathname of the file holding the node's last fully-applied network assignment."
  (merge-pathnames "network.json" (node-runtime-state-directory node-runtime)))

(defun node-runtime-network-pending-path (node-runtime)
  "Pathname of the file holding network intent written before the kernel changes, kept
until they all succeed so a partial apply can be retried."
  (merge-pathnames "network-pending.json" (node-runtime-state-directory node-runtime)))

(defun read-node-network-file (path)
  "Parse the node-network JSON at PATH, or return NIL when the file does not exist."
  (when (probe-file path) (com.inuoe.jzon:parse path)))

(defun wireguard-endpoint-messages-object (endpoints)
  (coerce
   (mapcar (lambda (endpoint)
             (json-object "name" (slot-value endpoint 'gr8s.node.v1::name)
                          "address" (slot-value endpoint 'gr8s.node.v1::address)
                          "port" (slot-value endpoint 'gr8s.node.v1::port)))
           endpoints)
   'vector))

(defun wireguard-next-hop-object (hop)
  (let ((object
          (json-object
           "nodeID" (slot-value hop 'gr8s.node.v1::node-id)
           "nodeName" (slot-value hop 'gr8s.node.v1::node-name)
           "underlayAddress" (slot-value hop 'gr8s.node.v1::underlay-address)
           "wireguardPublicKey"
           (ag-grpc:base64-encode
            (slot-value hop 'gr8s.node.v1::wireguard-public-key))
           "wireguardListenPort"
           (slot-value hop 'gr8s.node.v1::wireguard-listen-port))))
    (let ((endpoints (slot-value hop 'gr8s.node.v1::wireguard-endpoints)))
      (when endpoints
        (setf (gethash "wireguardEndpoints" object)
              (wireguard-endpoint-messages-object endpoints))))
    object))

(defun node-network-object (network &optional routes)
  "Build the persisted node-network object (version 1) from the node-protocol NETWORK
message and its ROUTES. This is the on-disk and in-memory shape the rest of this file
validates and reconciles against."
  (let* ((backend (slot-value network 'gr8s.node.v1::overlay-backend))
         (cluster-cidrs
           (or (slot-value network 'gr8s.node.v1::cluster-pod-cidrs)
               (list (slot-value network 'gr8s.node.v1::cluster-pod-cidr))))
         (node-cidrs
           (or (slot-value network 'gr8s.node.v1::node-pod-cidrs)
               (list (slot-value network 'gr8s.node.v1::node-pod-cidr)))))
    (json-object
     "version" 1
     "clusterPodCIDR" (first cluster-cidrs)
     "clusterPodCIDRs" (coerce cluster-cidrs 'vector)
     "nodePodCIDR" (first node-cidrs)
     "nodePodCIDRs" (coerce node-cidrs 'vector)
     "serviceTranslations"
     (coerce (mapcar
              (lambda (identity)
                (json-object "podUID" (slot-value identity 'gr8s.node.v1::pod-uid)
                             "nodeID" (slot-value identity 'gr8s.node.v1::node-id)
                             "nodeName" (slot-value identity 'gr8s.node.v1::node-name)
                             "podIP" (slot-value identity 'gr8s.node.v1::pod-ip)
                             "address" (slot-value identity 'gr8s.node.v1::translation-ip)
                             "sandboxID" (slot-value identity 'gr8s.node.v1::sandbox-id)
                             "interfaceName" (slot-value identity 'gr8s.node.v1::interface-name)
                             "incarnationGeneration"
                             (slot-value identity 'gr8s.node.v1::incarnation-generation)))
              (slot-value network 'gr8s.node.v1::service-translations)) 'vector)
     "dnsAddress" (slot-value network 'gr8s.node.v1::dns-address)
     "vni" (slot-value network 'gr8s.node.v1::vni)
     "mtu" (slot-value network 'gr8s.node.v1::mtu)
     "underlayAddress" (slot-value network 'gr8s.node.v1::underlay-address)
     "overlayBackend" (if (zerop (length backend)) "vxlan" backend)
     "wireguardListenPort"
     (slot-value network 'gr8s.node.v1::wireguard-listen-port)
     "routes"
     (coerce
      (mapcar
       (lambda (route)
         (let ((object
                 (json-object
                  "nodeID" (slot-value route 'gr8s.node.v1::node-id)
                  "podCIDR" (slot-value route 'gr8s.node.v1::pod-cidr)
                  "podCIDRs"
                  (coerce (or (slot-value route 'gr8s.node.v1::pod-cidrs)
                              (list (slot-value route 'gr8s.node.v1::pod-cidr)))
                          'vector)
                  "underlayAddress"
                  (slot-value route 'gr8s.node.v1::underlay-address)
                  "region" (let ((value (slot-value route 'gr8s.node.v1::region)))
                             (if (plusp (length value)) value "unknown-region"))
                  "zone" (let ((value (slot-value route 'gr8s.node.v1::zone)))
                           (if (plusp (length value)) value "unknown-zone"))
                  "capacityScore" (slot-value route 'gr8s.node.v1::capacity-score)
                  "linkCost" (let ((value (slot-value route 'gr8s.node.v1::link-cost)))
                               (if (plusp value) value 100))))
               (key (slot-value route 'gr8s.node.v1::wireguard-public-key))
               (port (slot-value route 'gr8s.node.v1::wireguard-listen-port))
               (name (slot-value route 'gr8s.node.v1::node-name))
               (next-hop (slot-value route 'gr8s.node.v1::next-hop)))
           (when (plusp (length name))
             (setf (gethash "nodeName" object) name))
           (when (plusp (length key))
             (setf (gethash "wireguardPublicKey" object)
                   (ag-grpc:base64-encode key)))
           (when (plusp port)
             (setf (gethash "wireguardListenPort" object) port))
           (let ((endpoints (slot-value route 'gr8s.node.v1::wireguard-endpoints)))
             (when endpoints
               (setf (gethash "wireguardEndpoints" object)
                     (wireguard-endpoint-messages-object endpoints))))
           (when next-hop
             (setf (gethash "nextHop" object)
                   (wireguard-next-hop-object next-hop)))
           object))
       routes)
      'vector))))

(defun persisted-node-network-cidrs (network plural singular)
  "Return NETWORK's ordered CIDRs, falling back to its legacy singular field."
  (let ((values (gethash plural network)))
    (if values
        (progn
          (unless (and (vectorp values) (plusp (length values))
                       (every (lambda (value)
                                (and (stringp value) (plusp (length value))))
                              values))
            (invalid-cni "node network ~A must be a non-empty string array" plural))
          (coerce values 'list))
        (list (required-cni-string network singular)))))

(defun validate-node-network-cidr-pairs (network)
  "Validate ordered cluster/node Pod CIDRs and return the node CIDRs."
  (let ((cluster-cidrs
          (persisted-node-network-cidrs network "clusterPodCIDRs" "clusterPodCIDR"))
        (node-cidrs
          (persisted-node-network-cidrs network "nodePodCIDRs" "nodePodCIDR")))
    (unless (= (length cluster-cidrs) (length node-cidrs))
      (invalid-cni "cluster and node Pod CIDR families must have the same length"))
    (let ((families nil))
      (loop for cluster-cidr in cluster-cidrs
            for node-cidr in node-cidrs
            do (multiple-value-bind (cluster-family cluster-address cluster-prefix cluster-bits)
                   (parse-pod-cidr cluster-cidr)
                 (multiple-value-bind (node-family node-address node-prefix node-bits)
                     (parse-pod-cidr node-cidr)
                   (unless (and (eq cluster-family node-family)
                                (= cluster-bits node-bits)
                                (not (member node-family families))
                                (<= cluster-prefix node-prefix)
                                (<= node-prefix (- node-bits 2))
                                (= (ash cluster-address (- cluster-prefix cluster-bits))
                                   (ash node-address (- cluster-prefix node-bits)))
                                (zerop (logand node-address
                                               (1- (ash 1 (- node-bits node-prefix))))))
                     (invalid-cni "node Pod CIDR ~A is not a canonical subnet of ~A"
                                  node-cidr cluster-cidr))
                   (push node-family families)))))
    node-cidrs))

(defun validate-network-cidr (cidr)
  "Return (values ADDRESS PREFIX) for CIDR, a canonical IPv4 CIDR with a 0--30 prefix and
no host bits set. Signals INVALID-CNI on anything else."
  (handler-case
      (multiple-value-bind (address prefix) (parse-ipv4-cidr cidr)
        (unless (and (<= 0 prefix 30)
                     (zerop (logand address (1- (ash 1 (- 32 prefix))))))
          (invalid-cni "invalid network CIDR ~A" cidr))
        (values address prefix))
    (cni-error (condition) (error condition))
    (error () (invalid-cni "invalid network CIDR ~S" cidr))))

(defun network-cidr-subnet-p (subnet parent)
  "True when SUBNET lies wholly within PARENT (both validated as CIDRs). Signals
INVALID-CNI on a malformed CIDR."
  (multiple-value-bind (address prefix) (validate-network-cidr subnet)
    (multiple-value-bind (parent-address parent-prefix) (validate-network-cidr parent)
      (and (<= parent-prefix prefix)
           (= (ash address (- parent-prefix 32))
              (ash parent-address (- parent-prefix 32)))))))

(defun network-cidrs-overlap-p (left right)
  "True when LEFT and RIGHT overlap -- one contains the other at the shorter prefix.
Signals INVALID-CNI on a malformed CIDR."
  (multiple-value-bind (a a-prefix) (validate-network-cidr left)
    (multiple-value-bind (b b-prefix) (validate-network-cidr right)
      (let ((shift (- (min a-prefix b-prefix) 32)))
        (= (ash a shift) (ash b shift))))))

(defun pod-cidr-subnet-p (subnet parent)
  "Return whether canonical SUBNET lies wholly within same-family PARENT."
  (multiple-value-bind (family address prefix bits) (parse-pod-cidr subnet)
    (multiple-value-bind (parent-family parent-address parent-prefix parent-bits)
        (parse-pod-cidr parent)
      (and (eq family parent-family)
           (= bits parent-bits)
           (<= parent-prefix prefix)
           (zerop (logand address (1- (ash 1 (- bits prefix)))))
           (= (ash address (- parent-prefix bits))
              (ash parent-address (- parent-prefix bits)))
           (string= subnet
                    (format nil "~A/~D" (format-pod-address family address) prefix))))))

(defun validate-wireguard-peer-object (peer description)
  "Validate one authenticated direct peer or sparse next-hop JSON object."
  (unless (hash-table-p peer)
    (invalid-cni "invalid WireGuard ~A" description))
  (let ((id (required-cni-string peer "nodeID")))
    (unless (dns-label-p (gethash "nodeName" peer id))
      (invalid-cni "invalid WireGuard ~A node name" description)))
  (let ((name (gethash "nodeName" peer (gethash "nodeID" peer)))
        (address (required-cni-string peer "underlayAddress")))
    (unless (dns-label-p name)
      (invalid-cni "invalid WireGuard ~A node name" description))
    (handler-case (canonical-node-underlay-address address)
      (error () (invalid-cni "invalid WireGuard ~A underlay address" description))))
  (wireguard-decode-key
   (required-cni-string peer "wireguardPublicKey")
   (format nil "~A public key" description))
  (unless (typep (gethash "wireguardListenPort" peer) '(integer 1 65535))
    (invalid-cni "invalid WireGuard ~A listen port" description))
  (let ((names nil)
        (endpoints (gethash "wireguardEndpoints" peer #())))
    (unless (and (vectorp endpoints) (not (stringp endpoints)))
      (invalid-cni "WireGuard ~A endpoints must be an array" description))
    (loop for endpoint across endpoints
          do (unless (hash-table-p endpoint)
               (invalid-cni "invalid WireGuard ~A endpoint" description))
             (let ((name (required-cni-string endpoint "name"))
                   (address (required-cni-string endpoint "address"))
                   (port (gethash "port" endpoint)))
               (unless (and (dns-label-p name)
                            (not (member name names :test #'equal)))
                 (invalid-cni "invalid or duplicate WireGuard ~A endpoint name"
                              description))
               (handler-case (canonical-node-underlay-address address)
                 (error ()
                   (invalid-cni "invalid WireGuard ~A endpoint address" description)))
               (unless (typep port '(integer 1 65535))
                 (invalid-cni "invalid WireGuard ~A endpoint port" description))
               (push name names))))
  peer)

(defun validate-node-network-routes (network)
  "Validate NETWORK's peer routes across every configured Pod address family."
  (let ((routes (gethash "routes" network #()))
        (cluster-cidrs
          (persisted-node-network-cidrs network "clusterPodCIDRs" "clusterPodCIDR"))
        (cidrs (persisted-node-network-cidrs network "nodePodCIDRs" "nodePodCIDR"))
        (addresses (list (gethash "underlayAddress" network "")))
        (node-ids nil))
    (unless (and (vectorp routes) (not (stringp routes)))
      (invalid-cni "node routes must be an array"))
    (when (and (plusp (length routes)) (string= "" (first addresses)))
      (invalid-cni "peer routes require a local node underlay address"))
    (loop for route across routes
          do (unless (hash-table-p route) (invalid-cni "invalid node route"))
             (let* ((id (required-cni-string route "nodeID"))
                    (name (gethash "nodeName" route id))
                    (route-cidrs (gr8s.network::route-pod-cidrs route))
                    (address (required-cni-string route "underlayAddress")))
               (handler-case (canonical-node-underlay-address address)
                 (error () (invalid-cni "invalid peer underlay address ~A" address)))
               (unless (and (= (length route-cidrs) (length cluster-cidrs))
                            (loop for cidr in route-cidrs
                                  for cluster-cidr in cluster-cidrs
                                  always (and (pod-cidr-subnet-p cidr cluster-cidr)
                                              (notany (lambda (other)
                                                        (pod-cidrs-overlap-p cidr other))
                                                      cidrs)))
                            (not (member id node-ids :test #'string=))
                            (not (member address addresses :test #'string=)))
                 (invalid-cni "conflicting or out-of-range peer routes ~{~A~^, ~}"
                              route-cidrs))
               (when (string= "wireguard" (gethash "overlayBackend" network "vxlan"))
                 (validate-wireguard-peer-object route "peer")
                 (let ((next-hop (gethash "nextHop" route)))
                   (when next-hop
                     (validate-wireguard-peer-object next-hop "next hop"))))
               (unless (dns-label-p name)
                 (invalid-cni "invalid peer node name ~A" name))
               (dolist (field '("region" "zone"))
                 (let ((value (gethash field route "unknown")))
                   (unless (and (stringp value) (plusp (length value))
                                (<= (length value) 253))
                     (invalid-cni "invalid peer ~A" field))))
               (unless (typep (gethash "capacityScore" route 0) '(integer 0 100000))
                 (invalid-cni "invalid peer capacity score"))
               (unless (typep (gethash "linkCost" route 100) '(integer 0 100))
                 (invalid-cni "invalid peer link cost"))
               (setf cidrs (nconc route-cidrs cidrs))
               (push address addresses)
               (push id node-ids))))
  network)

(defun validate-node-network-object (network)
  "Validate a persisted or assigned node network end to end: version 1, node Pod CIDR a
subnet of the cluster Pod CIDR, a valid (or empty) local underlay address, valid peer
routes, the DNS address equal to the link-local Pod gateway, and MTU and VNI in range.
Returns NETWORK; signals INVALID-CNI on any violation."
  (unless (and (hash-table-p network) (eql 1 (gethash "version" network)))
    (invalid-cni "invalid persisted node network format"))
  (validate-node-network-cidr-pairs network)
  (gr8s.network::validate-service-translation-network network)
  (let ((address (gethash "underlayAddress" network "")))
    (unless (equal address "")
      (handler-case (canonical-node-underlay-address address)
        (error () (invalid-cni "invalid local node underlay address ~S" address)))))
  (validate-node-network-routes network)
  (unless (string= +dns-pod-server-address+
                   (required-cni-string network "dnsAddress"))
    (invalid-cni "node DNS address must be the link-local Pod gateway"))
  (unless (typep (gethash "mtu" network) '(integer 576 9000))
    (invalid-cni "invalid node network MTU"))
  (unless (typep (gethash "vni" network) '(integer 1 16777215))
    (invalid-cni "invalid VXLAN network identifier"))
  (let ((backend (gethash "overlayBackend" network "vxlan")))
    (unless (member backend '("vxlan" "wireguard") :test #'string=)
      (invalid-cni "invalid overlay backend ~A" backend))
    (when (and (string= backend "wireguard")
               (not (typep (gethash "wireguardListenPort" network)
                           '(integer 1 65535))))
      (invalid-cni "invalid WireGuard listen port")))
  network)

(defun publish-node-runtime-service-nat-inventory
    (node-runtime &optional (network (node-runtime-network node-runtime))
     &key reset-readiness previous-networks (ipam (node-runtime-ipam node-runtime)))
  "Seed the shared v2 managed-address and identity tables from the network assignment.
Called after a new assignment and after a retained Service LB map is opened on
restart, since the network may be restored before the dataplane starts."
  (let* ((dataplane (node-runtime-service-lb node-runtime))
         (managed (and dataplane (service-lb-map dataplane "gr8s_nat_pod_v2")))
         (identities (and dataplane (service-lb-map dataplane "gr8s_nat_id_v2"))))
    (when (and managed network)
      (gr8s.network::publish-service-nat-managed-cidrs
       managed (persisted-node-network-cidrs network "clusterPodCIDRs" "clusterPodCIDR")))
    (when (and identities reset-readiness)
      (gr8s.network::clear-service-nat-owner-readiness identities))
    (when (and identities network)
      (bt:with-lock-held (gr8s.network::*service-nat-owner-lifecycle-lock*)
       (gr8s.network::publish-service-nat-identities
        identities (gethash "serviceTranslations" network #())
        :preserve-readiness (not reset-readiness))
       (when previous-networks
        ;; CNI leases are allocated before owner rows are written. Hold IPAM
        ;; through retirement so a concurrent ADD cannot be mistaken for a
        ;; withdrawn replicated claim in this agent process.
        (if ipam
            (bt:with-lock-held ((node-ipam-lock ipam))
              (gr8s.network::retire-service-nat-withdrawn-identities
               identities previous-networks (gethash "serviceTranslations" network #())
               (loop for key being the hash-keys of (node-ipam-service-snat-allocations ipam)
                       using (hash-value alias)
                     for addresses = (gethash key (node-ipam-allocations ipam))
                     for primary = (find-if-not (lambda (address) (find #\: address)) addresses)
                     when (and primary alias)
                       append (gr8s.network::service-nat-identity-pair
                               (node-runtime-node-id node-runtime) (car key) (cdr key)
                               primary alias))))
            (gr8s.network::retire-service-nat-withdrawn-identities
             identities previous-networks (gethash "serviceTranslations" network #()) nil)))))))

(defun configure-node-runtime-network (node-runtime network &key (persist t))
  "Apply NETWORK as this node's overlay configuration and record it on the runtime.
Validates NETWORK, opens IPAM if needed and -- under the network lock -- refuses to change
the durable node Pod CIDR, then (when PERSIST) writes pending intent, runs the network
reconciler to converge the kernel, admits the overlay through an active host firewalld
(fail-soft, managed nodes only), and promotes pending to applied. Leaves CNI operations
ready for new Pods. Returns the NODE-RUNTIME; signals INVALID-CNI on an invalid or
conflicting network."
  (validate-node-network-object network)
  (let ((runtime (node-runtime-runtime node-runtime))
        (address (gethash "underlayAddress" network "")))
    (when (and (typep runtime 'containerd-runtime) (plusp (length address)))
      (setf (containerd-runtime-host-address runtime) address)))
  (when (node-runtime-manager node-runtime)
    (validate-pod-pool-host-routes (persisted-node-network-cidrs
                                    network "clusterPodCIDRs" "clusterPodCIDR")
                                  (node-runtime-state-directory node-runtime)))
  (bt:with-lock-held ((node-runtime-network-lock node-runtime))
    (let ((existing (node-runtime-network node-runtime)))
      (when (and existing
                 (not (equal (persisted-node-network-cidrs
                              existing "nodePodCIDRs" "nodePodCIDR")
                             (persisted-node-network-cidrs
                              network "nodePodCIDRs" "nodePodCIDR"))))
        (invalid-cni "refusing to change the agent's durable Pod CIDR")))
    (let ((ipam
            (or (node-runtime-ipam node-runtime)
                (open-node-ipam
                 (merge-pathnames "ipam/" (node-runtime-state-directory node-runtime))
                 (persisted-node-network-cidrs
                  network "nodePodCIDRs" "nodePodCIDR")))))
      (let ((previous (remove nil (list
                                    (node-runtime-network node-runtime)
                                    (read-node-network-file (node-runtime-network-path node-runtime))
                                    (read-node-network-file (node-runtime-network-pending-path node-runtime))))))
        (dolist (old previous) (validate-node-network-object old))
        ;; Write intent first. Retain the last applied network until all kernel
        ;; changes succeed so partial peer installation/removal can be retried.
        (when persist
          (write-private-text-atomically
           (node-runtime-network-pending-path node-runtime)
           (com.inuoe.jzon:stringify network)))
        (when (node-runtime-network-reconciler node-runtime)
          (funcall (node-runtime-network-reconciler node-runtime) network previous))
        ;; Admit this node's overlay through an active host firewalld (podster-vwy):
        ;; cross-node traffic is kernel-routed (conntrack-tracked), so firewalld
        ;; would drop the forwarded/encapsulated packets without a scoped ACCEPT.
        ;; No-op without firewalld; fail-soft. Only meaningful for a managed node.
        (ignore-errors (ensure-node-runtime-overlay-firewall node-runtime network))
        ;; Retire withdrawn owner incarnations while the previous applied
        ;; network is still durable. A crash after promotion must not strand
        ;; enabled rows that the new assignment no longer names.
        (publish-node-runtime-service-nat-inventory
         node-runtime network :previous-networks previous :ipam ipam)
        (when persist
          (write-private-text-atomically
           (node-runtime-network-path node-runtime)
           (com.inuoe.jzon:stringify network))
          (when (probe-file (node-runtime-network-pending-path node-runtime))
            (delete-file (node-runtime-network-pending-path node-runtime)))))
      (setf (node-runtime-network node-runtime) network
            (node-runtime-ipam node-runtime) ipam
            (node-runtime-cni-operations node-runtime)
            (make-routed-cni-operations
             ipam :node-id (node-runtime-node-id node-runtime)
                  :service-risk-ready-p
                  (lambda () (node-runtime-local-risk-ready-p node-runtime))
                  :mtu (gethash "mtu" network)
                  :dns-address (gethash "dnsAddress" network)))))
  node-runtime)

(defun node-network-overlay-firewall-identity (network)
  "Return NETWORK's firewalld identity as (Pod-CIDR interface UDP-port)."
  (let* ((cidrs (persisted-node-network-cidrs network "nodePodCIDRs" "nodePodCIDR"))
         (cidr-value (if (rest cidrs) cidrs (first cidrs))))
    (if (string= "wireguard" (gethash "overlayBackend" network "vxlan"))
      (list cidr-value
            +node-wireguard-interface+
            (gethash "wireguardListenPort" network))
      (list cidr-value
            +node-vxlan-interface+
            +node-vxlan-udp-port+))))

(defun call-overlay-firewall-function (function identity)
  "Call FUNCTION with the Pod CIDR, interface and UDP port in IDENTITY."
  (destructuring-bind (cidr interface port) identity
    (funcall function cidr :interface interface :port port)))

(defun ensure-node-runtime-overlay-firewall
    (node-runtime network &key (ensure #'ensure-overlay-firewall)
                               (remove #'remove-overlay-firewall))
  "Admit NETWORK's overlay once per NODE-RUNTIME process, using ENSURE to apply it.
Repeated cached snapshots carry the same desired network; remembering a successful
apply prevents each snapshot from spawning three firewall-cmd processes. A failed or
inactive-firewalld attempt is not remembered, so a later snapshot can retry."
  (when (and (node-runtime-manager node-runtime)
             (plusp (length (gethash "underlayAddress" network ""))))
    (let ((desired (node-network-overlay-firewall-identity network))
          (current (node-runtime-overlay-firewall-identity node-runtime)))
      (unless (equal desired current)
        (when current
          (ignore-errors (call-overlay-firewall-function remove current))
          (setf (node-runtime-overlay-firewall-identity node-runtime) nil))
        (when (call-overlay-firewall-function ensure desired)
          (setf (node-runtime-overlay-firewall-identity node-runtime) desired)
          t)))))

(defun apply-node-runtime-network (node-runtime snapshot)
  "Configure the node network from SNAPSHOT's assigned network. A managed agent given no
assigned network signals INVALID-CNI in native mode; external CNI mode leaves all
link, route, overlay and IPAM ownership to the configured plugins."
  (when (and (node-runtime-manager node-runtime)
             (string= "external"
                      (managed-containerd-cni-mode (node-runtime-manager node-runtime))))
    (return-from apply-node-runtime-network nil))
  (let ((network (slot-value snapshot 'gr8s.node.v1::network)))
    (cond
      (network (configure-node-runtime-network node-runtime (node-network-object network (slot-value snapshot 'gr8s.node.v1::routes))))
      ((node-runtime-manager node-runtime)
       (invalid-cni "managed agent snapshot has no assigned network")))))

(defun node-runtime-has-allocations-p (node-runtime)
  "Report whether durable Pod leases require preserving the node dataplane."
  (let ((ipam (node-runtime-ipam node-runtime)))
    (and ipam
         (bt:with-lock-held ((node-ipam-lock ipam))
           (plusp (hash-table-count (node-ipam-allocations ipam)))))))

(defun cleanup-node-runtime-gateway (node-runtime)
  "Remove the owned gateway after node services stop and all leases are gone."
  ;; Keep the gateway while Pods or partially installed leases outlive us.
  (when (and (node-runtime-manager node-runtime)
             (string= "native" (managed-containerd-cni-mode (node-runtime-manager node-runtime)))
             (node-runtime-ipam node-runtime)
             (not (node-runtime-has-allocations-p node-runtime)))
    (remove-node-gateway)
    ;; The node is going away with no Pods left; withdraw the overlay firewall
    ;; accepts we programmed (podster-vwy) so the host firewall is left as we
    ;; found it. Fail-soft; a no-op without an active firewalld.
    (let ((identity (node-runtime-overlay-firewall-identity node-runtime)))
      (when identity
        (ignore-errors
          (call-overlay-firewall-function #'remove-overlay-firewall identity))))))

(defun reconcile-cached-node-network (node-runtime)
  "Re-apply the node's durable network to repair kernel state -- e.g. VXLAN FDB entries a
link event flushed -- even when the control-plane revision has not changed, re-ensuring
the node gateway when Pods still hold allocations. Held under the apply lock; a no-op
without a network reconciler. Returns NIL."
  ;; Kernel link events can flush permanent VXLAN FDB entries even when the
  ;; control-plane revision is unchanged. Repair from durable local topology.
  (when (and (node-runtime-network-reconciler node-runtime)
             (or (null (node-runtime-manager node-runtime))
                 (string= "native"
                          (managed-containerd-cni-mode (node-runtime-manager node-runtime)))))
    (bt:with-lock-held ((node-runtime-apply-lock node-runtime))
      (let* ((pending (read-node-network-file (node-runtime-network-pending-path node-runtime)))
             (network (or pending (node-runtime-network node-runtime))))
        (when network
          (configure-node-runtime-network node-runtime network :persist (not (null pending)))
          (when (and (node-runtime-manager node-runtime)
                     (node-runtime-has-allocations-p node-runtime))
            (ensure-node-gateway))))))
  nil)

(defun update-node-runtime-wireguard-path-telemetry
    (node-runtime network
     &key (start #'try-start-wireguard-path-telemetry-dataplane)
       (poll #'poll-wireguard-path-telemetry))
  "Lazily sample passive telemetry before endpoint selection can change."
  (unless (node-runtime-wireguard-path-telemetry node-runtime)
    (setf (node-runtime-wireguard-path-telemetry node-runtime) (funcall start)))
  (let ((dataplane (node-runtime-wireguard-path-telemetry node-runtime)))
    (when dataplane
      (apply-wireguard-path-telemetry-samples
       (node-runtime-wireguard-path-state node-runtime)
       (funcall poll dataplane network))))
  nil)

(defun reconcile-node-runtime-wireguard-paths (node-runtime)
  "Observe, trial and durably select WireGuard endpoints; fail soft on a tick."
  (let ((network (node-runtime-network node-runtime)))
    (when (and network
               (string= "wireguard" (gethash "overlayBackend" network "vxlan")))
      (handler-case
          (progn
            (update-node-runtime-wireguard-path-telemetry node-runtime network)
            (reconcile-wireguard-path-state
             (node-runtime-wireguard-path-state node-runtime) network
             :probe-function (lambda (route) (probe-wireguard-route route)))
            (reconcile-wireguard-path-mtus
             (node-runtime-wireguard-path-state node-runtime) network)
            (apply-wireguard-selected-safe-mtu
             (node-runtime-wireguard-path-state node-runtime) network)
            (persist-wireguard-path-state
             (node-runtime-wireguard-path-state-path node-runtime)
             (node-runtime-wireguard-path-state node-runtime))
            ;; Path evidence is runtime state, not a control-plane snapshot; make
            ;; Service choices follow it on the same reconciliation tick.
            (when (node-runtime-service-lb-controller node-runtime)
              (converge-node-runtime-service-lb node-runtime)))
        (error (condition)
          (format *error-output* "gr8s: WireGuard path reconciliation failed: ~A~%"
                  condition)))))
  nil)

(defun service-endpoint-route (network address)
  (find-if (lambda (route)
             (ignore-errors
               (ipv4-cidr-contains-p (gethash "podCIDR" route) address)))
           (coerce (gethash "routes" network #()) 'list)))

(defun steer-service-endpoints (node-runtime endpoints &key (maximum 4))
  "Choose a bounded, deterministic backend subset from local authenticated state."
  (let ((network (node-runtime-network node-runtime))
        (state (node-runtime-wireguard-path-state node-runtime)))
    (if (or (null network) (<= (length endpoints) 1))
        endpoints
        (let* ((routes (coerce (gethash "routes" network #()) 'list))
               ;; A same-zone route carries the source's authenticated region/zone.
               ;; When this node is alone in its zone, keep a distinct local domain.
               (same-zone-route (find 1 routes :key (lambda (route)
                                                      (gethash "linkCost" route 100))))
               (local-domain
                 (if same-zone-route
                     (list (gethash "region" same-zone-route "unknown-region")
                           (gethash "zone" same-zone-route "unknown-zone"))
                     (list "local" "local")))
               (ranked
                (rank-network-steering-candidates
                 (loop for endpoint in endpoints
                       for address = (first endpoint)
                       for route = (service-endpoint-route network address)
                       for next-hop = (and route (gethash "nextHop" route))
                       for peer-id = (and route (gethash "nodeID" (or next-hop route)))
                       for peer = (and peer-id state
                                       (gethash peer-id
                                                (wireguard-path-state-peers state)))
                       for observation = (and peer
                                              (wireguard-peer-path-state-selected peer)
                                              (wireguard-observation-for-endpoint
                                               peer
                                               (wireguard-peer-path-state-selected peer)))
                       collect
                       (list
                        :value endpoint
                        :node-name (if route (gethash "nodeName" route) "local")
                        :same-node (null route)
                        :same-zone (and route (= 1 (gethash "linkCost" route 100)))
                        :same-region (and route (<= (gethash "linkCost" route 100) 10))
                        :failure-domain (if route
                                            (list (gethash "region" route "unknown-region")
                                                  (gethash "zone" route "unknown-zone"))
                                            local-domain)
                        :capacity (if route (gethash "capacityScore" route 0) 100000)
                        :link-cost (if route (gethash "linkCost" route 100) 0)
                        :healthy (if observation
                                     (wireguard-path-healthy-p observation)
                                     t)
                        :path-score (if observation
                                        (wireguard-path-score observation)
                                        (if route 10000 0))
                        :active-flows
                        (if observation
                            (wireguard-path-observation-passive-active-flows observation)
                            0))))))
          (mapcar (lambda (candidate) (getf candidate :value))
                  (subseq ranked 0 (min (length ranked) (max 1 (min maximum 16)))))))))

(defun handle-node-runtime-cni
    (node-runtime request &key (chained-operations (make-chained-cni-operations)))
  "Service one agent CNI REQUEST in the manager's configured ownership mode.
External mode treats gr8s as an optional chained policy plugin and never requires
the native node IPAM. Native mode dispatches to the assigned routed CNI operations."
  (if (and (node-runtime-manager node-runtime)
           (string= "external"
                    (managed-containerd-cni-mode (node-runtime-manager node-runtime))))
      (let ((response
              (handle-agent-cni-request request :operations chained-operations :chained t)))
        (if (slot-value response 'gr8s.node.v1::success)
            (handler-case
                (let* ((command (slot-value request 'gr8s.node.v1::command))
                       (configuration
                         (when (string= command "ADD")
                           (parse-cni-configuration
                            (trivial-utf-8:utf-8-bytes-to-string
                             (slot-value request 'gr8s.node.v1::network-configuration))
                            :require-previous t)))
                       (address (and configuration
                                     (chained-cni-ipv4-address
                                      (cni-configuration-previous-result configuration)))))
                  (update-node-runtime-external-cni-endpoint
                   node-runtime command
                   (slot-value request 'gr8s.node.v1::container-id)
                   (slot-value request 'gr8s.node.v1::interface-name)
                   address)
                  response)
              (error (condition) (agent-cni-error-response condition)))
            response))
      (let ((operations
              (bt:with-lock-held ((node-runtime-network-lock node-runtime))
                (node-runtime-cni-operations node-runtime))))
        (if operations
            (handle-agent-cni-request request :operations operations :chained nil)
            (agent-cni-error-response
             (make-condition 'cni-error :message "node network assignment is not ready"))))))

(defun node-runtime-stopping-p (node-runtime)
  "True when a stop has been requested of NODE-RUNTIME (read under its lock)."
  (bt:with-lock-held ((node-runtime-lock node-runtime))
    (node-runtime-stop-requested node-runtime)))

(defun wait-for-node-runtime-stop (node-runtime)
  "Block until a stop is requested of NODE-RUNTIME, waiting on its state condition under
the runtime lock."
  (bt:with-lock-held ((node-runtime-lock node-runtime))
    (loop until (node-runtime-stop-requested node-runtime)
          do (bt:condition-wait
              (node-runtime-state-changed node-runtime)
              (node-runtime-lock node-runtime)))))

(defun run-node-runtime-body (node-runtime)
  "Run the agent's main loop: start the reconciliation worker (which each tick repairs the
cached network and re-converges NetworkPolicy and host-port forwarders, fail-soft), mark
the runtime running and notify waiters, then block until a stop is requested. On exit,
unwinds every service it started -- the worker, the host- and node-port forwarders, the
health-check servers and runtime deletions."
  (unwind-protect
       (progn
         (when (node-runtime-device-plugin-manager node-runtime)
           (gr8s.kubelet::start-device-plugin-manager (node-runtime-device-plugin-manager node-runtime)))
         (when (node-runtime-resource-manager node-runtime)
           (gr8s.kubelet::verify-node-resource-recovery (node-runtime-resource-manager node-runtime))
           (gr8s.kubelet::save-node-resource-checkpoint (node-runtime-resource-manager node-runtime))
           (setf (node-runtime-pod-resources-server node-runtime)
                 (gr8s.kubelet::start-podresources-server (node-runtime-resource-manager node-runtime)
                                                        (node-runtime-dynamic-resource-manager node-runtime))))
         (setf (node-runtime-worker node-runtime)
               (start-reconciliation-worker
                (node-runtime-reconciler node-runtime)
                :before-reconcile (lambda ()
                                    (gr8s.kubelet::reconcile-node-resource-manager (node-runtime-resource-manager node-runtime))
                                    (reconcile-cached-node-network node-runtime)
                                    (reconcile-node-runtime-wireguard-paths node-runtime)
                                    (when (node-runtime-service-lb node-runtime)
                                      (handler-case
                                          (when (gr8s.network:service-packet-gc-compatible-p
                                                 (node-runtime-service-lb node-runtime))
                                            (gr8s.network:sweep-service-packet-state
                                             (node-runtime-service-lb node-runtime)))
                                        (error (condition)
                                          (format *error-output* "gr8s: Service flow GC failed: ~A~%" condition))))
                                    ;; Re-run dataplane convergence every tick, not only on a new
                                    ;; control-plane snapshot: the out-of-process CNI plugin adds Pod
                                    ;; allocations the agent must pick up to populate local/host/remote
                                    ;; redirect tables for live Pods (podster-6yd). Fail-soft.
                                    (handler-case
                                        (converge-node-network-policies node-runtime)
                                      (error (condition)
                                        (format *error-output* "gr8s: NetworkPolicy convergence failed: ~A~%" condition)))
                                    (handler-case
                                        (converge-host-port-forwarders (node-runtime-host-port-forwarders node-runtime)
                                                                       (node-runtime-store node-runtime))
                                      (error (condition)
                                        (format *error-output* "gr8s: host port convergence failed: ~A~%" condition))))
                :observer (lambda (pod status) (cache-node-observation node-runtime pod status))))
         (bt:with-lock-held ((node-runtime-lock node-runtime))
           (setf (node-runtime-state node-runtime) :running)
           (bt:condition-notify (node-runtime-state-changed node-runtime)))
         (wait-for-node-runtime-stop node-runtime))
    (when (node-runtime-worker node-runtime)
      (stop-reconciliation-worker (node-runtime-worker node-runtime))
      (setf (node-runtime-worker node-runtime) nil))
    (stop-host-port-forwarders (node-runtime-host-port-forwarders node-runtime))
    (stop-host-port-forwarders (node-runtime-node-port-forwarders node-runtime))
    (stop-health-check-servers (node-runtime-health-check-servers node-runtime))
    (when (node-runtime-wireguard-path-telemetry node-runtime)
      (stop-wireguard-path-telemetry-dataplane
       (node-runtime-wireguard-path-telemetry node-runtime))
      (setf (node-runtime-wireguard-path-telemetry node-runtime) nil))
    (stop-runtime-deletions (node-runtime-runtime node-runtime))
    (gr8s.kubelet::stop-local-resource-server (node-runtime-pod-resources-server node-runtime))
    (gr8s.kubelet::stop-device-plugin-manager (node-runtime-device-plugin-manager node-runtime))))

(defun call-with-agent-cni-server
    (node-runtime function &key operations)
  "Run FUNCTION with the agent CNI server listening on the managed-containerd socket,
dispatching each request to OPERATIONS when supplied or else to the node runtime's current
operations. Stops the server on exit. Errors when the agent is not managed."
  (let ((manager (node-runtime-manager node-runtime)))
    (unless manager
      (error "the agent CNI service requires managed containerd"))
    (let ((server
            (start-agent-cni-server
             (managed-containerd-agent-cni-socket-path manager)
             (lambda (request)
               (if operations
                   (handle-agent-cni-request request :operations operations)
                   (handle-node-runtime-cni node-runtime request))))))
      (unwind-protect
           (funcall function)
        (stop-agent-cni-server server)))))

(defun call-with-service-lb (node-runtime function)
  "Bring up the in-kernel ClusterIP socket load balancer for the agent's
lifetime, then run FUNCTION.  Must run inside the managed-containerd scope so
the bpffs is mounted.  On any failure the dataplane stays NIL and the
control-plane userspace proxy continues to serve Services, so this never blocks
the node from starting."
  (let* ((manager (node-runtime-manager node-runtime))
         (disabled (let ((v (uiop:getenv "GR8S_DISABLE_SERVICE_LB")))
                     (and v (string= v "1"))))
         (pin-directory
           (and manager (not disabled)
                (namestring (merge-pathnames
                             "service-lb/"
                             (uiop:ensure-directory-pathname
                              (managed-containerd-bpf-directory manager))))))
         (dataplane
           (and pin-directory
                ;; The node cgroup2 root whose subtree holds the Pod processes.
                (try-start-service-lb-dataplane
                 "/sys/fs/cgroup" pin-directory
                 :packet-services
                 (when (equal "1" (uiop:getenv "GR8S_ENABLE_PACKET_SERVICES"))
                   (if (equal "1" (uiop:getenv "GR8S_PREPARE_PACKET_SERVICES_V2"))
                       :v2 t))))))
    (when dataplane
      (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
        (setf (node-runtime-service-risk-ready-revision node-runtime) nil
              (node-runtime-service-selection-ready-revision node-runtime) nil
              (node-runtime-service-selection-grant-digest node-runtime) nil))
      (setf (node-runtime-service-lb node-runtime) dataplane
            (node-runtime-service-lb-controller node-runtime)
            (make-service-lb-controller (node-runtime-store node-runtime) dataplane
                                        (node-runtime-node-name node-runtime)
                                        :endpoint-steerer
                                        (lambda (endpoints)
                                          (steer-service-endpoints
                                           node-runtime endpoints))))
      (publish-node-runtime-service-nat-inventory
       node-runtime (node-runtime-network node-runtime) :reset-readiness t))
    (handler-case
        (setf (node-runtime-gateway-steering node-runtime) (start-gateway-steering))
      (error (condition)
        (format *error-output* "gr8s: Gateway listener steering unavailable: ~A~%" condition)))
    (unwind-protect
         (funcall function)
      (when (node-runtime-gateway-controller node-runtime)
        (ignore-errors (stop-gateway-controller (node-runtime-gateway-controller node-runtime)))
        (setf (node-runtime-gateway-controller node-runtime) nil))
      (when (node-runtime-gateway-steering node-runtime)
        (ignore-errors (stop-gateway-steering (node-runtime-gateway-steering node-runtime)))
        (setf (node-runtime-gateway-steering node-runtime) nil))
      (when (node-runtime-service-lb node-runtime)
        (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
          (setf (node-runtime-service-risk-ready-revision node-runtime) nil
                (node-runtime-service-selection-ready-revision node-runtime) nil
                (node-runtime-service-selection-grant-digest node-runtime) nil))
        ;; Endpoint guards hold these same maps. Keep the canonical pins so a
        ;; clean agent restart reopens them rather than creating disconnected
        ;; Service tables while existing endpoint links still use the old ones.
        (ignore-errors (stop-service-lb-dataplane (node-runtime-service-lb node-runtime) :remove-pins nil))
        (setf (node-runtime-service-lb node-runtime) nil
              (node-runtime-service-lb-controller node-runtime) nil)))))

(defun call-with-node-runtime-services (node-runtime)
  "Run the agent body with the services its runtime needs layered around it: for managed
containerd, the Service LB, agent CNI server and DNS server; for unmanaged containerd,
just the DNS server; for any other runtime, nothing."
  (let ((body (lambda () (run-node-runtime-body node-runtime))))
    (if (containerd-runtime-p (node-runtime-runtime node-runtime))
        (if (node-runtime-manager node-runtime)
            (call-with-service-lb
             node-runtime
             (lambda ()
               (call-with-agent-cni-server
                node-runtime
                (lambda () (call-with-dns-server body :address +dns-pod-server-address+
                                                 :forward-rules (node-runtime-dns-forward-rules node-runtime)
                                                 :resolver
                                           (make-cluster-dns-resolver (node-runtime-store node-runtime)))))))
            (call-with-dns-server body :address +dns-pod-server-address+
                                       :forward-rules (node-runtime-dns-forward-rules node-runtime)
                                       :resolver
                                        (make-cluster-dns-resolver (node-runtime-store node-runtime))))
        (funcall body))))

(defun call-with-external-cni-dns-gateway
    (node-runtime function &key (ensure #'ensure-node-gateway) (remove #'remove-node-gateway))
  "Keep only gr8s's node-local DNS address while external plugins own Pod networking.
The gateway exists before the DNS listener starts and is removed after that listener
stops, including when the agent body exits with an error. Native mode continues to
create and retain the same gateway according to its durable IPAM leases."
  (if (and (node-runtime-manager node-runtime)
           (string= "external"
                    (managed-containerd-cni-mode (node-runtime-manager node-runtime))))
      (unwind-protect
           (progn (funcall ensure) (funcall function))
        (funcall remove))
      (funcall function)))

(defun node-runtime-thread-main (node-runtime)
  "The node-runtime thread's entry point: run the agent under managed containerd and its
services, cleaning up the node gateway on exit. Records any error and the final :failed or
:stopped state on the runtime, notifying waiters either way."
  (handler-case
      (unwind-protect
           (call-with-managed-containerd
            (node-runtime-manager node-runtime)
            (lambda ()
              (call-with-external-cni-dns-gateway
               node-runtime (lambda () (call-with-node-runtime-services node-runtime)))))
        (cleanup-node-runtime-gateway node-runtime))
    (error (condition)
      (bt:with-lock-held ((node-runtime-lock node-runtime))
        (setf (node-runtime-error node-runtime) condition
              (node-runtime-state node-runtime) :failed)
        (bt:condition-notify (node-runtime-state-changed node-runtime)))))
  (bt:with-lock-held ((node-runtime-lock node-runtime))
    (unless (eq :failed (node-runtime-state node-runtime))
      (setf (node-runtime-state node-runtime) :stopped))
    (bt:condition-notify (node-runtime-state-changed node-runtime))))

(defun start-node-runtime (node-runtime)
  "Start NODE-RUNTIME's agent thread and block until it is running, returning the runtime.
Idempotent while already running; re-signals the stored error if a previous start failed.
Wires the containerd Pod lister to hide Pods already in a terminal phase."
  (let ((runtime (node-runtime-runtime node-runtime)) (store (node-runtime-store node-runtime)))
    (when (typep runtime 'containerd-runtime)
      (setf (containerd-runtime-pod-lister runtime)
            (lambda ()
              (remove-if (lambda (pod)
                           (terminal-pod-phase-p
                            (with-store-lock (store)
                              (gethash (pod-uid pod) (pod-store-pod-observed-phases store)))))
                         (list-pods store))))))
  (bt:with-lock-held ((node-runtime-lock node-runtime))
    (case (node-runtime-state node-runtime)
      (:running (return-from start-node-runtime node-runtime))
      (:starting)
      (:failed (error (node-runtime-error node-runtime)))
      (:stopped
       (setf (node-runtime-state node-runtime) :starting
             (node-runtime-stop-requested node-runtime) nil
             (node-runtime-error node-runtime) nil
             (node-runtime-thread node-runtime)
             (bt:make-thread
              (lambda () (node-runtime-thread-main node-runtime))
              :name "gr8s node runtime"))))
    (loop while (eq :starting (node-runtime-state node-runtime))
          do (bt:condition-wait
              (node-runtime-state-changed node-runtime)
              (node-runtime-lock node-runtime)))
    (when (eq :failed (node-runtime-state node-runtime))
      (error (node-runtime-error node-runtime))))
  node-runtime)

(defun stop-node-runtime (node-runtime)
  "Request NODE-RUNTIME stop and wait for its thread to exit, returning NIL. Cancels all
in-flight node operations and stops the volume-reclaim queue (replacing it, since a
runtime may start again). Safe to call from the runtime's own thread, where it skips the
join."
  (let ((thread nil))
    (cancel-all-node-operations node-runtime "node runtime stopped")
    ;; A runtime can start again, and a stopped queue can't.
    (work-queue-stop (shiftf (node-runtime-reclaim-queue node-runtime) (make-volume-reclaim-queue)))
    (bt:with-lock-held ((node-runtime-lock node-runtime))
      (when (member (node-runtime-state node-runtime) '(:starting :running))
        (setf (node-runtime-stop-requested node-runtime) t)
        (bt:condition-notify (node-runtime-state-changed node-runtime)))
      (setf thread (node-runtime-thread node-runtime)))
    (when (and thread (not (eq thread (bt:current-thread))))
      (ignore-errors (bt:join-thread thread)))
    (bt:with-lock-held ((node-runtime-lock node-runtime))
      (unless (eq :failed (node-runtime-state node-runtime))
        (setf (node-runtime-state node-runtime) :stopped))))
  nil)

(defun put-assigned-pod (store pod)
  "Persist and index the assigned POD in STORE, returning it. Refuses (by erroring) to
overwrite a different UID still terminating under the same name, and to re-assign a UID
already marked deleting unless the incoming Pod is itself deleting; a later incoming
deletion deadline cannot postpone an earlier one. Holds the store lock."
  (with-store-lock (store)
    (let ((existing (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store))))
      (when (and existing (not (equal (pod-uid existing) (pod-uid pod))))
        ;; A force delete may free the API name before the old UID's runtime
        ;; cleanup finishes. Keep its durable record until removal completes;
        ;; retry this snapshot rather than overwrite the only recovery record.
        (error 'runtime-error :message "Previous Pod UID is still terminating; retry assignment"))
      (when (and existing (deletion-requested-p existing))
        (unless (deletion-requested-p pod)
          (error 'runtime-error :message "A deleted Pod UID cannot be assigned again"))
        (when (< (pod-deletion-deadline existing) (pod-deletion-deadline pod))
          (let ((old (gethash "metadata" (pod-to-object existing)))
                (new (gethash "metadata" (pod-to-object pod))))
            (setf (gethash "deletionTimestamp" new) (gethash "deletionTimestamp" old)
                  (gethash "deletionGracePeriodSeconds" new) (gethash "deletionGracePeriodSeconds" old))))))
    (persist-pod store pod)
    (index-pod store pod))
  pod)

(defun remove-unassigned-pods (node-runtime assignments
                               &key (on-failure (lambda (pod condition)
                                                  (declare (ignore pod))
                                                  (error condition))))
  "Withdraw each local Pod the server no longer assigns. ON-FAILURE takes the Pod and the condition."
  (let ((assigned-uids (make-hash-table :test #'equal)))
    (dolist (assignment assignments)
      (setf (gethash (slot-value assignment 'gr8s.node.v1::uid)
                     assigned-uids)
            t))
    (dolist (pod (list-pods (node-runtime-store node-runtime)))
      (unless (gethash (pod-uid pod) assigned-uids)
        (handler-case
            (progn
              ;; Serialize with the background reconciler and persist deletion intent
              ;; before CRI calls. A transient removal failure must never turn into
              ;; runtime-ensure recreating an assignment the server has withdrawn.
              (when (pod-finalizers-present-p pod)
                (let ((store (node-runtime-store node-runtime)))
                  (with-store-lock (store)
                    (let ((current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store))))
                      (when (and current (equal (pod-uid current) (pod-uid pod)))
                        (let ((copy (copy-core-object (pod-to-object current))))
                          (setf (gethash "finalizers" (gethash "metadata" copy)) #())
                          (update-pod-unlocked store (parse-pod copy) (pod-resource-version current))))))))
              (delete-reconciled-pod (node-runtime-reconciler node-runtime)
                                     (pod-namespace pod) (pod-name pod) :uid (pod-uid pod) :grace-period 0))
          (error (condition) (funcall on-failure pod condition)))))))

(defun withdrawal-durable-p (node-runtime pod)
  "True once POD's deletion can't be lost: its local record is gone or says it is deleting."
  (let* ((store (node-runtime-store node-runtime))
         (current (with-store-lock (store)
                    (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store)))))
    (or (null current)
        (not (equal (pod-uid current) (pod-uid pod)))
        (deletion-requested-p current))))

(defun parse-node-assignment (assignment)
  "Return ASSIGNMENT's Pod, or NIL after logging one this agent can't read. Its UID stays assigned."
  (handler-case (assignment-pod assignment)
    (error (condition)
      (format *error-output* "gr8s Pod ~A/~A assignment rejected: ~A~%"
              (slot-value assignment 'gr8s.node.v1::namespace)
              (slot-value assignment 'gr8s.node.v1::name) condition)
      nil)))

(defun pod-observed-status-message (pod status &optional events runtime-deleted)
  "Encode real observations, private Event transport and independent physical cleanup acknowledgement."
  (let ((wire-status (copy-core-object status)))
    (when events (setf (gethash "gr8sRuntimeEvents" wire-status) events))
    (make-instance
     'gr8s.node.v1::pod-observed-status
     :namespace (pod-namespace pod) :name (pod-name pod) :uid (pod-uid pod)
     :resource-version (pod-resource-version pod)
     :phase (gethash "phase" status "Unknown") :reason (gethash "reason" status "")
     :message (gethash "message" status "") :pod-ip (gethash "podIP" status "")
     :status-json (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify wire-status))
     :runtime-deleted runtime-deleted)))

(defun node-runtime-service-translation-record
    (node-runtime pod status &key (sandbox-id nil sandbox-id-p))
  "Report a lease only for this Pod's actual current sandbox and observed IPv4."
  (let ((ipam (node-runtime-ipam node-runtime))
        (runtime (node-runtime-runtime node-runtime)))
    (when (or (null ipam) (pod-host-network-p pod))
      (return-from node-runtime-service-translation-record nil))
    ;; No CRI operation for ordinary endpoints without private leases.
    (unless (bt:with-lock-held ((node-ipam-lock ipam))
              (plusp (hash-table-count (gr8s.network::node-ipam-service-snat-allocations ipam))))
      (return-from node-runtime-service-translation-record nil))
    (unless sandbox-id-p
      (unless (typep runtime 'containerd-runtime)
        (return-from node-runtime-service-translation-record nil))
      (let ((sandbox (containerd-owned-sandbox runtime (pod-uid pod))))
        (setf sandbox-id (and sandbox (cri-pod-sandbox-info-id sandbox)))))
    (when sandbox-id
      (bt:with-lock-held ((node-ipam-lock ipam))
        (loop for key being the hash-keys of (gr8s.network::node-ipam-service-snat-allocations ipam)
                using (hash-value alias)
              for addresses = (gethash key (node-ipam-allocations ipam))
              for original = (find-if (lambda (value) (not (find #\: value))) addresses)
              for primary = (and original (gr8s.network::node-ipam-address-identity original))
              when (and (equal sandbox-id (car key)) primary
                        (member primary (mapcar #'gr8s.network::service-translation-address-key
                                                (gr8s.network::service-translation-status-addresses status))
                                :test #'equal))
                return (let ((record
                               (json-object "address" alias "podIP" primary
                                            "sandboxID" sandbox-id "interfaceName" (cdr key)
                                            "podUID" (pod-uid pod)
                                            "nodeID" (node-runtime-node-id node-runtime)
                                            "nodeName" (node-runtime-node-name node-runtime)))
                             (generation (gethash key (gr8s.network::node-ipam-incarnations ipam))))
                         (when generation
                           (setf (gethash "incarnationGeneration" record) generation))
                         record))))))

(defun cache-node-observation (node-runtime pod status)
  "Persist actual status and transport Events without confusing runtime deletion with public phase."
  (setf status (copy-core-object status))
  (remhash "gr8sServiceTranslation" status)
  (let ((translation (node-runtime-service-translation-record node-runtime pod status)))
    (when translation (setf (gethash "gr8sServiceTranslation" status) translation)))
  (let* ((store (node-runtime-store node-runtime))
         (before (pod-observed-status store pod))
         (address (gethash "podIP" status)))
    (save-pod-observation store pod status)
    ;; A Pod's policy can only be written once it has an address. Policies that
    ;; select it may not change when it gets one, so no snapshot would follow.
    (when (and (stringp address) (plusp (length address))
               (not (equal address (and (hash-table-p before) (gethash "podIP" before)))))
      (handler-case (converge-node-network-policies node-runtime)
        (error (condition)
          (format *error-output* "gr8s: NetworkPolicy convergence failed: ~A~%" condition)))))
  (let* ((finalization (pod-finalization-state (node-runtime-store node-runtime) pod))
         (message (pod-observed-status-message
                   pod status (runtime-events (node-runtime-runtime node-runtime) (pod-uid pod))
                   (and finalization (gethash "runtimeDeleted" finalization)))))
    (bt:with-lock-held ((node-runtime-observed-lock node-runtime))
      (setf (gethash (pod-uid pod) (node-runtime-observed-statuses node-runtime)) message))
    message))

(defun endpoint-telemetry-message (sandbox interface address counters error)
  "Build an ENDPOINT-TELEMETRY message for one Pod endpoint from its eBPF COUNTERS (any
absent field defaults to 0) and an ERROR string (\"\" on success)."
  (make-instance
   'gr8s.node.v1::endpoint-telemetry
   :sandbox-id sandbox :interface-name interface :pod-ip address
   :allowed-packets (gethash "allowedPackets" counters 0)
   :allowed-bytes (gethash "allowedBytes" counters 0)
   :dropped-packets (gethash "droppedPackets" counters 0)
   :dropped-bytes (gethash "droppedBytes" counters 0)
   :rejected-spoofs (gethash "rejectedSpoofs" counters 0)
   :malformed-packets (gethash "malformedPackets" counters 0)
   :unsupported-packets (gethash "unsupportedPackets" counters 0)
   :error-message error))

(defun node-runtime-endpoint-telemetry (node-runtime counter-reader)
  "Collect per-endpoint firewall telemetry for every local Pod allocation, reading each
one's counters through COUNTER-READER; an endpoint whose counters can't be read yields a
message carrying that error instead of counts. NIL on an unmanaged agent or before IPAM
exists."
  (let ((manager (node-runtime-manager node-runtime))
        (ipam (node-runtime-ipam node-runtime)))
    (when (and manager ipam)
      (let ((allocations
              (bt:with-lock-held ((node-ipam-lock ipam))
                (loop for key being the hash-keys of (node-ipam-allocations ipam)
                        using (hash-value addresses)
                      collect (list (car key) (cdr key) (first addresses)))))
            (root (managed-containerd-bpf-directory manager)))
        (loop for (sandbox interface address) in allocations
              collect (handler-case
                          (endpoint-telemetry-message sandbox interface address
                                                      (funcall counter-reader root sandbox) "")
                        (error (condition)
                          (endpoint-telemetry-message
                           sandbox interface address (make-hash-table :test #'equal)
                           (princ-to-string condition)))))))))

(defun pod-certificate-claim-message (claim)
  "Encode one podCertificate claim plist as its node-protocol message (KEP-4317)."
  (make-instance
   'gr8s.node.v1::pod-certificate-claim
   :name (getf claim :name) :namespace (getf claim :namespace)
   :signer-name (or (getf claim :signer-name) "")
   :pkix-public-key (or (getf claim :pkix-public-key) "")
   :stub-pkcs10-request (or (getf claim :stub-pkcs10-request) "")
   :pod-name (getf claim :pod-name) :pod-uid (getf claim :pod-uid)
   :service-account-name (or (getf claim :service-account-name) "")
   :service-account-uid (or (getf claim :service-account-uid) "")
   :max-expiration-seconds (or (getf claim :max-expiration-seconds) 0)))

(defun wireguard-peer-observation-messages
    (statuses &key network path-state
                    (now (- (get-universal-time) 2208988800)) (fresh-seconds 180))
  "Encode fresh kernel-observed WireGuard sessions as NAT rendezvous evidence."
  (loop for status in statuses
        for handshake = (wireguard-peer-status-latest-handshake-seconds status)
        when (and (= 32 (length (wireguard-peer-status-public-key status)))
                  (not (string= "" (wireguard-peer-status-endpoint-address status)))
                  (<= 1 (wireguard-peer-status-endpoint-port status) 65535)
                  (plusp (wireguard-peer-status-received-bytes status))
                  (<= 0 (- now handshake) fresh-seconds))
          collect
          (let* ((route
                   (and network
                        (find (wireguard-peer-status-public-key status)
                              (coerce (gethash "routes" network #()) 'list)
                              :test #'equalp
                              :key (lambda (candidate)
                                     (ignore-errors
                                       (ag-grpc:base64-decode
                                        (gethash "wireguardPublicKey" candidate "")))))))
                 (peer (and route path-state
                            (gethash (gethash "nodeID" route)
                                     (wireguard-path-state-peers path-state))))
                 (observation
                   (and peer (wireguard-peer-path-state-selected peer)
                        (wireguard-observation-for-endpoint
                         peer (wireguard-peer-path-state-selected peer)))))
            (make-instance
             'gr8s.node.v1::wireguard-peer-observation
             :peer-public-key (wireguard-peer-status-public-key status)
             :address (wireguard-peer-status-endpoint-address status)
             :port (wireguard-peer-status-endpoint-port status)
             :latest-handshake-unix-seconds handshake
             :received-bytes (wireguard-peer-status-received-bytes status)
             :path-score (if observation
                             (steering-bounded-integer
                              (wireguard-path-score observation) 10000 10000)
                             10000)
             :healthy (and observation (wireguard-path-healthy-p observation))
             :active-flows (if observation
                               (steering-bounded-integer
                                (wireguard-path-observation-passive-active-flows
                                 observation)
                                1000)
                               0)))))

(defun node-runtime-service-receiver-report
    (node-runtime &key (lookup #'whistler/loader:map-lookup))
  "Report only current local v2 receivers proven by both pinned owner rows.
The revision is zero when risk inventory or owner readback is unavailable."
  (handler-case
      (let* ((revision (node-runtime-received-revision node-runtime))
             (network (node-runtime-network node-runtime))
             (dataplane (node-runtime-service-lb node-runtime))
             (owners (and dataplane (service-lb-map dataplane "gr8s_nat_id_v2"))))
        (unless (and network owners (node-runtime-local-risk-ready-p node-runtime))
          (return-from node-runtime-service-receiver-report (values nil 0)))
        (let ((receivers
                (loop for record in
                      (gr8s.network::service-nat-ready-local-receivers
                       owners (gethash "serviceTranslations" network #())
                       (node-runtime-node-id node-runtime) :lookup lookup)
                      for rows = (gr8s.network::service-nat-identity-rows record)
                      collect (make-instance 'gr8s.node.v1::service-receiver-proof
                                             :pod-uid (gethash "podUID" record)
                                             :incarnation (subseq (cdar rows) 8 24)))))
          (if (and (= revision (node-runtime-received-revision node-runtime))
                   (node-runtime-local-risk-ready-p node-runtime))
              (values receivers revision)
              (values nil 0))))
    (error () (values nil 0))))

(defun node-runtime-status (node-runtime &key (counter-reader #'read-cni-policy-counters))
  "Build the node's NODE-STATUS heartbeat: observation timestamp, pending podCertificate
claims, registered CSI drivers (rescanned here, on this thread, so a slow driver can't
delay the heartbeat), the observed status of each assigned Pod, and endpoint telemetry.
Prunes cache entries for UIDs no longer assigned, never reports a status for an older
resource version than the one assigned, and retains a final \"Deleted\" acknowledgement
while the server still assigns that UID at that version."
  (let ((pods (list-pods (node-runtime-store node-runtime)))
        (receiver-report (multiple-value-list
                          (node-runtime-service-receiver-report node-runtime))))
    (make-instance
     'gr8s.node.v1::node-status
     :service-receivers (first receiver-report)
     :service-receiver-revision (second receiver-report)
     :service-receiver-report-present t
     :observed-at-unix-nanos (* (- (get-universal-time) 2208988800) 1000000000)
     :resource-capacity (gr8s.kubelet::node-resource-capacity-entries (node-runtime-resource-manager node-runtime))
     :resource-allocatable (gr8s.kubelet::node-resource-capacity-entries (node-runtime-resource-manager node-runtime) :allocatable t)
     :device-plugin-resources
     (gr8s.kubelet::device-plugin-resource-entries (node-runtime-device-plugin-manager node-runtime))
     :pod-certificate-requests
     (mapcar #'pod-certificate-claim-message
             (node-pending-pod-certificate-claims (node-runtime-store node-runtime)))
     :csi-drivers
     (when (containerd-runtime-p (node-runtime-runtime node-runtime))
       ;; Reporting runs on its own thread, so a slow driver can't delay heartbeats.
       (handler-case (scan-csi-plugin-registry)
         (error (condition) (format *error-output* "gr8s CSI registry scan failed: ~A~%" condition)))
       (csi-driver-registrations))
     :wireguard-peer-observations
     (handler-case
         (wireguard-peer-observation-messages
          (read-wireguard-peer-statuses)
          :network (node-runtime-network node-runtime)
          :path-state (node-runtime-wireguard-path-state node-runtime))
       (error () nil))
     :pods
     (bt:with-lock-held ((node-runtime-observed-lock node-runtime))
       ;; Prune deleted UIDs and never publish a cache entry for an older Pod
       ;; resource version while its replacement is still reconciling.
       (let ((uids (union (mapcar #'pod-uid pods)
                          (loop for uid being the hash-keys of (node-runtime-assigned-versions node-runtime)
                                collect uid) :test #'equal)))
         (maphash (lambda (uid message)
                    (declare (ignore message))
                    (unless (member uid uids :test #'string=)
                      (remhash uid (node-runtime-observed-statuses node-runtime))))
                  (node-runtime-observed-statuses node-runtime)))
       (append
        (loop for pod in pods
             for message = (gethash (pod-uid pod) (node-runtime-observed-statuses node-runtime))
             when (and message
                       (string= (pod-resource-version pod)
                                (slot-value message 'gr8s.node.v1::resource-version)))
               collect message)
        ;; Local desired state disappears after runtime removal. Retain the
        ;; final acknowledgement while the server still assigns this UID/RV.
        (loop for uid being the hash-keys of (node-runtime-assigned-versions node-runtime)
                using (hash-value version)
              for message = (gethash uid (node-runtime-observed-statuses node-runtime))
              when (and message (not (find uid pods :key #'pod-uid :test #'equal))
                        (equal "Deleted" (slot-value message 'gr8s.node.v1::reason))
                        (equal version (slot-value message 'gr8s.node.v1::resource-version)))
                collect message)))
     :endpoints (node-runtime-endpoint-telemetry node-runtime counter-reader))))

(defun node-runtime-wireguard-key-path (node-runtime)
  "Return the node-local WireGuard private-key path outside runtime state."
  (merge-pathnames
   "wireguard.key"
   (uiop:pathname-parent-directory-pathname
    (node-runtime-state-directory node-runtime))))

(defun node-runtime-wireguard-metrics-text (node-runtime)
  "Read and render this runtime's selected WireGuard overlay telemetry."
  (let ((network (bt:with-lock-held ((node-runtime-network-lock node-runtime))
                   (node-runtime-network node-runtime)))
        (key-path (node-runtime-wireguard-key-path node-runtime)))
    (concatenate
     'string
     (wireguard-metrics-text
      network (or (node-runtime-node-name node-runtime) "")
      :key-age-reader
      (lambda ()
        (let ((written (and (probe-file key-path) (file-write-date key-path))))
          (and written (max 0 (- (get-universal-time) written))))))
     (wireguard-path-metrics-text
      (node-runtime-wireguard-path-state node-runtime)
      (or (node-runtime-node-name node-runtime) "")))))

(defun receive-node-snapshot-intent (node-runtime snapshot)
  "Persist exact urgent deletion intent before cancelling creation or waiting for runtime I/O."
  ;; Parse every assignment before changing any local intent. One that can't
  ;; be read stays assigned, so its running Pod isn't mistaken for a withdrawn one.
  (let* ((assignments (slot-value snapshot 'gr8s.node.v1::pods))
         (pods (remove nil (mapcar #'parse-node-assignment assignments)))
         (revision (slot-value snapshot 'gr8s.node.v1::revision))
         (urgent nil))
    (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
      (when (< revision (node-runtime-received-revision node-runtime))
        (return-from receive-node-snapshot-intent nil))
      (dolist (existing (list-pods (node-runtime-store node-runtime)))
        (let ((assigned (find (pod-uid existing) pods :key #'pod-uid :test #'equal)))
          (when (if assigned
                    (deletion-requested-p assigned)
                    (not (find (pod-uid existing) assignments
                               :key (lambda (assignment) (slot-value assignment 'gr8s.node.v1::uid))
                               :test #'equal)))
            (handler-case
                (let ((projected
                        (if assigned
                            ;; Preserve the server's RV, timestamp and grace.
                            ;; Existing earlier deadlines cannot be extended.
                            (put-assigned-pod (node-runtime-store node-runtime) assigned)
                            (mark-pod-deleting (node-runtime-store node-runtime)
                                               (pod-namespace existing) (pod-name existing)
                                               :uid (pod-uid existing) :grace-period 0))))
                  (when (pod-runtime-cleanup-pending-p (node-runtime-store node-runtime) projected)
                    (pushnew (pod-uid projected) urgent :test #'equal)))
              (kubernetes-error (condition)
                ;; An independently completed deletion or replacement is not
                ;; authority to cancel the new UID that now owns this name.
                (unless (member (kubernetes-error-status-code condition) '(404 409))
                  (error condition)))))))
      ;; A failed persist never publishes the revision or cancels CRI. A retry
      ;; may repeat already durable deletion intent, but cannot undo it.
      (setf (node-runtime-received-revision node-runtime) revision))
    (when urgent
      (prioritize-reconciler-deletions (node-runtime-reconciler node-runtime) urgent))
    (not (null urgent))))

(defun ensure-node-snapshot-current (node-runtime snapshot)
  "Fence obsolete application before it can create another Pod or acknowledge a revision."
  (when (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
          (< (slot-value snapshot 'gr8s.node.v1::revision)
             (node-runtime-received-revision node-runtime)))
    (error 'pod-reconciliation-superseded)))

(defvar *node-network-policy-lock* (bt:make-lock "gr8s node network policy")
  "Serializes writes of Pods' policies from snapshots and from new Pod addresses.")

(defun converge-node-network-policies (node-runtime)
  "Write each local Pod's resolved NetworkPolicy into its pinned maps (data only; its
guards enforce it, no recompile or re-attach). Runs for every snapshot, so removing the
last policy opens a Pod again, and when a Pod gets its address. Fail-soft: never aborts
snapshot application."
  (bt:with-lock-held (*node-network-policy-lock*)
    (converge-node-network-policies-unlocked node-runtime)))

(defun converge-node-network-policies-unlocked
    (node-runtime &key (policy-converger #'converge-pod-network-policies))
  "Write every local Pod's dataplane into its pinned maps, with the caller holding
*node-network-policy-lock*: the same-node Pod->Pod delivery table and the Pod->host
redirect table (each populated first and independently, since the NetworkPolicy
resolution below can throw on an unsupported policy), then the resolved NetworkPolicy in
both directions. Native mode reloads IPAM first to pick up allocations the
out-of-process CNI plugin added. External mode uses the durable endpoint registry
written after chained CNI ADD and deliberately skips native-veth delivery maps.
A no-op unless the agent is managed with a store and known endpoints."
  (let ((manager (node-runtime-manager node-runtime))
        (ipam (node-runtime-ipam node-runtime))
        (store (node-runtime-store node-runtime)))
    (when (and manager store)
      ;; The out-of-process CNI plugin persists every allocation to the ipam file;
      ;; reload it so the dataplane tables below cover Pods added since the agent's
      ;; ipam was opened, not only those present at startup (podster-6yd).
      (when ipam (ignore-errors (reload-node-ipam-allocations ipam)))
      (let* ((root (managed-containerd-bpf-directory manager))
             (native-p (string= "native" (managed-containerd-cni-mode manager)))
             (endpoints
               (if native-p
                   (when ipam
                     (bt:with-lock-held ((node-ipam-lock ipam))
                       (loop for key being the hash-keys of (node-ipam-allocations ipam)
                               using (hash-value addresses)
                             collect (list (car key) (cdr key) (first addresses)))))
                   (node-runtime-external-cni-endpoint-list node-runtime))))
        ;; Same-node Pod->Pod delivery table (epic podster-pnd): every local Pod
        ;; gets the node-wide {dest IP -> ifindex/MAC} table so the egress guard
        ;; can redirect in-cluster traffic past the host firewall's FORWARD reject.
        ;; Populate it FIRST and independently: resolving an unsupported
        ;; NetworkPolicy (below) can throw, and keeping that resolution out of this
        ;; let's bindings is what lets the delivery table still be written.
        (when native-p
          (converge-node-local-pod-delivery
           endpoints
           :directory-fn (lambda (sandbox)
                           (nth-value 2 (cni-pin-paths root sandbox)))))
        ;; Pod->host delivery table (podster-9b1): every local Pod gets the node's
        ;; host-local destinations (the API server 10.96.0.1, this node's own IP)
        ;; so the egress guard redirects that traffic to lo, past the host
        ;; firewall's INPUT reject. Independent and fail-soft, like the table above.
        (when native-p
          (converge-node-host-redirect
           (mapcar #'first endpoints)
           (ignore-errors (containerd-node-address (node-runtime-runtime node-runtime)))
           :directory-fn (lambda (sandbox)
                           (nth-value 2 (cni-pin-paths root sandbox)))))
        ;; NetworkPolicy, both directions (origin/main). Spec resolution can throw
        ;; on an unsupported policy, so it stays after the delivery tables above,
        ;; which must populate regardless.
        (let ((specs (network-policy-specs-from-objects
                      (list-core-resources store "networkpolicies")))
              (ip-map (gr8s.network::pod-ip-identity-map store)))
          (funcall policy-converger
                   specs endpoints
                   :pod-finder (lambda (address) (gethash address ip-map))
                   :directory-fn (lambda (sandbox)
                                   (nth-value 2 (cni-pin-paths root sandbox)))))))))

(defvar *runtime-outage-snapshot-wait-seconds* 2
  "How long a snapshot waits for a restarting container runtime before giving up this attempt.")

(defun reconcile-node-snapshot (node-runtime snapshot)
  "Apply one control-plane SNAPSHOT to this node and return the assigned Pods' observed
statuses. Errors unless the runtime is running, and waits briefly for a restarting
container runtime -- leaving the revision unacknowledged (NODE-SNAPSHOT-INCOMPLETE) rather
than act against a down runtime. Under the apply lock, and re-checking the snapshot is
still current at each step, it applies the assigned network, records the assigned
versions, withdraws Pods the server no longer assigns, installs the assigned resource
objects, converges the Service LB, node ports, health checks, NetworkPolicy and Gateway
listeners (all fail-soft), then creates or updates each assigned Pod and caches its
observation. Signals NODE-SNAPSHOT-INCOMPLETE when any Pod could not be applied or parsed,
so the revision is retried."
  (unless (eq :running (node-runtime-state node-runtime))
    (error 'runtime-error :message "node runtime is not running"))
  ;; Don't start, stop or fail Pods against a runtime that is restarting. Wait a
  ;; little for it, then leave the revision unacknowledged so it is retried.
  (let ((runtime (node-runtime-runtime node-runtime)))
    (when (runtime-unavailable-message runtime)
      (let ((availability (and (containerd-runtime-p runtime) (containerd-runtime-availability runtime))))
        (unless (and availability
                     (wait-for-runtime-available availability *runtime-outage-snapshot-wait-seconds*)
                     (not (runtime-unavailable-message runtime)))
          (error 'node-snapshot-incomplete
                 :message (format nil "skipping Pod synchronization: ~A"
                                  (or (runtime-unavailable-message runtime) "container runtime is down")))))))
  (bt:with-lock-held ((node-runtime-apply-lock node-runtime))
    (ensure-node-snapshot-current node-runtime snapshot)
    (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
      (setf (node-runtime-service-risk-ready-revision node-runtime) nil
            (node-runtime-service-selection-ready-revision node-runtime) nil))
    (apply-node-runtime-network node-runtime snapshot)
    (publish-node-snapshot-service-receivers node-runtime snapshot)
    (ensure-node-snapshot-service-receivers-ready node-runtime snapshot)
    (let ((assignments (slot-value snapshot 'gr8s.node.v1::pods))
          (failed nil))
      (bt:with-lock-held ((node-runtime-observed-lock node-runtime))
        (clrhash (node-runtime-assigned-versions node-runtime))
        (dolist (assignment assignments)
          (setf (gethash (slot-value assignment 'gr8s.node.v1::uid)
                         (node-runtime-assigned-versions node-runtime))
                (slot-value assignment 'gr8s.node.v1::resource-version))))
      (remove-unassigned-pods
       node-runtime assignments
       :on-failure
       (lambda (pod condition)
         ;; Deletion intent is durable, so the reconciliation worker keeps retrying
         ;; this Pod. Only a lost intent has to hold back the acknowledgement.
         (unless (and (typep condition 'kubernetes-error)
                      (member (kubernetes-error-status-code condition) '(404 409)))
           (format *error-output* "gr8s Pod ~A/~A removal failed: ~A~%"
                   (pod-namespace pod) (pod-name pod) condition))
         (unless (withdrawal-durable-p node-runtime pod)
           (push pod failed))))
      (install-assigned-resource-objects
       (node-runtime-store node-runtime) assignments
       (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json))
      ;; Converge the socket LB from the just-installed Service/EndpointSlice
      ;; discovery data. A transient map error must not abort Pod reconciliation;
      ;; the v2 snapshot acknowledgement is withheld below until risk readback.
      (when (node-runtime-service-lb-controller node-runtime)
        (handler-case
            (let* ((controller (node-runtime-service-lb-controller node-runtime))
                   (risk-map (service-lb-map (node-runtime-service-lb node-runtime)
                                             "gr8s_nat_risk_v2"))
                   (grant-mode (node-snapshot-service-grant-mode node-runtime snapshot)))
              (converge-node-runtime-service-lb
               node-runtime :publish-services-p
               (cond ((null risk-map) t)
                     ((and grant-mode
                           (node-runtime-service-selection-grant-digest node-runtime))
                      :retain)
                     (t nil)))
              (when (gr8s.controllers:service-lb-risk-published-p controller)
                (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
                  (when (= (node-runtime-received-revision node-runtime)
                           (slot-value snapshot 'gr8s.node.v1::revision))
                    (setf (node-runtime-service-risk-ready-revision node-runtime)
                          (slot-value snapshot 'gr8s.node.v1::revision)))))
              (when (and (eq grant-mode :current)
                         (node-runtime-local-risk-ready-p node-runtime))
                (converge-node-runtime-service-lb node-runtime :publish-services-p t)
                (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
                  (when (= (node-runtime-received-revision node-runtime)
                           (slot-value snapshot 'gr8s.node.v1::revision))
                    (setf (node-runtime-service-selection-ready-revision node-runtime)
                          (slot-value snapshot 'gr8s.node.v1::revision)
                          (node-runtime-service-selection-grant-digest node-runtime)
                          (copy-seq (slot-value snapshot
                                                'gr8s.node.v1::service-risk-grant-digest)))))))
          (error (condition)
            (format *error-output* "gr8s: Service LB convergence failed: ~A~%" condition))))
      (handler-case
          (progn
            (converge-node-port-forwarders (node-runtime-node-port-forwarders node-runtime)
                                           (node-runtime-store node-runtime)
                                           :node-name (node-runtime-node-name node-runtime)
                                           :node-address
                                           (ignore-errors (containerd-node-address
                                                           (node-runtime-runtime node-runtime))))
            (converge-health-check-servers (node-runtime-health-check-servers node-runtime)
                                           (node-runtime-store node-runtime)
                                           :node-name (node-runtime-node-name node-runtime)))
        (error (condition)
          (format *error-output* "gr8s: node port convergence failed: ~A~%" condition)))
      ;; Attach per-Pod NetworkPolicy classifiers from the just-installed policy
      ;; objects. Fail-soft, like the Service LB above.
      (when (node-runtime-manager node-runtime)
        (handler-case
            (converge-node-network-policies node-runtime)
          (error (condition)
            (format *error-output* "gr8s: NetworkPolicy convergence failed: ~A~%" condition))))
      ;; Reconcile Gateway API L7 proxy listeners from the stored Gateway and
      ;; HTTPRoute objects. Created lazily; fail-soft like the convergences above.
      (handler-case
          (progn
            (unless (node-runtime-gateway-controller node-runtime)
              (setf (node-runtime-gateway-controller node-runtime)
                    (let ((steering (node-runtime-gateway-steering node-runtime)))
                      (make-gateway-controller
                       (node-runtime-store node-runtime)
                       :cert-dir (merge-pathnames "gateway-certs/"
                                                  (node-runtime-state-directory node-runtime))
                       :register-fn
                       (lambda (port listener)
                         (when steering
                           (gateway-steering-register
                            steering port (gateway-listener-socket-fd listener)))
                         (ensure-gateway-listener-firewall port))
                       :unregister-fn
                       (lambda (port)
                         (remove-gateway-listener-firewall port)
                         (when steering (gateway-steering-unregister steering port)))))))
            (converge-gateway-listeners (node-runtime-gateway-controller node-runtime))
            (converge-gateway-l4-listeners (node-runtime-gateway-controller node-runtime)))
        (error (condition)
          (format *error-output* "gr8s: Gateway convergence failed: ~A~%" condition)))
      (let* ((parsed (mapcar #'parse-node-assignment assignments))
             (statuses
               (loop for pod in (stable-sort (remove nil parsed)
                                             (lambda (left right)
                                               (and (deletion-requested-p left)
                                                    (not (deletion-requested-p right)))))
                     for status = (handler-case
                                      (progn
                                        (ensure-node-snapshot-current node-runtime snapshot)
                                        (put-assigned-pod (node-runtime-store node-runtime) pod)
                                        (ensure-node-snapshot-current node-runtime snapshot)
                                        (let* ((started (get-internal-real-time))
                                               (status (reconcile-pod (node-runtime-reconciler node-runtime)
                                                                      (pod-namespace pod) (pod-name pod))))
                                          ;; As the kubelet's pod workers and start latency measure them.
                                          (ignore-errors
                                           (note-pod-sync (pod-uid pod) (pod-resource-version pod) (deletion-requested-p pod)
                                                          (/ (- (get-internal-real-time) started) internal-time-units-per-second))
                                           (note-pod-phase (pod-uid pod) (gethash "phase" status)))
                                          (cache-node-observation node-runtime pod status)))
                                    ;; The next Pod still has to run. Cancellation and
                                    ;; supersession aren't errors, so they still unwind this.
                                    (error (condition)
                                      (format *error-output* "gr8s Pod ~A/~A assignment failed: ~A~%"
                                              (pod-namespace pod) (pod-name pod) condition)
                                      (push pod failed)
                                      nil))
                     when status collect status)))
        (ensure-node-snapshot-current node-runtime snapshot)
        (bt:with-lock-held ((node-runtime-observed-lock node-runtime))
          (forget-unassigned-pod-records (node-runtime-assigned-versions node-runtime)))
        (when (or failed (member nil parsed))
          (error 'node-snapshot-incomplete
                 :message (format nil "~D Pod assignment~:P not applied"
                                  (+ (length failed) (count nil parsed)))))
        (ensure-node-snapshot-service-risk-ready node-runtime)
        (ensure-node-snapshot-service-receivers-ready node-runtime snapshot)
        (ensure-node-snapshot-service-selection-ready node-runtime snapshot)
        statuses))))

(defun node-operation-response (request status &key (exit-code 0) (message ""))
  "Build an OPERATION-RESPONSE for REQUEST carrying STATUS, exit code and message."
  (make-instance
   'gr8s.node.v1::operation-response
   :operation-id (slot-value request 'gr8s.node.v1::operation-id)
   :status status
   :exit-code exit-code
   :error-message message))

(defun node-operation-stream (request channel data &key (sequence 1) (eof t))
  "Build an OPERATION-STREAM frame for REQUEST carrying DATA on CHANNEL, with the given
sequence number and EOF flag."
  (make-instance
   'gr8s.node.v1::operation-stream
   :operation-id (slot-value request 'gr8s.node.v1::operation-id)
   :sequence sequence
   :channel channel
   :data data
   :eof eof))

(defun assigned-operation-pod (node-runtime request)
  "Return the Pod that REQUEST targets, erroring (\"not assigned to this agent\") when the
stored Pod's UID does not match the request's."
  (let* ((namespace (slot-value request 'gr8s.node.v1::namespace))
         (name (slot-value request 'gr8s.node.v1::pod))
         (uid (slot-value request 'gr8s.node.v1::pod-uid))
         (pod (get-pod (node-runtime-store node-runtime) namespace name)))
    (unless (string= uid (pod-uid pod))
      (error 'runtime-error
             :message (format nil "Pod ~A/~A is not assigned to this agent"
                              namespace name)))
    pod))

(defun wireguard-network-explanation (node-runtime destination-peer-id)
  "Explain DESTINATION-PEER-ID through its effective direct or sparse peer."
  (let* ((network (node-runtime-network node-runtime))
         (route
           (and network
                (find destination-peer-id (gethash "routes" network #())
                      :test #'string=
                      :key (lambda (candidate)
                             (gethash "nodeID" candidate)))))
         (hop (and route (gethash "nextHop" route)))
         (effective-peer-id
           (if hop (required-cni-string hop "nodeID") destination-peer-id))
         (object
           (wireguard-path-explanation-object
            (node-runtime-wireguard-path-state node-runtime) effective-peer-id)))
    (setf (gethash "destinationPeerID" object) destination-peer-id
          (gethash "nextHopPeerID" object) effective-peer-id
          (gethash "topologyReason" object)
          (if hop "sparse-next-hop" "direct-peer"))
    (when route
      (setf (gethash "destinationPodCIDR" object) (gethash "podCIDR" route)))
    object))

(defun handle-node-operation (node-runtime request)
  "Carry out a synchronous node operation for REQUEST -- container logs, or a one-shot
exec -- and return the list of (tag . message) replies to emit (a stdout/stderr stream
plus a completion response). Verifies the Pod is assigned first; any error, including an
unsupported kind, becomes a single failed response."
  (handler-case
      (let ((kind (slot-value request 'gr8s.node.v1::kind)))
        (unless (= kind gr8s.node.v1::+operationkind-operation_kind_network_explain+)
          (assigned-operation-pod node-runtime request))
        (case kind
          (#.gr8s.node.v1::+operationkind-operation_kind_network_explain+
           (let ((json
                   (com.inuoe.jzon:stringify
                    (wireguard-network-explanation
                     node-runtime
                     (slot-value request 'gr8s.node.v1::peer-id)))))
             (list
              (cons :operation-stream
                    (node-operation-stream
                     request gr8s.node.v1::+streamchannel-stream_channel_stdout+
                     (trivial-utf-8:string-to-utf-8-bytes json)))
              (cons :operation-response
                    (node-operation-response
                     request gr8s.node.v1::+operationstatus-operation_status_complete+)))))
          (#.gr8s.node.v1::+operationkind-operation_kind_logs+
           (let ((logs
                   (runtime-logs
                    (node-runtime-runtime node-runtime)
                    (slot-value request 'gr8s.node.v1::pod-uid)
                    (slot-value request 'gr8s.node.v1::container)
                    :previous (slot-value request 'gr8s.node.v1::previous))))
             (list
              (cons
               :operation-stream
               (node-operation-stream
                request
                gr8s.node.v1::+streamchannel-stream_channel_stdout+
                (trivial-utf-8:string-to-utf-8-bytes logs)))
              (cons
               :operation-response
               (node-operation-response
                request
                gr8s.node.v1::+operationstatus-operation_status_complete+)))))
          (#.gr8s.node.v1::+operationkind-operation_kind_exec+
           (let* ((result
                    (runtime-exec-sync
                     (node-runtime-runtime node-runtime)
                     (slot-value request 'gr8s.node.v1::pod-uid)
                     (slot-value request 'gr8s.node.v1::container)
                     (slot-value request 'gr8s.node.v1::command)))
                  (messages nil)
                  (sequence 0))
             (flet ((emit (enabled channel data)
                      (when (and enabled (plusp (length data)))
                        (push
                         (cons :operation-stream
                               (node-operation-stream
                                request channel data
                                :sequence (incf sequence)))
                         messages))))
               (emit (slot-value request 'gr8s.node.v1::stdout)
                     gr8s.node.v1::+streamchannel-stream_channel_stdout+
                     (runtime-exec-result-stdout result))
               (emit (slot-value request 'gr8s.node.v1::stderr)
                     gr8s.node.v1::+streamchannel-stream_channel_stderr+
                     (runtime-exec-result-stderr result)))
             (nreverse
              (push
               (cons
                :operation-response
                (node-operation-response
                 request
                 gr8s.node.v1::+operationstatus-operation_status_complete+
                 :exit-code (runtime-exec-result-exit-code result)))
               messages))))
          (otherwise
           (error 'runtime-error :message "Unsupported node operation"))))
    (error (condition)
      (list
       (cons
        :operation-response
        (node-operation-response
         request gr8s.node.v1::+operationstatus-operation_status_failed+
         :exit-code 1 :message (princ-to-string condition)))))))

(defstruct (node-exec-operation
             (:constructor make-node-exec-operation
                 (node-runtime request socket session emit)))
  node-runtime
  request
  socket
  ;; The SPDY connection to the runtime's streaming server.
  session
  emit
  thread
  ;; An alist of channel keyword to the stream carrying it.
  streams
  ;; What the error stream has said so far, read as one status at its end.
  (status-octets (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  (sequence 0)
  (last-input-sequence 0)
  (exit-code 0)
  (finished-p nil)
  (trace-p nil)
  (cancel-requested-p nil)
  cancellation-error
  (output-bytes 0)
  (max-output-bytes most-positive-fixnum)
  ;; Output sent to a control plane that acknowledges it, and not yet acknowledged.
  (unacknowledged-output 0)
  (lock (bt:make-lock "gr8s interactive exec operation"))
  (output-window (bt:make-condition-variable :name "gr8s exec output window")))

(defgeneric cleanup-node-operation (operation)
  (:documentation "Release operation-kind-specific resources after its socket closes."))

(defmethod cleanup-node-operation ((operation node-exec-operation))
  (values))

(defun find-node-exec-operation (node-runtime operation-id)
  "Return the live node operation registered under OPERATION-ID, or NIL. Holds the
operations lock."
  (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
    (gethash operation-id (node-runtime-operations node-runtime))))

(defun remember-node-exec-operation (node-runtime operation)
  "Register OPERATION under its operation id, erroring when one by that id already exists.
Holds the operations lock."
  (let ((operation-id
          (slot-value (node-exec-operation-request operation)
                      'gr8s.node.v1::operation-id)))
    (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
      (when (gethash operation-id (node-runtime-operations node-runtime))
        (error 'runtime-error :message "Node operation already exists"))
      (setf (gethash operation-id (node-runtime-operations node-runtime))
            operation))))

(defun forget-node-exec-operation (operation)
  "Remove OPERATION from the operations table, but only while it is still the entry
registered under its id. Holds the operations lock."
  (let* ((node-runtime (node-exec-operation-node-runtime operation))
         (operation-id
           (slot-value (node-exec-operation-request operation)
                       'gr8s.node.v1::operation-id)))
    (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
      (when (eq operation
                (gethash operation-id (node-runtime-operations node-runtime)))
        (remhash operation-id (node-runtime-operations node-runtime))))))

(defun emit-node-exec-response (operation status &key (exit-code 0) message)
  "Emit a terminal OPERATION-RESPONSE for OPERATION with STATUS, exit code and optional
message, through the operation's emit function."
  (funcall
   (node-exec-operation-emit operation) :operation-response
   (node-operation-response
    (node-exec-operation-request operation) status
    :exit-code exit-code :message (or message ""))))

(defun finish-node-exec-operation (operation &key error (emit-p t))
  "Finish OPERATION exactly once: mark it finished, deregister it, shut down and close its
socket, and -- unless EMIT-P is NIL -- emit a completed response with its exit code, or a
failed response carrying ERROR. Idempotent; a second call does nothing."
  (let ((finish-p nil)
        (exit-code 0))
    (bt:with-lock-held ((node-exec-operation-lock operation))
      (unless (node-exec-operation-finished-p operation)
        (setf (node-exec-operation-finished-p operation) t
              finish-p t
              exit-code (node-exec-operation-exit-code operation))))
    (when finish-p
      (forget-node-exec-operation operation)
      (ignore-errors
        (usocket:socket-shutdown (node-exec-operation-socket operation) :io))
      (ignore-errors
        (usocket:socket-close (node-exec-operation-socket operation)))
      (cleanup-node-operation operation)
      (when emit-p
        (if error
            (emit-node-exec-response
             operation gr8s.node.v1::+operationstatus-operation_status_failed+
             :exit-code 1 :message error)
            (emit-node-exec-response
             operation gr8s.node.v1::+operationstatus-operation_status_complete+
             :exit-code exit-code))))))

(defun node-exec-status-exit-code (data)
  "Parse the runtime's SPDY error-stream status DATA and return the command's exit code: 0
on \"Success\", otherwise the ExitCode cause, defaulting to 1 (also 1 on any parse error)."
  (handler-case
      (let* ((status
               (com.inuoe.jzon:parse
                (trivial-utf-8:utf-8-bytes-to-string data)))
             (details (gethash "details" status))
             (causes (and details (gethash "causes" details))))
        (if (equal "Success" (gethash "status" status))
            0
            (or (loop for cause across causes
                      when (string= "ExitCode" (gethash "reason" cause ""))
                        return (parse-integer (gethash "message" cause "")
                                              :junk-allowed t))
                1)))
    (error () 1)))

(defun wait-for-node-exec-output-window (operation size)
  "Return once SIZE more output bytes may go to the control plane, or NIL if the operation has
finished. Only a control plane that acknowledges output asks for this: then a slow client holds
up this exec's reads from the runtime, as a kubelet's streams do, instead of its output piling up."
  (if (not (slot-value (node-exec-operation-request operation) 'gr8s.node.v1::acknowledges-output))
      t
      (bt:with-lock-held ((node-exec-operation-lock operation))
        (loop
          (when (node-exec-operation-finished-p operation) (return nil))
          (when (< (node-exec-operation-unacknowledged-output operation) +exec-output-window-bytes+)
            (incf (node-exec-operation-unacknowledged-output operation) size)
            (return t))
          ;; FINISH-NODE-EXEC-OPERATION doesn't signal this variable, so look again regularly.
          (bt:condition-wait (node-exec-operation-output-window operation)
                             (node-exec-operation-lock operation) :timeout 0.2)))))

(defun emit-node-exec-stream (operation channel data)
  "Emit one OPERATION-STREAM frame of DATA on CHANNEL for OPERATION, assigning the next
sequence number under the operation lock."
  (let ((sequence nil))
    (bt:with-lock-held ((node-exec-operation-lock operation))
      (setf sequence (incf (node-exec-operation-sequence operation))))
    (funcall
     (node-exec-operation-emit operation) :operation-stream
     (node-operation-stream
      (node-exec-operation-request operation) channel data
      :sequence sequence))))

(defun open-node-exec-streams (operation)
  "Open the streams the runtime expects for OPERATION's channels, in the order clients use."
  (let* ((request (node-exec-operation-request operation))
         (session (node-exec-operation-session operation))
         (streams (list (cons :error (spdy-open-stream session "error")))))
    (flet ((open-channel (slot channel name)
             (when (slot-value request slot)
               (push (cons channel (spdy-open-stream session name)) streams))))
      (open-channel 'gr8s.node.v1::stdin :stdin "stdin")
      (open-channel 'gr8s.node.v1::stdout :stdout "stdout")
      (open-channel 'gr8s.node.v1::stderr :stderr "stderr")
      (open-channel 'gr8s.node.v1::tty :resize "resize"))
    (setf (node-exec-operation-streams operation) streams)))

(defun run-node-exec-reader (operation)
  "Forward output until the error stream and every output stream have ended."
  (let ((streams (node-exec-operation-streams operation))
        (open (remove-if (lambda (entry) (member (car entry) '(:stdin :resize))) (node-exec-operation-streams operation)))
        (status (node-exec-operation-status-octets operation)))
    (flet ((channel-of (id) (car (rassoc id streams))))
      (handler-case
          (loop while open
                do (let ((frame (spdy-read-frame (node-exec-operation-session operation))))
                     (ecase (first frame)
                       ((nil) (return))
                       (:reset (setf open (remove (second frame) open :key #'cdr)))
                       (:data
                        (destructuring-bind (id fin data) (rest frame)
                          (case (channel-of id)
                            (:stdout (when (and (plusp (length data))
                                                (wait-for-node-exec-output-window operation (length data)))
                                       (emit-node-exec-stream
                                        operation gr8s.node.v1::+streamchannel-stream_channel_stdout+ data)))
                            (:stderr (when (and (plusp (length data))
                                                (wait-for-node-exec-output-window operation (length data)))
                                       (emit-node-exec-stream
                                        operation gr8s.node.v1::+streamchannel-stream_channel_stderr+ data)))
                            (:error (loop for octet across data do (vector-push-extend octet status))))
                          (when fin (setf open (remove id open :key #'cdr))))))))
        (error (condition)
          (unless (node-exec-operation-finished-p operation)
            (finish-node-exec-operation operation :error (princ-to-string condition)))
          (return-from run-node-exec-reader nil)))))
  ;; A stream that ended without a status was closed from this side.
  (when (plusp (length (node-exec-operation-status-octets operation)))
    (bt:with-lock-held ((node-exec-operation-lock operation))
      (setf (node-exec-operation-exit-code operation)
            (node-exec-status-exit-code (coerce (node-exec-operation-status-octets operation)
                                                '(simple-array (unsigned-byte 8) (*)))))))
  (finish-node-exec-operation operation))

(defun start-node-exec-operation (node-runtime request emit)
  "Start a streamed exec or attach for REQUEST: open the connection to the runtime's
streaming server and its per-channel streams, register the operation, emit an \"accepted\"
response, and spawn a reader thread that forwards output until the streams end. Returns
the operation. Verifies the Pod is assigned first, and closes the socket and errors if
stream setup fails."
  (assigned-operation-pod node-runtime request)
  (let* ((runtime (node-runtime-runtime node-runtime))
         (uid (slot-value request 'gr8s.node.v1::pod-uid))
         (container (slot-value request 'gr8s.node.v1::container))
         (channels (list :stdin (slot-value request 'gr8s.node.v1::stdin)
                         :stdout (slot-value request 'gr8s.node.v1::stdout)
                         :stderr (slot-value request 'gr8s.node.v1::stderr)
                         :tty (slot-value request 'gr8s.node.v1::tty)))
         (url (if (= (slot-value request 'gr8s.node.v1::kind)
                     gr8s.node.v1::+operationkind-operation_kind_attach+)
                  (apply #'runtime-attach-url runtime uid container channels)
                  (apply #'runtime-exec-url runtime uid container
                         (slot-value request 'gr8s.node.v1::command) channels))))
    (multiple-value-bind (socket session) (connect-runtime-stream url)
      (let ((operation
              (make-node-exec-operation
               node-runtime request socket session emit)))
        (handler-case (open-node-exec-streams operation)
          (error (condition)
            (ignore-errors (usocket:socket-close socket))
            (error 'runtime-error :message (princ-to-string condition))))
        (remember-node-exec-operation node-runtime operation)
        (emit-node-exec-response
         operation gr8s.node.v1::+operationstatus-operation_status_accepted+)
        (setf (node-exec-operation-thread operation)
              (bt:make-thread
               (lambda () (run-node-exec-reader operation))
               :name "gr8s interactive exec reader"))
        operation))))

(defun node-terminal-size-octets (input)
  "Return the JSON the runtime's resize stream reads for a terminal-resize INPUT."
  (trivial-utf-8:string-to-utf-8-bytes
   (format nil "{\"Width\":~D,\"Height\":~D}~%"
           (slot-value input 'gr8s.node.v1::columns)
           (slot-value input 'gr8s.node.v1::rows))))

(defun write-node-exec-input (operation input)
  "Forward one interactive INPUT for OPERATION to the runtime -- stdin data/EOF, or a
terminal resize. Ignores a replay of the last input, and signals on an older input
sequence or an unsupported channel. Holds the operation lock while advancing the
last-input sequence."
  ;; The generated binding renames this field's slot because SEQUENCE is a
  ;; Common Lisp symbol, while preserving the protobuf :SEQUENCE initarg.
  (let ((sequence
          (slot-value input 'gr8s.node.v1::proto-sequence))
        (session (node-exec-operation-session operation))
        (streams (node-exec-operation-streams operation)))
    (bt:with-lock-held ((node-exec-operation-lock operation))
      (let ((last-sequence (node-exec-operation-last-input-sequence operation)))
        (when (< sequence last-sequence)
          (error 'runtime-error :message "Interactive input sequence is stale"))
        ;; The control plane retries once when a relay reply is lost. The first send
        ;; may already have applied both the data and its output acknowledgement.
        (when (= sequence last-sequence)
          (return-from write-node-exec-input operation)))
      (setf (node-exec-operation-last-input-sequence operation) sequence)
      (let ((acknowledged (slot-value input 'gr8s.node.v1::acknowledged-bytes)))
        (when (plusp acknowledged)
          (setf (node-exec-operation-unacknowledged-output operation)
                (max 0 (- (node-exec-operation-unacknowledged-output operation) acknowledged)))
          (bt:condition-notify (node-exec-operation-output-window operation)))))
    (case (slot-value input 'gr8s.node.v1::channel)
      (#.gr8s.node.v1::+streamchannel-stream_channel_stdin+
       (let ((stdin (cdr (assoc :stdin streams))) (data (slot-value input 'gr8s.node.v1::data))
             (eof (slot-value input 'gr8s.node.v1::eof)))
         (when (and stdin (or eof (plusp (length data))))
           (spdy-write-data session stdin data :fin eof))))
      (#.gr8s.node.v1::+streamchannel-stream_channel_terminal_resize+
       (let ((resize (cdr (assoc :resize streams))))
         (when resize (spdy-write-data session resize (node-terminal-size-octets input)))))
      (otherwise
       (error 'runtime-error :message "Unsupported interactive input channel")))))

(defparameter *reclaim-volume-call* #'reclaim-provisioned-volume
  "Remove a provisioned volume's directory, taking the state directory and the PV.")

(defun start-volume-reclaim-operation (node-runtime request emit)
  "Queue a volume's removal. A request for one already running joins it, so a control plane
that reconnects or restarts gets the answer without a second deletion racing the first."
  (let ((volume (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string
                                       (slot-value request 'gr8s.node.v1::volume-json))))
        (directory (node-runtime-state-directory node-runtime))
        (reclaim *reclaim-volume-call*))
    (work-queue-submit
     (node-runtime-reclaim-queue node-runtime)
     (storage-resource-name volume)
     (volume-reclaim-lane volume)
     (lambda () (funcall reclaim directory volume))
     :on-done
     (lambda (value condition)
       (declare (ignore value))
       (funcall
        emit :operation-response
        (if condition
            (node-operation-response request gr8s.node.v1::+operationstatus-operation_status_failed+
                                     :exit-code 1 :message (princ-to-string condition))
            (node-operation-response request gr8s.node.v1::+operationstatus-operation_status_complete+)))))))

(defun start-metrics-operation (node-runtime request emit)
  "Report this node's container usage on its own thread, since it waits on the container runtime."
  (bt:make-thread
   (lambda ()
     (handler-case
         (let ((metrics
                 (kubelet-stats-summary-object
                  (collect-kubelet-node-stats
                   (node-runtime-runtime node-runtime)
                   (node-runtime-node-name node-runtime)))))
           (funcall emit :operation-stream
                    (node-operation-stream
                     request gr8s.node.v1::+streamchannel-stream_channel_stdout+
                     (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify metrics))))
           (funcall emit :operation-response
                    (node-operation-response request gr8s.node.v1::+operationstatus-operation_status_complete+)))
       (error (condition)
         (funcall emit :operation-response
                  (node-operation-response request gr8s.node.v1::+operationstatus-operation_status_failed+
                                           :exit-code 1 :message (princ-to-string condition))))))
   :name "gr8s container metrics"))

(defun dispatch-node-operation (node-runtime variant payload emit)
  "Dispatch one operation-protocol envelope (VARIANT, PAYLOAD) to its handler, emitting
replies through EMIT. A new request starts the matching operation (metrics, volume
reclaim, port-forward, streamed exec/attach, or a synchronous op); input and cancel are
routed to the live operation; a closed session abandons all operations. A request that
errors becomes a failed response; an error on any other variant is re-signaled."
  (handler-case
      (case variant
        (:operation-request
         (cond
           ((= (slot-value payload 'gr8s.node.v1::kind)
               gr8s.node.v1::+operationkind-operation_kind_metrics+)
            (start-metrics-operation node-runtime payload emit))
           ((= (slot-value payload 'gr8s.node.v1::kind)
               gr8s.node.v1::+operationkind-operation_kind_reclaim_volume+)
            (start-volume-reclaim-operation node-runtime payload emit))
           ((= (slot-value payload 'gr8s.node.v1::kind)
               gr8s.node.v1::+operationkind-operation_kind_port_forward+)
            (start-node-port-forward-operation node-runtime payload emit))
           ((= (slot-value payload 'gr8s.node.v1::kind)
               gr8s.node.v1::+operationkind-operation_kind_slynk+)
            (start-node-slynk-operation node-runtime payload emit))
           ((= (slot-value payload 'gr8s.node.v1::kind)
               gr8s.node.v1::+operationkind-operation_kind_trace+)
            (start-node-trace-operation node-runtime payload emit))
           ;; Every exec streams through the runtime's streaming server, as kubelet's do: a
           ;; synchronous one would hold this session's reader until the command ended.
           ((member (slot-value payload 'gr8s.node.v1::kind)
                    (list gr8s.node.v1::+operationkind-operation_kind_attach+
                          gr8s.node.v1::+operationkind-operation_kind_exec+))
            (start-node-exec-operation node-runtime payload emit))
           (t
            (dolist (reply (handle-node-operation node-runtime payload))
              (funcall emit (car reply) (cdr reply))))))
        (:operation-input
         (let ((operation
                 (find-node-exec-operation
                  node-runtime
                  (slot-value payload 'gr8s.node.v1::operation-id))))
           ;; One operation's input, which can arrive after it ended, is only that
           ;; operation's problem: the session carries every other Pod's traffic.
           (cond
             ;; A forwarded connection can end while its last data is on the way.
             ((and (null operation) (plusp (slot-value payload 'gr8s.node.v1::acknowledged-bytes))))
             ((null operation)
              (funcall
               emit :operation-response
               (node-operation-response
                payload gr8s.node.v1::+operationstatus-operation_status_failed+
                :exit-code 1 :message "Interactive operation was not found")))
             ((typep operation 'node-port-forward-operation)
              (handler-case (write-node-port-forward-input operation payload)
                (error (condition)
                  (finish-node-exec-operation operation :error (princ-to-string condition)))))
             ((typep operation 'node-slynk-operation)
              (handler-case (write-node-slynk-input operation payload)
                (error (condition)
                  (finish-node-exec-operation operation :error (princ-to-string condition)))))
             ((node-exec-operation-trace-p operation)
              (acknowledge-node-trace-output operation payload))
             (t
              (handler-case (write-node-exec-input operation payload)
                (error (condition)
                  (finish-node-exec-operation operation :error (princ-to-string condition))))))))
        (:operation-cancel
         (let ((operation
                 (find-node-exec-operation
                  node-runtime
                  (slot-value payload 'gr8s.node.v1::operation-id))))
           (when operation
             (let ((reason (or (slot-value payload 'gr8s.node.v1::reason)
                               "operation cancelled")))
               (if (node-exec-operation-trace-p operation)
                   (request-node-trace-stop operation reason)
                   (finish-node-exec-operation operation :error reason))))))
        (:session-closed
         (abandon-all-node-operations node-runtime))
        (otherwise
         (error 'runtime-error :message "Unsupported operation envelope")))
    (error (condition)
      (if (eq variant :operation-request)
          (funcall
           emit :operation-response
           (node-operation-response
            payload gr8s.node.v1::+operationstatus-operation_status_failed+
            :exit-code 1 :message (princ-to-string condition)))
          (error condition)))))

(defun cancel-all-node-operations (node-runtime reason)
  "Finish every live node operation as a failure with REASON, emitting each a failed
response."
  (let ((operations nil))
    (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
      (maphash (lambda (id operation)
                 (declare (ignore id))
                 (push operation operations))
               (node-runtime-operations node-runtime)))
    (dolist (operation operations)
      (finish-node-exec-operation operation :error reason))))

(defun abandon-all-node-operations (node-runtime)
  "Finish every live node operation without emitting any response, for a session that has
already gone away."
  (let ((operations nil))
    (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
      (maphash (lambda (id operation)
                 (declare (ignore id))
                 (push operation operations))
               (node-runtime-operations node-runtime)))
    (dolist (operation operations)
      (finish-node-exec-operation operation :emit-p nil))))
