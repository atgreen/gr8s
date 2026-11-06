(in-package #:gr8s)

(defstruct (node-runtime (:constructor %make-node-runtime))
  state-directory
  runtime
  manager
  network
  network-reconciler
  ipam
  cni-operations
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
  ;; Listening host ports by (ip . port); see pod-host-ports.lisp.
  (host-port-forwarders (make-hash-table :test #'equal))
  ;; Listening Service node ports by (protocol ip . port), likewise.
  (node-port-forwarders (make-hash-table :test #'equal))
  ;; Gateway API L7 proxy listeners, reconciled from stored Gateway/HTTPRoute
  ;; objects. NIL until the first reconcile creates it.
  gateway-controller)

(defun make-node-runtime (state-directory runtime manager
                          &key (network-reconciler
                                 (when manager #'reconcile-node-vxlan-network)))
  (let* ((directory (uiop:ensure-directory-pathname state-directory))
         (store (open-store (merge-pathnames "desired/" directory))))
    ;; The control plane serves every watch; a journal here would only repeat its own.
    (setf (pod-store-watch-journal-p store) nil)
    (when (containerd-runtime-p runtime)
      (setf (containerd-runtime-resource-store runtime) store))
    (let ((node-runtime
            (%make-node-runtime
             :state-directory directory :runtime runtime :manager manager
             :network-reconciler network-reconciler
             :store store :reconciler (make-reconciler store runtime))))
      (let ((applied (read-node-network-file (node-runtime-network-path node-runtime)))
            (pending (read-node-network-file (node-runtime-network-pending-path node-runtime))))
        (when applied
          (validate-node-network-object applied)
          (setf (node-runtime-network node-runtime) applied))
        (when (or pending applied)
          (configure-node-runtime-network node-runtime (or pending applied)
                                          :persist (not (null pending)))))
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
  (merge-pathnames "network.json" (node-runtime-state-directory node-runtime)))

(defun node-runtime-network-pending-path (node-runtime)
  (merge-pathnames "network-pending.json" (node-runtime-state-directory node-runtime)))

(defun read-node-network-file (path)
  (when (probe-file path) (com.inuoe.jzon:parse path)))

(defun node-network-object (network &optional routes)
  (json-object
   "version" 1
   "clusterPodCIDR" (slot-value network 'gr8s.node.v1::cluster-pod-cidr)
   "nodePodCIDR" (slot-value network 'gr8s.node.v1::node-pod-cidr)
   "dnsAddress" (slot-value network 'gr8s.node.v1::dns-address)
   "vni" (slot-value network 'gr8s.node.v1::vni)
   "mtu" (slot-value network 'gr8s.node.v1::mtu)
   "underlayAddress" (slot-value network 'gr8s.node.v1::underlay-address)
   "routes" (coerce
             (mapcar (lambda (route)
                       (json-object "nodeID" (slot-value route 'gr8s.node.v1::node-id)
                                    "podCIDR" (slot-value route 'gr8s.node.v1::pod-cidr)
                                    "underlayAddress" (slot-value route 'gr8s.node.v1::underlay-address)))
                     routes) 'vector)))

(defun validate-network-cidr (cidr)
  (handler-case
      (multiple-value-bind (address prefix) (parse-ipv4-cidr cidr)
        (unless (and (<= 0 prefix 30)
                     (zerop (logand address (1- (ash 1 (- 32 prefix))))))
          (invalid-cni "invalid network CIDR ~A" cidr))
        (values address prefix))
    (cni-error (condition) (error condition))
    (error () (invalid-cni "invalid network CIDR ~S" cidr))))

(defun network-cidr-subnet-p (subnet parent)
  (multiple-value-bind (address prefix) (validate-network-cidr subnet)
    (multiple-value-bind (parent-address parent-prefix) (validate-network-cidr parent)
      (and (<= parent-prefix prefix)
           (= (ash address (- parent-prefix 32))
              (ash parent-address (- parent-prefix 32)))))))

(defun network-cidrs-overlap-p (left right)
  (multiple-value-bind (a a-prefix) (validate-network-cidr left)
    (multiple-value-bind (b b-prefix) (validate-network-cidr right)
      (let ((shift (- (min a-prefix b-prefix) 32)))
        (= (ash a shift) (ash b shift))))))

(defun validate-node-network-routes (network)
  (let ((routes (gethash "routes" network #()))
        (cidrs (list (gethash "nodePodCIDR" network)))
        (addresses (list (gethash "underlayAddress" network "")))
        (node-ids nil))
    (unless (and (vectorp routes) (not (stringp routes)))
      (invalid-cni "node routes must be an array"))
    (when (and (plusp (length routes)) (string= "" (first addresses)))
      (invalid-cni "peer routes require a local node underlay address"))
    (loop for route across routes
          do (unless (hash-table-p route) (invalid-cni "invalid node route"))
             (let* ((id (required-cni-string route "nodeID"))
                    (cidr (required-cni-string route "podCIDR"))
                    (address (required-cni-string route "underlayAddress")))
               (handler-case (canonical-node-underlay-address address)
                 (error () (invalid-cni "invalid peer underlay address ~A" address)))
               (unless (and (network-cidr-subnet-p cidr (gethash "clusterPodCIDR" network))
                            (notany (lambda (other) (network-cidrs-overlap-p cidr other)) cidrs)
                            (not (member id node-ids :test #'string=))
                            (not (member address addresses :test #'string=)))
                 (invalid-cni "conflicting or out-of-range peer route ~A" cidr))
               (push cidr cidrs) (push address addresses) (push id node-ids))))
  network)

(defun validate-node-network-object (network)
  (unless (and (hash-table-p network) (eql 1 (gethash "version" network)))
    (invalid-cni "invalid persisted node network format"))
  (unless (network-cidr-subnet-p (required-cni-string network "nodePodCIDR")
                                 (required-cni-string network "clusterPodCIDR"))
    (invalid-cni "node Pod CIDR must be a subnet of the cluster Pod CIDR"))
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
  network)

(defun configure-node-runtime-network (node-runtime network &key (persist t))
  (validate-node-network-object network)
  (let ((runtime (node-runtime-runtime node-runtime))
        (address (gethash "underlayAddress" network "")))
    (when (and (typep runtime 'containerd-runtime) (plusp (length address)))
      (setf (containerd-runtime-host-address runtime) address)))
  (when (node-runtime-manager node-runtime)
    (validate-pod-pool-host-routes (gethash "clusterPodCIDR" network)
                                  (node-runtime-state-directory node-runtime)))
  (bt:with-lock-held ((node-runtime-network-lock node-runtime))
    (let ((existing (node-runtime-network node-runtime)))
      (when (and existing
                 (not (string= (gethash "nodePodCIDR" existing)
                               (gethash "nodePodCIDR" network))))
        (invalid-cni "refusing to change the agent's durable Pod CIDR")))
    (let ((ipam
            (or (node-runtime-ipam node-runtime)
                (open-node-ipam
                 (merge-pathnames "ipam/" (node-runtime-state-directory node-runtime))
                 (gethash "nodePodCIDR" network)))))
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
        (when (and (node-runtime-manager node-runtime)
                   (plusp (length (gethash "underlayAddress" network ""))))
          (ignore-errors (ensure-overlay-firewall (gethash "nodePodCIDR" network))))
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
             ipam :mtu (gethash "mtu" network)
                  :dns-address (gethash "dnsAddress" network)))))
  node-runtime)

(defun apply-node-runtime-network (node-runtime snapshot)
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
  (when (and (node-runtime-manager node-runtime) (node-runtime-ipam node-runtime)
             (not (node-runtime-has-allocations-p node-runtime)))
    (remove-node-gateway)))

(defun reconcile-cached-node-network (node-runtime)
  ;; Kernel link events can flush permanent VXLAN FDB entries even when the
  ;; control-plane revision is unchanged. Repair from durable local topology.
  (when (node-runtime-network-reconciler node-runtime)
    (bt:with-lock-held ((node-runtime-apply-lock node-runtime))
      (let* ((pending (read-node-network-file (node-runtime-network-pending-path node-runtime)))
             (network (or pending (node-runtime-network node-runtime))))
        (when network
          (configure-node-runtime-network node-runtime network :persist (not (null pending)))
          (when (and (node-runtime-manager node-runtime)
                     (node-runtime-has-allocations-p node-runtime))
            (ensure-node-gateway))))))
  nil)

(defun handle-node-runtime-cni (node-runtime request)
  (let ((operations
          (bt:with-lock-held ((node-runtime-network-lock node-runtime))
            (node-runtime-cni-operations node-runtime))))
    (if operations
        (handle-agent-cni-request request :operations operations :chained nil)
        (agent-cni-error-response
         (make-condition 'cni-error :message "node network assignment is not ready")))))

(defun node-runtime-stopping-p (node-runtime)
  (bt:with-lock-held ((node-runtime-lock node-runtime))
    (node-runtime-stop-requested node-runtime)))

(defun wait-for-node-runtime-stop (node-runtime)
  (bt:with-lock-held ((node-runtime-lock node-runtime))
    (loop until (node-runtime-stop-requested node-runtime)
          do (bt:condition-wait
              (node-runtime-state-changed node-runtime)
              (node-runtime-lock node-runtime)))))

(defun run-node-runtime-body (node-runtime)
  (unwind-protect
       (progn
         (setf (node-runtime-worker node-runtime)
               (start-reconciliation-worker
                (node-runtime-reconciler node-runtime)
                :before-reconcile (lambda ()
                                    (reconcile-cached-node-network node-runtime)
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
    (stop-runtime-deletions (node-runtime-runtime node-runtime))))

(defun call-with-agent-cni-server
    (node-runtime function &key operations)
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
                (try-start-service-lb-dataplane "/sys/fs/cgroup" pin-directory))))
    (when dataplane
      (setf (node-runtime-service-lb node-runtime) dataplane
            (node-runtime-service-lb-controller node-runtime)
            (make-service-lb-controller (node-runtime-store node-runtime) dataplane)))
    (unwind-protect
         (funcall function)
      (when (node-runtime-gateway-controller node-runtime)
        (ignore-errors (stop-gateway-controller (node-runtime-gateway-controller node-runtime)))
        (setf (node-runtime-gateway-controller node-runtime) nil))
      (when (node-runtime-service-lb node-runtime)
        (ignore-errors (stop-service-lb-dataplane (node-runtime-service-lb node-runtime)))
        (setf (node-runtime-service-lb node-runtime) nil
              (node-runtime-service-lb-controller node-runtime) nil)))))

(defun call-with-node-runtime-services (node-runtime)
  (let ((body (lambda () (run-node-runtime-body node-runtime))))
    (if (containerd-runtime-p (node-runtime-runtime node-runtime))
        (if (node-runtime-manager node-runtime)
            (call-with-service-lb
             node-runtime
             (lambda ()
               (call-with-agent-cni-server
                node-runtime
                (lambda () (call-with-dns-server body :service-resolver
                                           (store-service-dns-resolver (node-runtime-store node-runtime)))))))
            (call-with-dns-server body :service-resolver
                                        (store-service-dns-resolver (node-runtime-store node-runtime))))
        (funcall body))))

(defun node-runtime-thread-main (node-runtime)
  (handler-case
      (unwind-protect
           (call-with-managed-containerd
            (node-runtime-manager node-runtime)
            (lambda () (call-with-node-runtime-services node-runtime)))
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

(defun assignment-pod (assignment)
  (let* ((json (trivial-utf-8:utf-8-bytes-to-string
                (slot-value assignment 'gr8s.node.v1::pod-json)))
         (pod (parse-pod json))
         (namespace (slot-value assignment 'gr8s.node.v1::namespace))
         (name (slot-value assignment 'gr8s.node.v1::name))
         (uid (slot-value assignment 'gr8s.node.v1::uid))
         (resource-version
           (slot-value assignment 'gr8s.node.v1::resource-version)))
    (unless (and (string= namespace (pod-namespace pod))
                 (string= name (pod-name pod))
                 (string= uid (pod-uid pod))
                 (string= resource-version (pod-resource-version pod)))
      (error "Pod assignment identity does not match its Pod JSON"))
    pod))

(defun put-assigned-pod (store pod)
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

(defun cache-node-observation (node-runtime pod status)
  "Persist actual status and transport Events without confusing runtime deletion with public phase."
  (save-pod-observation (node-runtime-store node-runtime) pod status)
  (let* ((finalization (pod-finalization-state (node-runtime-store node-runtime) pod))
         (message (pod-observed-status-message
                   pod status (runtime-events (node-runtime-runtime node-runtime) (pod-uid pod))
                   (and finalization (gethash "runtimeDeleted" finalization)))))
    (bt:with-lock-held ((node-runtime-observed-lock node-runtime))
      (setf (gethash (pod-uid pod) (node-runtime-observed-statuses node-runtime)) message))
    message))

(defun endpoint-telemetry-message (sandbox interface address counters error)
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
  (let ((manager (node-runtime-manager node-runtime))
        (ipam (node-runtime-ipam node-runtime)))
    (when (and manager ipam)
      (let ((allocations
              (bt:with-lock-held ((node-ipam-lock ipam))
                (loop for key being the hash-keys of (node-ipam-allocations ipam)
                        using (hash-value address)
                      collect (list (car key) (cdr key) address))))
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

(defun node-runtime-status (node-runtime &key (counter-reader #'read-cni-policy-counters))
  (let ((pods (list-pods (node-runtime-store node-runtime))))
    (make-instance
     'gr8s.node.v1::node-status
     :observed-at-unix-nanos (* (- (get-universal-time) 2208988800) 1000000000)
     :pod-certificate-requests
     (mapcar #'pod-certificate-claim-message
             (node-pending-pod-certificate-claims (node-runtime-store node-runtime)))
     :csi-drivers
     (when (containerd-runtime-p (node-runtime-runtime node-runtime))
       ;; Reporting runs on its own thread, so a slow driver can't delay heartbeats.
       (handler-case (scan-csi-plugin-registry)
         (error (condition) (format *error-output* "gr8s CSI registry scan failed: ~A~%" condition)))
       (csi-driver-registrations))
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

(defun pod-ip-identity-map (store)
  "Map each known Pod IP -> (cons namespace label-alist), for policy selection."
  (let ((map (make-hash-table :test #'equal)))
    (dolist (pod (list-pods store) map)
      (let* ((status (gethash (pod-uid pod) (pod-store-pod-observed-statuses store)))
             (ip (and status (gethash "podIP" status)))
             (metadata (gethash "metadata" (pod-object pod) (make-hash-table :test #'equal)))
             (labels (gethash "labels" metadata)))
        (when (and (stringp ip) (plusp (length ip)))
          (let ((alist '()))
            (when (hash-table-p labels)
              (maphash (lambda (k v) (push (cons k v) alist)) labels))
            (setf (gethash ip map) (cons (pod-namespace pod) alist))))))))

(defun converge-node-network-policies (node-runtime)
  "Write each local Pod's resolved egress NetworkPolicy into its pinned maps
(data-only; the egress guard enforces it, no recompile/re-attach). Always runs,
so clearing the last policy resets a Pod's mode to open. Fail-soft: never aborts
snapshot application."
  (let ((manager (node-runtime-manager node-runtime))
        (ipam (node-runtime-ipam node-runtime))
        (store (node-runtime-store node-runtime)))
    (when (and manager ipam store)
      ;; The out-of-process CNI plugin persists every allocation to the ipam file;
      ;; reload it so the dataplane tables below cover Pods added since the agent's
      ;; ipam was opened, not only those present at startup (podster-6yd).
      (ignore-errors (reload-node-ipam-allocations ipam))
      (let ((root (managed-containerd-bpf-directory manager))
            (endpoints (bt:with-lock-held ((node-ipam-lock ipam))
                         (loop for key being the hash-keys of (node-ipam-allocations ipam)
                                 using (hash-value address)
                               collect (list (car key) (cdr key) address)))))
        ;; Same-node Pod->Pod delivery table (epic podster-pnd): every local Pod
        ;; gets the node-wide {dest IP -> ifindex/MAC} table so the egress guard
        ;; can redirect in-cluster traffic past the host firewall's FORWARD reject.
        ;; Populate it FIRST and independently: resolving an unsupported
        ;; NetworkPolicy (below) can throw, and keeping that resolution out of this
        ;; let's bindings is what lets the delivery table still be written.
        (converge-node-local-pod-delivery
         endpoints
         :directory-fn (lambda (sandbox)
                         (nth-value 2 (cni-pin-paths root sandbox))))
        ;; Pod->host delivery table (podster-9b1): every local Pod gets the node's
        ;; host-local destinations (the API server 10.96.0.1, this node's own IP)
        ;; so the egress guard redirects that traffic to lo, past the host
        ;; firewall's INPUT reject. Independent and fail-soft, like the table above.
        (converge-node-host-redirect
         (mapcar #'first endpoints)
         (ignore-errors (containerd-node-address (node-runtime-runtime node-runtime)))
         :directory-fn (lambda (sandbox)
                         (nth-value 2 (cni-pin-paths root sandbox))))
        (let ((specs (network-policy-specs-from-objects
                      (list-core-resources store "networkpolicies")))
              (ip-map (pod-ip-identity-map store)))
          (converge-pod-egress-policies
           specs endpoints
           :pod-finder (lambda (address)
                         (let ((id (gethash address ip-map)))
                           (if id (values (car id) (cdr id)) (values nil nil))))
           :directory-fn (lambda (sandbox)
                           (nth-value 2 (cni-pin-paths root sandbox)))))))))

(defvar *runtime-outage-snapshot-wait-seconds* 2
  "How long a snapshot waits for a restarting container runtime before giving up this attempt.")

(defun reconcile-node-snapshot (node-runtime snapshot)
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
    (apply-node-runtime-network node-runtime snapshot)
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
      ;; discovery data. A transient map error must not abort snapshot application.
      (when (node-runtime-service-lb-controller node-runtime)
        (handler-case
            (converge-service-lb-controller (node-runtime-service-lb-controller node-runtime))
          (error (condition)
            (format *error-output* "gr8s: Service LB convergence failed: ~A~%" condition))))
      (handler-case
          (converge-node-port-forwarders (node-runtime-node-port-forwarders node-runtime)
                                         (node-runtime-store node-runtime))
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
                    (make-gateway-controller
                     (node-runtime-store node-runtime)
                     :cert-dir (merge-pathnames "gateway-certs/"
                                                (node-runtime-state-directory node-runtime)))))
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
        statuses))))

(defun node-operation-response (request status &key (exit-code 0) (message ""))
  (make-instance
   'gr8s.node.v1::operation-response
   :operation-id (slot-value request 'gr8s.node.v1::operation-id)
   :status status
   :exit-code exit-code
   :error-message message))

(defun node-operation-stream (request channel data &key (sequence 1) (eof t))
  (make-instance
   'gr8s.node.v1::operation-stream
   :operation-id (slot-value request 'gr8s.node.v1::operation-id)
   :sequence sequence
   :channel channel
   :data data
   :eof eof))

(defun assigned-operation-pod (node-runtime request)
  (let* ((namespace (slot-value request 'gr8s.node.v1::namespace))
         (name (slot-value request 'gr8s.node.v1::pod))
         (uid (slot-value request 'gr8s.node.v1::pod-uid))
         (pod (get-pod (node-runtime-store node-runtime) namespace name)))
    (unless (string= uid (pod-uid pod))
      (error 'runtime-error
             :message (format nil "Pod ~A/~A is not assigned to this agent"
                              namespace name)))
    pod))

(defun handle-node-operation (node-runtime request)
  (handler-case
      (progn
        (assigned-operation-pod node-runtime request)
        (case (slot-value request 'gr8s.node.v1::kind)
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
  (lock (bt:make-lock "gr8s interactive exec operation")))

(defun find-node-exec-operation (node-runtime operation-id)
  (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
    (gethash operation-id (node-runtime-operations node-runtime))))

(defun remember-node-exec-operation (node-runtime operation)
  (let ((operation-id
          (slot-value (node-exec-operation-request operation)
                      'gr8s.node.v1::operation-id)))
    (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
      (when (gethash operation-id (node-runtime-operations node-runtime))
        (error 'runtime-error :message "Node operation already exists"))
      (setf (gethash operation-id (node-runtime-operations node-runtime))
            operation))))

(defun forget-node-exec-operation (operation)
  (let* ((node-runtime (node-exec-operation-node-runtime operation))
         (operation-id
           (slot-value (node-exec-operation-request operation)
                       'gr8s.node.v1::operation-id)))
    (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
      (when (eq operation
                (gethash operation-id (node-runtime-operations node-runtime)))
        (remhash operation-id (node-runtime-operations node-runtime))))))

(defun emit-node-exec-response (operation status &key (exit-code 0) message)
  (funcall
   (node-exec-operation-emit operation) :operation-response
   (node-operation-response
    (node-exec-operation-request operation) status
    :exit-code exit-code :message (or message ""))))

(defun finish-node-exec-operation (operation &key error (emit-p t))
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
      (when emit-p
        (if error
            (emit-node-exec-response
             operation gr8s.node.v1::+operationstatus-operation_status_failed+
             :exit-code 1 :message error)
            (emit-node-exec-response
             operation gr8s.node.v1::+operationstatus-operation_status_complete+
             :exit-code exit-code))))))

(defun node-exec-status-exit-code (data)
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

(defun emit-node-exec-stream (operation channel data)
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
                            (:stdout (when (plusp (length data))
                                       (emit-node-exec-stream
                                        operation gr8s.node.v1::+streamchannel-stream_channel_stdout+ data)))
                            (:stderr (when (plusp (length data))
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
  ;; The generated binding renames this field's slot because SEQUENCE is a
  ;; Common Lisp symbol, while preserving the protobuf :SEQUENCE initarg.
  (let ((sequence
          (slot-value input 'gr8s.node.v1::proto-sequence))
        (session (node-exec-operation-session operation))
        (streams (node-exec-operation-streams operation)))
    (bt:with-lock-held ((node-exec-operation-lock operation))
      (unless (> sequence (node-exec-operation-last-input-sequence operation))
        (error 'runtime-error :message "Interactive input sequence is stale"))
      (setf (node-exec-operation-last-input-sequence operation) sequence))
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
         (let ((metrics (runtime-container-metrics (node-runtime-runtime node-runtime))))
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
           ((or (= (slot-value payload 'gr8s.node.v1::kind)
                   gr8s.node.v1::+operationkind-operation_kind_attach+)
                (and (= (slot-value payload 'gr8s.node.v1::kind)
                        gr8s.node.v1::+operationkind-operation_kind_exec+)
                     (or (slot-value payload 'gr8s.node.v1::stdin)
                         (slot-value payload 'gr8s.node.v1::tty))))
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
             (finish-node-exec-operation
              operation :error
              (or (slot-value payload 'gr8s.node.v1::reason)
                  "operation cancelled")))))
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
  (let ((operations nil))
    (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
      (maphash (lambda (id operation)
                 (declare (ignore id))
                 (push operation operations))
               (node-runtime-operations node-runtime)))
    (dolist (operation operations)
      (finish-node-exec-operation operation :error reason))))

(defun abandon-all-node-operations (node-runtime)
  (let ((operations nil))
    (bt:with-lock-held ((node-runtime-operations-lock node-runtime))
      (maphash (lambda (id operation)
                 (declare (ignore id))
                 (push operation operations))
               (node-runtime-operations node-runtime)))
    (dolist (operation operations)
      (finish-node-exec-operation operation :emit-p nil))))
