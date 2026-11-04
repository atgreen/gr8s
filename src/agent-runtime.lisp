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
  (lock (bt:make-lock "gr8s node runtime"))
  (state-changed (bt:make-condition-variable :name "gr8s node runtime state"))
  (apply-lock (bt:make-lock "gr8s node snapshot application"))
  (received-revision -1)
  (arrival-lock (bt:make-lock "gr8s node snapshot arrival")))

(defun make-node-runtime (state-directory runtime manager
                          &key (network-reconciler
                                 (when manager #'reconcile-node-vxlan-network)))
  (let* ((directory (uiop:ensure-directory-pathname state-directory))
         (store (open-store (merge-pathnames "desired/" directory))))
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
              (pod-resource-version pod)))
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
                :before-reconcile (lambda () (reconcile-cached-node-network node-runtime))
                :observer (lambda (pod status) (cache-node-observation node-runtime pod status))))
         (bt:with-lock-held ((node-runtime-lock node-runtime))
           (setf (node-runtime-state node-runtime) :running)
           (bt:condition-notify (node-runtime-state-changed node-runtime)))
         (wait-for-node-runtime-stop node-runtime))
    (when (node-runtime-worker node-runtime)
      (stop-reconciliation-worker (node-runtime-worker node-runtime))
      (setf (node-runtime-worker node-runtime) nil))
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

(defun call-with-node-runtime-services (node-runtime)
  (let ((body (lambda () (run-node-runtime-body node-runtime))))
    (if (containerd-runtime-p (node-runtime-runtime node-runtime))
        (if (node-runtime-manager node-runtime)
            (call-with-agent-cni-server
             node-runtime
             (lambda () (call-with-dns-server body :service-resolver
                                        (store-service-dns-resolver (node-runtime-store node-runtime)))))
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

(defun remove-unassigned-pods (node-runtime assignments)
  (let ((assigned-uids (make-hash-table :test #'equal)))
    (dolist (assignment assignments)
      (setf (gethash (slot-value assignment 'gr8s.node.v1::uid)
                     assigned-uids)
            t))
    (dolist (pod (list-pods (node-runtime-store node-runtime)))
      (unless (gethash (pod-uid pod) assigned-uids)
        ;; Serialize with the background reconciler and persist deletion intent
        ;; before CRI calls. A transient removal failure must never turn into
        ;; runtime-ensure recreating an assignment the server has withdrawn.
        (delete-reconciled-pod (node-runtime-reconciler node-runtime)
                               (pod-namespace pod) (pod-name pod) :grace-period 0)))))

(defun pod-observed-status-message (pod status &optional events)
  (let ((wire-status (copy-core-object status)))
    (when events (setf (gethash "gr8sRuntimeEvents" wire-status) events))
  (make-instance
   'gr8s.node.v1::pod-observed-status
   :namespace (pod-namespace pod)
   :name (pod-name pod)
   :uid (pod-uid pod)
   :resource-version (pod-resource-version pod)
   :phase (gethash "phase" status "Unknown")
   :reason (gethash "reason" status "")
   :message (gethash "message" status "")
   :pod-ip (gethash "podIP" status "")
   :status-json (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify wire-status)))))

(defun cache-node-observation (node-runtime pod status)
  (save-pod-observation (node-runtime-store node-runtime) pod status)
  (let ((message (pod-observed-status-message pod status (runtime-events (node-runtime-runtime node-runtime) (pod-uid pod)))))
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

(defun node-runtime-status (node-runtime &key (counter-reader #'read-cni-policy-counters))
  (let ((pods (list-pods (node-runtime-store node-runtime))))
    (make-instance
     'gr8s.node.v1::node-status
     :observed-at-unix-nanos (* (- (get-universal-time) 2208988800) 1000000000)
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
  ;; Parse and validate every assignment before changing any local intent.
  (let ((pods (mapcar #'assignment-pod (slot-value snapshot 'gr8s.node.v1::pods)))
        (revision (slot-value snapshot 'gr8s.node.v1::revision))
        (urgent nil))
    (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
      (when (< revision (node-runtime-received-revision node-runtime))
        (return-from receive-node-snapshot-intent nil))
      (dolist (existing (list-pods (node-runtime-store node-runtime)))
        (let ((assigned (find (pod-uid existing) pods :key #'pod-uid :test #'equal)))
          (when (or (null assigned) (deletion-requested-p assigned))
            (handler-case
                (progn
                  (if assigned
                      ;; Preserve the server's RV, deletion timestamp and grace.
                      ;; put-assigned-pod also prevents extending an earlier deadline.
                      (put-assigned-pod (node-runtime-store node-runtime) assigned)
                      (mark-pod-deleting (node-runtime-store node-runtime)
                                         (pod-namespace existing) (pod-name existing)
                                         :uid (pod-uid existing) :grace-period 0))
                  (setf urgent t))
              (kubernetes-error (condition)
                ;; An independently completed deletion or replacement is not
                ;; authority to cancel the new UID that now owns this name.
                (unless (member (kubernetes-error-status-code condition) '(404 409))
                  (error condition)))))))
      ;; A failed persist never publishes the revision or cancels CRI. A retry
      ;; may repeat already durable deletion intent, but cannot undo it.
      (setf (node-runtime-received-revision node-runtime) revision))
    (when urgent
      (cancel-running-pod-convergence (node-runtime-reconciler node-runtime)))
    urgent))

(defun ensure-node-snapshot-current (node-runtime snapshot)
  "Fence obsolete application before it can create another Pod or acknowledge a revision."
  (when (bt:with-lock-held ((node-runtime-arrival-lock node-runtime))
          (< (slot-value snapshot 'gr8s.node.v1::revision)
             (node-runtime-received-revision node-runtime)))
    (error 'pod-reconciliation-superseded)))

(defun reconcile-node-snapshot (node-runtime snapshot)
  (unless (eq :running (node-runtime-state node-runtime))
    (error 'runtime-error :message "node runtime is not running"))
  (bt:with-lock-held ((node-runtime-apply-lock node-runtime))
    (ensure-node-snapshot-current node-runtime snapshot)
    (apply-node-runtime-network node-runtime snapshot)
    (let ((assignments (slot-value snapshot 'gr8s.node.v1::pods)))
      (bt:with-lock-held ((node-runtime-observed-lock node-runtime))
        (clrhash (node-runtime-assigned-versions node-runtime))
        (dolist (assignment assignments)
          (setf (gethash (slot-value assignment 'gr8s.node.v1::uid)
                         (node-runtime-assigned-versions node-runtime))
                (slot-value assignment 'gr8s.node.v1::resource-version))))
      (remove-unassigned-pods node-runtime assignments)
      (install-assigned-resource-objects
       (node-runtime-store node-runtime) assignments
       (slot-value snapshot 'gr8s.node.v1::service-discovery-objects-json))
      (loop for assignment in assignments
            for pod = (progn
                        (ensure-node-snapshot-current node-runtime snapshot)
                        (put-assigned-pod (node-runtime-store node-runtime)
                                          (assignment-pod assignment)))
            for status = (progn
                           (ensure-node-snapshot-current node-runtime snapshot)
                           (reconcile-pod (node-runtime-reconciler node-runtime)
                                          (pod-namespace pod) (pod-name pod)))
            collect (cache-node-observation node-runtime pod status)
              into statuses
            finally (ensure-node-snapshot-current node-runtime snapshot)
                    (return statuses)))))

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
                    (slot-value request 'gr8s.node.v1::container))))
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
                 (node-runtime request socket stream emit)))
  node-runtime
  request
  socket
  stream
  emit
  thread
  (sequence 0)
  (last-input-sequence 0)
  (exit-code 0)
  (finished-p nil)
  (lock (bt:make-lock "gr8s interactive exec operation"))
  (write-lock (bt:make-lock "gr8s interactive exec websocket writer")))

(defun runtime-websocket-request (target host port key)
  (format nil
          "GET ~A HTTP/1.1~C~CHost: ~A:~D~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-WebSocket-Key: ~A~C~CSec-WebSocket-Version: 13~C~CSec-WebSocket-Protocol: v5.channel.k8s.io~C~C~C~C"
          target #\Return #\Linefeed host port #\Return #\Linefeed
          #\Return #\Linefeed #\Return #\Linefeed key #\Return #\Linefeed
          #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))

(defun connect-runtime-websocket (url)
  (multiple-value-bind (host port target) (parse-runtime-stream-url url)
    (let* ((socket
             (usocket:socket-connect
              host port :element-type '(unsigned-byte 8)))
           (stream (usocket:socket-stream socket))
           (key
             (ag-grpc:base64-encode
              (make-array 16 :element-type '(unsigned-byte 8)
                             :initial-contents
                             (loop repeat 16 collect (random 256))))))
      (handler-case
          (progn
            (write-sequence
             (ascii-octets
              (runtime-websocket-request target host port key))
             stream)
            (finish-output stream)
            (multiple-value-bind (status headers)
                (parse-http-response-head (read-http-response-head stream))
              (unless (= 101 status)
                (error 'runtime-error
                       :message
                       (format nil "containerd rejected exec with HTTP ~D"
                               status)))
              (unless (string-equal
                       "v5.channel.k8s.io"
                       (cdr (assoc :sec-websocket-protocol headers)))
                (error 'runtime-error
                       :message "containerd did not negotiate remotecommand v5")))
            (values socket stream))
        (error (condition)
          (ignore-errors (usocket:socket-close socket))
          (if (typep condition 'runtime-error)
              (error condition)
              (error 'runtime-error :message (princ-to-string condition))))))))

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

(defun node-exec-output-channel (wire-channel)
  (case wire-channel
    (1 gr8s.node.v1::+streamchannel-stream_channel_stdout+)
    (2 gr8s.node.v1::+streamchannel-stream_channel_stderr+)))

(defun node-exec-status-exit-code (data)
  (handler-case
      (let* ((status
               (com.inuoe.jzon:parse
                (trivial-utf-8:utf-8-bytes-to-string data)))
             (details (gethash "details" status))
             (causes (and details (gethash "causes" details))))
        (or (loop for cause across causes
                  when (string= "ExitCode" (gethash "reason" cause ""))
                    return (parse-integer (gethash "message" cause "")
                                          :junk-allowed t))
            1))
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

(defun run-node-exec-reader (operation)
  (handler-case
      (loop
        (multiple-value-bind (opcode payload)
            (read-websocket-frame (node-exec-operation-stream operation))
          (case opcode
            (2
             (when (zerop (length payload))
               (error 'runtime-error :message "Empty remotecommand frame"))
             (let ((channel (aref payload 0))
                   (data (subseq payload 1)))
               (cond
                 ((node-exec-output-channel channel)
                  (emit-node-exec-stream
                   operation (node-exec-output-channel channel) data))
                 ((= channel 3)
                  (bt:with-lock-held ((node-exec-operation-lock operation))
                    (setf (node-exec-operation-exit-code operation)
                          (node-exec-status-exit-code data)))))))
            (8 (return))
            (9
             (bt:with-lock-held ((node-exec-operation-write-lock operation))
               (write-websocket-frame
                (node-exec-operation-stream operation) 10 payload
                :masked-p t)))
            (10)
            (otherwise
             (error 'runtime-error
                    :message (format nil "Unsupported WebSocket opcode ~D"
                                     opcode))))))
    (error (condition)
      (unless (node-exec-operation-finished-p operation)
        (finish-node-exec-operation operation :error (princ-to-string condition)))
      (return-from run-node-exec-reader nil)))
  (finish-node-exec-operation operation))

(defun start-node-exec-operation (node-runtime request emit)
  (assigned-operation-pod node-runtime request)
  (let ((url
          (runtime-exec-url
           (node-runtime-runtime node-runtime)
           (slot-value request 'gr8s.node.v1::pod-uid)
           (slot-value request 'gr8s.node.v1::container)
           (slot-value request 'gr8s.node.v1::command)
           :stdin (slot-value request 'gr8s.node.v1::stdin)
           :stdout (slot-value request 'gr8s.node.v1::stdout)
           :stderr (slot-value request 'gr8s.node.v1::stderr)
           :tty (slot-value request 'gr8s.node.v1::tty))))
    (multiple-value-bind (socket stream) (connect-runtime-websocket url)
      (let ((operation
              (make-node-exec-operation
               node-runtime request socket stream emit)))
        (remember-node-exec-operation node-runtime operation)
        (emit-node-exec-response
         operation gr8s.node.v1::+operationstatus-operation_status_accepted+)
        (setf (node-exec-operation-thread operation)
              (bt:make-thread
               (lambda () (run-node-exec-reader operation))
               :name "gr8s interactive exec reader"))
        operation))))

(defun node-exec-input-payload (input)
  (case (slot-value input 'gr8s.node.v1::channel)
    (#.gr8s.node.v1::+streamchannel-stream_channel_stdin+
     (let ((data (slot-value input 'gr8s.node.v1::data)))
       (when (plusp (length data))
         (concatenate '(vector (unsigned-byte 8)) #(0) data))))
    (#.gr8s.node.v1::+streamchannel-stream_channel_terminal_resize+
     (concatenate
      '(vector (unsigned-byte 8)) #(4)
      (trivial-utf-8:string-to-utf-8-bytes
       (with-output-to-string (output)
         (com.inuoe.jzon:stringify
          (let ((size (make-hash-table :test #'equal)))
            (setf (gethash "width" size)
                  (slot-value input 'gr8s.node.v1::columns)
                  (gethash "height" size)
                  (slot-value input 'gr8s.node.v1::rows))
            size)
          :stream output)))))
    (otherwise
     (error 'runtime-error :message "Unsupported interactive input channel"))))

(defun write-node-exec-input (operation input)
  ;; The generated binding renames this field's slot because SEQUENCE is a
  ;; Common Lisp symbol, while preserving the protobuf :SEQUENCE initarg.
  (let ((sequence
          (slot-value input 'gr8s.node.v1::proto-sequence)))
    (bt:with-lock-held ((node-exec-operation-lock operation))
      (unless (> sequence (node-exec-operation-last-input-sequence operation))
        (error 'runtime-error :message "Interactive input sequence is stale"))
      (setf (node-exec-operation-last-input-sequence operation) sequence)))
  (bt:with-lock-held ((node-exec-operation-write-lock operation))
    (let ((payload (node-exec-input-payload input)))
      (when payload
        (write-websocket-frame
         (node-exec-operation-stream operation) 2 payload :masked-p t)))
    (when (slot-value input 'gr8s.node.v1::eof)
      (write-websocket-frame
       (node-exec-operation-stream operation) 2 #(255 0) :masked-p t))))

(defun dispatch-node-operation (node-runtime variant payload emit)
  (handler-case
      (case variant
        (:operation-request
         (if (and (= (slot-value payload 'gr8s.node.v1::kind)
                     gr8s.node.v1::+operationkind-operation_kind_exec+)
                  (or (slot-value payload 'gr8s.node.v1::stdin)
                      (slot-value payload 'gr8s.node.v1::tty)))
             (start-node-exec-operation node-runtime payload emit)
             (dolist (reply (handle-node-operation node-runtime payload))
               (funcall emit (car reply) (cdr reply)))))
        (:operation-input
         (let ((operation
                 (find-node-exec-operation
                  node-runtime
                  (slot-value payload 'gr8s.node.v1::operation-id))))
           (unless operation
             (error 'runtime-error :message "Interactive operation was not found"))
           (write-node-exec-input operation payload)))
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
