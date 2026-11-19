;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Durable, pod-scoped CPU and NUMA admission. Never repin an admitted Pod.
(in-package #:gr8s.kubelet)

(defstruct (node-resource-manager (:constructor %make-node-resource-manager))
  topology policy topology-policy reserved checkpoint checkpoint-present-p cpu-state-path devices runtime store
  (allocations (core-object)) (lock (bt:make-lock "node resource allocations")))

(defun reject-node-resource-admission (reason control &rest arguments)
  "Reject a Pod permanently when its requested resource affinity cannot fit."
  (error 'gr8s.runtime:resource-admission-error :reason reason :message (apply #'format nil control arguments)))

(defun resource-pod-spec (pod) (gethash "spec" (pod-to-object pod)))
(defun resource-pod-containers (pod)
  (let ((spec (resource-pod-spec pod)))
    (coerce (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec #())) 'list)))

(defun resource-container-request (container resource)
  (let ((quantity (container-resource-quantity container "requests" resource)))
    (if quantity (* (container-quantity-coefficient quantity) (expt 10 (container-quantity-scale quantity))) 0)))

(defun resource-container-stages (spec)
  "Concurrent container sets, including restartable init containers in each later stage."
  (let ((sidecars nil) (stages nil))
    (loop for container across (gethash "initContainers" spec #())
          do (push (cons container (copy-list sidecars)) stages)
             (when (equal "Always" (gethash "restartPolicy" container)) (push container sidecars)))
    (nreverse (cons (append sidecars (coerce (gethash "containers" spec #()) 'list)) stages))))

(defun resource-exclusive-count (manager spec container)
  "Only whole CPU requests in Guaranteed Pods are eligible for exclusive allocation."
  (let ((cpu (resource-container-request container "cpu")))
    (if (and (equal "static" (node-resource-manager-policy manager))
             (equal "Guaranteed" (pod-spec-qos-class spec)) (integerp cpu) (plusp cpu)) cpu 0)))

(defun resource-request-snapshot (spec)
  (let ((result (core-object)))
    (maphash (lambda (resource value) (setf (gethash resource result) (policy-value-string value)))
             (pod-spec-resource-totals spec))
    result))

(defun resource-container-request-snapshot (pod)
  (let ((result (core-object)))
    (dolist (container (resource-pod-containers pod))
      (setf (gethash (gethash "name" container) result)
            (copy-core-object (gethash "requests" (gethash "resources" container (core-object)) (core-object)))))
    result))

(defun resource-used-cpus (manager)
  (loop for plan being the hash-values of (node-resource-manager-allocations manager)
        append (coerce (gethash "cpus" plan #()) 'list)))

(defun resource-shared-cpus (manager)
  (sort (set-difference (coerce (gethash "online" (node-resource-manager-topology manager)) 'list)
                        (resource-used-cpus manager)) #'<))

(defun resource-manager-config (manager)
  (core-object "policy" (node-resource-manager-policy manager)
               "topologyPolicy" (node-resource-manager-topology-policy manager)
               "reserved" (format-cpu-set (node-resource-manager-reserved manager))
               "topology" (node-resource-manager-topology manager)))

(defun config-without-memory-totals (config)
  "CONFIG less each NUMA node's MemTotal. The kernel reports it a few kB
differently from one boot to the next, and no reservation is keyed on it;
VALIDATE-RESOURCE-CHECKPOINT checks that the reservations still fit."
  (let* ((copy (gr8s.resources::copy-core-object config))
         (topology (and (hash-table-p copy) (gethash "topology" copy)))
         (nodes (and (hash-table-p topology) (gethash "nodes" topology))))
    (when (vectorp nodes)
      (map nil (lambda (node) (when (hash-table-p node) (remhash "memory" node))) nodes))
    copy))

(defun save-node-resource-checkpoint (manager)
  "Write the authoritative reservations before exposing any new exclusive CPU."
  (ensure-directories-exist (node-resource-manager-checkpoint manager))
  (gr8s.store::write-text-atomically
   (node-resource-manager-checkpoint manager)
   (com.inuoe.jzon:stringify (core-object "version" 1 "config" (resource-manager-config manager)
                                         "allocations" (node-resource-manager-allocations manager))))
  ;; KubeVirt reads policyName from this conventional path to discover CPUManager.
  ;; This is a compatibility report; allocations.json remains authoritative.
  (when (node-resource-manager-cpu-state-path manager)
    (let ((entries (core-object)))
      (maphash (lambda (uid plan)
                 (let ((containers (core-object)))
                   (maphash (lambda (name allocation)
                              (when (plusp (length (gethash "cpus" allocation #())))
                                (setf (gethash name containers) (format-cpu-set (coerce (gethash "cpus" allocation) 'list)))))
                            (gethash "containers" plan))
                   (when (plusp (hash-table-count containers)) (setf (gethash uid entries) containers))))
               (node-resource-manager-allocations manager))
      (ensure-directories-exist (node-resource-manager-cpu-state-path manager))
      (gr8s.store::write-text-atomically
       (node-resource-manager-cpu-state-path manager)
       (com.inuoe.jzon:stringify (core-object "policyName" (node-resource-manager-policy manager)
                                             "defaultCpuSet" (format-cpu-set (resource-shared-cpus manager)) "entries" entries))))))

(defun make-node-resource-manager (directory &key (policy "none") (topology-policy "none") reserved-cpus
                                                 topology devices runtime store cpu-state-path)
  "Restore only checkpoints matching the configured policies and physical topology."
  (unless (member policy '("none" "static") :test #'equal) (error "Unsupported CPU manager policy ~A" policy))
  (unless (member topology-policy '("none" "single-numa-node") :test #'equal) (error "Unsupported topology manager policy ~A" topology-policy))
  (let* ((topology (or topology (discover-resource-topology)))
         (online (coerce (gethash "online" topology) 'list)) (reserved (parse-cpu-set (or reserved-cpus "")))
         (manager (%make-node-resource-manager
                   :topology topology :policy policy :topology-policy topology-policy :reserved reserved
                   :devices devices :runtime runtime :store store :cpu-state-path cpu-state-path
                   :checkpoint (merge-pathnames "resources/allocations.json" (uiop:ensure-directory-pathname directory)))))
    (unless (subsetp reserved online) (error "Reserved CPUs must be online"))
    (when (and (equal policy "static") (or (null reserved) (= (length reserved) (length online))))
      (error "Static CPU policy requires --reserved-cpus and at least one exclusive CPU"))
    (setf (node-resource-manager-checkpoint-present-p manager) (not (null (probe-file (node-resource-manager-checkpoint manager)))))
    (when (node-resource-manager-checkpoint-present-p manager)
      (let ((root (com.inuoe.jzon:parse (node-resource-manager-checkpoint manager))))
        (unless (and (eql 1 (gethash "version" root)) (hash-table-p (gethash "allocations" root)))
          (error "Invalid resource-manager checkpoint"))
        (unless (gr8s.store::json-value-equal-p (config-without-memory-totals (gethash "config" root))
                                                (config-without-memory-totals (resource-manager-config manager)))
          (when (plusp (hash-table-count (gethash "allocations" root)))
            (error "Resource policies or topology changed with live reservations; drain this node first")))
        (setf (node-resource-manager-allocations manager) (gethash "allocations" root))))
    (validate-resource-checkpoint manager)
    manager))

(defun resource-node-memory-fits-p (manager node requests)
  (loop for resource being the hash-keys of requests using (hash-value requested)
        always (or (not (or (equal resource "memory") (hugepage-size resource)))
                   (<= (+ requested
                          (loop for plan being the hash-values of (node-resource-manager-allocations manager)
                                when (eql node (gethash "node" plan)) sum (gethash resource (gethash "memory" plan) 0)))
                       (topology-node-memory (node-resource-manager-topology manager) node resource)))))

(defun resource-device-node-fits-p (manager pod node)
  "Check concurrent stage demand against healthy, topology-compatible device IDs."
  (let ((devices (node-resource-manager-devices manager)))
    (or (null devices)
        (loop for resource being the hash-keys of (device-plugin-manager-plugins devices) using (hash-value plugin)
              always
              (let* ((foreign (loop for uid being the hash-keys of (device-plugin-manager-allocations devices) using (hash-value containers)
                                    unless (equal uid (pod-uid pod))
                                    append (loop for resources being the hash-values of containers
                                                 append (coerce (gethash "ids" (gethash resource resources (core-object)) #()) 'list))))
                     (available (count-if (lambda (device) (and (equal "Healthy" (dp::health device))
                                                                (not (member (dp::id device) foreign :test #'equal))
                                                                (device-on-numa-node-p device node))) (device-plugin-devices plugin)))
                     (peak (loop for stage in (resource-container-stages (resource-pod-spec pod))
                                 maximize (loop for container in stage sum (resource-container-request container resource)))))
                (and (>= available peak)
                     (loop for resources being the hash-values of (gethash (pod-uid pod) (device-plugin-manager-allocations devices) (core-object))
                           for reservation = (gethash resource resources)
                           always (or (null reservation)
                                      (every (lambda (id) (let ((device (find id (device-plugin-devices plugin) :key #'dp::id :test #'equal)))
                                                           (and device (device-on-numa-node-p device node))))
                                             (gethash "ids" reservation))))))))))

(defun resource-node-shared-cpus-fit-p (manager pod node pool pod-pool-p)
  "A NUMA-pinned shared container must retain at least one runnable CPU."
  (or (not (equal "static" (node-resource-manager-policy manager)))
      (let ((needed (or (and (not pod-pool-p)
                             (some (lambda (c) (zerop (resource-exclusive-count manager (resource-pod-spec pod) c)))
                                   (resource-pod-containers pod)))
                        (loop for plan being the hash-values of (node-resource-manager-allocations manager)
                              thereis (and (eql node (gethash "node" plan))
                                           (loop for allocation being the hash-values of (gethash "containers" plan)
                                                 thereis (zerop (length (gethash "cpus" allocation)))))))))
        (or (not needed)
            (set-difference (intersection (resource-shared-cpus manager)
                                          (topology-node-cpus (node-resource-manager-topology manager) node)) pool)))))

(defun plan-node-pod-resources (manager pod)
  "Choose a common affinity and stage reusable CPU pool while the manager lock is held."
  (let* ((spec (resource-pod-spec pod)) (stages (resource-container-stages spec))
         (count (loop for stage in stages maximize (loop for c in stage sum (resource-exclusive-count manager spec c))))
         (pod-cpu (let ((resources (gethash "resources" spec)))
                    (resource-container-request (core-object "resources" resources) "cpu")))
         (pod-pool-p (and (equal "static" (node-resource-manager-policy manager))
                          (equal "Guaranteed" (pod-spec-qos-class spec)) (integerp pod-cpu) (plusp pod-cpu)))
         (count (if pod-pool-p (max count pod-cpu) count))
         (available (sort (set-difference (resource-shared-cpus manager) (node-resource-manager-reserved manager)) #'<))
         (strict (equal "single-numa-node" (node-resource-manager-topology-policy manager)))
         (requests (pod-spec-resource-totals spec))
         (candidates (if strict (topology-node-ids (node-resource-manager-topology manager)) (list nil)))
         (node nil) (pool nil) (found nil) (containers (core-object)) (memory (core-object)))
    (dolist (candidate candidates)
      (let ((local (if strict (intersection available (topology-node-cpus (node-resource-manager-topology manager) candidate)) available)))
        (when (and (>= (length local) count)
                   (or (not strict) (and (resource-node-memory-fits-p manager candidate requests)
                                          (resource-device-node-fits-p manager pod candidate)
                                          (resource-node-shared-cpus-fit-p manager pod candidate
                                                                           (subseq (sort (copy-list local) #'<) 0 count) pod-pool-p))))
          (setf node candidate pool (subseq (sort local #'<) 0 count) found t)
          (return))))
    (unless found (reject-node-resource-admission (if strict "TopologyAffinityError" "OutOfcpu")
                                            "No common CPU, memory, hugepage and device placement is available for ~A/~A"
                                            (pod-namespace pod) (pod-name pod)))
    ;; Init containers may reuse the final application pool; restartable init
    ;; containers keep their slice in every stage after they start.
    (dolist (stage stages)
      (let* ((fixed (loop for c in stage for old = (gethash (gethash "name" c) containers)
                          when old append (coerce (gethash "cpus" old #()) 'list)))
             (remaining (set-difference pool fixed)))
        (dolist (container stage)
          (let* ((name (gethash "name" container)) (n (resource-exclusive-count manager spec container)))
            (unless (gethash name containers)
              (let ((selected (subseq (sort remaining #'<) 0 n)))
                (setf remaining (set-difference remaining selected)
                      (gethash name containers) (core-object "cpus" (coerce selected 'vector) "memory" (core-object)))))))
        ))
    (when pod-pool-p
      (dolist (container (resource-pod-containers pod))
        (let* ((name (gethash "name" container)) (allocation (gethash name containers)))
          (when (zerop (length (gethash "cpus" allocation)))
            (let* ((concurrent (remove-duplicates
                                (loop for stage in stages when (find container stage)
                                      append (loop for other in stage
                                                   append (coerce (gethash "cpus" (gethash (gethash "name" other) containers)) 'list)))))
                   (shared (sort (set-difference pool concurrent) #'<)))
              (unless shared (reject-node-resource-admission "OutOfcpu" "Pod CPU budget leaves no CPUs for its shared containers"))
              (setf (gethash "cpus" allocation) (coerce shared 'vector)
                    (gethash "shared" allocation) t))))))
    (when strict
      (maphash (lambda (resource amount)
                 (when (or (equal resource "memory") (hugepage-size resource)) (setf (gethash resource memory) amount))) requests)
      (dolist (container (resource-pod-containers pod))
        (let ((allocation (gethash (gethash "name" container) containers)))
          (maphash (lambda (resource amount)
                     (declare (ignore amount))
                     (let ((requested (resource-container-request container resource)))
                       (when (plusp requested) (setf (gethash resource (gethash "memory" allocation)) requested)))) memory))))
    (core-object "node" node "cpus" (coerce pool 'vector) "memory" memory "containers" containers "requests" (resource-request-snapshot spec)
                 "containerRequests" (resource-container-request-snapshot pod)
                 "podLevelMemory" (if (and strict (gethash "memory" (or (pod-level-resource-list spec "requests") (core-object)))) t :false)
                 "podLevel" (if pod-pool-p t :false))))

(defun prepare-node-pod-resources (manager pod)
  "Reserve all providers durably, then exclude new dedicated CPUs from shared containers."
  ;; Snapshot application can admit a Pod before the periodic worker runs.
  (when (and (node-resource-manager-runtime manager) (node-resource-manager-store manager))
    (reconcile-node-resource-manager manager :repair nil))
  (bt:with-lock-held ((node-resource-manager-lock manager))
    (unless (gethash (pod-uid pod) (node-resource-manager-allocations manager))
      (let* ((devices (node-resource-manager-devices manager))
             (plan (if devices
                       (bt:with-lock-held ((device-plugin-manager-allocation-lock devices))
                         (bt:with-lock-held ((device-plugin-manager-lock devices)) (plan-node-pod-resources manager pod)))
                       (plan-node-pod-resources manager pod))))
        (when devices
          (reserve-pod-plugin-devices devices pod (gethash "node" plan)))
        (setf (gethash (pod-uid pod) (node-resource-manager-allocations manager)) plan)))
    (save-node-resource-checkpoint manager)
    (when (or (equal "static" (node-resource-manager-policy manager))
              (equal "single-numa-node" (node-resource-manager-topology-policy manager)))
      (reconcile-node-cpu-sets manager)))
  t)

(defun node-container-resources (manager pod container &optional resources)
  "Overlay CPU/memory affinities on every CRI create and update, including resize."
  (let* ((resources (or resources (cri-linux-container-resources
                                 (container-with-pod-level-limits (resource-pod-spec pod) container))))
         (plan (gethash (pod-uid pod) (node-resource-manager-allocations manager)))
         (allocation (and plan (gethash (gethash "name" container) (gethash "containers" plan))))
         (debug (find (gethash "name" container) (gethash "ephemeralContainers" (resource-pod-spec pod) #())
                      :key (lambda (entry) (gethash "name" entry)) :test #'equal))
         (target (and debug plan (gethash (gethash "targetContainerName" debug)
                                          (gethash "containers" plan))))
         ;; Debug containers consume no new reservation. They share the target
         ;; container or the Pod's existing dedicated pool, never a foreign Pod's CPUs.
         (cpus (or (and allocation (coerce (gethash "cpus" allocation #()) 'list))
                   (and debug plan (coerce (or (and target (gethash "cpus" target)) (gethash "cpus" plan)) 'list))))
         (node (and plan (gethash "node" plan))))
    (when (equal "static" (node-resource-manager-policy manager))
      (let ((shared (resource-shared-cpus manager)))
        (when node (setf shared (intersection shared (topology-node-cpus (node-resource-manager-topology manager) node))))
        (unless (or cpus shared) (reject-node-resource-admission "OutOfcpu" "NUMA affinity has no shared CPUs"))
        (setf (gr8s.cri.v1::cpuset-cpus resources) (format-cpu-set (or cpus shared)))))
    (when node (setf (gr8s.cri.v1::cpuset-mems resources) (write-to-string node)))
    ;; Prioritise OOM kills by QoS the way the kubelet does, so the kernel
    ;; sacrifices BestEffort before Burstable before Guaranteed under memory
    ;; pressure instead of treating every container's default score of 0 alike.
    (setf (gr8s.cri.v1::oom-score-adj resources)
          (container-oom-score-adj (pod-spec-qos-class (resource-pod-spec pod))
                                   container (node-memory-capacity-bytes)))
    resources))

(defun update-node-container-affinity (manager pod container id)
  "A container may exit between ListContainers and UpdateContainerResources."
  (let ((socket (containerd-runtime-socket-path (node-resource-manager-runtime manager))))
    (handler-case
        (cri-update-container-resources socket id (node-container-resources manager pod container))
      (error (failure)
        (multiple-value-bind (status absent)
            (handler-case (values (cri-container-status socket id) nil)
              (ag-grpc:grpc-status-error (condition)
                (values nil (= ag-grpc:+grpc-status-not-found+ (ag-grpc:grpc-status-error-code condition))))
              (error () (values nil nil)))
          (unless (or absent (and status (= gr8s.cri.v1::+containerstate-container_exited+ (cri-container-info-state status))))
            (error failure)))))))

(defun repair-node-cpu-sets (manager)
  "Periodic/release repair must leave lifecycle cleanup able to make progress.
Admission still calls the strict reconciler before starting a dedicated container."
  (handler-case (reconcile-node-cpu-sets manager)
    (error (condition) (format *error-output* "gr8s CPU affinity repair will retry: ~A~%" condition))))

(defun reconcile-node-cpu-sets (manager)
  "Apply affinities to existing live containers before admitting exclusive work."
  (let ((runtime (node-resource-manager-runtime manager)) (store (node-resource-manager-store manager)))
    (when (and runtime store)
      (dolist (pod (list-pods store))
        (let ((sandbox (containerd-owned-sandbox runtime (pod-uid pod))))
          (when sandbox
            (dolist (summary (containerd-containers runtime sandbox))
              (when (= gr8s.cri.v1::+containerstate-container_running+ (cri-container-summary-state summary))
                (let ((container (find (cdr (assoc +gr8s-container-label+ (cri-container-summary-labels summary) :test #'equal))
                                       (append (resource-pod-containers pod)
                                               (coerce (gethash "ephemeralContainers" (resource-pod-spec pod) #()) 'list))
                                       :key (lambda (c) (gethash "name" c)) :test #'equal)))
                  (when container
                    (let* ((state (load-container-lifecycle-state runtime (pod-uid pod)))
                           (entry (gethash (gethash "name" container) (gethash "containers" state)))
                           (applied (and entry (gethash "appliedResources" entry))))
                      (when applied
                        (setf container (copy-core-object container) (gethash "resources" container) applied)))
                    (update-node-container-affinity manager pod container (cri-container-summary-id summary))))))))))))

(defun release-node-pod-resources (manager pod)
  "Return CPUs and NUMA reservations only after native cleanup has completed."
  (bt:with-lock-held ((node-resource-manager-lock manager))
    (when (remhash (pod-uid pod) (node-resource-manager-allocations manager))
      (save-node-resource-checkpoint manager)
      (repair-node-cpu-sets manager))))

(defun node-resource-capacity-entries (manager &key allocatable)
  "Report actual capacity, subtracting explicit CPU reservations from allocatable."
  (when manager
    (let* ((topology (node-resource-manager-topology manager))
           (cpus (length (gethash "online" topology)))
           (memory (loop for node in (topology-node-ids topology) sum (topology-node-memory topology node "memory")))
           (capacity (node-reported-capacity)))
      (setf (gethash "cpu" capacity) (write-to-string (if allocatable (- cpus (length (node-resource-manager-reserved manager))) cpus))
            (gethash "memory" capacity) (write-to-string memory))
      (loop for name being the hash-keys of capacity using (hash-value amount) collect (cons name amount)))))

(defun node-resource-resize-verdict (manager pod)
  "Affinity reservations remain immutable for a UID; require replacement to resize them."
  (bt:with-lock-held ((node-resource-manager-lock manager))
    (let ((plan (gethash (pod-uid pod) (node-resource-manager-allocations manager))))
      (when (and plan
                 (or (plusp (length (gethash "cpus" plan))) (gethash "node" plan))
                 (or (not (gr8s.store::json-value-equal-p (gethash "requests" plan) (resource-request-snapshot (resource-pod-spec pod))))
                     (not (gr8s.store::json-value-equal-p (gethash "containerRequests" plan) (resource-container-request-snapshot pod)))))
        (values "Infeasible" "Replace this Pod to change its dedicated CPU or NUMA reservation")))))

(defun resource-container-executing-p (runtime summary)
  "Only an authoritative Exited/NotFound result permits releasing an affinity."
  (handler-case
      (/= gr8s.cri.v1::+containerstate-container_exited+
          (cri-container-info-state (cri-container-status (containerd-runtime-socket-path runtime) (cri-container-summary-id summary))))
    (ag-grpc:grpc-status-error (condition) (/= ag-grpc:+grpc-status-not-found+ (ag-grpc:grpc-status-error-code condition)))
    (error () t)))

(defun reconcile-node-resource-manager (manager &key (repair t))
  "Release terminal reservations only after no assigned container can execute."
  (when manager
    (bt:with-lock-held ((node-resource-manager-lock manager))
      (let* ((store (node-resource-manager-store manager)) (runtime (node-resource-manager-runtime manager))
             (pods (list-pods store)) (released nil))
        (maphash
         (lambda (uid plan)
           (declare (ignore plan))
           (let ((pod (find uid pods :key #'pod-uid :test #'equal)))
             (when (or (null pod) (deletion-requested-p pod) (terminal-pod-phase-p (gethash "phase" (or (pod-observed-status store pod) (core-object)))))
               (let ((sandbox (containerd-owned-sandbox runtime uid)))
                 (unless (and sandbox (some (lambda (summary) (resource-container-executing-p runtime summary))
                                            (containerd-containers runtime sandbox)))
                   (push uid released)
                   (when (and pod (node-resource-manager-devices manager))
                     (release-plugin-devices (node-resource-manager-devices manager) pod)))))))
         (node-resource-manager-allocations manager))
        (dolist (uid released) (remhash uid (node-resource-manager-allocations manager)))
        (when released (save-node-resource-checkpoint manager))
        (when (and repair (equal "static" (node-resource-manager-policy manager))) (repair-node-cpu-sets manager))))))

(defun validate-resource-checkpoint (manager)
  "Fail closed on malformed, overlapping, offline or reserved CPU assignments."
  (let ((seen nil) (online (coerce (gethash "online" (node-resource-manager-topology manager)) 'list)))
    (maphash
     (lambda (uid plan)
       (declare (ignore uid))
       (unless (and (hash-table-p plan) (vectorp (gethash "cpus" plan))
                    (hash-table-p (gethash "containers" plan)) (hash-table-p (gethash "requests" plan)))
         (error "Invalid allocation in resource checkpoint"))
       (let ((pool (coerce (gethash "cpus" plan) 'list)) (node (gethash "node" plan)))
         (unless (and (every (lambda (cpu) (and (integerp cpu) (member cpu online))) pool)
                      (= (length pool) (length (remove-duplicates pool)))
                      (not (intersection pool seen)) (not (intersection pool (node-resource-manager-reserved manager)))
                      (or (null node) (member node (topology-node-ids (node-resource-manager-topology manager)))))
           (error "Invalid or overlapping CPU affinity in resource checkpoint"))
         (setf seen (append pool seen))
         (maphash (lambda (name allocation)
                    (declare (ignore name))
                    (unless (and (hash-table-p allocation) (vectorp (gethash "cpus" allocation))
                                 (subsetp (coerce (gethash "cpus" allocation) 'list) pool))
                      (error "Container affinity is outside its checkpointed Pod CPU pool")))
                  (gethash "containers" plan))))
     (node-resource-manager-allocations manager))
    ;; A node's memory total is not part of the configuration compared at
    ;; restore, so a node that shrank below what is pinned to it is caught here.
    (dolist (node (topology-node-ids (node-resource-manager-topology manager)))
      (let ((pinned (loop for plan being the hash-values of (node-resource-manager-allocations manager)
                          when (and (eql node (gethash "node" plan)) (hash-table-p (gethash "memory" plan)))
                            sum (gethash "memory" (gethash "memory" plan) 0))))
        (unless (<= pinned (topology-node-memory (node-resource-manager-topology manager) node "memory"))
          (error "NUMA node ~D no longer has the memory reserved on it; drain this node first" node))))))

(defun verify-node-resource-recovery (manager)
  "Refuse to reset affinity for live containers when its authoritative file is missing."
  (when (and (not (node-resource-manager-checkpoint-present-p manager))
             (node-resource-manager-runtime manager)
             (or (equal "static" (node-resource-manager-policy manager))
                 (equal "single-numa-node" (node-resource-manager-topology-policy manager)))
             (some (lambda (summary) (= gr8s.cri.v1::+containerstate-container_running+ (cri-container-summary-state summary)))
                   (cri-list-containers (containerd-runtime-socket-path (node-resource-manager-runtime manager))
                                        :labels (list (cons +gr8s-managed-label+ "true")))))
    (error "Resource checkpoint is missing while managed containers are running; drain this node before resetting affinity")))

(defun node-pod-device-config (manager pod container)
  "Carry the admitted affinity through late registration and every Allocate retry."
  (let ((node (bt:with-lock-held ((node-resource-manager-lock manager))
                (let ((plan (gethash (pod-uid pod) (node-resource-manager-allocations manager))))
                  (unless plan (device-plugin-error "Pod has no resource admission reservation"))
                  (gethash "node" plan)))))
    (device-plugin-container-config (node-resource-manager-devices manager) pod container :numa-node node)))
