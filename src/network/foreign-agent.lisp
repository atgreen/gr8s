;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The foreign-cluster CNI node agent (docs/design-foreign-cluster-networking.md,
;;;; podster-982.3).
;;;;
;;;; On a cluster whose kubelet and container runtime are not gr8s's, this agent
;;;; owns only the network slice of a node: it serves the gr8s CNI plugin's Unix
;;;; socket, allocates Pod addresses from the node's own podCIDR, wires routed
;;;; veths, and keeps every local Pod's Whistler NetworkPolicy guard maps fed
;;;; from the cluster's NetworkPolicies, Namespaces and Pods -- all read through
;;;; the desired-state seam over a FOREIGN-RESOURCE-VIEW.  It never creates,
;;;; deletes or observes Pods; the foreign kubelet owns their lifecycle.

(in-package #:gr8s.network)

(defstruct (foreign-cni-agent (:constructor %make-foreign-cni-agent))
  "One node's foreign-cluster CNI service and its policy convergence loop."
  view node-name ipam bpf-root server
  (lock (bt:make-lock "gr8s foreign CNI agent"))
  (wake (bt:make-condition-variable :name "gr8s foreign CNI agent wake"))
  (pending t) (running t)
  converge-thread policy-converger policy-writer)

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
  (bt:with-lock-held ((foreign-cni-agent-lock agent))
    (setf (foreign-cni-agent-pending agent) t)
    (bt:condition-notify (foreign-cni-agent-wake agent))))

(defun foreign-agent-endpoints (agent)
  "Every local Pod endpoint (SANDBOX INTERFACE ADDRESS) the agent's IPAM holds."
  (let ((ipam (foreign-cni-agent-ipam agent)))
    (bt:with-lock-held ((node-ipam-lock ipam))
      (loop for key being the hash-keys of (node-ipam-allocations ipam)
              using (hash-value addresses)
            collect (list (car key) (cdr key) (first addresses))))))

(defun foreign-agent-converge (agent)
  "Write every local Pod's resolved NetworkPolicy into its pinned guard maps."
  (let* ((view (foreign-cni-agent-view agent))
         (root (foreign-cni-agent-bpf-root agent))
         (specs (network-policy-specs-from-objects
                 (gr8s.resources::list-core-resources view "networkpolicies")))
         (ip-map (pod-ip-identity-map view)))
    (funcall (foreign-cni-agent-policy-converger agent)
             specs (foreign-agent-endpoints agent)
             :pod-finder (lambda (address) (gethash address ip-map))
             :directory-fn (lambda (sandbox) (nth-value 2 (cni-pin-paths root sandbox)))
             :writer (foreign-cni-agent-policy-writer agent))))

(defun foreign-agent-converge-loop (agent)
  (loop while (foreign-cni-agent-running agent)
        do (bt:with-lock-held ((foreign-cni-agent-lock agent))
             (loop until (or (foreign-cni-agent-pending agent)
                             (not (foreign-cni-agent-running agent)))
                   do (bt:condition-wait (foreign-cni-agent-wake agent)
                                         (foreign-cni-agent-lock agent)))
             (setf (foreign-cni-agent-pending agent) nil))
           (when (foreign-cni-agent-running agent)
             (handler-case (foreign-agent-converge agent)
               (error (condition)
                 (format *error-output* "~&gr8s foreign CNI agent: policy convergence failed: ~A~%"
                         condition))))))

(defun start-foreign-cni-agent
    (cluster &key node-name state-directory bpf-root socket-path
                  (mtu 1450) operations-factory
                  (policy-converger #'converge-pod-network-policies)
                  (policy-writer #'write-pod-network-policy)
                  (stop-predicate (constantly nil)))
  "Start the foreign-cluster CNI agent against CLUSTER and return it, serving CNI
requests on SOCKET-PATH with addresses from this node's podCIDR and NetworkPolicy
converged into the guard maps under BPF-ROOT.  OPERATIONS-FACTORY receives the
agent's IPAM and returns the CNI operations, overriding the routed dataplane
(tests); POLICY-CONVERGER and POLICY-WRITER override the map writes."
  (let* ((agent (%make-foreign-cni-agent
                 :node-name node-name :bpf-root bpf-root
                 :policy-converger policy-converger :policy-writer policy-writer))
         (view (gr8s.resources::make-foreign-resource-view
                cluster
                :on-change (lambda (resource change key object)
                             (declare (ignore change key object))
                             (when (member resource '("pods" "namespaces" "networkpolicies")
                                           :test #'equal)
                               (foreign-agent-nudge agent))))))
    (setf (foreign-cni-agent-view agent) view)
    (let ((node (foreign-agent-wait-for-node view node-name stop-predicate)))
      (unless node
        (gr8s.resources::stop-foreign-resource-view view)
        (return-from start-foreign-cni-agent nil))
      (handler-case
          (progn
            (setf (foreign-cni-agent-ipam agent)
                  (open-node-ipam (uiop:ensure-directory-pathname state-directory)
                                  (foreign-node-pod-cidrs node))
                  (foreign-cni-agent-server agent)
                  (let ((operations
                          (if operations-factory
                              (funcall operations-factory (foreign-cni-agent-ipam agent))
                              (make-routed-cni-operations
                               (foreign-cni-agent-ipam agent)
                               :node-id node-name :mtu mtu))))
                    (start-agent-cni-server
                     socket-path
                     (lambda (request)
                       (prog1 (handle-agent-cni-request request :operations operations)
                         ;; A new or departed endpoint changes which guards exist.
                         (foreign-agent-nudge agent)))))
                  (foreign-cni-agent-converge-thread agent)
                  (bt:make-thread (lambda () (foreign-agent-converge-loop agent))
                                  :name "gr8s foreign CNI agent policy"))
            agent)
        (error (condition)
          (stop-foreign-cni-agent agent)
          (error condition))))))

(defun stop-foreign-cni-agent (agent)
  "Stop AGENT's CNI server, convergence loop and informers."
  (bt:with-lock-held ((foreign-cni-agent-lock agent))
    (setf (foreign-cni-agent-running agent) nil)
    (bt:condition-notify (foreign-cni-agent-wake agent)))
  (let ((server (foreign-cni-agent-server agent)))
    (when server (ignore-errors (stop-agent-cni-server server))))
  (let ((thread (foreign-cni-agent-converge-thread agent)))
    (when (and thread (bt:thread-alive-p thread))
      (ignore-errors (bt:join-thread thread))))
  (let ((view (foreign-cni-agent-view agent)))
    (when view (ignore-errors (gr8s.resources::stop-foreign-resource-view view))))
  nil)

(defun run-foreign-cni-agent (cluster &rest options &key stop-predicate &allow-other-keys)
  "Run the foreign CNI agent until STOP-PREDICATE returns true."
  (let ((agent (apply #'start-foreign-cni-agent cluster options)))
    (when agent
      (unwind-protect
           (loop until (funcall stop-predicate) do (sleep 1))
        (stop-foreign-cni-agent agent)))))
