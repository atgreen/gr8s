;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Persist controller Pod-pool settings independently of Pod objects, validate
;;;; allocation geometry and preserve existing node assignments across restarts.
;;;; Host-route validation is shared with agent network configuration.

(in-package #:gr8s)

(defun make-node-pool-config (cidr node-prefix)
  "Construct the versioned on-disk pool configuration object."
  (json-object "version" 1 "clusterPodCIDR" cidr "nodePrefix" node-prefix))

(defun validate-node-pool-config (configuration)
  "Validate canonical IPv4 pool geometry and reserved-address exclusions."
  (unless (and (hash-table-p configuration) (eql 1 (gethash "version" configuration)))
    (invalid-cni "invalid Pod-pool configuration format"))
  (let ((cidr (gethash "clusterPodCIDR" configuration))
        (node-prefix (gethash "nodePrefix" configuration)))
    (unless (stringp cidr) (invalid-cni "cluster Pod CIDR must be a string"))
    (multiple-value-bind (address prefix) (validate-network-cidr cidr)
      (unless (string= cidr (format nil "~A/~D" (format-ipv4-integer address) prefix))
        (invalid-cni "cluster Pod CIDR must be canonical"))
      (unless (and (typep node-prefix '(integer 1 30)) (<= prefix node-prefix))
        (invalid-cni "node Pod prefix /~A does not fit pool ~A" node-prefix cidr)))
    (dolist (reserved '("0.0.0.0/8" "127.0.0.0/8" "169.254.0.0/16" "224.0.0.0/4"
                        "240.0.0.0/4" "10.96.0.1/32"))
      (when (ipv4-prefixes-overlap-p cidr reserved)
        (invalid-cni "Pod pool ~A overlaps reserved range ~A" cidr reserved))))
  configuration)

(defun node-pool-settings-equal-p (left right)
  "Compare the immutable allocation geometry of two pool configurations."
  (and (string= (gethash "clusterPodCIDR" left) (gethash "clusterPodCIDR" right))
       (= (gethash "nodePrefix" left) (gethash "nodePrefix" right))))

(defun validate-node-pool-assignments (configuration nodes)
  "Reject persisted node blocks outside the configured fixed-size pool."
  (dolist (node nodes)
    (let ((cidr (node-record-pod-cidr node)))
      (multiple-value-bind (address prefix) (validate-network-cidr cidr)
        (declare (ignore address))
        (unless (and (= prefix (gethash "nodePrefix" configuration))
                     (network-cidr-subnet-p cidr (gethash "clusterPodCIDR" configuration)))
          (invalid-cni "node ~A has Pod CIDR ~A incompatible with the configured pool"
                       (node-record-name node) cidr))))))

(defun legacy-node-pool-config (nodes)
  "Recognize the previously shipped /16 pool with /24 node allocations."
  (when nodes
    (let ((legacy (make-node-pool-config "10.88.0.0/16" 24)))
      (handler-case
          (progn (validate-node-pool-assignments legacy nodes) legacy)
        (cni-error () nil)))))

(defun persisted-node-route-identities (state-directory)
  "Derive allowed route/link identities from this agent's durable local journal."
  (let* ((root (uiop:ensure-directory-pathname state-directory))
         (ipam-path (merge-pathnames "ipam/allocations.json" root))
         (ipam (when (probe-file ipam-path) (com.inuoe.jzon:parse ipam-path)))
         (result nil))
    (dolist (file '("network.json" "network-pending.json"))
      (let ((network (read-node-network-file (merge-pathnames file root))))
        (when network
          (validate-node-network-object network)
          (when ipam
            (unless (and (eql 1 (gethash "version" ipam))
                         (string= (gethash "cidr" ipam "") (gethash "nodePodCIDR" network)))
              (invalid-cni "durable IPAM does not match the node network journal"))
            (loop for allocation across (gethash "allocations" ipam #())
                  for context = (make-cni-context
                                 :container-id (required-cni-string allocation "sandboxID")
                                 :interface-name (required-cni-string allocation "interfaceName"))
                  for address = (required-cni-string allocation "address")
                  for owner = (routed-cni-owner context)
                  do (unless (and (safe-cni-container-id-p (cni-context-container-id context))
                                  (ipv4-prefixes-overlap-p (format nil "~A/32" address)
                                                           (gethash "nodePodCIDR" network)))
                       (invalid-cni "invalid durable Pod allocation in route ownership journal"))
                     (push (list :cidr (format nil "~A/32" address)
                                 :name (routed-cni-host-name context) :owner owner :kind "veth"
                                 :mac (routed-veth-mac owner "host")) result)))
          (unless (string= "" (gethash "underlayAddress" network))
            (dolist (cidr (cons (format nil "~A/32" (vxlan-router-address (gethash "nodePodCIDR" network)))
                               (loop for route across (gethash "routes" network #())
                                     append (list (gethash "podCIDR" route)
                                                  (format nil "~A/32" (vxlan-router-address (gethash "podCIDR" route)))))))
              (push (list :cidr cidr :name +node-vxlan-interface+
                          :owner (node-vxlan-owner network) :kind "vxlan"
                          :mac (vxlan-router-mac (gethash "nodePodCIDR" network))
                          :network network) result))))))
    result))

(defun route-link-matches-identity-p (attributes identity)
  "Match an allowed route against the actual kernel link's ownership and type."
  (and (equalp (gethash 3 attributes) (netlink-string (getf identity :name)))
       (network-link-kind-p attributes (getf identity :kind))
       (equalp (gethash 1 attributes) (getf identity :mac))
       (or (equalp (gethash 20 attributes) (netlink-string (getf identity :owner)))
           (network-link-untagged-p attributes))
       (let ((network (getf identity :network)))
         (or (not network)
             (let* ((info (netlink-attributes (gethash 18 attributes) 0))
                    (vxlan (netlink-attributes (gethash 2 info) 0)))
               (and (equalp (gethash 1 vxlan) (netlink-integer (gethash "vni" network) 4))
                    (equalp (gethash 4 vxlan) (ipv4-network-octets (gethash "underlayAddress" network)))
                    (equalp (gethash 15 vxlan) #(18 181))))))))

(defun validate-pod-pool-host-routes
    (cidr state-directory &key (route-reader #'read-ipv4-host-routes)
                              (link-reader #'network-link-attributes-by-index))
  "Reject overlapping host routes, allowing only exact journal-owned dataplane routes.
This runs while Pods come and go. A Pod's lease outlives its route both ways: ADD persists
the lease before installing the route, and DEL removes the route before releasing the lease.
So reading the journal on both sides of the route dump finds the lease of any Pod route in
it, and an owned route whose link has since gone left with its link."
  (let* ((before (persisted-node-route-identities state-directory))
         (routes (funcall route-reader))
         (owned (append before (persisted-node-route-identities state-directory))))
    (dolist (route routes)
      (when (and (plusp (nth-value 1 (parse-ipv4-cidr (getf route :cidr))))
                 (ipv4-prefixes-overlap-p cidr (getf route :cidr)))
        (let ((identities (remove-if-not
                           (lambda (item) (string= (getf route :cidr) (getf item :cidr))) owned)))
          (unless (and identities (plusp (getf route :index 0))
                       (let ((attributes (handler-case (funcall link-reader (getf route :index))
                                           (rtnetlink-error (condition)
                                             (if (= 19 (rtnetlink-error-errno condition)) :gone nil)))))
                         (or (eq :gone attributes)
                             (and attributes
                                  (some (lambda (identity) (route-link-matches-identity-p attributes identity))
                                        identities)))))
            (invalid-cni "Pod pool ~A overlaps host route ~A in table ~A"
                         cidr (getf route :cidr) (getf route :table)))))))
  t)

(defun ensure-controller-node-pool
    (store state-directory options &key (route-reader #'read-ipv4-host-routes)
                                        (link-reader #'network-link-attributes-by-index))
  "Load or persist pool geometry, preserving every existing node assignment."
  (let* ((path (merge-pathnames "network/pool.json"
                                (uiop:ensure-directory-pathname state-directory)))
         (stored (when (probe-file path) (com.inuoe.jzon:parse path)))
         ;; A Node created through the API runs no Pods and holds no block.
         (nodes (remove-if #'node-record-api-only (list-nodes store)))
         (legacy (and (not stored) (legacy-node-pool-config nodes)))
         (base (or stored legacy
                   (make-node-pool-config +default-cluster-pod-cidr+ +default-node-pod-prefix+))))
    (when (and nodes (not stored) (not legacy)
               (not (and (getf options :cluster-pod-cidr-supplied-p)
                         (getf options :node-pod-prefix-supplied-p))))
      (invalid-cni "existing custom node allocations require explicit pool CIDR and node prefix"))
    (validate-node-pool-config base)
    (let ((configuration
            (validate-node-pool-config
             (make-node-pool-config
              (if (getf options :cluster-pod-cidr-supplied-p)
                  (getf options :cluster-pod-cidr) (gethash "clusterPodCIDR" base))
              (if (getf options :node-pod-prefix-supplied-p)
                  (getf options :node-pod-prefix) (gethash "nodePrefix" base))))))
      (when (and nodes (or stored legacy)
                 (not (node-pool-settings-equal-p configuration base)))
        (invalid-cni "refusing to change Pod-pool geometry while node allocations exist"))
      (validate-node-pool-assignments configuration nodes)
      (validate-pod-pool-host-routes
       (gethash "clusterPodCIDR" configuration)
       (merge-pathnames "agent/runtime/" (uiop:ensure-directory-pathname state-directory))
       :route-reader route-reader :link-reader link-reader)
      (unless (and stored (node-pool-settings-equal-p stored configuration))
        (write-private-text-atomically path (com.inuoe.jzon:stringify configuration)))
      configuration)))
