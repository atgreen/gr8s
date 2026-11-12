;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Persist controller Pod-pool settings independently of Pod objects, validate
;;;; allocation geometry and preserve existing node assignments across restarts.
;;;; Host-route validation is shared with agent network configuration.

(in-package #:gr8s.agent)

(defun make-node-pool-config (cidr node-prefix &optional (cidrs (vector cidr)) (node-prefixes (vector node-prefix)))
  "Construct the versioned on-disk pool configuration object."
  (json-object "version" 1
               "clusterPodCIDR" cidr "nodePrefix" node-prefix
               "clusterPodCIDRs" (coerce cidrs 'vector)
               "nodePrefixes" (coerce node-prefixes 'vector)))

(defun node-pool-cluster-cidrs (configuration)
  "Return CONFIGURATION's ordered families, including legacy pool files."
  (let ((cidrs (gethash "clusterPodCIDRs" configuration)))
    (if (and (vectorp cidrs) (plusp (length cidrs)))
        cidrs (vector (gethash "clusterPodCIDR" configuration)))))

(defun node-pool-prefixes (configuration)
  "Return CONFIGURATION's ordered per-family node prefixes, including legacy files."
  (let ((prefixes (gethash "nodePrefixes" configuration)))
    (if (and (vectorp prefixes) (plusp (length prefixes)))
        prefixes (vector (gethash "nodePrefix" configuration)))))

(defun validate-node-pool-config (configuration)
  "Validate canonical IPv4 pool geometry and reserved-address exclusions."
  (unless (and (hash-table-p configuration) (eql 1 (gethash "version" configuration)))
    (invalid-cni "invalid Pod-pool configuration format"))
  (let ((cidrs (node-pool-cluster-cidrs configuration))
        (prefixes (node-pool-prefixes configuration)))
    (unless (= (length cidrs) (length prefixes))
      (invalid-cni "cluster Pod CIDRs and node prefixes must have equal lengths"))
    (handler-case
        (multiple-value-bind (normalized-cidrs normalized-prefixes)
            (normalize-pod-pool-geometry cidrs prefixes)
          (declare (ignore normalized-cidrs normalized-prefixes)))
      (error (condition) (invalid-cni "invalid Pod-pool geometry: ~A" condition)))
    (loop for cidr across cidrs for node-prefix across prefixes
          do (handler-case
                 (multiple-value-bind (family address prefix bits) (parse-pod-cidr cidr)
                   (unless (string= cidr (format nil "~A/~D" (format-pod-address family address) prefix))
                     (invalid-cni "cluster Pod CIDR must be canonical"))
                   (unless (and (typep node-prefix `(integer 1 ,(- bits 2)))
                                (<= prefix node-prefix)
                                (zerop (logand address (1- (ash 1 (- bits prefix))))))
                     (invalid-cni "node Pod prefix /~A does not fit pool ~A" node-prefix cidr)))
               (cni-error (condition) (error condition))
               (error (condition) (invalid-cni "invalid Pod pool ~A: ~A" cidr condition))))
    (dolist (reserved '("0.0.0.0/8" "127.0.0.0/8" "169.254.0.0/16" "224.0.0.0/4"
                        "240.0.0.0/4" "10.96.0.1/32" "::/128" "::1/128"
                        "fe80::/10" "ff00::/8"))
      (loop for cidr across cidrs
            when (pod-cidrs-overlap-p cidr reserved)
              do (invalid-cni "Pod pool ~A overlaps reserved range ~A" cidr reserved))))
  configuration)

(defun node-pool-settings-equal-p (left right)
  "Compare the immutable allocation geometry of two pool configurations."
  (and (equalp (node-pool-cluster-cidrs left) (node-pool-cluster-cidrs right))
       (equalp (node-pool-prefixes left) (node-pool-prefixes right))))

(defun validate-node-pool-assignments (configuration nodes)
  "Reject persisted node blocks outside the configured fixed-size pool."
  (dolist (node nodes)
    (let ((assigned (node-record-all-pod-cidrs node))
          (pools (node-pool-cluster-cidrs configuration))
          (prefixes (node-pool-prefixes configuration)))
      (unless (= (length assigned) (length pools))
        (invalid-cni "node ~A has ~D Pod CIDRs, configured pool has ~D"
                     (node-record-name node) (length assigned) (length pools)))
      (loop for cidr across assigned for pool across pools for expected across prefixes
            do (multiple-value-bind (family address prefix bits) (parse-pod-cidr cidr)
                 (declare (ignore address bits))
                 (unless (and (= prefix expected) (pod-cidrs-overlap-p cidr pool))
                   (invalid-cni "node ~A has Pod CIDR ~A incompatible with pool ~A"
                                (node-record-name node) cidr pool)))))))

(defun legacy-node-pool-config (nodes)
  "Recognize the previously shipped /16 pool with /24 node allocations."
  (when nodes
    (let ((legacy (make-node-pool-config "10.88.0.0/16" 24)))
      (handler-case
          (progn (validate-node-pool-assignments legacy nodes) legacy)
        ((or cni-error rtnetlink-error) () nil)))))

(defun persisted-node-route-identities (state-directory)
  "Derive allowed route/link identities from this agent's durable local journal."
  (let* ((root (uiop:ensure-directory-pathname state-directory))
         (ipam-path (merge-pathnames "ipam/allocations.json" root))
         (ipam (probe-file ipam-path))
         (result nil))
    (dolist (file '("network.json" "network-pending.json"))
      (let ((network (read-node-network-file (merge-pathnames file root))))
        (when network
          (validate-node-network-object network)
          (when ipam
            ;; Restore through the central schema validator, including private
            ;; Service leases. Do not maintain a second list of IPAM versions.
            (let* ((network-cidrs (persisted-node-network-cidrs
                                   network "nodePodCIDRs" "nodePodCIDR"))
                   (restored (open-node-ipam (merge-pathnames "ipam/" root) network-cidrs)))
              (loop for key being the hash-keys of (node-ipam-allocations restored)
                      using (hash-value addresses)
                    for context = (make-cni-context :container-id (car key) :interface-name (cdr key))
                    for owner = (routed-cni-owner context)
                    for alias = (gethash key (gr8s.network::node-ipam-service-snat-allocations restored))
                    do (unless (safe-cni-container-id-p (cni-context-container-id context))
                         (invalid-cni "invalid durable Pod owner in route ownership journal"))
                       (dolist (address (append addresses (when alias (list alias))))
                         (push (list :cidr (format nil "~A/~D" address
                                                  (if (find #\: address) 128 32))
                                     :name (routed-cni-host-name context)
                                     :owner owner :kind "veth"
                                     :mac (routed-veth-mac owner "host"))
                               result)))))
          (unless (string= "" (gethash "underlayAddress" network))
            (if (string= "wireguard" (gethash "overlayBackend" network "vxlan"))
                (dolist (cidr (append
                                (loop for local in (persisted-node-network-cidrs
                                                    network "nodePodCIDRs" "nodePodCIDR")
                                      collect (format nil "~A/~D"
                                                      (vxlan-router-address local)
                                                      (if (find #\: local) 128 32)))
                                (loop for route across (gethash "routes" network #())
                                      append (gr8s.network::route-pod-cidrs route))))
                  (push (list :cidr cidr :name +node-wireguard-interface+
                              :owner (node-wireguard-owner network)
                              :kind "wireguard") result))
                (dolist (cidr (append
                                (loop for local in (persisted-node-network-cidrs
                                                    network "nodePodCIDRs" "nodePodCIDR")
                                      collect (format nil "~A/~D"
                                                      (vxlan-router-address local)
                                                      (if (find #\: local) 128 32)))
                                (loop for route across (gethash "routes" network #())
                                      append (loop for peer in (gr8s.network::route-pod-cidrs route)
                                                   append (list peer
                                                                (format nil "~A/~D"
                                                                        (vxlan-router-address peer)
                                                                        (if (find #\: peer) 128 32)))))))
                  (push (list :cidr cidr :name +node-vxlan-interface+
                              :owner (node-vxlan-owner network) :kind "vxlan"
                              :mac (vxlan-router-mac (gethash "nodePodCIDR" network))
                              :network network) result)))))))
    result))

(defun route-link-matches-identity-p (attributes identity)
  "Match an allowed route against the actual kernel link's ownership and type."
  (and (equalp (gethash 3 attributes) (netlink-string (getf identity :name)))
       (network-link-kind-p attributes (getf identity :kind))
       (or (null (getf identity :mac))
           (equalp (gethash 1 attributes) (getf identity :mac)))
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
    (cidr state-directory &key (route-reader #'read-ip-host-routes)
                              (link-reader #'network-link-attributes-by-index))
  "Reject overlapping host routes, allowing only exact journal-owned dataplane routes.
This runs while Pods come and go. A Pod's lease outlives its route both ways: ADD persists
the lease before installing the route, and DEL removes the route before releasing the lease.
So reading the journal on both sides of the route dump finds the lease of any Pod route in
it, and an owned route whose link has since gone left with its link."
  (let* ((cidrs (cond ((stringp cidr) (list cidr))
                      ((vectorp cidr) (coerce cidr 'list))
                      (t cidr)))
         (before (persisted-node-route-identities state-directory))
         (routes (funcall route-reader))
         (owned (append before (persisted-node-route-identities state-directory))))
    (dolist (route routes)
      (when (and (plusp (nth-value 2 (parse-pod-cidr (getf route :cidr))))
                 (some (lambda (pool) (pod-cidrs-overlap-p pool (getf route :cidr)))
                       cidrs))
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
            (invalid-cni "Pod pool ~{~A~^, ~} overlaps host route ~A in table ~A"
                         cidrs (getf route :cidr) (getf route :table)))))))
  t)

(defun ensure-controller-node-pool
    (store state-directory options &key (route-reader #'read-ip-host-routes)
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
             (let* ((cidrs (if (getf options :cluster-pod-cidr-supplied-p)
                               (getf options :cluster-pod-cidrs)
                               (node-pool-cluster-cidrs base)))
                    (prefixes (if (or (getf options :cluster-pod-cidr-supplied-p)
                                      (getf options :node-pod-prefix-supplied-p)
                                      (getf options :node-pod-prefix-ipv6-supplied-p))
                                  (map 'vector
                                       (lambda (cidr)
                                         (if (find #\: cidr)
                                             (getf options :node-pod-prefix-ipv6)
                                             (getf options :node-pod-prefix)))
                                       cidrs)
                                  (node-pool-prefixes base))))
               (make-node-pool-config (aref cidrs 0) (aref prefixes 0) cidrs prefixes)))))
      (when (and nodes (or stored legacy)
                 (not (node-pool-settings-equal-p configuration base)))
        (invalid-cni "refusing to change Pod-pool geometry while node allocations exist"))
      (validate-node-pool-assignments configuration nodes)
      (validate-pod-pool-host-routes
       (node-pool-cluster-cidrs configuration)
       (merge-pathnames "agent/runtime/" (uiop:ensure-directory-pathname state-directory))
       :route-reader route-reader :link-reader link-reader)
      (unless (and stored (node-pool-settings-equal-p stored configuration))
        (write-private-text-atomically path (com.inuoe.jzon:stringify configuration)))
      configuration)))
