;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The "routed" CNI data plane: attach a Pod to the gr8s overlay over a
;;;; point-to-point veth pair, with the agent -- not the client -- owning
;;;; addressing and the policy boundary.
;;;;
;;;; Each Pod gets a host-side veth and an in-netns peer. The Pod carries its
;;;; address as a /32 with a host route back over the veth and a permanent
;;;; neighbor for the link-local node gateway (169.254.1.1), so no subnet is on
;;;; the wire and every packet is routed. Addresses come from agent-owned IPAM
;;;; keyed by (container-id, interface); client IPAM settings are never trusted.
;;;; The lifecycle wraps an inner policy CNI (the eBPF enforcement layer): ADD
;;;; installs the link, then the policy, and keeps the durable address lease
;;;; until DEL has torn both down, so a crash mid-ADD still cleans up. The
;;;; enforcement boundary is always the agent-owned host veth ingress, regardless
;;;; of the direction or interface the client requests.

(in-package #:gr8s.network)

(defun routed-cni-owner (context)
  "The ownership tag gr8s stamps on this endpoint's links,
   \"gr8s:<container-id>/<interface>\", so a link can be matched back to the
   endpoint that created it."
  (format nil "gr8s:~A/~A" (cni-context-container-id context)
          (cni-context-interface-name context)))

(defun routed-cni-host-name (context)
  "The host-side veth name for CONTEXT's (container-id, interface) endpoint."
  (routed-veth-name (cni-context-container-id context)
                    (cni-context-interface-name context)))

(defun check-routed-cni-link (context address)
  "Verify the assigned Pod /32, host route, node gateway, and static Pod neighbor."
  (let* ((host (routed-cni-host-name context))
         (owner (routed-cni-owner context))
         (gateway +node-gateway-address+))
    (unless (and (network-link-owned-p host owner)
                 (network-address-present-p +node-gateway-interface+ gateway 32)
                 (node-gateway-owned-or-adoptable-p gateway)
                 (not (network-address-present-p host gateway 32))
                 (network-route-present-p address 32 host :source gateway))
      (invalid-cni "routed host endpoint or node gateway is missing or misconfigured"))
    (let ((mac (gethash 1 (network-link-attributes host))))
      (call-with-cni-network-namespace
       (cni-context-netns context)
       (lambda ()
         (let ((peer (cni-context-interface-name context)))
           (unless (and (network-link-owned-p peer owner)
                        (network-address-present-p peer address 32)
                        (network-route-present-p gateway 32 peer)
                        (network-route-present-p "0.0.0.0" 0 peer :gateway gateway)
                        (permanent-network-neighbor-p peer gateway mac))
             (invalid-cni "routed Pod endpoint, routes or permanent gateway neighbor is misconfigured"))))))))

(defun remove-routed-cni-link (context)
  "Delete this endpoint's host veth, which also removes its peer and connected
   routes -- idempotent and safe even after the Pod netns is gone. A no-op when
   the link is already absent (interface index 0). Refuses, via INVALID-CNI, to
   remove a link tagged as owned by a different endpoint, and re-signals any
   rtnetlink error other than ENODEV."
  ;; Deleting either end deletes the pair and its connected routes. This works
  ;; even after containerd has already destroyed the Pod network namespace.
  (handler-case
      (let ((host (routed-cni-host-name context)))
        (unless (zerop (native-interface-index host))
          (unless (routed-veth-owned-or-untagged-p host (routed-cni-owner context) "host")
            (invalid-cni "refusing to remove a link owned by another endpoint"))
          (delete-network-link host)))
    (rtnetlink-error (condition)
      (unless (= 19 (rtnetlink-error-errno condition)) (error condition)))))

(defun routed-cni-result (configuration context host address dns-address)
  "Build the CNI ADD result object: the HOST and Pod interfaces, the Pod's
   ADDRESS as a /32 with gateway 169.254.1.1, a default route via that gateway,
   and DNS-ADDRESS as the sole nameserver."
  (json-object
   "cniVersion" (cni-configuration-version configuration)
   "interfaces"
   (vector (json-object "name" host)
           (json-object "name" (cni-context-interface-name context)
                        "sandbox" (cni-context-netns context)))
   "ips" (vector (json-object "interface" 1
                              "address" (concatenate 'string address "/32")
                              "gateway" "169.254.1.1"))
   "routes" (vector (json-object "dst" "0.0.0.0/0" "gw" "169.254.1.1"))
   "dns" (json-object "nameservers" (vector dns-address))))

(defun make-routed-cni-operations
    (ipam &key (mtu 1450) (dns-address +dns-pod-server-address+)
            (install-link (lambda (context address)
                            (configure-routed-veth context address :mtu mtu)))
            (check-link #'check-routed-cni-link)
            (remove-link #'remove-routed-cni-link)
            (policy (make-cni-operations)))
  "Bind a CNI lifecycle to agent-owned IPAM; never trust client IPAM settings."
  (make-cni-operations
   :prepare
   (lambda (configuration context)
     ;; Client direction and interface settings never select the enforcement
     ;; boundary: Pod egress arrives at its agent-owned host veth ingress.
     (setf (cni-configuration-direction configuration) "ingress"
           (cni-configuration-policy-interface-name configuration)
           (routed-cni-host-name context)))
   :add
   (lambda (configuration context map-path link-path)
     (let* ((address (allocate-pod-address ipam
                       (cni-context-container-id context)
                       (cni-context-interface-name context)))
            (host (funcall install-link context address)))
       ;; Keep the durable lease on failure. DEL must remove links and policy
       ;; before releasing an address, including after a crash during ADD.
       (setf (cni-configuration-endpoint-address configuration) address)
       (funcall (cni-operations-add policy)
                configuration context map-path link-path)
       (setf (cni-configuration-previous-result configuration)
             (routed-cni-result configuration context host address dns-address))))
   :check
   (lambda (configuration context map-path link-path)
     (let ((address (check-pod-address ipam (cni-context-container-id context)
                                      (cni-context-interface-name context))))
       (setf (cni-configuration-endpoint-address configuration) address)
       (funcall check-link context address))
     (funcall (cni-operations-check policy)
              configuration context map-path link-path))
   :delete
   (lambda (configuration context map-path link-path directory)
     (funcall (cni-operations-delete policy)
              configuration context map-path link-path directory)
     (funcall remove-link context)
     (release-pod-address ipam (cni-context-container-id context)
                          (cni-context-interface-name context)))
   :status (cni-operations-status policy)))
