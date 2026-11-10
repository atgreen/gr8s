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
  "Verify assigned Pod host routes, node gateways, and static Pod neighbors."
  (let* ((host (routed-cni-host-name context))
         (owner (routed-cni-owner context))
         (addresses (if (stringp address) (list address) address))
         (gateways (mapcar (lambda (item)
                             (if (find #\: item)
                                 +node-gateway-ipv6-address+
                                 +node-gateway-address+))
                           addresses)))
    (unless (and (network-link-owned-p host owner)
                 (node-gateway-owned-or-adoptable-p (first gateways))
                 (loop for item in addresses
                       for gateway in gateways
                       always (and
                               (network-address-present-p
                                +node-gateway-interface+ gateway
                                (if (find #\: gateway) 128 32))
                               (if (find #\: gateway)
                                   (network-address-present-p host gateway 128)
                                   (not (network-address-present-p host gateway 32)))
                               (network-route-present-p
                                item (if (find #\: item) 128 32) host
                                :source (unless (find #\: item) gateway)))))
      (invalid-cni "routed host endpoint or node gateway is missing or misconfigured"))
    (let ((mac (gethash 1 (network-link-attributes host))))
      (call-with-cni-network-namespace
       (cni-context-netns context)
       (lambda ()
         (let ((peer (cni-context-interface-name context)))
           (unless (and
                    (network-link-owned-p peer owner)
                    (loop for item in addresses
                          for gateway in gateways
                          always (and
                                  (network-address-present-p
                                   peer item (if (find #\: item) 128 32))
                                  (network-route-present-p
                                   gateway (if (find #\: gateway) 128 32) peer)
                                  (network-route-present-p
                                   (if (find #\: item) "::" "0.0.0.0") 0 peer
                                   :gateway gateway)
                                  (permanent-network-neighbor-p
                                   peer gateway mac))))
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

(defun routed-service-return-mac
    (context &key (link-owned #'network-link-owned-p)
                  (call-in-netns #'call-with-cni-network-namespace)
                  (link-attributes #'network-link-attributes))
  "Read the peer MAC only after checking both links' durable endpoint owner."
  (let ((owner (routed-cni-owner context)))
    (unless (funcall link-owned (routed-cni-host-name context) owner)
      (invalid-cni "Service return path host link belongs to another endpoint"))
    (funcall call-in-netns
     (cni-context-netns context)
     (lambda ()
       (let ((peer (cni-context-interface-name context)))
         (unless (funcall link-owned peer owner)
           (invalid-cni "Service return path peer belongs to another endpoint"))
         (let ((mac (gethash 1 (funcall link-attributes peer))))
           (unless (and (vectorp mac) (= 6 (length mac)))
             (invalid-cni "Service return path peer has no Ethernet identity"))
           (copy-seq mac)))))))

(defun install-routed-service-return-path
    (context address &key (endpoint-mac #'routed-service-return-mac)
                          (route-present #'network-route-present-p)
                          (install-route #'replace-network-route)
                          (install-neighbor #'replace-permanent-network-neighbor))
  "Publish a private IPv4 return route to the owned veth, never a Pod address.
An exact retained route may be adopted. EXCL prevents stealing another route;
partial failure retains the IPAM lease until DEL removes the endpoint."
  (canonical-service-translation-ipv4 address)
  (let ((host (routed-cni-host-name context))
        (mac (funcall endpoint-mac context)))
    ;; The Pod does not own this IP and cannot answer ARP for it. The neighbor
    ;; must be present before publishing a route that can deliver return frames.
    (funcall install-neighbor host address mac)
    (unless (funcall route-present address 32 host :source +node-gateway-address+)
      (handler-case
          (funcall install-route address 32 host :source +node-gateway-address+ :exclusive t)
        (rtnetlink-error (condition)
          (unless (and (= 17 (rtnetlink-error-errno condition))
                       (funcall route-present address 32 host :source +node-gateway-address+))
            (error condition)))))
    address))

(defun check-routed-service-return-path
    (context address &key (endpoint-mac #'routed-service-return-mac)
                          (route-present #'network-route-present-p)
                          (neighbor-present #'permanent-network-neighbor-p))
  "Verify the private host route and permanent neighbor without repairing them."
  (canonical-service-translation-ipv4 address)
  (let ((host (routed-cni-host-name context))
        (mac (funcall endpoint-mac context)))
    (unless (and (funcall route-present address 32 host :source +node-gateway-address+)
                 (funcall neighbor-present host address mac))
      (invalid-cni "Service return route or permanent neighbor is missing or misconfigured")))
  t)

(defun routed-cni-result (configuration context host addresses dns-address)
  "Build the CNI ADD result object: the HOST and Pod interfaces, the Pod's
   addresses as /32 or /128 host routes with family-specific link-local gateways
   and default routes, and DNS-ADDRESS as the sole nameserver."
  (let ((addresses (if (stringp addresses) (list addresses) addresses)))
    (json-object
     "cniVersion" (cni-configuration-version configuration)
     "interfaces"
     (vector (json-object "name" host)
             (json-object "name" (cni-context-interface-name context)
                          "sandbox" (cni-context-netns context)))
     "ips"
     (coerce
      (mapcar (lambda (address)
                (let ((ipv6-p (not (null (find #\: address)))))
                  (json-object "interface" 1
                               "address" (format nil "~A/~D" address
                                                 (if ipv6-p 128 32))
                               "gateway" (if ipv6-p "fe80::1" "169.254.1.1"))))
              addresses)
      'vector)
     "routes"
     (coerce
      (mapcar (lambda (address)
                (if (find #\: address)
                    (json-object "dst" "::/0" "gw" "fe80::1")
                    (json-object "dst" "0.0.0.0/0" "gw" "169.254.1.1")))
              addresses)
      'vector)
     "dns" (json-object "nameservers" (vector dns-address)))))

(defun make-routed-cni-operations
    (ipam &key node-id (service-risk-ready-p (constantly nil))
            (mtu 1450) (dns-address +dns-pod-server-address+)
            (install-link (lambda (context address)
                            (configure-routed-veth context address :mtu mtu)))
            (check-link #'check-routed-cni-link)
            (remove-link #'remove-routed-cni-link)
            (install-service-return #'install-routed-service-return-path)
            (check-service-return #'check-routed-service-return-path)
            (publish-service-owner #'publish-cni-service-nat-owner)
            (check-service-owner #'check-cni-service-nat-owner)
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
     (let* ((addresses (allocate-pod-addresses ipam
                         (cni-context-container-id context)
                         (cni-context-interface-name context)))
            (return-address
              (or (service-snat-address ipam (cni-context-container-id context)
                                             (cni-context-interface-name context))
                  (when (and (cni-configuration-service-packet-root configuration)
                             (some (lambda (address) (not (find #\: address))) addresses))
                    (allocate-service-snat-address ipam (cni-context-container-id context)
                                                      (cni-context-interface-name context)))))
            (host (funcall install-link context addresses)))
       ;; Keep the durable lease on failure. DEL must remove links and policy
       ;; before releasing an address, including after a crash during ADD.
       (setf (cni-configuration-endpoint-address configuration) (first addresses)
             (cni-configuration-endpoint-addresses configuration) addresses
             (cni-configuration-service-node-id configuration) node-id
             (cni-configuration-service-return-address configuration) return-address)
       (if (eq (cni-service-profile configuration) :v2)
           (progn
             (unless (funcall service-risk-ready-p)
               (invalid-cni "v2 Service risk inventory is not published for the current snapshot"))
             (unless return-address
               (invalid-cni "v2 Service endpoint has no private return address"))
             (funcall install-service-return context return-address)
             (funcall publish-service-owner configuration context addresses return-address)
             (funcall (cni-operations-add policy)
                      configuration context map-path link-path))
           (progn
             (funcall (cni-operations-add policy)
                      configuration context map-path link-path)
             (when return-address (funcall install-service-return context return-address))))
       (setf (cni-configuration-previous-result configuration)
             (routed-cni-result configuration context host addresses dns-address))))
   :check
   (lambda (configuration context map-path link-path)
     (let ((addresses (check-pod-addresses ipam (cni-context-container-id context)
                                          (cni-context-interface-name context))))
       (setf (cni-configuration-endpoint-address configuration) (first addresses)
             (cni-configuration-endpoint-addresses configuration) addresses
             (cni-configuration-service-node-id configuration) node-id
             (cni-configuration-service-return-address configuration)
             (service-snat-address ipam (cni-context-container-id context)
                                   (cni-context-interface-name context)))
       (funcall check-link context addresses))
     ;; CHECK does not invent leases for retained endpoints from older versions.
     ;; Such endpoints are not ready for future source translation until ADD.
     (let ((address (service-snat-address ipam (cni-context-container-id context)
                                             (cni-context-interface-name context))))
       (if (eq (cni-service-profile configuration) :v2)
           (progn
             (unless (funcall service-risk-ready-p)
               (invalid-cni "v2 Service risk inventory is not published for the current snapshot"))
             (unless address
               (invalid-cni "v2 Service endpoint has no private return address"))
             (funcall check-service-return context address)
             (funcall check-service-owner configuration context
                      (cni-configuration-endpoint-addresses configuration) address)
             (funcall (cni-operations-check policy)
                      configuration context map-path link-path))
           (progn
             (funcall (cni-operations-check policy)
                      configuration context map-path link-path)
             (when address (funcall check-service-return context address))))))
   :delete
   (lambda (configuration context map-path link-path directory)
     (funcall (cni-operations-delete policy)
              configuration context map-path link-path directory)
     (funcall remove-link context)
     (release-pod-address ipam (cni-context-container-id context)
                          (cni-context-interface-name context)))
   :status (cni-operations-status policy)))
