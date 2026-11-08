;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The per-node VXLAN overlay tunnel: the gr8s-vxlan device and the FDB, ARP and
;;;; route entries that carry Pod traffic between nodes (RFC 7348, UDP port 4789).
;;;;
;;;; gr8s programs one VXLAN device per node directly over rtnetlink. Every peer node
;;;; is a static tunnel endpoint: a permanent FDB entry maps the peer's router MAC to
;;;; its underlay address, a static ARP entry pins that MAC, and a route sends the
;;;; peer's Pod CIDR through the device's router address. Dynamic MAC learning is off,
;;;; so a peer cannot steer another node's traffic by announcing a MAC. Two choices a
;;;; maintainer would otherwise have to reverse-engineer: the router address is the Pod
;;;; CIDR's network address -- a /32 IPAM already reserves -- so the overlay gateway
;;;; costs no Pod allocation, and the router MAC is a deterministic hash of the CIDR,
;;;; so every node agrees on a peer's MAC without coordinating. The device carries an
;;;; owner tag ("gr8s:vxlan:CIDR:VNI:underlay"); reconciliation adopts an untagged
;;;; device only when its VXLAN parameters already match, and refuses to replace one it
;;;; does not own, so a foreign interface of the same name is never clobbered.

(in-package #:gr8s.network)

(defparameter +node-vxlan-interface+ "gr8s-vxlan")

(defun route-pod-cidrs (route)
  "Return ROUTE's ordered Pod CIDRs, accepting the legacy singular field."
  (let ((cidrs (gethash "podCIDRs" route)))
    (if cidrs
        (progn
          (unless (and (vectorp cidrs) (plusp (length cidrs))
                       (every (lambda (cidr) (and (stringp cidr) (plusp (length cidr))))
                              cidrs))
            (invalid-cni "peer Pod CIDRs must be a non-empty string array"))
          (coerce cidrs 'list))
        (list (required-cni-string route "podCIDR")))))

(defun network-pod-cidrs (network plural singular)
  "Return NETWORK's ordered Pod CIDRs, accepting the legacy singular field."
  (let ((cidrs (gethash plural network)))
    (if (and (vectorp cidrs) (plusp (length cidrs)))
        (coerce cidrs 'list)
        (list (required-cni-string network singular)))))

(defun vxlan-router-address (pod-cidr)
  "Return POD-CIDR's network address: this node's family-specific overlay router."
  ;; IPAM excludes the network address. Use that reserved host address as the node's
  ;; overlay router address, without consuming any Pod allocation.
  (multiple-value-bind (family address prefix bits) (parse-pod-cidr pod-cidr)
    (declare (ignore prefix bits))
    (format-pod-address family address)))

(defun vxlan-router-mac (pod-cidr)
  "Return the router MAC for POD-CIDR as a 6-octet sequence: a locally-administered
unicast address whose last five bytes are a SHA-256 of the CIDR. Deterministic, so every
node derives the same MAC for a given CIDR with no coordination and a peer cannot pick its own."
  (netlink-octets
   #(2) ; locally administered, unicast
   (subseq (ironclad:digest-sequence
            :sha256 (trivial-utf-8:string-to-utf-8-bytes pod-cidr)) 0 5)))

(defun create-node-vxlan (local-address pod-cidr vni mtu)
  "Create the gr8s-vxlan device over rtnetlink with LOCAL-ADDRESS as the underlay source,
the POD-CIDR-derived router MAC, the given VNI and MTU, dynamic MAC learning disabled, and
the tunnel on UDP 4789. Creates the link as a side effect; signals on an rtnetlink error.
Does not tag ownership or bring the link up -- ENSURE-NODE-VXLAN does that."
  (call-rtnetlink
   16 #x600
   (netlink-octets
    (netlink-interface-message)
    (netlink-attribute 3 (netlink-string +node-vxlan-interface+))
    (netlink-attribute 1 (vxlan-router-mac pod-cidr))
    (netlink-attribute 4 (netlink-integer mtu 4))
    (netlink-attribute
     18 (netlink-octets
         (netlink-attribute 1 (netlink-string "vxlan"))
         (netlink-attribute
          #x8002 (netlink-octets
                  (netlink-attribute 1 (netlink-integer vni 4))
                  (netlink-attribute 4 (ipv4-network-octets local-address))
                  (netlink-attribute 7 #(0)) ; disable dynamic MAC learning
                  (netlink-attribute 15 #(18 181))))))))) ; UDP port 4789

(defun node-vxlan-owned-or-adoptable-p (network)
  "True when this node may use the existing gr8s-vxlan device for NETWORK: either it
already carries this node's owner tag, or it is an untagged VXLAN device whose MAC, VNI,
underlay address and UDP port all match NETWORK -- in which case it is adopted (its owner
tag is written) as a side effect. NIL when the device belongs to another node network."
  (let* ((name +node-vxlan-interface+)
         (owner (node-vxlan-owner network))
         (attributes (network-link-attributes name))
         (info (gethash 18 attributes))
         (data (and info (gethash 2 (netlink-attributes info 0))))
         (vxlan (and data (netlink-attributes data 0))))
    (cond
      ((equalp (gethash 20 attributes) (netlink-string owner)) t)
      ((and vxlan
            (plusp (length (gethash "underlayAddress" network "")))
            (network-link-untagged-p attributes)
            (network-link-kind-p attributes "vxlan")
            (equalp (gethash 1 attributes) (vxlan-router-mac (gethash "nodePodCIDR" network)))
            (equalp (gethash 1 vxlan) (netlink-integer (gethash "vni" network) 4))
            (equalp (gethash 4 vxlan) (ipv4-network-octets (gethash "underlayAddress" network)))
            (equalp (gethash 15 vxlan) #(18 181)))
       (set-network-link-owner name owner)
       t))))

(defun ensure-node-vxlan (local-address pod-cidrs vni mtu)
  "Idempotently bring up this node's VXLAN device for the given overlay parameters and
return its interface name. Creates and owner-tags the device when absent (rolling the
creation back if tagging fails), verifies ownership -- signaling INVALID-CNI when the
device belongs to another node network -- then sets the MTU, adds the router /32 address,
brings the link up and enables IPv4 forwarding. Safe to call repeatedly."
  (let* ((cidrs (if (stringp pod-cidrs) (list pod-cidrs) pod-cidrs))
         (pod-cidr (first cidrs))
         (owner (format nil "gr8s:vxlan:~A:~D:~A" pod-cidr vni local-address)))
    (when (zerop (native-interface-index +node-vxlan-interface+))
      (create-node-vxlan local-address pod-cidr vni mtu)
      (handler-case
          (set-network-link-owner +node-vxlan-interface+ owner)
        (error (condition)
          (ignore-errors (delete-network-link +node-vxlan-interface+))
          (error condition))))
    (unless (node-vxlan-owned-or-adoptable-p
             (json-object "nodePodCIDR" pod-cidr "vni" vni "underlayAddress" local-address))
      (invalid-cni "VXLAN interface belongs to another node network"))
    (set-network-link-mtu +node-vxlan-interface+ mtu)
    (dolist (cidr cidrs)
      (multiple-value-bind (family address prefix bits) (parse-pod-cidr cidr)
        (declare (ignore address prefix))
        (add-network-address +node-vxlan-interface+ (vxlan-router-address cidr) bits)
        (when (eq family :ipv6) (enable-node-ipv6-forwarding))))
    (set-network-link-up +node-vxlan-interface+)
    (enable-node-ipv4-forwarding))
  +node-vxlan-interface+)

(defun replace-vxlan-peer (pod-cidr underlay-address &optional (mac-cidr pod-cidr))
  "Install or replace the tunnel to one peer: a permanent FDB entry mapping the peer's
router MAC to UNDERLAY-ADDRESS, a static ARP entry pinning that MAC, a /32 route to the
router address, and a route for the peer's POD-CIDR through it. Idempotent (each is a
replace). Side-effects the kernel over rtnetlink; returns NIL."
  (let ((interface +node-vxlan-interface+)
        (router (vxlan-router-address pod-cidr))
        (mac (vxlan-router-mac mac-cidr)))
    ;; AF_BRIDGE FDB: remote router MAC -> underlay IPv4 destination.
    (call-rtnetlink
     28 #x500
     (netlink-octets
      (netlink-neighbor-message 7 interface 128 2) ; PERMANENT, SELF
      (netlink-attribute 2 mac)
      (netlink-attribute 1 (ipv4-network-octets underlay-address))))
    (multiple-value-bind (family address prefix bits) (parse-pod-cidr pod-cidr)
      ;; Static ARP/NDP avoids floods and pins the peer's actual VXLAN MAC.
      (replace-permanent-network-neighbor interface router mac)
      (replace-network-route router bits interface)
      (replace-network-route (format-pod-address family address) prefix interface
                             :gateway router)))
  nil)

(defun call-rtnetlink-delete (type payload)
  "Send an rtnetlink delete (message TYPE, PAYLOAD) that tolerates the object already
being gone: ENOENT, ESRCH and ENODEV (errno 2, 3, 19) are swallowed, any other
RTNETLINK-ERROR is re-signaled. Makes a deletion idempotent."
  (handler-case (call-rtnetlink type 0 payload)
    (rtnetlink-error (condition)
      (unless (member (rtnetlink-error-errno condition) '(2 3 19))
        (error condition)))))

(defun delete-network-route (destination prefix interface)
  "Delete the route to DESTINATION/PREFIX on INTERFACE over rtnetlink, tolerating its
absence. The scope is left as NOWHERE so a route of any existing scope matches."
  (multiple-value-bind (family bytes) (network-address-wire-values destination)
    (call-rtnetlink-delete
     25 (netlink-octets
         (vector family prefix 0 0 254 4 255 1) ; scope NOWHERE accepts any old scope
         (netlink-integer 0 4)
         (netlink-attribute 1 bytes)
         (netlink-attribute 4 (netlink-integer (cni-interface-index interface) 4))))))

(defun remove-vxlan-peer (pod-cidr underlay-address &optional (mac-cidr pod-cidr))
  "Withdraw one peer's tunnel -- the POD-CIDR route, the router /32 route, the static ARP
entry and the FDB entry -- the inverse of REPLACE-VXLAN-PEER. A no-op when the VXLAN
device is absent. Each deletion tolerates the entry already being gone; returns NIL."
  (unless (zerop (native-interface-index +node-vxlan-interface+))
    (let ((interface +node-vxlan-interface+)
          (router (vxlan-router-address pod-cidr)))
      (multiple-value-bind (family address prefix bits) (parse-pod-cidr pod-cidr)
        (delete-network-route (format-pod-address family address) prefix interface)
        (delete-network-route router bits interface))
      (call-rtnetlink-delete
       29 (netlink-octets
           (netlink-neighbor-message (if (find #\: router) 10 2) interface 128 0)
           (netlink-attribute 1 (nth-value 1 (network-address-wire-values router)))))
      (call-rtnetlink-delete
       29 (netlink-octets
           (netlink-neighbor-message 7 interface 128 2)
           (netlink-attribute 2 (vxlan-router-mac mac-cidr))
           (netlink-attribute 1 (ipv4-network-octets underlay-address))))))
  nil)

(defun node-vxlan-owner (network)
  "Return the owner-tag string gr8s stamps on the VXLAN device for NETWORK,
\"gr8s:vxlan:CIDR:VNI:underlay\", identifying which node network a device belongs to."
  (format nil "gr8s:vxlan:~A:~D:~A" (gethash "nodePodCIDR" network)
          (gethash "vni" network) (gethash "underlayAddress" network "")))

(defun node-vxlan-route-pairs (network)
  "Return a list of (POD-CIDR . UNDERLAY-ADDRESS) conses, one per entry in NETWORK's
\"routes\" array: the set of peers this node should tunnel to."
  (loop for route across (gethash "routes" network #())
        append (loop for cidr in (route-pod-cidrs route)
                     collect (cons cidr (gethash "underlayAddress" route)))))

(defun node-vxlan-route-specs (network)
  "Return (CIDR UNDERLAY PRIMARY-CIDR) entries for VXLAN reconciliation."
  (loop for route across (gethash "routes" network #())
        for cidrs = (route-pod-cidrs route)
        append (loop for cidr in cidrs
                     collect (list cidr (gethash "underlayAddress" route)
                                   (first cidrs)))))

(defun reconcile-node-vxlan-network (network previous-networks)
  "Converge this node's VXLAN dataplane onto NETWORK, using PREVIOUS-NETWORKS (earlier
network intents) to know which peers and identities to retire. Creates or adopts the
device, removes peers no longer wanted and installs the wanted ones; when NETWORK carries
no local underlay address the device is torn down. When the existing device is neither
owned nor adoptable and no previous identity owned it either, signals INVALID-CNI rather
than seize a foreign interface. An underlay/VNI change replaces the tunnel, and the
durable journal keeps both identities so a crash mid-change can be retried. Returns NIL,
and is a no-op when the node has never had an overlay."
  (let* ((local (gethash "underlayAddress" network ""))
         (wanted (node-vxlan-route-specs network))
         (previous
           (remove-duplicates (mapcan #'node-vxlan-route-specs previous-networks)
                              :test #'equal)))
    (when (and (string= local "")
               (notany (lambda (old)
                         (plusp (length (gethash "underlayAddress" old ""))))
                       previous-networks))
      (return-from reconcile-node-vxlan-network nil))
    (unless (zerop (native-interface-index +node-vxlan-interface+))
      (unless (node-vxlan-owned-or-adoptable-p network)
        ;; An underlay/VNI change requires replacing our tunnel. The durable
        ;; journal retains both identities if the process stops halfway.
        (unless (some (lambda (old)
                        (and (plusp (length (gethash "underlayAddress" old "")))
                             (node-vxlan-owned-or-adoptable-p old)))
                      previous-networks)
          (invalid-cni "refusing to replace an unowned VXLAN interface"))
        (delete-network-link +node-vxlan-interface+)
        (setf previous nil)))
    (cond
      ((string= local "")
       (delete-network-link +node-vxlan-interface+))
      (t
       (ensure-node-vxlan local (network-pod-cidrs
                                 network "nodePodCIDRs" "nodePodCIDR")
                          (gethash "vni" network) (gethash "mtu" network))
       ;; Remove changed FDB entries before reusing their router MAC/address.
       (dolist (route previous)
         (unless (member route wanted :test #'equal)
           (apply #'remove-vxlan-peer route)))
       (dolist (route wanted) (apply #'replace-vxlan-peer route))))))
