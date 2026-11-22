;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; gr8s node-networking helpers layered over the cl-rtnetlink library.
;;;;
;;;; The Linux rtnetlink (NETLINK_ROUTE) wire codec and the link, address, route
;;;; and neighbor operations now live in the standalone cl-rtnetlink library
;;;; (installed via ocicl); gr8s.network re-homes its public API in package.lisp.
;;;; What remains here is the gr8s-specific layer those primitives serve: the
;;;; routed-veth helpers that stamp each link with a stable alias and a derived
;;;; MAC so a create interrupted by a crash can be recognized and adopted on
;;;; retry; link ownership and tagging checks; the node gateway; host-route
;;;; discovery; and IPv4/IPv6 forwarding.  A kernel error still surfaces as the
;;;; library's RTNETLINK-ERROR condition, which gr8s handlers catch.

(in-package #:gr8s.network)

;; Raw socket syscalls for the one AF_NETLINK path gr8s still drives itself: the
;; WireGuard generic-netlink client in wireguard.lisp.  The rtnetlink route
;; transactions use cl-rtnetlink's own private socket; these stay here because a
;; gr8s network file is the only remaining caller.
(sb-alien:define-alien-routine ("socket" %rtnl-socket) sb-alien:int
  (domain sb-alien:int) (type sb-alien:int) (protocol sb-alien:int))
(sb-alien:define-alien-routine ("connect" %rtnl-connect) sb-alien:int
  (fd sb-alien:int) (address sb-alien:system-area-pointer)
  (length sb-alien:unsigned-int))
(sb-alien:define-alien-routine ("send" %rtnl-send) sb-alien:long
  (fd sb-alien:int) (buffer sb-alien:system-area-pointer)
  (length sb-alien:unsigned-long) (flags sb-alien:int))
(sb-alien:define-alien-routine ("recv" %rtnl-recv) sb-alien:long
  (fd sb-alien:int) (buffer sb-alien:system-area-pointer)
  (length sb-alien:unsigned-long) (flags sb-alien:int))

(defun routed-veth-name (sandbox-id interface-name)
  "Derive the host-side veth name for SANDBOX-ID's INTERFACE-NAME: \"gr\" followed
   by 13 hex characters of a SHA-256 digest. Stable across process restarts and
   dumped images (unlike SXHASH) and within the 15-character name limit."
  ;; A stable digest, unlike SXHASH, survives a new dumped image or process.
  (concatenate
   'string "gr"
   (subseq (ironclad:byte-array-to-hex-string
            (ironclad:digest-sequence
             :sha256 (trivial-utf-8:string-to-utf-8-bytes
                      (format nil "~A/~A" sandbox-id interface-name)))) 0 13)))

(defun network-identity-mac (identity)
  "Derive a stable 6-byte MAC from IDENTITY: a locally-administered unicast
   leading octet (0x02) followed by five bytes of its SHA-256 digest."
  (netlink-octets #(2)
                  (subseq (ironclad:digest-sequence
                           :sha256 (trivial-utf-8:string-to-utf-8-bytes identity)) 0 5)))

(defun routed-veth-mac (owner role)
  "The MAC for OWNER's veth end in ROLE (e.g. \"host\" or \"pod\"), stable per
   owner and role."
  (network-identity-mac (format nil "~A:~A" owner role)))

(defun %create-routed-veth (host-name peer-name netns &key (mtu 1450) owner)
  "Create a veth pair via RTM_NEWLINK (NLM_F_CREATE|NLM_F_EXCL): HOST-NAME in the
   caller's namespace and PEER-NAME placed into the network namespace at path
   NETNS, both at MTU, and -- when OWNER is given -- with the deterministic
   host/pod MACs derived from it. Signals INVALID-CNI on an unsafe name and
   RTNETLINK-ERROR (EEXIST) when a name is already taken. Closes the namespace fd
   before returning."
  (validate-network-interface-name host-name)
  (validate-network-interface-name peer-name)
  (let ((fd (sb-posix:open netns sb-posix:o-rdonly 0)))
    (unwind-protect
         (call-rtnetlink
          16 #x600 ; RTM_NEWLINK, CREATE | EXCL
          (netlink-octets
           (netlink-interface-message)
           (netlink-attribute 3 (netlink-string host-name))
           (if owner (netlink-attribute 1 (routed-veth-mac owner "host")) #())
           (netlink-attribute 4 (netlink-integer mtu 4))
           (netlink-attribute
            18 ; IFLA_LINKINFO
            (netlink-octets
             (netlink-attribute 1 (netlink-string "veth"))
             (netlink-attribute
              #x8002 ; IFLA_INFO_DATA | NLA_F_NESTED
              (netlink-attribute
               1 ; VETH_INFO_PEER, embeds an ifinfomsg
               (netlink-octets
                (netlink-interface-message)
                (netlink-attribute 3 (netlink-string peer-name))
                (if owner (netlink-attribute 1 (routed-veth-mac owner "pod")) #())
                (netlink-attribute 4 (netlink-integer mtu 4))
                (netlink-attribute 28 (netlink-integer fd 4)))))))))
      (sb-posix:close fd))))

(defun set-network-link-owner (name owner)
  "Set NAME's link alias (IFLA_IFALIAS) to OWNER, the ownership tag gr8s reads
   back to recognize its own links."
  (call-rtnetlink
   16 0 (netlink-octets
         (netlink-interface-message :index (cni-interface-index name))
         (netlink-attribute 20 (netlink-string owner)))))

(defun create-routed-veth (host-name peer-name netns &key (mtu 1450) owner)
  "Create the veth pair (see %CREATE-ROUTED-VETH) and, when OWNER is given, stamp
   the ownership alias on both ends -- a separate link-update the kernel requires
   because veth NEWLINK ignores IFLA_IFALIAS. On any failure deletes the host
   link and resignals, so a partial create leaves nothing behind."
  (%create-routed-veth host-name peer-name netns :mtu mtu :owner owner)
  ;; Linux applies IFLA_IFALIAS through changelink, not veth newlink.
  (handler-case
      (when owner
        (set-network-link-owner host-name owner)
        (call-with-cni-network-namespace
         netns (lambda () (set-network-link-owner peer-name owner))))
    (error (condition)
      (ignore-errors (delete-network-link host-name))
      (error condition))))

(defun read-family-host-routes (family)
  "Read non-default routes for address FAMILY from all Linux routing tables."
  (let* ((ipv6-p (= family 10))
         (bits (if ipv6-p 128 32))
         (zero (make-array (/ bits 8) :element-type '(unsigned-byte 8)
                                      :initial-element 0)))
    (loop for message in (call-rtnetlink
                          26 #x300
                          (netlink-octets (vector family 0 0 0 0 0 0 0)
                                           (netlink-integer 0 4)))
          when (and (>= (length message) 28)
                    (= 24 (netlink-read-integer message 4 2))
                    (= family (aref message 16))
                    (plusp (aref message 17)))
            collect (let* ((attributes (netlink-attributes message 28))
                           (destination (gethash 1 attributes zero))
                           (index (gethash 4 attributes))
                           (table (gethash 15 attributes)))
                      (list :cidr (format nil "~A/~D"
                                          (format-pod-address
                                           (if ipv6-p :ipv6 :ipv4)
                                           (network-prefix-octets-integer
                                            destination bits))
                                          (aref message 17))
                            :index (if index (netlink-read-integer index 0 4) 0)
                            :table (if table (netlink-read-integer table 0 4)
                                       (aref message 20)))))))

(defun read-ipv4-host-routes ()
  "Read non-default IPv4 routes from all Linux routing tables via rtnetlink."
  (read-family-host-routes 2))

(defun read-ip-host-routes ()
  "Read non-default IPv4 and IPv6 routes from all Linux routing tables."
  (append (read-family-host-routes 2) (read-family-host-routes 10)))

(defun network-link-owned-p (name owner)
  "True when the link NAME's alias is exactly OWNER -- i.e. gr8s owns the link."
  (let ((alias (gethash 20 (network-link-attributes name))))
    (and alias (equalp alias (netlink-string owner)))))

(defun network-link-untagged-p (attributes)
  "True when ATTRIBUTES carry no ownership alias -- absent, empty, or a lone NUL
   -- marking an adoptable, untagged link."
  (let ((alias (gethash 20 attributes)))
    (or (null alias) (zerop (length alias)) (equalp alias #(0)))))

(defun network-link-kind-p (attributes kind)
  "True when ATTRIBUTES describe a link of the given KIND (e.g. \"veth\",
   \"dummy\"), read from IFLA_LINKINFO's nested kind attribute."
  (let ((info (gethash 18 attributes)))
    (and info (equalp (gethash 1 (netlink-attributes info 0)) (netlink-string kind)))))

(defun routed-veth-owned-or-untagged-p (name owner role)
  "True when the link NAME is safe to use as OWNER's ROLE end: either it already
   carries OWNER's alias, or it is an untagged veth whose MAC matches the one
   derived for OWNER and ROLE. The latter adopts a link left behind by a crash
   between creation and aliasing."
  (let ((attributes (network-link-attributes name)))
    (or (equalp (gethash 20 attributes) (netlink-string owner))
        (and (network-link-untagged-p attributes)
             (network-link-kind-p attributes "veth")
             (equalp (gethash 1 attributes) (routed-veth-mac owner role))))))

(defparameter +node-gateway-interface+ "gr8s-gateway")
(defparameter +node-gateway-address+ "169.254.1.1")
(defparameter +node-gateway-ipv6-address+ "fe80::1")

(defun node-gateway-owner (address)
  "Return the stable ownership tag for the node-local gateway ADDRESS."
  (format nil "gr8s:gateway:~A" address))

(defun node-gateway-owned-or-adoptable-p (address)
  "Recognize our dummy gateway by kind, MAC, and ownership tag.
An untagged matching link is recoverable after a crash during creation."
  (let* ((attributes (network-link-attributes +node-gateway-interface+))
         (owner (node-gateway-owner address)))
    (and (network-link-kind-p attributes "dummy")
         (equalp (gethash 1 attributes) (network-identity-mac owner))
         (or (equalp (gethash 20 attributes) (netlink-string owner))
             (network-link-untagged-p attributes)))))

(defun ensure-node-gateway (&optional (address +node-gateway-address+))
  "Ensure one owned, up dummy interface carries the node gateway /32.
Refuse foreign links; concurrent endpoint ADD requests share this interface."
  (let* ((addresses (if (stringp address) (list address) address))
         (primary (first addresses))
         (name +node-gateway-interface+) (owner (node-gateway-owner primary)))
    (when (zerop (native-interface-index name))
      (handler-case
          (call-rtnetlink
           16 #x600
           (netlink-octets
            (netlink-interface-message)
            (netlink-attribute 3 (netlink-string name))
            (netlink-attribute 1 (network-identity-mac owner))
            (netlink-attribute 18 (netlink-attribute 1 (netlink-string "dummy")))))
        (rtnetlink-error (condition)
          ;; Another CNI ADD may have created the same node-local link.
          (unless (= 17 (rtnetlink-error-errno condition)) (error condition)))))
    (unless (node-gateway-owned-or-adoptable-p primary)
      (invalid-cni "node gateway interface is owned by another network"))
    (set-network-link-owner name owner)
    (dolist (item addresses)
      (add-network-address name item (if (find #\: item) 128 32)))
    (set-network-link-up name)
    name))

(defun remove-node-gateway (&optional (address +node-gateway-address+))
  "Remove the owned gateway when its node no longer has durable Pod leases."
  (unless (zerop (native-interface-index +node-gateway-interface+))
    (unless (node-gateway-owned-or-adoptable-p address)
      (invalid-cni "refusing to remove another network's gateway interface"))
    (delete-network-link +node-gateway-interface+))
  nil)

(defun enable-node-ipv4-forwarding ()
  "Enable IPv4 forwarding by writing 1 to /proc/sys/net/ipv4/ip_forward, skipping
   the write when it is already on. Returns NIL."
  (let ((path #P"/proc/sys/net/ipv4/ip_forward"))
    (unless (string= "1" (string-trim '(#\Space #\Newline #\Tab)
                                     (uiop:read-file-string path)))
      (with-open-file (stream path :direction :output :if-exists :overwrite)
        (write-line "1" stream))))
  nil)

(defun enable-node-ipv6-forwarding ()
  "Enable IPv6 forwarding, skipping the write when it is already on."
  (let ((path #P"/proc/sys/net/ipv6/conf/all/forwarding"))
    (unless (string= "1" (string-trim '(#\Space #\Newline #\Tab)
                                     (uiop:read-file-string path)))
      (with-open-file (stream path :direction :output :if-exists :overwrite)
        (write-line "1" stream))))
  nil)

(defun network-interface-ipv6-sysctl (name)
  "The disable_ipv6 sysctl of interface NAME in the calling thread's network namespace."
  (format nil "/proc/sys/net/ipv6/conf/~A/disable_ipv6" (validate-network-interface-name name)))

(defun disable-network-interface-ipv6 (name)
  "Turn IPv6 off on interface NAME, so it sends none of IPv6's link-local traffic
(duplicate address detection, router solicitations, MLD reports). A kernel without
IPv6 has nothing to turn off."
  (let ((path (network-interface-ipv6-sysctl name)))
    (when (probe-file path)
      (with-open-file (stream path :direction :output :if-exists :overwrite)
        (write-line "1" stream))))
  nil)

(defun network-interface-ipv6-disabled-p (name)
  "True when interface NAME has no IPv6, whether turned off or absent from the kernel."
  (let ((path (network-interface-ipv6-sysctl name)))
    (or (not (probe-file path))
        (string= "1" (string-trim '(#\Space #\Newline) (uiop:read-file-string path))))))

(defun veth-scoped-gateway-addresses (gateways)
  "Return the IPv6 link-local gateways that must live on each host veth."
  (remove-if-not (lambda (address) (find #\: address)) gateways))

(defun configure-routed-veth (context address &key (mtu 1450)
                                              (gateway +node-gateway-address+))
  "Create a routed /32 and/or /128 Pod endpoint. The caller owns IPAM and BPF lifecycle."
  (require-cni-context context :network-namespace t)
  (let* ((addresses (if (stringp address) (list address) address))
         (gateways (if (stringp gateway)
                       (mapcar (lambda (item)
                                 (if (find #\: item)
                                     +node-gateway-ipv6-address+
                                     gateway))
                               addresses)
                       gateway))
         (peer (validate-network-interface-name
                (cni-context-interface-name context)))
         (host (routed-veth-name (cni-context-container-id context) peer))
         (owner (format nil "gr8s:~A/~A" (cni-context-container-id context) peer)))
    (when (some (lambda (item) (not (find #\: item))) addresses)
      (enable-node-ipv4-forwarding))
    (when (some (lambda (item) (find #\: item)) addresses)
      (enable-node-ipv6-forwarding))
    (unless (= (length addresses) (length gateways))
      (invalid-cni "each Pod address requires a family-specific gateway"))
    ;; An existing host endpoint is retained for idempotent ADD and recovery.
    (when (zerop (native-interface-index host))
      (create-routed-veth host peer (cni-context-netns context)
                          :mtu mtu :owner owner))
    (unless (routed-veth-owned-or-untagged-p host owner "host")
      (invalid-cni "host link ~A is owned by another endpoint" host))
    (call-with-cni-network-namespace
     (cni-context-netns context)
     (lambda ()
       (unless (routed-veth-owned-or-untagged-p peer owner "pod")
         (invalid-cni "Pod link ~A is owned by another endpoint" peer))))
    ;; MAC identities are installed atomically with veth creation. They allow
    ;; adoption after a crash between NEWLINK and the separate alias updates.
    (set-network-link-owner host owner)
    (set-network-link-mtu host mtu)
    (ensure-node-gateway gateways)
    ;; IPv4 uses the shared dummy gateway. IPv6 link-local addresses are
    ;; interface-scoped, so the gateway must also live on every host veth.
    (loop for item in gateways
          unless (find #\: item)
            do (remove-network-address host item 32))
    (dolist (item (veth-scoped-gateway-addresses gateways))
      (add-network-address host item 128))
    (set-network-link-up host)
    (loop for item in addresses
          for next-gateway in gateways
          do (replace-network-route item (if (find #\: item) 128 32) host
                                    :source (unless (find #\: item) next-gateway)))
    (let ((host-mac (gethash 1 (network-link-attributes host))))
      (call-with-cni-network-namespace
       (cni-context-netns context)
       (lambda ()
         (set-network-link-owner peer owner)
         (set-network-link-mtu peer mtu)
         (set-network-link-up "lo")
         ;; An IPv4-only Pod's guard drops every IPv6 packet as spoofed; turn
         ;; IPv6 off before the link comes up so the Pod never sends any.
         (unless (some (lambda (item) (find #\: item)) addresses)
           (disable-network-interface-ipv6 peer))
         (loop for item in addresses
               do (add-network-address peer item (if (find #\: item) 128 32)))
         (set-network-link-up peer)
         (loop for item in gateways
               do (replace-network-route item (if (find #\: item) 128 32) peer)
                  (replace-permanent-network-neighbor peer item host-mac)
                  (replace-network-route (if (find #\: item) "::" "0.0.0.0")
                                         0 peer :gateway item))))
    host)))
