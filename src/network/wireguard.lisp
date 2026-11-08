;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Native WireGuard overlay reconciliation through Linux netlink UAPIs.

(in-package #:gr8s.network)

(defparameter +node-wireguard-interface+ "gr8s-wg")

(defun wireguard-decode-key (encoded context)
  "Decode ENCODED as one canonical 32-byte WireGuard key for CONTEXT."
  (handler-case
      (let ((key (ag-grpc:base64-decode encoded)))
        (unless (and (= 32 (length key))
                     (string= encoded (ag-grpc:base64-encode key)))
          (error "not one canonical 32-byte key"))
        key)
    (error (condition)
      (invalid-cni "invalid WireGuard ~A: ~A" context condition))))

(defun netlink-network-short (value)
  "Encode VALUE as an unsigned 16-bit integer in network byte order."
  (vector (ldb (byte 8 8) value) (ldb (byte 8 0) value)))

(defun wireguard-endpoint (address port)
  "Encode one sockaddr_in endpoint for ADDRESS and PORT."
  (netlink-octets
   (netlink-integer 2 2) ; AF_INET is host-order in sockaddr_in.
   (netlink-network-short port)
   (ipv4-network-octets address)
   (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun wireguard-allowed-ip-attributes (cidr)
  "Encode one WireGuard IPv4 allowed-ip entry for CIDR."
  (multiple-value-bind (address prefix) (parse-ipv4-cidr cidr)
    (unless (and (<= 0 prefix 32)
                 (zerop (logand address (1- (ash 1 (- 32 prefix))))))
      (invalid-cni "invalid WireGuard allowed IP ~A" cidr))
    (netlink-octets
     (netlink-attribute 1 (netlink-integer 2 2)) ; WGALLOWEDIP_A_FAMILY
     (netlink-attribute 2
                        (ipv4-network-octets (format-ipv4-integer address)))
     (netlink-attribute 3 (vector prefix)))))

(defun wireguard-peer-attributes (route)
  "Encode one peer's WireGuard Generic Netlink attributes from ROUTE."
  (let ((port (gethash "wireguardListenPort" route)))
    (unless (typep port '(integer 1 65535))
      (invalid-cni "invalid WireGuard peer listen port"))
    (netlink-octets
     (netlink-attribute
      1 (wireguard-decode-key
         (required-cni-string route "wireguardPublicKey") "peer public key"))
     ;; Replace allowed IPs so stale Pod CIDRs cannot remain reachable.
     (netlink-attribute 3 (netlink-integer 2 4))
     (netlink-attribute
      4 (wireguard-endpoint (required-cni-string route "underlayAddress") port))
     (netlink-attribute
      #x8009
      (netlink-attribute #x8000
                         (wireguard-allowed-ip-attributes
                          (required-cni-string route "podCIDR")))))))

(defun wireguard-device-attributes (interface private-key network)
  "Encode a complete replace-peers WireGuard device configuration."
  (unless (= 32 (length private-key))
    (invalid-cni "WireGuard private key must contain exactly 32 bytes"))
  (let ((port (gethash "wireguardListenPort" network)))
    (unless (typep port '(integer 1 65535))
      (invalid-cni "invalid WireGuard listen port"))
    (netlink-octets
     (netlink-attribute 2 (netlink-string interface))
     (netlink-attribute 3 private-key)
     (netlink-attribute 5 (netlink-integer 1 4)) ; WGDEVICE_F_REPLACE_PEERS
     (netlink-attribute 6 (netlink-integer port 2))
     (netlink-attribute
      #x8008
      (apply #'netlink-octets
             (loop for route across (gethash "routes" network #())
                   collect (netlink-attribute
                            #x8000 (wireguard-peer-attributes route))))))))

(defun generic-netlink-request-message (family-id command version attributes &key (flags 0))
  "Encode one acknowledged Generic Netlink request with additional FLAGS."
  (netlink-message
   family-id (logior flags 5)
   (netlink-octets (vector command version 0 0) attributes)))

(defun call-generic-netlink (family-id command version attributes &key (timeout 5) (flags 0))
  "Send COMMAND and ATTRIBUTES to one Generic Netlink FAMILY-ID and return replies."
  (let ((fd (%rtnl-socket 16 (logior 3 #o2000000) 16)) ; NETLINK_GENERIC
        (address (netlink-octets (netlink-integer 16 2)
                                 (make-array 10 :element-type '(unsigned-byte 8)
                                                :initial-element 0)))
        (message (generic-netlink-request-message
                  family-id command version attributes :flags flags))
        (buffer (make-array 65536 :element-type '(unsigned-byte 8)))
        (replies nil)
        (deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (when (minusp fd) (fail-rtnetlink "generic socket" (sb-alien:get-errno)))
    (unwind-protect
         (progn
           (sb-sys:with-pinned-objects (address message)
             (unless (zerop (%rtnl-connect fd (sb-sys:vector-sap address) 12))
               (fail-rtnetlink "generic connect" (sb-alien:get-errno)))
             (unless (= (length message)
                        (%rtnl-send fd (sb-sys:vector-sap message)
                                    (length message) 0))
               (fail-rtnetlink "generic send" (sb-alien:get-errno))))
           (loop
             (let ((remaining (/ (- deadline (get-internal-real-time))
                                 internal-time-units-per-second)))
               (unless (and (plusp remaining)
                            (sb-sys:wait-until-fd-usable fd :input remaining))
                 (invalid-cni "timed out waiting for Generic Netlink acknowledgement")))
             (let ((count
                     (sb-sys:with-pinned-objects (buffer)
                       (%rtnl-recv fd (sb-sys:vector-sap buffer)
                                   (length buffer) 32))))
               (when (minusp count)
                 (fail-rtnetlink "generic receive" (sb-alien:get-errno)))
               (when (> count (length buffer))
                 (invalid-cni "Generic Netlink datagram exceeds receive buffer"))
               (multiple-value-bind (messages acknowledged)
                   (parse-netlink-reply buffer count 1)
                 (setf replies (nconc replies messages))
                 (when acknowledged (return replies))))))
      (sb-posix:close fd))))

(defun generic-netlink-family-id (name)
  "Resolve Generic Netlink family NAME through nlctrl."
  (let* ((replies
           (call-generic-netlink
            16 3 2 (netlink-attribute 2 (netlink-string name))))
         (reply (first replies)))
    (unless (and reply (>= (length reply) 20))
      (invalid-cni "Generic Netlink family ~A returned no identity" name))
    (let ((id (gethash 1 (netlink-attributes reply 20))))
      (unless (and id (= 2 (length id)))
        (invalid-cni "Generic Netlink family ~A returned an invalid identity" name))
      (netlink-read-integer id 0 2))))

(defun configure-wireguard-device (interface private-key network)
  "Replace INTERFACE's WireGuard private key, listen port, and complete peer set."
  (call-generic-netlink
   (generic-netlink-family-id "wireguard") 1 1
   (wireguard-device-attributes interface private-key network))
  nil)

(defstruct wireguard-peer-status
  "One peer observation returned by Linux's WireGuard Generic Netlink API."
  public-key
  (latest-handshake-seconds 0)
  (latest-handshake-nanoseconds 0)
  (received-bytes 0)
  (transmitted-bytes 0))

(defun wireguard-nested-attribute-payloads (bytes)
  "Return every top-level nested attribute payload in BYTES, preserving order."
  (let ((offset 0) (payloads nil))
    (loop while (< offset (length bytes))
          do (when (< (- (length bytes) offset) 4)
               (invalid-cni "truncated WireGuard nested attribute"))
             (let ((size (netlink-read-integer bytes offset 2)))
               (unless (<= 4 size (- (length bytes) offset))
                 (invalid-cni "invalid WireGuard nested attribute length"))
               (push (subseq bytes (+ offset 4) (+ offset size)) payloads)
               (incf offset (netlink-align size))))
    (nreverse payloads)))

(defun wireguard-peer-status-from-attributes (attributes)
  "Decode one peer ATTRIBUTES payload returned by WG_CMD_GET_DEVICE."
  (let* ((key (gethash 1 attributes))
         (handshake (gethash 6 attributes))
         (received (gethash 7 attributes))
         (transmitted (gethash 8 attributes)))
    (unless (and key (= 32 (length key)))
      (invalid-cni "WireGuard peer status has no valid public key"))
    (unless (or (null handshake) (= 16 (length handshake)))
      (invalid-cni "WireGuard peer status has an invalid handshake timestamp"))
    (unless (and received (= 8 (length received)) transmitted (= 8 (length transmitted)))
      (invalid-cni "WireGuard peer status has invalid byte counters"))
    (make-wireguard-peer-status
     :public-key key
     :latest-handshake-seconds (if handshake (netlink-read-integer handshake 0 8) 0)
     :latest-handshake-nanoseconds (if handshake (netlink-read-integer handshake 8 8) 0)
     :received-bytes (netlink-read-integer received 0 8)
     :transmitted-bytes (netlink-read-integer transmitted 0 8))))

(defun wireguard-peer-statuses-from-messages (messages)
  "Decode all peer observations from WG_CMD_GET_DEVICE reply MESSAGES."
  (loop for message in messages
        for device = (netlink-attributes message 20)
        for peers = (gethash 8 device)
        when peers
          append (loop for payload in (wireguard-nested-attribute-payloads peers)
                       collect (wireguard-peer-status-from-attributes
                                (netlink-attributes payload 0)))))

(defun wireguard-device-public-key-from-messages (messages)
  "Return the local device public key from WG_CMD_GET_DEVICE MESSAGES, or NIL."
  (loop for message in messages
        for device = (netlink-attributes message 20)
        for key = (gethash 4 device)
        when (and key (= 32 (length key))) return key))

(defun wireguard-device-messages (&optional (interface +node-wireguard-interface+))
  "Return the kernel's complete Generic Netlink description of INTERFACE."
  (call-generic-netlink
   (generic-netlink-family-id "wireguard") 0 1
   (netlink-attribute 2 (netlink-string interface))
   :flags #x300)) ; NLM_F_ROOT | NLM_F_MATCH (NLM_F_DUMP)

(defun read-wireguard-peer-statuses (&optional (interface +node-wireguard-interface+))
  "Read INTERFACE's peers, handshake times and byte counters from the kernel."
  (wireguard-peer-statuses-from-messages
   (wireguard-device-messages interface)))

(defun wireguard-peer-key-set (keys)
  "Return canonical, order-independent base64 identities for WireGuard KEYS."
  (sort (mapcar #'ag-grpc:base64-encode keys) #'string<))

(defun wireguard-desired-peer-keys (network)
  "Return NETWORK's decoded desired peer public keys."
  (loop for route across (gethash "routes" network #())
        collect (wireguard-decode-key
                 (required-cni-string route "wireguardPublicKey")
                 "peer public key")))

(defun wireguard-live-peer-keys-match-p
    (network &key (status-reader #'read-wireguard-peer-statuses))
  "True when the live peer key set exactly matches NETWORK's desired peers."
  (equal (wireguard-peer-key-set (wireguard-desired-peer-keys network))
         (wireguard-peer-key-set
          (mapcar #'wireguard-peer-status-public-key (funcall status-reader)))))

(defun wireguard-topology-identity (network)
  "Return the WireGuard configuration fields whose change requires replacement."
  (list (gethash "nodePodCIDR" network)
        (gethash "underlayAddress" network)
        (gethash "mtu" network)
        (gethash "wireguardListenPort" network)
        (loop for route across (gethash "routes" network #())
              collect (list (gethash "nodeID" route)
                            (gethash "podCIDR" route)
                            (gethash "underlayAddress" route)
                            (gethash "wireguardPublicKey" route)
                            (gethash "wireguardListenPort" route)))))

(defun wireguard-live-configuration-matches-p (network private-key)
  "True when the kernel already has PRIVATE-KEY's identity and NETWORK's peers."
  (handler-case
      (let* ((messages (wireguard-device-messages))
             (local-key (wireguard-device-public-key-from-messages messages))
             (statuses (wireguard-peer-statuses-from-messages messages)))
        (and local-key
             (equalp local-key (gr8s.security::wireguard-public-key private-key))
             (wireguard-live-peer-keys-match-p
              network :status-reader (lambda () statuses))))
    (error () nil)))

(defun node-wireguard-owner (network)
  "Return the ownership alias for NETWORK's node-local WireGuard device."
  (format nil "gr8s:wireguard:~A" (gethash "nodePodCIDR" network)))

(defun node-wireguard-owned-p (network)
  "Whether the existing gr8s-wg is a WireGuard device owned by NETWORK."
  (let ((attributes (network-link-attributes +node-wireguard-interface+)))
    (and (network-link-kind-p attributes "wireguard")
         (equalp (gethash 20 attributes)
                 (netlink-string (node-wireguard-owner network))))))

(defun create-node-wireguard (mtu)
  "Create the node WireGuard link at MTU, leaving ownership and keys unset."
  (call-rtnetlink
   16 #x600
   (netlink-octets
    (netlink-interface-message)
    (netlink-attribute 3 (netlink-string +node-wireguard-interface+))
    (netlink-attribute 4 (netlink-integer mtu 4))
    (netlink-attribute
     18 (netlink-attribute 1 (netlink-string "wireguard"))))))

(defun ensure-node-wireguard (network)
  "Create or retain NETWORK's owned WireGuard link and return its name."
  (let ((name +node-wireguard-interface+)
        (owner (node-wireguard-owner network)))
    (when (zerop (native-interface-index name))
      (handler-case
          (progn
            (create-node-wireguard (gethash "mtu" network))
            (set-network-link-owner name owner))
        (error (condition)
          (ignore-errors (delete-network-link name))
          (error condition))))
    (unless (node-wireguard-owned-p network)
      (invalid-cni "WireGuard interface is owned by another network"))
    (set-network-link-mtu name (gethash "mtu" network))
    (add-network-address name
                         (vxlan-router-address (gethash "nodePodCIDR" network)) 32)
    (set-network-link-up name)
    name))

(defun wireguard-route-cidrs (network)
  "Return NETWORK's peer Pod CIDRs."
  (loop for route across (gethash "routes" network #())
        collect (gethash "podCIDR" route)))

(defun remove-owned-wireguard (networks)
  "Remove gr8s-wg when one of NETWORKS proves that gr8s owns it."
  (unless (zerop (native-interface-index +node-wireguard-interface+))
    (unless (some #'node-wireguard-owned-p networks)
      (invalid-cni "refusing to remove an unowned WireGuard interface"))
    (delete-network-link +node-wireguard-interface+))
  nil)

(defun reconcile-node-wireguard-network (network previous-networks private-key)
  "Converge the owned WireGuard link, complete peer set, and Pod-CIDR routes."
  (let* ((local (gethash "underlayAddress" network ""))
         (wanted (wireguard-route-cidrs network))
         (previous (first previous-networks))
         (previous-routes
           (remove-duplicates
            (mapcan #'wireguard-route-cidrs previous-networks) :test #'equal)))
    (when (string= local "")
      (remove-owned-wireguard (cons network previous-networks))
      (return-from reconcile-node-wireguard-network nil))
    (unless (zerop (native-interface-index +node-wireguard-interface+))
      (unless (node-wireguard-owned-p network)
        (unless (some #'node-wireguard-owned-p previous-networks)
          (invalid-cni "refusing to replace an unowned WireGuard interface"))
        (delete-network-link +node-wireguard-interface+)
        (setf previous-routes nil)))
    (ensure-node-wireguard network)
    ;; WGDEVICE_F_REPLACE_PEERS deletes and recreates every peer, which resets
    ;; handshake and byte-counter telemetry. Replace only for actual topology or
    ;; key drift; unchanged cached-network repair still verifies the live keys.
    (when (or (null previous)
              (not (equal (wireguard-topology-identity network)
                          (wireguard-topology-identity previous)))
              (not (wireguard-live-configuration-matches-p network private-key)))
      (configure-wireguard-device +node-wireguard-interface+ private-key network))
    (dolist (cidr previous-routes)
      (unless (member cidr wanted :test #'equal)
        (multiple-value-bind (address prefix) (parse-ipv4-cidr cidr)
          (remove-network-route (format-ipv4-integer address) prefix
                                +node-wireguard-interface+))))
    (dolist (cidr wanted)
      (multiple-value-bind (address prefix) (parse-ipv4-cidr cidr)
        (replace-network-route
         (format-ipv4-integer address) prefix +node-wireguard-interface+
         :source (vxlan-router-address (gethash "nodePodCIDR" network))))))
  nil)

(defun reconcile-node-overlay-network (network previous-networks private-key)
  "Dispatch NETWORK to the selected overlay and retire the previously owned other backend."
  (let ((backend (gethash "overlayBackend" network "vxlan")))
    (cond
      ((string= backend "wireguard")
       (unless (zerop (native-interface-index +node-vxlan-interface+))
         (when (some #'node-vxlan-owned-or-adoptable-p previous-networks)
           (delete-network-link +node-vxlan-interface+)))
       (reconcile-node-wireguard-network network previous-networks private-key))
      ((string= backend "vxlan")
       (unless (zerop (native-interface-index +node-wireguard-interface+))
         (remove-owned-wireguard (cons network previous-networks)))
       (reconcile-node-vxlan-network network previous-networks))
      (t (invalid-cni "unsupported overlay backend ~A" backend)))))
