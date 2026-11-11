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
  "Encode one WireGuard IPv4 or IPv6 allowed-ip entry for CIDR."
  (multiple-value-bind (family address prefix bits) (parse-pod-cidr cidr)
    (unless (and (zerop (logand address (1- (ash 1 (- bits prefix)))))
                 (string= cidr
                          (format nil "~A/~D" (format-pod-address family address) prefix)))
      (invalid-cni "invalid WireGuard allowed IP ~A" cidr))
    (netlink-octets
     (netlink-attribute 1 (netlink-integer (if (eq family :ipv6) 10 2) 2))
     (netlink-attribute 2 (nth-value 1
                                    (network-address-wire-values
                                     (format-pod-address family address))))
     (netlink-attribute 3 (vector prefix)))))

(defun wireguard-peer-identity (peer)
  "Return the security-relevant identity advertised for PEER."
  (list (gethash "nodeName" peer (required-cni-string peer "nodeID"))
        (required-cni-string peer "underlayAddress")
        (required-cni-string peer "wireguardPublicKey")
        (gethash "wireguardListenPort" peer)
        (sort
         (loop for endpoint across (gethash "wireguardEndpoints" peer #())
               collect (list (required-cni-string endpoint "name")
                             (required-cni-string endpoint "address")
                             (gethash "port" endpoint)))
         #'string< :key #'first)))

(defun wireguard-peer-identity-equal-p (left right)
  "Whether LEFT and RIGHT consistently describe the same authenticated peer."
  (equal (wireguard-peer-identity left) (wireguard-peer-identity right)))

(defun wireguard-peer-routes (network)
  "Group destination Pod CIDRs by their authenticated direct or sparse next hop."
  (let ((groups (make-hash-table :test #'equal)))
    (loop for route across (gethash "routes" network #())
          for peer = (or (gethash "nextHop" route) route)
          for peer-id = (required-cni-string peer "nodeID")
          for existing = (gethash peer-id groups)
          for group = (or existing
                          (setf (gethash peer-id groups)
                                (json-object
                                 "nodeID" peer-id
                                 "nodeName" (gethash "nodeName" peer peer-id)
                                 "underlayAddress"
                                 (required-cni-string peer "underlayAddress")
                                 "wireguardPublicKey"
                                 (required-cni-string peer "wireguardPublicKey")
                                 "wireguardListenPort"
                                 (gethash "wireguardListenPort" peer)
                                 "wireguardEndpoints"
                                 (gethash "wireguardEndpoints" peer #())
                                 "podCIDRs" nil)))
          when (and existing
                    (not (wireguard-peer-identity-equal-p existing peer)))
            do (invalid-cni
                "conflicting WireGuard next-hop identity for ~A" peer-id)
          when (string= (required-cni-string route "nodeID") peer-id)
            do (setf (gethash "probeCIDR" group)
                     (first (route-pod-cidrs route)))
          do (dolist (cidr (route-pod-cidrs route))
               (pushnew cidr (gethash "podCIDRs" group) :test #'string=)))
    (let ((result nil))
      (maphash
       (lambda (peer-id group)
         (declare (ignore peer-id))
         (let ((cidrs (sort (copy-list (gethash "podCIDRs" group)) #'string<)))
           (setf (gethash "podCIDRs" group) (coerce cidrs 'vector)
                 ;; Active probes need any destination known to traverse this peer.
                 (gethash "podCIDR" group) (first cidrs)))
         (push group result))
       groups)
      (sort result #'string< :key (lambda (group) (gethash "nodeID" group))))))

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
     ;; Keep the kernel's authenticated UDP mapping warm so a rendezvous node
     ;; can observe and redistribute the reflexive endpoint for hole punching.
     (netlink-attribute 5 (netlink-integer 25 2))
     (netlink-attribute
      #x8009
      (apply #'netlink-octets
             (loop for cidr in (route-pod-cidrs route)
                   for index from 0
                   collect (netlink-attribute
                            (logior #x8000 index)
                            (wireguard-allowed-ip-attributes cidr))))))))

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
             (loop for route in (wireguard-peer-routes network)
                   collect (netlink-attribute
                            #x8000 (wireguard-peer-attributes route))))))))

(defun wireguard-peer-endpoint-device-attributes
    (interface public-key address port)
  "Encode a non-destructive update of one peer's endpoint. It deliberately
omits replace flags and allowed IPs, leaving identity and routing intact."
  (unless (= 32 (length public-key))
    (invalid-cni "WireGuard peer public key must contain exactly 32 bytes"))
  (unless (typep port '(integer 1 65535))
    (invalid-cni "invalid WireGuard peer endpoint port"))
  (netlink-octets
   (netlink-attribute 2 (netlink-string interface))
   (netlink-attribute
    #x8008
    (netlink-attribute
     #x8000
     (netlink-octets
      (netlink-attribute 1 public-key)
      (netlink-attribute 4 (wireguard-endpoint address port)))))))

(defun wireguard-single-peer-device-attributes (interface peer cidrs)
  "Encode a non-destructive add/update of PEER with exactly CIDRS as AllowedIPs."
  (let ((staged (json-object
                 "nodeID" (required-cni-string peer "nodeID")
                 "underlayAddress" (required-cni-string peer "underlayAddress")
                 "wireguardPublicKey" (required-cni-string peer "wireguardPublicKey")
                 "wireguardListenPort" (gethash "wireguardListenPort" peer)
                 "podCIDRs" (coerce cidrs 'vector))))
    (netlink-octets
     (netlink-attribute 2 (netlink-string interface))
     (netlink-attribute
      #x8008
      (netlink-attribute #x8000 (wireguard-peer-attributes staged))))))

(defun wireguard-remove-peer-device-attributes (interface public-key)
  "Encode a non-destructive removal of one WireGuard peer."
  (netlink-octets
   (netlink-attribute 2 (netlink-string interface))
   (netlink-attribute
    #x8008
    (netlink-attribute
     #x8000
     (netlink-octets
      (netlink-attribute 1 public-key)
      (netlink-attribute 3 (netlink-integer 1 4))))))) ; WGPEER_F_REMOVE_ME

(defun wireguard-peer-session-reset-device-attributes (interface public-key)
  "Encode a non-destructive expiration of PUBLIC-KEY's current Noise keypair.
Linux expires the peer keypair when its disabled all-zero preshared key is
re-applied. Endpoint, allowed IPs, identity, and the peer itself remain intact."
  (unless (= 32 (length public-key))
    (invalid-cni "WireGuard peer public key must contain exactly 32 bytes"))
  (netlink-octets
   (netlink-attribute 2 (netlink-string interface))
   (netlink-attribute
    #x8008
    (netlink-attribute
     #x8000
     (netlink-octets
      (netlink-attribute 1 public-key)
      ;; WGPEER_A_PRESHARED_KEY. All zeroes mean no PSK, as in the complete
      ;; peer configuration; setting it still expires Linux's live keypair.
      (netlink-attribute
       2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))))))

(defun configure-wireguard-peer-endpoint
    (public-key address port &optional (interface +node-wireguard-interface+))
  "Change only PUBLIC-KEY's endpoint on INTERFACE."
  (call-generic-netlink
   (generic-netlink-family-id "wireguard") 1 1
   (wireguard-peer-endpoint-device-attributes
    interface public-key address port))
  nil)

(defun configure-wireguard-peer-cidrs
    (peer cidrs &optional (interface +node-wireguard-interface+))
  "Add or update PEER non-destructively with exactly CIDRS as AllowedIPs."
  (call-generic-netlink
   (generic-netlink-family-id "wireguard") 1 1
   (wireguard-single-peer-device-attributes interface peer cidrs))
  nil)

(defun configure-wireguard-staged-peer
    (peer probe-cidr &optional (interface +node-wireguard-interface+))
  "Add PEER non-destructively with only PROBE-CIDR routed to it."
  (configure-wireguard-peer-cidrs peer (list probe-cidr) interface))

(defun remove-wireguard-peer
    (public-key &optional (interface +node-wireguard-interface+))
  "Remove PUBLIC-KEY from INTERFACE without disturbing other peers."
  (call-generic-netlink
   (generic-netlink-family-id "wireguard") 1 1
   (wireguard-remove-peer-device-attributes interface public-key))
  nil)

(defun reset-wireguard-peer-session
    (public-key &optional (interface +node-wireguard-interface+))
  "Expire only PUBLIC-KEY's live session on INTERFACE, retaining its LKG config."
  (call-generic-netlink
   (generic-netlink-family-id "wireguard") 1 1
   (wireguard-peer-session-reset-device-attributes interface public-key))
  nil)

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
  (endpoint-address "")
  (endpoint-port 0)
  (latest-handshake-seconds 0)
  (latest-handshake-nanoseconds 0)
  (received-bytes 0)
  (transmitted-bytes 0))

(defun wireguard-endpoint-tuple-object (endpoint)
  (json-object "name" (first endpoint)
               "address" (second endpoint)
               "port" (third endpoint)))

(defun wireguard-endpoint-object-tuple (object)
  (unless (hash-table-p object)
    (error "Invalid persisted WireGuard endpoint"))
  (let ((name (gethash "name" object))
        (address (gethash "address" object))
        (port (gethash "port" object)))
    (unless (and (stringp name) (plusp (length name))
                 (stringp address) (plusp (length address))
                 (typep port '(integer 1 65535)))
      (error "Invalid persisted WireGuard endpoint"))
    (list name address port)))

(defun persisted-wireguard-integer (object key minimum maximum &optional default)
  (let ((value (gethash key object default)))
    (unless (and (integerp value) (<= minimum value maximum))
      (error "Invalid persisted WireGuard field ~A" key))
    value))

(defun persisted-wireguard-keyword (object key choices &optional default)
  (let* ((value (gethash key object default))
         (match (and (stringp value) (assoc value choices :test #'string=))))
    (unless match (error "Invalid persisted WireGuard field ~A" key))
    (cdr match)))

(defun wireguard-path-observation-object (observation)
  (let ((object
          (json-object
           "name" (wireguard-path-observation-name observation)
           "address" (wireguard-path-observation-address observation)
           "port" (wireguard-path-observation-port observation)
           "latestHandshakeSeconds"
           (wireguard-path-observation-latest-handshake-seconds observation)
           "handshakeAgeSeconds" (wireguard-path-observation-handshake-age-seconds observation)
           "transferredBytesDelta" (wireguard-path-observation-transferred-bytes-delta observation)
           "transferredBytesTotal" (wireguard-path-observation-transferred-bytes-total observation)
           "passiveTcpSamples" (wireguard-path-observation-passive-tcp-samples observation)
           "passiveRetransmits" (wireguard-path-observation-passive-retransmits observation)
           "passiveActiveFlows" (wireguard-path-observation-passive-active-flows observation)
           "passiveBytesPerSecond" (wireguard-path-observation-passive-bytes-per-second observation)
           "safeMTU" (wireguard-path-observation-safe-mtu observation)
           "lastMTUProbeAt" (wireguard-path-observation-last-mtu-probe-at observation)
           "mtuReason" (string-downcase
                        (symbol-name (wireguard-path-observation-mtu-reason observation)))
           "mtuChangedAt" (wireguard-path-observation-mtu-changed-at observation)
           "mtuUpgradeSuccesses"
           (wireguard-path-observation-mtu-upgrade-successes observation)
           "consecutiveSuccesses" (wireguard-path-observation-consecutive-successes observation)
           "consecutiveFailures" (wireguard-path-observation-consecutive-failures observation))))
    (when (wireguard-path-observation-trial-latency-milliseconds observation)
      (setf (gethash "trialLatencyMilliseconds" object)
            (wireguard-path-observation-trial-latency-milliseconds observation)))
    (when (wireguard-path-observation-passive-rtt-microseconds observation)
      (setf (gethash "passiveRttMicroseconds" object)
            (wireguard-path-observation-passive-rtt-microseconds observation)))
    (when (wireguard-path-observation-passive-congestion-window observation)
      (setf (gethash "passiveCongestionWindow" object)
            (wireguard-path-observation-passive-congestion-window observation)))
    (when (wireguard-path-observation-mtu-upgrade-candidate observation)
      (setf (gethash "mtuUpgradeCandidate" object)
            (wireguard-path-observation-mtu-upgrade-candidate observation)))
    object))

(defun wireguard-path-observation-from-object (object)
  (unless (hash-table-p object)
    (error "Invalid persisted WireGuard observation"))
  (labels ((optional-integer (key minimum maximum)
             (let ((value (gethash key object)))
               (when value
                 (unless (and (integerp value) (<= minimum value maximum))
                   (error "Invalid persisted WireGuard field ~A" key)))
               value)))
    (let ((name (gethash "name" object))
          (address (gethash "address" object))
          (candidate (optional-integer "mtuUpgradeCandidate" 576 9000)))
      (unless (and (stringp name) (plusp (length name))
                   (stringp address) (plusp (length address)))
        (error "Invalid persisted WireGuard observation identity"))
      (make-wireguard-path-observation
       :name name :address address
       :port (persisted-wireguard-integer object "port" 1 65535)
       :latest-handshake-seconds
       (persisted-wireguard-integer object "latestHandshakeSeconds" 0 most-positive-fixnum 0)
       :handshake-age-seconds
       (persisted-wireguard-integer object "handshakeAgeSeconds" 0 most-positive-fixnum
                                    most-positive-fixnum)
       :transferred-bytes-delta
       (persisted-wireguard-integer object "transferredBytesDelta" 0 most-positive-fixnum 0)
       :transferred-bytes-total
       (persisted-wireguard-integer object "transferredBytesTotal" 0 most-positive-fixnum 0)
       :passive-rtt-microseconds (optional-integer "passiveRttMicroseconds" 0 10000000)
       :passive-tcp-samples
       (persisted-wireguard-integer object "passiveTcpSamples" 0 1000000000 0)
       :passive-retransmits
       (persisted-wireguard-integer object "passiveRetransmits" 0 1000000000 0)
       :passive-congestion-window (optional-integer "passiveCongestionWindow" 0 1000000)
       :passive-active-flows
       (persisted-wireguard-integer object "passiveActiveFlows" 0 1000000 0)
       :passive-bytes-per-second
       (persisted-wireguard-integer object "passiveBytesPerSecond" 0 1000000000000 0)
       :safe-mtu (persisted-wireguard-integer object "safeMTU" 576 9000 1420)
       :last-mtu-probe-at
       (persisted-wireguard-integer object "lastMTUProbeAt" 0 most-positive-fixnum 0)
       :mtu-reason
       (persisted-wireguard-keyword
        object "mtuReason"
        '(("initial" . :initial) ("probe-verified" . :probe-verified)
          ("maximum-verified" . :maximum-verified)
          ("packet-size-black-hole" . :packet-size-black-hole))
        "initial")
       :mtu-changed-at
       (persisted-wireguard-integer object "mtuChangedAt" 0 most-positive-fixnum 0)
       :mtu-upgrade-candidate candidate
       :mtu-upgrade-successes
       (persisted-wireguard-integer object "mtuUpgradeSuccesses" 0 3 0)
       :trial-latency-milliseconds
       (optional-integer "trialLatencyMilliseconds" 0 3600000)
       :consecutive-successes
       (persisted-wireguard-integer object "consecutiveSuccesses" 0 1000000000 0)
       :consecutive-failures
       (persisted-wireguard-integer object "consecutiveFailures" 0 1000000000 0)))))

(defun wireguard-peer-path-state-object (peer)
  (json-object
   "peerID" (wireguard-peer-path-state-peer-id peer)
   "selected" (wireguard-endpoint-tuple-object
               (wireguard-peer-path-state-selected peer))
   "previous" (wireguard-endpoint-tuple-object
               (wireguard-peer-path-state-previous peer))
   "reason" (string-downcase
             (symbol-name (wireguard-peer-path-state-reason peer)))
   "changedAt" (wireguard-peer-path-state-changed-at peer)
   "lastTrialAt" (wireguard-peer-path-state-last-trial-at peer)
   "observations"
   (coerce (mapcar #'wireguard-path-observation-object
                   (wireguard-peer-path-state-observations peer))
           'vector)))

(defun wireguard-path-state-object (state)
  (let ((peers (make-hash-table :test #'equal)))
    (maphash
     (lambda (peer-id peer)
       (setf (gethash peer-id peers)
             (wireguard-peer-path-state-object peer)))
     (wireguard-path-state-peers state))
    (json-object
     "version" 1
     "peers" peers
     "history" (coerce (wireguard-path-state-history state) 'vector))))

(defun persist-wireguard-path-state (path state)
  "Atomically persist STATE with private permissions."
  (write-private-text-atomically
   path (com.inuoe.jzon:stringify (wireguard-path-state-object state)))
  state)

(defun load-wireguard-path-state (path)
  "Load PATH, or return empty restart-safe state when it does not exist."
  (if (not (probe-file path))
      (make-wireguard-path-state)
      (let* ((object (com.inuoe.jzon:parse path))
             (state (make-wireguard-path-state))
             (peers (and (hash-table-p object) (gethash "peers" object)))
             (history (and (hash-table-p object) (gethash "history" object #()))))
        (unless (and (eql 1 (gethash "version" object))
                     (hash-table-p peers)
                     (vectorp history)
                     (<= (length history) 64)
                     (every #'hash-table-p history))
          (error "Invalid WireGuard path state"))
        (maphash
         (lambda (peer-id peer)
           (unless (and (stringp peer-id) (hash-table-p peer)
                        (vectorp (gethash "observations" peer #())))
             (error "Invalid persisted WireGuard peer"))
           (setf
            (gethash peer-id (wireguard-path-state-peers state))
            (make-wireguard-peer-path-state
             :peer-id peer-id
             :selected
             (wireguard-endpoint-object-tuple (gethash "selected" peer))
             :previous
             (wireguard-endpoint-object-tuple (gethash "previous" peer))
             :reason
             (persisted-wireguard-keyword
              peer "reason"
              '(("initial" . :initial) ("current-unhealthy" . :current-unhealthy)
                ("sustained-improvement" . :sustained-improvement)
                ("candidate-unproven" . :candidate-unproven)
                ("current-preferred" . :current-preferred)
                ("no-healthy-alternative" . :no-healthy-alternative)
                ("endpoint-withdrawn" . :endpoint-withdrawn)))
             :changed-at
             (persisted-wireguard-integer peer "changedAt" 0 most-positive-fixnum 0)
             :last-trial-at
             (persisted-wireguard-integer peer "lastTrialAt" 0 most-positive-fixnum 0)
             :observations
             (loop for observation across (gethash "observations" peer #())
                   collect (wireguard-path-observation-from-object observation)))))
         peers)
        (setf (wireguard-path-state-history state) (coerce history 'list))
        state)))

(defun record-wireguard-path-decision
    (state peer-id selected previous reason changed-at)
  "Commit one human-readable decision and retain the newest 64 events."
  (let ((peer (or (gethash peer-id (wireguard-path-state-peers state))
                  (setf (gethash peer-id (wireguard-path-state-peers state))
                        (make-wireguard-peer-path-state :peer-id peer-id)))))
    (setf (wireguard-peer-path-state-selected peer) (copy-list selected)
          (wireguard-peer-path-state-previous peer) (copy-list previous)
          (wireguard-peer-path-state-reason peer) reason
          (wireguard-peer-path-state-changed-at peer) changed-at)
    (push (json-object
           "peerID" peer-id
           "selected" (wireguard-endpoint-tuple-object selected)
           "previous" (wireguard-endpoint-tuple-object previous)
           "reason" (string-downcase (symbol-name reason))
           "changedAt" changed-at)
          (wireguard-path-state-history state))
    (when (> (length (wireguard-path-state-history state)) 64)
      (setf (wireguard-path-state-history state)
            (subseq (wireguard-path-state-history state) 0 64)))
    peer))

(defun wireguard-path-explanation-object (state peer-id)
  "Return durable, human-readable evidence for PEER-ID, or signal if unknown."
  (let ((peer (gethash peer-id (wireguard-path-state-peers state))))
    (unless peer (error "No WireGuard path observations for peer ~A" peer-id))
    (json-object
     "peerID" peer-id
     "selected" (wireguard-endpoint-tuple-object
                  (wireguard-peer-path-state-selected peer))
     "previous" (wireguard-endpoint-tuple-object
                  (wireguard-peer-path-state-previous peer))
     "reason" (string-downcase (symbol-name (wireguard-peer-path-state-reason peer)))
     "changedAt" (wireguard-peer-path-state-changed-at peer)
     "lastTrialAt" (wireguard-peer-path-state-last-trial-at peer)
     "candidates"
     (coerce
      (mapcar
       (lambda (observation)
         (let ((object (wireguard-path-observation-object observation)))
           (setf (gethash "healthy" object) (wireguard-path-healthy-p observation)
                 (gethash "score" object) (wireguard-path-score observation))
           object))
       (wireguard-peer-path-state-observations peer))
      'vector))))

(defun wireguard-route-endpoints (route)
  "Return the authenticated underlay endpoint followed by advertised candidates."
  (cons (list "underlay" (gethash "underlayAddress" route)
              (gethash "wireguardListenPort" route))
        (loop for endpoint across (gethash "wireguardEndpoints" route #())
              collect (wireguard-endpoint-object-tuple endpoint))))

(defun wireguard-observation-for-endpoint (peer endpoint)
  (or (find endpoint (wireguard-peer-path-state-observations peer)
            :test #'equal
            :key (lambda (observation)
                   (list (wireguard-path-observation-name observation)
                         (wireguard-path-observation-address observation)
                         (wireguard-path-observation-port observation))))
      (let ((observation
              (make-wireguard-path-observation
               :name (first endpoint) :address (second endpoint) :port (third endpoint))))
        (push observation (wireguard-peer-path-state-observations peer))
        observation)))

(defun wireguard-observation-endpoint (observation)
  (list (wireguard-path-observation-name observation)
        (wireguard-path-observation-address observation)
        (wireguard-path-observation-port observation)))

(defun apply-wireguard-path-telemetry-samples (state samples)
  "Apply peer telemetry only to the endpoint selected while it accumulated."
  (maphash
   (lambda (peer-id telemetry)
     (let ((peer (gethash peer-id (wireguard-path-state-peers state))))
       (when peer
         (apply-wireguard-path-telemetry
          (wireguard-observation-for-endpoint
           peer (wireguard-peer-path-state-selected peer))
          telemetry))))
   samples)
  state)

(defun wireguard-path-round-trip-p
    (public-key endpoint baseline-received-bytes probe
     &key (status-reader #'read-wireguard-peer-statuses)
       (timeout-milliseconds 250)
       (clock-milliseconds
         (lambda ()
           (floor (* 1000 (get-internal-real-time))
                  internal-time-units-per-second)))
       (sleep-function #'sleep))
  "Prove that authenticated traffic returned over exactly ENDPOINT. A fresh
handshake alone is insufficient: a recently dead link can retain one for minutes."
  (destructuring-bind (name address port) endpoint
    (declare (ignore name))
    (let ((started (funcall clock-milliseconds)))
      (loop
        (funcall probe)
        (when (some
               (lambda (status)
                 (and (equalp public-key (wireguard-peer-status-public-key status))
                      (string= address (wireguard-peer-status-endpoint-address status))
                      (= port (wireguard-peer-status-endpoint-port status))
                      (> (wireguard-peer-status-received-bytes status)
                         baseline-received-bytes)))
               (funcall status-reader))
          (return t))
        (when (>= (- (funcall clock-milliseconds) started) timeout-milliseconds)
          (return nil))
        (funcall sleep-function 0.025)))))

(defun reconcile-wireguard-path-inventory (state network now)
  "Prune durable evidence to authenticated routes and currently advertised endpoints."
  (let ((routes (make-hash-table :test #'equal))
        (departed nil))
    (loop for route in (wireguard-peer-routes network)
          for peer-id = (gethash "nodeName" route (gethash "nodeID" route))
          do (setf (gethash peer-id routes) route))
    (maphash
     (lambda (peer-id peer)
       (let ((route (gethash peer-id routes)))
         (if (null route)
             (push peer-id departed)
             (let* ((endpoints (wireguard-route-endpoints route))
                    (selected (wireguard-peer-path-state-selected peer)))
               (setf (wireguard-peer-path-state-observations peer)
                     (remove-if-not
                      (lambda (observation)
                        (find (wireguard-observation-endpoint observation)
                              endpoints :test #'equal))
                      (wireguard-peer-path-state-observations peer)))
               (unless (find selected endpoints :test #'equal)
                 (let ((replacement (copy-list (first endpoints))))
                   (record-wireguard-path-decision
                    state peer-id replacement selected :endpoint-withdrawn now)
                   ;; A withdrawn endpoint cannot remain the rollback target.
                   (setf (wireguard-peer-path-state-previous peer)
                         (copy-list replacement))))
               (unless (find (wireguard-peer-path-state-previous peer)
                             endpoints :test #'equal)
                 (setf (wireguard-peer-path-state-previous peer)
                       (copy-list (wireguard-peer-path-state-selected peer))))))))
     (wireguard-path-state-peers state))
    (dolist (peer-id departed)
      (remhash peer-id (wireguard-path-state-peers state))))
  state)

(defun reconcile-wireguard-path-state
    (state network
     &key now
       (status-reader #'read-wireguard-peer-statuses)
       (trial-function #'trial-wireguard-peer-endpoint)
       (endpoint-setter #'configure-wireguard-peer-endpoint)
       (health-function #'wireguard-path-round-trip-p)
       probe-function)
  "Observe and conservatively trial one authenticated endpoint per peer.
Successful exploratory trials are restored unless selection commits them."
  (let ((now (or now (- (get-universal-time) 2208988800)))
        (statuses (funcall status-reader)))
    (reconcile-wireguard-path-inventory state network now)
    (loop for route in (wireguard-peer-routes network)
          for peer-id = (gethash "nodeName" route (gethash "nodeID" route))
          for public-key = (wireguard-decode-key
                            (gethash "wireguardPublicKey" route) "peer public key")
          for status = (find public-key statuses :test #'equalp
                             :key #'wireguard-peer-status-public-key)
          when status
            do (let* ((endpoints (wireguard-route-endpoints route))
                      (kernel-endpoint
                        (find-if (lambda (endpoint)
                                   (and (string= (second endpoint)
                                                 (wireguard-peer-status-endpoint-address status))
                                        (= (third endpoint)
                                           (wireguard-peer-status-endpoint-port status))))
                                 endpoints))
                      (peer (or (gethash peer-id (wireguard-path-state-peers state))
                                (setf (gethash peer-id (wireguard-path-state-peers state))
                                      (make-wireguard-peer-path-state
                                       :peer-id peer-id
                                       ;; WireGuard roaming may move the live endpoint
                                       ;; before the first observation. The authenticated
                                       ;; control-plane underlay remains the initial LKG;
                                       ;; never let an unrecorded roam erase rollback state.
                                       :selected (copy-list (first endpoints))
                                       :previous (copy-list (first endpoints))))))
                      (selected (or (find (wireguard-peer-path-state-selected peer) endpoints
                                          :test #'equal)
                                    kernel-endpoint (first endpoints)))
                      (observations
                        (mapcar (lambda (endpoint)
                                  (wireguard-observation-for-endpoint peer endpoint))
                                endpoints))
                      (current (wireguard-observation-for-endpoint peer selected))
                      (selected-handshake-baseline
                        (wireguard-path-observation-latest-handshake-seconds current))
                      (kernel-observation
                        (and kernel-endpoint
                             (wireguard-observation-for-endpoint peer kernel-endpoint)))
                      (kernel-handshake-baseline
                        (if kernel-observation
                            (wireguard-path-observation-latest-handshake-seconds
                             kernel-observation)
                            0))
                      (alternatives
                        (remove-if
                         (lambda (observation)
                           (equal selected (wireguard-observation-endpoint observation)))
                         (copy-list observations)))
                      (roamed-candidate
                        (and kernel-endpoint
                             (find kernel-endpoint alternatives :test #'equal
                                   :key #'wireguard-observation-endpoint)))
                      (candidate nil)
                      (transferred (+ (wireguard-peer-status-received-bytes status)
                                      (wireguard-peer-status-transmitted-bytes status))))
              ;; Re-apply the durable selection only when Linux has no endpoint.
              ;; An exact authenticated advertised roam is preserved below long
              ;; enough to verify transactionally; an unknown roam is not.
              (unless kernel-endpoint
                ;; Preserve an exact mTLS-advertised kernel roam long enough to
                ;; verify it transactionally. Unknown endpoints are not in
                ;; ENDPOINTS, yield NIL here, and are reset to the durable LKG.
                (funcall endpoint-setter public-key (second selected) (third selected)))
              ;; Kernel peer telemetry belongs to the endpoint that is actually
              ;; live, not necessarily the durable selection. Misattribution here
              ;; makes a dead selected path look fresh after an authenticated roam.
              (when kernel-observation
                (setf (wireguard-path-observation-latest-handshake-seconds kernel-observation)
                      (wireguard-peer-status-latest-handshake-seconds status)
                      (wireguard-path-observation-handshake-age-seconds kernel-observation)
                      (max 0 (- now (wireguard-peer-status-latest-handshake-seconds status)))
                      (wireguard-path-observation-transferred-bytes-delta kernel-observation)
                      (max 0 (- transferred
                                (wireguard-path-observation-transferred-bytes-total
                                 kernel-observation)))
                      (wireguard-path-observation-transferred-bytes-total kernel-observation)
                      transferred))
              (setf (wireguard-path-observation-handshake-age-seconds current)
                    (cond
                      ((eq current kernel-observation)
                       (max 0 (- now
                                 (wireguard-peer-status-latest-handshake-seconds status))))
                      ((plusp selected-handshake-baseline)
                       (max 0 (- now selected-handshake-baseline)))
                      (t most-positive-fixnum)))
              ;; A fresh authenticated kernel handshake is new evidence and
              ;; must clear an earlier failure streak; using HEALTHY-P here
              ;; would make two startup misses latch the path unhealthy forever.
              (if (if probe-function
                      (funcall health-function public-key selected
                               (wireguard-peer-status-received-bytes status)
                               (lambda () (funcall probe-function route))
                               :status-reader status-reader)
                      (<= (wireguard-path-observation-handshake-age-seconds current) 180))
                  (setf (wireguard-path-observation-consecutive-successes current)
                        (1+ (wireguard-path-observation-consecutive-successes current))
                        (wireguard-path-observation-consecutive-failures current) 0)
                  (setf (wireguard-path-observation-consecutive-successes current) 0
                        (wireguard-path-observation-consecutive-failures current)
                        (1+ (wireguard-path-observation-consecutive-failures current))))
              (setf candidate
                    (or roamed-candidate
                        (and (not (wireguard-path-healthy-p current))
                             (find (wireguard-peer-path-state-previous peer) alternatives
                                   :test #'equal
                                   :key #'wireguard-observation-endpoint))
                        (first
                         (sort alternatives #'< :key
                               (lambda (observation)
                                 (+ (wireguard-path-observation-consecutive-successes observation)
                                    (wireguard-path-observation-consecutive-failures observation)))))))
              (when (and candidate
                         (or (not (wireguard-path-healthy-p current))
                             (wireguard-path-trial-allowed-p peer now)))
                (setf (wireguard-peer-path-state-last-trial-at peer) now)
                (multiple-value-bind (success latency-or-reason)
                    (funcall trial-function public-key selected
                             (wireguard-observation-endpoint candidate)
                             :baseline-handshake-seconds
                             selected-handshake-baseline
                             :verified-handshake-seconds
                             (if (eq candidate kernel-observation)
                                 kernel-handshake-baseline
                                 (wireguard-path-observation-latest-handshake-seconds candidate))
                             :baseline-received-bytes
                             (wireguard-peer-status-received-bytes status)
                             :probe (and probe-function
                                         (lambda () (funcall probe-function route))))
                  (if success
                      (let ((verified
                              (find public-key (funcall status-reader) :test #'equalp
                                    :key #'wireguard-peer-status-public-key)))
                        (setf (wireguard-path-observation-trial-latency-milliseconds candidate)
                              latency-or-reason
                              (wireguard-path-observation-latest-handshake-seconds candidate)
                              (if verified
                                  (wireguard-peer-status-latest-handshake-seconds verified)
                                  (wireguard-path-observation-latest-handshake-seconds candidate))
                              (wireguard-path-observation-handshake-age-seconds candidate) 0
                              (wireguard-path-observation-consecutive-failures candidate) 0
                              (wireguard-path-observation-consecutive-successes candidate)
                              (1+ (wireguard-path-observation-consecutive-successes candidate))))
                      (setf (wireguard-path-observation-consecutive-successes candidate) 0
                            (wireguard-path-observation-consecutive-failures candidate)
                            (1+ (wireguard-path-observation-consecutive-failures candidate))))
                  (multiple-value-bind (chosen reason)
                      (select-wireguard-path current observations)
                    (let ((chosen-endpoint (wireguard-observation-endpoint chosen)))
                      (if (and success (equal chosen-endpoint
                                              (wireguard-observation-endpoint candidate)))
                          (progn
                            (record-wireguard-path-decision
                             state peer-id chosen-endpoint selected reason now)
                            (setf (wireguard-peer-path-state-selected peer) chosen-endpoint))
                          (when success
                            (funcall endpoint-setter public-key (second selected) (third selected))))))))))
  state))

(defun wireguard-mtu-probe-run (argv)
  (handler-case
      (multiple-value-bind (out err code)
          (uiop:run-program argv :output :string :error-output :string
                                 :ignore-error-status t)
        (declare (ignore out err))
        (and code (zerop code)))
    (error () nil)))

(defun probe-wireguard-route-mtu
    (route mtu &key (runner #'wireguard-mtu-probe-run))
  "Verify one inner IPv4 packet of MTU bytes with DF set over gr8s-wg."
  (unless (typep mtu '(integer 576 9000))
    (error "WireGuard MTU probe size must be between 576 and 9000"))
  (funcall runner
           (list "ping" "-4" "-n" "-q" "-c" "1" "-W" "1"
                 "-M" "do" "-I" +node-wireguard-interface+
                 "-s" (write-to-string (- mtu 28))
                 (vxlan-router-address (gethash "podCIDR" route)))))

(defun wireguard-selected-safe-mtu (state default)
  "Return the minimum verified MTU across all selected peer paths."
  (let ((mtus nil))
    (maphash
     (lambda (peer-id peer)
       (declare (ignore peer-id))
       (let ((observation
               (find (wireguard-peer-path-state-selected peer)
                     (wireguard-peer-path-state-observations peer)
                     :test #'equal :key #'wireguard-observation-endpoint)))
         (when observation
           (push (wireguard-path-observation-safe-mtu observation) mtus))))
     (wireguard-path-state-peers state))
    (if mtus (min default (reduce #'min mtus)) default)))

(defun reconcile-wireguard-path-mtus
    (state network &key now (minimum-interval-seconds 300)
                         (maximum-probes-per-tick 1)
                         (probe-function #'probe-wireguard-route-mtu))
  "Probe a bounded number of oldest selected paths and return the safe device MTU."
  (let ((now (or now (- (get-universal-time) 2208988800)))
        (maximum (gethash "mtu" network 1420))
        (due nil))
    (unless (typep maximum-probes-per-tick '(integer 0 1024))
      (error "WireGuard MTU probe budget must be between 0 and 1024"))
    (loop for route in (wireguard-peer-routes network)
          for peer-id = (gethash "nodeName" route (gethash "nodeID" route))
          for peer = (gethash peer-id (wireguard-path-state-peers state))
          for observation = (and peer
                                 (wireguard-observation-for-endpoint
                                  peer (wireguard-peer-path-state-selected peer)))
          when (and observation
                    (>= (- now (wireguard-path-observation-last-mtu-probe-at observation))
                        minimum-interval-seconds))
            do (push (list route peer-id observation) due))
    (setf due
          (sort due
                (lambda (left right)
                  (let ((left-at (wireguard-path-observation-last-mtu-probe-at
                                  (third left)))
                        (right-at (wireguard-path-observation-last-mtu-probe-at
                                   (third right))))
                    (or (< left-at right-at)
                        (and (= left-at right-at)
                             (string< (second left) (second right))))))))
    (loop repeat maximum-probes-per-tick
          for candidate in due
          for route = (first candidate)
          for observation = (third candidate)
          do (setf (wireguard-path-observation-last-mtu-probe-at observation) now)
             (multiple-value-bind (discovered reason)
                 (discover-wireguard-path-mtu
                  (lambda (size) (funcall probe-function route size))
                  :minimum 576 :maximum maximum)
               (when discovered
                 (update-wireguard-path-mtu observation discovered
                                            :reason reason :now now))))
    (wireguard-selected-safe-mtu state maximum)))

(defun apply-wireguard-selected-safe-mtu
    (state network &key (setter #'set-network-link-mtu))
  "Apply the cluster-safe selected-path MTU to the owned WireGuard interface."
  (let ((mtu (wireguard-selected-safe-mtu state (gethash "mtu" network 1420))))
    (funcall setter +node-wireguard-interface+ mtu)
    mtu))

(defun probe-wireguard-route (route)
  "Send one harmless UDP byte toward ROUTE's overlay router to provoke a handshake."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type :datagram :protocol :udp)))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect
            socket
            (sb-bsd-sockets:make-inet-address
             (vxlan-router-address (gethash "podCIDR" route)))
            9)
           (sb-bsd-sockets:socket-send
            socket
            (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)
            1))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun trial-wireguard-next-hop
    (peer &key
            configurer
            (previous-cidrs nil)
            (restorer #'configure-wireguard-peer-cidrs)
            (route-adder #'replace-network-route)
            (route-remover #'remove-network-route)
            (peer-remover #'remove-wireguard-peer)
            (round-trip-verifier #'wireguard-path-round-trip-p)
            (probe-sender #'probe-wireguard-route)
            (status-reader #'read-wireguard-peer-statuses)
            (timeout-milliseconds 3000))
  "Stage and authenticate PEER through its own router /32 before CIDR migration.
The existing peer set and destination AllowedIPs remain untouched until this
returns true. Failure removes only the staged peer and probe route."
  (let* ((gateway-cidr (required-cni-string peer "probeCIDR"))
         (gateway-address (vxlan-router-address gateway-cidr))
         (probe-cidr (format nil "~A/32" gateway-address))
         (public-key
           (wireguard-decode-key
            (required-cni-string peer "wireguardPublicKey")
            "staged next-hop public key"))
         (endpoint
           (list "underlay" (required-cni-string peer "underlayAddress")
                 (gethash "wireguardListenPort" peer)))
         (existing (find public-key (funcall status-reader)
                         :key #'wireguard-peer-status-public-key :test #'equalp))
         (baseline (if existing (wireguard-peer-status-received-bytes existing) 0))
         (probe-route (json-object "podCIDR" gateway-cidr))
         (staged-p nil)
         (route-p nil))
    (handler-case
        (progn
          (if configurer
              (funcall configurer peer probe-cidr)
              (configure-wireguard-peer-cidrs
               peer (append (copy-list previous-cidrs) (list probe-cidr))))
          (setf staged-p t)
          (funcall route-adder gateway-address 32 +node-wireguard-interface+)
          (setf route-p t)
          (unless (funcall round-trip-verifier
                           public-key endpoint baseline
                           (lambda () (funcall probe-sender probe-route))
                           :timeout-milliseconds timeout-milliseconds)
            (invalid-cni "sparse next-hop ~A failed authenticated path trial"
                         (gethash "nodeID" peer)))
          t)
      (error (condition)
        (when route-p
          (ignore-errors
           (funcall route-remover gateway-address 32 +node-wireguard-interface+)))
        (when staged-p
          (ignore-errors
           (if previous-cidrs
               (funcall restorer peer previous-cidrs)
               (funcall peer-remover public-key))))
        (if (typep condition '(or cni-error rtnetlink-error))
            (error condition)
            (invalid-cni "sparse next-hop trial failed: ~A" condition))))))

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
         (endpoint (gethash 4 attributes))
         (handshake (gethash 6 attributes))
         (received (gethash 7 attributes))
         (transmitted (gethash 8 attributes)))
    (unless (and key (= 32 (length key)))
      (invalid-cni "WireGuard peer status has no valid public key"))
    (unless (or (null handshake) (= 16 (length handshake)))
      (invalid-cni "WireGuard peer status has an invalid handshake timestamp"))
    (unless (or (null endpoint)
                (and (= 16 (length endpoint))
                     (= 2 (netlink-read-integer endpoint 0 2))))
      (invalid-cni "WireGuard peer status has an invalid IPv4 endpoint"))
    (unless (and received (= 8 (length received)) transmitted (= 8 (length transmitted)))
      (invalid-cni "WireGuard peer status has invalid byte counters"))
    (make-wireguard-peer-status
     :public-key key
     :endpoint-address
     (if endpoint
         (format nil "~{~D~^.~}" (coerce (subseq endpoint 4 8) 'list))
         "")
     :endpoint-port
     (if endpoint
         (+ (ash (aref endpoint 2) 8) (aref endpoint 3))
         0)
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

(defun trial-wireguard-peer-endpoint
    (public-key current candidate
     &key baseline-handshake-seconds
       (verified-handshake-seconds 0)
       baseline-received-bytes
       (timeout-milliseconds 3000)
       (endpoint-setter #'configure-wireguard-peer-endpoint)
       (session-resetter #'reset-wireguard-peer-session)
       probe
       (status-reader #'read-wireguard-peer-statuses)
       (clock-milliseconds
         (lambda ()
           (floor (* 1000 (get-internal-real-time))
                  internal-time-units-per-second)))
       (sleep-function #'sleep))
  "Transactionally trial CANDIDATE without sacrificing CURRENT. First require
returned authenticated bytes at the exact candidate endpoint while the existing
session remains valid. Only then expire that session and require a handshake newer
than BASELINE-HANDSHAKE-SECONDS. Restore CURRENT on any failure."
  (destructuring-bind (candidate-name candidate-address candidate-port) candidate
    (declare (ignore candidate-name))
    (destructuring-bind (current-name current-address current-port) current
      (declare (ignore current-name))
      (let ((started (funcall clock-milliseconds))
            (candidate-verified-p nil)
            (session-reset-p nil))
        (labels ((restore ()
                   (funcall endpoint-setter public-key current-address current-port)
                   ;; Once the candidate keypair was deliberately expired, make
                   ;; rollback establish a new session on the exact LKG endpoint.
                   (when session-reset-p
                     (funcall session-resetter public-key)
                     (when probe (funcall probe))))
                 (candidate-status ()
                   (find public-key (funcall status-reader) :test #'equalp
                         :key #'wireguard-peer-status-public-key))
                 (candidate-endpoint-p (status)
                   (and status
                        (string= candidate-address
                                 (wireguard-peer-status-endpoint-address status))
                        (= candidate-port
                           (wireguard-peer-status-endpoint-port status)))))
          (handler-case
              (progn
                (funcall endpoint-setter
                         public-key candidate-address candidate-port)
                (loop
                  (when probe (funcall probe))
                  (let ((status (candidate-status)))
                    (when (and (not candidate-verified-p)
                               (candidate-endpoint-p status)
                               (> (wireguard-peer-status-received-bytes status)
                                  baseline-received-bytes))
                      ;; Candidate traffic has returned under the authenticated
                      ;; peer identity. A peer may already have initiated a fresh
                      ;; handshake while roaming us here; accept that evidence
                      ;; only when it is newer than this endpoint's remembered
                      ;; baseline. Otherwise it is now safe to force a rekey.
                      (setf candidate-verified-p t)
                      (when (or (> (wireguard-peer-status-latest-handshake-seconds status)
                                   baseline-handshake-seconds)
                                (and (plusp verified-handshake-seconds)
                                     (>= (wireguard-peer-status-latest-handshake-seconds status)
                                         verified-handshake-seconds)))
                        (return
                          (values t (- (funcall clock-milliseconds) started))))
                      (funcall session-resetter public-key)
                      (setf session-reset-p t))
                    (when (and session-reset-p
                               (candidate-endpoint-p status)
                               (> (wireguard-peer-status-latest-handshake-seconds status)
                                  baseline-handshake-seconds))
                      (return
                        (values t (- (funcall clock-milliseconds) started)))))
                  (when (>= (- (funcall clock-milliseconds) started)
                            timeout-milliseconds)
                    (restore)
                    (return (values nil :handshake-timeout)))
                  (funcall sleep-function 0.05)))
            (error ()
              (ignore-errors (restore))
              (values nil :trial-error))))))))

(defun wireguard-peer-key-set (keys)
  "Return canonical, order-independent base64 identities for WireGuard KEYS."
  (sort (mapcar #'ag-grpc:base64-encode keys) #'string<))

(defun wireguard-desired-peer-keys (network)
  "Return NETWORK's decoded desired peer public keys."
  (loop for route in (wireguard-peer-routes network)
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
                            (route-pod-cidrs route)
                            (gethash "underlayAddress" route)
                            (gethash "wireguardPublicKey" route)
                            (gethash "wireguardListenPort" route)
                            (let ((hop (gethash "nextHop" route)))
                              (and hop
                                   (list (gethash "nodeID" hop)
                                         (gethash "underlayAddress" hop)
                                         (gethash "wireguardPublicKey" hop)
                                         (gethash "wireguardListenPort" hop))))))))

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
    ;; Existing owned links may carry a lower path MTU proven by the tuner.
    ;; Cached topology repair must not briefly raise them back into a known
    ;; packet-size black hole; the path reconciler applies the safe value.
    (dolist (cidr (network-pod-cidrs network "nodePodCIDRs" "nodePodCIDR"))
      (multiple-value-bind (family address prefix bits) (parse-pod-cidr cidr)
        (declare (ignore address prefix))
        (add-network-address name (vxlan-router-address cidr) bits)
        (when (eq family :ipv6) (enable-node-ipv6-forwarding))))
    (set-network-link-up name)
    (enable-node-ipv4-forwarding)
    name))

(defun wireguard-route-cidrs (network)
  "Return NETWORK's peer Pod CIDRs."
  (loop for route across (gethash "routes" network #())
        append (route-pod-cidrs route)))

(defun wireguard-source-address (network cidr)
  "Return this node's overlay router address in CIDR's family."
  (multiple-value-bind (family address prefix bits) (parse-pod-cidr cidr)
    (declare (ignore address prefix bits))
    (let ((local
            (find family (network-pod-cidrs network "nodePodCIDRs" "nodePodCIDR")
                  :key (lambda (candidate) (nth-value 0 (parse-pod-cidr candidate))))))
      (unless local
        (invalid-cni "no local Pod CIDR for peer family ~A" cidr))
      (vxlan-router-address local))))

(defun wireguard-peer-group-by-key (groups encoded-key)
  "Find the peer group in GROUPS authenticated by ENCODED-KEY."
  (find encoded-key groups :test #'string=
        :key (lambda (group) (gethash "wireguardPublicKey" group))))

(defun wireguard-peer-group-cidrs (group)
  (if group (coerce (gethash "podCIDRs" group #()) 'list) nil))

(defun trial-wireguard-topology-migrations
    (previous network &key (trial-function #'trial-wireguard-next-hop)
                           (route-remover #'remove-network-route))
  "Authenticate every peer gaining destination CIDRs before replacing peers.
Returns the staged gateway /32 addresses whose temporary routes need cleanup."
  (let ((old-groups (wireguard-peer-routes previous))
        (staged-addresses nil))
    (handler-case
        (progn
          (dolist (group (wireguard-peer-routes network))
            (let* ((encoded-key (gethash "wireguardPublicKey" group))
                   (old (wireguard-peer-group-by-key old-groups encoded-key))
                   (old-cidrs (wireguard-peer-group-cidrs old))
                   (new-cidrs (wireguard-peer-group-cidrs group)))
              (when (set-difference new-cidrs old-cidrs :test #'string=)
                (funcall trial-function group :previous-cidrs old-cidrs)
                (push (vxlan-router-address
                       (required-cni-string group "probeCIDR"))
                      staged-addresses))))
          staged-addresses)
      (error (condition)
        ;; A later candidate must not leak successful earlier probe routes.
        (dolist (address staged-addresses)
          (ignore-errors
           (funcall route-remover address 32 +node-wireguard-interface+)))
        (error condition)))))

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
      (let ((staged-addresses nil))
        (handler-case
            (progn
              ;; A topology optimization may move destination AllowedIPs to a
              ;; different authenticated peer. Keep the complete LKG config
              ;; live while each gaining peer proves returned encrypted bytes.
              (when (and previous
                         (wireguard-live-peer-keys-match-p previous))
                (setf staged-addresses
                      (trial-wireguard-topology-migrations previous network)))
              (configure-wireguard-device
               +node-wireguard-interface+ private-key network))
          (error (condition)
            (when previous
              (ignore-errors
               (configure-wireguard-device
                +node-wireguard-interface+ private-key previous)))
            (dolist (address staged-addresses)
              (ignore-errors
               (remove-network-route address 32 +node-wireguard-interface+)))
            (error condition)))
        (dolist (address staged-addresses)
          (ignore-errors
           (remove-network-route address 32 +node-wireguard-interface+)))))
    (dolist (cidr previous-routes)
      (unless (member cidr wanted :test #'equal)
        (multiple-value-bind (family address prefix bits) (parse-pod-cidr cidr)
          (declare (ignore bits))
          (remove-network-route (format-pod-address family address) prefix
                                +node-wireguard-interface+))))
    (dolist (cidr wanted)
      (multiple-value-bind (family address prefix bits) (parse-pod-cidr cidr)
        (declare (ignore bits))
        (replace-network-route
         (format-pod-address family address) prefix +node-wireguard-interface+
         :source (wireguard-source-address network cidr)))))
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
