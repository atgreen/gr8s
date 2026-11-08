;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Linux rtnetlink (NETLINK_ROUTE) client for the CNI data path.
;;;;
;;;; gr8s configures host networking -- veth pairs, link attributes, addresses,
;;;; routes, and permanent neighbors -- by encoding UAPI netlink messages by hand
;;;; and exchanging them over a private AF_NETLINK socket, rather than forking
;;;; iproute2. Each transaction opens its own socket in the calling thread's
;;;; network namespace, so a worker that has entered a Pod netns programs that
;;;; namespace without disturbing others. Requests carry NLM_F_ACK, so the
;;;; kernel's error reply surfaces as a Lisp condition (rtnetlink-error). The
;;;; routed-veth helpers stamp each link with a stable alias and a derived MAC so
;;;; that a create interrupted by a crash can be recognized and adopted on retry.

(in-package #:gr8s.network)

;; Linux UAPI messages are constructed here rather than invoking iproute2.
;; Every transaction gets a private socket in the calling thread's namespace.
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

(define-condition rtnetlink-error (cni-error)
  ((errno :initarg :errno :reader rtnetlink-error-errno)))

(defun fail-rtnetlink (operation errno)
  "Signal RTNETLINK-ERROR for OPERATION with ERRNO, its message the matching
   strerror text. Does not return normally."
  (error 'rtnetlink-error :errno errno
         :message (format nil "rtnetlink ~A: ~A" operation
                          (sb-int:strerror errno))))

(defun netlink-octets (&rest parts)
  "Concatenate PARTS into one (unsigned-byte 8) vector."
  (apply #'concatenate '(vector (unsigned-byte 8)) parts))

(defun netlink-integer (value size)
  "Encode VALUE as a SIZE-byte vector in the host's byte order (little-endian on
   this build)."
  (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (index size bytes)
      (setf (aref bytes index)
            (ldb (byte 8 (* 8 #+little-endian index
                                 #-little-endian (- size index 1))) value)))))

(defun netlink-read-integer (bytes offset size)
  "Decode the SIZE-byte integer at OFFSET in BYTES, in the host's byte order."
  (loop for index below size
        sum (ash (aref bytes (+ offset index))
                 (* 8 #+little-endian index
                      #-little-endian (- size index 1)))))

(defun netlink-align (size)
  "Round SIZE up to the 4-byte netlink alignment."
  (logand (+ size 3) (lognot 3)))

(defun netlink-string (string)
  "Encode STRING as NUL-terminated UTF-8 bytes, the form netlink string
   attributes expect."
  (netlink-octets (trivial-utf-8:string-to-utf-8-bytes string) #(0)))

(defun netlink-attribute (type payload)
  "Encode one netlink attribute (nlattr) of TYPE wrapping PAYLOAD: the 4-byte
   length/type header, the payload, and trailing zero padding to netlink
   alignment."
  (let ((size (+ 4 (length payload))))
    (netlink-octets
     (netlink-integer size 2) (netlink-integer type 2) payload
     (make-array (- (netlink-align size) size)
                 :element-type '(unsigned-byte 8) :initial-element 0))))

(defun netlink-message (type flags payload &optional (sequence 1))
  "Wrap PAYLOAD in an nlmsghdr of TYPE and FLAGS (total length, type, flags,
   SEQUENCE, and a zero port id)."
  (netlink-octets
   (netlink-integer (+ 16 (length payload)) 4)
   (netlink-integer type 2) (netlink-integer flags 2)
   (netlink-integer sequence 4) (netlink-integer 0 4) payload))

(defun parse-netlink-reply (buffer count sequence)
  "Return matching payloads and whether the kernel acknowledged the request."
  (let ((offset 0) (payloads nil) (acknowledged nil))
    (loop while (< offset count)
          do (when (< (- count offset) 16)
               (invalid-cni "truncated rtnetlink reply header"))
             (let ((size (netlink-read-integer buffer offset 4))
                   (type (netlink-read-integer buffer (+ offset 4) 2))
                   (reply-sequence (netlink-read-integer buffer (+ offset 8) 4)))
               (unless (<= 16 size (- count offset))
                 (invalid-cni "invalid rtnetlink reply length"))
               (when (= sequence reply-sequence)
                 (case type
                   (2 ; NLMSG_ERROR includes successful ACKs (error = 0).
                    (when (< size 20)
                      (invalid-cni "truncated rtnetlink acknowledgement"))
                    (let ((code (netlink-read-integer buffer (+ offset 16) 4)))
                      (unless (zerop code)
                        (fail-rtnetlink "request" (- (expt 2 32) code)))
                      (setf acknowledged t)))
                   (3 (setf acknowledged t)) ; NLMSG_DONE
                   (4 (invalid-cni "rtnetlink receive overrun"))
                   (otherwise
                    (push (subseq buffer offset (+ offset size)) payloads))))
               (incf offset (netlink-align size))))
    (values (nreverse payloads) acknowledged)))

(defun call-rtnetlink (type flags payload &key (timeout 5))
  "Run one rtnetlink request/response transaction and return the kernel's reply
   messages -- those that are neither an ACK nor NLMSG_DONE, possibly none.
   Opens a private CLOEXEC AF_NETLINK socket in the calling thread's namespace,
   forces NLM_F_REQUEST|NLM_F_ACK onto FLAGS, sends TYPE with PAYLOAD, and reads
   until the kernel acknowledges. Signals RTNETLINK-ERROR on a socket error or a
   non-zero kernel status, or INVALID-CNI on a malformed reply, a datagram larger
   than the 64 KiB buffer, or TIMEOUT seconds without acknowledgement. Closes the
   socket before returning."
  (let ((fd (%rtnl-socket 16 (logior 3 #o2000000) 0)) ; AF_NETLINK, CLOEXEC
        (address (netlink-octets (netlink-integer 16 2)
                                (make-array 10 :element-type '(unsigned-byte 8)
                                               :initial-element 0)))
        (message (netlink-message type (logior flags 5) payload))
        (buffer (make-array 65536 :element-type '(unsigned-byte 8)))
        (replies nil)
        (deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (when (minusp fd) (fail-rtnetlink "socket" (sb-alien:get-errno)))
    (unwind-protect
         (progn
           (sb-sys:with-pinned-objects (address message)
             (unless (zerop (%rtnl-connect fd (sb-sys:vector-sap address) 12))
               (fail-rtnetlink "connect" (sb-alien:get-errno)))
             (unless (= (length message)
                        (%rtnl-send fd (sb-sys:vector-sap message)
                                    (length message) 0))
               (fail-rtnetlink "send" (sb-alien:get-errno))))
           (loop
             (let ((remaining (/ (- deadline (get-internal-real-time))
                                 internal-time-units-per-second)))
               (unless (and (plusp remaining)
                            (sb-sys:wait-until-fd-usable fd :input remaining))
                 (invalid-cni "timed out waiting for rtnetlink acknowledgement")))
             (let ((count
                     (sb-sys:with-pinned-objects (buffer)
                       ;; MSG_TRUNC lets us detect an oversized datagram.
                       (%rtnl-recv fd (sb-sys:vector-sap buffer)
                                   (length buffer) 32))))
               (when (minusp count)
                 (fail-rtnetlink "receive" (sb-alien:get-errno)))
               (when (> count (length buffer))
                 (invalid-cni "rtnetlink datagram exceeds receive buffer"))
               (multiple-value-bind (messages acknowledged)
                   (parse-netlink-reply buffer count 1)
                 (setf replies (nconc replies messages))
                 (when acknowledged (return replies))))))
      (sb-posix:close fd))))

(defun netlink-interface-message (&key (index 0) (flags 0) (change 0))
  "Encode an ifinfomsg body: interface INDEX, link FLAGS, and the CHANGE mask
   selecting which flag bits FLAGS applies to."
  (netlink-octets #(0 0 0 0) (netlink-integer index 4)
                  (netlink-integer flags 4) (netlink-integer change 4)))

(defun validate-network-interface-name (name)
  "Return NAME when it is a safe Linux interface name -- a string of 1 to 15
   characters drawn from [A-Za-z0-9-_.] that is neither \".\" nor \"..\" -- and
   signal INVALID-CNI otherwise. Guards names before they reach the kernel or a
   namespace path."
  (unless (and (stringp name) (<= 1 (length name) 15)
               (every (lambda (character)
                        (or (and (char<= #\a character #\z))
                            (and (char<= #\A character #\Z))
                            (and (char<= #\0 character #\9))
                            (find character "-_."))) name)
               (not (member name '("." "..") :test #'string=)))
    (invalid-cni "unsafe network interface name ~S" name))
  name)

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

(defun netlink-attributes (message offset)
  "Parse the netlink attributes in MESSAGE from OFFSET into a hash table from
   attribute type (with the nested/byte-order flag bits masked off) to its raw
   payload bytes. Signals INVALID-CNI on a truncated or malformed attribute."
  (let ((attributes (make-hash-table)))
    (loop while (< offset (length message))
          do (when (< (- (length message) offset) 4)
               (invalid-cni "truncated rtnetlink attribute"))
             (let ((size (netlink-read-integer message offset 2))
                   (type (logand #x3fff
                                 (netlink-read-integer message (+ offset 2) 2))))
               (unless (<= 4 size (- (length message) offset))
                 (invalid-cni "invalid rtnetlink attribute length"))
               (setf (gethash type attributes)
                     (subseq message (+ offset 4) (+ offset size)))
               (incf offset (netlink-align size))))
    attributes))

(defun network-link-attributes-by-index (index)
  "Read kernel link attributes for an interface index in this namespace."
  (unless (plusp index) (fail-rtnetlink "link lookup" 19))
  (let* ((messages (call-rtnetlink 18 0 (netlink-interface-message :index index)))
         (message (find 16 messages :key (lambda (item) (netlink-read-integer item 4 2)))))
    (unless (and message (>= (length message) 32))
      (invalid-cni "kernel returned no link information for index ~A" index))
    (netlink-attributes message 32)))

(defun network-link-attributes (name)
  "Read kernel link attributes for a validated interface name."
  (network-link-attributes-by-index
   (native-interface-index (validate-network-interface-name name))))

(defun read-ipv4-host-routes ()
  "Read non-default IPv4 routes from all Linux routing tables via rtnetlink."
  (loop for message in (call-rtnetlink 26 #x300
                                      (netlink-octets #(2 0 0 0 0 0 0 0) (netlink-integer 0 4)))
        when (and (>= (length message) 28) (= 24 (netlink-read-integer message 4 2))
                  (= 2 (aref message 16)) (plusp (aref message 17)))
          collect (let* ((attributes (netlink-attributes message 28))
                         (destination (gethash 1 attributes #(0 0 0 0)))
                         (index (gethash 4 attributes)) (table (gethash 15 attributes)))
                    (list :cidr (format nil "~A/~D"
                                        (format-ipv4-integer
                                         (loop for byte across destination
                                               for shift from 24 downto 0 by 8 sum (ash byte shift)))
                                        (aref message 17))
                          :index (if index (netlink-read-integer index 0 4) 0)
                          :table (if table (netlink-read-integer table 0 4) (aref message 20))))))

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

(defun set-network-link-mtu (name mtu)
  "Set the link NAME's MTU to MTU."
  (call-rtnetlink
   16 0 (netlink-octets
         (netlink-interface-message :index (cni-interface-index name))
         (netlink-attribute 4 (netlink-integer mtu 4)))))

(defun set-network-link-up (name)
  "Bring the link NAME administratively up (set IFF_UP)."
  (call-rtnetlink 16 0
                  (netlink-interface-message
                   :index (cni-interface-index name) :flags 1 :change 1)))

(defun delete-network-link (name)
  "Delete the link NAME (RTM_DELLINK). A no-op when it no longer exists, and
   tolerant of ENODEV -- the namespace or peer can vanish between the index
   lookup and the delete. Signals INVALID-CNI on an unsafe name."
  (validate-network-interface-name name)
  (let ((index (native-interface-index name)))
    (unless (zerop index)
      (handler-case
          (call-rtnetlink 17 0 (netlink-interface-message :index index))
        (rtnetlink-error (condition)
          ;; Namespace destruction can remove the peer between lookup and DEL.
          (unless (= 19 (rtnetlink-error-errno condition)) (error condition)))))))

(defun ipv4-network-octets (address)
  "Return ADDRESS, a dotted-quad IPv4 string, as its four network-order bytes."
  (let ((integer (parse-ipv4-integer address)))
    (make-array 4 :element-type '(unsigned-byte 8)
                  :initial-contents
                  (loop for shift from 24 downto 0 by 8
                        collect (ldb (byte 8 shift) integer)))))

(defun network-address-wire-values (address)
  "Return ADDRESS's rtnetlink family, network-order bytes, and address width."
  (if (find #\: address)
      (values 10 (0conf:parse-ipv6 address) 128)
      (values 2 (ipv4-network-octets address) 32)))

(defun add-network-address (name address prefix)
  "Assign ADDRESS/PREFIX to the link NAME (RTM_NEWADDR). Idempotent: an
   already-present address (EEXIST) is accepted. Signals INVALID-CNI on a prefix
   outside 0..32."
  (multiple-value-bind (family bytes bits) (network-address-wire-values address)
    (unless (<= 0 prefix bits) (invalid-cni "invalid address prefix ~A" prefix))
    (handler-case
        (call-rtnetlink
         20 #x600 ; RTM_NEWADDR, CREATE | EXCL
         (netlink-octets
          (vector family prefix (if (= family 10) 2 0) 0)
          (netlink-integer (cni-interface-index name) 4)
          (netlink-attribute 1 bytes) ; IFA_ADDRESS
          (netlink-attribute 2 bytes))) ; IFA_LOCAL
      (rtnetlink-error (condition)
        (unless (= 17 (rtnetlink-error-errno condition)) (error condition))))))

(defun replace-network-route (destination prefix name &key gateway source)
  "Install or replace the main-table route to DESTINATION/PREFIX out of the link
   NAME (RTM_NEWROUTE, NLM_F_CREATE|NLM_F_REPLACE) as a static unicast route,
   optionally via GATEWAY and with preferred SOURCE. Signals INVALID-CNI on a
   prefix outside 0..32."
  (multiple-value-bind (family bytes bits) (network-address-wire-values destination)
    (unless (<= 0 prefix bits) (invalid-cni "invalid route prefix ~A" prefix))
    (flet ((same-family-bytes (value)
             (when value
               (multiple-value-bind (other-family other-bytes)
                   (network-address-wire-values value)
                 (unless (= family other-family)
                   (invalid-cni "route address families do not match"))
                 other-bytes))))
      (call-rtnetlink
       24 #x500 ; RTM_NEWROUTE, CREATE | REPLACE
       (netlink-octets
        (vector family prefix 0 0 254 4 (if gateway 0 253) 1)
        (netlink-integer 0 4)
        (netlink-attribute 1 bytes)
        (netlink-attribute 4 (netlink-integer (cni-interface-index name) 4))
        (if gateway (netlink-attribute 5 (same-family-bytes gateway)) #())
        (if source (netlink-attribute 7 (same-family-bytes source)) #()))))))

(defun remove-network-route (destination prefix name)
  "Delete the main-table route to DESTINATION/PREFIX through NAME, accepting absence."
  (multiple-value-bind (family bytes bits) (network-address-wire-values destination)
    (unless (<= 0 prefix bits) (invalid-cni "invalid route prefix ~A" prefix))
    (handler-case
        (call-rtnetlink
         25 0 ; RTM_DELROUTE
         (netlink-octets
          (vector family prefix 0 0 254 4 0 1)
          (netlink-integer 0 4)
          (netlink-attribute 1 bytes)
          (netlink-attribute 4 (netlink-integer (cni-interface-index name) 4))))
      (rtnetlink-error (condition)
        (unless (= 3 (rtnetlink-error-errno condition)) ; ESRCH
          (error condition))))))

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

(defun remove-network-address (name address prefix)
  "Delete an IP address from NAME, accepting an already absent address."
  (multiple-value-bind (family bytes bits) (network-address-wire-values address)
    (unless (<= 0 prefix bits) (invalid-cni "invalid address prefix ~A" prefix))
    (handler-case
        (call-rtnetlink
         21 0
         (netlink-octets
          (vector family prefix 0 0) (netlink-integer (cni-interface-index name) 4)
          (netlink-attribute 1 bytes)
          (netlink-attribute 2 bytes)))
      (rtnetlink-error (condition)
        (unless (= 99 (rtnetlink-error-errno condition)) (error condition))))))

(defun network-address-present-p (name address prefix)
  "Check an exact IP address/prefix assignment through rtnetlink."
  (multiple-value-bind (family bytes) (network-address-wire-values address)
    (let ((index (cni-interface-index name)))
      (loop for message in (call-rtnetlink 22 #x300
                                          (netlink-octets (vector family 0 0 0)
                                                           (netlink-integer 0 4)))
            thereis (and (>= (length message) 24) (= 20 (netlink-read-integer message 4 2))
                         (= family (aref message 16)) (= prefix (aref message 17))
                         (= index (netlink-read-integer message 20 4))
                         (equalp bytes (gethash 2 (netlink-attributes message 24))))))))

(defun netlink-neighbor-message (family interface state flags)
  "Encode Linux ndmsg fields for a neighbor or VXLAN FDB transaction."
  (netlink-octets (vector family 0 0 0)
                  (netlink-integer (cni-interface-index interface) 4)
                  (netlink-integer state 2) (vector flags 1)))

(defun replace-permanent-network-neighbor (interface address mac)
  "Install a neighbor that survives ARP/NDP cache aging on INTERFACE."
  (multiple-value-bind (family bytes) (network-address-wire-values address)
    (call-rtnetlink
     28 #x500
     (netlink-octets (netlink-neighbor-message family interface 128 0)
                     (netlink-attribute 1 bytes)
                     (netlink-attribute 2 mac)))))

(defun permanent-network-neighbor-p (interface address mac)
  "Check the MAC and NUD_PERMANENT state of an IP neighbor via rtnetlink."
  (multiple-value-bind (family bytes) (network-address-wire-values address)
    (let ((index (cni-interface-index interface)))
      (loop for message in (call-rtnetlink 30 #x300
                                          (netlink-neighbor-message family interface 0 0))
            thereis (and (>= (length message) 28) (= 28 (netlink-read-integer message 4 2))
                         (= family (aref message 16)) (= index (netlink-read-integer message 20 4))
                         (logtest 128 (netlink-read-integer message 24 2))
                         (let ((attributes (netlink-attributes message 28)))
                           (and (equalp bytes (gethash 1 attributes))
                                (equalp mac (gethash 2 attributes)))))))))

(defun network-route-present-p (destination prefix interface &key gateway source)
  "Check a main-table IP route, output interface, gateway and optional source."
  (multiple-value-bind (family bytes) (network-address-wire-values destination)
    (flet ((value-bytes (value)
             (when value
               (multiple-value-bind (other-family other-bytes)
                   (network-address-wire-values value)
                 (and (= family other-family) other-bytes)))))
      (let ((index (cni-interface-index interface))
            (zero (make-array (length bytes) :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
        (loop for message in (call-rtnetlink
                              26 #x300
                              (netlink-octets (vector family 0 0 0 0 0 0 0)
                                               (netlink-integer 0 4)))
              thereis (and (>= (length message) 28) (= 24 (netlink-read-integer message 4 2))
                           (= family (aref message 16)) (= prefix (aref message 17))
                           (= 254 (aref message 20))
                           (let ((attributes (netlink-attributes message 28)))
                             (and (equalp bytes (gethash 1 attributes zero))
                                  (equalp (netlink-integer index 4) (gethash 4 attributes))
                                  (equalp (value-bytes gateway) (gethash 5 attributes))
                                  (or (not source)
                                      (equalp (value-bytes source)
                                              (gethash 7 attributes)))))))))))

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
    ;; Migrate an endpoint created by the earlier per-veth gateway layout.
    (loop for item in gateways
          do (remove-network-address host item (if (find #\: item) 128 32)))
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
         (loop for item in addresses
               do (add-network-address peer item (if (find #\: item) 128 32)))
         (set-network-link-up peer)
         (loop for item in gateways
               do (replace-network-route item (if (find #\: item) 128 32) peer)
                  (replace-permanent-network-neighbor peer item host-mac)
                  (replace-network-route (if (find #\: item) "::" "0.0.0.0")
                                         0 peer :gateway item))))
    host)))
