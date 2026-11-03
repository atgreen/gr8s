(in-package #:gr8s)

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
  (error 'rtnetlink-error :errno errno
         :message (format nil "rtnetlink ~A: ~A" operation
                          (sb-int:strerror errno))))

(defun netlink-octets (&rest parts)
  (apply #'concatenate '(vector (unsigned-byte 8)) parts))

(defun netlink-integer (value size)
  (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (index size bytes)
      (setf (aref bytes index)
            (ldb (byte 8 (* 8 #+little-endian index
                                 #-little-endian (- size index 1))) value)))))

(defun netlink-read-integer (bytes offset size)
  (loop for index below size
        sum (ash (aref bytes (+ offset index))
                 (* 8 #+little-endian index
                      #-little-endian (- size index 1)))))

(defun netlink-align (size)
  (logand (+ size 3) (lognot 3)))

(defun netlink-string (string)
  (netlink-octets (trivial-utf-8:string-to-utf-8-bytes string) #(0)))

(defun netlink-attribute (type payload)
  (let ((size (+ 4 (length payload))))
    (netlink-octets
     (netlink-integer size 2) (netlink-integer type 2) payload
     (make-array (- (netlink-align size) size)
                 :element-type '(unsigned-byte 8) :initial-element 0))))

(defun netlink-message (type flags payload &optional (sequence 1))
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
  (netlink-octets #(0 0 0 0) (netlink-integer index 4)
                  (netlink-integer flags 4) (netlink-integer change 4)))

(defun validate-network-interface-name (name)
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
  ;; A stable digest, unlike SXHASH, survives a new dumped image or process.
  (concatenate
   'string "gr"
   (subseq (ironclad:byte-array-to-hex-string
            (ironclad:digest-sequence
             :sha256 (trivial-utf-8:string-to-utf-8-bytes
                      (format nil "~A/~A" sandbox-id interface-name)))) 0 13)))

(defun network-identity-mac (identity)
  (netlink-octets #(2)
                  (subseq (ironclad:digest-sequence
                           :sha256 (trivial-utf-8:string-to-utf-8-bytes identity)) 0 5)))

(defun routed-veth-mac (owner role)
  (network-identity-mac (format nil "~A:~A" owner role)))

(defun %create-routed-veth (host-name peer-name netns &key (mtu 1450) owner)
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
  (call-rtnetlink
   16 0 (netlink-octets
         (netlink-interface-message :index (cni-interface-index name))
         (netlink-attribute 20 (netlink-string owner)))))

(defun create-routed-veth (host-name peer-name netns &key (mtu 1450) owner)
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

(defun network-link-attributes (name)
  (let* ((index (native-interface-index (validate-network-interface-name name)))
         (messages (call-rtnetlink
                    18 0 (netlink-interface-message
                          :index (if (zerop index)
                                     (fail-rtnetlink "link lookup" 19) index))))
         (message (find 16 messages
                        :key (lambda (item) (netlink-read-integer item 4 2)))))
    (unless (and message (>= (length message) 32))
      (invalid-cni "kernel returned no link information for ~A" name))
    (netlink-attributes message 32)))

(defun network-link-owned-p (name owner)
  (let ((alias (gethash 20 (network-link-attributes name))))
    (and alias (equalp alias (netlink-string owner)))))

(defun network-link-untagged-p (attributes)
  (let ((alias (gethash 20 attributes)))
    (or (null alias) (zerop (length alias)) (equalp alias #(0)))))

(defun network-link-kind-p (attributes kind)
  (let ((info (gethash 18 attributes)))
    (and info (equalp (gethash 1 (netlink-attributes info 0)) (netlink-string kind)))))

(defun routed-veth-owned-or-untagged-p (name owner role)
  (let ((attributes (network-link-attributes name)))
    (or (equalp (gethash 20 attributes) (netlink-string owner))
        (and (network-link-untagged-p attributes)
             (network-link-kind-p attributes "veth")
             (equalp (gethash 1 attributes) (routed-veth-mac owner role))))))

(defun set-network-link-mtu (name mtu)
  (call-rtnetlink
   16 0 (netlink-octets
         (netlink-interface-message :index (cni-interface-index name))
         (netlink-attribute 4 (netlink-integer mtu 4)))))

(defun set-network-link-up (name)
  (call-rtnetlink 16 0
                  (netlink-interface-message
                   :index (cni-interface-index name) :flags 1 :change 1)))

(defun delete-network-link (name)
  (validate-network-interface-name name)
  (let ((index (native-interface-index name)))
    (unless (zerop index)
      (handler-case
          (call-rtnetlink 17 0 (netlink-interface-message :index index))
        (rtnetlink-error (condition)
          ;; Namespace destruction can remove the peer between lookup and DEL.
          (unless (= 19 (rtnetlink-error-errno condition)) (error condition)))))))

(defun ipv4-network-octets (address)
  (let ((integer (parse-ipv4-integer address)))
    (make-array 4 :element-type '(unsigned-byte 8)
                  :initial-contents
                  (loop for shift from 24 downto 0 by 8
                        collect (ldb (byte 8 shift) integer)))))

(defun add-network-address (name address prefix)
  (unless (<= 0 prefix 32) (invalid-cni "invalid IPv4 prefix ~A" prefix))
  (handler-case
      (call-rtnetlink
       20 #x600 ; RTM_NEWADDR, CREATE | EXCL
       (netlink-octets
        (vector 2 prefix 0 0) ; AF_INET, prefix, flags, scope
        (netlink-integer (cni-interface-index name) 4)
        (netlink-attribute 1 (ipv4-network-octets address)) ; IFA_ADDRESS
        (netlink-attribute 2 (ipv4-network-octets address)))) ; IFA_LOCAL
    (rtnetlink-error (condition)
      (unless (= 17 (rtnetlink-error-errno condition)) (error condition)))))

(defun replace-network-route (destination prefix name &key gateway source)
  (unless (<= 0 prefix 32) (invalid-cni "invalid route prefix ~A" prefix))
  (call-rtnetlink
   24 #x500 ; RTM_NEWROUTE, CREATE | REPLACE
   (netlink-octets
    (vector 2 prefix 0 0 254 4 (if gateway 0 253) 1) ; main, static, unicast
    (netlink-integer 0 4)
    (netlink-attribute 1 (ipv4-network-octets destination))
    (netlink-attribute 4 (netlink-integer (cni-interface-index name) 4))
    (if gateway (netlink-attribute 5 (ipv4-network-octets gateway)) #())
    (if source (netlink-attribute 7 (ipv4-network-octets source)) #()))))

(defun enable-node-ipv4-forwarding ()
  (let ((path #P"/proc/sys/net/ipv4/ip_forward"))
    (unless (string= "1" (string-trim '(#\Space #\Newline #\Tab)
                                     (uiop:read-file-string path)))
      (with-open-file (stream path :direction :output :if-exists :overwrite)
        (write-line "1" stream))))
  nil)

(defun configure-routed-veth (context address &key (mtu 1450)
                                              (gateway "169.254.1.1"))
  "Create a routed /32 Pod endpoint. The caller owns IPAM and BPF lifecycle."
  (require-cni-context context :network-namespace t)
  (enable-node-ipv4-forwarding)
  (let* ((peer (validate-network-interface-name
                (cni-context-interface-name context)))
         (host (routed-veth-name (cni-context-container-id context) peer))
         (owner (format nil "gr8s:~A/~A" (cni-context-container-id context) peer)))
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
    (add-network-address host gateway 32)
    (set-network-link-up host)
    (replace-network-route address 32 host :source gateway)
    (call-with-cni-network-namespace
     (cni-context-netns context)
     (lambda ()
       (set-network-link-owner peer owner)
       (set-network-link-mtu peer mtu)
       (set-network-link-up "lo")
       (add-network-address peer address 32)
       (set-network-link-up peer)
       (replace-network-route gateway 32 peer)
       (replace-network-route "0.0.0.0" 0 peer :gateway gateway)))
    host))
