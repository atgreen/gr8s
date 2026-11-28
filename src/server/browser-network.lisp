;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Browser nodes' Pod network (podster-57fv.3, docs/design-browser-nodes.md).
;;;;
;;;; A browser Pod is an ordinary member of the cluster network: it has an address in its
;;;; node's Pod CIDR, which Services, EndpointSlices and Gateways use like any other. The
;;;; server hosting the node gives that CIDR a TAP device whose first address is the Pods'
;;;; gateway, so the kernel here routes the CIDR to it, and the cluster's routes carry the
;;;; CIDR to this host (assigned-node-routes adds it to the host's route). Each Ethernet
;;;; frame the device gives up goes to the browser as one binary WebSocket message, where
;;;; the page switches it to the Pod's virtual NIC, and each frame a Pod sends comes back
;;;; the same way. The packets themselves cross this host's kernel, so its routing,
;;;; firewall and egress handling see them as they see any Pod's.
;;;;
;;;; Creating a TAP device takes CAP_NET_ADMIN. Without it, browser Pods simply have no
;;;; address, and everything else about the node still works.

(in-package #:gr8s.server)

(defconstant +tunsetiff+ #x400454ca)
(defconstant +iff-tap+ #x0002)
(defconstant +iff-no-pi+ #x1000)

(defun open-tap-device (name)
  "Open a new TAP device NAME (Ethernet frames, no packet information header) and return
its file descriptor. The device lasts as long as the descriptor. Signals on failure."
  (let ((fd (sb-unix:unix-open "/dev/net/tun" sb-unix:o_rdwr 0)))
    (unless fd (error "cannot open /dev/net/tun"))
    (sb-alien:with-alien ((request (array (sb-alien:unsigned 8) 40)))
      (dotimes (i 40) (setf (sb-alien:deref request i) 0))
      (loop for byte across (sb-ext:string-to-octets name :external-format :ascii)
            for i from 0 below 15
            do (setf (sb-alien:deref request i) byte))
      (let ((flags (logior +iff-tap+ +iff-no-pi+)))
        (setf (sb-alien:deref request 16) (ldb (byte 8 0) flags)
              (sb-alien:deref request 17) (ldb (byte 8 8) flags)))
      (unless (zerop (sb-alien:alien-funcall
                      (sb-alien:extern-alien "ioctl" (function sb-alien:int sb-alien:int sb-alien:unsigned-long
                                                               (* (array (sb-alien:unsigned 8) 40))))
                      fd +tunsetiff+ (sb-alien:addr request)))
        (sb-unix:unix-close fd)
        (error "cannot create TAP device ~A (CAP_NET_ADMIN is needed)" name)))
    fd))

(defun read-tap-frame (fd buffer)
  "Read one frame from FD into BUFFER; return its length, or NIL when the device is gone."
  (sb-sys:with-pinned-objects (buffer)
    (let ((count (sb-unix:unix-read fd (sb-sys:vector-sap buffer) (length buffer))))
      (and count (plusp count) count))))

(defun write-tap-frame (fd frame)
  "Give FRAME, an octet vector, to the kernel through FD. A frame the device refuses is dropped."
  (let ((frame (coerce frame '(simple-array (unsigned-byte 8) (*)))))
    (sb-sys:with-pinned-objects (frame)
      (sb-unix:unix-write fd frame 0 (length frame)))))

;;; Addresses

(defun parse-ipv4-cidr (cidr)
  "CIDR (\"10.80.16.0/20\") as (values network-integer prefix-length)."
  (destructuring-bind (address prefix) (uiop:split-string cidr :separator '(#\/))
    (values (reduce (lambda (sum part) (+ (* sum 256) (parse-integer part)))
                    (uiop:split-string address :separator '(#\.)) :initial-value 0)
            (parse-integer prefix))))

(defun ipv4-string (integer)
  (format nil "~{~D~^.~}" (loop for shift from 24 downto 0 by 8 collect (ldb (byte 8 shift) integer))))

(defstruct (browser-network (:constructor %make-browser-network (cidr gateway prefix)))
  "A browser node's Pod network: its CIDR, the gateway address the host's device holds,
and which addresses its Pods have, by Pod uid."
  cidr gateway prefix
  (lock (bt:make-lock "gr8s browser network"))
  (addresses (make-hash-table :test #'equal))
  device fd thread
  ;; The Pods' NetworkPolicy, enforced on every frame (below), or NIL to pass all.
  (policy nil)
  ;; Frames relayed to and from the Pods, and those the policy dropped.
  (frames-in 0) (frames-out 0) (dropped-in 0) (dropped-out 0))

(defun make-browser-network (cidr)
  "The network for Pod CIDR, an IPv4 CIDR: its first host address is the gateway."
  (multiple-value-bind (network prefix) (parse-ipv4-cidr cidr)
    (%make-browser-network cidr (ipv4-string (1+ network)) prefix)))

(defun browser-network-address (network uid)
  "The address of the Pod UID on NETWORK, given one when it has none yet."
  (bt:with-lock-held ((browser-network-lock network))
    (or (gethash uid (browser-network-addresses network))
        (multiple-value-bind (base prefix) (parse-ipv4-cidr (browser-network-cidr network))
          (let ((taken (loop for address being the hash-values of (browser-network-addresses network)
                             collect address))
                (last (+ base (1- (expt 2 (- 32 prefix))) -1)))
            (loop for candidate from (+ base 2) to last
                  for address = (ipv4-string candidate)
                  unless (member address taken :test #'equal)
                    do (return (setf (gethash uid (browser-network-addresses network)) address))
                  finally (error 'runtime-error :message "The browser node's Pod CIDR is full")))))))

(defun seed-browser-network-addresses (network store node-name)
  "Give the Pods bound to NODE-NAME in STORE back the addresses they had on NETWORK: each
keeps its last observed podIP when that is one of NETWORK's Pod addresses and no other Pod
has it yet. A restarted server hands out addresses afresh, so a tab that rejoins with its
Pods still running found them given to other Pods, and their own gone (podster-r34s)."
  (multiple-value-bind (base prefix) (parse-ipv4-cidr (browser-network-cidr network))
    (let ((last (+ base (1- (expt 2 (- 32 prefix))) -1))
          (kept (with-store-lock (store)
                  (loop for pod being the hash-values of (gr8s.store:pod-store-pods store)
                        for status = (and (equal node-name (gr8s.model::pod-node-name pod))
                                          (gethash (gr8s.model::pod-uid pod)
                                                   (gr8s.store:pod-store-pod-observed-statuses store)))
                        for address = (and (hash-table-p status) (gethash "podIP" status))
                        when (stringp address)
                          collect (cons (gr8s.model::pod-uid pod) address)))))
      (bt:with-lock-held ((browser-network-lock network))
        (loop for (uid . address) in kept
              for integer = (ignore-errors (parse-ipv4-cidr (format nil "~A/32" address)))
              when (and integer (<= (+ base 2) integer last)
                        (not (gethash uid (browser-network-addresses network)))
                        (not (find address (loop for taken being the hash-values of (browser-network-addresses network)
                                                 collect taken)
                                   :test #'equal)))
                do (setf (gethash uid (browser-network-addresses network)) address)))
      network)))

(defun release-browser-network-address (network uid)
  (bt:with-lock-held ((browser-network-lock network))
    (remhash uid (browser-network-addresses network))))

;;; The device and the relay

(defun browser-tap-name (node-name)
  "The TAP device name for NODE-NAME: gb- and its last six characters, within IFNAMSIZ."
  (format nil "gb-~A" (subseq node-name (max 0 (- (length node-name) 6)))))

(defun start-browser-network-device (network node-name send-frame)
  "Give NETWORK a TAP device on this host holding its gateway address, and call SEND-FRAME
with each frame the kernel sends to its Pods until the device is closed. Returns NETWORK,
or NIL when this process may not create devices (no CAP_NET_ADMIN), after saying why."
  (let ((name (browser-tap-name node-name)))
    (handler-case
        (let ((fd (open-tap-device name)))
          (setf (browser-network-device network) name
                (browser-network-fd network) fd)
          (gr8s.network::add-network-address name (browser-network-gateway network)
                                             (browser-network-prefix network))
          (gr8s.network::set-network-link-up name)
          ;; A host's firewalld would refuse forwarding to and from the device, as it
          ;; would the overlay's: trust it, as gr8s does its overlay. Fail-soft, and only
          ;; as root: anyone else's firewall-cmd asks polkit, which prompts a desktop user.
          (ignore-errors
           (when (and (zerop (sb-posix:geteuid)) (gr8s.network::host-firewalld-active-p))
             (gr8s.network::host-firewall-run (list "firewall-cmd" "--zone" "trusted" "--add-interface" name))))
          (setf (browser-network-thread network)
                (bt:make-thread
                 (lambda ()
                   (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8))))
                     (loop for count = (read-tap-frame fd buffer)
                           while (and count (browser-network-fd network))
                           do (let ((frame (subseq buffer 0 count))
                                    (policy (browser-network-policy network)))
                                (if (browser-frame-admit-p policy network frame :ingress)
                                    (progn (incf (browser-network-frames-in network))
                                           (ignore-errors (funcall send-frame frame)))
                                    (incf (browser-network-dropped-in network)))))))
                 :name (format nil "gr8s browser network ~A" name)))
          network)
      (error (condition)
        (format *error-output* "gr8s browser node ~A has no Pod network: ~A~%" node-name condition)
        (when (browser-network-fd network)
          (ignore-errors (sb-unix:unix-close (browser-network-fd network)))
          (setf (browser-network-fd network) nil))
        nil))))

(defun browser-network-receive (network frame)
  "Give FRAME, from the browser's Pods, to this host's kernel."
  (let ((fd (browser-network-fd network))
        (policy (browser-network-policy network)))
    (when fd
      (if (browser-frame-admit-p policy network frame :egress)
          (progn (incf (browser-network-frames-out network))
                 (write-tap-frame fd frame))
          (incf (browser-network-dropped-out network))))))

(defun stop-browser-network-device (network)
  "Close NETWORK's device, which removes it and its route."
  (let ((fd (browser-network-fd network)))
    (setf (browser-network-fd network) nil)
    (when fd (ignore-errors (sb-unix:unix-close fd)))
    (when (browser-network-device network)
      (ignore-errors
       (when (and (zerop (sb-posix:geteuid)) (gr8s.network::host-firewalld-active-p))
         (gr8s.network::host-firewall-run
          (list "firewall-cmd" "--zone" "trusted" "--remove-interface" (browser-network-device network))))))
    (let ((thread (browser-network-thread network)))
      (when (and thread (bt:thread-alive-p thread))
        (ignore-errors (bt:destroy-thread thread))))))

;;; NetworkPolicy (podster-57fv.7). A browser Pod's packets cross this host's kernel, but
;;; not the veth where gr8s's eBPF guards stand, so the relay enforces the Pod's policy
;;; itself, from the same resolved projection the nodes get: a direction a policy selects
;;; the Pod for admits only what its rules allow, and replies to what was admitted. The
;;; hosting node itself, at the gateway address, always reaches its Pods, as a node does
;;; through its gateway. Every frame from the browser must also come from an address the
;;; server gave one of its Pods: the browser is not trusted to keep to its own.

(defparameter +browser-flow-idle-seconds+ 300
  "How long an admitted connection's replies stay admitted after its last packet.")

(defstruct (browser-policy (:constructor make-browser-policy ()))
  "Each Pod's policy, by address: (ingress-isolated ingress-entries egress-isolated
egress-entries), and the admitted connections whose replies pass."
  (lock (bt:make-lock "gr8s browser policy"))
  (pods (make-hash-table :test #'equal))
  (flows (make-hash-table :test #'equal)))

(defun browser-policy-update (policy store pods)
  "Resolve the policy of PODS, a list of (address . pod-object), against STORE's
NetworkPolicies, replacing what POLICY held."
  (let* ((specs (gr8s.network::network-policy-specs-from-objects
                 (gr8s.network::network-policy-projection store)))
         (table (make-hash-table :test #'equal)))
    (loop for (address . object) in pods
          for metadata = (gethash "metadata" object)
          for pod = (gr8s.network::make-np-pod
                     :name (gethash "name" metadata) :namespace (gethash "namespace" metadata)
                     :labels (or (gethash "labels" metadata) (core-object))
                     :ip address :ips (list address)
                     :ports (gr8s.network::np-container-ports object))
          do (multiple-value-bind (in-isolated in-entries) (gr8s.network::pod-network-policy-entries pod specs :ingress)
               (multiple-value-bind (out-isolated out-entries) (gr8s.network::pod-network-policy-entries pod specs :egress)
                 (setf (gethash address table) (list in-isolated in-entries out-isolated out-entries)))))
    (bt:with-lock-held ((browser-policy-lock policy))
      (setf (browser-policy-pods policy) table))))

(defun browser-policy-entries-admit-p (entries address protocol port)
  "Whether one of ENTRIES, as pod-network-policy-entries makes them, admits ADDRESS on
PROTOCOL (a number) and PORT (NIL for a protocol without ports)."
  (some (lambda (entry)
          (destructuring-bind (cidr excepts ports) entry
            (and (not (find #\: cidr))
                 (gr8s.network::network-address-in-cidr-p cidr address)
                 (notany (lambda (except) (gr8s.network::network-address-in-cidr-p except address)) excepts)
                 (or (eq ports :all)
                     (some (lambda (range)
                             (destructuring-bind (range-protocol first last) range
                               (and (eql range-protocol protocol)
                                    (or (null first) (and port (<= first port (or last first)))))))
                           ports)))))
        entries))

(defun ipv4-frame-flow (frame)
  "FRAME's IPv4 flow as (values protocol source source-port destination destination-port),
or NIL when it isn't a well-formed IPv4 frame. Ports are NIL for protocols without them."
  (when (and (>= (length frame) 34) (= (aref frame 12) #x08) (= (aref frame 13) #x00)
             (= (ash (aref frame 14) -4) 4) (>= (logand (aref frame 14) #x0f) 5)
             (>= (length frame) (+ 14 (* 4 (logand (aref frame 14) #x0f)))))
    (let* ((header (* 4 (logand (aref frame 14) #x0f)))
           (protocol (aref frame 23))
           (l4 (+ 14 header))
           (ports-p (and (member protocol '(6 17 132)) (>= (length frame) (+ l4 4))
                         (zerop (logand (aref frame 20) #x1f)) (zerop (aref frame 21)))))
      (flet ((address (at) (format nil "~D.~D.~D.~D" (aref frame at) (aref frame (+ at 1))
                                   (aref frame (+ at 2)) (aref frame (+ at 3))))
             (port (at) (+ (* 256 (aref frame at)) (aref frame (1+ at)))))
        (values protocol (address 26) (and ports-p (port l4))
                (address 30) (and ports-p (port (+ l4 2))))))))

(defun browser-pod-address-p (network address)
  "Whether ADDRESS is one of NETWORK's Pods'."
  (bt:with-lock-held ((browser-network-lock network))
    (loop for pod being the hash-values of (browser-network-addresses network)
          thereis (equal pod address))))

(defun arp-frame-admit-p (network frame direction)
  "Whether FRAME is ARP for IPv4 over Ethernet that may pass in DIRECTION: from the
browser, only when its sender address is one of its Pods' (or 0.0.0.0, a probe), so a tab
can't claim the gateway or another node's addresses."
  (and (>= (length frame) 42)
       (= (aref frame 12) #x08) (= (aref frame 13) #x06)
       (= (aref frame 14) 0) (= (aref frame 15) 1)          ; Ethernet
       (= (aref frame 16) #x08) (= (aref frame 17) #x00)    ; IPv4
       (= (aref frame 18) 6) (= (aref frame 19) 4)
       (= (aref frame 20) 0) (member (aref frame 21) '(1 2)) ; request or reply
       (or (eq direction :ingress)
           (let ((sender (format nil "~D.~D.~D.~D" (aref frame 28) (aref frame 29) (aref frame 30) (aref frame 31))))
             (or (string= sender "0.0.0.0") (browser-pod-address-p network sender))))))

(defun browser-frame-admit-p (policy network frame direction)
  "Whether FRAME may pass in DIRECTION: :egress from the browser's Pods, :ingress to them.
Only IPv4 and ARP pass at all (podster-vlnv): IPv6 and every other kind are dropped, as
nothing checks them. IPv4 must be well formed and, from the browser, come from one of its
Pods' addresses, and with POLICY keep to the Pods' NetworkPolicy; ARP must be well formed
and, from the browser, speak only for its Pods."
  (cond ((ipv4-frame-flow frame)
         (and (or (eq direction :ingress)
                  (browser-pod-address-p network (nth-value 1 (ipv4-frame-flow frame))))
              (or (null policy) (browser-policy-admit-p policy network frame direction))))
        (t (arp-frame-admit-p network frame direction))))

(defun browser-policy-admit-p (policy network frame direction)
  "Whether FRAME, a well-formed IPv4 frame (browser-frame-admit-p checks that and its
source), keeps to the NetworkPolicy of the browser's Pods in DIRECTION."
  (multiple-value-bind (protocol source source-port destination destination-port) (ipv4-frame-flow frame)
    (let ((now (get-universal-time))
          (pod-address (if (eq direction :egress) source destination))
          (peer (if (eq direction :egress) destination source))
          (port destination-port))
      (bt:with-lock-held ((browser-policy-lock policy))
        (let ((flows (browser-policy-flows policy))
              (reverse (list protocol destination destination-port source source-port))
              (forward (list protocol source source-port destination destination-port)))
          (flet ((admit ()
                   (setf (gethash forward flows) now)
                   t))
            (cond
              ;; A reply to an admitted connection, or more of one.
              ((let ((seen (or (gethash reverse flows) (gethash forward flows))))
                 (and seen (< (- now seen) +browser-flow-idle-seconds+)))
               (admit))
              ((and (eq direction :ingress) (equal source (browser-network-gateway network))) (admit))
              (t
               (destructuring-bind (&optional in-isolated in-entries out-isolated out-entries)
                   (gethash pod-address (browser-policy-pods policy))
                 (let ((isolated (if (eq direction :ingress) in-isolated out-isolated))
                       (entries (if (eq direction :ingress) in-entries out-entries)))
                   (when (or (not isolated) (browser-policy-entries-admit-p entries peer protocol port))
                     (when (> (hash-table-count flows) 65536)
                       (loop for key being the hash-keys of flows using (hash-value seen)
                             when (>= (- now seen) +browser-flow-idle-seconds+) do (remhash key flows)))
                     (admit))))))))))))
