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
  device fd thread)

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
          (setf (browser-network-thread network)
                (bt:make-thread
                 (lambda ()
                   (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8))))
                     (loop for count = (read-tap-frame fd buffer)
                           while (and count (browser-network-fd network))
                           do (ignore-errors (funcall send-frame (subseq buffer 0 count))))))
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
  (let ((fd (browser-network-fd network)))
    (when fd (write-tap-frame fd frame))))

(defun stop-browser-network-device (network)
  "Close NETWORK's device, which removes it and its route."
  (let ((fd (browser-network-fd network)))
    (setf (browser-network-fd network) nil)
    (when fd (ignore-errors (sb-unix:unix-close fd)))
    (let ((thread (browser-network-thread network)))
      (when (and thread (bt:thread-alive-p thread))
        (ignore-errors (bt:destroy-thread thread))))))
