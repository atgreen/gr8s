;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The node's flow-event ring buffer (podster-e9a). Every endpoint guard writes
;;;; to one ring the agent pins at <bpf root>/flow_events: a drop, with its
;;;; reason, and an isolated Pod's new connection, with the flow it allowed. This
;;;; file creates or reopens that pin and decodes its events; the layout is the
;;;; FLOW-EVENT struct in egress-guard-program.lisp.

(in-package #:gr8s.network)

(defparameter +flow-events-bytes+ 262144
  "The shared ring's size: a power-of-two multiple of the page size, as the kernel
requires. At 48 bytes an event, with its header, it holds about 5,000 events.")

(defparameter +flow-event-size+ 40
  "Bytes in one FLOW-EVENT.")

(defconstant +bpf-map-type-ringbuf+ 27)

(defstruct flow-record
  "One decoded flow event. ADDRESS and PEER are text; the ports are numbers, and
0 when the packet had none."
  ifindex endpoint kind reason direction family protocol pod-port peer peer-port length)

(defun flow-events-pin-path (bpf-root)
  "Where the node's flow-event ring is pinned under BPF-ROOT."
  (namestring (merge-pathnames +flow-events-map-name+ (uiop:ensure-directory-pathname bpf-root))))

(defun flow-events-map-info (fd)
  "A Whistler MAP-INFO for the flow-event ring open on FD."
  (whistler/loader::make-map-info :name +flow-events-map-name+ :type +bpf-map-type-ringbuf+
                                  :key-size 0 :value-size 0 :max-entries +flow-events-bytes+
                                  :flags 0 :fd fd))

(defun check-flow-events-ring (fd &key (object-info #'bpf-object-kernel-info))
  "Refuse an FD that isn't a flow-event ring of the expected size, since its size
is the mask the consumer reads with."
  (let ((info (funcall object-info fd)))
    (unless (and (>= (length info) 16)
                 (= +bpf-map-type-ringbuf+ (netlink-read-integer info 0 4))
                 (= +flow-events-bytes+ (netlink-read-integer info 16 4)))
      (invalid-cni "pinned ~A is not a ~D-byte ring buffer" +flow-events-map-name+ +flow-events-bytes+))))

(defun open-flow-events-ring
    (bpf-root &key create
                (path-exists-p #'probe-file)
                (open-pinned #'whistler/loader:open-pinned-object)
                (check #'check-flow-events-ring)
                (create-map #'whistler/loader::create-map)
                (pin-object #'whistler/loader:pin-bpf-object)
                (close-fd #'sb-posix:close))
  "Return a MAP-INFO for the ring pinned under BPF-ROOT, or NIL when there is none.
With CREATE, make and pin it first when it's missing; the agent does that, and
the CNI only opens it."
  (let ((path (flow-events-pin-path bpf-root)))
    (cond
      ((funcall path-exists-p path)
       (let ((fd (funcall open-pinned path)))
         (handler-bind ((error (lambda (condition)
                                 (declare (ignore condition))
                                 (ignore-errors (funcall close-fd fd)))))
           (funcall check fd))
         (flow-events-map-info fd)))
      (create
       (let ((info (flow-events-map-info -1)))
         (funcall create-map info)
         (handler-bind ((error (lambda (condition)
                                 (declare (ignore condition))
                                 (ignore-errors (funcall close-fd (whistler/loader:map-info-fd info))))))
           (funcall pin-object (whistler/loader:map-info-fd info) path))
         info)))))

(defconstant +bpf-map-type-array+ 2)

(defvar *report-every-connection* t
  "Whether this node's guards report every Pod's new connections (`--flow-events
connections', the default) or only drops and isolated Pods' connections (`drops').")

(defun flow-config-pin-path (bpf-root)
  "Where the node's flow-event settings are pinned under BPF-ROOT."
  (namestring (merge-pathnames +flow-config-map-name+ (uiop:ensure-directory-pathname bpf-root))))

(defun flow-config-map-info (fd)
  "A Whistler MAP-INFO for the flow-event settings open on FD."
  (whistler/loader::make-map-info :name +flow-config-map-name+ :type +bpf-map-type-array+
                                  :key-size 4 :value-size 4 :max-entries 1 :flags 0 :fd fd))

(defun flow-config-map-p (info)
  "Whether kernel map INFO has the flow-event settings' shape: a one-word, one-entry array."
  (and (>= (length info) 20)
       (= +bpf-map-type-array+ (netlink-read-integer info 0 4))
       (= 4 (netlink-read-integer info 8 4))
       (= 4 (netlink-read-integer info 12 4))
       (= 1 (netlink-read-integer info 16 4))))

(defun open-flow-config
    (bpf-root &key create
                (path-exists-p #'probe-file)
                (open-pinned #'whistler/loader:open-pinned-object)
                (object-info #'bpf-object-kernel-info)
                (create-map #'whistler/loader::create-map)
                (pin-object #'whistler/loader:pin-bpf-object)
                (close-fd #'sb-posix:close))
  "Return a MAP-INFO for the flow-event settings pinned under BPF-ROOT, or NIL when there
are none. With CREATE, make and pin them first when they're missing; the agent does
that, and the CNI only opens them."
  (let ((path (flow-config-pin-path bpf-root)))
    (cond
      ((funcall path-exists-p path)
       (let ((fd (funcall open-pinned path)))
         (unless (flow-config-map-p (funcall object-info fd))
           (ignore-errors (funcall close-fd fd))
           (invalid-cni "pinned ~A is not a one-word array" +flow-config-map-name+))
         (flow-config-map-info fd)))
      (create
       (let ((info (flow-config-map-info -1)))
         (funcall create-map info)
         (handler-bind ((error (lambda (condition)
                                 (declare (ignore condition))
                                 (ignore-errors (funcall close-fd (whistler/loader:map-info-fd info))))))
           (funcall pin-object (whistler/loader:map-info-fd info) path))
         info)))))

(defun set-flow-reporting (config connections &key (update #'whistler/loader:map-update))
  "Have the guards bound to CONFIG report every Pod's new connections when CONNECTIONS
is true, or only drops and isolated Pods' connections."
  (funcall update config (service-lb-bytes 0 4) (service-lb-bytes (if connections 1 0) 4)))

(defun flow-event-ipv4-text (octets start)
  "The dotted IPv4 address in OCTETS' four bytes at START, in network order."
  (format nil "~{~D~^.~}" (coerce (subseq octets start (+ start 4)) 'list)))

(defun flow-event-ipv6-text (octets start)
  "The IPv6 address in OCTETS' sixteen bytes at START, in network order, without
zero compression."
  (format nil "~(~{~X~^:~}~)"
          (loop for offset from start below (+ start 16) by 2
                collect (logior (ash (aref octets offset) 8) (aref octets (1+ offset))))))

(defun pod-interface-addresses ()
  "Map each interface index with a Pod host route on it (a /32 or /128 in the main
table, as the routed CNI installs on a Pod's host veth) to that address, IPv4 first."
  (let ((addresses (make-hash-table)))
    (dolist (route (reverse (read-ip-host-routes)) addresses)
      (destructuring-bind (&key cidr index table) route
        (let ((slash (position #\/ cidr)))
          (when (and (= table 254) (plusp index)
                     (member (subseq cidr (1+ slash)) '("32" "128") :test #'string=))
            (setf (gethash index addresses) (subseq cidr 0 slash))))))))

(defun decode-flow-event (octets)
  "Decode one ring event, or return NIL for one too short to be a FLOW-EVENT."
  (flet ((u8 (offset) (aref octets offset))
         (u32le (offset) (netlink-read-integer octets offset 4))
         (port (offset) (logior (ash (aref octets offset) 8) (aref octets (1+ offset)))))
    (when (>= (length octets) +flow-event-size+)
      (let ((family (u8 11)) (endpoint (u32le 4)))
        (make-flow-record
         :ifindex (u32le 0)
         :endpoint (unless (zerop endpoint)
                     (format nil "~{~D~^.~}" (list (ldb (byte 8 24) endpoint) (ldb (byte 8 16) endpoint)
                                                   (ldb (byte 8 8) endpoint) (ldb (byte 8 0) endpoint))))
         :kind (case (u8 8) (1 :drop) (2 :allowed) (t :unknown))
         :reason (case (u8 9) (1 :spoof) (2 :malformed) (3 :unsupported) (4 :policy))
         :direction (case (u8 10) (1 :egress) (2 :ingress))
         :family (case family (4 :ipv4) (6 :ipv6))
         :protocol (case family ((4 6) (u8 12)))
         :pod-port (port 14)
         :peer (case family
                 (4 (flow-event-ipv4-text octets 24))
                 (6 (flow-event-ipv6-text octets 24)))
         :peer-port (port 16)
         :length (u32le 20))))))
