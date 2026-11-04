;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Encode ClusterIP Service load-balancing state into the byte layout the
;;;; Whistler cgroup/connect4 program expects (network/gr8s-service-lb.lisp).
;;;; The agent writes these entries into the pinned gr8s_service_v4 and
;;;; gr8s_backend_v4 maps; the in-kernel program reads them to rewrite a
;;;; connect(2) from a Service VIP:port to a chosen backend Pod IP:targetPort.
;;;;
;;;; Two byte-order conventions meet here, and getting them wrong silently
;;;; misroutes traffic, so the encoders are pure and unit-tested:
;;;;
;;;;   * Scalar map keys and the service metadata (backend count, base slot)
;;;;     are logical integers the program does arithmetic on.  They are stored
;;;;     little-endian so a native load on the host CPU yields the value.
;;;;
;;;;   * Backend addr/port are copied verbatim into the kernel's user_ip4 /
;;;;     user_port socket-address fields, which are network byte order.  They
;;;;     are stored big-endian so the program's load/store round-trips the exact
;;;;     bytes the kernel expects.
;;;;
;;;; The VIP key mirrors what the program composes from the socket address:
;;;; (vip << 16) | htons(port), where VIP is the four address octets read as a
;;;; little-endian integer (i.e. the network-order bytes loaded on a LE host).

(in-package #:gr8s)

;;; ---------------------------------------------------------------------------
;;; In-process JIT: compile Whistler forms to loadable specs without an ELF.
;;;
;;; This is deliberately generic (it takes arbitrary defmap/defprog forms) so
;;; the egress guard can later move onto the same path.  Compilation is pure
;;; userspace and needs no privileges or kernel; only creating maps, loading the
;;; program, and attaching it to a cgroup require CAP_BPF (done by the agent).

(defvar *service-lb-program-forms* nil
  "Evaluatable (whistler:defprog ...) forms for the ClusterIP socket LB.
Set in src/service-lb-program.lisp, read in the WHISTLER package.")

(defvar *service-lb-map-forms* nil
  "Evaluatable (whistler:defmap ...) forms for the ClusterIP socket LB maps.")

(defun compile-whistler-program (map-forms program-forms)
  "JIT-compile MAP-FORMS and PROGRAM-FORMS in-process.
Returns (values map-specs prog-specs): plists carrying the map metadata and the
compiled program instruction bytes plus map-fd relocations, ready to hand to the
loader's map-creation and program-loading steps.  No ELF is produced."
  (whistler/loader::compile-bpf-forms map-forms program-forms))

(defun compile-service-lb ()
  "JIT-compile the ClusterIP socket load balancer. See compile-whistler-program."
  (compile-whistler-program *service-lb-map-forms* *service-lb-program-forms*))

;;; ---------------------------------------------------------------------------
;;; Control-plane map byte encoding (byte-order contract in the file header).

(defun service-lb-octets (address)
  "Return ADDRESS as a list of its four octets (most significant first)."
  (let ((host (parse-ipv4-integer address)))
    (list (ldb (byte 8 24) host) (ldb (byte 8 16) host)
          (ldb (byte 8 8) host) (ldb (byte 8 0) host))))

(defun service-lb-bytes (value width)
  "Serialize unsigned VALUE little-endian into WIDTH octets."
  (let ((buffer (make-array width :element-type '(unsigned-byte 8))))
    (dotimes (index width buffer)
      (setf (aref buffer index) (ldb (byte 8 (* 8 index)) value)))))

(defun service-lb-vip-key (address port)
  "Return the 8-octet gr8s_service_v4 key for ADDRESS:PORT.
The program composes (vip << 16) | htons(port) where vip is the address octets
read little-endian, then serializes that scalar; this reproduces its bytes."
  (unless (typep port '(integer 1 65535))
    (error "Service port ~S is out of range" port))
  (destructuring-bind (o0 o1 o2 o3) (service-lb-octets address)
    (let* ((vip (logior o0 (ash o1 8) (ash o2 16) (ash o3 24)))
           (vport (logior (ash (ldb (byte 8 0) port) 8) (ldb (byte 8 8) port)))
           (key (logior (ash vip 16) vport)))
      (service-lb-bytes key 8))))

(defun service-lb-service-value (backend-count base-slot)
  "Return the 8-octet gr8s_service_v4 value: count u16 @0, base slot u32 @4."
  (unless (typep backend-count '(integer 0 65535))
    (error "Service backend count ~S is out of range" backend-count))
  (let ((buffer (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace buffer (service-lb-bytes backend-count 2) :start1 0)
    (replace buffer (service-lb-bytes base-slot 4) :start1 4)
    buffer))

(defun service-lb-backend-key (slot)
  "Return the 4-octet gr8s_backend_v4 key for SLOT."
  (service-lb-bytes slot 4))

(defun service-lb-backend-value (address port)
  "Return the 8-octet gr8s_backend_v4 value: addr u32 @0 and port u16 @4, both in
network byte order so the program copies them verbatim into the socket address."
  (unless (typep port '(integer 1 65535))
    (error "Backend port ~S is out of range" port))
  (let ((buffer (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace buffer (coerce (service-lb-octets address) '(vector (unsigned-byte 8))) :start1 0)
    (setf (aref buffer 4) (ldb (byte 8 8) port)
          (aref buffer 5) (ldb (byte 8 0) port))
    buffer))

(defun service-lb-entries (address port base-slot backends)
  "Plan the map entries for one ClusterIP:PORT over BACKENDS.
BACKENDS is a list of (ip . target-port) conses, assigned consecutive slots from
BASE-SLOT.  Returns three values: the VIP key, the service value, and a list of
(backend-key . backend-value) octet-vector pairs."
  (values
   (service-lb-vip-key address port)
   (service-lb-service-value (length backends) base-slot)
   (loop for (ip . target-port) in backends
         for slot from base-slot
         collect (cons (service-lb-backend-key slot)
                       (service-lb-backend-value ip target-port)))))
