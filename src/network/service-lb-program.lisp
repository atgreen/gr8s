;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The Whistler source for the ClusterIP socket load balancer (connect4, sendmsg4
;;;; and recvmsg4 hooks), held as data so
;;;; the agent can JIT-compile it in-process (via whistler/loader) and load it
;;;; straight into the kernel.  gr8s never writes or embeds an ELF object for
;;;; this program: the full Whistler compiler is already in the image, so the
;;;; agent compiles Lisp to eBPF at load time.  Keeping the program as forms
;;;; also opens the door to specializing it per node before loading.
;;;;
;;;; This file is read with *package* bound to WHISTLER, so every symbol in the
;;;; quoted forms below (defmap, defprog, ctx, map-lookup, when-let, load, <<,
;;;; logior, get-prandom-u32, ...) interns in the WHISTLER package, exactly as
;;;; if the program were written in a standalone *.lisp compiled by the CLI.
;;;; The gr8s-visible bindings are defined under the GR8S package.
;;;;
;;;; See src/service-lb.lisp for the control-plane map byte encoding (and the
;;;; byte-order contract the program below depends on), and network/ has no
;;;; counterpart on purpose: there is no ELF build step.

(in-package #:whistler)

;; Whistler lists helpers by name; bpf_get_netns_cookie is available to these
;; programs from Linux 5.7 and identifies the connecting client's network namespace.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (pushnew '("GET-NETNS-COOKIE" . 122) whistler/compiler:*builtin-helpers* :test #'equal)
  ;; bpf_set_retval (Linux 5.19) lets a cgroup hook fail connect(2) with an errno of its choosing.
  (pushnew '("SET-RETVAL" . 187) whistler/compiler:*builtin-helpers* :test #'equal))

;; Map definitions, as evaluatable (whistler:defmap ...) forms.
;;
;;   gr8s_service_v4   key u64  (protocol << 48) | (vip << 16) | htons(port)
;;                     value 16 count u16 @0, affinity u16 @2, base slot u32 @4,
;;                              affinity timeout seconds u32 @8, flags u32 @12 (bit 0: refuse,
;;                              set for a Service with no endpoints at all)
;;   gr8s_backend_v4   key u32  backend slot
;;                     value 8  addr u32 @0, port u16 @4 (both network byte order), zero u16 @6
;;   gr8s_backend_index_v4
;;                     key 16   service key u64 @0, backend value u64 @8
;;                     value u32 the backend's offset among the service's slots
;;   gr8s_affinity_v4  key 16   service key u64 @0, client netns cookie u64 @8
;;                     value 16 backend value u64 @0, last seen seconds u64 @8
;;   gr8s_reverse_v4   key 16   socket cookie u64 @0, backend value u64 @8
;;                     value u64 vip u32 | (port u16 << 32), as the client addressed it
;;
;; The service, backend and index maps are NO_PREALLOC hashes so memory tracks live
;; Services/backends; the LRUs forget clients and sockets that have long gone away.
;; A backend value doubles as the backend's identity: the index checks membership
;; for every Service while shared slots are repacked, and finds the current offset
;; so affinity follows the backend rather than a slot that a change shifts.
(defparameter gr8s.network::*service-lb-map-forms*
  '((defmap gr8s-service-v4 :type :hash
      :key-size 8 :value-size 16 :max-entries 4096 :map-flags 1)
    (defmap gr8s-backend-v4 :type :hash
      :key-size 4 :value-size 8 :max-entries 65536 :map-flags 1)
    (defmap gr8s-backend-index-v4 :type :hash
      :key-size 16 :value-size 4 :max-entries 65536 :map-flags 1)
    (defmap gr8s-affinity-v4 :type :lru-hash
      :key-size 16 :value-size 16 :max-entries 65536)
    (defmap gr8s-reverse-v4 :type :lru-hash
      :key-size 16 :value-size 8 :max-entries 65536)
    (defmap gr8s-service-v6 :type :hash
      :key-size 20 :value-size 16 :max-entries 4096 :map-flags 1)
    (defmap gr8s-backend-v6 :type :hash
      :key-size 4 :value-size 20 :max-entries 65536 :map-flags 1)
    (defmap gr8s-backend-index-v6 :type :hash
      :key-size 40 :value-size 4 :max-entries 65536 :map-flags 1)
    (defmap gr8s-affinity-v6 :type :lru-hash
      :key-size 32 :value-size 32 :max-entries 65536)
    (defmap gr8s-reverse-v6 :type :lru-hash
      :key-size 32 :value-size 20 :max-entries 65536)
    ;; Egress capture (podster-wv1w.2): network namespace cookie -> 1 for each Pod
    ;; whose egress policy names domains, and the IPv4 prefixes that stay outside the
    ;; capture because they are the cluster's own (Pod and Service ranges, nodes,
    ;; link-local), where address policy applies as before.
    (defmap gr8s-egress-capture :type :hash
      :key-size 8 :value-size 1 :max-entries 4096 :map-flags 1)
    (defmap gr8s-egress-exempt-v4 :type :lpm-trie
      :key-size 8 :value-size 1 :max-entries 256 :map-flags 1)
    ;; Pod IPv4 (network order) -> its network namespace cookie, written at CNI ADD,
    ;; from which the agent fills gr8s-egress-capture. Pinned here only to outlive
    ;; an agent restart; no program reads it.
    (defmap gr8s-pod-netns-v4 :type :hash
      :key-size 4 :value-size 8 :max-entries 4096 :map-flags 1)))

(defun gr8s.network::service-lb-steer-program (name section)
  "Return the (defprog NAME ...) form steering a socket address hook at SECTION.
connect(2) and an unconnected sendmsg(2) alike are rewritten in place from a
Service VIP:port and protocol to a backend chosen uniformly at random, or for a
ClientIP affinity Service to the backend this client last used while that is within
the timeout and the backend still serves.  The client is its network namespace,
which owns the source address a packet-level proxy would key on; a socket hook runs
before any source address is chosen.  A Service with no endpoints at all is refused
with ECONNREFUSED, as kube-proxy rejects it; one whose endpoints are all elsewhere
(internalTrafficPolicy Local) keeps a zero count and is left untouched, as kube-proxy
drops it.  No DNAT, no conntrack: the socket talks to the real backend.
For UDP the socket's (cookie, backend) is remembered, so the recvmsg4 hook can show
replies as coming from the address the client sent to.
A Pod whose netns is in gr8s-egress-capture (podster-wv1w.2) instead has TCP to any
address outside gr8s-egress-exempt-v4 sent to the node egress proxy at 169.254.1.2,
keeping the port; its DNS to the node gateway sent to the egress DNS gate there; and UDP
to port 443 refused with EPERM so QUIC clients fall back to TCP, where the proxy can see
the name they ask for. In mode 2 (the map's value; podster-wv1w.8) its TCP may reach only
the synthetic range 198.18.0.0/15, which the node delivers to the proxy unchanged; any
other address outside gr8s-egress-exempt-v4 is refused with EPERM."
  `(defprog ,name (:type :cgroup-sock-addr :section ,section :license "GPL")
     (let* ((vip u64 (cast u64 (ctx user-ip4)))
            (vport u64 (logand (cast u64 (ctx user-port)) #xffff))
            (proto u64 (logand (cast u64 (ctx protocol)) #xff))
            (key u64 (logior (<< proto 48) (logior (<< vip 16) vport))))
       (when (= (map-lookup gr8s-service-v4 key) 0)
         (when-let ((capture u64 (map-lookup gr8s-egress-capture (get-netns-cookie (ctx-ptr)))))
           (when (and (= proto 17) (= vport #xbb01)) ; port 443, network order
             (set-retval #xffffffff)                 ; -EPERM
             (return 0))
           ;; DNS to the node gateway goes to the egress DNS gate on the proxy
           ;; address, which answers only the names the Pod's policy allows. A UDP
           ;; reply is shown as the gateway's, as for a Service.
           (when (and (= vport #x3500) (= vip #x0101fea9)) ; 169.254.1.1:53
             (when (= proto 17)
               (let ((socket (make-gr8s-lb-pair)))
                 (setf (gr8s-lb-pair-first socket) (get-socket-cookie (ctx-ptr))
                       (gr8s-lb-pair-second socket) #x35000201fea9) ; 169.254.1.2:53
                 (setf (getmap gr8s-reverse-v4 socket) (logior vip (<< vport 32)))))
             (setf (ctx user-ip4) #x0201fea9)
             (return 1))
           (when (= proto 6)
             (let ((exempt (make-gr8s-egress-lpm-key)))
               (setf (gr8s-egress-lpm-key-prefixlen exempt) 32
                     (gr8s-egress-lpm-key-address exempt) (cast u32 vip))
               (when (= (map-lookup-ptr gr8s-egress-exempt-v4 exempt) 0)
                 ;; Mode 2: synthetic addresses pass as dialled, so the proxy sees
                 ;; which one; a real public address is refused.
                 (when (= (load u8 capture 0) 2)
                   (when (= (logand vip #xfeff) #x12c6) ; 198.18.0.0/15, network order
                     (return 1))
                   (set-retval #xffffffff)              ; -EPERM
                   (return 0))
                 (setf (ctx user-ip4) #x0201fea9)     ; 169.254.1.2, network order
                 (return 1))))))
       (when-let ((service u64 (map-lookup gr8s-service-v4 key)))
         (let ((count u32 (cast u32 (load u16 service 0))))
           (when (and (= count 0) (> (logand (load u32 service 12) 1) 0))
             (set-retval #xffffff91)      ; -ECONNREFUSED as the int the helper takes
             (return 0))
           (when (> count 0)
             (let* ((offset u32 (mod (get-prandom-u32) count))
                    (sticky u64 (load u16 service 2))
                    (timeout u64 (load u32 service 8))
                    (now u64 (/ (ktime-get-ns) 1000000000))
                    (client (make-gr8s-lb-pair)))
               (when (> sticky 0)
                 (setf (gr8s-lb-pair-first client) key
                       (gr8s-lb-pair-second client) (get-netns-cookie (ctx-ptr)))
                 (when-let ((held (map-lookup-ptr gr8s-affinity-v4 client)))
                   (when (<= (- now (load u64 held 8)) timeout)
                     (let ((probe (make-gr8s-lb-pair)))
                       (setf (gr8s-lb-pair-first probe) key
                             (gr8s-lb-pair-second probe) (load u64 held 0))
                       (when-let ((index (map-lookup-ptr gr8s-backend-index-v4 probe)))
                         (let ((found u32 (load u32 index 0)))
                           (when (< found count)
                             (setf offset found))))))))
               (let ((slot u32 (+ (load u32 service 4) offset)))
                 (when-let ((backend u64 (map-lookup gr8s-backend-v4 slot)))
                   (let ((identity u64 (load u64 backend 0)))
                     ;; A reconcile may have repacked this slot for another
                     ;; Service before publishing our new base. Validate the
                     ;; copied backend identity before using it, even without
                     ;; affinity. A miss fails closed and the next connect can
                     ;; retry after reconciliation has completed.
                     (let ((member-key (make-gr8s-lb-pair)))
                       (setf (gr8s-lb-pair-first member-key) key
                             (gr8s-lb-pair-second member-key) identity)
                       (when (= (map-lookup-ptr gr8s-backend-index-v4 member-key) 0)
                         (set-retval #xffffff91)
                         (return 0)))
                     (when (> sticky 0)
                       (let ((entry (make-gr8s-lb-pair)))
                         (setf (gr8s-lb-pair-first entry) identity
                               (gr8s-lb-pair-second entry) now)
                         (map-update-ptr gr8s-affinity-v4 client entry 0)))
                     (when (= proto 17)
                       (let ((socket (make-gr8s-lb-pair)))
                         (setf (gr8s-lb-pair-first socket) (get-socket-cookie (ctx-ptr))
                               (gr8s-lb-pair-second socket) identity)
                         (setf (getmap gr8s-reverse-v4 socket) (logior vip (<< vport 32)))))
                     (setf (ctx user-ip4) (cast u32 identity))
                     (setf (ctx user-port) (cast u32 (logand (>> identity 32) #xffff)))))))))))
     1))

(defun gr8s.network::service-lb-v6-steer-program (name section)
  "Return an IPv6 socket-address hook equivalent to SERVICE-LB-STEER-PROGRAM."
  `(defprog ,name (:type :cgroup-sock-addr :section ,section :license "GPL")
     (let ((key (make-gr8s-lb-v6-service-key)))
       (setf (gr8s-lb-v6-service-key-address key 0) (ctx user-ip6 0)
             (gr8s-lb-v6-service-key-address key 1) (ctx user-ip6 1)
             (gr8s-lb-v6-service-key-address key 2) (ctx user-ip6 2)
             (gr8s-lb-v6-service-key-address key 3) (ctx user-ip6 3)
             (gr8s-lb-v6-service-key-port key) (cast u16 (ctx user-port))
             (gr8s-lb-v6-service-key-protocol key) (cast u8 (ctx protocol)))
       (when-let ((service (map-lookup-ptr gr8s-service-v6 key)))
         (let ((count u32 (cast u32 (load u16 service 0))))
           (when (and (= count 0) (> (logand (load u32 service 12) 1) 0))
             (set-retval #xffffff91)
             (return 0))
           (when (> count 0)
             (let* ((offset u32 (mod (get-prandom-u32) count))
                    (sticky u64 (load u16 service 2))
                    (timeout u64 (load u32 service 8))
                    (now u64 (/ (ktime-get-ns) 1000000000))
                    (client (make-gr8s-lb-v6-affinity-key)))
               (when (> sticky 0)
                 (setf (gr8s-lb-v6-affinity-key-address client 0) (ctx user-ip6 0)
                       (gr8s-lb-v6-affinity-key-address client 1) (ctx user-ip6 1)
                       (gr8s-lb-v6-affinity-key-address client 2) (ctx user-ip6 2)
                       (gr8s-lb-v6-affinity-key-address client 3) (ctx user-ip6 3)
                       (gr8s-lb-v6-affinity-key-port client) (cast u16 (ctx user-port))
                       (gr8s-lb-v6-affinity-key-protocol client) (cast u8 (ctx protocol))
                       (gr8s-lb-v6-affinity-key-cookie client) (get-netns-cookie (ctx-ptr)))
                 (when-let ((held (map-lookup-ptr gr8s-affinity-v6 client)))
                   (when (<= (- now (load u64 held 24)) timeout)
                     (let ((probe (make-gr8s-lb-v6-index-key)))
                       (setf (gr8s-lb-v6-index-key-vip-address probe 0) (ctx user-ip6 0)
                             (gr8s-lb-v6-index-key-vip-address probe 1) (ctx user-ip6 1)
                             (gr8s-lb-v6-index-key-vip-address probe 2) (ctx user-ip6 2)
                             (gr8s-lb-v6-index-key-vip-address probe 3) (ctx user-ip6 3)
                             (gr8s-lb-v6-index-key-vip-port probe) (cast u16 (ctx user-port))
                             (gr8s-lb-v6-index-key-protocol probe) (cast u8 (ctx protocol))
                             (gr8s-lb-v6-index-key-backend-address probe 0) (load u32 held 0)
                             (gr8s-lb-v6-index-key-backend-address probe 1) (load u32 held 4)
                             (gr8s-lb-v6-index-key-backend-address probe 2) (load u32 held 8)
                             (gr8s-lb-v6-index-key-backend-address probe 3) (load u32 held 12)
                             (gr8s-lb-v6-index-key-backend-port probe) (load u16 held 16))
                       (when-let ((index (map-lookup-ptr gr8s-backend-index-v6 probe)))
                         (let ((found u32 (load u32 index 0)))
                           (when (< found count) (setf offset found))))))))
               (let ((slot u32 (+ (load u32 service 4) offset)))
                 (when-let ((backend u64 (map-lookup gr8s-backend-v6 slot)))
                   ;; Copy the selected address into the membership key before
                   ;; invoking another helper. Use that checked copy for every
                   ;; subsequent operation, rather than rereading the slot.
                   (let ((member-key (make-gr8s-lb-v6-index-key)))
                     (setf (gr8s-lb-v6-index-key-vip-address member-key 0) (gr8s-lb-v6-service-key-address key 0)
                           (gr8s-lb-v6-index-key-vip-address member-key 1) (gr8s-lb-v6-service-key-address key 1)
                           (gr8s-lb-v6-index-key-vip-address member-key 2) (gr8s-lb-v6-service-key-address key 2)
                           (gr8s-lb-v6-index-key-vip-address member-key 3) (gr8s-lb-v6-service-key-address key 3)
                           (gr8s-lb-v6-index-key-vip-port member-key) (gr8s-lb-v6-service-key-port key)
                           (gr8s-lb-v6-index-key-protocol member-key) (gr8s-lb-v6-service-key-protocol key)
                           (gr8s-lb-v6-index-key-backend-address member-key 0) (load u32 backend 0)
                           (gr8s-lb-v6-index-key-backend-address member-key 1) (load u32 backend 4)
                           (gr8s-lb-v6-index-key-backend-address member-key 2) (load u32 backend 8)
                           (gr8s-lb-v6-index-key-backend-address member-key 3) (load u32 backend 12)
                           (gr8s-lb-v6-index-key-backend-port member-key) (load u16 backend 16))
                     (when (= (map-lookup-ptr gr8s-backend-index-v6 member-key) 0)
                       (set-retval #xffffff91)
                       (return 0))
                     (when (> sticky 0)
                       (let ((entry (make-gr8s-lb-v6-affinity-value)))
                         (setf (gr8s-lb-v6-affinity-value-address entry 0) (gr8s-lb-v6-index-key-backend-address member-key 0)
                               (gr8s-lb-v6-affinity-value-address entry 1) (gr8s-lb-v6-index-key-backend-address member-key 1)
                               (gr8s-lb-v6-affinity-value-address entry 2) (gr8s-lb-v6-index-key-backend-address member-key 2)
                               (gr8s-lb-v6-affinity-value-address entry 3) (gr8s-lb-v6-index-key-backend-address member-key 3)
                               (gr8s-lb-v6-affinity-value-port entry) (gr8s-lb-v6-index-key-backend-port member-key)
                               (gr8s-lb-v6-affinity-value-seen entry) now)
                         (map-update-ptr gr8s-affinity-v6 client entry 0)))
                     (when (= (ctx protocol) 17)
                       (let ((socket (make-gr8s-lb-v6-reverse-key))
                             (original (make-gr8s-lb-v6-address)))
                         (setf (gr8s-lb-v6-reverse-key-cookie socket) (get-socket-cookie (ctx-ptr))
                               (gr8s-lb-v6-reverse-key-address socket 0) (gr8s-lb-v6-index-key-backend-address member-key 0)
                               (gr8s-lb-v6-reverse-key-address socket 1) (gr8s-lb-v6-index-key-backend-address member-key 1)
                               (gr8s-lb-v6-reverse-key-address socket 2) (gr8s-lb-v6-index-key-backend-address member-key 2)
                               (gr8s-lb-v6-reverse-key-address socket 3) (gr8s-lb-v6-index-key-backend-address member-key 3)
                               (gr8s-lb-v6-reverse-key-port socket) (gr8s-lb-v6-index-key-backend-port member-key)
                               (gr8s-lb-v6-address-address original 0) (ctx user-ip6 0)
                               (gr8s-lb-v6-address-address original 1) (ctx user-ip6 1)
                               (gr8s-lb-v6-address-address original 2) (ctx user-ip6 2)
                               (gr8s-lb-v6-address-address original 3) (ctx user-ip6 3)
                               (gr8s-lb-v6-address-port original) (cast u16 (ctx user-port)))
                         (map-update-ptr gr8s-reverse-v6 socket original 0)))
                     (setf (ctx user-ip6 0) (gr8s-lb-v6-index-key-backend-address member-key 0)
                           (ctx user-ip6 1) (gr8s-lb-v6-index-key-backend-address member-key 1)
                           (ctx user-ip6 2) (gr8s-lb-v6-index-key-backend-address member-key 2)
                           (ctx user-ip6 3) (gr8s-lb-v6-index-key-backend-address member-key 3)
                           (ctx user-port) (cast u32 (gr8s-lb-v6-index-key-backend-port member-key)))))))))))
     1))

;; The program forms: one 16-octet pair type the maps' keys and values share, the
;; connect4 and sendmsg4 steering programs, and the recvmsg4 program that shows a
;; UDP reply from a backend as coming from the Service address the client used.
(defparameter gr8s.network::*service-lb-program-forms*
  (list '(defstruct gr8s-lb-pair (first u64) (second u64))
        '(defstruct gr8s-egress-lpm-key (prefixlen u32) (address u32))
        '(defstruct gr8s-lb-v6-service-key
           (address (array u32 4)) (port u16) (protocol u8) (pad u8))
        '(defstruct gr8s-lb-v6-address
           (address (array u32 4)) (port u16) (pad u16))
        '(defstruct gr8s-lb-v6-affinity-key
           (address (array u32 4)) (port u16) (protocol u8) (pad0 u8)
           (pad1 u32) (cookie u64))
        '(defstruct gr8s-lb-v6-affinity-value
           (address (array u32 4)) (port u16) (pad0 u16) (pad1 u32) (seen u64))
        '(defstruct gr8s-lb-v6-index-key
           (vip-address (array u32 4)) (vip-port u16) (protocol u8) (pad0 u8)
           (backend-address (array u32 4)) (backend-port u16) (pad1 u16))
        '(defstruct gr8s-lb-v6-reverse-key
           (cookie u64) (address (array u32 4)) (port u16) (pad0 u16) (pad1 u32))
        (gr8s.network::service-lb-steer-program 'gr8s-service-lb "cgroup/connect4")
        (gr8s.network::service-lb-steer-program 'gr8s-service-lb-sendmsg "cgroup/sendmsg4")
        '(defprog gr8s-service-lb-recvmsg (:type :cgroup-sock-addr
                                           :section "cgroup/recvmsg4"
                                           :license "GPL")
          (let ((socket (make-gr8s-lb-pair)))
            (setf (gr8s-lb-pair-first socket) (get-socket-cookie (ctx-ptr))
                  (gr8s-lb-pair-second socket)
                  (logior (cast u64 (ctx user-ip4))
                          (<< (logand (cast u64 (ctx user-port)) #xffff) 32)))
            (when-let ((original (map-lookup-ptr gr8s-reverse-v4 socket)))
              (let ((address u64 (load u64 original 0)))
                (setf (ctx user-ip4) (cast u32 (logand address #xffffffff)))
                (setf (ctx user-port) (cast u32 (>> address 32))))))
          1)
        (gr8s.network::service-lb-v6-steer-program
         'gr8s-service-lb-v6 "cgroup/connect6")
        (gr8s.network::service-lb-v6-steer-program
         'gr8s-service-lb-sendmsg-v6 "cgroup/sendmsg6")
        '(defprog gr8s-service-lb-recvmsg-v6
             (:type :cgroup-sock-addr :section "cgroup/recvmsg6" :license "GPL")
          (let ((socket (make-gr8s-lb-v6-reverse-key)))
            (setf (gr8s-lb-v6-reverse-key-cookie socket) (get-socket-cookie (ctx-ptr))
                  (gr8s-lb-v6-reverse-key-address socket 0) (ctx user-ip6 0)
                  (gr8s-lb-v6-reverse-key-address socket 1) (ctx user-ip6 1)
                  (gr8s-lb-v6-reverse-key-address socket 2) (ctx user-ip6 2)
                  (gr8s-lb-v6-reverse-key-address socket 3) (ctx user-ip6 3)
                  (gr8s-lb-v6-reverse-key-port socket) (cast u16 (ctx user-port)))
            (when-let ((original (map-lookup-ptr gr8s-reverse-v6 socket)))
              (setf (ctx user-ip6 0) (load u32 original 0)
                    (ctx user-ip6 1) (load u32 original 4)
                    (ctx user-ip6 2) (load u32 original 8)
                    (ctx user-ip6 3) (load u32 original 12)
                    (ctx user-port) (cast u32 (load u16 original 16)))))
          1)))
