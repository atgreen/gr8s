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
;; A backend value doubles as the backend's identity: the index finds where a backend
;; sits now, so affinity follows the backend rather than a slot that a change shifts.
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
      :key-size 16 :value-size 8 :max-entries 65536)))

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
replies as coming from the address the client sent to."
  `(defprog ,name (:type :cgroup-sock-addr :section ,section :license "GPL")
     (let* ((vip u64 (cast u64 (ctx user-ip4)))
            (vport u64 (logand (cast u64 (ctx user-port)) #xffff))
            (proto u64 (logand (cast u64 (ctx protocol)) #xff))
            (key u64 (logior (<< proto 48) (logior (<< vip 16) vport))))
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
                     (setf (ctx user-ip4) (load u32 backend 0))
                     (setf (ctx user-port) (cast u32 (load u16 backend 4)))))))))))
     1))

;; The program forms: one 16-octet pair type the maps' keys and values share, the
;; connect4 and sendmsg4 steering programs, and the recvmsg4 program that shows a
;; UDP reply from a backend as coming from the Service address the client used.
(defparameter gr8s.network::*service-lb-program-forms*
  (list '(defstruct gr8s-lb-pair (first u64) (second u64))
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
          1)))
