;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The Whistler source for the ClusterIP socket load balancer, held as data so
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
  (pushnew '("GET-NETNS-COOKIE" . 122) whistler/compiler:*builtin-helpers* :test #'equal))

;; Map definitions, as evaluatable (whistler:defmap ...) forms.
;;
;;   gr8s_service_v4   key u64  (protocol << 48) | (vip << 16) | htons(port)
;;                     value 16 count u16 @0, affinity u16 @2, base slot u32 @4,
;;                              affinity timeout seconds u32 @8, set epoch u32 @12
;;   gr8s_backend_v4   key u32  backend slot
;;                     value 8  addr u32 @0, port u16 @4 (both network byte order)
;;   gr8s_affinity_v4  key u64  service key mixed with the client's netns cookie
;;                     value u64 (seen seconds << 32) | (epoch16 << 16) | backend offset
;;
;; The service and backend maps are NO_PREALLOC hashes so memory tracks live
;; Services/backends; the LRU forgets clients that have long gone away.
(defparameter gr8s::*service-lb-map-forms*
  '((defmap gr8s-service-v4 :type :hash
      :key-size 8 :value-size 16 :max-entries 4096 :map-flags 1)
    (defmap gr8s-backend-v4 :type :hash
      :key-size 4 :value-size 8 :max-entries 65536 :map-flags 1)
    (defmap gr8s-affinity-v4 :type :lru-hash
      :key-size 8 :value-size 8 :max-entries 65536)))

;; The cgroup/connect4 program, as an evaluatable (whistler:defprog ...) form.
;; A connect(2) whose destination matches a Service VIP:port and protocol is
;; rewritten in place to a backend chosen uniformly at random, or for a ClientIP
;; affinity Service to the one this client last used while that is within the
;; timeout and the backend set is unchanged.  The client is its network namespace,
;; which owns the source address a packet-level proxy would key on; a kernel
;; socket hook runs before any source address is chosen.  A Service with no ready
;; backends keeps a zero count and is left untouched.  No DNAT, no conntrack: the
;; socket connects directly to the real backend, so the return path needs no
;; reverse translation.  Connected UDP takes this path too; unconnected sendto(2)
;; does not pass through connect4.
(defparameter gr8s::*service-lb-program-forms*
  '((defprog gr8s-service-lb (:type :cgroup-sock-addr
                              :section "cgroup/connect4"
                              :license "GPL")
      (let* ((vip u64 (cast u64 (ctx user-ip4)))
             (vport u64 (logand (cast u64 (ctx user-port)) #xffff))
             (proto u64 (logand (cast u64 (ctx protocol)) #xff))
             (key u64 (logior (<< proto 48) (logior (<< vip 16) vport))))
        (when-let ((service u64 (map-lookup gr8s-service-v4 key)))
          (let ((count u32 (cast u32 (load u16 service 0))))
            (when (> count 0)
              (let ((offset u32 (mod (get-prandom-u32) count)))
                (when (> (load u16 service 2) 0)
                  (let* ((epoch u64 (logand (load u32 service 12) #xffff))
                         (timeout u64 (load u32 service 8))
                         (now u64 (/ (ktime-get-ns) 1000000000))
                         (client u64 (logxor key (* (get-netns-cookie (ctx-ptr)) #x1E3779B1))))
                    (when-let ((cached u64 (map-lookup gr8s-affinity-v4 client)))
                      (let ((entry u64 (load u64 cached 0)))
                        (when (and (= (logand (>> entry 16) #xffff) epoch)
                                   (<= (- now (>> entry 32)) timeout))
                          (setf offset (mod (cast u32 (logand entry #xffff)) count)))))
                    (setf (getmap gr8s-affinity-v4 client)
                          (logior (<< now 32) (logior (<< epoch 16) (cast u64 offset))))))
                (let ((slot u32 (+ (load u32 service 4) offset)))
                  (when-let ((backend u64 (map-lookup gr8s-backend-v4 slot)))
                    (setf (ctx user-ip4) (load u32 backend 0))
                    (setf (ctx user-port) (cast u32 (load u16 backend 4))))))))))
      1)))
