;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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

;; Map definitions, as evaluatable (whistler:defmap ...) forms.
;;
;;   gr8s_service_v4  key u64  (vip << 16) | htons(port)
;;                    value 8  count u16 @0, base slot u32 @4
;;   gr8s_backend_v4  key u32  backend slot
;;                    value 8  addr u32 @0, port u16 @4 (both network byte order)
;;
;; Both are NO_PREALLOC hashes so memory tracks live Services/backends.
(defparameter gr8s::*service-lb-map-forms*
  '((defmap gr8s-service-v4 :type :hash
      :key-size 8 :value-size 8 :max-entries 4096 :map-flags 1)
    (defmap gr8s-backend-v4 :type :hash
      :key-size 4 :value-size 8 :max-entries 65536 :map-flags 1)))

;; The cgroup/connect4 program, as an evaluatable (whistler:defprog ...) form.
;; A connect(2) whose destination matches a Service VIP:port is rewritten in
;; place to a backend chosen uniformly at random; a Service with no ready
;; backends keeps a zero count and is left untouched.  No DNAT, no conntrack:
;; the socket connects directly to the real backend, so the return path needs
;; no reverse translation.
(defparameter gr8s::*service-lb-program-forms*
  '((defprog gr8s-service-lb (:type :cgroup-sock-addr
                              :section "cgroup/connect4"
                              :license "GPL")
      (let* ((vip u64 (cast u64 (ctx user-ip4)))
             (vport u64 (logand (cast u64 (ctx user-port)) #xffff))
             (key u64 (logior (<< vip 16) vport)))
        (when-let ((service u64 (map-lookup gr8s-service-v4 key)))
          (let ((count u32 (cast u32 (load u16 service 0))))
            (when (> count 0)
              (let ((slot u32 (+ (load u32 service 4)
                                 (mod (get-prandom-u32) count))))
                (when-let ((backend u64 (map-lookup gr8s-backend-v4 slot)))
                  (setf (ctx user-ip4) (load u32 backend 0))
                  (setf (ctx user-port) (cast u32 (load u16 backend 4)))))))))
      1)))
