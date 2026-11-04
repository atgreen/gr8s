;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The Whistler source for the per-endpoint egress guard, held as data so the
;;;; agent can JIT-compile it in-process (like the socket LB) instead of loading
;;;; an embedded ELF object.  This is the single in-image source of the program;
;;;; the legacy standalone network/gr8s-egress-guard.lisp remains only until the
;;;; CNI load path and the fixture test are converted off the ELF (podster-7q2.5b
;;;; / .5c).  A drift-guard test asserts the two compile to identical bytecode.
;;;;
;;;; This file is read with *package* bound to WHISTLER, so every symbol in the
;;;; forms below (defmap, defprog, map-lookup, tc-data, ntohl, ...) and the two
;;;; helper macros intern in the WHISTLER package, exactly as the standalone
;;;; program does.  The gr8s-visible form bindings live under the GR8S package.

(in-package #:whistler)

;; Helper macros used by the program body.  They must be defined before the
;; program form is compiled (compile-bpf-forms macroexpands the body), so they
;; live here alongside the forms rather than inside the quoted data.
(defmacro add-pod-counter (pointer delta)
  `(when (/= ,pointer 0) (atomic-add ,pointer 0 ,delta)))

(defmacro drop-pod-packet (reason)
  `(progn
     (add-pod-counter dropped-packets 1)
     (add-pod-counter dropped-bytes (ctx u32 0))
     ,(ecase reason
        (:spoof '(add-pod-counter spoofs 1))
        (:malformed '(add-pod-counter malformed 1))
        (:unsupported '(add-pod-counter unsupported 1)))
     (return TC_ACT_SHOT)))

(defparameter gr8s::*egress-guard-map-forms*
  '((defmap rejected-spoofs :type :array
      :key-size 4 :value-size 8 :max-entries 1)
    ;; Agent-initialized identity: IPv4, MAC high 32 bits, MAC low 16 bits (u32),
    ;; schema version. A zero-initialized/unconfigured endpoint fails closed.
    (defmap endpoint-identity :type :array
      :key-size 4 :value-size 16 :max-entries 1 :map-flags 128) ; RDONLY_PROG
    ;; Allowed packets/bytes, dropped packets/bytes, malformed, unsupported.
    (defmap traffic-stats :type :array
      :key-size 4 :value-size 8 :max-entries 6)))

(defparameter gr8s::*egress-guard-program-forms*
  '((defprog gr8s-egress-guard (:type :tc :section "classifier" :license "GPL")
      ;; Look up every counter before branching. This also ensures Whistler's
      ;; cached constant map-key stack slots dominate every use on every path.
      (let ((allowed-packets (map-lookup traffic-stats 0))
            (allowed-bytes (map-lookup traffic-stats 1))
            (dropped-packets (map-lookup traffic-stats 2))
            (dropped-bytes (map-lookup traffic-stats 3))
            (malformed (map-lookup traffic-stats 4))
            (unsupported (map-lookup traffic-stats 5))
            (spoofs (map-lookup rejected-spoofs 0))
            (identity (map-lookup endpoint-identity 0))
            (data u64 (tc-data)) (data-end u64 (tc-data-end)))
        (when (> (+ data 14) data-end) (drop-pod-packet :malformed))
        ;; Keep all helpers before packet bounds proofs. Whistler may otherwise
        ;; rematerialize tc-data across a lookup and lose the verifier range.
        (if (/= identity 0)
          (progn
            (when (/= (load u32 identity 12) 1) (drop-pod-packet :spoof))
            (when (or (/= (ntohl (load u32 data 6)) (load u32 identity 4))
                      (/= (ntohs (load u16 data 10)) (load u32 identity 8)))
              (drop-pod-packet :spoof))
            (let ((protocol u16 (eth-type data)))
              (cond
                ((= protocol #x0800)
                 (when (> (+ data 34) data-end) (drop-pod-packet :malformed))
                 (let ((ip u64 (+ data 14)))
                   (when (or (/= (logand (load u8 ip 0) #xf0) #x40)
                             (< (logand (load u8 ip 0) 15) 5)
                             (< (ntohs (load u16 ip 2))
                                (* (logand (load u8 ip 0) 15) 4))
                             (> (+ 14 (ntohs (load u16 ip 2))) (ctx u32 0)))
                     (drop-pod-packet :malformed))
                   (when (/= (ntohl (ipv4-src-addr ip)) (load u32 identity 0))
                     (drop-pod-packet :spoof))
                   ;; DNS to the node gateway (169.254.1.1:53, UDP or TCP):
                   ;; redirect the query to the loopback ingress so it is
                   ;; delivered with iif=lo, which the host firewall trusts,
                   ;; instead of crossing the (possibly default-deny) INPUT path
                   ;; on port 53. Zeroing the destination MAC first makes lo's
                   ;; eth_type_trans classify the reinjected frame as PACKET_HOST,
                   ;; not PACKET_OTHERHOST (which drops it before INPUT). The node
                   ;; DNS server answers on 169.254.1.1:53; its reply is host-
                   ;; originated (OUTPUT) and routes back to the Pod normally.
                   ;; TCP and UDP carry the destination port at the same L4 offset
                   ;; (bytes 2-3), so one dport test covers both; for TCP every
                   ;; inbound segment of the flow is redirected the same way.
                   (let ((l4-proto u8 (load u8 ip 9)))
                     (when (and (or (= l4-proto 17) (= l4-proto 6)) ; UDP or TCP
                                (= (logand (load u8 ip 0) 15) 5)   ; no IP options (ihl = 5)
                                (= (ntohl (load u32 ip 16)) #xa9fe0101) ; dst = 169.254.1.1
                                (<= (+ data 42) data-end)          ; L4 ports in bounds
                                (= (ntohs (load u16 ip 22)) 53))   ; dport = 53
                       (add-pod-counter allowed-packets 1)
                       (add-pod-counter allowed-bytes (ctx u32 0))
                       (store u32 data 0 0)                        ; zero dst MAC bytes 0-3
                       (store u16 data 4 0)                        ; zero dst MAC bytes 4-5
                       (return (redirect 1 1))))))               ; lo = ifindex 1, BPF_F_INGRESS
                ((= protocol #x0806)
                 (when (> (+ data 42) data-end) (drop-pod-packet :malformed))
                 (let ((arp u64 (+ data 14)))
                   (when (or (/= (ntohs (load u16 arp 0)) 1)
                             (/= (ntohs (load u16 arp 2)) #x0800)
                             (/= (load u8 arp 4) 6) (/= (load u8 arp 5) 4)
                             (and (/= (ntohs (load u16 arp 6)) 1)
                                  (/= (ntohs (load u16 arp 6)) 2)))
                     (drop-pod-packet :malformed))
                   (when (or (/= (ntohl (load u32 arp 14)) (load u32 identity 0))
                             (/= (ntohl (load u32 arp 8)) (load u32 identity 4))
                             (/= (ntohs (load u16 arp 12)) (load u32 identity 8)))
                     (drop-pod-packet :spoof))))
                (t (drop-pod-packet :unsupported)))))
          (drop-pod-packet :spoof))
        (add-pod-counter allowed-packets 1)
        (add-pod-counter allowed-bytes (ctx u32 0))
        TC_ACT_OK))))
