;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
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
        (:unsupported '(add-pod-counter unsupported 1))
        (:policy '(add-pod-counter policy-drops 1)))
     (return TC_ACT_SHOT)))

;; Keys for the map-driven NetworkPolicy egress rules. The LPM-trie key is the
;; kernel's {prefixlen, data} layout for IPv4 (addr stored in network order);
;; the port key ties an allowed (proto, port) to the CIDR's rule group.
(defstruct netpol-lpm-key (prefixlen u32) (addr u32))
(defstruct netpol-port-key (group u32) (proto u8) (pad u8) (port u16))
;; Key for the same-node Pod delivery table: an LPM /32, same {prefixlen, addr}
;; shape as netpol-lpm-key (which the program resolves identically and works).
(defstruct local-pod-key (prefixlen u32) (addr u32))

(defparameter gr8s::*egress-guard-map-forms*
  '((defmap rejected-spoofs :type :array
      :key-size 4 :value-size 8 :max-entries 1)
    ;; Agent-initialized identity: IPv4, MAC high 32 bits, MAC low 16 bits (u32),
    ;; schema version. A zero-initialized/unconfigured endpoint fails closed.
    (defmap endpoint-identity :type :array
      :key-size 4 :value-size 16 :max-entries 1 :map-flags 128) ; RDONLY_PROG
    ;; Allowed packets/bytes, dropped packets/bytes, malformed, unsupported, policy.
    (defmap traffic-stats :type :array
      :key-size 4 :value-size 8 :max-entries 7)
    ;; NetworkPolicy egress (data-only, updated by the agent on policy change):
    ;; mode 0 = Pod not egress-isolated (policy not enforced); 1 = default-deny.
    (defmap netpol-egress-mode :type :array
      :key-size 4 :value-size 4 :max-entries 1)
    ;; Allowed destination CIDRs -> rule-group id (#xffffffff = all ports).
    (defmap netpol-egress-cidr :type :lpm-trie
      :key-size 8 :value-size 4 :max-entries 1024 :map-flags 1) ; BPF_F_NO_PREALLOC
    ;; Allowed (group, proto, port) tuples for port-restricted rules.
    (defmap netpol-egress-port :type :hash
      :key-size 8 :value-size 1 :max-entries 1024)
    ;; Same-node Pod delivery table (agent-populated): destination Pod IPv4
    ;; (network order) -> 16-byte value {dest host-veth ifindex (u32, host order),
    ;; dest Pod MAC (6 bytes, wire order), dest host-veth MAC (6 bytes, wire order)}.
    ;; A hit means the destination Pod lives on this node, so the packet can be
    ;; delivered straight to its veth, bypassing the kernel forward path.
    (defmap local-pod-v4 :type :lpm-trie
      :key-size 8 :value-size 16 :max-entries 4096 :map-flags 1))) ; /32 keys, like netpol-egress-cidr

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
            (policy-drops (map-lookup traffic-stats 6))
            (spoofs (map-lookup rejected-spoofs 0))
            (identity (map-lookup endpoint-identity 0))
            (mode (map-lookup netpol-egress-mode 0))
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
                       (return (redirect 1 1))))                   ; lo = ifindex 1, BPF_F_INGRESS
                   ;; NetworkPolicy egress (map-driven; agent updates the maps on
                   ;; policy change, no recompile). When the Pod is egress-isolated
                   ;; (mode=1): the destination must match an allowed CIDR, and for
                   ;; port-restricted rules the (group, proto, dport) must be listed.
                   (when (/= mode 0)
                     (when (/= (load u32 mode 0) 0)
                       ;; Read every packet field BEFORE any map lookup:
                       ;; bpf_map_lookup_elem resets the verifier's proven packet
                       ;; range, so a packet deref after a lookup is rejected.
                       (let ((dst u32 (load u32 ip 16))
                             (proto u8 (load u8 ip 9))
                             (ihl u8 (logand (load u8 ip 0) 15))
                             (dport u16 0)
                             (has-port u8 0))
                         (when (and (= ihl 5) (<= (+ data 38) data-end))
                           (setf dport (ntohs (load u16 ip 22)) has-port 1))
                         (let ((lkey (make-netpol-lpm-key)))
                           (setf (netpol-lpm-key-prefixlen lkey) 32
                                 (netpol-lpm-key-addr lkey) dst)
                           ;; lkey is a variable (fields setf'd), so pass it with
                           ;; the -ptr helper; a bare map-lookup would key off the
                           ;; pointer value, not {prefixlen,addr}. See local-pod-v4.
                           (let ((hit (map-lookup-ptr netpol-egress-cidr lkey)))
                             (if (/= hit 0)
                                 (let ((grp u32 (load u32 hit 0)))
                                   (when (/= grp #xffffffff)
                                     (if (= has-port 1)
                                         (let ((pkey (make-netpol-port-key)))
                                           (setf (netpol-port-key-group pkey) grp
                                                 (netpol-port-key-proto pkey) proto
                                                 (netpol-port-key-pad pkey) 0
                                                 (netpol-port-key-port pkey) dport)
                                           (when (= (map-lookup-ptr netpol-egress-port pkey) 0)
                                             (drop-pod-packet :policy)))
                                         (drop-pod-packet :policy))))
                                 (drop-pod-packet :policy))))))
                   ;; Same-node Pod->Pod fast path. Policy has allowed the packet
                   ;; above; if the destination is a Pod on this node, deliver it
                   ;; straight to that Pod's veth via bpf_redirect, bypassing the
                   ;; kernel forward path and the host firewall's FORWARD reject.
                   ;; A map lookup resets the verifier's proven packet range, so
                   ;; re-prove the L2 bounds before rewriting the MAC header.
                   (when (> (+ data 34) data-end) (drop-pod-packet :malformed))
                   (let ((lpk (make-local-pod-key)))
                     (setf (local-pod-key-prefixlen lpk) 32
                           (local-pod-key-addr lpk) (load u32 ip 16))
                     ;; lpk is a variable (we setf its fields), so the key expr
                     ;; is not a literal make- form -- lower-map-lookup can't see
                     ;; it is a struct pointer and would spill the POINTER value
                     ;; as the key. Use map-lookup-ptr so R2 = &lpk (its contents).
                     (let ((ep (map-lookup-ptr local-pod-v4 lpk)))
                       (when (/= ep 0)
                         (when (> (+ data 14) data-end) (drop-pod-packet :malformed))
                         (store u32 data 0 (load u32 ep 4))    ; dst MAC [0:4] = Pod MAC
                         (store u16 data 4 (load u16 ep 8))    ; dst MAC [4:6]
                         (store u32 data 6 (load u32 ep 10))   ; src MAC [0:4] = veth MAC
                         (store u16 data 10 (load u16 ep 14))  ; src MAC [4:6]
                         (add-pod-counter allowed-packets 1)
                         (add-pod-counter allowed-bytes (ctx u32 0))
                         (return (redirect (load u32 ep 0) 0))))))))
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
