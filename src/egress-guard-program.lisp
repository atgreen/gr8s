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

;; Keys for the map-driven NetworkPolicy rules. The LPM-trie keys use the
;; kernel's {prefixlen, data} layout. An address is stored as the packet
;; carries it (network order); a port key holds the rule group, the IP
;; protocol, a zero pad byte and the port in network order, so a port range
;; is a set of prefixes. The flow key names a connection from the Pod's side:
;; the peer, the Pod's port, the peer's port and the protocol, so both
;; directions of one connection share it.
(defstruct netpol-lpm-key (prefixlen u32) (addr u32))
(defstruct netpol-port-key (prefixlen u32) (group u32) (proto u8) (pad u8) (port u16))
(defstruct netpol-flow-key (peer u32) (pod-port u16) (peer-port u16) (proto u8) (pad0 u8) (pad1 u16))
(defstruct netpol-flow-stamp (ns u64))
;; A key or value held in a variable is a pointer, so these use map-lookup-ptr and
;; map-update-ptr: plain map-lookup would key the map by the pointer's own bytes.

;; Is (ADDR, PROTO, PORT) allowed by the CIDR and port tries? HAS-PORT is 0 when
;; the packet carries no readable L4 ports, which then matches only rules that
;; allow every port of the protocol (or every protocol).
(defmacro netpol-allowed (cidr-map port-map addr proto port has-port)
  `(let ((verdict u32 0)
         (lkey (make-netpol-lpm-key)))
     (setf (netpol-lpm-key-prefixlen lkey) 32
           (netpol-lpm-key-addr lkey) ,addr)
     (let ((hit (map-lookup-ptr ,cidr-map lkey)))
       (when (/= hit 0)
         (let ((pkey (make-netpol-port-key)))
           (setf (netpol-port-key-prefixlen pkey) (if (= ,has-port 1) 64 40)
                 (netpol-port-key-group pkey) (load u32 hit 0)
                 (netpol-port-key-proto pkey) ,proto
                 (netpol-port-key-pad pkey) 0
                 (netpol-port-key-port pkey) (if (= ,has-port 1) ,port 0))
           (when (/= (map-lookup-ptr ,port-map pkey) 0)
             (setf verdict 1)))))
     verdict))

;; How long a connection's replies stay allowed after its last packet.
(defmacro netpol-flow-lifetime (proto)
  `(if (= ,proto 6) 7200000000000 180000000000))

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
    ;; NetworkPolicy, data the agent writes on policy change (no recompile):
    ;; [0] is 1 when the Pod is isolated for egress, [1] when isolated for ingress.
    (defmap netpol-mode :type :array
      :key-size 4 :value-size 4 :max-entries 2)
    ;; Peer CIDRs -> the rule group of the longest matching prefix (0 = nothing allowed).
    (defmap netpol-egress-cidr :type :lpm-trie
      :key-size 8 :value-size 4 :max-entries 16384 :map-flags 1) ; BPF_F_NO_PREALLOC
    ;; (group, protocol, port) prefixes each group allows.
    (defmap netpol-egress-ports :type :lpm-trie
      :key-size 12 :value-size 1 :max-entries 4096 :map-flags 1)
    (defmap netpol-ingress-cidr :type :lpm-trie
      :key-size 8 :value-size 4 :max-entries 16384 :map-flags 1)
    (defmap netpol-ingress-ports :type :lpm-trie
      :key-size 12 :value-size 1 :max-entries 4096 :map-flags 1)
    ;; Connections allowed in either direction -> when their last packet passed, so
    ;; that their replies pass the other direction's isolation.
    (defmap netpol-flows :type :lru-hash
      :key-size 12 :value-size 8 :max-entries 4096)))

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
            (egress-mode (map-lookup netpol-mode 0))
            (ingress-mode (map-lookup netpol-mode 1))
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
                   ;; NetworkPolicy (map-driven; the agent rewrites the maps on policy
                   ;; change). Egress isolation allows a packet that its rules allow, or
                   ;; that answers a connection the ingress guard admitted. Either
                   ;; isolation records the connection, so that its replies pass.
                   (let ((egress-on u32 (if (/= egress-mode 0) (load u32 egress-mode 0) 0))
                         (ingress-on u32 (if (/= ingress-mode 0) (load u32 ingress-mode 0) 0)))
                     (when (or (/= egress-on 0) (/= ingress-on 0))
                       ;; Copy every packet field into the stack key BEFORE any helper
                       ;; call: Whistler rematerializes a let-bound packet load at its
                       ;; uses, and a load after a helper call reads clobbered registers.
                       (let ((fkey (make-netpol-flow-key))
                             (has-port u8 0))
                         (setf (netpol-flow-key-peer fkey) (load u32 ip 16)
                               (netpol-flow-key-proto fkey) (load u8 ip 9))
                         (when (and (= (logand (load u8 ip 0) 15) 5) (<= (+ data 38) data-end))
                           (setf (netpol-flow-key-pod-port fkey) (load u16 ip 20)
                                 (netpol-flow-key-peer-port fkey) (load u16 ip 22)
                                 has-port 1))
                         (let ((now u64 (ktime-get-ns)))
                           (when (/= egress-on 0)
                             (when (= (netpol-allowed netpol-egress-cidr netpol-egress-ports
                                                      (netpol-flow-key-peer fkey) (netpol-flow-key-proto fkey)
                                                      (netpol-flow-key-peer-port fkey) has-port)
                                      0)
                               (let ((flow (map-lookup-ptr netpol-flows fkey)))
                                 (when (= flow 0) (drop-pod-packet :policy))
                                 (when (> (- now (load u64 flow 0)) (netpol-flow-lifetime (netpol-flow-key-proto fkey)))
                                   (drop-pod-packet :policy)))))
                           (let ((stamp (make-netpol-flow-stamp)))
                             (setf (netpol-flow-stamp-ns stamp) now)
                             (map-update-ptr netpol-flows fkey stamp 0))))))))
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
        TC_ACT_OK))
    ;; Pod ingress (host veth egress, or the Pod interface's ingress when chained):
    ;; the same rules for the packet's source and the Pod's destination port. Only
    ;; IPv4 is governed; the node gateway address, from which the node's probes,
    ;; DNS answers and proxies reach the Pod, always passes.
    (defprog gr8s-ingress-guard (:type :tc :section "classifier" :license "GPL")
      ;; Read the packet's fields into locals before any helper call or stack struct:
      ;; the calls clobber the registers holding the context and packet pointers.
      (let ((data u64 (tc-data))
            (data-end u64 (tc-data-end))
            (ipv4 u8 0)
            (peer u32 0)
            (proto u8 0)
            (sport u16 0)
            (dport u16 0)
            (has-port u8 0))
        (when (and (<= (+ data 34) data-end)
                   (= (eth-type data) #x0800)
                   (= (logand (load u8 data 14) #xf0) #x40))
          (setf ipv4 1
                peer (load u32 data 26)
                proto (load u8 data 23))
          (when (and (= (logand (load u8 data 14) 15) 5) (<= (+ data 38) data-end))
            (setf sport (load u16 data 34)
                  dport (load u16 data 36)
                  has-port 1)))
        (when (and (= ipv4 1) (/= (ntohl peer) #xa9fe0101))
          (let ((policy-drops (map-lookup traffic-stats 6))
                (egress-mode (map-lookup netpol-mode 0))
                (ingress-mode (map-lookup netpol-mode 1)))
            (let ((egress-on u32 (if (/= egress-mode 0) (load u32 egress-mode 0) 0))
                  (ingress-on u32 (if (/= ingress-mode 0) (load u32 ingress-mode 0) 0)))
              (when (or (/= egress-on 0) (/= ingress-on 0))
                (let ((now u64 (ktime-get-ns)))
                  ;; Whistler builds a stack struct's address in r1 whatever r1 holds,
                  ;; so the key is made just after a helper call, when r1 is free.
                  (let ((fkey (make-netpol-flow-key)))
                    (setf (netpol-flow-key-peer fkey) peer
                          (netpol-flow-key-pod-port fkey) dport
                          (netpol-flow-key-peer-port fkey) sport
                          (netpol-flow-key-proto fkey) proto)
                    (when (/= ingress-on 0)
                      (when (= (netpol-allowed netpol-ingress-cidr netpol-ingress-ports
                                               peer proto dport has-port)
                               0)
                        (let ((flow (map-lookup-ptr netpol-flows fkey)))
                          (when (= flow 0)
                            (add-pod-counter policy-drops 1)
                            (return TC_ACT_SHOT))
                          (when (> (- now (load u64 flow 0)) (netpol-flow-lifetime proto))
                            (add-pod-counter policy-drops 1)
                            (return TC_ACT_SHOT)))))
                    (let ((stamp (make-netpol-flow-stamp)))
                      (setf (netpol-flow-stamp-ns stamp) now)
                      (map-update-ptr netpol-flows fkey stamp 0))))))))
        TC_ACT_OK))))
