(in-package #:whistler)

(defmap rejected-spoofs :type :array
  :key-size 4 :value-size 8 :max-entries 1)

;; Agent-initialized identity: IPv4, MAC high 32 bits, MAC low 16 bits (u32),
;; schema version. A zero-initialized/unconfigured endpoint fails closed.
(defmap endpoint-identity :type :array
  :key-size 4 :value-size 16 :max-entries 1 :map-flags 128) ; RDONLY_PROG

;; Allowed packets/bytes, dropped packets/bytes, malformed, unsupported.
(defmap traffic-stats :type :array
  :key-size 4 :value-size 8 :max-entries 6)

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

(defprog gr8s-egress-guard (:type :tc :section "classifier" :license "GPL")
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
                 (drop-pod-packet :spoof))))
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
