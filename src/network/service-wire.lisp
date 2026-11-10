;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Experimental Service identity transport for podster-p9c.14. Standalone
;;;; codec only: no attached program or CNI/agent profile uses this yet.
;;;; Geneve keeps the complete inner packet, including IPv4 options. A critical
;;;; experimental option carries the frontend and both full endpoint epochs.
(in-package #:whistler)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (pushnew '("SKB-ADJUST-ROOM" . 50) whistler/compiler:*builtin-helpers* :test #'equal))

(defmacro wire-metadata-valid-p (metadata)
  `(and (= (load u32 ,metadata 0) (htonl #x47523853)) ; GR8S
        (= (load u8 ,metadata 4) 1)
        (or (= (load u8 ,metadata 5) 1) (= (load u8 ,metadata 5) 2))
        (= (load u16 ,metadata 6) (htons 48))
        (/= (load u32 ,metadata 8) 0) (/= (load u16 ,metadata 12) 0)
        (or (= (load u8 ,metadata 14) 6) (= (load u8 ,metadata 14) 17))
        (= (load u8 ,metadata 15) 0)
        (/= (logior (load u64 ,metadata 16) (load u64 ,metadata 24)) 0)
        (/= (logior (load u64 ,metadata 32) (load u64 ,metadata 40)) 0)))

(defmacro wire-ip-sum (address)
  `(let ((wire-sum u32 (+ ,@(loop for offset below 20 by 2
                                collect `(cast u32 (load u16 ,address ,offset))))))
     (setf wire-sum (+ (logand wire-sum #xffff) (>> wire-sum 16)))
     (+ (logand wire-sum #xffff) (>> wire-sum 16))))

(defmacro wire-metadata-equal-p (first second)
  `(and ,@(loop for offset below 48 by 8
                collect `(= (load u64 ,first ,offset) (load u64 ,second ,offset)))))

(defmacro wire-check-inner (base end length)
  `(progn
     (when (> (+ ,base 34) ,end) (return TC_ACT_SHOT))
     (unless (and (= (eth-type ,base) #x0800)
                  (= (>> (load u8 ,base 14) 4) 4)
                  (>= (logand (load u8 ,base 14) 15) 5)
                  (or (= (load u8 ,base 23) 6) (= (load u8 ,base 23) 17))
                  (= (logand (ntohs (load u16 ,base 20)) #x3fff) 0))
       (return TC_ACT_SHOT))
     (let ((wire-ihl u32 (* (logand (load u8 ,base 14) 15) 4))
           (wire-total u32 (ntohs (load u16 ,base 16))))
       (when (or (> (+ ,base 14 wire-ihl) ,end)
                 (< wire-total (+ wire-ihl (if (= (load u8 ,base 23) 6) 20 8)))
                 (> (+ wire-total 14) ,length))
         (return TC_ACT_SHOT)))))

(defmacro wire-encapsulate (metadata)
  "Add102 bytes; caller authorizes and owns METADATA before invoking this macro.
Epochs are opaque16-byte strings, copied exactly from the canonical map ABI.
No state update or endpoint authority is supplied by this codec."
  `(let ((wire-data u64 (tc-data)) (wire-end u64 (tc-data-end))
         (wire-size u32 (ctx u32 0)) (wire-header (make-wire-prefix)))
     (unless (wire-metadata-valid-p ,metadata) (return TC_ACT_SHOT))
     (wire-check-inner wire-data wire-end wire-size)
     (when (> wire-size 65447) (return TC_ACT_SHOT))
     (when (/= (load u8 wire-data 23) (load u8 ,metadata 14)) (return TC_ACT_SHOT))
     (store u8 wire-header 0 #x45)
     (store u8 wire-header 1 (load u8 wire-data 15))
     (store u16 wire-header 2 (htons (+ wire-size 88)))
     (store u16 wire-header 6 (htons #x4000))
     (store u8 wire-header 8 64) (store u8 wire-header 9 17)
     (store u32 wire-header 12 (load u32 wire-data 26))
     (store u32 wire-header 16 (load u32 wire-data 30))
     (store u16 wire-header 10 (cast u16 (logxor (wire-ip-sum wire-header) #xffff)))
     ;; A deterministic nonzero UDP source port is enough for this transport;
     ;; neither classification nor endpoint identity relies on it.
     (store u16 wire-header 20 (htons 49152))
     (store u16 wire-header 22 (htons 6081))
     (store u16 wire-header 24 (htons (+ wire-size 68)))
     ;; UDP checksum zero is valid for this IPv4-only experimental envelope.
     (store u8 wire-header 28 13) (store u8 wire-header 29 #x40)
     (store u16 wire-header 30 (htons #x6558))
     (store u8 wire-header 32 #x67) (store u8 wire-header 33 #x72)
     (store u8 wire-header 34 #x38)
     (store u16 wire-header 36 (htons #xfffe))
     (store u8 wire-header 38 #x80) (store u8 wire-header 39 12)
     ,@(loop for offset below 48 by 8
             collect `(store u64 wire-header ,(+ 40 offset) (load u64 ,metadata ,offset)))
     (when (/= (skb-load-bytes (ctx-ptr) 0 (+ wire-header 88) 14) 0) (return TC_ACT_SHOT))
     ;; ENCAP_L2(14), L2_ETH, L3_IPV4, L4_UDP, FIXED_GSO. Packet pointers
     ;; become invalid; only the stack prefix is used after this helper.
     (when (/= (skb-adjust-room (ctx-ptr) 102 1 #x0e00000000000053) 0)
       (return TC_ACT_SHOT))
     (when (/= (skb-store-bytes (ctx-ptr) 14 wire-header 102 0) 0) (return TC_ACT_SHOT))))

(defmacro wire-check-envelope (&optional (addresses t))
  "Validate framing only. Callers must separately validate all identity/flow
ownership before accepting metadata or changing any NAT/policy state."
  `(let ((wire-data u64 (tc-data)) (wire-end u64 (tc-data-end))
         (wire-size u32 (ctx u32 0)))
     (when (> (+ wire-data 136) wire-end) (return TC_ACT_SHOT))
     (unless (and (= (eth-type wire-data) #x0800)
                  (= (load u8 wire-data 14) #x45) (> (load u8 wire-data 22) 0)
                  (= (load u8 wire-data 23) 17)
                  (= (logand (ntohs (load u16 wire-data 20)) #xbfff) 0)
                  (= (+ (ntohs (load u16 wire-data 16)) 14) wire-size)
                  (= (wire-ip-sum (+ wire-data 14)) #xffff)
                  (/= (load u16 wire-data 34) 0)
                  (= (load u16 wire-data 36) (htons 6081))
                  (= (+ (ntohs (load u16 wire-data 38)) 34) wire-size)
                  (= (load u16 wire-data 40) 0)
                  (= (load u8 wire-data 42) 13) (= (load u8 wire-data 43) #x40)
                  (= (load u16 wire-data 44) (htons #x6558))
                  (= (load u32 wire-data 46) (htonl #x67723800))
                  (= (load u16 wire-data 50) (htons #xfffe))
                  (= (load u8 wire-data 52) #x80) (= (load u8 wire-data 53) 12)
                  (wire-metadata-valid-p (+ wire-data 54)))
       (return TC_ACT_SHOT))
     (wire-check-inner (+ wire-data 102) wire-end (- wire-size 102))
     (unless (and (= (load u8 wire-data 125) (load u8 wire-data 68))
                  ,@(when addresses
                      '((= (load u32 wire-data 26) (load u32 wire-data 128))
                        (= (load u32 wire-data 30) (load u32 wire-data 132)))))
       (return TC_ACT_SHOT))))

(defmacro wire-decapsulate ()
  "Remove an authorized envelope. Keep current outer Ethernet addresses: routing
has already selected the receiver's link, and the saved inner MACs may be stale."
  `(progn
     (wire-check-envelope)
     (wire-strip-authorized)))

(defmacro wire-strip-authorized ()
  "Strip only after framing, identities and flow ownership have been checked.
Used after authorized NAT changes make inner and outer addresses differ."
  `(progn
     (let ((wire-data u64 (tc-data)))
       (when (> (+ wire-data 128) (tc-data-end)) (return TC_ACT_SHOT))
       ;; RFC6040: CE is propagated only to an ECN-capable inner packet.
       (when (= (logand (load u8 wire-data 15) 3) 3)
         (when (= (logand (load u8 wire-data 117) 3) 0) (return TC_ACT_SHOT))
         (let ((wire-old u16 (load u16 wire-data 116))
               (wire-new u16 (logior (load u16 wire-data 116) #x0300)))
           (when (/= (l3-csum-replace (ctx-ptr) 126 wire-old wire-new 2) 0)
             (return TC_ACT_SHOT))
           ;; Reload and bound the packet after the checksum helper. No extra
           ;; stack byte (or live pointer to it) is needed just to set CE.
           (let ((wire-fresh u64 (tc-data)))
             (when (> (+ wire-fresh 118) (tc-data-end)) (return TC_ACT_SHOT))
             (store u8 wire-fresh 117 (logior (load u8 wire-fresh 117) 3))))))
     (when (/= (skb-adjust-room (ctx-ptr) -102 1 1) 0) (return TC_ACT_SHOT))))

(in-package #:gr8s.network)

(defun service-wire-struct-forms ()
  '((whistler::defstruct whistler::wire-prefix (whistler::words (array whistler::u64 13)))
    (whistler::defstruct whistler::wire-byte (whistler::value whistler::u8))))

(defun compile-service-wire-codec ()
  "Compile a codec fixture. Its read-only metadata map stands in for a future
authorized state owner; these programs must never be attached as endpoint guards."
  (compile-whistler-program
   '((whistler::defmap whistler::gr8s-wire-fixture :type :array
       :key-size 4 :value-size 48 :max-entries 1 :map-flags 128))
   (append
    (service-wire-struct-forms)
    '((whistler::defprog whistler::gr8s-wire-wrap (:type :tc :section "classifier" :license "GPL")
        (let ((whistler::metadata (whistler::map-lookup whistler::gr8s-wire-fixture 0)))
          (when (= whistler::metadata 0) (return whistler::TC_ACT_SHOT))
          (whistler::wire-encapsulate whistler::metadata)
          whistler::TC_ACT_OK))
      (whistler::defprog whistler::gr8s-wire-unwrap (:type :tc :section "classifier" :license "GPL")
        (whistler::wire-check-envelope)
        (let ((whistler::data (whistler::tc-data))
              (whistler::metadata (whistler::map-lookup whistler::gr8s-wire-fixture 0)))
          (when (= whistler::metadata 0) (return whistler::TC_ACT_SHOT))
          (when (> (+ whistler::data 102) (whistler::tc-data-end)) (return whistler::TC_ACT_SHOT))
          (unless (whistler::wire-metadata-equal-p whistler::metadata (+ whistler::data 54))
            (return whistler::TC_ACT_SHOT)))
        (whistler::wire-decapsulate)
        whistler::TC_ACT_OK)))))
