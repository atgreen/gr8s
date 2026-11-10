;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Packet Service translation for clients whose sockets live in another kernel.
;;;; Service/backend/membership maps have exactly the socket LB's schema. Flow
;;;; state is node-wide: a backend stays selected for an established flow even
;;;; while EndpointSlices change. The reverse path validates the forward entry
;;;; before using a reverse entry, so interrupted two-map publication fails closed.

(in-package #:whistler)

(defvar gr8s.network::*service-wire-locks-p* nil)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (dolist (helper '(("SKB-STORE-BYTES" . 9) ("L3-CSUM-REPLACE" . 10)
                    ("L4-CSUM-REPLACE" . 11)))
    (pushnew helper whistler/compiler:*builtin-helpers* :test #'equal)))

(defparameter gr8s.network::*service-packet-extra-map-forms*
  '((defmap gr8s-pkt-fwd-lock :type :hash
      :key-size 16 :value-size 8 :max-entries 65536 :map-flags 1)
    (defmap gr8s-pkt-rev-lock :type :hash
      :key-size 16 :value-size 8 :max-entries 65536 :map-flags 1)
    (defmap gr8s-pkt-forward :type :hash
      :key-size 16 :value-size 16 :max-entries 65536 :map-flags 1)
    (defmap gr8s-pkt-reverse :type :hash
      :key-size 16 :value-size 16 :max-entries 65536 :map-flags 1)
    (defmap gr8s-pkt-affinity :type :lru-hash
      :key-size 16 :value-size 16 :max-entries 65536)
    (defmap gr8s-pkt-tcp :type :hash
      :key-size 16 :value-size 64 :max-entries 65536 :map-flags 1)
    ;; Requests, replies, no endpoints, invalid membership, tuple collision,
    ;; failed publication/protocol validation/checksum/header writes, malformed packets.
    (defmap gr8s-pkt-stats :type :array
      :key-size 4 :value-size 8 :max-entries 7)))

(defparameter gr8s.network::*service-packet-struct-forms*
  '((defstruct gr8s-pkt-pair (first u64) (second u64))
    (defstruct gr8s-pkt-flow
      (source u32) (destination u32) (sport u16) (dport u16)
      (protocol u8) (pad0 u8) (pad1 u16))
    (defstruct gr8s-pkt-meta
      (l4 u32) (seq u32) (ack u32) (end u32) (flags u16) (window u16) (timestamp u32) (echo u32))
    (defstruct gr8s-pkt-tcp-input (seq u32) (ack u32) (header u64))
    ;; SYN/client=1, SYN/server=2, established=4, FIN/client=8, FIN/server=16,
    ;; FIN ACK/client=32, FIN ACK/server=64, reset=128, closed=256, legacy=512.
    ;; TS/client=1024, TS/server=2048, WS/client=4096, WS/server=8192.
    ;; TS-floor valid/client=16384, valid/server=32768. Minute ages use reserved
    ;; option bytes; all previously used field offsets and the 64-byte map stay fixed.
    ;; Packet flags pack TS-present=256, WS-present=512, WS shift in bits12..15.
    (defstruct gr8s-pkt-tcp-state
      (backend u64) (client-isn u32) (server-isn u32)
      (client-end u32) (server-end u32) (client-ack u32) (server-ack u32)
      (client-window u32) (server-window u32) (client-fin u32) (server-fin u32)
      (flags u16) (client-ts-age u16) (server-ts-age u16)
      (client-scale u8) (server-scale u8) (client-ts u32) (server-ts u32))))

(defmacro pkt-count (pointer)
  `(when (/= ,pointer 0) (atomic-add ,pointer 0 1)))

(defmacro pkt-unlock ()
  ;; Try-locks are transient map reservations, never persistent flow state.
  ;; Always release both on every success/drop path; no packet waits on a lock.
  `(progn
     ,@(when gr8s.network::*service-wire-locks-p*
         '((when (/= wire-held 0)
             (map-delete-ptr gr8s-nat-wl-v2 wire-locked)
             (setf wire-held 0))))
     (when (/= (logand held-locks 2) 0)
       (map-delete-ptr gr8s-pkt-rev-lock locked-reverse))
     (when (/= (logand held-locks 1) 0)
       (map-delete-ptr gr8s-pkt-fwd-lock locked-forward))
     (setf held-locks 0)))

(defmacro pkt-drop (counter)
  `(progn (pkt-count ,counter) (pkt-unlock) (return TC_ACT_SHOT)))

(defmacro pkt-lock (direction key)
  "Reserve a tuple without waiting. All flow readers/writers follow this protocol.
A forward packet takes its forward key then its reverse key; a reply takes the
reverse key then the forward key. Contention drops/releases rather than waiting,
so opposite acquisition orders cannot deadlock."
  (let ((map (ecase direction (:forward 'gr8s-pkt-fwd-lock) (:reverse 'gr8s-pkt-rev-lock)))
        (copy (ecase direction (:forward 'locked-forward) (:reverse 'locked-reverse)))
        (bit (ecase direction (:forward 1) (:reverse 2))))
    `(progn
       (setf (gr8s-pkt-flow-source ,copy) (gr8s-pkt-flow-source ,key)
             (gr8s-pkt-flow-destination ,copy) (gr8s-pkt-flow-destination ,key)
             (gr8s-pkt-flow-sport ,copy) (gr8s-pkt-flow-sport ,key)
             (gr8s-pkt-flow-dport ,copy) (gr8s-pkt-flow-dport ,key)
             (gr8s-pkt-flow-protocol ,copy) (gr8s-pkt-flow-protocol ,key)
             (gr8s-pkt-flow-pad0 ,copy) 0 (gr8s-pkt-flow-pad1 ,copy) 0)
       (when (/= (map-update-ptr ,map ,copy ,copy 1) 0) (pkt-drop failed))
       (setf held-locks (logior held-locks ,bit)
             now (ktime-get-ns)))))

(defmacro pkt-lifetime (flow &optional (key flow))
  `(let ((lifetime u64 180000000000))
     (when (= (gr8s-pkt-flow-protocol ,flow) 6)
       (setf lifetime 7200000000000)
       (when-let ((tcp (map-lookup-ptr gr8s-pkt-tcp ,key)))
         (when (and (/= (logand (load u32 tcp 48) 1) 0)
                    (= (logand (load u32 tcp 48) 4) 0))
           (setf lifetime 120000000000))
         (when (/= (logand (load u32 tcp 48) 256) 0)
           (setf lifetime 120000000000))
         (when (/= (logand (load u32 tcp 48) 128) 0)
           (setf lifetime 10000000000))))
     lifetime))

(defmacro pkt-seq-after (left right)
  `(and (/= ,left ,right) (< (cast u32 (- ,left ,right)) #x80000000)))

(defmacro pkt-tcp-forget (key)
  `(when-let ((tcp (map-lookup-ptr gr8s-pkt-tcp ,key)))
     (when (/= (map-delete-ptr gr8s-pkt-tcp ,key) 0) (pkt-drop failed))))

(defmacro pkt-tcp-ts-expired (age)
  ;; A flow must be used within 2h or is removed before observation. On every
  ;; tracked packet, expire both floors at 24 days, before 16-bit minutes wrap.
  `(>= (cast u16 (- (cast u16 (/ now 60000000000)) ,age)) 34560))

(defmacro pkt-tcp-fresh-syn-timestamp (tcp)
  `(and (= (logand (load u16 ,tcp 48) 19456) 19456)
        (not (pkt-tcp-ts-expired (load u16 ,tcp 50)))
        (/= (logand (gr8s-pkt-meta-flags meta) 256) 0)
        (pkt-seq-after (gr8s-pkt-meta-timestamp meta) (load u32 ,tcp 56))))

(defmacro pkt-tcp-new-generation (key backend)
  "A new sequence or fresh negotiated timestamp identifies a new incarnation.
Same-ISN active retransmissions retain their backend. After closure, a strictly
newer timestamp can distinguish even a reused ISN; older SYNs fail closed.
Caller holds the forward reservation; reverse readers cannot commit concurrently."
  `(when (and (= (gr8s-pkt-flow-protocol ,key) 6)
              (= (logand (gr8s-pkt-meta-flags meta) 18) 2))
     (let ((tcp (map-lookup-ptr gr8s-pkt-tcp ,key)) (replace u32 1))
       (when (/= tcp 0)
         (when (= (load u64 tcp 0) ,backend)
           (when (/= (logand (load u32 tcp 48) 1) 0)
             (if (= (load u32 tcp 8) (gr8s-pkt-meta-seq meta))
                 (unless (and (/= (logand (load u32 tcp 48) 384) 0)
                              (pkt-tcp-fresh-syn-timestamp tcp))
                   (setf replace 0))
                 (progn
                   (when (and (= (logand (load u16 tcp 48) 19456) 19456)
                              (not (pkt-tcp-ts-expired (load u16 tcp 50)))
                              (/= (logand (gr8s-pkt-meta-flags meta) 256) 0)
                              (pkt-seq-after (load u32 tcp 56) (gr8s-pkt-meta-timestamp meta)))
                     (pkt-drop failed))
                   (unless (or (pkt-seq-after (gr8s-pkt-meta-seq meta) (load u32 tcp 16))
                               (pkt-tcp-fresh-syn-timestamp tcp))
                     (pkt-drop failed)))))))
       (when (/= replace 0)
         (when (/= (map-delete-ptr gr8s-pkt-forward ,key) 0) (pkt-drop failed))
         (pkt-tcp-forget ,key)
         (setf (gr8s-pkt-pair-first target) 0)))))

(defmacro pkt-tcp-syn-options (reverse)
  "Record options from the first SYN in this direction; retransmits cannot renegotiate."
  (let ((scale (if reverse 'gr8s-pkt-tcp-state-server-scale 'gr8s-pkt-tcp-state-client-scale))
        (timestamp (if reverse 'gr8s-pkt-tcp-state-server-ts 'gr8s-pkt-tcp-state-client-ts))
        (age (if reverse 'gr8s-pkt-tcp-state-server-ts-age 'gr8s-pkt-tcp-state-client-ts-age))
        (ts-bit (if reverse 34816 17408)) (ws-bit (if reverse 8192 4096)))
    `(progn
       ;; The high scale byte bit marks initialized option metadata, including
       ;; a SYN without options. Older retained flows keep compatibility tracking.
       ,@(unless reverse '((setf (gr8s-pkt-tcp-state-client-scale state) 128)))
       (when (/= (logand (gr8s-pkt-meta-flags meta) 256) 0)
         (setf (,timestamp state) (gr8s-pkt-meta-timestamp meta)
               (,age state) (cast u16 (/ now 60000000000))
               (gr8s-pkt-tcp-state-flags state)
               (logior (gr8s-pkt-tcp-state-flags state) ,ts-bit)))
       (when (/= (logand (gr8s-pkt-meta-flags meta) 512) 0)
         (setf (,scale state) (logior ,(if reverse 0 128) (logand (>> (gr8s-pkt-meta-flags meta) 12) 15))
               (gr8s-pkt-tcp-state-flags state)
               (logior (gr8s-pkt-tcp-state-flags state) ,ws-bit))))))

(defmacro pkt-tcp-trackable (reverse)
  "Conservative metadata acceptance; uncertain packets still reach the endpoint.
Window bounds retain the largest negotiated window, allowing retransmission and
window shrink. Timestamp floors advance only at/before observed receiver ACKs."
  (let ((acked (if reverse 'gr8s-pkt-tcp-state-server-ack 'gr8s-pkt-tcp-state-client-ack))
        (window (if reverse 'gr8s-pkt-tcp-state-client-window 'gr8s-pkt-tcp-state-server-window))
        (timestamp (if reverse 'gr8s-pkt-tcp-state-server-ts 'gr8s-pkt-tcp-state-client-ts))
        (age (if reverse 'gr8s-pkt-tcp-state-server-ts-age 'gr8s-pkt-tcp-state-client-ts-age))
        (valid (if reverse 32768 16384)))
    `(or (/= (logand (gr8s-pkt-tcp-state-flags state) 512) 0)
         (= (logand (gr8s-pkt-tcp-state-client-scale state) 128) 0)
         (and
          ;; RST must reach ordinary sequence validation even without TSopt.
          (or (/= (logand (gr8s-pkt-meta-flags meta) 4) 0)
              (/= (logand (gr8s-pkt-tcp-state-flags state) 3072) 3072)
              (and (/= (logand (gr8s-pkt-meta-flags meta) 256) 0)
                   (or (= (logand (gr8s-pkt-tcp-state-flags state) ,valid) 0)
                       (pkt-tcp-ts-expired (,age state))
                       (not (pkt-seq-after (,timestamp state) (gr8s-pkt-meta-timestamp meta))))))
          (or (= (logand (gr8s-pkt-meta-flags meta) 16) 0)
              (/= (logand (gr8s-pkt-tcp-state-flags state) 3) 3)
              (and (not (pkt-seq-after
                         (gr8s-pkt-meta-ack meta)
                         (,(if reverse 'gr8s-pkt-tcp-state-client-end 'gr8s-pkt-tcp-state-server-end) state)))
                   (pkt-seq-after
                    (gr8s-pkt-meta-ack meta)
                    (,(if reverse 'gr8s-pkt-tcp-state-client-isn 'gr8s-pkt-tcp-state-server-isn) state))))
          (or (/= (logand (gr8s-pkt-tcp-state-flags state) 3) 3)
              (let ((window u32 (,window state)))
                ;; Keepalive and zero-window probes need one sequence position.
                (when (= window 0) (setf window 1))
                (and (not (pkt-seq-after (gr8s-pkt-meta-end meta)
                                         (cast u32 (+ (,acked state) window))))
                     (not (pkt-seq-after (,acked state)
                                         (cast u32 (+ (gr8s-pkt-meta-end meta) window)))))))))))

(defmacro pkt-tcp-expire-timestamps ()
  `(progn
     (when (pkt-tcp-ts-expired (gr8s-pkt-tcp-state-client-ts-age state))
       (setf (gr8s-pkt-tcp-state-flags state) (logand (gr8s-pkt-tcp-state-flags state) 49151)))
     (when (pkt-tcp-ts-expired (gr8s-pkt-tcp-state-server-ts-age state))
       (setf (gr8s-pkt-tcp-state-flags state) (logand (gr8s-pkt-tcp-state-flags state) 32767)))))

(defmacro pkt-tcp-update-options (reverse)
  (let ((acked (if reverse 'gr8s-pkt-tcp-state-server-ack 'gr8s-pkt-tcp-state-client-ack))
        (scale (if reverse 'gr8s-pkt-tcp-state-server-scale 'gr8s-pkt-tcp-state-client-scale))
        (window-field (if reverse 'gr8s-pkt-tcp-state-server-window 'gr8s-pkt-tcp-state-client-window))
        (timestamp (if reverse 'gr8s-pkt-tcp-state-server-ts 'gr8s-pkt-tcp-state-client-ts))
        (age (if reverse 'gr8s-pkt-tcp-state-server-ts-age 'gr8s-pkt-tcp-state-client-ts-age))
        (valid (if reverse 32768 16384)))
    `(when (= (logand (gr8s-pkt-meta-flags meta) 4) 0)
       (when (and (= (logand (gr8s-pkt-tcp-state-flags state) 3072) 3072)
                  (/= (logand (gr8s-pkt-meta-flags meta) 256) 0)
                  (not (pkt-seq-after (gr8s-pkt-meta-seq meta) (,acked state)))
                  (or (= (logand (gr8s-pkt-tcp-state-flags state) ,valid) 0)
                      (not (pkt-seq-after (,timestamp state) (gr8s-pkt-meta-timestamp meta)))))
         (setf (,timestamp state) (gr8s-pkt-meta-timestamp meta)
               (,age state) (cast u16 (/ now 60000000000))
               (gr8s-pkt-tcp-state-flags state) (logior (gr8s-pkt-tcp-state-flags state) ,valid)))
       (let ((window u32 (gr8s-pkt-meta-window meta)))
         ;; SYN window fields are never scaled; both peers must have offered WSopt.
         (when (and (= (logand (gr8s-pkt-meta-flags meta) 2) 0)
                    (= (logand (gr8s-pkt-tcp-state-flags state) 12288) 12288))
           (let ((shift u32 (logand (,scale state) 15)))
             (when (> shift 14) (setf shift 14))
             (setf window (cast u32 (<< window shift)))))
         (when (> window (,window-field state))
           (setf (,window-field state) window))))))

(defmacro pkt-tcp-parse-options ()
  "Walk at most forty TCP option bytes, copying through skb_load_bytes for nonlinear skbs."
  `(when (> header 20)
     (let ((cursor u32 20))
       (dotimes (option 40)
         (when (< cursor header)
           (when (/= (skb-load-bytes (ctx-ptr) (+ (gr8s-pkt-meta-l4 meta) cursor) wire 1) 0)
             (pkt-drop malformed))
           (let ((kind u32 (load u8 wire 0)))
             (cond
               ((= kind 0) (setf cursor header))
               ((= kind 1) (setf cursor (+ cursor 1)))
               (t
                (when (> (+ cursor 2) header) (pkt-drop malformed))
                (when (/= (skb-load-bytes (ctx-ptr) (+ (gr8s-pkt-meta-l4 meta) cursor) wire 2) 0)
                  (pkt-drop malformed))
                (let ((size u32 (load u8 wire 1)))
                  (when (or (< size 2) (> (+ cursor size) header)) (pkt-drop malformed))
                  (cond
                    ((= kind 3)
                     (when (/= size 3) (pkt-drop malformed))
                     (when (/= (logand (gr8s-pkt-meta-flags meta) 2) 0)
                       (when (/= (logand (gr8s-pkt-meta-flags meta) 512) 0) (pkt-drop malformed))
                       (when (/= (skb-load-bytes (ctx-ptr) (+ (gr8s-pkt-meta-l4 meta) (+ cursor 2)) wire 1) 0)
                         (pkt-drop malformed))
                       (let ((shift u32 (load u8 wire 0)))
                         (when (> shift 14) (setf shift 14))
                         (setf (gr8s-pkt-meta-flags meta)
                               (logior (gr8s-pkt-meta-flags meta) (logior 512 (<< shift 12)))))))
                    ((= kind 8)
                     (when (or (/= size 10) (/= (logand (gr8s-pkt-meta-flags meta) 256) 0))
                       (pkt-drop malformed))
                     (when (/= (skb-load-bytes (ctx-ptr) (+ (gr8s-pkt-meta-l4 meta) (+ cursor 2)) wire 8) 0)
                       (pkt-drop malformed))
                     (setf (gr8s-pkt-meta-timestamp meta) (ntohl (load u32 wire 0))
                           (gr8s-pkt-meta-echo meta) (ntohl (load u32 wire 4))
                           (gr8s-pkt-meta-flags meta) (logior (gr8s-pkt-meta-flags meta) 256))))
                  (setf cursor (+ cursor size)))))))))))

(defmacro pkt-tcp-lifecycle (reverse)
  "Observe closure only from sequence/ACK evidence for the current generation.
Uncertain controls still reach the endpoint for challenge ACK processing, but
cannot shorten the NAT lifetime. A FIN consumes sequence space; both FINs must
be cumulatively acknowledged before the entry becomes a closed tombstone."
  (let ((end (if reverse 'gr8s-pkt-tcp-state-server-end 'gr8s-pkt-tcp-state-client-end))
        (acked (if reverse 'gr8s-pkt-tcp-state-server-ack 'gr8s-pkt-tcp-state-client-ack))
        (other-end (if reverse 'gr8s-pkt-tcp-state-client-end 'gr8s-pkt-tcp-state-server-end))
        (other-acked (if reverse 'gr8s-pkt-tcp-state-client-ack 'gr8s-pkt-tcp-state-server-ack))
        (fin (if reverse 'gr8s-pkt-tcp-state-server-fin 'gr8s-pkt-tcp-state-client-fin))
        (other-fin (if reverse 'gr8s-pkt-tcp-state-client-fin 'gr8s-pkt-tcp-state-server-fin))
        (fin-bit (if reverse 16 8)) (other-fin-bit (if reverse 8 16))
        (ack-bit (if reverse 32 64)))
    `(when (= (logand (gr8s-pkt-tcp-state-flags state) 512) 0)
       (when (and (/= (logand (gr8s-pkt-meta-flags meta) 4) 0)
                  ;; SYN-SENT accepts ISS < ACK <= SND.NXT (RFC9293 3.10.7.3).
                  ;; A peer may refuse without acknowledging all SYN payload.
                  ,(if reverse
                       '(or (and (= (logand (gr8s-pkt-tcp-state-flags state) 2) 0)
                                 (/= (logand (gr8s-pkt-meta-flags meta) 16) 0)
                                 (pkt-seq-after (gr8s-pkt-meta-ack meta)
                                                (gr8s-pkt-tcp-state-client-isn state))
                                 (not (pkt-seq-after (gr8s-pkt-meta-ack meta)
                                                     (gr8s-pkt-tcp-state-client-end state))))
                            (and (/= (logand (gr8s-pkt-tcp-state-flags state) 2) 0)
                                 (= (gr8s-pkt-meta-seq meta) (gr8s-pkt-tcp-state-server-ack state))
                                 (= (gr8s-pkt-meta-seq meta) (gr8s-pkt-tcp-state-server-end state))))
                       '(and (/= (logand (gr8s-pkt-tcp-state-flags state) 2) 0)
                             (= (gr8s-pkt-meta-seq meta) (gr8s-pkt-tcp-state-client-ack state))
                             (= (gr8s-pkt-meta-seq meta) (gr8s-pkt-tcp-state-client-end state))))
                  ;; An ACK on the reset must not refer to unsent/old data.
                  (or (= (logand (gr8s-pkt-meta-flags meta) 16) 0)
                      (and (not (pkt-seq-after (gr8s-pkt-meta-ack meta) (,other-end state)))
                           (not (pkt-seq-after (,other-acked state) (gr8s-pkt-meta-ack meta))))))
         (setf (gr8s-pkt-tcp-state-flags state)
               (logior (gr8s-pkt-tcp-state-flags state) 128)))
       (when (and (/= (logand (gr8s-pkt-tcp-state-flags state) 4) 0)
                  (= (logand (gr8s-pkt-meta-flags meta) 6) 0)
                  (/= (logand (gr8s-pkt-meta-flags meta) 16) 0)
                  (not (pkt-seq-after (gr8s-pkt-meta-ack meta) (,other-end state)))
                  (not (pkt-seq-after (,other-acked state) (gr8s-pkt-meta-ack meta))))
         ;; An in-window FIN may precede a data gap. Only the peer's later
         ;; cumulative ACK proves receipt through that FIN; no early retirement.
         (when (and (/= (logand (gr8s-pkt-meta-flags meta) 1) 0)
                    (or (and (= (logand (gr8s-pkt-tcp-state-flags state) ,fin-bit) 0)
                             (not (pkt-seq-after (,acked state) (gr8s-pkt-meta-seq meta)))
                             (not (pkt-seq-after (,end state) (gr8s-pkt-meta-end meta))))
                        (and (/= (logand (gr8s-pkt-tcp-state-flags state) ,fin-bit) 0)
                             (= (gr8s-pkt-meta-end meta) (,fin state)))))
           (setf (,fin state) (gr8s-pkt-meta-end meta)
                 (gr8s-pkt-tcp-state-flags state)
                 (logior (gr8s-pkt-tcp-state-flags state) ,fin-bit)))
         ;; Only a packet from this sender's observed stream can acknowledge
         ;; the peer FIN; a delayed ACK from an older generation cannot close it.
         (when (and (/= (logand (gr8s-pkt-tcp-state-flags state) ,other-fin-bit) 0)
                    (not (pkt-seq-after (,acked state) (gr8s-pkt-meta-seq meta)))
                    (not (pkt-seq-after (gr8s-pkt-meta-seq meta) (,end state)))
                    (not (pkt-seq-after (,other-fin state) (gr8s-pkt-meta-ack meta))))
           (setf (gr8s-pkt-tcp-state-flags state)
                 (logior (gr8s-pkt-tcp-state-flags state) ,ack-bit))))
       (when (= (logand (gr8s-pkt-tcp-state-flags state) 120) 120)
         (setf (gr8s-pkt-tcp-state-flags state)
               (logior (gr8s-pkt-tcp-state-flags state) 256))))))

(defmacro pkt-tcp-observe (key backend reverse)
  "Keep initial sequence/handshake metadata bound to this NAT backend.
Protocol state is published before a new forward entry; interrupted publication
cannot create a reverse-translatable TCP flow without its metadata."
  (let ((end-field (if reverse 'gr8s-pkt-tcp-state-server-end 'gr8s-pkt-tcp-state-client-end))
        (ack-field (if reverse 'gr8s-pkt-tcp-state-client-ack 'gr8s-pkt-tcp-state-server-ack)))
    `(when (= (gr8s-pkt-flow-protocol ,key) 6)
       (let ((state (make-gr8s-pkt-tcp-state)))
         (when-let ((tcp (map-lookup-ptr gr8s-pkt-tcp ,key)))
           (when (= (load u64 tcp 0) ,backend)
             ,@(loop for offset from 0 below 64 by 8
                     collect `(store u64 state ,offset (load u64 tcp ,offset)))))
         (if (or (/= (logand (gr8s-pkt-tcp-state-flags state) 384) 0)
                 (not (pkt-tcp-trackable ,reverse)))
             ;; Preserve translation for delayed controls, without refreshing
             ;; the tombstone or changing this generation's protocol metadata.
             (when-let ((held (map-lookup-ptr gr8s-pkt-forward ,key)))
               (setf now (load u64 held 8)))
             (progn
               (pkt-tcp-expire-timestamps)
               (when (= (gr8s-pkt-tcp-state-backend state) 0)
                 (setf (gr8s-pkt-tcp-state-backend state) ,backend
                       (gr8s-pkt-tcp-state-flags state) 516)
                 ,@(unless reverse
                     '((when (= (logand (gr8s-pkt-meta-flags meta) 18) 2)
                         (setf (gr8s-pkt-tcp-state-flags state) 1
                               (gr8s-pkt-tcp-state-client-isn state) (gr8s-pkt-meta-seq meta)
                               (gr8s-pkt-tcp-state-client-ack state) (gr8s-pkt-meta-seq meta))
                         (pkt-tcp-syn-options nil))))
                 (setf ,(if reverse '(gr8s-pkt-tcp-state-server-end state)
                                   '(gr8s-pkt-tcp-state-client-end state)) (gr8s-pkt-meta-end meta)))
               ,@(if reverse
                     '((when (/= (logand (gr8s-pkt-tcp-state-flags state) 1) 0)
                         (when (= (logand (gr8s-pkt-tcp-state-flags state) 2) 0)
                           (unless (or (= (logand (gr8s-pkt-meta-flags meta) 18) 2)
                                       (and (/= (logand (gr8s-pkt-meta-flags meta) 16) 0)
                                            (or (= (logand (gr8s-pkt-meta-flags meta) 6) 2)
                                                (= (logand (gr8s-pkt-meta-flags meta) 6) 4))
                                            (pkt-seq-after (gr8s-pkt-meta-ack meta)
                                                           (gr8s-pkt-tcp-state-client-isn state))
                                            (not (pkt-seq-after (gr8s-pkt-meta-ack meta)
                                                               (gr8s-pkt-tcp-state-client-end state)))))
                             (pkt-drop failed)))
                         (when (/= (logand (gr8s-pkt-meta-flags meta) 2) 0)
                           (when (and (/= (logand (gr8s-pkt-tcp-state-flags state) 2) 0)
                                      (/= (gr8s-pkt-tcp-state-server-isn state) (gr8s-pkt-meta-seq meta)))
                             (pkt-drop failed))
                           (when (= (logand (gr8s-pkt-tcp-state-flags state) 2) 0)
                             ;; Echoed SYN timestamps distinguish an older SYN-ACK
                             ;; even when the client reused exactly the same ISN.
                             (when (and (/= (logand (gr8s-pkt-meta-flags meta) 16) 0)
                                        (/= (logand (gr8s-pkt-tcp-state-flags state) 1024) 0)
                                        (/= (logand (gr8s-pkt-meta-flags meta) 256) 0)
                                        (pkt-seq-after (gr8s-pkt-tcp-state-client-ts state)
                                                       (gr8s-pkt-meta-echo meta)))
                               (pkt-drop failed))
                             (setf (gr8s-pkt-tcp-state-server-isn state) (gr8s-pkt-meta-seq meta)
                                   (gr8s-pkt-tcp-state-server-end state) (gr8s-pkt-meta-end meta)
                                   (gr8s-pkt-tcp-state-server-ack state) (gr8s-pkt-meta-seq meta))
                             (pkt-tcp-syn-options t))
                           (setf (gr8s-pkt-tcp-state-flags state)
                                 (logior (gr8s-pkt-tcp-state-flags state) 2)))
                         ;; In a simultaneous open, the client SYN-ACK can be
                         ;; followed by a server ACK rather than another client ACK.
                         (when (and (= (logand (gr8s-pkt-tcp-state-flags state) 3) 3)
                                    (= (logand (gr8s-pkt-meta-flags meta) 6) 0)
                                    (/= (logand (gr8s-pkt-meta-flags meta) 16) 0)
                                    (pkt-seq-after (gr8s-pkt-tcp-state-server-ack state)
                                                   (gr8s-pkt-tcp-state-server-isn state))
                                    (pkt-seq-after (gr8s-pkt-meta-ack meta)
                                                   (gr8s-pkt-tcp-state-client-isn state))
                                    (pkt-seq-after (gr8s-pkt-meta-seq meta)
                                                   (gr8s-pkt-tcp-state-server-isn state)))
                           (setf (gr8s-pkt-tcp-state-flags state)
                                 (logior (gr8s-pkt-tcp-state-flags state) 4)))))
                     '((when (/= (logand (gr8s-pkt-tcp-state-flags state) 1) 0)
                         (if (/= (logand (gr8s-pkt-meta-flags meta) 2) 0)
                             (when (/= (gr8s-pkt-meta-seq meta) (gr8s-pkt-tcp-state-client-isn state))
                               (pkt-drop failed))
                             (when (= (logand (gr8s-pkt-tcp-state-flags state) 4) 0)
                               (unless (and (/= (logand (gr8s-pkt-tcp-state-flags state) 2) 0)
                                            (/= (logand (gr8s-pkt-meta-flags meta) 16) 0)
                                            (pkt-seq-after (gr8s-pkt-meta-ack meta)
                                                           (gr8s-pkt-tcp-state-server-isn state))
                                            (not (pkt-seq-after (gr8s-pkt-meta-ack meta)
                                                               (gr8s-pkt-tcp-state-server-end state)))
                                            (pkt-seq-after (gr8s-pkt-meta-seq meta)
                                                           (gr8s-pkt-tcp-state-client-isn state)))
                                 (pkt-drop failed))
                               (when (= (logand (gr8s-pkt-meta-flags meta) 4) 0)
                                 (setf (gr8s-pkt-tcp-state-flags state)
                                       (logior (gr8s-pkt-tcp-state-flags state) 4))))))))
               (pkt-tcp-lifecycle ,reverse)
               (when (and (/= (logand (gr8s-pkt-meta-flags meta) 4) 0)
                          (= (logand (gr8s-pkt-tcp-state-flags state) 128) 0))
                 (when-let ((held (map-lookup-ptr gr8s-pkt-forward ,key)))
                   (setf now (load u64 held 8))))
               (when (and (= (logand (gr8s-pkt-meta-flags meta) 4) 0)
                          (or (/= (logand (gr8s-pkt-tcp-state-flags state) 512) 0)
                              (pkt-seq-after (gr8s-pkt-meta-end meta) (,end-field state))))
                 (setf (,end-field state) (gr8s-pkt-meta-end meta)))
               (when (/= (logand (gr8s-pkt-meta-flags meta) 16) 0)
                 (when (and (= (logand (gr8s-pkt-meta-flags meta) 4) 0)
                            ;; ACK evidence must come from this generation's
                            ;; observed sender stream, including retransmissions.
                            (or (/= (logand (gr8s-pkt-tcp-state-flags state) 512) 0)
                                (and (not (pkt-seq-after
                                           (,(if reverse 'gr8s-pkt-tcp-state-server-ack
                                                         'gr8s-pkt-tcp-state-client-ack) state)
                                           (gr8s-pkt-meta-seq meta)))
                                     (not (pkt-seq-after (gr8s-pkt-meta-seq meta)
                                                        (,end-field state)))))
                            (not (pkt-seq-after (gr8s-pkt-meta-ack meta)
                                               (,(if reverse 'gr8s-pkt-tcp-state-client-end
                                                             'gr8s-pkt-tcp-state-server-end) state)))
                            (pkt-seq-after (gr8s-pkt-meta-ack meta) (,ack-field state)))
                   (setf (,ack-field state) (gr8s-pkt-meta-ack meta))))
               (pkt-tcp-update-options ,reverse)
               (when (/= (map-update-ptr gr8s-pkt-tcp ,key state 0) 0) (pkt-drop failed))))))))

(defmacro pkt-make-reverse-key (reverse flow backend)
  `(setf (gr8s-pkt-flow-source ,reverse) (cast u32 ,backend)
         (gr8s-pkt-flow-destination ,reverse) (gr8s-pkt-flow-source ,flow)
         (gr8s-pkt-flow-sport ,reverse) (cast u16 (>> ,backend 32))
         (gr8s-pkt-flow-dport ,reverse) (gr8s-pkt-flow-sport ,flow)
         (gr8s-pkt-flow-protocol ,reverse) (gr8s-pkt-flow-protocol ,flow)
         (gr8s-pkt-flow-pad0 ,reverse) 0
         (gr8s-pkt-flow-pad1 ,reverse) 0))

(defmacro pkt-write-address (flow target meta reverse)
  "Rewrite one address and transport port, maintaining IP and TCP/UDP checksums.
All original fields and TARGET are stack copies: helpers invalidate packet pointers."
  (let ((address-field (if reverse 'gr8s-pkt-flow-source 'gr8s-pkt-flow-destination))
        (port-field (if reverse 'gr8s-pkt-flow-sport 'gr8s-pkt-flow-dport))
        (address-offset (if reverse 26 30))
        (port-offset (if reverse 0 2)))
    `(let ((checksum u32 (+ (gr8s-pkt-meta-l4 ,meta)
                            (if (= (gr8s-pkt-flow-protocol ,flow) 6) 16 6)))
           (udp-flags u64 (if (= (gr8s-pkt-flow-protocol ,flow) 17) 32 0)))
       (when (/= (l3-csum-replace (ctx-ptr) 24 (,address-field ,flow)
                                 (cast u32 (gr8s-pkt-pair-first ,target)) 4) 0)
         (pkt-drop failed))
       (when (/= (l4-csum-replace (ctx-ptr) checksum (,address-field ,flow)
                                 (cast u32 (gr8s-pkt-pair-first ,target))
                                 (logior udp-flags 20)) 0)
         (pkt-drop failed))
       (when (/= (l4-csum-replace (ctx-ptr) checksum (,port-field ,flow)
                                 (logand (>> (gr8s-pkt-pair-first ,target) 32) #xffff)
                                 (logior udp-flags 2)) 0)
         (pkt-drop failed))
       (when (/= (skb-store-bytes (ctx-ptr) ,address-offset ,target 4 2) 0)
         (pkt-drop failed))
       (when (/= (skb-store-bytes (ctx-ptr) (+ (gr8s-pkt-meta-l4 ,meta) ,port-offset)
                                  (+ ,target 4) 2 2) 0)
         (pkt-drop failed)))))

(defun gr8s.network::service-packet-forward-form ()
  ;; One 16-byte scratch key serves affinity, membership and reverse lookups.
  ;; Reconstruct its fields at every use to keep the combined guard below the
  ;; kernel's stack limit without retaining unrelated stack structs.
  '((pkt-lock :forward flow)
    (let ((probe (make-gr8s-pkt-pair)))
      (let ((key u64 (logior (<< (cast u64 (gr8s-pkt-flow-protocol flow)) 48)
                           (logior (<< (cast u64 (gr8s-pkt-flow-destination flow)) 16)
                                    (cast u64 (gr8s-pkt-flow-dport flow))))))
      (when-let ((held (map-lookup-ptr gr8s-pkt-forward flow)))
        (if (<= (- now (load u64 held 8)) (pkt-lifetime flow))
            (progn
              (setf (gr8s-pkt-pair-first target) (load u64 held 0))
              (pkt-tcp-new-generation flow (gr8s-pkt-pair-first target)))
            ;; Under the tuple reservation no packet/collector can refresh or
            ;; republish this key between expiration and NOEXIST insertion.
            (progn
              (when (/= (map-delete-ptr gr8s-pkt-forward flow) 0) (pkt-drop failed))
              (pkt-tcp-forget flow))))
      (when (= (gr8s-pkt-pair-first target) 0)
        (pkt-tcp-forget flow)
        (when-let ((service (map-lookup gr8s-service-v4 key)))
          (let ((count u32 (load u16 service 0)))
            (when (= count 0) (pkt-drop empty))
            (let ((offset u32 (mod (get-prandom-u32) count))
                  (sticky u32 (load u16 service 2))
                  (timeout u64 (load u32 service 8)))
              (setf (gr8s-pkt-pair-first probe) key
                    (gr8s-pkt-pair-second probe) (cast u64 (gr8s-pkt-flow-source flow)))
              (when (/= sticky 0)
                (when-let ((held (map-lookup-ptr gr8s-pkt-affinity probe)))
                  (when (<= (- (/ now 1000000000) (load u64 held 8)) timeout)
                    (progn
                      (setf (gr8s-pkt-pair-first probe) key
                            (gr8s-pkt-pair-second probe) (load u64 held 0))
                      (when-let ((index (map-lookup-ptr gr8s-backend-index-v4 probe)))
                        (when (< (load u32 index 0) count)
                          (setf offset (load u32 index 0))))))))
              (let ((slot u32 (+ (load u32 service 4) offset)))
                (when-let ((backend (map-lookup gr8s-backend-v4 slot)))
                  (setf (gr8s-pkt-pair-first target) (load u64 backend 0))))
              (when (= (gr8s-pkt-pair-first target) 0) (pkt-drop membership))
              (progn
                (setf (gr8s-pkt-pair-first probe) key
                      (gr8s-pkt-pair-second probe) (gr8s-pkt-pair-first target))
                (when (= (map-lookup-ptr gr8s-backend-index-v4 probe) 0)
                  (pkt-drop membership)))
              ;; Hairpin requires source NAT, which is added with the external
              ;; traffic path. Do not emit a DNAT-only connection that cannot reply.
              (when (= (cast u32 (gr8s-pkt-pair-first target)) (gr8s-pkt-flow-source flow))
                (pkt-drop collision))
              (let ((entry (make-gr8s-pkt-pair)))
                (pkt-make-reverse-key probe flow (gr8s-pkt-pair-first target))
                (pkt-lock :reverse probe)
                (setf (gr8s-pkt-pair-first entry)
                      (logior (cast u64 (gr8s-pkt-flow-destination flow))
                               (<< (cast u64 (gr8s-pkt-flow-dport flow)) 32))
                      (gr8s-pkt-pair-second entry) now)
                (when-let ((existing (map-lookup-ptr gr8s-pkt-reverse probe)))
                  (when (/= (load u64 existing 0) (gr8s-pkt-pair-first entry))
                    (pkt-drop collision)))
                ;; NOEXIST reserves a reverse tuple. Recheck after a racing
                ;; insert; another Service can never take ownership silently.
                (when (/= (map-update-ptr gr8s-pkt-reverse probe entry 1) 0)
                  (let ((existing (map-lookup-ptr gr8s-pkt-reverse probe)))
                    (when (= existing 0) (pkt-drop failed))
                    (when (/= (load u64 existing 0) (gr8s-pkt-pair-first entry))
                      (pkt-drop collision))))
              (setf (gr8s-pkt-pair-second target) now)
              ;; Only one concurrent first packet may publish this flow. A
              ;; losing packet retries through the winner on its next attempt.
              (setf new-flow 1)
              (when (/= sticky 0)
                (progn
                  (setf (gr8s-pkt-pair-first probe) key
                        (gr8s-pkt-pair-second probe) (cast u64 (gr8s-pkt-flow-source flow))
                        (gr8s-pkt-pair-second target) (/ now 1000000000))
                  (map-update-ptr gr8s-pkt-affinity probe target 0))))))))
      (when (/= (gr8s-pkt-pair-first target) 0)
        ;; Confirm the reverse reservation before sending another packet. A
        ;; failed or concurrent publication must not create a one-way NAT flow.
        (progn
          (pkt-make-reverse-key probe flow (gr8s-pkt-pair-first target))
          (when (= (logand held-locks 2) 0) (pkt-lock :reverse probe))
          (let ((entry (map-lookup-ptr gr8s-pkt-reverse probe)))
            (when (= entry 0) (pkt-drop failed))
            (when (/= (load u64 entry 0)
                      (logior (cast u64 (gr8s-pkt-flow-destination flow))
                               (<< (cast u64 (gr8s-pkt-flow-dport flow)) 32)))
              (pkt-drop collision))))
        (pkt-tcp-observe flow (gr8s-pkt-pair-first target) nil)
        (setf (gr8s-pkt-pair-second target) now)
        (when (/= (map-update-ptr gr8s-pkt-forward flow target (if (/= new-flow 0) 1 0)) 0)
          (pkt-drop failed))
        (pkt-write-address flow target meta nil)
        (pkt-count requests))))))

(defun gr8s.network::service-packet-reverse-form ()
  '((pkt-lock :reverse flow)
    (when-let ((entry (map-lookup-ptr gr8s-pkt-reverse flow)))
      (let ((service u64 (load u64 entry 0)))
        (setf (gr8s-pkt-pair-first target) service)
        (setf (gr8s-pkt-flow-source locked-forward) (gr8s-pkt-flow-destination flow)
              (gr8s-pkt-flow-destination locked-forward) (cast u32 service)
              (gr8s-pkt-flow-sport locked-forward) (gr8s-pkt-flow-dport flow)
              (gr8s-pkt-flow-dport locked-forward) (cast u16 (>> service 32))
              (gr8s-pkt-flow-protocol locked-forward) (gr8s-pkt-flow-protocol flow))
        (pkt-lock :forward locked-forward)
        (let ((held (map-lookup-ptr gr8s-pkt-forward locked-forward)))
          (when (= held 0) (pkt-drop failed))
          (when (> (- now (load u64 held 8)) (pkt-lifetime flow locked-forward)) (pkt-drop failed))
          (when (/= (load u64 held 0)
                    (logior (cast u64 (gr8s-pkt-flow-source flow))
                             (<< (cast u64 (gr8s-pkt-flow-sport flow)) 32)))
            (pkt-drop collision))
          (pkt-tcp-observe locked-forward
                           (logior (cast u64 (gr8s-pkt-flow-source flow))
                                   (<< (cast u64 (gr8s-pkt-flow-sport flow)) 32)) t)
          (let ((refreshed (make-gr8s-pkt-pair)))
            (setf (gr8s-pkt-pair-first refreshed) (load u64 held 0)
                  (gr8s-pkt-pair-second refreshed) now)
            (when (/= (map-update-ptr gr8s-pkt-forward locked-forward refreshed 0) 0)
              (pkt-drop failed)))))
      (pkt-write-address flow target meta t)
      (pkt-count replies))))

(defun gr8s.network::service-packet-gc-program-form ()
  "Maintenance only: input is an Ethernet/IPv4 envelope with kind at34, key at36.
Runs through BPF_PROG_TEST_RUN, never attached to a traffic interface. Results:
0 unchanged, 1 reclaimed, 2 contention/helper failure, 3 invalid input."
  '(defprog gr8s-packet-gc (:type :tc :section "classifier" :license "GPL")
     (let ((flow (make-gr8s-pkt-flow)) (target (make-gr8s-pkt-pair))
           (locked-forward (make-gr8s-pkt-flow)) (locked-reverse (make-gr8s-pkt-flow))
           (held-locks u32 0) (changed u32 0) (failed u64 0)
           (now u64 (ktime-get-ns)) (data u64 (tc-data)) (data-end u64 (tc-data-end)))
       (when (> (+ data 52) data-end) (return 3))
       (when (> (load u8 data 34) 1) (return 3))
       (when (/= (skb-load-bytes (ctx-ptr) 36 flow 16) 0) (return 3))
       (when (or (/= (gr8s-pkt-flow-pad0 flow) 0) (/= (gr8s-pkt-flow-pad1 flow) 0)
                 (and (/= (gr8s-pkt-flow-protocol flow) 6) (/= (gr8s-pkt-flow-protocol flow) 17)))
         (return 3))
       (if (= (load u8 data 34) 0)
           (progn
             (pkt-lock :forward flow)
             (when-let ((held (map-lookup-ptr gr8s-pkt-forward flow)))
               (when (> (- now (load u64 held 8)) (pkt-lifetime flow))
                 (setf (gr8s-pkt-pair-first target) (load u64 held 0))
                 (pkt-make-reverse-key locked-reverse flow (gr8s-pkt-pair-first target))
                 (pkt-lock :reverse locked-reverse)
                 ;; The forward reservation prevents refresh/replacement
                 ;; while its paired reverse reservation is taken.
                 (when-let ((entry (map-lookup-ptr gr8s-pkt-reverse locked-reverse)))
                   (when (= (load u64 entry 0)
                            (logior (cast u64 (gr8s-pkt-flow-destination flow))
                                    (<< (cast u64 (gr8s-pkt-flow-dport flow)) 32)))
                     (when (/= (map-delete-ptr gr8s-pkt-reverse locked-reverse) 0)
                       (pkt-drop failed))))
                 (when (/= (map-delete-ptr gr8s-pkt-forward flow) 0) (pkt-drop failed))
                 (pkt-tcp-forget flow)
                 (setf changed 1))))
           (progn
             (pkt-lock :reverse flow)
             (when-let ((entry (map-lookup-ptr gr8s-pkt-reverse flow)))
               (let ((service u64 (load u64 entry 0)))
                 (setf (gr8s-pkt-flow-source locked-forward) (gr8s-pkt-flow-destination flow)
                       (gr8s-pkt-flow-destination locked-forward) (cast u32 service)
                       (gr8s-pkt-flow-sport locked-forward) (gr8s-pkt-flow-dport flow)
                       (gr8s-pkt-flow-dport locked-forward) (cast u16 (>> service 32))
                       (gr8s-pkt-flow-protocol locked-forward) (gr8s-pkt-flow-protocol flow))
                 (pkt-lock :forward locked-forward)
                 (let ((held (map-lookup-ptr gr8s-pkt-forward locked-forward)))
                   (if (= held 0)
                       (progn (pkt-tcp-forget locked-forward) (setf changed 1))
                       (if (/= (load u64 held 0)
                               (logior (cast u64 (gr8s-pkt-flow-source flow))
                                       (<< (cast u64 (gr8s-pkt-flow-sport flow)) 32)))
                           ;; Retire only the obsolete reverse entry when a
                           ;; replacement backend owns this live forward key.
                           (setf changed 1)
                           (when (> (- now (load u64 held 8)) (pkt-lifetime flow locked-forward))
                             (when (/= (map-delete-ptr gr8s-pkt-forward locked-forward) 0)
                               (pkt-drop failed))
                             (pkt-tcp-forget locked-forward)
                             (setf changed 1))))
                   (when (/= changed 0)
                     (when (/= (map-delete-ptr gr8s-pkt-reverse flow) 0) (pkt-drop failed))))))))
       ;; Return constants after releasing helper-clobbered registers; the
       ;; decision itself is made while CHANGED is still live in the SSA path.
       (if (= changed 0)
           (progn (pkt-unlock) (return 0))
           (progn (pkt-unlock) (return 1))))))

(defun gr8s.network::service-packet-processing-form (body)
  `(
         (setf (gr8s-pkt-meta-l4 meta) (+ 14 (* (logand (load u8 data 14) 15) 4)))
         (when (or (< (gr8s-pkt-meta-l4 meta) 34) (> (gr8s-pkt-meta-l4 meta) 74))
           (pkt-drop malformed))
         (when (> (+ (gr8s-pkt-meta-l4 meta)
                     (if (= (load u8 data 23) 6) 20 8)) (ctx u32 0))
           (pkt-drop malformed))
         (when (or (< (ntohs (load u16 data 16))
                      (+ (- (gr8s-pkt-meta-l4 meta) 14)
                         (if (= (load u8 data 23) 6) 20 8)))
                   (> (+ 14 (ntohs (load u16 data 16))) (ctx u32 0)))
           (pkt-drop malformed))
         (setf (gr8s-pkt-flow-source flow) (load u32 data 26)
               (gr8s-pkt-flow-destination flow) (load u32 data 30)
               (gr8s-pkt-flow-protocol flow) (load u8 data 23))
         ;; The port offset can include IPv4 options and the skb can be
         ;; non-linear. Copy through the kernel helper rather than relying on
         ;; repeated scalar stack loads to retain a verifier packet-range ID.
         (when (/= (skb-load-bytes (ctx-ptr) (gr8s-pkt-meta-l4 meta) (+ flow 8) 4) 0)
           (pkt-drop malformed))
         (when (= (gr8s-pkt-flow-protocol flow) 6)
           ;; Reuse the still-empty target while parsing, then clear it before selection.
           (let ((wire u64 target)
                 (length u32 (- (ntohs (load u16 data 16)) (- (gr8s-pkt-meta-l4 meta) 14))))
             (when (/= (skb-load-bytes (ctx-ptr) (+ (gr8s-pkt-meta-l4 meta) 4) wire 16) 0)
               (pkt-drop malformed))
             (let ((header u32 (* (>> (load u8 wire 8) 4) 4)))
               (when (or (< header 20) (> header length)) (pkt-drop malformed))
               (setf (gr8s-pkt-meta-seq meta) (ntohl (load u32 wire 0))
                     (gr8s-pkt-meta-ack meta) (ntohl (load u32 wire 4))
                     (gr8s-pkt-meta-flags meta) (cast u32 (load u8 wire 9))
                     (gr8s-pkt-meta-window meta) (cast u32 (ntohs (load u16 wire 10)))
                     (gr8s-pkt-meta-end meta)
                     (cast u32 (+ (gr8s-pkt-meta-seq meta)
                                  (+ (- length header)
                                     (+ (if (/= (logand (gr8s-pkt-meta-flags meta) 2) 0) 1 0)
                                        (if (/= (logand (gr8s-pkt-meta-flags meta) 1) 0) 1 0))))))
               (when (and (/= (logand (gr8s-pkt-meta-flags meta) 2) 0)
                          (/= (logand (gr8s-pkt-meta-flags meta) 5) 0)) (pkt-drop malformed))
               (pkt-tcp-parse-options)))
           (setf (gr8s-pkt-pair-first target) 0 (gr8s-pkt-pair-second target) 0))
         ,@body
         (pkt-unlock)))

(defun gr8s.network::service-packet-body-form (body &key continue-guard)
  "Build a packet translator body. CONTINUE-GUARD skips ineligible packets without
returning from the enclosing guard, so non-Service traffic still crosses policy."
  `(let ((requests (map-lookup gr8s-pkt-stats 0))
         (replies (map-lookup gr8s-pkt-stats 1))
         (empty (map-lookup gr8s-pkt-stats 2))
         (membership (map-lookup gr8s-pkt-stats 3))
         (collision (map-lookup gr8s-pkt-stats 4))
         (failed (map-lookup gr8s-pkt-stats 5))
         (malformed (map-lookup gr8s-pkt-stats 6))
         (now u64 (ktime-get-ns)))
     (let ((flow (make-gr8s-pkt-flow)) (target (make-gr8s-pkt-pair))
           (meta (make-gr8s-pkt-meta))
           (data u64 (tc-data)) (data-end u64 (tc-data-end)))
       ;; The original tuple never changes. Its same-direction lock key can
       ;; alias it; only the opposite-direction tuple needs another buffer.
       (let ((locked-forward u64 ,(if (eq (second (first body)) :forward) 'flow '(make-gr8s-pkt-flow)))
             (locked-reverse u64 ,(if (eq (second (first body)) :reverse) 'flow '(make-gr8s-pkt-flow)))
             (held-locks u32 0) (new-flow u32 0))
       ,@(if continue-guard
             `((when (> (+ data 34) data-end) (pkt-drop malformed))
               (when (and (= (eth-type data) #x0800)
                          (= (logand (load u8 data 14) #xf0) #x40)
                          (= (logand (ntohs (load u16 data 20)) #x3fff) 0)
                          (or (= (load u8 data 23) 6) (= (load u8 data 23) 17)))
                 ,@(gr8s.network::service-packet-processing-form body)))
             `((when (> (+ data 14) data-end) (pkt-drop malformed))
               (when (/= (eth-type data) #x0800) (return TC_ACT_OK))
               (when (> (+ data 34) data-end) (pkt-drop malformed))
               (when (/= (logand (load u8 data 14) #xf0) #x40) (pkt-drop malformed))
               (when (< (logand (load u8 data 14) 15) 5) (pkt-drop malformed))
               (when (/= (logand (ntohs (load u16 data 20)) #x3fff) 0) (return TC_ACT_OK))
               (when (and (/= (load u8 data 23) 6) (/= (load u8 data 23) 17))
                 (return TC_ACT_OK))
               ,@(gr8s.network::service-packet-processing-form body)
               TC_ACT_OK))))))

(defun gr8s.network::service-packet-program-form (name body)
  `(defprog ,name (:type :tc :section "classifier" :license "GPL")
     ,(gr8s.network::service-packet-body-form body)))

(in-package #:gr8s.network)

(defun service-packet-map-forms ()
  "The canonical socket frontend/backend schemas plus packet-specific state."
  (append (remove-if-not
           (lambda (form) (member (symbol-name (second form))
                                  '("GR8S-SERVICE-V4" "GR8S-BACKEND-V4" "GR8S-BACKEND-INDEX-V4")
                                  :test #'equal))
           *service-lb-map-forms*)
          *service-packet-extra-map-forms*))

(defun service-packet-map-specs ()
  "Shared CNI map schemas, derived from the same forms the compiler consumes."
  (mapcar (lambda (form)
            (let ((options (cddr form)))
              (list (substitute #\_ #\- (string-downcase (symbol-name (second form))))
                    (whistler/compiler:resolve-map-type (getf options :type))
                    (getf options :key-size) (getf options :value-size)
                    (getf options :max-entries) (or (getf options :map-flags) 0))))
          (service-packet-map-forms)))

(defparameter *service-packet-stage-map-form*
  '(whistler::defmap whistler::gr8s-pkt-stages :type :prog-array
     :key-size 4 :value-size 4 :max-entries 8))

(defun service-packet-guard-forms ()
  "Compose a tail-call pipeline that preserves identity/policy/NAT ordering.
Each stage gets a fresh BPF stack. An unpopulated stage fails closed. The
ordinary guard source is immutable and still compiles without Service support."
  (let* ((anchor '(whistler::when
                   (/= (whistler::ntohl (whistler::ipv4-src-addr whistler::ip))
                       (whistler::load whistler::u32 whistler::identity 0))
                   (whistler::drop-pod-packet :spoof)))
         (replacements 0))
    (labels ((insert-forward (form)
               (cond ((and (consp form) (eq (car form) 'let)
                           (position anchor (cddr form) :test #'equal))
                      (incf replacements)
                      ;; Keep the canonical IPv4 validation prefix. Policy and
                      ;; delivery run in their own unmodified stage after NAT.
                      `(let ,(second form)
                         ,@(subseq (cddr form) 0 (1+ (position anchor (cddr form) :test #'equal)))
                         (whistler::tail-call whistler::gr8s-pkt-stages 0)
                         (return whistler::TC_ACT_SHOT)))
                     ((and (consp form) (eq (car form) 'cond)
                           (equal (caadr form) '(= whistler::protocol #x0800)))
                      ;; ARP, IPv6 and other traffic go straight to the complete
                      ;; canonical policy/identity guard, without a NAT stage.
                      `(cond ,(insert-forward (second form))
                             (t (whistler::tail-call whistler::gr8s-pkt-stages 1)
                                (return whistler::TC_ACT_SHOT))))
                     ((consp form) (mapcar #'insert-forward form))
                     (t form))))
      (let* ((forms (mapcar #'insert-forward *egress-guard-program-forms*))
             (ingress (find "GR8S-INGRESS-GUARD" forms
                            :key (lambda (form) (symbol-name (second form))) :test #'equal))
             (body (fourth ingress))
             (policy (copy-tree (first *egress-guard-program-forms*))))
        (unless (and (= replacements 1) ingress (eq (car body) 'let)
                     (equal (car (last body)) 'whistler::TC_ACT_OK))
          (error "Endpoint guard Service translation boundaries changed"))
        (setf (second policy) 'whistler::gr8s-egress-policy
              (car (last body))
              '(progn (whistler::tail-call whistler::gr8s-pkt-stages 2)
                      whistler::TC_ACT_SHOT))
        (append
         *service-packet-struct-forms* forms
         (list policy
               `(whistler::defprog whistler::gr8s-packet-forward
                    (:type :tc :section "classifier" :license "GPL")
                  ,(service-packet-body-form (service-packet-forward-form) :continue-guard t)
                  (whistler::tail-call whistler::gr8s-pkt-stages 1)
                  whistler::TC_ACT_SHOT)
               (service-packet-program-form 'whistler::gr8s-packet-reverse
                                            (service-packet-reverse-form))))))))

(defun compile-service-packet-lb ()
  "Compile the IPv4 TCP/UDP forward and reverse TC classifiers over shared maps."
  (compile-whistler-program
   (service-packet-map-forms)
   (append *service-packet-struct-forms*
           (list (service-packet-program-form 'whistler::gr8s-packet-forward
                                              (service-packet-forward-form))
                 (service-packet-program-form 'whistler::gr8s-packet-reverse
                                              (service-packet-reverse-form))))))

(defun compile-service-packet-gc ()
  "Compile maintenance against the exact packet flow/coordination schemas."
  (compile-whistler-program
   (service-packet-map-forms)
   (append *service-packet-struct-forms* (list (service-packet-gc-program-form)))))

(setf *service-packet-gc-program-forms*
      (append *service-packet-struct-forms* (list (service-packet-gc-program-form))))
