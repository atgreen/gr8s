;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Packet Service translation for clients whose sockets live in another kernel.
;;;; Service/backend/membership maps have exactly the socket LB's schema. Flow
;;;; state is node-wide: a backend stays selected for an established flow even
;;;; while EndpointSlices change. The reverse path validates the forward entry
;;;; before using a reverse entry, so interrupted two-map publication fails closed.

(in-package #:whistler)

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
    ;; Requests, replies, no endpoints, invalid membership, tuple collision,
    ;; failed map/checksum/header writes, malformed packets.
    (defmap gr8s-pkt-stats :type :array
      :key-size 4 :value-size 8 :max-entries 7)))

(defparameter gr8s.network::*service-packet-struct-forms*
  '((defstruct gr8s-pkt-pair (first u64) (second u64))
    (defstruct gr8s-pkt-flow
      (source u32) (destination u32) (sport u16) (dport u16)
      (protocol u8) (pad0 u8) (pad1 u16))
    (defstruct gr8s-pkt-meta (l4 u32))))

(defmacro pkt-count (pointer)
  `(when (/= ,pointer 0) (atomic-add ,pointer 0 1)))

(defmacro pkt-unlock ()
  ;; Try-locks are transient map reservations, never persistent flow state.
  ;; Always release both on every success/drop path; no packet waits on a lock.
  `(progn
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

(defmacro pkt-lifetime (flow)
  `(if (= (gr8s-pkt-flow-protocol ,flow) 6) 7200000000000 180000000000))

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
            (setf (gr8s-pkt-pair-first target) (load u64 held 0))
            ;; Under the tuple reservation no packet/collector can refresh or
            ;; republish this key between expiration and NOEXIST insertion.
            (when (/= (map-delete-ptr gr8s-pkt-forward flow) 0) (pkt-drop failed))))
      (when (= (gr8s-pkt-pair-first target) 0)
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
              (when (/= (map-update-ptr gr8s-pkt-forward flow target 1) 0)
                (pkt-drop failed))
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
        (setf (gr8s-pkt-pair-second target) now)
        (when (/= (map-update-ptr gr8s-pkt-forward flow target 0) 0)
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
          (when (> (- now (load u64 held 8)) (pkt-lifetime flow)) (pkt-drop failed))
          (when (/= (load u64 held 0)
                    (logior (cast u64 (gr8s-pkt-flow-source flow))
                             (<< (cast u64 (gr8s-pkt-flow-sport flow)) 32)))
            (pkt-drop collision))
          (let ((refreshed (make-gr8s-pkt-pair)))
            (setf (gr8s-pkt-pair-first refreshed) (load u64 held 0)
                  (gr8s-pkt-pair-second refreshed) now)
            (when (/= (map-update-ptr gr8s-pkt-forward locked-forward refreshed 0) 0)
              (pkt-drop failed)))))
      (pkt-write-address flow target meta t)
      (pkt-count replies))))

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
           (locked-forward (make-gr8s-pkt-flow)) (locked-reverse (make-gr8s-pkt-flow))
           (held-locks u32 0)
           (data u64 (tc-data)) (data-end u64 (tc-data-end)))
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
               TC_ACT_OK)))))

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
