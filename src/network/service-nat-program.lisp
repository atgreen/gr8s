;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Staged IPv4 Service NAT engine, ABI v2. This is a standalone component until
;;;; policy canonicalization, legacy migration, GC and receiver readiness are
;;;; integrated. Existing attached v1 programs and their maps remain unchanged.
(in-package #:gr8s.network)

(defvar *service-nat-local-identity-p* nil
  "Bind while composing CNI guards to fence state against endpoint_identity48.
The standalone tuple engine has no local endpoint map and leaves this disabled.")

(defparameter *service-nat-map-forms*
  '((whistler::defmap whistler::gr8s-nat-fwd-v2 :type :hash
      :key-size 16 :value-size 64 :max-entries 65536 :map-flags 1)
    (whistler::defmap whistler::gr8s-nat-rev-v2 :type :hash
      :key-size 16 :value-size 32 :max-entries 65536 :map-flags 1)
    (whistler::defmap whistler::gr8s-nat-fl-v2 :type :hash
      :key-size 16 :value-size 8 :max-entries 65536 :map-flags 1)
    (whistler::defmap whistler::gr8s-nat-rl-v2 :type :hash
      :key-size 16 :value-size 8 :max-entries 65536 :map-flags 1)
    (whistler::defmap whistler::gr8s-nat-tcp-v2 :type :hash
      :key-size 32 :value-size 64 :max-entries 65536 :map-flags 1)
    ;; Primary and alias keys carry the same 128-bit endpoint incarnation.
    ;; flags: ABI2 in high16; enabled=1, complete direct history=2, receiver=4.
    ;; role: primary=1, alias=2. Programs cannot modify authoritative identities.
    (whistler::defmap whistler::gr8s-nat-id-v2 :type :hash
      :key-size 4 :value-size 32 :max-entries 65536 :map-flags 128)
    (whistler::defmap whistler::gr8s-nat-st-v2 :type :array
      :key-size 4 :value-size 8 :max-entries 7)))

(defparameter *service-nat-struct-forms*
  '((whistler::defstruct whistler::gr8s-nat-meta
      ;; L4 is prefix-compatible with gr8s-pkt-meta for checksum helpers.
      (whistler::l4 whistler::u32) (whistler::length whistler::u32))
    (whistler::defstruct whistler::gr8s-nat-state
      (whistler::backend whistler::u64) (whistler::seen whistler::u64)
      (whistler::epoch0 whistler::u64) (whistler::epoch1 whistler::u64)
      (whistler::wire-source whistler::u32) (whistler::wire-sport whistler::u16)
      ;; kind bit0: Service, bit1: source translated. active: policy committed.
      (whistler::kind whistler::u8) (whistler::active whistler::u8)
      (whistler::version whistler::u32) (whistler::backend-tracked whistler::u32)
      (whistler::backend-epoch0 whistler::u64) (whistler::backend-epoch1 whistler::u64))
    (whistler::defstruct whistler::gr8s-nat-return
      (whistler::key0 whistler::u64) (whistler::key1 whistler::u64)
      (whistler::epoch0 whistler::u64) (whistler::epoch1 whistler::u64))))

(defun expand-service-nat-form (form)
  "Reuse checked packet parsing/checksum/reservation macros with separate v2 maps.
Expand only PKT macros: ordinary Lisp/Whistler control forms must stay source."
  (let ((renames '((whistler::gr8s-pkt-tcp . whistler::gr8s-nat-tcp-v2)
                   (whistler::gr8s-pkt-forward . whistler::gr8s-nat-fwd-v2)
                   (whistler::gr8s-pkt-reverse . whistler::gr8s-nat-rev-v2)
                   (whistler::gr8s-pkt-fwd-lock . whistler::gr8s-nat-fl-v2)
                   (whistler::gr8s-pkt-rev-lock . whistler::gr8s-nat-rl-v2)
                   (whistler::gr8s-pkt-stats . whistler::gr8s-nat-st-v2))))
    (labels ((walk (value)
               (cond ((symbolp value) (or (cdr (assoc value renames)) value))
                     ((atom value) value)
                     ((and (symbolp (car value))
                           (or (alexandria:starts-with-subseq "PKT-" (symbol-name (car value)))
                               (alexandria:starts-with-subseq "NAT-" (symbol-name (car value))))
                           (macro-function (car value)))
                      (walk (macroexpand-1 value)))
                     (t (mapcar #'walk value)))))
      (walk form))))

(in-package #:whistler)

(defmacro nat-copy (destination source size)
  `(progn ,@(loop for offset from 0 below size by 8
                  collect `(store u64 ,destination ,offset (load u64 ,source ,offset)))))

(defmacro nat-context (key magic)
  `(progn ,@(loop for offset from 0 below 16 by 4
                  collect `(store u32 (ctx-ptr) ,(+ 48 offset) (load u32 ,key ,offset)))
          (store u32 (ctx-ptr) 64 ,magic)))

(defmacro nat-read-context (key)
  `(progn ,@(loop for offset from 0 below 16 by 4
                  collect `(store u32 ,key ,offset (ctx u32 ,(+ 48 offset))))))

(defmacro nat-clear-context ()
  `(progn ,@(loop for offset from 48 to 64 by 4 collect `(store u32 (ctx-ptr) ,offset 0))))

(defmacro nat-pass () `(progn (pkt-unlock) (return TC_ACT_OK)))

(defmacro nat-release-reverse ()
  `(progn
     (when (/= (logand held-locks 2) 0)
       (map-delete-ptr gr8s-pkt-rev-lock locked-reverse))
     (setf held-locks (logand held-locks 1))))

(defmacro nat-owner-p (owner address role)
  `(and (/= ,owner 0) (= (logand (load u32 ,owner 4) #xffff0000) #x20000)
        (= (load u32 ,owner 24) ,address) (= (load u32 ,owner 28) ,role)
        (/= (logior (load u64 ,owner 8) (load u64 ,owner 16)) 0)))

(defmacro nat-return-key (key original state)
  `(setf (gr8s-pkt-flow-source ,key) (cast u32 (load u64 ,state 0))
         (gr8s-pkt-flow-destination ,key) (load u32 ,state 32)
         (gr8s-pkt-flow-sport ,key) (cast u16 (>> (load u64 ,state 0) 32))
         (gr8s-pkt-flow-dport ,key) (load u16 ,state 36)
         (gr8s-pkt-flow-protocol ,key) (gr8s-pkt-flow-protocol ,original)
         (gr8s-pkt-flow-pad0 ,key) 0 (gr8s-pkt-flow-pad1 ,key) 0))

(defmacro nat-return-owned-p (entry original state)
  `(and (/= ,entry 0)
        (= (load u64 ,entry 0) (load u64 ,original 0))
        (= (load u64 ,entry 8) (load u64 ,original 8))
        (= (load u64 ,entry 16) (load u64 ,state 16))
        (= (load u64 ,entry 24) (load u64 ,state 24))))

(defmacro nat-tcp-key (key original state)
  `(progn (nat-copy ,key ,original 16)
          (store u64 ,key 16 (load u64 ,state 16))
          (store u64 ,key 24 (load u64 ,state 24))))

(defmacro nat-live-p (state original scratch)
  `(progn
     (nat-tcp-key ,scratch ,original ,state)
     (<= (- now (load u64 ,state 8))
         (if (= (load u8 ,state 39) 0) 5000000000
             (if (= (gr8s-pkt-flow-protocol ,original) 6)
                 (let ((tcp (map-lookup-ptr gr8s-nat-tcp-v2 ,scratch)))
                   (if (and (/= tcp 0) (= (load u64 tcp 0) (load u64 ,state 0)))
                       (pkt-lifetime ,original ,scratch) 7200000000000))
                 180000000000)))))

(defmacro nat-valid-state (state original scratch)
  "Validate both endpoint incarnations and any alias before touching a packet."
  `(let ((valid u32 0)
         (owner (map-lookup-ptr gr8s-nat-id-v2 ,original)))
     (when (and (nat-owner-p owner (gr8s-pkt-flow-source ,original) 1)
                (/= (logand (load u32 owner 4) 1) 0)
                (= (load u32 ,state 40) 2) (<= (load u8 ,state 38) 3)
                (<= (load u8 ,state 39) 1) (<= (load u32 ,state 44) 1)
                (= (load u64 ,state 16) (load u64 owner 8))
                (= (load u64 ,state 24) (load u64 owner 16)))
       (setf valid 1)
       (if (= (logand (load u8 ,state 38) 2) 0)
           (unless (and (= (load u32 ,state 32) (gr8s-pkt-flow-source ,original))
                        (= (load u16 ,state 36) (gr8s-pkt-flow-sport ,original)))
             (setf valid 0))
           (progn
             (when (or (= (load u32 owner 0) (gr8s-pkt-flow-source ,original))
                       (/= (load u32 owner 0) (load u32 ,state 32))) (setf valid 0))
             (let ((alias (map-lookup-ptr gr8s-nat-id-v2 (+ ,state 32))))
               (unless (and (nat-owner-p alias (gr8s-pkt-flow-source ,original) 2)
                            (/= (logand (load u32 alias 4) 1) 0)
                            (= (load u32 alias 0) (load u32 ,state 32))
                            (= (load u64 alias 8) (load u64 ,state 16))
                            (= (load u64 alias 16) (load u64 ,state 24)))
                 (setf valid 0)))))
       (when (/= (load u32 ,state 44) 0)
         (let ((backend (map-lookup-ptr gr8s-nat-id-v2 ,state)))
           (unless (and (nat-owner-p backend (cast u32 (load u64 ,state 0)) 1)
                        (= (load u64 backend 8) (load u64 ,state 48))
                        (= (load u64 backend 16) (load u64 ,state 56))
                        (or (= (logand (load u8 ,state 38) 2) 0)
                            (/= (logand (load u32 backend 4) 4) 0)))
             (setf valid 0))))
       ;; Active v2 TCP claims always have matching metadata. Losing it cannot
       ;; authorize midstream reconstruction as a legacy connection.
       (when (and (= (gr8s-pkt-flow-protocol ,original) 6)
                  (= (load u8 ,state 39) 1))
         (nat-tcp-key ,scratch ,original ,state)
         (let ((tcp (map-lookup-ptr gr8s-nat-tcp-v2 ,scratch)))
           (unless (and (/= tcp 0) (= (load u64 tcp 0) (load u64 ,state 0)))
             (setf valid 0))))
       (when (and (/= (load u8 ,state 38) 0) (= (load u32 ,state 44) 0))
         (setf valid 0)))
     valid))

(defmacro nat-same-source-incarnation (state original)
  `(let ((owner (map-lookup-ptr gr8s-nat-id-v2 ,original)))
     (and (nat-owner-p owner (gr8s-pkt-flow-source ,original) 1)
          (= (load u64 owner 8) (load u64 ,state 16))
          (= (load u64 owner 16) (load u64 ,state 24)))))

(defmacro nat-replaced-direct-peer-p (state original)
  "Only a proven new primary peer may invalidate an old, untranslated direct
claim. Service/alias claims, disabled identities and same-epoch metadata faults
must retain their fail-closed behavior. Caller holds both tuple reservations."
  `(let ((owner (map-lookup-ptr gr8s-nat-id-v2 ,original))
         (peer (map-lookup-ptr gr8s-nat-id-v2 ,state)))
     (and (= (load u32 ,state 40) 2) (= (load u8 ,state 38) 0)
          (<= (load u8 ,state 39) 1) (= (load u32 ,state 44) 1)
          (= (load u32 ,state 32) (gr8s-pkt-flow-source ,original))
          (= (load u16 ,state 36) (gr8s-pkt-flow-sport ,original))
          (nat-owner-p owner (gr8s-pkt-flow-source ,original) 1)
          (/= (logand (load u32 owner 4) 1) 0)
          (= (load u64 owner 8) (load u64 ,state 16))
          (= (load u64 owner 16) (load u64 ,state 24))
          (nat-owner-p peer (cast u32 (load u64 ,state 0)) 1)
          (/= (logand (load u32 peer 4) 1) 0)
          (or (/= (load u64 peer 8) (load u64 ,state 48))
              (/= (load u64 peer 16) (load u64 ,state 56))))))

(defmacro nat-local-profile-p ()
  (if gr8s.network::*service-nat-local-identity-p* 1 0))

(defmacro nat-local-source-p (original state)
  (if gr8s.network::*service-nat-local-identity-p*
      `(let ((local (map-lookup endpoint-identity 0)))
         (and (/= local 0)
              (or (= (load u32 local 12) 1) (= (load u32 local 12) 2))
              (= (ntohl (load u32 local 0)) (gr8s-pkt-flow-source ,original))
              (= (load u64 local 32) (load u64 ,state 16))
              (= (load u64 local 40) (load u64 ,state 24))))
      1))

(defmacro nat-retire (original state probe)
  `(progn
     (nat-return-key ,probe ,original ,state)
     (pkt-lock :reverse ,probe)
     (when-let ((entry (map-lookup-ptr gr8s-nat-rev-v2 ,probe)))
       (when (nat-return-owned-p entry ,original ,state)
         (when (/= (map-delete-ptr gr8s-nat-rev-v2 ,probe) 0) (pkt-drop failed))))
     ;; Return claim is already removed; reuse its scratch for the epoch key.
     (nat-tcp-key ,probe ,original ,state)
     (pkt-tcp-forget ,probe)
     (when (/= (map-delete-ptr gr8s-nat-fwd-v2 ,original) 0) (pkt-drop failed))
     (nat-release-reverse)))

(defmacro nat-pair-required (original state probe)
  `(progn
     (nat-return-key ,probe ,original ,state)
     (pkt-lock :reverse ,probe)
     (let ((entry (map-lookup-ptr gr8s-nat-rev-v2 ,probe)))
       (unless (nat-return-owned-p entry ,original ,state) (pkt-drop collision)))))

(defmacro nat-select-backend (original state scratch result)
  `(let ((key u64 (logior (<< (cast u64 (gr8s-pkt-flow-protocol ,original)) 48)
                         (logior (<< (cast u64 (gr8s-pkt-flow-destination ,original)) 16)
                                  (cast u64 (gr8s-pkt-flow-dport ,original))))))
     (setf (gr8s-nat-state-backend ,state)
           (logior (cast u64 (gr8s-pkt-flow-destination ,original))
                   (<< (cast u64 (gr8s-pkt-flow-dport ,original)) 32)))
     (when-let ((service (map-lookup gr8s-service-v4 key)))
       (let ((count u32 (load u16 service 0))
             (sticky u32 (load u16 service 2)) (timeout u64 (load u32 service 8))
             (offset u32 0) (base u32 (load u32 service 4))
             (selection u64 ,scratch))
         (when (= count 0) (pkt-drop empty))
         (setf offset (mod (get-prandom-u32) count)
               (gr8s-nat-state-kind ,state) 1
               (gr8s-pkt-pair-first selection) key
               (gr8s-pkt-pair-second selection) (cast u64 (gr8s-pkt-flow-source ,original)))
         (when (/= sticky 0)
           (when-let ((held (map-lookup-ptr gr8s-pkt-affinity selection)))
             (when (<= (- (/ now 1000000000) (load u64 held 8)) timeout)
               (setf (gr8s-pkt-pair-second selection) (load u64 held 0))
               (when-let ((index (map-lookup-ptr gr8s-backend-index-v4 selection)))
                 (when (< (load u32 index 0) count) (setf offset (load u32 index 0)))))))
         (setf (gr8s-nat-state-backend ,state) 0)
         (when-let ((backend (map-lookup gr8s-backend-v4 (+ base offset))))
           (setf (gr8s-nat-state-backend ,state) (load u64 backend 0)))
         (when (= (gr8s-nat-state-backend ,state) 0) (pkt-drop membership))
         (setf (gr8s-pkt-pair-second selection) (gr8s-nat-state-backend ,state))
         (when (= (map-lookup-ptr gr8s-backend-index-v4 selection) 0) (pkt-drop membership))
         ;; Affinity is selection metadata; it grants no tuple ownership.
         (when (/= sticky 0)
           (let ((value u64 ,result))
             (setf (gr8s-pkt-pair-second selection) (cast u64 (gr8s-pkt-flow-source ,original))
                   (gr8s-pkt-pair-first value) (gr8s-nat-state-backend ,state)
                   (gr8s-pkt-pair-second value) (/ now 1000000000))
             (map-update-ptr gr8s-pkt-affinity selection value 0)))))))

(defmacro nat-reserve-candidates (original state probe alias)
  "At most16 attempts. A source-preserving tuple is preferred, then private
alias ports. Only an identical original tuple/incarnation may adopt a claim."
  `(let ((claimed u32 0) (entry (make-gr8s-nat-return)))
     (setf (gr8s-nat-return-key0 entry) (load u64 ,original 0)
           (gr8s-nat-return-key1 entry) (load u64 ,original 8)
           (gr8s-nat-return-epoch0 entry) (load u64 ,state 16)
           (gr8s-nat-return-epoch1 entry) (load u64 ,state 24))
     ,@(loop for attempt below 16 collect
         `(when (= claimed 0)
            ,@(when (plusp attempt)
                `((if (= (logand (gr8s-nat-state-kind ,state) 2) 0)
                      (setf (gr8s-nat-state-kind ,state) (logior (gr8s-nat-state-kind ,state) 2)
                            (gr8s-nat-state-wire-source ,state) ,alias)
                      (setf (gr8s-nat-state-wire-sport ,state)
                            (ntohs (cast u16 (+ (ntohs (gr8s-nat-state-wire-sport ,state)) 1)))))))
            (when (and (/= (logand (gr8s-nat-state-kind ,state) 2) 0)
                       (= (gr8s-nat-state-wire-sport ,state) 0))
              (setf (gr8s-nat-state-wire-sport ,state) (ntohs 1)))
            (when (= (nat-valid-state ,state ,original ,probe) 0) (pkt-drop membership))
            (nat-return-key ,probe ,original ,state)
            (pkt-lock :reverse ,probe)
            (let ((existing (map-lookup-ptr gr8s-nat-rev-v2 ,probe)))
              (if (or (= existing 0) (nat-return-owned-p existing ,original ,state))
                  (progn
                    (when (/= (map-update-ptr gr8s-nat-rev-v2 ,probe entry 1) 0)
                      (let ((raced (map-lookup-ptr gr8s-nat-rev-v2 ,probe)))
                        (unless (nat-return-owned-p raced ,original ,state) (pkt-drop failed))))
                    (setf claimed 1))
                  (nat-release-reverse)))))
     (when (= claimed 0) (pkt-drop collision))))

(defun gr8s.network::service-nat-select-form ()
  '((nat-clear-context)
    ;; Same-node backend responses must not become fresh direct connections.
    ;; Reserve the wire return tuple before validating its original owner.
    (pkt-lock :reverse flow)
    ;; TARGET is idle after parsing and this early-return key is never needed
    ;; once normal selection starts. Reuse it to stay below the512-byte stack.
    (let ((original u64 target) (state (make-gr8s-nat-state))
          (probe (make-gr8s-nat-return)) (have u32 0) (alias u32 0) (owner-flags u32 0))
      (when-let ((entry (map-lookup-ptr gr8s-nat-rev-v2 flow)))
        (nat-copy original entry 16)
        (pkt-lock :forward original)
        (let ((held (map-lookup-ptr gr8s-nat-fwd-v2 original)))
          (when (= held 0) (pkt-drop failed))
          (nat-copy state held 64)
          (unless (and (nat-return-owned-p entry original state)
                       (nat-live-p state original probe) (= (gr8s-nat-state-active state) 1)
                       (/= (nat-valid-state state original probe) 0)) (pkt-drop failed))
          (nat-return-key probe original state)
          (unless (and (= (load u64 probe 0) (load u64 flow 0))
                       (= (load u64 probe 8) (load u64 flow 8))) (pkt-drop collision)))
        (nat-pass))
      (nat-release-reverse)
      (pkt-lock :forward flow)
      (when-let ((held (map-lookup-ptr gr8s-nat-fwd-v2 flow)))
        (nat-copy state held 64)
        (if (nat-live-p state flow probe)
            (if (/= (nat-valid-state state flow probe) 0)
                (setf have 1)
                ;; Revoking a receiver/alias or replacing a backend must not
                ;; silently retarget an active connection. A new source owner
                ;; may retire its predecessor's binding under paired locks.
                (if (nat-same-source-incarnation state flow)
                    (pkt-drop failed)
                    (nat-retire flow state probe)))
            (nat-retire flow state probe)))
      (when (= have 0)
        ;; A retired binding must not leave old kind/backend epochs in the new one.
        (setf (gr8s-nat-state-kind state) 0 (gr8s-nat-state-active state) 0
              (gr8s-nat-state-backend-tracked state) 0
              (gr8s-nat-state-backend-epoch0 state) 0 (gr8s-nat-state-backend-epoch1 state) 0
              (gr8s-nat-state-version state) 2 (gr8s-nat-state-seen state) now
              (gr8s-nat-state-wire-source state) (gr8s-pkt-flow-source flow)
              (gr8s-nat-state-wire-sport state) (gr8s-pkt-flow-sport flow))
        (nat-select-backend flow state probe target)
        (let ((owner (map-lookup-ptr gr8s-nat-id-v2 flow)))
          (unless (and (nat-owner-p owner (gr8s-pkt-flow-source flow) 1)
                       (/= (logand (load u32 owner 4) 1) 0))
            (when (or (/= (nat-local-profile-p) 0)
                      (/= (gr8s-nat-state-kind state) 0) (/= owner 0)) (pkt-drop membership))
            (nat-pass))
          (setf (gr8s-nat-state-epoch0 state) (load u64 owner 8)
                (gr8s-nat-state-epoch1 state) (load u64 owner 16)
                alias (load u32 owner 0) owner-flags (load u32 owner 4)))
        (unless (nat-local-source-p flow state) (pkt-drop failed))
        (let ((backend (map-lookup-ptr gr8s-nat-id-v2 state)))
          (when (nat-owner-p backend (cast u32 (gr8s-nat-state-backend state)) 1)
            (setf (gr8s-nat-state-backend-tracked state) 1
                  (gr8s-nat-state-backend-epoch0 state) (load u64 backend 8)
                  (gr8s-nat-state-backend-epoch1 state) (load u64 backend 16))))
        (when (and (/= (logand (gr8s-nat-state-kind state) 1) 0)
                   (or (= (logand owner-flags 2) 0)
                       (= (cast u32 (gr8s-nat-state-backend state)) (gr8s-pkt-flow-source flow))))
          (setf (gr8s-nat-state-kind state) 3 (gr8s-nat-state-wire-source state) alias))
        (nat-reserve-candidates flow state probe alias)
        (when (/= (map-update-ptr gr8s-nat-fwd-v2 flow state 1) 0) (pkt-drop failed)))
      (unless (nat-local-source-p flow state) (pkt-drop failed))
      (when (= (logand held-locks 2) 0) (nat-pair-required flow state probe))
      (when (/= (logand (gr8s-nat-state-kind state) 1) 0)
        (pkt-write-address flow state meta nil)
        (pkt-count requests))
      (nat-context flow #x47523801))))

(defun gr8s.network::service-nat-generation-form ()
  '((nat-clear-context)
    (unless (and (= (gr8s-pkt-flow-protocol flow) 6)
                 (= (logand (gr8s-pkt-meta-flags meta) 18) 2)) (nat-pass))
    (pkt-lock :reverse flow)
    (when (/= (map-lookup-ptr gr8s-nat-rev-v2 flow) 0) (nat-pass))
    (nat-release-reverse)
    (pkt-lock :forward flow)
    (let ((binding (map-lookup-ptr gr8s-nat-fwd-v2 flow))
          (tcp-key (make-gr8s-nat-return)) (probe (make-gr8s-pkt-flow)))
      (when (= binding 0) (nat-pass))
      ;; A suspended old endpoint must not retire a replacement's generation.
      ;; A new endpoint can leave its predecessor for select's safe retirement.
      (unless (nat-local-source-p flow binding) (nat-pass))
      ;; Old source epochs and expired pairs are retired by selection. For the
      ;; same source owner, only proven sequence/timestamp evidence can replace.
      (unless (and (nat-same-source-incarnation binding flow)
                   (nat-live-p binding flow tcp-key)) (nat-pass))
      (nat-pair-required flow binding probe)
      (nat-tcp-key tcp-key flow binding)
      (when (= (load u8 binding 39) 1)
        (let ((tcp (map-lookup-ptr gr8s-nat-tcp-v2 tcp-key)))
          (unless (and (/= tcp 0) (= (load u64 tcp 0) (load u64 binding 0)))
            (pkt-drop failed))))
      (setf (gr8s-pkt-pair-first target) (load u64 binding 0))
      (pkt-tcp-new-generation tcp-key (gr8s-pkt-pair-first target))
      (when (= (gr8s-pkt-pair-first target) 0)
        ;; The forward/TCP entries are gone; the return claim was checked while
        ;; both tuple reservations were held and cannot belong to another flow.
        (when (/= (map-delete-ptr gr8s-nat-rev-v2 probe) 0) (pkt-drop failed))))))

(defun gr8s.network::service-nat-commit-form ()
  '((when (= (ctx u32 64) 0) (nat-pass))
    (when (/= (ctx u32 64) #x47523801) (pkt-drop failed))
    (let ((original (make-gr8s-pkt-flow)) (state u64 0) (probe (make-gr8s-nat-return)))
      (nat-read-context original)
      (pkt-lock :forward original)
      (let ((held (map-lookup-ptr gr8s-nat-fwd-v2 original)))
        (when (= held 0) (pkt-drop failed)) (setf state held))
      (unless (nat-local-source-p original state) (pkt-drop failed))
      (unless (and (nat-live-p state original probe) (/= (nat-valid-state state original probe) 0)
                   (= (gr8s-pkt-flow-source flow) (gr8s-pkt-flow-source original))
                   (= (gr8s-pkt-flow-sport flow) (gr8s-pkt-flow-sport original))
                   (= (gr8s-pkt-flow-destination flow) (cast u32 (gr8s-nat-state-backend state)))
                   (= (gr8s-pkt-flow-dport flow) (cast u16 (>> (gr8s-nat-state-backend state) 32)))
                   (= (gr8s-pkt-flow-protocol flow) (gr8s-pkt-flow-protocol original)))
        (pkt-drop failed))
      (nat-pair-required original state probe)
      (let ((selected-backend u64 (load u64 state 0)))
        (nat-tcp-key probe original state)
        (pkt-tcp-observe probe selected-backend nil))
      (when (/= (logand (gr8s-nat-state-kind state) 2) 0)
        (setf (gr8s-pkt-pair-first target)
              (logior (cast u64 (gr8s-nat-state-wire-source state))
                      (<< (cast u64 (gr8s-nat-state-wire-sport state)) 32)))
        (pkt-write-address flow target meta t))
      (setf (gr8s-nat-state-active state) 1 (gr8s-nat-state-seen state) now)
      (nat-clear-context))))

(defun gr8s.network::service-nat-prepare-form ()
  '((nat-clear-context)
    (pkt-lock :reverse flow)
    (let ((entry (map-lookup-ptr gr8s-nat-rev-v2 flow)))
      (when (= entry 0)
        (let ((destination (map-lookup-ptr gr8s-nat-id-v2 (+ flow 4))))
          (when (and (/= destination 0) (= (load u32 destination 28) 2)) (pkt-drop failed)))
        (nat-pass))
      (let ((original (make-gr8s-pkt-flow)) (state (make-gr8s-nat-state)) (probe (make-gr8s-nat-return)))
        (nat-copy original entry 16)
        (pkt-lock :forward original)
        (let ((held (map-lookup-ptr gr8s-nat-fwd-v2 original)))
          (when (= held 0) (pkt-drop failed)) (nat-copy state held 64))
        (unless (nat-local-source-p original state) (pkt-drop failed))
        (unless (nat-return-owned-p entry original state) (pkt-drop failed))
        (nat-return-key probe original state)
        (unless (and (= (load u64 probe 0) (load u64 flow 0))
                     (= (load u64 probe 8) (load u64 flow 8))) (pkt-drop collision))
        ;; A backend on another node observes its replies as direct outbound
        ;; traffic. After client IP reuse that direct claim belongs to a peer
        ;; incarnation which is permanently gone. Remove only this owned pair
        ;; before normal ingress policy, so a replacement SYN/datagram can reach
        ;; the backend. Nothing here authorizes it or seeds a reply exception.
        ;; Both reservations are already held: do not try to acquire them again.
        (when (nat-replaced-direct-peer-p state original)
          (when (/= (map-delete-ptr gr8s-nat-rev-v2 flow) 0) (pkt-drop failed))
          (nat-tcp-key probe original state)
          (pkt-tcp-forget probe)
          (when (/= (map-delete-ptr gr8s-nat-fwd-v2 original) 0) (pkt-drop failed))
          (nat-pass))
        (unless (and (nat-live-p state original probe)
                     (/= (nat-valid-state state original probe) 0)) (pkt-drop failed))
        (when (= (gr8s-nat-state-active state) 0)
          ;; An egress-denied direct packet may have reserved this plain tuple.
          ;; It provides no translation or reply authorization. Let incoming
          ;; traffic reach ingress policy without observing/refreshing the claim;
          ;; pending Service/alias claims still cannot admit translated replies.
          (unless (= (gr8s-nat-state-kind state) 0) (pkt-drop failed))
          (nat-pass))
        (when (/= (logand (gr8s-nat-state-kind state) 2) 0)
          (setf (gr8s-pkt-pair-first target)
                (logior (cast u64 (gr8s-pkt-flow-source original))
                        (<< (cast u64 (gr8s-pkt-flow-sport original)) 32)))
          (pkt-write-address flow target meta nil))
        (nat-context original #x47523802)))))

(defun gr8s.network::service-nat-restore-form ()
  '((when (= (ctx u32 64) 0) (nat-pass))
    (when (/= (ctx u32 64) #x47523802) (pkt-drop failed))
    (let ((original (make-gr8s-pkt-flow)) (state u64 0) (probe (make-gr8s-nat-return)))
      (nat-read-context original)
      (pkt-lock :forward original)
      (let ((held (map-lookup-ptr gr8s-nat-fwd-v2 original)))
        (when (= held 0) (pkt-drop failed)) (setf state held))
      (unless (nat-local-source-p original state) (pkt-drop failed))
      (unless (and (nat-live-p state original probe) (= (gr8s-nat-state-active state) 1)
                   (/= (nat-valid-state state original probe) 0)
                   (= (gr8s-pkt-flow-source flow) (cast u32 (gr8s-nat-state-backend state)))
                   (= (gr8s-pkt-flow-sport flow) (cast u16 (>> (gr8s-nat-state-backend state) 32)))
                   (= (gr8s-pkt-flow-destination flow) (gr8s-pkt-flow-source original))
                   (= (gr8s-pkt-flow-dport flow) (gr8s-pkt-flow-sport original))
                   (= (gr8s-pkt-flow-protocol flow) (gr8s-pkt-flow-protocol original)))
        (pkt-drop failed))
      (nat-pair-required original state probe)
      (let ((selected-backend u64 (load u64 state 0)))
        (nat-tcp-key probe original state)
        (pkt-tcp-observe probe selected-backend t))
      (when (/= (logand (gr8s-nat-state-kind state) 1) 0)
        (setf (gr8s-pkt-pair-first target)
              (logior (cast u64 (gr8s-pkt-flow-destination original))
                      (<< (cast u64 (gr8s-pkt-flow-dport original)) 32)))
        (pkt-write-address flow target meta t)
        (pkt-count replies))
      (setf (gr8s-nat-state-seen state) now)
      (nat-clear-context))))

(defun gr8s.network::service-nat-program-form (name body)
  "Compact parsing for selection/preparation. Generation and policy-approved
commit/restore use the full TCP parser and incarnation-keyed lifecycle tracker."
  `(defprog ,name (:type :tc :section "classifier" :license "GPL")
     (let ((requests (map-lookup gr8s-pkt-stats 0)) (replies (map-lookup gr8s-pkt-stats 1))
           (empty (map-lookup gr8s-pkt-stats 2)) (membership (map-lookup gr8s-pkt-stats 3))
           (collision (map-lookup gr8s-pkt-stats 4)) (failed (map-lookup gr8s-pkt-stats 5))
           (malformed (map-lookup gr8s-pkt-stats 6)) (now u64 (ktime-get-ns)))
       (let ((flow (make-gr8s-pkt-flow)) (target (make-gr8s-pkt-pair)) (meta (make-gr8s-nat-meta))
             (locked-forward (make-gr8s-pkt-flow)) (locked-reverse (make-gr8s-pkt-flow))
             (held-locks u32 0) (data u64 (tc-data)) (data-end u64 (tc-data-end)))
         (when (> (+ data 14) data-end) (pkt-drop malformed))
         (when (/= (eth-type data) #x0800) (return TC_ACT_OK))
         (when (> (+ data 34) data-end) (pkt-drop malformed))
         (when (or (/= (logand (load u8 data 14) #xf0) #x40)
                   (< (logand (load u8 data 14) 15) 5)) (pkt-drop malformed))
         (when (/= (logand (ntohs (load u16 data 20)) #x3fff) 0) (return TC_ACT_OK))
         (when (and (/= (load u8 data 23) 6) (/= (load u8 data 23) 17)) (return TC_ACT_OK))
         (setf (gr8s-nat-meta-l4 meta) (+ 14 (* (logand (load u8 data 14) 15) 4)))
         (when (or (> (+ (gr8s-nat-meta-l4 meta) (if (= (load u8 data 23) 6) 20 8)) (ctx u32 0))
                   (< (ntohs (load u16 data 16))
                      (+ (- (gr8s-nat-meta-l4 meta) 14) (if (= (load u8 data 23) 6) 20 8)))
                   (> (+ 14 (ntohs (load u16 data 16))) (ctx u32 0))) (pkt-drop malformed))
         (setf (gr8s-nat-meta-length meta) (- (ntohs (load u16 data 16)) (- (gr8s-nat-meta-l4 meta) 14))
               (gr8s-pkt-flow-source flow) (load u32 data 26)
               (gr8s-pkt-flow-destination flow) (load u32 data 30)
               (gr8s-pkt-flow-protocol flow) (load u8 data 23))
         (when (/= (skb-load-bytes (ctx-ptr) (gr8s-nat-meta-l4 meta) (+ flow 8) 4) 0)
           (pkt-drop malformed))
         (when (= (gr8s-pkt-flow-protocol flow) 6)
           (when (/= (skb-load-bytes (ctx-ptr) (+ (gr8s-nat-meta-l4 meta) 12) target 2) 0)
             (pkt-drop malformed))
           (let ((header u32 (* (>> (load u8 target 0) 4) 4)))
             (when (or (< header 20) (> header (gr8s-nat-meta-length meta))) (pkt-drop malformed)))
           (when (and (/= (logand (load u8 target 1) 2) 0)
                      (/= (logand (load u8 target 1) 5) 0)) (pkt-drop malformed)))
         (setf (gr8s-pkt-pair-first target) 0 (gr8s-pkt-pair-second target) 0)
         ,@body
         (pkt-unlock)
         TC_ACT_OK))))

(defmacro nat-gc-retire (original state wire scratch)
  "Caller owns both tuple reservations. Copy identity before removing its map row."
  `(progn
     (nat-tcp-key ,scratch ,original ,state)
     (when-let ((entry (map-lookup-ptr gr8s-nat-rev-v2 ,wire)))
       (when (nat-return-owned-p entry ,original ,state)
         (when (/= (map-delete-ptr gr8s-nat-rev-v2 ,wire) 0) (pkt-drop failed))))
     (pkt-tcp-forget ,scratch)
     (when (/= (map-delete-ptr gr8s-nat-fwd-v2 ,scratch) 0) (pkt-drop failed))
     (setf changed 1)))

(defun gr8s.network::service-nat-gc-program-form ()
  "Maintenance only, never attached. Kind at34, key at36: forward0/reverse1 use
16-byte tuples; TCP2 uses32-byte incarnation keys. Return0 unchanged,1 reclaimed,
2 contention/helper failure,3 invalid envelope. One key per bounded invocation."
  '(defprog gr8s-nat-gc (:type :tc :section "classifier" :license "GPL")
     (let ((input (make-gr8s-nat-return)) (probe (make-gr8s-pkt-flow))
           (scratch (make-gr8s-nat-return))
           (locked-forward (make-gr8s-pkt-flow)) (locked-reverse (make-gr8s-pkt-flow))
           (held-locks u32 0) (changed u32 0) (failed u64 0)
           (now u64 (ktime-get-ns)) (data u64 (tc-data)) (data-end u64 (tc-data-end)))
       (when (> (+ data 52) data-end) (return 3))
       (let ((kind u32 (load u8 data 34)))
         (when (> kind 2) (return 3))
         (when (and (= kind 2) (> (+ data 68) data-end)) (return 3))
         (when (/= (skb-load-bytes (ctx-ptr) 36 input (if (= kind 2) 32 16)) 0) (return 3))
         (when (or (/= (gr8s-pkt-flow-pad0 input) 0) (/= (gr8s-pkt-flow-pad1 input) 0)
                   (and (/= (gr8s-pkt-flow-protocol input) 6)
                        (/= (gr8s-pkt-flow-protocol input) 17))) (return 3))
         (cond
           ((= kind 0)
            (pkt-lock :forward input)
            (when-let ((held (map-lookup-ptr gr8s-nat-fwd-v2 input)))
              (unless (nat-live-p held input scratch)
                (nat-return-key probe input held)
                (pkt-lock :reverse probe)
                (nat-gc-retire input held probe scratch))))
           ((= kind 1)
            (pkt-lock :reverse input)
            (when-let ((entry (map-lookup-ptr gr8s-nat-rev-v2 input)))
              (pkt-lock :forward entry)
              (let ((held (map-lookup-ptr gr8s-nat-fwd-v2 entry)))
                (if (= held 0)
                    (progn
                      (pkt-tcp-forget entry)
                      (when (/= (map-delete-ptr gr8s-nat-rev-v2 input) 0) (pkt-drop failed))
                      (setf changed 1))
                    (progn
                      (nat-return-key probe entry held)
                      (if (and (nat-return-owned-p entry entry held)
                               (= (load u64 probe 0) (load u64 input 0))
                               (= (load u64 probe 8) (load u64 input 8)))
                          (unless (nat-live-p held entry scratch)
                            (nat-gc-retire entry held input scratch))
                          (progn
                            ;; A replacement in the same source epoch shares
                            ;; its TCP key: an obsolete reverse row cannot erase it.
                            (unless (and (= (load u64 entry 16) (load u64 held 16))
                                         (= (load u64 entry 24) (load u64 held 24)))
                              (pkt-tcp-forget entry))
                            (when (/= (map-delete-ptr gr8s-nat-rev-v2 input) 0) (pkt-drop failed))
                            (setf changed 1))))))))
           (t
            (when (or (/= (gr8s-pkt-flow-protocol input) 6)
                      (= (logior (load u64 input 16) (load u64 input 24)) 0)) (return 3))
            (pkt-lock :forward input)
            (when-let ((tcp (map-lookup-ptr gr8s-nat-tcp-v2 input)))
              (let ((held (map-lookup-ptr gr8s-nat-fwd-v2 input)))
                (if (or (= held 0) (/= (load u64 input 16) (load u64 held 16))
                        (/= (load u64 input 24) (load u64 held 24)))
                    (progn (pkt-tcp-forget input) (setf changed 1))
                    (unless (nat-live-p held input scratch)
                      (nat-return-key probe input held)
                      (pkt-lock :reverse probe)
                      (nat-gc-retire input held probe scratch))))))))
       (if (= changed 0)
           (progn (pkt-unlock) (return 0))
           (progn (pkt-unlock) (return 1))))))

(in-package #:gr8s.network)

(defun compile-service-nat ()
  "Standalone v2 graph: generation precedes select, policy separates select/commit
and prepare/restore. Maintenance runs only through test-run, never attachment.
These maps/programs are not yet installed by the agent."
  (compile-whistler-program
   (append (subseq (service-packet-map-forms) 0 3)
           (list (find 'whistler::gr8s-pkt-affinity *service-packet-extra-map-forms* :key #'second))
           *service-nat-map-forms*)
   (append *service-packet-struct-forms* *service-nat-struct-forms*
           (loop for (name body) in
                  (list (list 'whistler::gr8s-nat-generation (service-nat-generation-form))
                        (list 'whistler::gr8s-nat-select (service-nat-select-form))
                        (list 'whistler::gr8s-nat-commit (service-nat-commit-form))
                        (list 'whistler::gr8s-nat-prepare (service-nat-prepare-form))
                        (list 'whistler::gr8s-nat-restore (service-nat-restore-form)))
                 collect (expand-service-nat-form
                          (if (member name '(whistler::gr8s-nat-generation whistler::gr8s-nat-commit
                                              whistler::gr8s-nat-restore))
                              (service-packet-program-form name body)
                              (service-nat-program-form name body))))
           (list (expand-service-nat-form (service-nat-gc-program-form))))))
