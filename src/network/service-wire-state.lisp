;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Per-key receiver-state collection; experimental, never attached.
(in-package #:whistler)

(defmacro wire-gc-invalid ()
  `(progn (pkt-unlock) (return 3)))

(defmacro wire-gc-known-row (row)
  `(unless (and (= (load u32 ,row 88) 1) (<= (load u32 ,row 92) 1))
     (wire-gc-invalid)))

(defmacro wire-gc-peer-identities-p (row)
  ;; Maintenance is global: there is no particular receiving endpoint_identity.
  `(and (wire-metadata-valid-p ,row) (= (load u8 ,row 5) 1)
        (wire-owner-matches-p (+ ,row 48) (+ ,row 16))
        (wire-owner-matches-p (+ ,row 52) (+ ,row 32))))

(defmacro wire-gc-collect-pair (visible incoming row)
  "Both tuple locks are held. WL serializes against outgoing wire selection."
  `(progn
     (wire-gc-known-row ,row)
     (wire-invert probe (+ ,row 64))
     (unless (and (wire-flow-equal-p probe ,visible)
                  (= (load u32 ,visible 0) (load u32 ,incoming 4))
                  (= (load u16 ,visible 8) (load u16 ,incoming 10))
                  (= (load u8 ,visible 12) (load u8 ,incoming 12)))
       (wire-gc-invalid))
     (setf wire-locked ,visible)
     (wire-take-candidate)
     (let ((index (map-lookup-ptr gr8s-nat-ri-v2 ,incoming))
           (paired u32 0))
       (when (and (/= index 0) (wire-flow-equal-p index ,visible))
         (setf paired 1))
       ;; An orphan or unfinished publication gets five seconds to recover.
       ;; Fully published TCP ownership lasts as long as established TCP NAT.
       (when (and (wire-gc-peer-identities-p ,row)
                  (<= (- now (load u64 ,row 80))
                      (if (and (= paired 1) (= (load u32 ,row 92) 1))
                          (if (= (load u8 ,row 14) 6) 7200000000000 180000000000)
                          5000000000)))
         (pkt-unlock) (return 0))
       ;; Delete only our matching index. Another tuple's index remains intact.
       ;; A helper failure can leave an orphan, which a later invocation repairs.
       (when (= paired 1)
         (when (/= (map-delete-ptr gr8s-nat-ri-v2 ,incoming) 0) (pkt-drop failed)))
       (when (/= (map-delete-ptr gr8s-nat-rx-v2 ,visible) 0) (pkt-drop failed))
       (pkt-unlock) (return 1))))

(defun gr8s.network::service-wire-gc-program-form ()
  "Private maintenance ABI: kind0 visible reply key, kind1 incoming wire key.
Both keys are16 bytes at36. Return0 live/absent,1 collected,2 contention/helper
failure,3 invalid/unknown schema. Never attach or inject this control packet."
  '(defprog gr8s-wire-gc (:type :tc :section "classifier" :license "GPL")
     (let ((input (make-gr8s-pkt-flow)) (other (make-gr8s-pkt-flow))
           (probe (make-gr8s-pkt-flow))
           (locked-forward (make-gr8s-pkt-flow)) (locked-reverse (make-gr8s-pkt-flow))
           (held-locks u32 0) (wire-held u32 0) (wire-locked u64 0) (failed u64 0)
           (now u64 (ktime-get-ns)) (data u64 (tc-data)) (data-end u64 (tc-data-end)))
       (when (> (+ data 52) data-end) (return 3))
       (unless (and (= (ctx u32 0) 52) (= (eth-type data) #x0800)
                    (= (load u8 data 14) #x45) (= (load u8 data 23) 253)
                    (<= (load u8 data 34) 1) (= (load u8 data 35) 0)) (return 3))
       (when (/= (skb-load-bytes (ctx-ptr) 36 input 16) 0) (return 3))
       (unless (and (= (gr8s-pkt-flow-pad0 input) 0) (= (gr8s-pkt-flow-pad1 input) 0)
                    (or (= (gr8s-pkt-flow-protocol input) 6)
                        (= (gr8s-pkt-flow-protocol input) 17))) (return 3))
       (if (= (load u8 data 34) 0)
           (progn
             (pkt-lock :forward input)
             (let ((row (map-lookup-ptr gr8s-nat-rx-v2 input)))
               (when (= row 0) (pkt-unlock) (return 0))
               (wire-gc-known-row row)
               (nat-copy other (+ row 48) 16)
               (pkt-lock :reverse other)
               (wire-gc-collect-pair input other row)))
           (progn
             (pkt-lock :reverse input)
             (let ((index (map-lookup-ptr gr8s-nat-ri-v2 input)))
               (when (= index 0) (pkt-unlock) (return 0))
               (nat-copy other index 16)
               (pkt-lock :forward other)
               (let ((row (map-lookup-ptr gr8s-nat-rx-v2 other)))
                 (when (/= row 0) (wire-gc-known-row row))
                 (if (or (= row 0) (not (wire-flow-equal-p (+ row 48) input)))
                     (progn
                       (when (/= (map-delete-ptr gr8s-nat-ri-v2 input) 0) (pkt-drop failed))
                       (pkt-unlock) (return 1))
                     (wire-gc-collect-pair other input row))))))
       (pkt-unlock) 0)))

(in-package #:gr8s.network)

(defun compile-service-wire-gc ()
  "Compile the standalone receiver collector with the exact wire graph map ABI."
  (let* ((*service-wire-locks-p* t)
         (forms (service-wire-guard-forms))
         (structs (remove-if (lambda (f) (eq (first f) 'whistler::defprog)) forms)))
    (compile-whistler-program
     (append (service-nat-guard-map-forms) *service-wire-rx-maps*)
     (append structs (list (expand-service-wire-form (service-wire-gc-program-form)))))))

(defun run-service-wire-gc-key (program-fd direction key)
  "Run one receiver transaction: direction0 visible reply,1 incoming wire."
  (check-type direction (integer 0 1))
  (unless (= (length key) 16) (error "Invalid receiver Service GC key width"))
  (run-service-gc-envelope program-fd direction key))

(defun sweep-service-wire-state
    (dataplane &key (budget 128) (next-key #'whistler/loader:map-get-next-key)
                   (run #'run-service-wire-gc-key))
  "Standalone receiver enumeration, at most BUDGET keys per map per tick.
The caller must verify retained writers and map/profile identities first.
The node agent does not invoke this experimental profile yet."
  (sweep-service-state-profile dataplane "gr8s_wire_gc"
                               '(("gr8s_nat_rx_v2" 0) ("gr8s_nat_ri_v2" 1))
                               budget next-key run))
