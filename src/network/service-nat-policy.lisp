;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; IPv4 alias-aware policy forms compose into the opted-in v2 TC graph.
;;;; Preserve canonical rule compilation, but keep wire tuples and peer epochs
;;;; in a separate reply table. The 48-byte local identity rejects old adopters.
(in-package #:gr8s.network)

(defparameter *service-nat-pod-map-form*
  '(whistler::defmap whistler::gr8s-nat-pod-v2 :type :lpm-trie
     :key-size 8 :value-size 1 :max-entries 4096 :map-flags 129))

(defun publish-service-nat-managed-cidrs
    (map cidrs &key (update #'whistler/loader:map-update))
  "Mark every IPv4 cluster Pod CIDR as managed before a v2 policy may use it.
An identity-map miss for any address in these ranges must fail closed, including
an alias whose owner is temporarily absent from a replicated snapshot. Retain
previous CIDRs while old endpoints may still have live flows."
  (let ((present (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))
        (count 0))
    (dolist (cidr cidrs count)
      (unless (find #\: cidr)
        (funcall update map (netpol-cidr-lpm-key cidr) present)
        (incf count)))))

(defun service-nat-identity-pair
    (node-id sandbox-id interface-name primary alias)
  "Encode both owner rows from one Pod incarnation. The local agent uses its
trusted IPAM lease; the replicated inventory uses an authenticated Pod claim.
Only the enabled bit is staged: attachment publishes local receiver readiness,
while complete history and cluster-wide receiver proof need further fences."
  (flet ((address-key (address)
           (let ((number (canonical-service-translation-ipv4 address)))
             (make-array 4 :element-type '(unsigned-byte 8)
                         :initial-contents
                         (list (ldb (byte 8 24) number) (ldb (byte 8 16) number)
                               (ldb (byte 8 8) number) (ldb (byte 8 0) number))))))
   (let* ((primary-key (address-key primary))
         (alias-key (address-key alias))
         (epoch (service-translation-incarnation-token
                 node-id sandbox-id interface-name primary alias))
         (flags (service-lb-bytes #x20001 4)))
    (unless (and (not (equalp primary-key alias-key))
                 (some #'plusp epoch))
      (invalid-cni "invalid v2 Service translation identity"))
    (flet ((value (role)
             (concatenate '(vector (unsigned-byte 8))
                          alias-key flags epoch primary-key (service-lb-bytes role 4))))
      (list (cons primary-key (value 1)) (cons alias-key (value 2)))))))

(defun service-nat-identity-rows (record)
  "Encode the authenticated primary/alias pair from replicated inventory."
  (service-nat-identity-pair
   (service-translation-string record "nodeID")
   (service-translation-string record "sandboxID")
   (service-translation-string record "interfaceName")
   (service-translation-string record "podIP")
   (service-translation-string record "address")))

(defun cni-service-nat-owner-map-path (configuration)
  (unless (eq (cni-service-profile configuration) :v2)
    (invalid-cni "local v2 Service owner map requires the v2 profile"))
  (namestring (merge-pathnames
               "gr8s_nat_id_v2"
               (uiop:ensure-directory-pathname
                (cni-configuration-service-packet-root configuration)))))

(defun service-nat-owner-row-matches-p (actual expected)
  "Accept the two readiness bits added after publication, but require the
same enabled ABI-v2 owner, address pair, epoch, and role."
  (and (typep actual '(simple-array (unsigned-byte 8) (*)))
       (= 32 (length actual))
       (= #x20001 (logand (netlink-read-integer actual 4 4) #xfffffff9))
       (equalp (subseq actual 0 4) (subseq expected 0 4))
       (equalp (subseq actual 8 32) (subseq expected 8 32))))

(defvar *service-nat-owner-publication-lock*
  (bt:make-lock "gr8s v2 Service owner publication")
  "Serialize local and replicated owner updates with receiver readiness writes.")

(defvar *service-nat-owner-lifecycle-lock*
  (bt:make-lock "gr8s v2 Service owner lifecycle")
  "Keep snapshot owner publication out of CNI DEL until its links are gone.")

(defun publish-service-nat-owner-pair
    (map rows &key (lookup #'whistler/loader:map-lookup)
                   (update #'whistler/loader:map-update)
                   (preserve-readiness t))
  "Preserve readiness only when both pinned rows still name this incarnation.
Replacement, a missing half, or an invalid ABI clears readiness on both rows.
All publishers and future readiness-bit writers must hold this lock."
  (bt:with-lock-held (*service-nat-owner-publication-lock*)
    (let* ((old (mapcar (lambda (row) (funcall lookup map (car row))) rows))
           (same-pair (and preserve-readiness
                           (every #'service-nat-owner-row-matches-p old
                                  (mapcar #'cdr rows)))))
      ;; Publish alias first so a newly visible primary cannot rely on an old
      ;; alias row. A transient mismatch drops packets in the v2 graph.
      (dolist (row (reverse rows))
        (let* ((index (if (equalp (car row) (caar rows)) 0 1))
               (old-value (nth index old))
               (value (copy-seq (cdr row)))
               (readiness (if same-pair
                              (logand (netlink-read-integer old-value 4 4) #x6)
                              0)))
          (replace value (service-lb-bytes (logior #x20001 readiness) 4) :start1 4)
          (funcall update map (car row) value)))
      2)))

(defun withdraw-service-nat-owner-pair
    (map rows &key (lookup #'whistler/loader:map-lookup)
                   (update #'whistler/loader:map-update))
  "Disable this incarnation's rows before its Pod lease and link are removed.
Keep tombstones for future flow-aware GC; never alter a replacement owner."
  (bt:with-lock-held (*service-nat-owner-publication-lock*)
    (let ((count 0))
      (dolist (row rows count)
        (let ((actual (funcall lookup map (car row))))
          (when (service-nat-owner-row-matches-p actual (cdr row))
            (let ((disabled (copy-seq actual)))
              (replace disabled (service-lb-bytes #x20000 4) :start1 4)
              (funcall update map (car row) disabled)
              (incf count))))))))

(defun clear-service-nat-owner-readiness
    (map &key (next-key #'whistler/loader:map-get-next-key)
              (lookup #'whistler/loader:map-lookup)
              (update #'whistler/loader:map-update))
  "Clear readiness on every retained owner row before a restarted node serves
traffic. The owner map may survive while a history or receiver map is lost."
  (bt:with-lock-held (*service-nat-owner-publication-lock*)
    (let ((count 0) (keys nil))
      (loop for key = (funcall next-key map nil) then (funcall next-key map key)
            while key do (push (copy-seq key) keys))
      (dolist (key keys)
        (let ((value (funcall lookup map key)))
          (when (and (typep value '(simple-array (unsigned-byte 8) (32)))
                     (/= (logand (netlink-read-integer value 4 4) #x6) 0))
            (let ((cleared (copy-seq value)))
              (replace cleared
                       (service-lb-bytes
                        (logand (netlink-read-integer value 4 4) #xfffffff9) 4)
                       :start1 4)
              (funcall update map key cleared)
              (incf count)))))
      count)))

(defun publish-cni-service-nat-owner
    (configuration context addresses alias
     &key (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (lookup #'whistler/loader:map-lookup)
          (update #'whistler/loader:map-update)
          (close #'sb-posix:close))
  "Stage this node's paired owner rows in the schema-checked shared v2 map.
The return route must already exist. A failed or partial update stops CNI ADD;
the attachment fence keeps incomplete owner state out of the live datapath."
  (let* ((primary (find-if-not (lambda (address) (find #\: address)) addresses))
         (rows (service-nat-identity-pair
                (cni-configuration-service-node-id configuration)
                (cni-context-container-id context) (cni-context-interface-name context)
                primary alias))
         (path (cni-service-nat-owner-map-path configuration))
         (fd (funcall open path)))
    (unwind-protect
         (let ((map (funcall map-info fd "gr8s_nat_id_v2" :profile :v2)))
           (publish-service-nat-owner-pair map rows :lookup lookup :update update)
           rows)
      (funcall close fd))))

(defun mark-service-nat-owner-receiver-ready
    (map rows &key (lookup #'whistler/loader:map-lookup)
                   (update #'whistler/loader:map-update))
  "Publish receiver readiness only for the exact enabled owner pair. The
  primary row is written last, so a partial update cannot advertise a ready
  backend before its matching alias row is ready."
  (bt:with-lock-held (*service-nat-owner-publication-lock*)
    (let ((actual (mapcar (lambda (row) (funcall lookup map (car row))) rows)))
      (unless (every #'service-nat-owner-row-matches-p actual (mapcar #'cdr rows))
        (invalid-cni "v2 Service receiver owner pair changed during attachment"))
      (loop for row in (reverse rows)
            for value in (reverse actual)
            do (let ((ready (copy-seq value)))
                 (replace ready
                          (service-lb-bytes
                           (logior (netlink-read-integer ready 4 4) #x4) 4)
                          :start1 4)
                 (funcall update map (car row) ready)))
      2)))

(defun mark-cni-service-nat-receiver-ready
    (configuration context addresses alias
     &key (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (lookup #'whistler/loader:map-lookup)
          (update #'whistler/loader:map-update)
          (close #'sb-posix:close))
  "Mark a native endpoint ready only after CNI attached both v2 TCX guards."
  (let* ((rows (service-nat-identity-pair
                (cni-configuration-service-node-id configuration)
                (cni-context-container-id context) (cni-context-interface-name context)
                (find-if-not (lambda (address) (find #\: address)) addresses) alias))
         (fd (funcall open (cni-service-nat-owner-map-path configuration))))
    (unwind-protect
         (mark-service-nat-owner-receiver-ready
          (funcall map-info fd "gr8s_nat_id_v2" :profile :v2) rows
          :lookup lookup :update update)
      (funcall close fd))))

(defun withdraw-cni-service-nat-owner
    (configuration context addresses alias
     &key (path-exists-p #'probe-file)
          (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (lookup #'whistler/loader:map-lookup)
          (update #'whistler/loader:map-update)
          (close #'sb-posix:close))
  "Disable a CNI-owned v2 pair on DEL, including a partially failed ADD.
Missing pins are harmless; matching rows are left as disabled tombstones."
  (let ((path (cni-service-nat-owner-map-path configuration)))
    (when (funcall path-exists-p path)
      (let ((rows (service-nat-identity-pair
                   (cni-configuration-service-node-id configuration)
                   (cni-context-container-id context) (cni-context-interface-name context)
                   (find-if-not (lambda (address) (find #\: address)) addresses)
                   alias))
            (fd (funcall open path)))
        (unwind-protect
             (withdraw-service-nat-owner-pair
              (funcall map-info fd "gr8s_nat_id_v2" :profile :v2) rows
              :lookup lookup :update update)
          (funcall close fd)))))
  nil)

(defun check-cni-service-nat-owner
    (configuration context addresses alias
     &key (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (lookup #'whistler/loader:map-lookup)
          (close #'sb-posix:close))
  "CHECK rejects a missing, disabled, mismatched, or stale owner pair before
reporting the retained v2 endpoint healthy. It never creates owner rows."
  (let* ((primary (find-if-not (lambda (address) (find #\: address)) addresses))
         (rows (service-nat-identity-pair
                (cni-configuration-service-node-id configuration)
                (cni-context-container-id context) (cni-context-interface-name context)
                primary alias))
         (fd (funcall open (cni-service-nat-owner-map-path configuration))))
    (unwind-protect
         (let ((map (funcall map-info fd "gr8s_nat_id_v2" :profile :v2)))
           (dolist (row rows)
             (unless (service-nat-owner-row-matches-p
                      (funcall lookup map (car row)) (cdr row))
               (invalid-cni "v2 Service endpoint owner pair is missing or stale"))))
      (funcall close fd)))
  nil)

(defun publish-service-nat-identities
    (map records &key (lookup #'whistler/loader:map-lookup)
                      (update #'whistler/loader:map-update)
                      (preserve-readiness t))
  "Stage paired v2 identity rows from the validated replicated inventory.
Retirement and complete-history/receiver bits are left to the activation fence."
  (let ((count 0))
    (loop for record across records do
      (incf count (publish-service-nat-owner-pair
                   map (service-nat-identity-rows record)
                   :lookup lookup :update update
                   :preserve-readiness preserve-readiness)))
    count))

(defun retire-service-nat-withdrawn-identities
    (map previous-networks current-records local-rows
     &key (lookup #'whistler/loader:map-lookup)
          (update #'whistler/loader:map-update))
  "Disable owners removed from a previous or pending network assignment, retaining their
rows as tombstones. A current trusted claim or live local IPAM lease protects its
exact incarnation. Never retire an unrelated row that reused the same address."
  (let ((current (append
                  (loop for record across current-records
                        append (service-nat-identity-rows record))
                  local-rows))
        (retired 0))
    (dolist (network previous-networks retired)
      (loop for record across (gethash "serviceTranslations" network #())
            for rows = (service-nat-identity-rows record)
            unless (every (lambda (row) (member row current :test #'equalp)) rows)
              do (incf retired (withdraw-service-nat-owner-pair
                                map rows :lookup lookup :update update))))))

(defun service-nat-identities-published-p
    (map records &key (lookup #'whistler/loader:map-lookup)
                      (next-key #'whistler/loader:map-get-next-key))
  "Read back exactly the trusted owner inventory before a snapshot ACK.
Missing, stale, disabled expected rows or extra enabled rows keep the receiver
unready. Disabled tombstones remain until flow-aware reclamation."
  (and map (vectorp records) (not (stringp records))
       (bt:with-lock-held (*service-nat-owner-publication-lock*)
         ;; This lock serializes agent writers. A separate cross-process fence
         ;; is required before CNI can publish receiver readiness to live Pods.
         (let* ((rows (loop for record across records
                            append (service-nat-identity-rows record)))
                (expected (make-hash-table :test #'equalp))
                (seen (make-hash-table :test #'equalp)))
           (dolist (row rows) (setf (gethash (car row) expected) t))
           (and (= (length rows) (hash-table-count expected))
                (every (lambda (row)
                         (service-nat-owner-row-matches-p
                          (funcall lookup map (car row)) (cdr row)))
                       rows)
                (loop for key = (funcall next-key map nil)
                        then (funcall next-key map key)
                      while key
                      always (if (gethash key expected)
                                 (and (not (gethash key seen))
                                      (setf (gethash key seen) t))
                                 (let ((value (funcall lookup map key)))
                                   (and (typep value '(simple-array (unsigned-byte 8) (32)))
                                        (= #x20000 (netlink-read-integer value 4 4))))))
                (= (hash-table-count seen) (hash-table-count expected)))))))

(defun service-nat-ready-local-receivers
    (map records node-id &key (lookup #'whistler/loader:map-lookup))
  "Return only this node's trusted owner records whose pinned primary and
alias rows still match and both carry receiver readiness. A missing or stale
half is omitted; the status stream reports the complete resulting set."
  (unless (and map (vectorp records) (not (stringp records)))
    (return-from service-nat-ready-local-receivers nil))
  (bt:with-lock-held (*service-nat-owner-publication-lock*)
    (loop for record across records
          for local-p = (string= node-id (service-translation-string record "nodeID"))
          for rows = (when local-p (service-nat-identity-rows record))
          when (and local-p
                    (every (lambda (row)
                             (let ((actual (funcall lookup map (car row))))
                               (and (service-nat-owner-row-matches-p actual (cdr row))
                                    (/= (logand (netlink-read-integer actual 4 4) #x4) 0))))
                           rows))
            collect record)))

(defparameter *service-nat-policy-key-form*
  '(whistler::defstruct whistler::netpol-flow-key-v2
     (whistler::peer whistler::u32) (whistler::pod-port whistler::u16)
     (whistler::peer-port whistler::u16) (whistler::proto whistler::u8)
     (whistler::pad0 whistler::u8) (whistler::pad1 whistler::u16)
     (whistler::pad2 whistler::u32) (whistler::epoch0 whistler::u64)
     (whistler::epoch1 whistler::u64)))

(defun service-nat-policy-map-forms ()
  (append
   (loop for source in *egress-guard-map-forms*
         for form = (copy-tree source)
         do (case (second form)
              (whistler::endpoint-identity (setf (getf (cddr form) :value-size) 48))
              (whistler::netpol-flows
               (setf (second form) 'whistler::netpol-flows-v2
                     (getf (cddr form) :key-size) 32)))
         collect form)
   (list (find 'whistler::gr8s-nat-id-v2 *service-nat-map-forms* :key #'second)
         *service-nat-pod-map-form*)))

(in-package #:whistler)

(defmacro nat-policy-drop ()
  `(progn
     (add-pod-counter dropped-packets 1)
     (add-pod-counter dropped-bytes (ctx u32 0))
     (add-pod-counter policy-drops 1)
     (return TC_ACT_SHOT)))

(defmacro nat-policy-local (identity)
  `(progn
     (when (or (= ,identity 0) (= (load u32 ,identity 0) 0)
               (and (/= (load u32 ,identity 12) 1) (/= (load u32 ,identity 12) 2)))
       (nat-policy-drop))
     (let ((primary u32 (ntohl (load u32 ,identity 0))))
       (let ((owner (map-lookup gr8s-nat-id-v2 primary)))
         (unless (and (nat-owner-p owner primary 1)
                      (/= (logand (load u32 owner 4) 1) 0)
                      (= (load u64 owner 8) (load u64 ,identity 32))
                      (= (load u64 owner 16) (load u64 ,identity 40)))
           (nat-policy-drop))))))

(defmacro nat-policy-peer (key canonical)
  "Only rule lookup uses CANONICAL. Reply state keeps the wire peer and ports."
  `(progn
     (setf ,canonical (load u32 ,key 0))
     (let ((owner (map-lookup-ptr gr8s-nat-id-v2 ,key)))
       (if (/= owner 0)
           (progn
             (unless (and (= (logand (load u32 owner 4) #xffff0000) #x20000)
                          (/= (logand (load u32 owner 4) 1) 0)
                          (or (= (load u32 owner 28) 1) (= (load u32 owner 28) 2)))
               (nat-policy-drop))
             (setf ,canonical (load u32 owner 24))
             (let ((primary (map-lookup-ptr gr8s-nat-id-v2 (+ owner 24))))
               (unless (and (nat-owner-p primary ,canonical 1)
                            (/= (logand (load u32 primary 4) 1) 0)
                            (= (load u64 primary 8) (load u64 owner 8))
                            (= (load u64 primary 16) (load u64 owner 16)))
                 (nat-policy-drop))
               (if (= (load u32 owner 28) 1)
                   (unless (= ,canonical (load u32 ,key 0)) (nat-policy-drop))
                   (unless (and (/= ,canonical (load u32 ,key 0))
                                (= (load u32 owner 0) (load u32 ,key 0))
                                (= (load u32 primary 0) (load u32 ,key 0)))
                     (nat-policy-drop)))
               (store u64 ,key 16 (load u64 primary 8))
               (store u64 ,key 24 (load u64 primary 16))
               (when (= ,canonical (ntohl (load u32 local-identity 0)))
                 (unless (and (= (load u64 ,key 16) (load u64 local-identity 32))
                              (= (load u64 ,key 24) (load u64 local-identity 40)))
                   (nat-policy-drop)))))
           ;; Unknown managed addresses cannot be classified as ordinary
           ;; external IPs: a missing alias must not bypass an IPBlock exception.
           (let ((prefix (make-netpol-lpm-key)))
             (setf (netpol-lpm-key-prefixlen prefix) 32
                   (netpol-lpm-key-addr prefix) (load u32 ,key 0))
             (when (/= (map-lookup-ptr gr8s-nat-pod-v2 prefix) 0)
               (nat-policy-drop)))))))

(in-package #:gr8s.network)

(defun service-nat-policy-forms ()
  "Reuse canonical policy rules without changing the legacy guard profile.
These guards return an authorization decision, never redirect or rewrite L2.
The eventual NAT pipeline must commit translation before a delivery stage."
  (let ((key-count 0))
    (labels ((contains (symbol tree)
               (or (eq symbol tree)
                   (and (consp tree) (some (lambda (item) (contains symbol item)) tree))))
             (walk (form)
               (cond
                 ((eq form 'whistler::netpol-flows) 'whistler::netpol-flows-v2)
                 ((atom form) form)
                 ((and (eq (car form) 'let)
                       (find '(whistler::fkey (whistler::make-netpol-flow-key)) (second form)
                             :test #'equal))
                  (incf key-count)
                  (let* ((body (cddr form))
                         (boundary (position-if (lambda (item) (contains 'whistler::netpol-allowed item)) body)))
                    (unless boundary (error "Canonical IPv4 policy boundary changed"))
                    `(let ,(subst 'whistler::make-netpol-flow-key-v2 'whistler::make-netpol-flow-key
                                  (second form))
                       ,@(mapcar #'walk (subseq body 0 boundary))
                       (let ((whistler::canonical-peer whistler::u32 0))
                         (whistler::nat-policy-peer whistler::fkey whistler::canonical-peer)
                         ,@(mapcar #'walk (subseq body boundary))))))
                 ((eq (car form) 'whistler::netpol-allowed)
                  (let ((result (mapcar #'walk form)))
                    (setf (fourth result) 'whistler::canonical-peer)
                    ;; Kubernetes self/host-node exceptions must also survive
                    ;; hairpin source translation. The peer resolver has checked
                    ;; a self peer's epoch against this endpoint's local identity.
                    `(if (or (= whistler::canonical-peer
                                (whistler::ntohl (whistler::load whistler::u32 whistler::local-identity 0)))
                             (/= (whistler::map-lookup whistler::host-redirect-v4 whistler::canonical-peer) 0))
                         1 ,result)))
                 ((and (eq (car form) 'return) (consp (second form))
                       (eq (car (second form)) 'whistler::redirect))
                  '(return whistler::TC_ACT_OK))
                 ((and (eq (car form) 'whistler::store) (eq (third form) 'whistler::data))
                  ;; Canonical redirects rewrite MACs; authorization must leave
                  ;; the packet untouched until post-policy NAT and delivery.
                  '(progn))
                 (t (mapcar #'walk form)))))
      (let ((forms
              (loop for source in *egress-guard-program-forms*
                    for form = (walk source)
                    do (setf (fourth form)
                             `(let ((whistler::dropped-packets (whistler::map-lookup whistler::traffic-stats 2))
                                    (whistler::dropped-bytes (whistler::map-lookup whistler::traffic-stats 3))
                                    (whistler::policy-drops (whistler::map-lookup whistler::traffic-stats 6))
                                    (whistler::local-identity (whistler::map-lookup whistler::endpoint-identity 0)))
                                (whistler::nat-policy-local whistler::local-identity)
                                ,(fourth form)))
                    collect (expand-service-nat-form form))))
        (unless (= key-count 2) (error "Expected two canonical IPv4 policy key sites, got ~D" key-count))
        (cons *service-nat-policy-key-form* forms)))))

(defun compile-service-nat-policy ()
  "Compile the standalone IPv4 alias-aware policy profile."
  (compile-whistler-program (service-nat-policy-map-forms) (service-nat-policy-forms)))
