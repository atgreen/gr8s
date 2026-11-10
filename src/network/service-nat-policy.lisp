;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Standalone IPv4 alias-aware policy profile. It is not installed by CNI yet.
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
Only the enabled bit is staged: complete history and receiver readiness need
separate cluster-wide publication fences before the v2 graph is attached."
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

(defun publish-cni-service-nat-owner
    (configuration context addresses alias
     &key (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (update #'whistler/loader:map-update)
          (close #'sb-posix:close))
  "Stage this node's paired owner rows in the schema-checked shared v2 map.
The return route must already exist. A failed or partial update stops CNI ADD;
the attachment fence keeps incomplete owner state out of the live datapath."
  (unless (eq (cni-service-profile configuration) :v2)
    (invalid-cni "local v2 Service owner publication requires the v2 profile"))
  (let* ((primary (find-if-not (lambda (address) (find #\: address)) addresses))
         (rows (service-nat-identity-pair
                (cni-configuration-service-node-id configuration)
                (cni-context-container-id context) (cni-context-interface-name context)
                primary alias))
         (path (namestring (merge-pathnames
                            "gr8s_nat_id_v2"
                            (uiop:ensure-directory-pathname
                             (cni-configuration-service-packet-root configuration)))))
         (fd (funcall open path)))
    (unwind-protect
         (let ((map (funcall map-info fd "gr8s_nat_id_v2" :profile :v2)))
           ;; The alias row is written first; until the primary is present with
           ;; the same epoch, the graph rejects the pair rather than guessing.
           (dolist (row (reverse rows))
             (funcall update map (car row) (cdr row)))
           rows)
      (funcall close fd))))

(defun publish-service-nat-identities
    (map records &key (update #'whistler/loader:map-update))
  "Stage paired v2 identity rows from the validated replicated inventory.
Retirement and complete-history/receiver bits are left to the activation fence."
  (let ((count 0))
    (loop for record across records do
      (dolist (row (service-nat-identity-rows record))
        (funcall update map (car row) (cdr row))
        (incf count)))
    count))

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
  "Standalone IPv4 alias-aware policy profile; not yet installed by CNI."
  (compile-whistler-program (service-nat-policy-map-forms) (service-nat-policy-forms)))
