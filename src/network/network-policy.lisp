;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Enforce networking.k8s.io/v1 NetworkPolicy. The control plane, which sees
;;;; every Pod and Namespace, resolves each policy's peers: podSelector and
;;;; namespaceSelector peers become the selected Pods' addresses, and an egress
;;;; rule's named ports become the numbers each destination Pod gives them. It
;;;; projects that resolved policy to every node. A node selects its own Pods
;;;; with each policy's podSelector, resolves ingress named ports against the
;;;; Pod's own containers, and writes the Pod's allowed peers and ports for each
;;;; direction into the Pod's pinned maps. Its egress guard (host veth ingress)
;;;; and ingress guard (host veth egress) enforce them, and record each allowed
;;;; connection so that its replies pass the other direction.
;;;;
;;;; IPv4 only. A Pod's node reaches it from the node gateway address whatever
;;;; its ingress policy, so probes and node DNS keep working.

(in-package #:gr8s.network)

;;; ---------------------------------------------------------------------------
;;; Spec model. Selectors are LabelSelector hash tables; labels are hash tables.

(defstruct (np-port (:constructor make-np-port (protocol port &optional end-port)))
  "A policy port: PROTOCOL is :tcp/:udp/:sctp; PORT an integer, a port name, or NIL for
every port of PROTOCOL; END-PORT the last port of a range starting at PORT."
  protocol port end-port)

(defstruct (np-peer (:constructor make-np-peer (&key cidr except pod-selector namespace-selector)))
  "One from/to peer: an ipBlock CIDR and its excepted CIDRs, or Pod and Namespace selectors."
  cidr except pod-selector namespace-selector)

(defstruct (np-rule (:constructor make-np-rule (&key (peers :all) ports)))
  "One ingress/egress entry: allow any of PEERS (:all when the rule names none) on any
of PORTS (every port when NIL)."
  peers ports)

(defstruct (np-spec (:constructor make-np-spec (&key namespace name pod-selector policy-types ingress egress)))
  "A NetworkPolicy: governs Pods in NAMESPACE that POD-SELECTOR matches, for its
POLICY-TYPES (\"Ingress\"/\"Egress\")."
  namespace name pod-selector (policy-types '()) (ingress '()) (egress '()))

(defstruct (np-pod (:constructor make-np-pod (&key name namespace labels ip ips ports)))
  "A Pod as policy sees it: its labels, primary IP, every IP, and its containers'
named ports as (name protocol-keyword number) lists."
  name namespace labels ip (ips '()) (ports '()))

(defun np-pod-addresses (pod)
  "Every address of POD, preserving API order and the legacy primary IP fallback."
  (or (np-pod-ips pod) (and (np-pod-ip pod) (list (np-pod-ip pod)))))

(defun np-labels (&rest pairs)
  "Make a label table from alternating keys and values."
  (let ((labels (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key labels) value))
    labels))

(defun np-selector-matches-p (selector labels)
  "Apply a LabelSelector to LABELS. An empty selector matches everything."
  (workload-selector-matches-p (if (hash-table-p selector) selector (make-hash-table :test #'equal))
                               (if (hash-table-p labels) labels (make-hash-table :test #'equal))))

(defun np-spec-selects-pod-p (spec pod)
  "True when SPEC governs POD: same namespace, and its podSelector matches."
  (and (equal (np-spec-namespace spec) (np-pod-namespace pod))
       (np-selector-matches-p (np-spec-pod-selector spec) (np-pod-labels pod))))

;;; ---------------------------------------------------------------------------
;;; Parsing a networking.k8s.io/v1 NetworkPolicy object (a jzon hash table).

(defun %np-proto-keyword (protocol)
  "A NetworkPolicyPort protocol -> keyword; absent defaults to TCP."
  (cond ((member protocol '(nil null)) :tcp)
        ((string-equal protocol "TCP") :tcp)
        ((string-equal protocol "UDP") :udp)
        ((string-equal protocol "SCTP") :sctp)
        (t (error "unsupported NetworkPolicy protocol ~S" protocol))))

(defun %np-parse-ports (ports)
  "A vector of NetworkPolicyPort -> np-ports."
  (map 'list (lambda (port)
               (let ((number (gethash "port" port)) (end (gethash "endPort" port)))
                 (make-np-port (%np-proto-keyword (gethash "protocol" port))
                               (if (member number '(nil null)) nil number)
                               (and (integerp end) end))))
       (or ports #())))

(defun %np-selector (selector)
  "SELECTOR when it is a hash table (a parsed label selector), else NIL."
  (and (hash-table-p selector) selector))

(defun %np-parse-peer (peer)
  "A NetworkPolicyPeer -> np-peer."
  (let ((block (gethash "ipBlock" peer)))
    (make-np-peer :cidr (and (hash-table-p block) (gethash "cidr" block))
                  :except (and (hash-table-p block) (coerce (gethash "except" block #()) 'list))
                  :pod-selector (%np-selector (gethash "podSelector" peer))
                  :namespace-selector (%np-selector (gethash "namespaceSelector" peer)))))

(defun %np-parse-rule (rule peers-key)
  "An ingress/egress entry -> np-rule; PEERS-KEY is \"from\" or \"to\". A rule naming no
peers allows every peer."
  (let ((peers (gethash peers-key rule)))
    (make-np-rule :peers (if (and (vectorp peers) (plusp (length peers)))
                             (map 'list #'%np-parse-peer peers)
                             :all)
                  :ports (%np-parse-ports (gethash "ports" rule)))))

(defun network-policy-types (spec)
  "SPEC's policyTypes, defaulted as Kubernetes does: Ingress, plus Egress when it has egress rules."
  (let ((types (coerce (gethash "policyTypes" spec #()) 'list)))
    (or types
        (append '("Ingress")
                (let ((egress (gethash "egress" spec)))
                  (when (and (vectorp egress) (plusp (length egress))) '("Egress")))))))

(defun parse-network-policy-json (object)
  "Build an np-spec from a parsed NetworkPolicy OBJECT."
  (let* ((metadata (gethash "metadata" object))
         (spec (gethash "spec" object)))
    (make-np-spec
     :namespace (or (and metadata (gethash "namespace" metadata)) "default")
     :name (and metadata (gethash "name" metadata))
     :pod-selector (%np-selector (gethash "podSelector" spec))
     :policy-types (network-policy-types spec)
     :ingress (map 'list (lambda (rule) (%np-parse-rule rule "from")) (gethash "ingress" spec #()))
     :egress (map 'list (lambda (rule) (%np-parse-rule rule "to")) (gethash "egress" spec #())))))

(defun parse-network-policy (json-string)
  "Parse a NetworkPolicy JSON string into an np-spec."
  (parse-network-policy-json (com.inuoe.jzon:parse json-string)))

(defun network-policy-specs-from-objects (objects)
  "Parse stored or projected NetworkPolicy OBJECTS into np-specs."
  (mapcar #'parse-network-policy-json objects))

;;; ---------------------------------------------------------------------------
;;; Control plane: resolve peers into addresses and project the result to nodes.

(defun np-pod-named-port (pod name protocol)
  "The number POD's containers give port NAME for PROTOCOL, or NIL."
  (third (find-if (lambda (entry) (and (equal name (first entry)) (eq protocol (second entry))))
                  (np-pod-ports pod))))

(defun network-address-in-cidr-p (cidr address)
  "True when ADDRESS lies in same-family CIDR; NIL for invalid or mixed families."
  (ignore-errors
   (let* ((slash (position #\/ cidr))
          (network-text (subseq cidr 0 slash))
          (prefix (parse-integer cidr :start (1+ slash))))
     (multiple-value-bind (network-family network-bytes bits)
         (network-address-wire-values network-text)
       (multiple-value-bind (address-family address-bytes)
           (network-address-wire-values address)
         (and (= network-family address-family)
              (<= prefix bits)
              (let ((whole (floor prefix 8))
                    (partial (mod prefix 8)))
                (and (loop for index below whole
                           always (= (aref network-bytes index) (aref address-bytes index)))
                     (or (zerop partial)
                         (= (ldb (byte partial (- 8 partial)) (aref network-bytes whole))
                            (ldb (byte partial (- 8 partial)) (aref address-bytes whole))))))))))))

(defun ipv4-cidr-contains-p (cidr address)
  "Compatibility wrapper for callers that require an IPv4 CIDR and address."
  (and (not (find #\: cidr)) (not (find #\: address))
       (network-address-in-cidr-p cidr address)))

(defun np-peer-pods (peer policy-namespace pods namespace-labels)
  "The PODS a selector PEER selects. NAMESPACE-LABELS maps each namespace to its labels."
  (let ((pod-selector (np-peer-pod-selector peer))
        (namespace-selector (np-peer-namespace-selector peer)))
    (remove-if-not
     (lambda (pod)
       (and (if namespace-selector
                (np-selector-matches-p namespace-selector (gethash (np-pod-namespace pod) namespace-labels))
                (equal (np-pod-namespace pod) policy-namespace))
            (or (null pod-selector) (np-selector-matches-p pod-selector (np-pod-labels pod)))))
     pods)))

(defun np-block-pods (peer pods)
  "The PODS whose address an ipBlock PEER covers, excepted ranges excluded."
  (remove-if-not (lambda (pod)
                   (some (lambda (address)
                           (and (network-address-in-cidr-p (np-peer-cidr peer) address)
                                (notany (lambda (except)
                                          (network-address-in-cidr-p except address))
                                        (np-peer-except peer))))
                         (np-pod-addresses pod)))
                 pods))

(defun np-ip-block (cidr &optional except)
  "An ipBlock peer object for CIDR, carrying an \"except\" array when EXCEPT is
   given."
  (core-object "ipBlock" (if except
                             (core-object "cidr" cidr "except" (coerce except 'vector))
                             (core-object "cidr" cidr))))

(defun np-port-object (port)
  "An np-port as a NetworkPolicyPort."
  (let ((object (core-object "protocol" (string-upcase (symbol-name (np-port-protocol port))))))
    (when (np-port-port port) (setf (gethash "port" object) (np-port-port port)))
    (when (np-port-end-port port) (setf (gethash "endPort" object) (np-port-end-port port)))
    object))

(defun np-pod-peers (pods)
  "ipBlock peers for PODS' addresses, in a stable order and without repeats."
  (mapcar (lambda (ip) (np-ip-block (format nil "~A/~D" ip (if (find #\: ip) 128 32))))
          (sort (remove-duplicates (loop for pod in pods append (np-pod-addresses pod))
                                   :test #'equal)
                #'string<)))

(defun resolve-network-policy-rule (rule direction policy-namespace pods namespace-labels)
  "Resolve RULE into rule objects whose peers are only ipBlocks. A rule whose selector peers
select no Pod allows nothing and disappears. Egress named ports name each destination Pod's
own ports, so they become one rule per Pod that defines them."
  (let* ((peers (np-rule-peers rule))
         (named (remove-if-not (lambda (port) (stringp (np-port-port port))) (np-rule-ports rule)))
         (numbered (remove-if (lambda (port) (stringp (np-port-port port))) (np-rule-ports rule)))
         (peer-key (if (eq direction :ingress) "from" "to"))
         (resolved-peers
           (unless (eq peers :all)
             (loop for peer in peers
                   append (if (np-peer-cidr peer)
                              (list (np-ip-block (np-peer-cidr peer) (np-peer-except peer)))
                              (np-pod-peers (np-peer-pods peer policy-namespace pods namespace-labels))))))
         (rules '()))
    (flet ((rule-object (peer-objects ports)
             (let ((object (core-object)))
               (unless (eq peer-objects :all) (setf (gethash peer-key object) (coerce peer-objects 'vector)))
               (when ports (setf (gethash "ports" object) (map 'vector #'np-port-object ports)))
               object)))
      (cond
        ((and (not (eq peers :all)) (null resolved-peers)))
        ((or (eq direction :ingress) (null named))
         (push (rule-object (if (eq peers :all) :all resolved-peers) (np-rule-ports rule)) rules))
        (t
         (when numbered
           (push (rule-object (if (eq peers :all) :all resolved-peers) numbered) rules))
         (let ((destinations
                 (if (eq peers :all)
                     pods
                     (remove-duplicates
                      (loop for peer in peers
                            append (if (np-peer-cidr peer)
                                       (np-block-pods peer pods)
                                       (np-peer-pods peer policy-namespace pods namespace-labels)))))))
           (dolist (pod (sort (copy-list destinations) #'string< :key #'np-pod-ip))
             (let ((ports (loop for port in named
                                for number = (np-pod-named-port pod (np-port-port port) (np-port-protocol port))
                                when number collect (make-np-port (np-port-protocol port) number))))
               (when ports
                 (push (rule-object (np-pod-peers (list pod)) ports) rules))))))))
    (nreverse rules)))

(defun resolve-network-policy-object (object pods namespace-labels)
  "Return a copy of NetworkPolicy OBJECT whose spec a node can enforce without seeing other
Pods or Namespaces: defaulted policyTypes, and rules whose peers are only ipBlocks."
  (let* ((spec (parse-network-policy-json object))
         (source (gethash "spec" object))
         (resolved (core-object "podSelector" (copy-core-object (gethash "podSelector" source (core-object)))
                                "policyTypes" (coerce (np-spec-policy-types spec) 'vector)))
         (result (copy-core-object object)))
    (loop for (direction key rules) in `((:ingress "ingress" ,(np-spec-ingress spec)) (:egress "egress" ,(np-spec-egress spec)))
          do (setf (gethash key resolved)
                   (coerce (loop for rule in rules
                                 append (resolve-network-policy-rule rule direction (np-spec-namespace spec)
                                                                     pods namespace-labels))
                           'vector)))
    (setf (gethash "spec" result) resolved)
    result))

(defun np-container-ports (object)
  "Named container ports of a Pod OBJECT as (name protocol number) lists."
  (loop for container across (gethash "containers" (gethash "spec" object (core-object)) #())
        append (loop for port across (gethash "ports" container #())
                     for name = (gethash "name" port)
                     when (and (stringp name) (integerp (gethash "containerPort" port)))
                       collect (list name (%np-proto-keyword (gethash "protocol" port))
                                     (gethash "containerPort" port)))))

(defun network-policy-cluster-pods (store)
  "Every nonterminal Pod with at least one address that policy can select."
  (loop for pod in (list-pods store)
        for status = (pod-observed-status store pod)
        for addresses = (and (hash-table-p status)
                             (let ((plural (gethash "podIPs" status)))
                               (or (and (vectorp plural)
                                        (loop for entry across plural
                                              for address = (and (hash-table-p entry) (gethash "ip" entry))
                                              when (stringp address) collect address))
                                   (let ((single (gethash "podIP" status)))
                                     (and (stringp single) (list single))))))
        for object = (pod-to-object pod)
        when (and addresses
                  (not (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal)))
          collect (make-np-pod :name (pod-name pod) :namespace (pod-namespace pod)
                               :labels (gethash "labels" (gethash "metadata" object) (core-object))
                               :ip (first addresses) :ips addresses
                               :ports (np-container-ports object))))

(defun network-policy-namespace-labels (store)
  "Map each Namespace to its labels, including the kubernetes.io/metadata.name label
Kubernetes gives every Namespace."
  (let ((labels (make-hash-table :test #'equal)))
    (dolist (namespace (list-core-resources store "namespaces") labels)
      (let* ((metadata (gethash "metadata" namespace))
             (name (gethash "name" metadata))
             (own (copy-core-object (gethash "labels" metadata (core-object)))))
        (setf (gethash "kubernetes.io/metadata.name" own) name
              (gethash name labels) own)))))

(defun network-policy-projection (store)
  "The NetworkPolicies to project to nodes, each resolved against the current Pods and Namespaces."
  (let ((policies (list-core-resources store "networkpolicies")))
    (when policies
      (let ((pods (network-policy-cluster-pods store))
            (namespace-labels (network-policy-namespace-labels store)))
        (mapcar (lambda (object) (resolve-network-policy-object object pods namespace-labels)) policies)))))

;;; ---------------------------------------------------------------------------
;;; Node: a Pod's allowed peers and ports for one direction.

(defun np-port-ranges (port pod)
  "PORT as a list of (protocol-number first last) ranges, LAST NIL meaning every port.
A named port is resolved against POD's containers and gives nothing when undefined."
  (let ((protocol (netpol-proto-number (np-port-protocol port))) (number (np-port-port port)))
    (cond ((null number) (list (list protocol nil nil)))
          ((stringp number)
           (let ((resolved (np-pod-named-port pod number (np-port-protocol port))))
             (and resolved (list (list protocol resolved resolved)))))
          (t (list (list protocol number (or (np-port-end-port port) number)))))))

(defun pod-network-policy-entries (pod specs direction)
  "Resolve POD's policy for DIRECTION (:ingress or :egress) from projected SPECS.
Returns (values isolated entries). ISOLATED is true when a spec of that policyType selects
POD. Each entry is (cidr excepts ports), PORTS :all or a list of (protocol first last)."
  (let* ((type (ecase direction (:ingress "Ingress") (:egress "Egress")))
         (matching (remove-if-not (lambda (spec)
                                    (and (np-spec-selects-pod-p spec pod)
                                         (member type (np-spec-policy-types spec) :test #'string=)))
                                  specs))
         (entries '()))
    (dolist (spec matching)
      (dolist (rule (if (eq direction :ingress) (np-spec-ingress spec) (np-spec-egress spec)))
        (let ((ports (if (np-rule-ports rule)
                         (loop for port in (np-rule-ports rule) append (np-port-ranges port pod))
                         :all)))
          (when ports
            (if (eq (np-rule-peers rule) :all)
                (progn
                  (push (list "0.0.0.0/0" '() ports) entries)
                  (push (list "::/0" '() ports) entries))
                (dolist (peer (np-rule-peers rule))
                  ;; Projected peers are ipBlocks; preserve either address family.
                  (when (and (np-peer-cidr peer) (network-policy-cidr (np-peer-cidr peer)))
                    (push (list (np-peer-cidr peer)
                                (remove-if-not (lambda (except) (network-policy-cidr except))
                                               (np-peer-except peer))
                                ports)
                          entries))))))))
    (values (not (null matching)) (nreverse entries))))

;;; Longest-prefix tables. An address's entry is the longest prefix, among every rule
;;; CIDR and excepted CIDR, that contains it. That prefix's allowed ports are the union
;;; over the rules whose CIDR contains it and none of whose excepts do, so one lookup
;;; answers ipBlock.except exactly however rules overlap.

(defun np-prefix (cidr)
  "CIDR as (network . length), the network masked."
  (multiple-value-bind (address length) (parse-ipv4-cidr cidr)
    (cons (logand address (if (zerop length) 0 (ldb (byte 32 0) (ash -1 (- 32 length))))) length)))

(defun np-prefix-within-p (inner outer)
  "True when prefix INNER lies inside prefix OUTER."
  (and (>= (cdr inner) (cdr outer))
       (= (ash (car inner) (- (cdr outer) 32)) (ash (car outer) (- (cdr outer) 32)))))

(defun np-port-set-union (sets)
  "Union port SETS, each :all or a list of ranges, into :all or a sorted list without repeats."
  (if (member :all sets)
      :all
      (sort (remove-duplicates (apply #'append sets) :test #'equal)
            (lambda (a b) (let ((x (list (first a) (or (second a) -1) (or (third a) -1)))
                                (y (list (first b) (or (second b) -1) (or (third b) -1))))
                            (loop for i in x for j in y
                                  unless (= i j) return (< i j)))))))

(defun np-port-prefixes (first last)
  "Cover ports FIRST..LAST with aligned (port . bits) prefixes, BITS of the 16 being fixed."
  (let ((prefixes '()))
    (loop while (<= first last)
          do (let ((size 1))
               (loop while (and (zerop (mod first (* 2 size))) (<= (+ first (* 2 size) -1) last) (< size 65536))
                     do (setf size (* 2 size)))
               (push (cons first (- 17 (integer-length size))) prefixes)
               (incf first size)))
    (nreverse prefixes)))

(defun %network-policy-tables (entries prefix-function address-bits)
  "Compile ENTRIES into the Pod's tries. Returns (values cidrs ports): CIDRS a list of
((network . length) . group), PORTS a list of (group protocol port bits), protocol NIL for
every protocol and port NIL for every port. Group 0 allows nothing."
  (let* ((prefixes (remove-duplicates
                    (loop for (cidr excepts) in entries
                          collect (funcall prefix-function cidr)
                          append (mapcar prefix-function excepts))
                    :test #'equal))
         (groups '()) (cidrs '()))
    (dolist (prefix (sort prefixes (lambda (a b) (if (= (cdr a) (cdr b)) (< (car a) (car b)) (< (cdr a) (cdr b))))))
      (let* ((within-p (lambda (inner outer)
                         (and (>= (cdr inner) (cdr outer))
                              (= (ash (car inner) (- (cdr outer) address-bits))
                                 (ash (car outer) (- (cdr outer) address-bits))))))
             (sets (loop for (cidr excepts ports) in entries
                         when (and (funcall within-p prefix (funcall prefix-function cidr))
                                   (notany (lambda (except)
                                             (funcall within-p prefix
                                                      (funcall prefix-function except)))
                                           excepts))
                           collect ports))
             (set (and sets (np-port-set-union sets)))
             (group (cond ((null set) 0)
                          ((position set groups :test #'equal) (1+ (position set groups :test #'equal)))
                          (t (setf groups (append groups (list set))) (length groups)))))
        (push (cons prefix group) cidrs)))
    (values (nreverse cidrs)
            (loop for set in groups for group from 1
                  append (if (eq set :all)
                             (list (list group nil nil 0))
                             (loop for (protocol first last) in set
                                   append (if (null first)
                                              (list (list group protocol nil 0))
                                              (loop for (port . bits) in (np-port-prefixes first last)
                                                    collect (list group protocol port bits)))))))))

(defun network-policy-tables (entries)
  "Compile IPv4 ENTRIES into the Pod's CIDR and port tries."
  (%network-policy-tables entries #'np-prefix 32))

(defun np-prefix-v6 (cidr)
  "IPv6 CIDR as (128-bit-network-integer . prefix-length), with host bits masked."
  (let* ((slash (position #\/ cidr))
         (address (subseq cidr 0 slash))
         (length (parse-integer cidr :start (1+ slash)))
         (value (network-octets-integer (0conf:parse-ipv6 address))))
    (cons (logand value (if (zerop length) 0 (ash -1 (- 128 length)))) length)))

(defun network-policy-tables-v6 (entries)
  "Compile IPv6 ENTRIES into the Pod's CIDR and port tries."
  (%network-policy-tables entries #'np-prefix-v6 128))

;;; ---------------------------------------------------------------------------
;;; Map encodings, matching the structs in src/egress-guard-program.lisp.

(defun %netpol-u32-le (value)
  "VALUE as a fresh 4-byte little-endian octet vector."
  (let ((bytes (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 bytes) (setf (aref bytes i) (ldb (byte 8 (* 8 i)) value)))))

(defun netpol-cidr-lpm-key (cidr)
  "LPM key for CIDR: u32 prefix length, then its masked network in wire order."
  (if (find #\: cidr)
      (destructuring-bind (network . length) (np-prefix-v6 cidr)
        (netpol-prefix-lpm-key-v6 network length))
      (destructuring-bind (network . length) (np-prefix cidr)
        (netpol-prefix-lpm-key network length))))

(defun netpol-prefix-lpm-key (network length)
  "The eBPF LPM-trie key for the prefix NETWORK/LENGTH: the prefix LENGTH as a
   little-endian u32, then NETWORK's four octets in network (big-endian) order."
  (concatenate '(vector (unsigned-byte 8)) (%netpol-u32-le length)
               (vector (ldb (byte 8 24) network) (ldb (byte 8 16) network)
                       (ldb (byte 8 8) network) (ldb (byte 8 0) network))))

(defun netpol-prefix-lpm-key-v6 (network length)
  "The eBPF IPv6 LPM key: little-endian prefix length plus 16 wire-order bytes."
  (concatenate '(vector (unsigned-byte 8)) (%netpol-u32-le length)
               (loop with bytes = (make-array 16 :element-type '(unsigned-byte 8))
                     for index below 16
                     do (setf (aref bytes index) (ldb (byte 8 (* 8 (- 15 index))) network))
                     finally (return bytes))))

(defun netpol-port-lpm-key (group protocol port bits)
  "LPM key for a port entry: {prefixlen, group (host order), protocol, pad, port (network
order)}. The prefix covers the group alone when PROTOCOL is NIL, the group and protocol when
PORT is NIL, and otherwise BITS bits of the port too."
  (concatenate '(vector (unsigned-byte 8))
               (%netpol-u32-le (cond ((null protocol) 32) ((null port) 40) (t (+ 48 bits))))
               (%netpol-u32-le group)
               (vector (or protocol 0) 0 (ldb (byte 8 8) (or port 0)) (ldb (byte 8 0) (or port 0)))))

(defun network-policy-family-map-contents (entries family)
  "The exact CIDR and port trie contents for one address FAMILY's ENTRIES."
  (multiple-value-bind (cidrs ports)
      (ecase family
        (:ipv4 (network-policy-tables entries))
        (:ipv6 (network-policy-tables-v6 entries)))
    (values (mapcar (lambda (entry)
                      (cons (ecase family
                              (:ipv4 (netpol-prefix-lpm-key (car (car entry)) (cdr (car entry))))
                              (:ipv6 (netpol-prefix-lpm-key-v6 (car (car entry)) (cdr (car entry)))))
                            (%netpol-u32-le (cdr entry))))
                    cidrs)
            (mapcar (lambda (entry)
                      (cons (apply #'netpol-port-lpm-key entry)
                            (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1)))
                    ports))))

(defun network-policy-map-contents (entries)
  "Return IPv4 CIDRs/ports then IPv6 CIDRs/ports for a Pod's mixed-family ENTRIES."
  (let ((ipv4 (remove-if (lambda (entry) (find #\: (first entry))) entries))
        (ipv6 (remove-if-not (lambda (entry) (find #\: (first entry))) entries)))
    (multiple-value-bind (cidr-v4 ports-v4)
        (network-policy-family-map-contents ipv4 :ipv4)
      (multiple-value-bind (cidr-v6 ports-v6)
          (network-policy-family-map-contents ipv6 :ipv6)
        (values cidr-v4 ports-v4 cidr-v6 ports-v6)))))

;;; ---------------------------------------------------------------------------
;;; Writing a Pod's policy into its pinned maps, as data: no recompile, no re-attach.

(defun netpol-map-keys (trie)
  "Every key in the BPF map TRIE."
  (loop for key = (whistler/loader::map-get-next-key trie nil) then (whistler/loader::map-get-next-key trie key)
        while key collect key))

(defun write-pod-network-policy
    (directory egress ingress
     &key (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (update #'whistler/loader:map-update)
          (delete #'whistler/loader::map-delete)
          (keys #'netpol-map-keys)
          (exists #'probe-file)
          (close #'sb-posix:close))
  "Write a Pod's resolved policy into its pinned maps under DIRECTORY. EGRESS and INGRESS
are (isolated . entries). Each trie gets exactly the new contents, and the mode map, which
turns enforcement on or off, is written last. A Pod whose maps predate these returns NIL
untouched. OPEN/MAP-INFO/UPDATE/DELETE/KEYS/EXISTS/CLOSE are injectable for testing."
  (flet ((path (name) (concatenate 'string (namestring directory) name)))
    (unless (funcall exists (path "netpol_mode"))
      (return-from write-pod-network-policy nil))
    (let ((fds '()))
      (unwind-protect
           (flet ((open-map (name)
                    (let ((fd (funcall open (path name))))
                      (push fd fds)
                      (funcall map-info fd name)))
                  (replace-contents (trie contents)
                    (dolist (entry contents) (funcall update trie (car entry) (cdr entry)))
                    (dolist (key (funcall keys trie))
                      (unless (find key contents :key #'car :test #'equalp)
                        (funcall delete trie key)))))
             (handler-case
                 (progn
                   (loop for (direction cidr-name ports-name cidr-v6-name ports-v6-name)
                           in '((:egress "netpol_egress_cidr" "netpol_egress_ports"
                                        "netpol_egress_cidr_v6" "netpol_egress_ports_v6")
                                (:ingress "netpol_ingress_cidr" "netpol_ingress_ports"
                                         "netpol_ingress_cidr_v6" "netpol_ingress_ports_v6"))
                         for (isolated . entries) = (if (eq direction :egress) egress ingress)
                         do (multiple-value-bind (cidrs ports cidrs-v6 ports-v6)
                                (network-policy-map-contents (and isolated entries))
                              (replace-contents (open-map ports-name) ports)
                              (replace-contents (open-map cidr-name) cidrs)
                              (replace-contents (open-map ports-v6-name) ports-v6)
                              (replace-contents (open-map cidr-v6-name) cidrs-v6)))
                   (let ((mode (open-map "netpol_mode")))
                     (funcall update mode (%netpol-u32-le 0) (%netpol-u32-le (if (car egress) 1 0)))
                     (funcall update mode (%netpol-u32-le 1) (%netpol-u32-le (if (car ingress) 1 0))))
                   t)
               (error (condition)
                 ;; Fail closed. A partial write -- e.g. an eBPF LPM trie hitting
                 ;; its capacity -- must never leave a policy-selected Pod in the
                 ;; zero-initialised allow-all mode. Drop every allow rule and
                 ;; isolate both directions so the Pod defaults to deny, then alarm
                 ;; and resignal so the caller does not record this policy as
                 ;; written and retries it on the next convergence.
                 (ignore-errors
                   (dolist (name '("netpol_egress_cidr" "netpol_egress_ports"
                                   "netpol_egress_cidr_v6" "netpol_egress_ports_v6"
                                   "netpol_ingress_cidr" "netpol_ingress_ports"
                                   "netpol_ingress_cidr_v6" "netpol_ingress_ports_v6"))
                     (replace-contents (open-map name) '()))
                   (let ((mode (open-map "netpol_mode")))
                     (funcall update mode (%netpol-u32-le 0) (%netpol-u32-le 1))
                     (funcall update mode (%netpol-u32-le 1) (%netpol-u32-le 1))))
                 (format *error-output*
                         "gr8s: ALARM network policy write for ~A failed; failing closed (deny-all): ~A~%"
                         directory condition)
                 (error condition))))
        (dolist (fd fds) (ignore-errors (funcall close fd)))))))

(defvar *pod-network-policy-written* (make-hash-table :test #'equal)
  "The policy last written into each Pod's maps, by pin directory, so that an unchanged
policy is not rewritten on every snapshot.")

(defvar *pod-network-policy-written-lock* (bt:make-lock "gr8s network policy writes"))

(defun converge-pod-network-policies
    (specs endpoints &key pod-finder directory-fn (writer #'write-pod-network-policy))
  "Resolve and write the policy of each local Pod ENDPOINT (SANDBOX INTERFACE ADDRESS).
POD-FINDER maps an address to an np-pod, or NIL; DIRECTORY-FN maps a sandbox to its pin
directory. Fail-soft per endpoint; returns the sandboxes written."
  (let ((written '()))
    ;; Forget Pods that are gone, so the record stays the size of the node.
    (let ((current (mapcar (lambda (endpoint) (funcall directory-fn (first endpoint))) endpoints)))
      (bt:with-lock-held (*pod-network-policy-written-lock*)
        (loop for directory in (loop for key being the hash-keys of *pod-network-policy-written* collect key)
              unless (member directory current :test #'equal)
                do (remhash directory *pod-network-policy-written*))))
    (dolist (endpoint endpoints (nreverse written))
      (handler-case
          (destructuring-bind (sandbox interface address) endpoint
            (declare (ignore interface))
            (let ((pod (funcall pod-finder address)))
              (when pod
                (let* ((directory (funcall directory-fn sandbox))
                       (policy (list (multiple-value-call #'cons (pod-network-policy-entries pod specs :egress))
                                     (multiple-value-call #'cons (pod-network-policy-entries pod specs :ingress)))))
                  (unless (equal policy (bt:with-lock-held (*pod-network-policy-written-lock*)
                                          (gethash directory *pod-network-policy-written*)))
                    (when (funcall writer directory (first policy) (second policy))
                      (bt:with-lock-held (*pod-network-policy-written-lock*)
                        (setf (gethash directory *pod-network-policy-written*) policy))
                      (push sandbox written)))))))
        (error (condition)
          (format *error-output* "gr8s: netpol endpoint ~S failed: ~A~%" endpoint condition))))))

;;; ---------------------------------------------------------------------------
;;; The per-Pod compiled classifier (src/network-policy-program.lisp) takes a flat
;;; rule list. It is stateless and has no exceptions or port ranges; the map-driven
;;; guards above are what enforce Pods' policies.

(defun resolve-pod-policy (pod specs pods direction)
  "Flatten POD's DIRECTION policy for the compiled classifier: (values isolated policy).
Selector peers select among PODS; single numeric ports only."
  (let* ((type (ecase direction (:ingress "Ingress") (:egress "Egress")))
         (matching (remove-if-not (lambda (spec)
                                    (and (np-spec-selects-pod-p spec pod)
                                         (member type (np-spec-policy-types spec) :test #'string=)))
                                  specs)))
    (if (null matching)
        (values nil nil)
        (values
         t
         (make-network-policy
          :direction direction
          :rules (loop for spec in matching
                       append (loop for rule in (if (eq direction :ingress) (np-spec-ingress spec) (np-spec-egress spec))
                                    for ports = (loop for port in (np-rule-ports rule)
                                                      when (integerp (np-port-port port))
                                                        collect (cons (np-port-protocol port) (np-port-port port)))
                                    append (if (eq (np-rule-peers rule) :all)
                                               (list (make-netpol-rule "0.0.0.0/0" ports))
                                               (loop for peer in (np-rule-peers rule)
                                                     append (if (np-peer-cidr peer)
                                                                (list (make-netpol-rule (np-peer-cidr peer) ports))
                                                                (mapcar (lambda (selected)
                                                                          (make-netpol-rule (format nil "~A/32" (np-pod-ip selected)) ports))
                                                                        (np-peer-pods peer (np-spec-namespace spec) pods
                                                                                      (make-hash-table :test #'equal)))))))))))))

(defun compile-pod-policy (pod specs pods direction)
  "Resolve and JIT-compile POD's DIRECTION policy as a classifier: (values isolated map-specs
prog-specs), or NILs when POD is not isolated for DIRECTION."
  (multiple-value-bind (isolated policy) (resolve-pod-policy pod specs pods direction)
    (if isolated
        (multiple-value-bind (maps progs) (compile-network-policy policy)
          (values t maps progs))
        (values nil nil nil))))

;;; ---------------------------------------------------------------------------
;;; API validation, as upstream's ValidateNetworkPolicySpec does for what clients send.

(defun validate-network-policy-port (port path)
  "Check one NetworkPolicyPort: a known protocol, a port number or name, and an endPort only
after a numeric port it is not below."
  (let ((protocol (gethash "protocol" port "TCP")) (number (gethash "port" port)) (end (gethash "endPort" port)))
    (unless (member protocol '("TCP" "UDP" "SCTP" null) :test #'equal)
      (core-resource-error 422 "Invalid" "~A.protocol: Unsupported value: ~S" path protocol))
    (cond ((member number '(nil null)))
          ((integerp number)
           (unless (<= 1 number 65535)
             (core-resource-error 422 "Invalid" "~A.port: Invalid value: ~A: must be between 1 and 65535, inclusive" path number)))
          ((not (and (stringp number) (<= 1 (length number) 15) (dns-label-p number) (some #'alpha-char-p number)))
           (core-resource-error 422 "Invalid" "~A.port: Invalid value: ~S: must be a valid port name" path number)))
    (unless (member end '(nil null))
      (cond ((member number '(nil null))
             (core-resource-error 422 "Invalid" "~A.endPort: Required value: may not be set when `port` is not specified" path))
            ((not (integerp number))
             (core-resource-error 422 "Invalid" "~A.endPort: Required value: may not be set when `port` is non-numeric" path))
            ((not (and (integerp end) (<= number end 65535)))
             (core-resource-error 422 "Invalid" "~A.endPort: Invalid value: ~A: must be greater than or equal to `port`" path end))))))

(defun network-policy-cidr (text)
  "Parse TEXT as address/prefix, returning family bits, address integer, and prefix."
  (let ((slash (and (stringp text) (position #\/ text))))
    (when slash
      (let* ((address (subseq text 0 slash)) (digits (subseq text (1+ slash)))
             (prefix (and (<= 1 (length digits) 3) (every #'digit-char-p digits) (parse-integer digits))))
        (cond ((null prefix) nil)
              ((find #\: address)
               (and (<= prefix 128) (not (find #\% address))
                    (handler-case
                        (values 128 (network-octets-integer (0conf:parse-ipv6 address)) prefix)
                      (error () nil))))
              ((and (<= prefix 32) (networking-canonical-ip-p address))
               (values 32 (parse-ipv4-integer address) prefix)))))))

(defun validate-network-policy-peer (peer path)
  "Check one NetworkPolicyPeer: selectors, or an ipBlock alone whose exceptions lie inside its CIDR."
  (let ((block (gethash "ipBlock" peer)))
    (when (hash-table-p block)
      (when (or (hash-table-p (gethash "podSelector" peer)) (hash-table-p (gethash "namespaceSelector" peer)))
        (core-resource-error 422 "Invalid" "~A: Forbidden: may not specify more than 1 peer type" path))
      (let ((cidr (gethash "cidr" block)))
        (multiple-value-bind (family network prefix) (network-policy-cidr cidr)
          (unless family
            (core-resource-error 422 "Invalid" "~A.ipBlock.cidr: Invalid value: ~S: must be a valid CIDR" path cidr))
          (loop for except across (gethash "except" block #())
                do (multiple-value-bind (inner-family inner-network inner-prefix) (network-policy-cidr except)
                     (unless (and inner-family (= family inner-family) (> inner-prefix prefix)
                                  (= (ash inner-network (- prefix family))
                                     (ash network (- prefix family))))
                       (core-resource-error 422 "Invalid" "~A.ipBlock.except: Invalid value: ~S: must be a strict subset of `cidr`"
                                            path except)))))))))

(defun validate-network-policy-spec (spec)
  "Reject a NetworkPolicy spec upstream's API would: bad policyTypes, ports or peers."
  (loop for type across (gethash "policyTypes" spec #())
        do (unless (member type '("Ingress" "Egress") :test #'equal)
             (core-resource-error 422 "Invalid" "spec.policyTypes: Unsupported value: ~S: supported values: \"Ingress\", \"Egress\"" type)))
  (dolist (direction '(("ingress" "from") ("egress" "to")))
    (destructuring-bind (key peers-key) direction
      (let ((rules (gethash key spec #())))
        (when (and (vectorp rules) (not (stringp rules)))
          (loop for rule across rules
                for index from 0
                when (hash-table-p rule)
                  do (loop for port across (gethash "ports" rule #())
                           for position from 0
                           when (hash-table-p port)
                             do (validate-network-policy-port port (format nil "spec.~A[~D].ports[~D]" key index position)))
                     (loop for peer across (gethash peers-key rule #())
                           for position from 0
                           when (hash-table-p peer)
                             do (validate-network-policy-peer peer (format nil "spec.~A[~D].~A[~D]" key index peers-key position)))))))))
