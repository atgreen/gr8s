;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Resolve Kubernetes NetworkPolicy resources into the per-Pod normalized rule
;;;; set that network-policy-program.lisp compiles into a classifier. This is the
;;;; bridge from declarative policy (podSelector, ipBlock/podSelector peers,
;;;; ports) to the concrete (CIDR, proto, port) rules a given Pod's compiled
;;;; firewall enforces. Pure functions over an in-memory cluster view, so the
;;;; whole mapping is unit-testable without a kernel or a live API.
;;;;
;;;; Supported subset of networking.k8s.io/v1: matchLabels podSelector, ipBlock
;;;; (cidr) and podSelector peers, and ports. Deferred (tracked under the epic):
;;;; matchExpressions, ipBlock.except, and label-based namespaceSelector (a
;;;; namespaceSelector here is treated as "any namespace" when present).

(in-package #:gr8s)

;;; ---------------------------------------------------------------------------
;;; Spec model: an in-memory subset of a NetworkPolicy and the cluster view it
;;; is resolved against. Selectors are alists of (label-name . value) strings.

(defstruct (np-port (:constructor make-np-port (protocol port)))
  "A policy port: PROTOCOL is :tcp/:udp/:sctp, PORT an integer."
  protocol port)

(defstruct (np-peer (:constructor make-np-peer (&key cidr pod-selector namespace-selector)))
  "One from/to peer: an ipBlock CIDR string, and/or a podSelector/namespaceSelector."
  cidr pod-selector namespace-selector)

(defstruct (np-rule (:constructor make-np-rule (&key peers ports)))
  "One ingress/egress entry: allow (any PEER) on (any PORT). Empty PEERS means
all peers; empty PORTS means all ports."
  peers ports)

(defstruct (np-spec (:constructor make-np-spec (&key namespace pod-selector policy-types ingress egress)))
  "A NetworkPolicy: applies to pods in NAMESPACE matching POD-SELECTOR. POLICY-TYPES
is a list of \"Ingress\"/\"Egress\" strings."
  namespace (pod-selector '()) (policy-types '()) (ingress '()) (egress '()))

(defstruct (np-pod (:constructor make-np-pod (&key name namespace labels ip)))
  "A cluster Pod as seen during resolution."
  name namespace (labels '()) ip)

;;; ---------------------------------------------------------------------------
;;; Resolution.

(defun label-selector-match-p (selector labels)
  "True when every (name . value) in SELECTOR is present in LABELS. An empty
SELECTOR matches every Pod, matching Kubernetes semantics."
  (every (lambda (pair)
           (let ((cell (assoc (car pair) labels :test #'string=)))
             (and cell (equal (cdr pair) (cdr cell)))))
         selector))

(defun np-spec-selects-pod-p (spec pod)
  "True when SPEC governs POD: same namespace and POD-SELECTOR matches."
  (and (string= (np-spec-namespace spec) (np-pod-namespace pod))
       (label-selector-match-p (np-spec-pod-selector spec) (np-pod-labels pod))))

(defun resolve-peer-cidrs (peer policy-namespace pods)
  "Expand PEER into a list of CIDR strings against the cluster POD view.
ipBlock yields its CIDR; a podSelector yields the matching Pods' /32s (restricted
to POLICY-NAMESPACE unless a namespaceSelector widens it to any namespace)."
  (cond
    ((np-peer-cidr peer) (list (np-peer-cidr peer)))
    ((np-peer-pod-selector peer)
     (loop for pod in pods
           when (and (np-pod-ip pod)
                     (label-selector-match-p (np-peer-pod-selector peer) (np-pod-labels pod))
                     (or (np-peer-namespace-selector peer)
                         (string= (np-pod-namespace pod) policy-namespace)))
             collect (format nil "~A/32" (np-pod-ip pod))))
    ((np-peer-namespace-selector peer)
     (loop for pod in pods when (np-pod-ip pod)
           collect (format nil "~A/32" (np-pod-ip pod))))
    (t '())))

(defun np-rule->netpol-rules (rule policy-namespace pods)
  "Expand one NetworkPolicy ingress/egress entry into netpol-rules: one per
resolved peer CIDR, each carrying the entry's ports. Empty peers => 0.0.0.0/0."
  (let ((ports (mapcar (lambda (p) (cons (np-port-protocol p) (np-port-port p)))
                       (np-rule-ports rule)))
        (cidrs (if (null (np-rule-peers rule))
                   (list "0.0.0.0/0")
                   (remove-duplicates
                    (mapcan (lambda (peer) (resolve-peer-cidrs peer policy-namespace pods))
                            (np-rule-peers rule))
                    :test #'string=))))
    (mapcar (lambda (cidr) (make-netpol-rule cidr ports)) cidrs)))

(defun resolve-pod-policy (pod specs pods direction)
  "Resolve POD's effective policy for DIRECTION (:ingress or :egress).
Returns (values isolated-p network-policy). ISOLATED-P is true when some SPEC of
the matching policyType selects POD, which makes DIRECTION default-deny; the
returned network-policy then carries the union of the matching specs' allow
rules. When no spec governs the direction, returns (values nil nil) -- the Pod
is unrestricted and no program should be attached."
  (let* ((type (ecase direction (:ingress "Ingress") (:egress "Egress")))
         (matching (remove-if-not
                    (lambda (spec)
                      (and (np-spec-selects-pod-p spec pod)
                           (member type (np-spec-policy-types spec) :test #'string=)))
                    specs)))
    (if (null matching)
        (values nil nil)
        (values t
                (make-network-policy
                 :direction direction
                 :rules (mapcan
                         (lambda (spec)
                           (mapcan (lambda (rule)
                                     (np-rule->netpol-rules rule (np-spec-namespace spec) pods))
                                   (ecase direction
                                     (:ingress (np-spec-ingress spec))
                                     (:egress (np-spec-egress spec)))))
                         matching))))))

(defun compile-pod-policy (pod specs pods direction)
  "Resolve and JIT-compile POD's DIRECTION policy in one step.
Returns (values isolated-p map-specs prog-specs); when POD is not isolated for
DIRECTION, returns (values nil nil nil) and nothing need be attached."
  (multiple-value-bind (isolated policy) (resolve-pod-policy pod specs pods direction)
    (if isolated
        (multiple-value-bind (maps progs) (compile-network-policy policy)
          (values t maps progs))
        (values nil nil nil))))

;;; ---------------------------------------------------------------------------
;;; Parse a networking.k8s.io/v1 NetworkPolicy object (a jzon hash-table) into
;;; the np-spec model. Arrays arrive as vectors, objects as hash-tables. We fail
;;; closed on unsupported forms (named/all-port rules) rather than silently
;;; widening the allow-list. Deferred: matchExpressions, ipBlock.except.

(defun %np-selector-alist (selector)
  "A LabelSelector hash-table -> its matchLabels as an alist of strings."
  (let ((result '()))
    (when selector
      (let ((labels (gethash "matchLabels" selector)))
        (when labels
          (maphash (lambda (k v) (push (cons k v) result)) labels))))
    (nreverse result)))

(defun %np-proto-keyword (protocol)
  "k8s port protocol string -> keyword; absent defaults to TCP."
  (cond ((null protocol) :tcp)
        ((string-equal protocol "TCP") :tcp)
        ((string-equal protocol "UDP") :udp)
        ((string-equal protocol "SCTP") :sctp)
        (t (error "unsupported NetworkPolicy protocol ~S" protocol))))

(defun %np-parse-ports (ports)
  "Vector of NetworkPolicyPort -> list of np-port. Errors on named/all-port
entries (no numeric port) so a restrictive rule never silently becomes open."
  (map 'list
       (lambda (p)
         (let ((port (gethash "port" p)))
           (unless (integerp port)
             (error "NetworkPolicy port ~S unsupported (named ports and protocol-only/all-port rules not yet supported)"
                    port))
           (make-np-port (%np-proto-keyword (gethash "protocol" p)) port)))
       (or ports #())))

(defun %np-parse-peer (peer)
  "A NetworkPolicyPeer hash-table -> np-peer."
  (let ((ip-block (gethash "ipBlock" peer))
        (pod-selector (gethash "podSelector" peer))
        (namespace-selector (gethash "namespaceSelector" peer)))
    (make-np-peer
     :cidr (and ip-block (gethash "cidr" ip-block))
     :pod-selector (and pod-selector (%np-selector-alist pod-selector))
     :namespace-selector (and namespace-selector t))))

(defun %np-parse-rule (rule peers-key)
  "An ingress/egress entry -> np-rule; PEERS-KEY is \"from\" or \"to\"."
  (make-np-rule
   :peers (map 'list #'%np-parse-peer (or (gethash peers-key rule) #()))
   :ports (%np-parse-ports (gethash "ports" rule))))

(defun parse-network-policy-json (object)
  "Build an np-spec from a parsed networking.k8s.io/v1 NetworkPolicy OBJECT."
  (let* ((metadata (gethash "metadata" object))
         (spec (gethash "spec" object))
         (namespace (or (and metadata (gethash "namespace" metadata)) "default"))
         (policy-types (coerce (or (gethash "policyTypes" spec) #()) 'list)))
    ;; k8s default: omitted policyTypes is [Ingress], plus Egress iff egress rules exist.
    (when (null policy-types)
      (setf policy-types (append '("Ingress")
                                 (when (gethash "egress" spec) '("Egress")))))
    (make-np-spec
     :namespace namespace
     :pod-selector (%np-selector-alist (gethash "podSelector" spec))
     :policy-types policy-types
     :ingress (map 'list (lambda (r) (%np-parse-rule r "from")) (or (gethash "ingress" spec) #()))
     :egress (map 'list (lambda (r) (%np-parse-rule r "to")) (or (gethash "egress" spec) #())))))

(defun parse-network-policy (json-string)
  "Parse a NetworkPolicy JSON string into an np-spec."
  (parse-network-policy-json (com.inuoe.jzon:parse json-string)))

(defun network-policy-specs-from-objects (objects)
  "Project stored NetworkPolicy objects (jzon hash-tables, e.g. from the resource
store) into np-specs for resolution. This is the control-plane side of feeding
the per-Pod firewall: the agent snapshot carries these alongside Pod identities."
  (mapcar #'parse-network-policy-json objects))

;;; ---------------------------------------------------------------------------
;;; Map-driven enforcement. A Pod's egress policy lives in the egress guard's
;;; pinned maps (netpol_egress_mode / _cidr / _port); the agent updates them as
;;; DATA on policy change -- no program recompile and no re-attach. These helpers
;;; encode the entries and write a Pod's resolved policy into its pinned maps.

(defun %netpol-u32-le (value)
  (let ((bytes (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 bytes) (setf (aref bytes i) (ldb (byte 8 (* 8 i)) value)))))

(defun %netpol-u16-le (value)
  (let ((bytes (make-array 2 :element-type '(unsigned-byte 8))))
    (setf (aref bytes 0) (ldb (byte 8 0) value) (aref bytes 1) (ldb (byte 8 8) value))
    bytes))

(defconstant +netpol-all-ports+ #xffffffff
  "LPM value meaning every protocol/port is allowed to the matched CIDR.")

(defun netpol-cidr-lpm-key (cidr)
  "LPM-trie key for CIDR: u32 prefixlen (host order) followed by the masked
network address in network byte order -- matching how the program reads the
destination straight out of the packet."
  (multiple-value-bind (address prefix) (parse-ipv4-cidr cidr)
    (let* ((mask (if (zerop prefix) 0 (ldb (byte 32 0) (- (ash 1 32) (ash 1 (- 32 prefix))))))
           (net (logand address mask)))
      (concatenate '(vector (unsigned-byte 8))
                   (%netpol-u32-le prefix)
                   (vector (ldb (byte 8 24) net) (ldb (byte 8 16) net)
                           (ldb (byte 8 8) net) (ldb (byte 8 0) net))))))

(defun netpol-port-hash-key (group proto port)
  "Hash key {group u32 LE, proto u8, pad u8, port u16 LE}, matching the program's
netpol-port-key struct."
  (concatenate '(vector (unsigned-byte 8))
               (%netpol-u32-le group)
               (vector proto 0)
               (%netpol-u16-le port)))

(defun write-pod-egress-policy
    (directory isolated policy
     &key (open #'whistler/loader:open-pinned-object)
          (map-info #'cni-policy-map-info)
          (update #'whistler/loader:map-update)
          (close #'sb-posix:close))
  "Write the Pod's resolved egress POLICY into its pinned netpol maps under
DIRECTORY. Sets netpol_egress_mode to ISOLATED; when isolated, populates the
allowed-CIDR LPM (value = group id, or all-ports sentinel for port-less rules)
and the per-group ports hash. Writes are idempotent. OPEN/MAP-INFO/UPDATE/CLOSE
are injectable for testing."
  (flet ((path (name) (concatenate 'string (namestring directory) name)))
    (let (mode-fd cidr-fd port-fd)
      (unwind-protect
           (progn
             (setf mode-fd (funcall open (path "netpol_egress_mode")))
             (funcall update (funcall map-info mode-fd "netpol_egress_mode")
                      (%netpol-u32-le 0) (%netpol-u32-le (if isolated 1 0)))
             (when isolated
               (setf cidr-fd (funcall open (path "netpol_egress_cidr"))
                     port-fd (funcall open (path "netpol_egress_port")))
               (let ((cidr (funcall map-info cidr-fd "netpol_egress_cidr"))
                     (port (funcall map-info port-fd "netpol_egress_port"))
                     (group 0))
                 (dolist (rule (network-policy-rules policy))
                   (let ((ports (netpol-rule-ports rule)))
                     (if (null ports)
                         (funcall update cidr (netpol-cidr-lpm-key (netpol-rule-cidr rule))
                                  (%netpol-u32-le +netpol-all-ports+))
                         (progn
                           (incf group)
                           (funcall update cidr (netpol-cidr-lpm-key (netpol-rule-cidr rule))
                                    (%netpol-u32-le group))
                           (dolist (pp ports)
                             (funcall update port
                                      (netpol-port-hash-key group (netpol-proto-number (car pp)) (cdr pp))
                                      (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))))))))))
        (when mode-fd (ignore-errors (funcall close mode-fd)))
        (when cidr-fd (ignore-errors (funcall close cidr-fd)))
        (when port-fd (ignore-errors (funcall close port-fd)))))))

(defun converge-pod-egress-policies
    (specs endpoints &key pod-finder directory-fn (writer #'write-pod-egress-policy))
  "For each local Pod ENDPOINT (SANDBOX INTERFACE ADDRESS), resolve its egress
policy against SPECS and write it into that Pod's pinned maps -- DIRECTORY-FN
maps a sandbox to its bpffs pin directory. Data-only: no attach, no recompile.
Fail-soft per endpoint; returns the list of sandboxes written."
  (let ((written '()))
    (dolist (endpoint endpoints (nreverse written))
      (handler-case
          (destructuring-bind (sandbox interface address) endpoint
            (declare (ignore interface))
            (multiple-value-bind (namespace labels) (funcall pod-finder address)
              (when namespace
                (multiple-value-bind (isolated policy)
                    (resolve-pod-policy
                     (make-np-pod :name sandbox :namespace namespace :labels labels :ip address)
                     specs '() :egress)
                  (funcall writer (funcall directory-fn sandbox) isolated policy)
                  (push sandbox written)))))
        (error (condition)
          (format *error-output* "gr8s: netpol endpoint ~S failed: ~A~%" endpoint condition)
          nil)))))

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
  "Parse TEXT as address/prefix, returning (values family-length address-integer-or-nil prefix), or NIL.
IPv4 addresses are returned as integers; an IPv6 one is only checked for form."
  (let ((slash (and (stringp text) (position #\/ text))))
    (when slash
      (let* ((address (subseq text 0 slash)) (digits (subseq text (1+ slash)))
             (prefix (and (<= 1 (length digits) 3) (every #'digit-char-p digits) (parse-integer digits))))
        (cond ((null prefix) nil)
              ((find #\: address)
               (and (<= prefix 128) (not (find #\% address))
                    (handler-case (progn (0conf:parse-ipv6 address) (values 128 nil prefix)) (error () nil))))
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
                                  (or (null network)
                                      (= (ash inner-network (- prefix 32)) (ash network (- prefix 32)))))
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
