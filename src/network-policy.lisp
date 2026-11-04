;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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
