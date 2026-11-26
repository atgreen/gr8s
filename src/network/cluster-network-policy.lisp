;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Enforce policy.networking.k8s.io/v1alpha2 ClusterNetworkPolicy (podster-wv1w.1,
;;;; docs/design-agent-egress.md) through the same per-Pod tries as NetworkPolicy.
;;;;
;;;; The control plane resolves each policy as it resolves NetworkPolicy: its subject
;;;; becomes the selected Pods by namespace/name, and pods, namespaces and nodes peers
;;;; become addresses, so a node enforces it without seeing other Pods. domainNames
;;;; peers are kept by name: no address admits them, since hosts behind shared CDN
;;;; addresses can't be told apart by IP; the node egress proxy admits them by SNI or
;;;; Host (podster-wv1w.2).
;;;;
;;;; The tries hold only what is allowed, while ClusterNetworkPolicy rules Accept, Deny
;;;; or Pass in order across tiers: Admin policies by priority, then the Pod's
;;;; NetworkPolicy (final for a Pod it isolates), then Baseline policies, and whatever
;;;; is left undecided is allowed. The tries resolve an address by its longest prefix,
;;;; and every rule's CIDR is one of the prefixes, so a rule covers every address whose
;;;; longest prefix is P exactly when its CIDR contains P. Evaluating the rules in order
;;;; for each such region gives one allowed port set per prefix, which becomes one
;;;; entry excepting the more specific prefixes -- the shape the NetworkPolicy writer
;;;; already takes. A Pod no ClusterNetworkPolicy selects takes NetworkPolicy's path
;;;; unchanged.

(in-package #:gr8s.network)

(defparameter +egress-proxy-address+ "169.254.1.2"
  "The node-local address captured connections are redirected to. Like the node
gateway 169.254.1.1 it is link-local, so it is never routed off the node.")

(defparameter +egress-synthetic-cidr+ gr8s.resources::+egress-synthetic-cidr+
  "The range synthetic DNS answers come from (podster-wv1w.8): RFC 2544's benchmarking
block, 198.18.0.0/15, which no public host uses. The node delivers it locally, to the
egress proxy; Pod pools and ServiceCIDRs may not overlap it.")

;;; ---------------------------------------------------------------------------
;;; Port sets: TCP, UDP and SCTP port intervals, and whether every other protocol
;;; (ICMP and the rest) is in the set. A ClusterNetworkPolicy rule without
;;; protocols matches all traffic, so "everything but TCP 22" must be expressible.

(defconstant +pset-max-port+ 65535)

(defun pset-empty () (list nil nil nil nil))

(defun pset-full ()
  (list (list (cons 0 +pset-max-port+)) (list (cons 0 +pset-max-port+))
        (list (cons 0 +pset-max-port+)) t))

(defun %pset-index (protocol)
  "The interval list index of protocol number PROTOCOL, or NIL for another protocol."
  (case protocol (6 0) (17 1) (132 2)))

(defun %intervals-normalize (intervals)
  "Sort and merge INTERVALS, a list of (first . last) inclusive."
  (let ((sorted (sort (copy-list intervals) #'< :key #'car)) (merged '()))
    (dolist (interval sorted (nreverse merged))
      (if (and merged (<= (car interval) (1+ (cdr (first merged)))))
          (setf (cdr (first merged)) (max (cdr (first merged)) (cdr interval)))
          (push (cons (car interval) (cdr interval)) merged)))))

(defun %intervals-difference (intervals removed)
  "The parts of INTERVALS not in REMOVED (both normalized)."
  (let ((result '()))
    (dolist (interval intervals (%intervals-normalize result))
      (let ((pieces (list (cons (car interval) (cdr interval)))))
        (dolist (cut removed)
          (setf pieces
                (loop for (first . last) in pieces
                      append (cond ((or (< (cdr cut) first) (> (car cut) last)) (list (cons first last)))
                                   (t (append (when (< first (car cut)) (list (cons first (1- (car cut)))))
                                              (when (> last (cdr cut)) (list (cons (1+ (cdr cut)) last)))))))))
        (setf result (append result pieces))))))

(defun pset-union (a b)
  (list (%intervals-normalize (append (first a) (first b)))
        (%intervals-normalize (append (second a) (second b)))
        (%intervals-normalize (append (third a) (third b)))
        (or (fourth a) (fourth b))))

(defun pset-difference (a b)
  (list (%intervals-difference (first a) (first b))
        (%intervals-difference (second a) (second b))
        (%intervals-difference (third a) (third b))
        (and (fourth a) (not (fourth b)))))

(defun pset-intersection (a b)
  (pset-difference a (pset-difference a b)))

(defun pset-empty-p (set)
  (and (null (first set)) (null (second set)) (null (third set)) (not (fourth set))))

(defun pset-from-ranges (ports)
  "PORTS as NetworkPolicy entries carry them -- :all, or (protocol first last) lists
with FIRST NIL for every port of the protocol -- as a port set."
  (if (eq ports :all)
      (pset-full)
      (let ((set (pset-empty)))
        (dolist (range ports set)
          (destructuring-bind (protocol first last) range
            (let ((index (%pset-index protocol)))
              (when index
                (setf (nth index set)
                      (%intervals-normalize
                       (cons (if first (cons first (or last first)) (cons 0 +pset-max-port+))
                             (nth index set)))))))))))

(defun pset-to-ranges (set)
  "SET as NetworkPolicy entry ports: :all, or (protocol first last) lists, or NIL when empty.
Every other protocol becomes one whole-protocol range per protocol number."
  (if (equal set (pset-full))
      :all
      (append
       (loop for protocol in '(6 17 132)
             for intervals in set
             append (loop for (first . last) in intervals
                          collect (if (and (= first 0) (= last +pset-max-port+))
                                      (list protocol nil nil)
                                      (list protocol first last))))
       (when (fourth set)
         (loop for protocol from 0 below 256
               unless (%pset-index protocol) collect (list protocol nil nil))))))

;;; ---------------------------------------------------------------------------
;;; Control plane: resolve a stored ClusterNetworkPolicy into what a node enforces.

(defun %cnp-protocol-number (key)
  (cdr (assoc key '(("tcp" . 6) ("udp" . 17) ("sctp" . 132)) :test #'equal)))

(defun cnp-protocol-ports (protocols)
  "A rule's protocols as resolved port objects (protocol, port, endPort), or :all when
the rule names none. Named ports are resolved per destination by the caller."
  (if (or (null protocols) (zerop (length protocols)))
      :all
      (loop for protocol across protocols
            append (loop for key in '("tcp" "udp" "sctp")
                         for body = (gethash key protocol)
                         when body
                           collect (let* ((port (gethash "destinationPort" body))
                                          (number (and port (gethash "number" port)))
                                          (range (and port (gethash "range" port)))
                                          (object (core-object "protocol" (string-upcase key))))
                                     (cond (number (setf (gethash "port" object) number))
                                           (range (setf (gethash "port" object) (gethash "start" range)
                                                        (gethash "endPort" object) (gethash "end" range))))
                                     object)))))

(defun %cnp-named-ports (protocols)
  (when protocols
    (loop for protocol across protocols
          for name = (gethash "destinationNamedPort" protocol)
          when (stringp name) collect name)))

(defun %cnp-namespaced-pods (selector pods namespace-labels)
  "PODS a NamespacedPod selector picks: namespaceSelector (absent or empty: all) and podSelector."
  (let ((namespace-selector (gethash "namespaceSelector" selector))
        (pod-selector (gethash "podSelector" selector)))
    (remove-if-not (lambda (pod)
                     (and (or (null namespace-selector)
                              (np-selector-matches-p namespace-selector
                                                     (gethash (np-pod-namespace pod) namespace-labels)))
                          (or (null pod-selector)
                              (np-selector-matches-p pod-selector (np-pod-labels pod)))))
                   pods)))

(defun %cnp-namespace-pods (selector pods namespace-labels)
  (remove-if-not (lambda (pod)
                   (np-selector-matches-p selector (gethash (np-pod-namespace pod) namespace-labels)))
                 pods))

(defun cnp-subject-pods (subject pods namespace-labels)
  "The PODS a policy's subject selects."
  (cond ((gethash "namespaces" subject) (%cnp-namespace-pods (gethash "namespaces" subject) pods namespace-labels))
        ((gethash "pods" subject) (%cnp-namespaced-pods (gethash "pods" subject) pods namespace-labels))))

(defun %cnp-host-cidr (address)
  (format nil "~A/~D" address (if (find #\: address) 128 32)))

(defun resolve-cnp-rule (rule direction pods namespace-labels nodes)
  "Resolve one rule into rule objects (name, action, networks, domainNames, ports) a node
enforces. NODES is a list of (labels . addresses). A destinationNamedPort is each
destination Pod's own number for it, so such a rule becomes one per Pod defining it."
  (let* ((peers (coerce (gethash (if (eq direction :egress) "to" "from") rule #()) 'list))
         (protocols (gethash "protocols" rule))
         (named (%cnp-named-ports protocols))
         (peer-pods '()) (networks '()) (domains '()))
    (dolist (peer peers)
      (cond ((gethash "pods" peer)
             (setf peer-pods (append peer-pods (%cnp-namespaced-pods (gethash "pods" peer) pods namespace-labels))))
            ((gethash "namespaces" peer)
             (setf peer-pods (append peer-pods (%cnp-namespace-pods (gethash "namespaces" peer) pods namespace-labels))))
            ((gethash "nodes" peer)
             (loop for (labels . addresses) in nodes
                   when (np-selector-matches-p (gethash "nodes" peer) labels)
                     do (setf networks (append networks (mapcar #'%cnp-host-cidr addresses)))))
            ((gethash "networks" peer)
             (setf networks (append networks (coerce (gethash "networks" peer) 'list))))
            ((gethash "domainNames" peer)
             (setf domains (append domains (coerce (gethash "domainNames" peer) 'list))))))
    (setf peer-pods (remove-duplicates peer-pods))
    (flet ((rule-object (cidrs domain-names ports)
             (let ((object (core-object "action" (gethash "action" rule)
                                        "networks" (coerce (remove-duplicates cidrs :test #'equal) 'vector))))
               (when (gethash "name" rule) (setf (gethash "name" object) (gethash "name" rule)))
               (when domain-names (setf (gethash "domainNames" object) (coerce domain-names 'vector)))
               (unless (eq ports :all) (setf (gethash "ports" object) (coerce ports 'vector)))
               object)))
      (let ((pod-cidrs (loop for pod in peer-pods append (mapcar #'%cnp-host-cidr (np-pod-addresses pod)))))
        (if named
            ;; Named ports exist only on Pods; the API forbids them with other peers.
            (loop for pod in (sort (copy-list peer-pods) #'string< :key #'np-pod-ip)
                  for ports = (loop for name in named
                                    append (loop for (port-name protocol number) in (np-pod-ports pod)
                                                 when (equal port-name name)
                                                   collect (core-object "protocol" (string-upcase (symbol-name protocol))
                                                                        "port" number)))
                  when ports collect (rule-object (mapcar #'%cnp-host-cidr (np-pod-addresses pod)) nil ports))
            (let ((ports (cnp-protocol-ports protocols)))
              (unless (eq ports :all)
                (when (null ports) (return-from resolve-cnp-rule nil)))
              (list (rule-object (append networks pod-cidrs) domains ports))))))))

(defun resolve-cluster-network-policy (object pods namespace-labels nodes)
  "A copy of ClusterNetworkPolicy OBJECT a node can enforce: its subject as the selected
Pods' \"namespace/name\" and every rule's peers as networks and domainNames."
  (let* ((spec (gethash "spec" object (core-object)))
         (subject (cnp-subject-pods (gethash "subject" spec (core-object)) pods namespace-labels))
         (resolved (core-object "tier" (gethash "tier" spec)
                                "priority" (gethash "priority" spec)
                                "subjectPods" (coerce (sort (mapcar (lambda (pod) (format nil "~A/~A" (np-pod-namespace pod)
                                                                                           (np-pod-name pod)))
                                                                    subject)
                                                            #'string<)
                                                      'vector)))
         (result (copy-core-object object)))
    (dolist (direction '(:egress :ingress))
      (let ((key (if (eq direction :egress) "egress" "ingress")))
        (setf (gethash key resolved)
              (coerce (loop for rule across (gethash key spec #())
                            append (resolve-cnp-rule rule direction pods namespace-labels nodes))
                      'vector))))
    (setf (gethash "spec" result) resolved)
    (remhash "status" result)
    result))

(defun cluster-network-policy-nodes (store)
  "Every Node as (labels . addresses) for nodes peers: its labels and its underlay address,
the InternalIP it reports."
  (let ((nodes (gr8s.store::with-store-lock (store)
                 (loop for node being the hash-values of (gr8s.store::pod-store-nodes store) collect node))))
    (loop for node in nodes
          for address = (gr8s.model::node-record-underlay-address node)
          collect (cons (or (gr8s.model::node-record-labels node) (core-object))
                        (when (and (stringp address) (plusp (length address))) (list address))))))

(defun cluster-network-policy-projection (store)
  "The ClusterNetworkPolicies to project to nodes, each resolved against the current Pods,
Namespaces and Nodes."
  (let ((policies (list-core-resources store "clusternetworkpolicies")))
    (when policies
      (let ((pods (cons (node-dns-policy-peer) (network-policy-cluster-pods store)))
            (namespace-labels (network-policy-namespace-labels store))
            (nodes (ignore-errors (cluster-network-policy-nodes store))))
        (mapcar (lambda (object) (resolve-cluster-network-policy object pods namespace-labels nodes))
                policies)))))

;;; ---------------------------------------------------------------------------
;;; Node: evaluate a Pod's tiers into NetworkPolicy-shaped entries.

(defstruct (cnp-rule (:constructor make-cnp-rule (&key action networks domain-names ports name)))
  "A resolved rule: ACTION :accept, :deny or :pass; NETWORKS CIDR strings; DOMAIN-NAMES;
PORTS a port set."
  action networks domain-names ports name)

(defstruct (cnp-spec (:constructor make-cnp-spec (&key name tier priority subject-pods egress ingress)))
  "A resolved ClusterNetworkPolicy: TIER :admin or :baseline, PRIORITY, the selected Pods
as \"namespace/name\" strings, and its rules in order per direction."
  name tier priority subject-pods egress ingress)

(defun %cnp-parse-rule (object)
  (make-cnp-rule
   :name (gethash "name" object)
   :action (cdr (assoc (gethash "action" object) '(("Accept" . :accept) ("Deny" . :deny) ("Pass" . :pass))
                       :test #'equal))
   :networks (coerce (gethash "networks" object #()) 'list)
   :domain-names (coerce (gethash "domainNames" object #()) 'list)
   :ports (multiple-value-bind (ports present) (gethash "ports" object)
            (if present
                (pset-from-ranges (loop for port across ports
                                        for protocol = (netpol-proto-number
                                                        (intern (string-upcase (gethash "protocol" port "TCP")) :keyword))
                                        collect (list protocol (gethash "port" port)
                                                      (or (gethash "endPort" port) (gethash "port" port)))))
                (pset-full)))))

(defun cluster-network-policy-specs-from-objects (objects)
  "Parse projected ClusterNetworkPolicies. An object the control plane didn't resolve is skipped."
  (loop for object in objects
        for spec = (gethash "spec" object)
        when (and (hash-table-p spec) (nth-value 1 (gethash "subjectPods" spec)))
          collect (make-cnp-spec
                   :name (gethash "name" (gethash "metadata" object))
                   :tier (if (equal (gethash "tier" spec) "Baseline") :baseline :admin)
                   :priority (gethash "priority" spec 0)
                   :subject-pods (coerce (gethash "subjectPods" spec) 'list)
                   :egress (map 'list #'%cnp-parse-rule (gethash "egress" spec #()))
                   :ingress (map 'list #'%cnp-parse-rule (gethash "ingress" spec #())))))

(defun cnp-selects-pod-p (spec pod)
  (member (format nil "~A/~A" (np-pod-namespace pod) (np-pod-name pod)) (cnp-spec-subject-pods spec)
          :test #'equal))

(defparameter +gr8-sandbox-label+ "gr8s.io/gr8-command"
  "The label gr8 gives the Pod it runs a command in.")

(defun gr8-sandbox-pod-p (pod)
  "True when POD is a gr8 sandbox: its egress is captured and named, and anything its
policies don't allow is denied (podster-1mzb)."
  (let ((labels (np-pod-labels pod)))
    (and (hash-table-p labels) (nth-value 1 (gethash +gr8-sandbox-label+ labels)) t)))

(defun gr8-sandbox-egress-rule ()
  "The rule after every policy's for a gr8 sandbox: deny what nothing above allowed."
  (make-cnp-rule :name "gr8-sandbox" :action :deny :networks '("0.0.0.0/0" "::/0")
                 :ports (pset-full)))

(defun pod-cluster-network-policy-tiers (pod cnps direction)
  "POD's DIRECTION rules, in evaluation order: (values admin-rules baseline-rules), each
the selecting policies' rules by priority (then name), in their written order. A gr8
sandbox's egress ends with the gr8-sandbox Deny."
  (flet ((tier (which)
           (loop for spec in (sort (remove-if-not (lambda (spec) (and (eq (cnp-spec-tier spec) which)
                                                                      (cnp-selects-pod-p spec pod)))
                                                  cnps)
                                   (lambda (a b) (if (= (cnp-spec-priority a) (cnp-spec-priority b))
                                                     (string< (cnp-spec-name a) (cnp-spec-name b))
                                                     (< (cnp-spec-priority a) (cnp-spec-priority b)))))
                 append (if (eq direction :egress) (cnp-spec-egress spec) (cnp-spec-ingress spec)))))
    (values (tier :admin)
            (append (tier :baseline)
                    (when (and (eq direction :egress) (gr8-sandbox-pod-p pod))
                      (list (gr8-sandbox-egress-rule)))))))

(defun %family-prefix-functions (family)
  (if (eq family :ipv4)
      (values #'np-prefix 32 "0.0.0.0/0")
      (values #'np-prefix-v6 128 "::/0")))

(defun %cidr-family (cidr) (if (find #\: cidr) :ipv6 :ipv4))

(defun ordered-policy-entries (np-isolated np-entries admin baseline family)
  "Entries (cidr excepts ports) for FAMILY that hold exactly what POD's tiers allow: ADMIN
rules in order, then NetworkPolicy (NP-ENTRIES, final when NP-ISOLATED), then BASELINE
rules, then everything undecided."
  (multiple-value-bind (prefix-of bits everything) (%family-prefix-functions family)
    (let* ((rules (append admin baseline))
           (cidrs (remove-duplicates
                   (append (list everything)
                           (loop for (cidr excepts) in np-entries
                                 when (eq (%cidr-family cidr) family)
                                   collect cidr
                                   and append (remove-if-not (lambda (e) (eq (%cidr-family e) family)) excepts))
                           (loop for rule in rules
                                 append (remove-if-not (lambda (c) (eq (%cidr-family c) family))
                                                       (cnp-rule-networks rule))))
                   :test #'equal :key prefix-of))
           (prefixes (mapcar (lambda (cidr) (cons (funcall prefix-of cidr) cidr)) cidrs)))
      (labels ((within-p (inner outer)
                 (and (>= (cdr inner) (cdr outer))
                      (= (ash (car inner) (- (cdr outer) bits)) (ash (car outer) (- (cdr outer) bits)))))
               (covers-p (cidr prefix) (within-p prefix (funcall prefix-of cidr)))
               (rule-covers-p (rule prefix)
                 (some (lambda (cidr) (and (eq (%cidr-family cidr) family) (covers-p cidr prefix)))
                       (cnp-rule-networks rule)))
               (run-tier (tier-rules prefix decided allowed)
                 (let ((done (pset-empty)))
                   (dolist (rule tier-rules (values decided allowed))
                     (when (rule-covers-p rule prefix)
                       (let ((matched (pset-difference (pset-difference (cnp-rule-ports rule) decided) done)))
                         (ecase (cnp-rule-action rule)
                           (:accept (setf allowed (pset-union allowed matched)
                                          decided (pset-union decided matched)))
                           (:deny (setf decided (pset-union decided matched)))
                           (:pass (setf done (pset-union done matched))))))))))
        (loop for (prefix . cidr) in prefixes
              for allowed = (let ((decided (pset-empty)) (allowed (pset-empty)))
                              (multiple-value-setq (decided allowed) (run-tier admin prefix decided allowed))
                              (when np-isolated
                                (let ((np (reduce #'pset-union
                                                  (loop for (entry-cidr excepts ports) in np-entries
                                                        when (and (eq (%cidr-family entry-cidr) family)
                                                                  (covers-p entry-cidr prefix)
                                                                  (notany (lambda (e) (and (eq (%cidr-family e) family)
                                                                                           (covers-p e prefix)))
                                                                          excepts))
                                                          collect (pset-from-ranges ports))
                                                  :initial-value (pset-empty))))
                                  (setf allowed (pset-union allowed (pset-difference np decided))
                                        decided (pset-full))))
                              (multiple-value-setq (decided allowed) (run-tier baseline prefix decided allowed))
                              (pset-union allowed (pset-difference (pset-full) decided)))
              unless (pset-empty-p allowed)
                collect (list cidr
                              (loop for (other . other-cidr) in prefixes
                                    when (and (not (equal other prefix)) (within-p other prefix))
                                      collect other-cidr)
                              (pset-to-ranges allowed)))))))

(defun pod-policy-entries (pod specs cnps direction)
  "POD's DIRECTION policy from NetworkPolicy SPECS and ClusterNetworkPolicy CNPS:
(values isolated entries), as POD-NETWORK-POLICY-ENTRIES returns for NetworkPolicy alone."
  (multiple-value-bind (np-isolated np-entries) (pod-network-policy-entries pod specs direction)
    (multiple-value-bind (admin baseline) (pod-cluster-network-policy-tiers pod cnps direction)
      (cond ((and (null admin) (null baseline))
             (values np-isolated np-entries))
            (t
             (let ((entries (append (ordered-policy-entries np-isolated np-entries admin baseline :ipv4)
                                    (ordered-policy-entries np-isolated np-entries admin baseline :ipv6))))
               ;; A captured Pod's connections leave through the node egress proxy,
               ;; which decides them itself; the guard must let them reach it.
               (when (and (eq direction :egress)
                          (or (gr8-sandbox-pod-p pod) (some #'cnp-rule-domain-names (append admin baseline))))
                 (push (list (format nil "~A/32" +egress-proxy-address+) '() '((6 nil nil) (17 53 53))) entries)
                 ;; And the synthetic addresses its DNS answers with, which reach the
                 ;; proxy too (podster-wv1w.8).
                 (push (list +egress-synthetic-cidr+ '() '((6 nil nil))) entries))
               (values t entries)))))))

(defun pod-egress-domain-rules (pod cnps)
  "POD's egress rules in evaluation order with the domain names each admits, for the node
egress proxy: a list of cnp-rule (Admin by priority, then Baseline)."
  (multiple-value-bind (admin baseline) (pod-cluster-network-policy-tiers pod cnps :egress)
    (append admin baseline)))

;;; ---------------------------------------------------------------------------
;;; Egress by name (podster-wv1w.2). A Pod whose egress rules name domains is
;;; captured: its TCP to destinations outside the cluster is redirected to the
;;; node egress proxy, which learns the destination name from the TLS SNI or HTTP
;;; Host and decides the connection here. The redirect keeps the original port but
;;; not the original address, so the proxy resolves the name itself and checks
;;; the address it will connect to against the address rules.

(defun egress-domain-matches-p (pattern host)
  "True when HOST matches a ClusterNetworkPolicy domainNames PATTERN: the same name, or
for \"*.example.com\" any name with one or more whole labels in front of example.com
(not example.com itself). Case and a trailing dot don't matter."
  (flet ((canonical (name) (string-downcase (string-right-trim "." name))))
    (let ((pattern (canonical pattern)) (host (canonical host)))
      (if (and (> (length pattern) 2) (string= "*." pattern :end2 2))
          (let ((suffix (subseq pattern 1)))
            (and (> (length host) (length suffix))
                 (string= suffix host :start2 (- (length host) (length suffix)))))
          (string= pattern host)))))

(defun pod-egress-captured-p (pod cnps &optional profiles)
  "True when POD is a gr8 sandbox, one of its egress ClusterNetworkPolicy rules names
domains, or a SecurityProfile among PROFILES selects it for credential injection."
  (or (gr8-sandbox-pod-p pod)
      (some #'cnp-rule-domain-names (pod-egress-domain-rules pod cnps))
      (some (lambda (profile) (funcall 'security-profile-selects-pod-p profile pod)) profiles)))

(defun pod-egress-allowed-domains (pod cnps)
  "The domain patterns POD's Accept rules name: what the node DNS server answers for it."
  (remove-duplicates
   (loop for rule in (pod-egress-domain-rules pod cnps)
         when (eq (cnp-rule-action rule) :accept) append (cnp-rule-domain-names rule))
   :test #'equal))

(defun %port-set-member-p (set protocol port)
  (let ((index (%pset-index protocol)))
    (if index
        (some (lambda (interval) (<= (car interval) port (cdr interval))) (nth index set))
        (fourth set))))

(defun egress-connection-verdict (pod specs cnps host address port)
  "Decide POD's TCP connection to HOST (a name, or NIL) at ADDRESS (a string, or NIL)
on PORT, as the tiers decide a packet: Admin rules in order, the Pod's NetworkPolicy
(final when it isolates the Pod), Baseline rules, then allow. A rule matches when one of
its domains matches HOST or one of its networks covers ADDRESS, on a port it names.
Returns (values allowed-p rule), RULE the deciding cnp-rule, or NIL."
  (multiple-value-bind (admin baseline) (pod-cluster-network-policy-tiers pod cnps :egress)
    (labels ((matches-p (rule)
               (and (%port-set-member-p (cnp-rule-ports rule) 6 port)
                    (or (and host (some (lambda (pattern) (egress-domain-matches-p pattern host))
                                        (cnp-rule-domain-names rule)))
                        (and address
                             (some (lambda (cidr) (network-address-in-cidr-p cidr address))
                                   (cnp-rule-networks rule))))))
             (tier (rules)
               ;; :accept, :deny, or NIL when the tier passes or doesn't decide.
               (dolist (rule rules nil)
                 (when (matches-p rule)
                   (return (case (cnp-rule-action rule)
                             (:accept (values :accept rule))
                             (:deny (values :deny rule))
                             (:pass nil)))))))
      (multiple-value-bind (decision rule) (tier admin)
        (when decision (return-from egress-connection-verdict (values (eq decision :accept) rule))))
      (multiple-value-bind (isolated entries) (pod-network-policy-entries pod specs :egress)
        (when isolated
          (return-from egress-connection-verdict
            (values (and address
                         (some (lambda (entry)
                                 (destructuring-bind (cidr excepts ports) entry
                                   (and (network-address-in-cidr-p cidr address)
                                        (notany (lambda (e) (network-address-in-cidr-p e address)) excepts)
                                        (%port-set-member-p (pset-from-ranges ports) 6 port))))
                               entries)
                         t)
                    nil))))
      (multiple-value-bind (decision rule) (tier baseline)
        (when decision (return-from egress-connection-verdict (values (eq decision :accept) rule))))
      (values t nil))))
