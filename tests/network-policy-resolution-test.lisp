;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove NetworkPolicy resolution: LabelSelectors with matchExpressions, the
;;;; control plane's resolution of Pod and Namespace selector peers and egress
;;;; named ports into addresses, a node's per-direction isolation and allowed
;;;; entries, the longest-prefix tables that give ipBlock.except and port ranges
;;;; exactly, and how a Pod's maps are rewritten as data.

(in-package #:gr8s/tests)
(def-suite network-policy-resolution :in gr8s)
(in-suite network-policy-resolution)

(defun npr-json (text) (com.inuoe.jzon:parse text))

(defun npr-pod (name namespace ip &rest labels)
  (gr8s.network::make-np-pod :name name :namespace namespace :ip ip :labels (apply #'gr8s.network::np-labels labels)))

(defun npr-policy (namespace spec)
  "A NetworkPolicy object in NAMESPACE with SPEC (JSON text)."
  (npr-json (format nil "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",
                          \"metadata\":{\"namespace\":\"~A\",\"name\":\"p\"},\"spec\":~A}" namespace spec)))

(defun npr-peers (rule key)
  "The cidr strings of a resolved rule's ipBlock peers."
  (map 'list (lambda (peer) (gethash "cidr" (gethash "ipBlock" peer))) (gethash key rule #())))

(test npr-label-selectors-apply-match-labels-and-expressions
  (let ((labels (gr8s.network::np-labels "app" "web" "tier" "fe")))
    (is (gr8s.network::np-selector-matches-p (npr-json "{}") labels))
    (is (gr8s.network::np-selector-matches-p (npr-json "{\"matchLabels\":{\"app\":\"web\"}}") labels))
    (is (not (gr8s.network::np-selector-matches-p (npr-json "{\"matchLabels\":{\"app\":\"db\"}}") labels)))
    (is (gr8s.network::np-selector-matches-p
         (npr-json "{\"matchExpressions\":[{\"key\":\"tier\",\"operator\":\"In\",\"values\":[\"fe\",\"be\"]}]}") labels))
    (is (not (gr8s.network::np-selector-matches-p
              (npr-json "{\"matchExpressions\":[{\"key\":\"tier\",\"operator\":\"NotIn\",\"values\":[\"fe\"]}]}") labels)))
    (is (gr8s.network::np-selector-matches-p
         (npr-json "{\"matchExpressions\":[{\"key\":\"team\",\"operator\":\"DoesNotExist\"}]}") labels))
    (is (not (gr8s.network::np-selector-matches-p
              (npr-json "{\"matchExpressions\":[{\"key\":\"team\",\"operator\":\"Exists\"}]}") labels)))))

(test npr-parse-defaults-policy-types-and-reads-every-peer-and-port-form
  (let ((spec (gr8s.network::parse-network-policy-json
               (npr-policy "prod" "{\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}},
                  \"ingress\":[{}, {\"from\":[{\"ipBlock\":{\"cidr\":\"10.0.0.0/8\",\"except\":[\"10.1.0.0/16\"]}},
                                              {\"namespaceSelector\":{},\"podSelector\":{\"matchLabels\":{\"r\":\"c\"}}}],
                                     \"ports\":[{\"port\":\"http\"},{\"protocol\":\"UDP\"},{\"port\":8000,\"endPort\":8080}]}]}"))))
    (is (equal '("Ingress") (gr8s.network::np-spec-policy-types spec)))
    (is (eq :all (gr8s.network::np-rule-peers (first (gr8s.network::np-spec-ingress spec)))))
    (is (null (gr8s.network::np-rule-ports (first (gr8s.network::np-spec-ingress spec)))))
    (destructuring-bind (block selectors) (gr8s.network::np-rule-peers (second (gr8s.network::np-spec-ingress spec)))
      (is (equal "10.0.0.0/8" (gr8s.network::np-peer-cidr block)))
      (is (equal '("10.1.0.0/16") (gr8s.network::np-peer-except block)))
      (is (hash-table-p (gr8s.network::np-peer-namespace-selector selectors)))
      (is (hash-table-p (gr8s.network::np-peer-pod-selector selectors))))
    (destructuring-bind (named protocol range) (gr8s.network::np-rule-ports (second (gr8s.network::np-spec-ingress spec)))
      (is (equal '(:tcp "http" nil) (list (gr8s.network::np-port-protocol named) (gr8s.network::np-port-port named) (gr8s.network::np-port-end-port named))))
      (is (equal '(:udp nil nil) (list (gr8s.network::np-port-protocol protocol) (gr8s.network::np-port-port protocol) (gr8s.network::np-port-end-port protocol))))
      (is (equal '(:tcp 8000 8080) (list (gr8s.network::np-port-protocol range) (gr8s.network::np-port-port range) (gr8s.network::np-port-end-port range))))))
  ;; Egress rules add Egress to the defaulted types; explicit types stand as written.
  (is (equal '("Ingress" "Egress")
             (gr8s.network::np-spec-policy-types (gr8s.network::parse-network-policy-json (npr-policy "a" "{\"podSelector\":{},\"egress\":[{}]}")))))
  (is (equal '("Egress")
             (gr8s.network::np-spec-policy-types (gr8s.network::parse-network-policy-json (npr-policy "a" "{\"podSelector\":{},\"policyTypes\":[\"Egress\"]}"))))))

(defparameter *npr-pods*
  (list (npr-pod "a" "prod" "10.0.1.5" "app" "api" "tier" "be")
        (npr-pod "b" "prod" "10.0.1.6" "app" "api")
        (npr-pod "c" "dev" "10.0.1.7" "app" "api")
        (npr-pod "d" "dev" "10.0.1.8" "app" "web")))

(defun npr-namespaces ()
  (let ((labels (make-hash-table :test #'equal)))
    (setf (gethash "prod" labels) (gr8s.network::np-labels "kubernetes.io/metadata.name" "prod" "env" "production")
          (gethash "dev" labels) (gr8s.network::np-labels "kubernetes.io/metadata.name" "dev"))
    labels))

(defun npr-resolve (namespace spec &optional (pods *npr-pods*))
  (gethash "spec" (gr8s.network::resolve-network-policy-object (npr-policy namespace spec) pods (npr-namespaces))))

(test npr-control-plane-resolves-pod-and-namespace-selectors-to-addresses
  ;; A podSelector alone selects in the policy's namespace.
  (let ((spec (npr-resolve "prod" "{\"podSelector\":{},\"ingress\":[{\"from\":[{\"podSelector\":{\"matchLabels\":{\"app\":\"api\"}}}]}]}")))
    (is (equal '("Ingress") (coerce (gethash "policyTypes" spec) 'list)))
    (is (equal '("10.0.1.5/32" "10.0.1.6/32") (npr-peers (aref (gethash "ingress" spec) 0) "from"))))
  ;; A namespaceSelector by the automatic name label selects every Pod there; with a
  ;; podSelector, only the matching ones; matchExpressions work in both.
  (let ((spec (npr-resolve "prod" "{\"podSelector\":{},\"ingress\":[{\"from\":[
                 {\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"dev\"}}},
                 {\"namespaceSelector\":{\"matchExpressions\":[{\"key\":\"env\",\"operator\":\"Exists\"}]},
                  \"podSelector\":{\"matchExpressions\":[{\"key\":\"tier\",\"operator\":\"In\",\"values\":[\"be\"]}]}}]}]}")))
    (is (equal '("10.0.1.7/32" "10.0.1.8/32" "10.0.1.5/32") (npr-peers (aref (gethash "ingress" spec) 0) "from"))))
  ;; ipBlocks pass through with their exceptions.
  (let* ((spec (npr-resolve "prod" "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
                  \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.0.0.0/8\",\"except\":[\"10.0.1.0/24\"]}}]}]}"))
         (block (gethash "ipBlock" (aref (gethash "to" (aref (gethash "egress" spec) 0)) 0))))
    (is (equal "10.0.0.0/8" (gethash "cidr" block)))
    (is (equal '("10.0.1.0/24") (coerce (gethash "except" block) 'list))))
  ;; A rule whose selectors select nothing allows nothing: it must not become "every peer".
  (let ((spec (npr-resolve "prod" "{\"podSelector\":{},\"ingress\":[{\"from\":[{\"podSelector\":{\"matchLabels\":{\"app\":\"none\"}}}]}]}")))
    (is (zerop (length (gethash "ingress" spec)))))
  ;; A rule naming no peers stays one that allows every peer.
  (let ((spec (npr-resolve "prod" "{\"podSelector\":{},\"ingress\":[{\"ports\":[{\"port\":80}]}]}")))
    (is (= 1 (length (gethash "ingress" spec))))
    (is (not (nth-value 1 (gethash "from" (aref (gethash "ingress" spec) 0)))))))

(test npr-control-plane-resolves-egress-named-ports-per-destination-pod
  (let* ((pods (list (gr8s.network::make-np-pod :name "s1" :namespace "prod" :ip "10.0.2.1" :labels (gr8s.network::np-labels "app" "srv")
                                        :ports '(("serve-80" :tcp 80)))
                     (gr8s.network::make-np-pod :name "s2" :namespace "prod" :ip "10.0.2.2" :labels (gr8s.network::np-labels "app" "srv")
                                        :ports '(("serve-80" :tcp 8080) ("serve-80" :udp 9090)))
                     (gr8s.network::make-np-pod :name "s3" :namespace "prod" :ip "10.0.2.3" :labels (gr8s.network::np-labels "app" "srv"))))
         (spec (npr-resolve "prod" "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
                  \"egress\":[{\"to\":[{\"podSelector\":{\"matchLabels\":{\"app\":\"srv\"}}}],
                               \"ports\":[{\"port\":\"serve-80\"},{\"port\":53,\"protocol\":\"UDP\"}]}]}" pods))
         (rules (coerce (gethash "egress" spec) 'list)))
    ;; The numbered port keeps every selected peer; each Pod defining the name gets its own rule.
    (is (= 3 (length rules)))
    (is (equal '("10.0.2.1/32" "10.0.2.2/32" "10.0.2.3/32") (npr-peers (first rules) "to")))
    (is (equal '(53) (map 'list (lambda (port) (gethash "port" port)) (gethash "ports" (first rules)))))
    (is (equal '("10.0.2.1/32") (npr-peers (second rules) "to")))
    (is (equal '(80) (map 'list (lambda (port) (gethash "port" port)) (gethash "ports" (second rules)))))
    (is (equal '("10.0.2.2/32") (npr-peers (third rules) "to")))
    (is (equal '(8080) (map 'list (lambda (port) (gethash "port" port)) (gethash "ports" (third rules))))))
  ;; Ingress named ports name the selected Pod's own ports, which its node resolves.
  (let ((spec (npr-resolve "prod" "{\"podSelector\":{},\"ingress\":[{\"ports\":[{\"port\":\"serve-80\"}]}]}")))
    (is (equal "serve-80" (gethash "port" (aref (gethash "ports" (aref (gethash "ingress" spec) 0)) 0))))))

(test npr-node-isolates-and-collects-entries-per-direction
  (let* ((pod (gr8s.network::make-np-pod :name "web" :namespace "prod" :ip "10.0.0.1"
                                 :labels (gr8s.network::np-labels "app" "web") :ports '(("http" :tcp 8080))))
         (specs (gr8s.network::network-policy-specs-from-objects
                 (list (npr-policy "prod" "{\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}},\"policyTypes\":[\"Ingress\"],
                          \"ingress\":[{\"from\":[{\"ipBlock\":{\"cidr\":\"10.1.0.0/16\",\"except\":[\"10.1.2.0/24\"]}}],
                                        \"ports\":[{\"port\":\"http\"},{\"port\":\"missing\"},{\"protocol\":\"UDP\",\"port\":5000,\"endPort\":5003}]},
                                       {\"ports\":[{\"port\":\"missing\"}]}]}")
                       (npr-policy "prod" "{\"podSelector\":{},\"policyTypes\":[\"Egress\"]}")
                       (npr-policy "dev" "{\"podSelector\":{},\"ingress\":[{}]}")))))
    (multiple-value-bind (isolated entries) (gr8s.network::pod-network-policy-entries pod specs :ingress)
      (is-true isolated)
      ;; The named port resolves against the Pod; the rule whose only port is undefined allows nothing.
      (is (equal '(("10.1.0.0/16" ("10.1.2.0/24") ((6 8080 8080) (17 5000 5003)))) entries)))
    (multiple-value-bind (isolated entries) (gr8s.network::pod-network-policy-entries pod specs :egress)
      (is-true isolated)
      (is (null entries)))
    (multiple-value-bind (isolated entries)
        (gr8s.network::pod-network-policy-entries (npr-pod "x" "other" "10.0.0.9") specs :ingress)
      (is-false isolated)
      (is (null entries)))))

(test npr-tables-give-exceptions-and-overlapping-rules-exactly
  ;; Everything in 10/8 except 10.1/16; TCP 80 to 10.1.2/24; UDP to 10.1.2.3.
  (multiple-value-bind (cidrs ports)
      (gr8s.network::network-policy-tables '(("10.0.0.0/8" ("10.1.0.0/16") :all)
                                     ("10.1.2.0/24" () ((6 80 80)))
                                     ("10.1.2.3/32" () ((17 nil nil)))))
    (flet ((group (cidr) (cdr (assoc (gr8s.network::np-prefix cidr) cidrs :test #'equal))))
      (is (= 4 (length cidrs)))
      (is (= 0 (group "10.1.0.0/16")))
      (let ((all (group "10.0.0.0/8")) (http (group "10.1.2.0/24")) (both (group "10.1.2.3/32")))
        (is (equal (list (list all nil nil 0)) (remove all ports :key #'first :test-not #'eql)))
        (is (equal (list (list http 6 80 16)) (remove http ports :key #'first :test-not #'eql)))
        ;; The /32 inherits TCP 80 from the /24 and adds every UDP port.
        (is (equal (list (list both 6 80 16) (list both 17 nil 0)) (remove both ports :key #'first :test-not #'eql))))))
  ;; Equal port sets share a group.
  (multiple-value-bind (cidrs ports)
      (gr8s.network::network-policy-tables '(("10.0.0.1/32" () ((6 443 443))) ("10.0.0.2/32" () ((6 443 443)))))
    (is (= 1 (length (remove-duplicates (mapcar #'cdr cidrs)))))
    (is (= 1 (length ports)))))

(test npr-port-ranges-become-exact-prefix-covers
  (dolist (range '((8000 8080) (1 65535) (0 65535) (80 80) (1024 2047) (5000 5003) (65535 65535)))
    (destructuring-bind (first last) range
      (let ((covered (loop for (port . bits) in (gr8s.network::np-port-prefixes first last)
                           do (is (zerop (mod port (ash 1 (- 16 bits)))) "~A/~A is not aligned" port bits)
                           sum (ash 1 (- 16 bits)))))
        (is (= (1+ (- last first)) covered) "~A-~A covers ~A ports" first last covered))))
  (is (equal '((0 . 0)) (gr8s.network::np-port-prefixes 0 65535)))
  (is (equal '((8000 . 10) (8064 . 12) (8080 . 16)) (gr8s.network::np-port-prefixes 8000 8080))))

(test npr-map-keys-encode-the-guard-structs
  ;; LPM key = u32 prefixlen (host/LE) ++ masked network address (network order).
  (is (equalp #(16 0 0 0 10 123 0 0) (gr8s.network::netpol-cidr-lpm-key "10.123.0.0/16")))
  (is (equalp #(32 0 0 0 192 168 5 5) (gr8s.network::netpol-cidr-lpm-key "192.168.5.5/32")))
  (is (equalp #(16 0 0 0 10 123 0 0) (gr8s.network::netpol-cidr-lpm-key "10.123.4.5/16")))
  ;; Port key = prefixlen, group (LE), protocol, pad, port (network order).
  (is (equalp #(32 0 0 0 2 0 0 0 0 0 0 0) (gr8s.network::netpol-port-lpm-key 2 nil nil 0)))
  (is (equalp #(40 0 0 0 2 0 0 0 17 0 0 0) (gr8s.network::netpol-port-lpm-key 2 17 nil 0)))
  (is (equalp #(64 0 0 0 1 0 0 0 6 0 31 144) (gr8s.network::netpol-port-lpm-key 1 6 8080 16)))
  (is (equalp #(58 0 0 0 1 0 0 0 6 0 31 64) (gr8s.network::netpol-port-lpm-key 1 6 8000 10))))

(test npr-ipv6-rules-survive-node-resolution-and-use-128-bit-lpm-keys
  (let* ((pod (npr-pod "web" "prod" "10.0.0.1" "app" "web"))
         (specs (gr8s.network::network-policy-specs-from-objects
                 (list (npr-policy
                        "prod"
                        "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],\"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"fd12:3456:789a::/64\",\"except\":[\"fd12:3456:789a:1::/80\"]}}],\"ports\":[{\"protocol\":\"TCP\",\"port\":443}]}]}")))))
    (multiple-value-bind (isolated entries)
        (gr8s.network::pod-network-policy-entries pod specs :egress)
      (is-true isolated)
      (is (equal '(("fd12:3456:789a::/64" ("fd12:3456:789a:1::/80") ((6 443 443))))
                 entries))))
  ;; LPM prefix length is host-order u32; the following 16 bytes are the
  ;; masked IPv6 network in wire order.
  (is (equalp #(64 0 0 0 253 18 52 86 120 154 0 0 0 0 0 0 0 0 0 0)
              (gr8s.network::netpol-cidr-lpm-key "fd12:3456:789a::/64"))))

(test npr-ipv6-ipblock-except-must-be-a-strict-subset
  (flet ((validate (cidr except)
           (gr8s.network::validate-network-policy-peer
            (npr-json (format nil
                              "{\"ipBlock\":{\"cidr\":\"~A\",\"except\":[\"~A\"]}}"
                              cidr except))
            "spec.egress[0].to[0]")))
    (finishes (validate "fd12:3456::/48" "fd12:3456:0:1::/64"))
    (signals gr8s.model::kubernetes-error
      (validate "fd12:3456::/48" "fd12:9999::/64"))
    (signals gr8s.model::kubernetes-error
      (validate "fd12:3456::/48" "fd12:3456::/48"))))

(defun npr-capture-writes (egress ingress &key existing (exists t))
  "Run write-pod-network-policy against in-memory maps holding EXISTING (name . keys).
Return (values result final-contents events)."
  (let ((maps (make-hash-table :test #'equal)) (events '()))
    (loop for (name . keys) in existing
          do (dolist (key keys) (setf (gethash key (gethash name maps (setf (gethash name maps) (make-hash-table :test #'equalp)))) #(1))))
    (let ((result (gr8s.network::write-pod-network-policy
                   "/pin/sand/" egress ingress
                   :exists (lambda (path) (declare (ignore path)) exists)
                   :open (lambda (path) (subseq path (length "/pin/sand/")))
                   :map-info (lambda (fd name) (declare (ignore fd))
                               (or (gethash name maps) (setf (gethash name maps) (make-hash-table :test #'equalp))))
                   :update (lambda (map key value) (push (list :update map) events) (setf (gethash key map) value))
                   :delete (lambda (map key) (push (list :delete map) events) (remhash key map))
                   :keys (lambda (map) (loop for key being the hash-keys of map collect key))
                   :close (constantly nil))))
      (values result maps (nreverse events)))))

(test npr-pod-maps-hold-exactly-the-new-policy-and-mode-goes-last
  (let ((stale (gr8s.network::netpol-cidr-lpm-key "192.168.0.0/16")))
    (multiple-value-bind (result maps events)
        (npr-capture-writes (list t (list "10.0.0.0/8" '() '((6 443 443))))
                            (list nil)
                            :existing (list (list "netpol_egress_cidr" stale)))
      (is-true result)
      (let ((cidr (gethash "netpol_egress_cidr" maps)))
        (is (= 1 (hash-table-count cidr)))
        (is (equalp #(1 0 0 0) (gethash (gr8s.network::netpol-cidr-lpm-key "10.0.0.0/8") cidr)))
        (is (null (gethash stale cidr))))
      (is (equalp #(1) (gethash (gr8s.network::netpol-port-lpm-key 1 6 443 16) (gethash "netpol_egress_ports" maps))))
      (is (zerop (hash-table-count (gethash "netpol_ingress_cidr" maps))))
      (let ((mode (gethash "netpol_mode" maps)))
        (is (equalp #(1 0 0 0) (gethash (gr8s.network::%netpol-u32-le 0) mode)))
        (is (equalp #(0 0 0 0) (gethash (gr8s.network::%netpol-u32-le 1) mode)))
        ;; The mode map is written after every trie.
        (is (eq mode (second (car (last events)))))
        (is (eq mode (second (car (last events 2))))))))
  ;; An endpoint created before these maps existed is left alone.
  (is (null (npr-capture-writes (list t) (list t) :exists nil))))

(test npr-pod-maps-fail-closed-when-a-trie-write-fails
  ;; A trie write that throws mid-way (e.g. an eBPF LPM map hitting its capacity)
  ;; must leave the Pod denied, not in the zero-initialised allow-all mode.
  (let* ((maps (make-hash-table :test #'equal))
         (egress-cidr (setf (gethash "netpol_egress_cidr" maps)
                            (make-hash-table :test #'equalp))))
    (flet ((trie-count (name) (hash-table-count (gethash name maps (make-hash-table)))))
      (signals error
        (gr8s.network::write-pod-network-policy
         "/pin/sand/"
         (list t (list "10.0.0.0/8" '() '((6 443 443)))) ; isolated egress with rules
         (list nil)
         :exists (constantly t)
         :open (lambda (path) (subseq path (length "/pin/sand/")))
         :map-info (lambda (fd name) (declare (ignore fd))
                     (or (gethash name maps) (setf (gethash name maps) (make-hash-table :test #'equalp))))
         ;; The egress CIDR trie is "full": adding to it throws.
         :update (lambda (map key value)
                   (when (eq map egress-cidr) (error "simulated LPM capacity exhaustion"))
                   (setf (gethash key map) value))
         :delete (lambda (map key) (remhash key map))
         :keys (lambda (map) (loop for key being the hash-keys of map collect key))
         :close (constantly nil)))
      ;; Deny-all: both directions isolated, every allow trie emptied.
      (let ((mode (gethash "netpol_mode" maps)))
        (is (equalp #(1 0 0 0) (gethash (gr8s.network::%netpol-u32-le 0) mode)))
        (is (equalp #(1 0 0 0) (gethash (gr8s.network::%netpol-u32-le 1) mode))))
      (dolist (name '("netpol_egress_cidr" "netpol_egress_ports"
                      "netpol_egress_cidr_v6" "netpol_egress_ports_v6"
                      "netpol_ingress_cidr" "netpol_ingress_ports"
                      "netpol_ingress_cidr_v6" "netpol_ingress_ports_v6"))
        (is (zerop (trie-count name)) "~A is emptied" name)))))

(test npr-converge-writes-changed-policies-and-skips-failures
  (let* ((specs (gr8s.network::network-policy-specs-from-objects
                 (list (npr-policy "prod" "{\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}},\"policyTypes\":[\"Egress\"],
                                            \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.0.0.0/8\"}}]}]}"))))
         (pods (list (cons "10.0.0.1" (npr-pod "web" "prod" "10.0.0.1" "app" "web"))
                     (cons "10.0.0.2" (npr-pod "db" "prod" "10.0.0.2" "app" "db"))))
         (endpoints '(("web" "eth0" "10.0.0.1") ("db" "eth0" "10.0.0.2") ("boom" "eth0" "10.0.0.3")))
         (writes '()))
    (flet ((converge ()
             (gr8s.network::converge-pod-network-policies
              specs endpoints
              :pod-finder (lambda (address)
                            (when (equal address "10.0.0.3") (error "boom"))
                            (cdr (assoc address pods :test #'equal)))
              :directory-fn (lambda (sandbox) (format nil "/npr-test/~A/" sandbox))
              :writer (lambda (directory egress ingress) (push (list directory egress ingress) writes) t))))
      (is (equal '("web" "db") (converge)))
      (is (equal '(t ("10.0.0.0/8" () :all)) (second (find "/npr-test/web/" writes :key #'first :test #'equal))))
      (is (equal '(nil) (second (find "/npr-test/db/" writes :key #'first :test #'equal))))
      ;; Nothing changed, so nothing is rewritten.
      (setf writes '())
      (is (null (converge)))
      (is (null writes))
      ;; The record forgets Pods that have gone.
      (setf endpoints '(("db" "eth0" "10.0.0.2")))
      (converge)
      (is (not (gethash "/npr-test/web/" gr8s.network::*pod-network-policy-written*))))))

(test npr-resolved-policy-compiles-to-a-classifier
  ;; The per-Pod compiled classifier (network-policy-program.lisp) still takes a flat policy.
  (let* ((pod (npr-pod "web" "prod" "10.0.0.1" "app" "web"))
         (dns (npr-pod "dns" "prod" "10.0.9.9" "app" "dns"))
         (spec (gr8s.network::parse-network-policy-json
                (npr-policy "prod" "{\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}},\"policyTypes\":[\"Egress\"],
                  \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.0.0.0/8\"}},{\"podSelector\":{\"matchLabels\":{\"app\":\"dns\"}}}],
                               \"ports\":[{\"protocol\":\"UDP\",\"port\":53}]}]}"))))
    (multiple-value-bind (isolated policy) (gr8s.network::resolve-pod-policy pod (list spec) (list pod dns) :egress)
      (is-true isolated)
      (is (equal '("10.0.0.0/8" "10.0.9.9/32") (mapcar #'gr8s.network::netpol-rule-cidr (gr8s.network::network-policy-rules policy)))))
    (multiple-value-bind (isolated maps progs) (gr8s.network::compile-pod-policy pod (list spec) (list pod dns) :egress)
      (is-true isolated)
      (is (null maps))
      (is (plusp (length (getf (first progs) :insns)))))
    (is (null (gr8s.network::compile-pod-policy pod (list spec) (list pod) :ingress)))))

(test npr-registered-as-stored-resource
  ;; NetworkPolicy is a stored core resource: the generic store path accepts it,
  ;; defaults kind/apiVersion/namespace, preserves spec, and it re-parses.
  (let* ((json "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",
                 \"metadata\":{\"name\":\"p\"},
                 \"spec\":{\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}},\"policyTypes\":[\"Egress\"]}}")
         (object (com.inuoe.jzon:parse json))
         (normalized (gr8s.resources::normalize-core-resource "networkpolicies" object "prod" "p" nil)))
    (is (string= "NetworkPolicy" (gethash "kind" normalized)))
    (is (string= "networking.k8s.io/v1" (gethash "apiVersion" normalized)))
    (is (string= "prod" (gethash "namespace" (gethash "metadata" normalized))))
    (let ((spec (gr8s.network::parse-network-policy-json normalized)))
      (is (equal "web" (gethash "app" (gethash "matchLabels" (gr8s.network::np-spec-pod-selector spec))))))))

(test npr-projection-resolves-stored-policies-against-pods-with-addresses
  (with-temporary-store (store path)
    (values path)
    (dolist (name '("prod" "dev"))
      (gr8s.resources::create-core-resource store "namespaces" (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" name)) nil))
    ;; No policy, no projection: nodes are not sent every Pod for nothing.
    (is (null (gr8s.network::network-policy-projection store)))
    (flet ((pod (namespace name labels ip &optional (phase "Running"))
             (let ((pod (create-pod store (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",
                           \"metadata\":{\"name\":\"~A\",\"namespace\":\"~A\",\"labels\":~A},
                           \"spec\":{\"containers\":[{\"name\":\"c\",\"image\":\"busybox\",
                                     \"ports\":[{\"name\":\"http\",\"containerPort\":8080}]}]}}" name namespace labels)))))
               (when ip
                 (setf (gethash (pod-uid pod) (gr8s.store::pod-store-pod-observed-statuses store))
                       (gr8s.resources::core-object "podIP" ip "phase" phase))))))
      (pod "prod" "client" "{\"role\":\"client\"}" "10.0.1.5")
      (pod "dev" "client" "{\"role\":\"client\"}" "10.0.1.6")
      (pod "prod" "pending" "{\"role\":\"client\"}" nil)
      (pod "prod" "done" "{\"role\":\"client\"}" "10.0.1.7" "Succeeded"))
    (gr8s.resources::create-core-resource
     store "networkpolicies"
     (npr-policy "prod" "{\"podSelector\":{\"matchLabels\":{\"app\":\"server\"}},
                          \"ingress\":[{\"from\":[{\"podSelector\":{\"matchLabels\":{\"role\":\"client\"}},
                                                   \"namespaceSelector\":{}}],
                                        \"ports\":[{\"port\":\"http\"}]}],
                          \"egress\":[{\"to\":[{\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"dev\"}}}],
                                       \"ports\":[{\"port\":\"http\"}]}]}")
     "prod")
    (let* ((projected (gr8s.network::network-policy-projection store))
           (spec (gethash "spec" (first projected))))
      (is (= 1 (length projected)))
      (is (equal '("Ingress" "Egress") (coerce (gethash "policyTypes" spec) 'list)))
      ;; Only Pods with an address that are not finished are peers.
      (is (equal '("10.0.1.5/32" "10.0.1.6/32") (npr-peers (aref (gethash "ingress" spec) 0) "from")))
      ;; The egress named port is the destination Pod's own number.
      (let ((egress (aref (gethash "egress" spec) 0)))
        (is (equal '("10.0.1.6/32") (npr-peers egress "to")))
        (is (equal '(8080) (map 'list (lambda (port) (gethash "port" port)) (gethash "ports" egress))))))))

(test npr-a-pod-getting-its-address-has-its-policy-written
  ;; Policies that only select a Pod do not change when it gets an address, so no
  ;; snapshot follows; the address itself must lead to the Pod's policy being written.
  (let ((directory (uiop:ensure-directory-pathname
                    (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-test-XXXXXX" (uiop:temporary-directory))))))
        (converged 0)
        (observed-runtime nil))
    (sb-int:encapsulate 'gr8s.agent::converge-node-network-policies-unlocked 'npr-count
                        (lambda (function runtime &rest arguments)
                          ;; Other live runtimes in the suite must neither count
                          ;; toward this observation nor lose their convergence.
                          (if (eq runtime observed-runtime)
                              (incf converged)
                              (apply function runtime arguments))))
    (unwind-protect
         (let* ((runtime (gr8s.agent::make-node-runtime directory (gr8s.runtime::make-fake-runtime) nil))
                (store (gr8s.agent::node-runtime-store runtime))
                (pod (create-pod store (parse-pod *valid-pod-json*))))
           (setf observed-runtime runtime)
           (gr8s.agent::cache-node-observation runtime pod (gr8s.resources::core-object "phase" "Pending"))
           (is (= 0 converged))
           (gr8s.agent::cache-node-observation runtime pod (gr8s.resources::core-object "phase" "Running" "podIP" "10.88.0.7"))
           (is (= 1 converged))
           ;; The same address again changes nothing.
           (gr8s.agent::cache-node-observation runtime pod (gr8s.resources::core-object "phase" "Running" "podIP" "10.88.0.7"
                                                                        "message" "still"))
           (is (= 1 converged)))
      (sb-int:unencapsulate 'gr8s.agent::converge-node-network-policies-unlocked 'npr-count)
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

;;; Explaining a connection (podster-5hv.3)

(defun npr-spec (namespace name spec)
  (let ((object (npr-policy namespace spec)))
    (setf (gethash "name" (gethash "metadata" object)) name)
    (gr8s.network::parse-network-policy-json object)))

(defun npr-explain (specs source destination port &optional (protocol "TCP") (namespace-labels (make-hash-table :test #'equal)))
  (gr8s.network::explain-network-connection specs source destination port protocol namespace-labels))

(defun npr-side (explanation side &optional (key "verdict"))
  (gethash key (gethash side explanation)))

(test npr-explains-open-allowed-and-denied-connections
  (let* ((web (list :pod (npr-pod "web-7c9-x" "shop" "10.0.0.5" "app" "web" "pod-template-hash" "7c9")))
         (db (list :pod (gr8s.network::make-np-pod :name "db-0" :namespace "shop" :ip "10.0.0.9"
                                                   :labels (gr8s.network::np-labels "app" "db")
                                                   :ports '(("pg" :tcp 5432)))))
         (lonely (list :pod (npr-pod "lonely" "shop" "10.0.0.7" "app" "lonely")))
         (specs (list (npr-spec "shop" "db" "{\"podSelector\":{\"matchLabels\":{\"app\":\"db\"}},
                        \"ingress\":[{\"ports\":[{\"port\":9187}]},
                                     {\"from\":[{\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}}}],
                                      \"ports\":[{\"port\":\"pg\"}]}]}"))))
    ;; Nothing isolates web, so leaving it is open; db's second rule admits it by named port.
    (let ((e (npr-explain specs web db 5432)))
      (is (equal "allowed" (gethash "verdict" e)))
      (is (equal "open" (npr-side e "egress")))
      (is (equal "allowed" (npr-side e "ingress")))
      (is (equalp #("shop/db") (npr-side e "ingress" "isolatedBy")))
      (let ((by (aref (npr-side e "ingress" "allowedBy") 0)))
        (is (equal "shop/db" (gethash "policy" by)))
        (is (= 2 (gethash "rule" by)))))
    ;; The first rule has no peers, so it admits anyone on 9187.
    (is (equal "allowed" (gethash "verdict" (npr-explain specs lonely db 9187))))
    ;; lonely to pg matches neither rule: denied, with a rule selecting lonely by its app label.
    (let* ((e (npr-explain specs lonely db 5432))
           (suggestion (npr-side e "ingress" "suggestion")))
      (is (equal "denied" (gethash "verdict" e)))
      (is (equalp #() (npr-side e "ingress" "allowedBy")))
      (is (search "# Add to shop/db, under spec.ingress:" suggestion))
      (is (search "app: lonely" suggestion))
      (is (search "port: 5432" suggestion))
      (is (null (search "namespaceSelector" suggestion)) "same namespace"))
    ;; A Pod's suggestion leaves out the labels that tell replicas apart.
    (let ((suggestion (npr-side (npr-explain (list (npr-spec "shop" "deny" "{\"podSelector\":{}}")) web db 80)
                                "ingress" "suggestion")))
      (is (search "app: web" suggestion))
      (is (null (search "pod-template-hash" suggestion))))))

(test npr-explains-namespaces-blocks-and-egress
  (let* ((prom (list :pod (npr-pod "prom-0" "monitoring" "10.0.1.4" "app.kubernetes.io/name" "prometheus")))
         (api (list :pod (npr-pod "api-1" "shop" "10.0.0.6" "app" "api")))
         (outside (list :address "203.0.113.8"))
         (namespace-labels (let ((table (make-hash-table :test #'equal)))
                             (setf (gethash "monitoring" table) (gr8s.network::np-labels "kubernetes.io/metadata.name" "monitoring"))
                             table))
         (specs (list (npr-spec "shop" "api" "{\"podSelector\":{\"matchLabels\":{\"app\":\"api\"}},
                        \"policyTypes\":[\"Ingress\",\"Egress\"],
                        \"ingress\":[{\"from\":[{\"ipBlock\":{\"cidr\":\"203.0.113.0/24\",\"except\":[\"203.0.113.8/32\"]}}]}],
                        \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"0.0.0.0/0\"}}],\"ports\":[{\"port\":443}]}]}"))))
    ;; A Pod in another namespace gets a namespaceSelector beside its podSelector.
    (let ((suggestion (npr-side (npr-explain specs prom api 8080 "TCP" namespace-labels) "ingress" "suggestion")))
      (is (search "app.kubernetes.io/name: prometheus" suggestion))
      (is (search "kubernetes.io/metadata.name: monitoring" suggestion)))
    ;; The excepted address is denied, and the suggestion names it as a /32.
    (let ((e (npr-explain specs outside api 8080)))
      (is (equal "denied" (gethash "verdict" e)))
      (is (equal "not-a-pod" (npr-side e "egress")))
      (is (search "cidr: 203.0.113.8/32" (npr-side e "ingress" "suggestion"))))
    (is (equal "allowed" (gethash "verdict" (npr-explain specs (list :address "203.0.113.9") api 8080))))
    ;; Egress: 443 out is allowed, 80 is denied leaving api.
    (is (equal "allowed" (npr-side (npr-explain specs api outside 443) "egress")))
    (let ((e (npr-explain specs api outside 80)))
      (is (equal "denied" (npr-side e "egress")))
      (is (search "spec.egress:" (npr-side e "egress" "suggestion")))
      (is (equal "not-a-pod" (npr-side e "ingress"))))
    ;; ICMP can't be named by a port, so only a port-less rule would admit it.
    (is (search "No ports" (npr-side (npr-explain specs prom api nil "ICMPv4" namespace-labels) "ingress" "suggestion")))
    (multiple-value-bind (ingress egress) (gr8s.network::np-pod-isolation specs (second api))
      (is (equal '("shop/api") ingress))
      (is (equal '("shop/api") egress)))))

(defun npr-namespaces-with-kube-system ()
  (let ((labels (npr-namespaces)))
    (setf (gethash "kube-system" labels) (gr8s.network::np-labels "kubernetes.io/metadata.name" "kube-system"))
    labels))

(test npr-the-usual-dns-rule-selects-the-node-dns-gateway
  ;; gr8s has no kube-dns Pods: Pods resolve through the node gateway. The rule
  ;; charts write to allow DNS must still allow it (podster-5hv.10).
  (let* ((pods (cons (gr8s.network::node-dns-policy-peer) *npr-pods*))
         (spec (gethash "spec" (gr8s.network::resolve-network-policy-object
                                (npr-policy "prod" "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
                                   \"egress\":[{\"to\":[{\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"kube-system\"}},
                                                        \"podSelector\":{\"matchLabels\":{\"k8s-app\":\"kube-dns\"}}}],
                                                \"ports\":[{\"port\":53,\"protocol\":\"UDP\"},{\"port\":\"dns-tcp\",\"protocol\":\"TCP\"}]}]}")
                                pods (npr-namespaces-with-kube-system))))
         (rules (coerce (gethash "egress" spec) 'list)))
    (is (equal '("169.254.1.1/32") (npr-peers (first rules) "to")))
    (is (equal '(53) (map 'list (lambda (port) (gethash "port" port)) (gethash "ports" (first rules)))))
    ;; The named port resolves against the gateway's own: dns-tcp is TCP 53.
    (is (equal '("169.254.1.1/32") (npr-peers (second rules) "to")))
    (is (equal '(53) (map 'list (lambda (port) (gethash "port" port)) (gethash "ports" (second rules)))))))

(defparameter *npr-api-server*
  (list :address "10.96.0.1" :port 443 :endpoints '("10.77.77.20" "10.77.77.21") :endpoint-port 6443))

(defun npr-resolve-with-api (spec)
  (coerce (gethash "egress" (gethash "spec" (gr8s.network::resolve-network-policy-object
                                              (npr-policy "prod" spec) *npr-pods* (npr-namespaces)
                                              :api-server *npr-api-server*)))
          'list))

(defun npr-admits-api-service-p (rules)
  "True when one of RULES is exactly the API Service: 10.96.0.1/32 on TCP 443."
  (some (lambda (rule)
          (and (equal '("10.96.0.1/32") (npr-peers rule "to"))
               (equal '(("TCP" 443))
                      (map 'list (lambda (port) (list (gethash "protocol" port) (gethash "port" port)))
                           (gethash "ports" rule)))))
        rules))

(test npr-a-rule-admitting-the-api-servers-endpoints-admits-its-service
  ;; Upstream matches egress after DNAT, at the API server's endpoints; gr8s Pods
  ;; reach it at the Service address, so a rule admitting an endpoint on its port
  ;; admits the Service address and port too (podster-5hv.10).
  (is (npr-admits-api-service-p
       (npr-resolve-with-api "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
          \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.77.77.20/32\"}}],\"ports\":[{\"port\":6443}]}]}")))
  (is (npr-admits-api-service-p
       (npr-resolve-with-api "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
          \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.77.0.0/16\"}}]}]}")))
  (is (npr-admits-api-service-p
       (npr-resolve-with-api "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
          \"egress\":[{\"ports\":[{\"port\":6000,\"endPort\":7000,\"protocol\":\"TCP\"}]}]}")))
  ;; Not on the endpoint's port, not covering an endpoint, or excepting it: no.
  (is (not (npr-admits-api-service-p
            (npr-resolve-with-api "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
               \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.77.77.20/32\"}}],\"ports\":[{\"port\":80}]}]}"))))
  (is (not (npr-admits-api-service-p
            (npr-resolve-with-api "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
               \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.88.0.0/16\"}}]}]}"))))
  (is (not (npr-admits-api-service-p
            (npr-resolve-with-api "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
               \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.77.77.0/24\",\"except\":[\"10.77.77.16/28\"]}}]}]}"))))
  (is (not (npr-admits-api-service-p
            (npr-resolve-with-api "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
               \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.77.77.20/32\"}}],\"ports\":[{\"port\":6443,\"protocol\":\"UDP\"}]}]}"))))
  ;; Without the API server's address, resolution is as before.
  (is (= 1 (length (coerce (gethash "egress" (npr-resolve "prod" "{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
          \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.77.77.20/32\"}}]}]}")) 'list)))))
