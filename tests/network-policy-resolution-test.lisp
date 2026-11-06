;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove NetworkPolicy resolution: selectors, peer expansion (ipBlock +
;;;; podSelector), per-direction isolation (default-deny), rule union across
;;;; policies, and that a resolved Pod policy JIT-compiles to a classifier.

(in-package #:gr8s/tests)
(def-suite network-policy-resolution :in gr8s)
(in-suite network-policy-resolution)

(defun npr-cidrs (policy)
  "The CIDR strings of a resolved network-policy's rules."
  (mapcar #'gr8s::netpol-rule-cidr (gr8s::network-policy-rules policy)))

(test npr-label-selector-matches-subset-and-empty
  ;; matchLabels is a subset test; an empty selector matches everything.
  (is (gr8s::label-selector-match-p '(("app" . "web")) '(("app" . "web") ("tier" . "fe"))))
  (is (not (gr8s::label-selector-match-p '(("app" . "web")) '(("app" . "db")))))
  (is (not (gr8s::label-selector-match-p '(("app" . "web")) '())))
  (is (gr8s::label-selector-match-p '() '(("app" . "web"))))
  (is (gr8s::label-selector-match-p '() '())))

(test npr-spec-selects-only-same-namespace-matching-pods
  (let ((spec (gr8s::make-np-spec :namespace "prod" :pod-selector '(("app" . "web"))
                                  :policy-types '("Egress")))
        (web-prod (gr8s::make-np-pod :name "w" :namespace "prod" :labels '(("app" . "web")) :ip "10.0.0.1"))
        (web-dev  (gr8s::make-np-pod :name "w" :namespace "dev"  :labels '(("app" . "web")) :ip "10.0.0.2"))
        (db-prod  (gr8s::make-np-pod :name "d" :namespace "prod" :labels '(("app" . "db"))  :ip "10.0.0.3")))
    (is (gr8s::np-spec-selects-pod-p spec web-prod))
    (is (not (gr8s::np-spec-selects-pod-p spec web-dev)))   ; wrong namespace
    (is (not (gr8s::np-spec-selects-pod-p spec db-prod))))) ; wrong labels

(test npr-peer-ipblock-and-podselector-expand
  (let ((pods (list (gr8s::make-np-pod :name "a" :namespace "prod" :labels '(("app" . "api")) :ip "10.0.1.5")
                    (gr8s::make-np-pod :name "b" :namespace "prod" :labels '(("app" . "api")) :ip "10.0.1.6")
                    (gr8s::make-np-pod :name "c" :namespace "other" :labels '(("app" . "api")) :ip "10.0.1.7"))))
    ;; ipBlock peer -> its CIDR verbatim.
    (is (equal '("172.16.0.0/12")
               (gr8s::resolve-peer-cidrs (gr8s::make-np-peer :cidr "172.16.0.0/12") "prod" pods)))
    ;; podSelector peer -> matching pods' /32s, restricted to the policy namespace.
    (let ((cidrs (gr8s::resolve-peer-cidrs
                  (gr8s::make-np-peer :pod-selector '(("app" . "api"))) "prod" pods)))
      (is (= 2 (length cidrs)))
      (is (member "10.0.1.5/32" cidrs :test #'string=))
      (is (member "10.0.1.6/32" cidrs :test #'string=))
      (is (not (member "10.0.1.7/32" cidrs :test #'string=)))))) ; other namespace excluded

(test npr-empty-peers-is-allow-all
  (let ((rule (gr8s::make-np-rule :peers '() :ports (list (gr8s::make-np-port :tcp 80)))))
    (is (equal '("0.0.0.0/0")
               (mapcar #'gr8s::netpol-rule-cidr (gr8s::np-rule->netpol-rules rule "prod" '()))))))

(test npr-not-selected-is-unrestricted
  ;; A Pod no policy selects for a direction is not isolated -> nothing attaches.
  (let ((pod (gr8s::make-np-pod :name "x" :namespace "prod" :labels '(("app" . "web")) :ip "10.0.0.9")))
    (multiple-value-bind (isolated policy) (gr8s::resolve-pod-policy pod '() '() :egress)
      (is (not isolated))
      (is (null policy)))))

(test npr-selected-is-default-deny-with-union-of-rules
  ;; Two egress policies select the Pod; its effective egress allow-list is the
  ;; union, and the Pod is isolated (default-deny).
  (let* ((pod (gr8s::make-np-pod :name "web" :namespace "prod" :labels '(("app" . "web")) :ip "10.0.0.1"))
         (dns (gr8s::make-np-pod :name "dns" :namespace "prod" :labels '(("app" . "dns")) :ip "10.0.9.9"))
         (p1 (gr8s::make-np-spec
              :namespace "prod" :pod-selector '(("app" . "web")) :policy-types '("Egress")
              :egress (list (gr8s::make-np-rule :peers (list (gr8s::make-np-peer :cidr "8.8.8.8/32"))
                                                :ports (list (gr8s::make-np-port :udp 53))))))
         (p2 (gr8s::make-np-spec
              :namespace "prod" :pod-selector '(("app" . "web")) :policy-types '("Egress")
              :egress (list (gr8s::make-np-rule :peers (list (gr8s::make-np-peer :pod-selector '(("app" . "dns")))))))))
    (multiple-value-bind (isolated policy) (gr8s::resolve-pod-policy pod (list p1 p2) (list pod dns) :egress)
      (is (not (null isolated)))
      (is (eq :egress (gr8s::network-policy-direction policy)))
      (let ((cidrs (npr-cidrs policy)))
        (is (member "8.8.8.8/32" cidrs :test #'string=))     ; from p1 ipBlock
        (is (member "10.0.9.9/32" cidrs :test #'string=))))  ; from p2 podSelector

    ;; Ingress is not governed here -> unrestricted.
    (multiple-value-bind (isolated policy) (gr8s::resolve-pod-policy pod (list p1 p2) (list pod dns) :ingress)
      (is (not isolated))
      (is (null policy)))))

(test npr-resolved-policy-compiles-to-a-classifier
  (let* ((pod (gr8s::make-np-pod :name "web" :namespace "prod" :labels '(("app" . "web")) :ip "10.0.0.1"))
         (spec (gr8s::make-np-spec
                :namespace "prod" :pod-selector '(("app" . "web")) :policy-types '("Egress")
                :egress (list (gr8s::make-np-rule :peers (list (gr8s::make-np-peer :cidr "10.0.0.0/8"))
                                                  :ports (list (gr8s::make-np-port :tcp 443)))))))
    (multiple-value-bind (isolated maps progs) (gr8s::compile-pod-policy pod (list spec) (list pod) :egress)
      (is (not (null isolated)))
      (is (null maps))
      (is (= 1 (length progs)))
      (is (plusp (length (getf (first progs) :insns)))))
    ;; Not isolated -> compile short-circuits with nothing to attach.
    (multiple-value-bind (isolated maps progs) (gr8s::compile-pod-policy pod (list spec) (list pod) :ingress)
      (is (not isolated))
      (is (null maps))
      (is (null progs)))))

(defparameter +npr-manifest+
  "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",
    \"metadata\":{\"namespace\":\"prod\",\"name\":\"web-egress\"},
    \"spec\":{\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}},
             \"policyTypes\":[\"Egress\"],
             \"egress\":[{\"to\":[{\"ipBlock\":{\"cidr\":\"10.0.0.0/8\"}},
                                  {\"podSelector\":{\"matchLabels\":{\"app\":\"dns\"}}}],
                          \"ports\":[{\"protocol\":\"UDP\",\"port\":53}]}]}}")

(test npr-parses-k8s-manifest-into-spec
  (let ((spec (gr8s::parse-network-policy +npr-manifest+)))
    (is (string= "prod" (gr8s::np-spec-namespace spec)))
    (is (equal '(("app" . "web")) (gr8s::np-spec-pod-selector spec)))
    (is (equal '("Egress") (gr8s::np-spec-policy-types spec)))
    (is (= 1 (length (gr8s::np-spec-egress spec))))
    (let* ((rule (first (gr8s::np-spec-egress spec)))
           (peers (gr8s::np-rule-peers rule))
           (ports (gr8s::np-rule-ports rule)))
      (is (= 2 (length peers)))
      (is (string= "10.0.0.0/8" (gr8s::np-peer-cidr (first peers))))
      (is (equal '(("app" . "dns")) (gr8s::np-peer-pod-selector (second peers))))
      (is (= 1 (length ports)))
      (is (eq :udp (gr8s::np-port-protocol (first ports))))
      (is (= 53 (gr8s::np-port-port (first ports)))))))

(test npr-manifest-end-to-end-resolves-and-compiles
  ;; Parse a real manifest, resolve for a selected Pod, and compile -- the whole
  ;; API-object -> compiled-firewall path.
  (let* ((spec (gr8s::parse-network-policy +npr-manifest+))
         (web (gr8s::make-np-pod :name "web" :namespace "prod" :labels '(("app" . "web")) :ip "10.1.0.1"))
         (dns (gr8s::make-np-pod :name "dns" :namespace "prod" :labels '(("app" . "dns")) :ip "10.9.9.9")))
    (multiple-value-bind (isolated policy) (gr8s::resolve-pod-policy web (list spec) (list web dns) :egress)
      (is (not (null isolated)))
      (let ((cidrs (npr-cidrs policy)))
        (is (member "10.0.0.0/8" cidrs :test #'string=))
        (is (member "10.9.9.9/32" cidrs :test #'string=))))   ; dns Pod resolved from podSelector
    (multiple-value-bind (isolated maps progs) (gr8s::compile-pod-policy web (list spec) (list web dns) :egress)
      (is (not (null isolated)))
      (is (null maps))
      (is (plusp (length (getf (first progs) :insns)))))))

(test npr-manifest-rejects-unsupported-ports-closed
  ;; A protocol-only (all-port) rule must error, never silently widen to allow-all.
  (let ((json "{\"metadata\":{\"namespace\":\"prod\"},
                \"spec\":{\"podSelector\":{},\"policyTypes\":[\"Egress\"],
                         \"egress\":[{\"ports\":[{\"protocol\":\"TCP\"}]}]}}"))
    (signals error (gr8s::parse-network-policy json))))

(test npr-registered-as-stored-resource
  ;; NetworkPolicy is a stored core resource: the generic store path accepts it,
  ;; defaults kind/apiVersion/namespace, preserves spec, and it re-parses.
  (let* ((json "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",
                 \"metadata\":{\"name\":\"p\"},
                 \"spec\":{\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}},\"policyTypes\":[\"Egress\"]}}")
         (object (com.inuoe.jzon:parse json))
         (normalized (gr8s::normalize-core-resource "networkpolicies" object "prod" "p" nil)))
    (is (string= "NetworkPolicy" (gethash "kind" normalized)))
    (is (string= "networking.k8s.io/v1" (gethash "apiVersion" normalized)))
    (is (string= "prod" (gethash "namespace" (gethash "metadata" normalized))))
    (is (not (null (gethash "spec" normalized))))
    (let ((spec (gr8s::parse-network-policy-json normalized)))
      (is (equal '(("app" . "web")) (gr8s::np-spec-pod-selector spec))))))

(test npr-specs-project-from-stored-objects
  (let* ((j1 "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",\"metadata\":{\"namespace\":\"a\"},\"spec\":{\"podSelector\":{},\"policyTypes\":[\"Egress\"]}}")
         (j2 "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",\"metadata\":{\"namespace\":\"b\"},\"spec\":{\"podSelector\":{},\"policyTypes\":[\"Ingress\"]}}")
         (specs (gr8s::network-policy-specs-from-objects
                 (list (com.inuoe.jzon:parse j1) (com.inuoe.jzon:parse j2)))))
    (is (= 2 (length specs)))
    (is (string= "a" (gr8s::np-spec-namespace (first specs))))
    (is (string= "b" (gr8s::np-spec-namespace (second specs))))))

(test npr-lpm-key-encodes-prefix-and-network-order-addr
  ;; LPM key = u32 prefixlen (host/LE) ++ masked network address (network order).
  (is (equalp #(16 0 0 0 10 123 0 0) (gr8s::netpol-cidr-lpm-key "10.123.0.0/16")))
  (is (equalp #(8 0 0 0 10 0 0 0) (gr8s::netpol-cidr-lpm-key "10.0.0.0/8")))
  (is (equalp #(32 0 0 0 192 168 5 5) (gr8s::netpol-cidr-lpm-key "192.168.5.5/32")))
  ;; A non-aligned address is masked to its network before encoding.
  (is (equalp #(16 0 0 0 10 123 0 0) (gr8s::netpol-cidr-lpm-key "10.123.4.5/16"))))

(test npr-port-hash-key-encodes-group-proto-port
  (is (equalp #(2 0 0 0 6 0 80 0) (gr8s::netpol-port-hash-key 2 6 80)))
  (is (equalp #(1 0 0 0 17 0 53 0) (gr8s::netpol-port-hash-key 1 17 53))))

(defun npr-capture-writes (directory isolated policy)
  "Run write-pod-egress-policy with injected seams; return (values mode-value
cidr-updates port-updates), where updates are (key . value) pairs."
  (let ((updates '()))
    (gr8s::write-pod-egress-policy
     directory isolated policy
     :open (lambda (path) path)
     :map-info (lambda (fd name) (declare (ignore fd)) name)
     :update (lambda (map key value) (push (list map key value) updates))
     :close (lambda (fd) (declare (ignore fd)) nil))
    (let ((u (nreverse updates)))
      (values (third (find "netpol_egress_mode" u :key #'first :test #'string=))
              (remove "netpol_egress_cidr" u :key #'first :test (complement #'string=))
              (remove "netpol_egress_port" u :key #'first :test (complement #'string=))))))

(test npr-write-pod-egress-policy-populates-maps
  ;; Isolated Pod: mode=1; an all-ports CIDR -> LPM sentinel; a port rule -> LPM
  ;; group id plus a ports-hash entry.
  (let ((policy (gr8s::make-network-policy
                 :rules (list (gr8s::make-netpol-rule "10.0.0.0/8")
                              (gr8s::make-netpol-rule "192.168.0.0/16" '((:tcp . 8080)))))))
    (multiple-value-bind (mode cidr port) (npr-capture-writes "/pin/sand/" t policy)
      (is (equalp #(1 0 0 0) mode))                       ; isolated
      (is (= 2 (length cidr)))
      ;; all-ports CIDR carries the #xffffffff sentinel.
      (let ((all (find #(8 0 0 0 10 0 0 0) cidr :key #'second :test #'equalp)))
        (is (and all (equalp #(255 255 255 255) (third all)))))
      ;; port-restricted CIDR carries a group id (1) and a matching ports entry.
      (let ((grp (find #(16 0 0 0 192 168 0 0) cidr :key #'second :test #'equalp)))
        (is (and grp (equalp #(1 0 0 0) (third grp)))))
      (is (= 1 (length port)))
      (is (equalp (gr8s::netpol-port-hash-key 1 6 8080) (second (first port)))))))

(test npr-write-pod-egress-policy-open-mode-when-not-isolated
  ;; Not isolated: mode=0 and the CIDR/ports maps are never touched.
  (let ((policy (gr8s::make-network-policy :rules '())))
    (multiple-value-bind (mode cidr port) (npr-capture-writes "/pin/sand/" nil policy)
      (is (equalp #(0 0 0 0) mode))
      (is (null cidr))
      (is (null port)))))

(test npr-converge-writes-isolated-and-open-skips-errors
  ;; converge resolves each endpoint and writes its policy: selected Pod isolated,
  ;; unselected Pod open (mode 0), and an endpoint whose finder errors is skipped.
  (let* ((spec (gr8s::make-np-spec
                :namespace "prod" :pod-selector '(("app" . "web")) :policy-types '("Egress")
                :egress (list (gr8s::make-np-rule :peers (list (gr8s::make-np-peer :cidr "10.0.0.0/8"))))))
         (writes '()))
    (let ((written
            (gr8s::converge-pod-egress-policies
             (list spec) '(("web" "eth0" "10.0.0.1") ("db" "eth0" "10.0.0.2") ("boom" "eth0" "10.0.0.3"))
             :pod-finder (lambda (addr)
                           (cond ((string= addr "10.0.0.3") (error "boom"))
                                 ((string= addr "10.0.0.1") (values "prod" '(("app" . "web"))))
                                 (t (values "prod" '(("app" . "db"))))))
             :directory-fn (lambda (sandbox) (format nil "/pin/~A/" sandbox))
             :writer (lambda (dir isolated policy)
                       (declare (ignore policy))
                       (push (list dir isolated) writes)))))
      (is (equal '("web" "db") written))               ; boom skipped (fail-soft)
      (is (equal "/pin/web/" (first (find t writes :key #'second))))    ; web isolated
      (is (equal "/pin/db/" (first (find nil writes :key #'second)))))))  ; db open
