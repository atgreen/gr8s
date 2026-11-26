;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove ClusterNetworkPolicy (podster-wv1w.1): the port-set algebra, the control
;;;; plane's resolution of subjects and peers, and the node's ordered evaluation of
;;;; Admin, NetworkPolicy and Baseline tiers into the allow-only entries the Pod's
;;;; tries hold.

(in-package #:gr8s/tests)
(def-suite cluster-network-policy :in gr8s)
(in-suite cluster-network-policy)

(defun cnp-rule (action networks &optional ports)
  "A resolved rule: PORTS as entry ranges, or every protocol and port."
  (gr8s.network::make-cnp-rule :action action :networks networks
                               :ports (if ports (gr8s.network::pset-from-ranges ports) (gr8s.network::pset-full))))

(defun cnp-entries (admin baseline &key np-isolated np-entries)
  (gr8s.network::ordered-policy-entries np-isolated np-entries admin baseline :ipv4))

(defun cnp-ports-for (entries cidr)
  "The ports ENTRIES give CIDR's region, or NIL when it has no entry."
  (third (find cidr entries :key #'first :test #'equal)))

(test cnp-port-sets-subtract-and-render-as-entry-ranges
  (let* ((ssh (gr8s.network::pset-from-ranges '((6 22 22))))
         (rest (gr8s.network::pset-difference (gr8s.network::pset-full) ssh))
         (ranges (gr8s.network::pset-to-ranges rest)))
    (is (eq :all (gr8s.network::pset-to-ranges (gr8s.network::pset-full))))
    (is (member '(6 0 21) ranges :test #'equal))
    (is (member '(6 23 65535) ranges :test #'equal))
    (is (member '(17 nil nil) ranges :test #'equal))
    ;; ICMP is among the other protocols.
    (is (member '(1 nil nil) ranges :test #'equal))
    (is (gr8s.network::pset-empty-p (gr8s.network::pset-intersection ssh rest)))
    (is (equal (gr8s.network::pset-to-ranges (gr8s.network::pset-union ssh rest)) :all))))

(test cnp-an-earlier-accept-wins-and-a-deny-closes-the-rest
  ;; Accept TCP 443 to 192.0.2.0/24, then deny everything: only that is allowed.
  (let ((entries (cnp-entries (list (cnp-rule :accept '("192.0.2.0/24") '((6 443 443)))
                                    (cnp-rule :deny '("0.0.0.0/0")))
                              nil)))
    (is (equal '((6 443 443)) (cnp-ports-for entries "192.0.2.0/24")))
    (is (null (cnp-ports-for entries "0.0.0.0/0")))))

(test cnp-an-earlier-deny-wins-over-a-later-accept
  (let ((entries (cnp-entries (list (cnp-rule :deny '("192.0.2.7/32"))
                                    (cnp-rule :accept '("192.0.2.0/24")))
                              nil)))
    (is (null (cnp-ports-for entries "192.0.2.7/32")))
    ;; The rest of the /24 is accepted, and the rest of the world is undecided: allowed.
    (is (eq :all (cnp-ports-for entries "192.0.2.0/24")))
    (is (eq :all (cnp-ports-for entries "0.0.0.0/0")))
    ;; The /24's entry excepts the /32 so the longest prefix still decides.
    (is (member "192.0.2.7/32" (second (find "192.0.2.0/24" entries :key #'first :test #'equal)) :test #'equal))))

(test cnp-pass-hands-traffic-to-networkpolicy
  ;; Admin passes 10.0.0.0/8 and denies the rest; the Pod's NetworkPolicy, which
  ;; isolates it, allows TCP 80 to 10.1.0.0/16. Pass skips the Admin deny.
  (let ((entries (cnp-entries (list (cnp-rule :pass '("10.0.0.0/8"))
                                    (cnp-rule :deny '("0.0.0.0/0")))
                              nil
                              :np-isolated t
                              :np-entries '(("10.1.0.0/16" () ((6 80 80)))))))
    (is (equal '((6 80 80)) (cnp-ports-for entries "10.1.0.0/16")))
    (is (null (cnp-ports-for entries "10.0.0.0/8")))
    (is (null (cnp-ports-for entries "0.0.0.0/0")))))

(test cnp-networkpolicy-is-final-for-a-pod-it-isolates
  ;; Baseline would accept everything, but the Pod's NetworkPolicy decides first.
  (let ((entries (cnp-entries nil (list (cnp-rule :accept '("0.0.0.0/0")))
                              :np-isolated t
                              :np-entries '(("10.1.0.0/16" () :all)))))
    (is (eq :all (cnp-ports-for entries "10.1.0.0/16")))
    (is (null (cnp-ports-for entries "0.0.0.0/0")))))

(test cnp-baseline-applies-to-a-pod-no-networkpolicy-isolates
  (let ((entries (cnp-entries (list (cnp-rule :accept '("8.8.8.8/32") '((17 53 53))))
                              (list (cnp-rule :deny '("0.0.0.0/0"))))))
    (is (equal '((17 53 53)) (cnp-ports-for entries "8.8.8.8/32")))
    (is (null (cnp-ports-for entries "0.0.0.0/0"))))
  ;; Accept rules alone leave everything else allowed, as no policy decides it.
  (let ((entries (cnp-entries nil (list (cnp-rule :accept '("8.8.8.8/32") '((17 53 53)))))))
    (is (eq :all (cnp-ports-for entries "0.0.0.0/0")))))

(test cnp-a-deny-of-one-port-leaves-the-others
  (let ((entries (cnp-entries (list (cnp-rule :deny '("0.0.0.0/0") '((6 22 22)))) nil)))
    (let ((ports (cnp-ports-for entries "0.0.0.0/0")))
      (is (member '(6 23 65535) ports :test #'equal))
      (is (not (member '(6 22 22) ports :test #'equal)))
      (is (member '(17 nil nil) ports :test #'equal)))))

(defparameter *cnp-pods*
  (list (gr8s.network::make-np-pod :name "agent" :namespace "gr8" :ip "10.88.1.2"
                                   :labels (gr8s.network::np-labels "gr8s.io/gr8-command" "claude"))
        (gr8s.network::make-np-pod :name "web" :namespace "prod" :ip "10.88.2.2"
                                   :labels (gr8s.network::np-labels "app" "web")
                                   :ports '(("http" :tcp 8080)))
        (gr8s.network::make-np-pod :name "db" :namespace "prod" :ip "10.88.2.3"
                                   :labels (gr8s.network::np-labels "app" "db"))))

(defun cnp-namespace-labels ()
  (let ((labels (make-hash-table :test #'equal)))
    (dolist (name '("gr8" "prod"))
      (setf (gethash name labels) (gr8s.network::np-labels "kubernetes.io/metadata.name" name)))
    labels))

(defun cnp-resolve (json)
  (gr8s.network::resolve-cluster-network-policy
   (com.inuoe.jzon:parse json) *cnp-pods* (cnp-namespace-labels)
   (list (cons (gr8s.network::np-labels "kubernetes.io/hostname" "n1") '("10.77.77.10")))))

(test cnp-control-plane-resolves-subject-and-peers
  (let* ((policy (cnp-resolve "{\"apiVersion\":\"policy.networking.k8s.io/v1alpha2\",\"kind\":\"ClusterNetworkPolicy\",
             \"metadata\":{\"name\":\"claude-egress\"},
             \"spec\":{\"tier\":\"Admin\",\"priority\":10,
               \"subject\":{\"pods\":{\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"gr8\"}},
                                      \"podSelector\":{\"matchLabels\":{\"gr8s.io/gr8-command\":\"claude\"}}}},
               \"egress\":[
                 {\"name\":\"anthropic\",\"action\":\"Accept\",\"to\":[{\"domainNames\":[\"api.anthropic.com\"]}],
                  \"protocols\":[{\"tcp\":{\"destinationPort\":{\"number\":443}}}]},
                 {\"action\":\"Accept\",\"to\":[{\"pods\":{\"namespaceSelector\":{},\"podSelector\":{\"matchLabels\":{\"app\":\"web\"}}}}],
                  \"protocols\":[{\"destinationNamedPort\":\"http\"}]},
                 {\"action\":\"Accept\",\"to\":[{\"nodes\":{}}],\"protocols\":[{\"tcp\":{\"destinationPort\":{\"range\":{\"start\":10250,\"end\":10255}}}}]},
                 {\"action\":\"Deny\",\"to\":[{\"networks\":[\"0.0.0.0/0\"]}]}]}}"))
         (spec (gethash "spec" policy))
         (rules (coerce (gethash "egress" spec) 'list)))
    (is (equal '("gr8/agent") (coerce (gethash "subjectPods" spec) 'list)))
    (is (= 4 (length rules)))
    (destructuring-bind (domain named node deny) rules
      (is (equal '("api.anthropic.com") (coerce (gethash "domainNames" domain) 'list)))
      (is (zerop (length (gethash "networks" domain))))
      (is (equal 443 (gethash "port" (aref (gethash "ports" domain) 0))))
      ;; The named port is the destination Pod's own number.
      (is (equal '("10.88.2.2/32") (coerce (gethash "networks" named) 'list)))
      (is (equal 8080 (gethash "port" (aref (gethash "ports" named) 0))))
      (is (equal '("10.77.77.10/32") (coerce (gethash "networks" node) 'list)))
      (is (equal '(10250 10255) (list (gethash "port" (aref (gethash "ports" node) 0))
                                      (gethash "endPort" (aref (gethash "ports" node) 0)))))
      (is (equal "Deny" (gethash "action" deny)))
      (is (not (nth-value 1 (gethash "ports" deny)))))))

(test cnp-a-resolved-policy-drives-the-selected-pods-entries
  (let* ((policy (cnp-resolve "{\"metadata\":{\"name\":\"lockdown\"},
             \"spec\":{\"tier\":\"Admin\",\"priority\":1,
               \"subject\":{\"namespaces\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"gr8\"}}},
               \"egress\":[{\"action\":\"Accept\",\"to\":[{\"networks\":[\"192.0.2.0/24\"]}],
                            \"protocols\":[{\"tcp\":{\"destinationPort\":{\"number\":443}}}]},
                           {\"action\":\"Deny\",\"to\":[{\"networks\":[\"0.0.0.0/0\"]}]}]}}"))
         (cnps (gr8s.network::cluster-network-policy-specs-from-objects (list policy))))
    (multiple-value-bind (isolated entries)
        (gr8s.network::pod-policy-entries (first *cnp-pods*) '() cnps :egress)
      (is-true isolated)
      (is (equal '((6 443 443)) (cnp-ports-for entries "192.0.2.0/24")))
      (is (null (cnp-ports-for entries "0.0.0.0/0"))))
    ;; Not the subject, and no NetworkPolicy: nothing changes.
    (multiple-value-bind (isolated entries)
        (gr8s.network::pod-policy-entries (second *cnp-pods*) '() cnps :egress)
      (is (null isolated))
      (is (null entries)))
    ;; No ingress rules: ingress is NetworkPolicy's alone.
    (is (null (gr8s.network::pod-policy-entries (first *cnp-pods*) '() cnps :ingress)))))

(defun cnp-object (spec-json)
  (com.inuoe.jzon:parse
   (format nil "{\"apiVersion\":\"policy.networking.k8s.io/v1alpha2\",\"kind\":\"ClusterNetworkPolicy\",
                 \"metadata\":{\"name\":\"p\"},\"spec\":~A}" spec-json)))

(defun cnp-normalize (spec-json)
  (gr8s.resources::normalize-core-resource "clusternetworkpolicies" (cnp-object spec-json) nil "p" nil))

(defparameter +cnp-valid-spec+
  "{\"tier\":\"Admin\",\"priority\":10,
    \"subject\":{\"pods\":{\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"gr8\"}},
                           \"podSelector\":{}}},
    \"egress\":[{\"name\":\"api\",\"action\":\"Accept\",\"to\":[{\"domainNames\":[\"api.anthropic.com\",\"*.githubusercontent.com\"]}],
                 \"protocols\":[{\"tcp\":{\"destinationPort\":{\"number\":443}}}]},
                {\"action\":\"Deny\",\"to\":[{\"networks\":[\"0.0.0.0/0\",\"::/0\"]}]}],
    \"ingress\":[{\"action\":\"Pass\",\"from\":[{\"namespaces\":{}}]}]}")

(test cnp-is-a-cluster-scoped-stored-resource-validated-as-upstream
  (let ((object (cnp-normalize +cnp-valid-spec+)))
    (is (equal "ClusterNetworkPolicy" (gethash "kind" object)))
    (is (equal "policy.networking.k8s.io/v1alpha2" (gethash "apiVersion" object)))
    (is (not (nth-value 1 (gethash "namespace" (gethash "metadata" object))))))
  (let ((entry (find "clusternetworkpolicies"
                     (gr8s.resources::stored-resource-discovery "policy.networking.k8s.io/v1alpha2")
                     :key (lambda (entry) (gethash "name" entry)) :test #'equal)))
    (is (not (null entry)))
    (is (eq nil (gethash "namespaced" entry))))
  (dolist (bad '(;; tier, priority, subject
                 "{\"tier\":\"Developer\",\"priority\":1,\"subject\":{\"namespaces\":{}}}"
                 "{\"tier\":\"Admin\",\"priority\":1001,\"subject\":{\"namespaces\":{}}}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{},\"pods\":{\"podSelector\":{}}}}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"pods\":{}}}"
                 ;; actions, peers and protocols
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"egress\":[{\"action\":\"Allow\",\"to\":[{\"namespaces\":{}}]}]}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"egress\":[{\"action\":\"Deny\",\"to\":[{\"domainNames\":[\"example.com\"]}]}]}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"egress\":[{\"action\":\"Accept\",\"to\":[{\"domainNames\":[\"localhost\"]}]}]}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"egress\":[{\"action\":\"Accept\",\"to\":[{\"networks\":[\"10.0.0.1/8\"]}]}]}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"egress\":[{\"action\":\"Accept\",\"to\":[{\"networks\":[\"10.0.0.0/8\"]}],\"protocols\":[{\"destinationNamedPort\":\"http\"}]}]}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"egress\":[{\"action\":\"Accept\",\"to\":[{\"namespaces\":{}}],\"protocols\":[{\"tcp\":{\"destinationPort\":{\"range\":{\"start\":90,\"end\":80}}}}]}]}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"egress\":[{\"action\":\"Accept\",\"to\":[{\"namespaces\":{}}],\"protocols\":[{\"tcp\":{},\"udp\":{}}]}]}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"egress\":[{\"action\":\"Accept\",\"to\":[]}]}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"ingress\":[{\"action\":\"Accept\",\"from\":[{\"networks\":[\"10.0.0.0/8\"]}]}]}"
                 "{\"tier\":\"Admin\",\"priority\":1,\"subject\":{\"namespaces\":{}},\"egress\":[{\"action\":\"Accept\",\"to\":[{\"namespaces\":{}}],\"ports\":[]}]}"))
    (signals gr8s.resources::kubernetes-error (cnp-normalize bad))))

(test cnp-projection-reaches-the-node-snapshot
  (let* ((policy (cnp-resolve "{\"metadata\":{\"name\":\"lockdown\",\"uid\":\"u1\",\"resourceVersion\":\"3\"},
             \"spec\":{\"tier\":\"Admin\",\"priority\":1,
               \"subject\":{\"namespaces\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"gr8\"}}},
               \"egress\":[{\"action\":\"Deny\",\"to\":[{\"networks\":[\"0.0.0.0/0\"]}]}]}}"))
         (public (progn (setf (gethash "kind" policy) "ClusterNetworkPolicy")
                        (gr8s.kubelet::service-discovery-public-object policy)))
         (decoded (gr8s.kubelet::decode-service-discovery-entry
                   (gr8s.resources::stringify-to-utf-8-bytes public))))
    (is (equal "clusternetworkpolicies" (first (car decoded))))
    (let ((specs (gr8s.network::cluster-network-policy-specs-from-objects (list (cdr decoded)))))
      (is (= 1 (length specs)))
      (is (equal '("gr8/agent") (gr8s.network::cnp-spec-subject-pods (first specs)))))))

(test cnp-domain-names-match-as-upstream-specifies
  (is-true (gr8s.network::egress-domain-matches-p "api.anthropic.com" "API.Anthropic.com."))
  (is-false (gr8s.network::egress-domain-matches-p "api.anthropic.com" "evil-api.anthropic.com"))
  (is-true (gr8s.network::egress-domain-matches-p "*.githubusercontent.com" "raw.githubusercontent.com"))
  (is-true (gr8s.network::egress-domain-matches-p "*.githubusercontent.com" "a.b.githubusercontent.com"))
  (is-false (gr8s.network::egress-domain-matches-p "*.githubusercontent.com" "githubusercontent.com"))
  (is-false (gr8s.network::egress-domain-matches-p "*.githubusercontent.com" "notgithubusercontent.com")))

(defun cnp-claude-policies ()
  (gr8s.network::cluster-network-policy-specs-from-objects
   (list (cnp-resolve "{\"metadata\":{\"name\":\"claude\"},
             \"spec\":{\"tier\":\"Admin\",\"priority\":10,
               \"subject\":{\"namespaces\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"gr8\"}}},
               \"egress\":[{\"action\":\"Accept\",\"to\":[{\"domainNames\":[\"api.anthropic.com\",\"*.claude.com\"]}],
                            \"protocols\":[{\"tcp\":{\"destinationPort\":{\"number\":443}}}]},
                           {\"action\":\"Accept\",\"to\":[{\"networks\":[\"10.0.0.0/8\"]}]},
                           {\"action\":\"Deny\",\"to\":[{\"networks\":[\"0.0.0.0/0\"]}]}]}}"))))

(test cnp-the-egress-proxy-decides-captured-connections-by-name
  (let ((agent (first *cnp-pods*)) (web (second *cnp-pods*)) (cnps (cnp-claude-policies)))
    (is-true (gr8s.network::pod-egress-captured-p agent cnps))
    (is-false (gr8s.network::pod-egress-captured-p web cnps))
    (is (equal '("api.anthropic.com" "*.claude.com") (gr8s.network::pod-egress-allowed-domains agent cnps)))
    (flet ((verdict (host address port)
             (gr8s.network::egress-connection-verdict agent '() cnps host address port)))
      (is-true (verdict "api.anthropic.com" "160.79.104.10" 443))
      (is-true (verdict "platform.claude.com" "160.79.104.11" 443))
      ;; The wrong port, an unlisted name, or no name at all: the deny.
      (is-false (verdict "api.anthropic.com" "160.79.104.10" 80))
      (is-false (verdict "evil.example.com" "203.0.113.5" 443))
      (is-false (verdict nil "203.0.113.5" 443))
      ;; Address rules still apply to what the proxy connects to.
      (is-true (verdict nil "10.1.2.3" 5432)))
    ;; Not captured: no ClusterNetworkPolicy decides, so it is allowed.
    (is-true (gr8s.network::egress-connection-verdict web '() cnps "evil.example.com" "203.0.113.5" 443))))

(test cnp-a-captured-pod-may-reach-the-egress-proxy
  (multiple-value-bind (isolated entries)
      (gr8s.network::pod-policy-entries (first *cnp-pods*) '() (cnp-claude-policies) :egress)
    (is-true isolated)
    (is (equal '((6 nil nil) (17 53 53)) (cnp-ports-for entries "169.254.1.2/32")))
    (is (eq :all (cnp-ports-for entries "10.0.0.0/8")))
    (is (null (cnp-ports-for entries "0.0.0.0/0")))))

;;; podster-1mzb: a gr8 sandbox is always on synthetic DNS, and what nothing allows is denied.

(test a-gr8-sandbox-with-no-policy-reaches-only-the-egress-proxy
  (let ((sandbox (first *cnp-pods*)) (web (second *cnp-pods*)))
    (is-true (gr8s.network::gr8-sandbox-pod-p sandbox))
    (is-false (gr8s.network::gr8-sandbox-pod-p web))
    (is-true (gr8s.network::pod-egress-captured-p sandbox '()))
    (is-true (gr8s.network::pod-egress-synthetic-p sandbox '()) "its DNS is the gate's, with no names allowed")
    (is (null (gr8s.network::pod-egress-allowed-domains sandbox '())))
    (multiple-value-bind (isolated entries) (gr8s.network::pod-policy-entries sandbox '() '() :egress)
      (is-true isolated)
      (is (equal '((6 nil nil) (17 53 53)) (cnp-ports-for entries "169.254.1.2/32")))
      (is (equal '((6 nil nil)) (cnp-ports-for entries "198.18.0.0/15")))
      (is (null (cnp-ports-for entries "0.0.0.0/0")))
      (is (null (cnp-ports-for entries "::/0")) "nor IPv6")
      (is (= 2 (length entries)) "and nothing else"))
    (multiple-value-bind (allowed rule)
        (gr8s.network::egress-connection-verdict sandbox '() '() "example.com" "93.184.215.14" 443)
      (is-false allowed)
      (is (equal "gr8-sandbox" (gr8s.network::cnp-rule-name rule)) "the refusal names the sandbox rule"))
    ;; A Pod gr8 didn't make is untouched.
    (is-false (gr8s.network::pod-policy-entries web '() '() :egress))
    (is-true (gr8s.network::egress-connection-verdict web '() '() "example.com" "93.184.215.14" 443))))

(test a-gr8-sandbox-reaches-what-its-policies-allow-and-nothing-more
  (let* ((sandbox (first *cnp-pods*))
         (cnps (gr8s.network::cluster-network-policy-specs-from-objects
                (list (cnp-resolve "{\"metadata\":{\"name\":\"claude-names\"},
                   \"spec\":{\"tier\":\"Admin\",\"priority\":10,
                     \"subject\":{\"namespaces\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"gr8\"}}},
                     \"egress\":[{\"action\":\"Accept\",\"to\":[{\"domainNames\":[\"api.anthropic.com\"]}]}]}}")))))
    (is (equal '("api.anthropic.com") (gr8s.network::pod-egress-allowed-domains sandbox cnps)))
    (flet ((verdict (host address)
             (gr8s.network::egress-connection-verdict sandbox '() cnps host address 443)))
      (is-true (verdict "api.anthropic.com" "160.79.104.10"))
      (is-false (verdict "evil.example.com" "203.0.113.5"))
      (is-false (verdict nil "10.1.2.3") "a private address too: no policy allows it"))
    (multiple-value-bind (isolated entries) (gr8s.network::pod-policy-entries sandbox '() cnps :egress)
      (is-true isolated)
      (is (null (cnp-ports-for entries "0.0.0.0/0"))))))
