;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove the NetworkPolicy compiler turns a normalized policy into a Whistler
;;;; TC classifier with the rules partial-evaluated into literal branches (the
;;;; "compiled firewall" property), and that each policy JIT-compiles in-process
;;;; to a valid classifier with no maps.

(in-package #:gr8s/tests)
(def-suite network-policy :in gr8s)
(in-suite network-policy)

(defun netpol-flatten (form)
  "Flatten FORM into a list of its atoms."
  (cond ((null form) '())
        ((atom form) (list form))
        (t (append (netpol-flatten (car form)) (netpol-flatten (cdr form))))))

(defun netpol-form-has-number (forms n)
  "True if literal N appears anywhere in FORMS."
  (and (member n (netpol-flatten forms) :test #'eql) t))

(defun netpol-form-has-symbol (forms name)
  "True if a symbol named NAME (any package) appears anywhere in FORMS."
  (and (find name (netpol-flatten forms)
             :test (lambda (s x) (and (symbolp x) (string= s (symbol-name x)))))
       t))

(defun netpol-count-symbol (forms name)
  (count name (netpol-flatten forms)
         :test (lambda (s x) (and (symbolp x) (string= s (symbol-name x))))))

(test netpol-bakes-rule-constants-into-branches
  ;; allow egress to 10.0.0.0/8 on TCP/80 and UDP/53.
  (let* ((policy (gr8s.network::make-network-policy
                  :rules (list (gr8s.network::make-netpol-rule "10.0.0.0/8" '((:tcp . 80)))
                               (gr8s.network::make-netpol-rule "192.168.5.5/32" '((:udp . 53))))))
         (forms (gr8s.network::network-policy-egress-forms policy)))
    ;; 10.0.0.0/8 -> mask 0xff000000, net 0x0a000000.
    (is (netpol-form-has-number forms #xff000000))
    (is (netpol-form-has-number forms #x0a000000))
    ;; 192.168.5.5/32 -> mask 0xffffffff, net = the address itself.
    (is (netpol-form-has-number forms #xffffffff))
    (is (netpol-form-has-number forms (gr8s.controllers::parse-ipv4-integer "192.168.5.5")))
    ;; Protocol numbers (tcp=6, udp=17) and ports (80, 53) as literals.
    (is (netpol-form-has-number forms 6))
    (is (netpol-form-has-number forms 17))
    (is (netpol-form-has-number forms 80))
    (is (netpol-form-has-number forms 53))
    ;; Two allow rules -> two TC_ACT_OK leaves, plus one for the non-IPv4 (ARP)
    ;; pass branch, plus the default-deny TC_ACT_SHOT tail.
    (is (= 3 (netpol-count-symbol forms "TC_ACT_OK")))
    (is (netpol-form-has-symbol forms "TC_ACT_SHOT"))))

(test netpol-empty-policy-is-default-deny
  ;; A selected Pod with no egress rules: IPv4 egress is dropped, no allow
  ;; constants, but non-IPv4 still passes (one TC_ACT_OK for the ARP branch).
  (let* ((policy (gr8s.network::make-network-policy :rules '()))
         (forms (gr8s.network::network-policy-egress-forms policy)))
    (is (netpol-form-has-symbol forms "TC_ACT_SHOT"))
    (is (= 1 (netpol-count-symbol forms "TC_ACT_OK")))
    (is (not (netpol-form-has-number forms 80)))))

(test netpol-allow-all-cidr-short-circuits
  ;; 0.0.0.0/0 with no ports collapses to an unconditional allow.
  (let* ((policy (gr8s.network::make-network-policy
                  :rules (list (gr8s.network::make-netpol-rule "0.0.0.0/0"))))
         (forms (gr8s.network::network-policy-egress-forms policy)))
    ;; No CIDR comparison constant is emitted for the catch-all rule.
    (is (not (netpol-form-has-number forms #xffffffff)))
    (is (netpol-form-has-symbol forms "TC_ACT_OK"))))

(test netpol-compiles-in-process-to-a-classifier
  (let ((policy (gr8s.network::make-network-policy
                 :rules (list (gr8s.network::make-netpol-rule "10.0.0.0/8" '((:tcp . 80) (:tcp . 443)))
                              (gr8s.network::make-netpol-rule "172.16.0.0/12")))))
    (multiple-value-bind (map-specs prog-specs) (gr8s.network::compile-network-policy-egress policy)
      ;; All rules live in the program; no maps.
      (is (null map-specs))
      (is (= 1 (length prog-specs)))
      (let ((insns (getf (first prog-specs) :insns)))
        (is (string= "classifier" (getf (first prog-specs) :section)))
        (is (plusp (length insns)))
        (is (zerop (mod (length insns) 8)))))))

(test netpol-empty-policy-compiles
  (let ((policy (gr8s.network::make-network-policy :rules '())))
    (multiple-value-bind (map-specs prog-specs) (gr8s.network::compile-network-policy-egress policy)
      (is (null map-specs))
      (is (= 1 (length prog-specs)))
      (is (plusp (length (getf (first prog-specs) :insns)))))))

(test netpol-ingress-matches-source-not-destination
  ;; Ingress governs peer -> Pod and must match the SOURCE address (byte 26);
  ;; egress matches the DESTINATION (byte 30). Same rule, different offset, so
  ;; the generated load offset distinguishes the two directions.
  (let* ((rule (gr8s.network::make-netpol-rule "10.0.0.0/8"))
         (ingress (gr8s.network::make-network-policy :direction :ingress :rules (list rule)))
         (egress (gr8s.network::make-network-policy :direction :egress :rules (list rule)))
         (ing-forms (gr8s.network::network-policy-forms ingress))
         (egr-forms (gr8s.network::network-policy-forms egress)))
    ;; Both still bake in the CIDR constants.
    (is (netpol-form-has-number ing-forms #xff000000))
    (is (netpol-form-has-number egr-forms #xff000000))
    ;; Byte offset 26 (source) appears only for ingress; 30 (dst) only for egress.
    (is (netpol-form-has-number ing-forms 26))
    (is (not (netpol-form-has-number ing-forms 30)))
    (is (netpol-form-has-number egr-forms 30))
    (is (not (netpol-form-has-number egr-forms 26)))
    ;; Distinct program names so both can attach to one Pod (opposite directions).
    (is (netpol-form-has-symbol ing-forms "GR8S-NETPOL-INGRESS"))
    (is (netpol-form-has-symbol egr-forms "GR8S-NETPOL-EGRESS"))))

(test netpol-ingress-compiles-in-process
  (let ((policy (gr8s.network::make-network-policy
                 :direction :ingress
                 :rules (list (gr8s.network::make-netpol-rule "192.168.0.0/16" '((:tcp . 8080)))))))
    (multiple-value-bind (map-specs prog-specs) (gr8s.network::compile-network-policy-ingress policy)
      (is (null map-specs))
      (is (= 1 (length prog-specs)))
      (is (zerop (mod (length (getf (first prog-specs) :insns)) 8))))))
