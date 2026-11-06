;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Compile a Pod's normalized NetworkPolicy into a bespoke Whistler TC
;;;; classifier whose allow rules are partial-evaluated into branches -- no
;;;; runtime map lookups. This is gr8s's structural difference from map-driven
;;;; dataplanes: because Whistler JIT-compiles in-process, each Pod can carry a
;;;; program specialized to exactly its rules. The program is attached on the
;;;; Pod's host-veth ingress (the same hook as the egress guard), governs Pod
;;;; EGRESS (traffic leaving the Pod), and is stateless for now.
;;;;
;;;; Semantics (k8s NetworkPolicy, egress, IPv4):
;;;;   - A Pod selected by any egress policy is default-deny for IPv4 egress.
;;;;   - Each allow rule matches a destination CIDR and, optionally, a set of
;;;;     (protocol, port) pairs; a rule with no ports allows all L4 to the CIDR.
;;;;   - Non-IPv4 (ARP/ND) is not governed by NetworkPolicy and is passed, so
;;;;     the Pod can still resolve its gateway.
;;;; Known limitations (tracked under the epic): stateless (no reply/established
;;;; allowance -> see the conntrack task), IPv4 only, and packets carrying IP
;;;; options (ihl > 5) are dropped rather than parsed.

(in-package #:gr8s)

;;; ---------------------------------------------------------------------------
;;; Host-side normalized policy representation and the arithmetic that turns a
;;; CIDR / protocol name into the literal constants baked into the program.

(defstruct (netpol-rule (:constructor make-netpol-rule (cidr &optional ports)))
  "One allow rule: destination CIDR plus optional (proto . port) pairs.
PORTS nil means every protocol/port to CIDR is allowed."
  (cidr "0.0.0.0/0" :type string)
  (ports '() :type list))

(defstruct (network-policy (:constructor make-network-policy (&key (direction :egress) rules)))
  "A Pod's flattened policy for one direction."
  (direction :egress)
  (rules '() :type list))

(defun netpol-proto-number (proto)
  "Map a protocol keyword (:tcp :udp :sctp) or integer to its IP protocol number."
  (etypecase proto
    (integer proto)
    (keyword (ecase proto (:tcp 6) (:udp 17) (:sctp 132)))))

(defun netpol-cidr-mask-and-net (cidr)
  "Return the 32-bit host-order network MASK and masked NETWORK for CIDR."
  (multiple-value-bind (address prefix) (parse-ipv4-cidr cidr)
    (let ((mask (if (zerop prefix)
                    0
                    (ldb (byte 32 0) (- (ash 1 32) (ash 1 (- 32 prefix)))))))
      (values mask (logand address mask)))))

;;; ---------------------------------------------------------------------------
;;; Whistler program templates. Authored in the WHISTLER package so every DSL
;;; symbol (defprog, load, tc-data, TC_ACT_OK, u32, ...) interns exactly as the
;;; hand-written programs do; the per-rule constants are spliced in as literals.

(in-package #:whistler)

(defun gr8s::netpol-rule-match-form (rule addr-offset)
  "Build the match test for RULE, or :ANY when the rule allows all IPv4 traffic.
ADDR-OFFSET is the byte offset of the IPv4 address this direction matches on:
destination @ 30 for egress, source @ 26 for ingress. IP proto is @ byte 23 and
the L4 destination port @ byte 36 (IHL=5). Each rule's CIDR, protocol and port
are emitted as literal constants -- the partial evaluation that makes this a
\"compiled\" firewall."
  (multiple-value-bind (mask net) (gr8s::netpol-cidr-mask-and-net (gr8s::netpol-rule-cidr rule))
    (let ((cidr-test (unless (zerop mask)
                       `(= (logand (ntohl (load u32 data ,addr-offset)) ,mask) ,net)))
          (ports (gr8s::netpol-rule-ports rule)))
      (cond
        ((and (null ports) (null cidr-test)) :any)
        ((null ports) cidr-test)
        (t
         (let ((port-tests
                 (mapcar (lambda (pp)
                           `(and (= (load u8 data 23) ,(gr8s::netpol-proto-number (car pp)))
                                 (= (ntohs (load u16 data 36)) ,(cdr pp))))
                         ports)))
           `(and (<= (+ data 38) data-end)        ; L4 ports in bounds
                 ,@(when cidr-test (list cidr-test))
                 ,(if (= 1 (length port-tests))
                      (first port-tests)
                      `(or ,@port-tests)))))))))

(defun gr8s::netpol-rule-chain-form (rules addr-offset)
  "Fold RULES into a nested if-chain ending in the default-deny TC_ACT_SHOT."
  (if (null rules)
      'TC_ACT_SHOT
      (let ((match (gr8s::netpol-rule-match-form (first rules) addr-offset)))
        (if (eq match :any)
            'TC_ACT_OK
            `(if ,match TC_ACT_OK ,(gr8s::netpol-rule-chain-form (rest rules) addr-offset))))))

(defun gr8s::network-policy-program-form (prog-name addr-offset rules)
  "The shared classifier shell: parse L2/L3, pass non-IPv4, then apply RULES
(matching on ADDR-OFFSET) with a default-deny tail."
  `(defprog ,prog-name (:type :tc :section "classifier" :license "GPL")
     (let ((data u64 (tc-data)) (data-end u64 (tc-data-end)))
       (if (> (+ data 14) data-end)
           TC_ACT_SHOT                              ; runt frame
           (if (/= (eth-type data) #x0800)
               TC_ACT_OK                            ; non-IPv4 is not NetworkPolicy's concern
               (if (> (+ data 34) data-end)
                   TC_ACT_SHOT                      ; truncated IPv4 header
                   (if (/= (logand (load u8 data 14) #xf0) #x40)
                       TC_ACT_SHOT                  ; not IPv4
                       (if (/= (logand (load u8 data 14) 15) 5)
                           TC_ACT_SHOT              ; IP options present -> can't locate L4
                           ,(gr8s::netpol-rule-chain-form rules addr-offset)))))))))

(defun gr8s::network-policy-egress-forms (policy)
  "Egress classifier (Pod -> peer): match destination CIDR at byte 30."
  (list (gr8s::network-policy-program-form
         'gr8s-netpol-egress 30 (gr8s::network-policy-rules policy))))

(defun gr8s::network-policy-ingress-forms (policy)
  "Ingress classifier (peer -> Pod): match source CIDR at byte 26."
  (list (gr8s::network-policy-program-form
         'gr8s-netpol-ingress 26 (gr8s::network-policy-rules policy))))

(in-package #:gr8s)

;;; ---------------------------------------------------------------------------
;;; In-process JIT entries (no ELF), mirroring compile-egress-guard.

(defun network-policy-forms (policy)
  "Whistler defprog forms for POLICY, dispatched on its direction."
  (ecase (network-policy-direction policy)
    (:egress (network-policy-egress-forms policy))
    (:ingress (network-policy-ingress-forms policy))))

(defun compile-network-policy (policy)
  "JIT-compile POLICY's classifier in-process for its direction.
Returns (values map-specs prog-specs); map-specs is empty because the rules are
compiled into the program, not stored in maps."
  (compile-whistler-program nil (network-policy-forms policy)))

(defun compile-network-policy-egress (policy)
  "JIT-compile POLICY as an egress classifier."
  (compile-whistler-program nil (network-policy-egress-forms policy)))

(defun compile-network-policy-ingress (policy)
  "JIT-compile POLICY as an ingress classifier."
  (compile-whistler-program nil (network-policy-ingress-forms policy)))
