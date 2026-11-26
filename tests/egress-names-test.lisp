;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove policy DNS with synthetic addresses (podster-wv1w.8): an allowed name is
;;;; answered with an address from the reserved range that stands for the name, the
;;;; real addresses behind it are the public ones the trusted resolver returned, an
;;;; expired mapping is refreshed on connect and never used stale, and only Pods with a
;;;; hostname allowlist are put in synthetic mode.

(in-package #:gr8s/tests)
(def-suite egress-names :in gr8s)
(in-suite egress-names)

(test egress-synthetic-range-and-pinnable-addresses
  (is-true (gr8s.network::egress-synthetic-address-p "198.18.0.5"))
  (is-true (gr8s.network::egress-synthetic-address-p "198.19.255.1"))
  (is-false (gr8s.network::egress-synthetic-address-p "198.20.0.1"))
  (is-false (gr8s.network::egress-synthetic-address-p "10.0.0.1"))
  (is-false (gr8s.network::egress-synthetic-address-p "2001:db8::1"))
  ;; Only public IPv4 may be pinned: the cluster's own ranges stay under address
  ;; policy, and the synthetic range is never a destination.
  (is-true (gr8s.network::egress-pinnable-address-p "203.0.113.5"))
  (dolist (address '("10.1.2.3" "127.0.0.1" "169.254.1.1" "192.168.1.1" "100.64.0.1"
                     "198.18.0.9" "0.0.0.0" "224.0.0.1" "255.255.255.255" "2001:db8::1" "nonsense"))
    (is-false (gr8s.network::egress-pinnable-address-p address) "~A was pinnable" address)))

(test egress-names-answer-allowed-names-with-a-synthetic-address
  (let ((answers '(("api.example.com" ("203.0.113.5" "10.0.0.9" "203.0.113.6") 300 0)
                   ("other.example.com" ("198.51.100.7") 10 0))))
    (let ((table (egress-test-name-table (lambda () answers))))
      (multiple-value-bind (address ttl) (gr8s.network::egress-name-answer table "API.example.com.")
        (is-true (gr8s.network::egress-synthetic-address-p address))
        ;; The TTL is bounded so a mapping is refreshed often.
        (is (= gr8s.network::+egress-synthetic-ttl+ ttl))
        ;; The same name keeps its address; another name gets another.
        (is (equal address (gr8s.network::egress-name-answer table "api.example.com")))
        (multiple-value-bind (other other-ttl) (gr8s.network::egress-name-answer table "other.example.com")
          (is (not (equal address other)))
          (is (= 10 other-ttl)))
        ;; The address leads back to the name and the public addresses only.
        (multiple-value-bind (name addresses) (gr8s.network::egress-name-for-connect table address)
          (is (equal "api.example.com" name))
          (is (equal '("203.0.113.5" "203.0.113.6") addresses)))))))

(test egress-names-refuse-what-they-cannot-pin
  (let ((table (egress-test-name-table
                (lambda () '(("internal.example.com" ("10.0.0.9" "127.0.0.1") 60 0)
                             ("missing.example.com" () 60 3))))))
    ;; Only private addresses: refused rather than proxied past address policy.
    (is (equal '(nil 5) (multiple-value-list (gr8s.network::egress-name-answer table "internal.example.com"))))
    ;; NXDOMAIN passes through; a resolver failure is SERVFAIL.
    (is (equal '(nil 3) (multiple-value-list (gr8s.network::egress-name-answer table "missing.example.com"))))
    (is (equal '(nil 2) (multiple-value-list (gr8s.network::egress-name-answer table "down.example.com"))))
    ;; An address nobody was given names nothing.
    (is (null (gr8s.network::egress-name-for-connect table "198.18.200.1")))
    (is (null (gr8s.network::egress-name-for-connect table "203.0.113.5")))))

(test egress-names-refresh-an-expired-mapping-on-connect-and-never-use-it-stale
  (let* ((now 1000)
         (answers (list (list "api.example.com" '("203.0.113.5") 30 0))))
    (multiple-value-bind (table calls)
        (egress-test-name-table (lambda () answers) :clock (lambda () now))
      (let ((address (gr8s.network::egress-name-answer table "api.example.com")))
        (is (= 1 (gethash "api.example.com" calls)))
        ;; Within the TTL: no lookup.
        (incf now 10)
        (is (equal '("203.0.113.5") (nth-value 1 (gr8s.network::egress-name-for-connect table address))))
        (is (= 1 (gethash "api.example.com" calls)))
        ;; Past it, a connect refreshes the mapping in place.
        (incf now 60)
        (setf answers (list (list "api.example.com" '("203.0.113.9") 30 0)))
        (is (equal '("203.0.113.9") (nth-value 1 (gr8s.network::egress-name-for-connect table address))))
        (is (= 2 (gethash "api.example.com" calls)))
        ;; A failed refresh fails the connect, and is not retried at once.
        (incf now 60)
        (setf answers '())
        (is (null (gr8s.network::egress-name-for-connect table address)))
        (is (null (gr8s.network::egress-name-for-connect table address)))
        (is (= 3 (gethash "api.example.com" calls)))
        ;; The allocation outlives the failure: once the name resolves again, the
        ;; address a client cached still reaches it.
        (incf now 2)
        (setf answers (list (list "api.example.com" '("203.0.113.10") 30 0)))
        (is (equal '("api.example.com" ("203.0.113.10"))
                   (multiple-value-list (gr8s.network::egress-name-for-connect table address))))
        (is (equal address (gr8s.network::egress-name-answer table "api.example.com")))))))

(test egress-names-reuse-only-addresses-idle-past-the-grace
  (let* ((now 1000)
         (table (gr8s.network::make-egress-name-table
                 :resolve (lambda (name) (declare (ignore name)) (values '("203.0.113.5") 30 0))
                 :clock (lambda () now) :capacity 2)))
    (let ((a (gr8s.network::egress-name-answer table "a.example.com"))
          (b (gr8s.network::egress-name-answer table "b.example.com")))
      (is (not (equal a b)))
      ;; Full, and both still within the grace a cached answer may be used for: refused.
      (is (equal '(nil 2) (multiple-value-list (gr8s.network::egress-name-answer table "c.example.com"))))
      ;; Long idle: the least recently used address goes to the new name.
      (incf now (1+ gr8s.network::+egress-synthetic-reuse-grace+))
      (gr8s.network::egress-name-for-connect table b)
      (is (equal a (gr8s.network::egress-name-answer table "c.example.com")))
      (is (equal "c.example.com" (gr8s.network::egress-name-for-connect table a))))))

(test egress-synthetic-mode-is-for-pods-with-a-hostname-allowlist
  (let ((agent (first *cnp-pods*)) (web (second *cnp-pods*)) (cnps (cnp-claude-policies)))
    (is-true (gr8s.network::pod-egress-synthetic-p agent cnps))
    (is-false (gr8s.network::pod-egress-synthetic-p web cnps))
    (is-false (gr8s.network::pod-egress-synthetic-p agent '()))))

(test egress-capture-records-each-pods-mode
  ;; 1: captured by a SecurityProfile alone, admitted by SNI/Host; 2: synthetic mode.
  (let ((contents (gr8s.network::egress-capture-contents
                   '(("10.88.0.5" . 2) ("10.88.0.6" . 1) ("10.88.0.7" . 2))
                   (lambda (address) (cdr (assoc address '(("10.88.0.5" . 11) ("10.88.0.6" . 12)) :test #'equal))))))
    (is (equalp (list (cons (gr8s.network::%egress-u64-le 11) #(2))
                      (cons (gr8s.network::%egress-u64-le 12) #(1)))
                contents))))

(test egress-a-synthetic-mode-pod-may-reach-the-synthetic-range
  (multiple-value-bind (isolated entries)
      (gr8s.network::pod-policy-entries (first *cnp-pods*) '() (cnp-claude-policies) :egress)
    (is-true isolated)
    (is (equal '((6 nil nil)) (cnp-ports-for entries gr8s.network::+egress-synthetic-cidr+)))))

(test egress-the-synthetic-range-is-reserved
  (signals gr8s.network::cni-error
    (gr8s.agent::validate-node-pool-config (gr8s.agent::make-node-pool-config "198.18.0.0/16" 24)))
  (signals gr8s.network::cni-error
    (gr8s.agent::validate-node-pool-config (gr8s.agent::make-node-pool-config "198.16.0.0/12" 24)))
  (with-temporary-store (store path)
    (values path)
    (signals kubernetes-error
      (gr8s.resources::create-core-resource
       store "servicecidrs"
       (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "bench")
                                    "spec" (gr8s.resources::core-object "cidrs" (vector "198.19.0.0/24")))
       nil))
    (is (gr8s.resources::create-core-resource
         store "servicecidrs"
         (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "fine")
                                      "spec" (gr8s.resources::core-object "cidrs" (vector "198.20.0.0/24")))
         nil))))
