;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Pin the pure decision logic behind `gr8s doctor` (kernel-version gate,
;;;; firewalld DNS-reachability heuristic) without touching the host.

(in-package #:gr8s/tests)
(def-suite doctor :in gr8s)
(in-suite doctor)

(test doctor-parses-and-gates-kernel-version
  (is (equal '(7 2) (multiple-value-list (gr8s::doctor-kernel-version "7.2.11-200.fc44.x86_64"))))
  (is (equal '(6 6) (multiple-value-list (gr8s::doctor-kernel-version "6.6.0-generic"))))
  (is (gr8s::doctor-kernel-ok-p "7.2.11-200.fc44.x86_64"))
  (is (gr8s::doctor-kernel-ok-p "6.6.0-generic"))
  (is (gr8s::doctor-kernel-ok-p "6.12.3"))
  (is (not (gr8s::doctor-kernel-ok-p "6.5.13-x")))
  (is (not (gr8s::doctor-kernel-ok-p "5.15.0-foo"))))

(test doctor-port-spec-coverage
  (is (gr8s::doctor-port-spec-covers-p "53/udp" 53))
  (is (gr8s::doctor-port-spec-covers-p "1-1024/udp" 53))
  (is (gr8s::doctor-port-spec-covers-p "1025-65535/tcp" 20000))
  (is (not (gr8s::doctor-port-spec-covers-p "1025-65535/udp" 53)))
  (is (not (gr8s::doctor-port-spec-covers-p "80/tcp" 53))))

(test doctor-firewall-dns-decision
  ;; No active firewall -> not blocked.
  (is (not (gr8s::doctor-firewall-blocks-dns-p nil nil nil)))
  ;; Active, DNS not in ports or services -> blocked (the FedoraWorkstation case).
  (is (gr8s::doctor-firewall-blocks-dns-p t '("1025-65535/udp" "1025-65535/tcp") '("ssh" "samba-client")))
  ;; Active but the "dns" service is allowed -> not blocked.
  (is (not (gr8s::doctor-firewall-blocks-dns-p t '() '("ssh" "dns"))))
  ;; Active but a port range covers 53 -> not blocked.
  (is (not (gr8s::doctor-firewall-blocks-dns-p t '("1-1024/udp") '("ssh")))))

(test doctor-firewall-state-reads-firewall-cmd
  ;; Injected runner standing in for firewall-cmd.
  (flet ((runner (argv)
           (let ((sub (second argv)))
             (cond ((string= sub "--state") (values "running" 0))
                   ((string= sub "--list-ports") (values "1025-65535/udp 1025-65535/tcp" 0))
                   ((string= sub "--list-services") (values "ssh dhcpv6-client" 0))))))
    (multiple-value-bind (active ports services) (gr8s::doctor-firewall-state :runner #'runner)
      (is (not (null active)))
      (is (member "1025-65535/udp" ports :test #'string=))
      (is (member "ssh" services :test #'string=))
      (is (gr8s::doctor-firewall-blocks-dns-p active ports services))))
  ;; firewall-cmd missing (nil exit) -> no active firewall.
  (flet ((absent (argv) (declare (ignore argv)) (values "" nil)))
    (is (null (nth-value 0 (gr8s::doctor-firewall-state :runner #'absent))))))

(test doctor-run-returns-fail-count-with-injected-firewall
  ;; A smoke of the orchestrator: with a firewall that blocks DNS it still only
  ;; warns (no FAILs) on a sane host; the return value is the FAIL count.
  (let ((fails (gr8s::run-doctor
                :firewall (lambda () (values t '("1025-65535/udp") '("ssh"))))))
    (is (integerp fails))))