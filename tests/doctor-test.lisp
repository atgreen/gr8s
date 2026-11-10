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

(test doctor-classifies-live-stale-and-absent-kubelet-endpoints
  (with-temporary-store (store path)
    (declare (ignore store))
    (let* ((live (merge-pathnames "live.sock" path))
           (stale (merge-pathnames "stale.sock" path))
           (listener (make-instance 'sb-bsd-sockets:local-socket :type :stream :protocol 0)))
      (unwind-protect
           (progn
             (sb-bsd-sockets:socket-bind listener (namestring live))
             (sb-bsd-sockets:socket-listen listener 1)
             (is (eq :active (gr8s::kubelet-endpoint-status live)))
             (sb-bsd-sockets:socket-close listener)
             (rename-file live stale)
             (is (eq :stale (gr8s::kubelet-endpoint-status stale)))
             (is (eq :absent (gr8s::kubelet-endpoint-status live))))
        (ignore-errors (sb-bsd-sockets:socket-close listener))))))

(test doctor-fails-on-a-live-kubelet-endpoint-with-actionable-output
  (let ((output
          (with-output-to-string (*standard-output*)
            (is (= 1 (gr8s::doctor-check-kubelet-endpoints
                      (lambda (path)
                        (if (search "device-plugins" (namestring path))
                            :active
                            :absent))))))))
    (is (search "/var/lib/kubelet/device-plugins/kubelet.sock" output))
    (is (search "another kubelet is listening" output))
    (is (search "systemctl stop k3s" output))))

(test managed-node-preflight-refuses-a-live-kubelet-without-a-backtrace
  (let ((condition
          (handler-case
              (gr8s::ensure-kubelet-endpoints-available
               :probe (lambda (path)
                        (declare (ignore path))
                        :active)
               :command "serve")
            (gr8s.runtime:runtime-error (error) error))))
    (is (typep condition 'gr8s.runtime:runtime-error))
    (is (search "another kubelet is listening" (princ-to-string condition)))
    (is (search "gr8s serve --disable-agent" (princ-to-string condition)))))

(test doctor-run-returns-fail-count-with-injected-firewall
  ;; A smoke of the orchestrator: with a firewall that blocks DNS it still only
  ;; warns (no FAILs) on a sane host; the return value is the FAIL count.
  (let ((fails (gr8s::run-doctor
                :firewall (lambda () (values t '("1025-65535/udp") '("ssh"))))))
    (is (integerp fails))))
