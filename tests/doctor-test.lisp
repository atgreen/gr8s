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
  (is (equal '(7 2) (multiple-value-list (gr8s.server::doctor-kernel-version "7.2.11-200.fc44.x86_64"))))
  (is (equal '(6 6) (multiple-value-list (gr8s.server::doctor-kernel-version "6.6.0-generic"))))
  (is (gr8s.server::doctor-kernel-ok-p "7.2.11-200.fc44.x86_64"))
  (is (gr8s.server::doctor-kernel-ok-p "6.6.0-generic"))
  (is (gr8s.server::doctor-kernel-ok-p "6.12.3"))
  (is (not (gr8s.server::doctor-kernel-ok-p "6.5.13-x")))
  (is (not (gr8s.server::doctor-kernel-ok-p "5.15.0-foo"))))

(test doctor-port-spec-coverage
  (is (gr8s.server::doctor-port-spec-covers-p "53/udp" 53))
  (is (gr8s.server::doctor-port-spec-covers-p "1-1024/udp" 53))
  (is (gr8s.server::doctor-port-spec-covers-p "1025-65535/tcp" 20000))
  (is (not (gr8s.server::doctor-port-spec-covers-p "1025-65535/udp" 53)))
  (is (not (gr8s.server::doctor-port-spec-covers-p "80/tcp" 53))))

(test doctor-state-directory-ownership-decision
  (flet ((status (&rest args) (values (apply #'gr8s.server::doctor-state-directory-status args))))
    ;; Missing directory is fine -- gr8s will create it 0700.
    (is (eq :ok (status 0 nil nil nil nil)))
    ;; Owned by the running uid and not group/other-writable -> ok.
    (is (eq :ok (status 0 t t 0 #o40700)))
    (is (eq :ok (status 1000 t t 1000 #o40755)))
    ;; Root pointed at a user-owned directory (the reported first-run wall) -> fail.
    (is (eq :fail (status 0 t t 1000 #o40755)))
    ;; Owned by the running uid but group/other-writable -> fail.
    (is (eq :fail (status 0 t t 0 #o40777)))
    (is (eq :fail (status 0 t t 0 #o40702)))
    ;; Exists but is not a directory -> fail.
    (is (eq :fail (status 0 t nil 0 #o100600)))))

(test doctor-firewall-dns-decision
  ;; No active firewall -> not blocked.
  (is (not (gr8s.server::doctor-firewall-blocks-dns-p nil nil nil)))
  ;; Active, DNS not in ports or services -> blocked (the FedoraWorkstation case).
  (is (gr8s.server::doctor-firewall-blocks-dns-p t '("1025-65535/udp" "1025-65535/tcp") '("ssh" "samba-client")))
  ;; Active but the "dns" service is allowed -> not blocked.
  (is (not (gr8s.server::doctor-firewall-blocks-dns-p t '() '("ssh" "dns"))))
  ;; Active but a port range covers 53 -> not blocked.
  (is (not (gr8s.server::doctor-firewall-blocks-dns-p t '("1-1024/udp") '("ssh")))))

(test doctor-firewall-state-reads-firewall-cmd
  ;; Injected runner standing in for firewall-cmd.
  (flet ((runner (argv)
           (let ((sub (second argv)))
             (cond ((string= sub "--state") (values "running" 0))
                   ((string= sub "--list-ports") (values "1025-65535/udp 1025-65535/tcp" 0))
                   ((string= sub "--list-services") (values "ssh dhcpv6-client" 0))))))
    (multiple-value-bind (active ports services) (gr8s.server::doctor-firewall-state :runner #'runner)
      (is (not (null active)))
      (is (member "1025-65535/udp" ports :test #'string=))
      (is (member "ssh" services :test #'string=))
      (is (gr8s.server::doctor-firewall-blocks-dns-p active ports services))))
  ;; firewall-cmd missing (nil exit) -> no active firewall.
  (flet ((absent (argv) (declare (ignore argv)) (values "" nil)))
    (is (null (nth-value 0 (gr8s.server::doctor-firewall-state :runner #'absent))))))

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
             (is (eq :active (gr8s.kubelet::kubelet-endpoint-status live)))
             (sb-bsd-sockets:socket-close listener)
             (rename-file live stale)
             (is (eq :stale (gr8s.kubelet::kubelet-endpoint-status stale)))
             (is (eq :absent (gr8s.kubelet::kubelet-endpoint-status live))))
        (ignore-errors (sb-bsd-sockets:socket-close listener))))))

(test doctor-fails-on-a-live-kubelet-endpoint-with-actionable-output
  (let ((output
          (with-output-to-string (*standard-output*)
            (is (= 1 (gr8s.server::doctor-check-kubelet-endpoints
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
              (gr8s.server::ensure-kubelet-endpoints-available
               :probe (lambda (path)
                        (declare (ignore path))
                        :active)
               :command "serve")
            (gr8s.runtime::runtime-error (error) error))))
    (is (typep condition 'gr8s.runtime::runtime-error))
    (is (search "another kubelet is listening" (princ-to-string condition)))
    (is (search "gr8s serve --disable-agent" (princ-to-string condition)))))

(test doctor-run-returns-fail-count-with-injected-firewall
  ;; A smoke of the orchestrator: with a firewall that blocks DNS it still only
  ;; warns (no FAILs) on a sane host; the return value is the FAIL count.
  (let ((fails (gr8s.server::run-doctor
                :firewall (lambda () (values t '("1025-65535/udp") '("ssh"))))))
    (is (integerp fails))))

;;; podster-a5g: a killed gr8s instance leaves interfaces whose routes overlap
;;; the pod pool, crash-looping the next startup. `doctor --fix` deletes links
;;; it can PROVE gr8s created; everything else stays an operator decision.

(test doctor-recognizes-gr8s-owned-links
  (flet ((attrs (&key alias kind)
           (let ((table (make-hash-table)))
             (when alias (setf (gethash 20 table) (cl-rtnetlink::netlink-string alias)))
             (when kind
               (setf (gethash 18 table)
                     (cl-rtnetlink::netlink-octets
                      (cl-rtnetlink::netlink-attribute 1 (cl-rtnetlink::netlink-string kind)))))
             table)))
    (is (gr8s.server::doctor-gr8s-owned-link-p "gr8s-vxlan" (attrs)))
    (is (gr8s.server::doctor-gr8s-owned-link-p "gr8s-services" (attrs)))
    (is (gr8s.server::doctor-gr8s-owned-link-p
         "anything" (attrs :alias "gr8s:vxlan:10.80.0.0/20:1:192.0.2.1"))
        "the gr8s ownership alias marks a link whatever its name")
    (is (gr8s.server::doctor-gr8s-owned-link-p
         "grde05246b6b25c" (attrs :kind "veth"))
        "an orphan gr8s pod veth is recognized by kind and name shape")
    (is (not (gr8s.server::doctor-gr8s-owned-link-p "eth0" (attrs))))
    (is (not (gr8s.server::doctor-gr8s-owned-link-p "grde05246b6b25c" (attrs :kind "dummy")))
        "the veth name shape alone does not prove ownership")
    (is (not (gr8s.server::doctor-gr8s-owned-link-p
              "veth1234" (attrs :alias "flannel.1" :kind "veth"))))
    (is (not (gr8s.server::doctor-gr8s-owned-link-p nil nil))
        "a route whose link is unresolvable is never deleted")))

(test doctor-fix-deletes-owned-debris-and-revalidates
  (let* ((vxlan-attrs (let ((table (make-hash-table)))
                        (setf (gethash 20 table) (cl-rtnetlink::netlink-string "gr8s:vxlan:x"))
                        table))
         (violations (list (list :cidr "10.80.0.0/32" :table 255 :index 7
                                 :interface "gr8s-vxlan" :attributes vxlan-attrs)
                           (list :cidr "10.80.0.1/32" :table 254 :index 8
                                 :interface "gr8s-vxlan" :attributes vxlan-attrs)))
         (deleted nil)
         (calls 0))
    ;; With --fix: delete once (deduplicated), re-validate, report clean.
    (is (zerop (gr8s.server::doctor-check-pod-pool-routes
                "10.80.0.0/12" #P"/tmp/x/" t
                :violations-fn (lambda (cidr directory)
                                 (declare (ignore cidr directory))
                                 (incf calls)
                                 (if (= calls 1) violations nil))
                :deleter (lambda (name) (push name deleted)))))
    (is (equal '("gr8s-vxlan") deleted)
        "one shared link is deleted once, not per route")
    ;; Without --fix: the same debris FAILs with a hint at --fix.
    (is (= 1 (gr8s.server::doctor-check-pod-pool-routes
              "10.80.0.0/12" #P"/tmp/x/" nil
              :violations-fn (lambda (&rest args) (declare (ignore args)) violations)
              :deleter (lambda (name) (push name deleted)))))
    ;; Foreign debris is never deleted, with or without --fix.
    (let ((foreign (list (list :cidr "10.80.9.9/32" :table 254 :index 9
                               :interface "eth0" :attributes (make-hash-table)))))
      (is (= 1 (gr8s.server::doctor-check-pod-pool-routes
                "10.80.0.0/12" #P"/tmp/x/" t
                :violations-fn (lambda (&rest args) (declare (ignore args)) foreign)
                :deleter (lambda (name) (error "must not delete ~A" name)))))))
  ;; A clean host stays quiet.
  (is (zerop (gr8s.server::doctor-check-pod-pool-routes
              "10.80.0.0/12" #P"/tmp/x/" nil
              :violations-fn (lambda (&rest args) (declare (ignore args)) nil)
              :deleter (lambda (name) (error "must not delete ~A" name))))))

(test doctor-parses-fix-flag
  (let ((options (gr8s.server::parse-doctor-options '("--fix"))))
    (is (eq t (getf options :fix))))
  (let ((options (gr8s.server::parse-doctor-options nil)))
    (is (null (getf options :fix)))))
