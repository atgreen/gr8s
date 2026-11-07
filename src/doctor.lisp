;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; `gr8s doctor`: inspect and validate the host environment, turning the
;;;; cryptic failures we hit in practice (EHOSTUNREACH from a default-deny
;;;; firewall, pod-pool route overlaps, missing kernel/cgroup/bpffs support)
;;;; into actionable, up-front diagnostics.  Each check prints ok/warn/fail with
;;;; a remediation hint; the command exits non-zero only when a check FAILs.
;;;;
;;;; Pure decision helpers are separated from data gathering so the logic is
;;;; unit-tested without a host.

(in-package #:gr8s)

(defun doctor-report (status label &optional detail hint)
  "Print one check line.  STATUS is :ok, :warn, or :fail.  Returns STATUS."
  (format t "~&  [~A] ~A~@[: ~A~]~%"
          (ecase status (:ok " ok ") (:warn "warn") (:fail "FAIL")) label detail)
  (when (and hint (member status '(:warn :fail)))
    (format t "         -> ~A~%" hint))
  status)

;;; ---------------------------------------------------------------------------
;;; Pure decision helpers (unit-tested).

(defun doctor-kernel-version (release)
  "Return (values major minor) parsed from a uname release like \"7.2.11-x\"."
  (let* ((base (subseq release 0 (position #\- release)))
         (parts (uiop:split-string base :separator '(#\.))))
    (values (ignore-errors (parse-integer (first parts) :junk-allowed t))
            (ignore-errors (parse-integer (or (second parts) "0") :junk-allowed t)))))

(defun doctor-kernel-ok-p (release &key (min-major 6) (min-minor 6))
  "True when RELEASE is at least MIN-MAJOR.MIN-MINOR (TCX + cgroup/connect4)."
  (multiple-value-bind (major minor) (doctor-kernel-version release)
    (and major minor
         (or (> major min-major) (and (= major min-major) (>= minor min-minor))))))

(defun doctor-port-spec-covers-p (spec port)
  "SPEC is a firewalld port like \"53/udp\" or \"1025-65535/tcp\"; does it cover PORT?"
  (let* ((range (subseq spec 0 (position #\/ spec)))
         (dash (position #\- range)))
    (ignore-errors
     (if dash
         (<= (parse-integer range :end dash) port (parse-integer range :start (1+ dash)))
         (= port (parse-integer range))))))

(defun doctor-firewall-blocks-dns-p (active ports services)
  "True when a firewall is ACTIVE yet nothing opens inbound DNS (the \"dns\"
service or a port range covering 53), so the gateway DNS would be rejected."
  (and active
       (not (member "dns" services :test #'string=))
       (notany (lambda (spec) (doctor-port-spec-covers-p spec 53)) ports)))

;;; ---------------------------------------------------------------------------
;;; Data gathering (degrades gracefully; a probe failure becomes a warn).

(defun doctor-proc-string (path)
  "Read PATH and return its contents with surrounding whitespace trimmed (for
single-value /proc files)."
  (string-trim '(#\Space #\Newline #\Tab) (uiop:read-file-string path)))

(defun doctor-mounts ()
  "Return the contents of /proc/mounts, or \"\" when it cannot be read."
  (handler-case (uiop:read-file-string "/proc/mounts") (error () "")))

(defun doctor-firewall-state (&key (runner #'doctor-run))
  "Return (values active-p ports services) by asking firewall-cmd, or (nil nil nil)
when no active firewalld is present."
  (multiple-value-bind (out code) (funcall runner (list "firewall-cmd" "--state"))
    (declare (ignore out))
    (if (and code (zerop code))
        (values t
                (uiop:split-string (string-trim '(#\Newline) (funcall runner '("firewall-cmd" "--list-ports"))))
                (uiop:split-string (string-trim '(#\Newline) (funcall runner '("firewall-cmd" "--list-services")))))
        (values nil nil nil))))

(defun doctor-run (argv)
  "Run ARGV, returning (values stdout exit-code), or (values \"\" nil) if the
program is missing.  Used for optional host tools like firewall-cmd."
  (handler-case
      (multiple-value-bind (out err code)
          (uiop:run-program argv :output '(:string :stripped t) :ignore-error-status t
                                 :error-output nil)
        (declare (ignore err))
        (values out code))
    (error () (values "" nil))))

;;; ---------------------------------------------------------------------------
;;; The command.

(defun doctor-node-pod-cidr (state-directory)
  "Best-effort: this node's assigned Pod CIDR from a persisted agent network.json
   under STATE-DIRECTORY, or NIL when the node has not joined/networked yet."
  (let ((root (uiop:ensure-directory-pathname state-directory)))
    (dolist (rel '("agent/runtime/network.json" "runtime/network.json" "agent/network.json"))
      (let ((path (merge-pathnames rel root)))
        (when (probe-file path)
          (let ((net (ignore-errors (com.inuoe.jzon:parse path))))
            (when (and (hash-table-p net) (gethash "nodePodCIDR" net))
              (return-from doctor-node-pod-cidr (gethash "nodePodCIDR" net)))))))))

(defun run-doctor (&key (cluster-pod-cidr +default-cluster-pod-cidr+)
                        (state-directory (namestring (default-state-directory)))
                        (firewall #'doctor-firewall-state))
  "Run every environment check and return the number of FAILs."
  (let ((fails 0))
    (flet ((note (status label &optional detail hint)
             (when (eq (doctor-report status label detail hint) :fail) (incf fails))))
      (format t "~&gr8s doctor — host environment checks~%~%")

      ;; Kernel: TCX and cgroup/connect4 need a recent kernel.
      (handler-case
          (let ((release (doctor-proc-string "/proc/sys/kernel/osrelease")))
            (if (doctor-kernel-ok-p release)
                (note :ok "kernel" (format nil "~A (>= 6.6, TCX + cgroup/connect4)" release))
                (note :fail "kernel" (format nil "~A" release)
                      "gr8s eBPF needs Linux 6.6+ (TCX links, cgroup/connect4)")))
        (error (c) (note :warn "kernel" (format nil "could not read: ~A" c))))

      ;; cgroup v2 unified hierarchy (where the socket LB attaches).
      (let ((mounts (doctor-mounts)))
        (if (search "cgroup2 /sys/fs/cgroup" mounts)
            (note :ok "cgroup2" "/sys/fs/cgroup")
            (note :fail "cgroup2" "no cgroup2 at /sys/fs/cgroup"
                  "mount the unified cgroup2 hierarchy; gr8s attaches the socket LB there"))
        ;; bpffs for pinning policy/LB maps.
        (if (search " bpf " mounts)
            (note :ok "bpffs" "present")
            (note :warn "bpffs" "no bpf filesystem mounted"
                  "gr8s mounts a private bpffs under the agent state dir, but a host /sys/fs/bpf is recommended")))

      ;; IPv4 forwarding (Pod egress).
      (handler-case
          (if (string= "1" (doctor-proc-string "/proc/sys/net/ipv4/ip_forward"))
              (note :ok "ip_forward" "enabled")
              (note :warn "ip_forward" "disabled"
                    "gr8s enables net.ipv4.ip_forward at startup; set it to 1 to avoid surprises"))
        (error (c) (note :warn "ip_forward" (format nil "could not read: ~A" c))))

      ;; Pod-pool route overlap (the validate-pod-pool-host-routes trap).  A
      ;; FAIL here names the state dir we checked: the usual cause is that the
      ;; overlapping route belongs to a live Pod owned by an agent whose state
      ;; dir is not this one, so re-run against that agent before touching any
      ;; route.
      (let ((directory (uiop:ensure-directory-pathname state-directory)))
        (handler-case
            (progn
              (validate-pod-pool-host-routes cluster-pod-cidr directory)
              (note :ok "pod-pool routes"
                    (format nil "no host route overlaps ~A (state dir ~A)"
                            cluster-pod-cidr directory)))
          (cni-error (c)
            (note :fail "pod-pool routes"
                  (format nil "~A (checked state dir ~A)" c directory)
                  (format nil "if the route is a live Pod owned by another agent, re-run with ~
                               --state-directory pointing at that agent; otherwise remove the ~
                               genuinely stale route (sudo ip route del <cidr>)")))
          (error (c) (note :warn "pod-pool routes" (format nil "could not check: ~A" c)))))

      ;; Host firewall vs the gateway DNS (169.254.1.1:53) — podster-sp5.
      (handler-case
          (multiple-value-bind (active ports services) (funcall firewall)
            (cond
              ((not active) (note :ok "firewall DNS" "no active firewalld"))
              ((doctor-firewall-blocks-dns-p active ports services)
               ;; Not a problem since podster-sp5: Pod DNS to 169.254.1.1:53 is
               ;; eBPF-redirected to loopback ingress, bypassing the host
               ;; firewall's inbound path, so an un-opened :53 no longer blocks it.
               (note :ok "firewall DNS"
                     "firewalld active without inbound :53; Pod DNS still served via the eBPF redirect-to-loopback"))
              (t (note :ok "firewall DNS" "inbound DNS is permitted"))))
        (error (c) (note :warn "firewall DNS" (format nil "could not check: ~A" c))))

      ;; Host firewall vs the cross-node overlay (podster-vwy). Cross-node Pod
      ;; traffic is kernel-routed, so an active firewalld must be told to admit
      ;; the overlay; gr8s programs scoped ACCEPTs when the VXLAN comes up.
      (handler-case
          (let ((active (funcall firewall))
                (cidr (doctor-node-pod-cidr state-directory)))
            (cond
              ((not active)
               (note :ok "overlay firewall" "no active firewalld; the overlay needs no host-firewall rules"))
              ((null cidr)
               (note :ok "overlay firewall"
                     "no node network yet; gr8s programs the overlay ACCEPTs when the node joins and the VXLAN comes up"))
              ((overlay-firewall-present-p cidr)
               (note :ok "overlay firewall"
                     (format nil "firewalld admits the overlay (gr8s-vxlan + source ~A + ~D/udp)"
                             cidr +node-vxlan-udp-port+)))
              (t
               (note :warn "overlay firewall"
                     (format nil "firewalld is active but the overlay ACCEPTs for ~A are missing" cidr)
                     "gr8s programs these when the VXLAN comes up; cross-node Pod traffic stays blocked until it does"))))
        (error (c) (note :warn "overlay firewall" (format nil "could not check: ~A" c))))

      ;; The in-process eBPF programs compile (no ELF, no toolchain).
      (handler-case
          (multiple-value-bind (lb-maps lb-progs) (compile-service-lb)
            (multiple-value-bind (eg-maps eg-progs) (compile-egress-guard)
              (note :ok "eBPF compile"
                    (format nil "service LB (~D maps, ~D prog) + egress guard (~D maps, ~D prog)"
                            (length lb-maps) (length lb-progs) (length eg-maps) (length eg-progs)))))
        (error (c) (note :fail "eBPF compile" (format nil "Whistler compilation failed: ~A" c)
                         "this is a build/image problem, not a host one")))

      ;; Actually loading BPF into the kernel needs privilege.
      (unless (zerop (sb-posix:geteuid))
        (note :warn "bpf load" "skipped (not root)"
              "run 'sudo gr8s doctor' to verify the kernel accepts BPF map creation + program load"))

      (format t "~%~A~%" (if (zerop fails) "all checks passed (warnings are advisory)"
                             (format nil "~D check(s) FAILED" fails))))
    fails))
