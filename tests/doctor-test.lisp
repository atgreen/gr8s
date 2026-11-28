;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Pin the pure decision logic behind `gr8s doctor` (kernel-version gate,
;;;; firewalld DNS-reachability heuristic) without touching the host.

(in-package #:gr8s/tests)
(def-suite doctor :in gr8s)
(in-suite doctor)

(test doctor-host-command-bounds
  ;; PROGV also exercises the old implementation, which ignores these limits.
  (progv '(gr8s.server::*doctor-command-timeout* gr8s.server::*doctor-command-output-limit*)
      '(1 32)
    (multiple-value-bind (out code)
        (gr8s.server::doctor-run '("python3" "-c" "import time; print('partial', flush=True); time.sleep(2)"))
      (is (null code) "A timed-out command cannot establish a successful observation")
      (is (equal "" out) "Discard partial output"))
    (multiple-value-bind (out code)
        (gr8s.server::doctor-run '("python3" "-c" "print('x' * 64)"))
      (is (null code) "An oversized response cannot establish a successful observation")
      (is (equal "" out)))
    (multiple-value-bind (out code)
        (gr8s.server::doctor-run '("python3" "-c" "import sys; sys.stdout.write('x' * 32)"))
      (is (= 0 code))
      (is (equal (make-string 32 :initial-element #\x) out)))
    (multiple-value-bind (out code)
        (gr8s.server::doctor-run '("python3" "-c" "import sys; print('no'); sys.exit(7)"))
      (is (= 7 code))
      (is (equal "no" out)))))

(test doctor-host-command-reaps-interrupted-children
  (progv '(gr8s.server::*doctor-command-timeout* gr8s.server::*doctor-command-output-limit*)
      '(1 32)
    (dolist (action '("os.close(1)" "print('x' * 64, flush=True)"))
      (uiop:with-temporary-file (:pathname pid-file :keep nil)
        (multiple-value-bind (out code)
            (gr8s.server::doctor-run
             (list "python3" "-c"
                   (format nil "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); ~A; time.sleep(3)" action)
                   (namestring pid-file)))
          (is (null code))
          (is (equal "" out)))
        (let* ((pid (parse-integer (uiop:read-file-string pid-file)))
               (gone (handler-case (progn (sb-posix:kill pid 0) nil)
                       (sb-posix:syscall-error (c)
                         (= sb-posix:esrch (sb-posix:syscall-errno c))))))
          (is (eq t gone) "Interrupted direct child must be terminated and reaped"))))))

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

(test doctor-nfs-client-decision
  ;; /proc/filesystems parsing: the "nodev<TAB>nfs4" shape, and plain names.
  (let ((procfs (format nil "nodev~Asysfs~%nodev~Atmpfs~%~Aext4~%nodev~Anfs~%nodev~Anfs4~%"
                        #\Tab #\Tab #\Tab #\Tab #\Tab)))
    (is (gr8s.server::doctor-filesystem-listed-p procfs "nfs"))
    (is (gr8s.server::doctor-filesystem-listed-p procfs "nfs4"))
    (is (gr8s.server::doctor-filesystem-listed-p procfs "ext4"))
    (is (not (gr8s.server::doctor-filesystem-listed-p procfs "nfsd")))
    (is (not (gr8s.server::doctor-filesystem-listed-p "" "nfs"))))
  (flet ((status (&rest args) (values (apply #'gr8s.server::doctor-nfs-client-status args))))
    ;; Already loaded, or loadable on demand -> ok. Absent is advisory (warn), never fail.
    (is (eq :ok (status t nil)))
    (is (eq :ok (status t t)))
    (is (eq :ok (status nil t)))
    (is (eq :warn (status nil nil)))))

(test doctor-firewall-dns-decision
  ;; No active firewall -> not blocked.
  (is (not (gr8s.server::doctor-dns-rules-incomplete-p nil nil nil)))
  ;; Active, DNS not in ports or services -> blocked (the FedoraWorkstation case).
  (is (gr8s.server::doctor-dns-rules-incomplete-p t '("1025-65535/udp" "1025-65535/tcp") '("ssh" "samba-client")))
  ;; Active but the "dns" service is allowed -> not blocked.
  (is (not (gr8s.server::doctor-dns-rules-incomplete-p t '() '("ssh" "dns"))))
  ;; Both TCP and UDP ranges cover 53.
  (is (not (gr8s.server::doctor-dns-rules-incomplete-p t '("1-1024/udp" "1-1024/tcp") '("ssh")))))

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
      (is (gr8s.server::doctor-dns-rules-incomplete-p active ports services))))
  ;; A missing client does not establish that the daemon is inactive.
  (flet ((absent (argv) (declare (ignore argv)) (values "" nil)))
    (signals error (gr8s.server::doctor-firewall-state :runner #'absent))))

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

(test doctor-refuses-a-mistyped-command-as-a-state-directory
  ;; podster-m6w: 'gr8s doctor diagnosis' checked an empty ./diagnosis/ state directory,
  ;; found a running node's routes stale, and advised the --fix that tears them down.
  (flet ((message (arguments)
           (handler-case (progn (gr8s.server::parse-doctor-options arguments) nil)
             (error (condition) (princ-to-string condition)))))
    (is (search "did you mean 'diagnose'" (message '("diagnosis"))))
    (is (search "did you mean 'observe'" (message '("obsrve"))))
    (let ((text (message '("frobnicate"))))
      (is (search "unknown doctor command: frobnicate" text))
      (is (null (search "did you mean" text)))))
  ;; A path, or a word naming a directory that exists, is still a state directory.
  (is (equal "/srv/gr8s" (getf (gr8s.server::parse-doctor-options '("/srv/gr8s")) :state-directory)))
  (let ((here (car (last (pathname-directory (uiop:getcwd))))))
    (uiop:with-current-directory ((uiop:pathname-parent-directory-pathname (uiop:getcwd)))
      (is (equal here (getf (gr8s.server::parse-doctor-options (list here)) :state-directory))))))

(test doctor-parses-fix-flag
  (let ((options (gr8s.server::parse-doctor-options '("--fix"))))
    (is (eq t (getf options :fix))))
  (let ((options (gr8s.server::parse-doctor-options nil)))
    (is (null (getf options :fix)))))

;;; podster-rnh: gvision's join stalled because firewalld's default zone
;;; dropped raft :7000 arriving on the unzoned wg0 -- gr8s listened happily
;;; and nothing logged. Doctor now maps the member's recorded endpoint to its
;;; interface and firewalld zone and fails when the cluster ports are dropped.

(defun port-admission-runner (&key (zone-of "no zone") (default "FedoraServer")
                                   (ports "") (addr-lines "2: wlp1s0 inet 192.0.2.10/24 brd ..."))
  (lambda (argv)
    (let ((text (format nil "~{~A~^ ~}" argv)))
      (cond
        ((search "--get-zone-of-interface" text)
         (if (equal zone-of "no zone") (values "no zone" 1) (values zone-of 0)))
        ((search "--get-default-zone" text) (values default 0))
        ((search "--list-ports" text) (values ports 0))
        ((search "ip -4 -o addr" text) (values addr-lines 0))
        (t (values "" 1))))))

(test doctor-resolves-interface-and-zone-for-an-address
  (let ((runner (port-admission-runner
                 :addr-lines (format nil "1: lo inet 127.0.0.1/8 scope host lo~%7: wg0 inet 10.77.77.21/24 scope global wg0"))))
    (is (equal "wg0" (gr8s.server::doctor-interface-for-address "10.77.77.21" :runner runner)))
    (is (null (gr8s.server::doctor-interface-for-address "192.0.2.99" :runner runner))))
  (multiple-value-bind (zone defaulted-p)
      (gr8s.server::doctor-zone-of-interface "wg0" :runner (port-admission-runner))
    (is (equal "FedoraServer" zone))
    (is (eq t defaulted-p) "an unzoned interface falls to the default zone"))
  (multiple-value-bind (zone defaulted-p)
      (gr8s.server::doctor-zone-of-interface "wg0" :runner (port-admission-runner :zone-of "trusted"))
    (is (equal "trusted" zone))
    (is (null defaulted-p))))

(test doctor-port-admission-decision
  (multiple-value-bind (status detail hint)
      (gr8s.server::doctor-port-admission-status "trusted" nil "wg0" nil '(7000 7443 6443))
    (declare (ignorable detail))
    (is (eq :warn status))
    (is (search "zone target" hint)))
  (multiple-value-bind (status detail hint)
      (gr8s.server::doctor-port-admission-status
       "FedoraServer" t "wg0" '("7000/tcp" "7443/tcp" "6443/tcp") '(7000 7443 6443))
    (declare (ignorable detail))
    (is (eq :ok status))
    (is (null hint)))
  (multiple-value-bind (status detail hint)
      (gr8s.server::doctor-port-admission-status
       "FedoraServer" t "wg0" '("22/tcp") '(7000 7443 6443))
    (is (eq :warn status))
    (is (search "7000" detail))
    (is (search "test the endpoint from a peer" hint))))

(test doctor-cluster-port-check-reads-the-ha-endpoint
  (let* ((root (uiop:ensure-directory-pathname
                (sb-posix:mkdtemp
                 (namestring (merge-pathnames "gr8s-doctor-XXXXXX" (uiop:temporary-directory)))))))
    (unwind-protect
         (progn
           ;; No endpoint: nothing to check.
           (is (zerop (gr8s.server::doctor-check-cluster-port-admission
                       root :runner (port-admission-runner) :firewalld-active-p t)))
           (ensure-directories-exist (merge-pathnames "metadata/" root))
           (with-open-file (out (merge-pathnames "metadata/server-ha-endpoint.json" root)
                                :direction :output)
             (write-string "{\"format\":\"gr8s-serve-ha-endpoint\",\"version\":1,\"memberId\":\"gvision\",\"host\":\"10.77.77.21\",\"port\":7000,\"apiUrl\":\"https://10.77.77.21:6443\"}" out))
           (let ((runner (port-admission-runner
                          :addr-lines "7: wg0 inet 10.77.77.21/24 scope global wg0")))
             (is (= 0 (gr8s.server::doctor-check-cluster-port-admission
                       root :runner runner :firewalld-active-p t))
                 "missing explicit ports warn, because effective policy is unknown")
             (is (zerop (gr8s.server::doctor-check-cluster-port-admission
                         root :runner runner :firewalld-active-p nil))
                 "without firewalld there is nothing to admit"))
           (let ((runner (port-admission-runner
                          :zone-of "trusted"
                          :addr-lines "7: wg0 inet 10.77.77.21/24 scope global wg0")))
             (is (zerop (gr8s.server::doctor-check-cluster-port-admission
                         root :runner runner :firewalld-active-p t))
                 "a zone name alone cannot establish a failure")))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test doctor-removes-a-service-interface-another-cluster-left
  (flet ((check (status fix &key serve-pid (deleter (lambda (name) (error "must not delete ~A" name))))
           (let ((*standard-output* (make-broadcast-stream)))
             (gr8s.server::doctor-check-service-interface
              "/var/lib/gr8s/server/" fix
              :status-fn (lambda (directory) (declare (ignore directory)) status)
              :serve-pid-fn (lambda () serve-pid)
              :deleter deleter))))
    (is (zerop (check :absent t)))
    (is (zerop (check :owned t)))
    ;; A rebuilt cluster's serve refuses to start beside it, so it is a FAIL...
    (is (= 1 (check :foreign nil)))
    ;; ...that --fix clears.
    (let ((deleted nil))
      (is (zerop (check :foreign t :deleter (lambda (name) (push name deleted)))))
      (is (equal '("gr8s-services") deleted)))
    ;; With a serve running it may be that process's, under another state directory.
    (is (zerop (check :foreign t :serve-pid 4242)))
    (is (= 1 (check :foreign t :deleter (lambda (name) (declare (ignore name)) (error "EPERM")))))))

(test doctor-recognizes-a-running-serve
  (flet ((command-line (&rest arguments)
           (format nil "~{~A~C~}" (loop for argument in arguments
                                        append (list argument (code-char 0))))))
    (is-true (gr8s.server::doctor-serve-command-line-p
              (command-line "/usr/bin/gr8s" "serve" "--raft-init")))
    (is-false (gr8s.server::doctor-serve-command-line-p (command-line "/usr/bin/gr8s" "doctor" "--fix")))
    (is-false (gr8s.server::doctor-serve-command-line-p (command-line "/usr/bin/k3s" "serve")))
    (is-false (gr8s.server::doctor-serve-command-line-p ""))))

(test doctor-judges-flushed-write-latency
  ;; Lab, 2026-11-19: 0.8 ms on the founder's SSD, 10 ms on a consumer NVMe in a
  ;; guest, 179 ms on btrfs with compression on a busy SATA disk.
  (flet ((status (milliseconds control-plane-p)
           (nth-value 0 (gr8s.server::doctor-storage-latency-status milliseconds control-plane-p))))
    (is (eq :ok (status 0.8 t)))
    (is (eq :ok (status 10 t)))
    (is (eq :warn (status 40 t)))
    (is (eq :fail (status 179 t)))
    (is (eq :warn (status 179 nil)) "a worker keeps no Raft log; slow is a warning there"))
  (is (search "179.0 ms" (nth-value 1 (gr8s.server::doctor-storage-latency-status 179 t))))
  (let ((mounts (format nil "/dev/vda3 / btrfs rw,compress=zstd:1 0 0~%/dev/vda3 /var btrfs rw,compress=zstd:1,subvol=/var 0 0~%/dev/vdb /var/lib/gr8s xfs rw,noatime 0 0~%/dev/vdc /var/lib/gr8s-other ext4 rw 0 0~%")))
    (is (equal "xfs rw,noatime on /var/lib/gr8s"
               (gr8s.server::doctor-mount-for-path mounts "/var/lib/gr8s/server")))
    (is (equal "btrfs rw,compress=zstd:1,subvol=/var on /var"
               (gr8s.server::doctor-mount-for-path mounts "/var/log")))
    (is (equal "btrfs rw,compress=zstd:1 on /" (gr8s.server::doctor-mount-for-path mounts "/srv"))))
  (let ((root (uiop:ensure-directory-pathname
               (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-doctor-XXXXXX" (uiop:temporary-directory)))))))
    (unwind-protect
         (flet ((check (milliseconds)
                  (let* ((out (make-string-output-stream))
                         (fails (let ((*standard-output* out))
                                  (gr8s.server::doctor-check-storage-latency
                                   root :measure-fn (lambda (directory) (declare (ignore directory)) milliseconds)
                                        :mounts-fn (lambda () "/dev/vda3 / btrfs rw,compress=zstd:1 0 0")))))
                    (values fails (get-output-stream-string out)))))
           ;; The real measurement runs, returns a time and leaves nothing behind.
           (is (typep (gr8s.server::doctor-measure-flush-milliseconds root :writes 3) '(real 0)))
           (is (null (uiop:directory-files root)))
           (is (zerop (check 0.8)))
           (is (zerop (check 179)) "without a Raft log this is a worker")
           (ensure-directories-exist (merge-pathnames "raft/" root))
           (with-open-file (out (merge-pathnames "raft/control-plane.log" root) :direction :output)
             (write-string "x" out))
           (multiple-value-bind (fails text) (check 179)
             (is (= 1 fails))
             (is (search "btrfs rw,compress=zstd:1 on /" text) "a poor result names the filesystem")))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  (is (zerop (let ((*standard-output* (make-broadcast-stream)))
               (gr8s.server::doctor-check-storage-latency "/nonexistent/gr8s/state/")))
      "no state directory yet: nothing to measure"))

(test doctor-firewall-probe-failures-are-not-inactivity
  (dolist (code '(nil 1 29 36 251 253 254))
    (signals error
      (gr8s.server::doctor-firewall-state
       :runner (lambda (argv) (declare (ignore argv)) (values "PRIVATE-FAILURE" code)))))
  (is (equal '(nil nil nil)
             (multiple-value-list
              (gr8s.server::doctor-firewall-state
               :runner (lambda (argv) (declare (ignore argv)) (values "not running" 252))))))
  (dolist (failed-operation '("--list-ports" "--list-services"))
    (signals error
      (gr8s.server::doctor-firewall-state
       :runner (lambda (argv)
                 (if (equal failed-operation (second argv))
                     (values "PRIVATE-FAILURE" 253)
                     (values "" 0)))))))

(test doctor-port-admission-requires-tcp
  (multiple-value-bind (status detail hint)
      (gr8s.server::doctor-port-admission-status
       "public" nil "wg0" '("7000/udp" "7443/udp" "6443/udp") '(7000 7443 6443))
    (declare (ignore hint))
    (is (eq :warn status))
    (is (search "7000" detail)))
  (multiple-value-bind (status detail hint)
      (gr8s.server::doctor-port-admission-status
       "public" nil "wg0" '("6000-8000/tcp") '(7000 7443 6443))
    (declare (ignore detail hint))
    (is (eq :ok status))))

(test doctor-dns-check-distinguishes-protocols
  (is (gr8s.server::doctor-dns-rules-incomplete-p t '("53/tcp") nil))
  (is (gr8s.server::doctor-dns-rules-incomplete-p t '("53/udp") nil))
  (is (not (gr8s.server::doctor-dns-rules-incomplete-p t '("53/udp" "53/tcp") nil)))
  (is (gr8s.server::doctor-dns-rules-incomplete-p t '("53/sctp") nil)))

(test doctor-corrupt-ha-endpoint-is-not-absence
  (let ((root (uiop:ensure-directory-pathname
               (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-doctor-corrupt-XXXXXX" (uiop:temporary-directory)))))))
    (unwind-protect
         (progn
           (ensure-directories-exist (merge-pathnames "metadata/" root))
           (dolist (contents '("{PRIVATE-BROKEN" "null" "[]" "{}"
                               "{\"host\":\"127.0.0.1\",\"port\":\"bad\"}"))
             (with-open-file (out (merge-pathnames "metadata/server-ha-endpoint.json" root)
                                  :direction :output :if-exists :supersede)
               (write-string contents out))
             (let ((output (with-output-to-string (*standard-output*)
                             (gr8s.server::doctor-check-cluster-port-admission
                              root :firewalld-active-p t
                              :runner (lambda (&rest args) (declare (ignore args))
                                        (error "must not probe with invalid metadata"))))))
               (is (search "[warn]" output))
               (is (search "HA endpoint" output))
               (is-false (search "nothing to admit" output))
               (is-false (search "PRIVATE-BROKEN" output)))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test doctor-api-url-admission-port
  (let* ((root (uiop:ensure-directory-pathname
                (sb-posix:mkdtemp
                 (namestring (merge-pathnames "gr8s-doctor-url-XXXXXX" (uiop:temporary-directory))))))
         (path (merge-pathnames "metadata/server-ha-endpoint.json" root)))
    (unwind-protect
         (progn
           (ensure-directories-exist path)
           (dolist (case '(("nonsense" nil) ("https://" nil)
                           ("https://10.77.77.21:bad" nil)
                           ("https://10.77.77.21:0" nil)
                           ("https://10.77.77.21:65536" nil)
                           ("ftp://10.77.77.21:6443" nil)
                           ("https://10.77.77.21" 443)
                           ("https://10.77.77.21:443" 443)
                           ("https://10.77.77.21:8443" 8443)))
             (destructuring-bind (url port) case
               (with-open-file (out path :direction :output :if-exists :supersede)
                 (com.inuoe.jzon:stringify
                  (gr8s.resources::core-object
                   "format" "gr8s-serve-ha-endpoint" "version" 1
                   "memberId" "test" "host" "10.77.77.21" "port" 7000 "apiUrl" url)
                  :stream out))
               (let* ((calls 0)
                      (delegate (port-admission-runner
                                 :addr-lines "7: wg0 inet 10.77.77.21/24 scope global wg0"
                                 :ports (format nil "7000/tcp 7443/tcp ~D/tcp" (or port 6443))))
                      (output
                        (with-output-to-string (*standard-output*)
                          (gr8s.server::doctor-check-cluster-port-admission
                           root :firewalld-active-p t
                           :runner (lambda (argv) (incf calls) (funcall delegate argv))))))
                 (if port
                     (progn (is (search "[ ok ]" output) "URL ~A: ~A" url output)
                            (is (plusp calls)))
                     (progn (is (search "[warn]" output) "URL ~A: ~A" url output)
                            (is (zerop calls) "Invalid metadata must not probe ports")))))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test doctor-checks-api-interface-separately
  (let* ((root (uiop:ensure-directory-pathname
                (sb-posix:mkdtemp
                 (namestring (merge-pathnames "gr8s-doctor-zones-XXXXXX" (uiop:temporary-directory))))))
         (path (merge-pathnames "metadata/server-ha-endpoint.json" root)))
    (unwind-protect
         (progn
           (ensure-directories-exist path)
           (dolist (api-host '("192.0.2.10" "api.example.invalid"))
             (with-open-file (out path :direction :output :if-exists :supersede)
               (com.inuoe.jzon:stringify
                (gr8s.resources::core-object
                 "format" "gr8s-serve-ha-endpoint" "version" 1
                 "memberId" "test" "host" "10.77.77.21" "port" 7000
                 "apiUrl" (format nil "https://~A:6443" api-host)) :stream out))
             (dolist (api-open '(nil t))
               (let* ((result nil)
                      (output
                        (with-output-to-string (*standard-output*)
                          (setf result
                                (gr8s.server::doctor-check-cluster-port-admission
                                 root :firewalld-active-p t
                                 :runner
                                 (lambda (argv)
                                   (cond
                                     ((equal argv '("ip" "-4" "-o" "addr" "show"))
                                      (values (format nil "7: wg0 inet 10.77.77.21/24 scope global wg0~%2: eth0 inet 192.0.2.10/24 scope global eth0") 0))
                                     ((member "--get-zone-of-interface=wg0" argv :test #'equal)
                                      (values "trusted" 0))
                                     ((member "--get-zone-of-interface=eth0" argv :test #'equal)
                                      (values "public" 0))
                                     ((member "--zone=trusted" argv :test #'equal) (values "" 0))
                                     ((member "--zone=public" argv :test #'equal)
                                      (values (if api-open "6443/tcp" "") 0))
                                     (t (error "Unexpected probe: ~S" argv)))))))))
                 (cond
                   ((equal api-host "api.example.invalid")
                    (is (search "[warn]" output))
                    (is (search api-host output))
                    (is (zerop result)))
                   (api-open
                    (is (search "6443" output))
                    (is (search "eth0" output))
                    (is (zerop result)))
                   (t
                    (is (search "[warn]" output))
                    (is (search "eth0" output))
                    (is (zerop result))))))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test doctor-port-query-errors-are-unknown
  (dolist (failure '("address" "zone" "default" "ports"))
    (dolist (code '(nil 29 36 253))
      (let* ((queries nil)
             (result nil)
             (output
               (with-output-to-string (*standard-output*)
                 (setf result
                       (gr8s.server::doctor-check-address-port-admission
                        "10.77.77.21" '(7000)
                        :runner
                        (lambda (argv)
                          (let ((kind (cond ((equal (first argv) "ip") "address")
                                            ((member "--get-zone-of-interface=wg0" argv :test #'equal) "zone")
                                            ((member "--get-default-zone" argv :test #'equal) "default")
                                            (t "ports"))))
                            (push kind queries)
                            (cond
                              ((equal kind failure) (values "PRIVATE-PROBE-ERROR" code))
                              ((equal kind "address") (values "7: wg0 inet 10.77.77.21/24 scope global wg0" 0))
                              ((equal kind "zone")
                               (if (equal failure "default") (values "no zone" 1) (values "trusted" 0)))
                              ((equal kind "default") (values "trusted" 0))
                              (t (values "7000/tcp" 0))))))))))
        (is (search "[warn]" output) "~A code ~S: ~A" failure code output)
        (is-false (search "[ ok ]" output))
        (is-false (search "[FAIL]" output))
        (is-false (search "PRIVATE-PROBE-ERROR" output))
        (is (zerop result))
        (is (equal failure (first queries)) "Do not probe beyond the failed observation")))))

(test doctor-port-list-is-not-effective-policy
  ;; Empty explicit ports also occurs when services or rich rules allow traffic.
  ;; Zone names can survive changes to their target and therefore prove nothing.
  (dolist (zone '("public" "trusted"))
    (multiple-value-bind (status detail hint)
        (gr8s.server::doctor-port-admission-status zone nil "eth0" nil '(6443))
      (is (eq :warn status))
      (is (search "explicit TCP" detail))
      (is (search "6443" detail))
      (is-false (search "dropped" hint))
      (is-false (search "--add-interface" hint))
      (is (search "services" hint))))
  (multiple-value-bind (status detail hint)
      (gr8s.server::doctor-port-admission-status "public" nil "eth0" '("6443/tcp") '(6443))
    (is (eq :ok status))
    (is (search "explicit TCP" detail))
    (is (search "reachability" detail))
    (is (null hint))))

(test doctor-storage-probe-preserves-existing-files
  (let* ((root (uiop:ensure-directory-pathname
                (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-doctor-storage-XXXXXX" (uiop:temporary-directory))))))
         (path (merge-pathnames (format nil ".doctor-flush-~D" (sb-posix:getpid)) root)))
    (unwind-protect
         (progn
           (with-open-file (out path :direction :output) (write-string "existing-data" out))
           (is (typep (gr8s.server::doctor-measure-flush-milliseconds root :writes 1) '(real 0)))
           (is (probe-file path))
           (when (probe-file path)
             (is (equal "existing-data" (uiop:read-file-string path))))
           (is (= 1 (length (uiop:directory-files root)))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test doctor-node-listener-port-is-observed-not-assumed
  (let* ((root (uiop:ensure-directory-pathname
                (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-doctor-node-XXXXXX" (uiop:temporary-directory))))))
         (node-path (merge-pathnames "metadata/server-node-endpoint.json" root))
         (runner (port-admission-runner :zone-of "public" :ports "7000/tcp 6443/tcp 8444/tcp"
                                       :addr-lines (format nil "7: wg0 inet 10.77.77.21/24 scope global wg0~%2: eth0 inet 192.0.2.20/24 scope global eth0"))))
    (unwind-protect
         (progn
           (ensure-directories-exist node-path)
           (with-open-file (out (merge-pathnames "metadata/server-ha-endpoint.json" root) :direction :output)
             (com.inuoe.jzon:stringify
              (gr8s.resources::core-object "format" "gr8s-serve-ha-endpoint" "version" 1
               "memberId" "test" "host" "10.77.77.21" "port" 7000 "apiUrl" "https://10.77.77.21:6443") :stream out))
           (flet ((check () (with-output-to-string (*standard-output*)
                             (gr8s.server::doctor-check-cluster-port-admission root :firewalld-active-p t :runner runner))))
             (let ((output (check)))
               (is (search "node listener" output))
               (is (search "not recorded" output))
               (is-false (search "7443" output)))
             (with-open-file (out node-path :direction :output)
               (com.inuoe.jzon:stringify
                (gr8s.resources::core-object "format" "gr8s-serve-node-endpoint" "version" 1
                 "host" "192.0.2.20" "port" 8444) :stream out))
             (let ((output (check)))
               (is (search "8444" output))
               (is (search "eth0" output))
               (is-false (search "7443" output))
               (is-false (search "[warn]" output)))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test doctor-default-cluster-firewall-probe-preserves-unknown
  (let* ((root (uiop:ensure-directory-pathname
                (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-doctor-state-XXXXXX" (uiop:temporary-directory))))))
         (path (merge-pathnames "metadata/server-ha-endpoint.json" root))
         (legacy (symbol-function 'gr8s.network::host-firewalld-active-p)))
    (unwind-protect
         (progn
           (ensure-directories-exist path)
           (with-open-file (out path :direction :output)
             (com.inuoe.jzon:stringify
              (gr8s.resources::core-object "format" "gr8s-serve-ha-endpoint" "version" 1
               "memberId" "test" "host" "10.77.77.21" "port" 7000
               "apiUrl" "https://10.77.77.21:6443") :stream out))
           ;; The runtime's Boolean helper intentionally collapses failures.
           ;; Diagnostics must use its own error-aware injected runner instead.
           (setf (symbol-function 'gr8s.network::host-firewalld-active-p) (lambda () nil))
           (dolist (code '(nil 29 36 251 253 252))
             (let* ((calls 0)
                    (output
                      (with-output-to-string (*standard-output*)
                        (gr8s.server::doctor-check-cluster-port-admission
                         root :runner (lambda (argv)
                                        (incf calls)
                                        (assert (equal argv '("firewall-cmd" "--state")))
                                        (values "PRIVATE-STATE-ERROR" code))))))
               (is (= 1 calls))
               (if (eql code 252)
                   (is (search "firewalld is inactive" output))
                   (progn
                     (is (search "[warn]" output))
                     (is (search "state is unknown" output))
                     (is-false (search "[ ok ]" output))))
               (is-false (search "PRIVATE-STATE-ERROR" output)))))
      (setf (symbol-function 'gr8s.network::host-firewalld-active-p) legacy)
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test the-gr8s-image-carries-every-doctor-file
  ;; gr8s.asd lists the doctor's files again for the image; when the two lists
  ;; drifted, pulls.lisp was missing from v1.37.2-gr8s.5 and every Pod the doctor
  ;; read closely failed with an undefined function.
  (flet ((names (component)
           (sort (mapcar #'asdf:component-name (asdf:component-children component)) #'string<)))
    (let ((standalone (asdf:find-system
                       (progn (asdf:load-asd (asdf:system-relative-pathname "gr8s" "src/diagnostics/gr8s-doctor.asd"))
                              "gr8s-doctor")))
          (image (asdf:find-component "gr8s" '("src" "diagnostics"))))
      (is (equal (names standalone) (names image))))
    (is-true (fboundp 'gr8s-diagnose::pull-findings))))

;;; podster-71m: gr8s doctor reads through gr8s's own API client, not kubectl.

(test doctor-api-getter-reads-the-cluster-as-kubectl-did
  (with-core-api (store path)
    (values path)
    (gr8s.resources::create-core-resource
     store "configmaps" (core-fixture "ConfigMap" "settings") "default")
    (let ((getter (gr8s.server::doctor-api-getter
                   (list :server (format nil "http://127.0.0.1:~D" *core-api-port*))))
          (gr8s-diagnose::*read-failures* nil))
      (multiple-value-bind (list state) (funcall getter "ConfigMap" "default" nil)
        (is (eq :present state))
        (let ((item (find "settings" (gethash "items" list) :test #'equal
                          :key (lambda (item) (gethash "name" (gethash "metadata" item))))))
          (is (hash-table-p item))
          ;; As kubectl -o json gives each listed item its kind.
          (is (equal "ConfigMap" (gethash "kind" item)))
          (is (equal "v1" (gethash "apiVersion" item)))))
      (multiple-value-bind (object state) (funcall getter "ConfigMap" "default" "settings")
        (is (eq :present state))
        (is (equal "settings" (gethash "name" (gethash "metadata" object)))))
      (is (eq :absent (nth-value 1 (funcall getter "ConfigMap" "default" "missing"))))
      (is (eq :present (nth-value 1 (funcall getter "Namespace" nil nil))) "a cluster-scoped list")
      (is (eq :unknown (nth-value 1 (funcall getter "NoSuchKind" nil nil))))
      (is (null gr8s-diagnose::*read-failures*) "a kind the cluster doesn't serve is no failure"))))

(test doctor-api-getter-says-why-a-read-failed
  (let* ((closed (let ((socket (usocket:socket-listen "127.0.0.1" 0)))
                   (prog1 (usocket:get-local-port socket) (usocket:socket-close socket))))
         (getter (gr8s.server::doctor-api-getter (list :server (format nil "http://127.0.0.1:~D" closed))))
         (gr8s-diagnose::*read-failures* nil))
    (is (eq :unknown (nth-value 1 (funcall getter "Pod" nil nil))))
    (is (= 1 (length gr8s-diagnose::*read-failures*)))
    (is (search (format nil "127.0.0.1:~D" closed) (first gr8s-diagnose::*read-failures*)))
    ;; A previous log or a member that can't be reached is expected, not a failure.
    (funcall getter "PreviousLog" "default" "web/app")
    (funcall getter "MemberView" nil (format nil "127.0.0.1:~D" closed))
    (is (= 1 (length gr8s-diagnose::*read-failures*)))
    (is (search "Could not read from the cluster: "
                (first (gr8s-diagnose::read-failure-warnings))))))

(test a-silent-api-server-is-an-error-not-a-fatal-timeout
  ;; podster-iumy: a read the server never answers ran out of time with SBCL's TIMEOUT, a
  ;; serious condition IGNORE-ERRORS doesn't catch, and one in a dashboard thread ended
  ;; the dashboard. It is an ordinary error, naming the server.
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t))
         (server (format nil "http://127.0.0.1:~D" (usocket:get-local-port listener)))
         (accepted '()))
    (unwind-protect
         (let ((acceptor (bt:make-thread
                          (lambda () (ignore-errors (push (usocket:socket-accept listener) accepted)))
                          :name "silent server")))
           (let ((condition (handler-case (progn (gr8s.server::doctor-api-get (list :server server) "/api" :seconds 1) nil)
                              (error (error) error))))
             (is (typep condition 'error))
             (is (search "no answer from" (princ-to-string condition)))
             (is (search server (princ-to-string condition))))
           (is (null (ignore-errors (gr8s.server::doctor-api-get (list :server server) "/api" :seconds 1))))
           (bt:join-thread acceptor))
      (dolist (socket accepted) (ignore-errors (usocket:socket-close socket)))
      (usocket:socket-close listener))))

(test gr8s-doctor-diagnoses-without-kubectl
  ;; The whole run, as `gr8s doctor diagnose' makes it, with no kubectl on PATH.
  (with-core-api (store path)
    (values store)
    (let ((kubeconfig (merge-pathnames "kubeconfig" path))
          (old-path (uiop:getenv "PATH")))
      (with-open-file (out kubeconfig :direction :output :if-exists :supersede)
        (format out "apiVersion: v1~%kind: Config~%current-context: test~%clusters:~%- name: test~%  cluster: {server: \"http://127.0.0.1:~D\"}~%users:~%- name: test~%  user: {}~%contexts:~%- name: test~%  context: {cluster: test, user: test}~%"
                *core-api-port*))
      (unwind-protect
           (progn
             (sb-posix:setenv "PATH" "/nonexistent" 1)
             (let* ((json (with-output-to-string (*standard-output*)
                            (let ((gr8s-diagnose::*call-with-getter* #'gr8s.server::call-with-doctor-api-getter))
                              (gr8s-diagnose:doctor-main
                               (list "diagnose" "--kubeconfig" (namestring kubeconfig) "--json")))))
                    (report (com.inuoe.jzon:parse json)))
               (is (not (equal "incomplete" (gethash "status" report))) "~A" (gethash "warnings" report))
               (is (every (lambda (entry) (not (equal "unknown" (gethash "result" entry))))
                          (gethash "coverage" report)))))
        (sb-posix:setenv "PATH" old-path 1)))))

(test doctor-without-kubectl-says-so
  ;; The doctor on its own still reads through kubectl, and says when it can't run it.
  (let ((old-path (uiop:getenv "PATH")))
    (unwind-protect
         (let ((gr8s-diagnose::*read-failures* nil))
           (sb-posix:setenv "PATH" "/nonexistent" 1)
           (is (eq :unknown (nth-value 1 (funcall (gr8s-diagnose::kubectl-getter nil nil) "Pod" nil nil))))
           (is (search "kubectl" (format nil "~{~A~}" gr8s-diagnose::*read-failures*))))
      (sb-posix:setenv "PATH" old-path 1))))

(test gr8s-doctor-says-when-a-file-is-not-a-kubeconfig
  (let ((empty (uiop:with-temporary-file (:pathname path :keep t) path)))
    (unwind-protect
         (let* ((said (make-string-output-stream))
                (code (let ((*error-output* said)
                            (gr8s-diagnose::*call-with-getter* #'gr8s.server::call-with-doctor-api-getter))
                        (gr8s-diagnose:doctor-main (list "diagnose" "--kubeconfig" (namestring empty))))))
           (is (= 2 code))
           (is (search "is not a kubeconfig" (get-output-stream-string said))))
      (ignore-errors (delete-file empty)))))
