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

(in-package #:gr8s.server)

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

(defun doctor-state-directory-status (euid exists-p is-dir-p owner-uid mode)
  "Decide the state-directory ownership check; return (values status detail hint).
gr8s refuses a store it does not own or that others can write (check-store-
generation-directory, applied to the state root with :metadata t: owned by the
effective uid and not group/other-writable). A missing directory is fine -- gr8s
creates it 0700. MODE/OWNER-UID are ignored when EXISTS-P is NIL."
  (cond
    ((not exists-p)
     (values :ok "does not exist yet; gr8s will create it mode 0700" nil))
    ((not is-dir-p)
     (values :fail "exists but is not a directory"
             "point --state-directory at a directory gr8s owns, or remove the conflicting file"))
    ((/= euid owner-uid)
     (values :fail
             (format nil "owned by uid ~D, but gr8s runs as uid ~D" owner-uid euid)
             (format nil "gr8s refuses a store it does not own; run as uid ~D, or ~
                          'sudo chown -R ~D <dir> && sudo chmod 700 <dir>', or use a ~
                          root-owned path such as /var/lib/gr8s under sudo" owner-uid euid)))
    ((not (zerop (logand #o022 mode)))
     (values :fail
             (format nil "owned by uid ~D but mode ~3,'0O is group- or world-writable"
                     owner-uid (logand #o777 mode))
             "'sudo chmod 700 <dir>'; gr8s refuses a store other users can write"))
    (t
     (values :ok (format nil "owned by uid ~D, mode ~3,'0O" owner-uid (logand #o777 mode)) nil))))

(defun doctor-filesystem-listed-p (filesystems name)
  "True when /proc/filesystems lists NAME. Each line is an optional \"nodev\" tag
and the filesystem name, whitespace-separated (e.g. \"nodev\\tnfs4\")."
  (some (lambda (line)
          (member name (remove "" (uiop:split-string line :separator '(#\Space #\Tab))
                               :test #'equal)
                  :test #'string=))
        (uiop:split-string (string-trim '(#\Newline) filesystems) :separator '(#\Newline))))

(defun doctor-nfs-client-status (loaded-p loadable-p)
  "Decide the kernel NFS-client check; return (values status detail hint). gr8s
mounts NFS PersistentVolumes through the mount(2) syscall, so the only host
prerequisite is the in-kernel NFS client -- never mount.nfs or nfs-utils. Its
absence is advisory, not a failure: a cluster that mounts no NFS volumes never
needs it, so a missing client warns rather than fails."
  (cond
    (loaded-p (values :ok "in-kernel NFS client present (nfs/nfs4)" nil))
    (loadable-p (values :ok "in-kernel NFS client available (module loads on demand)" nil))
    (t (values :warn "no in-kernel NFS client (no nfs/nfs4 support found)"
               "only needed for NFS PersistentVolumes; 'sudo modprobe nfs' (v3) or ~
                'sudo modprobe nfsv4' -- gr8s mounts via mount(2) and needs no nfs-utils/mount.nfs"))))

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

(defun doctor-node-network (state-directory)
  "Best-effort: return this node's persisted agent network object, or NIL."
  (let ((root (uiop:ensure-directory-pathname state-directory)))
    (dolist (rel '("agent/runtime/network.json" "runtime/network.json" "agent/network.json"))
      (let ((path (merge-pathnames rel root)))
        (when (probe-file path)
          (let ((net (ignore-errors (com.inuoe.jzon:parse path))))
            (when (and (hash-table-p net) (gethash "nodePodCIDR" net))
              (return-from doctor-node-network net))))))))

(defun doctor-node-pod-cidr (state-directory)
  "Best-effort: this node's assigned Pod CIDR, or NIL before it joins."
  (let ((network (doctor-node-network state-directory)))
    (and network (gethash "nodePodCIDR" network))))

(defparameter +kubelet-host-endpoints+
  '(#P"/var/lib/kubelet/device-plugins/kubelet.sock"
    #P"/var/lib/kubelet/pod-resources/kubelet.sock")
  "Standard host-wide kubelet endpoints owned by a managed gr8s node.")

(defun doctor-check-kubelet-endpoints
    (&optional (probe #'gr8s.kubelet::kubelet-endpoint-status))
  "Report whether another kubelet owns a host-wide endpoint; return FAIL count."
  (loop with fails = 0
        for path in +kubelet-host-endpoints+
        for status = (funcall probe path)
        do (ecase status
             (:absent
              (doctor-report :ok "kubelet endpoint" (format nil "~A is available" path)))
             (:stale
              (doctor-report :ok "kubelet endpoint"
                             (format nil "~A is stale and will be replaced" path)))
             (:active
              (incf fails)
              (doctor-report
               :fail "kubelet endpoint"
               (format nil "another kubelet is listening on ~A" path)
               "stop the other kubelet (for example, 'sudo systemctl stop k3s') or run 'gr8s serve --disable-agent'"))
             (:non-socket
              (incf fails)
              (doctor-report
               :fail "kubelet endpoint"
               (format nil "~A exists and is not a Unix socket" path)
               "move the conflicting file out of the standard kubelet endpoint path")))
        finally (return fails)))

(defparameter +gr8s-fixed-interface-names+
  '("gr8s-vxlan" "gr8s-gateway" "gr8s-services" "gr8s-wg")
  "The fixed interface names gr8s creates on a node (vxlan overlay, pod
gateway, service network, wireguard overlay).")

(defun doctor-gr8s-owned-link-p (name attributes)
  "Judge from the kernel link alone whether gr8s created it: one of its fixed
interface names, the ownership alias gr8s stamps on its devices (\"gr8s:...\"
or \"gr8s-services/...\"), or a pod veth (kind veth, name gr + hex digits).
Only such links may be deleted by --fix; anything else stays an operator call."
  (or (and name (member name +gr8s-fixed-interface-names+ :test #'string=) t)
      (let ((alias (and (hash-table-p attributes) (gethash 20 attributes))))
        (and alias (>= (length alias) 4)
             (loop for i below 4
                   always (eql (aref alias i) (char-code (char "gr8s" i))))))
      (and name (hash-table-p attributes)
           (gr8s.network::network-link-kind-p attributes "veth")
           (and (cl-ppcre:scan "^gr[0-9a-f]+$" name) t))))

(defun doctor-check-pod-pool-routes
    (cluster-pod-cidr directory fix
     &key (violations-fn #'gr8s.agent::pod-pool-host-route-violations)
          (deleter (lambda (name) (gr8s.network::delete-network-link name))))
  "Report the pod-pool overlap check (the validate-pod-pool-host-routes trap);
with FIX, first delete stale gr8s-owned links so startup stops crash-looping
on debris a killed instance left behind (podster-a5g). Routes whose links are
not provably gr8s-owned are never touched. Returns the FAIL count."
  (flet ((describe-violations (violations)
           (format nil "~{~{~A in table ~A~@[ (interface ~A)~]~}~^; ~}"
                   (mapcar (lambda (violation)
                             (list (getf violation :cidr) (getf violation :table)
                                   (getf violation :interface)))
                           violations))))
    (handler-case
        (let ((violations (funcall violations-fn cluster-pod-cidr directory)))
          (if (null violations)
              (progn (doctor-report :ok "pod-pool routes"
                                    (format nil "no host route overlaps ~A (state dir ~A)"
                                            cluster-pod-cidr directory))
                     0)
              (let* ((owned (remove-if-not
                             (lambda (violation)
                               (doctor-gr8s-owned-link-p (getf violation :interface)
                                                         (getf violation :attributes)))
                             violations))
                     (fails 0))
                (cond
                  ((and fix owned)
                   (dolist (name (remove-duplicates
                                  (mapcar (lambda (violation) (getf violation :interface)) owned)
                                  :test #'string= :from-end t))
                     (handler-case
                         (progn (funcall deleter name)
                                (doctor-report :ok "pod-pool fix"
                                               (format nil "removed stale gr8s interface ~A" name)))
                       (error (condition)
                         (incf fails)
                         (doctor-report :fail "pod-pool fix"
                                        (format nil "could not remove ~A: ~A" name condition)
                                        "interface removal needs root; re-run under sudo"))))
                   (let ((remaining (funcall violations-fn cluster-pod-cidr directory)))
                     (if remaining
                         (progn
                           (incf fails)
                           (doctor-report :fail "pod-pool routes"
                                          (format nil "~A (checked state dir ~A)"
                                                  (describe-violations remaining) directory)
                                          "the remaining routes are not gr8s-owned; if one belongs to a live Pod of another agent, re-run with --state-directory pointing at it; otherwise remove it by hand"))
                         (doctor-report :ok "pod-pool routes" "clean after removing stale gr8s interfaces")))
                   fails)
                  (t
                   (doctor-report :fail "pod-pool routes"
                                  (format nil "~A (checked state dir ~A)"
                                          (describe-violations violations) directory)
                                  (if owned
                                      "stale gr8s-owned interfaces found; 'sudo gr8s doctor --fix' removes them"
                                      "if the route is a live Pod owned by another agent, re-run with --state-directory pointing at that agent; otherwise remove the genuinely stale route (sudo ip route del <cidr>)"))
                   1)))))
      (error (condition)
        (doctor-report :warn "pod-pool routes" (format nil "could not check: ~A" condition))
        0))))

(defun doctor-state-ca-fingerprint (state-directory)
  "The fingerprint of the cluster CA kept under STATE-DIRECTORY, or NIL when it
holds no cluster."
  (let ((path (merge-pathnames "pki/pki/cluster-ca.crt"
                               (uiop:ensure-directory-pathname state-directory))))
    (when (probe-file path)
      (gr8s.security::octets-to-hex
       (pure-tls:certificate-fingerprint
        (first (pure-tls:load-certificate-chain path)))))))

(defun doctor-service-interface-status (state-directory)
  "Who owns the host's service interface: :ABSENT when there is none, :OWNED when
the cluster in STATE-DIRECTORY stamped it, :FOREIGN otherwise -- another
cluster's, or debris when STATE-DIRECTORY was wiped."
  (if (zerop (gr8s.network::native-interface-index
              gr8s.apiserver::+service-network-interface+))
      :absent
      (let ((fingerprint (doctor-state-ca-fingerprint state-directory)))
        (if (and fingerprint
                 (gr8s.apiserver::service-network-owned-by-p
                  (gr8s.apiserver::service-network-owner fingerprint)))
            :owned
            :foreign))))

(defun doctor-serve-command-line-p (command-line)
  "True when COMMAND-LINE, a /proc cmdline with NUL-separated arguments, is a
running `gr8s serve`."
  (let ((arguments (uiop:split-string command-line :separator (list (code-char 0)))))
    (and (equal "gr8s" (file-namestring (or (first arguments) "")))
         (equal "serve" (second arguments)))))

(defun doctor-running-serve-pid ()
  "The pid of a running `gr8s serve` on this host, or NIL."
  (dolist (entry (directory #P"/proc/*/"))
    (let ((pid (ignore-errors (parse-integer (car (last (pathname-directory entry)))))))
      (when (and pid (/= pid (sb-posix:getpid))
                 (doctor-serve-command-line-p
                  (or (ignore-errors
                       (uiop:read-file-string (merge-pathnames "cmdline" entry)))
                      "")))
        (return pid)))))

(defun doctor-check-service-interface
    (state-directory fix
     &key (status-fn #'doctor-service-interface-status)
          (serve-pid-fn #'doctor-running-serve-pid)
          (deleter (lambda (name) (gr8s.network::delete-network-link name))))
  "Report a service interface another cluster left behind: `gr8s serve` refuses
to start beside one (`service interface belongs to another cluster`), which
crash-loops a cluster rebuilt in a wiped state directory (podster-mg4). With
FIX, delete it -- unless a serve is running, whose interface it may be when
STATE-DIRECTORY is not that process's. Returns the FAIL count."
  (let ((name gr8s.apiserver::+service-network-interface+))
    (handler-case
        (ecase (funcall status-fn state-directory)
          (:absent 0)
          (:owned
           (doctor-report :ok "service interface"
                          (format nil "~A belongs to the cluster in ~A" name state-directory))
           0)
          (:foreign
           (let ((pid (funcall serve-pid-fn)))
             (cond
               (pid
                (doctor-report
                 :warn "service interface"
                 (format nil "~A does not belong to the cluster in ~A, and gr8s serve is running (pid ~D)"
                         name state-directory pid)
                 "re-run with --state-directory pointing at that process's state directory")
                0)
               (fix
                (handler-case
                    (progn (funcall deleter name)
                           (doctor-report :ok "service interface fix"
                                          (format nil "removed stale gr8s interface ~A" name))
                           0)
                  (error (condition)
                    (doctor-report :fail "service interface fix"
                                   (format nil "could not remove ~A: ~A" name condition)
                                   "interface removal needs root; re-run under sudo")
                    1)))
               (t
                (doctor-report
                 :fail "service interface"
                 (format nil "~A belongs to another cluster, not the one in ~A"
                         name state-directory)
                 "gr8s serve will not start beside it; 'sudo gr8s doctor --fix' removes it")
                1)))))
      (error (condition)
        (doctor-report :warn "service interface" (format nil "could not check: ~A" condition))
        0))))

(defun doctor-interface-for-address (address &key (runner #'doctor-run))
  "The interface holding ADDRESS, from `ip -4 -o addr`, or NIL."
  (let ((out (funcall runner (list "ip" "-4" "-o" "addr" "show"))))
    (loop for line in (uiop:split-string out :separator '(#\Newline))
          for parts = (remove "" (uiop:split-string line) :test #'equal)
          when (and (> (length parts) 3)
                    (string= "inet" (third parts))
                    (let ((cidr (fourth parts)))
                      (string= address (subseq cidr 0 (or (position #\/ cidr) (length cidr))))))
            return (second parts))))

(defun doctor-zone-of-interface (interface &key (runner #'doctor-run))
  "The firewalld zone serving INTERFACE: its assigned zone, else (values
default-zone T) -- traffic on an unzoned interface falls into the default zone,
which is exactly how a WireGuard mesh ends up silently dropped (podster-rnh)."
  (multiple-value-bind (out code)
      (funcall runner (list "firewall-cmd" (format nil "--get-zone-of-interface=~A" interface)))
    (let ((zone (string-trim '(#\Space #\Newline) out)))
      (if (and code (zerop code) (plusp (length zone)) (not (equal zone "no zone")))
          (values zone nil)
          (values (string-trim '(#\Space #\Newline)
                               (funcall runner '("firewall-cmd" "--get-default-zone")))
                  t)))))

(defun doctor-port-admission-status (zone defaulted-p interface port-specs needed-ports)
  "Decide the cluster-port admission check; return (values status detail hint)."
  (let ((missing (remove-if (lambda (port)
                              (some (lambda (spec) (doctor-port-spec-covers-p spec port))
                                    port-specs))
                            needed-ports)))
    (cond
      ((equal zone "trusted")
       (values :ok (format nil "~A is in the trusted zone" interface) nil))
      ((null missing)
       (values :ok (format nil "zone ~A admits ~{~D~^, ~} on ~A" zone needed-ports interface) nil))
      (t
       (values :fail
               (format nil "~A is served by zone ~A~:[~; (by default; the interface is in no zone)~], which does not admit ~{~D~^, ~}"
                       interface zone defaulted-p missing)
               (format nil "cluster traffic arriving on ~A is dropped; 'sudo firewall-cmd --zone=trusted --add-interface=~A --permanent && sudo firewall-cmd --reload' (member traffic is mTLS-authenticated), or admit each port: ~{--add-port=~D/tcp ~}"
                       interface interface missing))))))

(defun doctor-check-cluster-port-admission (state-directory
                                            &key (runner #'doctor-run)
                                                 (firewalld-active-p (gr8s.network::host-firewalld-active-p)))
  "When this state directory is an HA member, verify the host firewall admits
its raft, node and API ports on the interface its endpoints bind. gvision's
join stalled for exactly this: gr8s listened on wg0 while firewalld's default
zone dropped inbound 7000 without a trace (podster-rnh). Returns the FAIL count."
  (let* ((path (merge-pathnames "metadata/server-ha-endpoint.json"
                                (uiop:ensure-directory-pathname state-directory)))
         (endpoint (and (probe-file path)
                        (ignore-errors (com.inuoe.jzon:parse path)))))
    (cond
      ((null endpoint)
       (doctor-report :ok "cluster ports" "no HA endpoint recorded; nothing to admit")
       0)
      ((not firewalld-active-p)
       (doctor-report :ok "cluster ports" "no active firewalld; nothing drops them")
       0)
      (t
       (let* ((host (gethash "host" endpoint))
              (raft-port (gethash "port" endpoint))
              (api-port (or (let ((url (gethash "apiUrl" endpoint)))
                              (and (stringp url)
                                   (let ((colon (position #\: url :from-end t)))
                                     (ignore-errors (parse-integer (subseq url (1+ colon)))))))
                            6443))
              (needed (remove nil (list raft-port 7443 api-port)))
              (interface (and (stringp host) (doctor-interface-for-address host :runner runner))))
         (if (null interface)
             (progn
               (doctor-report :warn "cluster ports"
                              (format nil "no interface currently holds the recorded member address ~A" host)
                              "the member cannot serve its persisted endpoint; check the address or the interface it should live on")
               0)
             (multiple-value-bind (zone defaulted-p)
                 (doctor-zone-of-interface interface :runner runner)
               (multiple-value-bind (out code)
                   (funcall runner (list "firewall-cmd" (format nil "--zone=~A" zone) "--list-ports"))
                 (multiple-value-bind (status detail hint)
                     (doctor-port-admission-status
                      zone defaulted-p interface
                      (and code (zerop code) (uiop:split-string (string-trim '(#\Newline) out)))
                      needed)
                   (doctor-report status "cluster ports" detail hint)
                   (if (eq status :fail) 1 0))))))))))

(defun run-doctor (&key (cluster-pod-cidr +default-cluster-pod-cidr+)
                        (state-directory (namestring (default-state-directory)))
                        (firewall #'doctor-firewall-state)
                        fix)
  "Run every environment check and return the number of FAILs."
  (let ((fails 0))
    (flet ((note (status label &optional detail hint)
             (when (eq (doctor-report status label detail hint) :fail) (incf fails))))
      (format t "~&gr8s doctor — host environment checks~%~%")

      (incf fails (doctor-check-kubelet-endpoints))

      ;; Store directory ownership: gr8s refuses a state dir it does not own or
      ;; that others can write (check-store-generation-directory -> "Unsafe store
      ;; generation directory"), a common first-run wall when a root process is
      ;; pointed at a user-owned directory.
      (handler-case
          (let* ((path (string-right-trim "/" (namestring (uiop:ensure-directory-pathname state-directory))))
                 (stat (ignore-errors (sb-posix:lstat path))))
            (multiple-value-bind (status detail hint)
                (doctor-state-directory-status
                 (sb-posix:geteuid)
                 (and stat t)
                 (and stat (sb-posix:s-isdir (sb-posix:stat-mode stat)))
                 (and stat (sb-posix:stat-uid stat))
                 (and stat (sb-posix:stat-mode stat)))
              (note status "store directory" (format nil "~A: ~A" path detail) hint)))
        (error (c) (note :warn "store directory" (format nil "could not check: ~A" c))))

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
      ;; route.  With --fix, provably gr8s-owned debris (a killed instance's
      ;; vxlan/gateway/services links or orphan pod veths) is deleted first.
      (incf fails (doctor-check-pod-pool-routes
                   cluster-pod-cidr (uiop:ensure-directory-pathname state-directory) fix))

      ;; A service interface stamped by another cluster's CA: what a rebuild in
      ;; a wiped state directory inherits, and what serve refuses to start beside.
      (incf fails (doctor-check-service-interface state-directory fix))

      ;; HA cluster ports vs the host firewall (podster-rnh): a member whose
      ;; raft/node/API ports are dropped on its own listen interface stalls
      ;; joins and replication without a single log line.
      (incf fails (doctor-check-cluster-port-admission state-directory))

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
      ;; the selected overlay; gr8s programs scoped ACCEPTs when its link comes up.
      (handler-case
          (let ((active (funcall firewall))
                (network (doctor-node-network state-directory)))
            (cond
              ((not active)
               (note :ok "overlay firewall" "no active firewalld; the overlay needs no host-firewall rules"))
              ((null network)
               (note :ok "overlay firewall"
                     "no node network yet; gr8s programs overlay ACCEPTs when the node joins"))
              (t
               (destructuring-bind (cidr interface port)
                   (node-network-overlay-firewall-identity network)
                 (if (overlay-firewall-present-p cidr :interface interface :port port)
                     (note :ok "overlay firewall"
                           (format nil "firewalld admits the overlay (~A + source ~A + ~D/udp)"
                                   interface cidr port))
                     (note :warn "overlay firewall"
                           (format nil "firewalld is active but ~A/source ~A/~D/udp ACCEPTs are missing"
                                   interface cidr port)
                           "gr8s programs these when the overlay comes up; cross-node Pod traffic stays blocked until it does"))))))
        (error (c) (note :warn "overlay firewall" (format nil "could not check: ~A" c))))

      ;; In-kernel NFS client for NFS PersistentVolumes (podster-0fr). gr8s
      ;; mounts NFS through mount(2), not mount.nfs, so the one host prerequisite
      ;; is the kernel client; advisory, since a cluster using no NFS volumes
      ;; never needs it. The module usually auto-loads on first mount, so a
      ;; dry-run modprobe counts as available.
      (handler-case
          (let* ((filesystems (handler-case (uiop:read-file-string "/proc/filesystems") (error () "")))
                 (loaded (or (doctor-filesystem-listed-p filesystems "nfs4")
                             (doctor-filesystem-listed-p filesystems "nfs")))
                 (loadable (or loaded
                               (flet ((loadable-p (module)
                                        (let ((code (nth-value 1 (doctor-run (list "modprobe" "-nq" module)))))
                                          (and code (zerop code)))))
                                 (or (loadable-p "nfs") (loadable-p "nfsv4"))))))
            (multiple-value-bind (status detail hint) (doctor-nfs-client-status loaded loadable)
              (note status "nfs client" detail hint)))
        (error (c) (note :warn "nfs client" (format nil "could not check: ~A" c))))

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
