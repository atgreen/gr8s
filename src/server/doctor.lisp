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

(defun doctor-port-spec-covers-p (spec port &key protocol)
  "Does a firewalld port or range cover PORT and, when supplied, PROTOCOL?"
  (let* ((slash (position #\/ spec))
         (range (subseq spec 0 slash))
         (dash (position #\- range)))
    (and (or (null protocol) (and slash (string= protocol (subseq spec (1+ slash)))))
         (ignore-errors
          (if dash
              (<= (parse-integer range :end dash) port (parse-integer range :start (1+ dash)))
              (= port (parse-integer range)))))))

(defun doctor-dns-rules-incomplete-p (active ports services)
  "True when the inspected zone lacks the dns service or explicit TCP+UDP53 rules.
This describes listed configuration, not reachability through the full firewall."
  (and active
       (not (member "dns" services :test #'string=))
       (not (every (lambda (protocol)
                     (some (lambda (spec) (doctor-port-spec-covers-p spec 53 :protocol protocol)) ports))
                   '("tcp" "udp")))))

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

(defun doctor-firewalld-active-p (&key (runner #'doctor-run))
  "Return active state; only NOT_RUNNING proves inactivity."
  (multiple-value-bind (out code) (funcall runner '("firewall-cmd" "--state"))
    (declare (ignore out))
    (case code
      (0 t)
      (252 nil)
      (otherwise (error "firewall-cmd --state failed (exit ~S); firewalld state is unknown" code)))))

(defun doctor-firewall-state (&key (runner #'doctor-run))
  "Return active-p, ports and services. Only NOT_RUNNING proves inactivity.
Signal on unreadable state or rule lists so the caller reports an unknown check."
  (labels ((read-list (option)
             (multiple-value-bind (out code) (funcall runner (list "firewall-cmd" option))
               (unless (eql code 0)
                 (error "firewall-cmd ~A failed (exit ~S); rules could not be read" option code))
               (uiop:split-string (string-trim '(#\Newline) out)))))
    (if (doctor-firewalld-active-p :runner runner)
        (values t (read-list "--list-ports") (read-list "--list-services"))
        (values nil nil nil))))

(defparameter *doctor-command-timeout* 5)
(defparameter *doctor-command-output-limit* (* 1024 1024))

(defun doctor-run (argv)
  "Run ARGV with bounded time and output. Return stdout and exit-code, or
empty output and NIL when unavailable, timed out or oversized. Partial output
cannot establish an observation. Used for optional host tools like firewall-cmd."
  (handler-case
      (let ((process (uiop:launch-program argv :output :stream :error-output nil)))
        (unwind-protect
             (sb-ext:with-timeout *doctor-command-timeout*
               (let ((out (with-output-to-string (out)
                            (loop for character = (read-char (uiop:process-info-output process) nil nil)
                                  for size from 0 while character
                                  do (when (>= size *doctor-command-output-limit*)
                                       (error "Host command output limit exceeded"))
                                     (write-char character out)))))
                 (values (uiop:stripln out) (uiop:wait-process process))))
          (unwind-protect
               (progn
                 (when (uiop:process-alive-p process)
                   (uiop:terminate-process process :urgent t))
                 (uiop:wait-process process))
            (uiop:close-streams process))))
    (sb-ext:timeout () (values "" nil))
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

;;; Flushed-write latency. Every Raft commit waits for one flush of the log, so a
;;; member on a slow disk restarts slowly and sends its heartbeats late under
;;; load. On the lab a voter at 179 ms a flush (btrfs with compression on a busy
;;; SATA disk) looked like a network fault for days.

(defun doctor-storage-latency-status (milliseconds control-plane-p)
  "Judge the median time of one flushed 4 kB write. Returns (values STATUS DETAIL HINT)."
  (let ((detail (format nil "~,1F ms per flushed write" milliseconds)))
    (cond
      ((< milliseconds 2) (values :ok detail nil))
      ((< milliseconds 20)
       (values :ok (format nil "~A (adequate; a disk with power-loss protection flushes in under 1 ms)" detail) nil))
      ((or (< milliseconds 100) (not control-plane-p))
       (values :warn detail
               (if control-plane-p
                   "a control-plane member this slow restarts slowly and may send heartbeats late under load"
                   "slow for container and volume writes; a control-plane member needs under 20 ms")))
      (t (values :fail detail
                 "too slow for a control-plane member: every commit waits for a flush. Use a faster disk, and a filesystem without compression or copy-on-write for the state directory")))))

(defun doctor-mount-for-path (mounts path)
  "The /proc/mounts line in MOUNTS whose mount point is the longest prefix of PATH,
as \"FSTYPE OPTIONS on MOUNTPOINT\", or NIL."
  (let ((best nil) (best-length -1))
    (dolist (line (uiop:split-string mounts :separator '(#\Newline)))
      (let ((fields (remove "" (uiop:split-string line :separator '(#\Space)) :test #'equal)))
        (when (>= (length fields) 4)
          (let* ((point (second fields)) (length (length point)))
            (when (and (> length best-length)
                       (or (equal point "/") (equal point path)
                           (and (< length (length path)) (string= point path :end2 length)
                                (char= #\/ (char path length)))))
              (setf best (format nil "~A ~A on ~A" (third fields) (fourth fields) point)
                    best-length length))))))
    best))

(defun doctor-measure-flush-milliseconds (directory &key (writes 50) (budget-seconds 2))
  "Median milliseconds of flushed 4 kB writes to a private scratch file.
Stop between writes after WRITES or BUDGET-SECONDS; a single fsync may take longer."
  (let ((block (make-array 4096 :element-type '(unsigned-byte 8) :initial-element 0))
        (deadline (+ (get-internal-real-time) (* budget-seconds internal-time-units-per-second)))
        (times nil))
    (multiple-value-bind (fd path)
        (sb-posix:mkstemp
         (namestring (merge-pathnames ".doctor-flush-XXXXXX"
                                     (uiop:ensure-directory-pathname directory))))
      (let ((stream nil))
        (unwind-protect
             (progn
               (setf stream (sb-sys:make-fd-stream fd :output t :auto-close t
                                                  :element-type '(unsigned-byte 8)))
               (loop repeat writes
                     while (or (null times) (< (get-internal-real-time) deadline))
                     do (let ((start (get-internal-real-time)))
                          (write-sequence block stream)
                          (finish-output stream)
                          (sb-posix:fsync fd)
                          (push (- (get-internal-real-time) start) times))))
          (unwind-protect
               (if stream (close stream) (sb-posix:close fd))
            (ignore-errors (delete-file path))))))
    (* 1000 (/ (nth (floor (length times) 2) (sort times #'<)) internal-time-units-per-second))))

(defun doctor-check-storage-latency
    (state-directory &key (measure-fn #'doctor-measure-flush-milliseconds)
                          (mounts-fn #'doctor-mounts))
  "Time flushed writes where gr8s keeps its state. Returns the FAIL count."
  (let* ((directory (uiop:ensure-directory-pathname state-directory))
         (path (string-right-trim "/" (namestring directory))))
    (handler-case
        (if (not (uiop:directory-exists-p directory))
            0
            (multiple-value-bind (status detail hint)
                (doctor-storage-latency-status
                 (funcall measure-fn directory)
                 (and (probe-file (merge-pathnames "raft/control-plane.log" directory)) t))
              (doctor-report status "storage"
                             (format nil "~A: ~A~@[ (~A)~]" path detail
                                     (and (not (eq status :ok))
                                          (ignore-errors (doctor-mount-for-path (funcall mounts-fn) path))))
                             hint)
              (if (eq status :fail) 1 0)))
      (error (c)
        (doctor-report :warn "storage" (format nil "~A: could not measure: ~A" path c))
        0))))

(defun doctor-interface-for-address (address &key (runner #'doctor-run))
  "The interface holding ADDRESS, from `ip -4 -o addr`, or NIL."
  (multiple-value-bind (out code) (funcall runner (list "ip" "-4" "-o" "addr" "show"))
    (unless (eql code 0) (error "Could not inspect local addresses"))
    (loop for line in (uiop:split-string out :separator '(#\Newline))
          for parts = (remove "" (uiop:split-string line) :test #'equal)
          when (and (> (length parts) 3)
                    (string= "inet" (third parts))
                    (let ((cidr (fourth parts)))
                      (string= address (subseq cidr 0 (or (position #\/ cidr) (length cidr))))))
            return (second parts))))

(defun doctor-zone-of-interface (interface &key (runner #'doctor-run))
  "Return the assigned zone, or the default zone for a confirmed unzoned interface.
Query failures are unknown observations and signal an error."
  (multiple-value-bind (out code)
      (funcall runner (list "firewall-cmd" (format nil "--get-zone-of-interface=~A" interface)))
    (let ((zone (string-trim '(#\Space #\Newline) out)))
      (cond
        ((and (eql code 0) (plusp (length zone)) (not (equal zone "no zone")))
         (values zone nil))
        ((and (member code '(0 1)) (equal zone "no zone"))
         (multiple-value-bind (default default-code)
             (funcall runner '("firewall-cmd" "--get-default-zone"))
           (let ((name (string-trim '(#\Space #\Newline) default)))
             (unless (and (eql default-code 0) (plusp (length name)))
               (error "Could not inspect default firewall zone"))
             (values name t))))
        (t (error "Could not inspect interface firewall zone"))))))

(defun doctor-port-admission-status (zone defaulted-p interface port-specs needed-ports)
  "Describe explicit TCP port coverage, without inferring effective packet policy."
  (let ((missing (remove-if (lambda (port)
                              (some (lambda (spec) (doctor-port-spec-covers-p spec port :protocol "tcp"))
                                    port-specs))
                            needed-ports)))
    (if (null missing)
        (values :ok
                (format nil "zone ~A lists explicit TCP rules for ~{~D~^, ~} on ~A; reachability is not tested"
                        zone needed-ports interface)
                nil)
        (values :warn
                (format nil "zone ~A on ~A~:[~; (default zone)~] has no explicit TCP rules for ~{~D~^, ~}; effective admission is unknown"
                        zone interface defaulted-p missing)
                "inspect enabled services, rich rules, zone target and policies; test the endpoint from a peer before changing firewall rules"))))

(defun doctor-ha-api-port (url)
  "Return the HTTPS endpoint port, or NIL when URL cannot identify one."
  (handler-case
      (when (stringp url)
        (let* ((uri (puri:parse-uri url))
               (host (puri:uri-host uri))
               (port (or (puri:uri-port uri) 443)))
          (when (and (eq :https (puri:uri-scheme uri))
                     (stringp host) (plusp (length host))
                     (typep port '(integer 1 65535)))
            port)))
    (error () nil)))

(defun doctor-read-ha-endpoint (path)
  "Read endpoint metadata, distinguishing absence from unreadable or invalid data."
  (handler-case
      (if (not (probe-file path))
          (values nil :absent)
          (let* ((endpoint (com.inuoe.jzon:parse path))
                 (api-port (and (hash-table-p endpoint)
                                (doctor-ha-api-port (gethash "apiUrl" endpoint)))))
            (if (and (hash-table-p endpoint)
                     (equal "gr8s-serve-ha-endpoint" (gethash "format" endpoint))
                     (eql 1 (gethash "version" endpoint))
                     (every (lambda (key)
                              (let ((value (gethash key endpoint)))
                                (and (stringp value) (plusp (length value)))))
                            '("memberId" "host" "apiUrl"))
                     (typep (gethash "port" endpoint) '(integer 1 65535))
                     api-port)
                (values endpoint :present api-port)
                (values nil :invalid))))
    (error () (values nil :unreadable))))

(defun doctor-check-address-port-admission (host needed &key (runner #'doctor-run))
  "Check listed TCP port admission on the local interface holding HOST."
  (handler-case
      (let ((interface (doctor-interface-for-address host :runner runner)))
        (if (null interface)
            (progn
              (doctor-report :warn "cluster ports"
                             (format nil "cannot map recorded endpoint ~A to a local IPv4 interface; admission for ~{~D~^, ~} could not be checked"
                                     host needed)
                             "check the advertised address, local listener and any DNS or forwarding path")
              0)
            (multiple-value-bind (zone defaulted-p)
                (doctor-zone-of-interface interface :runner runner)
              (multiple-value-bind (out code)
                  (funcall runner (list "firewall-cmd" (format nil "--zone=~A" zone) "--list-ports"))
                (unless (eql code 0) (error "Could not inspect firewall ports"))
                (multiple-value-bind (status detail hint)
                    (doctor-port-admission-status
                     zone defaulted-p interface
                     (uiop:split-string (string-trim '(#\Newline) out))
                     needed)
                  (doctor-report status "cluster ports" detail hint)
                  (if (eq status :fail) 1 0))))))
    (error ()
      (doctor-report :warn "cluster ports"
                     (format nil "could not inspect interface or firewall state for ~A; admission is unknown" host)
                     "check access to ip and firewall-cmd, then retry")
      0)))

(defun doctor-check-node-port-admission (state-directory &key (runner #'doctor-run))
  "Inspect the configured node listener without inventing missing endpoint facts."
  (handler-case
      (let ((path (merge-pathnames "metadata/server-node-endpoint.json"
                                  (uiop:ensure-directory-pathname state-directory))))
        (if (not (probe-file path))
            (progn
              (doctor-report :warn "node listener" "endpoint not recorded; firewall coverage is unknown"
                             "inspect the member startup configuration for node-listen and node-port")
              0)
            (let ((record (com.inuoe.jzon:parse path)))
              (unless (and (hash-table-p record)
                           (equal "gr8s-serve-node-endpoint" (gethash "format" record))
                           (eql 1 (gethash "version" record))
                           (stringp (gethash "host" record))
                           (plusp (length (gethash "host" record)))
                           (typep (gethash "port" record) '(integer 1 65535)))
                (error "Invalid node endpoint record"))
              (doctor-check-address-port-admission
               (gethash "host" record) (list (gethash "port" record)) :runner runner))))
    (error ()
      (doctor-report :warn "node listener" "endpoint metadata is unreadable or invalid; firewall coverage is unknown")
      0)))

(defun doctor-check-cluster-port-admission (state-directory
                                            &key (runner #'doctor-run)
                                                 (firewalld-active-p :probe))
  "When this state directory is an HA member, verify the host firewall admits
its recorded Raft and API ports on their respective local IPv4 interfaces.
The configured node listener is checked independently when recorded. gvision's
join stalled for exactly this: gr8s listened on wg0 while firewalld's default
zone dropped inbound 7000 without a trace (podster-rnh). Returns the FAIL count."
  (multiple-value-bind (endpoint state api-port)
      (doctor-read-ha-endpoint
       (merge-pathnames "metadata/server-ha-endpoint.json"
                        (uiop:ensure-directory-pathname state-directory)))
    (when (and (eq state :present) (eq firewalld-active-p :probe))
      (setf firewalld-active-p
            (handler-case (doctor-firewalld-active-p :runner runner)
              (error () :unknown))))
    (cond
      ((member state '(:invalid :unreadable))
       (doctor-report :warn "cluster ports"
                      "HA endpoint metadata is unreadable or invalid; admission could not be checked"
                      "inspect metadata/server-ha-endpoint.json and restore the recorded member configuration")
       0)
      ((eq state :absent)
       (doctor-report :ok "cluster ports" "no HA endpoint recorded; nothing to admit")
       0)
      ((eq firewalld-active-p :unknown)
       (doctor-report :warn "cluster ports" "firewalld state is unknown; admission could not be checked"
                      "check access to firewall-cmd and retry")
       0)
      ((not firewalld-active-p)
       (doctor-report :ok "cluster ports" "firewalld is inactive; other firewall rules and reachability are not checked")
       0)
      (t
       (+ (doctor-check-node-port-admission state-directory :runner runner)
          (let* ((host (gethash "host" endpoint))
                 (api-host (puri:uri-host (puri:parse-uri (gethash "apiUrl" endpoint))))
                 (raft-ports (list (gethash "port" endpoint))))
            (if (equal host api-host)
                (doctor-check-address-port-admission host (append raft-ports (list api-port))
                                                     :runner runner)
                (+ (doctor-check-address-port-admission host raft-ports :runner runner)
                   (doctor-check-address-port-admission api-host (list api-port)
                                                        :runner runner)))))))))

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

      ;; How long a flushed write takes where the Raft log lives.
      (incf fails (doctor-check-storage-latency state-directory))

      ;; HA cluster ports vs the host firewall (podster-rnh): a member whose
      ;; raft/node/API ports are dropped on its own listen interface stalls
      ;; joins and replication without a single log line.
      (incf fails (doctor-check-cluster-port-admission state-directory))

      ;; Host firewall vs the gateway DNS (169.254.1.1:53) — podster-sp5.
      (handler-case
          (multiple-value-bind (active ports services) (funcall firewall)
            (cond
              ((not active) (note :ok "firewall DNS" "no active firewalld"))
              ((doctor-dns-rules-incomplete-p active ports services)
               ;; Not a problem since podster-sp5: Pod DNS to 169.254.1.1:53 is
               ;; eBPF-redirected to loopback ingress, bypassing the host
               ;; firewall's inbound path, so an un-opened :53 no longer blocks it.
               (note :ok "firewall DNS"
                     "default zone lacks the dns service or explicit TCP+UDP :53 rules; Pod DNS is designed to use loopback redirection (not probed)"))
              (t (note :ok "firewall DNS" "default zone lists the dns service or TCP+UDP :53 rules; other zones and packet reachability were not checked"))))
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
