;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The gr8s command-line entry point: argument parsing and the run loops.
;;;;
;;;; Every invocation lands in MAIN, which dispatches on CNI_COMMAND (containerd
;;;; runs this same binary as its CNI plugin) and otherwise on the subcommand --
;;;; serve, agent, witness, join-token, kubeconfig, runtime, wireguard, doctor and the
;;;; informational ones. Each subcommand parses its own arguments into an options
;;;; plist; SERVE and AGENT own the long-running processes. SERVE wires the store,
;;;; PKI, node gRPC server, runtime, reconciliation worker and (unless disabled)
;;;; an in-process local agent together and tears them down in reverse on
;;;; shutdown; AGENT enrolls a node and runs its session against a control plane.
;;;; Shutdown is cooperative: signal handlers set *SHUTDOWN-REQUESTED* and the run
;;;; loops poll it.

(in-package #:gr8s.server)

(defvar *shutdown-requested* nil)

(defun default-state-directory ()
  "The default gr8s state directory: gr8s/ under $XDG_STATE_HOME, or under
   ~/.local/state/ when that variable is unset."
  (merge-pathnames
   "gr8s/"
   (uiop:ensure-directory-pathname
    (or (uiop:getenv "XDG_STATE_HOME")
        (merge-pathnames ".local/state/" (user-homedir-pathname))))))

(defun gr8s-root-directory ()
  "The gr8s tree root (holding build/containerd etc.). GR8S_ROOT wins; otherwise
   the dumped executable derives it from its own location -- <root>/build/gr8s
   -> <root> -- the way the old launcher script did from $0. In a dev image
   (sbcl.core, not our executable) that derivation is skipped and we fall back to
   the current directory."
  (uiop:ensure-directory-pathname
   (or (uiop:getenv "GR8S_ROOT")
       (let ((core sb-ext:*core-pathname*))
         (when (and core (equal (pathname-name core) "gr8s"))
           (ignore-errors
            (uiop:pathname-parent-directory-pathname
             (uiop:pathname-directory-pathname (truename core))))))
       (uiop:getcwd))))

(defun default-containerd-executable ()
  "The default managed-containerd binary path: build/containerd/bin/containerd
   under the gr8s root (see GR8S-ROOT-DIRECTORY)."
  (namestring
   (merge-pathnames "build/containerd/bin/containerd"
                    (gr8s-root-directory))))

(defun default-containerd-oci-runtime ()
  "The default OCI runtime path: build/containerd/bin/runc under the gr8s root."
  (namestring
   (merge-pathnames "build/containerd/bin/runc"
                    (gr8s-root-directory))))

(defun parse-port (value)
  "Parse VALUE as a port integer in 1..65535, or signal an error naming the bad
   value."
  (handler-case
      (let ((port (parse-integer value :junk-allowed nil)))
        (unless (<= 1 port 65535)
          (error "port must be between 1 and 65535"))
        port)
    (error ()
      (error "invalid port: ~A" value))))

(defun notify-service-manager (message)
  "Send one datagram MESSAGE to a Type=notify service manager (NOTIFY_SOCKET).
Outside systemd (no NOTIFY_SOCKET) this is a no-op, and a notification failure
never takes the service down with it. Returns true when a datagram was sent."
  (let ((name (uiop:getenv "NOTIFY_SOCKET")))
    (when (and name (plusp (length name)))
      (ignore-errors
        (let ((socket (make-instance (if (char= #\@ (char name 0))
                                         'sb-bsd-sockets:local-abstract-socket
                                         'sb-bsd-sockets:local-socket)
                                     :type :datagram)))
          (unwind-protect
               (progn
                 (sb-bsd-sockets:socket-connect
                  socket (if (char= #\@ (char name 0)) (subseq name 1) name))
                 (sb-bsd-sockets:socket-send socket message nil)
                 t)
            (sb-bsd-sockets:socket-close socket)))))))

(defvar *service-ready-signaled* nil
  "Set once READY=1 has been sent, so the startup-timeout keepalive stops pushing
the Type=notify start deadline out once the service is actually serving.")

(defun notify-service-manager-ready ()
  "Tell a Type=notify service manager the service is now serving."
  (setf *service-ready-signaled* t)
  (notify-service-manager "READY=1"))

(defun notify-service-manager-extend-timeout (seconds)
  "Push the current Type=notify start/stop deadline out by SECONDS from now
(sd_notify EXTEND_TIMEOUT_USEC), so a live but still-recovering member outlasts
TimeoutStartSec. Like a watchdog ping, it must be re-sent before it elapses."
  (notify-service-manager
   (format nil "EXTEND_TIMEOUT_USEC=~D" (round (* seconds 1000000)))))

(defstruct (startup-timeout-keepalive (:constructor %make-startup-timeout-keepalive))
  thread (stop nil))

(defun start-startup-timeout-keepalive (&key (interval 15) (extension 90))
  "Keep the Type=notify start deadline pushed out from the first startup phase
until READY=1. podster-lmm extends the deadline inside the HA recovery wait, but
a cold rejoin's earlier work (store open, Raft catch-up) can itself exceed
TimeoutStartSec before that loop is reached, so systemd kills and restart-loops
the member (podster-qoa). Send one extension now and re-send every INTERVAL
seconds -- shorter than EXTENSION so a ping never lapses -- until the service
signals ready or STOP is set. Returns a handle for STOP-STARTUP-TIMEOUT-KEEPALIVE."
  (setf *service-ready-signaled* nil)
  (let ((keepalive (%make-startup-timeout-keepalive)))
    (notify-service-manager-extend-timeout extension)
    (setf (startup-timeout-keepalive-thread keepalive)
          (bt:make-thread
           (lambda ()
             (loop until (or (startup-timeout-keepalive-stop keepalive)
                             *service-ready-signaled*)
                   do (notify-service-manager-extend-timeout extension)
                      (sleep interval)))
           :name "gr8s startup timeout keepalive"))
    keepalive))

(defun stop-startup-timeout-keepalive (keepalive)
  "Stop a startup-timeout keepalive and join its thread. Idempotent and safe in an
unwind, so a startup that fails before READY=1 does not leak the thread."
  (when keepalive
    (setf (startup-timeout-keepalive-stop keepalive) t)
    (let ((thread (startup-timeout-keepalive-thread keepalive)))
      (when (and thread (bt:thread-alive-p thread))
        (ignore-errors (bt:join-thread thread))))))

(defun option-value (arguments option)
  "The value following OPTION in ARGUMENTS (its second element), or signal an
   error that OPTION requires a value."
  (unless (rest arguments)
    (error "~A requires a value" option))
  (second arguments))

(defun parse-dns-forward-rule (value)
  "Parse ZONE=IP[:PORT] into a canonical zone and one IPv4 upstream."
  (let ((equals (position #\= value)))
    (unless (and equals (plusp equals) (< equals (1- (length value))))
      (error "DNS forward rule must be ZONE=IP[:PORT]: ~A" value))
    (let* ((zone (canonical-dns-name (subseq value 0 equals)))
           (target (subseq value (1+ equals)))
           (colon (position #\: target :from-end t))
           (address (if colon (subseq target 0 colon) target))
           (port (if colon (parse-port (subseq target (1+ colon))) 53)))
      (unless (dns-subdomain-p zone)
        (error "invalid DNS forwarding zone: ~A" zone))
      (parse-ipv4-integer address)
      (cons zone (cons address port)))))

(defun add-dns-forward-rule (rules value)
  "Add VALUE to ordered RULES, grouping repeated zones into one upstream list."
  (let* ((parsed (parse-dns-forward-rule value))
         (existing (assoc (car parsed) rules :test #'equal)))
    (if existing
        (progn (setf (cdr existing) (append (cdr existing) (list (cdr parsed)))) rules)
        (append rules (list (list (car parsed) (cdr parsed)))))))

(defun add-dns-serve-zone (zones value)
  "Add a canonical external DNS zone to serve authoritatively from the node DNS
(podster-iga), deduplicated and order-preserving."
  (let ((zone (canonical-dns-name value)))
    (unless (dns-subdomain-p zone)
      (error "invalid DNS serve zone: ~A" value))
    (if (member zone zones :test #'equal) zones (append zones (list zone)))))

(defun parse-wireguard-endpoint (value)
  "Parse NAME=IPV4:PORT into the authenticated endpoint tuple advertised by an agent."
  (let* ((equals (position #\= value))
         (target (and equals (subseq value (1+ equals))))
         (colon (and target (position #\: target :from-end t))))
    (unless (and equals (plusp equals) target colon (plusp colon)
                 (< colon (1- (length target))))
      (error "WireGuard endpoint must be NAME=IPV4:PORT: ~A" value))
    (let ((name (subseq value 0 equals))
          (address (subseq target 0 colon))
          (port (subseq target (1+ colon))))
      (unless (dns-label-p name)
        (error "WireGuard endpoint name must be a lowercase DNS label: ~A" name))
      (list name (canonical-node-underlay-address address) (parse-port port)))))

(defun add-wireguard-endpoint (endpoints value)
  "Append parsed VALUE to ENDPOINTS, rejecting ambiguous duplicate names."
  (let ((endpoint (parse-wireguard-endpoint value)))
    (when (assoc (first endpoint) endpoints :test #'equal)
      (error "duplicate WireGuard endpoint name: ~A" (first endpoint)))
    (append endpoints (list endpoint))))

(defun add-registry-ca (registry-cas value)
  "Append VALUE, a registry HOST[:PORT] optionally followed by =FILE, to
REGISTRY-CAS. FILE holds the PEM CAs that registry is verified against instead
of the system roots; a bare HOST trusts the cluster CA (:CLUSTER), for a
registry serving a cert-manager certificate from the cluster's ca issuer."
  (let* ((separator (position #\= value))
         (host (subseq value 0 separator))
         (file (and separator (subseq value (1+ separator)))))
    (unless (gr8s.image-distribution::valid-registry-host-p host)
      (error "--registry-ca needs a registry HOST or HOST:PORT, not ~S" host))
    (when (assoc host registry-cas :test #'string-equal)
      (error "duplicate --registry-ca for ~A" host))
    (when (and file (not (and (uiop:absolute-pathname-p (pathname file)) (probe-file file))))
      (error "--registry-ca file ~S must be an existing absolute path" file))
    (append registry-cas (list (cons host (or file :cluster))))))

(defun validate-cni-options (options)
  "Validate the managed-containerd CNI ownership and plugin search paths."
  (unless (member (getf options :cni-mode) '("native" "external") :test #'string=)
    (error "CNI mode must be native or external"))
  (dolist (path (append (when (getf options :cni-conf-dir)
                          (list (getf options :cni-conf-dir)))
                        (getf options :cni-bin-dirs)))
    (unless (uiop:absolute-pathname-p (pathname path))
      (error "CNI paths must be absolute: ~A" path)))
  (if (string= "external" (getf options :cni-mode))
      (unless (getf options :cni-conf-dir)
        (error "external CNI mode requires --cni-conf-dir"))
      (when (getf options :cni-conf-dir)
        (error "--cni-conf-dir requires external CNI mode")))
  options)

(defun validate-node-resource-options (options)
  "Reject policies that cannot be enforced by this node's runtime."
  (let ((static (equal "static" (getf options :cpu-manager-policy)))
        (numa (equal "single-numa-node" (getf options :topology-manager-policy))))
    (when (and static (null (gr8s.kubelet::parse-cpu-set (or (getf options :reserved-cpus) ""))))
      (error "Static CPU policy requires --reserved-cpus"))
    (when (and (or static numa)
               (not (and (equal "containerd" (getf options :runtime))
                         (equal "managed" (getf options :containerd-mode)))))
      (error "CPU and topology policies require managed containerd")))
  options)

(defun parse-serve-options (arguments)
  "Parse `gr8s serve' ARGUMENTS into an options plist on top of the serve
   defaults. Signals on an unknown option, a missing option value, or an out-of-
   range value."
  (let ((options (list :command :serve
                       :state-directory (namestring (default-state-directory))
                       :listen "0.0.0.0"
                       :port 6443
                       :node-port 7443
                       :node-listen "127.0.0.1"
                       :node-address nil
                       :wireguard-endpoints nil
                       :wireguard-relay-address nil
                       :wireguard-relay-listen "0.0.0.0"
                       :wireguard-relay-port-start 42000
                       :wireguard-relay-max-channels 1024
                       :node-name "gr8s-local"
                       :disable-agent nil
                       :pod-network-egress "agent"
                       :raft-compaction :auto
                       :cluster-pod-cidr +default-cluster-pod-cidr+
                       :cluster-pod-cidrs (vector +default-cluster-pod-cidr+)
                       :node-pod-prefix +default-node-pod-prefix+
                       :node-pod-prefix-ipv6 64
                       :overlay-backend "vxlan"
                       :runtime "containerd"
                       :cpu-manager-policy "none"
                       :topology-manager-policy "none"
                       :reserved-cpus nil
                       :containerd-mode "managed"
                       :containerd-executable (default-containerd-executable)
                       :containerd-oci-runtime (default-containerd-oci-runtime)
                       :containerd-socket "/run/containerd/containerd.sock"
                       :containerd-log-root "/var/log/gr8s/pods/"
                       :registry-credentials-file nil
                       :registry-cas nil
                       :image-credential-provider-config nil
                       :image-credential-provider-bin-dir nil
                       :cni-mode "native"
                       :cni-conf-dir nil
                       :cni-bin-dirs nil
                       :dns-forward-rules nil
                       :dns-serve-zones nil
                       :kubeconfig nil
                       :kubelet-port +kubelet-default-port+
                       :local-storage-path +default-local-storage-path+)))
    (loop while arguments
          for option = (first arguments)
          do (if (member option '("--disable-agent" "--raft-init" "--cluster-reset" "--raft-compaction" "--no-raft-compaction" "--containerd-no-sync") :test #'string=)
                 (progn
                   (cond ((string= option "--disable-agent") (setf (getf options :disable-agent) t))
                         ((string= option "--raft-init") (setf (getf options :raft-init) t))
                         ((string= option "--cluster-reset") (setf (getf options :cluster-reset) t))
                         ((string= option "--raft-compaction") (setf (getf options :raft-compaction) t))
                         ((string= option "--no-raft-compaction") (setf (getf options :raft-compaction) nil))
                         ((string= option "--containerd-no-sync") (setf (getf options :containerd-no-sync) t)))
                   (setf arguments (rest arguments)))
                 (let ((value (option-value arguments option)))
                   (cond
                     ((string= option "--state-directory")
                      (setf (getf options :state-directory) value))
                     ((string= option "--listen")
                      (setf (getf options :listen) value))
                     ((string= option "--port")
                      (setf (getf options :port) (parse-port value)))
                     ((string= option "--debug-slynk-port")
                      (setf (getf options :debug-slynk-port) (parse-port value)))
                     ((string= option "--cluster-pod-cidr")
                      (let ((cidrs (coerce (uiop:split-string value :separator '(#\,)) 'vector)))
                        (validate-node-pool-config
                         (make-node-pool-config
                          (aref cidrs 0) (getf options :node-pod-prefix)
                          cidrs (map 'vector (lambda (cidr)
                                               (if (find #\: cidr)
                                                   (getf options :node-pod-prefix-ipv6)
                                                   (getf options :node-pod-prefix)))
                                     cidrs)))
                        (setf (getf options :cluster-pod-cidr) (aref cidrs 0)
                              (getf options :cluster-pod-cidrs) cidrs))
                      (setf
                            (getf options :cluster-pod-cidr-supplied-p) t))
                     ((string= option "--node-pod-prefix")
                      (let ((prefix (parse-integer value :junk-allowed nil)))
                        (unless (<= 1 prefix 30) (error "node Pod prefix must be 1..30"))
                        (setf (getf options :node-pod-prefix) prefix
                              (getf options :node-pod-prefix-supplied-p) t)))
                     ((string= option "--node-pod-prefix-ipv6")
                      (let ((prefix (parse-integer value :junk-allowed nil)))
                        (unless (<= 1 prefix 126) (error "IPv6 node Pod prefix must be 1..126"))
                        (setf (getf options :node-pod-prefix-ipv6) prefix
                              (getf options :node-pod-prefix-ipv6-supplied-p) t)))
                     ((string= option "--overlay-backend")
                      (unless (member value '("vxlan" "wireguard") :test #'string=)
                        (error "overlay backend must be vxlan or wireguard"))
                      (setf (getf options :overlay-backend) value))
                     ((string= option "--flow-events")
                      (unless (member value '("connections" "drops") :test #'string=)
                        (error "--flow-events must be connections or drops"))
                      (setf (getf options :flow-events) value))
                     ((string= option "--pod-masquerade")
                      (unless (member value '("outside" "off") :test #'string=)
                        (error "--pod-masquerade must be outside or off"))
                      (setf (getf options :pod-masquerade) value))
                     ((string= option "--pod-network-egress")
                      (unless (member value '("agent" "direct") :test #'string=)
                        (error "Pod network egress must be agent or direct"))
                      (setf (getf options :pod-network-egress) value))
                     ((string= option "--node-listen")
                      (setf (getf options :node-listen)
                            (format-ipv4-integer (parse-ipv4-integer value))))
                     ((string= option "--node-address")
                      (setf (getf options :node-address)
                            (canonical-node-underlay-address value)))
                     ((string= option "--wireguard-endpoint")
                      (setf (getf options :wireguard-endpoints)
                            (add-wireguard-endpoint
                             (getf options :wireguard-endpoints) value)))
                     ((string= option "--wireguard-relay-address")
                      (setf (getf options :wireguard-relay-address)
                            (format-ipv4-integer (parse-ipv4-integer value))))
                     ((string= option "--wireguard-relay-listen")
                      (setf (getf options :wireguard-relay-listen)
                            (format-ipv4-integer (parse-ipv4-integer value))))
                     ((string= option "--wireguard-relay-port-start")
                      (setf (getf options :wireguard-relay-port-start)
                            (parse-port value)))
                     ((string= option "--wireguard-relay-max-channels")
                      (let ((count (parse-integer value :junk-allowed nil)))
                        (unless (plusp count)
                          (error "WireGuard relay max channels must be positive"))
                        (setf (getf options :wireguard-relay-max-channels) count)))
                     ((string= option "--node-port")
                      (setf (getf options :node-port) (parse-port value)))
                     ((string= option "--node-name")
                      (setf (getf options :node-name)
                            (ensure-valid-node-name value)))
                     ((string= option "--browser-listen")
                      (multiple-value-bind (host port) (parse-agent-server value)
                        (setf (getf options :browser-listen) (list host port))))
                     ((string= option "--browser-distro")
                      (unless (probe-file value) (error "--browser-distro ~A does not exist" value))
                      (setf (getf options :browser-distro) value))
                     ((string= option "--virtual-node")
                      (setf (getf options :virtual-nodes)
                            (append (getf options :virtual-nodes) (list (ensure-valid-node-name value)))))
                     ((string= option "--runtime")
                      (unless (member value '("containerd" "fake")
                                      :test #'string=)
                        (error "runtime must be containerd or fake"))
                      (setf (getf options :runtime) value))
                     ((string= option "--containerd-socket")
                      (setf (getf options :containerd-socket) value))
                     ((string= option "--cpu-manager-policy")
                (unless (member value '("none" "static") :test #'equal) (error "CPU policy must be none or static"))
                (setf (getf options :cpu-manager-policy) value))
               ((string= option "--reserved-cpus")
                (gr8s.kubelet::parse-cpu-set value)
                (setf (getf options :reserved-cpus) value))
               ((string= option "--topology-manager-policy")
                (unless (member value '("none" "single-numa-node") :test #'equal) (error "Topology policy must be none or single-numa-node"))
                (setf (getf options :topology-manager-policy) value))
               ((string= option "--topology-manager-scope")
                (unless (equal value "pod") (error "Topology manager scope must be pod")))
               ((string= option "--containerd-mode")
                      (unless (member value '("managed" "external") :test #'string=)
                        (error "containerd mode must be managed or external"))
                      (setf (getf options :containerd-mode) value))
                     ((string= option "--containerd-executable")
                      (setf (getf options :containerd-executable) value))
                     ((string= option "--containerd-oci-runtime")
                      (setf (getf options :containerd-oci-runtime) value))
                     ((string= option "--containerd-log-root")
                      (setf (getf options :containerd-log-root) value))
                     ((string= option "--registry-credentials-file")
                      (setf (getf options :registry-credentials-file) value))
                     ((string= option "--registry-ca")
                      (setf (getf options :registry-cas)
                            (add-registry-ca (getf options :registry-cas) value)))
                     ((string= option "--image-credential-provider-config")
                      (setf (getf options :image-credential-provider-config) value))
                     ((string= option "--image-credential-provider-bin-dir")
                      (setf (getf options :image-credential-provider-bin-dir) value))
                     ((string= option "--cni-mode")
                      (setf (getf options :cni-mode) value))
                     ((string= option "--cni-conf-dir")
                      (setf (getf options :cni-conf-dir) value))
                     ((string= option "--cni-bin-dir")
                      (setf (getf options :cni-bin-dirs)
                            (append (getf options :cni-bin-dirs) (list value))))
                     ((string= option "--dns-forward")
                      (setf (getf options :dns-forward-rules)
                            (add-dns-forward-rule (getf options :dns-forward-rules) value)))
                     ((string= option "--dns-serve-zone")
                      (setf (getf options :dns-serve-zones)
                            (add-dns-serve-zone (getf options :dns-serve-zones) value)))
                     ((string= option "--kubeconfig")
                      (setf (getf options :kubeconfig) value))
                     ((string= option "--kubelet-port")
                      (setf (getf options :kubelet-port) (if (equal value "0") 0 (parse-port value))))
                     ;; podster-cm3: the Pod interface MTU handed to every node.
                     ;; Set it below the underlay's when that is itself a tunnel
                     ;; (WireGuard at 1420 leaves 1370 after vxlan overhead).
                     ((string= option "--mtu")
                      (let ((mtu (parse-integer value)))
                        (unless (<= 1280 mtu 9000)
                          (error "serve --mtu must be between 1280 and 9000"))
                        (setf (getf options :mtu) mtu)))
                     ;; HA (podster-c2d.7.1): opt in to a Raft-replicated control
                     ;; plane. Absent these, serve runs single-node as before.
                     ((string= option "--raft-id")
                      (setf (getf options :raft-id) value))
                     ((string= option "--raft-listen")
                      (setf (getf options :raft-listen) value))
                     ((string= option "--raft-port")
                      (setf (getf options :raft-port) (parse-port value)))
                     ;; Joining takes the agent's and witness's flag names; the
                     ;; one-time token is bound to --node-name.
                     ((string= option "--join")
                      (setf (getf options :raft-join) value))
                     ((string= option "--token")
                      (setf (getf options :raft-token) value))
                     ((string= option "--ca-pin")
                      (setf (getf options :raft-ca-pin) value))
                     ((string= option "--local-storage-path")
                      (unless (storage-absolute-path-p value)
                        (error "local storage path must be absolute without traversal"))
                      (setf (getf options :local-storage-path) value))
                     ((string= option "--audit-log-path")
                      (setf (getf options :audit-log-path) value))
                     (t (error "unknown serve option: ~A" option)))
                   (setf arguments (cddr arguments)))))
    (when (getf options :cluster-reset)
      (when (getf options :raft-join)
        (error "--cluster-reset recovers this member alone; it cannot be combined with --join"))
      ;; The reset member continues as the (re-)founding sole voter.
      (setf (getf options :raft-init) t))
    (when (and (eq t (getf options :raft-compaction))
               (not (or (getf options :raft-init) (getf options :raft-join))))
      (error "--raft-compaction requires --raft-init or --join"))
    (when (eq :auto (getf options :raft-compaction))
      (setf (getf options :raft-compaction)
            (not (null (or (getf options :raft-init) (getf options :raft-join))))))
    (unless (eq (null (getf options :image-credential-provider-config))
                (null (getf options :image-credential-provider-bin-dir)))
      (error "image credential provider config and bin directory must be specified together"))
    (when (getf options :wireguard-relay-address)
      (unless (string= "wireguard" (getf options :overlay-backend))
        (error "WireGuard relay requires --overlay-backend wireguard"))
      (when (or (getf options :raft-init) (getf options :raft-join))
        (error "WireGuard relay currently requires a single control-plane owner"))
      (when (> (+ (getf options :wireguard-relay-port-start)
                  (* 2 (getf options :wireguard-relay-max-channels)) -1)
               65535)
        (error "WireGuard relay UDP port range exceeds 65535")))
    (validate-node-resource-options (validate-cni-options options))))

(defun parse-agent-options (arguments)
  "Parse `gr8s agent' ARGUMENTS into an options plist. Signals on an unknown
   option, when any of --server, --node-name or --state-directory is missing, or
   -- when the state directory holds no enrollment (node.key, node.crt, ca.crt)
   -- when --token or --ca-pin is missing."
  (let ((options (list :command :agent
                       :server nil
                       :token nil
                       :ca-pin nil
                       :node-name nil
                       :state-directory nil
                       :runtime "containerd"
                       :cpu-manager-policy "none"
                       :topology-manager-policy "none"
                       :reserved-cpus nil
                       :containerd-mode "managed"
                       :containerd-executable (default-containerd-executable)
                       :containerd-oci-runtime (default-containerd-oci-runtime)
                       :containerd-socket "/run/containerd/containerd.sock"
                       :containerd-log-root "/var/log/gr8s/pods/"
                       :registry-credentials-file nil
                       :registry-cas nil
                       :image-credential-provider-config nil
                       :image-credential-provider-bin-dir nil
                       :cni-mode "native"
                       :cni-conf-dir nil
                       :cni-bin-dirs nil
                       :wireguard-endpoints nil
                       :dns-forward-rules nil
                       :dns-serve-zones nil
                       :kubelet-port +kubelet-default-port+)))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--kubelet-port")
                (setf (getf options :kubelet-port) (if (equal value "0") 0 (parse-port value))))
               ((string= option "--node-address")
                (setf (getf options :node-address) (canonical-node-underlay-address value)))
               ((string= option "--wireguard-endpoint")
                (setf (getf options :wireguard-endpoints)
                      (add-wireguard-endpoint
                       (getf options :wireguard-endpoints) value)))
               ((string= option "--server")
                (setf (getf options :server) value))
               ((string= option "--flow-events")
                (unless (member value '("connections" "drops") :test #'string=)
                  (error "--flow-events must be connections or drops"))
                (setf (getf options :flow-events) value))
               ((string= option "--pod-masquerade")
                (unless (member value '("outside" "off") :test #'string=)
                  (error "--pod-masquerade must be outside or off"))
                (setf (getf options :pod-masquerade) value))
               ((string= option "--token")
                (setf (getf options :token) value))
               ((string= option "--ca-pin")
                (setf (getf options :ca-pin) value))
               ((string= option "--node-name")
                (setf (getf options :node-name)
                      (ensure-valid-node-name value)))
               ((string= option "--state-directory")
                (setf (getf options :state-directory) value))
               ((string= option "--runtime")
                (unless (member value '("containerd" "fake")
                                :test #'string=)
                  (error "runtime must be containerd or fake"))
                (setf (getf options :runtime) value))
               ((string= option "--cpu-manager-policy")
                (unless (member value '("none" "static") :test #'equal) (error "CPU policy must be none or static"))
                (setf (getf options :cpu-manager-policy) value))
               ((string= option "--reserved-cpus")
                (gr8s.kubelet::parse-cpu-set value)
                (setf (getf options :reserved-cpus) value))
               ((string= option "--topology-manager-policy")
                (unless (member value '("none" "single-numa-node") :test #'equal) (error "Topology policy must be none or single-numa-node"))
                (setf (getf options :topology-manager-policy) value))
               ((string= option "--topology-manager-scope")
                (unless (equal value "pod") (error "Topology manager scope must be pod")))
               ((string= option "--containerd-mode")
                (unless (member value '("managed" "external") :test #'string=)
                  (error "containerd mode must be managed or external"))
                (setf (getf options :containerd-mode) value))
               ((string= option "--containerd-executable")
                (setf (getf options :containerd-executable) value))
               ((string= option "--containerd-oci-runtime")
                (setf (getf options :containerd-oci-runtime) value))
               ((string= option "--containerd-socket")
                (setf (getf options :containerd-socket) value))
               ((string= option "--containerd-log-root")
                (setf (getf options :containerd-log-root) value))
               ((string= option "--registry-credentials-file")
                (setf (getf options :registry-credentials-file) value))
               ((string= option "--registry-ca")
                (setf (getf options :registry-cas)
                      (add-registry-ca (getf options :registry-cas) value)))
               ((string= option "--image-credential-provider-config")
                (setf (getf options :image-credential-provider-config) value))
               ((string= option "--image-credential-provider-bin-dir")
                (setf (getf options :image-credential-provider-bin-dir) value))
               ((string= option "--cni-mode")
                (setf (getf options :cni-mode) value))
               ((string= option "--cni-conf-dir")
                (setf (getf options :cni-conf-dir) value))
               ((string= option "--cni-bin-dir")
                (setf (getf options :cni-bin-dirs)
                      (append (getf options :cni-bin-dirs) (list value))))
               ((string= option "--dns-forward")
                (setf (getf options :dns-forward-rules)
                      (add-dns-forward-rule (getf options :dns-forward-rules) value)))
               ((string= option "--dns-serve-zone")
                (setf (getf options :dns-serve-zones)
                      (add-dns-serve-zone (getf options :dns-serve-zones) value)))
               (t (error "unknown agent option: ~A" option)))
             (setf arguments (cddr arguments)))
    (dolist (required '(:server :node-name :state-directory))
      (unless (getf options required)
        (error "agent requires --~(~A~)" required)))
    (let ((directory (uiop:ensure-directory-pathname (getf options :state-directory))))
      (unless (every (lambda (name) (probe-file (merge-pathnames name directory)))
                     '("node.key" "node.crt" "ca.crt"))
        (dolist (required '(:token :ca-pin))
          (unless (getf options required)
            (error "unenrolled agent requires --~(~A~)" required)))))
    (unless (eq (null (getf options :image-credential-provider-config))
                (null (getf options :image-credential-provider-bin-dir)))
      (error "image credential provider config and bin directory must be specified together"))
    (validate-node-resource-options (validate-cni-options options))))

(defun parse-join-token-options (arguments)
  "Parse `gr8s join-token' ARGUMENTS into an options plist (role defaults to
   \"node\"). Signals on an unknown option, an invalid --role, or a missing
   --node-name."
  (let ((options (list :command :join-token :role "node"
                       :state-directory (namestring (default-state-directory)))))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--node-name")
                (setf (getf options :node-name) (ensure-valid-node-name value)))
               ((string= option "--state-directory")
                (setf (getf options :state-directory) value))
               ((string= option "--role")
                (unless (member value '("node" "control-plane" "witness") :test #'string=)
                  (error "join-token --role must be node, control-plane, or witness"))
                (setf (getf options :role) value))
               (t (error "unknown join-token option: ~A" option)))
             (setf arguments (cddr arguments)))
    (unless (getf options :node-name) (error "join-token requires --node-name"))
    options))

(defun parse-witness-options (arguments)
  "Options for 'gr8s witness': a headless Raft voting member (a quorum
   tie-breaker) that joins an existing cluster and holds no application state."
  (let ((options (list :command :witness
                       :listen "127.0.0.1" :port 0
                       :state-directory (namestring (default-state-directory)))))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--join") (setf (getf options :join) value))
               ((string= option "--node-name")
                (setf (getf options :node-name) (ensure-valid-node-name value)))
               ((string= option "--member-id") (setf (getf options :member-id) value))
               ((string= option "--token") (setf (getf options :token) value))
               ((string= option "--ca-pin") (setf (getf options :ca-pin) value))
               ((string= option "--listen") (setf (getf options :listen) value))
               ((string= option "--port") (setf (getf options :port) (parse-port value)))
               ((string= option "--state-directory") (setf (getf options :state-directory) value))
               (t (error "unknown witness option: ~A" option)))
             (setf arguments (cddr arguments)))
    (unless (getf options :join) (error "witness requires --join HOST:PORT"))
    (unless (getf options :member-id)
      (setf (getf options :member-id)
            (or (getf options :node-name)
                (error "witness requires --node-name or --member-id"))))
    options))

(defun run-witness (options &key (stop-predicate (lambda () *shutdown-requested*)))
  "Start a headless witness member, join the cluster at --join, and run until
   shutdown. The witness persists its Raft WAL under the state directory, votes
   and counts toward quorum, but never leads and serves no state machine."
  (multiple-value-bind (host port) (parse-agent-server (getf options :join))
    (let* ((state (uiop:ensure-directory-pathname (getf options :state-directory)))
           (root (merge-pathnames "raft/" state))
           (credentials (progn
                          (gr8s.raft.transport::raft-reap-snapshot-directory root)
                          (ensure-raft-joiner-credentials
                           root (getf options :member-id) host port
                           :role :witness :node-name (getf options :node-name)
                           :token (getf options :token) :ca-pin (getf options :ca-pin))))
           (member (start-raft-member (getf options :member-id)
                                      :host (getf options :listen)
                                      :port (getf options :port)
                                      :storage-path (merge-pathnames "witness.log" root)
                                      :initial-role :witness
                                      :credentials credentials)))
      (unwind-protect
           (progn
             (unless (raft-cluster-join member host port
                                        :role :witness
                                        :node-name (getf options :node-name))
               (error "witness ~A could not join the cluster at ~A:~D"
                      (getf options :member-id) host port))
             (raft-member-start member)
             (format t "gr8s witness ~A joined the cluster via ~A:~D; holding quorum.~%"
                     (getf options :member-id) host port)
             (finish-output)
             (loop until (funcall stop-predicate) do (sleep 0.2)))
        (ignore-errors (stop-raft-member member)))
      0)))

(defun print-node-join-token (options &optional (output *standard-output*))
  "Mint a join token from the control plane's existing cluster PKI and write it,
   with the node name and CA pin, as JSON to OUTPUT. A control-plane role reads
   the PKI under raft/. Signals when the selected state directory holds no cluster
   CA, rather than minting a fresh trust identity. Returns 0."
  (let* ((state (uiop:ensure-directory-pathname (getf options :state-directory)))
         (root (merge-pathnames "pki/" state))
         ;; Control-plane tokens have their own store and CA, so a token for a
         ;; worker node can't admit a Raft member.
         (root (if (member (getf options :role) '("control-plane" "witness") :test #'equal)
                   (merge-pathnames "raft/" root)
                   root)))
    ;; The token command must use an existing control plane's CA, never create
    ;; a new trust identity merely because the caller selected the wrong path.
    (unless (and (probe-file (merge-pathnames "pki/cluster-ca.crt" root))
                 (probe-file (merge-pathnames "pki/cluster-ca.key" root)))
      (error "cluster PKI does not exist in the selected control-plane state directory"))
    (let* ((pki (ensure-cluster-pki root))
           (name (getf options :node-name))
           (role (getf options :role))
           (token (create-join-token
                   pki name :role (cond ((equal role "control-plane") :voter)
                                        ((equal role "witness") :witness)
                                        (t :node)))))
      (com.inuoe.jzon:stringify
       (json-object "nodeName" name "role" role "token" token
                    "caPin" (cluster-pki-ca-fingerprint pki)) :stream output)
      (terpri output)
      (finish-output output)))
  0)

(defun parse-kubeconfig-options (arguments)
  "Parse `gr8s kubeconfig' ARGUMENTS into an options plist (--output file,
   --server URL). Signals on an unknown option."
  (let ((options (list :command :kubeconfig
                       :output nil
                       :server "https://127.0.0.1:6443"
                       :state-directory (namestring (default-state-directory)))))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--output")
                (setf (getf options :output) value))
               ((string= option "--server")
                (setf (getf options :server) value))
               ((string= option "--state-directory")
                (setf (getf options :state-directory) value))
               (t (error "unknown kubeconfig option: ~A" option)))
             (setf arguments (cddr arguments)))
    options))

(defun default-client-kubeconfig ()
  (or (uiop:getenv "KUBECONFIG")
      (namestring (merge-pathnames ".kube/config" (user-homedir-pathname)))))

(defun parse-debug-options (arguments)
  "Parse a debug subcommand and its options. The icl subcommand opens the same
authenticated tunnel as slynk and launches ICL's browser mode (icl -b
--connect) against it; slynk opens the tunnel for a manual SLY connect."
  (when (equal "trace" (first arguments))
    (return-from parse-debug-options (parse-trace-options (rest arguments))))
  (let ((sub (first arguments)))
    (unless (member sub '("slynk" "icl") :test #'equal)
      (error "unknown debug subcommand: ~A" (or sub ""))))
  (let* ((icl (equal "icl" (first arguments)))
         (options (list :command :debug-slynk
                        :icl icl
                        :icl-binary "icl"
                        ;; ICL is handed the port we pick, so a random port is fine;
                        ;; slynk prints the port for a human to point SLY at 4005.
                        :local-port (if icl 0 4005)
                        :kubeconfig (default-client-kubeconfig)))
         (rest (rest arguments)))
    ;; A bare positional name is shorthand for --node, so `gr8s debug icl <node>`.
    (when (and rest (not (uiop:string-prefix-p "-" (first rest))))
      (setf (getf options :node) (pop rest)))
    (loop while rest
          for option = (pop rest)
          do (cond
               ((equal option "--no-launch") (setf (getf options :no-launch) t))
               ((equal option "--unsafe-visualizations") (setf (getf options :unsafe-visualizations) t))
               (t
                (unless rest (error "~A requires a value" option))
                (let ((value (pop rest)))
                  (cond ((equal option "--node") (setf (getf options :node) value))
                        ((equal option "--selector") (setf (getf options :selector) value))
                        ((equal option "--member") (setf (getf options :member) value))
                        ((equal option "--kubeconfig") (setf (getf options :kubeconfig) value))
                        ((equal option "--icl-binary") (setf (getf options :icl-binary) value))
                        ((equal option "--local-port")
                         (setf (getf options :local-port) (parse-integer value :junk-allowed nil)))
                        (t (error "unknown debug ~A option: ~A" (if icl "icl" "slynk") option)))))))
    (unless (= 1 (count-if (lambda (key) (getf options key)) '(:node :selector :member)))
      (error "debug ~A requires exactly one target: a node name, or --node/--selector/--member"
             (if icl "icl" "slynk")))
    (unless (<= (if icl 0 1) (getf options :local-port) 65535)
      (error "debug ~A --local-port must be ~D..65535"
             (if icl "icl" "slynk") (if icl 0 1)))
    (dolist (key '(:node :member))
      (when (and (getf options key) (not (path-segment-name-p (getf options key))))
        (error "debug target must be a valid Kubernetes name")))
    options))

(defun selected-ready-node-name (items selector)
  "Return the sole Ready node in ITEMS, with errors that name SELECTOR."
  (let ((ready
          (loop for node across items
                for conditions = (gethash "conditions" (gethash "status" node) #())
                when (find-if (lambda (condition)
                                (and (equal "Ready" (gethash "type" condition))
                                     (equal "True" (gethash "status" condition))))
                              conditions)
                  collect (gethash "name" (gethash "metadata" node)))))
    (unless (= 1 (length ready))
      (error "node selector ~S resolved to ~D Ready nodes; exactly one is required"
             selector (length ready)))
    (first ready)))

(defun kubeconfig-named-entry (entries name)
  (or (find name entries :test #'equal
            :key (lambda (entry) (gethash "name" entry)))
      (error "kubeconfig refers to missing entry ~S" name)))

(defun read-debug-kubeconfig (path &optional context-name)
  "Return server, token, CA, client certificate and key from PATH's CONTEXT-NAME, by
default its current context."
  (let* ((file (truename path))
         (root (let ((root (gr8s.resources:parse-yaml (uiop:read-file-string file))))
                 (unless (hash-table-p root) (error "~A is not a kubeconfig" (namestring file)))
                 root))
         (context-entry (kubeconfig-named-entry
                         (gethash "contexts" root #()) (or context-name (gethash "current-context" root))))
         (context (gethash "context" context-entry))
         (cluster (gethash "cluster" (kubeconfig-named-entry
                                      (gethash "clusters" root #()) (gethash "cluster" context))))
         (user (gethash "user" (kubeconfig-named-entry
                                 (gethash "users" root #()) (gethash "user" context))))
         (directory (uiop:pathname-directory-pathname file)))
    (labels ((relative (value) (and value (namestring (merge-pathnames value directory)))))
      (list :server (gethash "server" cluster)
            :token (gethash "token" user)
            :ca-file (relative (gethash "certificate-authority" cluster))
            :ca-data (gethash "certificate-authority-data" cluster)
            :client-certificate (relative (gethash "client-certificate" user))
            :client-certificate-data (gethash "client-certificate-data" user)
            :client-key (relative (gethash "client-key" user))
            :client-key-data (gethash "client-key-data" user)))))

(defun materialize-kubeconfig-data (text suffix)
  (when text
    (let ((path (merge-pathnames (format nil "gr8s-debug-~A.~A" (generate-uid) suffix)
                                 (uiop:temporary-directory))))
      (with-open-file (out path :direction :output :if-exists :error
                                :element-type '(unsigned-byte 8))
        (write-sequence (ag-grpc:base64-decode text) out))
      (sb-posix:chmod path #o600)
      (namestring path))))

(defun debug-api-url-parts (url)
  (let* ((secure-p (uiop:string-prefix-p "https://" url))
         (prefix (if secure-p "https://" "http://")))
    (unless (or secure-p (uiop:string-prefix-p "http://" url))
      (error "kubeconfig server must use http:// or https://"))
    (let* ((tail (subseq url (length prefix)))
           (slash (or (position #\/ tail) (length tail)))
           (authority (subseq tail 0 slash))
           (base-path (if (< slash (length tail)) (subseq tail slash) ""))
           (colon (position #\: authority :from-end t))
           (host (if colon (subseq authority 0 colon) authority))
           (port (if colon (parse-integer (subseq authority (1+ colon)))
                     (if secure-p 443 80))))
      (values secure-p host port base-path))))

(defun open-debug-api-stream (config)
  (multiple-value-bind (secure-p host port base-path)
      (debug-api-url-parts (getf config :server))
    (let* ((socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)))
           (plain (usocket:socket-stream socket)))
      (values
       (if secure-p
           (pure-tls:make-tls-client-stream
            plain :hostname host
            :context (pure-tls:make-tls-context
                      :verify-mode pure-tls:+verify-required+
                      :ca-file (getf config :ca-file) :auto-load-system-ca nil)
            :client-certificate (getf config :client-certificate)
            :client-key (getf config :client-key))
           plain)
       socket host port base-path))))

(defun write-debug-http-request (stream method host port target token
                                 &key websocket-key (websocket-protocol "gr8s.slynk.v1") body)
  "Write one request; BODY, when given, is an object sent as JSON."
  (write-sequence
   (gr8s.protocol::ascii-octets
    (with-output-to-string (request)
      (flet ((line (control &rest args)
               (apply #'format request control args)
               (write-string (format nil "~C~C" #\Return #\Linefeed) request)))
        (line "~A ~A HTTP/1.1" method target)
        (line "Host: ~A:~D" host port)
        (line "Connection: ~A" (if websocket-key "Upgrade" "close"))
        (when websocket-key
          (line "Upgrade: websocket")
          (line "Sec-WebSocket-Version: 13")
          (line "Sec-WebSocket-Key: ~A" websocket-key)
          (line "Sec-WebSocket-Protocol: ~A" websocket-protocol))
        (when token (line "Authorization: Bearer ~A" token))
        (cond (body
               (line "Content-Type: application/json")
               (line "Content-Length: ~D" (length (gr8s.resources:stringify-to-utf-8-bytes body))))
              ;; A POST without a body must say so.
              ((member method '("POST" "PUT") :test #'equal) (line "Content-Length: 0")))
        (line ""))))
   stream)
  (when body (write-sequence (gr8s.resources:stringify-to-utf-8-bytes body) stream))
  (finish-output stream))

(defun call-with-debug-kubeconfig (path function &key context)
  "Call FUNCTION with PATH's current-context connection config. The TLS client
   takes only file paths, while `gr8s kubeconfig` emits inline certificate data,
   so certificate-authority-data and friends are materialized into private
   temporary files for the duration of the call and removed on the way out
   (podster-7jb). Explicit file paths pass through untouched. CONTEXT names
   another context than the current one."
  (let ((config (read-debug-kubeconfig path context))
        (temporary nil))
    (labels ((materialize (data-key file-key suffix)
               (when (and (null (getf config file-key)) (getf config data-key))
                 (let ((file (materialize-kubeconfig-data (getf config data-key) suffix)))
                   (push file temporary)
                   (setf (getf config file-key) file)))))
      (unwind-protect
           (progn
             (materialize :ca-data :ca-file "ca.crt")
             (materialize :client-certificate-data :client-certificate "client.crt")
             (materialize :client-key-data :client-key "client.key")
             (funcall function config))
        (dolist (file temporary) (ignore-errors (delete-file file)))))))

(defun debug-api-request-json (config method target &key body)
  "Send METHOD to TARGET on CONFIG's server, with BODY as JSON when given. Returns
   (values parsed-body status headers): the JSON body parsed when there is one (NIL
   otherwise), the HTTP status, and the response headers, leaving non-200 handling
   to the caller."
  (multiple-value-bind (stream socket host port base-path) (open-debug-api-stream config)
    (unwind-protect
         (progn
           (write-debug-http-request stream method host port (concatenate 'string base-path target)
                                     (getf config :token) :body body)
           (multiple-value-bind (status headers)
               (gr8s.protocol::parse-http-response-head
                (gr8s.protocol::read-http-response-head stream))
             (let* ((length (parse-integer (or (cdr (assoc :content-length headers)) "0")))
                    (body (make-array length :element-type '(unsigned-byte 8))))
               (read-sequence body stream)
               (values (when (plusp length)
                         (ignore-errors
                          (com.inuoe.jzon:parse body)))
                       status headers))))
      (ignore-errors (close stream))
      (ignore-errors (usocket:socket-close socket)))))

(defun debug-api-get-json (config target)
  (multiple-value-bind (body status) (debug-api-request-json config "GET" target)
    (unless (= status 200) (error "Kubernetes API returned HTTP ~D" status))
    body))

(defun random-websocket-key ()
  (ag-grpc:base64-encode (secure-random-octets 16)))

(defun open-debug-websocket (config target &key (protocol "gr8s.slynk.v1"))
  (multiple-value-bind (stream socket host port base-path) (open-debug-api-stream config)
    (let ((key (random-websocket-key)))
      (handler-case
          (progn
            (write-debug-http-request stream "GET" host port
                                      (concatenate 'string base-path target)
                                      (getf config :token) :websocket-key key
                                      :websocket-protocol protocol)
            (multiple-value-bind (status headers)
                (gr8s.protocol::parse-http-response-head
                 (gr8s.protocol::read-http-response-head stream))
              (unless (= status 101)
                ;; A Kubernetes Status body says why.
                (let* ((length (min (* 64 1024) (or (ignore-errors (parse-integer (cdr (assoc :content-length headers)))) 0)))
                       (body (make-array length :element-type '(unsigned-byte 8)))
                       (message (ignore-errors
                                 (read-sequence body stream)
                                 (gethash "message" (com.inuoe.jzon:parse body)))))
                  (error "the Kubernetes API rejected the WebSocket upgrade with HTTP ~D~@[: ~A~]"
                         status (and (stringp message) message)))))
            (values stream socket))
        (error (condition)
          (ignore-errors (close stream))
          (ignore-errors (usocket:socket-close socket))
          (error condition))))))

(defun debug-slynk-target (options config)
  (cond
    ((getf options :member)
     (format nil "/apis/gr8s.io/v1/controlplanemembers/~A/slynk" (getf options :member)))
    (t
     (let ((node (or (getf options :node)
                     (let* ((selector (getf options :selector))
                            (response (debug-api-get-json
                                       config
                                       (format nil "/api/v1/nodes?labelSelector=~A"
                                               (drakma:url-encode selector :utf-8)))))
                       (selected-ready-node-name (gethash "items" response #()) selector)))))
       (format nil "/apis/gr8s.io/v1/nodes/~A/slynk" node)))))

(defun relay-local-slynk-to-websocket (local remote write-lock)
  (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8)))
        (fd (sb-sys:fd-stream-fd local)))
    (loop for count = (sb-sys:with-pinned-objects (buffer)
                        (or (sb-unix:unix-read fd (sb-sys:vector-sap buffer) (length buffer)) 0))
          while (plusp count)
          do (bt:with-lock-held (write-lock)
               (gr8s.protocol::write-websocket-frame remote 2 (subseq buffer 0 count) :masked-p t)))))

(defun relay-websocket-to-local-slynk (remote local write-lock)
  (loop
    (multiple-value-bind (opcode payload) (gr8s.protocol:read-websocket-frame remote)
      (case opcode
        (2 (write-sequence payload local) (finish-output local))
        (8 (return))
        (9 (bt:with-lock-held (write-lock)
             (gr8s.protocol::write-websocket-frame remote 10 payload :masked-p t)))
        (10)
        (otherwise (error "Slynk API sent an unsupported WebSocket frame"))))))

(defun run-debug-slynk-command-with-config (options config)
  (let ((target (debug-slynk-target options config)))
    (multiple-value-bind (remote remote-socket) (open-debug-websocket config target)
      (let ((listener nil) (local-socket nil) (local nil) (writer nil)
            (icl-process nil)
            (local-disconnected nil)
            (write-lock (bt:make-lock "gr8s debug Slynk websocket writer")))
        (unwind-protect
             (progn
               (setf listener (usocket:socket-listen "127.0.0.1" (getf options :local-port)
                                                     :reuse-address t
                                                     :element-type '(unsigned-byte 8)))
               (let ((port (usocket:get-local-port listener)))
                 (cond
                   ((not (getf options :icl))
                    (format t "gr8s Slynk tunnel: 127.0.0.1:~D -> ~A~%~
                               Connect SLY now; Ctrl-C closes the local and remote debugger.~%"
                            port target))
                   ((getf options :no-launch)
                    (format t "gr8s icl tunnel: 127.0.0.1:~D -> ~A~%~
                               Run:  ~A -b --connect 127.0.0.1:~D~%~
                               Ctrl-C closes the tunnel and the remote debugger.~%"
                            port target (getf options :icl-binary) port))
                   (t
                    (format t "gr8s icl: 127.0.0.1:~D -> ~A; launching ~A ...~%"
                            port target (getf options :icl-binary))
                    (finish-output)
                    (handler-case
                        (setf icl-process
                              (uiop:launch-program
                               (append (list (getf options :icl-binary) "-b"
                                             "--connect" (format nil "127.0.0.1:~D" port))
                                       (when (getf options :unsafe-visualizations)
                                         (list "--unsafe-visualizations")))
                               :output :interactive :error-output :interactive :input :interactive))
                      (error (condition)
                        (format t "could not launch ~A (~A). Connect it manually:~%  ~
                                   ~A -b --connect 127.0.0.1:~D~%"
                                (getf options :icl-binary) condition
                                (getf options :icl-binary) port)))))
                 (finish-output))
               (setf local-socket (usocket:socket-accept listener)
                     local (usocket:socket-stream local-socket)
                     writer (bt:make-thread
                             (lambda ()
                               (unwind-protect
                                    (handler-case
                                        (relay-local-slynk-to-websocket local remote write-lock)
                                      (error () nil))
                                 ;; Local SLY EOF must interrupt the blocking
                                 ;; API read so this command closes the remote
                                 ;; debugger instead of leaving an orphaned
                                 ;; tunnel until Ctrl-C.
                                 (bt:with-lock-held (write-lock)
                                   (setf local-disconnected t))
                                 (ignore-errors
                                  (usocket:socket-shutdown remote-socket :io))))
                             :name "gr8s debug Slynk local input"))
               (handler-case
                   (relay-websocket-to-local-slynk remote local write-lock)
                 (error (condition)
                   (unless (bt:with-lock-held (write-lock) local-disconnected)
                     (error condition))))
               0)
          (when icl-process (ignore-errors (uiop:terminate-process icl-process)))
          (when writer (stop-exec-input-reader writer))
          (when writer (ignore-errors (bt:join-thread writer)))
          (when local-socket (ignore-errors (usocket:socket-close local-socket)))
          (when listener (ignore-errors (usocket:socket-close listener)))
          (ignore-errors
           (bt:with-lock-held (write-lock)
             (gr8s.protocol::write-websocket-frame
              remote 8 (make-array 2 :element-type '(unsigned-byte 8)
                                     :initial-contents '(3 232)) :masked-p t)))
          (ignore-errors (close remote))
          (ignore-errors (usocket:socket-close remote-socket)))))))

(defun run-debug-slynk-command (options)
  (handler-case
      (call-with-debug-kubeconfig
       (getf options :kubeconfig)
       (lambda (config)
         (unless (or (getf config :token)
                     (and (getf config :client-certificate) (getf config :client-key)))
           (error "kubeconfig has no bearer token or client certificate credentials"))
         (run-debug-slynk-command-with-config options config)))
    (sb-sys:interactive-interrupt ()
      (format t "~&gr8s Slynk tunnel closed.~%")
      0)))

(defun parse-doctor-options (arguments)
  "Parse `gr8s doctor' options: --state-directory/--cluster-pod-cidr VALUE, or a
bare positional state directory for backward compatibility.  A missing
:state-directory leaves run-doctor to use the shared default-state-directory."
  (when (equal (first arguments) "observe")
    (return-from parse-doctor-options (parse-doctor-observe-options (rest arguments))))
  (let ((route (gr8s-diagnose:doctor-command-route arguments)))
    (when route (return-from parse-doctor-options route)))
  (when (equal (first arguments) "host") (setf arguments (rest arguments)))
  (let ((options (list :command :doctor))
        (positional-seen nil))
    (loop while arguments
          for option = (first arguments)
          do (cond
               ((string= option "--state-directory")
                (setf (getf options :state-directory) (option-value arguments option)
                      arguments (cddr arguments)))
               ((string= option "--cluster-pod-cidr")
                (setf (getf options :cluster-pod-cidr) (option-value arguments option)
                      arguments (cddr arguments)))
               ((string= option "--fix")
                (setf (getf options :fix) t arguments (rest arguments)))
               ((and (not positional-seen)
                     (plusp (length option))
                     (char/= (char option 0) #\-))
                ;; A bare word is a state directory only if it names one: a mistyped
                ;; subcommand checked as an empty state directory makes a running
                ;; node's routes look stale, and the advice is a --fix that tears them down.
                (unless (or (find #\/ option) (uiop:directory-exists-p option))
                  (error "unknown doctor command: ~A~@[ (did you mean '~A'?)~]; see 'gr8s doctor --help'"
                         option (nearest-doctor-command option)))
                (setf (getf options :state-directory) option
                      positional-seen t
                      arguments (rest arguments)))
               (t (error "unknown doctor option: ~A" option))))
    options))

(defparameter +doctor-commands+ '("diagnose" "observe" "impact" "host" "checkup")
  "The words `gr8s doctor' takes as a command.")

(defun nearest-doctor-command (word)
  "The doctor command WORD most likely misspells, or NIL when none is close."
  (flet ((distance (a b)
           ;; Levenshtein distance, one row at a time.
           (let ((row (coerce (loop for i to (length b) collect i) 'vector)))
             (loop for i from 1 to (length a)
                   do (let ((previous (aref row 0)))
                        (setf (aref row 0) i)
                        (loop for j from 1 to (length b)
                              do (let ((above (aref row j)))
                                   (setf (aref row j)
                                         (min (1+ above) (1+ (aref row (1- j)))
                                              (+ previous (if (char-equal (char a (1- i)) (char b (1- j))) 0 1))))
                                   (setf previous above)))))
             (aref row (length b)))))
    (let ((best (first (sort (copy-list +doctor-commands+) #'< :key (lambda (command) (distance word command))))))
      (when (<= (distance word best) (max 2 (floor (length best) 3)))
        best))))

(defun parse-wireguard-options (arguments)
  "Parse `gr8s wireguard rotate-key --state-directory DIR'. The key is replaced
offline and takes effect the next time the node agent starts."
  (unless (string= (first arguments) "rotate-key")
    (error "unknown wireguard subcommand: ~A" (or (first arguments) "")))
  (let ((options (list :command :wireguard-rotate-key
                       :state-directory (namestring (default-state-directory))))
        (arguments (rest arguments)))
    (loop while arguments
          for option = (first arguments)
          do (cond
               ((string= option "--state-directory")
                (setf (getf options :state-directory) (option-value arguments option)
                      arguments (cddr arguments)))
               (t (error "unknown wireguard rotate-key option: ~A" option))))
    options))

(defun parse-network-options (arguments)
  "Parse `gr8s network explain NODE PEER [--kubeconfig PATH | --server URL]'."
  (unless (string= (first arguments) "explain")
    (error "unknown network subcommand: ~A" (or (first arguments) "")))
  (unless (and (second arguments) (third arguments))
    (error "network explain requires NODE and PEER"))
  (let ((options (list :command :network-explain
                       :node (second arguments) :peer (third arguments)
                       :kubeconfig (default-client-kubeconfig)))
        (arguments (cdddr arguments)))
    (unless (and (dns-label-p (getf options :node))
                 (dns-label-p (getf options :peer)))
      (error "network explain NODE and PEER must be DNS labels"))
    (loop while arguments
          for option = (first arguments)
          do (cond
               ((string= option "--server")
                (setf (getf options :server) (option-value arguments option)
                      arguments (cddr arguments)))
               ((string= option "--kubeconfig")
                (setf (getf options :kubeconfig) (option-value arguments option)
                      arguments (cddr arguments)))
               (t (error "unknown network explain option: ~A" option))))
    options))

(defun print-network-explanation (options &optional (output *standard-output*))
  "Fetch and print one agent's durable path decision and candidate evidence.
Authenticates through the kubeconfig like the other operator commands;
--server bypasses it for an explicit endpoint, such as a test server."
  (flet ((explain (config)
           (multiple-value-bind (object status)
               (debug-api-request-json
                config "GET"
                (format nil "/gr8s/v1/network/explain?node=~A&peer=~A"
                        (getf options :node) (getf options :peer)))
             (unless (= status 200)
               (error "network explain failed: ~A"
                      (member-api-error-message object status)))
             (let ((selected (gethash "selected" object)))
               (format output "Node ~A → peer ~A~%" (getf options :node) (gethash "peerID" object))
               (when (gethash "destinationPeerID" object)
                 (format output "Topology: destination ~A via ~A (~A)~%"
                         (gethash "destinationPeerID" object)
                         (gethash "nextHopPeerID" object)
                         (gethash "topologyReason" object)))
               (format output "Selected: ~A (~A:~D), reason: ~A~%"
                       (gethash "name" selected) (gethash "address" selected)
                       (gethash "port" selected) (gethash "reason" object))
               (loop for candidate across (gethash "candidates" object #())
                     do (format output "  ~A ~A:~D  ~:[unhealthy~;healthy~]  score=~D  handshake-age=~Ds  successes=~D failures=~D~%"
                                (gethash "name" candidate) (gethash "address" candidate)
                                (gethash "port" candidate) (gethash "healthy" candidate)
                                (gethash "score" candidate)
                                (gethash "handshakeAgeSeconds" candidate)
                                (gethash "consecutiveSuccesses" candidate)
                                (gethash "consecutiveFailures" candidate)))))))
    (if (getf options :server)
        (explain (list :server (getf options :server)))
        (call-with-debug-kubeconfig (getf options :kubeconfig) #'explain))
    (finish-output output)
    0))

(defun rotate-wireguard-node-key (options &optional (output *standard-output*))
  "Replace the durable node-local WireGuard identity and print its public key.
The new identity takes effect when the node agent next starts."
  (multiple-value-bind (private-key public-key)
      (gr8s.security::rotate-wireguard-key-pair (getf options :state-directory))
    (declare (ignore private-key))
    (format output "WireGuard public key: ~A~%" (ag-grpc:base64-encode public-key))
    (finish-output output))
  0)

(defun default-browser-opener ()
  "The platform command that opens a URL in the user's default browser."
  #+darwin "open"
  #-darwin "xdg-open")

(defun dashboard-session-token ()
  "A fresh unguessable URL-path token for one dashboard session (192 bits of hex)."
  (format nil "~(~{~2,'0X~}~)" (coerce (secure-random-octets 24) 'list)))

(defun dashboard-session-file (port)
  "Where the dashboard serving PORT records its URL for this user: a private file in
$XDG_RUNTIME_DIR (else the cache directory), so a second `gr8s dashboard' can point at
the one already running instead of failing on the port."
  (let ((runtime (uiop:getenv "XDG_RUNTIME_DIR")))
    (merge-pathnames (format nil "gr8s/dashboard-~D.json" port)
                     (if (and runtime (plusp (length runtime)))
                         (uiop:ensure-directory-pathname runtime)
                         (uiop:xdg-cache-home)))))

(defun dashboard-kubeconfig-name (kubeconfig)
  "KUBECONFIG's full path, so two spellings of one file compare equal."
  (namestring (or (ignore-errors (truename kubeconfig)) kubeconfig)))

(defun record-dashboard-session (port url kubeconfig)
  "Note this process's dashboard on PORT, readable only by this user."
  (let ((file (dashboard-session-file port)))
    (ensure-directories-exist file)
    (with-open-file (out file :direction :output :if-exists :supersede)
      (sb-posix:chmod (namestring file) #o600)
      (com.inuoe.jzon:stringify (core-object "pid" (sb-posix:getpid) "port" port
                                             "url" url "kubeconfig" (dashboard-kubeconfig-name kubeconfig))
                                :stream out))))

(defun forget-dashboard-session (port)
  "Remove PORT's session record, when it is still this process's."
  (let* ((file (dashboard-session-file port))
         (session (ignore-errors (com.inuoe.jzon:parse file))))
    (when (and (hash-table-p session) (eql (gethash "pid" session) (sb-posix:getpid)))
      (ignore-errors (delete-file file)))))

(defun running-dashboard-session (port)
  "The session record of a live dashboard on PORT, or NIL: its process must still exist."
  (let ((session (ignore-errors (com.inuoe.jzon:parse (dashboard-session-file port)))))
    (when (and (hash-table-p session)
               (eql (gethash "port" session) port)
               (integerp (gethash "pid" session))
               (stringp (gethash "url" session))
               (ignore-errors (sb-posix:kill (gethash "pid" session) 0) t))
      session)))

(defun report-dashboard-port-in-use (port options kubeconfig)
  "Say why the dashboard can't take PORT: point at the dashboard already there, opening
it unless OPTIONS say :no-launch, or name the port as another program's. The exit code."
  (let ((session (running-dashboard-session port)))
    (cond
      (session
       (let ((url (gethash "url" session))
             (theirs (gethash "kubeconfig" session)))
         (format t "gr8s dashboard is already running at ~A~%" url)
         (unless (equal theirs (dashboard-kubeconfig-name kubeconfig))
           (format t "  (for ~A; for ~A, start another with --port)~%" theirs (dashboard-kubeconfig-name kubeconfig)))
         (unless (getf options :no-launch)
           (ignore-errors
            (uiop:launch-program (list (or (getf options :browser) (default-browser-opener)) url)
                                 :output :interactive :error-output :interactive)))
         0))
      (t
       (format *error-output* "gr8s dashboard: port ~D is in use by another program; choose another with --port N~%"
               port)
       1))))

(defun dashboard-kubeconfig-config (path)
  "Read kubeconfig PATH into a config plist for OPEN-DEBUG-API-STREAM, writing any
inline certificate/key/CA data out to 0600 temp files."
  (let ((raw (read-debug-kubeconfig path)))
    (list :server (getf raw :server)
          :token (getf raw :token)
          :ca-file (or (getf raw :ca-file)
                       (materialize-kubeconfig-data (getf raw :ca-data) "crt"))
          :client-certificate (or (getf raw :client-certificate)
                                  (materialize-kubeconfig-data (getf raw :client-certificate-data) "crt"))
          :client-key (or (getf raw :client-key)
                          (materialize-kubeconfig-data (getf raw :client-key-data) "key")))))

(defun write-dashboard-proxy-request (stream method host port target token content-type body)
  "Write one HTTP request to the cluster-API STREAM. The kubeconfig client
certificate authenticates the mTLS stream; a Bearer TOKEN is added when the
kubeconfig uses one instead."
  (write-sequence
   (gr8s.protocol::ascii-octets
    (with-output-to-string (request)
      (flet ((line (control &rest args)
               (apply #'format request control args)
               (write-string (format nil "~C~C" #\Return #\Linefeed) request)))
        (line "~A ~A HTTP/1.1" method target)
        (line "Host: ~A:~D" host port)
        (line "Connection: close")
        (line "Accept: application/json, */*")
        (when token (line "Authorization: Bearer ~A" token))
        (when (and content-type (plusp (length content-type)))
          (line "Content-Type: ~A" content-type))
        (line "Content-Length: ~D" (if body (length body) 0))
        (line ""))))
   stream)
  (when (and body (plusp (length body))) (write-sequence body stream))
  (finish-output stream))

(defun read-dashboard-proxy-body (stream headers)
  "Read a proxied response body from STREAM, honouring Content-Length or chunked
transfer encoding (watch streams arrive chunked)."
  (let ((content-length (cdr (assoc :content-length headers)))
        (transfer-encoding (cdr (assoc :transfer-encoding headers))))
    (cond
      ((and transfer-encoding (search "chunked" (string-downcase transfer-encoding)))
       (let ((body (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
         (loop for size = (ignore-errors
                            (parse-integer (gr8s.http-client::read-crlf-line stream)
                                           :radix 16 :junk-allowed t))
               while (and size (plusp size))
               do (let ((chunk (make-array size :element-type '(unsigned-byte 8))))
                    (read-sequence chunk stream)
                    (loop for octet across chunk do (vector-push-extend octet body))
                    (gr8s.http-client::read-crlf-line stream)))
         (coerce body '(simple-array (unsigned-byte 8) (*)))))
      ((and content-length (plusp (length content-length)))
       (let* ((length (parse-integer content-length))
              (body (make-array length :element-type '(unsigned-byte 8))))
         (read-sequence body stream)
         body))
      (t (make-array 0 :element-type '(unsigned-byte 8))))))

(defun dashboard-proxy-forward (config method target request)
  "Forward the browser REQUEST to the running cluster's API over an mTLS stream
built from the kubeconfig CONFIG -- the same connection `gr8s debug slynk' uses --
returning the upstream body as octets and copying its status and content type.
METHOD is a keyword; TARGET is the apiserver path+query. An API server that can't
be reached, or fails mid-answer, is a 502 with the reason, not a server error."
  (when (dashboard-websocket-request-p request)
    (return-from dashboard-proxy-forward
      (if (and (eq method :get) (gr8s.apiserver::true-parameter-p (hunchentoot:get-parameter "watch" request)))
          (serve-dashboard-websocket-watch config target request)
          ;; Answered at once: a handshake left waiting holds up every other
          ;; WebSocket the browser opens to the dashboard.
          (progn (setf (hunchentoot:return-code*) hunchentoot:+http-not-implemented+
                       (hunchentoot:content-type*) "text/plain")
                 "gr8s dashboard: only watches are relayed over a WebSocket"))))
  (let ((body (ignore-errors (hunchentoot:raw-post-data :force-binary t :request request)))
        (stream nil) (socket nil))
    (unwind-protect
         (handler-case
             (multiple-value-bind (opened opened-socket host port base-path) (open-debug-api-stream config)
               (setf stream opened socket opened-socket)
               (write-dashboard-proxy-request
                stream (symbol-name method) host port
                (concatenate 'string base-path target) (getf config :token)
                (hunchentoot:header-in :content-type request) body)
               (multiple-value-bind (status headers)
                   (gr8s.protocol::parse-http-response-head
                    (gr8s.protocol::read-http-response-head stream))
                 (setf (hunchentoot:return-code*) status
                       (hunchentoot:content-type*)
                       (or (cdr (assoc :content-type headers)) "application/json"))
                 (read-dashboard-proxy-body stream headers)))
           (error (condition)
             (setf (hunchentoot:return-code*) hunchentoot:+http-bad-gateway+
                   (hunchentoot:content-type*) "text/plain")
             (format nil "gr8s dashboard: the cluster API at ~A is unreachable: ~A"
                     (getf config :server) condition)))
      (when stream (ignore-errors (close stream)))
      (when socket (ignore-errors (usocket:socket-close socket))))))

;;; The /wsMultiplexer live-update relay.
;;;
;;; The Headlamp frontend multiplexes every resource watch over one WebSocket.
;;; This relay speaks that protocol on the browser side (see the contract in
;;; src/apiserver/dashboard.lisp) and, per watch subscription, opens a classic
;;; chunked HTTP watch (GET path?watch=1...) to the running cluster over the same
;;; mTLS stream `gr8s debug slynk' uses, reframing each newline-delimited watch
;;; event as a DATA frame to the browser. Each watch runs in its own thread so a
;;; CLOSE (or the WebSocket dropping) can shut its upstream socket down and unblock
;;; the read, exactly as the Slynk tunnel tears a relay down.

(defstruct dashboard-watch
  "One live upstream watch inside a /wsMultiplexer session."
  key thread socket)

(defun begin-dashboard-multiplexer (request)
  "Complete the WebSocket upgrade handshake for the multiplexer on REQUEST and
return the raw client stream (the connection is now in frames, not HTTP)."
  (let ((key (hunchentoot:header-in :sec-websocket-key request)))
    (setf (hunchentoot:return-code*) 101
          (hunchentoot:content-type*) nil
          (hunchentoot:header-out :connection) "Upgrade"
          (hunchentoot:header-out :upgrade) "websocket"
          (hunchentoot:header-out :sec-websocket-accept)
          (gr8s.apiserver::websocket-accept-value key)
          (hunchentoot:header-out :sec-websocket-protocol)
          gr8s.apiserver::+dashboard-multiplexer-protocol+)
    (let ((stream (hunchentoot::start-output 101 nil)))
      (finish-output stream)
      stream)))

(defun stream-watch-events (stream headers emit alive-p)
  "Read a Kubernetes watch response body from STREAM and call EMIT with each
newline-delimited watch-event JSON string, until the stream ends or ALIVE-P
returns NIL. Watch bodies arrive chunked; a single event may span chunks and a
chunk may hold several events, so reassemble across chunk boundaries and split on
LF. ALIVE-P is only consulted between chunks -- a CLOSE unblocks a blocked read by
shutting the socket, which surfaces as an error to the caller."
  (let ((chunked (let ((te (cdr (assoc :transfer-encoding headers))))
                   (and te (search "chunked" (string-downcase te)))))
        (pending (make-array 256 :element-type '(unsigned-byte 8)
                                 :adjustable t :fill-pointer 0)))
    (labels ((flush-lines ()
               (loop for nl = (position 10 pending)
                     while nl
                     do (let ((line (subseq pending 0 nl))
                              (tail (subseq pending (1+ nl))))
                          (when (plusp (length line))
                            (funcall emit (trivial-utf-8:utf-8-bytes-to-string line)))
                          (setf (fill-pointer pending) 0)
                          (loop for octet across tail do (vector-push-extend octet pending)))))
             (absorb (buffer count)
               (dotimes (i count) (vector-push-extend (aref buffer i) pending))
               (flush-lines)))
      (if chunked
          (loop
            (unless (funcall alive-p) (return))
            (let ((size (ignore-errors
                          (parse-integer (gr8s.http-client::read-crlf-line stream)
                                         :radix 16 :junk-allowed t))))
              (unless (and size (plusp size)) (return))
              (let ((chunk (make-array size :element-type '(unsigned-byte 8))))
                (unless (= (read-sequence chunk stream) size) (return))
                (gr8s.http-client::read-crlf-line stream) ; trailing CRLF
                (absorb chunk size))))
          ;; Non-chunked (unusual for a watch): read until EOF in blocks.
          (let ((block (make-array 4096 :element-type '(unsigned-byte 8))))
            (loop
              (unless (funcall alive-p) (return))
              (let ((count (read-sequence block stream)))
                (when (zerop count) (return))
                (absorb block count))))))))

(defun run-dashboard-watch (config message target watch send-frame alive-p claim forget)
  "Relay one upstream watch to the browser. Open an mTLS stream for TARGET (the
bare apiserver path+query), require a 200, then stream each watch event to the
browser as a DATA frame built from MESSAGE, until the stream ends or ALIVE-P is
NIL. On a non-200 send one ERROR frame; on a clean end send COMPLETE. CLAIM records
this watch's socket under the session lock and reports whether the watch is still
registered (a CLOSE during connect can have dropped it); FORGET removes the watch
from the session however the relay ends."
  (unwind-protect
       (handler-case
           (multiple-value-bind (stream socket host port base-path)
               (open-debug-api-stream config)
             ;; Publish the socket under the session lock so a concurrent CLOSE can
             ;; shut it down; if the watch was already dropped, stop now.
             (unless (funcall claim socket)
               (ignore-errors (close stream))
               (ignore-errors (usocket:socket-close socket))
               (return-from run-dashboard-watch))
             (unwind-protect
                  (progn
                    (write-dashboard-proxy-request
                     stream "GET" host port (concatenate 'string base-path target)
                     (getf config :token) nil nil)
                    (multiple-value-bind (status headers)
                        (gr8s.protocol::parse-http-response-head
                         (gr8s.protocol::read-http-response-head stream))
                      (if (= status 200)
                          (progn
                            (stream-watch-events
                             stream headers
                             (lambda (event)
                               (funcall send-frame
                                        (gr8s.apiserver::dashboard-multiplexer-frame
                                         message "DATA" event)))
                             alive-p)
                            (when (funcall alive-p)
                              (funcall send-frame
                                       (gr8s.apiserver::dashboard-multiplexer-frame
                                        message "COMPLETE"))))
                          (funcall send-frame
                                   (gr8s.apiserver::dashboard-multiplexer-frame
                                    message "ERROR"
                                    (format nil "{\"error\":\"upstream watch returned HTTP ~D\"}"
                                            status))))))
               (ignore-errors (close stream))
               (ignore-errors (usocket:socket-close socket))))
         (error () nil))
    (funcall forget)))

(defun serve-dashboard-multiplexer (config request)
  "Serve the /wsMultiplexer WebSocket for the `gr8s dashboard' command: upgrade
the connection, then read the frontend's REQUEST/CLOSE control frames and keep one
upstream mTLS watch (built from the kubeconfig CONFIG) per subscription alive,
relaying every watch event back. Returns when the WebSocket closes."
  (unless (and (string-equal (hunchentoot:header-in :upgrade request) "websocket")
               (hunchentoot:header-in :sec-websocket-key request))
    (setf (hunchentoot:return-code*) hunchentoot:+http-bad-request+
          (hunchentoot:content-type*) "text/plain")
    (return-from serve-dashboard-multiplexer
      "gr8s dashboard multiplexer requires a WebSocket upgrade"))
  (let ((client (begin-dashboard-multiplexer request))
        (write-lock (bt:make-lock "gr8s dashboard multiplexer writer"))
        (watches (make-hash-table :test #'equal))
        (watches-lock (bt:make-lock "gr8s dashboard multiplexer watches"))
        (session-open t))
    (labels ((send-frame (text)
               (bt:with-lock-held (write-lock)
                 (ignore-errors
                  (gr8s.protocol::write-websocket-frame
                   client 1 (trivial-utf-8:string-to-utf-8-bytes text)))))
             (drop-watch (key watch)
               ;; Remove WATCH only if it is still the one registered under KEY.
               (bt:with-lock-held (watches-lock)
                 (when (eq (gethash key watches) watch) (remhash key watches))))
             (shut (socket)
               ;; Wake the watch thread reading SOCKET; run-dashboard-watch closes it on its
               ;; way out. Closing it here, under that read, would leave the read spinning.
               (when socket
                 (ignore-errors (usocket:socket-shutdown socket :io))))
             (stop-watch (key)
               ;; Read the socket under the lock: the watch thread also publishes it
               ;; there, so we never miss a socket that was just opened.
               (shut (bt:with-lock-held (watches-lock)
                       (let ((watch (gethash key watches)))
                         (when watch (remhash key watches) (dashboard-watch-socket watch))))))
             (stop-all ()
               (let ((sockets (bt:with-lock-held (watches-lock)
                                (prog1 (loop for w being the hash-values of watches
                                             for s = (dashboard-watch-socket w)
                                             when s collect s)
                                  (clrhash watches)))))
                 (mapc #'shut sockets)))
             (start-watch (message)
               (let* ((key (gr8s.apiserver::dashboard-multiplexer-key message))
                      (target (gr8s.apiserver::dashboard-watch-upstream-target
                               (gr8s.apiserver::dashboard-mux-message-path message)
                               (gr8s.apiserver::dashboard-mux-message-query message)))
                      (watch (make-dashboard-watch :key key)))
                 ;; A re-REQUEST for the same key replaces the running watch.
                 (stop-watch key)
                 (bt:with-lock-held (watches-lock) (setf (gethash key watches) watch))
                 (flet ((registered-p ()
                          (and session-open
                               (eq (bt:with-lock-held (watches-lock) (gethash key watches))
                                   watch))))
                   (setf (dashboard-watch-thread watch)
                         (bt:make-thread
                          (lambda ()
                            (run-dashboard-watch
                             config message target watch #'send-frame
                             #'registered-p
                             (lambda (socket) ; claim: publish socket, report liveness
                               (bt:with-lock-held (watches-lock)
                                 (setf (dashboard-watch-socket watch) socket)
                                 (and session-open (eq (gethash key watches) watch))))
                             (lambda () (drop-watch key watch))))
                          :name "gr8s dashboard watch"))))))
      (unwind-protect
           (handler-case
               (loop
                 (multiple-value-bind (opcode payload fin-p masked-p)
                     (gr8s.protocol::read-websocket-frame client)
                   (declare (ignore fin-p masked-p))
                   (case opcode
                     ((1 2)             ; a client control message (text/binary)
                      (let ((message (gr8s.apiserver::dashboard-parse-multiplexer-message
                                      (trivial-utf-8:utf-8-bytes-to-string payload))))
                        (when message
                          (let ((type (gr8s.apiserver::dashboard-mux-message-type message)))
                            (cond
                              ((string= type "REQUEST") (start-watch message))
                              ((string= type "CLOSE")
                               (stop-watch (gr8s.apiserver::dashboard-multiplexer-key message))))))))
                     (8 (return))       ; client close
                     (9 (bt:with-lock-held (write-lock) ; ping -> pong
                          (ignore-errors (gr8s.protocol::write-websocket-frame client 10 payload))))
                     (10)               ; pong
                     (otherwise nil))))
             (error () nil))
        (setf session-open nil)
        (stop-all)
        (ignore-errors (close client)))
      "")))

;;; Headlamp also watches some resources over a WebSocket of their own, as the Kubernetes
;;; API allows: a GET ?watch=1 upgraded, each event a text message. The cluster API
;;; watches over chunked HTTP only, so the dashboard answers the upgrade itself and relays
;;; the watch. Passed on as a plain GET, the watch never ended, so the browser's handshake
;;; waited it out -- minutes -- and Chrome, which opens one WebSocket to a host at a time,
;;; held every other one behind it: the Agent tab's terminals stayed blank (podster-c7r).

(defun websocket-fd-stream (stream)
  "The socket's fd-stream beneath STREAM, a WebSocket hunchentoot has handed over, or NIL."
  (loop for inner = stream then (cond ((typep inner 'flexi-streams:flexi-stream) (flexi-streams:flexi-stream-stream inner))
                                      ((typep inner 'chunga:chunked-stream) (chunga:chunked-stream-stream inner)))
        while inner
        when (typep inner 'sb-sys:fd-stream) return inner))

(defun keep-websocket-open (stream)
  "Let STREAM, a WebSocket hunchentoot has handed over, stay quiet as long as its two ends
like: the server's idle timeout would hang up a watch, or a terminal, with nothing to say.
Return STREAM."
  (let ((fd-stream (websocket-fd-stream stream)))
    (when fd-stream (setf (sb-impl::fd-stream-timeout fd-stream) nil)))
  stream)

(defun stop-reading-websocket (stream)
  "Wake a thread blocked reading STREAM, a WebSocket hunchentoot has handed over, with an
end of file, leaving STREAM open: close it only once that thread is done with it. A stream
closed under a blocked read leaves the read polling a dead descriptor forever, which SBCL's
wait answers at once, so the thread spins (podster-gek)."
  (let ((fd-stream (websocket-fd-stream stream)))
    (when (and fd-stream (open-stream-p fd-stream))
      ;; shutdown(fd, SHUT_RD): later reads see end of file; what is written still goes out.
      (sb-alien:alien-funcall
       (sb-alien:extern-alien "shutdown" (function sb-alien:int sb-alien:int sb-alien:int))
       (sb-sys:fd-stream-fd fd-stream) 0))))

(defun dashboard-websocket-request-p (request)
  "Whether REQUEST asks for a WebSocket."
  (and (string-equal (hunchentoot:header-in :upgrade request) "websocket")
       (hunchentoot:header-in :sec-websocket-key request)))

(defun serve-dashboard-websocket-watch (config target request)
  "Answer REQUEST's WebSocket upgrade at once, then send each event of the watch of
TARGET, on the running cluster's API, as a text message, until either side ends it."
  (let* ((offered (remove "" (mapcar (lambda (name) (string-trim " " name))
                                     (uiop:split-string (or (hunchentoot:header-in :sec-websocket-protocol request) "")
                                                        :separator '(#\,)))
                          :test #'string=))
         (write-lock (bt:make-lock "gr8s dashboard watch socket writer"))
         (upstream-lock (bt:make-lock "gr8s dashboard watch socket upstream"))
         (upstream nil)
         (open t)
         ;; The close status the browser gets: a normal one, unless the watch was refused.
         (closing '(3 232))
         client reader)
    (setf (hunchentoot:return-code*) 101
          (hunchentoot:content-type*) nil
          (hunchentoot:header-out :connection) "Upgrade"
          (hunchentoot:header-out :upgrade) "websocket"
          (hunchentoot:header-out :sec-websocket-accept)
          (gr8s.apiserver::websocket-accept-value (hunchentoot:header-in :sec-websocket-key request)))
    ;; A browser that offered protocols needs one of them back.
    (when offered (setf (hunchentoot:header-out :sec-websocket-protocol) (first offered)))
    (setf client (keep-websocket-open (hunchentoot::start-output 101 nil)))
    (finish-output client)
    (labels ((send (opcode payload)
               (bt:with-lock-held (write-lock)
                 (ignore-errors (gr8s.protocol::write-websocket-frame client opcode payload))))
             (hang-up ()
               (bt:with-lock-held (upstream-lock)
                 (setf open nil)
                 (when upstream
                   (ignore-errors (usocket:socket-shutdown upstream :io))))))
      (setf reader (bt:make-thread
                    (lambda ()
                      (handler-case
                          (loop (multiple-value-bind (opcode payload) (gr8s.protocol::read-websocket-frame client)
                                  (case opcode
                                    (8 (return))
                                    (9 (send 10 payload)))))
                        (error () nil))
                      ;; The browser has gone: so has the watch.
                      (hang-up))
                    :name "gr8s dashboard watch socket reader"))
      (unwind-protect
           (handler-case
               (multiple-value-bind (stream socket host port base-path) (open-debug-api-stream config)
                 (unwind-protect
                      (when (bt:with-lock-held (upstream-lock) (and open (setf upstream socket)))
                        (write-dashboard-proxy-request stream "GET" host port (concatenate 'string base-path target)
                                                       (getf config :token) nil nil)
                        (multiple-value-bind (status headers)
                            (gr8s.protocol::parse-http-response-head (gr8s.protocol::read-http-response-head stream))
                          (if (= status 200)
                              (stream-watch-events stream headers
                                                   (lambda (event) (send 1 (trivial-utf-8:string-to-utf-8-bytes event)))
                                                   (lambda () open))
                              ;; A watch refused ends in a close the browser reads as an error.
                              (setf closing (append '(3 243) (coerce (trivial-utf-8:string-to-utf-8-bytes
                                                                      (format nil "upstream watch returned HTTP ~D" status))
                                                                     'list))))))
                   (ignore-errors (close stream))
                   (ignore-errors (usocket:socket-close socket))))
             (error () nil))
        (send 8 (coerce closing '(vector (unsigned-byte 8))))
        (hang-up)
        ;; The reader may still be waiting on the browser: wake it, and close only once it has gone.
        (ignore-errors (stop-reading-websocket client))
        (ignore-errors (bt:join-thread reader))
        (ignore-errors (close client))))
    ""))

(defvar *dashboard-verbose* nil
  "True when `gr8s dashboard --verbose' asked for every request and server error on stderr.")

(defclass dashboard-command-acceptor (hunchentoot:easy-acceptor)
  ((proxy-fn :initarg :proxy-fn :reader dashboard-acceptor-proxy-fn)
   (multiplexer-fn :initarg :multiplexer-fn :reader dashboard-acceptor-multiplexer-fn))
  (:documentation "The loopback acceptor the `gr8s dashboard' command runs."))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor dashboard-command-acceptor) request)
  (let ((gr8s.apiserver::*dashboard-proxy-fn* (dashboard-acceptor-proxy-fn acceptor))
        (gr8s.apiserver::*dashboard-multiplexer-fn* (dashboard-acceptor-multiplexer-fn acceptor)))
    (or (gr8s.apiserver::dashboard-response request)
        (progn
          (setf (hunchentoot:return-code*) hunchentoot:+http-not-found+
                (hunchentoot:content-type*) "text/plain")
          "gr8s dashboard: not found"))))

(defun parse-dashboard-options (arguments)
  "Parse `gr8s dashboard' options."
  (let ((options (list :command :dashboard
                       :kubeconfig nil :port 8080 :browser nil :no-launch nil :verbose nil))
        (rest arguments))
    (loop while (and rest (uiop:string-prefix-p "--" (first rest)))
          do (let ((option (pop rest)))
               (cond
                 ((string= option "--no-launch") (setf (getf options :no-launch) t))
                 ((string= option "--verbose") (setf (getf options :verbose) t))
                 (t
                  (unless rest (error "~A requires a value" option))
                  (let ((value (pop rest)))
                    (cond
                      ((string= option "--kubeconfig") (setf (getf options :kubeconfig) value))
                      ((string= option "--port") (setf (getf options :port) (parse-port value)))
                      ((string= option "--browser") (setf (getf options :browser) value))
                      (t (error "unknown dashboard option: ~A" option))))))))
    (when rest
      (error "usage: gr8s dashboard [--kubeconfig PATH] [--port N] [--browser CMD] [--no-launch] [--verbose]"))
    options))

(defun run-dashboard-command (options)
  "Serve the embedded dashboards and open them in a browser, like `icl -b'. A
foreground process: it starts a loopback web server with a page of tabs -- the
Kubernetes dashboard (Headlamp), the Network view, an Agent terminal and a REPL --
reverse-proxies Headlamp's Kubernetes calls over mTLS to the running cluster
(authenticating with the kubeconfig, as `gr8s debug slynk' does), draws the Network
view from the cluster's flow events, opens the browser, and runs until Ctrl-C. Everything lives
under an unguessable per-session token so other local processes cannot reach it.
OPTIONS' :tab, a tab's name such as \"network\", opens on that tab. Only with :verbose does it log
each request and each worker error."
  (unless (gr8s.apiserver::dashboard-assets-present-p)
    (error "this gr8s build has no embedded dashboard; rebuild with 'make dashboard-assets'"))
  (let* ((kubeconfig (or (getf options :kubeconfig) (default-client-kubeconfig)))
         (config (dashboard-kubeconfig-config kubeconfig))
         (port (getf options :port 8080))
         (token (dashboard-session-token))
         (agent-base (format nil "/agent/~A/" token))
         (lisp-base (format nil "/lisp/~A/" token))
         (network-base (format nil "/network/~A/" token))
         (network (make-dashboard-network config))
         (lisp (make-dashboard-lisp config))
         (agent (make-dashboard-agent (namestring (truename kubeconfig))))
         (apps (make-dashboard-apps config))
         (url (format nil "http://127.0.0.1:~D/ui/~A/~@[#~A~]" port token (getf options :tab)))
         (verbose (getf options :verbose))
         (acceptor (make-instance 'gr8s-dashboard-acceptor
                                  :address "127.0.0.1" :port port
                                  :access-log-destination (and verbose *error-output*)
                                  :message-log-destination (and verbose *error-output*)
                                  :shell-path (format nil "/ui/~A/" token)
                                  :tabs (append (list (list "headlamp" (format nil "/dashboard/~A/" token) "Headlamp"))
                                                (list (list "network" network-base "Network"))
                                                (list (list "agent" agent-base "Agent"))
                                                (list (list "repl" lisp-base "REPL")))
                                  :agent agent :agent-base agent-base
                                  :lisp lisp :lisp-base lisp-base
                                  :network network :network-base network-base
                                  :apps apps
                                  :proxy-fn (lambda (method target request)
                                              (dashboard-proxy-forward config method target request))
                                  :multiplexer-fn (lambda (request)
                                                    (serve-dashboard-multiplexer config request)))))
    ;; Acceptor worker threads read the base globally, so set it (one-shot process).
    (setf gr8s.apiserver::*dashboard-base* (format nil "/dashboard/~A" token)
          *dashboard-verbose* verbose
          *shutdown-requested* nil)
    (install-shutdown-handlers)
    (handler-case (hunchentoot:start acceptor)
      (usocket:address-in-use-error ()
        (stop-dashboard-agents agent)
        (return-from run-dashboard-command (report-dashboard-port-in-use port options kubeconfig))))
    (ignore-errors (record-dashboard-session port url kubeconfig))
    (unwind-protect
         (progn
           (format t "gr8s dashboard: ~A~%  cluster API ~A (via ~A)~%"
                   url (getf config :server) kubeconfig)
           (if (getf options :no-launch)
               (format t "Open the URL above. Press Ctrl-C to stop.~%")
               (progn
                 (handler-case
                     (uiop:launch-program
                      (list (or (getf options :browser) (default-browser-opener)) url)
                      :output :interactive :error-output :interactive)
                   (error (condition)
                     (format t "could not launch a browser (~A); open the URL above.~%" condition)))
                 (format t "Serving the dashboard. Press Ctrl-C to stop.~%")))
           (finish-output)
           (loop until *shutdown-requested* do (sleep 0.2)))
      (ignore-errors (hunchentoot:stop acceptor))
      (ignore-errors (forget-dashboard-session port))
      (stop-dashboard-agents agent)
      (stop-dashboard-lisp lisp)
      (stop-dashboard-network network)
      (stop-dashboard-apps apps))
    0))

(defun parse-net-agent-options (arguments)
  "Parse `gr8s net-agent` options: the foreign-cluster network services agent
(docs/design-foreign-cluster-networking.md). Each feature -- the CNI, the
service LB, the Gateway -- is independently selectable; at least one must be."
  (let ((options (list :command :net-agent :cni t)))
    (loop for (option value) on arguments by #'cddr
          do (unless value (error "~A requires a value" option))
             (cond ((equal option "--kubeconfig") (setf (getf options :kubeconfig) value))
                   ((equal option "--node-name") (setf (getf options :node-name) value))
                   ((equal option "--state-directory") (setf (getf options :state-directory) value))
                   ((equal option "--bpf-root") (setf (getf options :bpf-root) value))
                   ((equal option "--socket") (setf (getf options :socket-path) value))
                   ((equal option "--mtu") (setf (getf options :mtu) (parse-integer value)))
                   ((equal option "--overlay-backend")
                    (unless (member value '("vxlan" "wireguard") :test #'string=)
                      (error "overlay backend must be vxlan or wireguard"))
                    (setf (getf options :overlay-backend) value))
                   ((equal option "--wireguard-listen-port")
                    (setf (getf options :wireguard-listen-port) (parse-integer value)))
                   ((equal option "--cni")
                    ;; A flag with an explicit value keeps the pairwise parse.
                    (setf (getf options :cni) (string= value "true")))
                   ((equal option "--gateway")
                    (setf (getf options :gateway) (string= value "true")))
                   ((equal option "--listenerset-api-group")
                    (unless (member value '("gateway.networking.k8s.io"
                                            "gateway.networking.x-k8s.io") :test #'equal)
                      (error "unsupported ListenerSet API group: ~A" value))
                    (setf (getf options :listenerset-api-group) value))
                   ((equal option "--service-lb")
                    (setf (getf options :service-lb) (string= value "true")))
                   ((equal option "--flow-events")
                    (unless (member value '("connections" "drops") :test #'string=)
                      (error "--flow-events must be connections or drops"))
                    (setf (getf options :flow-events) value))
                   ((equal option "--flow-port")
                    (let ((port (parse-integer value)))
                      (unless (<= 0 port 65535) (error "--flow-port must be 0 to 65535"))
                      (setf (getf options :flow-port) port)))
                   (t (error "unknown net-agent option: ~A" option))))
    (unless (or (getf options :cni) (getf options :gateway) (getf options :service-lb))
      (error "net-agent with --cni false needs --gateway or --service-lb"))
    options))

(defun start-net-agent-flows (view node-name bpf-root port)
  "Collect this node's flow events from BPF-ROOT, naming Pods from VIEW, and serve them
on loopback PORT (none with 0). Return a function that stops both, or NIL when the
node can't collect them."
  (handler-case
      (let* ((collector (gr8s.agent::start-flow-collector
                         bpf-root node-name view :pod-lookup #'gr8s.agent::reported-pod-at-address))
             (listener (handler-case (and (plusp port) (gr8s.agent::start-flow-listener collector :port port))
                         (error (condition)
                           (format *error-output* "~&gr8s net-agent: flow port ~D unavailable: ~A~%" port condition)
                           nil))))
        (lambda ()
          (when listener (gr8s.agent::stop-flow-listener listener))
          (gr8s.agent::stop-flow-collector collector)))
    (error (condition)
      (format *error-output* "~&gr8s net-agent: flow events unavailable: ~A~%" condition)
      nil)))

(defun run-net-agent-command (options)
  "Run the foreign-cluster network services agent until shutdown is requested."
  (let ((cluster (if (getf options :kubeconfig)
                     (gr8s.kube-client:cluster-from-kubeconfig (getf options :kubeconfig))
                     (gr8s.kube-client:cluster-from-service-account)))
        (node-name (or (getf options :node-name)
                       (uiop:getenv "NODE_NAME")
                       (machine-instance)))
        (state-directory (uiop:ensure-directory-pathname
                          (or (getf options :state-directory)
                              (merge-pathnames "net-agent/" (default-state-directory)))))
        (overlay-backend (or (getf options :overlay-backend) "vxlan")))
    ;; WireGuard mode generates/loads a durable node key pair up front, exactly
    ;; as native gr8s does, and advertises the public key via a Node annotation.
    ;; The overlay is part of the CNI feature, so no key without it.
    (multiple-value-bind (wireguard-private-key wireguard-public-key)
        (when (and (getf options :cni) (string= overlay-backend "wireguard"))
          (ensure-wireguard-key-pair state-directory))
    (gr8s.network::run-foreign-net-agent
     cluster
     :cni (getf options :cni)
     :node-name node-name
     :state-directory state-directory
     :bpf-root (or (getf options :bpf-root) "/sys/fs/bpf/gr8s")
     :socket-path (or (getf options :socket-path) "/run/gr8s/cni.sock")
     :mtu (or (getf options :mtu) 1450)
     :overlay-backend overlay-backend
     :wireguard-private-key wireguard-private-key
     :wireguard-public-key wireguard-public-key
     :wireguard-listen-port (or (getf options :wireguard-listen-port) 51820)
     :extra-factory
     (when (or (getf options :gateway) (getf options :service-lb) (getf options :cni))
       (lambda (view)
         (setf (gr8s.resources::foreign-resource-view-listenerset-group view)
               (getf options :listenerset-api-group))
         (let ((convergers '()) (stoppers '()))
           (when (getf options :cni)
             ;; The guards' flow events, for readers that come through the cluster
             ;; API's pods/portforward. Without CAP_BPF the node just has none.
             (let ((stopper (start-net-agent-flows
                             view node-name (or (getf options :bpf-root) "/sys/fs/bpf/gr8s")
                             (getf options :flow-port gr8s.agent::+default-flow-listener-port+))))
               (when stopper (push stopper stoppers))))
           (when (getf options :gateway)
             (multiple-value-bind (converger stopper)
                 (gr8s.controllers:start-foreign-gateway
                  view :cert-dir (merge-pathnames "gateway-certs/" state-directory)
                  :cluster cluster :node-name node-name)
               (push converger convergers) (push stopper stoppers)))
           (when (getf options :service-lb)
             ;; Attaching needs CAP_BPF, a bpffs and a modern kernel; without
             ;; them the cluster keeps whatever Service proxy it already runs.
             (let ((dataplane (gr8s.network::try-start-service-lb-dataplane
                               "/sys/fs/cgroup"
                               (namestring
                                (merge-pathnames
                                 "service-lb/"
                                 (uiop:ensure-directory-pathname
                                  (or (getf options :bpf-root) "/sys/fs/bpf/gr8s")))))))
               (when dataplane
                 (multiple-value-bind (converger stopper)
                     (gr8s.controllers:start-foreign-service-lb
                      view dataplane :node-name node-name)
                   (push converger convergers) (push stopper stoppers)))))
           (values (let ((ordered (nreverse convergers)))
                     (lambda ()
                       ;; Each layer fails soft on its own: a gateway pass
                       ;; tripping over one object must not starve the LB.
                       (dolist (converger ordered)
                         (handler-case (funcall converger)
                           (error (condition)
                             (format *error-output*
                                     "~&gr8s net-agent extra layer failed: ~A~%"
                                     condition))))))
                   (let ((ordered (nreverse stoppers)))
                     (lambda () (mapc #'funcall ordered)))))))
     :stop-predicate (lambda () *shutdown-requested*))
    0)))

(defun parse-cni-install-options (arguments)
  "Parse `gr8s cni-install` options: the shell-free initContainer step that
installs this binary as the node's CNI plugin, mounts the bpffs, and writes the
gr8s CNI conflist. Defaults match the gr8s-net chart's mount paths, so a
distroless image needs no /bin/sh, coreutils or util-linux."
  (let ((options (list :command :cni-install
                       :cni-bin-dir "/host-cni-bin"
                       :cni-conf-dir "/host-cni-conf"
                       :bpf-mount "/host-bpf"
                       :conflist "05-gr8s.conflist"
                       :cni-name "gr8s"
                       :socket "/run/gr8s/cni.sock"
                       :map-pin-root "/run/gr8s/bpf"
                       :direction "egress")))
    (loop for (option value) on arguments by #'cddr
          do (unless value (error "~A requires a value" option))
             (cond ((equal option "--cni-bin-dir") (setf (getf options :cni-bin-dir) value))
                   ((equal option "--cni-conf-dir") (setf (getf options :cni-conf-dir) value))
                   ((equal option "--bpf-mount") (setf (getf options :bpf-mount) value))
                   ((equal option "--conflist") (setf (getf options :conflist) value))
                   ((equal option "--cni-name") (setf (getf options :cni-name) value))
                   ((equal option "--socket") (setf (getf options :socket) value))
                   ((equal option "--map-pin-root") (setf (getf options :map-pin-root) value))
                   ((equal option "--direction") (setf (getf options :direction) value))
                   (t (error "unknown cni-install option: ~A" option))))
    options))

(defun run-cni-install-command (options)
  "Install the gr8s CNI plugin on the node without a shell: copy this running
executable into the host CNI bin directory, mount a bpffs where Pod maps and TCX
links are pinned, and write the CNI conflist -- each file write atomic (temp +
rename), the mount idempotent. This is what the initContainer runs, so the image
needs no shell/coreutils/util-linux. Returns 0."
  (let* ((bin-dir (uiop:ensure-directory-pathname (getf options :cni-bin-dir)))
         (conf-dir (uiop:ensure-directory-pathname (getf options :cni-conf-dir)))
         (bin-target (merge-pathnames "gr8s" bin-dir))
         (conflist (merge-pathnames (getf options :conflist) conf-dir)))
    (ensure-directories-exist bin-dir)
    (ensure-directories-exist conf-dir)
    ;; Copy this running binary into place atomically, keeping the exec bit.
    ;; /proc/self/exe is the full executable (SBCL core appended), which the
    ;; kubelet invokes as the "gr8s" CNI plugin.
    ;; Copy straight to the final name, not via a temp + rename: on a hostPath
    ;; the data copy surfaces on the host but the in-container rename does not, so
    ;; a temp+rename leaves "gr8s.tmp" on the node and no "gr8s". Atomicity is not
    ;; needed here -- the init step completes before the agent starts and before
    ;; any Pod that would invoke the plugin is scheduled. Unlink any stale binary
    ;; first so a replacement never hits ETXTBSY against a running copy.
    (uiop:delete-file-if-exists bin-target)
    (uiop:copy-file #P"/proc/self/exe" bin-target)
    (sb-posix:chmod (namestring bin-target) #o755)
    ;; Mount the bpffs (idempotent: a surviving mount is reused, not overmounted).
    (gr8s.kubelet::mount-managed-bpffs (getf options :bpf-mount))
    ;; Write the conflist directly (see the binary note on hostPath renames).
    (with-open-file (stream conflist :direction :output
                                     :if-exists :supersede :if-does-not-exist :create)
      (format stream "{\"cniVersion\":\"1.0.0\",\"name\":\"~A\",\"plugins\":[{\"type\":\"gr8s\",\"socket\":\"~A\",\"direction\":\"~A\",\"mapPinRoot\":\"~A\"}]}~%"
              (getf options :cni-name) (getf options :socket)
              (getf options :direction) (getf options :map-pin-root)))
    (format t "~&gr8s cni-install: plugin ~A, bpffs ~A, conflist ~A~%"
            bin-target (getf options :bpf-mount) conflist)
    0))

(defun parse-cli-options (arguments)
  "Dispatch ARGUMENTS to the matching subcommand option parser and return its
   options plist. No arguments, or help/version/notices, yield a bare :command
   plist. Signals on an unknown command."
  (let ((help-flag (find-if (lambda (argument)
                              (member argument '("--help" "-h") :test #'string=))
                            arguments)))
    (cond
    ((null arguments)
     (list :command :help :help-path nil))
    ((member (first arguments) '("help" "h") :test #'string=)
     (list :command :help
           :help-path (remove-if (lambda (argument)
                                   (member argument '("--help" "-h") :test #'string=))
                                 (rest arguments))))
    (help-flag
     (list :command :help
           :help-path (remove-if (lambda (argument)
                                   (member argument '("--help" "-h") :test #'string=))
                                 arguments)))
    ((and (null (rest arguments))
          (member (first arguments)
                  '("runtime" "wireguard" "network" "debug"
                    "certificate" "secrets-encrypt" "backup")
                  :test #'string=))
     (list :command :help :help-path arguments))
    ((member (first arguments) '("version" "--version" "-v") :test #'string=)
     (let ((tail (rest arguments)) (options (list :command :version)))
       (when tail
         (unless (and (equal (first tail) "--state-directory") (second tail) (null (cddr tail)))
           (error "version accepts --state-directory DIR"))
         (setf (getf options :state-directory) (second tail)))
       options))
    ((string= "skill" (first arguments))
     (when (rest arguments) (error "skill accepts no arguments"))
     (list :command :skill))
    ((string= "notices" (first arguments))
     (list :command :notices))
    ((string= "serve" (first arguments))
     (parse-serve-options (rest arguments)))
    ((string= "agent" (first arguments))
     (parse-agent-options (rest arguments)))
    ((string= "net-agent" (first arguments))
     (parse-net-agent-options (rest arguments)))
    ((string= "cni-install" (first arguments))
     (parse-cni-install-options (rest arguments)))
    ((string= "join-token" (first arguments))
     (parse-join-token-options (rest arguments)))
    ((string= "witness" (first arguments))
     (parse-witness-options (rest arguments)))
    ((string= "kubeconfig" (first arguments))
     (parse-kubeconfig-options (rest arguments)))
    ((string= "runtime" (first arguments))
     (parse-runtime-options (rest arguments)))
    ((string= "debug" (first arguments))
     (parse-debug-options (rest arguments)))
    ((string= "wireguard" (first arguments))
     (parse-wireguard-options (rest arguments)))
    ((string= "network" (first arguments))
     (parse-network-options (rest arguments)))
    ((string= "certificate" (first arguments))
     (parse-certificate-options (rest arguments)))
    ((string= "secrets-encrypt" (first arguments))
     (parse-secrets-encrypt-options (rest arguments)))
    ((string= "backup" (first arguments))
     (parse-backup-options (rest arguments)))
    ((string= "restore" (first arguments))
     (parse-restore-options (rest arguments)))
    ((string= "status" (first arguments))
     (parse-status-options (rest arguments)))
    ((string= "upgrade" (first arguments))
     (parse-upgrade-options (rest arguments)))
    ((string= "member" (first arguments))
     (parse-member-options (rest arguments)))
    ((string= "doctor" (first arguments))
     (parse-doctor-options (rest arguments)))
    ((string= "dashboard" (first arguments))
     (parse-dashboard-options (rest arguments)))
    ((string= "mcp" (first arguments))
     (parse-mcp-options (rest arguments)))
    (t (error "unknown command: ~A" (first arguments))))))

(defun parse-trace-duration (text)
  "Parse a trace duration in milliseconds, seconds, or minutes."
  (let* ((unit (cond ((uiop:string-suffix-p text "ms") "ms")
                     ((uiop:string-suffix-p text "s") "s")
                     ((uiop:string-suffix-p text "m") "m")
                     (t nil)))
         (digits (if unit (subseq text 0 (- (length text) (length unit))) text))
         (value (parse-integer digits :junk-allowed nil))
         (milliseconds (* value (cond ((equal unit "m") 60000)
                                      ((equal unit "s") 1000)
                                      (t 1)))))
    (unless (<= 1 milliseconds 300000)
      (error "trace duration must be between 1ms and 300s"))
    milliseconds))

(defun parse-trace-options (arguments)
  "Parse `gr8s debug trace` selector, authentication and bpftrace-compatible source options."
  (let ((options (list :command :trace :server "https://127.0.0.1:6443"
                       :namespace "default" :selector "" :duration-milliseconds 30000))
        (rest arguments))
    (loop while (and rest (uiop:string-prefix-p "--" (first rest)))
          do (let ((option (pop rest)))
               (unless rest (error "~A requires a value" option))
               (let ((value (pop rest)))
                 (cond ((string= option "--server") (setf (getf options :server) value))
                       ((string= option "--namespace") (setf (getf options :namespace) value))
                       ((string= option "--selector") (setf (getf options :selector) value))
                       ((string= option "--duration")
                        (setf (getf options :duration-milliseconds) (parse-trace-duration value)))
                       ((string= option "--token") (setf (getf options :token) value))
                       ((string= option "--ca-file") (setf (getf options :ca-file) value))
                       (t (error "unknown trace option: ~A" option))))))
    (unless (= 1 (length rest))
      (error "usage: gr8s debug trace [options] BPFTRACE-SOURCE"))
    (setf (getf options :source) (first rest))
    options))

(defun trace-server-parts (url namespace)
  (let* ((secure-p (uiop:string-prefix-p "https://" url))
         (prefix (if secure-p "https://" "http://")))
    (unless (or secure-p (uiop:string-prefix-p "http://" url))
      (error "trace server must use http:// or https://"))
    (let* ((tail (subseq url (length prefix)))
           (slash (or (position #\/ tail) (length tail)))
           (authority (subseq tail 0 slash))
           (colon (position #\: authority :from-end t))
           (host (if colon (subseq authority 0 colon) authority))
           (port (if colon (parse-integer (subseq authority (1+ colon)) :junk-allowed nil)
                     (if secure-p 443 80))))
      (values secure-p host port
              (format nil "/apis/gr8s.io/v1/namespaces/~A/traces" namespace)))))

(defun open-trace-client-stream (secure-p host port ca-file)
  (let* ((socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)))
         (stream (usocket:socket-stream socket)))
    (values
     (if secure-p
         (progn
           (unless ca-file (error "https trace requires --ca-file"))
           (pure-tls:make-tls-client-stream
            stream :hostname host
            :context (pure-tls:make-tls-context
                      :verify-mode pure-tls:+verify-required+
                      :ca-file ca-file :auto-load-system-ca nil)))
         stream)
     socket)))

(defun run-trace-command (options)
  "Open the trace WebSocket, send its request frame, and print node-labelled records."
  (multiple-value-bind (secure-p host port path)
      (trace-server-parts (getf options :server) (getf options :namespace))
    (multiple-value-bind (stream socket)
        (open-trace-client-stream secure-p host port (getf options :ca-file))
      (unwind-protect
           (let* ((key-bytes (make-array 16 :element-type '(unsigned-byte 8)))
                  (key (progn (dotimes (index 16)
                                (setf (aref key-bytes index) (random 256)))
                              (ag-grpc:base64-encode key-bytes)))
                  (token (getf options :token)))
             (write-sequence
              (gr8s.protocol::ascii-octets
               (with-output-to-string (request)
                 (flet ((line (control &rest arguments)
                          (apply #'format request control arguments)
                          (write-char #\Return request)
                          (write-char #\Linefeed request)))
                   (line "GET ~A HTTP/1.1" path)
                   (line "Host: ~A:~D" host port)
                   (line "Upgrade: websocket")
                   (line "Connection: Upgrade")
                   (line "Sec-WebSocket-Version: 13")
                   (line "Sec-WebSocket-Key: ~A" key)
                   (line "Sec-WebSocket-Protocol: gr8s.trace.v1")
                   (when token (line "Authorization: Bearer ~A" token))
                   (line ""))))
              stream)
             (finish-output stream)
             (multiple-value-bind (status headers)
                 (gr8s.protocol::parse-http-response-head
                  (gr8s.protocol::read-http-response-head stream))
               (declare (ignore headers))
               (unless (= status 101)
                 (error "Trace API rejected the WebSocket upgrade with HTTP ~D" status)))
             (gr8s.protocol::write-websocket-frame
              stream 1
              (trivial-utf-8:string-to-utf-8-bytes
               (com.inuoe.jzon:stringify
                (core-object "selector" (getf options :selector)
                             "source" (getf options :source)
                             "durationMilliseconds" (getf options :duration-milliseconds))))
              :masked-p t)
             (loop
               (multiple-value-bind (opcode payload)
                   (gr8s.protocol:read-websocket-frame stream)
                 (case opcode
                   (1 (let* ((object (com.inuoe.jzon:parse payload))
                             (data (gethash "data" object)))
                        (if data
                            (format t "[~A] ~A" (gethash "node" object) data)
                            (format t "~A~%" (trivial-utf-8:utf-8-bytes-to-string payload)))
                        (finish-output)))
                   (8 (return 0))
                   (9 (gr8s.protocol::write-websocket-frame stream 10 payload :masked-p t))
                   (otherwise nil)))))
        (ignore-errors (close stream))
        (ignore-errors (usocket:socket-close socket))))))


(defun parse-runtime-options (arguments)
  "Parse `runtime install <gvisor|kata> [options]` / `runtime list [options]`."
  (let ((subcommand (first arguments)))
    (cond
      ((string= subcommand "install")
       (let ((name (second arguments))
             (options (list :command :runtime-install
                            :state-directory (namestring (default-state-directory)))))
         (when (or (null name) (uiop:string-prefix-p "--" name))
           (error "usage: gr8s runtime install <gvisor|kata> [options]"))
         (setf (getf options :runtime-name) name)
         (loop for (option value) on (cddr arguments) by #'cddr do
           (cond
             ((string= option "--state-directory") (setf (getf options :state-directory) value))
             ((string= option "--version") (setf (getf options :version) value))
             ((string= option "--release") (setf (getf options :release) value))
             ((string= option "--hypervisor") (setf (getf options :hypervisor) value))
             ((string= option "--sha256") (setf (getf options :sha256) value))
             ((string= option "--bundle") (setf (getf options :bundle-path) value))
             (t (error "unknown runtime install option: ~A" option))))
         options))
      ((string= subcommand "list")
       (let ((options (list :command :runtime-list
                            :state-directory (namestring (default-state-directory)))))
         (loop for (option value) on (rest arguments) by #'cddr do
           (cond
             ((string= option "--state-directory") (setf (getf options :state-directory) value))
             (t (error "unknown runtime list option: ~A" option))))
         options))
      (t (error "unknown runtime subcommand: ~A (use install or list)"
                (or subcommand "<none>"))))))

(defun kubeconfig-ca-data (ca-certificate ca-certificates)
  (let ((octets
          (if ca-certificates
              (babel:string-to-octets
               (with-output-to-string (stream)
                 (dolist (certificate ca-certificates)
                   (write-string (certificate-pem certificate) stream)))
               :encoding :utf-8)
              (pure-tls::read-file-bytes ca-certificate))))
    (ag-grpc:base64-encode octets)))

(defun print-kubeconfig (stream server-url &key ca-certificate ca-certificates
                                             client-certificate client-key)
  "Write an authenticated gr8s administrative kubeconfig to STREAM."
  (unless (and (or ca-certificate ca-certificates) client-certificate client-key)
    (error "a CA certificate, client certificate, and client key are required"))
  (format stream
          "apiVersion: v1~%kind: Config~%clusters:~%  - name: gr8s~%    cluster:~%      certificate-authority-data: ~A~%      server: ~A~%contexts:~%  - name: gr8s~%    context:~%      cluster: gr8s~%      namespace: default~%      user: gr8s~%current-context: gr8s~%users:~%  - name: gr8s~%    user:~%      client-certificate-data: ~A~%      client-key-data: ~A~%"
          (kubeconfig-ca-data ca-certificate ca-certificates) server-url
          (ag-grpc:base64-encode (pure-tls::read-file-bytes client-certificate))
          (ag-grpc:base64-encode (pure-tls::read-file-bytes client-key))))

(defun write-kubeconfig (path server-url &key private ca-certificate ca-certificates
                                             client-certificate client-key)
  "Write a kubeconfig to PATH, readable only by its owner when PRIVATE."
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :if-exists :supersede
                          :if-does-not-exist :create)
    (print-kubeconfig stream server-url :ca-certificate ca-certificate
                      :ca-certificates ca-certificates
                      :client-certificate client-certificate :client-key client-key))
  (when private (sb-posix:chmod path #o600))
  path)

(defun default-kubeconfig-path (options)
  "Return where serve writes its kubeconfig when none was named."
  (merge-pathnames "kubeconfig" (uiop:ensure-directory-pathname (getf options :state-directory))))

(defun write-administrative-kubeconfig (options &optional stream)
  "Write or print a kubeconfig for the existing cluster selected by OPTIONS."
  (let* ((state (uiop:ensure-directory-pathname (getf options :state-directory)))
         (root (merge-pathnames "pki/" state)))
    (unless (and (probe-file (merge-pathnames "pki/cluster-ca.crt" root))
                 (probe-file (merge-pathnames "pki/cluster-ca.key" root)))
      (error "cluster PKI does not exist in the selected state directory"))
    (let ((pki (ensure-cluster-pki root)))
      (multiple-value-bind (certificate key) (ensure-admin-client-credentials pki)
        (if stream
                            (print-kubeconfig stream (getf options :server)
                              :ca-certificates (cluster-pki-trust-certificates pki)
                              :client-certificate certificate :client-key key)
            (write-kubeconfig (getf options :output) (getf options :server)
                              :ca-certificates (cluster-pki-trust-certificates pki)
                              :client-certificate certificate :client-key key :private t))))))

(defun runtime-from-options (options)
  "Construct the Pod runtime OPTIONS select, returning (values runtime manager).
   For containerd in managed mode MANAGER is a supervised containerd and the
   runtime talks to its socket; in external mode the runtime talks to the
   configured socket and MANAGER is NIL; any other runtime is the fake runtime
   with MANAGER NIL."
  (cond
    ;; A runtime made for the agent, such as a browser node's (podster-57fv).
    ((getf options :runtime-object)
     (values (getf options :runtime-object) nil))
    ((string= (getf options :runtime) "containerd")
     (if (string= (getf options :containerd-mode) "managed")
         (let* ((state-directory
                  (uiop:ensure-directory-pathname
                   (getf options :state-directory)))
                (manager
                  (make-managed-containerd
                   :state-directory state-directory
                   :executable (getf options :containerd-executable)
                   :oci-runtime (getf options :containerd-oci-runtime)
                   :metadata-no-sync (getf options :containerd-no-sync)
                   :runtime-assets *embedded-runtime-assets*
                   :cni-mode (getf options :cni-mode)
                   :cni-config-directory (getf options :cni-conf-dir)
                   :cni-bin-directories (getf options :cni-bin-dirs)
                   :extra-runtime-handlers
                   ;; Runtime addons are a node-level resource at the node's
                   ;; state root. serve runs its local agent (and thus
                   ;; containerd) under <state>/agent/, so it passes
                   ;; :runtime-addons-directory to point back at <state>, where
                   ;; the operator installed them. A standalone `gr8s agent`
                   ;; falls back to its own --state-directory.
                   (load-installed-runtime-addons
                    (uiop:ensure-directory-pathname
                     (or (getf options :runtime-addons-directory)
                         (getf options :state-directory))))
                   :cni-bin-directory
                   (uiop:pathname-directory-pathname
                    (pathname (getf options :containerd-executable))))))
           (values
            (make-containerd-runtime
             :socket-path (managed-containerd-socket-path manager)
             :log-root (getf options :containerd-log-root)
             :host-network nil
             :dns-servers (list +dns-pod-server-address+)
             :dns-searches +dns-pod-searches+
             :dns-options +dns-pod-options+
             :registry-credentials
             (when (getf options :registry-credentials-file)
               (load-node-registry-credentials (getf options :registry-credentials-file)))
             :credential-providers
             (when (getf options :image-credential-provider-config)
               (load-image-credential-providers
                (getf options :image-credential-provider-config)
                (uiop:ensure-directory-pathname
                 (getf options :image-credential-provider-bin-dir))))
             :availability (managed-containerd-availability manager))
            manager))
         (values
          (make-containerd-runtime
           :socket-path (getf options :containerd-socket)
           :log-root (getf options :containerd-log-root)
           :host-network nil
           :dns-servers (list +dns-pod-server-address+)
           :dns-searches +dns-pod-searches+
           :dns-options +dns-pod-options+
           :registry-credentials
           (when (getf options :registry-credentials-file)
             (load-node-registry-credentials (getf options :registry-credentials-file)))
           :credential-providers
           (when (getf options :image-credential-provider-config)
             (load-image-credential-providers
              (getf options :image-credential-provider-config)
              (uiop:ensure-directory-pathname
               (getf options :image-credential-provider-bin-dir)))))
          nil)))
    (t
     (values (make-fake-runtime) nil))))

(defun parse-agent-server (server)
  "Split SERVER as HOST:PORT at its last colon, returning (values host port) with
   PORT parsed and range-checked. Signals unless both parts are non-empty."
  (let ((separator (position #\: server :from-end t)))
    (unless (and separator (plusp separator) (< separator (1- (length server))))
      (error "agent server must be HOST:PORT"))
    (values (subseq server 0 separator)
            (parse-port (subseq server (1+ separator))))))

(defun agent-state-path (options name)
  "The pathname of NAME inside the agent's --state-directory."
  (merge-pathnames name
                   (uiop:ensure-directory-pathname
                    (getf options :state-directory))))

(defun parse-agent-servers (server)
  "Parse --server into a list of (host port). Accepts a comma-separated list of
   HOST:PORT so an agent can fail over across HA control-plane members."
  (loop for spec in (uiop:split-string server :separator '(#\,))
        for trimmed = (string-trim '(#\Space) spec)
        unless (zerop (length trimmed))
          collect (multiple-value-bind (host port) (parse-agent-server trimmed)
                    (list host port))))

(defun managed-containerd-options-p (options)
  "True when OPTIONS starts gr8s's managed containerd node services."
  (and (equal "containerd" (getf options :runtime))
       (equal "managed" (getf options :containerd-mode))))

(defun ensure-kubelet-endpoints-available
    (&key (probe #'gr8s.kubelet::kubelet-endpoint-status) (command "agent"))
  "Refuse to replace a live kubelet's host-wide endpoints before node startup."
  (dolist (path +kubelet-host-endpoints+)
    (case (funcall probe path)
      (:active
       (error 'runtime-error
              :message
              (format nil
                      "another kubelet is listening on ~A; stop it (for example, 'sudo systemctl stop k3s')~A"
                      path
                      (if (string= command "serve")
                          " or run 'gr8s serve --disable-agent'"
                          ""))))
      (:non-socket
       (error 'runtime-error
              :message
              (format nil "kubelet endpoint ~A exists and is not a Unix socket; move it out of the way"
                      path)))))
  t)

(defun ensure-running-as-root (&key (command "agent") (euid (sb-posix:geteuid)))
  "Refuse to start a privileged COMMAND when not effectively root.
The managed containerd runtime, the eBPF dataplane, CNI networking and
container mounts all need real root; without it gr8s would otherwise fail deep
in startup -- pulling images, loading a cgroup/connect4 program, or mounting a
Pod -- with an opaque error far from the cause. Fail fast, like kubeadm's
preflight, with one actionable line. EUID is injectable for tests."
  (unless (zerop euid)
    (error 'runtime-error
           :message
           (format nil
                   "gr8s ~A must run as root: the managed containerd runtime, eBPF dataplane and Pod networking require root privileges, but the effective uid is ~D. Re-run with sudo~A."
                   command euid
                   (if (string= command "serve")
                       ", or run a control-plane-only process with 'gr8s serve --disable-agent' (or '--runtime fake'), which needs no privileges"
                       ""))))
  t)

(defconstant +in-cluster-api-port+ 6443
  "Fixed port of the in-cluster apiserver (0.0.0.0:6443) that backs the
\"kubernetes\" Service. It is distinct from the admin API's --port, must be
admitted through the host firewall for cross-node Pods, and is the port a node
agent masquerades Pod->apiserver traffic toward.")

(defun agent (options &key control
                            (stop-predicate (lambda () *shutdown-requested*)))
  "Run a node agent against the control plane at --server until STOP-PREDICATE is
   true, then return 0. Enrolls the node (writing node.key, node.crt and ca.crt)
   when it is not yet enrolled, builds and starts the runtime and the kubelet
   server, then runs the node session -- reconciling desired-state snapshots and
   dispatching operations -- and stops the kubelet and runtime on exit. CONTROL,
   when given, is the session control handle (used by the in-process agent)."
  (when (managed-containerd-options-p options)
    (ensure-running-as-root :command "agent")
    (ensure-kubelet-endpoints-available :command "agent"))
  (let* ((enrollment-endpoints (parse-agent-servers (getf options :server)))
         (session-endpoints
           (parse-agent-servers (or (getf options :session-server)
                                    (getf options :server))))
         (host (first (first session-endpoints)))
         (port (second (first session-endpoints))))
    (let ((node-name (getf options :node-name))
          (private-key (agent-state-path options "node.key"))
          (certificate (agent-state-path options "node.crt"))
          (ca-certificate (agent-state-path options "ca.crt"))
          (identity (agent-state-path options "identity.json"))
          (node-runtime nil)
          (kubelet nil)
          (image-distribution nil))
      (unless (and (probe-file private-key)
                   (probe-file certificate)
                   (probe-file ca-certificate))
        (enroll-node-over-endpoints
         enrollment-endpoints node-name (getf options :token) (getf options :ca-pin)
         private-key certificate ca-certificate))
      (multiple-value-bind (wireguard-private-key wireguard-public-key)
          (ensure-wireguard-key-pair (getf options :state-directory))
        (multiple-value-bind (runtime manager) (runtime-from-options options)
          (when (and manager (containerd-runtime-p runtime))
            (multiple-value-bind (tracker-call tracker-close)
                (gr8s.agent::make-image-tracker-rpc-client
                 host port node-name ca-certificate certificate private-key)
              (gr8s.image-distribution::start-registry-trust
               (agent-state-path options "registry-trust/")
               (loop for (registry . file) in (getf options :registry-cas)
                     collect (cons registry (if (eq file :cluster) ca-certificate file))))
              (setf image-distribution
                    (gr8s.security::start-node-image-distribution
                     (agent-state-path options "images/")
                     tracker-call tracker-close ca-certificate certificate private-key
                     (or (getf options :node-address)
                         (discover-local-primary-ipv4)
                         "127.0.0.1"))
                    (gr8s.runtime.containerd::containerd-runtime-registry-host-config-directory runtime)
                    (managed-containerd-directory manager "containerd/certs.d")
                    (gr8s.runtime.containerd::containerd-runtime-image-mirror-port runtime)
                    (gr8s.security::node-image-distribution-mirror-port image-distribution))
              ;; Admit this node's image-peer listener so peers on other nodes
              ;; can fetch blobs from it; without the rule a host firewall drops
              ;; the mirror's cross-node P2P fetch and it falls back to origin.
              (ignore-errors
                (ensure-image-peer-firewall
                 gr8s.security::+image-peer-default-port+))
              ;; Source-NAT cross-node Pod->apiserver traffic to this node's IP.
              ;; The "kubernetes" Service endpoint is the control plane's node IP,
              ;; so without this the reply path is asymmetric and the stateful
              ;; host firewall drops it (TLS handshake timeout in e2e BeforeSuite).
              ;; Skipped for a loopback control plane (this node's own agent).
              (ignore-errors
                (ensure-apiserver-masquerade host +in-cluster-api-port+))
              ;; Admit the Service NodePort range so Pods and off-node clients
              ;; can reach <nodeIP>:<nodePort> relays; without it the host
              ;; firewall rejects the port and NodePort Services fail
              ;; (EHOSTUNREACH), as do their conformance tests.
              (ignore-errors
                (ensure-node-port-range-firewall
                 +node-port-minimum+ +node-port-maximum+))))
          (setf node-runtime
              (make-node-runtime
               (agent-state-path options "runtime/") runtime manager
               :wireguard-private-key wireguard-private-key
               :dns-forward-rules (getf options :dns-forward-rules)
               :dns-serve-zones (getf options :dns-serve-zones)
               :cpu-manager-policy (getf options :cpu-manager-policy "none")
               :reserved-cpus (getf options :reserved-cpus)
               :topology-manager-policy (getf options :topology-manager-policy "none")))
        (setf (node-runtime-node-name node-runtime) node-name)
        (setf (gr8s.agent::node-runtime-node-id node-runtime)
              (gethash "nodeId" (load-agent-identity identity node-name) ""))
        (unwind-protect
             (progn
               (start-node-runtime node-runtime)
               ;; serve issues its own agent's kubelet certificates (CONTROL marks that
               ;; agent); a standalone agent gets them from the control plane, and its
               ;; kubelet, with no API server beside it, asks that host's to review callers.
               (when (and (null control) (managed-containerd-options-p options)
                          (plusp (or (getf options :kubelet-port) 0)))
                 (unless (getf options :kubelet-api-server)
                   (setf (getf options :kubelet-api-server)
                         (format nil "~A:~D" host +in-cluster-api-port+)))
                 (when (gr8s.agent::kubelet-credentials-due-p (getf options :state-directory))
                   (gr8s.agent::request-kubelet-credentials
                    host port node-name (getf options :state-directory)
                    :underlay-address (getf options :node-address))))
               (setf kubelet (start-agent-kubelet-server
                              options node-name runtime
                              :network-metrics-function
                              (lambda ()
                                (gr8s.agent:node-runtime-wireguard-metrics-text
                                 node-runtime))))
               ;; serve admits its own agent's kubelet port; a standalone agent admits its own.
               (when (and kubelet (null control))
                 (ignore-errors
                   (ensure-control-plane-firewall nil :kubelet-port (getf options :kubelet-port))))
               ;; Enrolled, runtime up, kubelet serving: the node is ready even
               ;; though the session below reconnects for the process lifetime.
               (notify-service-manager-ready)
               (run-node-session
                host port node-name identity
                (lambda (snapshot)
                  (setf (gr8s.agent::node-runtime-node-id node-runtime)
                        (gethash "nodeId" (load-agent-identity identity node-name) ""))
                  (reconcile-node-snapshot node-runtime snapshot))
                :endpoints session-endpoints
                :snapshot-observer (lambda (snapshot) (receive-node-snapshot-intent node-runtime snapshot))
                :gateway-config-handler
                (lambda (update) (gr8s.agent::reconcile-node-gateway-config node-runtime update))
                :gateway-session-reset
                (lambda () (gr8s.agent::reset-node-gateway-session node-runtime))
                :operation-handler
                (lambda (variant payload emit)
                  (dispatch-node-operation node-runtime variant payload emit))
                :status-provider (lambda () (node-runtime-status node-runtime))
                :runtime-health (lambda () (runtime-unavailable-message runtime))
                :credential-token-function-setter
                (when (containerd-runtime-p runtime)
                  (lambda (function)
                    (setf (containerd-runtime-credential-provider-token-function runtime) function)))
                :wireguard-public-key wireguard-public-key
                :wireguard-endpoints (getf options :wireguard-endpoints)
                :capabilities
                (when (and (gr8s.agent::node-runtime-service-lb node-runtime)
                           (service-lb-map
                            (gr8s.agent::node-runtime-service-lb node-runtime)
                            "gr8s_nat_risk_v2"))
                  (list "service-risk-v2"))
                :ca-certificate-path ca-certificate
                :certificate-path certificate :private-key-path private-key
                :underlay-address (getf options :node-address)
                :reconnect-delay 0.1 :control control
                :kubelet-port (if kubelet (getf options :kubelet-port) 0)
                :stop-predicate stop-predicate))
          (when kubelet (stop-kubelet-server kubelet))
          (stop-node-runtime node-runtime)
          (when image-distribution
            (ignore-errors
              (remove-image-peer-firewall gr8s.security::+image-peer-default-port+))
            (ignore-errors
              (remove-apiserver-masquerade host +in-cluster-api-port+))
            (ignore-errors
              (remove-node-port-range-firewall
               +node-port-minimum+ +node-port-maximum+))
            (gr8s.security::stop-node-image-distribution image-distribution)))))))
  0)

(defstruct local-node-agent
  thread
  control)

(defun kubelet-serving-addresses (local-addresses options)
  "The IPv4 SANs for a kubelet serving certificate: every LOCAL-ADDRESSES entry plus
the configured node addresses and loopback, deduplicated, with NIL, empty and the
unspecified 0.0.0.0 dropped. The apiserver (and a Prometheus kubelet scrape) reaches
the kubelet at the node InternalIP -- the WireGuard underlay -- so it must be a SAN,
alongside the LAN primary and 127.0.0.1 (podster-6ls)."
  (remove-duplicates
   (remove-if (lambda (address) (or (null address) (zerop (length address))
                                    (string= address "0.0.0.0")))
              (append local-addresses
                      (list (getf options :node-address)
                            (getf options :node-listen)
                            "127.0.0.1")))
   :test #'equal))

(defun start-local-node-agent
    (server pki node-name state-directory &optional runtime-options
     &key endpoints session-endpoints)
  "Start serve's in-process node agent on its own thread and return the
   LOCAL-NODE-AGENT handle. Points the agent at the local node SERVER over
   loopback, mints a join token from PKI when STATE-DIRECTORY holds no enrollment
   yet, and issues kubelet credentials only for a managed containerd node with a
   kubelet port (otherwise the kubelet is disabled). RUNTIME-OPTIONS seed the
   agent's options; without them it runs the fake runtime."
  (let* ((directory (uiop:ensure-directory-pathname state-directory))
         (certificate (merge-pathnames "node.crt" directory))
         (token (unless (probe-file certificate)
                  (create-join-token pki node-name)))
         (worker (make-local-node-agent
                  :control (make-node-session-control)))
         (options (or (and runtime-options (copy-list runtime-options))
                      (list :runtime "fake"))))
    (setf (getf options :command) :agent
          (getf options :server)
          (format nil "~{~A~^,~}"
                  (mapcar (lambda (endpoint)
                            (format nil "~A:~D" (first endpoint) (second endpoint)))
                          (or endpoints
                              (list
                               (list
                                (let ((host (getf options :node-listen "127.0.0.1")))
                                  (if (string= host "0.0.0.0") "127.0.0.1" host))
                                (node-grpc-server-port server))))))
          (getf options :session-server)
          (format nil "~{~A~^,~}"
                  (mapcar (lambda (endpoint)
                            (format nil "~A:~D" (first endpoint) (second endpoint)))
                          (or session-endpoints endpoints
                              (list
                               (list
                                (let ((host (getf options :node-listen "127.0.0.1")))
                                  (if (string= host "0.0.0.0") "127.0.0.1" host))
                                (node-grpc-server-port server))))))
          (getf options :token) token
          (getf options :ca-pin) (cluster-pki-ca-fingerprint pki)
          (getf options :node-name) node-name
          (getf options :state-directory) (namestring directory)
          ;; Containerd runs under <node-state>/agent/, but runtime addons live
          ;; at the node state root the operator manages, so look for them in the
          ;; parent of this agent directory.
          (getf options :runtime-addons-directory)
          (namestring (uiop:pathname-parent-directory-pathname directory)))
    ;; Only a managed containerd node has the in-cluster API its kubelet delegates reviews to.
    (if (and (plusp (or (getf options :kubelet-port) 0))
             (equal "containerd" (getf options :runtime)) (equal "managed" (getf options :containerd-mode)))
        ;; The serving cert must carry the node's InternalIP (the apiserver proxies
        ;; to the kubelet there, as does a Prometheus kubelet scrape), not just the
        ;; default-route source -- the InternalIP is the WireGuard underlay address,
        ;; while discover-local-primary-ipv4 returns the LAN primary (podster-6ls).
        (issue-kubelet-credentials
         pki directory node-name
         (kubelet-serving-addresses
          (append (ignore-errors (gr8s.network::host-ipv4-addresses))
                  (list (discover-local-primary-ipv4)))
          options))
        (setf (getf options :kubelet-port) 0))
    (when (managed-containerd-options-p options)
      ;; Run synchronously so serve's top-level error handler prints one concise
      ;; diagnostic instead of an unhandled backtrace from the local-agent thread.
      (ensure-kubelet-endpoints-available :command "serve"))
    (if (getf options :architecture)
        (setf (gethash node-name gr8s.agent::*agent-architectures*) (getf options :architecture))
        (remhash node-name gr8s.agent::*agent-architectures*))
    (setf (local-node-agent-thread worker)
          (bt:make-thread
           (lambda ()
             (agent options
                    :control (local-node-agent-control worker)))
           :name "gr8s local node agent"))
    worker))

(defun stop-local-node-agent (worker)
  "Stop the in-process node agent WORKER: cancel its session, wait briefly for its
   thread to exit, forcibly destroy it if it will not, and join it. Returns NIL."
  (cancel-node-session (local-node-agent-control worker))
  (let ((thread (local-node-agent-thread worker)))
    (when thread
      (loop repeat 200
            while (bt:thread-alive-p thread)
            do (sleep 0.01))
      (when (bt:thread-alive-p thread)
        (ignore-errors (bt:destroy-thread thread)))
      (ignore-errors (bt:join-thread thread))))
  nil)

(defun request-shutdown (&rest ignored)
  "Request cooperative shutdown by setting *SHUTDOWN-REQUESTED*. Ignores its
   arguments so it can serve directly as a signal handler."
  (declare (ignore ignored))
  (setf *shutdown-requested* t))

(defvar *stale-timeout-guard-installed* nil
  "True once unhandled timeouts no longer end the process.")

(defun install-stale-timeout-guard ()
  "Continue from a timeout that nothing handles, rather than ending the whole process.
Timers interrupt their target thread, so one firing as its WITH-TIMEOUT scope exits can
arrive afterward, in unrelated code such as a lock wait. A timeout still in scope has a
handler and never gets here. A busy host makes this race likely."
  (unless *stale-timeout-guard-installed*
    (let ((previous sb-ext:*invoke-debugger-hook*))
      (setf *stale-timeout-guard-installed* t
            sb-ext:*invoke-debugger-hook*
            (lambda (condition hook)
              (when (typep condition '(or sb-ext:timeout bt2:timeout))
                ;; Only the signal's own restart: FIND-RESTART also returns unrelated outer ones.
                (let ((restart (find-if (lambda (candidate)
                                          (and (eq 'continue (restart-name candidate))
                                               (member condition
                                                       (sb-kernel::restart-associated-conditions candidate))))
                                        (compute-restarts condition))))
                  (when restart
                    (format *error-output* "gr8s ignored a late timeout in thread ~A: ~A~%"
                            (sb-thread:thread-name sb-thread:*current-thread*) condition)
                    (invoke-restart restart))))
              (when previous (funcall previous condition hook)))))))

(defvar *prompt-fatal-exit-installed* nil)

(defconstant +fatal-exit-timeout-seconds+ 10
  "How long a process ending on an unhandled error waits for its threads to unwind.")

(defun install-prompt-fatal-exit ()
  "End promptly on an error nothing handles. SBCL's quit waits SB-EXT:*EXIT-TIMEOUT*, 60
seconds, for every thread to unwind, and a control-plane member sat that long with its
listeners closed before systemd could restart it (podster-2aum). Installed before the hooks
that recover from some conditions, it runs only once the process is ending."
  (unless *prompt-fatal-exit-installed*
    (let ((previous sb-ext:*invoke-debugger-hook*))
      (setf *prompt-fatal-exit-installed* t
            sb-ext:*invoke-debugger-hook*
            (lambda (condition hook)
              (when previous
                (setf sb-ext:*exit-timeout* (min sb-ext:*exit-timeout* +fatal-exit-timeout-seconds+))
                (funcall previous condition hook)))))))

(defun install-shutdown-handlers ()
  "On SBCL, install signal handlers: SIGINT and SIGTERM request cooperative
   shutdown, and SIGUSR1 dumps thread backtraces."
  #+sbcl
  (progn
    (sb-sys:enable-interrupt sb-unix:sigint #'request-shutdown)
    (sb-sys:enable-interrupt sb-unix:sigterm #'request-shutdown)
    (sb-sys:enable-interrupt sb-unix:sigusr1 #'dump-thread-backtraces)))

(defstruct reconciliation-worker
  reconciler
  observer
  before-reconcile
  gateway-reconcile
  ;; HA (podster-c2d.7): a nullary predicate that is true when this control
  ;; plane may act as the cluster leader. When set and false, the pass is
  ;; skipped so controllers only drive reconciliation on the Raft leader; NIL
  ;; (the default) always runs, keeping the single-node path unchanged.
  leader-gate
  (leader-active nil)
  (leadership-generation 0)
  thread
  gateway-thread
  (gateway-pending nil)
  (gateway-wake-up (bt:make-condition-variable :name "gr8s Gateway reconciliation wake-up"))
  (stop-requested nil)
  (pending nil)
  pending-scope
  (pass-scope :full)
  (full-repair-deadline 0)
  resource-change-observer
  (interval 1.0)
  (shutdown-timeout 5.0)
  (metrics-attempts 0)
  (metrics-completed 0)
  (metrics-failures 0)
  (metrics-in-flight 0)
  (metrics-duration-total 0)
  (metrics-duration-last 0)
  (metrics-duration-max 0)
  metrics-last-success
  (lock (bt:make-lock "gr8s reconciliation worker"))
  (wake-up (bt:make-condition-variable :name "gr8s reconciliation wake-up")))

(defun reconciliation-worker-stopping-p (worker)
  "True when WORKER has been asked to stop (read under its lock)."
  (bt:with-lock-held ((reconciliation-worker-lock worker))
    (reconciliation-worker-stop-requested worker)))

(defun invalidate-reconciliation-leadership (worker)
  "An observed leadership loss invalidates even a still-running full repair."
  (bt:with-lock-held ((reconciliation-worker-lock worker))
    (incf (reconciliation-worker-leadership-generation worker))
    (setf (reconciliation-worker-leader-active worker) nil)))

(defun request-reconciliation (worker &key (scope :full))
  "Queue Gateway publication independently after a successful leader repair."
  (bt:with-lock-held ((reconciliation-worker-lock worker))
    (unless (reconciliation-worker-stop-requested worker)
      (when (and (eq scope :gateway) (reconciliation-worker-gateway-reconcile worker)
                 (reconciliation-worker-leader-active worker))
        (setf (reconciliation-worker-gateway-pending worker) t)
        (bt:condition-notify (reconciliation-worker-gateway-wake-up worker))
        (return-from request-reconciliation nil))
      (when (or (not (reconciliation-worker-pending worker)) (not (eq scope :gateway)))
        (setf (reconciliation-worker-pending-scope worker)
              (if (eq scope :gateway) :gateway :full)))
      (unless (reconciliation-worker-pending worker)
        (setf (reconciliation-worker-pending worker) t)
        (bt:condition-notify (reconciliation-worker-wake-up worker))))))

(defun reconciliation-deadline (seconds &optional (now (get-internal-real-time)))
  "Keep the running clock integral so long uptimes retain subsecond precision."
  (+ now (round (* seconds internal-time-units-per-second))))

(defun wait-for-reconciliation (worker)
  "Wait for pending work or the periodic repair deadline; batch for at most 5ms."
  (bt:with-lock-held ((reconciliation-worker-lock worker))
    (flet ((remaining (deadline)
             (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))
      (let ((deadline (reconciliation-worker-full-repair-deadline worker)))
        (loop until (or (reconciliation-worker-stop-requested worker)
                        (reconciliation-worker-pending worker)
                        (<= (remaining deadline) 0))
              do (bt:condition-wait (reconciliation-worker-wake-up worker)
                                   (reconciliation-worker-lock worker)
                                   :timeout (max 0.000001 (remaining deadline)))))
      (when (reconciliation-worker-pending worker)
        ;; A fixed deadline cannot be extended indefinitely by continuous writes.
        (let ((deadline (reconciliation-deadline 0.005)))
          (loop until (or (reconciliation-worker-stop-requested worker)
                          (<= (remaining deadline) 0))
                do (bt:condition-wait (reconciliation-worker-wake-up worker)
                                     (reconciliation-worker-lock worker)
                                     :timeout (max 0.000001 (remaining deadline)))))))))

(defun reconciliation-worker-loop (worker)
  "Drive WORKER's reconciliation passes until it is asked to stop. Each iteration,
   when the leader gate is absent or returns true, runs the before-reconcile hook
   and a full reconcile pass; errors and stray timeouts are logged, not
   propagated, so one bad pass never kills the loop. Between passes it waits on the
   wake-up condition for up to the configured interval, so a stop or a notify wakes
   it promptly."
  (loop
        do (bt:with-lock-held ((reconciliation-worker-lock worker))
             (when (reconciliation-worker-stop-requested worker) (return))
             ;; Everything committed before this point is covered by this pass.
             ;; Later changes keep PENDING set for a follow-up, even during a pass.
             (setf (reconciliation-worker-pass-scope worker)
                   :full
                   (reconciliation-worker-pending worker) nil
                   (reconciliation-worker-pending-scope worker) nil))
           (handler-case
               ;; Only drive controllers when we hold leadership; a follower
               ;; reconciles nothing and simply waits to be promoted.
               (let ((generation (bt:with-lock-held ((reconciliation-worker-lock worker))
                                   (reconciliation-worker-leadership-generation worker))))
                 (if (let ((gate (reconciliation-worker-leader-gate worker)))
                     (or (null gate) (funcall gate)))
                   (progn
                     (call-with-reconciliation-metrics
                      worker (lambda () (run-controller-pass worker)))
                     (if (let ((gate (reconciliation-worker-leader-gate worker)))
                           (or (null gate) (funcall gate)))
                         (bt:with-lock-held ((reconciliation-worker-lock worker))
                           (when (= generation (reconciliation-worker-leadership-generation worker))
                             (setf (reconciliation-worker-leader-active worker) t)))
                         (invalidate-reconciliation-leadership worker)))
                   (invalidate-reconciliation-leadership worker)))
             ;; Timeouts are serious conditions, not errors, and a late one can land here.
             ((or error sb-ext:timeout bt2:timeout) (error)
               (format *error-output* "gr8s reconciliation error: ~A~%" error)))
           (when (eq (reconciliation-worker-pass-scope worker) :full)
             (bt:with-lock-held ((reconciliation-worker-lock worker))
               (setf (reconciliation-worker-full-repair-deadline worker)
                     (reconciliation-deadline (reconciliation-worker-interval worker)))))
           (wait-for-reconciliation worker)))

(defun gateway-reconciliation-admitted-p (worker)
  "Admit only against the repaired generation that survives the leadership check."
  (let ((generation (bt:with-lock-held ((reconciliation-worker-lock worker))
                      (and (reconciliation-worker-leader-active worker)
                           (reconciliation-worker-leadership-generation worker)))))
    (and generation
         (let ((gate (reconciliation-worker-leader-gate worker)))
           (or (null gate) (funcall gate)))
         (bt:with-lock-held ((reconciliation-worker-lock worker))
           (and (not (reconciliation-worker-stop-requested worker))
                (reconciliation-worker-leader-active worker)
                (= generation (reconciliation-worker-leadership-generation worker)))))))

(defun gateway-reconciliation-worker-loop (worker)
  "Publish deltas independently of controller repair. Node fences still serialize delivery."
  (loop
    (bt:with-lock-held ((reconciliation-worker-lock worker))
      (loop until (or (reconciliation-worker-stop-requested worker)
                      (reconciliation-worker-gateway-pending worker))
            do (bt:condition-wait (reconciliation-worker-gateway-wake-up worker)
                                 (reconciliation-worker-lock worker)))
      (when (reconciliation-worker-stop-requested worker) (return))
      ;; Batch against a fixed deadline, even under continuous writes.
      (let ((deadline (reconciliation-deadline 0.005)))
        (loop for remaining = (- deadline (get-internal-real-time))
              while (and (plusp remaining) (not (reconciliation-worker-stop-requested worker)))
              do (bt:condition-wait (reconciliation-worker-gateway-wake-up worker)
                                   (reconciliation-worker-lock worker)
                                   :timeout (/ remaining internal-time-units-per-second))))
      (when (reconciliation-worker-stop-requested worker) (return))
      (setf (reconciliation-worker-gateway-pending worker) nil))
    (handler-case
        (if (gateway-reconciliation-admitted-p worker)
            (call-with-reconciliation-metrics
             worker (lambda ()
                      (gr8s.kubelet::call-with-discovery-projection-cache
                       (reconciliation-worker-gateway-reconcile worker))))
            (progn
              (invalidate-reconciliation-leadership worker)
              (request-reconciliation worker)))
      ((or error sb-ext:timeout bt2:timeout) (condition)
        (format *error-output* "gr8s Gateway reconciliation error: ~A~%" condition)
        ;; Full repair is the recovery path even without another resource write.
        (request-reconciliation worker)))))

(defun start-reconciliation-worker (reconciler &key (interval 1.0) observer before-reconcile
                                                     leader-gate watch-resources gateway-reconcile resource-change-handler)
  "Start a worker with periodic repair and optional committed-resource wakeups.
WATCH-RESOURCES is enabled for the control plane; the agent's local periodic
worker keeps its existing cadence. LEADER-GATE still gates every pass."
  (let* ((worker (make-reconciliation-worker
                  :reconciler reconciler :interval interval :observer observer
                  :before-reconcile before-reconcile :leader-gate leader-gate
                  :gateway-reconcile gateway-reconcile))
         (store (gr8s.kubelet::reconciler-store reconciler))
         (callback (when watch-resources
                     (lambda ()
                       (let ((scope gr8s.resources::*core-resource-change-scope*))
                         (when resource-change-handler
                           (handler-case
                               (funcall resource-change-handler gr8s.resources::*core-resource-changes*)
                             (error (condition)
                               (setf scope :full)
                               (format *error-output* "gr8s change collection failed; requesting full repair: ~A~%" condition))))
                         (request-reconciliation worker :scope scope))))))
    (when callback
      (setf (reconciliation-worker-resource-change-observer worker) callback)
      (gr8s.resources::add-core-resource-change-observer store callback))
    (handler-case
        (progn
          (setf (reconciliation-worker-thread worker)
              (bt:make-thread (lambda () (reconciliation-worker-loop worker))
                              :name "gr8s reconciler"))
          (when gateway-reconcile
            (setf (reconciliation-worker-gateway-thread worker)
                  (bt:make-thread (lambda () (gateway-reconciliation-worker-loop worker))
                                  :name "gr8s Gateway publisher"))))
      (error (condition)
        (stop-reconciliation-worker worker)
        (error condition)))
    worker))

(defun stop-reconciliation-worker (worker)
  "Ask WORKER to stop and wake its thread, wait up to the worker's shutdown
   timeout for the thread to exit, forcibly destroy it (with a warning) if it
   overruns, then join it. Returns NIL."
  ;; Store -> worker is the notification lock order. Unsubscribe before taking
  ;; the worker lock, and leave no callback retaining a stopped worker.
  (when (reconciliation-worker-resource-change-observer worker)
    (gr8s.resources::remove-core-resource-change-observer
     (gr8s.kubelet::reconciler-store (reconciliation-worker-reconciler worker))
     (reconciliation-worker-resource-change-observer worker))
    (setf (reconciliation-worker-resource-change-observer worker) nil))
  (bt:with-lock-held ((reconciliation-worker-lock worker))
    (setf (reconciliation-worker-stop-requested worker) t)
    (bt:condition-notify (reconciliation-worker-wake-up worker))
    (bt:condition-notify (reconciliation-worker-gateway-wake-up worker)))
  (dolist (thread (list (reconciliation-worker-thread worker)
                       (reconciliation-worker-gateway-thread worker)))
    (when thread
      (let ((deadline (+ (get-internal-real-time)
                         (* (reconciliation-worker-shutdown-timeout worker)
                            internal-time-units-per-second))))
        (loop while (and (bt:thread-alive-p thread)
                         (< (get-internal-real-time) deadline))
              do (sleep 0.01))
        (when (bt:thread-alive-p thread)
          (format *error-output*
                  "gr8s reconciliation worker did not stop in time; terminating it.~%")
          (bt:destroy-thread thread))
        (handler-case (bt:join-thread thread)
          (error () nil)))))
  nil)

(defun serve-dials-pods-through-agents-p (options)
  "Return whether serve reaches Pods and nodes through their agents' own sessions, so that no
node needs to be reachable from the control plane. Only --pod-network-egress direct says not."
  (not (equal "direct" (getf options :pod-network-egress "agent"))))

(defun serve-bootstraps-cluster-p (options local-agent ha)
  "Return whether serve creates the standard namespaces and default ClusterRoles at startup.
A single control plane is a real cluster whether its agents are local or remote, so it
always does. A Raft member does so only with a local managed containerd agent, as before:
its writes need the Raft leader, which a member may not yet be (or ever be) at startup."
  (or (null ha)
      (and local-agent (equal "containerd" (getf options :runtime))
           (equal "managed" (getf options :containerd-mode)))))

(defparameter *recovery-wait-report-seconds* '(10 . 30)
  "How long WAIT-FOR-HA-APPLICATION waits before its first report of why, and
between later ones. An ordinary restart recovers within the first.")

(defun wait-for-ha-application (ha)
  "Keep Raft listening while application-dependent services wait for catch-up.
   While blocked, periodically log WHY: the quorum arithmetic and which members
   have never been heard from, so a quorum lost forever is diagnosable from the
   journal instead of an eternally silent wait (podster-0d9)."
  (when ha
    (let ((store (ha-control-plane-store ha)) (member (ha-control-plane-member ha))
          (next-report 0) (next-extend 0))
      (when (gr8s.store::store-access-blocked-p store)
        (format t "gr8s HA: waiting for committed application recovery~%")
        (finish-output))
      (loop while (and (not *shutdown-requested*) (gr8s.store::store-access-blocked-p store))
            do (unless (and (gr8s.raft.transport::raft-member-running member)
                            (bt:thread-alive-p (gr8s.raft.transport::raft-member-tick-thread member)))
                 (error "Raft clock stopped before application recovery completed"))
               ;; The recovery wait is deliberately unbounded -- an operator ends a
               ;; permanently lost quorum with --cluster-reset -- so a live, still-
               ;; recovering member must not be killed on the Type=notify start
               ;; timeout and restart-looped (podster-lmm). Keep pushing the start
               ;; deadline out while we loop; the 90s extension outlasts the 20s
               ;; re-send interval, so systemd only fires once we stop looping.
               (when (>= (get-internal-real-time) next-extend)
                 (notify-service-manager-extend-timeout 90)
                 (setf next-extend (+ (get-internal-real-time)
                                      (* 20 internal-time-units-per-second))))
               (when (>= (get-internal-real-time) next-report)
                 ;; First report after a grace period: an ordinary restart
                 ;; recovers within seconds and deserves no quorum lecture.
                 (when (plusp next-report)
                   ;; A report that fails must say so: silence here reads as
                   ;; "nothing to report" while the member waits for ever.
                   (format t "~A~%" (handler-case (gr8s.ha:ha-recovery-wait-report ha)
                                      (error (condition)
                                        (format nil "gr8s HA: still waiting for committed application recovery; the report of why failed: ~A"
                                                condition))))
                   (finish-output))
                 (setf next-report (+ (get-internal-real-time)
                                      (* (if (plusp next-report)
                                             (cdr *recovery-wait-report-seconds*)
                                             (car *recovery-wait-report-seconds*))
                                         internal-time-units-per-second))))
               (sleep 0.05))))
  (not *shutdown-requested*))

(defun serve (options)
  "Own state before any application/PKI initialization, through final teardown."
  (call-with-serve-state-ownership options (lambda () (serve-owned options))))

(defun run-serve-command (options)
  "Own state before any application/PKI initialization, through final teardown."
  (call-with-serve-state-ownership
   options
   (lambda ()
     (when (and (not (getf options :disable-agent))
                (managed-containerd-options-p options))
       ;; Fail before opening the store, PKI, listeners, or containerd. The
       ;; top-level handler then emits one actionable line without a worker
       ;; thread backtrace.
       (ensure-running-as-root :command "serve")
       (ensure-kubelet-endpoints-available :command "serve"))
     (serve-owned options))))

(defun serve-owned (options)
  "Run the gr8s control plane until shutdown, returning 0. Opens the store and
   PKI, starts the memory monitor, optional HA/Raft, and the node gRPC server
   (opening its firewalld port when it listens off loopback); unless
   --disable-agent, starts an in-process local node agent, and on a managed
   containerd node also brings up the API aggregator and Service network.
   Writes an authenticated kubeconfig, serves the HTTPS API, and runs the
   reconciliation worker. On *SHUTDOWN-REQUESTED* it tears every component down in
   reverse, withdrawing the firewalld port it opened."
  (require-serve-state-ownership options)
  (let* ((address (getf options :listen))
         (port (getf options :port))
         ;; The admin API (ADDRESS:PORT above, e.g. a loopback port reached over
         ;; an SSH tunnel) is distinct from the in-cluster API, which always
         ;; listens on 0.0.0.0:+IN-CLUSTER-API-PORT+ so Pods can reach it through
         ;; the "kubernetes" Service. The Service endpoint must advertise this
         ;; port, never the admin PORT: advertising PORT points 10.96.0.1:443 at
         ;; a loopback-only admin listener and every in-cluster API call is
         ;; refused. Bind it once and feed both the listener and the endpoint.
         (in-cluster-api-port +in-cluster-api-port+)
         (state-directory
           (uiop:ensure-directory-pathname (getf options :state-directory)))
         ;; Start before the store opens: open-store and the HA join/catch-up below
         ;; can outlast TimeoutStartSec on a cold rejoin, before wait-for-ha-application
         ;; starts extending the deadline (podster-qoa). The keepalive covers that gap.
         (startup-timeout-keepalive (start-startup-timeout-keepalive))
         (store (progn
                  (when (or (getf options :raft-init) (getf options :raft-join))
                    (gr8s.raft.transport::raft-reap-snapshot-directory
                     (merge-pathnames "raft/transfers/" state-directory)))
                  (open-store state-directory
                              :defer-restore-completion
                              (and (or (getf options :raft-init) (getf options :raft-join)) t))))
         (pool (ensure-controller-node-pool store state-directory options))
         (pki (ensure-control-plane-pki state-directory options))
         (server nil)
         (debug-port nil)
         (api-server nil)
         (service-network-created nil)
         (aggregator nil)
         (worker nil)
         (node-server nil)
         (ha nil)
         (memory-monitor nil)
         (local-agent nil)
         (virtual-nodes nil)
         (browser-join nil)
         (pki-authority-observer nil)
         (kubeconfig-path nil))
    (setf *shutdown-requested* nil)
    (install-shutdown-handlers)
    (unwind-protect
         (progn
           (setf memory-monitor (start-memory-monitor store))
           (setf ha (maybe-start-ha-control-plane store pki options))
           (unless (wait-for-ha-application ha) (return-from serve-owned 0))
           (check-cluster-format-level store)
           (when ha
             (ensure-ha-pki-authority store ha)
             ;; Extraction can promote a different CA than the one loaded before
             ;; Raft joined. All subsequently started listeners receive this object.
             (setf pki (ensure-cluster-pki (merge-pathnames "pki/" state-directory)))
             (setf pki-authority-observer
                   (lambda ()
                     (let ((current
                             (ensure-cluster-pki
                              (merge-pathnames "pki/" state-directory))))
                       ;; PKI is a lexical cell also captured by certificate
                       ;; reconcilers started below, so future issuance follows
                       ;; the replicated active signer as well.
                       (setf pki current)
                       (multiple-value-bind (certificate key)
                           (ensure-apiserver-kubelet-client-credentials current)
                         (setf *kubelet-proxy-credentials*
                               (list (cluster-pki-trust-certificates current)
                                     certificate key)))
                       (when node-server
                         (refresh-node-grpc-server-pki node-server current))
                       (when server
                         (ensure-kubernetes-api-credentials
                          current :addresses
                          (list address (serve-api-advertise-address options)))
                         (setf (slot-value server 'gr8s.apiserver::client-ca)
                               (cluster-pki-trust-certificates current)))
                       (when kubeconfig-path
                         (multiple-value-bind (admin-certificate admin-key)
                             (ensure-admin-client-credentials current)
                           (write-kubeconfig
                            kubeconfig-path
                            (format nil "https://~A:~D"
                                    (serve-api-advertise-address options) port)
                            :ca-certificates (cluster-pki-trust-certificates current)
                            :client-certificate admin-certificate :client-key admin-key
                            :private (null (getf options :kubeconfig)))))
                       (when (pod-store-in-cluster-config store)
                         (setf (getf (pod-store-in-cluster-config store) :ca-pem)
                               (uiop:read-file-string
                                (cluster-pki-ca-certificate-path current)))))))
             (gr8s.resources::add-pki-authority-observer
              store pki-authority-observer))
           (multiple-value-bind (certificate key) (ensure-apiserver-kubelet-client-credentials pki)
             (setf *kubelet-proxy-credentials*
                   (list (cluster-pki-trust-certificates pki) certificate key)))
           ;; Refuse to expose the node control plane without authentication.
           ;; Without PKI the node listener is plaintext and trusts the hello's
           ;; node-name with no credential; a misconfiguration must fail loudly
           ;; rather than silently serve an unauthenticated node control plane.
           (unless (or pki (getf options :insecure-node-listener))
             (error "Refusing to start the node control-plane listener without PKI: ~
                     node sessions would be unauthenticated and plaintext. Configure ~
                     cluster PKI, or set :insecure-node-listener for a deliberate ~
                     test/dev insecure listener."))
           (setf node-server
                 (start-node-grpc-server
                  store :host (getf options :node-listen "127.0.0.1")
                  :port (getf options :node-port)
                  :session-admission-fn
                  (when ha (lambda () (ha-control-plane-admits-node-sessions-p ha)))
                  :session-endpoints-fn
                  (when ha
                    (lambda ()
                      (ha-control-plane-node-session-endpoints ha (getf options :node-port))))
                  :pki pki :cluster-pod-cidr (gethash "clusterPodCIDR" pool)
                  :node-prefix (gethash "nodePrefix" pool)
                  :cluster-pod-cidrs (node-pool-cluster-cidrs pool)
                  :node-prefixes (node-pool-prefixes pool)
                  :overlay-backend (getf options :overlay-backend)
                  :mtu (getf options :mtu)
                  :wireguard-listen-port 51820
                  :wireguard-relay-address (getf options :wireguard-relay-address)
                  :wireguard-relay-listen (getf options :wireguard-relay-listen)
                  :wireguard-relay-port-start (getf options :wireguard-relay-port-start)
                  :wireguard-relay-max-channels
                  (getf options :wireguard-relay-max-channels)))
           ;; Close the registration race with an authority application between
           ;; the initial reload and listener construction.
           (when pki-authority-observer
             (funcall pki-authority-observer))
           (when ha
             (configure-raft-node-operation-routing
              (ha-control-plane-member ha) node-server))
           ;; Admit the routable, authenticated node endpoints through an active
           ;; host firewalld. The enrollment port is omitted for a loopback-only
           ;; node server; the kubelet port is omitted unless serve will start a
           ;; managed local containerd agent. No-op without firewalld; fail-soft.
           (ignore-errors
             (ensure-control-plane-firewall
              (unless (string= "127.0.0.1" (getf options :node-listen "127.0.0.1"))
                (getf options :node-port))
              :kubelet-port
              (when (and (not (getf options :disable-agent))
                         (equal "containerd" (getf options :runtime))
                         (equal "managed" (getf options :containerd-mode)))
                (getf options :kubelet-port))
              ;; A managed-containerd control-plane node also hosts the in-cluster
              ;; apiserver (0.0.0.0:IN-CLUSTER-API-PORT) that backs the "kubernetes"
              ;; Service; admit it so Pods on other nodes can reach 10.96.0.1:443.
              :in-cluster-api-port
              (when (and (not (getf options :disable-agent))
                         (equal "containerd" (getf options :runtime))
                         (equal "managed" (getf options :containerd-mode)))
                in-cluster-api-port)
              ;; HA replication and joins arrive on the raft listener; a
              ;; firewalled raft port stalls a join silently (podster-rnh).
              :raft-port
              (when (and (or (getf options :raft-init) (getf options :raft-join))
                         (getf options :raft-listen)
                         (not (string= "127.0.0.1" (getf options :raft-listen))))
                (or (getf options :raft-port) +serve-raft-default-port+))
              :relay-port-start
              (when (getf options :wireguard-relay-address)
                (getf options :wireguard-relay-port-start))
              :relay-max-channels
              (when (getf options :wireguard-relay-address)
                (getf options :wireguard-relay-max-channels))))
           (let* ((runtime (make-control-plane-runtime store node-server))
                  (reconciler (make-reconciler store runtime)))
             (setf gr8s.apiserver::*pod-network-dialer*
                   (when (serve-dials-pods-through-agents-p options)
                     (let ((local-node (unless (getf options :disable-agent) (getf options :node-name))))
                       (lambda (node address port timeout)
                         ;; This host's own Pods and kubelet are reached on this host.
                         (if (equal node local-node)
                             (usocket:socket-connect address port :element-type '(unsigned-byte 8)
                                                                  :timeout timeout :nodelay t)
                             (gr8s.runtime:open-dial-stream runtime node address port))))))
             (when ha
               (install-member-slynk-handler node-server state-directory store reconciler))
             (unless (getf options :disable-agent)
               (setf local-agent
                     (start-local-node-agent
                      node-server pki (getf options :node-name)
                      (merge-pathnames "agent/" state-directory)
                      options
                      :endpoints (when ha
                                   (ha-control-plane-node-endpoints
                                    ha (getf options :node-port)))
                      :session-endpoints (when ha
                                           (ha-control-plane-node-session-endpoints
                                            ha (getf options :node-port))))))
             ;; Virtual nodes: agents this process runs for nodes whose containers
             ;; live elsewhere (docs/design-browser-nodes.md).
             (when (or (getf options :virtual-nodes) (getf options :browser-listen))
               (setf virtual-nodes
                     (make-virtual-node-host store node-server pki (merge-pathnames "virtual-nodes/" state-directory)))
               (dolist (name (getf options :virtual-nodes))
                 (start-virtual-node virtual-nodes name)))
             (when (getf options :browser-listen)
               (destructuring-bind (address port) (getf options :browser-listen)
                 (setf browser-join (start-browser-join-listener virtual-nodes address port
                                                                 :distro (getf options :browser-distro)))
                 (format t "gr8s browser nodes join at http://~A:~D/~%" address port)))
             (when (getf options :debug-slynk-port)
               (setf debug-port (start-debug-server (getf options :debug-slynk-port) state-directory
                                                    :store store :reconciler reconciler)))
             (unwind-protect
                  (progn
                    ;; podster-40i: in HA the one-shot bootstrap writes go
                    ;; through Raft and 503 ("not the Raft leader") until this
                    ;; member has won election, so they must wait for leadership.
                    ;; The founder (--raft-init) waits briefly to win it; a joiner
                    ;; (--join) never performs them -- the leader's writes
                    ;; replicate to it. Per-member runtime (the aggregator, the
                    ;; service VIP, and this member's own in-cluster API listener)
                    ;; still comes up on every member, leader or not.
                    (let ((leaderp
                            (cond ((null ha) t)
                                  ((getf options :raft-join) nil)
                                  (t (let ((won (loop repeat 100
                                                      when (ha-control-plane-leader-p ha) return t
                                                      do (sleep 0.1))))
                                       (unless won
                                         (format *error-output*
                                                 "~&[serve] HA founder has not won election in 10s; skipping one-shot bootstrap writes (podster-40i)~%"))
                                       won)))))
                      (when (and leaderp (serve-bootstraps-cluster-p options local-agent ha))
                        (ensure-native-bootstrap-namespaces store))
                      (when (and local-agent (equal "containerd" (getf options :runtime))
                                 (equal "managed" (getf options :containerd-mode)))
                        (when leaderp
                          (ensure-extension-apiserver-authentication store pki)
                          (ensure-native-api-service store (serve-api-advertise-address options)
                                                     in-cluster-api-port))
                        (setf aggregator (start-api-aggregator store pki))
                        (setf service-network-created (ensure-in-cluster-network pki))
                        ;; The external control-plane API (started below on
                        ;; ADDRESS:PORT) already serves the in-cluster apiserver
                        ;; endpoint when it binds a wildcard address or the
                        ;; advertised address on the in-cluster port, and its cert
                        ;; already covers the advertised address. Starting a second
                        ;; listener on 0.0.0.0:+in-cluster-api-port+ then just
                        ;; collides on 6443 and the external API never binds
                        ;; (podster-o2h). Only start the dedicated in-cluster
                        ;; listener when the external one does not cover it.
                        (unless (external-api-covers-in-cluster-endpoint-p
                                 address port (serve-api-advertise-address options)
                                 in-cluster-api-port)
                          (setf api-server
                                (start-in-cluster-api
                                 store runtime reconciler pki
                                 :port in-cluster-api-port
                                 :debug-state-directory state-directory
                                 :debug-member-resolver (make-debug-member-resolver ha)
                                 :control-plane-membership-fn (make-control-plane-membership-fn ha)
                                 ;; Pods write here. A follower carries their writes to the
                                 ;; leader, as the external listener does (podster-0qf).
                                 :leader-status-fn (when ha (lambda () (ha-control-plane-leader-status ha)))
                                 :linearizable-read-fn
                                 (when ha (lambda () (ha-control-plane-await-linearizable-read ha))))))
                        (setf (pod-store-in-cluster-config store)
                              (list :host "10.96.0.1" :port 443
                                    :ca-pem (uiop:read-file-string (cluster-pki-ca-certificate-path pki))))
                        (when leaderp
                          (ensure-native-namespace-root-cas store)))
                      (when leaderp
                        (seed-default-storage-class store state-directory
                                                    :path (getf options :local-storage-path))))
                    (start-volume-reclaimer store node-server (lambda () *shutdown-requested*))
                    ;; Enable structured API audit logging when a path is given,
                    ;; so who-did-what-when-from-where is recoverable.
                    (when (getf options :audit-log-path)
                      (setf gr8s.apiserver::*api-audit-sink*
                            (gr8s.apiserver::api-audit-log-sink
                             (open (getf options :audit-log-path) :direction :output
                                   :if-exists :append :if-does-not-exist :create
                                   :external-format :utf-8))))
                    (setf server
                          (start-in-cluster-api
                           store runtime reconciler pki :address address :port port
                           :certificate-addresses
                           (list (serve-api-advertise-address options))
                           :debug-state-directory state-directory
                           :debug-member-resolver (make-debug-member-resolver ha)
                           :control-plane-membership-fn (make-control-plane-membership-fn ha)
                           :control-plane-metrics-fn
                           (lambda ()
                             (concatenate 'string
                                          (if ha (gr8s.ha::ha-metrics-text ha) "")
                                          (reconciliation-worker-metrics-text worker)))
                           :leader-status-fn (when ha (lambda () (ha-control-plane-leader-status ha)))
                           :linearizable-read-fn
                           (when ha (lambda () (ha-control-plane-await-linearizable-read ha)))
                           :follows-a-leader-fn
                           (when ha (lambda () (ha-control-plane-follows-a-leader-p ha)))))
                    (setf worker (start-reconciliation-worker reconciler
                                  :watch-resources t
                                  :resource-change-handler
                                  (lambda (changes) (gr8s.controllers::note-gateway-resource-changes runtime changes))
                                  :gateway-reconcile
                                  (lambda ()
                                    (gr8s.controllers::publish-gateway-resource-changes runtime))
                                  :leader-gate (when ha (lambda () (ha-control-plane-leader-p ha)))
                                  :before-reconcile (lambda ()
                                      ;; Isolate each controller: one that throws
                                      ;; must not starve every controller after it
                                      ;; (which would also stall service-discovery
                                      ;; projection to node agents). Log and go on;
                                      ;; the next pass retries from committed state.
                                      (macrolet ((run (form)
                                                   `(handler-case ,form
                                                      (error (condition)
                                                        (format *error-output*
                                                                "gr8s: reconcile step ~S failed this pass, continuing: ~A~%"
                                                                ',(if (consp form) (first form) form)
                                                                condition)))))
                                      (run (reconcile-crd-deletions store))
                                      (run (reconcile-flowcontrol store))
                                      (run (reconcile-cluster-role-aggregation store))
                                      (run (collect-orphaned-custom-resources store))
                                      (run (reconcile-certificate-signing-requests store pki))
                                      (run (reconcile-pod-certificate-requests store pki))
                                      (run (reconcile-certificates store pki))
                                      (run (gr8s.controllers::ensure-egress-ca store))
                                      (run (reconcile-storage-bindings store))
                                      (run (reconcile-volume-attachments store))
                                      (run (reconcile-resource-quotas store))
                                      (run (reconcile-namespace-deletions reconciler))
                                      (run (reconcile-namespace-defaults store))
                                      (run (collect-orphaned-api-objects reconciler))
                                      (run (reconcile-workloads reconciler))
                                      (run (reconcile-horizontal-pod-autoscalers reconciler))
                                      (run (reconcile-storage-version-migrations store))
                                      (run (reconcile-endpointslices store))
                                      (run (reconcile-endpoints store))
                                      (run (reconcile-native-api-endpoints
                                            store (and ha (ha-control-plane-live-api-endpoints ha))))
                                      (run (reconcile-service-ip-addresses store))
                                      (run (reconcile-service-load-balancer-status store))
                                      (run (reconcile-ingress-status store))
                                      (run (gr8s.apiserver::reconcile-gateway-status node-server))
                                      (run (prune-projected-tokens store))
                                      ;; Each snapshot also carries projected tokens, renewed when due.
                                      (run (publish-service-discovery-snapshots runtime))
                                      ;; ClusterIP Services are load-balanced in-kernel by the
                                      ;; agent's eBPF socket LB; the control plane only keeps the
                                      ;; in-cluster API address present.
                                      (when service-network-created
                                        (run (ensure-in-cluster-network pki)))))))
                    (let* ((kubeconfig (or (getf options :kubeconfig) (default-kubeconfig-path options)))
                           (client-address (serve-local-kubeconfig-address options)))
                      (setf kubeconfig-path kubeconfig)
                      ;; A file the user named keeps its usual mode, as they may read it as another user.
                      (multiple-value-bind (admin-certificate admin-key)
                          (ensure-admin-client-credentials pki)
                        (write-kubeconfig
                         kubeconfig (format nil "https://~A:~D" client-address port)
                         :ca-certificates (cluster-pki-trust-certificates pki)
                         :client-certificate admin-certificate :client-key admin-key
                         :private (null (getf options :kubeconfig))))
                      (format t "gr8s kubeconfig: ~A~%" (namestring kubeconfig)))
                    (format t "gr8s listening on https://~A:~D~%" address port)
                    (finish-output)
                    (notify-service-manager-ready)
                    (loop until *shutdown-requested* do (sleep 0.1)))
               (when debug-port (stop-debug-server debug-port))
               (when aggregator (stop-api-aggregator aggregator))
               (when worker (stop-reconciliation-worker worker))
               (when runtime (stop-runtime-deletions runtime))
               (when server (stop-server server))
               (when api-server (stop-server api-server))
               (when (or api-server service-network-created)
                 (remove-in-cluster-network pki))
               (setf (pod-store-in-cluster-config store) nil))))
      (when pki-authority-observer
        (gr8s.resources::remove-pki-authority-observer
         store pki-authority-observer))
      (when browser-join (ignore-errors (hunchentoot:stop browser-join :soft nil)))
      (when virtual-nodes (stop-virtual-nodes virtual-nodes))
      (when local-agent (stop-local-node-agent local-agent))
      (when ha (stop-ha-control-plane ha))
      (when node-server
        (stop-node-grpc-server node-server)
        ;; Mirror the enrollment and authenticated kubelet firewall lifecycle.
        (ignore-errors
          (remove-control-plane-firewall
           (unless (string= "127.0.0.1" (getf options :node-listen "127.0.0.1"))
             (getf options :node-port))
           :kubelet-port
           (when (and (not (getf options :disable-agent))
                      (equal "containerd" (getf options :runtime))
                      (equal "managed" (getf options :containerd-mode)))
             (getf options :kubelet-port))
           :in-cluster-api-port
           (when (and (not (getf options :disable-agent))
                      (equal "containerd" (getf options :runtime))
                      (equal "managed" (getf options :containerd-mode)))
             in-cluster-api-port)
           :relay-port-start
           (when (getf options :wireguard-relay-address)
             (getf options :wireguard-relay-port-start))
           :relay-max-channels
           (when (getf options :wireguard-relay-address)
             (getf options :wireguard-relay-max-channels)))))
      (when memory-monitor (stop-memory-monitor memory-monitor))
      ;; READY=1 already stopped it on a normal start; this covers a startup that
      ;; errors before READY so the keepalive thread never outlives serve (podster-qoa).
      (stop-startup-timeout-keepalive startup-timeout-keepalive)))
  0)

(defun ensure-control-plane-pki (state-directory options)
  "Return this control plane's PKI. One joining a Raft cluster gets the cluster's node CA first."
  (let ((root (merge-pathnames "pki/" state-directory)))
    (if (getf options :raft-join)
        (multiple-value-bind (host port) (parse-agent-server (getf options :raft-join))
          (ensure-joining-control-plane-pki root (or (getf options :raft-id) (getf options :node-name)) host port
                                            :node-name (getf options :node-name)
                                            :token (getf options :raft-token)
                                            :ca-pin (getf options :raft-ca-pin)))
        (ensure-cluster-pki root))))

(defun maybe-start-ha-control-plane (store pki options)
  "Start a Raft-replicated control plane when --raft-init or --join was
   given, else NIL (single-node)."
  (when (or (getf options :raft-init) (getf options :raft-join))
    (let ((id (or (getf options :raft-id) (getf options :node-name)))
          (join (getf options :raft-join)))
      (multiple-value-bind (join-host join-port)
          (if join (parse-agent-server join) (values nil nil))
        (when (getf options :cluster-reset)
          (let ((removed (gr8s.ha:reset-control-plane-membership
                          (gr8s.store::pod-store-path store) id)))
            (if removed
                (format t "gr8s HA: cluster reset: ~A is now the sole voter; removed ~{~A~^, ~}~%~
                           gr8s HA: remove --cluster-reset from the service arguments before adding members again~%"
                        id removed)
                (format t "gr8s HA: cluster reset: ~A is already the only durable member~%" id))))
        (format t "gr8s HA: Raft member ~A (~:[join ~A:~D~;founding cluster~])~%"
                id (getf options :raft-init) join-host join-port)
        (start-ha-control-plane
         store
         :id id
         :host (or (getf options :raft-listen) "127.0.0.1")
         :port (or (getf options :raft-port) +serve-raft-default-port+)
         :init (getf options :raft-init)
         :compaction-interval (when (getf options :raft-compaction) 1)
         :after-recovery-fn
         (when *serve-state-lease*
           (lambda (member)
             (require-serve-state-ownership options)
             (gr8s.resources::reap-store-snapshot-startup-temporaries-unlocked member store)))
         :join-host join-host :join-port join-port
         :node-name (getf options :node-name)
         :token (getf options :raft-token)
         :ca-pin (getf options :raft-ca-pin)
         :api-url (format nil "https://~A:~D" (serve-api-advertise-address options)
                          (getf options :port))
         :pki pki)))))

(defun make-control-plane-membership-fn (ha)
  "The acceptor's HA membership surface (podster-9x6), or NIL outside HA."
  (when ha
    (lambda (action &optional id)
      (ecase action
        (:list (gr8s.ha:ha-control-plane-membership ha))
        (:remove (gr8s.ha:ha-control-plane-remove-member ha id))
        (:transfer-leadership (gr8s.ha:ha-control-plane-transfer-leadership ha id))))))

(defun make-debug-member-resolver (ha)
  "Return an exact member lookup closure for the Slynk API, or NIL outside HA."
  (when ha
    (let ((member (ha-control-plane-member ha)))
      (lambda (id)
        (bt:with-lock-held ((gr8s.raft.transport::raft-member-lock member))
          (let* ((node (gr8s.raft.transport::raft-member-node member))
                 (role (gethash id (gr8s.raft:raft-node-roles node)))
                 (url (gethash id (gr8s.raft:raft-node-api-urls node))))
            (values (equal id (gr8s.raft:raft-node-id node)) url (not (null role)))))))))

(defun print-skill (&optional (stream *standard-output*))
  "Print embedded operator guidance without accessing cluster state."
  (write-string "# gr8s operator and agent guide

## Orient yourself

gr8s is a self-contained Kubernetes-compatible cluster written in Common Lisp.
`gr8s serve` runs a control plane and local agent; `gr8s agent` runs a worker;
`gr8s witness` participates in HA quorum. The default runtime is managed
containerd. The same executable also acts as its CNI plugin, and `gr8s
net-agent` runs that eBPF dataplane as a network services provider on a
cluster gr8s did not create (see the foreign-cluster section below). Use
kubectl for Kubernetes resources and gr8s commands for host/runtime
administration.

This command prints static guidance to stdout, needs no cluster or root access,
and changes no state. Save it with `gr8s skill > gr8s-guide.md` for an agent.
Use `gr8s help` and `gr8s help COMMAND` for command discovery.

With cluster access, run `gr8s status --kubeconfig KUBECONFIG` first: one
screen of cluster health — API, nodes, workload exceptions, networking,
storage, versions, recent Warning events — where every warn/fail line names
the next command to run (`--output json` for a stable machine-readable form;
exit 0 healthy, 1 warnings, 2 failures).

## First-time setup and inventory

Real workloads need Linux 6.6+ with TCX eBPF support, root, cgroup v2, and
registry connectivity (or preloaded images). Start in a disposable VM.

    sudo gr8s serve --state-directory /var/lib/gr8s --kubeconfig /root/gr8s.yaml

Keep this process running. In another terminal:

    sudo kubectl --kubeconfig /root/gr8s.yaml get nodes -o wide
    sudo kubectl --kubeconfig /root/gr8s.yaml get pods -A -o wide

The kubeconfig is owner-only. Use the actual installation's state directory,
kubeconfig, namespace, and endpoints in all examples. Without an explicit state
directory, gr8s uses $XDG_STATE_HOME/gr8s or ~/.local/state/gr8s; sudo can change
that home. The default API is HTTPS on all interfaces, port 6443; the agent
supervisor uses 7443.
An agent's --server HOST:PORT is the supervisor, not the Kubernetes API URL.
`--runtime fake` is for development and does not prove real container/BPF health.

The state directory must be owned by the user gr8s runs as and must not be
writable by group or others; gr8s refuses a store it does not own and exits with
`Unsafe store generation directory`. Pointing a root process at a directory
owned by another user is the usual cause: use a root-owned path such as
/var/lib/gr8s, or `sudo chown -R root STATE_DIR && sudo chmod 700 STATE_DIR`.
`gr8s doctor` reports this as the \"store directory\" check.

Record the launch arguments, service unit, runtime mode, overlay backend,
node names, and state/log paths before changing a cluster. Check version
with `gr8s version --state-directory /var/lib/gr8s`.

## Networking a foreign cluster (gr8s net-agent)

gr8s also runs as a network services provider for a Kubernetes cluster it did
not create. A DaemonSet of `gr8s net-agent` Pods serves any combination of
three independently selectable features from the Whistler eBPF dataplane:

- `cni` (Helm `cni.enabled`, on by default): Pod networking and IPAM from
  each node's `spec.podCIDR`, cross-node traffic over a VXLAN fabric or an
  encrypted WireGuard fabric, NetworkPolicy enforced in eBPF for TCP, UDP,
  and SCTP, and hostPort. This replaces the cluster's CNI and NetworkPolicy
  controller.
- `service-lb` (Helm `serviceLb.enabled`, on by default): a kube-proxy
  replacement -- ClusterIP and NodePort Services, hostPort DNAT, and cluster
  DNS reachability through the eBPF socket/packet load balancer.
- `gateway` (Helm `gateway.enabled`, off by default): the Gateway API
  (GatewayClass `gr8s.io/gateway-controller`) -- HTTPRoute routing, status,
  and per-Gateway LoadBalancer Services -- and `networking.k8s.io/v1` Ingress
  (IngressClass `gr8s.io/ingress-controller`) served by the same proxy.

With the cni feature off, the gateway and service LB run alongside the
cluster's incumbent CNI; they only require that Pod IPs are reachable from
the host network, which most CNIs provide.

There is no gr8s control plane, store, or state directory of cluster identity
in this mode: desired state comes from the host cluster's API server via
list+watch, so administer the cluster with its own kubectl. Install with the
Helm chart in deploy/chart/gr8s-net. Disable the cluster's own CNI, NetworkPolicy
controller, and kube-proxy only for the features that replace them (for the full
stack on k3s: --flannel-backend=none --disable-network-policy
--disable-kube-proxy); with `cni.enabled=false` and `serviceLb.enabled=false`
the incumbents stay, and only the Gateway is added:

    helm install gr8s-net deploy/chart/gr8s-net -n kube-system \\
      --set apiServer.host=CONTROL_PLANE_IP \\
      --set overlay.backend=wireguard \\
      --set gateway.enabled=true

Key values beyond the three feature toggles: `overlay.backend` (vxlan by
default; wireguard encrypts Pod-CIDR-to-Pod-CIDR traffic only -- node and
API-server traffic stays in the clear so the agent can bootstrap; cni feature
only), `apiServer.host`/`apiServer.port` (required with serviceLb and no
other proxy: the agent cannot reach the API server through the kubernetes
Service ClusterIP that it is itself about to serve), and
`gateway.tls.enabled` (grants cluster-wide Secret read for TLS listeners; off
by default because it is the one grant that turns a node compromise into
cluster-wide secret exposure).

With the cni feature on, the chart's init container runs `gr8s cni-install`,
a shell-free step that copies the binary into the host CNI bin directory,
mounts the bpffs, and writes the conflist. The agent container runs `gr8s
net-agent`, selecting features with --cni/--service-lb/--gateway true|false
(--cni defaults to true; at least one feature must be on). Outside the chart
it also accepts --kubeconfig (defaults to in-cluster ServiceAccount
credentials), --node-name, --state-directory, --overlay-backend,
--wireguard-listen-port, and --mtu.

Troubleshooting in this mode: read the gr8s-net DaemonSet Pod logs in the
install namespace; store-oriented gr8s commands do not apply. The service LB
needs CAP_BPF, a mounted bpffs, and a modern kernel, and fails soft without
them -- the cluster keeps whatever Service proxy it already runs. With the
WireGuard backend each agent persists a key pair in its state directory and
publishes the public key as the `gr8s.io/wireguard-public-key` Node
annotation (this needs the nodes patch RBAC grant, which the chart gates on
the backend); peers are built from the other Nodes' annotation, InternalIP,
and podCIDR, so a node missing the annotation cannot join the encrypted
fabric. Upstream conformance harnesses live in deploy/conformance/.

## First response to a failure

1. Check host prerequisites with `sudo gr8s doctor --state-directory /var/lib/gr8s`.
   It diagnoses kernel, cgroups, bpffs, Pod route overlap, and firewall/DNS issues.
   Check free space too: `df -h STATE_DIR`. A full disk does not announce
   itself. The image pull-through proxy answers 503, so Pods sit in
   ImagePullBackOff; the server exits on `No space left on device`; and in HA the
   member drops out of quorum. Free space before diagnosing anything above it --
   rotated logs under /var/log are usually the quickest win, and the images are
   under STATE_DIR/agent.
2. Inspect Kubernetes state with your kubeconfig:

       kubectl get nodes -o wide
       kubectl get pods -A -o wide
       kubectl -n NAMESPACE describe pod POD
       kubectl -n NAMESPACE get events --sort-by=.metadata.creationTimestamp
       kubectl -n NAMESPACE logs POD -c CONTAINER --tail=200
       kubectl -n NAMESPACE logs POD -c CONTAINER --previous --tail=200

3. Read the gr8s process/service logs as well as container logs. For networking,
   inspect Services, EndpointSlices, NetworkPolicies, DNS, host routes, and
   firewall rules. `gr8s network explain NODE PEER` explains a selected WireGuard
   path; it is not a general packet capture. See its help for connection options.
4. For resource pressure, use `kubectl top nodes` and `kubectl top pods -A`.
   Inspect certificate expiry with `gr8s certificate status --help` and encryption
   state with `gr8s secrets-encrypt status --help` before planning maintenance.

Capture timestamps, affected namespace/Pod UID/node, exact commands, exit codes,
and relevant logs. Redact tokens, keys, kubeconfigs, and Secret values. Distinguish
observations from hypotheses; verify recovery against the original symptom.

Before risky maintenance, take an offline backup: stop the server, then
`gr8s backup save --state-directory DIR --output FILE --key-file KEY` (create the
key once with `gr8s backup keygen`). The encrypted bundle captures cluster
identity, keys, and the Raft store; `gr8s backup verify` authenticates it and
`gr8s restore` rebuilds a fresh state directory from it. See docs/backup-restore.md.

## HA troubleshooting playbook

In an HA cluster, orient with membership before anything else:

    gr8s member list --kubeconfig KUBECONFIG

Each durable member is shown with role, address, and contact state. A voter
marked `never-heard` is a ghost: it holds a quorum vote it can never cast.
Contact is only meaningful when the serving member is the leader; off-leader
it reads `unknown` and the output names the leader to query. Exit 1 means
ghosts exist.

The journals explain refusals -- grep for these lines and trust them:

- `refusing join of X as voter: REASON` (leader) and `could not join the
  cluster at HOST:PORT: REASON` (joiner): the admission refusal and why
  (`change-in-flight` means another membership change has not committed).
- `committed node delta for X conflicts with this member's state; skipped`:
  this member's replica of X has diverged in stable fields. One-shot bursts
  during leadership churn self-heal; a steady stream means a baked fork --
  wipe and rejoin this member (checklist below).
- `blocking application store access for restore/checkpoint` followed within
  about a second by `application store access resumed`: a routine checkpoint.
  They come in pairs, more often under write load. Writes that land in one get
  a 503 (`Application restore is blocking ...`) and succeed on retry -- re-run
  a `kubectl apply` or `helm` step that failed that way. A `blocking` line with
  no `resumed` after it is the problem case.
- `application drain timed out after Ns; K requests still active: METHOD
  PATH (AGEs)`: a checkpoint could not drain; the named request holds a
  store lease. The API rejects with 503 while draining.
- `gr8s node session to HOST:PORT ended: ...; reconnecting` (agent side), with
  the node NotReady for `AgentNotReady: Readiness follows the gr8s node session
  lease`: the agent has no session with the leader. The text after `ended:` is
  the reason. `Node sessions require an active control-plane leader` means that
  member is not the serving leader; the agent moves to the members the refusal
  names. A timeout means the address does not answer on the node port.
- `service interface belongs to another cluster` (serve exits at startup): the
  host still has the `gr8s-services` interface of a cluster whose state was
  removed. `sudo gr8s doctor --fix --state-directory STATE_DIR` removes it.
- `HA state requires its Raft startup options; standalone fallback is
  refused`: the state directory holds an HA member but the arguments name no HA
  mode. See the startup arguments below.
- `waiting for a quorum: N of M voting members; ...not heard from since
  startup`: who is missing and whether the cluster can proceed. A joiner
  that stays at `no application snapshot bytes have arrived` has a
  reachability problem -- usually a firewalled raft port; `gr8s doctor`'s
  \"cluster ports\" check maps the member address to its interface and
  firewalld zone and prints the exact repair.
- `gr8s raft: clock thread ...s late` on one member, or a member that takes far
  longer than the others to restart: suspect its disk. Every commit waits for a
  flush of the Raft log. `gr8s doctor --state-directory STATE_DIR` times
  flushed writes there in its \"storage\" check: under 2 ms is good, under
  20 ms adequate, and over 100 ms fails a control-plane member.

Member failure decision tree:

- A member is gone but a quorum of live voters remains: `gr8s member remove
  NAME`, then rejoin it (or its replacement) with a fresh
  `gr8s join-token --role control-plane` token. Names may be reused.
- The missing members broke quorum permanently: `gr8s serve --cluster-reset`
  on a surviving voter (see docs/backup-restore.md for the full decision).
- Never wipe a live voter's state directory without removing it from the
  membership first: a committed voter that vanishes still costs quorum, and
  its single-use join token is already burned.

HA startup arguments, which live in the service environment and are read on
every start: the member that founded the cluster keeps `--raft-init` for good
(on a state directory that already holds the cluster it resumes it); every
other control-plane member keeps `--join HOST:PORT --token ... --ca-pin ...`.
`--cluster-reset` is for one start only and cannot be combined with `--join`:
once the member is up, replace it with `--raft-init`, or the next restart
resets the membership again. After a crash loop systemd refuses further starts
(`Start request repeated too quickly`) until `systemctl reset-failed UNIT`.

Tokens come from a control-plane member's own state directory:

    gr8s join-token --node-name NAME --role node|control-plane|witness \
        --state-directory STATE_DIR

The output is JSON with the token and the CA pin. A token admits that one name
in that one role, once.

Wipe-and-rejoin checklist, in order (skipping a step crash-loops):
stop the workloads and the service with `gr8s-killall.sh`, which also unmounts
what is mounted under the state directory; remove the state directory; run
`gr8s doctor --fix --state-directory STATE_DIR` to clear leftover gr8s network
interfaces; mint a fresh control-plane token; update the service environment;
start. Watch the join: enrollment errors and snapshot-transfer progress both
appear in the journal.

A joiner is listed as `learner` until it has caught up, and its service stays
`activating` while it logs `waiting for committed application recovery`. To
tell catching up from stuck, watch its state directory:
`du -sh STATE_DIR/snapshot-artifacts STATE_DIR/application-generations`. Growth
means the snapshot is arriving, which can take minutes over a slow link. No
growth at all, with the raft port reachable in both directions, is a fault:
collect both journals before restarting anything.

Rebuilding a cluster from nothing, when no member's state is worth keeping:
on every node run `gr8s-killall.sh`, remove the state directory, and run
`gr8s doctor --fix`; start the founder with `--raft-init`; join each further
control-plane member, then the witness, then the agents, each with its own
fresh token. The new cluster has a new CA: write a new kubeconfig with
`gr8s kubeconfig --state-directory STATE_DIR --server URL --output FILE`,
and have clients trust the new CA. Workloads and their PersistentVolume
bindings are gone with the old state; data on an NFS server stays there under
the old `pvc-<uid>` directories, unattached.

Replica forensics: every member's API serves its own replica, so the same
object can be diffed across members to find a fork:

    kubectl --server=https://MEMBER:6443 get node NAME -o json

Operational properties worth relying on: service restarts do not restart
workloads (containers and shims survive; `gr8s-killall.sh` is how workloads
are actually stopped), so restart freely for upgrades -- one member at a
time, leader last. Suspending or losing any member, the leader included, is
tolerated: survivors elect within seconds and the returning member rejoins
as a follower. Dead peers surface as connection errors within ~15 seconds.

If `gr8s status` reports a member with store access blocked by an interrupted
application restore, that member is Ready yet cannot run store-backed work --
volume provisioning, aggregation -- until restarted; restart it to re-drive
recovery to completion.

## NFS PersistentVolumes

gr8s provisions and mounts NFS itself through the `mount(2)` syscall -- no
`mount.nfs`, `nfs-common` or `nfs-utils`, only the host's in-kernel NFS client,
which `gr8s doctor` reports on. A `gr8s.io/nfs` StorageClass needs `server` and
`share`; each PVC gets its own `pvc-<uid>` subdirectory, created on the node
where its Pod first runs by mounting the share as root. ReadWriteMany is allowed.

Getting dynamic NFS working is almost always about the server's export, not gr8s.
When a Pod sticks in `ContainerCreating`, read `kubectl describe pod` -- the
`FailedMount` reason is the signal:

- `access denied` / `Permission denied`: the export does not admit the mounting
  node, or it squashes root. The export's host list must include each node's
  address *as the server sees it* -- a node reaching the server over a tunnel
  (WireGuard) presents its tunnel address, not its LAN address. And the export
  must be `no_root_squash` (\"No mapping\" on a Synology), because gr8s creates
  the per-claim directory as root. gr8s mounts from a privileged source port, so
  a `secure` export is fine and `insecure` is not required.
- `No such file or directory` on an NFSv4 attempt: usually the server's `fsid=0`
  pseudo-root; gr8s falls back to NFSv3 on its own, so this is rarely fatal.

A Pod can schedule onto any eligible node, so admit every node's address or
confine NFS Pods with a nodeSelector/affinity. The server name is resolved on the
node, so use an IP or a host-resolvable name -- never a Service name or
ClusterIP. Static `nfs:` PVs work too (reclaim policy must be `Retain`). See
docs/persistent-storage.md for the full reference.

## Private registries

The image mirror verifies every registry's TLS certificate against the system
roots. A Pod pulling from a registry with a private or self-signed CA sits in
ImagePullBackOff, and the event or the gr8s journal names a TLS verification
error. Prefer trusting the CA cluster-wide, with no restart: create a
ClusterTrustBundle whose `spec.trustBundle` holds the CA PEM, annotated
`gr8s.io/registries: HOST:PORT[, HOST:PORT...]`. From its next snapshot, every
node verifies exactly those registries against it, and against nothing else;
deleting the bundle withdraws the trust the same way. `kubectl get
clustertrustbundles` shows what the cluster trusts.
For an in-cluster registry with a certificate from the `ca` issuer, the PEM is
the cluster CA (`ca.crt` in any namespace's `kube-root-ca.crt` ConfigMap).
Per node, the service argument `--registry-ca HOST:PORT=/path/to/ca.pem` also
works (a bare `--registry-ca HOST:PORT` trusts the cluster CA) and needs a
restart; a host named both ways trusts both. The certificate must name the
address images use: an image reference by IP needs that IP in the
Certificate's `ipAddresses`. Never work around this with a plain-http registry.

## Live Lisp inspection with Slynk

You can inspect a running process without restarting it or installing a debug
DaemonSet. Open an authenticated, lifetime-bound tunnel using API credentials:

    gr8s debug slynk --node NODE --kubeconfig /root/gr8s.yaml --local-port 4005

Alternatively use --selector LABELS (must match exactly one Ready node) or
--member ID (an exact HA control-plane member). Connect a SLY client to the
printed loopback endpoint while the tunnel command remains running. This path
does not require starting gr8s with --debug-slynk-port.

`gr8s debug icl NODE` opens the same tunnel and launches the ICL browser IDE
(https://atgreen.github.io/icl) against it on the operator machine; nothing
ICL-related runs on the node. --no-launch prints the `icl -b --connect` line
instead, for when icl is not installed or to compose another Slynk client.

A member or agent allows one debug session at a time: \"already has an active
Slynk session\" means someone is connected now. On a control-plane member, one
left behind by a client that went away ends by itself within half a minute.

Useful forms include (debug-threads), (debug-backtraces), (debug-pod \"default\"
\"web\"), and (debug-journal 20). They live in the GR8S.APISERVER package, and a
Slynk session starts in CL-USER: evaluate (in-package :gr8s.apiserver) first, or
qualify them, as in (gr8s.apiserver::debug-threads). These helpers inspect the
target process's local context; choose the node/member relevant to the failure.
Slynk evaluates Lisp with the process's privileges: inspect first and obtain
operator authorization before evaluating forms that mutate live state.

For direct local control-plane debugging, start serve with --debug-slynk-port 4017.
The listener is loopback-only and requires the fresh private session secret at
<state>/debug/slynk.secret. In a source checkout, use:

    python3 scripts/gr8s-debug.py --port 4017 --state-directory /var/lib/gr8s '(debug-threads)'

Do not publish the secret or expose the listener. SIGUSR1 also dumps thread
backtraces to the process diagnostic output; SIGTERM/Ctrl-C requests cooperative
shutdown so runtime work can finish.

## Selector-scoped kernel tracing

`gr8s debug trace` sends a program written in a bpftrace-compatible language to nodes
hosting matching Pods. [Whistler](https://github.com/atgreen/Whistler) JIT-compiles
it to eBPF, then loads and attaches it in-process. No separate bpftrace binary,
compiler installation, or DaemonSet is needed. Kernel probes are constrained to
the selected Pods' container/sandbox cgroups.

    gr8s debug trace --server https://API_HOST:PORT --ca-file /path/to/ca.crt --token TOKEN --namespace default --selector app=api --duration 10s 'kprobe:tcp_sendmsg { @[comm] = count(); }'

Use your actual API endpoint and credentials. Unlike debug slynk, trace currently
accepts --token and --ca-file directly, not --kubeconfig. HTTPS requires the CA
file. Avoid putting a real token into shared transcripts or shell history.
Authorization requires create on traces.gr8s.io in the requested namespace.
Kernel probe availability depends on the node kernel; verifier/attach failures
are returned to the client.

Output identifies nodes; aggregation maps remain per node. Default duration is
30s, maximum 300s; limits include one session per node and eight cluster-wide.
Membership is fixed at trace start: restart the trace after a container restart.
Completion or client disconnect cleans up attachments. Output is ephemeral, so
save relevant evidence securely. Begin with a narrow selector and short duration.

## Gateway backends and NetworkPolicy

The gr8s gateway runs on each node's host network, not as a Pod. A
NetworkPolicy that admits a backend's traffic by `namespaceSelector` or
`podSelector` therefore never matches the gateway, and a default-deny ingress
policy in the backend's namespace cuts its routes off: the gateway answers
`the gateway backend connection failed: ... TIMEOUT`. When a route times out,
look for NetworkPolicies in the backend namespace before anything else.

The gateway also connects to the backend itself, so a backend behind a TCPRoute,
TLSRoute or GRPCRoute sees the node as every client. When it needs the client's
address (an agent registry, an audit log), annotate its Service
`gr8s.io/proxy-protocol: v2` and have the backend accept PROXY protocol v2 from
the address it sees the gateway connect from: the gateway then sends a header
naming the client before any other byte. Annotate only a backend that expects
the header; any other breaks. A NodePort with `externalTrafficPolicy: Local`
keeps client addresses too, but pins the Pod to the node clients dial.

## Built-in APIs -- do not install upstream duplicates

gr8s serves several Kubernetes APIs natively that you would otherwise install as
a separate controller. Installing the upstream version on top registers the same
API group a second time and wedges discovery: `kubectl` then reports `<group>,
Kind=X matches multiple kinds` and EVERY resource in that group fails to apply.
Before `helm install`-ing or applying any controller, check whether gr8s already
serves its group -- `kubectl api-resources --api-group=GROUP` or
`kubectl get --raw /apis` -- and if so, use the native resources; do not add the
upstream CRDs.

- **cert-manager (`cert-manager.io/v1`): built in.** gr8s implements Issuer,
  ClusterIssuer, Certificate and CertificateRequest with a native controller --
  do NOT install upstream cert-manager or its CRDs. It is a compatible subset:
  `selfSigned` and `ca` issuers only (acme/vault/venafi are rejected at
  admission), and a `ca` issuer signs from the gr8s cluster CA, not from a
  Secret-held CA (any `spec.ca.secretName` is ignored). A Certificate's issued
  key pair is written to its `spec.secretName` as a `kubernetes.io/tls` Secret,
  so a Gateway/Ingress TLS listener can reference it directly. To give services
  one trusted CA, point a `ca` ClusterIssuer at the cluster CA and trust that CA
  on clients.
- **network-policy-api (`policy.networking.k8s.io/v1alpha2`): built in.**
  ClusterNetworkPolicy, tiered Admin -> NetworkPolicy -> Baseline, with Accept,
  Deny and Pass. Do NOT install the upstream CRDs. An egress `domainNames` peer
  (Accept only) is enforced by name, not by resolved address: the Pods it
  selects have their outbound TCP to public addresses sent to the node egress
  proxy (169.254.1.2), which admits a connection by its TLS SNI or HTTP Host, and
  their DNS answered only for allowed names (REFUSED otherwise). UDP 443 is
  refused so QUIC falls back to TCP. A captured Pod can't reach a public address
  by IP alone. Every proxied connection, request and DNS answer or refusal is a
  flow event: it appears in the flows and the Network view under the name it went
  to, refusals in red.
- **OpenKruise Agents SecurityProfile (`agents.kruise.io/v1alpha1`): a built-in
  subset.** Credential injection: the node egress proxy overwrites the named
  headers of matching requests with a value rendered from a Secret
  (`tokenTransformation` `ApiKey`, `{{ .Token }}`, `failStrategy: Block` only;
  anything else is rejected at admission), plus gr8s's own type `OAuthRefresh`
  for a token endpoint: the proxy swaps the real refresh token in, keeps the
  new tokens the response carries (the node writes them back to the Secret)
  and hands the client stand-ins. A stand-in (`gr8s-injected`) sent anywhere
  its rules don't inject for gets 403 saying where it is bound. The Pod keeps only a placeholder. A
  selected Pod's Secret travels only with that Pod's assignment. For HTTPS the
  proxy terminates TLS with a leaf from the egress CA, which Pods trust through
  the `gr8s-egress` ClusterTrustBundle (a projected `clusterTrustBundle` volume);
  a request whose Host differs from its TLS name gets 421, and one whose
  credential is missing gets 403. Do NOT install Kruise Agents' CRDs.
- **gr8 (`gr8.gr8s.io/v1alpha1` SandboxProfile): gr8s's own.** What a
  command run by `gr8` gets in the caller's home (`readWrite`, `readOnly`,
  `placeholders` credential files) and placeholder environment, and how the node
  egress proxy treats its egress (`spec.egress`): `tls: Terminate` (the default:
  every allowed host's TLS is terminated with a leaf from the egress CA and each
  request reported) or `Passthrough`, `passthroughHosts` for clients that pin
  certificates, and `enforcement: Enforce` (the default) or `Audit`, which reports
  a broken rule such as domain fronting and forwards. `spec.namespaceSelector`
  scopes a profile to namespaces; one that selects wins over one that doesn't.
  `spec.egress.binaries` (`[{hosts, paths}]`) lets a host be reached only by the
  listed programs or their children; the node finds the program behind each
  connection from the Pod's /proc, and the flow event names it.
  A gr8 sandbox gets the caller's Wayland display, audio and GPU (the agent's
  built-in device plugin offers render nodes as `gr8s.io/dri`) unless gr8 is
  run with --no-display, --no-audio or --no-gpu; never X11 or D-Bus.
  `spec.run` makes a profile one gr8 run's alone (a policy file's); the node
  prefers it for that run's Pod and never applies it to another.
  A gr8 sandbox is always on synthetic DNS, and anything no policy allows is
  denied; `gr8 --allow NAME` allows a name for one run. It requests 1 CPU and
  1Gi and is limited to half the node's (`--cpu`, `--memory`). `gr8 --login NAME`
  stores a tool's OAuth login (claude, or one described in
  ~/.config/gr8/logins.yaml: commands, file, token key paths, expiry, inject
  hosts, refresh endpoint) as the Secret login-NAME with a SecurityProfile
  injecting the access token and handling the refresh; sandboxed runs see the
  tool's file with stand-ins at the token keys. `--logout NAME`, `--logins`.
  A gr8 policy file (`gr8.gr8s.io/v1alpha1` Policy, client-side) says all a
  command gets: `hosts`, `credentials` (`from: env:NAME`, `file:PATH#key/path` or
  `login:NAME`, `hosts`, `header`, `template`, `env` for its own stand-in, which
  the proxy swaps by value in any header or Basic auth, `prefix`, `paths`,
  `methods`), `home`, `env`,
  `egress` (as `spec.egress`), `desktop` and `resources`. `gr8 CMD` reads
  `~/.config/gr8/policies/CMD.yaml`, else `.gr8/CMD.yaml` in the working
  directory, or `--policy NAME|FILE`, and creates resources for that run alone
  (a ClusterNetworkPolicy, Secrets and a SecurityProfile owned by the Pod, a
  `spec.run` SandboxProfile), removed when it ends. A working-directory policy is
  shown and pinned by content, and asked about again when it changes. See
  docs/gr8.md and docs/design-agent-egress.md.

If you have already installed an upstream duplicate and wedged a group, recover
by removing it and its CRDs (`helm uninstall ...`; `kubectl delete crd ...`);
the native group returns once the duplicate CRDs are gone.

## Serving external service names (--dns-serve-zone)

Instead of running ExternalDNS to push records into a managed DNS provider, gr8s
can serve your service hostnames authoritatively from its own node DNS -- it
already owns both the Gateway state and a DNS server, so the record is the live
state, like CoreDNS's `k8s_external` or the cluster's own `cluster.local`.

Start the control plane (or an agent) with `--dns-serve-zone ZONE` (repeatable),
e.g. `--dns-serve-zone lab.example.net`. Each node then serves that zone
authoritatively on its own address at `:53` (firewall opened automatically): a
name matching a Gateway listener, HTTPRoute, or Ingress hostname resolves to that
node's gateway address, an in-zone name that matches nothing is NXDOMAIN, and
anything outside the zone is REFUSED (the listener is never an open forwarder).

Then point one static forward/delegation at the nodes -- it never changes, even
as the gateway re-homes, because each node returns its own live address and a
down node simply drops out of the list:

- An upstream resolver (e.g. pfSense/Unbound `Domain Override`, or a BIND `NS`
  delegation): forward `ZONE` to the gr8s node addresses (list them for HA).
- Clients resolve through that upstream; roaming clients too, as long as they
  reach the upstream.

Composes with `--dns-forward ZONE=IP` (stub-forward a zone OUT); they are
independent -- a cluster can forward some zones upstream and serve one zone
authoritatively. The served answer carries a short TTL so a gateway change is
picked up within seconds. Pods resolve the same names through the cluster DNS.

## Dashboard tabs for the cluster's own apps

`gr8s dashboard` shows Headlamp, the Network view, an Agent terminal and a REPL. A
cluster-scoped `DashboardTab` (`dashboard.gr8s.io/v1`) adds a tab for one of the
cluster's own web apps, such as Grafana, to every reader's dashboard. Its CRD is
not built in, and release packages don't carry it; install it once per cluster:

    kubectl apply -f https://raw.githubusercontent.com/atgreen/gr8s/main/deploy/crds/dashboardtabs.dashboard.gr8s.io.yaml

Then name the app's Service:

    kubectl apply -f - <<'EOF'
    apiVersion: dashboard.gr8s.io/v1
    kind: DashboardTab
    metadata: {name: grafana}
    spec:
      title: Grafana     # the tab's label, at most 40 characters; the name by default
      service: {namespace: monitoring, name: grafana, port: 80}   # port by number or name
      path: /            # where the tab opens in the app; / by default
    EOF

The dashboard reads the DashboardTabs each time its page loads: reload it to see
a new tab. Deleting a DashboardTab removes its tab. The app is reached through the
cluster API's services/proxy with the reader's kubeconfig, so no Ingress or route
to Pods is needed, but each reader needs `get` on `services/proxy` in the app's
namespace. Check the path the tab uses with
`kubectl get --raw /api/v1/namespaces/NS/services/NAME:PORT/proxy/`. List the
tabs with `kubectl get dashboardtabs`.

Creating a DashboardTab is an RBAC decision (`create` on `dashboardtabs`): it
puts the app in front of every reader. Each app tab is served from a loopback
origin of its own, behind a per-tab secret, so the app's code can't reach the
Headlamp proxy that acts with the reader's credentials. The dashboard frames the
app even when it sends X-Frame-Options or a CSP frame-ancestors directive.

## Container logs

A container's log is `/var/log/gr8s/pods/POD-UID/CONTAINER.log` on its node
(`CONTAINER.N.log` for its Nth restart). Past 10 MiB it is rotated, as kubelet
rotates one: renamed `CONTAINER.log.TIME` (UTC), with five files kept in all.
`kubectl logs` reads only the file being written, as with kubelet; read the
rotated ones on the node. `--tail`, `--since` and `--limit-bytes` read only that
much of the file, so ask for them on a busy container: an agent from before
v1.37.2-gr8s.7 read the whole file into memory instead, and a 471 MB log once
took a member's API down.

## Upgrading gr8s

Upgrade with `gr8s upgrade`, not by copying binaries: `gr8s upgrade plan --to
VERSION` shows each host's step and refuses what isn't safe (a voter whose restart
would cost the quorum, a downgrade); `gr8s upgrade apply --to VERSION` carries it
out, voters one at a time with the leader last, then agents, and records progress
in a ClusterUpgrade (`gr8s upgrade status`). Releases are signed OCI artifacts in
ghcr.io/atgreen/gr8s-packages; a host checks the signature before installing.
A host running a gr8s from before `gr8s upgrade` is upgraded on the host with
`sudo gr8s upgrade self --to VERSION`, once: the first move onto a release that
has the command. A witness needn't run the release (it stores the log without
reading it); miniwit, the Go witness, isn't gr8s at all. Before starting another
upgrade, read `gr8s upgrade status` (or `kubectl get clusterupgrades`); `apply`
resumes an unfinished one. A registry that refuses access (ghcr.io answers 403)
holds no such release, or it isn't public. Ask before applying: every host
restarts.

`kubectl get nodes` shows the release each node's agent runs; `v0.0.0-unknown`
is an agent from before agents reported it, due an upgrade. `gr8s status` warns
when agents and members run different releases, which is expected only during
an upgrade.

## Maintenance and agent working practices

Persistent state contains cluster identity and data. Preserve it across restarts;
back it up using the deployment's recovery procedure before upgrades. Do not
remove state, BPF pins, namespaces, or runtime files as a first troubleshooting
step. Stop gr8s cooperatively before offline maintenance.

Discover runtime inventory with `gr8s runtime list`; and node enrollment
with `gr8s join-token --help`. Join tokens and CA pins belong to the existing
cluster: do not bootstrap a replacement state directory to repair enrollment.

For an AI agent: confirm the target/context, gather read-only evidence first,
explain a proposed change and its rollback, and ask before destructive actions.
Do not assume Kubernetes compatibility means every upstream feature is supported.

In a source checkout, README.md and docs/building-and-testing.md cover setup;
docs/installing.md covers systemd, upgrades, rollback, and cleanup;
docs/runtime.md covers runtime payloads, air-gapped images, and registry TLS trust;
docs/design-gr8s-trace.md describes tracing limits and authorization;
docs/design-foreign-cluster-networking.md describes the foreign-cluster
CNI/Gateway design, and deploy/ holds its chart and conformance harness.
" stream))

(defun ensure-ha-pki-authority (store ha &key (timeout 30))
  "Wait for the encrypted cluster PKI bootstrap record, creating it only on the leader.
No HA API may start from member-local certificate state before this converges."
  (loop repeat (* timeout 10)
        for envelope = (gr8s.resources::current-pki-authority-envelope store)
        do (cond
             (envelope
              (gr8s.resources::reconcile-pki-authority store)
              (return envelope))
             ((ha-control-plane-leader-p ha)
              (return (gr8s.resources::publish-pki-authority store)))
             (t (sleep 0.1)))
        finally (error "HA PKI authority did not converge within ~D seconds" timeout)))

(defparameter +cli-commands+
  '(("serve" "Run the control plane and local node agent")
    ("agent" "Run a node agent") ("witness" "Run an HA quorum witness")
    ("net-agent" "Provide network services to a foreign cluster")
    ("cni-install" "Install this binary as the node's CNI plugin")
    ("join-token" "Print a cluster join token")
    ("runtime" "Manage sandbox runtimes")
    ("kubeconfig" "Print or write a cluster kubeconfig")
    ("doctor" "Diagnose resources, survey a cluster, or check the host")
    ("status" "Show cluster health at a glance")
    ("member" "List or remove HA control-plane members, or move the leadership")
    ("upgrade" "Roll the cluster onto a signed gr8s release, host by host")
    ("debug" "Inspect live processes and trace Pods")
    ("wireguard" "Manage WireGuard identity")
    ("network" "Inspect cluster networking") ("certificate" "Manage certificates")
    ("secrets-encrypt" "Manage secrets encryption")
    ("backup" "Capture and verify encrypted state backups")
    ("restore" "Restore a state backup into a fresh state directory")
    ("skill" "Print guidance for operators and AI agents")
    ("dashboard" "Open the dashboards (Headlamp, the Network view, an agent terminal and a REPL) in a browser")
    ("mcp" "Serve read-only cluster tools to an AI agent over MCP (stdio)")
    ("version" "Print version information") ("notices" "Print license notices")))

(defun print-help-rows (rows)
  (dolist (row rows)
    (format t "   ~30A ~A~%" (first row) (second row))))

(defun command-help-page (path)
  "Return NAME, description, usage, commands and options for help PATH."
  (labels ((page (description usage &key commands options)
             (list description usage commands options))
           (simple (description &optional (usage "[OPTIONS]"))
             (page description usage :options '(("--help, -h" "show help")))))
    (cond
      ((equal path '("doctor"))
       (page "Diagnose resources, survey a cluster, or check the host" "COMMAND [OPTIONS]"
             :commands '(("diagnose [KIND/NAME]" "Find the causes behind current problems")
                          ("observe" "Show recent flows and the drops NetworkPolicies cause")
                          ("impact KIND/NAME" "Say what would stop working if a resource went away")
                          ("host" "Run local host checks (legacy doctor options)"))))
      ((and (equal (first path) "doctor") (equal (second path) "observe"))
       (page "Show the cluster's recent flow events: drops with their reason, and new connections"
             "[OPTIONS]"
             :options '(("-f, --follow" "Keep printing new events until interrupted")
                        ("-n, --namespace NAME" "Only flows with a Pod in NAME on either side")
                        ("--pod NAME" "Only flows of the Pod NAME, on either side")
                        ("--node NAME" "Only flows seen on node NAME")
                        ("--verdict dropped|forwarded" "Only drops, or only allowed connections")
                        ("--kubeconfig FILE" "Cluster credentials (default $KUBECONFIG or ~/.kube/config)")
                        ("--json" "Print each event as the API sends it, one JSON object per line")
                        ("--serve" "Serve them as Hubble's Observer API instead, for the stock hubble CLI")
                        ("--listen HOST:PORT" "Where --serve listens (default 127.0.0.1:4245, where hubble looks)"))))
      ((and (equal (first path) "doctor") (equal (second path) "impact"))
       (page "What would stop working if a resource went away; read-only"
             "KIND/NAME [OPTIONS]"
             :options '(("KIND/NAME" "A node, workload, Pod, Secret, ConfigMap or claim")
                        ("-n, --namespace NAME" "Namespace of the resource")
                        ("--kubeconfig FILE" "Cluster credentials (default: KUBECONFIG, ~/.kube/config, then a member's own)")
                        ("--context NAME" "Kubeconfig context")
                        ("--json" "Emit the affected resources as JSON"))))
      ((and (equal (first path) "doctor")
            (member (second path) '("diagnose" "checkup") :test #'equal))
       (page "Read-only cluster diagnostics; incomplete evidence is reported"
             "[KIND/NAME] [OPTIONS]"
             :options '(("KIND/NAME" "One resource; default is everything you can see")
                        ("-n, --namespace NAME" "Survey or look in one namespace")
                        ("--kubeconfig FILE" "Cluster credentials (default: KUBECONFIG, ~/.kube/config, then a member's own)")
                        ("--context NAME" "Kubeconfig context")
                        ("--notes" "Also list configuration and history notes")
                        ("--markdown" "Write the report as Markdown instead of rendering it")
                        ("--json" "Emit problems, findings, evidence and coverage"))))
      ((and (equal (first path) "doctor") (equal (second path) "host"))
       (page "Check the local host environment" "[OPTIONS]"
             :options '(("--state-directory DIR" "Node state directory")
                        ("--cluster-pod-cidr CIDR" "Pod network range")
                        ("--fix" "Repair supported local host problems"))))
      ((equal path '("skill"))
       (simple "Print offline Markdown guidance for operators and AI agents" ""))
      ((equal path '("mcp"))
       (page "Serve the doctor, flows and control-plane state to an AI agent as Model Context Protocol tools, on stdin and stdout"
             "[OPTIONS]"
             :options '(("--kubeconfig PATH" "Cluster kubeconfig (default $KUBECONFIG or ~/.kube/config)")
                        ("--help, -h" "show help"))))
      ((equal path '("dashboard"))
       (page "Serve the dashboards, Headlamp, the Network view, an agent terminal and a REPL, and open them in a browser; runs until Ctrl-C"
             "[OPTIONS]"
             :options '(("--kubeconfig PATH" "Cluster kubeconfig (default $KUBECONFIG or ~/.kube/config)")
                        ("--port N" "Loopback port to serve on (default 8080)")
                        ("--browser CMD" "Browser launcher (default xdg-open/open)")
                        ("--no-launch" "Print the dashboard URL instead of launching a browser")
                        ("--verbose" "Log every request and server error to stderr")
                        ("--help, -h" "show help"))))
      ((equal path '("serve"))
       (page "Run the control plane and local node agent" "[OPTIONS]"
             :options '(("--state-directory DIR" "Folder holding cluster state")
                        ("--listen IPV4" "API listen address") ("--port PORT" "API port")
                        ("--node-port PORT" "Agent supervisor port") ("--node-name NAME" "Node name")
                        ("--disable-agent" "Run only the control plane")
                        ("--browser-listen HOST:PORT" "Serve the browser-node join page and sessions there (podster-57fv)")
                        ("--browser-distro FILE" "The root image (erofs) browser nodes boot Pods from")
                        ("--virtual-node NAME" "Also run a virtual node NAME in this process on the fake runtime (repeatable; podster-57fv)")
                        ("--raft-init" "Found an HA control-plane cluster")
                        ("--cluster-reset" "Rewrite HA membership to this member alone (quorum lost forever)")
                        ("--join HOST:PORT" "Join an HA control-plane cluster through a member's Raft address")
                        ("--token TOKEN" "Control-plane join token for --node-name")
                        ("--ca-pin SHA256" "Raft CA fingerprint the joined member must present")
                        ("--raft-compaction" "Enable automatic HA checkpoints (the HA default)")
                        ("--no-raft-compaction" "Disable automatic HA checkpoints for diagnostics")
                        ("--overlay-backend NAME" "vxlan or wireguard")
                        ("--pod-network-egress MODE" "agent (default) or direct: reach webhook, aggregated-API and proxied Pods and nodes through their agents, or by route")
                        ("--mtu N" "Pod interface MTU (default 1450; 1420 for wireguard)")
                        ("--runtime NAME" "containerd or fake")
                        ("--flow-events WHAT" "connections (default): report every Pod's new connections and drops; drops: drops and isolated Pods' connections only")
                        ("--pod-masquerade WHAT" "outside (default): Pod traffic leaving the cluster's Pod network takes the node's address; off: it keeps the Pod's, for a network that routes Pod CIDRs")
                        ("--containerd-mode MODE" "managed or external")
                        ("--registry-ca HOST[=FILE]" "Verify registry HOST against FILE's CAs (default: the cluster CA); repeatable")
                        ("--cni-mode MODE" "native or external")
                        ("--help, -h" "show help"))))
      ((equal path '("kubeconfig"))
       (page "Print or write an authenticated cluster kubeconfig" "[OPTIONS]"
             :options '(("--state-directory DIR" "Folder holding cluster state")
                        ("--server URL" "Kubernetes API URL")
                        ("--output FILE" "Write kubeconfig to a private file")
                        ("--help, -h" "show help"))))
      ((equal path '("agent"))
       (page "Run a node agent" "[OPTIONS]"
             :options '(("--server HOST:PORT" "Control-plane supervisor address")
                        ("--token TOKEN" "Cluster join token") ("--ca-pin SHA256" "Cluster CA fingerprint")
                        ("--node-name NAME" "Node name") ("--state-directory DIR" "Folder holding node state")
                        ("--node-address IPV4" "Node address to advertise")
                        ("--kubelet-port PORT" "Port of the kubelet's endpoints (default 10250; 0 turns them off)")
                        ("--wireguard-endpoint NAME=IPV4:PORT" "WireGuard endpoint; repeatable")
                        ("--runtime NAME" "containerd or fake")
                        ("--flow-events WHAT" "connections (default): report every Pod's new connections and drops; drops: drops and isolated Pods' connections only")
                        ("--pod-masquerade WHAT" "outside (default): Pod traffic leaving the cluster's Pod network takes the node's address; off: it keeps the Pod's, for a network that routes Pod CIDRs")
                        ("--containerd-mode MODE" "managed or external")
                        ("--registry-ca HOST[=FILE]" "Verify registry HOST against FILE's CAs (default: the cluster CA); repeatable")
                        ("--cni-mode MODE" "native or external")
                        ("--help, -h" "show help"))))
      ((equal path '("net-agent"))
       (page "Provide network services to a foreign cluster" "[OPTIONS]"
             :options '(("--cni BOOL" "CNI, IPAM, overlay, NetworkPolicy, hostPort (default true)")
                        ("--service-lb BOOL" "Replace kube-proxy with the eBPF socket LB")
                        ("--gateway BOOL" "Serve the Gateway API and Ingress")
                        ("--listenerset-api-group GROUP" "Choose the stable or experimental ListenerSet group (default: discover, prefer stable)")
                        ("--kubeconfig FILE" "Host cluster access (default: in-cluster ServiceAccount)")
                        ("--node-name NAME" "This node's Kubernetes name (default: $NODE_NAME)")
                        ("--state-directory DIR" "Folder holding IPAM and key state")
                        ("--bpf-root DIR" "bpffs pin root (default /sys/fs/bpf/gr8s)")
                        ("--socket PATH" "CNI control socket (default /run/gr8s/cni.sock)")
                        ("--mtu N" "Pod interface MTU (default 1450)")
                        ("--overlay-backend NAME" "vxlan or wireguard (default vxlan)")
                        ("--wireguard-listen-port PORT" "Shared WireGuard UDP port (default 51820)")
                        ("--flow-port PORT" "Loopback port serving flow events to port-forwards (default 4246; 0: none)")
                        ("--flow-events WHAT" "connections (default) or drops: which flow events this node reports")
                        ("--help, -h" "show help"))))
      ((equal path '("cni-install"))
       (page "Install this binary as the node's CNI plugin (the net-agent init step)"
             "[OPTIONS]"
             :options '(("--cni-bin-dir DIR" "Host CNI bin mount (default /host-cni-bin)")
                        ("--cni-conf-dir DIR" "Host CNI conf mount (default /host-cni-conf)")
                        ("--bpf-mount DIR" "bpffs mount point (default /host-bpf)")
                        ("--conflist NAME" "Conflist filename (default 05-gr8s.conflist)")
                        ("--cni-name NAME" "CNI network name (default gr8s)")
                        ("--socket PATH" "Agent socket in the conflist (default /run/gr8s/cni.sock)")
                        ("--map-pin-root DIR" "Map pin root in the conflist (default /run/gr8s/bpf)")
                        ("--direction NAME" "Guard attach direction (default egress)")
                        ("--help, -h" "show help"))))
      ((equal path '("runtime"))
       (page "Manage sandbox runtimes" "COMMAND [OPTIONS]"
             :commands '(("install" "Download, verify, and stage a runtime")
                         ("list" "List embedded assets and installed addons"))
             :options '(("--help, -h" "show help"))))
      ((equal path '("runtime" "install"))
       (page "Download, verify, and stage a sandbox runtime" "<gvisor|kata> [OPTIONS]"
             :options '(("--state-directory DIR" "Folder holding runtime addons")
                        ("--version VERSION" "Runtime version") ("--release RELEASE" "gVisor release")
                        ("--hypervisor NAME" "Kata hypervisor: qemu, clh, fc, or dragonball")
                        ("--sha256 HEX" "Expected bundle digest") ("--bundle FILE" "Use a local bundle")
                        ("--help, -h" "show help"))))
      ((equal path '("runtime" "list"))
       (simple "List embedded assets and installed runtime addons" "[--state-directory DIR]"))
      ((equal path '("debug"))
       (page "Inspect live processes and trace Pods" "COMMAND [OPTIONS]"
             :commands '(("slynk" "Open Slynk to one node or control-plane member")
                         ("icl" "Open ICL's browser IDE on one node or member")
                         ("trace" "Trace Pods with a bpftrace-compatible language"))
             :options '(("--help, -h" "show help"))))
      ((equal path '("debug" "trace"))
       (page "Trace selected Pods with a bpftrace-compatible language" "[OPTIONS] BPFTRACE-SOURCE"
             :options '(("--server URL" "API endpoint (default https://127.0.0.1:6443)")
                        ("--namespace NAME" "Pod namespace (default default)")
                        ("--selector LABELS" "Select Pods by Kubernetes labels")
                        ("--duration TIME" "Duration from 1ms to 300s (default 30s)")
                        ("--token TOKEN" "API bearer token")
                        ("--ca-file FILE" "CA certificate required for HTTPS")
                        ("--help, -h" "show help"))))
      ((equal path '("debug" "slynk"))
       (page "Open a lifetime-bound Slynk tunnel" "(--node NAME | --selector LABELS | --member ID) [OPTIONS]"
             :options '(("--node NAME" "Target one exact Kubernetes node")
                        ("--selector LABELS" "Require exactly one Ready matching node")
                        ("--member ID" "Target one exact HA control-plane member")
                        ("--kubeconfig FILE" "Authentication and API endpoint")
                        ("--local-port PORT" "Loopback port (default 4005)")
                        ("--help, -h" "show help"))))
      ((equal path '("debug" "icl"))
       (page "Tunnel to a node's live image and open ICL's browser IDE on it"
             "[NODE | --node NAME | --selector LABELS | --member ID] [OPTIONS]"
             :options '(("NODE" "Target node name (positional shorthand for --node)")
                        ("--node NAME" "Target one exact Kubernetes node")
                        ("--selector LABELS" "Require exactly one Ready matching node")
                        ("--member ID" "Target one exact HA control-plane member")
                        ("--kubeconfig FILE" "Authentication and API endpoint")
                        ("--no-launch" "Print the icl --connect line instead of launching")
                        ("--icl-binary PATH" "icl executable to launch (default: icl)")
                        ("--unsafe-visualizations" "Allow JavaScript in ICL visualizations")
                        ("--help, -h" "show help"))))
      ((equal path '("wireguard"))
       (page "Manage WireGuard identity" "COMMAND [OPTIONS]"
             :commands '(("rotate-key" "Replace this node's identity on its next start"))
             :options '(("--help, -h" "show help"))))
      ((equal path '("network"))
       (page "Inspect cluster networking" "COMMAND [OPTIONS]"
             :commands '(("explain NODE PEER" "Explain an agent's selected WireGuard path"))
             :options '(("--help, -h" "show help"))))
      ((equal path '("certificate"))
       (page "Manage certificates" "COMMAND [OPTIONS]"
             :commands '(("status" "Inventory certificates and expiry warnings")
                         ("check" "Inventory certificates and expiry warnings")
                         ("rotate" "Rotate locally owned leaf certificates")
                         ("rotate-ca" "Stage a cluster CA trust transition")
                         ("service-account-key" "Rotate the token signer safely"))
             :options '(("--help, -h" "show help"))))
      ((member path '(("certificate" "rotate-ca")
                      ("certificate" "service-account-key")) :test #'equal)
       (page (if (equal (second path) "rotate-ca")
                 "Rotate the cluster certificate authority"
                 "Rotate the ServiceAccount signing key")
             "COMMAND [OPTIONS]"
             :commands '(("prepare" "Stage new signing material alongside the active material")
                         ("promote" "Make the staged signing material active")
                         ("finalize" "Remove retiring material after safety gates pass"))
             :options '(("--kubeconfig PATH" "update replicated HA authority through the API")
                        ("--state-directory PATH" "operate on an offline single-node state directory")
                        ("--help, -h" "show help"))))
      ((equal path '("secrets-encrypt"))
       (page "Manage secrets encryption" "COMMAND [OPTIONS]"
             :commands '(("status" "Show encryption status")
                         ("enable" "Enable encryption and rewrite existing Secrets")
                         ("disable" "Rewrite Secrets as plaintext and discard keys")
                         ("prepare" "Create a new encryption key")
                         ("promote" "Make the prepared key active for new writes")
                         ("reencrypt" "Rewrite all Secrets with the active key")
                         ("finalize" "Discard superseded encryption keys"))
             :options '(("--help, -h" "show help"))))
      ((equal path '("status"))
       (page "Show cluster health at a glance" "[OPTIONS]"
             :options '(("--kubeconfig PATH" "Cluster kubeconfig (default $KUBECONFIG or ~/.kube/config)")
                        ("--output FORMAT" "text (default) or json")
                        ("--help, -h" "show help"))))
      ((equal path '("upgrade"))
       (page "Roll the cluster onto a signed gr8s release, host by host" "COMMAND [OPTIONS]"
             :commands '(("plan --to VERSION" "Show what apply would do, and why it is safe or not; changes nothing")
                         ("apply --to VERSION" "Upgrade each host in turn: voters one at a time, the leader last, then agents")
                         ("status" "Show the latest upgrade, host by host")
                         ("rollback" "Return each host to the release it ran before the latest upgrade")
                         ("finalize" "Let the cluster use the release's formats, once every voter runs it")
                         ("self --to VERSION" "Upgrade this host, as root, without the cluster")
                         ("mirror --from REF --to REF" "Copy a release to another registry, by digest")
                         ("publish --to REF FILES..." "Push release packages as a signed artifact (the release workflow)"))
             :options '(("--to VERSION|REF" "The release: a version in --repository, or REGISTRY/REPOSITORY:TAG")
                        ("--repository REPO" "Where releases are published (default ghcr.io/atgreen/gr8s-packages)")
                        ("--registry-ca HOST=FILE" "Trust FILE's CAs for registry HOST (repeatable)")
                        ("--kubeconfig PATH" "Cluster kubeconfig (default $KUBECONFIG or ~/.kube/config)")
                        ("--yes" "apply without asking")
                        ("--allow-quorum-loss" "apply even when a voter's restart leaves no quorum: the API stops meanwhile")
                        ("--allow-downgrade" "apply an older release than a host runs (rollback does this itself)")
                        ("--no-finalize" "apply without raising the cluster's format level at the end")
                        ("--key-file PATH" "publish: the Ed25519 release key (or GR8S_RELEASE_SIGNING_KEY)")
                        ("--help, -h" "show help"))))
      ((equal path '("member"))
       (page "List or remove HA control-plane members, or move the leadership" "COMMAND [OPTIONS]"
             :commands '(("list" "Show the durable membership, with contact state (default)")
                         ("remove NAME" "Propose removing a member; commits once the remaining voters agree")
                         ("transfer-leadership NAME" "Hand the leadership to voter NAME, as before restarting the leader"))
             :options '(("--kubeconfig PATH" "Cluster kubeconfig (default $KUBECONFIG or ~/.kube/config)")
                        ("--output FORMAT" "text (default) or json")
                        ("--help, -h" "show help"))))
      ((equal path '("backup"))
       (page "Capture and verify encrypted state backups" "COMMAND [OPTIONS]"
             :commands '(("keygen" "Create a private backup key file")
                         ("save" "Capture an offline state directory into an encrypted bundle")
                         ("verify" "Authenticate a bundle end to end without restoring it"))
             :options '(("--key-file FILE" "Private key file of 64 hexadecimal characters")
                        ("--state-directory PATH" "State directory to capture (save; default system path)")
                        ("--output FILE" "Bundle to create (save); an existing file is never overwritten")
                        ("--input FILE" "Bundle to read (verify)")
                        ("--help, -h" "show help"))))
      ((equal path '("restore"))
       (page "Restore a state backup into a fresh state directory" "[OPTIONS]"
             :options '(("--input FILE" "Bundle to restore")
                        ("--state-directory PATH" "Target directory; must not exist (default system path)")
                        ("--key-file FILE" "Private key file of 64 hexadecimal characters")
                        ("--help, -h" "show help"))))
      ((and (= (length path) 1) (assoc (first path) +cli-commands+ :test #'string=))
       (simple (second (assoc (first path) +cli-commands+ :test #'string=))))
      ((and (> (length path) 1)
            (member (first path) '("wireguard" "network" "debug" "certificate" "secrets-encrypt" "backup")
                    :test #'string=))
       (simple (format nil "Run the ~{~A~^ ~} command" path)))
      (t (error "no help for command: ~{~A~^ ~}" path)))))

(defun print-help (&optional path)
  "Print k3s-style top-level or contextual help for PATH."
  (if (null path)
      (progn
        (format t "~&NAME:~%   gr8s - A self-contained, Kubernetes-compatible cluster~%~%")
        (format t "USAGE:~%   gr8s [global options] command [command options]~%~%")
        (format t "VERSION:~%   ~A~%~%COMMANDS:~%" +gr8s-version+)
        (print-help-rows +cli-commands+)
        (print-help-rows '(("help, h" "Show commands or help for one command")))
        (format t "~%GLOBAL OPTIONS:~%")
        (print-help-rows '(("--help, -h" "show help") ("--version, -v" "print the version"))))
      (destructuring-bind (description usage commands options) (command-help-page path)
        (format t "~&NAME:~%   gr8s ~{~A~^ ~} - ~A~%~%" path description)
        (format t "USAGE:~%   gr8s ~{~A~^ ~} ~A~%" path usage)
        (when commands
          (format t "~%COMMANDS:~%")
          (print-help-rows commands))
        (when options
          (format t "~%OPTIONS:~%")
          (print-help-rows options)))))

(defun print-gr8s-banner (role)
  "Print a startup banner (Spring-Boot style) naming the role gr8s is starting."
  (fresh-line)
  (terpri)
  (dolist (line '("               ___"
                  "    __ _ _ __ ( _ )  ___"
                  "   / _` | '__|/ _ \\ / __|"
                  "  | (_| | |  | (_) |\\__ \\"
                  "   \\__, |_|   \\___/ |___/"
                  "   |___/"))
    (write-line line))
  (terpri)
  (format t "   gr8s ~A · a self-contained, Kubernetes-compatible cluster~%" +gr8s-version+)
  (multiple-value-bind (major minor) (kubernetes-api-version-components)
    (format t "   Kubernetes API v~A.~A · ~A~%~%" major minor role))
  (finish-output))

(defparameter +system-ca-bundles+
  '("/etc/ssl/certs/ca-certificates.crt"                ; Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt"                  ; RHEL 8, older Fedora
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" ; Fedora 41+, RHEL 9+
    "/etc/ssl/ca-bundle.pem"                            ; openSUSE
    "/etc/ssl/cert.pem")                                ; macOS, Alpine
  "Where distributions keep the system CA bundle, most common first.")

(defun ensure-system-ca-bundle (&key (getenv #'uiop:getenv) (setenv #'sb-posix:setenv)
                                     (exists-p #'probe-file))
  "Name this host's CA bundle in SSL_CERT_FILE when neither it nor SSL_CERT_DIR is set.
pure-tls, which verifies registries, webhooks and foreign API servers, looks in fewer
places than distributions now use: on Fedora 44 it finds none, verifies against nothing,
and refuses every public registry (podster-8ak). Returns the bundle named, or NIL."
  (unless (or (plusp (length (funcall getenv "SSL_CERT_FILE")))
              (plusp (length (funcall getenv "SSL_CERT_DIR"))))
    (let ((bundle (find-if exists-p +system-ca-bundles+)))
      (when bundle
        (funcall setenv "SSL_CERT_FILE" bundle 1)
        bundle))))

(defun main-with-environment (arguments environment cni-entry)
  "The gr8s entry point, with its environment reader and CNI handler injected so
   tests can drive it. Writes the CNI plugin image when the first argument is the
   CNI-image command; runs CNI-ENTRY when ENVIRONMENT reports CNI_COMMAND
   (containerd invokes this binary as its CNI plugin); otherwise parses ARGUMENTS
   and runs the chosen subcommand, printing a banner and installing the
   timeout/memory guards for the long-running ones. Returns the process exit code,
   and 2 for any error it catches."
  (when (equal (first arguments) +cni-image-command+)
    (write-cni-plugin-image (second arguments)))
  (if (funcall environment "CNI_COMMAND")
      (funcall cni-entry)
      (handler-case
          (let ((options (parse-cli-options arguments)))
            (when (member (getf options :command) '(:serve :agent :witness))
              (print-gr8s-banner (case (getf options :command)
                                   (:serve "control plane")
                                   (:agent "node agent")
                                   (:witness "witness arbiter")))
              (install-prompt-fatal-exit)
              (install-stale-timeout-guard)
              (install-memory-hooks))
            (when (member (getf options :command) '(:serve :agent :net-agent))
              (setf gr8s.network::*report-every-connection*
                    (not (equal "drops" (getf options :flow-events)))))
            (when (member (getf options :command) '(:serve :agent))
              (setf gr8s.network::*masquerade-pod-egress*
                    (not (equal "off" (getf options :pod-masquerade)))))
            (case (getf options :command)
              (:help (print-help (getf options :help-path)) 0)
              (:version (format t "gr8s ~A~%" +gr8s-version+) 0)
              (:skill (print-skill) 0)
              (:notices (print-notices) 0)
              (:kubeconfig
               (if (getf options :output)
                   (write-administrative-kubeconfig options)
                   (write-administrative-kubeconfig options *standard-output*))
               0)
              (:join-token (print-node-join-token options))
              (:runtime-install
               (install-runtime (getf options :runtime-name)
                                (getf options :state-directory)
                                :version (getf options :version)
                                :release (getf options :release)
                                :hypervisor (getf options :hypervisor)
                                :sha256 (getf options :sha256)
                                :bundle-path (getf options :bundle-path))
               0)
              (:runtime-list
               (print-runtime-list (getf options :state-directory))
               0)
              (:trace (run-trace-command options))
              (:dashboard (run-dashboard-command options))
              (:mcp (run-mcp-command options))
              (:debug-slynk (run-debug-slynk-command options))
              (:wireguard-rotate-key
               (rotate-wireguard-node-key options))
              (:network-explain
               (print-network-explanation options))
              (:certificate-status
               (run-certificate-status options))
              (:certificate-rotate
               (run-certificate-rotation options))
              ((:certificate-ca-prepare :certificate-ca-promote :certificate-ca-finalize)
               (run-cluster-ca-rotation options))
              ((:certificate-service-account-key-prepare
                :certificate-service-account-key-promote
                :certificate-service-account-key-finalize)
               (run-service-account-signing-key-rotation options))
              ((:secrets-encrypt-status :secrets-encrypt-enable
                :secrets-encrypt-disable :secrets-encrypt-prepare
                :secrets-encrypt-promote :secrets-encrypt-reencrypt
                :secrets-encrypt-finalize)
               (run-secrets-encrypt-command options))
              ((:backup-keygen :backup-save :backup-verify)
               (run-backup-command options))
              (:restore (run-restore-command options))
              (:status (run-status-command options))
              (:upgrade-plan (run-upgrade-plan-command options))
              (:upgrade-apply (run-upgrade-apply-command options))
              (:upgrade-status (run-upgrade-status-command options))
              (:upgrade-rollback (run-upgrade-rollback-command options))
              (:upgrade-finalize (run-upgrade-finalize-command options))
              (:upgrade-self (run-upgrade-self-command options))
              (:upgrade-publish (run-upgrade-publish-command options))
              (:upgrade-mirror (run-upgrade-mirror-command options))
              (:member-list (run-member-list-command options))
              (:member-remove (run-member-remove-command options))
              (:member-transfer-leadership (run-member-transfer-leadership-command options))
              (:doctor-cluster
               (let ((gr8s-diagnose::*call-with-getter* #'call-with-doctor-api-getter))
                 (gr8s-diagnose:doctor-main (getf options :arguments))))
              (:doctor-observe (run-doctor-observe options))
              (:hubble-serve (run-hubble-serve options))
              (:doctor
               (if (plusp (apply #'run-doctor
                                 (append
                                  (when (getf options :state-directory)
                                    (list :state-directory (getf options :state-directory)))
                                  (when (getf options :cluster-pod-cidr)
                                    (list :cluster-pod-cidr (getf options :cluster-pod-cidr)))
                                  (when (getf options :fix)
                                    (list :fix t)))))
                   1 0))
              (:serve (run-serve-command options))
              (:agent
               (setf *shutdown-requested* nil)
               (install-shutdown-handlers)
               (agent options))
              (:net-agent
               (setf *shutdown-requested* nil)
               (install-shutdown-handlers)
               (run-net-agent-command options))
              (:cni-install
               (run-cni-install-command options))
              (:witness
               (setf *shutdown-requested* nil)
               (install-shutdown-handlers)
               (run-witness options))))
        (sb-int:broken-pipe ()
          (ignore-errors (close *standard-output* :abort t))
          0)
        (error (error)
          (format *error-output* "gr8s: ~A~%" error)
          2))))

(defun main (&optional (arguments (uiop:command-line-arguments)))
  "The gr8s process entry point: dispatch ARGUMENTS (the command-line arguments by
   default) with the real environment and CNI handler. Returns the process exit
   code."
  (ensure-system-ca-bundle)
  (main-with-environment arguments
                         #'uiop:getenv
                         (lambda () (cni-main))))
