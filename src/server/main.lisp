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
                       :image-credential-provider-config nil
                       :image-credential-provider-bin-dir nil
                       :cni-mode "native"
                       :cni-conf-dir nil
                       :cni-bin-dirs nil
                       :dns-forward-rules nil
                       :kubeconfig nil
                       :kubelet-port +kubelet-default-port+
                       :local-storage-path +default-local-storage-path+)))
    (loop while arguments
          for option = (first arguments)
          do (if (member option '("--disable-agent" "--raft-init" "--raft-compaction" "--no-raft-compaction" "--containerd-no-sync") :test #'string=)
                 (progn
                   (cond ((string= option "--disable-agent") (setf (getf options :disable-agent) t))
                         ((string= option "--raft-init") (setf (getf options :raft-init) t))
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
                     ((string= option "--kubeconfig")
                      (setf (getf options :kubeconfig) value))
                     ((string= option "--kubelet-port")
                      (setf (getf options :kubelet-port) (if (equal value "0") 0 (parse-port value))))
                     ;; HA (podster-c2d.7.1): opt in to a Raft-replicated control
                     ;; plane. Absent these, serve runs single-node as before.
                     ((string= option "--raft-id")
                      (setf (getf options :raft-id) value))
                     ((string= option "--raft-listen")
                      (setf (getf options :raft-listen) value))
                     ((string= option "--raft-port")
                      (setf (getf options :raft-port) (parse-port value)))
                     ((string= option "--raft-join")
                      (setf (getf options :raft-join) value))
                     ((string= option "--raft-node-name")
                      (setf (getf options :raft-node-name) value))
                     ((string= option "--raft-token")
                      (setf (getf options :raft-token) value))
                     ((string= option "--raft-ca-pin")
                      (setf (getf options :raft-ca-pin) value))
                     ((string= option "--local-storage-path")
                      (unless (storage-absolute-path-p value)
                        (error "local storage path must be absolute without traversal"))
                      (setf (getf options :local-storage-path) value))
                     ((string= option "--audit-log-path")
                      (setf (getf options :audit-log-path) value))
                     (t (error "unknown serve option: ~A" option)))
                   (setf arguments (cddr arguments)))))
    (when (and (eq t (getf options :raft-compaction))
               (not (or (getf options :raft-init) (getf options :raft-join))))
      (error "--raft-compaction requires --raft-init or --raft-join"))
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
                       :image-credential-provider-config nil
                       :image-credential-provider-bin-dir nil
                       :cni-mode "native"
                       :cni-conf-dir nil
                       :cni-bin-dirs nil
                       :wireguard-endpoints nil
                       :dns-forward-rules nil)))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--node-address")
                (setf (getf options :node-address) (canonical-node-underlay-address value)))
               ((string= option "--wireguard-endpoint")
                (setf (getf options :wireguard-endpoints)
                      (add-wireguard-endpoint
                       (getf options :wireguard-endpoints) value)))
               ((string= option "--server")
                (setf (getf options :server) value))
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
  "Parse `gr8s debug slynk' target and local tunnel options."
  (unless (equal "slynk" (first arguments))
    (error "unknown debug subcommand: ~A" (or (first arguments) "")))
  (let ((options (list :command :debug-slynk :local-port 4005
                       :kubeconfig (default-client-kubeconfig)))
        (rest (rest arguments)))
    (loop while rest
          for option = (pop rest)
          do (unless rest (error "~A requires a value" option))
             (let ((value (pop rest)))
               (cond ((equal option "--node") (setf (getf options :node) value))
                     ((equal option "--selector") (setf (getf options :selector) value))
                     ((equal option "--member") (setf (getf options :member) value))
                     ((equal option "--kubeconfig") (setf (getf options :kubeconfig) value))
                     ((equal option "--local-port")
                      (setf (getf options :local-port)
                            (parse-integer value :junk-allowed nil)))
                     (t (error "unknown debug slynk option: ~A" option)))))
    (unless (= 1 (count-if (lambda (key) (getf options key)) '(:node :selector :member)))
      (error "debug slynk requires exactly one of --node, --selector, or --member"))
    (unless (<= 1 (getf options :local-port) 65535)
      (error "debug slynk --local-port must be 1..65535"))
    (dolist (key '(:node :member))
      (when (and (getf options key) (not (path-segment-name-p (getf options key))))
        (error "debug slynk target must be a valid Kubernetes name")))
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

(defun read-debug-kubeconfig (path)
  "Return server, token, CA, client certificate and key from PATH's current context."
  (let* ((file (truename path))
         (root (gr8s.resources:parse-yaml (uiop:read-file-string file)))
         (context-entry (kubeconfig-named-entry
                         (gethash "contexts" root #()) (gethash "current-context" root)))
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

(defun write-debug-http-request (stream method host port target token &key websocket-key)
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
          (line "Sec-WebSocket-Protocol: gr8s.slynk.v1"))
        (when token (line "Authorization: Bearer ~A" token))
        (line ""))))
   stream)
  (finish-output stream))

(defun debug-api-get-json (config target)
  (multiple-value-bind (stream socket host port base-path) (open-debug-api-stream config)
    (unwind-protect
         (progn
           (write-debug-http-request stream "GET" host port (concatenate 'string base-path target)
                                     (getf config :token))
           (multiple-value-bind (status headers)
               (gr8s.protocol::parse-http-response-head
                (gr8s.protocol::read-http-response-head stream))
             (unless (= status 200) (error "Kubernetes API returned HTTP ~D" status))
             (let* ((length (parse-integer (or (cdr (assoc :content-length headers)) "0")))
                    (body (make-array length :element-type '(unsigned-byte 8))))
               (read-sequence body stream)
               (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string body)))))
      (ignore-errors (close stream))
      (ignore-errors (usocket:socket-close socket)))))

(defun random-websocket-key ()
  (ag-grpc:base64-encode (secure-random-octets 16)))

(defun open-debug-websocket (config target)
  (multiple-value-bind (stream socket host port base-path) (open-debug-api-stream config)
    (let ((key (random-websocket-key)))
      (handler-case
          (progn
            (write-debug-http-request stream "GET" host port
                                      (concatenate 'string base-path target)
                                      (getf config :token) :websocket-key key)
            (multiple-value-bind (status headers)
                (gr8s.protocol::parse-http-response-head
                 (gr8s.protocol::read-http-response-head stream))
              (declare (ignore headers))
              (unless (= status 101)
                (error "Slynk API rejected the WebSocket upgrade with HTTP ~D" status)))
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
            (local-disconnected nil)
            (write-lock (bt:make-lock "gr8s debug Slynk websocket writer")))
        (unwind-protect
             (progn
               (setf listener (usocket:socket-listen "127.0.0.1" (getf options :local-port)
                                                     :reuse-address t
                                                     :element-type '(unsigned-byte 8)))
               (format t "gr8s Slynk tunnel: 127.0.0.1:~D -> ~A~%"
                       (usocket:get-local-port listener) target)
               (format t "Connect SLY now; Ctrl-C closes the local and remote debugger.~%")
               (finish-output)
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
      (let* ((config (read-debug-kubeconfig (getf options :kubeconfig)))
             (temporary nil))
        (labels ((materialize (data-key file-key suffix)
                   (when (and (null (getf config file-key)) (getf config data-key))
                     (let ((path (materialize-kubeconfig-data (getf config data-key) suffix)))
                       (push path temporary)
                       (setf (getf config file-key) path)))))
          (unwind-protect
               (progn
                 (materialize :ca-data :ca-file "ca.crt")
                 (materialize :client-certificate-data :client-certificate "client.crt")
                 (materialize :client-key-data :client-key "client.key")
                 (unless (or (getf config :token)
                             (and (getf config :client-certificate) (getf config :client-key)))
                   (error "kubeconfig has no bearer token or client certificate credentials"))
                 (run-debug-slynk-command-with-config options config))
            (dolist (path temporary) (ignore-errors (delete-file path))))))
    (sb-sys:interactive-interrupt ()
      (format t "~&gr8s Slynk tunnel closed.~%")
      0)))

(defun parse-doctor-options (arguments)
  "Parse `gr8s doctor' options: --state-directory/--cluster-pod-cidr VALUE, or a
bare positional state directory for backward compatibility.  A missing
:state-directory leaves run-doctor to use the shared default-state-directory."
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
               ((and (not positional-seen)
                     (plusp (length option))
                     (char/= (char option 0) #\-))
                (setf (getf options :state-directory) option
                      positional-seen t
                      arguments (rest arguments)))
               (t (error "unknown doctor option: ~A" option))))
    options))

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
  "Parse `gr8s network explain NODE PEER [--server URL]'."
  (unless (string= (first arguments) "explain")
    (error "unknown network subcommand: ~A" (or (first arguments) "")))
  (unless (and (second arguments) (third arguments))
    (error "network explain requires NODE and PEER"))
  (let ((options (list :command :network-explain
                       :node (second arguments) :peer (third arguments)
                       :server "http://127.0.0.1:8080"))
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
               (t (error "unknown network explain option: ~A" option))))
    options))

(defun print-network-explanation (options &optional (output *standard-output*))
  "Fetch and print one agent's durable path decision and candidate evidence."
  (multiple-value-bind (body status)
      (drakma:http-request
       (format nil "~A/gr8s/v1/network/explain?node=~A&peer=~A"
               (string-right-trim "/" (getf options :server))
               (getf options :node) (getf options :peer))
       :method :get :proxy nil)
    (let ((body-text
            (etypecase body
              (string body)
              ((array (unsigned-byte 8) (*))
               (trivial-utf-8:utf-8-bytes-to-string body)))))
    (unless (= status 200)
      (error "network explain failed with HTTP ~D: ~A" status
             body-text))
    (let* ((object (com.inuoe.jzon:parse
                    body-text))
           (selected (gethash "selected" object)))
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
                       (gethash "consecutiveFailures" candidate)))))
    (finish-output output))
  0)

(defun rotate-wireguard-node-key (options &optional (output *standard-output*))
  "Replace the durable node-local WireGuard identity and print its public key.
The new identity takes effect when the node agent next starts."
  (multiple-value-bind (private-key public-key)
      (gr8s.security::rotate-wireguard-key-pair (getf options :state-directory))
    (declare (ignore private-key))
    (format output "WireGuard public key: ~A~%" (ag-grpc:base64-encode public-key))
    (finish-output output))
  0)

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
                  '("runtime" "patch" "wireguard" "network" "debug"
                    "certificate" "secrets-encrypt")
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
    ((string= "join-token" (first arguments))
     (parse-join-token-options (rest arguments)))
    ((string= "witness" (first arguments))
     (parse-witness-options (rest arguments)))
    ((string= "kubeconfig" (first arguments))
     (parse-kubeconfig-options (rest arguments)))
    ((string= "runtime" (first arguments))
     (parse-runtime-options (rest arguments)))
    ((string= "trace" (first arguments))
     (parse-trace-options (rest arguments)))
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
    ((string= "doctor" (first arguments))
     (parse-doctor-options (rest arguments)))
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
  "Parse `gr8s trace` selector, authentication and bpftrace source options."
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
      (error "usage: gr8s trace [options] BPFTRACE-SOURCE"))
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
                   (1 (let* ((object (com.inuoe.jzon:parse
                                      (trivial-utf-8:utf-8-bytes-to-string payload)))
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
               :cpu-manager-policy (getf options :cpu-manager-policy "none")
               :reserved-cpus (getf options :reserved-cpus)
               :topology-manager-policy (getf options :topology-manager-policy "none")))
        (setf (node-runtime-node-name node-runtime) node-name)
        (setf (gr8s.agent::node-runtime-node-id node-runtime)
              (gethash "nodeId" (load-agent-identity identity node-name) ""))
        (unwind-protect
             (progn
               (start-node-runtime node-runtime)
               (setf kubelet (start-agent-kubelet-server
                              options node-name runtime
                              :network-metrics-function
                              (lambda ()
                                (gr8s.agent:node-runtime-wireguard-metrics-text
                                 node-runtime))))
               (run-node-session
                host port node-name identity
                (lambda (snapshot)
                  (setf (gr8s.agent::node-runtime-node-id node-runtime)
                        (gethash "nodeId" (load-agent-identity identity node-name) ""))
                  (reconcile-node-snapshot node-runtime snapshot))
                :endpoints session-endpoints
                :snapshot-observer (lambda (snapshot) (receive-node-snapshot-intent node-runtime snapshot))
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
        (issue-kubelet-credentials pki directory node-name
                                   (remove-duplicates (remove nil (list (discover-local-primary-ipv4) "127.0.0.1"))
                                                      :test #'equal))
        (setf (getf options :kubelet-port) 0))
    (when (managed-containerd-options-p options)
      ;; Run synchronously so serve's top-level error handler prints one concise
      ;; diagnostic instead of an unhandled backtrace from the local-agent thread.
      (ensure-kubelet-endpoints-available :command "serve"))
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
  ;; HA (podster-c2d.7): a nullary predicate that is true when this control
  ;; plane may act as the cluster leader. When set and false, the pass is
  ;; skipped so controllers only drive reconciliation on the Raft leader; NIL
  ;; (the default) always runs, keeping the single-node path unchanged.
  leader-gate
  thread
  (stop-requested nil)
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

(defun reconciliation-worker-loop (worker)
  "Drive WORKER's reconciliation passes until it is asked to stop. Each iteration,
   when the leader gate is absent or returns true, runs the before-reconcile hook
   and a full reconcile pass; errors and stray timeouts are logged, not
   propagated, so one bad pass never kills the loop. Between passes it waits on the
   wake-up condition for up to the configured interval, so a stop or a notify wakes
   it promptly."
  (loop until (reconciliation-worker-stopping-p worker)
        do (handler-case
               ;; Only drive controllers when we hold leadership; a follower
               ;; reconciles nothing and simply waits to be promoted.
               (when (let ((gate (reconciliation-worker-leader-gate worker)))
                       (or (null gate) (funcall gate)))
                 (call-with-reconciliation-metrics
                  worker
                  (lambda () (run-controller-pass worker))))
             ;; Timeouts are serious conditions, not errors, and a late one can land here.
             ((or error sb-ext:timeout bt2:timeout) (error)
               (format *error-output* "gr8s reconciliation error: ~A~%" error)))
           (bt:with-lock-held ((reconciliation-worker-lock worker))
             (unless (reconciliation-worker-stop-requested worker)
               (bt:condition-wait
                (reconciliation-worker-wake-up worker)
                (reconciliation-worker-lock worker)
                :timeout (reconciliation-worker-interval worker))))))

(defun start-reconciliation-worker (reconciler &key (interval 1.0) observer before-reconcile
                                                     leader-gate)
  "Create a reconciliation worker around RECONCILER and start its thread, then
   return the worker. INTERVAL bounds the wait between passes; OBSERVER and
   BEFORE-RECONCILE are passed through; LEADER-GATE, when set, gates each pass on
   leadership."
  (let ((worker (make-reconciliation-worker
                 :reconciler reconciler :interval interval :observer observer
                 :before-reconcile before-reconcile :leader-gate leader-gate)))
    (setf (reconciliation-worker-thread worker)
          (bt:make-thread
           (lambda () (reconciliation-worker-loop worker))
           :name "gr8s reconciler"))
    worker))

(defun stop-reconciliation-worker (worker)
  "Ask WORKER to stop and wake its thread, wait up to the worker's shutdown
   timeout for the thread to exit, forcibly destroy it (with a warning) if it
   overruns, then join it. Returns NIL."
  (bt:with-lock-held ((reconciliation-worker-lock worker))
    (setf (reconciliation-worker-stop-requested worker) t)
    (bt:condition-notify (reconciliation-worker-wake-up worker)))
  (let ((thread (reconciliation-worker-thread worker)))
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

(defun serve-bootstraps-cluster-p (options local-agent ha)
  "Return whether serve creates the standard namespaces and default ClusterRoles at startup.
A single control plane is a real cluster whether its agents are local or remote, so it
always does. A Raft member does so only with a local managed containerd agent, as before:
its writes need the Raft leader, which a member may not yet be (or ever be) at startup."
  (or (null ha)
      (and local-agent (equal "containerd" (getf options :runtime))
           (equal "managed" (getf options :containerd-mode)))))

(defun wait-for-ha-application (ha)
  "Keep Raft listening while application-dependent services wait for catch-up."
  (when ha
    (let ((store (ha-control-plane-store ha)) (member (ha-control-plane-member ha)))
      (when (gr8s.store::store-access-blocked-p store)
        (format t "gr8s HA: waiting for committed application recovery~%")
        (finish-output))
      (loop while (and (not *shutdown-requested*) (gr8s.store::store-access-blocked-p store))
            do (unless (and (gr8s.raft.transport::raft-member-running member)
                            (bt:thread-alive-p (gr8s.raft.transport::raft-member-tick-thread member)))
                 (error "Raft clock stopped before application recovery completed"))
               (sleep 0.05))))
  (not *shutdown-requested*))

(defun serve (options)
  "Own state before any application/PKI initialization, through final teardown."
  (call-with-serve-state-ownership options (lambda () (serve-owned options))))

(defun run-serve-command (options)
  "Own state before evaluating startup patches, through patch shutdown."
  (call-with-serve-state-ownership
   options
   (lambda ()
     (when (and (not (getf options :disable-agent))
                (managed-containerd-options-p options))
       ;; Fail before opening the store, PKI, listeners, or containerd. The
       ;; top-level handler then emits one actionable line without a worker
       ;; thread backtrace.
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
         (pki-authority-observer nil)
         (kubeconfig-path nil))
    (declare (ignore patch-policy-checked))
    (setf *shutdown-requested* nil)
    (install-shutdown-handlers)
    (unwind-protect
         (progn
           (setf memory-monitor (start-memory-monitor store))
           (setf ha (maybe-start-ha-control-plane store pki options))
           (unless (wait-for-ha-application ha) (return-from serve-owned 0))
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
                  :pki pki :cluster-pod-cidr (gethash "clusterPodCIDR" pool)
                  :node-prefix (gethash "nodePrefix" pool)
                  :cluster-pod-cidrs (node-pool-cluster-cidrs pool)
                  :node-prefixes (node-pool-prefixes pool)
                  :overlay-backend (getf options :overlay-backend)
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
              :relay-port-start
              (when (getf options :wireguard-relay-address)
                (getf options :wireguard-relay-port-start))
              :relay-max-channels
              (when (getf options :wireguard-relay-address)
                (getf options :wireguard-relay-max-channels))))
           (let* ((runtime (make-control-plane-runtime store node-server))
                  (reconciler (make-reconciler store runtime)))
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
             (when (getf options :debug-slynk-port)
               (setf debug-port (start-debug-server (getf options :debug-slynk-port) state-directory
                                                    :store store :reconciler reconciler)))
             (unwind-protect
                  (progn
                    ;; podster-40i: in HA the one-shot bootstrap writes go
                    ;; through Raft and 503 ("not the Raft leader") until this
                    ;; member has won election, so they must wait for leadership.
                    ;; The founder (--raft-init) waits briefly to win it; a joiner
                    ;; (--raft-join) never performs them -- the leader's writes
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
                        (setf api-server
                              (start-in-cluster-api
                               store runtime reconciler pki
                               :port in-cluster-api-port
                               :debug-state-directory state-directory
                               :debug-member-resolver (make-debug-member-resolver ha)))
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
                           :control-plane-metrics-fn
                           (lambda ()
                             (concatenate 'string
                                          (if ha (gr8s.ha::ha-metrics-text ha) "")
                                          (reconciliation-worker-metrics-text worker)))
                           :leader-status-fn (when ha (lambda () (ha-control-plane-leader-status ha)))))
                    (setf worker (start-reconciliation-worker reconciler
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
                                      (run (reconcile-service-ip-addresses store))
                                      (run (reconcile-service-load-balancer-status store))
                                      (run (reconcile-ingress-status store))
                                      (run (prune-projected-tokens store))
                                      ;; Each snapshot also carries projected tokens, renewed when due.
                                      (run (publish-service-discovery-snapshots runtime))
                                      ;; ClusterIP Services are load-balanced in-kernel by the
                                      ;; agent's eBPF socket LB; the control plane only keeps the
                                      ;; in-cluster API address present.
                                      (when service-network-created
                                        (run (ensure-in-cluster-network pki)))))))
                    (let* ((kubeconfig (or (getf options :kubeconfig) (default-kubeconfig-path options)))
                           (client-address (serve-api-advertise-address options)))
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
      (when memory-monitor (stop-memory-monitor memory-monitor))))
  0)

(defun ensure-control-plane-pki (state-directory options)
  "Return this control plane's PKI. One joining a Raft cluster gets the cluster's node CA first."
  (let ((root (merge-pathnames "pki/" state-directory)))
    (if (getf options :raft-join)
        (multiple-value-bind (host port) (parse-agent-server (getf options :raft-join))
          (ensure-joining-control-plane-pki root (or (getf options :raft-id) (getf options :node-name)) host port
                                            :node-name (getf options :raft-node-name)
                                            :token (getf options :raft-token)
                                            :ca-pin (getf options :raft-ca-pin)))
        (ensure-cluster-pki root))))

(defun maybe-start-ha-control-plane (store pki options)
  "Start a Raft-replicated control plane when --raft-init or --raft-join was
   given, else NIL (single-node)."
  (when (or (getf options :raft-init) (getf options :raft-join))
    (let ((id (or (getf options :raft-id) (getf options :node-name)))
          (join (getf options :raft-join)))
      (multiple-value-bind (join-host join-port)
          (if join (parse-agent-server join) (values nil nil))
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
         :node-name (getf options :raft-node-name)
         :token (getf options :raft-token)
         :ca-pin (getf options :raft-ca-pin)
         :api-url (format nil "https://~A:~D" (serve-api-advertise-address options)
                          (getf options :port))
         :pki pki)))))

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
containerd. The same executable also acts as its CNI plugin. Use kubectl for
Kubernetes resources and gr8s commands for host/runtime administration.

This command prints static guidance to stdout, needs no cluster or root access,
and changes no state. Save it with `gr8s skill > gr8s-guide.md` for an agent.
Use `gr8s help` and `gr8s help COMMAND` for command discovery.

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
that home. The default API is loopback port 8080; the agent supervisor uses 7443.
An agent's --server HOST:PORT is the supervisor, not the Kubernetes API URL.
`--runtime fake` is for development and does not prove real container/BPF health.

Record the launch arguments, service unit, runtime mode, overlay backend,
node names, and state/log paths before changing a cluster. Check version and
live patch level with `gr8s version --state-directory /var/lib/gr8s`.

## First response to a failure

1. Check host prerequisites with `sudo gr8s doctor --state-directory /var/lib/gr8s`.
   It diagnoses kernel, cgroups, bpffs, Pod route overlap, and firewall/DNS issues.
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

## Live Lisp inspection with Slynk

You can inspect a running process without restarting it or installing a debug
DaemonSet. Open an authenticated, lifetime-bound tunnel using API credentials:

    gr8s debug slynk --node NODE --kubeconfig /root/gr8s.yaml --local-port 4005

Alternatively use --selector LABELS (must match exactly one Ready node) or
--member ID (an exact HA control-plane member). Connect a SLY client to the
printed loopback endpoint while the tunnel command remains running. This path
does not require starting gr8s with --debug-slynk-port.

In the GR8S package, useful forms include (debug-threads), (debug-backtraces),
(debug-pod \"default\" \"web\"), and (debug-journal 20). These helpers inspect the
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

`gr8s trace` sends an ephemeral bpftrace program to nodes hosting matching Pods.
Whistler compiles and attaches it in-process: no bpftrace binary, compiler
installation, or DaemonSet is needed. Kernel probes are constrained to the
selected Pods' container/sandbox cgroups.

    gr8s trace --server https://API_HOST:PORT --ca-file /path/to/ca.crt --token TOKEN --namespace default --selector app=api --duration 10s 'kprobe:tcp_sendmsg { @[comm] = count(); }'

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

## Maintenance and agent working practices

Persistent state contains cluster identity and data. Preserve it across restarts;
back it up using the deployment's recovery procedure before upgrades. Do not
remove state, BPF pins, namespaces, or runtime files as a first troubleshooting
step. Stop gr8s cooperatively before offline maintenance.

Discover signed live patch inspection, planning, status, and history with
`gr8s patch --help`; runtime inventory with `gr8s runtime list`; and node enrollment
with `gr8s join-token --help`. Join tokens and CA pins belong to the existing
cluster: do not bootstrap a replacement state directory to repair enrollment.

For an AI agent: confirm the target/context, gather read-only evidence first,
explain a proposed change and its rollback, and ask before destructive actions.
Do not assume Kubernetes compatibility means every upstream feature is supported.

In a source checkout, README.md and docs/building-and-testing.md cover setup;
docs/installing.md covers systemd, upgrades, rollback, and cleanup;
docs/runtime.md covers runtime payloads and air-gapped images;
docs/design-gr8s-trace.md describes tracing limits and authorization.
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
    ("join-token" "Print a cluster join token")
    ("runtime" "Manage sandbox runtimes") ("patch" "Manage live patches")
    ("kubeconfig" "Print or write a cluster kubeconfig")
    ("doctor" "Diagnose a node state directory")
    ("debug" "Open an authenticated on-demand debugger tunnel")
    ("trace" "Trace Pods with bpftrace") ("wireguard" "Manage WireGuard identity")
    ("network" "Inspect cluster networking") ("certificate" "Manage certificates")
    ("secrets-encrypt" "Manage secrets encryption")
    ("skill" "Print guidance for operators and AI agents")
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
      ((equal path '("skill"))
       (simple "Print offline Markdown guidance for operators and AI agents" ""))
      ((equal path '("serve"))
       (page "Run the control plane and local node agent" "[OPTIONS]"
             :options '(("--state-directory DIR" "Folder holding cluster state")
                        ("--listen IPV4" "API listen address") ("--port PORT" "API port")
                        ("--node-port PORT" "Agent supervisor port") ("--node-name NAME" "Node name")
                        ("--disable-agent" "Run only the control plane")
                        ("--raft-init" "Found an HA control-plane cluster")
                        ("--raft-join HOST:PORT" "Join an HA control-plane cluster")
                        ("--raft-compaction" "Enable automatic HA checkpoints (the HA default)")
                        ("--no-raft-compaction" "Disable automatic HA checkpoints for diagnostics")
                        ("--overlay-backend NAME" "vxlan or wireguard")
                        ("--runtime NAME" "containerd or fake")
                        ("--containerd-mode MODE" "managed or external")
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
                        ("--wireguard-endpoint NAME=IPV4:PORT" "WireGuard endpoint; repeatable")
                        ("--runtime NAME" "containerd or fake")
                        ("--containerd-mode MODE" "managed or external")
                        ("--cni-mode MODE" "native or external")
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
       (page "Open authenticated on-demand debugger tunnels" "COMMAND [OPTIONS]"
             :commands '(("slynk" "Open Slynk to one node or control-plane member"))
             :options '(("--help, -h" "show help"))))
      ((equal path '("debug" "slynk"))
       (page "Open a lifetime-bound Slynk tunnel" "(--node NAME | --selector LABELS | --member ID) [OPTIONS]"
             :options '(("--node NAME" "Target one exact Kubernetes node")
                        ("--selector LABELS" "Require exactly one Ready matching node")
                        ("--member ID" "Target one exact HA control-plane member")
                        ("--kubeconfig FILE" "Authentication and API endpoint")
                        ("--local-port PORT" "Loopback port (default 4005)")
                        ("--help, -h" "show help"))))
      ((equal path '("patch"))
       (page "Manage live patches" "COMMAND [OPTIONS]"
             :commands '( ("inspect IMAGE" "Inspect a patch image") ("plan IMAGE" "Plan a rollout")
                         ("apply PLAN" "Apply a rollout plan") ("status [PLAN]" "Show rollout status")
                         ("pause|resume|abort PLAN" "Control a rollout")
                         ("history --node NODE" "Show node patch history")
                         ("import OCI-LAYOUT" "Import an offline patch"))
             :options '(("--help, -h" "show help"))))
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
      ((and (= (length path) 1) (assoc (first path) +cli-commands+ :test #'string=))
       (simple (second (assoc (first path) +cli-commands+ :test #'string=))))
      ((and (> (length path) 1)
            (member (first path) '("patch" "wireguard" "network" "debug" "certificate" "secrets-encrypt")
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
              (install-stale-timeout-guard)
              (install-memory-hooks))
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
              (:doctor
               (if (plusp (apply #'run-doctor
                                 (append
                                  (when (getf options :state-directory)
                                    (list :state-directory (getf options :state-directory)))
                                  (when (getf options :cluster-pod-cidr)
                                    (list :cluster-pod-cidr (getf options :cluster-pod-cidr))))))
                   1 0))
              (:serve (run-serve-command options))
              (:agent
               (setf *shutdown-requested* nil)
               (install-shutdown-handlers)
               (agent options))
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
  (main-with-environment arguments
                         #'uiop:getenv
                         (lambda () (cni-main))))
