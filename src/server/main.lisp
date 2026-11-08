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

(defun parse-serve-options (arguments)
  "Parse `gr8s serve' ARGUMENTS into an options plist on top of the serve
   defaults. Signals on an unknown option, a missing option value, or an out-of-
   range value, and -- because gr8s v1 serves only on loopback -- unless --listen
   is 127.0.0.1."
  (let ((options (list :command :serve
                       :state-directory (namestring (default-state-directory))
                       :listen "127.0.0.1"
                       :port 8080
                       :node-port 7443
                       :node-listen "127.0.0.1"
                       :node-address nil
                       :node-name "gr8s-local"
                       :disable-agent nil
                       :cluster-pod-cidr +default-cluster-pod-cidr+
                       :cluster-pod-cidrs (vector +default-cluster-pod-cidr+)
                       :node-pod-prefix +default-node-pod-prefix+
                       :node-pod-prefix-ipv6 64
                       :overlay-backend "vxlan"
                       :runtime "containerd"
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
          do (if (member option '("--disable-agent" "--raft-init" "--containerd-no-sync") :test #'string=)
                 (progn
                   (cond ((string= option "--disable-agent") (setf (getf options :disable-agent) t))
                         ((string= option "--raft-init") (setf (getf options :raft-init) t))
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
                     (t (error "unknown serve option: ~A" option)))
                   (setf arguments (cddr arguments)))))
    (unless (string= "127.0.0.1" (getf options :listen))
      (error "gr8s v1 only listens on 127.0.0.1"))
    (unless (eq (null (getf options :image-credential-provider-config))
                (null (getf options :image-credential-provider-bin-dir)))
      (error "image credential provider config and bin directory must be specified together"))
    (validate-cni-options options)))

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
                       :dns-forward-rules nil)))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--node-address")
                (setf (getf options :node-address) (canonical-node-underlay-address value)))
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
    (validate-cni-options options)))

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
           (credentials (ensure-raft-joiner-credentials
                         root (getf options :member-id) host port
                         :role :witness :node-name (getf options :node-name)
                         :token (getf options :token) :ca-pin (getf options :ca-pin)))
           (storage (open-file-raft-storage (merge-pathnames "witness.log" root)))
           (member (start-raft-member (getf options :member-id)
                                      :host (getf options :listen)
                                      :port (getf options :port)
                                      :apply-fn (lambda (command) (declare (ignore command)) nil)
                                      :storage storage
                                      :credentials credentials)))
      (unwind-protect
           (progn
             (raft-member-start member)
             (unless (raft-cluster-join member host port
                                        :role :witness
                                        :node-name (getf options :node-name))
               (error "witness ~A could not join the cluster at ~A:~D"
                      (getf options :member-id) host port))
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
                       :server "http://127.0.0.1:8080")))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--output")
                (setf (getf options :output) value))
               ((string= option "--server")
                (setf (getf options :server) value))
               (t (error "unknown kubeconfig option: ~A" option)))
             (setf arguments (cddr arguments)))
    options))

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
  (cond
    ((or (null arguments)
         (member (first arguments) '("help" "--help" "-h") :test #'string=))
     (list :command :help))
    ((member (first arguments) '("version" "--version" "-v") :test #'string=)
     (list :command :version))
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
    ((string= "wireguard" (first arguments))
     (parse-wireguard-options (rest arguments)))
    ((string= "doctor" (first arguments))
     (parse-doctor-options (rest arguments)))
    (t (error "unknown command: ~A" (first arguments)))))

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

(defun print-kubeconfig (stream server-url)
  "Write a minimal gr8s kubeconfig -- one cluster, context and anonymous user
   pointing at SERVER-URL -- to STREAM."
  (format stream
          "apiVersion: v1~%kind: Config~%clusters:~%  - name: gr8s~%    cluster:~%      server: ~A~%contexts:~%  - name: gr8s~%    context:~%      cluster: gr8s~%      namespace: default~%      user: gr8s~%current-context: gr8s~%users:~%  - name: gr8s~%    user: {}~%"
          server-url))

(defun write-kubeconfig (path server-url &key private)
  "Write a kubeconfig to PATH, readable only by its owner when PRIVATE."
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :if-exists :supersede
                          :if-does-not-exist :create)
    (print-kubeconfig stream server-url))
  (when private (sb-posix:chmod path #o600))
  path)

(defun default-kubeconfig-path (options)
  "Return where serve writes its kubeconfig when none was named."
  (merge-pathnames "kubeconfig" (uiop:ensure-directory-pathname (getf options :state-directory))))

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

(defun agent (options &key control
                            (stop-predicate (lambda () *shutdown-requested*)))
  "Run a node agent against the control plane at --server until STOP-PREDICATE is
   true, then return 0. Enrolls the node (writing node.key, node.crt and ca.crt)
   when it is not yet enrolled, builds and starts the runtime and the kubelet
   server, then runs the node session -- reconciling desired-state snapshots and
   dispatching operations -- and stops the kubelet and runtime on exit. CONTROL,
   when given, is the session control handle (used by the in-process agent)."
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
                    (gr8s.security::node-image-distribution-mirror-port image-distribution))))
          (setf node-runtime
              (make-node-runtime
               (agent-state-path options "runtime/") runtime manager
               :wireguard-private-key wireguard-private-key
               :dns-forward-rules (getf options :dns-forward-rules)))
        (setf (node-runtime-node-name node-runtime) node-name)
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
                :ca-certificate-path ca-certificate
                :certificate-path certificate :private-key-path private-key
                :underlay-address (getf options :node-address)
                :reconnect-delay 0.1 :control control
                :kubelet-port (if kubelet (getf options :kubelet-port) 0)
                :stop-predicate stop-predicate))
          (when kubelet (stop-kubelet-server kubelet))
          (stop-node-runtime node-runtime)
          (when image-distribution
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
                 (when (reconciliation-worker-before-reconcile worker)
                   (funcall (reconciliation-worker-before-reconcile worker)))
                 (reconcile-all (reconciliation-worker-reconciler worker)
                                :observer (reconciliation-worker-observer worker)))
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

(defun serve (options)
  "Run the gr8s control plane until shutdown, returning 0. Opens the store and
   PKI, starts the memory monitor, optional HA/Raft, and the node gRPC server
   (opening its firewalld port when it listens off loopback); unless
   --disable-agent, starts an in-process local node agent, and on a managed
   containerd node also brings up the in-cluster API server, aggregator and
   Service network. Writes a kubeconfig, serves the HTTP API, and runs the
   reconciliation worker. On *SHUTDOWN-REQUESTED* it tears every component down in
   reverse, withdrawing the firewalld port it opened."
  (let* ((address (getf options :listen))
         (port (getf options :port))
         (state-directory
           (uiop:ensure-directory-pathname (getf options :state-directory)))
         (store (open-store state-directory))
         (pool (ensure-controller-node-pool store state-directory options))
         (pki (ensure-control-plane-pki state-directory options))
         (server nil)
         (api-server nil)
         (debug-port nil)
         (service-network-created nil)
         (aggregator nil)
         (worker nil)
         (node-server nil)
         (ha nil)
         (memory-monitor nil)
         (local-agent nil))
    (setf *shutdown-requested* nil)
    (install-shutdown-handlers)
    (unwind-protect
         (progn
           (setf memory-monitor (start-memory-monitor store))
           (setf ha (maybe-start-ha-control-plane store pki options))
           (multiple-value-bind (certificate key) (ensure-apiserver-kubelet-client-credentials pki)
             (setf *kubelet-proxy-credentials* (list (cluster-pki-ca-certificate pki) certificate key)))
           (setf node-server
                 (start-node-grpc-server
                  store :host (getf options :node-listen "127.0.0.1")
                  :port (getf options :node-port)
                  :pki pki :cluster-pod-cidr (gethash "clusterPodCIDR" pool)
                  :node-prefix (gethash "nodePrefix" pool)
                  :cluster-pod-cidrs (node-pool-cluster-cidrs pool)
                  :node-prefixes (node-pool-prefixes pool)
                  :overlay-backend (getf options :overlay-backend)
                  :wireguard-listen-port 51820))
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
                (getf options :kubelet-port))))
           (let* ((runtime (make-control-plane-runtime store node-server))
                  (reconciler (make-reconciler store runtime)))
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
                          (ensure-native-api-service store))
                        (setf aggregator (start-api-aggregator store pki))
                        (setf service-network-created (ensure-in-cluster-network pki))
                        (setf api-server (start-in-cluster-api store runtime reconciler pki))
                        (setf (pod-store-in-cluster-config store)
                              (list :host "10.96.0.1" :port 443
                                    :ca-pem (uiop:read-file-string (cluster-pki-ca-certificate-path pki))))
                        (when leaderp
                          (ensure-native-namespace-root-cas store)))
                      (when leaderp
                        (seed-default-storage-class store state-directory
                                                    :path (getf options :local-storage-path))))
                    (start-volume-reclaimer store node-server (lambda () *shutdown-requested*))
                    (setf server
                          (start-server
                           :address address :port port
                           :store store :runtime runtime
                           :reconciler reconciler
                           :leader-status-fn (when ha (lambda () (ha-control-plane-leader-status ha)))))
                    (setf worker (start-reconciliation-worker reconciler
                                  :leader-gate (when ha (lambda () (ha-control-plane-leader-p ha)))
                                  :before-reconcile (lambda ()
                                      (reconcile-crd-deletions store)
                                      (reconcile-flowcontrol store)
                                      (reconcile-cluster-role-aggregation store)
                                      (collect-orphaned-custom-resources store)
                                      (reconcile-certificate-signing-requests store pki)
                                      (reconcile-pod-certificate-requests store pki)
                                      (reconcile-certificates store pki)
                                      (reconcile-storage-bindings store)
                                      (reconcile-volume-attachments store)
                                      (reconcile-resource-quotas store)
                                      (reconcile-namespace-deletions reconciler)
                                      (reconcile-namespace-defaults store)
                                      (collect-orphaned-api-objects reconciler)
                                      (reconcile-workloads reconciler)
                                      (reconcile-horizontal-pod-autoscalers reconciler)
                                      (reconcile-storage-version-migrations store)
                                      (reconcile-endpointslices store)
                                      (reconcile-endpoints store)
                                      (reconcile-service-ip-addresses store)
                                      (reconcile-service-load-balancer-status store)
                                      (reconcile-ingress-status store)
                                      (prune-projected-tokens store)
                                      ;; Each snapshot also carries projected tokens, renewed when due.
                                      (publish-service-discovery-snapshots runtime)
                                      ;; ClusterIP Services are load-balanced in-kernel by the
                                      ;; agent's eBPF socket LB; the control plane only keeps the
                                      ;; in-cluster API address present.
                                      (when service-network-created
                                        (ensure-in-cluster-network pki)))))
                    (let ((kubeconfig (or (getf options :kubeconfig) (default-kubeconfig-path options))))
                      ;; A file the user named keeps its usual mode, as they may read it as another user.
                      (write-kubeconfig kubeconfig (format nil "http://~A:~D" address port)
                                        :private (null (getf options :kubeconfig)))
                      (format t "gr8s kubeconfig: ~A~%" (namestring kubeconfig)))
                    (format t "gr8s listening on http://~A:~D~%" address port)
                    (finish-output)
                    (loop until *shutdown-requested* do (sleep 0.1)))
               (when debug-port (stop-debug-server debug-port))
               (when aggregator (stop-api-aggregator aggregator))
               (when worker (stop-reconciliation-worker worker))
               (when runtime (stop-runtime-deletions runtime))
               (when server (stop-server server))
               (when api-server (stop-server api-server))
               (when (or api-server service-network-created) (remove-in-cluster-network pki))
               (setf (pod-store-in-cluster-config store) nil))))
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
             (getf options :kubelet-port)))))
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
         :port (or (getf options :raft-port) 0)
         :init (getf options :raft-init)
         :join-host join-host :join-port join-port
         :node-name (getf options :raft-node-name)
         :token (getf options :raft-token)
         :ca-pin (getf options :raft-ca-pin)
         :api-url (format nil "http://~A:~D" (getf options :listen) (getf options :port))
         :pki pki)))))

(defun print-help ()
  "Print the gr8s version line and the command and option usage to standard
   output."
  (multiple-value-bind (major minor) (kubernetes-api-version-components)
    (format t "~&gr8s ~A — a self-contained, Kubernetes-compatible cluster~%" +gr8s-version+)
    (format t "Kubernetes API v~A.~A~%" major minor)
    (format t "Copyright (C) 2026 Anthony Green · Apache-2.0 License~%~%"))
  (format t "Usage: gr8s <command> [options]~%~%")
  (format t "Cluster:~%")
  (format t "  serve        Run the control plane (and, by default, a local node agent)~%")
  (format t "  agent        Run a node agent that joins a control plane~%")
  (format t "  witness      Run a witness arbiter for HA quorum~%")
  (format t "  join-token   Print a token for a node or control-plane to join~%~%")
  (format t "Runtime:~%")
  (format t "  runtime install <gvisor|kata>   Download, verify and stage a sandbox runtime~%")
  (format t "  runtime list                    List embedded assets and installed addons~%~%")
  (format t "Tools:~%")
  (format t "  kubeconfig   Print or write a cluster kubeconfig~%")
  (format t "  doctor       Diagnose a node's state directory~%")
  (format t "  wireguard rotate-key   Replace this node's WireGuard identity on its next start~%")
  (format t "  version      Print the gr8s version~%")
  (format t "  notices      Print third-party copyright and license notices~%~%")
  (format t "serve options:~%")
  (format t "  --state-directory DIR   --listen IPV4   --port PORT   --node-port PORT   --node-name NAME~%")
  (format t "  --kubeconfig FILE   --cluster-pod-cidr CIDR[,CIDR]   --node-pod-prefix BITS   --node-pod-prefix-ipv6 BITS   --disable-agent~%")
  (format t "  --overlay-backend vxlan|wireguard~%")
  (format t "  --runtime containerd|fake   --containerd-mode managed|external~%")
  (format t "  --containerd-{executable,oci-runtime,socket,log-root} PATH   --containerd-no-sync~%")
  (format t "  --registry-credentials-file DOCKER-CONFIG.json~%")
  (format t "  --image-credential-provider-{config FILE,bin-dir DIR}~%")
  (format t "  --cni-mode native|external   --cni-conf-dir DIR   --cni-bin-dir DIR (repeatable)~%")
  (format t "  --dns-forward ZONE=IP[:PORT] (repeat for multiple zones or upstreams)~%")
  (format t "  --node-listen IPV4   --node-address IPV4   --debug-slynk-port PORT   --local-storage-path DIR~%~%")
  (format t "agent options:~%")
  (format t "  --server HOST:PORT   --node-name NAME   --state-directory DIR   --token TOKEN   --ca-pin SHA256~%")
  (format t "  --node-address IPV4   --runtime containerd|fake   --containerd-mode managed|external~%")
  (format t "  --registry-credentials-file DOCKER-CONFIG.json~%")
  (format t "  --image-credential-provider-{config FILE,bin-dir DIR}~%")
  (format t "  --cni-mode native|external   --cni-conf-dir DIR   --cni-bin-dir DIR (repeatable)~%")
  (format t "  --dns-forward ZONE=IP[:PORT] (repeat for multiple zones or upstreams)~%~%")
  (format t "runtime install options:~%")
  (format t "  --state-directory DIR   --version V   --hypervisor qemu|clh|fc|dragonball (kata)~%")
  (format t "  --sha256 HEX (kata; trust-on-first-use)   --bundle FILE (use a local bundle)   --release R (gvisor)~%~%")
  (format t "join-token / witness / kubeconfig / doctor take their own options; see the docs.~%"))

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
              (:help (print-help) 0)
              (:version (format t "gr8s ~A~%" +gr8s-version+) 0)
              (:notices (print-notices) 0)
              (:kubeconfig
               (if (getf options :output)
                   (write-kubeconfig (getf options :output) (getf options :server))
                   (print-kubeconfig *standard-output* (getf options :server)))
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
              (:wireguard-rotate-key
               (rotate-wireguard-node-key options))
              (:doctor
               (if (plusp (apply #'run-doctor
                                 (append
                                  (when (getf options :state-directory)
                                    (list :state-directory (getf options :state-directory)))
                                  (when (getf options :cluster-pod-cidr)
                                    (list :cluster-pod-cidr (getf options :cluster-pod-cidr))))))
                   1 0))
              (:serve (serve options))
              (:agent
               (setf *shutdown-requested* nil)
               (install-shutdown-handlers)
               (agent options))
              (:witness
               (setf *shutdown-requested* nil)
               (install-shutdown-handlers)
               (run-witness options))))
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
