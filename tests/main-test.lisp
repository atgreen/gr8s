(in-package #:gr8s/tests)

(in-suite gr8s)

(test reconciliation-metrics-preserve-values-errors-and-nonlocal-exits
  (with-temporary-store (store path)
    (values path)
    (let ((worker (gr8s.server::make-reconciliation-worker
                   :reconciler (make-reconciler store (make-fake-runtime)))))
      (is-false (search "last_success_age_seconds" (gr8s.server::reconciliation-worker-metrics-text worker)))
      (is (equal '(7 9) (multiple-value-list
                         (gr8s.server::call-with-reconciliation-metrics
                          worker (lambda ()
                                   (is (= 1 (gr8s.server::reconciliation-worker-metrics-in-flight worker)))
                                   (is (search "gr8s_reconciliation_in_flight 1"
                                               (gr8s.server::reconciliation-worker-metrics-text worker)))
                                   (values 7 9))))))
      (let ((success (gr8s.server::reconciliation-worker-metrics-last-success worker)))
        (signals simple-error
          (gr8s.server::call-with-reconciliation-metrics worker (lambda () (error "fixture failure"))))
        (is (eq :escaped
                (catch 'pass-abort
                  (gr8s.server::call-with-reconciliation-metrics worker
                    (lambda () (throw 'pass-abort :escaped))))))
        (is (eql success (gr8s.server::reconciliation-worker-metrics-last-success worker))))
      (is (= 3 (gr8s.server::reconciliation-worker-metrics-attempts worker)))
      (is (= 1 (gr8s.server::reconciliation-worker-metrics-completed worker)))
      (is (= 2 (gr8s.server::reconciliation-worker-metrics-failures worker)))
      (is (zerop (gr8s.server::reconciliation-worker-metrics-in-flight worker)))
      (let ((text (gr8s.server::reconciliation-worker-metrics-text worker)))
        (is (search "gr8s_reconciliation_last_success_age_seconds " text))
        (is (search "gr8s_reconciliation_worker_running 0" text))
        (is-false (search (namestring path) text)))
      (is (equal "" (gr8s.server::reconciliation-worker-metrics-text nil))))))

(test reconciliation-metrics-observe-real-worker-failure-and-recovery
  (with-temporary-store (store path)
    (values path)
    (let ((attempts 0) (worker nil))
      (unwind-protect
           (progn
             (setf worker (start-reconciliation-worker
                           (make-reconciler store (make-fake-runtime)) :interval 0.01
                           :before-reconcile (lambda ()
                                               (when (<= (incf attempts) 2)
                                                 (error "transient pass fixture")))))
             (is (poll-until
                  (lambda ()
                    (bt:with-lock-held ((gr8s.server::reconciliation-worker-lock worker))
                      (plusp (gr8s.server::reconciliation-worker-metrics-completed worker)))) :timeout 5))
             (is (search "gr8s_reconciliation_worker_running 1"
                         (gr8s.server::reconciliation-worker-metrics-text worker))))
        (when worker (stop-reconciliation-worker worker)))
      (is (= 2 (gr8s.server::reconciliation-worker-metrics-failures worker)))
      (is (plusp (gr8s.server::reconciliation-worker-metrics-completed worker)))
      (is (zerop (gr8s.server::reconciliation-worker-metrics-in-flight worker)))
      (is (search "gr8s_reconciliation_worker_running 0"
                  (gr8s.server::reconciliation-worker-metrics-text worker))))))

(test cli-options-default-to-containerd
  (let ((options (parse-cli-options '("serve"))))
    (is (string= "containerd" (getf options :runtime)))
    (is (string= "managed" (getf options :containerd-mode)))
    (is (search "build/containerd/bin/containerd"
                (getf options :containerd-executable)))
    (is (search "build/containerd/bin/runc"
                (getf options :containerd-oci-runtime)))
    (is (string= "/var/log/gr8s/pods/"
                 (getf options :containerd-log-root)))
    (is-false (getf options :registry-credentials-file))
    (is-false (getf options :image-credential-provider-config))
    (is-false (getf options :image-credential-provider-bin-dir))
    (is (string= "native" (getf options :cni-mode)))
    (is-false (getf options :cni-conf-dir))
    (is-false (getf options :cni-bin-dirs))
    (is (string= "vxlan" (getf options :overlay-backend)))
    (is (= 7443 (getf options :node-port)))
    (is (string= "gr8s-local" (getf options :node-name)))
    (is-false (getf options :disable-agent))))

(test serve-selects-the-cluster-overlay-backend
  (is (string= "wireguard"
               (getf (parse-cli-options '("serve" "--overlay-backend" "wireguard"))
                     :overlay-backend)))
  (signals error (parse-cli-options '("serve" "--overlay-backend" "bogus"))))

(test wireguard-rotate-key-command-replaces-only-the-persisted-private-identity
  (with-temporary-store (store directory)
    (declare (ignore store))
    (multiple-value-bind (old-private old-public)
        (gr8s.security::ensure-wireguard-key-pair directory)
      (let* ((arguments (list "wireguard" "rotate-key" "--state-directory"
                              (namestring directory)))
             (options (parse-cli-options arguments))
             (output
               (with-output-to-string (*standard-output*)
                 (is (= 0 (gr8s.server::main-with-environment
                           arguments (constantly nil) (constantly 99)))))))
        (is (eq :wireguard-rotate-key (getf options :command)))
        (is (equal (namestring directory) (getf options :state-directory)))
        (multiple-value-bind (new-private new-public)
            (gr8s.security::ensure-wireguard-key-pair directory)
          (is-false (equalp old-private new-private))
          (is-false (equalp old-public new-public))
          (is (search (ag-grpc:base64-encode new-public) output))
          (is-false (search (ag-grpc:base64-encode new-private) output))))))
  (signals error (parse-cli-options '("wireguard" "rotate-key" "--bogus")))
  (signals error (parse-cli-options '("wireguard" "unknown"))))

(test network-explain-command-requires-node-and-peer
  (let ((options (parse-cli-options
                  '("network" "explain" "worker-a" "worker-b"
                    "--server" "http://127.0.0.1:18080"))))
    (is (eq :network-explain (getf options :command)))
    (is (equal "worker-a" (getf options :node)))
    (is (equal "worker-b" (getf options :peer)))
    (is (equal "http://127.0.0.1:18080" (getf options :server))))
  (signals error (parse-cli-options '("network" "explain" "worker-a")))
  (signals error (parse-cli-options '("network" "bogus" "worker-a" "worker-b"))))

(test external-cni-options-are-explicit-and-validated
  (let ((options
          (parse-cli-options
           '("agent" "--server" "10.0.0.1:7443" "--token" "t" "--ca-pin" "p"
             "--node-name" "worker-a" "--state-directory" "/var/lib/gr8s"
             "--cni-mode" "external" "--cni-conf-dir" "/etc/cni/net.d"
             "--cni-bin-dir" "/opt/cni/bin" "--cni-bin-dir" "/var/lib/example-cni/bin"))))
    (is (string= "external" (getf options :cni-mode)))
    (is (string= "/etc/cni/net.d" (getf options :cni-conf-dir)))
    (is (equal '("/opt/cni/bin" "/var/lib/example-cni/bin") (getf options :cni-bin-dirs))))
  (signals error (parse-cli-options '("serve" "--cni-mode" "external")))
  (signals error (parse-cli-options '("serve" "--cni-mode" "native"
                                     "--cni-conf-dir" "/etc/cni/net.d")))
  (signals error (parse-cli-options '("serve" "--cni-mode" "bogus"))))

(test cli-options-dispatch-one-image-into-serve-and-agent-roles
  (let ((serve-options
          (parse-cli-options
           '("serve" "--node-port" "17443" "--node-name" "control-a"
             "--disable-agent"))))
    (is (eq :serve (getf serve-options :command)))
    (is (= 17443 (getf serve-options :node-port)))
    (is (string= "control-a" (getf serve-options :node-name)))
    (is-true (getf serve-options :disable-agent)))
  (let ((agent-options
          (parse-cli-options
           '("agent" "--server" "10.0.0.1:7443"
             "--token" "bootstrap-secret" "--ca-pin" "sha256-pin"
             "--node-name" "worker-a" "--state-directory" "/var/lib/gr8s"))))
    (is (eq :agent (getf agent-options :command)))
    (is (string= "10.0.0.1:7443" (getf agent-options :server)))
    (is (string= "bootstrap-secret" (getf agent-options :token)))
    (is (string= "sha256-pin" (getf agent-options :ca-pin)))
    (is (string= "worker-a" (getf agent-options :node-name)))
    (is (string= "/var/lib/gr8s" (getf agent-options :state-directory)))
    (is (string= "containerd" (getf agent-options :runtime)))
    (is (string= "managed" (getf agent-options :containerd-mode)))))

(test cli-doctor-parses-state-directory-flag-positional-and-cidr
  ;; Bare `doctor' leaves state-directory unset so run-doctor falls back to the
  ;; shared default-state-directory (not the old hardcoded /var/lib/gr8s).
  (let ((options (parse-cli-options '("doctor"))))
    (is (eq :doctor (getf options :command)))
    (is-false (getf options :state-directory)))
  ;; The --state-directory VALUE form must consume its value, not swallow the
  ;; flag name as the directory (the bug behind the false-positive advice).
  (let ((options (parse-cli-options
                  '("doctor" "--state-directory" "/var/lib/gr8s-helm/agent"
                    "--cluster-pod-cidr" "10.88.0.0/16"))))
    (is (string= "/var/lib/gr8s-helm/agent" (getf options :state-directory)))
    (is (string= "10.88.0.0/16" (getf options :cluster-pod-cidr))))
  ;; A bare positional path still works for backward compatibility.
  (let ((options (parse-cli-options '("doctor" "/srv/gr8s"))))
    (is (string= "/srv/gr8s" (getf options :state-directory))))
  (signals error (parse-cli-options '("doctor" "--bogus"))))

(test agent-role-rejects-incomplete-or-invalid-option-combinations
  (dolist (arguments
           '(("agent")
             ("agent" "--server" "127.0.0.1:7443")
             ("agent" "--server" "127.0.0.1:7443" "--token" "t"
              "--ca-pin" "p" "--node-name" "worker-a")
             ("agent" "--server" "127.0.0.1:7443" "--token" "t"
              "--ca-pin" "p" "--node-name" "worker-a"
              "--state-directory" "/tmp/a" "--disable-agent")
             ("serve" "--node-port" "0")))
    (signals error (parse-cli-options arguments))))

(test top-level-help-lists-node-role-commands
  (let ((help (with-output-to-string (*standard-output*)
                (gr8s.server::print-help))))
    (dolist (word '("NAME:" "USAGE:" "COMMANDS:" "serve" "agent"
                    "witness" "join-token" "--help, -h" "--version, -v"))
      (is (search word help)))))

(test cli-help-dispatches-before-command-validation
  (dolist (arguments '(("agent" "--help")
                       ("agent" "-h")
                       ("help" "agent")
                       ("h" "agent")
                       ("runtime" "--help")
                       ("runtime" "install" "--help")
                       ("help" "runtime" "install")))
    (let ((options (parse-cli-options arguments)))
      (is (eq :help (getf options :command)))
      (is (equal (remove-if (lambda (argument)
                              (member argument '("help" "h" "--help" "-h")
                                      :test #'string=))
                            arguments)
                 (getf options :help-path))))))

(test every-top-level-command-has-contextual-help
  (dolist (command '("serve" "agent" "witness" "join-token" "runtime"
                     "kubeconfig" "doctor" "debug" "wireguard"
                     "network" "certificate" "secrets-encrypt" "version"
                     "notices"))
    (let* ((arguments (list command "--help"))
           (output (with-output-to-string (*standard-output*)
                     (is (= 0 (gr8s.server::main-with-environment
                               arguments (constantly nil) (constantly 99)))))))
      (is (search "NAME:" output))
      (is (search (format nil "gr8s ~A" command) output))
      (is (search "USAGE:" output)))))

(test agent-help-is-concise-and-specific
  (let ((help (with-output-to-string (*standard-output*)
                (gr8s.server::print-help '("agent")))))
    (dolist (text '("NAME:" "gr8s agent - Run a node agent"
                    "USAGE:" "gr8s agent [OPTIONS]"
                    "OPTIONS:" "--server HOST:PORT" "--token TOKEN"
                    "--ca-pin SHA256" "--node-name NAME"
                    "--state-directory DIR" "--help, -h"))
      (is (search text help)))
    (is-false (search "serve options:" help))))

(test runtime-help-describes-its-subcommands
  (let ((help (with-output-to-string (*standard-output*)
                (gr8s.server::print-help '("runtime")))))
    (is (search "COMMANDS:" help))
    (is (search "install" help))
    (is (search "list" help)))
  (let ((help (with-output-to-string (*standard-output*)
                (gr8s.server::print-help '("runtime" "install")))))
    (is (search "gr8s runtime install <gvisor|kata> [OPTIONS]" help))
    (is (search "--hypervisor" help))))

(test bare-command-groups-show-contextual-help
  (dolist (command '("runtime" "wireguard" "network"
                     "certificate" "secrets-encrypt"))
    (let ((output (with-output-to-string (*standard-output*)
                    (is (= 0 (gr8s.server::main-with-environment
                              (list command) (constantly nil) (constantly 99)))))))
      (is (search (format nil "gr8s ~A" command) output))
      (is (search "COMMANDS:" output)))))

(test removed-patch-command-is-rejected
  ;; Runtime patching was removed; the `patch` command must not survive as CLI
  ;; scaffolding -- it is neither dispatched nor advertised in help.
  (signals error (parse-cli-options '("patch")))
  (signals error (parse-cli-options '("patch" "inspect" "some-image")))
  (let ((help (with-output-to-string (*standard-output*)
                (gr8s.server::print-help))))
    (is-false (search "patch" help))
    (is-false (search "Manage live patches" help))))

(test secrets-encrypt-help-explains-each-stage
  (let ((help (with-output-to-string (*standard-output*)
                (gr8s.server::print-help '("secrets-encrypt")))))
    (dolist (description '("Show encryption status"
                           "Enable encryption and rewrite existing Secrets"
                           "Rewrite Secrets as plaintext and discard keys"
                           "Create a new encryption key"
                           "Make the prepared key active for new writes"
                           "Rewrite all Secrets with the active key"
                           "Discard superseded encryption keys"))
      (is (search description help)))))

(test cni-environment-dispatches-before-command-line-parsing
  (let ((called nil))
    (is (= 27
           (gr8s.server::main-with-environment
            '("not-a-gr8s-command")
            (lambda (name)
              (and (string= name "CNI_COMMAND") "VERSION"))
            (lambda ()
              (setf called t)
              27))))
    (is (eq t called))))

(test cli-treats-a-closed-output-pipe-as-success
  (multiple-value-bind (read-descriptor write-descriptor) (sb-posix:pipe)
    (sb-posix:close read-descriptor)
    (let ((output (sb-sys:make-fd-stream write-descriptor
                                         :output t
                                         :element-type 'character
                                         :buffering :none
                                         :auto-close t))
          (status nil)
          (closed nil))
      (unwind-protect
           (let ((*standard-output* output)
                 (*error-output* (make-broadcast-stream)))
             (setf status (gr8s.server::main-with-environment
                           '("help") (constantly nil) (constantly 99))
                   closed (not (open-stream-p output))))
        (ignore-errors (close output)))
      (is (= 0 status))
      (is-true closed))))

(test runtime-list-command-reports-the-dumped-payload
  ;; #161 replaced the runtime-assets command with `runtime list`.
  (let ((options (parse-cli-options '("runtime" "list" "--state-directory" "/tmp/gr8s-runtime-list-test/"))))
    (is (eq :runtime-list (getf options :command)))
    (is (equal "/tmp/gr8s-runtime-list-test/" (getf options :state-directory))))
  (let ((gr8s.runtime::*embedded-runtime-assets*
          (list (gr8s.runtime::make-runtime-asset
                 :name "containerd"
                 :octets (make-array 42 :element-type '(unsigned-byte 8))))))
    (let ((output (with-output-to-string (*standard-output*)
                    (gr8s.runtime::print-runtime-list (uiop:temporary-directory)))))
      (is (search "containerd" output))
      (is (search "42 bytes" output)))))

(test trace-command-parses-auth-scope-duration-and-source
  (let ((options
          (parse-cli-options
           '("debug" "trace" "--server" "https://cp:6443" "--namespace" "alpha"
             "--selector" "app=api" "--duration" "30s" "--token" "secret"
             "--ca-file" "/tmp/ca.crt"
             "kprobe:tcp_sendmsg { @[comm] = count(); }"))))
    (is (eq :trace (getf options :command)))
    (is (equal "alpha" (getf options :namespace)))
    (is (equal "app=api" (getf options :selector)))
    (is (= 30000 (getf options :duration-milliseconds)))
    (is (equal "secret" (getf options :token)))
    (is (search "tcp_sendmsg" (getf options :source))))
  (signals error (parse-cli-options '("debug" "trace" "--selector" "app=api")))
  (signals error (parse-cli-options '("debug" "trace" "--duration" "301s" "kprobe:vfs_read {}"))))

(test debug-trace-help-describes-source-and-scope
  (let ((help (with-output-to-string (*standard-output*)
                (gr8s.server::print-help '("debug" "trace"))))
        (group-help (with-output-to-string (*standard-output*)
                      (gr8s.server::print-help '("debug")))))
    (is (search "trace" group-help))
    (is (search "gr8s debug trace [OPTIONS] BPFTRACE-SOURCE" help))
    (dolist (option '("--server" "--namespace" "--selector" "--duration" "--token" "--ca-file"))
      (is (search option help))))
  (signals error (parse-cli-options '("trace" "kprobe:vfs_read {}"))))

(test cli-options-describe-a-loopback-containerd-server
  (let ((options
          (parse-cli-options
           '("serve" "--state-directory" "/tmp/gr8s-state"
             "--listen" "127.0.0.1" "--port" "18080"
             "--runtime" "containerd"
             "--containerd-mode" "external"
             "--containerd-socket" "/tmp/containerd.sock"
             "--containerd-log-root" "/tmp/gr8s-logs/"
             "--registry-credentials-file" "/etc/gr8s/registry.json"
             "--image-credential-provider-config" "/etc/gr8s/providers.yaml"
             "--image-credential-provider-bin-dir" "/usr/libexec/gr8s/credentials/"
             "--dns-forward" "corp.example=192.0.2.53"
             "--dns-forward" "dev.corp.example=192.0.2.54:5353"
             "--kubeconfig" "/tmp/gr8s.conf"))))
    (is (eq :serve (getf options :command)))
    (is (string= "/tmp/gr8s-state" (getf options :state-directory)))
    (is (= 18080 (getf options :port)))
    (is (string= "containerd" (getf options :runtime)))
    (is (string= "external" (getf options :containerd-mode)))
    (is (string= "/tmp/containerd.sock"
                 (getf options :containerd-socket)))
    (is (string= "/tmp/gr8s-logs/"
                 (getf options :containerd-log-root)))
    (is (string= "/etc/gr8s/registry.json"
                 (getf options :registry-credentials-file)))
    (is (string= "/etc/gr8s/providers.yaml"
                 (getf options :image-credential-provider-config)))
    (is (string= "/usr/libexec/gr8s/credentials/"
                 (getf options :image-credential-provider-bin-dir)))
    (is (equal '(("corp.example" ("192.0.2.53" . 53))
                 ("dev.corp.example" ("192.0.2.54" . 5353)))
               (getf options :dns-forward-rules)))
    (is (string= "/tmp/gr8s.conf" (getf options :kubeconfig)))))

(test managed-containerd-options-build-an-owned-runtime
  (let ((options (parse-cli-options
                  '("serve" "--state-directory" "/tmp/gr8s-managed"))))
    (multiple-value-bind (runtime manager)
        (gr8s.server::runtime-from-options options)
      (is (typep manager 'gr8s.kubelet::managed-containerd))
      (is (string= "/tmp/gr8s-managed/containerd/run/containerd.sock"
                   (gr8s.kubelet::managed-containerd-socket-path manager)))
      (is (string= (gr8s.kubelet::managed-containerd-socket-path manager)
                   (gr8s.runtime.containerd::containerd-runtime-socket-path runtime)))
      (is (not (gr8s.runtime.containerd::containerd-runtime-host-network runtime)))
      (is (equal '("169.254.1.1")
                 (gr8s.runtime.containerd::containerd-runtime-dns-servers runtime)))
      (is (equal '("default.svc.cluster.local"
                   "svc.cluster.local"
                   "cluster.local")
                 (gr8s.runtime.containerd::containerd-runtime-dns-searches runtime)))
      (is (equal '("ndots:5")
                 (gr8s.runtime.containerd::containerd-runtime-dns-options runtime))))))

(test managed-containerd-uses-runtime-assets-from-the-dumped-image
  (let* ((assets
           (list (gr8s.runtime::make-runtime-asset :name "containerd" :octets #(1))
                 (gr8s.runtime::make-runtime-asset
                  :name "containerd-shim-runc-v2" :octets #(2))
                 (gr8s.runtime::make-runtime-asset :name "runc" :octets #(3))))
         (gr8s.runtime::*embedded-runtime-assets* assets)
         (options (parse-cli-options
                   '("serve" "--state-directory" "/tmp/gr8s-embedded"))))
    (multiple-value-bind (runtime manager)
        (gr8s.server::runtime-from-options options)
      (declare (ignore runtime))
      (is (eq assets (gr8s.kubelet::managed-containerd-runtime-assets manager))))))

(test external-containerd-options-do-not-create-a-supervisor
  (let ((options
          (parse-cli-options
           '("serve" "--containerd-mode" "external"
             "--containerd-socket" "/tmp/external-containerd.sock"))))
    (multiple-value-bind (runtime manager)
        (gr8s.server::runtime-from-options options)
      (is (null manager))
      (is (string= "/tmp/external-containerd.sock"
                   (gr8s.runtime.containerd::containerd-runtime-socket-path runtime)))
      (is (not (gr8s.runtime.containerd::containerd-runtime-host-network runtime))))))

(test kubeconfig-points-kubectl-at-gr8s
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (path (merge-pathnames "config" directory)))
      (multiple-value-bind (certificate key) (gr8s.apiserver::ensure-admin-client-credentials pki)
        (gr8s.server::write-kubeconfig path "https://127.0.0.1:6443"
                               :ca-certificate (gr8s.security::cluster-pki-ca-certificate-path pki)
                               :client-certificate certificate :client-key key))
      (let ((text (uiop:read-file-string path)))
        (is (search "server: https://127.0.0.1:6443" text))
        (is (search "current-context: gr8s" text))))))

(test serve-defaults-to-the-standard-secure-kubernetes-api
  (let ((options (gr8s.server::parse-serve-options nil)))
    (is (string= "0.0.0.0" (getf options :listen)))
    (is (= 6443 (getf options :port)))))

(test administrative-kubeconfig-embeds-cluster-trust-and-client-identity
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (path (merge-pathnames "admin.kubeconfig" directory)))
      (multiple-value-bind (certificate key)
          (gr8s.apiserver::ensure-admin-client-credentials pki)
        (gr8s.server::write-kubeconfig
         path "https://127.0.0.1:6443"
         :ca-certificate (gr8s.security::cluster-pki-ca-certificate-path pki)
         :client-certificate certificate :client-key key :private t))
      (let ((text (uiop:read-file-string path)))
        (is (search "server: https://127.0.0.1:6443" text))
        (is (search "certificate-authority-data:" text))
        (is (search "client-certificate-data:" text))
        (is (search "client-key-data:" text))
        (is-false (search "user: {}" text))))))

(test administrative-kubeconfig-embeds-the-complete-ca-rotation-trust-window
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki-root (merge-pathnames "pki/" directory))
           (pki (gr8s.security::ensure-cluster-pki pki-root))
           (path (merge-pathnames "rotating.kubeconfig" directory)))
      (gr8s.server::prepare-cluster-ca-rotation pki-root)
      (setf pki (gr8s.security::ensure-cluster-pki pki-root))
      (multiple-value-bind (certificate key)
          (gr8s.apiserver::ensure-admin-client-credentials pki)
        (gr8s.server::write-kubeconfig
         path "https://127.0.0.1:6443"
         :ca-certificates (gr8s.security::cluster-pki-trust-certificates pki)
         :client-certificate certificate :client-key key))
      (let ((text (uiop:read-file-string path)))
        (is (search
             (gr8s.server::kubeconfig-ca-data
              nil (gr8s.security::cluster-pki-trust-certificates pki))
             text))
        (is (= 2 (length (gr8s.security::cluster-pki-trust-certificates pki))))))))

(test kubeconfig-without-output-prints-to-stdout
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (options (gr8s.server::parse-cli-options
                     (list "kubeconfig" "--state-directory" (namestring directory)))))
      (is (null (getf options :output)))
      (multiple-value-bind (certificate key) (gr8s.apiserver::ensure-admin-client-credentials pki)
        (let ((text (with-output-to-string (stream)
                      (gr8s.server::print-kubeconfig
                       stream (getf options :server)
                       :ca-certificate (gr8s.security::cluster-pki-ca-certificate-path pki)
                       :client-certificate certificate :client-key key))))
          (is (search "server: https://127.0.0.1:6443" text))
          (is (search "current-context: gr8s" text)))))))

(test serve-defaults-its-kubeconfig-into-the-state-directory
  (let* ((directory (merge-pathnames (format nil "gr8s-kubeconfig-~36R/" (random (expt 36 8)))
                                     (uiop:temporary-directory)))
         (options (gr8s.server::parse-cli-options (list "serve" "--state-directory" (namestring directory))))
         (path (gr8s.server::default-kubeconfig-path options)))
    (unwind-protect
         (progn
           (is (null (getf options :kubeconfig)))
           (is (equal (merge-pathnames "kubeconfig" directory) path))
           (let ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" directory))))
             (multiple-value-bind (certificate key) (gr8s.apiserver::ensure-admin-client-credentials pki)
               (gr8s.server::write-kubeconfig path "https://127.0.0.1:6443" :private t
                                      :ca-certificate (gr8s.security::cluster-pki-ca-certificate-path pki)
                                      :client-certificate certificate :client-key key)))
           (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat path)))))
           (is (search "server: https://127.0.0.1:6443" (uiop:read-file-string path))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test server-api-refuses-non-loopback-listeners
  (signals error
    (start-server :address "0.0.0.0" :port 18080)))

(test reconciliation-worker-retries-transient-runtime-failures
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime))
           (worker nil))
      (set-fake-runtime-failure runtime "transient")
      (unwind-protect
           (progn
             (setf worker
                   (start-reconciliation-worker reconciler :interval 0.01))
             (loop repeat 100
                   until (= 1 (fake-runtime-ensure-count runtime))
                   do (sleep 0.01))
             (is (= 1 (fake-runtime-ensure-count runtime))))
        (when worker (stop-reconciliation-worker worker))))))

(test reconciliation-worker-stops-without-waiting-for-its-cadence
  (with-temporary-store (store path)
    (let* ((worker (start-reconciliation-worker
                    (make-reconciler store (make-fake-runtime))
                    :interval 10.0))
           (started (get-internal-real-time)))
      (sleep 0.05)
      (setf started (get-internal-real-time))
      (stop-reconciliation-worker worker)
      (is (< (/ (- (get-internal-real-time) started)
                internal-time-units-per-second)
             1.0)))))

(test node-listener-and-underlay-options-are-explicit-and-validated
  (let ((options (gr8s.server::parse-serve-options
                  '("--node-listen" "0.0.0.0" "--node-address" "192.0.2.10"))))
    (is (string= "0.0.0.0" (getf options :node-listen)))
    (is (string= "192.0.2.10" (getf options :node-address)))
    (is (string= "0.0.0.0" (getf options :listen))))
  (let ((options (gr8s.server::parse-agent-options
                  '("--server" "192.0.2.1:7443" "--token" "test" "--ca-pin" "test"
                    "--node-name" "worker-a" "--state-directory" "/tmp/worker-a"
                    "--node-address" "192.0.2.11"))))
    (is (string= "192.0.2.11" (getf options :node-address))))
  (dolist (address '("127.0.0.1" "0.0.0.0" "224.0.0.1" "255.255.255.255" "192.0.2.1/24"))
    (signals error (gr8s.server::parse-serve-options (list "--node-address" address)))))

(test wireguard-endpoint-options-are-named-repeatable-and-validated
  (let ((options
          (gr8s.server::parse-agent-options
           '("--server" "192.0.2.1:7443" "--token" "test" "--ca-pin" "test"
             "--node-name" "worker-a" "--state-directory" "/tmp/worker-a"
             "--wireguard-endpoint" "private=10.0.0.11:51820"
             "--wireguard-endpoint" "public=192.0.2.11:51821"))))
    (is (equal '(("private" "10.0.0.11" 51820)
                 ("public" "192.0.2.11" 51821))
               (getf options :wireguard-endpoints))))
  (dolist (value '("private" "=10.0.0.11:51820" "private=127.0.0.1:51820"
                   "private=10.0.0.11:0" "private=10.0.0.11:not-a-port"))
    (signals error
      (gr8s.server::parse-agent-options
       (list "--server" "192.0.2.1:7443" "--token" "test" "--ca-pin" "test"
             "--node-name" "worker-a" "--state-directory" "/tmp/worker-a"
             "--wireguard-endpoint" value))))
  (signals error
    (gr8s.server::parse-agent-options
     '("--server" "192.0.2.1:7443" "--token" "test" "--ca-pin" "test"
       "--node-name" "worker-a" "--state-directory" "/tmp/worker-a"
       "--wireguard-endpoint" "private=10.0.0.11:51820"
       "--wireguard-endpoint" "private=192.0.2.11:51820"))))

(test wireguard-relay-options-are-explicit-and-bounded
  (let ((options
          (gr8s.server::parse-serve-options
           '("--overlay-backend" "wireguard"
             "--wireguard-relay-address" "203.0.113.9"
             "--wireguard-relay-listen" "0.0.0.0"
             "--wireguard-relay-port-start" "46000"
             "--wireguard-relay-max-channels" "17"))))
    (is (string= "203.0.113.9" (getf options :wireguard-relay-address)))
    (is (string= "0.0.0.0" (getf options :wireguard-relay-listen)))
    (is (= 46000 (getf options :wireguard-relay-port-start)))
    (is (= 17 (getf options :wireguard-relay-max-channels))))
  (signals error
    (gr8s.server::parse-serve-options
     '("--wireguard-relay-address" "203.0.113.9")))
  (signals error
    (gr8s.server::parse-serve-options
     '("--overlay-backend" "wireguard"
       "--wireguard-relay-address" "203.0.113.9"
       "--wireguard-relay-port-start" "65535")))
  (signals error
    (gr8s.server::parse-serve-options
     '("--overlay-backend" "wireguard"
       "--wireguard-relay-address" "203.0.113.9"
       "--raft-init"))))

(test dns-forward-options-apply-to-serve-and-standalone-agents
  (let ((agent (gr8s.server::parse-agent-options
                '("--server" "192.0.2.1:7443" "--token" "test" "--ca-pin" "test"
                  "--node-name" "worker-a" "--state-directory" "/tmp/worker-a"
                  "--dns-forward" "corp.example=192.0.2.53"
                  "--dns-forward" "corp.example=192.0.2.54:5353"))))
    (is (equal '(("corp.example" ("192.0.2.53" . 53) ("192.0.2.54" . 5353)))
               (getf agent :dns-forward-rules))))
  (dolist (invalid '("corp.example" "=192.0.2.53" "corp.example=not-an-ip"
                     "corp.example=192.0.2.53:0"))
    (signals error (gr8s.server::parse-serve-options (list "--dns-forward" invalid)))))

(test join-token-command-uses-the-running-clusters-persisted-pki
  (with-temporary-store (store path)
    (assert store)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (options (parse-cli-options
                     (list "join-token" "--node-name" "worker-b"
                           "--state-directory" (namestring path))))
           (json (with-output-to-string (stream)
                   (is (= 0 (gr8s.server::print-node-join-token options stream)))))
           (result (com.inuoe.jzon:parse json)))
      (is (string= "worker-b" (gethash "nodeName" result)))
      (is (string= (gr8s.security::cluster-pki-ca-fingerprint pki) (gethash "caPin" result)))
      (multiple-value-bind (identifier secret) (gr8s.security::split-join-token (gethash "token" result))
        (declare (ignore secret))
        (let ((record (gr8s.security::load-token-record pki identifier)))
          (is (string= "worker-b" (gethash "nodeName" record)))
          (is (string= "unused" (gethash "state" record))))))))

(test join-token-command-does-not-bootstrap-a-new-cluster
  (with-temporary-store (store path)
    (assert store)
    (signals error
      (gr8s.server::print-node-join-token
       (parse-cli-options (list "join-token" "--node-name" "worker-b"
                                "--state-directory" (namestring path)))
       (make-broadcast-stream)))
    (is-false (probe-file (merge-pathnames "pki/" path)))))

(test enrolled-agent-restarts-without-a-bootstrap-token
  (with-temporary-store (store path)
    (assert store)
    (let* ((directory (merge-pathnames "enrolled-agent/" path))
           (arguments (list "agent" "--server" "127.0.0.1:7443" "--node-name" "worker-a"
                            "--state-directory" (namestring directory))))
      (signals error (parse-cli-options arguments))
      (dolist (name '("node.key" "node.crt"))
        (gr8s.security::write-private-text-exclusively (merge-pathnames name directory) "fixture"))
      (signals error (parse-cli-options arguments))
      (gr8s.security::write-private-text-exclusively (merge-pathnames "ca.crt" directory) "fixture")
      (let ((options (parse-cli-options arguments)))
        (is (eq :agent (getf options :command)))
        (is-false (getf options :token))
        (is-false (getf options :ca-pin))))))

(defun run-with-stale-timeout-guard (function)
  "Call FUNCTION with the process-wide timeout guard installed, then remove it."
  (let ((hook sb-ext:*invoke-debugger-hook*) (installed gr8s.server::*stale-timeout-guard-installed*))
    (unwind-protect
         (progn
           (setf gr8s.server::*stale-timeout-guard-installed* nil)
           (gr8s.server::install-stale-timeout-guard)
           (funcall function))
      (setf sb-ext:*invoke-debugger-hook* hook
            gr8s.server::*stale-timeout-guard-installed* installed))))

(test a-late-timeout-interrupt-cannot-end-a-thread-holding-a-lock
  ;; This is what crashed a full run: a timer fired after its scope, during a lock wait.
  (let ((*error-output* (make-broadcast-stream))
        (lock (bt:make-lock "held by another thread"))
        (waiting (sb-thread:make-semaphore))
        (finished nil))
    (run-with-stale-timeout-guard
     (lambda ()
       (let* ((worker
                (bt:with-lock-held (lock)
                  (prog1
                      (sb-thread:make-thread
                       (lambda ()
                         (sb-thread:signal-semaphore waiting)
                         (bt:with-lock-held (lock) (setf finished t))))
                    (sb-thread:wait-on-semaphore waiting)
                    (sleep 0.2)))))
         (values worker)
         (sb-thread:join-thread worker :timeout 10)
         (is-true finished))
       (let* ((gate (sb-thread:make-semaphore)) (result nil)
              (worker (sb-thread:make-thread
                       (lambda ()
                         (sb-thread:wait-on-semaphore gate)
                         (setf result :completed)))))
         (sleep 0.2)
         (sb-thread:interrupt-thread worker
                                     (lambda () (cerror "Continue" 'sb-ext:timeout :seconds 30)))
         (sleep 0.2)
         (is (sb-thread:thread-alive-p worker))
         (sb-thread:signal-semaphore gate)
         (sb-thread:join-thread worker :timeout 10)
         (is (eq :completed result)))))))

(test the-guard-only-continues-timeouts
  (let ((hook sb-ext:*invoke-debugger-hook*) (installed gr8s.server::*stale-timeout-guard-installed*)
        (seen nil))
    (unwind-protect
         (progn
           (setf gr8s.server::*stale-timeout-guard-installed* nil
                 sb-ext:*invoke-debugger-hook* (lambda (condition hook)
                                                 (declare (ignore hook))
                                                 (push condition seen)))
           (gr8s.server::install-stale-timeout-guard)
           ;; Other conditions, and a timeout with nothing to continue, reach the old hook.
           (let ((real (make-condition 'simple-error :format-control "real"))
                 (bare (make-condition 'sb-ext:timeout)))
             (funcall sb-ext:*invoke-debugger-hook* real nil)
             (funcall sb-ext:*invoke-debugger-hook* bare nil)
             (is (equal (list bare real) seen))))
      (setf sb-ext:*invoke-debugger-hook* hook
            gr8s.server::*stale-timeout-guard-installed* installed))))

(test the-worker-loop-survives-a-timeout
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let* ((calls 0)
           (*error-output* (make-broadcast-stream))
           (worker (gr8s.server::start-reconciliation-worker
                    (gr8s.kubelet::make-reconciler store (make-fake-runtime))
                    :interval 0.05
                    :before-reconcile (lambda ()
                                        (when (= 1 (incf calls))
                                          (signal 'sb-ext:timeout :seconds 30)
                                          (error 'sb-ext:timeout :seconds 30))))))
      (unwind-protect
           (progn
             (loop repeat 100 until (> calls 2) do (sleep 0.05))
             (is (> calls 2)))
        (gr8s.server::stop-reconciliation-worker worker)))))

(test skill-command-prints-offline-guidance
  (is (eq :skill (getf (parse-cli-options '("skill")) :command)))
  (signals error (parse-cli-options '("skill" "unexpected")))
  (let ((output (with-output-to-string (*standard-output*)
                  (is (= 0 (gr8s.server::main-with-environment
                            '("skill") (constantly nil) (constantly 99)))))))
    (is (search "# gr8s operator and agent guide" output))
    (is (search "gr8s debug slynk" output))
    (is (search "gr8s debug trace --server" output))
    (is (search "gr8s doctor" output))
    (is (search "gr8s net-agent" output))
    (is (search "deploy/chart/gr8s-net" output)))
  (dolist (arguments '(("help") ("skill" "--help") ("help" "skill")))
    (let ((output (with-output-to-string (*standard-output*)
                    (is (= 0 (gr8s.server::main-with-environment
                              arguments (constantly nil) (constantly 99)))))))
      (is (search "skill" output)))))

(test net-agent-features-are-independently-selectable
  (let ((options (gr8s.server::parse-net-agent-options nil)))
    (is (eq :net-agent (getf options :command)))
    (is-true (getf options :cni))
    (is-false (getf options :gateway))
    (is-false (getf options :service-lb)))
  (let ((options (gr8s.server::parse-net-agent-options
                  '("--cni" "false" "--gateway" "true"))))
    (is-false (getf options :cni))
    (is-true (getf options :gateway)))
  (is-true (getf (gr8s.server::parse-net-agent-options
                  '("--cni" "false" "--service-lb" "true"))
                 :service-lb))
  ;; An agent with every feature off would only watch and do nothing.
  (signals error (gr8s.server::parse-net-agent-options '("--cni" "false")))
  (signals error (gr8s.server::parse-net-agent-options '("--cni")))
  (signals error (gr8s.server::parse-net-agent-options '("--unknown" "x"))))


(test serve-compaction-defaults-to-ha-and-supports-explicit-overrides
  (is-false (getf (gr8s.server::parse-serve-options nil) :raft-compaction))
  (is-true (getf (gr8s.server::parse-serve-options '("--raft-init")) :raft-compaction))
  (is-true (getf (gr8s.server::parse-serve-options '("--raft-join" "127.0.0.1:7449")) :raft-compaction))
  (is-false (getf (gr8s.server::parse-serve-options '("--raft-init" "--no-raft-compaction")) :raft-compaction))
  (is-false (getf (gr8s.server::parse-serve-options '("--no-raft-compaction")) :raft-compaction))
  (is-false (getf (gr8s.server::parse-serve-options '("--raft-init" "--raft-compaction" "--no-raft-compaction")) :raft-compaction))
  (is-true (getf (gr8s.server::parse-serve-options '("--raft-init" "--no-raft-compaction" "--raft-compaction")) :raft-compaction))
  (is-true (getf (gr8s.server::parse-serve-options '("--raft-init" "--raft-compaction")) :raft-compaction))
  (is-true (getf (gr8s.server::parse-serve-options '("--raft-compaction" "--raft-join" "127.0.0.1:7449")) :raft-compaction))
  (signals error (gr8s.server::parse-serve-options '("--raft-compaction"))))

(test production-ha-startup-forwards-default-and-explicit-compaction
  (dolist (enabled '(nil t))
    (with-temporary-store (store root)
      (declare (ignore root))
      (let* ((options (gr8s.server::parse-serve-options
                       (append '("--raft-init" "--node-name" "cli-compaction" "--listen" "127.0.0.1")
                               (unless enabled '("--no-raft-compaction")))))
             (ha nil))
        ;; Bind an ephemeral transport port in this source-level startup test.
        (setf (getf options :raft-port) 0)
        (unwind-protect
             (progn
               (setf ha (gr8s.server::maybe-start-ha-control-plane store nil options))
               (is (not (null ha)))
               (is (eq enabled (not (null (gr8s.ha::ha-control-plane-compaction-thread ha)))))
               (is (eql (if enabled 1 nil) (gr8s.ha::ha-control-plane-compaction-interval ha))))
          (when ha (gr8s.ha::stop-ha-control-plane ha)))))))
