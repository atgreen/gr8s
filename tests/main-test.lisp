(in-package #:gr8s/tests)

(in-suite gr8s)

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
    (is (= 7443 (getf options :node-port)))
    (is (string= "gr8s-local" (getf options :node-name)))
    (is-false (getf options :disable-agent))))

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

(test help-documents-every-node-role-option
  (let ((help (with-output-to-string (*standard-output*)
                (gr8s::print-help))))
    (dolist (word '("gr8s serve" "gr8s agent" "--node-port"
                    "--disable-agent" "--server" "--token" "--ca-pin"
                    "--node-name" "--state-directory"))
      (is (search word help)))))

(test cni-environment-dispatches-before-command-line-parsing
  (let ((called nil))
    (is (= 27
           (gr8s::main-with-environment
            '("not-a-gr8s-command")
            (lambda (name)
              (and (string= name "CNI_COMMAND") "VERSION"))
            (lambda ()
              (setf called t)
              27))))
    (is (eq t called))))

(test runtime-assets-command-reports-the-dumped-payload
  (is (eq :runtime-assets
          (getf (parse-cli-options '("runtime-assets")) :command)))
  (let ((gr8s::*embedded-runtime-assets*
          (list (gr8s::make-runtime-asset
                 :name "containerd"
                 :octets (make-array 42 :element-type '(unsigned-byte 8))))))
    (let ((output (with-output-to-string (*standard-output*)
                    (gr8s::print-runtime-assets))))
      (is (search "containerd" output))
      (is (search "42 bytes" output)))))

(test cli-options-describe-a-loopback-containerd-server
  (let ((options
          (parse-cli-options
           '("serve" "--state-directory" "/tmp/gr8s-state"
             "--listen" "127.0.0.1" "--port" "18080"
             "--runtime" "containerd"
             "--containerd-mode" "external"
             "--containerd-socket" "/tmp/containerd.sock"
             "--containerd-log-root" "/tmp/gr8s-logs/"
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
    (is (string= "/tmp/gr8s.conf" (getf options :kubeconfig)))))

(test managed-containerd-options-build-an-owned-runtime
  (let ((options (parse-cli-options
                  '("serve" "--state-directory" "/tmp/gr8s-managed"))))
    (multiple-value-bind (runtime manager)
        (gr8s::runtime-from-options options)
      (is (typep manager 'gr8s::managed-containerd))
      (is (string= "/tmp/gr8s-managed/containerd/run/containerd.sock"
                   (gr8s::managed-containerd-socket-path manager)))
      (is (string= (gr8s::managed-containerd-socket-path manager)
                   (gr8s::containerd-runtime-socket-path runtime)))
      (is (not (gr8s::containerd-runtime-host-network runtime)))
      (is (equal '("169.254.1.1")
                 (gr8s::containerd-runtime-dns-servers runtime)))
      (is (equal '("default.svc.cluster.local"
                   "svc.cluster.local"
                   "cluster.local")
                 (gr8s::containerd-runtime-dns-searches runtime)))
      (is (equal '("ndots:5")
                 (gr8s::containerd-runtime-dns-options runtime))))))

(test managed-containerd-uses-runtime-assets-from-the-dumped-image
  (let* ((assets
           (list (gr8s::make-runtime-asset :name "containerd" :octets #(1))
                 (gr8s::make-runtime-asset
                  :name "containerd-shim-runc-v2" :octets #(2))
                 (gr8s::make-runtime-asset :name "runc" :octets #(3))))
         (gr8s::*embedded-runtime-assets* assets)
         (options (parse-cli-options
                   '("serve" "--state-directory" "/tmp/gr8s-embedded"))))
    (multiple-value-bind (runtime manager)
        (gr8s::runtime-from-options options)
      (declare (ignore runtime))
      (is (eq assets (gr8s::managed-containerd-runtime-assets manager))))))

(test external-containerd-options-do-not-create-a-supervisor
  (let ((options
          (parse-cli-options
           '("serve" "--containerd-mode" "external"
             "--containerd-socket" "/tmp/external-containerd.sock"))))
    (multiple-value-bind (runtime manager)
        (gr8s::runtime-from-options options)
      (is (null manager))
      (is (string= "/tmp/external-containerd.sock"
                   (gr8s::containerd-runtime-socket-path runtime)))
      (is (not (gr8s::containerd-runtime-host-network runtime))))))

(test kubeconfig-points-kubectl-at-gr8s
  (let ((path (merge-pathnames
               (format nil "gr8s-kubeconfig-~36R/config" (random (expt 36 8)))
               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (gr8s:write-kubeconfig path "http://127.0.0.1:18080")
           (let ((text (uiop:read-file-string path)))
             (is (search "server: http://127.0.0.1:18080" text))
             (is (search "current-context: gr8s" text))))
      (uiop:delete-directory-tree
       (uiop:pathname-directory-pathname path)
       :validate t :if-does-not-exist :ignore))))

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
  (let ((options (gr8s::parse-serve-options
                  '("--node-listen" "0.0.0.0" "--node-address" "192.0.2.10"))))
    (is (string= "0.0.0.0" (getf options :node-listen)))
    (is (string= "192.0.2.10" (getf options :node-address)))
    (is (string= "127.0.0.1" (getf options :listen))))
  (let ((options (gr8s::parse-agent-options
                  '("--server" "192.0.2.1:7443" "--token" "test" "--ca-pin" "test"
                    "--node-name" "worker-a" "--state-directory" "/tmp/worker-a"
                    "--node-address" "192.0.2.11"))))
    (is (string= "192.0.2.11" (getf options :node-address))))
  (dolist (address '("127.0.0.1" "0.0.0.0" "224.0.0.1" "255.255.255.255" "192.0.2.1/24"))
    (signals error (gr8s::parse-serve-options (list "--node-address" address)))))

(test join-token-command-uses-the-running-clusters-persisted-pki
  (with-temporary-store (store path)
    (assert store)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (options (parse-cli-options
                     (list "join-token" "--node-name" "worker-b"
                           "--state-directory" (namestring path))))
           (json (with-output-to-string (stream)
                   (is (= 0 (gr8s::print-node-join-token options stream)))))
           (result (com.inuoe.jzon:parse json)))
      (is (string= "worker-b" (gethash "nodeName" result)))
      (is (string= (gr8s:cluster-pki-ca-fingerprint pki) (gethash "caPin" result)))
      (multiple-value-bind (identifier secret) (gr8s::split-join-token (gethash "token" result))
        (declare (ignore secret))
        (let ((record (gr8s::load-token-record pki identifier)))
          (is (string= "worker-b" (gethash "nodeName" record)))
          (is (string= "unused" (gethash "state" record))))))))

(test join-token-command-does-not-bootstrap-a-new-cluster
  (with-temporary-store (store path)
    (assert store)
    (signals error
      (gr8s::print-node-join-token
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
        (gr8s::write-private-text-exclusively (merge-pathnames name directory) "fixture"))
      (signals error (parse-cli-options arguments))
      (gr8s::write-private-text-exclusively (merge-pathnames "ca.crt" directory) "fixture")
      (let ((options (parse-cli-options arguments)))
        (is (eq :agent (getf options :command)))
        (is-false (getf options :token))
        (is-false (getf options :ca-pin))))))
