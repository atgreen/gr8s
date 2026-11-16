(in-package #:gr8s/tests)

(in-suite gr8s)

(test containerd-platform-follows-the-host-machine-type
  (is (string= "linux/amd64"
               (gr8s.kubelet::containerd-platform-for-machine "x86_64")))
  (is (string= "linux/amd64"
               (gr8s.kubelet::containerd-platform-for-machine "X86-64")))
  (is (string= "linux/arm64"
               (gr8s.kubelet::containerd-platform-for-machine "aarch64")))
  (is (string= "linux/arm64"
               (gr8s.kubelet::containerd-platform-for-machine "ARM64")))
  (signals error
    (gr8s.kubelet::containerd-platform-for-machine "mips64")))

(test managed-containerd-syncs-metadata-unless-told-not-to
  (flet ((config (&rest arguments)
           (gr8s.kubelet::managed-containerd-config-text
            (apply #'gr8s.kubelet::make-managed-containerd
                   :state-directory "/var/lib/gr8s/" :executable "/opt/gr8s/bin/containerd"
                   :oci-runtime "/opt/gr8s/bin/runc" :cni-bin-directory "/opt/gr8s/bin/cni/"
                   :platform "linux/amd64" arguments))))
    (is (not (search "no_sync" (config))))
    (let ((unsynced (config :metadata-no-sync t)))
      (is (search "[plugins.'io.containerd.metadata.v1.bolt']" unsynced))
      (is (search "no_sync = true" unsynced))
      ;; The table must not swallow the keys that follow it.
      (is (search "snapshotter = 'overlayfs'" unsynced))))
  (is (getf (gr8s.server::parse-cli-options '("serve" "--containerd-no-sync" "--port" "18080")) :containerd-no-sync))
  (is (not (getf (gr8s.server::parse-cli-options '("serve" "--port" "18080")) :containerd-no-sync))))

(test native-v2-cni-profile-requires-explicit-staged-opt-in
  (let* ((manager (gr8s.kubelet::make-managed-containerd
                   :state-directory "/var/lib/gr8s/"
                   :executable "/opt/gr8s/bin/containerd"
                   :oci-runtime "/opt/gr8s/bin/runc"
                   :cni-bin-directory "/opt/gr8s/bin/cni/"
                   :platform "linux/amd64"))
         (names '("GR8S_ENABLE_PACKET_SERVICES"
                  "GR8S_PREPARE_PACKET_SERVICES_V2"
                  "GR8S_ENABLE_NATIVE_SERVICE_V2"))
         (prior (mapcar #'uiop:getenv names)))
    (unwind-protect
         (progn
           (dolist (name names) (sb-posix:unsetenv name))
           (is-false (search "servicePacketProfile"
                             (gr8s.kubelet::managed-containerd-cni-config-text manager)))
           (sb-posix:setenv (third names) "1" 1)
           (signals error (gr8s.kubelet::managed-containerd-cni-config-text manager))
           (sb-posix:setenv (first names) "1" 1)
           (signals error (gr8s.kubelet::managed-containerd-cni-config-text manager))
           (sb-posix:setenv (second names) "1" 1)
           (is (search "\"servicePacketProfile\":\"v2\""
                       (gr8s.kubelet::managed-containerd-cni-config-text manager))))
      (loop for name in names
            for value in prior
            do (if value (sb-posix:setenv name value 1)
                   (sb-posix:unsetenv name))))))

(test managed-containerd-appends-extra-runtime-handlers
  ;; podster-mgw: optional runtime payloads (e.g. a gVisor runsc addon) register
  ;; as additional CRI handlers after the built-in runc, without disturbing it.
  (let* ((manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory "/var/lib/gr8s/"
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/"
            :platform "linux/amd64"
            :extra-runtime-handlers
            (list (list :name "runsc" :runtime-type "io.containerd.runsc.v1"))))
         (config (gr8s.kubelet::managed-containerd-config-text manager))
         (runc (search "containerd.runtimes.runc]" config))
         (runsc (search "containerd.runtimes.runsc]" config)))
    ;; runc stays the default and keeps its options.
    (is (search "default_runtime_name = 'runc'" config))
    (is (search "runtime_type = 'io.containerd.runc.v2'" config))
    (is (search "BinaryName = '/opt/gr8s/bin/runc'" config))
    ;; the addon handler is present, typed, and ordered after runc.
    (is (search "runtime_type = 'io.containerd.runsc.v1'" config))
    (is (and runc runsc (< runc runsc)))
    ;; an options-less handler emits no empty [...options] table.
    (is (not (search "runtimes.runsc.options]" config)))))

(test managed-containerd-puts-addon-bin-dirs-on-the-shim-path
  ;; podster-nhf: containerd execs a runtime's shim binary by name, so an
  ;; addon's bin dir must be on the launched process PATH, with runc's own
  ;; prefix still leading.
  (let* ((manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory "/var/lib/gr8s/"
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/"
            :platform "linux/amd64"
            :extra-runtime-handlers
            (list (list :name "runsc" :runtime-type "io.containerd.runsc.v1"
                        :bin-dir "/var/lib/gr8s/runtime-addons/gvisor/"))))
         (path-entry (find-if (lambda (entry) (uiop:string-prefix-p "PATH=" entry))
                              (gr8s.kubelet::managed-containerd-environment manager))))
    (is (uiop:string-prefix-p "PATH=/opt/gr8s/bin:" path-entry))
    (is (search "/var/lib/gr8s/runtime-addons/gvisor:" path-entry))))

(test managed-containerd-keeps-all-state-under-its-private-directory
  (let* ((manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory "/var/lib/gr8s/"
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/"
            :platform "linux/arm64"))
         (config (gr8s.kubelet::managed-containerd-config-text manager)))
    (is (string= "/var/lib/gr8s/containerd/run/containerd.sock"
                 (gr8s.kubelet::managed-containerd-socket-path manager)))
    (is (string= "/var/lib/gr8s/containerd/run/gr8s-cni.sock"
                 (gr8s.kubelet::managed-containerd-agent-cni-socket-path manager)))
    (is (equal '("/opt/gr8s/bin/containerd"
                 "--config"
                 "/var/lib/gr8s/containerd/config.toml")
               (gr8s.kubelet::managed-containerd-command manager)))
    (is (search "root = '/var/lib/gr8s/containerd/root'" config))
    (is (search "state = '/var/lib/gr8s/containerd/run'" config))
    (is (search "address = '/var/lib/gr8s/containerd/run/containerd.sock'"
                config))
    (is (search
         (format nil "socket_dir = '~A'"
                 (gr8s.kubelet::managed-containerd-shim-socket-directory manager))
         config))
    (is (<= (length (gr8s.kubelet::managed-containerd-shim-socket-directory manager))
            42))
    (is (uiop:string-prefix-p
         "/tmp/gr8s-shims-"
         (gr8s.kubelet::managed-containerd-shim-socket-directory manager)))
    (is (search "BinaryName = '/opt/gr8s/bin/runc'" config))
    (is (search "Root = '/var/lib/gr8s/containerd/run/runc'" config))
    (is (search "restrict_oom_score_adj = true" config))
    (is (search "disable_hugetlb_controller = false" config))
    (is (search "tolerate_missing_hugetlb_controller = false" config))
    (is (search "bin_dirs = [\"/opt/gr8s/bin/cni/\"]" config))
    (is (search "conf_dir = '/var/lib/gr8s/containerd/cni/net.d'" config))
    (is (search "platform = 'linux/arm64'" config))))

(test managed-containerd-routes-registry-pulls-through-its-private-host-config
  (let* ((manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory "/var/lib/gr8s/"
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/"))
         (config (gr8s.kubelet::managed-containerd-config-text manager)))
    (is (search "[plugins.'io.containerd.cri.v1.images'.registry]" config))
    (is (search "config_path = '/var/lib/gr8s/containerd/certs.d'" config))))

(test managed-containerd-can-delegate-cni-configuration-to-operator-owned-plugins
  (let* ((root (merge-pathnames
                (format nil "gr8s-external-cni-~36R/" (random (expt 36 8)))
                (uiop:temporary-directory)))
         (config-directory (merge-pathnames "net.d/" root))
         (sentinel (merge-pathnames "10-calico.conflist" config-directory))
         (manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory (merge-pathnames "state/" root)
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/"
            :cni-bin-directories '("/opt/cni/bin/" "/var/lib/example-cni/bin/")
            :cni-mode "external"
            :cni-config-directory config-directory
            :platform "linux/amd64")))
    (unwind-protect
         (progn
           (ensure-directories-exist sentinel)
           (with-open-file (stream sentinel :direction :output :if-does-not-exist :create)
             (write-string "operator-owned" stream))
           (gr8s.kubelet::write-managed-containerd-config manager)
           (let ((config (gr8s.kubelet::managed-containerd-config-text manager)))
             (is (search "bin_dirs = [\"/opt/gr8s/bin/cni/\", \"/opt/cni/bin/\", \"/var/lib/example-cni/bin/\"]"
                         config))
             (is (search (format nil "conf_dir = '~A'" (namestring config-directory)) config)))
           (is (string= "operator-owned" (uiop:read-file-string sentinel)))
           (is-false (probe-file (gr8s.kubelet::managed-containerd-cni-config-path manager))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(test managed-containerd-escapes-operator-cni-bin-paths-as-toml
  (let* ((manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory "/var/lib/gr8s/"
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/"
            :cni-bin-directories '("/opt/operator's cni/")))
         (config (gr8s.kubelet::managed-containerd-config-text manager)))
    (is (search "bin_dirs = [\"/opt/gr8s/bin/cni/\", \"/opt/operator's cni/\"]"
                config))
    (is (string= "\"a\\\\b\\\"c\"" (gr8s.kubelet::toml-basic-string "a\\b\"c")))))

(test containerd-launcher-creates-a-new-log-file
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-containerd-log-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (log-path (merge-pathnames "containerd/containerd.log" directory)))
    (unwind-protect
         (let ((process
                 (gr8s.kubelet::launch-containerd-process
                  '("/bin/true") (namestring log-path)
                  #+sbcl (copy-list (sb-ext:posix-environ))
                  #-sbcl nil)))
           (uiop:wait-process process)
           (is (probe-file log-path)))
      (uiop:delete-directory-tree directory
                                  :validate t :if-does-not-exist :ignore))))

(test containerd-stop-prefers-graceful-termination
  (let ((alive t)
        (events nil))
    (gr8s.kubelet::terminate-containerd-process
     :child
     :timeout 0.1
     :process-alive-p (lambda (process)
                        (declare (ignore process))
                        alive)
     :terminator (lambda (process &key urgent)
                   (declare (ignore process))
                   (push (if urgent :kill :term) events)
                   (setf alive nil))
     :waiter (lambda (process)
               (declare (ignore process))
               (push :wait events))
     :sleeper (lambda (seconds) (declare (ignore seconds))))
    (is (equal '(:term :wait) (reverse events)))))

(test containerd-stop-forces-a-process-that-ignores-the-deadline
  (let ((events nil))
    (gr8s.kubelet::terminate-containerd-process
     :child
     :timeout 0
     :process-alive-p (lambda (process)
                        (declare (ignore process))
                        t)
     :terminator (lambda (process &key urgent)
                   (declare (ignore process))
                   (push (if urgent :kill :term) events))
     :waiter (lambda (process)
               (declare (ignore process))
               (push :wait events))
     :sleeper (lambda (seconds) (declare (ignore seconds))))
    (is (equal '(:term :kill :wait) (reverse events)))))

(test managed-containerd-writes-config-and-owns-its-child-process
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-managed-containerd-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (launched-command nil)
         (launched-log nil)
         (launched-environment nil)
         (stopped-process nil)
         (ready-count 0)
         (manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory directory
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/"
            :launcher (lambda (command log-path environment)
                        (setf launched-command command
                              launched-log log-path
                              launched-environment environment)
                        :child-process)
            :process-alive-p (lambda (process)
                               (eq process :child-process))
            :readiness-probe (lambda (socket-path)
                               (declare (ignore socket-path))
                               (incf ready-count)
                               t)
            :stopper (lambda (process)
                       (setf stopped-process process)))))
    (unwind-protect
         (progn
           (gr8s.kubelet::start-managed-containerd manager :timeout 0.1)
           (is (equal (gr8s.kubelet::managed-containerd-command manager)
                      launched-command))
           (is (string= (namestring (merge-pathnames "containerd/containerd.log"
                                                     directory))
                        launched-log))
           (is (uiop:string-prefix-p
                "PATH=/opt/gr8s/bin:"
                (find-if (lambda (entry) (uiop:string-prefix-p "PATH=" entry))
                         launched-environment)))
           (is (= 1 ready-count))
           (is (eq :child-process
                   (gr8s.kubelet::managed-containerd-process manager)))
           (is (string= (gr8s.kubelet::managed-containerd-config-text manager)
                        (uiop:read-file-string
                         (gr8s.kubelet::managed-containerd-config-path manager))))
           (let ((cni-config
                   (uiop:read-file-string
                    (gr8s.kubelet::managed-containerd-directory
                     manager "containerd/cni/net.d/10-gr8s.conflist"))))
             (is-false (search "\"type\":\"bridge\"" cni-config))
             (is-false (search "\"type\":\"host-local\"" cni-config))
             (is-false (search "\"type\":\"firewall\"" cni-config))
             (is (search "\"type\":\"gr8s\"" cni-config))
             (is (not (search "\"type\":\"gr8s-whistler\"" cni-config)))
             (is (search "\"direction\":\"egress\"" cni-config))
             (is (search
                  (format nil "\"socket\":~A"
                          (com.inuoe.jzon:stringify
                           (gr8s.kubelet::managed-containerd-agent-cni-socket-path
                            manager)))
                  cni-config))
             ;; The egress guard is JIT-compiled in-process; the conflist carries
             ;; no ELF "program" path.
             (is (not (search "gr8s-whistler.bpf.o" cni-config)))
             (is (not (search "\"program\"" cni-config)))
             (is (search
                  "\"mapPinRoot\":\""
                  cni-config))
             (is (search
                  (gr8s.kubelet::managed-containerd-directory
                   manager "containerd/bpf")
                  cni-config))
             (let* ((object (com.inuoe.jzon:parse cni-config))
                    (plugins (gethash "plugins" object)))
               (is (= 1 (length plugins)))
               (is-false (gethash "ipam" (aref plugins 0)))))
           (gr8s.kubelet::stop-managed-containerd manager)
           (is (eq :child-process stopped-process))
           (is (null (gr8s.kubelet::managed-containerd-process manager))))
      (gr8s.kubelet::stop-managed-containerd manager)
      (uiop:delete-directory-tree directory
                                  :validate t :if-does-not-exist :ignore))))

(test managed-containerd-reclaims-the-runtime-left-by-a-killed-agent
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-managed-owner-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory directory
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/"))
         (signals nil)
         (alive t))
    (unwind-protect
         (progn
           (gr8s.kubelet::write-managed-containerd-owner manager 2718 "4242")
           (gr8s.kubelet::reclaim-stale-managed-containerd
            manager
            :process-start-time (lambda (pid)
                                  (is (= 2718 pid))
                                  "4242")
            :process-command (lambda (pid)
                               (declare (ignore pid))
                               (gr8s.kubelet::managed-containerd-command manager))
            :process-alive-p (lambda (pid)
                               (declare (ignore pid))
                               alive)
            :signaler (lambda (pid signal)
                        (push (list pid signal) signals)
                        (when (= signal sb-posix:sigterm)
                          (setf alive nil)))
            :sleeper (lambda (seconds) (declare (ignore seconds))))
           (is (equal (list (list 2718 sb-posix:sigterm)) (reverse signals)))
           (is-false (probe-file (gr8s.kubelet::managed-containerd-owner-path manager))))
      (uiop:delete-directory-tree directory
                                  :validate t :if-does-not-exist :ignore))))

(test managed-containerd-never-signals-a-reused-owner-pid
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-managed-owner-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory directory
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/")))
    (unwind-protect
         (progn
           (gr8s.kubelet::write-managed-containerd-owner manager 2718 "old-start")
           (is-false
            (gr8s.kubelet::reclaim-stale-managed-containerd
             manager
             :process-start-time (lambda (pid) (declare (ignore pid)) "new-start")
             :process-command (lambda (pid)
                                (declare (ignore pid))
                                (gr8s.kubelet::managed-containerd-command manager))
             :process-alive-p (lambda (pid) (declare (ignore pid)) t)
             :signaler (lambda (&rest arguments)
                         (declare (ignore arguments))
                         (fail "a recycled pid was signaled"))))
           (is-false (probe-file (gr8s.kubelet::managed-containerd-owner-path manager))))
      (uiop:delete-directory-tree directory
                                  :validate t :if-does-not-exist :ignore))))

(test managed-containerd-reads-linux-process-identity
  (let* ((pid (sb-posix:getpid))
         (command (gr8s.kubelet::linux-process-command pid)))
    (is (parse-integer (gr8s.kubelet::linux-process-start-time pid)))
    (is (and command (plusp (length (first command)))))
    (is (gr8s.kubelet::linux-process-alive-p pid))))

(test managed-containerd-lifecycle-wraps-the-server-body
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-managed-lifecycle-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (events nil)
         (process (list :managed-containerd-process))
         (manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory directory
            :executable "/opt/gr8s/containerd"
            :oci-runtime "/opt/gr8s/runc"
            :cni-bin-directory "/opt/gr8s/cni/"
            :bpf-mounter (lambda (directory)
                           (is (search "containerd/bpf" directory))
                           (push :bpf-mount events))
            :bpf-unmounter (lambda (directory)
                             (is (search "containerd/bpf" directory))
                             (push :bpf-unmount events))
            :launcher (lambda (command log-path environment)
                        (declare (ignore command log-path environment))
                        (push :start events)
                        process)
            :process-alive-p (lambda (candidate)
                               (eq candidate process))
            :readiness-probe (lambda (socket-path)
                               (declare (ignore socket-path))
                               t)
            :stopper (lambda (candidate)
                       (is (eq process candidate))
                       (push :stop events)))))
    (unwind-protect
         (progn
           (gr8s.kubelet::call-with-managed-containerd
            manager
            (lambda ()
              (push :body events)))
           (is (equal '(:bpf-mount :start :body :stop :bpf-unmount)
                      (reverse events)))
           (is (null (gr8s.kubelet::managed-containerd-process manager))))
      (gr8s.kubelet::stop-managed-containerd manager)
      (uiop:delete-directory-tree directory
                                  :validate t :if-does-not-exist :ignore))))

(test embedded-runtime-is-prepared-before-containerd-and-released-after-it
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-managed-assets-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (events nil)
         (assets (list (gr8s.runtime::make-runtime-asset :name "containerd" :octets #(1))
                       (gr8s.runtime::make-runtime-asset
                        :name "containerd-shim-runc-v2" :octets #(2))
                       (gr8s.runtime::make-runtime-asset :name "runc" :octets #(3))
                       (gr8s.runtime::make-runtime-asset :name "bridge" :octets #(4))
                       (gr8s.runtime::make-runtime-asset
                        :name "host-local" :octets #(5))
                       (gr8s.runtime::make-runtime-asset
                        :name "loopback" :octets #(6))
                       (gr8s.runtime::make-runtime-asset
                        :name "gr8s-whistler.bpf.o" :octets #(8))))
         (manager
           (gr8s.kubelet::make-managed-containerd
            :state-directory directory
            :runtime-assets assets
            :runtime-preparer
            (lambda (payload runtime-directory function)
              (declare (ignore payload))
              (push :prepare events)
              (funcall function
                       `(("containerd" . ,(merge-pathnames "containerd"
                                                          runtime-directory))
                         ("containerd-shim-runc-v2"
                          . ,(merge-pathnames "containerd-shim-runc-v2"
                                             runtime-directory))
                         ("runc" . ,(merge-pathnames "runc"
                                                    runtime-directory))
                         ("bridge" . ,(merge-pathnames "bridge"
                                                      runtime-directory))
                         ("host-local" . ,(merge-pathnames "host-local"
                                                          runtime-directory))
                         ("loopback" . ,(merge-pathnames "loopback"
                                                        runtime-directory))
                         ("gr8s"
                          . ,(merge-pathnames "gr8s"
                                             runtime-directory))
                         ("gr8s-whistler.bpf.o"
                          . ,(merge-pathnames "gr8s-whistler.bpf.o"
                                             runtime-directory))))
              (push :release events))
            :bpf-mounter (lambda (directory)
                           (declare (ignore directory))
                           (push :bpf-mount events))
            :bpf-unmounter (lambda (directory)
                             (declare (ignore directory))
                             (push :bpf-unmount events))
            :cni-bin-directory "/opt/gr8s/cni/"
            :launcher (lambda (command log-path environment)
                        (declare (ignore log-path))
                        (push :start events)
                        (is (search "runtime/bin/containerd" (first command)))
                        (is (find-if (lambda (entry)
                                      (search "runtime/bin" entry))
                                    environment))
                        :child)
            :process-alive-p (lambda (process) (eq process :child))
            :readiness-probe (lambda (socket) (declare (ignore socket)) t)
            :stopper (lambda (process)
                       (declare (ignore process))
                       (push :stop events)))))
    (unwind-protect
         (progn
           (gr8s.kubelet::call-with-managed-containerd
            manager (lambda () (push :body events)))
           (is (equal '(:prepare :bpf-mount :start :body :stop
                        :bpf-unmount :release)
                      (reverse events)))
           (is (search "runtime/bin/runc"
                       (gr8s.kubelet::managed-containerd-config-text manager)))
           (is (search "runtime/bin/"
                       (gr8s.kubelet::managed-containerd-cni-bin-directory manager))))
      (gr8s.kubelet::stop-managed-containerd manager)
      (uiop:delete-directory-tree directory
                                  :validate t :if-does-not-exist :ignore))))

(test agent-restart-reuses-bpffs-and-keeps-live-endpoint-pins
  (with-temporary-store (store path)
    (assert store)
    (let* ((directory (merge-pathnames "bpf/" path))
           (pin (merge-pathnames "sandbox/endpoint_identity" directory))
           (unmounted 0))
      (gr8s.security::write-private-text-exclusively pin "simulated pin")
      (is (gr8s.kubelet::mount-managed-bpffs
           directory :mounted-p (lambda (target filesystem)
                                  (is (string= "bpf" filesystem))
                                  (is (probe-file target)) t)
           :mounter (lambda (&rest args) (declare (ignore args))
                      (fail "restart overmounted the surviving pins"))))
      (gr8s.kubelet::unmount-managed-bpffs
       directory :unmounter (lambda (&rest args) (declare (ignore args)) (incf unmounted) 0))
      (is (= 0 unmounted))
      (delete-file pin)
      (gr8s.kubelet::unmount-managed-bpffs
       directory :unmounter (lambda (&rest args) (declare (ignore args)) (incf unmounted) 0))
      (is (= 1 unmounted)))))

(defun supervised-test-manager (directory &rest arguments)
  "A managed containerd whose process is a cons the test kills by setting its CAR."
  ;; Keyword arguments given first win, so ARGUMENTS override these defaults.
  (apply #'gr8s.kubelet::make-managed-containerd
         (append arguments
                 (list :state-directory directory
                       :executable "/opt/gr8s/bin/containerd"
                       :oci-runtime "/opt/gr8s/bin/runc"
                       :cni-bin-directory "/opt/gr8s/bin/cni/"
                       :process-alive-p (lambda (process) (car process))
                       :exit-describer (lambda (process) (declare (ignore process)) "exit status 2")
                       :readiness-probe (lambda (socket) (declare (ignore socket)) t)
                       :stopper (lambda (process) (setf (car process) nil))
                       :supervision-interval 0.02))))

(test managed-containerd-supervisor-restarts-a-dead-containerd-and-reports-the-outage
  (let* ((directory (merge-pathnames (format nil "gr8s-supervise-~36R/" (random (expt 36 8)))
                                     (uiop:temporary-directory)))
         (launches nil)
         (manager (supervised-test-manager
                   directory
                   :restart-initial-delay 0.2
                   :launcher (lambda (command log environment)
                               (declare (ignore command log environment))
                               (let ((process (list t)))
                                 (push process launches)
                                 process))))
         (availability (gr8s.kubelet::managed-containerd-availability manager))
         (log (make-string-output-stream)))
    (unwind-protect
         (let ((*error-output* log))
           (gr8s.kubelet::call-with-running-containerd
            manager
            (lambda ()
              (is (= 1 (length launches)))
              (is (null (gr8s.kubelet::runtime-availability-message availability)))
              ;; containerd panics.
              (setf (car (first launches)) nil)
              ;; The CRI caller sees the outage at once, before the supervisor polls.
              (is (search "container runtime is down" (gr8s.kubelet::runtime-availability-message availability)))
              (is (wait-until (lambda () (gr8s.kubelet::runtime-availability-down-message availability)) :timeout 5))
              (is (search "exit status 2" (gr8s.kubelet::runtime-availability-message availability)))
              ;; It is restarted after the backoff, not in a hot loop.
              (is (= 1 (length launches)))
              (is (wait-until (lambda () (= 2 (length launches))) :timeout 5))
              (is (wait-until (lambda () (null (gr8s.kubelet::runtime-availability-message availability))) :timeout 5))
              (is (= 1 (gr8s.kubelet::managed-containerd-restarts manager)))
              (is (= 1 (gr8s.kubelet::runtime-availability-outages availability)))
              (is (eq (first launches) (gr8s.kubelet::managed-containerd-process manager))))))
      (gr8s.kubelet::stop-managed-containerd manager)
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))
    (let ((text (get-output-stream-string log)))
      (is (search "gr8s managed containerd exited (exit status 2)" text))
      (is (search "gr8s managed containerd restarted (restart 1)" text)))
    ;; Stopping ends supervision: the stopped process is not restarted.
    (is (= 2 (length launches)))
    (is (null (gr8s.kubelet::managed-containerd-supervisor manager)))
    (is (null (gr8s.kubelet::runtime-availability-liveness availability)))))

(test managed-containerd-supervisor-backs-off-while-restarts-fail
  (let* ((directory (merge-pathnames (format nil "gr8s-supervise-~36R/" (random (expt 36 8)))
                                     (uiop:temporary-directory)))
         (launch-times nil)
         (failing nil)
         (manager (supervised-test-manager
                   directory
                   :restart-initial-delay 0.1
                   :restart-max-delay 0.4
                   :readiness-probe (lambda (socket) (declare (ignore socket)) (not failing))
                   :launcher (lambda (command log environment)
                               (declare (ignore command log environment))
                               (push (get-internal-real-time) launch-times)
                               ;; A failed restart exits before it is ready.
                               (list (not failing)))))
         (availability (gr8s.kubelet::managed-containerd-availability manager)))
    (unwind-protect
         (let ((*error-output* (make-broadcast-stream)))
           (gr8s.kubelet::call-with-running-containerd
            manager
            (lambda ()
              (setf failing t)
              (setf (car (gr8s.kubelet::managed-containerd-process manager)) nil)
              (is (wait-until (lambda () (>= (length launch-times) 5)) :timeout 10))
              (is (gr8s.kubelet::runtime-availability-message availability))
              (let ((gaps (loop for (later earlier) on launch-times
                                while earlier
                                collect (/ (- later earlier) internal-time-units-per-second))))
                ;; Delays double from 0.1s and stop growing at 0.4s.
                (is (>= (first (last gaps)) 0.08))
                (is (every (lambda (gap) (< gap 1.0)) gaps))
                (is (>= (first gaps) 0.35)))
              (setf failing nil)
              (is (wait-until (lambda () (null (gr8s.kubelet::runtime-availability-message availability)))
                              :timeout 5)))))
      (gr8s.kubelet::stop-managed-containerd manager)
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test runtime-availability-waiters-wake-when-the-runtime-returns
  (let ((availability (gr8s.kubelet::make-runtime-availability)))
    (is (gr8s.kubelet::wait-for-runtime-available availability 0))
    (gr8s.kubelet::note-runtime-unavailable availability "container runtime is down: test")
    (is (not (gr8s.kubelet::wait-for-runtime-available availability 0.05)))
    (bt:make-thread (lambda () (sleep 0.1) (gr8s.kubelet::note-runtime-available availability)))
    (is (gr8s.kubelet::wait-for-runtime-available availability 5))
    (is (null (gr8s.kubelet::runtime-availability-message availability)))))
