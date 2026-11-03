(in-package #:gr8s/tests)

(in-suite gr8s)

(test containerd-platform-follows-the-host-machine-type
  (is (string= "linux/amd64"
               (gr8s::containerd-platform-for-machine "x86_64")))
  (is (string= "linux/amd64"
               (gr8s::containerd-platform-for-machine "X86-64")))
  (is (string= "linux/arm64"
               (gr8s::containerd-platform-for-machine "aarch64")))
  (is (string= "linux/arm64"
               (gr8s::containerd-platform-for-machine "ARM64")))
  (signals error
    (gr8s::containerd-platform-for-machine "mips64")))

(test managed-containerd-keeps-all-state-under-its-private-directory
  (let* ((manager
           (gr8s::make-managed-containerd
            :state-directory "/var/lib/gr8s/"
            :executable "/opt/gr8s/bin/containerd"
            :oci-runtime "/opt/gr8s/bin/runc"
            :cni-bin-directory "/opt/gr8s/bin/cni/"
            :platform "linux/arm64"))
         (config (gr8s::managed-containerd-config-text manager)))
    (is (string= "/var/lib/gr8s/containerd/run/containerd.sock"
                 (gr8s::managed-containerd-socket-path manager)))
    (is (string= "/var/lib/gr8s/containerd/run/gr8s-cni.sock"
                 (gr8s::managed-containerd-agent-cni-socket-path manager)))
    (is (equal '("/opt/gr8s/bin/containerd"
                 "--config"
                 "/var/lib/gr8s/containerd/config.toml")
               (gr8s::managed-containerd-command manager)))
    (is (search "root = '/var/lib/gr8s/containerd/root'" config))
    (is (search "state = '/var/lib/gr8s/containerd/run'" config))
    (is (search "address = '/var/lib/gr8s/containerd/run/containerd.sock'"
                config))
    (is (search
         (format nil "socket_dir = '~A'"
                 (gr8s::managed-containerd-shim-socket-directory manager))
         config))
    (is (<= (length (gr8s::managed-containerd-shim-socket-directory manager))
            42))
    (is (uiop:string-prefix-p
         "/tmp/gr8s-shims-"
         (gr8s::managed-containerd-shim-socket-directory manager)))
    (is (search "BinaryName = '/opt/gr8s/bin/runc'" config))
    (is (search "Root = '/var/lib/gr8s/containerd/run/runc'" config))
    (is (search "restrict_oom_score_adj = true" config))
    (is (search "bin_dirs = ['/opt/gr8s/bin/cni/']" config))
    (is (search "conf_dir = '/var/lib/gr8s/containerd/cni/net.d'" config))
    (is (search "platform = 'linux/arm64'" config))))

(test containerd-launcher-creates-a-new-log-file
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-containerd-log-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (log-path (merge-pathnames "containerd/containerd.log" directory)))
    (unwind-protect
         (let ((process
                 (gr8s::launch-containerd-process
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
    (gr8s::terminate-containerd-process
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
    (gr8s::terminate-containerd-process
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
           (gr8s::make-managed-containerd
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
           (gr8s::start-managed-containerd manager :timeout 0.1)
           (is (equal (gr8s::managed-containerd-command manager)
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
                   (gr8s::managed-containerd-process manager)))
           (is (string= (gr8s::managed-containerd-config-text manager)
                        (uiop:read-file-string
                         (gr8s::managed-containerd-config-path manager))))
           (let ((cni-config
                   (uiop:read-file-string
                    (gr8s::managed-containerd-directory
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
                           (gr8s::managed-containerd-agent-cni-socket-path
                            manager)))
                  cni-config))
             (is (search "gr8s-whistler.bpf.o" cni-config))
             (is (search
                  "\"mapPinRoot\":\""
                  cni-config))
             (is (search
                  (gr8s::managed-containerd-directory
                   manager "containerd/bpf")
                  cni-config))
             (let* ((object (com.inuoe.jzon:parse cni-config))
                    (plugins (gethash "plugins" object)))
               (is (= 1 (length plugins)))
               (is-false (gethash "ipam" (aref plugins 0)))))
           (gr8s::stop-managed-containerd manager)
           (is (eq :child-process stopped-process))
           (is (null (gr8s::managed-containerd-process manager))))
      (gr8s::stop-managed-containerd manager)
      (uiop:delete-directory-tree directory
                                  :validate t :if-does-not-exist :ignore))))

(test managed-containerd-lifecycle-wraps-the-server-body
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-managed-lifecycle-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (events nil)
         (process (list :managed-containerd-process))
         (manager
           (gr8s::make-managed-containerd
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
           (gr8s::call-with-managed-containerd
            manager
            (lambda ()
              (push :body events)))
           (is (equal '(:bpf-mount :start :body :stop :bpf-unmount)
                      (reverse events)))
           (is (null (gr8s::managed-containerd-process manager))))
      (gr8s::stop-managed-containerd manager)
      (uiop:delete-directory-tree directory
                                  :validate t :if-does-not-exist :ignore))))

(test embedded-runtime-is-prepared-before-containerd-and-released-after-it
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-managed-assets-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (events nil)
         (assets (list (gr8s::make-runtime-asset :name "containerd" :octets #(1))
                       (gr8s::make-runtime-asset
                        :name "containerd-shim-runc-v2" :octets #(2))
                       (gr8s::make-runtime-asset :name "runc" :octets #(3))
                       (gr8s::make-runtime-asset :name "bridge" :octets #(4))
                       (gr8s::make-runtime-asset
                        :name "host-local" :octets #(5))
                       (gr8s::make-runtime-asset
                        :name "loopback" :octets #(6))
                       (gr8s::make-runtime-asset
                        :name "gr8s-whistler.bpf.o" :octets #(8))))
         (manager
           (gr8s::make-managed-containerd
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
           (gr8s::call-with-managed-containerd
            manager (lambda () (push :body events)))
           (is (equal '(:prepare :bpf-mount :start :body :stop
                        :bpf-unmount :release)
                      (reverse events)))
           (is (search "runtime/bin/runc"
                       (gr8s::managed-containerd-config-text manager)))
           (is (search "runtime/bin/"
                       (gr8s::managed-containerd-cni-bin-directory manager))))
      (gr8s::stop-managed-containerd manager)
      (uiop:delete-directory-tree directory
                                  :validate t :if-does-not-exist :ignore))))
