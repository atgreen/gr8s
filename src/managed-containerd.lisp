(in-package #:gr8s)

(defstruct (managed-containerd (:constructor %make-managed-containerd))
  state-directory
  executable
  oci-runtime
  cni-bin-directory
  shim-socket-directory
  platform
  (snapshotter "overlayfs")
  ;; Whether containerd skips fsync on metadata commits; see --containerd-no-sync.
  metadata-no-sync
  launcher
  process-alive-p
  readiness-probe
  stopper
  runtime-assets
  ;; Optional CRI runtime handlers beyond the built-in runc, e.g. a gVisor
  ;; runsc addon (podster-mgw). Each entry is a plist
  ;;   (:name STRING :runtime-type STRING :options ALIST-OF (KEY . TOML-SCALAR))
  ;; appended after runc in the generated containerd config.
  extra-runtime-handlers
  runtime-preparer
  bpf-mounter
  bpf-unmounter
  process)

(defun containerd-platform-for-machine (machine)
  (let ((normalized (string-downcase machine)))
    (cond
      ((member normalized '("x86_64" "x86-64" "amd64") :test #'string=)
       "linux/amd64")
      ((member normalized '("aarch64" "arm64") :test #'string=)
       "linux/arm64")
      (t
       (error "unsupported containerd machine architecture: ~A" machine)))))

(defun launch-containerd-process (command log-path environment)
  (ensure-directories-exist log-path)
  (with-open-file (stream log-path
                          :direction :output
                          :if-exists :append
                          :if-does-not-exist :create)
    (finish-output stream))
  (uiop:launch-program command
                       :output log-path
                       :error-output log-path
                       :environment environment
                       :if-output-exists :append
                       :if-error-output-exists :append))

(defun containerd-process-alive-p (process)
  (uiop:process-alive-p process))

(defun containerd-cri-ready-p (socket-path)
  (and (probe-file socket-path)
       (handler-case
           (progn
             (cri-runtime-version socket-path :timeout 1)
             t)
         (error () nil))))

(defun terminate-containerd-process
    (process
     &key (timeout 5.0)
          (process-alive-p #'uiop:process-alive-p)
          (terminator #'uiop:terminate-process)
          (waiter #'uiop:wait-process)
          (sleeper #'sleep))
  (when (funcall process-alive-p process)
    (funcall terminator process :urgent nil)
    (let ((deadline (+ (get-internal-real-time)
                       (* timeout internal-time-units-per-second))))
      (loop while (and (funcall process-alive-p process)
                       (< (get-internal-real-time) deadline))
            do (funcall sleeper 0.05)))
    (when (funcall process-alive-p process)
      (funcall terminator process :urgent t)))
  (ignore-errors (funcall waiter process)))

(defun default-shim-socket-directory (state-directory)
  (format nil "/tmp/gr8s-shims-~8,'0X/"
          (logand #xffffffff
                  (sxhash (namestring
                           (uiop:ensure-directory-pathname state-directory))))))

(defun make-managed-containerd
    (&key state-directory executable oci-runtime cni-bin-directory
          shim-socket-directory
          extra-runtime-handlers
          runtime-assets
          (runtime-preparer #'call-with-runtime-assets)
          (bpf-mounter #'mount-managed-bpffs)
          (bpf-unmounter #'unmount-managed-bpffs)
          (platform (containerd-platform-for-machine (machine-type)))
          (snapshotter "overlayfs")
          metadata-no-sync
          (launcher #'launch-containerd-process)
          (process-alive-p #'containerd-process-alive-p)
          (readiness-probe #'containerd-cri-ready-p)
          (stopper #'terminate-containerd-process))
  (let ((state (uiop:ensure-directory-pathname state-directory)))
    (%make-managed-containerd
     :state-directory state
     :executable executable
     :oci-runtime oci-runtime
     :cni-bin-directory
     (namestring (uiop:ensure-directory-pathname cni-bin-directory))
     :shim-socket-directory
     (or shim-socket-directory (default-shim-socket-directory state))
     :extra-runtime-handlers extra-runtime-handlers
     :platform platform
     :snapshotter snapshotter
     :metadata-no-sync metadata-no-sync
     :launcher launcher
     :process-alive-p process-alive-p
     :readiness-probe readiness-probe
     :runtime-assets runtime-assets
     :runtime-preparer runtime-preparer
     :bpf-mounter bpf-mounter
     :bpf-unmounter bpf-unmounter
     :stopper stopper)))

(defun managed-containerd-directory (manager relative-path)
  (namestring
   (merge-pathnames relative-path
                    (managed-containerd-state-directory manager))))

(defun managed-containerd-config-path (manager)
  (managed-containerd-directory manager "containerd/config.toml"))

(defun managed-containerd-socket-path (manager)
  (managed-containerd-directory manager "containerd/run/containerd.sock"))

(defun managed-containerd-agent-cni-socket-path (manager)
  (managed-containerd-directory manager "containerd/run/gr8s-cni.sock"))

(defun managed-containerd-runtime-directory (manager)
  (managed-containerd-directory manager "containerd/runtime/bin/"))

(defun managed-containerd-bpf-directory (manager)
  (managed-containerd-directory manager "containerd/bpf/"))

(defun mount-managed-bpffs (directory &key (mounted-p #'filesystem-mounted-at-p)
                                           (mounter #'%linux-mount))
  (let ((target (namestring (uiop:ensure-directory-pathname directory))))
    (ensure-directories-exist (merge-pathnames ".mount-point" target))
    ;; Reuse the node's surviving bpffs after an agent process restart. An
    ;; overmount would hide the pinned links and discard their counters.
    (unless (or (funcall mounted-p target "bpf")
                (zerop (funcall mounter "gr8s-bpf" target "bpf" #xe "")))
      (error "could not mount the gr8s BPF filesystem at ~A: ~A"
             target (sb-int:strerror (sb-alien:get-errno))))
    target))

(defun unmount-managed-bpffs (directory &key (unmounter #'%linux-umount))
  (let ((target (namestring (uiop:ensure-directory-pathname directory))))
    ;; Running Pods outlive the agent. Keep their maps and TCX links pinned;
    ;; the next process must adopt them before reconnecting to the server.
    (unless (or (directory (merge-pathnames #P"*/*" target))
                (zerop (funcall unmounter target 0)))
      (error "could not unmount the gr8s BPF filesystem at ~A: ~A"
             target (sb-int:strerror (sb-alien:get-errno))))
    target))

(defun managed-containerd-binary-directory (manager)
  (if (managed-containerd-runtime-assets manager)
      (managed-containerd-runtime-directory manager)
      (string-right-trim
       "/"
       (namestring
        (uiop:pathname-directory-pathname
         (pathname (managed-containerd-executable manager)))))))

(defun managed-containerd-environment (manager)
  (let* ((prefix (managed-containerd-binary-directory manager))
         ;; Runtime-addon bin dirs join the PATH so containerd can exec their
         ;; shim binaries (e.g. containerd-shim-runsc-v1) by name; runc's own
         ;; prefix stays first. With no addons this is byte-identical to the old
         ;; "PATH=<prefix>:<inherited>" form.
         (addon-directories
           (loop for handler in (managed-containerd-extra-runtime-handlers manager)
                 for directory = (getf handler :bin-dir)
                 when directory
                   collect (string-right-trim "/" (namestring directory))))
         (path (or (uiop:getenv "PATH") ""))
         (inherited #+sbcl (copy-list (sb-ext:posix-environ))
                    #-sbcl nil))
    (cons (format nil "PATH=~{~A:~}~A" (cons prefix addon-directories) path)
          (remove-if (lambda (entry)
                       (uiop:string-prefix-p "PATH=" entry))
                     inherited))))

(defun managed-containerd-command (manager)
  (list (managed-containerd-executable manager)
        "--config"
        (managed-containerd-config-path manager)))

(defun managed-containerd-runtime-handlers (manager)
  "The ordered CRI runtime handlers for the generated config. runc is the
   built-in default; any EXTRA-RUNTIME-HANDLERS (e.g. a gVisor runsc addon) are
   appended. Each handler is a plist (:name :runtime-type :options), where
   :options is an alist of (KEY . TOML-SCALAR) already rendered for TOML."
  (cons
   (list :name "runc"
         :runtime-type "io.containerd.runc.v2"
         :options
         (list (cons "BinaryName"
                     (format nil "'~A'" (managed-containerd-oci-runtime manager)))
               (cons "Root"
                     (format nil "'~A'"
                             (managed-containerd-directory manager "containerd/run/runc")))
               (cons "SystemdCgroup" "false")))
   (managed-containerd-extra-runtime-handlers manager)))

(defun managed-containerd-runtimes-toml (manager)
  "Render the [...containerd.runtimes] TOML block from the handler list. Emitting
   only runc yields the exact bytes the single-handler config produced before."
  (let ((prefix "plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes"))
    (with-output-to-string (stream)
      (format stream "      [~A]~%" prefix)
      (dolist (handler (managed-containerd-runtime-handlers manager))
        (let ((name (getf handler :name))
              (type (getf handler :runtime-type))
              (options (getf handler :options)))
          (format stream "        [~A.~A]~%          runtime_type = '~A'~%" prefix name type)
          (when options
            (format stream "          [~A.~A.options]~%" prefix name)
            (dolist (option options)
              (format stream "            ~A = ~A~%" (car option) (cdr option)))))))))

(defun managed-containerd-config-text (manager)
  (let ((root (managed-containerd-directory manager "containerd/root"))
        (state (managed-containerd-directory manager "containerd/run"))
        (temporary (managed-containerd-directory manager "containerd/tmp"))
        (runtimes (managed-containerd-runtimes-toml manager))
        (socket (managed-containerd-socket-path manager))
        (cni-config (managed-containerd-directory manager "containerd/cni/net.d"))
        (snapshotter (managed-containerd-snapshotter manager)))
    (format
     nil
     "version = 4~%root = '~A'~%state = '~A'~%temp = '~A'~%~
[plugins]~%~:[~;  [plugins.'io.containerd.metadata.v1.bolt']~%    no_sync = true~%~]  [plugins.'io.containerd.cri.v1.images']~%    snapshotter = '~A'~%~
  [plugins.'io.containerd.cri.v1.runtime']~%    disable_apparmor = true~%    restrict_oom_score_adj = true~%    netns_mounts_under_state_dir = true~%~
    [plugins.'io.containerd.cri.v1.runtime'.containerd]~%      default_runtime_name = 'runc'~%~A~
    [plugins.'io.containerd.cri.v1.runtime'.cni]~%      bin_dirs = ['~A']~%      conf_dir = '~A'~%      use_internal_loopback = true~%~
  [plugins.'io.containerd.nri.v1.nri']~%    disable = true~%~
  [plugins.'io.containerd.shim.v1.manager']~%    socket_dir = '~A'~%~
  [plugins.'io.containerd.transfer.v1.local']~%~
    [[plugins.'io.containerd.transfer.v1.local'.unpack_config]]~%      platform = '~A'~%      snapshotter = '~A'~%~
  [plugins.'io.containerd.server.v1.grpc']~%    address = '~A'~%~
  [plugins.'io.containerd.server.v1.ttrpc']~%    address = '~A.ttrpc'~%"
     root state temporary (managed-containerd-metadata-no-sync manager) snapshotter
     runtimes
     (managed-containerd-cni-bin-directory manager)
     cni-config (managed-containerd-shim-socket-directory manager)
     (managed-containerd-platform manager)
     snapshotter socket socket)))

(defun managed-containerd-log-path (manager)
  (managed-containerd-directory manager "containerd/containerd.log"))

(defun managed-containerd-cni-config-text (manager)
  ;; The egress guard is JIT-compiled in-process by the agent; the conflist
  ;; carries no ELF "program" path.
  (let ((map-pin-root (managed-containerd-bpf-directory manager)))
    (format
     nil
     "{\"cniVersion\":\"1.0.0\",\"name\":\"gr8s\",\"plugins\":[{\"type\":\"gr8s\",\"socket\":~A,\"direction\":\"egress\",\"mapPinRoot\":~A}]}~%"
     (com.inuoe.jzon:stringify
      (managed-containerd-agent-cni-socket-path manager))
     (com.inuoe.jzon:stringify (namestring map-pin-root)))))

(defun managed-containerd-cni-config-path (manager)
  (managed-containerd-directory
   manager "containerd/cni/net.d/10-gr8s.conflist"))

(defun write-managed-containerd-config (manager)
  (let ((path (managed-containerd-config-path manager)))
    (ensure-directories-exist path)
    (ensure-directories-exist
     (managed-containerd-directory manager "containerd/cni/net.d/"))
    (ensure-directories-exist
     (merge-pathnames
      ".state-directory"
      (managed-containerd-directory manager "containerd/cni/state/")))
    (ensure-directories-exist
     (merge-pathnames ".socket-directory"
                      (uiop:ensure-directory-pathname
                       (managed-containerd-shim-socket-directory manager))))
    (sb-posix:chmod (managed-containerd-shim-socket-directory manager) #o700)
    (with-open-file (stream path
                            :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (write-string (managed-containerd-config-text manager) stream))
    (with-open-file (stream (managed-containerd-cni-config-path manager)
                            :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (write-string (managed-containerd-cni-config-text manager) stream))
    path))

(defun stop-managed-containerd (manager)
  (let ((process (managed-containerd-process manager)))
    (when process
      (unwind-protect
           (funcall (managed-containerd-stopper manager) process)
        (setf (managed-containerd-process manager) nil))))
  nil)

(defun start-managed-containerd (manager &key (timeout 30))
  (let ((existing (managed-containerd-process manager)))
    (when (and existing
               (funcall (managed-containerd-process-alive-p manager) existing))
      (error 'runtime-error :message "managed containerd is already running")))
  (write-managed-containerd-config manager)
  (setf (managed-containerd-process manager)
        (funcall (managed-containerd-launcher manager)
                 (managed-containerd-command manager)
                 (managed-containerd-log-path manager)
                 (managed-containerd-environment manager)))
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (loop
      (when (funcall (managed-containerd-readiness-probe manager)
                     (managed-containerd-socket-path manager))
        (return manager))
      (unless (funcall (managed-containerd-process-alive-p manager)
                       (managed-containerd-process manager))
        (setf (managed-containerd-process manager) nil)
        (error 'runtime-error
               :message (format nil "managed containerd exited; see ~A"
                                (managed-containerd-log-path manager))))
      (when (>= (get-internal-real-time) deadline)
        (stop-managed-containerd manager)
        (error 'runtime-error
               :message (format nil "managed containerd was not ready after ~A seconds"
                                timeout)))
      (sleep 0.05))))

(defun call-with-running-containerd (manager function)
  (unwind-protect
       (progn
         (start-managed-containerd manager)
         ;; Archives under <state>/images/ are imported before any Pod can start.
         (preload-managed-containerd-images manager)
         (funcall function))
    (stop-managed-containerd manager)))

(defun prepared-runtime-path (name paths)
  (let ((entry (assoc name paths :test #'string=)))
    (unless entry
      (error "embedded runtime payload is missing ~A" name))
    (namestring (cdr entry))))

(defun call-with-managed-containerd (manager function)
  (cond
    ((null manager)
     (funcall function))
    ((managed-containerd-runtime-assets manager)
     (funcall
      (managed-containerd-runtime-preparer manager)
      (managed-containerd-runtime-assets manager)
      (managed-containerd-runtime-directory manager)
      (lambda (paths)
        (setf (managed-containerd-executable manager)
              (prepared-runtime-path "containerd" paths)
              (managed-containerd-oci-runtime manager)
              (prepared-runtime-path "runc" paths)
              (managed-containerd-cni-bin-directory manager)
              (namestring
               (uiop:pathname-directory-pathname
                (cdr (assoc "bridge" paths :test #'string=)))))
        (call-with-managed-bpffs manager function))))
    (t
     (call-with-managed-bpffs manager function))))

(defun call-with-managed-bpffs (manager function)
  (let ((directory (managed-containerd-bpf-directory manager)))
    (funcall (managed-containerd-bpf-mounter manager) directory)
    (unwind-protect
         (call-with-running-containerd manager function)
      (funcall (managed-containerd-bpf-unmounter manager) directory))))
