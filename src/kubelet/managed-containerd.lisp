;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; A node agent's self-managed containerd: launch, configure, supervise and
;;;; stop the container runtime the agent owns, as a node's service manager would
;;;; (podster-uqb.138).
;;;;
;;;; The agent writes containerd's config.toml and the gr8s CNI conflist under a
;;;; per-node state directory, launches containerd, and waits for its CRI socket
;;;; to answer before declaring it ready. A supervisor thread restarts the
;;;; process whenever it exits, backing off exponentially up to RESTART-MAX-DELAY
;;;; and resetting once an instance has run RESTART-STABLE-SECONDS; running Pods
;;;; survive the outage because their shims outlive containerd, which reconnects
;;;; to them on restart. The launched PID and Linux start time are persisted so
;;;; an agent restarted after SIGKILL can safely identify and replace its orphaned
;;;; containerd before writing a new configuration. RUNTIME-AVAILABILITY lets
;;;; the rest of the agent see the
;;;; gap: while containerd is down it pauses Pod synchronization and reports the
;;;; Node NotReady, as kubelet does for a dead runtime. The managed bpffs is
;;;; mounted before containerd and deliberately left pinned across an agent
;;;; restart so Pod BPF maps and TCX links (and their counters) survive for the
;;;; next process to adopt. Extra CRI runtime handlers (e.g. a gVisor runsc
;;;; addon, podster-mgw) append after the built-in runc in the generated config.

(in-package #:gr8s.kubelet)

(defstruct (runtime-availability (:constructor make-runtime-availability ()))
  "Whether the node's container runtime can serve CRI calls, and why not while it can't.
The managed containerd supervisor writes it; the agent reads it to pause Pod
synchronization and to report the Node NotReady, as kubelet does for a dead runtime."
  (lock (bt:make-lock "gr8s runtime availability"))
  (changed (bt:make-condition-variable :name "gr8s runtime availability changed"))
  down-message
  (outages 0)
  ;; Optional nullary predicate: is the runtime process alive right now? It lets a
  ;; caller whose CRI call just failed tell a dead runtime from a failed request
  ;; before the supervisor's next poll notices the exit.
  liveness)

(defun runtime-availability-message (availability)
  "Return why AVAILABILITY's runtime is down, or NIL while it is up or unsupervised."
  (when availability
    (or (bt:with-lock-held ((runtime-availability-lock availability))
          (runtime-availability-down-message availability))
        (let ((liveness (runtime-availability-liveness availability)))
          (when (and liveness (not (ignore-errors (funcall liveness))))
            "container runtime is down: managed containerd is not running")))))

(defun note-runtime-unavailable (availability message)
  "Record that the runtime is down because of MESSAGE."
  (bt:with-lock-held ((runtime-availability-lock availability))
    (unless (runtime-availability-down-message availability)
      (incf (runtime-availability-outages availability)))
    (setf (runtime-availability-down-message availability) message)
    (bt:condition-notify (runtime-availability-changed availability))))

(defun note-runtime-available (availability)
  "Record that the runtime serves CRI calls again and wake everyone waiting for it."
  (bt:with-lock-held ((runtime-availability-lock availability))
    (setf (runtime-availability-down-message availability) nil)
    (bt:condition-notify (runtime-availability-changed availability))))

(defun wait-for-runtime-available (availability timeout)
  "Wait up to TIMEOUT seconds for AVAILABILITY's runtime; return true when it is up."
  (or (null availability)
      (let ((deadline (+ (get-internal-real-time)
                         (* timeout internal-time-units-per-second))))
        (bt:with-lock-held ((runtime-availability-lock availability))
          (loop
            (unless (runtime-availability-down-message availability)
              (return t))
            (let ((remaining (/ (- deadline (get-internal-real-time))
                                internal-time-units-per-second)))
              (unless (plusp remaining)
                (return nil))
              ;; Notify wakes one waiter; a bounded wait lets every waiter see the change.
              (bt:condition-wait (runtime-availability-changed availability)
                                 (runtime-availability-lock availability)
                                 :timeout (min remaining 0.25))))))))

(defstruct (managed-containerd (:constructor %make-managed-containerd))
  state-directory
  executable
  oci-runtime
  cni-bin-directory
  cni-bin-directories
  (cni-mode "native")
  cni-config-directory
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
  ;; (manager) -> keeps containerd's state, with each container's environment, off
  ;; the disk (podster-j9gd); injectable for testing.
  state-mounter
  process
  ;; Supervision: a node agent restarts its runtime when it dies, as a real
  ;; node's service manager would (podster-uqb.138).
  (availability (make-runtime-availability))
  supervisor
  stopping-p
  (supervisor-lock (bt:make-lock "gr8s managed containerd supervisor"))
  (supervisor-changed (bt:make-condition-variable :name "gr8s managed containerd stop"))
  (supervision-interval 0.25)
  (restart-initial-delay 1)
  (restart-max-delay 30)
  ;; A containerd that ran this long before exiting restarts after the initial delay again.
  (restart-stable-seconds 60)
  (restarts 0)
  (exit-describer #'describe-containerd-exit))

(defun containerd-platform-for-machine (machine)
  "Map a uname MACHINE string (x86_64/x86-64/amd64, or aarch64/arm64; case-
   insensitive) to the containerd platform label \"linux/amd64\" or
   \"linux/arm64\". Signals an error on any other architecture."
  (let ((normalized (string-downcase machine)))
    (cond
      ((member normalized '("x86_64" "x86-64" "amd64") :test #'string=)
       "linux/amd64")
      ((member normalized '("aarch64" "arm64") :test #'string=)
       "linux/arm64")
      (t
       (error "unsupported containerd machine architecture: ~A" machine)))))

(defun launch-containerd-process (command log-path environment)
  "Launch COMMAND as a child process with ENVIRONMENT, appending its stdout and
   stderr to LOG-PATH (created if absent). Returns the UIOP process handle."
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
  "True while PROCESS has not yet exited."
  (uiop:process-alive-p process))

(defun describe-containerd-exit (process)
  "Describe how PROCESS exited, for the supervisor's log."
  (let ((code (ignore-errors (uiop:wait-process process))))
    (if code (format nil "exit status ~D" code) "exit status unknown")))

(defvar *last-cri-probe-error* nil
  "The most recent distinct CRI readiness-probe failure already logged. Lets the
probe surface why containerd answers no CRI call -- a process-alive-but-CRI-
unresponsive containerd would otherwise keep the Node NotReady silently -- without
spamming the log on every poll.")

(defun containerd-cri-ready-p (socket-path)
  "True when SOCKET-PATH exists and answers a CRI RuntimeVersion call within one
   second. Fail-soft: any error is caught and reported as NIL, but the first
   occurrence of each distinct failure is logged so the outage is diagnosable."
  (and (probe-file socket-path)
       (handler-case
           (progn
             (cri-runtime-version socket-path :timeout 1)
             (setf *last-cri-probe-error* nil)
             t)
         (error (condition)
           (let ((message (format nil "~A: ~A" (type-of condition) condition)))
             (unless (equal message *last-cri-probe-error*)
               (setf *last-cri-probe-error* message)
               (format *error-output*
                       "gr8s containerd CRI readiness probe failed (~A): ~A~%"
                       socket-path message)))
           nil))))

(defun terminate-containerd-process
    (process
     &key (timeout 5.0)
          (process-alive-p #'uiop:process-alive-p)
          (terminator #'uiop:terminate-process)
          (waiter #'uiop:wait-process)
          (sleeper #'sleep))
  "Stop PROCESS: request a graceful termination, poll up to TIMEOUT seconds for
   it to exit, then force it if still alive, and reap it. Bar the final reap, a
   no-op when PROCESS is already dead. The keyword hooks exist for testing."
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
  "A /tmp shim-socket directory path unique to STATE-DIRECTORY (keyed by a hash
   of its namestring), so two managed containerds on one host do not collide."
  (format nil "/tmp/gr8s-shims-~8,'0X/"
          (logand #xffffffff
                  (sxhash (namestring
                           (uiop:ensure-directory-pathname state-directory))))))

(defun make-managed-containerd
    (&key state-directory executable oci-runtime cni-bin-directory
          cni-bin-directories (cni-mode "native") cni-config-directory
          shim-socket-directory
          extra-runtime-handlers
          runtime-assets
          (runtime-preparer #'call-with-runtime-assets)
          (bpf-mounter #'mount-managed-bpffs)
          (bpf-unmounter #'unmount-managed-bpffs)
          (state-mounter #'mount-managed-containerd-state)
          (platform (containerd-platform-for-machine (machine-type)))
          (snapshotter "overlayfs")
          metadata-no-sync
          (launcher #'launch-containerd-process)
          (process-alive-p #'containerd-process-alive-p)
          (readiness-probe #'containerd-cri-ready-p)
          (stopper #'terminate-containerd-process)
          (exit-describer #'describe-containerd-exit)
          (restart-initial-delay 1)
          (restart-max-delay 30)
          (supervision-interval 0.25))
  "Construct a MANAGED-CONTAINERD. CNI-MODE is native or external. Native writes
   gr8s's conflist; external leaves CNI-CONFIG-DIRECTORY operator-owned.
   CNI-BIN-DIRECTORY and additional CNI-BIN-DIRECTORIES are normalized to
   directory namestrings; SHIM-SOCKET-DIRECTORY defaults to one
   derived from the state directory. The keyword collaborators (launcher,
   probes, stopper, exit describer, bpf mounters, runtime preparer) default to
   the real implementations and are overridable for testing."
  (unless (member cni-mode '("native" "external") :test #'string=)
    (error "unsupported CNI mode: ~A" cni-mode))
  (when (and (string= cni-mode "external") (null cni-config-directory))
    (error "external CNI mode requires a configuration directory"))
  (let ((state (uiop:ensure-directory-pathname state-directory)))
    (%make-managed-containerd
     :state-directory state
     :executable executable
     :oci-runtime oci-runtime
     :cni-bin-directory
     (namestring (uiop:ensure-directory-pathname cni-bin-directory))
     :cni-bin-directories
     (mapcar (lambda (directory)
               (namestring (uiop:ensure-directory-pathname directory)))
             cni-bin-directories)
     :cni-mode cni-mode
     :cni-config-directory
     (when cni-config-directory
       (namestring (uiop:ensure-directory-pathname cni-config-directory)))
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
     :state-mounter state-mounter
     :stopper stopper
     :exit-describer exit-describer
     :restart-initial-delay restart-initial-delay
     :restart-max-delay restart-max-delay
     :supervision-interval supervision-interval)))

(defun managed-containerd-cni-config-directory-path (manager)
  "Return the containerd CNI configuration directory selected for MANAGER."
  (or (managed-containerd-cni-config-directory manager)
      (managed-containerd-directory manager "containerd/cni/net.d")))

(defun managed-containerd-cni-bin-directory-list (manager)
  "Return embedded and operator CNI binary directories in lookup order."
  (remove-duplicates
   (cons (managed-containerd-cni-bin-directory manager)
         (managed-containerd-cni-bin-directories manager))
   :test #'string=))

(defun toml-basic-string (string)
  "Render STRING as one escaped TOML basic string."
  (with-output-to-string (stream)
    (write-char #\" stream)
    (loop for character across string
          for code = (char-code character)
          do (case character
               (#\" (write-string "\\\"" stream))
               (#\\ (write-string "\\\\" stream))
               (#\Backspace (write-string "\\b" stream))
               (#\Tab (write-string "\\t" stream))
               (#\Newline (write-string "\\n" stream))
               (#\Page (write-string "\\f" stream))
               (#\Return (write-string "\\r" stream))
               (otherwise
                (if (< code 32)
                    (format stream "\\u~4,'0X" code)
                    (write-char character stream)))))
    (write-char #\" stream)))

(defun toml-string-list (strings)
  "Render STRINGS as a TOML array of escaped basic strings."
  (format nil "[~{~A~^, ~}]" (mapcar #'toml-basic-string strings)))

(defun managed-containerd-directory (manager relative-path)
  "Resolve RELATIVE-PATH against MANAGER's state directory, as a namestring."
  (namestring
   (merge-pathnames relative-path
                    (managed-containerd-state-directory manager))))

(defun managed-containerd-config-path (manager)
  "Path to MANAGER's generated containerd config.toml."
  (managed-containerd-directory manager "containerd/config.toml"))

(defun managed-containerd-socket-path (manager)
  "Path to MANAGER's containerd CRI/gRPC control socket."
  (managed-containerd-directory manager "containerd/run/containerd.sock"))

(defun managed-containerd-agent-cni-socket-path (manager)
  "Path to the Unix socket the agent serves the gr8s CNI plugin on (named by the
   generated conflist)."
  (managed-containerd-directory manager "containerd/run/gr8s-cni.sock"))

(defun managed-containerd-runtime-directory (manager)
  "Directory the embedded runtime assets (containerd, runc, CNI plugins) are
   staged into when MANAGER carries them."
  (managed-containerd-directory manager "containerd/runtime/bin/"))

(defun managed-containerd-bpf-directory (manager)
  "Mount point for MANAGER's bpffs, where Pod BPF maps and TCX links are pinned."
  (managed-containerd-directory manager "containerd/bpf/"))

(defun mount-managed-bpffs (directory &key (mounted-p #'filesystem-mounted-at-p)
                                           (mounter #'%linux-mount))
  "Mount a bpffs at DIRECTORY (creating it) and return its namestring, unless one
   is already mounted there -- a surviving mount is reused rather than
   overmounted, which would hide the pinned links and discard their counters.
   Signals an error when the mount fails. MOUNTED-P and MOUNTER are injectable
   for testing."
  (let ((target (namestring (uiop:ensure-directory-pathname directory))))
    (ensure-directories-exist (merge-pathnames ".mount-point" target))
    ;; Reuse the node's surviving bpffs after an agent process restart. An
    ;; overmount would hide the pinned links and discard their counters.
    (unless (or (funcall mounted-p target "bpf")
                (zerop (funcall mounter "gr8s-bpf" target "bpf" #xe "")))
      (error "could not mount the gr8s BPF filesystem at ~A: ~A"
             target (sb-int:strerror (sb-alien:get-errno))))
    target))

(defun managed-containerd-shims-alive-p (socket &key (proc #P"/proc/"))
  "True when a containerd shim of the containerd at SOCKET is running: its containers'
state is in use."
  (let ((needle (namestring socket)))
    (some (lambda (directory)
            (let ((line (ignore-errors
                         (with-open-file (stream (merge-pathnames "cmdline" directory)
                                                 :element-type '(unsigned-byte 8))
                           (let ((octets (make-array 8192 :element-type '(unsigned-byte 8))))
                             (map 'string #'code-char
                                  (substitute 32 0 (subseq octets 0 (read-sequence octets stream)))))))))
              (and line (search "containerd-shim" line) (search needle line))))
          (uiop:subdirectories proc))))

(defun mounts-under-p (directory &key (mount-info (uiop:read-file-string #P"/proc/thread-self/mountinfo")))
  "True when anything is mounted at or below DIRECTORY."
  (let ((prefix (string-right-trim "/" (namestring directory))))
    (some (lambda (line)
            (let ((point (nth 4 (uiop:split-string line :separator " "))))
              (and point (eql 0 (search prefix point)))))
          (uiop:split-string mount-info :separator '(#\Newline)))))

(defun mount-managed-containerd-state
    (manager &key (euid (sb-posix:geteuid)) (mounted-p #'filesystem-mounted-at-p)
                  (mounter #'%linux-mount) (shims-alive-p #'managed-containerd-shims-alive-p)
                  (mounts-under-p #'mounts-under-p))
  "Keep MANAGER's containerd state on a tmpfs, as stock containerd keeps it under /run
(podster-j9gd): it holds each container's OCI spec, and so its environment, Secret
values given as env vars among them, which on disk would outlive the Pod. A tmpfs
already there is kept, across agent restarts, for the shims that outlive containerd.
State on disk that a running shim uses is left there, and said so, until the node's
Pods are gone or it restarts; dead state, as after a reboot, is removed first. Returns
:tmpfs, or :disk with why."
  (let ((directory (uiop:ensure-directory-pathname (managed-containerd-directory manager "containerd/run/")))
        (socket (managed-containerd-socket-path manager)))
    (ensure-directories-exist directory)
    (flet ((disk (why)
             (format *error-output* "gr8s: containerd's state stays on disk at ~A, ~A; Secret values given to containers as env vars are on disk with it~%"
                     (namestring directory) why)
             (values :disk why)))
      (cond ((/= euid 0) (values :disk "not root"))
            ((funcall mounted-p directory "tmpfs") :tmpfs)
            ((funcall shims-alive-p socket)
             (disk "while running containers use it (it moves to memory when the node restarts or its Pods are gone)"))
            ((funcall mounts-under-p directory) (disk "as something is still mounted under it"))
            (t
             ;; Nothing alive uses what is here: a previous boot's state.
             (dolist (entry (append (uiop:subdirectories directory) (uiop:directory-files directory)))
               (if (uiop:directory-pathname-p entry)
                   (uiop:delete-directory-tree entry :validate t :if-does-not-exist :ignore)
                   (ignore-errors (delete-file entry))))
             (if (zerop (funcall mounter "gr8s-containerd-state" (namestring directory) "tmpfs" #x6 "mode=0711"))
                 :tmpfs
                 (disk (format nil "as a tmpfs couldn't be mounted there: ~A" (sb-int:strerror (sb-alien:get-errno))))))))))

(defun unmount-managed-bpffs (directory &key (unmounter #'%linux-umount))
  "Unmount the bpffs at DIRECTORY and return its namestring, unless it still
   holds pinned Pod state (any nested */* entry) -- those maps and TCX links
   stay pinned for the next agent process to adopt. Signals an error when the
   unmount itself fails. UNMOUNTER is injectable for testing."
  (let ((target (namestring (uiop:ensure-directory-pathname directory))))
    ;; Running Pods outlive the agent. Keep their maps and TCX links pinned;
    ;; the next process must adopt them before reconnecting to the server.
    (unless (or (directory (merge-pathnames #P"*/*" target))
                (zerop (funcall unmounter target 0)))
      (error "could not unmount the gr8s BPF filesystem at ~A: ~A"
             target (sb-int:strerror (sb-alien:get-errno))))
    target))

(defun managed-containerd-binary-directory (manager)
  "Directory holding the containerd and runc binaries: the staged runtime
   directory when MANAGER carries embedded assets, otherwise the directory of
   its configured executable."
  (if (managed-containerd-runtime-assets manager)
      (managed-containerd-runtime-directory manager)
      (string-right-trim
       "/"
       (namestring
        (uiop:pathname-directory-pathname
         (pathname (managed-containerd-executable manager)))))))

(defun managed-containerd-environment (manager)
  "The child-process environment: the inherited environment with PATH replaced
   by one that puts MANAGER's binary directory first, then any runtime-addon bin
   directories, then the inherited PATH -- so containerd can exec runc and addon
   shims by name. OpenTelemetry's OTEL_* variables are left out: they configure the
   agent's own tracing, and containerd, which has OTel built in, would otherwise
   trace every CRI call the kubelet makes to the same collector (podster-krg)."
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
                       (or (uiop:string-prefix-p "PATH=" entry)
                           (uiop:string-prefix-p "OTEL_" entry)))
                     inherited))))

(defun managed-containerd-command (manager)
  "The argv that launches MANAGER's containerd against its generated config."
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
  "Render MANAGER's containerd config.toml as a string (schema version 4):
   root/state/temp under the state directory, the CRI image and runtime plugins
   (with the runtime-handler block), the CNI plugin dirs, and the gRPC and ttrpc
   control socket addresses."
  (let ((root (managed-containerd-directory manager "containerd/root"))
        (state (managed-containerd-directory manager "containerd/run"))
        (temporary (managed-containerd-directory manager "containerd/tmp"))
        (runtimes (managed-containerd-runtimes-toml manager))
        (socket (managed-containerd-socket-path manager))
        (registry-config (managed-containerd-directory manager "containerd/certs.d"))
        (cni-config (managed-containerd-cni-config-directory-path manager))
        (snapshotter (managed-containerd-snapshotter manager)))
    (format
     nil
     "version = 4~%root = '~A'~%state = '~A'~%temp = '~A'~%~
[plugins]~%~:[~;  [plugins.'io.containerd.metadata.v1.bolt']~%    no_sync = true~%~]  [plugins.'io.containerd.cri.v1.images']~%    snapshotter = '~A'~%~
    [plugins.'io.containerd.cri.v1.images'.registry]~%      config_path = '~A'~%~
  [plugins.'io.containerd.cri.v1.runtime']~%    disable_apparmor = true~%    disable_hugetlb_controller = false~%    tolerate_missing_hugetlb_controller = false~%    restrict_oom_score_adj = true~%    netns_mounts_under_state_dir = true~%~
    [plugins.'io.containerd.cri.v1.runtime'.containerd]~%      default_runtime_name = 'runc'~%~A~
    [plugins.'io.containerd.cri.v1.runtime'.cni]~%      bin_dirs = ~A~%      conf_dir = '~A'~%      use_internal_loopback = true~%~
  [plugins.'io.containerd.nri.v1.nri']~%    disable = true~%~
  [plugins.'io.containerd.shim.v1.manager']~%    socket_dir = '~A'~%~
  [plugins.'io.containerd.transfer.v1.local']~%~
    [[plugins.'io.containerd.transfer.v1.local'.unpack_config]]~%      platform = '~A'~%      snapshotter = '~A'~%~
  [plugins.'io.containerd.server.v1.grpc']~%    address = '~A'~%~
  [plugins.'io.containerd.server.v1.ttrpc']~%    address = '~A.ttrpc'~%"
     root state temporary (managed-containerd-metadata-no-sync manager) snapshotter registry-config
     runtimes
     (toml-string-list (managed-containerd-cni-bin-directory-list manager))
     cni-config (managed-containerd-shim-socket-directory manager)
     (managed-containerd-platform manager)
     snapshotter socket socket)))

(defun managed-containerd-log-path (manager)
  "Path to the file MANAGER's containerd stdout and stderr are appended to."
  (managed-containerd-directory manager "containerd/containerd.log"))

(defun managed-containerd-owner-path (manager)
  "Path to MANAGER's durable containerd process-identity record."
  (managed-containerd-directory manager "containerd/run/gr8s-owner"))

(defun linux-process-start-time (pid)
  "Return Linux PID's start-time ticks from /proc, or NIL when it is gone.
The start time disambiguates a live process from a later process that reused its
numeric PID."
  (handler-case
      (let* ((stat (uiop:read-file-string (format nil "/proc/~D/stat" pid)))
             ;; The command name may contain spaces and parentheses. Everything
             ;; after its final close parenthesis begins with field 3 (state).
             (tail (subseq stat (1+ (position #\) stat :from-end t))))
             (fields (remove ""
                             (uiop:split-string
                              tail :separator '(#\Space #\Tab #\Newline))
                             :test #'equal)))
        ;; starttime is field 22, hence element 19 when TAIL starts at field 3.
        (nth 19 fields))
    (error () nil)))

(defun linux-process-command (pid)
  "Return Linux PID's NUL-separated argv as a list, or NIL when unavailable."
  (handler-case
      (with-open-file (stream (format nil "/proc/~D/cmdline" pid)
                              :direction :input
                              :element-type '(unsigned-byte 8))
        ;; Procfs reports a zero file length, so consume it to EOF.
        (let ((bytes (make-array 128 :element-type '(unsigned-byte 8)
                                     :adjustable t :fill-pointer 0)))
          (loop for byte = (read-byte stream nil nil)
                while byte do (vector-push-extend byte bytes))
          (loop with start = 0
                for end = (position 0 bytes :start start)
                while end
                when (> end start)
                  collect (map 'string #'code-char (subseq bytes start end))
                do (setf start (1+ end)))))
    (error () nil)))

(defun linux-process-state (pid)
  "Return Linux PID's one-letter process state, or NIL when unavailable."
  (handler-case
      (let* ((stat (uiop:read-file-string (format nil "/proc/~D/stat" pid)))
             (tail (subseq stat (+ 2 (position #\) stat :from-end t)))))
        (char tail 0))
    (error () nil)))

(defun linux-process-alive-p (pid)
  "True when Linux PID exists, is not a zombie, and may be signaled."
  (handler-case
      (progn
        (sb-posix:kill pid 0)
        (let ((state (linux-process-state pid)))
          (and state (char/= state #\Z))))
    (sb-posix:syscall-error () nil)))

(defun write-managed-containerd-owner (manager pid start-time)
  "Persist PID and START-TIME as the identity of MANAGER's current containerd."
  (let ((path (managed-containerd-owner-path manager)))
    (ensure-directories-exist path)
    (with-open-file (stream path :direction :output :if-exists :supersede
                                 :if-does-not-exist :create)
      (format stream "~D~%~A~%" pid start-time))
    path))

(defun read-managed-containerd-owner (manager)
  "Return MANAGER's recorded containerd PID and start time, or no values."
  (handler-case
      (with-open-file (stream (managed-containerd-owner-path manager))
        (values (parse-integer (read-line stream)) (read-line stream)))
    (error () (values nil nil))))

(defun clear-managed-containerd-owner (manager)
  "Remove MANAGER's process-identity record, if any."
  (let ((path (managed-containerd-owner-path manager)))
    (when (probe-file path)
      (delete-file path))))

(defun record-managed-containerd-owner (manager process)
  "Persist PROCESS's Linux identity when it is a real UIOP child handle.
Injected test processes have no OS pid and therefore need no durable record."
  (let ((pid (ignore-errors (uiop:process-info-pid process))))
    (when pid
      (let ((start-time (linux-process-start-time pid)))
        (unless start-time
          (error 'runtime-error
                 :message "could not identify newly launched managed containerd"))
        (write-managed-containerd-owner manager pid start-time)))))

(defun reclaim-stale-managed-containerd
    (manager &key (timeout 5.0)
                  (process-start-time #'linux-process-start-time)
                  (process-command #'linux-process-command)
                  (process-alive-p #'linux-process-alive-p)
                  (signaler #'sb-posix:kill)
                  (sleeper #'sleep))
  "Stop the containerd a previous instance of MANAGER left after an unclean exit.
Only a process whose PID, Linux start time, and complete argv all match the
durable ownership record is signaled. This makes a stale record harmless after
PID reuse. Return true when an owned live process was reclaimed."
  (multiple-value-bind (pid recorded-start-time)
      (read-managed-containerd-owner manager)
    (unwind-protect
         (when (and pid recorded-start-time
                    (funcall process-alive-p pid)
                    (equal recorded-start-time (funcall process-start-time pid))
                    (equal (managed-containerd-command manager)
                           (funcall process-command pid)))
           (funcall signaler pid sb-posix:sigterm)
           (let ((deadline (+ (get-internal-real-time)
                              (* timeout internal-time-units-per-second))))
             (loop while (and (funcall process-alive-p pid)
                              (equal recorded-start-time
                                     (funcall process-start-time pid))
                              (< (get-internal-real-time) deadline))
                   do (funcall sleeper 0.05))
             (when (and (funcall process-alive-p pid)
                        (equal recorded-start-time
                               (funcall process-start-time pid)))
               (funcall signaler pid sb-posix:sigkill)))
           t)
      (clear-managed-containerd-owner manager))))

(defun managed-containerd-cni-config-text (manager)
  "Render the gr8s CNI conflist (JSON) naming the agent's CNI socket and the
   bpffs map-pin root, with egress direction. Because the egress guard is
   JIT-compiled in-process, the conflist carries no ELF program path. An
   explicit native v2 opt-in requires the staged v2 packet maps as well."
  ;; The egress guard is JIT-compiled in-process by the agent; the conflist
  ;; carries no ELF "program" path.
  (let* ((map-pin-root (managed-containerd-bpf-directory manager))
         (packet-services-p (equal "1" (uiop:getenv "GR8S_ENABLE_PACKET_SERVICES")))
         (prepare-v2-p (equal "1" (uiop:getenv "GR8S_PREPARE_PACKET_SERVICES_V2")))
         (native-v2-p (equal "1" (uiop:getenv "GR8S_ENABLE_NATIVE_SERVICE_V2"))))
    (when (and native-v2-p (not (and packet-services-p prepare-v2-p)))
      (error "Native v2 Service profile requires packet Services and v2 map preparation"))
    (format
     nil
     "{\"cniVersion\":\"1.0.0\",\"name\":\"gr8s\",\"plugins\":[{\"type\":\"gr8s\",\"socket\":~A,\"direction\":\"egress\",\"mapPinRoot\":~A~A}]}~%"
     (com.inuoe.jzon:stringify
      (managed-containerd-agent-cni-socket-path manager))
     (com.inuoe.jzon:stringify (namestring map-pin-root))
     (if packet-services-p
         (format nil ",\"servicePacketRoot\":~A~A"
                 (com.inuoe.jzon:stringify
                  (namestring (merge-pathnames "service-lb/" map-pin-root)))
                 (if native-v2-p ",\"servicePacketProfile\":\"v2\"" ""))
         ""))))

(defun managed-containerd-cni-config-path (manager)
  "Path to MANAGER's generated gr8s CNI conflist."
  (managed-containerd-directory
   manager "containerd/cni/net.d/10-gr8s.conflist"))

(defun write-managed-containerd-config (manager)
  "Create MANAGER's runtime directory tree, write its containerd config.toml and
   gr8s CNI conflist, and lock the shim-socket directory to mode 0700. Returns
   the config path."
  (let ((path (managed-containerd-config-path manager)))
    (ensure-directories-exist path)
    (ensure-directories-exist
     (merge-pathnames ".directory"
                      (uiop:ensure-directory-pathname
                       (managed-containerd-cni-config-directory-path manager))))
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
    (when (string= "native" (managed-containerd-cni-mode manager))
      (with-open-file (stream (managed-containerd-cni-config-path manager)
                              :direction :output
                              :if-exists :supersede
                              :if-does-not-exist :create)
        (write-string (managed-containerd-cni-config-text manager) stream)))
    path))

(defun managed-containerd-stopping (manager)
  "True once MANAGER has been asked to stop (read under the supervisor lock)."
  (bt:with-lock-held ((managed-containerd-supervisor-lock manager))
    (managed-containerd-stopping-p manager)))

(defun managed-containerd-supervisor-wait (manager seconds)
  "Wait SECONDS unless MANAGER is stopping; return true when it is."
  (let ((deadline (+ (get-internal-real-time) (* seconds internal-time-units-per-second))))
    (bt:with-lock-held ((managed-containerd-supervisor-lock manager))
      (loop
        (when (managed-containerd-stopping-p manager)
          (return t))
        (let ((remaining (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))
          (unless (plusp remaining)
            (return nil))
          (bt:condition-wait (managed-containerd-supervisor-changed manager)
                             (managed-containerd-supervisor-lock manager)
                             :timeout remaining))))))

(defun restart-managed-containerd (manager delay)
  "Restart MANAGER's dead containerd after DELAY seconds, backing off until it is ready.
Return the delay the next outage starts from, or NIL when MANAGER began stopping."
  (let ((delay delay))
    (loop
      (when (managed-containerd-supervisor-wait manager delay)
        (return nil))
      (handler-case
          (progn
            (start-managed-containerd manager)
            (return (min (managed-containerd-restart-max-delay manager) (* 2 delay))))
        (error (condition)
          (when (managed-containerd-stopping manager)
            (return nil))
          (setf delay (min (managed-containerd-restart-max-delay manager) (* 2 delay)))
          (format *error-output* "gr8s managed containerd restart failed: ~A; retrying in ~,1Fs~%"
                  condition delay))))))

(defun supervise-managed-containerd (manager)
  "Restart MANAGER's containerd whenever it exits, until MANAGER stops.
Pods keep running across the outage: their shims outlive containerd, which
reconnects to them when it starts again."
  (let ((delay (managed-containerd-restart-initial-delay manager))
        (started (get-internal-real-time)))
    (loop
      (when (managed-containerd-supervisor-wait manager (managed-containerd-supervision-interval manager))
        (return))
      (let ((process (managed-containerd-process manager)))
        (unless (and process (funcall (managed-containerd-process-alive-p manager) process))
          (let ((uptime (/ (- (get-internal-real-time) started) internal-time-units-per-second))
                (exit (if process
                          (or (ignore-errors (funcall (managed-containerd-exit-describer manager) process))
                              "exit status unknown")
                          "not running")))
            (when (>= uptime (managed-containerd-restart-stable-seconds manager))
              (setf delay (managed-containerd-restart-initial-delay manager)))
            (setf (managed-containerd-process manager) nil)
            (note-runtime-unavailable
             (managed-containerd-availability manager)
             (format nil "container runtime is down: managed containerd exited (~A)" exit))
            (format *error-output*
                    "gr8s managed containerd exited (~A) after ~,1Fs; restarting in ~,1Fs; see ~A~%"
                    exit uptime delay (managed-containerd-log-path manager))
            (let ((next (restart-managed-containerd manager delay)))
              (unless next
                (return))
              (setf delay next
                    started (get-internal-real-time))
              (incf (managed-containerd-restarts manager))
              (note-runtime-available (managed-containerd-availability manager))
              (format *error-output* "gr8s managed containerd restarted (restart ~D)~%"
                      (managed-containerd-restarts manager)))))))))

(defun start-managed-containerd-supervisor (manager)
  "Spawn MANAGER's supervisor thread, which restarts containerd on exit and logs
   to the agent's *error-output*. The thread is stored in MANAGER's SUPERVISOR
   slot."
  (setf (managed-containerd-supervisor manager)
        (let ((output *error-output*))
          ;; Log where the agent that owns this containerd logs.
          (bt:make-thread (lambda ()
                            (let ((*error-output* output))
                              (supervise-managed-containerd manager)))
                          :name "gr8s managed containerd supervisor"))))

(defun stop-managed-containerd-supervisor (manager)
  "Signal MANAGER's supervisor to stop and join its thread, skipping the join
   when called from the supervisor thread itself."
  (bt:with-lock-held ((managed-containerd-supervisor-lock manager))
    (setf (managed-containerd-stopping-p manager) t)
    (bt:condition-notify (managed-containerd-supervisor-changed manager)))
  (let ((thread (shiftf (managed-containerd-supervisor manager) nil)))
    (when (and thread (not (eq thread (bt:current-thread))))
      (ignore-errors (bt:join-thread thread)))))

(defun stop-managed-containerd (manager)
  "Stop MANAGER: halt the supervisor, then terminate the running containerd (via
   the configured stopper) and clear the process slot. Returns NIL."
  (stop-managed-containerd-supervisor manager)
  (let ((process (managed-containerd-process manager)))
    (when process
      (unwind-protect
           (funcall (managed-containerd-stopper manager) process)
        (setf (managed-containerd-process manager) nil))))
  (clear-managed-containerd-owner manager)
  nil)

(defun start-managed-containerd (manager &key (timeout 30))
  "Write MANAGER's config, launch containerd, and block until its CRI socket is
   ready, returning MANAGER. Signals a RUNTIME-ERROR when containerd is already
   running, exits during startup, or is not ready within TIMEOUT seconds
   (terminating it on timeout)."
  (let ((existing (managed-containerd-process manager)))
    (when (and existing
               (funcall (managed-containerd-process-alive-p manager) existing))
      (error 'runtime-error :message "managed containerd is already running")))
  ;; A SIGKILL prevents the previous agent's unwind cleanup. Reclaim only the
  ;; exact process identity it recorded before replacing its configuration.
  (reclaim-stale-managed-containerd manager)
  (when (managed-containerd-state-mounter manager)
    (funcall (managed-containerd-state-mounter manager) manager))
  (write-managed-containerd-config manager)
  (setf (managed-containerd-process manager)
        (funcall (managed-containerd-launcher manager)
                 (managed-containerd-command manager)
                 (managed-containerd-log-path manager)
                 (managed-containerd-environment manager)))
  (handler-case
      (record-managed-containerd-owner manager
                                       (managed-containerd-process manager))
    (error (condition)
      (let ((process (shiftf (managed-containerd-process manager) nil)))
        (when process
          (funcall (managed-containerd-stopper manager) process)))
      (clear-managed-containerd-owner manager)
      (error condition)))
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (loop
      (when (funcall (managed-containerd-readiness-probe manager)
                     (managed-containerd-socket-path manager))
        (return manager))
      (unless (funcall (managed-containerd-process-alive-p manager)
                       (managed-containerd-process manager))
        (setf (managed-containerd-process manager) nil)
        (clear-managed-containerd-owner manager)
        (error 'runtime-error
               :message (format nil "managed containerd exited; see ~A"
                                (managed-containerd-log-path manager))))
      (when (or (>= (get-internal-real-time) deadline)
                (managed-containerd-stopping manager))
        (let ((process (shiftf (managed-containerd-process manager) nil)))
          (when process
            (funcall (managed-containerd-stopper manager) process)))
        (clear-managed-containerd-owner manager)
        (error 'runtime-error
               :message (format nil "managed containerd was not ready after ~A seconds"
                                timeout)))
      (sleep 0.05))))

(defun call-with-running-containerd (manager function)
  "Start MANAGER's containerd (preloading its image archives) and supervisor,
   call FUNCTION with no arguments, and stop everything on unwind. Installs a
   liveness predicate on MANAGER's availability for the dynamic extent so a
   caller can tell a dead runtime from a failed call. Returns FUNCTION's values."
  (bt:with-lock-held ((managed-containerd-supervisor-lock manager))
    (setf (managed-containerd-stopping-p manager) nil))
  (setf (runtime-availability-liveness (managed-containerd-availability manager))
        (lambda ()
          (let ((process (managed-containerd-process manager)))
            (and process (funcall (managed-containerd-process-alive-p manager) process)))))
  (unwind-protect
       (progn
         (start-managed-containerd manager)
         ;; Archives under <state>/images/ are imported before any Pod can start.
         (preload-managed-containerd-images manager)
         (start-managed-containerd-supervisor manager)
         (funcall function))
    (setf (runtime-availability-liveness (managed-containerd-availability manager)) nil)
    (stop-managed-containerd manager)))

(defun prepared-runtime-path (name paths)
  "Return the namestring of the prepared runtime payload named NAME from PATHS
   (an alist). Signals an error when it is absent."
  (let ((entry (assoc name paths :test #'string=)))
    (unless entry
      (error "embedded runtime payload is missing ~A" name))
    (namestring (cdr entry))))

(defun call-with-managed-containerd (manager function)
  "Run FUNCTION with MANAGER fully provisioned. When MANAGER is NIL, just call
   FUNCTION. When MANAGER carries embedded runtime assets, stage them and point
   its executable, OCI runtime and CNI bin directory at the staged paths first.
   Either way, mount the bpffs and run a supervised containerd around FUNCTION."
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
  "Mount MANAGER's bpffs, run FUNCTION under a running supervised containerd, and
   unmount on unwind (the unmounter leaves pinned Pod state in place)."
  (let ((directory (managed-containerd-bpf-directory manager)))
    (funcall (managed-containerd-bpf-mounter manager) directory)
    (unwind-protect
         (call-with-running-containerd manager function)
      (funcall (managed-containerd-bpf-unmounter manager) directory))))
