;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The containerd Pod runtime backend, driving Pods over containerd's CRI socket.
;;;;
;;;; This implements the runtime generic-function protocol (runtime-ensure,
;;;; runtime-reconcile-containers, runtime-exec-url and the rest) against a real
;;;; containerd via CRI. gr8s owns only the sandboxes and containers it creates:
;;;; it stamps them with +gr8s-managed-label+ and +gr8s-uid-label+ and finds its
;;;; own work by those labels, so it can share a host with other CRI clients.
;;;; Around CRI it adds what Kubernetes semantics need but CRI does not give for
;;;; free -- image pull policy and credentials, mounts and projected volumes,
;;;; security and user namespaces, termination-message capture, lifecycle hooks,
;;;; and a durable record of container events for status. Convergence is
;;;; non-destructive: an unchanged sandbox and healthy sibling containers are left
;;;; running. CRI and other errors are funnelled through CALL-CONTAINERD-RUNTIME
;;;; so callers see a single runtime-error type from this layer.

(in-package #:gr8s.runtime.containerd)

(defstruct (containerd-runtime (:constructor %make-containerd-runtime))
  socket-path
  log-root
  host-network
  ;; Returns the Pods sharing this node, once an agent knows them; resizes are judged against them.
  pod-lister
  ;; The node's own address once an agent knows it; hostNetwork Pods share it.
  host-address
  dns-servers
  dns-searches
  dns-options
  ;; Static node credentials, after parsing a Docker config at startup.
  registry-credentials
  ;; Kubelet-compatible executable credential providers, in configured order.
  credential-providers
  ;; Obtains a Pod-bound token and ServiceAccount identity from the control plane.
  credential-provider-token-function
  ;; Managed nodes populate a per-registry hosts.toml immediately before CRI
  ;; PullImage so containerd tries the local P2P mirror, then its real upstream.
  registry-host-config-directory
  image-mirror-port
  resource-store
  probes
  (lifecycle-lock (bt:make-lock "native lifecycle checkpoint writes"))
  (hooks (make-container-hook-manager))
  (images (make-image-pull-manager))
  (deletions (make-deletion-controller))
  ;; Set for a supervised managed containerd; NIL trusts an external runtime to be up.
  availability)

(defmethod runtime-unavailable-message ((runtime containerd-runtime))
  (runtime-availability-message (containerd-runtime-availability runtime)))

(defun make-containerd-runtime
    (&key (socket-path "/run/containerd/containerd.sock")
          (log-root "/var/log/gr8s/pods/")
          (host-network t)
          dns-servers dns-searches dns-options registry-credentials credential-providers
          credential-provider-token-function availability
          registry-host-config-directory image-mirror-port)
  "Build a CONTAINERD-RUNTIME, defaulting the CRI socket, Pod log root and
   host-network on. AVAILABILITY, when given, is a managed containerd's readiness
   handle; NIL trusts an external runtime to already be up."
  (%make-containerd-runtime
   :availability availability
   :socket-path socket-path
   :log-root (uiop:ensure-directory-pathname log-root)
   :host-network host-network
   :dns-servers dns-servers
   :dns-searches dns-searches
   :dns-options dns-options
   :registry-credentials registry-credentials
   :credential-providers credential-providers
   :credential-provider-token-function credential-provider-token-function
   :registry-host-config-directory registry-host-config-directory
   :image-mirror-port image-mirror-port))

(defun call-containerd-runtime (thunk)
  "Call THUNK and return its values. Re-signals a runtime-error or
   kubernetes-error unchanged, and wraps any other error as a runtime-error, so
   callers see one error type from the CRI layer."
  (handler-case
      (funcall thunk)
    ((or runtime-error kubernetes-error) (condition)
      (error condition))
    (error (condition)
      (error 'runtime-error :message (princ-to-string condition)))))

(defun containerd-ownership-labels (uid)
  "The CRI label alist that marks a sandbox or container as gr8s-managed and tags
   it with Pod UID."
  (list (cons +gr8s-managed-label+ "true")
        (cons +gr8s-uid-label+ uid)))

(defun containerd-owned-sandbox (runtime uid)
  "The gr8s-owned sandbox for Pod UID on RUNTIME: the READY one if any, else the
   first found, or NIL when none exists."
  (let ((sandboxes (cri-list-pod-sandboxes (containerd-runtime-socket-path runtime)
                                          :labels (containerd-ownership-labels uid))))
    (or (find gr8s.cri.v1::+podsandboxstate-sandbox_ready+ sandboxes :key #'cri-pod-sandbox-info-state)
        (first sandboxes))))

(defun containerd-containers (runtime sandbox)
  "The gr8s-managed containers in SANDBOX on RUNTIME."
  (cri-list-containers
   (containerd-runtime-socket-path runtime)
   :sandbox-id (cri-pod-sandbox-info-id sandbox)
   :labels (list (cons +gr8s-managed-label+ "true"))))

(defun containerd-pod-log-directory (runtime uid)
  "The log directory for Pod UID: UID/ under RUNTIME's log root."
  (merge-pathnames (format nil "~A/" uid)
                   (containerd-runtime-log-root runtime)))

(defun containerd-phase (runtime containers &optional details)
  "The Kubernetes Pod phase for CONTAINERS by their CRI states: \"Pending\" when
   there are none, \"Running\" when any is running, and when all have exited
   \"Failed\" if any exited non-zero else \"Succeeded\"; otherwise \"Pending\".
   DETAILS supplies already-fetched container statuses for exit codes; any missing
   one is fetched from RUNTIME."
  (cond
    ((null containers) "Pending")
    ((find gr8s.cri.v1::+containerstate-container_running+
           containers :key #'cri-container-summary-state)
     "Running")
    ((every (lambda (container)
              (= gr8s.cri.v1::+containerstate-container_exited+
                 (cri-container-summary-state container)))
            containers)
     (if (some (lambda (container)
                 (not (zerop
                       (cri-container-info-exit-code
                        (or (find (cri-container-summary-id container) details
                                  :key #'cri-container-info-id :test #'equal)
                            (cri-container-status
                             (containerd-runtime-socket-path runtime)
                             (cri-container-summary-id container)))))))
               containers)
         "Failed"
         "Succeeded"))
    (t "Pending")))

(defun cri-status-timestamp (nanoseconds)
  "Format an observed CRI Unix timestamp for Kubernetes container state."
  (when (plusp nanoseconds)
    (multiple-value-bind (second minute hour day month year)
        (decode-universal-time (+ 2208988800 (floor nanoseconds 1000000000)) 0)
      (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ"
              year month day hour minute second))))

(defun container-start-cancelled-p (info)
  "Return whether INFO exited only because the agent abandoned its StartContainer call.
That says nothing about the container, so restart policy doesn't apply: a Pod that never
restarts would otherwise go straight to Failed. The agent's own cancellation now lets the
call finish (WITH-RUNNING-POD-CANCELLATION-DEFERRED), but the client timeout and the agent
exiting mid-call still abandon it."
  (let ((message (or (cri-container-info-message info) "")))
    (and (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+)
         (eql 128 (cri-container-info-exit-code info))
         (equal "StartError" (cri-container-info-reason info))
         (or (search "context canceled" message) (search "context deadline exceeded" message))
         t)))

(defun containerd-container-status-object (info)
  "Translate actual CRI state; consumers must not infer completion from an empty list."
  (let* ((running (= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_running+))
         (state (core-object))
         (id (format nil "containerd://~A" (cri-container-info-id info)))
         (started (cri-status-timestamp (cri-container-info-started-at info)))
         (finished (cri-status-timestamp (cri-container-info-finished-at info))))
    (cond
      (running
       (setf (gethash "running" state) (if started (core-object "startedAt" started) (core-object))))
      ((container-start-cancelled-p info)
       (setf (gethash "waiting" state) (core-object "reason" "ContainerCreating")))
      ((= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+)
       (let ((terminated (core-object "exitCode" (cri-container-info-exit-code info)
                                      "containerID" id)))
         (when started (setf (gethash "startedAt" terminated) started))
         (when finished (setf (gethash "finishedAt" terminated) finished))
         (when (cri-container-info-reason info)
           (setf (gethash "reason" terminated) (cri-container-info-reason info)))
         (let ((message (or (container-termination-message info) (cri-container-info-message info))))
           (when (and message (plusp (length message)))
             (setf (gethash "message" terminated) message)))
         (setf (gethash "terminated" state) terminated)))
      (t (setf (gethash "waiting" state)
               (core-object "reason" (if (= (cri-container-info-state info)
                                              gr8s.cri.v1::+containerstate-container_created+)
                                         "ContainerCreating" "ContainerStatusUnknown")))))
    (core-object "name" (or (cri-container-info-name info)
                            (cdr (assoc +gr8s-container-label+ (cri-container-info-labels info) :test #'equal)))
                 "containerID" id "image" (or (cri-container-info-image info) "")
                 "imageID" (or (cri-container-info-image-ref info) "")
                 "restartCount" (cri-container-info-attempt info)
                 "ready" running "started" running "state" state)))

(defmethod runtime-observe ((runtime containerd-runtime) uid)
  (call-containerd-runtime
   (lambda ()
     (let* ((sandbox (containerd-owned-sandbox runtime uid))
            (containers (when sandbox (containerd-containers runtime sandbox)))
            (details (loop for container in containers
                           collect (cri-container-status (containerd-runtime-socket-path runtime)
                                                         (cri-container-summary-id container))))
            (state (load-container-lifecycle-state runtime uid))
            (checkpoint-owned-p (plusp (hash-table-count (gethash "containers" state))))
            (history (when (or sandbox checkpoint-owned-p) (incorporate-container-log-history runtime uid state)))
            (all-statuses (container-lifecycle-statuses (mask-post-start-containers runtime details) (or history state)))
            (statuses (separate-ephemeral-statuses all-statuses state))
            (ephemeral (nth-value 1 (separate-ephemeral-statuses all-statuses state))))
       (when (or sandbox (and checkpoint-owned-p (plusp (length statuses))))
         (apply-init-container-observation
          (apply-container-probe-observation runtime
          (make-runtime-pod
          :uid uid
          :resource-version
          (or (and sandbox (cdr (assoc +gr8s-resource-version-label+
                          (cri-pod-sandbox-info-labels sandbox)
                          :test #'string=)))
              (gethash "resourceVersion" state ""))
          :spec-fingerprint (or (and sandbox (cdr (assoc +gr8s-spec-fingerprint-label+ (cri-pod-sandbox-info-labels sandbox) :test #'string=)))
                                (gethash "specFingerprint" state))
          :pod-ip (cond ((null sandbox) (gethash "podIP" state ""))
                        ((assoc +gr8s-host-network-label+ (cri-pod-sandbox-info-labels sandbox) :test #'string=)
                         (containerd-node-address runtime))
                        (t (cri-pod-sandbox-ip (containerd-runtime-socket-path runtime) (cri-pod-sandbox-info-id sandbox))))
          :phase (container-lifecycle-phase statuses (and sandbox (= gr8s.cri.v1::+podsandboxstate-sandbox_ready+
                                                                         (cri-pod-sandbox-info-state sandbox))))
          :container-details details
          :status (let ((status (core-object "containerStatuses" statuses)))
                    (when (plusp (length ephemeral)) (setf (gethash "ephemeralContainerStatuses" status) ephemeral))
                    status))) state))))))

(defun containerd-replace-uid (runtime uid)
  "Remove UID's sandbox for recreation under the same Pod, keeping its volumes."
  (cancel-runtime-pod-deletion (containerd-runtime-deletions runtime) uid)
  (containerd-delete-uid runtime uid (funcall *pod-deletion-clock*)))

(defmethod runtime-delete ((runtime containerd-runtime) uid)
  (containerd-replace-uid runtime uid)
  (cleanup-pod-volumes runtime uid))

(defun containerd-delete-uid (runtime uid deadline &key preserve-lifecycle)
  "Stop UID's containers concurrently against DEADLINE before removing its sandbox."
  (stop-container-probes runtime uid)
  (call-containerd-runtime
   (lambda ()
     (let ((sandbox (containerd-owned-sandbox runtime uid)))
       (when sandbox
         (let* ((containers (containerd-containers runtime sandbox))
                (failures (make-array (length containers) :initial-element nil))
                (register *runtime-deletion-register-cancel*)
                (threads
                  (loop for container in containers for index from 0
                        collect
                        (let ((id (cri-container-summary-id container)) (slot index))
                          (bt:make-thread
                           (lambda ()
                             (let ((*runtime-deletion-register-cancel* register))
                               (handler-case
                                   (cri-delete-container
                                    (containerd-runtime-socket-path runtime) id
                                    :grace-period (max 0 (- deadline (funcall *pod-deletion-clock*))))
                                 (error (condition) (setf (aref failures slot) condition)))))
                           :name "gr8s stop container")))))
           (mapc #'bt:join-thread threads)
           (loop for failure across failures when failure do (error failure)))
         (cri-delete-pod-sandbox
          (containerd-runtime-socket-path runtime)
          (cri-pod-sandbox-info-id sandbox))))
     (cleanup-pod-subpaths runtime uid)
     (unless preserve-lifecycle (forget-container-lifecycle-state runtime uid))
     nil)))

(defmethod runtime-terminate-pod ((runtime containerd-runtime) pod deadline)
  "Carry out one cancellable native Pod shutdown job."
  (begin-terminating-container-probes runtime (pod-uid pod))
  (stop-pod-containers-in-order runtime pod deadline)
  (when (pod-finalizers-present-p pod)
    (capture-containerd-finalized-pod runtime pod deadline))
  (containerd-delete-uid runtime (pod-uid pod) deadline :preserve-lifecycle (pod-finalizers-present-p pod))
  (cleanup-pod-volumes runtime (pod-uid pod)))

(defmethod runtime-delete-pod ((runtime containerd-runtime) pod)
  "Poll the native Pod shutdown job without holding reconciliation until exit."
  (begin-terminating-container-probes runtime (pod-uid pod))
  (poll-runtime-pod-deletion (containerd-runtime-deletions runtime) runtime pod))

(defmethod stop-runtime-deletions ((runtime containerd-runtime))
  "Join native deletion jobs before the containerd service exits."
  (stop-container-probes runtime)
  (stop-runtime-deletion-controller (containerd-runtime-deletions runtime)))

(defun containerd-termination-file (runtime pod spec attempt mounts)
  "Create ATTEMPT's world-writable termination message file; return it with its policy.
A container running as any user can write here, and a user mount at the path takes priority."
  (let* ((object (pod-runtime-container-object pod spec))
         (path (gethash "terminationMessagePath" object)))
    (unless (or (null path)
                (find path mounts :test #'equal
                      :key (lambda (mount) (slot-value mount 'gr8s.cri.v1::container-path))))
      (let ((file (merge-pathnames (format nil "termination/~A.~D" (container-spec-name spec) attempt)
                                   (containerd-pod-log-directory runtime (pod-uid pod)))))
        (write-projected-volume-file file (make-array 0 :element-type '(unsigned-byte 8)) #o666 nil)
        (cons file (gethash "terminationMessagePolicy" object "File"))))))

(defun read-termination-message-file (path)
  "Return at most the 4096 bytes Kubernetes keeps from the message file at PATH, or NIL."
  (ignore-errors
   (with-open-file (in path :element-type '(unsigned-byte 8))
     (let* ((buffer (make-array (min 4096 (file-length in)) :element-type '(unsigned-byte 8)))
            (count (read-sequence buffer in)))
       (when (plusp count)
         (sb-ext:octets-to-string buffer :end count :external-format '(:utf-8 :replacement #\?)))))))

(defun read-termination-log-tail (path)
  "Return the end of the CRI log at PATH, as FallbackToLogsOnError reports: 80 lines, 2048 bytes."
  (ignore-errors
   (when (and path (probe-file path))
     (let* ((text (format-pod-logs (uiop:read-file-string path) :tail-lines 80))
            (bytes (trivial-utf-8:string-to-utf-8-bytes text))
            (start (max 0 (- (length bytes) 2048))))
       (when (plusp (length bytes))
         (sb-ext:octets-to-string (coerce bytes '(vector (unsigned-byte 8))) :start start
                                  :external-format '(:utf-8 :replacement #\?)))))))

(defun container-termination-message (info)
  "Return the message an exited attempt left, honoring its termination message policy."
  (let* ((labels (cri-container-info-labels info))
         (file (cdr (assoc +gr8s-termination-file-label+ labels :test #'equal)))
         (policy (cdr (assoc +gr8s-termination-policy-label+ labels :test #'equal))))
    (when file
      (or (read-termination-message-file file)
          (when (and (equal policy "FallbackToLogsOnError")
                     (not (zerop (cri-container-info-exit-code info))))
            (read-termination-log-tail (cri-container-info-log-path info)))))))

(defun containerd-ephemeral-target-id (runtime pod spec)
  "Return the runtime ID of the container whose PID namespace SPEC targets, if it targets one."
  (let ((target (gethash "targetContainerName" (pod-runtime-container-object pod spec))))
    (when target
      (let ((container (containerd-owned-container runtime (pod-uid pod) target)))
        (unless container
          (error 'runtime-error
                 :message (format nil "Target container ~A is not running" target)))
        (cri-container-summary-id container)))))

(defun containerd-create-container (runtime pod sandbox-id sandbox-config spec &key (attempt 0))
  "Create and start container SPEC in SANDBOX-ID for POD on RUNTIME, and return
   its CRI container id. Pulls the image per its pull policy (with the Pod's
   credentials), assembles environment, mounts, security context and user
   namespace, wires up termination-message capture, records Created and Started
   lifecycle events, and runs the post-start hook. ATTEMPT is the restart attempt
   number, used for the log path and termination file."
  (let ((socket (containerd-runtime-socket-path runtime)))
    (let ((policy (gethash "imagePullPolicy" (pod-runtime-container-object pod spec)
                           (default-image-pull-policy (container-spec-image spec)))))
      (ensure-container-image runtime (container-spec-image spec) policy
                              (lambda ()
                                (pod-image-pull-credentials runtime pod (container-spec-name spec)
                                                            (container-spec-image spec)))))
    (let* ((environment (containerd-pod-environment runtime pod spec sandbox-id))
           (mounts (containerd-container-mounts runtime pod spec sandbox-id environment))
           (security (containerd-pod-security-context
                      pod spec :target-id (containerd-ephemeral-target-id runtime pod spec)
                               :image-user (lambda () (cri-image-user socket (container-spec-image spec)))
                               :userns (containerd-pod-user-namespace runtime pod)
                               :volume-groups (pod-volume-supplemental-groups
                                               (containerd-runtime-resource-store runtime) pod)))
           (termination (containerd-termination-file runtime pod spec attempt mounts))
           (termination-labels
             (when termination
               (list (cons +gr8s-termination-file-label+ (namestring (car termination)))
                     (cons +gr8s-termination-policy-label+ (cdr termination)))))
           (container-id
            (cri-create-container
             socket sandbox-id sandbox-config
             :name (container-spec-name spec)
             :image (container-spec-image spec)
             :command (expand-container-command (container-spec-command spec) environment)
             :args (expand-container-command (container-spec-args spec) environment)
             :env environment
             :mounts (map-mounts-into-user-namespace
                      (if termination
                          (append mounts
                                  (list (make-instance
                                         'gr8s.cri.v1::mount
                                         :container-path (gethash "terminationMessagePath" (pod-runtime-container-object pod spec))
                                         :host-path (namestring (car termination)))))
                          mounts)
                      (gr8s.cri.v1::userns-options (gr8s.cri.v1::namespace-options security)))
             :security-context security
             :resources (cri-linux-container-resources
                         ;; Without a pod cgroup of its own, a container is bounded by the Pod's limits.
                         (container-with-pod-level-limits (gethash "spec" (pod-to-object pod))
                                                          (pod-runtime-container-object pod spec)))
             :working-directory (gethash "workingDir" (pod-runtime-container-object pod spec))
             :stdin (gethash "stdin" (pod-runtime-container-object pod spec))
             :stdin-once (gethash "stdinOnce" (pod-runtime-container-object pod spec))
             :tty (gethash "tty" (pod-runtime-container-object pod spec))
             :uid (pod-uid pod)
             :attempt attempt
             :labels termination-labels
             :log-path (container-attempt-log-path (container-spec-name spec) attempt))))
      (record-container-lifecycle-event runtime (pod-uid pod) (container-spec-name spec) attempt
                                        "Created" (format nil "Created container ~A" (container-spec-name spec)))
      (with-running-pod-cancellation-deferred (cri-start-container socket container-id))
      (record-container-lifecycle-event runtime (pod-uid pod) (container-spec-name spec) attempt
                                        "Started" (format nil "Started container ~A" (container-spec-name spec)))
      (start-container-post-start-hook runtime pod spec container-id sandbox-id)
      container-id)))

(defmethod runtime-ensure ((runtime containerd-runtime) pod)
  "Converge native containers without destroying an unchanged sandbox or healthy siblings."
  (call-containerd-runtime
   (lambda ()
     (reconcile-container-probes runtime pod (counting-user-namespaced-pod-starts runtime pod #'converge-containerd-containers)))))

(defmethod runtime-reconcile-containers ((runtime containerd-runtime) pod observed)
  "Retry only eligible native containers, even while a sibling keeps the Pod Running."
  (checkpoint-container-lifecycle-observation runtime (pod-uid pod) observed)
  ;; A healthy Pod converges no further, so this is where live volumes must update.
  (refresh-pod-projected-volumes runtime pod)
  (when (reconcile-container-updates runtime pod observed)
    (setf observed (or (runtime-observe runtime (pod-uid pod)) observed)))
  (setf observed (reconcile-container-probes runtime pod observed))
  (if (or (native-container-progress-required-p pod observed)
          (container-probe-restart-required-p runtime pod observed))
      (runtime-ensure runtime pod)
      observed))

(defun directory-disk-bytes (path)
  "Return the file bytes under directory PATH, never following symbolic links; sparse holes count."
  (let ((total 0) (directory (handler-case (sb-posix:opendir path) (sb-posix:syscall-error () nil))))
    (when directory
      (unwind-protect
           (loop for entry = (sb-posix:readdir directory)
                 until (sb-alien:null-alien entry)
                 do (let ((name (sb-posix:dirent-name entry)))
                      (unless (member name '("." "..") :test #'equal)
                        (let* ((child (concatenate 'string (string-right-trim "/" path) "/" name))
                               (stat (handler-case (sb-posix:lstat child) (sb-posix:syscall-error () nil))))
                          (when stat
                            (if (= sb-posix:s-ifdir (logand (sb-posix:stat-mode stat) sb-posix:s-ifmt))
                                (incf total (directory-disk-bytes child))
                                (incf total (sb-posix:stat-size stat))))))))
        (sb-posix:closedir directory)))
    total))

(defmethod runtime-ephemeral-usage ((runtime containerd-runtime) pod)
  "Measure writable layers through CRI and disk-backed emptyDirs from their agent-owned directories."
  (let ((sandbox (containerd-owned-sandbox runtime (pod-uid pod))))
    (when sandbox
      (let ((usage (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
                         for source = (gethash "emptyDir" volume)
                         when (and source (not (equal "Memory" (gethash "medium" source))))
                           collect (cons (gethash "name" volume)
                                         (directory-disk-bytes
                                          (namestring (pod-volume-directory runtime pod (gethash "name" volume))))))))
        (values
         (cri-container-writable-bytes (containerd-runtime-socket-path runtime) (cri-pod-sandbox-info-id sandbox))
         (reduce #'+ usage :key #'cdr)
         usage)))))

(defmethod runtime-logs
    ((runtime containerd-runtime) uid container-name &key tail previous)
  (declare (ignore tail))
  (call-containerd-runtime
   (lambda ()
     (let* ((container (containerd-owned-container runtime uid container-name))
            (state (load-container-lifecycle-state runtime uid))
            (owned-entry (gethash container-name (gethash "containers" state)))
            (history (when owned-entry (incorporate-container-log-history runtime uid state)))
            (entry (gethash container-name (gethash "containers" (or history state))))
            (attempt (if container
                         (cri-container-info-attempt (cri-container-status (containerd-runtime-socket-path runtime)
                                                                           (cri-container-summary-id container)))
                         (known-container-attempt entry))))
       (unless (or container (and owned-entry (<= 0 attempt)))
         (error 'runtime-error :message (format nil "Container ~A is not owned by gr8s" container-name)))
       (let ((path (merge-pathnames
                    (container-attempt-log-path container-name (if previous (1- attempt) attempt))
                    (containerd-pod-log-directory runtime uid))))
         (when (and previous (or (zerop attempt) (not (probe-file path))))
           (error 'kubernetes-error
                  :status-code 400 :reason "BadRequest"
                  :message (format nil "previous terminated container ~S not found" container-name)))
         (if (probe-file path) (uiop:read-file-string path) ""))))))

(defun containerd-owned-container (runtime uid container-name)
  "Find the gr8s-owned container named CONTAINER-NAME in Pod UID's sandbox on
   RUNTIME, as a CRI-CONTAINER-SUMMARY, or NIL when the sandbox or the container
   is absent. Merges recorded lifecycle history into the live CRI status."
  (let ((sandbox (containerd-owned-sandbox runtime uid)))
    (and sandbox
         (let* ((state (incorporate-container-log-history runtime uid (load-container-lifecycle-state runtime uid)))
                (info (find container-name
                           (current-container-infos
                            (mapcar (lambda (item) (cri-container-status (containerd-runtime-socket-path runtime)
                                                                        (cri-container-summary-id item)))
                                    (containerd-containers runtime sandbox)) state)
                           :key #'cri-container-info-name :test #'equal)))
           (when info (make-cri-container-summary :id (cri-container-info-id info)
                                                  :state (cri-container-info-state info)
                                                  :labels (cri-container-info-labels info)))))))

(defmethod runtime-exec-url
    ((runtime containerd-runtime) uid container-name command
     &key stdin stdout stderr tty)
  (call-containerd-runtime
   (lambda ()
     (let ((container
             (containerd-owned-container runtime uid container-name)))
       (unless container
         (error 'runtime-error
                :message (format nil "Container ~A is not owned by gr8s"
                                 container-name)))
       (cri-exec-url
        (containerd-runtime-socket-path runtime)
        (cri-container-summary-id container)
        command
        :stdin stdin :stdout stdout :stderr stderr :tty tty)))))

(defmethod runtime-attach-url
    ((runtime containerd-runtime) uid container-name &key stdin stdout stderr tty)
  (call-containerd-runtime
   (lambda ()
     (let ((container (containerd-owned-container runtime uid container-name)))
       (unless container
         (error 'runtime-error
                :message (format nil "Container ~A is not owned by gr8s" container-name)))
       (cri-attach-url (containerd-runtime-socket-path runtime)
                       (cri-container-summary-id container)
                       :stdin stdin :stdout stdout :stderr stderr :tty tty)))))

(defmethod runtime-port-forward-url ((runtime containerd-runtime) uid port)
  (call-containerd-runtime
   (lambda ()
     (let ((sandbox (containerd-owned-sandbox runtime uid)))
       (unless sandbox
         (error 'runtime-error :message "The Pod has no sandbox on this node"))
       (cri-port-forward-url (containerd-runtime-socket-path runtime)
                             (cri-pod-sandbox-info-id sandbox) port)))))

(defmethod runtime-container-metrics ((runtime containerd-runtime))
  (call-containerd-runtime
   (lambda () (cri-container-metrics (containerd-runtime-socket-path runtime)))))

(defmethod runtime-exec-sync
    ((runtime containerd-runtime) uid container-name command &key (timeout 30))
  (call-containerd-runtime
   (lambda ()
     (let ((container
             (containerd-owned-container runtime uid container-name)))
       (unless container
         (error 'runtime-error
                :message (format nil "Container ~A is not owned by gr8s"
                                 container-name)))
       (cri-exec-sync
        (containerd-runtime-socket-path runtime)
        (cri-container-summary-id container)
        command :timeout timeout)))))
