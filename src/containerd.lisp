(in-package #:gr8s)

(defstruct (containerd-runtime (:constructor %make-containerd-runtime))
  socket-path
  log-root
  host-network
  dns-servers
  dns-searches
  dns-options
  resource-store
  probes
  (lifecycle-lock (bt:make-lock "native lifecycle checkpoint writes"))
  (deletions (make-deletion-controller)))

(defun make-containerd-runtime
    (&key (socket-path "/run/containerd/containerd.sock")
          (log-root "/var/log/gr8s/pods/")
          (host-network t)
          dns-servers dns-searches dns-options)
  (%make-containerd-runtime
   :socket-path socket-path
   :log-root (uiop:ensure-directory-pathname log-root)
   :host-network host-network
   :dns-servers dns-servers
   :dns-searches dns-searches
   :dns-options dns-options))

(defun call-containerd-runtime (thunk)
  (handler-case
      (funcall thunk)
    (runtime-error (condition)
      (error condition))
    (error (condition)
      (error 'runtime-error :message (princ-to-string condition)))))

(defun containerd-ownership-labels (uid)
  (list (cons +gr8s-managed-label+ "true")
        (cons +gr8s-uid-label+ uid)))

(defun containerd-owned-sandbox (runtime uid)
  (let ((sandboxes (cri-list-pod-sandboxes (containerd-runtime-socket-path runtime)
                                          :labels (containerd-ownership-labels uid))))
    (or (find gr8s.cri.v1::+podsandboxstate-sandbox_ready+ sandboxes :key #'cri-pod-sandbox-info-state)
        (first sandboxes))))

(defun containerd-containers (runtime sandbox)
  (cri-list-containers
   (containerd-runtime-socket-path runtime)
   :sandbox-id (cri-pod-sandbox-info-id sandbox)
   :labels (list (cons +gr8s-managed-label+ "true"))))

(defun containerd-pod-log-directory (runtime uid)
  (merge-pathnames (format nil "~A/" uid)
                   (containerd-runtime-log-root runtime)))

(defun containerd-phase (runtime containers &optional details)
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
      ((= (cri-container-info-state info) gr8s.cri.v1::+containerstate-container_exited+)
       (let ((terminated (core-object "exitCode" (cri-container-info-exit-code info)
                                      "containerID" id)))
         (when started (setf (gethash "startedAt" terminated) started))
         (when finished (setf (gethash "finishedAt" terminated) finished))
         (when (cri-container-info-reason info)
           (setf (gethash "reason" terminated) (cri-container-info-reason info)))
         (when (cri-container-info-message info)
           (setf (gethash "message" terminated) (cri-container-info-message info)))
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
            (statuses (container-lifecycle-statuses details (or history state))))
       (when (or sandbox (and checkpoint-owned-p (plusp (length statuses))))
         (apply-container-probe-observation runtime
          (apply-init-container-observation
          (make-runtime-pod
          :uid uid
          :resource-version
          (or (and sandbox (cdr (assoc +gr8s-resource-version-label+
                          (cri-pod-sandbox-info-labels sandbox)
                          :test #'string=)))
              (gethash "resourceVersion" state ""))
          :spec-fingerprint (or (and sandbox (cdr (assoc +gr8s-spec-fingerprint-label+ (cri-pod-sandbox-info-labels sandbox) :test #'string=)))
                                (gethash "specFingerprint" state))
          :pod-ip (if sandbox (cri-pod-sandbox-ip (containerd-runtime-socket-path runtime) (cri-pod-sandbox-info-id sandbox)) "")
          :phase (container-lifecycle-phase statuses (and sandbox (= gr8s.cri.v1::+podsandboxstate-sandbox_ready+
                                                                         (cri-pod-sandbox-info-state sandbox))))
          :container-details details
          :status (core-object "containerStatuses" statuses)) state)))))))

(defmethod runtime-delete ((runtime containerd-runtime) uid)
  (cancel-runtime-pod-deletion (containerd-runtime-deletions runtime) uid)
  (containerd-delete-uid runtime uid (funcall *pod-deletion-clock*)))

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
     (unless preserve-lifecycle (forget-container-lifecycle-state runtime uid))
     nil)))

(defmethod runtime-terminate-pod ((runtime containerd-runtime) pod deadline)
  "Carry out one cancellable native Pod shutdown job."
  (containerd-delete-uid runtime (pod-uid pod) deadline))

(defmethod runtime-delete-pod ((runtime containerd-runtime) pod)
  "Poll the native Pod shutdown job without holding reconciliation until exit."
  (stop-container-probes runtime (pod-uid pod))
  (poll-runtime-pod-deletion (containerd-runtime-deletions runtime) runtime pod))

(defmethod stop-runtime-deletions ((runtime containerd-runtime))
  "Join native deletion jobs before the containerd service exits."
  (stop-container-probes runtime)
  (stop-runtime-deletion-controller (containerd-runtime-deletions runtime)))

(defun containerd-create-container (runtime pod sandbox-id sandbox-config spec &key (attempt 0))
  (let ((socket (containerd-runtime-socket-path runtime)))
    (let ((policy (gethash "imagePullPolicy" (pod-runtime-container-object pod spec)
                           (if (or (uiop:string-suffix-p (container-spec-image spec) ":latest")
                                   (not (find #\: (car (last (uiop:split-string (container-spec-image spec) :separator '(#\/)))))))
                               "Always" "IfNotPresent"))))
      (when (or (equal policy "Always")
                (and (equal policy "IfNotPresent") (not (cri-image-present-p socket (container-spec-image spec)))))
        (cri-pull-image socket (container-spec-image spec))))
    (let ((container-id
            (cri-create-container
             socket sandbox-id sandbox-config
             :name (container-spec-name spec)
             :image (container-spec-image spec)
             :command (coerce (container-spec-command spec) 'list)
             :args (coerce (container-spec-args spec) 'list)
             :env (containerd-pod-environment runtime pod spec sandbox-id)
             :mounts (containerd-pod-mounts runtime pod spec)
             :security-context (containerd-pod-security-context pod spec)
             :working-directory (gethash "workingDir" (pod-runtime-container-object pod spec))
             :uid (pod-uid pod)
             :attempt attempt
             :log-path (container-attempt-log-path (container-spec-name spec) attempt))))
      (cri-start-container socket container-id))))

(defmethod runtime-ensure ((runtime containerd-runtime) pod)
  "Converge native containers without destroying an unchanged sandbox or healthy siblings."
  (call-containerd-runtime (lambda () (reconcile-container-probes runtime pod (converge-containerd-containers runtime pod)))))

(defmethod runtime-reconcile-containers ((runtime containerd-runtime) pod observed)
  "Retry only eligible native containers, even while a sibling keeps the Pod Running."
  (checkpoint-container-lifecycle-observation runtime (pod-uid pod) observed)
  (setf observed (reconcile-container-probes runtime pod observed))
  (if (or (native-container-progress-required-p pod observed)
          (container-probe-restart-required-p runtime pod observed))
      (runtime-ensure runtime pod)
      observed))

(defmethod runtime-logs
    ((runtime containerd-runtime) uid container-name &key tail)
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
       (let* ((path (merge-pathnames
                     (container-attempt-log-path container-name attempt)
                     (containerd-pod-log-directory runtime uid))))
         (if (probe-file path) (uiop:read-file-string path) ""))))))

(defun containerd-owned-container (runtime uid container-name)
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
