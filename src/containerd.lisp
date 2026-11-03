(in-package #:gr8s)

(defstruct (containerd-runtime (:constructor %make-containerd-runtime))
  socket-path
  log-root
  host-network
  dns-servers
  dns-searches
  dns-options
  resource-store)

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
  (first
   (cri-list-pod-sandboxes
    (containerd-runtime-socket-path runtime)
    :labels (containerd-ownership-labels uid))))

(defun containerd-containers (runtime sandbox)
  (cri-list-containers
   (containerd-runtime-socket-path runtime)
   :sandbox-id (cri-pod-sandbox-info-id sandbox)
   :labels (list (cons +gr8s-managed-label+ "true"))))

(defun containerd-pod-log-directory (runtime uid)
  (merge-pathnames (format nil "~A/" uid)
                   (containerd-runtime-log-root runtime)))

(defun containerd-phase (runtime containers)
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
                        (cri-container-status
                         (containerd-runtime-socket-path runtime)
                         (cri-container-summary-id container))))))
               containers)
         "Failed"
         "Succeeded"))
    (t "Pending")))

(defmethod runtime-observe ((runtime containerd-runtime) uid)
  (call-containerd-runtime
   (lambda ()
     (let ((sandbox (containerd-owned-sandbox runtime uid)))
       (when sandbox
         (make-runtime-pod
          :uid uid
          :resource-version
          (or (cdr (assoc +gr8s-resource-version-label+
                          (cri-pod-sandbox-info-labels sandbox)
                          :test #'string=))
              "")
          :spec-fingerprint (cdr (assoc +gr8s-spec-fingerprint-label+ (cri-pod-sandbox-info-labels sandbox) :test #'string=))
          :pod-ip (cri-pod-sandbox-ip (containerd-runtime-socket-path runtime)
                                      (cri-pod-sandbox-info-id sandbox))
          :phase (containerd-phase
                  runtime (containerd-containers runtime sandbox))))))))

(defmethod runtime-delete ((runtime containerd-runtime) uid)
  (call-containerd-runtime
   (lambda ()
     (let ((sandbox (containerd-owned-sandbox runtime uid)))
       (when sandbox
         (dolist (container (containerd-containers runtime sandbox))
           (cri-delete-container
            (containerd-runtime-socket-path runtime)
            (cri-container-summary-id container)))
         (cri-delete-pod-sandbox
          (containerd-runtime-socket-path runtime)
          (cri-pod-sandbox-info-id sandbox))))
     nil)))

(defun containerd-create-container (runtime pod sandbox-id sandbox-config spec)
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
             :log-path (format nil "~A.log" (container-spec-name spec)))))
      (cri-start-container socket container-id))))

(defmethod runtime-ensure ((runtime containerd-runtime) pod)
  (call-containerd-runtime
   (lambda ()
     (runtime-delete runtime (pod-uid pod))
     (let* ((log-directory
              (containerd-pod-log-directory runtime (pod-uid pod)))
            (sandbox-config
              (make-cri-pod-sandbox-config
               (pod-name pod) (pod-uid pod) (pod-namespace pod) 0
               (namestring log-directory)
               (containerd-runtime-host-network runtime)
               :resource-version (pod-resource-version pod)
               :spec-fingerprint (pod-runtime-spec-fingerprint pod)
               :privileged (pod-requests-privileged-container-p pod)
               :dns-servers (containerd-runtime-dns-servers runtime)
               :dns-searches (when (containerd-runtime-dns-searches runtime)
                               (cons (format nil "~A.svc.cluster.local" (pod-namespace pod))
                                     (cdr (containerd-runtime-dns-searches runtime))))
               :dns-options (containerd-runtime-dns-options runtime)))
            (sandbox-id nil))
       (ensure-directories-exist log-directory)
       (handler-case
           (progn
             (setf sandbox-id
                   (cri-run-pod-sandbox
                    (containerd-runtime-socket-path runtime)
                    :name (pod-name pod)
                    :uid (pod-uid pod)
                    :namespace (pod-namespace pod)
                    :log-directory (namestring log-directory)
                    :host-network (containerd-runtime-host-network runtime)
                    :resource-version (pod-resource-version pod)
                    :spec-fingerprint (pod-runtime-spec-fingerprint pod)
                    :privileged (pod-requests-privileged-container-p pod)
                    :dns-servers (containerd-runtime-dns-servers runtime)
                    :dns-searches (when (containerd-runtime-dns-searches runtime)
                               (cons (format nil "~A.svc.cluster.local" (pod-namespace pod))
                                     (cdr (containerd-runtime-dns-searches runtime))))
                    :dns-options (containerd-runtime-dns-options runtime)))
             (loop for spec across (pod-containers pod)
                   do (containerd-create-container
                       runtime pod sandbox-id sandbox-config spec))
             (or (runtime-observe runtime (pod-uid pod))
                 (make-runtime-pod
                  :uid (pod-uid pod)
                  :resource-version (pod-resource-version pod)
                  :phase "Pending")))
         (error (condition)
           (when sandbox-id
             (ignore-errors (runtime-delete runtime (pod-uid pod))))
           (error condition)))))))

(defmethod runtime-logs
    ((runtime containerd-runtime) uid container-name &key tail)
  (declare (ignore tail))
  (call-containerd-runtime
   (lambda ()
     (let* ((sandbox (containerd-owned-sandbox runtime uid))
            (container
              (and sandbox
                   (find container-name
                         (containerd-containers runtime sandbox)
                         :key (lambda (item)
                                (cdr (assoc +gr8s-container-label+
                                            (cri-container-summary-labels item)
                                            :test #'string=)))
                         :test #'string=))))
       (unless container
         (error 'runtime-error
                :message (format nil "Container ~A is not owned by gr8s"
                                 container-name)))
       (let ((path (merge-pathnames
                    (format nil "~A.log" container-name)
                    (containerd-pod-log-directory runtime uid))))
         (if (probe-file path)
             (uiop:read-file-string path)
             ""))))))

(defun containerd-owned-container (runtime uid container-name)
  (let ((sandbox (containerd-owned-sandbox runtime uid)))
    (and sandbox
         (find container-name
               (containerd-containers runtime sandbox)
               :key (lambda (item)
                      (cdr (assoc +gr8s-container-label+
                                  (cri-container-summary-labels item)
                                  :test #'string=)))
               :test #'string=))))

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
