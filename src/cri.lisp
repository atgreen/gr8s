(in-package #:gr8s)

(defstruct cri-version-info
  version
  runtime-name
  runtime-version
  runtime-api-version)

(defstruct cri-container-info
  id
  name
  (attempt 0)
  image
  image-ref
  (started-at 0)
  (finished-at 0)
  state
  exit-code
  reason
  message
  labels
  log-path)

(defstruct cri-pod-sandbox-info
  id
  labels)

(defstruct cri-container-summary
  id
  state
  labels)

(defun ensure-cri-status (operation status)
  (unless (= status ag-grpc:+grpc-status-ok+)
    (error 'runtime-error
           :message
           (format nil "CRI ~A failed with gRPC status ~D (~A)"
                   operation status (ag-grpc:grpc-status-name status)))))

(defun make-cri-exec-request
    (container-id command &key stdin stdout stderr tty)
  (make-instance 'gr8s.cri.v1::exec-request
                 :container-id container-id
                 :cmd command
                 :stdin stdin
                 :stdout stdout
                 :stderr stderr
                 :tty tty))

(defun make-cri-exec-sync-request (container-id command timeout)
  (make-instance 'gr8s.cri.v1::exec-sync-request
                 :container-id container-id
                 :cmd command
                 :timeout timeout))

(defun cri-exec-url
    (socket-path container-id command
     &key stdin stdout stderr tty (timeout 30))
  "Create a one-time CRI streaming URL for a command in CONTAINER-ID."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-exec
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-cri-exec-request
               container-id command
               :stdin stdin :stdout stdout :stderr stderr :tty tty)
              :timeout timeout)
           (ensure-cri-status "Exec" status)
           (gr8s.cri.v1::url response))
      (ag-grpc:channel-close channel))))

(defun cri-exec-sync
    (socket-path container-id command &key (timeout 30))
  "Run COMMAND synchronously in CONTAINER-ID and return captured output."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-exec-sync
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-cri-exec-sync-request container-id command timeout)
              :timeout timeout)
           (ensure-cri-status "ExecSync" status)
           (make-runtime-exec-result
            :stdout (gr8s.cri.v1::stdout response)
            :stderr (gr8s.cri.v1::stderr response)
            :exit-code (gr8s.cri.v1::exit-code response)))
      (ag-grpc:channel-close channel))))

(defun cri-runtime-version (socket-path &key (timeout 10))
  "Return the CRI version advertised on containerd's Unix socket."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-version
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::version-request
                             :version "0.1.0")
              :timeout timeout)
           (ensure-cri-status "Version" status)
           (make-cri-version-info
            :version (gr8s.cri.v1::version response)
            :runtime-name (gr8s.cri.v1::runtime-name response)
            :runtime-version (gr8s.cri.v1::runtime-version response)
            :runtime-api-version
            (gr8s.cri.v1::runtime-api-version response)))
      (ag-grpc:channel-close channel))))

(defun make-cri-pod-sandbox-config
    (name uid namespace attempt log-directory host-network
     &key resource-version spec-fingerprint dns-servers dns-searches dns-options privileged)
  (let ((metadata
          (make-instance 'gr8s.cri.v1::pod-sandbox-metadata
                         :name name
                         :uid uid
                         :namespace namespace
                         :attempt attempt)))
    (make-instance
     'gr8s.cri.v1::pod-sandbox-config
     :metadata metadata
     :hostname (if host-network "" name)
     :log-directory log-directory
     :dns-config
     (when dns-servers
       (make-instance 'gr8s.cri.v1::dns-config
                      :servers dns-servers
                      :searches dns-searches
                      :options dns-options))
     :labels (append
              (list (cons +gr8s-managed-label+ "true")
                    (cons +gr8s-uid-label+ uid))
              (when resource-version
                (list (cons +gr8s-resource-version-label+
                            resource-version)))
              (when spec-fingerprint (list (cons +gr8s-spec-fingerprint-label+ spec-fingerprint))))
     :linux
     (make-instance
      'gr8s.cri.v1::linux-pod-sandbox-config
      :security-context
      (make-instance
       'gr8s.cri.v1::linux-sandbox-security-context
       :privileged (not (null privileged))
       :namespace-options
       (make-instance
        'gr8s.cri.v1::namespace-option
        :network (if host-network
                     gr8s.cri.v1::+namespacemode-node+
                     gr8s.cri.v1::+namespacemode-pod+)))))))

(defun cri-run-pod-sandbox
    (socket-path &key name uid (namespace "default") (attempt 0)
                   log-directory host-network resource-version spec-fingerprint
                   dns-servers dns-searches dns-options privileged (timeout 120))
  "Create and start a CRI pod sandbox, returning its runtime ID."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (let* ((stub (gr8s.cri.v1::make-runtime-service-stub channel))
                (config
                  (make-cri-pod-sandbox-config
                   name uid namespace attempt log-directory host-network
                   :resource-version resource-version :spec-fingerprint spec-fingerprint
                   :dns-servers dns-servers
                   :dns-searches dns-searches
                   :dns-options dns-options :privileged privileged)))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-run-pod-sandbox
                stub
                (make-instance 'gr8s.cri.v1::run-pod-sandbox-request
                               :config config)
                :timeout timeout)
             (ensure-cri-status "RunPodSandbox" status)
             (gr8s.cri.v1::pod-sandbox-id response)))
      (ag-grpc:channel-close channel))))

(defun cri-pod-sandbox-ip-from-response (response)
  (let* ((sandbox (gr8s.cri.v1::status response))
         (network (and sandbox (gr8s.cri.v1::network sandbox))))
    (if network (gr8s.cri.v1::ip network) "")))

(defun cri-pod-sandbox-ip (socket-path sandbox-id &key (timeout 5))
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-pod-sandbox-status
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::pod-sandbox-status-request
                             :pod-sandbox-id sandbox-id) :timeout timeout)
           (ensure-cri-status "PodSandboxStatus" status)
           (cri-pod-sandbox-ip-from-response response))
      (ag-grpc:channel-close channel))))

(defun cri-delete-pod-sandbox (socket-path sandbox-id &key (timeout 30))
  "Stop and remove SANDBOX-ID through the CRI runtime service."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (let ((stub (gr8s.cri.v1::make-runtime-service-stub channel)))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-stop-pod-sandbox
                stub
                (make-instance 'gr8s.cri.v1::stop-pod-sandbox-request
                               :pod-sandbox-id sandbox-id)
                :timeout timeout)
             (declare (ignore response))
             (ensure-cri-status "StopPodSandbox" status))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-remove-pod-sandbox
                stub
                (make-instance 'gr8s.cri.v1::remove-pod-sandbox-request
                               :pod-sandbox-id sandbox-id)
                :timeout timeout)
             (declare (ignore response))
             (ensure-cri-status "RemovePodSandbox" status)))
      (ag-grpc:channel-close channel))))

(defun cri-pull-image (socket-path image &key timeout)
  "Pull IMAGE without a default operation deadline; callers may supply TIMEOUT."
  ;; Download and extraction can exceed an ordinary CRI request's deadline.
  ;; Match Kubernetes' remote image client: keep the cancellable call context,
  ;; but do not abort an active pull merely because two minutes have elapsed.
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::image-service-pull-image
              (gr8s.cri.v1::make-image-service-stub channel)
              (make-instance
               'gr8s.cri.v1::pull-image-request
               :image (make-instance 'gr8s.cri.v1::image-spec :image image))
              :timeout timeout)
           (ensure-cri-status "PullImage" status)
           (gr8s.cri.v1::image-ref response))
      (ag-grpc:channel-close channel))))

(defun cri-create-container
    (socket-path sandbox-id sandbox-config
     &key name image command args env uid mounts security-context working-directory
          (attempt 0) log-path (timeout 120))
  "Create a container in SANDBOX-ID and return its runtime ID."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-create-container
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance
               'gr8s.cri.v1::create-container-request
               :pod-sandbox-id sandbox-id
               :sandbox-config sandbox-config
               :config
               (make-instance
                'gr8s.cri.v1::container-config
                :metadata
                (make-instance 'gr8s.cri.v1::container-metadata
                               :name name
                               :attempt attempt)
                :image (make-instance 'gr8s.cri.v1::image-spec :image image)
                :command command
                :args args
                :working-dir (or working-directory "")
                :mounts mounts
                :linux (when security-context
                         (make-instance 'gr8s.cri.v1::linux-container-config :security-context security-context))
                :envs (loop for (key . value) in env
                            collect (make-instance 'gr8s.cri.v1::key-value
                                                   :key key :value value))
                :log-path log-path
                :labels (append
                         (list (cons +gr8s-managed-label+ "true")
                               (cons +gr8s-container-label+ name))
                         (when uid
                           (list (cons +gr8s-uid-label+ uid))))))
              :timeout timeout)
           (ensure-cri-status "CreateContainer" status)
           (gr8s.cri.v1::container-id response))
      (ag-grpc:channel-close channel))))

(defun cri-list-pod-sandboxes (socket-path &key labels (timeout 30))
  "Return CRI pod sandboxes matching LABELS."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-list-pod-sandbox
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance
               'gr8s.cri.v1::list-pod-sandbox-request
               :filter (make-instance 'gr8s.cri.v1::pod-sandbox-filter
                                      :label-selector labels))
              :timeout timeout)
           (ensure-cri-status "ListPodSandbox" status)
           (loop for sandbox in (gr8s.cri.v1::items response)
                 collect
                 (make-cri-pod-sandbox-info
                  :id (gr8s.cri.v1::id sandbox)
                  :labels (gr8s.cri.v1::labels sandbox))))
      (ag-grpc:channel-close channel))))

(defun cri-list-containers
    (socket-path &key sandbox-id labels (timeout 30))
  "Return CRI containers in SANDBOX-ID matching LABELS."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-list-containers
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance
               'gr8s.cri.v1::list-containers-request
               :filter (make-instance 'gr8s.cri.v1::container-filter
                                      :pod-sandbox-id (or sandbox-id "")
                                      :label-selector labels))
              :timeout timeout)
           (ensure-cri-status "ListContainers" status)
           (loop for container in (gr8s.cri.v1::containers response)
                 collect
                 (make-cri-container-summary
                  :id (gr8s.cri.v1::id container)
                  :state (gr8s.cri.v1::state container)
                  :labels (gr8s.cri.v1::labels container))))
      (ag-grpc:channel-close channel))))

(defun cri-start-container (socket-path container-id &key (timeout 30))
  "Start CONTAINER-ID through the CRI runtime service."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-start-container
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::start-container-request
                             :container-id container-id)
              :timeout timeout)
           (declare (ignore response))
           (ensure-cri-status "StartContainer" status))
      (ag-grpc:channel-close channel))))

(defun cri-container-status (socket-path container-id &key (timeout 30))
  "Return the current CRI status for CONTAINER-ID."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-container-status
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::container-status-request
                             :container-id container-id)
              :timeout timeout)
           (ensure-cri-status "ContainerStatus" status)
           (let ((container-status (gr8s.cri.v1::status response)))
             (make-cri-container-info
              :id (gr8s.cri.v1::id container-status)
              :name (when (gr8s.cri.v1::metadata container-status)
                      (gr8s.cri.v1::name (gr8s.cri.v1::metadata container-status)))
              :attempt (if (gr8s.cri.v1::metadata container-status)
                           (gr8s.cri.v1::attempt (gr8s.cri.v1::metadata container-status)) 0)
              :image (when (gr8s.cri.v1::image container-status)
                       (gr8s.cri.v1::image (gr8s.cri.v1::image container-status)))
              :image-ref (gr8s.cri.v1::image-ref container-status)
              :started-at (gr8s.cri.v1::started-at container-status)
              :finished-at (gr8s.cri.v1::finished-at container-status)
              :state (gr8s.cri.v1::state container-status)
              :exit-code (gr8s.cri.v1::exit-code container-status)
              :reason (gr8s.cri.v1::reason container-status)
              :message (gr8s.cri.v1::message container-status)
              :labels (gr8s.cri.v1::labels container-status)
              :log-path (gr8s.cri.v1::log-path container-status))))
      (ag-grpc:channel-close channel))))

(defun cri-delete-container (socket-path container-id &key (timeout 30))
  "Stop and remove CONTAINER-ID through the CRI runtime service."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (let ((stub (gr8s.cri.v1::make-runtime-service-stub channel)))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-stop-container
                stub
                (make-instance 'gr8s.cri.v1::stop-container-request
                               :container-id container-id
                               :timeout 1)
                :timeout timeout)
             (declare (ignore response))
             (ensure-cri-status "StopContainer" status))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-remove-container
                stub
                (make-instance 'gr8s.cri.v1::remove-container-request
                               :container-id container-id)
                :timeout timeout)
             (declare (ignore response))
             (ensure-cri-status "RemoveContainer" status)))
      (ag-grpc:channel-close channel))))

(defun cri-image-present-p (socket-path image &key (timeout 30))
  "Query the CRI image service without contacting a registry."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::image-service-image-status
              (gr8s.cri.v1::make-image-service-stub channel)
              (make-instance 'gr8s.cri.v1::image-status-request
                             :image (make-instance 'gr8s.cri.v1::image-spec :image image))
              :timeout timeout)
           (ensure-cri-status "ImageStatus" status)
           (not (null (gr8s.cri.v1::image response))))
      (ag-grpc:channel-close channel))))
