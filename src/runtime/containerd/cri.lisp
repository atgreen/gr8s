;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Perform native CRI requests with exact container identities, typed wire
;;;; observations, command budgets and separately bounded transport cleanup.

(in-package #:gr8s.runtime.containerd)

(defun make-unix-grpc-channel (&rest arguments)
  "Open a Unix gRPC channel through gr8s's transport integration."
  (apply #'gr8s::make-unix-grpc-channel arguments))

(defun register-runtime-deletion-cancel (function)
  "Register FUNCTION with the active runtime deletion operation, when any."
  (gr8s::register-runtime-deletion-cancel function))

(defun cri-json-object (&rest pairs)
  "Return an EQUAL hash table populated by alternating key and value PAIRS."
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr
          do (setf (gethash key object) value))
    object))

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
  labels
  (state gr8s.cri.v1::+podsandboxstate-sandbox_ready+))

(defstruct cri-container-summary
  id
  state
  labels)

(defun cri-protobuf-state (message)
  "Translate a decoded CRI enum state into its proto3 numeric representation."
  ;; The pinned generator initializes an omitted enum to NIL. Proto3 defines
  ;; that encoding as numeric zero (sandbox Ready or container Created).
  (or (gr8s.cri.v1::state message) 0))

(defun ensure-cri-status (operation status)
  "Reject unsuccessful CRI operations with their actual gRPC status."
  (unless (= status ag-grpc:+grpc-status-ok+)
    (error 'runtime-error
           :message
           (format nil "CRI ~A failed with gRPC status ~D (~A)"
                   operation status (ag-grpc:grpc-status-name status)))))

(defun ensure-cri-deletion-status (operation status)
  "Accept idempotent shutdown/removal of containers already absent from the runtime."
  (unless (= status ag-grpc:+grpc-status-not-found+)
    (ensure-cri-status operation status)))

(defun make-cri-exec-request
    (container-id command &key stdin stdout stderr tty)
  "Build an exact-container streaming Exec request with the requested channels."
  (make-instance 'gr8s.cri.v1::exec-request
                 :container-id container-id
                 :cmd command
                 :stdin stdin
                 :stdout stdout
                 :stderr stderr
                 :tty tty))

(defun make-cri-exec-sync-request (container-id command timeout)
  "Keep the declared command timeout in the CRI request independently of RPC overhead."
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

(defun cri-attach-url (socket-path container-id &key stdin stdout stderr tty (timeout 30))
  "Create a one-time CRI streaming URL attached to CONTAINER-ID's own process."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-attach
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::attach-request
                             :container-id container-id
                             :stdin stdin :stdout stdout :stderr stderr :tty tty)
              :timeout timeout)
           (ensure-cri-status "Attach" status)
           (gr8s.cri.v1::url response))
      (ag-grpc:channel-close channel))))

(defun cri-port-forward-url (socket-path sandbox-id port &key (timeout 30))
  "Create a one-time CRI streaming URL reaching PORT in SANDBOX-ID's network namespace."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-port-forward
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::port-forward-request
                             :pod-sandbox-id sandbox-id :port (list port))
              :timeout timeout)
           (ensure-cri-status "PortForward" status)
           (gr8s.cri.v1::url response))
      (ag-grpc:channel-close channel))))

(defparameter *cri-runtime-request-timeout* 120
  "Pinned kubelet CRI request overhead/cleanup budget, separate from command duration.")

(define-condition cri-command-timeout (runtime-error) ()
  (:documentation "A server-reported CRI ExecSync deadline, distinct from local transport expiry."))

(defun cri-server-command-timeout-p (condition)
  "Require real server grpc-status metadata and no local timeout cause."
  (and (= ag-grpc:+grpc-status-deadline-exceeded+ (ag-grpc::grpc-status-error-code condition))
       (null (ag-grpc::grpc-status-error-cause condition))
       (some (lambda (headers)
               (equal "4" (cdr (assoc "grpc-status" headers :test #'string-equal))))
             (list (ag-grpc::grpc-status-error-headers condition) (ag-grpc::grpc-status-error-trailers condition)))))

(defun cri-exec-sync
    (socket-path container-id command &key (timeout 30))
  "Keep the command timeout on the wire and allow kubelet's separate CRI cleanup budget."
  (let* ((client-timeout (when (plusp timeout) (+ *cri-runtime-request-timeout* timeout)))
         (channel (make-unix-grpc-channel socket-path :timeout client-timeout)))
    (unwind-protect
         (handler-case
             (multiple-value-bind (response status)
                 (gr8s.cri.v1::runtime-service-exec-sync
                  (gr8s.cri.v1::make-runtime-service-stub channel)
                  (make-cri-exec-sync-request container-id command timeout)
                  :timeout client-timeout)
               (ensure-cri-status "ExecSync" status)
               (make-runtime-exec-result
                :stdout (gr8s.cri.v1::stdout response)
                :stderr (gr8s.cri.v1::stderr response)
                :exit-code (gr8s.cri.v1::exit-code response)))
           (ag-grpc::grpc-status-error (condition)
             (if (cri-server-command-timeout-p condition)
                 (error 'cri-command-timeout :message (princ-to-string condition))
                 (error condition))))
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
     &key resource-version spec-fingerprint dns-servers dns-searches dns-options privileged hostname security
          annotations sysctls (pid-mode gr8s.cri.v1::+namespacemode-container+) host-ipc userns)
  "Build sandbox identity, ownership labels and annotations, hostname, and
   native network/security configuration."
  (let ((metadata
          (make-instance 'gr8s.cri.v1::pod-sandbox-metadata
                         :name name
                         :uid uid
                         :namespace namespace
                         :attempt attempt)))
    (make-instance
     'gr8s.cri.v1::pod-sandbox-config
     :metadata metadata
     :hostname (if host-network ""
                   (let ((selected (or hostname name)))
                     (if (> (length selected) 63)
                         (string-right-trim "-." (subseq selected 0 63)) selected)))
     :log-directory log-directory
     :annotations annotations
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
              (when spec-fingerprint (list (cons +gr8s-spec-fingerprint-label+ spec-fingerprint)))
              (when host-network (list (cons +gr8s-host-network-label+ "true"))))
     :linux
     (make-instance
      'gr8s.cri.v1::linux-pod-sandbox-config
      :sysctls sysctls
      :security-context
      (apply
       #'make-instance
       'gr8s.cri.v1::linux-sandbox-security-context
       :privileged (not (null privileged))
       :namespace-options
       (make-instance
        'gr8s.cri.v1::namespace-option
        :network (if host-network
                     gr8s.cri.v1::+namespacemode-node+
                     gr8s.cri.v1::+namespacemode-pod+)
        :pid pid-mode
        :ipc (if host-ipc gr8s.cri.v1::+namespacemode-node+ gr8s.cri.v1::+namespacemode-pod+)
        :userns-options userns)
       security)))))

(defun cri-run-pod-sandbox
    (socket-path &key name uid (namespace "default") (attempt 0)
                   log-directory host-network resource-version spec-fingerprint
                   dns-servers dns-searches dns-options privileged hostname security runtime-handler
                   annotations sysctls (pid-mode gr8s.cri.v1::+namespacemode-container+)
                   host-ipc userns (timeout 120))
  "Create and start a CRI pod sandbox under RUNTIME-HANDLER, returning its runtime ID."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (let* ((stub (gr8s.cri.v1::make-runtime-service-stub channel))
                (config
                  (make-cri-pod-sandbox-config
                   name uid namespace attempt log-directory host-network
                   :resource-version resource-version :spec-fingerprint spec-fingerprint
                   :dns-servers dns-servers
                   :dns-searches dns-searches
                   :dns-options dns-options :privileged privileged :hostname hostname
                   :security security :annotations annotations :sysctls sysctls
                   :pid-mode pid-mode :host-ipc host-ipc :userns userns)))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-run-pod-sandbox
                stub
                (make-instance 'gr8s.cri.v1::run-pod-sandbox-request
                               :config config :runtime-handler (or runtime-handler ""))
                :timeout timeout)
             (ensure-cri-status "RunPodSandbox" status)
             (gr8s.cri.v1::pod-sandbox-id response)))
      (ag-grpc:channel-close channel))))

(defun cri-pod-sandbox-ip-from-response (response)
  "Read the real CRI network address, leaving absent assignments empty."
  (let* ((sandbox (gr8s.cri.v1::status response))
         (network (and sandbox (gr8s.cri.v1::network sandbox))))
    (if network (gr8s.cri.v1::ip network) "")))

(defun cri-pod-sandbox-ip (socket-path sandbox-id &key (timeout 5))
  "Fetch one native sandbox address within the requested observation budget."
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
           (register-runtime-deletion-cancel (lambda () (ag-grpc:channel-close channel)))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-stop-pod-sandbox
                stub
                (make-instance 'gr8s.cri.v1::stop-pod-sandbox-request
                               :pod-sandbox-id sandbox-id)
                :timeout timeout)
             (declare (ignore response))
             (ensure-cri-deletion-status "StopPodSandbox" status))
           (register-runtime-deletion-cancel (lambda () (ag-grpc:channel-close channel)))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-remove-pod-sandbox
                stub
                (make-instance 'gr8s.cri.v1::remove-pod-sandbox-request
                               :pod-sandbox-id sandbox-id)
                :timeout timeout)
             (declare (ignore response))
             (ensure-cri-deletion-status "RemovePodSandbox" status)))
      (ag-grpc:channel-close channel))))

(defun cri-pull-image (socket-path image &key timeout auth)
  "Pull IMAGE without a default operation deadline; callers may supply TIMEOUT.
AUTH is a (username . password) credential for the registry."
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
               :image (make-instance 'gr8s.cri.v1::image-spec :image image)
               :auth (when auth
                       (make-instance 'gr8s.cri.v1::auth-config :username (car auth) :password (cdr auth))))
              :timeout timeout)
           (ensure-cri-status "PullImage" status)
           (gr8s.cri.v1::image-ref response))
      (ag-grpc:channel-close channel))))

(defun make-cri-container-config
    (&key name image command args env uid mounts security-context resources working-directory
          stdin stdin-once tty labels cdi-device-ids (attempt 0) log-path)
  "Build the complete CRI config, including DRA-provided CDI device names."
  (make-instance
   'gr8s.cri.v1::container-config
   :metadata (make-instance 'gr8s.cri.v1::container-metadata
                            :name name :attempt attempt)
   :image (make-instance 'gr8s.cri.v1::image-spec :image image)
   :command command
   :args args
   :working-dir (or working-directory "")
   :stdin (not (null stdin)) :stdin-once (not (null stdin-once)) :tty (not (null tty))
   :mounts mounts
   :linux (when (or security-context resources)
            (make-instance 'gr8s.cri.v1::linux-container-config
                           :security-context security-context :resources resources))
   :envs (loop for (key . value) in env
               collect (make-instance 'gr8s.cri.v1::key-value :key key :value value))
   :cdi-devices (mapcar (lambda (device-id)
                          (make-instance 'gr8s.cri.v1::cdi-device :name device-id))
                        cdi-device-ids)
   :log-path log-path
   :labels (append
            (list (cons +gr8s-managed-label+ "true")
                  (cons +gr8s-container-label+ name))
            (when uid (list (cons +gr8s-uid-label+ uid)))
            labels)))

(defun cri-create-container
    (socket-path sandbox-id sandbox-config
     &key name image command args env uid mounts security-context resources working-directory
          stdin stdin-once tty labels cdi-device-ids (attempt 0) log-path (timeout 120))
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
               :config (make-cri-container-config
                        :name name :image image :command command :args args :env env
                        :uid uid :mounts mounts :security-context security-context
                        :resources resources :working-directory working-directory
                        :stdin stdin :stdin-once stdin-once :tty tty :labels labels
                        :cdi-device-ids cdi-device-ids :attempt attempt :log-path log-path))
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
                  :state (cri-protobuf-state sandbox)
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
                  :state (cri-protobuf-state container)
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

(defun cri-container-metrics (socket-path &key (timeout 30))
  "Return every gr8s container's CPU seconds used and working set, by Pod UID and container name."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)) (pods (make-hash-table :test #'equal)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-list-container-stats
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::list-container-stats-request
                             :filter (make-instance 'gr8s.cri.v1::container-stats-filter))
              :timeout timeout)
           (ensure-cri-status "ListContainerStats" status)
           (dolist (stats (gr8s.cri.v1::stats response) pods)
             (let* ((attributes (gr8s.cri.v1::attributes stats))
                    (labels (and attributes (gr8s.cri.v1::labels attributes)))
                    (uid (cdr (assoc +gr8s-uid-label+ labels :test #'string=)))
                    (name (cdr (assoc +gr8s-container-label+ labels :test #'string=)))
                    (cpu (gr8s.cri.v1::cpu stats)) (memory (gr8s.cri.v1::memory stats))
                    (used (and cpu (gr8s.cri.v1::usage-core-nano-seconds cpu)))
                    (working (and memory (gr8s.cri.v1::working-set-bytes memory))))
               (when (and uid name used)
                 (setf (gethash name (or (gethash uid pods) (setf (gethash uid pods) (make-hash-table :test #'equal))))
                       (cri-json-object "cpu" (gr8s.cri.v1::value used)
                                        "memory" (if working
                                                     (gr8s.cri.v1::value working)
                                                     0)))))))
      (ag-grpc:channel-close channel))))

(defun cri-container-writable-bytes (socket-path sandbox-id &key (timeout 30))
  "Return (container-name . writable-layer-bytes) entries for SANDBOX-ID's containers."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-list-container-stats
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::list-container-stats-request
                             :filter (make-instance 'gr8s.cri.v1::container-stats-filter
                                                    :pod-sandbox-id sandbox-id))
              :timeout timeout)
           (ensure-cri-status "ListContainerStats" status)
           (loop for stats in (gr8s.cri.v1::stats response)
                 for attributes = (gr8s.cri.v1::attributes stats)
                 for metadata = (and attributes (gr8s.cri.v1::metadata attributes))
                 for layer = (gr8s.cri.v1::writable-layer stats)
                 for used = (and layer (gr8s.cri.v1::used-bytes layer))
                 when metadata
                   collect (cons (gr8s.cri.v1::name metadata)
                                 (if used (gr8s.cri.v1::value used) 0))))
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
              :state (cri-protobuf-state container-status)
              :exit-code (gr8s.cri.v1::exit-code container-status)
              :reason (gr8s.cri.v1::reason container-status)
              :message (gr8s.cri.v1::message container-status)
              :labels (gr8s.cri.v1::labels container-status)
              :log-path (gr8s.cri.v1::log-path container-status))))
      (ag-grpc:channel-close channel))))

(defun cri-stop-container (socket-path container-id &key (grace-period 0) (timeout (+ grace-period 30)))
  "Stop a container while retaining its real exit status and attempt metadata."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (progn
           (register-runtime-deletion-cancel (lambda () (ag-grpc:channel-close channel)))
           (multiple-value-bind (response status)
             (gr8s.cri.v1::runtime-service-stop-container
              (gr8s.cri.v1::make-runtime-service-stub channel)
              (make-instance 'gr8s.cri.v1::stop-container-request :container-id container-id :timeout grace-period)
              :timeout timeout)
           (declare (ignore response))
           (ensure-cri-deletion-status "StopContainer" status)))
      (ag-grpc:channel-close channel))))

(defparameter *containerd-cri-namespace* "k8s.io"
  "The containerd namespace in which the CRI plugin keeps its containers and tasks.")

(defun cri-running-task-error-p (condition)
  "Return whether CONDITION is RemoveContainer refusing a container whose task CRI calls exited.
containerd's tasks service can create a task and still fail the call, for example
'failed to get task pid: context canceled' when the client abandons StartContainer.
CRI then holds no task handle to clean up: it records the container exited, so
StopContainer does nothing and RemoveContainer fails on the leftover task for good
(podster-uqb.126)."
  (and (typep condition 'ag-grpc::grpc-status-error)
       (eql ag-grpc:+grpc-status-failed-precondition+ (ag-grpc::grpc-status-error-code condition))
       (search "cannot delete running task" (or (ag-grpc::grpc-status-error-message condition) ""))
       t))

(defun containerd-namespace-metadata ()
  "Return call metadata selecting the CRI plugin's containerd namespace."
  (ag-grpc:make-grpc-metadata (list (cons "containerd-namespace" *containerd-cri-namespace*))))

(defun make-containerd-kill-request (container-id)
  "Build a request to SIGKILL every process of CONTAINER-ID's task."
  (make-instance 'gr8s.containerd.tasks.v1::kill-request
                 :container-id container-id :signal 9 :all t))

(defun containerd-status-tolerating-absence (thunk)
  "Call THUNK, treating a task containerd no longer has as already handled."
  (handler-case (funcall thunk)
    (ag-grpc::grpc-status-error (condition)
      (unless (eql ag-grpc:+grpc-status-not-found+ (ag-grpc::grpc-status-error-code condition))
        (error condition)))))

(defun containerd-reap-task (socket-path container-id &key (timeout 30))
  "Kill and delete CONTAINER-ID's task through containerd's own Tasks API.
This is the cleanup CRI's StartContainer does when it holds the task, applied to a
task it lost track of. The CRI container record itself is left for RemoveContainer."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout))
        (metadata (containerd-namespace-metadata)))
    (unwind-protect
         (let ((stub (gr8s.containerd.tasks.v1::make-tasks-stub channel)))
           (register-runtime-deletion-cancel (lambda () (ag-grpc:channel-close channel)))
           (containerd-status-tolerating-absence
            (lambda ()
              (gr8s.containerd.tasks.v1::tasks-kill
               stub (make-containerd-kill-request container-id) :metadata metadata :timeout timeout)))
           ;; Delete refuses a task whose process is still exiting, so wait for it first.
           (handler-case
               (containerd-status-tolerating-absence
                (lambda ()
                  (gr8s.containerd.tasks.v1::tasks-wait
                   stub (make-instance 'gr8s.containerd.tasks.v1::wait-request :container-id container-id)
                   :metadata metadata :timeout (min timeout 10))))
             ;; An unfinished wait leaves Delete to report what is still wrong.
             (ag-grpc::grpc-status-error () nil))
           (containerd-status-tolerating-absence
            (lambda ()
              (gr8s.containerd.tasks.v1::tasks-delete
               stub (make-instance 'gr8s.containerd.tasks.v1::delete-task-request :container-id container-id)
               :metadata metadata :timeout timeout))))
      (ag-grpc:channel-close channel))))

(defun call-reaping-leftover-task (remove reap)
  "Call REMOVE; if a leftover task blocks it, call REAP and then REMOVE once more."
  (handler-case (funcall remove)
    (ag-grpc::grpc-status-error (condition)
      (unless (cri-running-task-error-p condition)
        (error condition))
      (funcall reap)
      (funcall remove))))

(defun cri-delete-container (socket-path container-id &key (grace-period 0)
                                                        (timeout (+ grace-period 30)))
  "Stop and remove CONTAINER-ID through the CRI runtime service.
A task CRI lost track of is killed through containerd so the removal can finish."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (let ((stub (gr8s.cri.v1::make-runtime-service-stub channel)))
           (register-runtime-deletion-cancel (lambda () (ag-grpc:channel-close channel)))
           (multiple-value-bind (response status)
               (gr8s.cri.v1::runtime-service-stop-container
                stub
                (make-instance 'gr8s.cri.v1::stop-container-request
                               :container-id container-id
                               :timeout grace-period)
                :timeout timeout)
             (declare (ignore response))
             (ensure-cri-deletion-status "StopContainer" status))
           ;; Register again to reject a superseded job between Stop and Remove.
           (register-runtime-deletion-cancel (lambda () (ag-grpc:channel-close channel)))
           (call-reaping-leftover-task
            (lambda ()
              (multiple-value-bind (response status)
                  (gr8s.cri.v1::runtime-service-remove-container
                   stub
                   (make-instance 'gr8s.cri.v1::remove-container-request
                                  :container-id container-id)
                   :timeout timeout)
                (declare (ignore response))
                (ensure-cri-deletion-status "RemoveContainer" status)))
            (lambda ()
              (format *error-output* "gr8s reaping container ~A's task CRI no longer tracks~%" container-id)
              (finish-output *error-output*)
              (containerd-reap-task socket-path container-id :timeout timeout))))
      (ag-grpc:channel-close channel))))

(defun cri-local-image (socket-path image timeout)
  "Return IMAGE's CRI record without contacting a registry, or NIL when the node lacks it."
  (let ((channel (make-unix-grpc-channel socket-path :timeout timeout)))
    (unwind-protect
         (multiple-value-bind (response status)
             (gr8s.cri.v1::image-service-image-status
              (gr8s.cri.v1::make-image-service-stub channel)
              (make-instance 'gr8s.cri.v1::image-status-request
                             :image (make-instance 'gr8s.cri.v1::image-spec :image image))
              :timeout timeout)
           (ensure-cri-status "ImageStatus" status)
           (gr8s.cri.v1::image response))
      (ag-grpc:channel-close channel))))

(defun cri-image-present-p (socket-path image &key (timeout 30))
  "Query the CRI image service without contacting a registry."
  (not (null (cri-local-image socket-path image timeout))))

(defun cri-image-id (socket-path image &key (timeout 30))
  "Return the ID of the local image IMAGE currently names, or NIL when the node lacks it."
  (let ((record (cri-local-image socket-path image timeout)))
    (when record (gr8s.cri.v1::id record))))

(defun cri-image-user (socket-path image &key (timeout 30))
  "Return the user a local IMAGE is configured to run as, for verifying
   runAsNonRoot when a Pod sets no explicit runAsUser (as the kubelet does):
   (values UID-or-NIL USERNAME), both NIL/\"\" when the node lacks the image."
  (let ((record (cri-local-image socket-path image timeout)))
    (when record
      (let ((uid (gr8s.cri.v1::uid record)))
        (values (when uid (gr8s.cri.v1::value uid))
                (gr8s.cri.v1::username record))))))
