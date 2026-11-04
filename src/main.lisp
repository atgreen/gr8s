(in-package #:gr8s)

(defvar *shutdown-requested* nil)

(defun default-state-directory ()
  (merge-pathnames
   "gr8s/"
   (uiop:ensure-directory-pathname
    (or (uiop:getenv "XDG_STATE_HOME")
        (merge-pathnames ".local/state/" (user-homedir-pathname))))))

(defun gr8s-root-directory ()
  (uiop:ensure-directory-pathname
   (or (uiop:getenv "GR8S_ROOT")
       (uiop:getcwd))))

(defun default-containerd-executable ()
  (namestring
   (merge-pathnames "build/containerd/bin/containerd"
                    (gr8s-root-directory))))

(defun default-containerd-oci-runtime ()
  (namestring
   (merge-pathnames "build/containerd/bin/runc"
                    (gr8s-root-directory))))

(defun parse-port (value)
  (handler-case
      (let ((port (parse-integer value :junk-allowed nil)))
        (unless (<= 1 port 65535)
          (error "port must be between 1 and 65535"))
        port)
    (error ()
      (error "invalid port: ~A" value))))

(defun option-value (arguments option)
  (unless (rest arguments)
    (error "~A requires a value" option))
  (second arguments))

(defun parse-serve-options (arguments)
  (let ((options (list :command :serve
                       :state-directory (namestring (default-state-directory))
                       :listen "127.0.0.1"
                       :port 8080
                       :node-port 7443
                       :node-listen "127.0.0.1"
                       :node-address nil
                       :node-name "gr8s-local"
                       :disable-agent nil
                       :cluster-pod-cidr +default-cluster-pod-cidr+
                       :node-pod-prefix +default-node-pod-prefix+
                       :runtime "containerd"
                       :containerd-mode "managed"
                       :containerd-executable (default-containerd-executable)
                       :containerd-oci-runtime (default-containerd-oci-runtime)
                       :containerd-socket "/run/containerd/containerd.sock"
                       :containerd-log-root "/var/log/gr8s/pods/"
                       :kubeconfig nil)))
    (loop while arguments
          for option = (first arguments)
          do (if (string= option "--disable-agent")
                 (progn
                   (setf (getf options :disable-agent) t)
                   (setf arguments (rest arguments)))
                 (let ((value (option-value arguments option)))
                   (cond
                     ((string= option "--state-directory")
                      (setf (getf options :state-directory) value))
                     ((string= option "--listen")
                      (setf (getf options :listen) value))
                     ((string= option "--port")
                      (setf (getf options :port) (parse-port value)))
                     ((string= option "--cluster-pod-cidr")
                      (validate-network-cidr value)
                      (setf (getf options :cluster-pod-cidr) value
                            (getf options :cluster-pod-cidr-supplied-p) t))
                     ((string= option "--node-pod-prefix")
                      (let ((prefix (parse-integer value :junk-allowed nil)))
                        (unless (<= 1 prefix 30) (error "node Pod prefix must be 1..30"))
                        (setf (getf options :node-pod-prefix) prefix
                              (getf options :node-pod-prefix-supplied-p) t)))
                     ((string= option "--node-listen")
                      (setf (getf options :node-listen)
                            (format-ipv4-integer (parse-ipv4-integer value))))
                     ((string= option "--node-address")
                      (setf (getf options :node-address)
                            (canonical-node-underlay-address value)))
                     ((string= option "--node-port")
                      (setf (getf options :node-port) (parse-port value)))
                     ((string= option "--node-name")
                      (setf (getf options :node-name)
                            (ensure-valid-node-name value)))
                     ((string= option "--runtime")
                      (unless (member value '("containerd" "podman" "fake")
                                      :test #'string=)
                        (error "runtime must be containerd, podman, or fake"))
                      (setf (getf options :runtime) value))
                     ((string= option "--containerd-socket")
                      (setf (getf options :containerd-socket) value))
                     ((string= option "--containerd-mode")
                      (unless (member value '("managed" "external") :test #'string=)
                        (error "containerd mode must be managed or external"))
                      (setf (getf options :containerd-mode) value))
                     ((string= option "--containerd-executable")
                      (setf (getf options :containerd-executable) value))
                     ((string= option "--containerd-oci-runtime")
                      (setf (getf options :containerd-oci-runtime) value))
                     ((string= option "--containerd-log-root")
                      (setf (getf options :containerd-log-root) value))
                     ((string= option "--kubeconfig")
                      (setf (getf options :kubeconfig) value))
                     (t (error "unknown serve option: ~A" option)))
                   (setf arguments (cddr arguments)))))
    (unless (string= "127.0.0.1" (getf options :listen))
      (error "gr8s v1 only listens on 127.0.0.1"))
    options))

(defun parse-agent-options (arguments)
  (let ((options (list :command :agent
                       :server nil
                       :token nil
                       :ca-pin nil
                       :node-name nil
                       :state-directory nil
                       :runtime "containerd"
                       :containerd-mode "managed"
                       :containerd-executable (default-containerd-executable)
                       :containerd-oci-runtime (default-containerd-oci-runtime)
                       :containerd-socket "/run/containerd/containerd.sock"
                       :containerd-log-root "/var/log/gr8s/pods/")))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--node-address")
                (setf (getf options :node-address) (canonical-node-underlay-address value)))
               ((string= option "--server")
                (setf (getf options :server) value))
               ((string= option "--token")
                (setf (getf options :token) value))
               ((string= option "--ca-pin")
                (setf (getf options :ca-pin) value))
               ((string= option "--node-name")
                (setf (getf options :node-name)
                      (ensure-valid-node-name value)))
               ((string= option "--state-directory")
                (setf (getf options :state-directory) value))
               ((string= option "--runtime")
                (unless (member value '("containerd" "podman" "fake")
                                :test #'string=)
                  (error "runtime must be containerd, podman, or fake"))
                (setf (getf options :runtime) value))
               ((string= option "--containerd-mode")
                (unless (member value '("managed" "external") :test #'string=)
                  (error "containerd mode must be managed or external"))
                (setf (getf options :containerd-mode) value))
               ((string= option "--containerd-executable")
                (setf (getf options :containerd-executable) value))
               ((string= option "--containerd-oci-runtime")
                (setf (getf options :containerd-oci-runtime) value))
               ((string= option "--containerd-socket")
                (setf (getf options :containerd-socket) value))
               ((string= option "--containerd-log-root")
                (setf (getf options :containerd-log-root) value))
               (t (error "unknown agent option: ~A" option)))
             (setf arguments (cddr arguments)))
    (dolist (required '(:server :node-name :state-directory))
      (unless (getf options required)
        (error "agent requires --~(~A~)" required)))
    (let ((directory (uiop:ensure-directory-pathname (getf options :state-directory))))
      (unless (every (lambda (name) (probe-file (merge-pathnames name directory)))
                     '("node.key" "node.crt" "ca.crt"))
        (dolist (required '(:token :ca-pin))
          (unless (getf options required)
            (error "unenrolled agent requires --~(~A~)" required)))))
    options))

(defun parse-join-token-options (arguments)
  (let ((options (list :command :join-token
                       :state-directory (namestring (default-state-directory)))))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--node-name")
                (setf (getf options :node-name) (ensure-valid-node-name value)))
               ((string= option "--state-directory")
                (setf (getf options :state-directory) value))
               (t (error "unknown join-token option: ~A" option)))
             (setf arguments (cddr arguments)))
    (unless (getf options :node-name) (error "join-token requires --node-name"))
    options))

(defun print-node-join-token (options &optional (output *standard-output*))
  (let* ((state (uiop:ensure-directory-pathname (getf options :state-directory)))
         (root (merge-pathnames "pki/" state)))
    ;; The token command must use an existing control plane's CA, never create
    ;; a new trust identity merely because the caller selected the wrong path.
    (unless (and (probe-file (merge-pathnames "pki/cluster-ca.crt" root))
                 (probe-file (merge-pathnames "pki/cluster-ca.key" root)))
      (error "cluster PKI does not exist in the selected control-plane state directory"))
    (let* ((pki (ensure-cluster-pki root))
           (name (getf options :node-name))
           (token (create-join-token pki name)))
      (com.inuoe.jzon:stringify
       (json-object "nodeName" name "token" token
                    "caPin" (cluster-pki-ca-fingerprint pki)) :stream output)
      (terpri output)
      (finish-output output)))
  0)

(defun parse-kubeconfig-options (arguments)
  (let ((options (list :command :kubeconfig
                       :output nil
                       :server "http://127.0.0.1:8080")))
    (loop while arguments
          for option = (first arguments)
          for value = (option-value arguments option)
          do (cond
               ((string= option "--output")
                (setf (getf options :output) value))
               ((string= option "--server")
                (setf (getf options :server) value))
               (t (error "unknown kubeconfig option: ~A" option)))
             (setf arguments (cddr arguments)))
    (unless (getf options :output)
      (error "kubeconfig requires --output"))
    options))

(defun parse-cli-options (arguments)
  (cond
    ((or (null arguments)
         (member (first arguments) '("help" "--help" "-h") :test #'string=))
     (list :command :help))
    ((string= "serve" (first arguments))
     (parse-serve-options (rest arguments)))
    ((string= "agent" (first arguments))
     (parse-agent-options (rest arguments)))
    ((string= "join-token" (first arguments))
     (parse-join-token-options (rest arguments)))
    ((string= "kubeconfig" (first arguments))
     (parse-kubeconfig-options (rest arguments)))
    ((string= "runtime-assets" (first arguments))
     (when (rest arguments)
       (error "runtime-assets takes no arguments"))
     (list :command :runtime-assets))
    (t (error "unknown command: ~A" (first arguments)))))

(defun print-runtime-assets ()
  (if *embedded-runtime-assets*
      (dolist (asset *embedded-runtime-assets*)
        (format t "~A: ~:D bytes~%"
                (runtime-asset-name asset)
                (length (runtime-asset-octets asset))))
      (format t "runtime assets: external~%")))

(defun write-kubeconfig (path server-url)
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :if-exists :supersede
                          :if-does-not-exist :create)
    (format stream
            "apiVersion: v1~%kind: Config~%clusters:~%  - name: gr8s~%    cluster:~%      server: ~A~%contexts:~%  - name: gr8s~%    context:~%      cluster: gr8s~%      namespace: default~%      user: gr8s~%current-context: gr8s~%users:~%  - name: gr8s~%    user: {}~%"
            server-url))
  path)

(defun runtime-from-options (options)
  (cond
    ((string= (getf options :runtime) "containerd")
     (if (string= (getf options :containerd-mode) "managed")
         (let* ((state-directory
                  (uiop:ensure-directory-pathname
                   (getf options :state-directory)))
                (manager
                  (make-managed-containerd
                   :state-directory state-directory
                   :executable (getf options :containerd-executable)
                   :oci-runtime (getf options :containerd-oci-runtime)
                   :runtime-assets *embedded-runtime-assets*
                   :cni-bin-directory
                   (uiop:pathname-directory-pathname
                    (pathname (getf options :containerd-executable))))))
           (values
            (make-containerd-runtime
             :socket-path (managed-containerd-socket-path manager)
             :log-root (getf options :containerd-log-root)
             :host-network nil
             :dns-servers (list +dns-pod-server-address+)
             :dns-searches +dns-pod-searches+
             :dns-options +dns-pod-options+)
            manager))
         (values
          (make-containerd-runtime
           :socket-path (getf options :containerd-socket)
           :log-root (getf options :containerd-log-root)
           :host-network nil
           :dns-servers (list +dns-pod-server-address+)
           :dns-searches +dns-pod-searches+
           :dns-options +dns-pod-options+)
          nil)))
    ((string= (getf options :runtime) "podman")
     (values (make-podman-runtime) nil))
    (t
     (values (make-fake-runtime) nil))))

(defun parse-agent-server (server)
  (let ((separator (position #\: server :from-end t)))
    (unless (and separator (plusp separator) (< separator (1- (length server))))
      (error "agent server must be HOST:PORT"))
    (values (subseq server 0 separator)
            (parse-port (subseq server (1+ separator))))))

(defun agent-state-path (options name)
  (merge-pathnames name
                   (uiop:ensure-directory-pathname
                    (getf options :state-directory))))

(defun agent (options &key control
                            (stop-predicate (lambda () *shutdown-requested*)))
  (multiple-value-bind (host port) (parse-agent-server (getf options :server))
    (let ((node-name (getf options :node-name))
          (private-key (agent-state-path options "node.key"))
          (certificate (agent-state-path options "node.crt"))
          (ca-certificate (agent-state-path options "ca.crt"))
          (identity (agent-state-path options "identity.json"))
          (node-runtime nil))
      (unless (and (probe-file private-key)
                   (probe-file certificate)
                   (probe-file ca-certificate))
        (enroll-node-over-grpc
         host port node-name (getf options :token) (getf options :ca-pin)
         private-key certificate ca-certificate))
      (multiple-value-bind (runtime manager) (runtime-from-options options)
        (setf node-runtime
              (make-node-runtime
               (agent-state-path options "runtime/") runtime manager))
        (unwind-protect
             (progn
               (start-node-runtime node-runtime)
               (run-node-session
                host port node-name identity
                (lambda (snapshot)
                  (reconcile-node-snapshot node-runtime snapshot))
                :snapshot-observer (lambda (snapshot) (receive-node-snapshot-intent node-runtime snapshot))
                :operation-handler
                (lambda (variant payload emit)
                  (dispatch-node-operation node-runtime variant payload emit))
                :status-provider (lambda () (node-runtime-status node-runtime))
                :ca-certificate-path ca-certificate
                :certificate-path certificate :private-key-path private-key
                :underlay-address (getf options :node-address)
                :reconnect-delay 0.1 :control control
                :stop-predicate stop-predicate))
          (stop-node-runtime node-runtime)))))
  0)

(defstruct local-node-agent
  thread
  control)

(defun start-local-node-agent
    (server pki node-name state-directory &optional runtime-options)
  (let* ((directory (uiop:ensure-directory-pathname state-directory))
         (certificate (merge-pathnames "node.crt" directory))
         (token (unless (probe-file certificate)
                  (create-join-token pki node-name)))
         (worker (make-local-node-agent
                  :control (make-node-session-control)))
         (options (or (and runtime-options (copy-list runtime-options))
                      (list :runtime "fake"))))
    (setf (getf options :command) :agent
          (getf options :server)
          (format nil "~A:~D"
                  (let ((host (getf options :node-listen "127.0.0.1")))
                    (if (string= host "0.0.0.0") "127.0.0.1" host))
                  (node-grpc-server-port server))
          (getf options :token) token
          (getf options :ca-pin) (cluster-pki-ca-fingerprint pki)
          (getf options :node-name) node-name
          (getf options :state-directory) (namestring directory))
    (setf (local-node-agent-thread worker)
          (bt:make-thread
           (lambda ()
             (agent options
                    :control (local-node-agent-control worker)))
           :name "gr8s local node agent"))
    worker))

(defun stop-local-node-agent (worker)
  (cancel-node-session (local-node-agent-control worker))
  (let ((thread (local-node-agent-thread worker)))
    (when thread
      (loop repeat 200
            while (bt:thread-alive-p thread)
            do (sleep 0.01))
      (when (bt:thread-alive-p thread)
        (ignore-errors (bt:destroy-thread thread)))
      (ignore-errors (bt:join-thread thread))))
  nil)

(defun request-shutdown (&rest ignored)
  (declare (ignore ignored))
  (setf *shutdown-requested* t))

(defun install-shutdown-handlers ()
  #+sbcl
  (progn
    (sb-sys:enable-interrupt sb-unix:sigint #'request-shutdown)
    (sb-sys:enable-interrupt sb-unix:sigterm #'request-shutdown)))

(defstruct reconciliation-worker
  reconciler
  observer
  before-reconcile
  thread
  (stop-requested nil)
  (interval 1.0)
  (shutdown-timeout 5.0)
  (lock (bt:make-lock "gr8s reconciliation worker"))
  (wake-up (bt:make-condition-variable :name "gr8s reconciliation wake-up")))

(defun reconciliation-worker-stopping-p (worker)
  (bt:with-lock-held ((reconciliation-worker-lock worker))
    (reconciliation-worker-stop-requested worker)))

(defun reconciliation-worker-loop (worker)
  (loop until (reconciliation-worker-stopping-p worker)
        do (handler-case
               (progn
                 (when (reconciliation-worker-before-reconcile worker)
                   (funcall (reconciliation-worker-before-reconcile worker)))
                 (reconcile-all (reconciliation-worker-reconciler worker)
                                :observer (reconciliation-worker-observer worker)))
             (error (error)
               (format *error-output* "gr8s reconciliation error: ~A~%" error)))
           (bt:with-lock-held ((reconciliation-worker-lock worker))
             (unless (reconciliation-worker-stop-requested worker)
               (bt:condition-wait
                (reconciliation-worker-wake-up worker)
                (reconciliation-worker-lock worker)
                :timeout (reconciliation-worker-interval worker))))))

(defun start-reconciliation-worker (reconciler &key (interval 1.0) observer before-reconcile)
  (let ((worker (make-reconciliation-worker
                 :reconciler reconciler :interval interval :observer observer
                 :before-reconcile before-reconcile)))
    (setf (reconciliation-worker-thread worker)
          (bt:make-thread
           (lambda () (reconciliation-worker-loop worker))
           :name "gr8s reconciler"))
    worker))

(defun stop-reconciliation-worker (worker)
  (bt:with-lock-held ((reconciliation-worker-lock worker))
    (setf (reconciliation-worker-stop-requested worker) t)
    (bt:condition-notify (reconciliation-worker-wake-up worker)))
  (let ((thread (reconciliation-worker-thread worker)))
    (when thread
      (let ((deadline (+ (get-internal-real-time)
                         (* (reconciliation-worker-shutdown-timeout worker)
                            internal-time-units-per-second))))
        (loop while (and (bt:thread-alive-p thread)
                         (< (get-internal-real-time) deadline))
              do (sleep 0.01))
        (when (bt:thread-alive-p thread)
          (format *error-output*
                  "gr8s reconciliation worker did not stop in time; terminating it.~%")
          (bt:destroy-thread thread))
        (handler-case (bt:join-thread thread)
          (error () nil)))))
  nil)

(defun serve (options)
  (let* ((address (getf options :listen))
         (port (getf options :port))
         (state-directory
           (uiop:ensure-directory-pathname (getf options :state-directory)))
         (store (open-store state-directory))
         (pool (ensure-controller-node-pool store state-directory options))
         (pki (ensure-cluster-pki (merge-pathnames "pki/" state-directory)))
         (server nil)
         (api-server nil)
         (service-controller nil)
         (service-network-created nil)
         (worker nil)
         (node-server nil)
         (local-agent nil))
    (setf *shutdown-requested* nil)
    (install-shutdown-handlers)
    (unwind-protect
         (progn
           (setf node-server
                 (start-node-grpc-server
                  store :host (getf options :node-listen "127.0.0.1")
                  :port (getf options :node-port)
                  :pki pki :cluster-pod-cidr (gethash "clusterPodCIDR" pool)
                  :node-prefix (gethash "nodePrefix" pool)))
           (let* ((runtime (make-control-plane-runtime store node-server))
                  (reconciler (make-reconciler store runtime)))
             (unless (getf options :disable-agent)
               (setf local-agent
                     (start-local-node-agent
                      node-server pki (getf options :node-name)
                      (merge-pathnames "agent/" state-directory)
                      options)))
             (unwind-protect
                  (progn
                    (when (and local-agent (equal "containerd" (getf options :runtime))
                               (equal "managed" (getf options :containerd-mode)))
                      (ensure-native-bootstrap-namespaces store)
                      (ensure-native-api-service store)
                      (setf service-network-created (ensure-in-cluster-network pki))
                      (setf api-server (start-in-cluster-api store runtime reconciler pki)
                            service-controller (make-native-service-controller store))
                      (setf (pod-store-in-cluster-config store)
                            (list :host "10.96.0.1" :port 443
                                  :ca-pem (uiop:read-file-string (cluster-pki-ca-certificate-path pki))))
                      (ensure-native-namespace-root-cas store))
                    (setf server
                          (start-server
                           :address address :port port
                           :store store :runtime runtime
                           :reconciler reconciler))
                    (setf worker (start-reconciliation-worker reconciler
                                  :before-reconcile (lambda ()
                                      (reconcile-crd-deletions store)
                                      (collect-orphaned-custom-resources store)
                                      (reconcile-certificate-signing-requests store pki)
                                      (reconcile-storage-bindings store)
                                      (collect-orphaned-api-objects reconciler)
                                      (reconcile-workloads reconciler)
                                      (reconcile-endpointslices store)
                                      (publish-service-discovery-snapshots runtime)
                                      (when service-controller
                                        (ensure-in-cluster-network pki)
                                        (reconcile-native-services service-controller)))))
                    (when (getf options :kubeconfig)
                      (write-kubeconfig
                       (getf options :kubeconfig)
                       (format nil "http://~A:~D" address port)))
                    (format t "gr8s listening on http://~A:~D~%" address port)
                    (finish-output)
                    (loop until *shutdown-requested* do (sleep 0.1)))
               (when worker (stop-reconciliation-worker worker))
               (when runtime (stop-runtime-deletions runtime))
               (when server (stop-server server))
               (when service-controller (stop-native-service-controller service-controller))
               (when api-server (stop-server api-server))
               (when (or api-server service-network-created) (remove-in-cluster-network pki))
               (setf (pod-store-in-cluster-config store) nil))))
      (when local-agent (stop-local-node-agent local-agent))
      (when node-server (stop-node-grpc-server node-server))))
  0)

(defun print-help ()
  (format t
          "Usage:~%  gr8s serve [--state-directory DIR] [--listen 127.0.0.1] [--port PORT] [--node-port PORT] [--node-listen IPV4] [--node-address IPV4] [--node-name NAME] [--cluster-pod-cidr CIDR] [--node-pod-prefix BITS] [--disable-agent] [--runtime containerd|podman|fake] [--containerd-mode managed|external] [--containerd-executable PATH] [--containerd-oci-runtime PATH] [--containerd-socket PATH] [--containerd-log-root DIR] [--kubeconfig FILE]~%  gr8s agent --server HOST:PORT [--token TOKEN --ca-pin SHA256] --node-name NAME --state-directory DIR [--node-address IPV4] [--runtime containerd|podman|fake] [--containerd-mode managed|external] [--containerd-executable PATH] [--containerd-oci-runtime PATH] [--containerd-socket PATH] [--containerd-log-root DIR]~%  gr8s join-token --node-name NAME [--state-directory CONTROL_PLANE_DIR]~%  gr8s kubeconfig --output FILE [--server URL]~%  gr8s runtime-assets~%"))

(defun main-with-environment (arguments environment cni-entry)
  (if (funcall environment "CNI_COMMAND")
      (funcall cni-entry)
      (handler-case
          (let ((options (parse-cli-options arguments)))
            (case (getf options :command)
              (:help (print-help) 0)
              (:kubeconfig
               (write-kubeconfig (getf options :output) (getf options :server))
               0)
              (:join-token (print-node-join-token options))
              (:runtime-assets
               (print-runtime-assets)
               0)
              (:serve (serve options))
              (:agent
               (setf *shutdown-requested* nil)
               (install-shutdown-handlers)
               (agent options))))
        (error (error)
          (format *error-output* "gr8s: ~A~%" error)
          2))))

(defun main (&optional (arguments (uiop:command-line-arguments)))
  (main-with-environment arguments
                         #'uiop:getenv
                         (lambda () (cni-main))))
