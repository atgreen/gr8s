;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Register kubelet v1beta1 device plugins, watch their healthy inventories,
;;;; checkpoint exclusive allocations, and pass their artifacts to CRI.
(in-package #:gr8s.kubelet)

(defparameter *device-plugin-directory* #P"/var/lib/kubelet/device-plugins/")
(defvar *device-plugin-watch* nil)

(defstruct device-plugin resource endpoint options channel thread (devices nil)
  ;; A plugin built into the agent answers here, (method request) -> response,
  ;; rather than over a Unix socket.
  local)
(defstruct (device-plugin-manager (:constructor %make-device-plugin-manager))
  directory checkpoint socket-path listener server thread
  (running nil)
  (plugins (make-hash-table :test #'equal))
  (allocations (make-hash-table :test #'equal))
  (clients nil)
  (workers nil)
  (lock (bt:make-lock "device plugin inventory"))
  (allocation-lock (bt:make-lock "device plugin allocations")))

;; ag-gRPC only uses this address for diagnostic context. AF_UNIX has no TCP
;; port; specializing the wrapper lets it share the normal HTTP/2 server.
(defclass device-plugin-client (usocket:stream-usocket) ())
(defmethod usocket:get-peer-address ((socket device-plugin-client)) "local")
(defmethod usocket:get-peer-port ((socket device-plugin-client)) 0)

(defun device-plugin-error (control &rest arguments)
  "Signal a node-side runtime failure with the device plugin's context."
  (error 'runtime-error :message (apply #'format nil control arguments)))

(defun save-device-plugin-checkpoint (manager)
  "Save selections and successful Allocate responses while allocation-lock is held."
  (let ((resources (core-object)))
    (bt:with-lock-held ((device-plugin-manager-lock manager))
      (maphash (lambda (name plugin) (declare (ignore plugin)) (setf (gethash name resources) "0"))
               (device-plugin-manager-plugins manager)))
    (ensure-directories-exist (device-plugin-manager-checkpoint manager))
    (gr8s.store::write-text-atomically
     (device-plugin-manager-checkpoint manager)
     (com.inuoe.jzon:stringify
      (core-object "version" 1 "resources" resources
                   "allocations" (device-plugin-manager-allocations manager))))))

(defun make-device-plugin-manager (state-directory &key (directory *device-plugin-directory*))
  "Restore one node's durable reservations without assuming plugins are healthy."
  (let* ((path (merge-pathnames "device-plugins/allocations.json" (uiop:ensure-directory-pathname state-directory)))
         (manager (%make-device-plugin-manager :directory (uiop:ensure-directory-pathname directory) :checkpoint path)))
    (when (probe-file path)
      (let ((root (com.inuoe.jzon:parse path)))
        (unless (and (eql 1 (gethash "version" root)) (hash-table-p (gethash "allocations" root)))
          (device-plugin-error "Invalid device allocation checkpoint ~A" path))
        (setf (device-plugin-manager-allocations manager) (gethash "allocations" root))
        (maphash (lambda (name count)
                   (declare (ignore count))
                   (setf (gethash name (device-plugin-manager-plugins manager)) (make-device-plugin :resource name)))
                 (gethash "resources" root (core-object)))))
    manager))

(defun device-plugin-unary (plugin method request response-type)
  "Call one bounded plugin RPC on an independent connection."
  (unless (device-plugin-endpoint plugin) (device-plugin-error "Device plugin ~A is unavailable" (device-plugin-resource plugin)))
  (let ((channel (make-unix-grpc-channel (device-plugin-endpoint plugin) :timeout 30)))
    (unwind-protect
         (let ((call (ag-grpc:call-unary channel (concatenate 'string "/v1beta1.DevicePlugin/" method)
                                       request :timeout 30 :response-type response-type)))
           (unless (= ag-grpc:+grpc-status-ok+ (ag-grpc:call-status call))
             (device-plugin-error "Device plugin ~A ~A failed: ~A" (device-plugin-resource plugin) method (ag-grpc:call-status call)))
           (ag-grpc:call-response call))
      (ag-grpc:channel-close channel))))

(defun watch-device-plugin (manager plugin)
  "Reconnect ListAndWatch until replaced or stopped; never retain stale health."
  (catch plugin
    (let ((*device-plugin-watch* plugin))
      (loop while (and (device-plugin-manager-running manager)
                   (eq plugin (gethash (device-plugin-resource plugin) (device-plugin-manager-plugins manager))))
        do (let ((channel nil))
             (unwind-protect
                  (handler-case
                      (progn
                        (setf channel (make-unix-grpc-channel (device-plugin-endpoint plugin) :timeout 5))
                        (bt:with-lock-held ((device-plugin-manager-lock manager))
                          (setf (device-plugin-channel plugin) channel))
                        (let ((stream (ag-grpc:call-server-stream
                                       channel "/v1beta1.DevicePlugin/ListAndWatch" (make-instance 'dp::empty)
                                       :timeout 86400 :response-type 'dp::list-and-watch-response)))
                          (loop for response = (ag-grpc:stream-receive-message stream) while response
                                do (let ((devices (dp::devices response)) (seen (make-hash-table :test #'equal)))
                                     (dolist (device devices)
                                       (unless (and (plusp (length (dp::id device))) (<= (length (dp::id device)) 63)
                                                    (member (dp::health device) '("Healthy" "Unhealthy") :test #'equal)
                                                    (not (gethash (dp::id device) seen)))
                                         (device-plugin-error "Invalid device inventory for ~A" (device-plugin-resource plugin)))
                                       (setf (gethash (dp::id device) seen) t))
                                     (bt:with-lock-held ((device-plugin-manager-lock manager))
                                       (setf (device-plugin-devices plugin) devices))))))
                    (error (condition)
                      (when (device-plugin-manager-running manager)
                        (format *error-output* "gr8s device plugin ~A: ~A~%" (device-plugin-resource plugin) condition))))
               (bt:with-lock-held ((device-plugin-manager-lock manager))
                 (setf (device-plugin-devices plugin) nil (device-plugin-channel plugin) nil))
               (when channel (ignore-errors (ag-grpc:channel-close channel)))))
           (when (device-plugin-manager-running manager) (sleep 1))))))

(defun interrupt-device-plugin-watch (plugin)
  "Wake a watcher blocked in poll; closing its socket alone need not wake it."
  (let ((thread (device-plugin-thread plugin)))
    (when (and thread (bt:thread-alive-p thread))
      (ignore-errors
        (bt:interrupt-thread thread (lambda ()
                                     (when (eq *device-plugin-watch* plugin)
                                       (throw plugin :stopped))))))))

(defun device-plugin-call (plugin method request response-type)
  "Call METHOD of PLUGIN: built into the agent, or over its Unix endpoint."
  (if (device-plugin-local plugin)
      (funcall (device-plugin-local plugin) method request)
      (device-plugin-unary plugin method request response-type)))

(defparameter *gr8s-dri-resource* "gr8s.io/dri"
  "The GPU render nodes a Pod asks for with this extended resource (podster-wv1w.16).")

(defparameter *gr8s-dri-slots* 16
  "How many Pods at once may hold the node's render nodes: they are shared, not handed out.")

(defvar *dri-directory* "/dev/dri/"
  "Where the node's GPU render nodes are; tests point it elsewhere.")

(defun dri-render-nodes (&optional (directory *dri-directory*))
  "This node's GPU render nodes, /dev/dri/renderD*. The card* nodes are left out: a
renderer needs none, and they also drive the display."
  (sort (loop for entry in (ignore-errors (directory (concatenate 'string directory "renderD*")))
              collect (namestring entry))
        #'string<))

(defun make-dri-device-plugin (&key (render-nodes (dri-render-nodes)))
  "The device plugin built into the agent for RENDER-NODES (podster-wv1w.16), or NIL
without any: *GR8S-DRI-SLOTS* healthy devices, each of which gives a container every
render node, read-write."
  (when render-nodes
    (make-device-plugin
     :resource *gr8s-dri-resource* :endpoint "built-in"
     :devices (loop for slot below *gr8s-dri-slots*
                    collect (make-instance 'dp::device :id (format nil "dri-~D" slot) :health "Healthy"))
     :local (lambda (method request)
              (declare (ignore request))
              (cond ((equal method "Allocate")
                     (make-instance
                      'dp::allocate-response
                      :container-responses
                      (list (make-instance 'dp::container-allocate-response
                                           :devices (loop for node in render-nodes
                                                          collect (make-instance 'dp::device-spec
                                                                                 :host-path node :container-path node
                                                                                 :permissions "rw"))))))
                    ((equal method "PreStartContainer") (make-instance 'dp::pre-start-container-response))
                    (t (device-plugin-error "Built-in device plugin has no ~A" method)))))))

(defun install-builtin-device-plugins (manager &key (dri (make-dri-device-plugin)))
  "Register the device plugins the agent itself provides: today the GPU render nodes."
  (when dri
    (bt:with-lock-held ((device-plugin-manager-lock manager))
      (setf (gethash (device-plugin-resource dri) (device-plugin-manager-plugins manager)) dri))))

(defparameter *device-plugin-call* #'device-plugin-call
  "Bounded unary transport, injectable for allocation failure and recovery tests.")

(defun register-device-plugin (manager request)
  "Validate a registration before watching its Unix endpoint asynchronously."
  (let* ((resource (dp::resource-name request)) (endpoint (dp::endpoint request))
         (plugin (make-device-plugin :resource resource
                                    :endpoint (namestring (merge-pathnames endpoint (device-plugin-manager-directory manager)))
                                    :options (dp::options request)))
         (old nil))
    (unless (and (equal "v1beta1" (dp::version request)) (extended-resource-name-p resource)
                 (plusp (length endpoint)) (<= (length endpoint) 255)
                 (not (member endpoint '("." "..") :test #'equal))
                 (every (lambda (c) (or (alphanumericp c) (find c "._-"))) endpoint))
      (device-plugin-error "Invalid device plugin registration"))
    (bt:with-lock-held ((device-plugin-manager-lock manager))
      (setf old (gethash resource (device-plugin-manager-plugins manager))
            (gethash resource (device-plugin-manager-plugins manager)) plugin))
    (when (and old (device-plugin-channel old)) (ignore-errors (ag-grpc:channel-close (device-plugin-channel old))))
    (when old (interrupt-device-plugin-watch old))
    (bt:with-lock-held ((device-plugin-manager-allocation-lock manager))
      (save-device-plugin-checkpoint manager))
    (setf (device-plugin-thread plugin)
          (bt:make-thread (lambda () (watch-device-plugin manager plugin)) :name (format nil "device plugin ~A" resource)))
    (make-instance 'dp::empty)))

(defun device-plugin-resource-entries (manager)
  "Report healthy capacity, including zero for each disconnected known resource."
  (when manager
    (bt:with-lock-held ((device-plugin-manager-lock manager))
      (loop for name being the hash-keys of (device-plugin-manager-plugins manager) using (hash-value plugin)
            collect (cons name (write-to-string (count "Healthy" (device-plugin-devices plugin) :key #'dp::health :test #'equal)))))))

(defun device-plugin-accept-loop (manager)
  "Serve root-only registrations with a bounded number of connection workers."
  (let ((slots (bt:make-semaphore :name "device plugin connections" :count 32)))
    (loop while (device-plugin-manager-running manager)
          do (handler-case
                 (let* ((native (sb-bsd-sockets:socket-accept (device-plugin-manager-listener manager)))
                        (client (make-instance 'device-plugin-client :socket native
                                               :stream (sb-bsd-sockets:socket-make-stream native :input t :output t
                                                                                         :element-type '(unsigned-byte 8) :buffering :full))))
                   (if (and (device-plugin-manager-running manager) (bt:wait-on-semaphore slots :timeout 0.001))
                       (bt:with-lock-held ((device-plugin-manager-lock manager))
                         (push client (device-plugin-manager-clients manager))
                         (push (bt:make-thread
                                (lambda ()
                                  (unwind-protect
                                       (handler-case (ag-grpc::server-handle-connection (device-plugin-manager-server manager) client)
                                         (error (condition) (when (device-plugin-manager-running manager)
                                                              (format *error-output* "gr8s device registration: ~A~%" condition))))
                                    (ignore-errors (usocket:socket-close client))
                                    (bt:with-lock-held ((device-plugin-manager-lock manager))
                                      (setf (device-plugin-manager-clients manager) (delete client (device-plugin-manager-clients manager))
                                            (device-plugin-manager-workers manager)
                                            (delete (bt:current-thread) (device-plugin-manager-workers manager))))
                                    (bt:signal-semaphore slots))) :name "device registration")
                               (device-plugin-manager-workers manager)))
                       (usocket:socket-close client)))
               (error (condition)
                 (when (device-plugin-manager-running manager)
                   (format *error-output* "gr8s device registration listener: ~A~%" condition)
                   (sleep 0.1)))))))

(defun start-device-plugin-manager (manager)
  "Own kubelet.sock, refusing to replace another live agent's registration socket."
  (when (device-plugin-manager-running manager) (return-from start-device-plugin-manager manager))
  (let* ((path (merge-pathnames "kubelet.sock" (device-plugin-manager-directory manager)))
         (native (make-instance 'sb-bsd-sockets:local-socket :type :stream :protocol 0)))
    (ensure-directories-exist path)
    (when (ignore-errors (sb-posix:lstat path))
      (let ((probe (make-instance 'sb-bsd-sockets:local-socket :type :stream :protocol 0)))
        (unwind-protect
             (when (ignore-errors (sb-bsd-sockets:socket-connect probe (namestring path)) t)
               (device-plugin-error "Another kubelet owns ~A" path))
          (sb-bsd-sockets:socket-close probe)))
      (unless (= sb-posix:s-ifsock (logand sb-posix:s-ifmt (sb-posix:stat-mode (sb-posix:lstat path))))
        (device-plugin-error "Device registration path is not a socket: ~A" path))
      (delete-file path))
    (handler-case
        (progn
          ;; Plugins watch their own socket for removal to detect a restarted
          ;; kubelet. Leave checkpoint and other regular files intact.
          (dolist (socket (uiop:directory-files (device-plugin-manager-directory manager)))
            (let ((stat (ignore-errors (sb-posix:lstat socket))))
              (when (and stat (= sb-posix:s-ifsock (logand sb-posix:s-ifmt (sb-posix:stat-mode stat))))
                (delete-file socket))))
          (sb-bsd-sockets:socket-bind native (namestring path))
          (sb-posix:chmod path #o600)
          (sb-bsd-sockets:socket-listen native 32)
          (setf (device-plugin-manager-listener manager) native
                (device-plugin-manager-socket-path manager) path
                (device-plugin-manager-server manager) (ag-grpc:make-grpc-server 0 :connection-idle-timeout 30)
                (device-plugin-manager-running manager) t)
          (ag-grpc:server-register-handler
           (device-plugin-manager-server manager) "/v1beta1.Registration/Register"
           (lambda (request context) (declare (ignore context)) (register-device-plugin manager request))
           :request-type 'dp::register-request :response-type 'dp::empty)
          (install-builtin-device-plugins manager)
          (setf (ag-grpc::server-state (device-plugin-manager-server manager)) :running
                (device-plugin-manager-thread manager)
                (bt:make-thread (lambda () (device-plugin-accept-loop manager)) :name "device plugin registry")))
      (error (condition) (sb-bsd-sockets:socket-close native) (error condition))))
  manager)

(defun stop-device-plugin-manager (manager)
  "Wake accept and close all owned transports; retain allocations for restart."
  (when (and manager (device-plugin-manager-running manager))
    (setf (device-plugin-manager-running manager) nil)
    (let ((wake (make-instance 'sb-bsd-sockets:local-socket :type :stream :protocol 0)))
      (unwind-protect
           (ignore-errors (sb-bsd-sockets:socket-connect wake (namestring (device-plugin-manager-socket-path manager))))
        (sb-bsd-sockets:socket-close wake)))
    (ignore-errors (bt:join-thread (device-plugin-manager-thread manager)))
    (ignore-errors (sb-bsd-sockets:socket-close (device-plugin-manager-listener manager)))
    (let ((channels nil) (clients nil) (threads nil) (plugins nil))
      (bt:with-lock-held ((device-plugin-manager-lock manager))
        (setf clients (copy-list (device-plugin-manager-clients manager))
              threads (copy-list (device-plugin-manager-workers manager)))
        (maphash (lambda (name plugin)
                   (declare (ignore name))
                   (push plugin plugins)
                   (when (device-plugin-channel plugin) (push (device-plugin-channel plugin) channels))
                   (when (device-plugin-thread plugin) (push (device-plugin-thread plugin) threads)))
                 (device-plugin-manager-plugins manager)))
      (dolist (channel channels) (ignore-errors (ag-grpc:channel-close channel)))
      (dolist (plugin plugins) (interrupt-device-plugin-watch plugin))
      (dolist (client clients) (ignore-errors (usocket:socket-close client)))
      (dolist (thread threads) (ignore-errors (bt:join-thread thread))))
    (ignore-errors (delete-file (device-plugin-manager-socket-path manager))))
  nil)

(defun device-plugin-used-ids (manager resource)
  "Collect this resource's durable reservations across all Pods and containers."
  (loop for pod being the hash-values of (device-plugin-manager-allocations manager)
        append (loop for container being the hash-values of pod
                     for reservation = (gethash resource container)
                     when reservation append (coerce (gethash "ids" reservation) 'list))))

(defun allocate-plugin-devices (manager pod container &key numa-node)
  "Allocate once per Pod UID/container/resource, retaining device identity on retries."
  (reserve-pod-plugin-devices manager pod numa-node (list container))
  (let ((responses nil) (uid (pod-uid pod)) (name (gethash "name" container)))
    (bt:with-lock-held ((device-plugin-manager-allocation-lock manager))
      (maphash
       (lambda (resource quantity)
         (let ((plugin (bt:with-lock-held ((device-plugin-manager-lock manager))
                         (gethash resource (device-plugin-manager-plugins manager)))))
           ;; Administratively advertised opaque resources have no plugin artifacts.
           (when plugin
             (let* ((count (container-quantity-integer (parse-container-quantity quantity)))
                    (pod-allocations (or (gethash uid (device-plugin-manager-allocations manager))
                                         (setf (gethash uid (device-plugin-manager-allocations manager)) (core-object))))
                    (allocations (or (gethash name pod-allocations) (setf (gethash name pod-allocations) (core-object))))
                    (reservation (gethash resource allocations)))
               (unless reservation
                 (device-plugin-error "Device inventory changed during reservation; retry ~A/~A" uid name))
               (unless (= count (length (gethash "ids" reservation)))
                 (device-plugin-error "Device request changed for ~A/~A" uid name))
               (unless (gethash "response" reservation)
                 (let* ((reply (funcall *device-plugin-call* plugin "Allocate"
                                (make-instance 'dp::allocate-request :container-requests
                                               (list (make-instance 'dp::container-allocate-request
                                                                    :devices-ids (coerce (gethash "ids" reservation) 'list))))
                                'dp::allocate-response))
                        (containers (dp::container-responses reply)))
                   (unless (= 1 (length containers)) (device-plugin-error "Invalid Allocate response from ~A" resource))
                   (setf (gethash "response" reservation) (ag-grpc:base64-encode (ag-proto:serialize-to-bytes (first containers))))
                   (save-device-plugin-checkpoint manager)))
               (when (and (device-plugin-options plugin) (dp::pre-start-required (device-plugin-options plugin)))
                 (funcall *device-plugin-call* plugin "PreStartContainer"
                                      (make-instance 'dp::pre-start-container-request :devices-ids (coerce (gethash "ids" reservation) 'list))
                                      'dp::pre-start-container-response))
               (push (ag-proto:deserialize-from-bytes 'dp::container-allocate-response
                       (ag-grpc:base64-decode (gethash "response" reservation))) responses)))))
       (gethash "limits" (gethash "resources" container (core-object)) (core-object))))
    responses))

(defun release-plugin-devices (manager pod)
  "Release a UID's reservations only after its native runtime cleanup completes."
  (bt:with-lock-held ((device-plugin-manager-allocation-lock manager))
    (when (remhash (pod-uid pod) (device-plugin-manager-allocations manager))
      (save-device-plugin-checkpoint manager))))

(defun device-plugin-container-config (manager pod container &key numa-node)
  "Validate plugin artifacts and translate them into a CRI configuration fragment."
  (let ((env nil) (mounts nil) (devices nil) (annotations nil) (cdi nil))
    (dolist (response (allocate-plugin-devices manager pod container :numa-node numa-node))
      (setf env (append env (dp::envs response)) annotations (append annotations (dp::annotations response)))
      (dolist (mount (dp::mounts response))
        (unless (and (storage-absolute-path-p (dp::host-path mount)) (storage-absolute-path-p (dp::container-path mount)))
          (device-plugin-error "Plugin returned a nonabsolute mount path"))
        (push (make-instance 'gr8s.cri.v1::mount :host-path (dp::host-path mount) :container-path (dp::container-path mount)
                                                :readonly (dp::read-only mount)) mounts))
      (dolist (device (dp::devices response))
        (unless (and (storage-absolute-path-p (dp::host-path device)) (storage-absolute-path-p (dp::container-path device))
                     (plusp (length (dp::permissions device))) (every (lambda (c) (find c "rwm")) (dp::permissions device)))
          (device-plugin-error "Plugin returned an invalid device path or permissions"))
        (push (make-instance 'gr8s.cri.v1::device :host-path (dp::host-path device) :container-path (dp::container-path device)
                                                 :permissions (dp::permissions device)) devices))
      (dolist (device (dp::cdi-devices response)) (push (dp::name device) cdi)))
    (list :env env :mounts (nreverse mounts) :devices (nreverse devices) :annotations annotations :cdi-device-ids (nreverse cdi))))

(defun device-on-numa-node-p (device node)
  "An absent topology hint imposes no NUMA restriction."
  (or (null node) (null (dp::topology device)) (null (dp::nodes (dp::topology device)))
      (find node (dp::nodes (dp::topology device)) :key #'dp::id)))

(defun device-container-conflicts-p (pod left right)
  "Regular init devices are reusable; sidecars coexist with subsequent containers."
  (some (lambda (stage)
          (and (find left stage :key (lambda (c) (gethash "name" c)) :test #'equal)
               (find right stage :key (lambda (c) (gethash "name" c)) :test #'equal)))
        (resource-container-stages (gethash "spec" (pod-to-object pod)))))

(defun device-plugin-conflicting-ids (manager resource pod name)
  (loop for uid being the hash-keys of (device-plugin-manager-allocations manager) using (hash-value containers)
        append (loop for other being the hash-keys of containers using (hash-value resources)
                     for reservation = (gethash resource resources)
                     when (and reservation (or (not (equal uid (pod-uid pod))) (device-container-conflicts-p pod name other)))
                       append (coerce (gethash "ids" reservation) 'list))))

(defun reserve-pod-plugin-devices (manager pod node &optional selected-containers)
  "Checkpoint topology-aligned IDs atomically before making any plugin RPC."
  (bt:with-lock-held ((device-plugin-manager-allocation-lock manager))
    (let* ((uid (pod-uid pod)) (old (gethash uid (device-plugin-manager-allocations manager)))
           (working (if old (copy-core-object old) (core-object))))
      (setf (gethash uid (device-plugin-manager-allocations manager)) working)
      (handler-case
          (progn
            (dolist (container (or selected-containers (resource-pod-containers pod)))
              (let* ((name (gethash "name" container))
                     (allocations (or (gethash name working) (setf (gethash name working) (core-object)))))
                (maphash
                 (lambda (resource amount)
                   (let ((plugin (bt:with-lock-held ((device-plugin-manager-lock manager))
                                   (gethash resource (device-plugin-manager-plugins manager)))))
                     (when plugin
                       (let ((count (container-quantity-integer (parse-container-quantity amount)))
                             (reservation (gethash resource allocations)))
                         (if reservation
                             (progn
                               (unless (= count (length (gethash "ids" reservation)))
                                 (device-plugin-error "Device request changed for ~A/~A" uid name))
                               (when node
                                 (bt:with-lock-held ((device-plugin-manager-lock manager))
                                   (unless (every (lambda (id)
                                                    (let ((device (find id (device-plugin-devices plugin) :key #'dp::id :test #'equal)))
                                                      (and device (device-on-numa-node-p device node))))
                                                  (gethash "ids" reservation))
                                     (device-plugin-error "Reserved ~A devices no longer match NUMA node ~D" resource node)))))
                             (let* ((used (device-plugin-conflicting-ids manager resource pod name))
                                    (ids (bt:with-lock-held ((device-plugin-manager-lock manager))
                                           (loop for device in (device-plugin-devices plugin)
                                                 when (and (equal "Healthy" (dp::health device))
                                                           (not (member (dp::id device) used :test #'equal))
                                                           (device-on-numa-node-p device node)) collect (dp::id device)))))
                               (unless (>= (length ids) count) (device-plugin-error "Insufficient NUMA-aligned ~A devices" resource))
                               (setf (gethash resource allocations) (core-object "ids" (coerce (subseq ids 0 count) 'vector)))))))))
                 (gethash "limits" (gethash "resources" container (core-object)) (core-object)))))
            (save-device-plugin-checkpoint manager))
        (error (condition)
          (if old (setf (gethash uid (device-plugin-manager-allocations manager)) old)
              (remhash uid (device-plugin-manager-allocations manager)))
          (error condition))))))
