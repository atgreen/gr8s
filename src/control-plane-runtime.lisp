(in-package #:gr8s)

(defstruct (control-plane-runtime
             (:constructor make-control-plane-runtime (store node-server)))
  store
  node-server)

(defun control-plane-pod-by-uid (runtime uid)
  (find uid (list-pods (control-plane-runtime-store runtime))
        :key #'pod-uid :test #'string=))

(defun pod-assignment (pod &optional store)
  (make-instance
   'gr8s.node.v1::pod-assignment
   :namespace (pod-namespace pod)
   :name (pod-name pod)
   :uid (pod-uid pod)
   :resource-version (pod-resource-version pod)
   :pod-json
   (trivial-utf-8:string-to-utf-8-bytes
    (with-output-to-string (stream)
      (com.inuoe.jzon:stringify (pod-to-object pod) :stream stream)))
   :deleting (deletion-requested-p pod)
   :resource-objects-json
   (when (and store (not (deletion-requested-p pod)))
     (mapcar (lambda (object)
               (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify object)))
             (pod-referenced-resource-objects store pod)))))

(defun node-desired-state-snapshot (store node-name &key excluded-uid)
  (make-instance
   'gr8s.node.v1::desired-state-snapshot
   :pods
   (mapcar
    (lambda (pod) (pod-assignment pod store))
    (sort
     (remove-if
      (lambda (pod)
        (or (not (equal node-name (pod-node-name pod)))
            (and excluded-uid (string= excluded-uid (pod-uid pod)))))
      (list-pods store))
     #'string< :key #'pod-name))))

(defun publish-node-snapshot (runtime node-name &key excluded-uid)
  (publish-node-desired-state
   (control-plane-runtime-node-server runtime)
   node-name
   (node-desired-state-snapshot
    (control-plane-runtime-store runtime) node-name
    :excluded-uid excluded-uid)))

(defun control-plane-observation (runtime pod)
  (make-runtime-pod
   :uid (pod-uid pod)
   :resource-version (pod-resource-version pod)
   :phase (pod-scheduling-phase (control-plane-runtime-store runtime) pod)
   :status (pod-observed-status (control-plane-runtime-store runtime) pod)
   :pod-ip (let ((status (pod-observed-status (control-plane-runtime-store runtime) pod)))
             (if status (gethash "podIP" status "") ""))))

(defmethod runtime-observe ((runtime control-plane-runtime) uid)
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    ;; An unscheduled Pod must remain absent from the runtime view so that the
    ;; reconciliation worker retries scheduling when a node becomes Ready.
    (and pod (pod-node-name pod) (control-plane-observation runtime pod))))

(defmethod runtime-ensure ((runtime control-plane-runtime) pod)
  (let ((node (schedule-pod (control-plane-runtime-store runtime) pod)))
    (when node
      (publish-node-snapshot runtime (node-record-name node)))
    (control-plane-observation runtime pod)))

(defmethod runtime-delete ((runtime control-plane-runtime) uid)
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (when (and pod (pod-node-name pod))
      ;; Snapshots are authoritative. Omitting the Pod tells the node agent to
      ;; stop it before the control-plane record is removed.
      (publish-node-snapshot runtime (pod-node-name pod) :excluded-uid uid)))
  nil)

(defmethod runtime-logs ((runtime control-plane-runtime) uid container &key tail)
  (declare (ignore tail))
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (unless (and pod (pod-node-name pod))
      (error 'runtime-error :message "Pod is not assigned to a node"))
    (let* ((request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id (generate-uid)
              :kind gr8s.node.v1::+operationkind-operation_kind_logs+
              :namespace (pod-namespace pod)
              :pod (pod-name pod)
              :pod-uid uid
              :container container
              :stdout t))
           (operation
             (request-node-operation
              (control-plane-runtime-node-server runtime)
              (pod-node-name pod) request)))
      (with-output-to-string (output)
        (dolist (message
                 (pending-node-operation-stream-messages operation))
          (when (= (slot-value message 'gr8s.node.v1::channel)
                   gr8s.node.v1::+streamchannel-stream_channel_stdout+)
            (write-string
             (trivial-utf-8:utf-8-bytes-to-string
              (slot-value message 'gr8s.node.v1::data))
             output)))))))

(defmethod runtime-exec-url
    ((runtime control-plane-runtime) uid container command
     &key stdin stdout stderr tty)
  (declare (ignore runtime uid container command stdin stdout stderr tty))
  (error 'runtime-error
         :message "Node-agent exec proxying is not implemented yet"))

(defun node-operation-channel-data (operation channel)
  (let ((output
          (make-array 0 :element-type '(unsigned-byte 8)
                        :adjustable t :fill-pointer 0)))
    (dolist (message (pending-node-operation-stream-messages operation))
      (when (= channel (slot-value message 'gr8s.node.v1::channel))
        (loop for octet across (slot-value message 'gr8s.node.v1::data)
              do (vector-push-extend octet output))))
    output))

(defmethod runtime-exec-sync
    ((runtime control-plane-runtime) uid container command &key (timeout 10))
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (unless (and pod (pod-node-name pod))
      (error 'runtime-error :message "Pod is not assigned to a node"))
    (let* ((request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id (generate-uid)
              :kind gr8s.node.v1::+operationkind-operation_kind_exec+
              :namespace (pod-namespace pod)
              :pod (pod-name pod)
              :pod-uid uid
              :container container
              :command command
              :stdout t
              :stderr t))
           (operation
             (request-node-operation
              (control-plane-runtime-node-server runtime)
              (pod-node-name pod) request :timeout timeout))
           (response (pending-node-operation-response operation)))
      (make-runtime-exec-result
       :stdout
       (node-operation-channel-data
        operation gr8s.node.v1::+streamchannel-stream_channel_stdout+)
       :stderr
       (node-operation-channel-data
        operation gr8s.node.v1::+streamchannel-stream_channel_stderr+)
       :exit-code (slot-value response 'gr8s.node.v1::exit-code)))))

(defstruct (control-plane-exec-session
             (:constructor make-control-plane-exec-session
                 (operation)))
  operation
  (input-sequence 0)
  (lock (bt:make-lock "gr8s control-plane exec session")))

(defmethod runtime-start-exec-session
    ((runtime control-plane-runtime) uid container command
     &key stdin stdout stderr tty)
  (let ((pod (control-plane-pod-by-uid runtime uid)))
    (unless (and pod (pod-node-name pod))
      (error 'runtime-error :message "Pod is not assigned to a node"))
    (make-control-plane-exec-session
     (queue-node-operation
      (control-plane-runtime-node-server runtime)
      (pod-node-name pod)
      (make-instance
       'gr8s.node.v1::operation-request
       :operation-id (generate-uid)
       :kind gr8s.node.v1::+operationkind-operation_kind_exec+
       :namespace (pod-namespace pod)
       :pod (pod-name pod)
       :pod-uid uid
       :container container
       :command command
       :stdin stdin :stdout stdout :stderr stderr :tty tty)))))

(defmethod runtime-send-exec-session-input
    ((runtime control-plane-runtime) (session control-plane-exec-session)
     channel data &key (rows 0) (columns 0) eof)
  (let ((sequence nil)
        (operation (control-plane-exec-session-operation session)))
    (bt:with-lock-held ((control-plane-exec-session-lock session))
      (setf sequence (incf (control-plane-exec-session-input-sequence session))))
    (send-node-operation-input
     (control-plane-runtime-node-server runtime) operation
     (make-instance
      'gr8s.node.v1::operation-input
      :operation-id
      (operation-request-id (pending-node-operation-request operation))
      :sequence sequence :channel channel :data data
      :rows rows :columns columns :eof eof))))

(defmethod runtime-next-exec-session-output
    ((runtime control-plane-runtime) (session control-plane-exec-session)
     cursor &key timeout)
  (declare (ignore runtime))
  (wait-for-next-node-operation-message
   (control-plane-exec-session-operation session) cursor :timeout timeout))

(defmethod runtime-exec-session-exit-code
    ((runtime control-plane-runtime) (session control-plane-exec-session))
  (declare (ignore runtime))
  (let ((operation (control-plane-exec-session-operation session)))
    (when (pending-node-operation-error operation)
      (error 'runtime-error :message (pending-node-operation-error operation)))
    (let ((response (pending-node-operation-response operation)))
      (unless response
        (error 'runtime-error :message "Node exec ended without a response"))
      (slot-value response 'gr8s.node.v1::exit-code))))

(defmethod runtime-cancel-exec-session
    ((runtime control-plane-runtime) (session control-plane-exec-session) reason)
  (cancel-node-operation
   (control-plane-runtime-node-server runtime)
   (control-plane-exec-session-operation session) reason))

(defmethod runtime-release-exec-session
    ((runtime control-plane-runtime) (session control-plane-exec-session))
  (release-node-operation
   (control-plane-runtime-node-server runtime)
   (control-plane-exec-session-operation session)))
