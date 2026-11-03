(in-package #:gr8s)

(defstruct (node-grpc-server
             (:constructor %make-node-grpc-server
                 (&key store grpc-server thread port heartbeat-timeout-seconds
                       pki cluster-pod-cidr node-prefix)))
  store
  grpc-server
  thread
  port
  heartbeat-timeout-seconds
  pki
  cluster-pod-cidr
  node-prefix
  (revisions (make-hash-table :test #'equal))
  (snapshots (make-hash-table :test #'equal))
  (acknowledged-revisions (make-hash-table :test #'equal))
  (operations (make-hash-table :test #'equal))
  (operation-queues (make-hash-table :test #'equal))
  (sessions (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s node sessions"))
  monitor-thread
  (stopping-p nil))

(defstruct (node-agent-session
             (:constructor make-node-agent-session (stream)))
  stream
  (lock (bt:make-lock "gr8s node agent session")))

(defstruct (pending-node-operation
             (:constructor make-pending-node-operation (node-name request)))
  node-name
  request
  session
  response
  (stream-messages nil)
  error
  (done-p nil)
  (lock (bt:make-lock "gr8s node operation"))
  (finished (bt:make-condition-variable :name "gr8s node operation finished")))

(defun operation-request-id (request)
  (slot-value request 'gr8s.node.v1::operation-id))

(defun send-node-agent-envelope (session envelope)
  (bt:with-lock-held ((node-agent-session-lock session))
    (ag-grpc:stream-send (node-agent-session-stream session) envelope)))

(defun queue-node-operation (server node-name request)
  (get-node (node-grpc-server-store server) node-name)
  (let* ((operation (make-pending-node-operation node-name request))
         (operation-id (operation-request-id request))
         (session nil))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (when (gethash operation-id (node-grpc-server-operations server))
        (error "Node operation ~A already exists" operation-id))
      (setf (gethash operation-id (node-grpc-server-operations server))
            operation
            session (gethash node-name (node-grpc-server-sessions server))
            (pending-node-operation-session operation) session)
      (unless session
        (setf (gethash node-name (node-grpc-server-operation-queues server))
              (nconc (gethash node-name
                              (node-grpc-server-operation-queues server))
                     (list operation)))))
    (when session
      (handler-case
          (send-node-agent-envelope
           session
           (make-server-envelope :operation-request request :sequence 0))
        (error (condition)
          (finish-node-operation operation :error (princ-to-string condition)))))
    operation))

(defun take-node-operations (server node-name)
  (bt:with-lock-held ((node-grpc-server-lock server))
    (prog1 (gethash node-name (node-grpc-server-operation-queues server))
      (remhash node-name (node-grpc-server-operation-queues server)))))

(defun find-node-operation (server operation-id)
  (bt:with-lock-held ((node-grpc-server-lock server))
    (gethash operation-id (node-grpc-server-operations server))))

(defun finish-node-operation (operation &key response error)
  (bt:with-lock-held ((pending-node-operation-lock operation))
    (unless (pending-node-operation-done-p operation)
      (setf (pending-node-operation-response operation) response
            (pending-node-operation-error operation) error
            (pending-node-operation-done-p operation) t)
      (bt:condition-notify (pending-node-operation-finished operation))))
  operation)

(defun release-node-operation (server operation)
  (let ((operation-id
          (operation-request-id
           (pending-node-operation-request operation))))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (when (eq operation
                (gethash operation-id (node-grpc-server-operations server)))
        (remhash operation-id (node-grpc-server-operations server)))))
  operation)

(defun wait-for-next-node-operation-message
    (operation cursor &key timeout)
  (let ((deadline
          (and timeout
               (+ (get-internal-real-time)
                  (* timeout internal-time-units-per-second)))))
    (bt:with-lock-held ((pending-node-operation-lock operation))
      (loop
        (let ((message
                (nth cursor
                     (pending-node-operation-stream-messages operation))))
          (when message
            (return (values message (1+ cursor) nil)))
          (when (pending-node-operation-done-p operation)
            (return (values nil cursor t))))
        (if deadline
            (let ((remaining
                    (/ (- deadline (get-internal-real-time))
                       internal-time-units-per-second)))
              (when (<= remaining 0)
                (error 'runtime-error
                       :message "Timed out waiting for node operation output"))
              (bt:condition-wait
               (pending-node-operation-finished operation)
               (pending-node-operation-lock operation)
               :timeout remaining))
            (bt:condition-wait
             (pending-node-operation-finished operation)
             (pending-node-operation-lock operation)))))))

(defun wait-for-node-operation (server operation &key (timeout 10))
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (bt:with-lock-held ((pending-node-operation-lock operation))
      (loop until (pending-node-operation-done-p operation)
            for remaining = (/ (- deadline (get-internal-real-time))
                               internal-time-units-per-second)
            when (<= remaining 0)
              do (setf (pending-node-operation-error operation)
                       "Node operation timed out"
                       (pending-node-operation-done-p operation) t)
                 (loop-finish)
            do (bt:condition-wait
                (pending-node-operation-finished operation)
                (pending-node-operation-lock operation)
                :timeout remaining)))
    (release-node-operation server operation)
    (when (pending-node-operation-error operation)
      (error 'runtime-error
             :message (pending-node-operation-error operation)))
    operation))

(defun request-node-operation (server node-name request &key (timeout 10))
  (wait-for-node-operation
   server (queue-node-operation server node-name request) :timeout timeout))

(defun live-node-operation-session (server operation operation-id)
  (unless (string= operation-id
                   (operation-request-id
                    (pending-node-operation-request operation)))
    (error 'runtime-error :message "Node operation ID does not match"))
  (unless (eq operation (find-node-operation server operation-id))
    (error 'runtime-error :message "Node operation is no longer active"))
  (bt:with-lock-held ((pending-node-operation-lock operation))
    (when (pending-node-operation-done-p operation)
      (error 'runtime-error :message "Node operation is already complete"))
    (or (pending-node-operation-session operation)
        (error 'runtime-error :message "Node operation has no live session"))))

(defun send-node-operation-envelope (server operation variant payload operation-id)
  (let ((session (live-node-operation-session server operation operation-id)))
    (handler-case
        (send-node-agent-envelope
         session (make-server-envelope variant payload :sequence 0))
      (error (condition)
        (finish-node-operation operation :error (princ-to-string condition))
        (error condition))))
  operation)

(defun send-node-operation-input (server operation input)
  (send-node-operation-envelope
   server operation :operation-input input
   (slot-value input 'gr8s.node.v1::operation-id)))

(defun cancel-node-operation (server operation reason)
  (let ((operation-id
          (operation-request-id (pending-node-operation-request operation))))
    (send-node-operation-envelope
     server operation :operation-cancel
     (make-instance 'gr8s.node.v1::operation-cancel
                    :operation-id operation-id :reason reason)
     operation-id)))

(defun note-node-operation-stream (server message)
  (let ((operation
          (find-node-operation
           server (slot-value message 'gr8s.node.v1::operation-id))))
    (when operation
      (bt:with-lock-held ((pending-node-operation-lock operation))
        (setf (pending-node-operation-stream-messages operation)
              (nconc (pending-node-operation-stream-messages operation)
                     (list message)))
        (bt:condition-notify (pending-node-operation-finished operation))))))

(defun note-node-operation-response (server response)
  (let ((operation
          (find-node-operation
           server (slot-value response 'gr8s.node.v1::operation-id))))
    (when (and operation
               (member (slot-value response 'gr8s.node.v1::status)
                       (list
                        gr8s.node.v1::+operationstatus-operation_status_complete+
                        gr8s.node.v1::+operationstatus-operation_status_failed+)))
      (finish-node-operation
       operation :response response
       :error (when (= (slot-value response 'gr8s.node.v1::status)
                       gr8s.node.v1::+operationstatus-operation_status_failed+)
                (slot-value response 'gr8s.node.v1::error-message))))))

(defun fail-node-session-operations (server session)
  (let ((operations nil))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (maphash
       (lambda (operation-id operation)
         (declare (ignore operation-id))
         (when (eq session (pending-node-operation-session operation))
           (push operation operations)))
       (node-grpc-server-operations server)))
    (dolist (operation operations)
      (unless (pending-node-operation-done-p operation)
        (finish-node-operation operation :error "Node disconnected")))))

(defun node-envelope-payload (envelope variant)
  (unless (eq variant (slot-value envelope 'gr8s.node.v1::payload-case))
    (error "Expected node-session payload ~S, received ~S"
           variant (slot-value envelope 'gr8s.node.v1::payload-case)))
  (slot-value envelope (find-symbol (symbol-name variant) :gr8s.node.v1)))

(defun current-node-snapshot (server node-name)
  (bt:with-lock-held ((node-grpc-server-lock server))
    (or (gethash node-name (node-grpc-server-snapshots server))
        (make-instance 'gr8s.node.v1::desired-state-snapshot))))

(defun note-node-snapshot-ack (server node-name ack)
  (let ((revision (slot-value ack 'gr8s.node.v1::revision)))
    (when (slot-value ack 'gr8s.node.v1::applied)
      (bt:with-lock-held ((node-grpc-server-lock server))
        (let ((published (gethash node-name
                                  (node-grpc-server-revisions server) 0))
              (acknowledged
                (gethash node-name
                         (node-grpc-server-acknowledged-revisions server) 0)))
          ;; Old acks cannot move convergence backwards, and an agent cannot
          ;; acknowledge a revision the server has never published.
          (when (and (> revision acknowledged) (<= revision published))
            (setf (gethash node-name
                           (node-grpc-server-acknowledged-revisions server))
                  revision)))))))

(defun handle-node-agent-envelope (server node-name envelope)
  (ensure-node-protocol-version
   (slot-value envelope 'gr8s.node.v1::protocol-version))
  (case (slot-value envelope 'gr8s.node.v1::payload-case)
    (:heartbeat
     (mark-node-ready (node-grpc-server-store server)
                      node-name (get-universal-time)))
    (:snapshot-ack
     (note-node-snapshot-ack
      server node-name
      (slot-value envelope 'gr8s.node.v1::snapshot-ack)))
    (:status
     (let ((status (slot-value envelope 'gr8s.node.v1::status)))
       (loop for pod-status in (slot-value status 'gr8s.node.v1::pods)
             for namespace =
               (slot-value pod-status 'gr8s.node.v1::namespace)
             for name = (slot-value pod-status 'gr8s.node.v1::name)
             for uid = (slot-value pod-status 'gr8s.node.v1::uid)
             for pod = (get-pod (node-grpc-server-store server)
                                namespace name)
             when (string= uid (pod-uid pod))
               do (update-pod-observed-phase
                   (node-grpc-server-store server) pod
                   (slot-value pod-status 'gr8s.node.v1::phase)))))
    (:operation-response
     (note-node-operation-response
      server (slot-value envelope 'gr8s.node.v1::operation-response)))
    (:operation-stream
     (note-node-operation-stream
      server (slot-value envelope 'gr8s.node.v1::operation-stream)))
    (otherwise
     (error "Unexpected node-session payload ~S"
            (slot-value envelope 'gr8s.node.v1::payload-case)))))

(defun send-node-protocol-error (stream condition &optional envelope)
  (ignore-errors
    (ag-grpc:stream-send
     stream
     (make-server-envelope
      :protocol-error
      (make-instance
       'gr8s.node.v1::protocol-error
       :supported-version +node-protocol-version+
       :received-version
       (if envelope
           (slot-value envelope 'gr8s.node.v1::protocol-version)
           0)
       :message (princ-to-string condition))
      :sequence 1))))

(defun handle-node-connect-internal (server context stream)
  (declare (ignore context))
  (let ((first (ag-grpc:stream-recv stream)))
    (unless first
      (error "Node session ended before its hello"))
    (ensure-node-protocol-version
     (slot-value first 'gr8s.node.v1::protocol-version))
    (let* ((hello (node-envelope-payload first :hello))
           (node-name (slot-value hello 'gr8s.node.v1::node-name))
           (node (get-node (node-grpc-server-store server) node-name))
           (operations (take-node-operations server node-name))
           (session (make-node-agent-session stream))
           (heartbeat-interval
             (max 1 (floor (node-grpc-server-heartbeat-timeout-seconds server)
                           2))))
      (bt:with-lock-held ((node-grpc-server-lock server))
        (setf (gethash node-name (node-grpc-server-sessions server)) session))
      (send-node-agent-envelope
       session
       (make-server-envelope
        :hello
        (make-instance 'gr8s.node.v1::server-hello
                       :node-id (node-record-id node)
                       :heartbeat-interval-seconds heartbeat-interval
                       :assigned-pod-cidr (node-record-pod-cidr node))
        :sequence 1))
      (send-node-agent-envelope
       session
       (make-server-envelope :desired-state
                             (current-node-snapshot server node-name)
                             :sequence 2))
      (loop for operation in operations
            for sequence from 3
            do (setf (pending-node-operation-session operation) session)
               (send-node-agent-envelope
                session
                (make-server-envelope
                 :operation-request
                 (pending-node-operation-request operation)
                 :sequence sequence)))
      (unwind-protect
           (loop for envelope = (ag-grpc:stream-recv stream)
                 while envelope
                 do (handle-node-agent-envelope server node-name envelope))
        (bt:with-lock-held ((node-grpc-server-lock server))
          (when (eq session
                    (gethash node-name (node-grpc-server-sessions server)))
            (remhash node-name (node-grpc-server-sessions server))))
        (fail-node-session-operations server session)))))

(defun handle-node-connect (server context stream)
  (handler-case
      (handle-node-connect-internal server context stream)
    (error (condition)
      ;; A malformed peer gets a protocol-level explanation and only its RPC
      ;; stream ends. The listener and other node sessions remain untouched.
      (send-node-protocol-error stream condition))))

(defun monitor-node-heartbeats (server)
  (loop until (node-grpc-server-stopping-p server)
        do (expire-node-heartbeats
            (node-grpc-server-store server)
            (- (get-universal-time)
               (node-grpc-server-heartbeat-timeout-seconds server)))
           (sleep 0.05)))

(defun handle-node-enrollment (server request context)
  (declare (ignore context))
  (let ((pki (node-grpc-server-pki server)))
    (unless pki
      (error "Node enrollment is disabled"))
    (ensure-node-protocol-version
     (slot-value request 'gr8s.node.v1::protocol-version))
    (let* ((node-name (slot-value request 'gr8s.node.v1::node-name))
           (token (slot-value request 'gr8s.node.v1::join-token))
           (csr (slot-value request 'gr8s.node.v1::certificate-request))
           (certificate
             (enroll-node-csr pki node-name token
                              (cluster-pki-ca-fingerprint pki) csr))
           (node-id (generate-uid))
           (pod-cidr
             (allocate-node-pod-cidr
              (node-grpc-server-store server)
              (node-grpc-server-cluster-pod-cidr server)
              (node-grpc-server-node-prefix server))))
      (register-node
       (node-grpc-server-store server)
       (make-node-record :id node-id :name node-name :pod-cidr pod-cidr))
      (make-instance
       'gr8s.node.v1::enroll-response
       :protocol-version +node-protocol-version+
       :node-id node-id
       :node-certificate (pki-ascii-octets certificate)
       :ca-certificate
       (pki-ascii-octets
        (uiop:read-file-string (cluster-pki-ca-certificate-path pki)))))))

(defun start-node-grpc-server (store &key (host "127.0.0.1") (port 0)
                                            (heartbeat-timeout-seconds 15)
                                            pki
                                            (cluster-pod-cidr "10.88.0.0/16")
                                            (node-prefix 24))
  (unless (plusp heartbeat-timeout-seconds)
    (error "Heartbeat timeout must be positive"))
  (let* ((grpc-server (ag-grpc:make-grpc-server port :host host))
         (server (%make-node-grpc-server
                  :store store
                  :grpc-server grpc-server
                  :port port
                  :heartbeat-timeout-seconds heartbeat-timeout-seconds
                  :pki pki
                  :cluster-pod-cidr cluster-pod-cidr
                  :node-prefix node-prefix)))
    (gr8s.node.v1::register-node-service-service
     grpc-server
     :connect-handler (lambda (context stream)
                        (handle-node-connect server context stream)))
    (when pki
      (gr8s.node.v1::register-enrollment-service-service
       grpc-server
       :enroll-handler (lambda (request context)
                         (handle-node-enrollment server request context))))
    (setf (node-grpc-server-thread server)
          (bt:make-thread
           (lambda () (ag-grpc:server-start grpc-server))
           :name "gr8s node gRPC server"))
    (loop repeat 500
          until (and (eql :running (ag-grpc:server-state grpc-server))
                     (ag-grpc::server-socket grpc-server))
          do (sleep 0.01))
    (unless (ag-grpc::server-socket grpc-server)
      (error "Node gRPC server failed to start listening"))
    (setf (node-grpc-server-port server)
          (usocket:get-local-port (ag-grpc::server-socket grpc-server))
          (node-grpc-server-monitor-thread server)
          (bt:make-thread (lambda () (monitor-node-heartbeats server))
                          :name "gr8s node heartbeat monitor"))
    server))

(defun stop-node-grpc-server (server)
  (setf (node-grpc-server-stopping-p server) t)
  (ignore-errors (ag-grpc:server-stop (node-grpc-server-grpc-server server)))
  (dolist (thread (list (node-grpc-server-monitor-thread server)
                        (node-grpc-server-thread server)))
    ;; Some usocket backends do not wake a thread already blocked in ACCEPT
    ;; when another thread closes the listener. Never let shutdown inherit
    ;; that platform quirk as an unbounded join.
    (when thread
      (loop repeat 100
            while (bt:thread-alive-p thread)
            do (sleep 0.01))
      (when (bt:thread-alive-p thread)
        ;; On SBCL/Linux a thread blocked in ACCEPT can retain the listening
        ;; file descriptor even after another thread closes its socket object.
        ;; The server has already closed every active connection, so ending
        ;; this otherwise-unwakeable acceptor is the final shutdown step.
        (ignore-errors (bt:destroy-thread thread)))
      (ignore-errors (bt:join-thread thread))))
  server)

(defun publish-node-desired-state (server node-name snapshot)
  (get-node (node-grpc-server-store server) node-name)
  (unless (typep snapshot 'gr8s.node.v1::desired-state-snapshot)
    (error "Desired state must be a DesiredStateSnapshot"))
  (let ((revision nil)
        (session nil))
    (bt:with-lock-held ((node-grpc-server-lock server))
      (setf revision
            (1+ (gethash node-name (node-grpc-server-revisions server) 0)))
      (setf (slot-value snapshot 'gr8s.node.v1::revision) revision
            (gethash node-name (node-grpc-server-revisions server)) revision
            (gethash node-name (node-grpc-server-snapshots server)) snapshot
            session (gethash node-name (node-grpc-server-sessions server))))
    (when session
      (handler-case
          (send-node-agent-envelope
           session
           (make-server-envelope :desired-state snapshot :sequence 0))
        (error () nil)))
    revision))

(defun node-session-acknowledged-revision (server node-name)
  (bt:with-lock-held ((node-grpc-server-lock server))
    (gethash node-name (node-grpc-server-acknowledged-revisions server) 0)))

(defun ascii-octets-to-string (octets)
  (map 'string #'code-char octets))

(defun verify-enrollment-ca-pin (ca-pem expected-fingerprint)
  (let* ((certificate (certificate-from-pem ca-pem))
         (fingerprint
           (octets-to-hex (pure-tls:certificate-fingerprint certificate))))
    (unless (string-equal fingerprint expected-fingerprint)
      (pki-fail "ca-pin-mismatch"
                "Enrollment response CA fingerprint does not match"))))

(defun enroll-node-over-grpc (host port node-name token ca-fingerprint
                              private-key-path certificate-path ca-certificate-path)
  (let* ((csr (generate-node-key-and-csr node-name private-key-path))
         (channel (ag-grpc:make-channel host port :timeout 10)))
    (unwind-protect
         (let* ((stub (gr8s.node.v1::make-enrollment-service-stub channel))
                (request
                  (make-instance
                   'gr8s.node.v1::enroll-request
                   :protocol-version +node-protocol-version+
                   :node-name node-name
                   :join-token token
                   :certificate-request csr)))
           (multiple-value-bind (response status call)
               (gr8s.node.v1::enrollment-service-enroll
                stub request :timeout 10)
             (declare (ignore status call))
             (ensure-node-protocol-version
              (slot-value response 'gr8s.node.v1::protocol-version))
             (let ((certificate
                     (ascii-octets-to-string
                      (slot-value response 'gr8s.node.v1::node-certificate)))
                   (ca-certificate
                     (ascii-octets-to-string
                      (slot-value response 'gr8s.node.v1::ca-certificate))))
               (verify-enrollment-ca-pin ca-certificate ca-fingerprint)
               (write-private-text-atomically certificate-path certificate)
               (write-private-text-atomically ca-certificate-path ca-certificate)
               (slot-value response 'gr8s.node.v1::node-id))))
      (ignore-errors (ag-grpc:channel-close channel)))))

(defun make-agent-identity (node-name &key (node-id "") (revision 0))
  (let ((identity (make-hash-table :test #'equal)))
    (setf (gethash "nodeName" identity) node-name
          (gethash "nodeId" identity) node-id
          (gethash "lastAppliedRevision" identity) revision)
    identity))

(defun load-agent-identity (path node-name)
  (if (probe-file path)
      (let ((identity (com.inuoe.jzon:parse path)))
        (unless (string= node-name (gethash "nodeName" identity ""))
          (error "Agent identity belongs to node ~S, not ~S"
                 (gethash "nodeName" identity) node-name))
        identity)
      (make-agent-identity node-name)))

(defun persist-agent-identity (path identity)
  (write-private-text-atomically
   path
   (with-output-to-string (stream)
     (com.inuoe.jzon:stringify identity :stream stream))))

(defun require-server-envelope (envelope variant)
  (unless envelope
    (error "Node session closed while waiting for ~S" variant))
  (ensure-node-protocol-version
   (slot-value envelope 'gr8s.node.v1::protocol-version))
  (node-envelope-payload envelope variant))

(defstruct (agent-node-session
             (:constructor make-agent-node-session (stream)))
  stream
  (sequence 0)
  (send-lock (bt:make-lock "gr8s agent node session send")))

(defun send-agent-session-envelope (session variant payload)
  (bt:with-lock-held ((agent-node-session-send-lock session))
    (ag-grpc:stream-send
     (agent-node-session-stream session)
     (make-agent-envelope
      variant payload :sequence (incf (agent-node-session-sequence session))))))

(defun apply-node-snapshot-and-respond
    (session identity identity-path snapshot apply-snapshot)
  (let ((revision (slot-value snapshot 'gr8s.node.v1::revision))
        (last-applied (gethash "lastAppliedRevision" identity 0))
        (statuses nil))
    (when (> revision last-applied)
      (let ((result (funcall apply-snapshot snapshot)))
        ;; Snapshot applicators written before status reporting commonly
        ;; return an incidental value. Only an explicit status list is sent.
        (when (and (listp result)
                   (every (lambda (status)
                            (typep status
                                   'gr8s.node.v1::pod-observed-status))
                          result))
          (setf statuses result)))
      (setf (gethash "lastAppliedRevision" identity) revision)
      ;; Durable state precedes the ack: after a crash, the agent may repeat
      ;; an ack but never claims work it did not persist.
      (persist-agent-identity identity-path identity))
    (when statuses
      (send-agent-session-envelope
       session :status
       (make-instance 'gr8s.node.v1::node-status :pods statuses)))
    (send-agent-session-envelope
     session :snapshot-ack
     (make-instance 'gr8s.node.v1::snapshot-ack
                    :revision revision :applied t))))

(defun handle-node-server-envelope
    (session envelope identity identity-path apply-snapshot operation-handler)
  (ensure-node-protocol-version
   (slot-value envelope 'gr8s.node.v1::protocol-version))
  (case (slot-value envelope 'gr8s.node.v1::payload-case)
    (:desired-state
     (apply-node-snapshot-and-respond
      session identity identity-path
      (slot-value envelope 'gr8s.node.v1::desired-state)
      apply-snapshot))
    ((:operation-request :operation-input :operation-cancel)
     (unless operation-handler
       (error "Agent has no operation handler"))
     (let ((variant (slot-value envelope 'gr8s.node.v1::payload-case)))
       (funcall
        operation-handler variant
        (slot-value envelope (find-symbol (symbol-name variant) :gr8s.node.v1))
        (lambda (reply-variant reply-payload)
          (send-agent-session-envelope session reply-variant reply-payload)))))
    (:protocol-error
     (error "Node server rejected the session: ~A"
            (slot-value
             (slot-value envelope 'gr8s.node.v1::protocol-error)
             'gr8s.node.v1::message)))
    (otherwise
     (error "Unexpected server payload ~S"
            (slot-value envelope 'gr8s.node.v1::payload-case)))))

(defstruct (node-session-control
             (:constructor %make-node-session-control))
  context
  cancel-function
  (lock (bt:make-lock "gr8s node session cancellation")))

(defun make-node-session-control ()
  (multiple-value-bind (context cancel-function)
      (cl-cancel:with-cancel (cl-cancel:background))
    (%make-node-session-control
     :context context :cancel-function cancel-function)))

(defun cancel-node-session (control)
  (let ((cancel-function nil))
    (bt:with-lock-held ((node-session-control-lock control))
      (setf cancel-function (node-session-control-cancel-function control)
            (node-session-control-cancel-function control) nil))
    (when cancel-function
      (funcall cancel-function)))
  nil)

(defun node-session-cancelled-p (control)
  (cl-cancel:done-p (node-session-control-context control)))

(define-condition node-session-interrupted (error) ())

(defun agent-session-monitor
    (session control session-thread heartbeat-interval
     stop-predicate finished-p finish-session)
  (let ((next-heartbeat
          (+ (get-internal-real-time)
             (* heartbeat-interval internal-time-units-per-second))))
    (handler-case
        (loop until (funcall finished-p)
              do (when (or (node-session-cancelled-p control)
                           (funcall stop-predicate))
                   (cancel-node-session control)
                   (funcall finish-session)
                   ;; POSIX does not require close(2) or shutdown(2) in one
                   ;; thread to wake another thread already blocked in poll(2).
                   ;; Interrupt the owner so it unwinds through the ordinary
                   ;; gRPC cleanup path instead of destroying the thread.
                   (when (bt:thread-alive-p session-thread)
                     (bt:interrupt-thread
                      session-thread
                      (lambda () (error 'node-session-interrupted))))
                   (return))
                 (when (>= (get-internal-real-time) next-heartbeat)
                   (send-agent-session-envelope
                    session :heartbeat
                    (make-instance 'gr8s.node.v1::heartbeat))
                   (setf next-heartbeat
                         (+ (get-internal-real-time)
                            (* heartbeat-interval
                               internal-time-units-per-second))))
                 (sleep 0.05))
      (error ()
        (funcall finish-session)))))

(defun run-one-node-session
    (host port node-name identity-path apply-snapshot operation-handler
     one-shot-p control stop-predicate)
  (let* ((identity (load-agent-identity identity-path node-name))
         (session-thread (bt:current-thread))
         (session-timeout (and one-shot-p 5))
         (channel (ag-grpc:make-channel host port :timeout session-timeout))
         (monitor-thread nil)
         (operation-session-p nil)
         (session-finished-p nil)
         (finish-lock (bt:make-lock "gr8s agent node session finish")))
    (labels ((finished-p ()
               (bt:with-lock-held (finish-lock) session-finished-p))
             (finish-session ()
               (let ((close-p nil))
                 (bt:with-lock-held (finish-lock)
                   (unless session-finished-p
                     (setf session-finished-p t
                           close-p t)))
                 (when close-p
                   (ignore-errors (ag-grpc:channel-close channel))))))
    (cl-cancel:with-cancellable
        (session-context (node-session-control-context control))
      (declare (ignore session-context))
      (unwind-protect
         (let* ((stub (gr8s.node.v1::make-node-service-stub channel))
                (stream (gr8s.node.v1::node-service-connect
                         stub :timeout session-timeout))
                (session (make-agent-node-session stream)))
           (send-agent-session-envelope
            session :hello
             (make-instance 'gr8s.node.v1::node-hello
                            :node-name node-name
                            :boot-id (generate-uid)
                            :agent-version "gr8s"
                            :last-applied-revision
                            (gethash "lastAppliedRevision" identity 0)))
           (send-agent-session-envelope
            session :heartbeat (make-instance 'gr8s.node.v1::heartbeat))
           (let* ((server-hello
                    (require-server-envelope
                     (ag-grpc:stream-read-message stream) :hello))
                  (node-id (slot-value server-hello 'gr8s.node.v1::node-id))
                  (persisted-node-id (gethash "nodeId" identity "")))
             (when (and (plusp (length persisted-node-id))
                        (not (string= persisted-node-id node-id)))
               (error "Server node identity changed from ~S to ~S"
                      persisted-node-id node-id))
             (setf (gethash "nodeId" identity) node-id)
             (unless one-shot-p
               (setf monitor-thread
                     (bt:make-thread
                      (lambda ()
                        (agent-session-monitor
                         session control session-thread
                         (slot-value server-hello
                                     'gr8s.node.v1::heartbeat-interval-seconds)
                         stop-predicate #'finished-p #'finish-session))
                      :name "gr8s agent session heartbeat")))
             (let* ((snapshot
                      (require-server-envelope
                       (ag-grpc:stream-read-message stream) :desired-state)))
               (apply-node-snapshot-and-respond
                session identity identity-path snapshot apply-snapshot)
               (setf operation-session-p t)
               (if one-shot-p
                   (progn
                     (ag-grpc:stream-close-send stream)
                     (loop while (ag-grpc:stream-read-message stream)))
                   (loop for envelope = (ag-grpc:stream-read-message stream)
                         while envelope
                         do (handle-node-server-envelope
                             session envelope identity identity-path
                             apply-snapshot operation-handler))))))
      (finish-session)
      (when (and operation-session-p operation-handler)
        ;; Operation emitters close over this gRPC session.  Give the agent a
        ;; lifecycle edge on every disconnect so it can close upstream
        ;; streams without trying to reply through a dead callback.
        (ignore-errors
          (funcall operation-handler :session-closed nil nil)))
      (when monitor-thread
        (ignore-errors (bt:join-thread monitor-thread)))
      (ignore-errors (ag-grpc:channel-close channel)))))))

(defun run-node-session (host port node-name identity-path apply-snapshot
                         &key max-sessions (reconnect-delay 1)
                           operation-handler
                           control
                           (stop-predicate (constantly nil)))
  (let ((completed 0)
        (control (or control (make-node-session-control))))
    (loop until (or (node-session-cancelled-p control)
                    (funcall stop-predicate))
          do (handler-case
          (progn
            (run-one-node-session host port node-name identity-path
                                  apply-snapshot operation-handler
                                  (not (null max-sessions)) control stop-predicate)
            (incf completed)
            (when (and max-sessions (>= completed max-sessions))
              (return completed)))
        (error (condition)
          (when max-sessions
            (error condition))))
             (unless (or (node-session-cancelled-p control)
                         (funcall stop-predicate))
               (sleep reconnect-delay)))
    completed))
