(in-package #:gr8s)

(defconstant +agent-cni-maximum-frame-size+ (* 16 1024 1024))
(defconstant +linux-sol-socket+ 1)
(defconstant +linux-so-peercred+ 17)

#+linux
(sb-alien:define-alien-type linux-ucred
  (sb-alien:struct linux-ucred
    (pid sb-alien:int)
    (uid sb-alien:unsigned-int)
    (gid sb-alien:unsigned-int)))

#+linux
(sb-alien:define-alien-routine ("getsockopt" %linux-getsockopt) sb-alien:int
  (descriptor sb-alien:int)
  (level sb-alien:int)
  (option sb-alien:int)
  (value (* linux-ucred))
  (length (* sb-alien:unsigned-int)))

(defstruct (agent-cni-server (:constructor %make-agent-cni-server))
  path
  socket
  handler
  peer-authorizer
  thread
  (stop-requested-p nil)
  (lock (bt:make-lock "gr8s agent CNI server")))

(defun agent-cni-peer-credentials (socket)
  #+linux
  (sb-alien:with-alien ((credentials linux-ucred)
                        (length sb-alien:unsigned-int 12))
    (unless (zerop
             (%linux-getsockopt
              (sb-bsd-sockets:socket-file-descriptor socket)
              +linux-sol-socket+ +linux-so-peercred+
              (sb-alien:addr credentials) (sb-alien:addr length)))
      (invalid-cni "could not authenticate the agent CNI peer: ~A"
                   (sb-int:strerror (sb-alien:get-errno))))
    (unless (= length 12)
      (invalid-cni "the kernel returned an invalid agent CNI credential size"))
    (values (sb-alien:slot credentials 'pid)
            (sb-alien:slot credentials 'uid)
            (sb-alien:slot credentials 'gid)))
  #-linux
  (declare (ignore socket))
  #-linux
  (error "agent CNI peer credentials require Linux"))

(defun authorize-agent-cni-peer (pid uid gid)
  (declare (ignore pid gid))
  (= uid (sb-posix:geteuid)))

(defun write-agent-cni-frame (stream message)
  (let* ((payload (ag-proto:serialize-to-bytes message))
         (length (length payload)))
    (when (> length +agent-cni-maximum-frame-size+)
      (invalid-cni "agent CNI message exceeds ~D bytes"
                   +agent-cni-maximum-frame-size+))
    (write-byte (ldb (byte 8 24) length) stream)
    (write-byte (ldb (byte 8 16) length) stream)
    (write-byte (ldb (byte 8 8) length) stream)
    (write-byte (ldb (byte 8 0) length) stream)
    (write-sequence payload stream)
    (finish-output stream)))

(defun read-agent-cni-frame (stream type)
  (let ((first (read-byte stream nil nil)))
    (unless first
      (invalid-cni "agent CNI peer closed without a response"))
    (let* ((second (read-byte stream))
           (third (read-byte stream))
           (fourth (read-byte stream))
           (length (logior (ash first 24)
                           (ash second 16)
                           (ash third 8)
                           fourth)))
      (when (> length +agent-cni-maximum-frame-size+)
        (invalid-cni "agent CNI frame length ~D exceeds the limit" length))
      (let ((payload (make-array length :element-type '(unsigned-byte 8))))
        (unless (= length (read-sequence payload stream))
          (invalid-cni "agent CNI frame was truncated"))
        (ag-proto:deserialize-from-bytes type payload)))))

(defun agent-cni-error-response (condition)
  (make-instance
   'gr8s.node.v1::cni-response
   :protocol-version +node-protocol-version+
   :success nil
   :error-code 100
   :error-message (princ-to-string condition)))

(defun empty-octet-vector ()
  (make-array 0 :element-type '(unsigned-byte 8)))

(defun handle-agent-cni-request
    (request &key (operations (make-cni-operations)) (chained t))
  (handler-case
      (progn
        (ensure-node-protocol-version
         (slot-value request 'gr8s.node.v1::protocol-version))
        (let* ((command (slot-value request 'gr8s.node.v1::command))
               (configuration-text
                 (trivial-utf-8:utf-8-bytes-to-string
                  (slot-value request
                              'gr8s.node.v1::network-configuration)))
               (context
                 (make-cni-context
                  :container-id
                  (slot-value request 'gr8s.node.v1::container-id)
                  :netns
                  (slot-value request 'gr8s.node.v1::network-namespace)
                  :interface-name
                  (slot-value request 'gr8s.node.v1::interface-name)))
               (result
                 (dispatch-cni-command
                  command configuration-text context operations :chained chained)))
          (make-instance
           'gr8s.node.v1::cni-response
           :protocol-version +node-protocol-version+
           :success t
           :result-json
           (if result
               (trivial-utf-8:string-to-utf-8-bytes
                (com.inuoe.jzon:stringify result))
               (empty-octet-vector)))))
    (error (condition)
      (agent-cni-error-response condition))))

(defun serve-agent-cni-client (server socket)
  (let ((stream nil))
    (unwind-protect
         (progn
           (setf stream
                 (sb-bsd-sockets:socket-make-stream
                  socket :input t :output t
                  :element-type '(unsigned-byte 8) :buffering :none))
           (let ((response
                   (handler-case
                       (progn
                         (multiple-value-bind (pid uid gid)
                             (agent-cni-peer-credentials socket)
                           (unless (funcall
                                    (agent-cni-server-peer-authorizer server)
                                    pid uid gid)
                             (invalid-cni
                              "agent CNI peer UID ~D is not authorized" uid)))
                         (let ((request
                               (read-agent-cni-frame
                                stream 'gr8s.node.v1::cni-request)))
                           (ensure-node-protocol-version
                            (slot-value request
                                        'gr8s.node.v1::protocol-version))
                           (let ((result
                                   (funcall (agent-cni-server-handler server)
                                            request)))
                             (unless (typep result 'gr8s.node.v1::cni-response)
                               (invalid-cni
                                "agent CNI handler returned ~S, not CniResponse"
                                (type-of result)))
                             result)))
                     (error (condition)
                       (agent-cni-error-response condition)))))
             (write-agent-cni-frame stream response)))
      (if stream
          (ignore-errors (close stream))
          (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun agent-cni-server-stopping-p (server)
  (bt:with-lock-held ((agent-cni-server-lock server))
    (agent-cni-server-stop-requested-p server)))

(defun run-agent-cni-server (server)
  (loop until (agent-cni-server-stopping-p server)
        do (when (sb-sys:wait-until-fd-usable
                  (sb-bsd-sockets:socket-file-descriptor
                   (agent-cni-server-socket server))
                  :input 0.1)
             (handler-case
                 (let ((client
                         (sb-bsd-sockets:socket-accept
                          (agent-cni-server-socket server))))
                   (unless (agent-cni-server-stopping-p server)
                     (serve-agent-cni-client server client)))
               (error (condition)
                 (unless (agent-cni-server-stopping-p server)
                   (format *error-output* "gr8s agent CNI error: ~A~%"
                           condition)))))))

(defun start-agent-cni-server
    (path handler &key (peer-authorizer #'authorize-agent-cni-peer))
  #+sbcl
  (let* ((socket-path (namestring (pathname path)))
         (directory (uiop:pathname-directory-pathname (pathname socket-path)))
         (socket
           (make-instance 'sb-bsd-sockets:local-socket
                          :type :stream :protocol 0))
         (server nil))
    (ensure-directories-exist (merge-pathnames ".socket-directory" directory))
    (ignore-errors (delete-file socket-path))
    (handler-case
        (progn
          (sb-bsd-sockets:socket-bind socket socket-path)
          (sb-bsd-sockets:socket-listen socket 16)
          (sb-posix:chmod socket-path #o600)
          (setf server
                (%make-agent-cni-server
                 :path socket-path :socket socket :handler handler
                 :peer-authorizer peer-authorizer))
          (setf (agent-cni-server-thread server)
                (bt:make-thread
                 (lambda () (run-agent-cni-server server))
                 :name "gr8s agent CNI server"))
          server)
      (error (condition)
        (ignore-errors (sb-bsd-sockets:socket-close socket))
        (ignore-errors (delete-file socket-path))
        (error condition))))
  #-sbcl
  (declare (ignore path handler peer-authorizer))
  #-sbcl
  (error "gr8s agent CNI sockets require SBCL on Linux"))

(defun stop-agent-cni-server (server)
  (let ((thread nil))
    (bt:with-lock-held ((agent-cni-server-lock server))
      (setf (agent-cni-server-stop-requested-p server) t
            thread (agent-cni-server-thread server)))
    (ignore-errors
      (sb-bsd-sockets:socket-close (agent-cni-server-socket server)))
    (when (and thread (not (eq thread (bt:current-thread))))
      (ignore-errors (bt:join-thread thread)))
    (ignore-errors (delete-file (agent-cni-server-path server))))
  nil)

(defun call-agent-cni (path request &key (timeout 5))
  #+sbcl
  (let ((socket
          (make-instance 'sb-bsd-sockets:local-socket
                         :type :stream :protocol 0))
        (stream nil))
    (handler-case
        (unwind-protect
             (sb-ext:with-timeout timeout
               (sb-bsd-sockets:socket-connect socket path)
               (setf stream
                     (sb-bsd-sockets:socket-make-stream
                      socket :input t :output t
                      :element-type '(unsigned-byte 8) :buffering :none))
               (write-agent-cni-frame stream request)
               (let ((response
                       (read-agent-cni-frame
                        stream 'gr8s.node.v1::cni-response)))
                 (ensure-node-protocol-version
                  (slot-value response 'gr8s.node.v1::protocol-version))
                 response))
          (if stream
              (ignore-errors (close stream))
              (ignore-errors (sb-bsd-sockets:socket-close socket))))
      (cni-error (condition) (error condition))
      (sb-ext:timeout ()
        (invalid-cni "timed out waiting for the gr8s agent CNI service"))
      (error (condition)
        (invalid-cni "gr8s agent CNI service is unavailable: ~A" condition))))
  #-sbcl
  (declare (ignore path request timeout))
  #-sbcl
  (error "gr8s agent CNI sockets require SBCL on Linux"))
