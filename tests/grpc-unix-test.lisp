(in-package #:gr8s/tests)

(in-suite gr8s)

#+sbcl
(defun make-unix-http2-test-server (path)
  (let ((listener (make-instance 'sb-bsd-sockets:local-socket
                                 :type :stream :protocol 0))
        (release (bt:make-semaphore :name "release Unix HTTP/2 test server")))
    (sb-bsd-sockets:socket-bind listener path)
    (sb-bsd-sockets:socket-listen listener 1)
    (values
     listener
     (bt:make-thread
      (lambda ()
        (let ((accepted (sb-bsd-sockets:socket-accept listener)))
          (unwind-protect
               (let* ((stream
                        (sb-bsd-sockets:socket-make-stream
                         accepted :input t :output t
                         :element-type '(unsigned-byte 8)
                         :buffering :full))
                      (socket
                        (make-instance 'usocket:stream-usocket
                                       :socket accepted :stream stream))
                      (connection
                        (make-instance 'ag-http2:http2-connection
                                       :socket socket :stream stream
                                       :tls-p nil :client-p nil)))
                 (setf (ag-http2:connection-multiplexer connection)
                       (ag-http2::make-stream-multiplexer :client-p nil))
                 (ag-http2:server-connection-handshake connection)
                 ;; Keep the peer open while the client sends its SETTINGS
                 ;; acknowledgement.  Closing immediately after the server
                 ;; handshake makes this test depend on thread scheduling.
                 (bt:wait-on-semaphore release))
            (ignore-errors
              (sb-bsd-sockets:socket-close accepted)))))
      :name "gr8s Unix HTTP/2 test server")
     release)))

#+sbcl
(test ag-grpc-channel-connects-over-a-unix-socket
  (if (not (fboundp 'gr8s.protocol::make-unix-grpc-channel))
      (is (fboundp 'gr8s.protocol::make-unix-grpc-channel))
      (let ((path (format nil "/tmp/gr8s-grpc-~36R.sock"
                          (random (expt 36 8))))
            (listener nil)
            (server-thread nil)
            (release-server nil)
            (channel nil))
        (ignore-errors (delete-file path))
        (unwind-protect
             (progn
               (multiple-value-setq (listener server-thread release-server)
                 (make-unix-http2-test-server path))
               (setf channel (gr8s.protocol::make-unix-grpc-channel path))
               (is (ag-grpc::channel-connected-p channel)))
          (when channel (ag-grpc:channel-close channel))
          (when listener
            (ignore-errors (sb-bsd-sockets:socket-close listener)))
          (when release-server (bt:signal-semaphore release-server))
          (when server-thread (bt:join-thread server-thread))
          (ignore-errors (delete-file path))))))

#-sbcl
(test ag-grpc-unix-sockets-require-sbcl
  (skip "Unix gRPC transport is currently implemented for SBCL on Linux"))
