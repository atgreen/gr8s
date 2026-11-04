;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Own Unix gRPC sockets across HTTP/2 negotiation and release partially
;;;; constructed transports on errors, deadlines and asynchronous cancellation.

(in-package #:gr8s)

#+sbcl
(defun make-unix-grpc-channel (path &key (timeout 30))
  "Open an ag-gRPC channel over the filesystem Unix socket at PATH."
  (let ((native-socket
          (make-instance 'sb-bsd-sockets:local-socket
                         :type :stream :protocol 0))
        (wrapped-socket nil)
        (channel nil)
        (ready nil))
    (unwind-protect
        (progn
          (sb-bsd-sockets:socket-connect native-socket path)
          (let ((stream
                  (sb-bsd-sockets:socket-make-stream
                   native-socket :input t :output t
                   :element-type '(unsigned-byte 8)
                   :buffering :full)))
            (setf wrapped-socket
                  (make-instance 'usocket:stream-usocket
                                 :socket native-socket :stream stream))
            (let ((connection
                    (make-instance 'ag-http2:http2-connection
                                   :socket wrapped-socket
                                   :stream stream
                                   :tls-p nil
                                   :client-p t)))
              (setf (ag-http2:connection-multiplexer connection)
                    (ag-http2::make-stream-multiplexer :client-p t))
              (ag-http2::connection-handshake connection)
              (setf channel
                    (ag-grpc:make-channel "localhost" 0
                                          :connect nil
                                          :timeout timeout)
                    (ag-grpc:channel-connection channel) connection)))
          (setf ready t)
          channel)
      ;; A deadline or private cancellation condition need not be an ERROR.
      ;; Do not transfer ownership until the whole constructor has succeeded.
      (unless ready
        (if wrapped-socket
            (ignore-errors (usocket:socket-close wrapped-socket))
            (ignore-errors (sb-bsd-sockets:socket-close native-socket :abort t)))))))

#-sbcl
(defun make-unix-grpc-channel (path &key (timeout 30))
  (declare (ignore path timeout))
  (error "gr8s's Unix gRPC transport currently requires SBCL"))
