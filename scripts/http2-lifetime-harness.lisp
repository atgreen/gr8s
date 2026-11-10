;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Native, unprivileged loopback probe for one long-lived RPC connection.
(in-package #:cl-user)

(defun lifetime-await (predicate)
  (loop repeat 1000 when (funcall predicate) return t do (sleep 0.01)
        finally (error "HTTP2 lifetime probe timed out")))

(defun lifetime-stream-count (mux)
  (bt2:with-lock-held ((ag-http2::multiplexer-lock mux))
    (hash-table-count (ag-http2::multiplexer-streams mux))))

(defun lifetime-no-delay (connection)
  (setf (sb-bsd-sockets:sockopt-tcp-nodelay
         (usocket:socket (ag-http2::connection-socket connection))) t))

(defun http2-lifetime-probe ()
  (let* ((server (ag-grpc:make-grpc-server 0 :host "127.0.0.1"))
         (thread nil) (channel nil) (server-mux nil) (calls 0) (peak 0)
         (samples nil) (baseline nil) (plateau-p t) (allowance (* 1024 1024)))
    (ag-grpc::server-register-handler
     server "/lifetime.Probe/Echo"
     (lambda (request ctx)
       (declare (ignore request))
       (let* ((connection (ag-grpc::context-connection ctx))
              (mux (ag-http2:connection-multiplexer connection)))
         (unless server-mux (lifetime-no-delay connection) (setf server-mux mux))
         (unless (eq mux server-mux) (error "Probe unexpectedly reconnected"))
         (setf peak (max peak (lifetime-stream-count mux)))
         (incf calls))
       (make-instance 'gr8s.node.v1::raft-ack))
     :request-type 'gr8s.node.v1::raft-ack :response-type 'gr8s.node.v1::raft-ack)
    (unwind-protect
         (progn
           (setf thread (bt:make-thread (lambda () (ag-grpc:server-start server))))
           (lifetime-await (lambda () (ag-grpc::server-socket server)))
           (setf channel (gr8s::make-raft-channel
                          nil "127.0.0.1" (usocket:get-local-port (ag-grpc::server-socket server)) 5))
           (lifetime-no-delay (ag-grpc::channel-connection channel))
           ;; Warm caches before comparing live bytes after full GC. Keep both
           ;; sides connected through all samples; teardown cannot hide retention.
           (dotimes (batch 6)
             ;; Exercise both explicit cancellation and nonlocal scope exits
             ;; over this same connection, without sending request messages.
             (dotimes (i 50)
               (let ((stream (ag-grpc:call-bidirectional-streaming channel "/lifetime.Probe/Echo")))
                 (ag-grpc:channel-cancel-stream channel (ag-grpc::bidi-stream-id stream))))
             (dotimes (i 50)
               (assert (eq :aborted
                           (catch 'lifetime-abort
                             (ag-grpc:with-bidi-stream (stream channel "/lifetime.Probe/Echo")
                               (throw 'lifetime-abort :aborted))))))
             ;; A successful reply also drains earlier reset frames on this connection.
             (dotimes (i 1000)
               (ag-grpc:call-unary channel "/lifetime.Probe/Echo"
                                   (make-instance 'gr8s.node.v1::raft-ack)
                                   :response-type 'gr8s.node.v1::raft-ack :timeout 0.75))
             (lifetime-await (lambda () (zerop (lifetime-stream-count server-mux))))
             (let ((client-mux (ag-http2:connection-multiplexer (ag-grpc::channel-connection channel))))
               (assert (zerop (lifetime-stream-count client-mux)))
               (sb-ext:gc :full t)
               (let ((live (sb-kernel:dynamic-usage)))
                 (unless baseline (setf baseline live))
                 (unless (<= live (+ baseline allowance)) (setf plateau-p nil))
                 (push (gr8s::core-object "calls" (* (1+ batch) 1000)
                                         "liveBytesAfterFullGc" live
                                         "pendingDeadlineEntries"
                                         (bt2:with-lock-held (cl-cancel::*timer-lock*)
                                           (length (cl-cancel::heap-data cl-cancel::*deadline-heap*)))
                                         "clientStreams" (lifetime-stream-count client-mux)
                                         "serverStreams" (lifetime-stream-count server-mux)) samples))))
           (assert (= 6000 calls))
           (assert (= 1 peak))
           (gr8s::core-object "passed" plateau-p "nativeHarness" t "productionServe" nil
                              "vmAcceptance" nil
                              "heapLimitMiB" (/ (sb-ext:dynamic-space-size) (* 1024 1024))
                              "calls" calls "connections" 1 "peakServerStreams" peak
                              "rpcTimeoutSeconds" 0.75
                              "directCancellations" 300 "abortedBidiScopes" 300
                              "growthAllowanceBytes" allowance "samples" (coerce (nreverse samples) 'vector)))
      (when channel (ignore-errors (ag-grpc:channel-close channel)))
      (ag-grpc:server-stop server)
      (when thread (bt:join-thread thread)))))

(defun http2-lifetime-main ()
  (handler-case
      (let ((result (http2-lifetime-probe)))
        (write-line (com.inuoe.jzon:stringify result))
        (uiop:quit (if (gethash "passed" result) 0 1)))
    (error (condition)
      (format *error-output* "HTTP2 lifetime probe failed: ~A~%" condition)
      (uiop:quit 1))))
