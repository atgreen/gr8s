;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Execute actual Kubernetes probe transports against an exact CRI attempt or
;;;; Pod IP. Bound the complete operation, disable HTTP proxies, implement local
;;;; redirects and header overrides, and use the standard gRPC Health/Check wire
;;;; protocol. This module never infers success from container Running status.

(in-package #:gr8s)

(defun probe-http-uri (action host port)
  "Parse the declared path first, then replace its authority as kubelet does."
  (let* ((path (gethash "path" action "/"))
         (uri (handler-case (puri:parse-uri path)
                (error () (let ((fallback (puri:parse-uri "/")))
                            (setf (puri:uri-path fallback) path) fallback))))
         (parsed-path (or (puri:uri-path uri) "")))
    (setf (puri:uri-scheme uri) (if (equal "HTTPS" (gethash "scheme" action)) :https :http)
          (puri:uri-host uri) host
          (puri:uri-port uri) port
          (puri:uri-is-ip6 uri) (not (null (find #\: host)))
          (puri:uri-path uri) (cond ((equal parsed-path "") "/")
                                    ((char= #\/ (char parsed-path 0)) parsed-path)
                                    (t (concatenate 'string "/" parsed-path))))
    uri))

(defun container-probe-http-headers (action)
  "Preserve repeated headers while applying kubelet's special Host/User-Agent/Accept rules."
  (let* ((headers (loop for header across (gethash "httpHeaders" action #())
                        collect (cons (gethash "name" header) (gethash "value" header ""))))
         (agent (or (cdr (assoc "User-Agent" headers :test #'string-equal)) "kube-probe/1.36"))
         (accept (assoc "Accept" headers :test #'string-equal))
         (host (assoc "Host" headers :test #'string-equal)))
    (setf headers (remove-if (lambda (entry) (member (car entry) '("Host" "User-Agent") :test #'string-equal)) headers))
    (cond ((null accept) (push (cons "Accept" "*/*") headers))
          ((equal "" (cdr accept)) (setf headers (remove "Accept" headers :key #'car :test #'string-equal))))
    (when (and host (plusp (length (cdr host)))) (push host headers))
    (values (unless (equal agent "") agent) headers)))

(defun container-probe-output-string (bytes)
  "Decode captured UTF-8 without turning a command's arbitrary output into a probe error."
  (sb-ext:octets-to-string bytes :external-format '(:utf-8 :replacement #\REPLACEMENT_CHARACTER)))

(defun container-probe-exec-output (result)
  "Preserve at most 10KiB of actual stdout followed by stderr, as kubelet combines them."
  (let ((bytes (make-array 10240 :element-type '(unsigned-byte 8) :fill-pointer 0)))
    (dolist (output (list (runtime-exec-result-stdout result) (runtime-exec-result-stderr result)))
      (let* ((source (if (stringp output) (trivial-utf-8:string-to-utf-8-bytes output) output))
             (count (min (length source) (- 10240 (length bytes)))))
        (loop for index below count do (vector-push (elt source index) bytes))))
    (container-probe-output-string bytes)))

(defun container-probe-http-content-length (headers)
  "Read a nonnegative Content-Length unless Transfer-Encoding owns the framing."
  (let ((value (and (null (cdr (assoc :transfer-encoding headers))) (cdr (assoc :content-length headers)))))
    (when value
      (let ((length (parse-integer value)))
        (when (minusp length) (error "Negative HTTP probe Content-Length"))
        length))))

(defun read-container-probe-http-body (body code headers &optional (body-limit 10240))
  "Read at most 10KiB of the final, framed response; reject a truncated known length."
  (unless (member code '(204 304))
    (let* ((content-length (container-probe-http-content-length headers))
           (limit (if content-length (min body-limit content-length) body-limit)))
      ;; Drakma's streamed body decodes chunks, but does not otherwise frame
      ;; Content-Length or report EOF at the last chunk without this option.
      (let ((wrapped (and (typep body 'flexi-streams:flexi-stream) (flexi-streams:flexi-stream-stream body))))
        (when (typep wrapped 'chunga:chunked-input-stream)
          (setf (chunga:chunked-input-stream-eof-after-last-chunk wrapped) t)))
      (when (plusp limit)
        (let* ((bytes (make-array limit :element-type '(unsigned-byte 8)))
               (read (read-sequence bytes body)))
          (when (and content-length (< read limit)) (error "Incomplete HTTP probe response body"))
          (return-from read-container-probe-http-body (container-probe-output-string (subseq bytes 0 read)))))))
  "")

(defun drain-container-probe-redirect-body (body code headers)
  "Match Go's redirect drain: at most 2KiB, skipping known larger bodies."
  (let ((length (container-probe-http-content-length headers)))
    (when (or (null length) (<= length 2048))
      ;; Ordinary drain errors do not prevent a redirect. The operation's
      ;; deadline and private cancellation are serious conditions, not ERROR,
      ;; and must still abort the whole request.
      (ignore-errors (read-container-probe-http-body body code headers 2048)))))

(defun run-http-container-probe (action host port timeout)
  "Perform a bounded HTTP(S) GET, reading only the terminal response's framed body."
  (let* ((uri (probe-http-uri action host port)) (original-host (puri:uri-host uri)))
    (multiple-value-bind (agent headers) (container-probe-http-headers action)
      (loop for redirects from 0
            do (multiple-value-bind (body code response-headers)
                   (drakma:http-request uri :method :get :proxy nil :redirect nil :want-stream t :verify nil
                                            :connection-timeout timeout :keep-alive nil :close t :force-binary t
                                            :user-agent agent :accept nil :additional-headers headers)
                 (unwind-protect
                      (let* ((location (cdr (assoc :location response-headers)))
                             (next (and (member code '(301 302 303 307 308)) location (puri:merge-uris location uri))))
                        (cond
                          ((and next (equal original-host (puri:uri-host next)))
                           ;; Follow before kubelet's terminal body read. Go
                           ;; drains only small/unknown intermediate bodies.
                           (when (>= redirects 9) (return (values nil "HTTP probe exceeded ten redirects")))
                           (unless (member (puri:uri-scheme next) '(:http :https)) (return (values nil "Unsupported probe redirect scheme")))
                           (drain-container-probe-redirect-body body code response-headers)
                           (setf uri next))
                          (t
                           (let ((output (read-container-probe-http-body body code response-headers)))
                             (unless (<= 200 code 399) (return (values nil (format nil "HTTP probe failed with statuscode: ~D" code))))
                             (if (or next (<= 300 code 399))
                                 (return (values t (format nil "Probe terminated redirects, Response body: ~A" output) :warning))
                                 (return (values t output)))))))
                   ;; Go ignores Body.Close errors. Abort also avoids an
                   ;; unnecessary TLS close-notify exchange after a probe.
                   (when body (ignore-errors (close body :abort t)))))))))

(defun call-with-container-probe-grpc-channel (host port timeout function)
  "Own the TCP socket before HTTP/2 negotiation, including failed or cancelled handshakes."
  (let ((socket (usocket:socket-connect host port :element-type '(unsigned-byte 8) :timeout timeout))
        (channel nil))
    (unwind-protect
         (let ((connection (make-instance 'ag-http2:http2-connection :socket socket
                                          :stream (usocket:socket-stream socket) :client-p t :tls-p nil)))
           (setf (ag-http2:connection-multiplexer connection) (ag-http2::make-stream-multiplexer :client-p t)
                 channel (ag-grpc:make-channel host port :connect nil :timeout timeout)
                 (ag-grpc:channel-connection channel) connection)
           (ag-http2::connection-handshake connection)
           (funcall function channel))
      (if (and channel (ag-grpc:channel-connection channel))
          (ag-grpc:channel-close channel)
          (ignore-errors (usocket:socket-close socket))))))

(defun run-grpc-container-probe (host action timeout)
  "Call grpc.health.v1.Health/Check and require a real SERVING response."
  (call-with-container-probe-grpc-channel
   host (gethash "port" action) timeout
   (lambda (channel)
     (let* ((service (trivial-utf-8:string-to-utf-8-bytes (or (gethash "service" action) "")))
            (request (make-array 8 :element-type '(unsigned-byte 8) :fill-pointer 0 :adjustable t)))
       (when (plusp (length service))
         (ag-proto::write-field-tag 1 2 request) (ag-proto::write-length-delimited service request))
       (let* ((ag-grpc::*grpc-user-agent* "kube-probe/1.36")
              (call (ag-grpc:call-unary channel "/grpc.health.v1.Health/Check" request :timeout timeout))
              (*core-protobuf-field-count* 0)
              (fields (and (ag-grpc:call-response call) (core-protobuf-fields (ag-grpc:call-response call)))))
         (let ((status (core-protobuf-value fields 1 0 0)))
           (cond
             ((/= ag-grpc:+grpc-status-ok+ (ag-grpc:call-status call))
              (values nil (format nil "gRPC health RPC status ~A: ~A" (ag-grpc:call-status call) (ag-grpc::call-status-message call))))
             ((= 1 status) (values t "gRPC health check SERVING"))
             (t (values nil (format nil "gRPC health service ~S is ~A (status ~D)"
                                    (gethash "service" action "")
                                    (case status (0 "UNKNOWN") (2 "NOT_SERVING") (3 "SERVICE_UNKNOWN") (t "unrecognized")) status))))))))))

(defun execute-container-probe (runtime container container-id pod-ip probe)
  "Execute the declared handler with one overall deadline and an exact target ID."
  (let ((timeout (gethash "timeoutSeconds" probe 1)))
    (handler-case
        (sb-sys:with-deadline (:seconds timeout)
          (cond
            ((gethash "exec" probe)
             (let ((result (cri-exec-sync (containerd-runtime-socket-path runtime) container-id
                                         (expand-static-probe-command container (gethash "command" (gethash "exec" probe))) :timeout timeout)))
               (let ((output (container-probe-exec-output result)))
                 (values (zerop (runtime-exec-result-exit-code result))
                         (if (plusp (length output)) output (format nil "Exec probe exited ~D" (runtime-exec-result-exit-code result)))))))
            ((gethash "httpGet" probe)
             (let* ((action (gethash "httpGet" probe)) (host (gethash "host" action "")))
               (run-http-container-probe action (if (equal "" host) pod-ip host) (resolve-container-probe-port container (gethash "port" action)) timeout)))
            ((gethash "tcpSocket" probe)
             (let* ((action (gethash "tcpSocket" probe)) (host (gethash "host" action ""))
                    (socket (usocket:socket-connect (if (equal "" host) pod-ip host) (resolve-container-probe-port container (gethash "port" action))
                                                    :element-type '(unsigned-byte 8) :timeout timeout)))
               (unwind-protect (values t "TCP connection succeeded") (usocket:socket-close socket))))
            ((gethash "grpc" probe) (run-grpc-container-probe pod-ip (gethash "grpc" probe) timeout))
            (t (values nil "Missing probe handler"))))
      (sb-sys:deadline-timeout () (values nil "Probe exceeded timeoutSeconds"))
      (error (condition) (values nil (princ-to-string condition))))))
