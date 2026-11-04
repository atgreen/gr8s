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
  "Build an HTTP probe URI, preserving the declared path/query and IPv6 brackets."
  (let ((path (gethash "path" action "")))
    (puri:parse-uri (format nil "~A://~A:~D~A" (string-downcase (gethash "scheme" action "HTTP"))
                            (if (find #\: host) (format nil "[~A]" host) host) port
                            (cond ((equal path "") "/") ((char= #\/ (char path 0)) path) (t (concatenate 'string "/" path)))))))

(defun run-http-container-probe (action host port timeout)
  "Perform a bounded HTTP(S) GET with kubelet redirect and response-size semantics."
  (let* ((uri (probe-http-uri action host port)) (original-host (puri:uri-host uri))
         (headers (loop for header across (gethash "httpHeaders" action #()) collect (cons (gethash "name" header) (gethash "value" header))))
         (agent (or (cdr (assoc "User-Agent" headers :test #'string-equal)) "kube-probe/1.36"))
         (accept (or (cdr (assoc "Accept" headers :test #'string-equal)) "*/*")))
    (loop for redirects from 0
          do (multiple-value-bind (body code response-headers)
                 (drakma:http-request uri :method :get :proxy nil :redirect nil :want-stream t :verify nil
                                          :connection-timeout timeout :keep-alive nil :close t :force-binary t
                                          :user-agent (unless (equal agent "") agent) :accept (unless (equal accept "") accept)
                                          :additional-headers (remove-if (lambda (entry) (member (car entry) '("User-Agent" "Accept") :test #'string-equal)) headers))
               (unwind-protect
                    (progn
                      ;; Read no more than kubelet's 10KiB body limit, including
                      ;; chunked responses; incomplete/erroring bodies fail.
                      (read-sequence (make-array 10240 :element-type '(unsigned-byte 8)) body)
                      (unless (<= 200 code 399) (return (values nil (format nil "HTTP probe failed with statuscode: ~D" code))))
                      (let ((location (cdr (assoc :location response-headers))))
                        (unless (and (member code '(301 302 303 307 308)) location)
                          (return (values t (if (<= 300 code 399) "Probe terminated redirects" "HTTP probe succeeded"))))
                        (let ((next (puri:merge-uris location uri)))
                          (unless (equalp original-host (puri:uri-host next))
                            (return (values t "Probe terminated nonlocal redirect")))
                          (when (>= redirects 9) (return (values nil "HTTP probe exceeded ten redirects")))
                          (unless (member (puri:uri-scheme next) '(:http :https)) (return (values nil "Unsupported probe redirect scheme")))
                          (setf uri next))))
                 (when body (close body)))))))

(defun run-grpc-container-probe (host action timeout)
  "Call grpc.health.v1.Health/Check and require a real SERVING response."
  (let* ((channel (ag-grpc:make-channel host (gethash "port" action) :timeout timeout))
         (service (trivial-utf-8:string-to-utf-8-bytes (or (gethash "service" action) "")))
         (request (make-array 8 :element-type '(unsigned-byte 8) :fill-pointer 0 :adjustable t)))
    (unwind-protect
         (progn
           (when (plusp (length service))
             (ag-proto::write-field-tag 1 2 request) (ag-proto::write-length-delimited service request))
           (let* ((ag-grpc::*grpc-user-agent* "kube-probe/1.36")
                  (call (ag-grpc:call-unary channel "/grpc.health.v1.Health/Check" request :timeout timeout))
                  (*core-protobuf-field-count* 0)
                  (fields (and (ag-grpc:call-response call) (core-protobuf-fields (ag-grpc:call-response call)))))
             (values (and (= ag-grpc:+grpc-status-ok+ (ag-grpc:call-status call)) (= 1 (core-protobuf-value fields 1 0 0)))
                     "gRPC health check completed")))
      (ag-grpc:channel-close channel))))

(defun execute-container-probe (runtime container container-id pod-ip probe)
  "Execute the declared handler with one overall deadline and an exact target ID."
  (let ((timeout (gethash "timeoutSeconds" probe 1)))
    (handler-case
        (sb-sys:with-deadline (:seconds timeout)
          (cond
            ((gethash "exec" probe)
             (let ((result (cri-exec-sync (containerd-runtime-socket-path runtime) container-id
                                         (expand-static-probe-command container (gethash "command" (gethash "exec" probe))) :timeout timeout)))
               (values (zerop (runtime-exec-result-exit-code result)) (format nil "Exec probe exited ~D" (runtime-exec-result-exit-code result)))))
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
