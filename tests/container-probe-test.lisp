;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify probe admission/defaults, real loopback HTTP/TCP/gRPC behavior and
;;;; deadline cleanup, then exercise asynchronous thresholds and native restart
;;;; integration with exact container identities and controlled observations.

(in-package #:gr8s/tests)
(def-suite container-probes :in gr8s)
(in-suite container-probes)

(defun checked-probe (json &optional (kind "readinessProbe"))
  "Validate a test declaration through production probe validation."
  (gr8s::validate-container-probe (com.inuoe.jzon:parse json) kind))

(test probes-validate-actions-and-default-typed-zero-scalars
  (let ((probe (checked-probe "{\"httpGet\":{\"port\":\"http\"},\"periodSeconds\":0,\"timeoutSeconds\":0}")))
    (is (= 10 (gethash "periodSeconds" probe))) (is (= 1 (gethash "timeoutSeconds" probe)))
    (is (= 3 (gethash "failureThreshold" probe))) (is (= 1 (gethash "successThreshold" probe)))
    (is (equal "HTTP" (gethash "scheme" (gethash "httpGet" probe)))))
  (dolist (json '("{}" "{\"exec\":{\"command\":[]}}" "{\"grpc\":{\"port\":\"named\"}}"
                  "{\"exec\":{\"command\":[\"true\"]},\"tcpSocket\":{\"port\":80}}"
                  "{\"httpGet\":{\"port\":80,\"httpHeaders\":[{\"name\":\"bad name\",\"value\":\"x\"}]}}"
                  "{\"tcpSocket\":{\"port\":80},\"terminationGracePeriodSeconds\":1}"))
    (signals gr8s:kubernetes-error (checked-probe json)))
  (signals gr8s:kubernetes-error (checked-probe "{\"exec\":{\"command\":[\"true\"]},\"successThreshold\":2}" "livenessProbe"))
  (is (= 2 (gethash "successThreshold" (checked-probe "{\"exec\":{\"command\":[\"true\"]},\"successThreshold\":2}")))))

(test probes-resolve-only-target-ports-and-static-command-values
  (let ((container (com.inuoe.jzon:parse "{\"name\":\"app\",\"ports\":[{\"name\":\"http\",\"containerPort\":8080}],\"env\":[{\"name\":\"DIRECT\",\"value\":\"value\"},{\"name\":\"INDIRECT\",\"valueFrom\":{\"fieldRef\":{\"fieldPath\":\"metadata.name\"}}}]}")))
    (is (= 8080 (gr8s::resolve-container-probe-port container "http")))
    (signals gr8s:runtime-error (gr8s::resolve-container-probe-port container "other"))
    (is (equal '("value" "" "$(UNKNOWN)" "$(DIRECT)" "")
               (gr8s::expand-static-probe-command container #("$(DIRECT)" "$(INDIRECT)" "$(UNKNOWN)" "$$(DIRECT)" ""))))))

(defun call-with-probe-http-server (function response)
  "Own a real ephemeral HTTP server; RESPONSE sees every complete request header."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8)))
         (thread (bt:make-thread
                  (lambda ()
                    (handler-case
                        (loop
                          (let ((socket (usocket:socket-accept listener)))
                            (unwind-protect
                                 (let* ((stream (flexi-streams:make-flexi-stream (usocket:socket-stream socket) :external-format :latin-1))
                                        (lines (loop for line = (read-line stream nil nil)
                                                     while (and line (plusp (length (string-trim '(#\Return) line)))) collect line)))
                                   (when lines
                                     (multiple-value-bind (status headers body) (funcall response lines)
                                       (flet ((line (text) (format stream "~A~C~C" text #\Return #\Newline)))
                                         (line (format nil "HTTP/1.1 ~D Test" status))
                                         (line (format nil "Content-Length: ~D" (length body)))
                                         (line "Connection: close")
                                         (dolist (entry headers) (line (format nil "~A: ~A" (car entry) (cdr entry))))
                                         (line "") (write-string body stream) (force-output stream)))))
                              (ignore-errors (usocket:socket-close socket)))))
                      (error () nil)))
                  :name "container probe HTTP fixture")))
    (unwind-protect (funcall function (usocket:get-local-port listener))
      (ignore-errors (usocket:socket-close listener))
      (when (bt:thread-alive-p thread) (ignore-errors (bt:destroy-thread thread)))
      (ignore-errors (bt:join-thread thread)))))

(test http-probes-use-real-status-headers-redirects-and-no-proxy
  (let ((requests nil))
    (call-with-probe-http-server
     (lambda (port)
       (let* ((drakma:*default-http-proxy* '("127.0.0.1" 1))
              (container (gr8s::core-object "name" "app"))
              (probe (checked-probe (format nil "{\"httpGet\":{\"port\":~D,\"path\":\"/start\",\"httpHeaders\":[{\"name\":\"Host\",\"value\":\"virtual.test\"},{\"name\":\"User-Agent\",\"value\":\"custom-probe\"},{\"name\":\"Accept\",\"value\":\"\"}]}}" port))))
         (is-true (gr8s::execute-container-probe (gr8s::make-containerd-runtime) container "exact-id" "127.0.0.1" probe))
         (is (= 2 (length requests)))
         (is (find-if (lambda (line) (search "Host: virtual.test" line :test #'char-equal)) (first requests)))
         (is (find-if (lambda (line) (search "User-Agent: custom-probe" line :test #'char-equal)) (first requests)))
         (is (not (find-if (lambda (line) (search "Accept:" line :test #'char-equal)) (first requests))))))
     (lambda (lines)
       (push lines requests)
       (if (search "/start" (first lines)) (values 302 '(("Location" . "/ready")) "redirect") (values 204 nil "")))))
  (call-with-probe-http-server
   (lambda (port)
     (is-false (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object "name" "app") "id" "127.0.0.1"
                                            (checked-probe (format nil "{\"httpGet\":{\"port\":~D}}" port)))))
   (lambda (lines) (declare (ignore lines)) (values 503 nil "unhealthy"))))

(test http-probe-timeout-is-a-failure-and-releases-the-connection
  (call-with-probe-http-server
   (lambda (port)
     (let ((start (get-internal-real-time)))
       (is-false (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object "name" "app") "id" "127.0.0.1"
                                              (checked-probe (format nil "{\"httpGet\":{\"port\":~D},\"timeoutSeconds\":1}" port))))
       (is (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 1.7))))
   (lambda (lines) (declare (ignore lines)) (sleep 2) (values 200 nil "too late"))))

(test tcp-probes-contact-the-actual-listener
  (let ((listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (is-true (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object "name" "app") "id" "127.0.0.1"
                                               (checked-probe (format nil "{\"tcpSocket\":{\"port\":~D}}" (usocket:get-local-port listener)))))
      (usocket:socket-close listener))))

(defclass probe-wire-request (ag-proto:proto-message)
  ((service :initarg :service :reader probe-wire-service))
  (:documentation "Decode the standard HealthCheckRequest service string in the wire test."))

(defclass probe-wire-response (ag-proto:proto-message)
  ((status :initarg :status :reader probe-wire-status))
  (:documentation "Serialize a standard grpc.health.v1.HealthCheckResponse status."))

(defmethod ag-proto:deserialize-from-bytes ((type (eql 'probe-wire-request)) bytes)
  "Read the actual health protocol request rather than a generated gr8s service."
  (let ((gr8s::*core-protobuf-field-count* 0))
    (make-instance 'probe-wire-request :service (gr8s::core-protobuf-string (gr8s::core-protobuf-fields bytes) 1))))

(defmethod ag-proto:serialize-to-bytes ((response probe-wire-response))
  "Emit the standard enum field for the real gRPC wire exchange."
  (make-array 2 :element-type '(unsigned-byte 8) :initial-contents (list 8 (probe-wire-status response))))

(test grpc-probes-call-the-standard-health-method-and-require-serving
  (let* ((server (ag-grpc:make-grpc-server 0 :host "127.0.0.1"))
         (thread nil) (health 1) (services nil) (agents nil))
    (ag-grpc:server-register-handler
     server "/grpc.health.v1.Health/Check"
     (lambda (request context)
       (push (probe-wire-service request) services)
       (push (cdr (assoc "user-agent" (ag-grpc::context-request-headers context) :test #'equal)) agents)
       (make-instance 'probe-wire-response :status health))
     :request-type 'probe-wire-request :response-type 'probe-wire-response)
    (unwind-protect
         (progn
           (setf thread (bt:make-thread (lambda () (ag-grpc:server-start server)) :name "probe health server"))
           (is-true (wait-until (lambda () (eq :running (ag-grpc::server-state server)))))
           (let ((probe (checked-probe (format nil "{\"grpc\":{\"port\":~D,\"service\":\"application\"}}" (usocket:get-local-port (ag-grpc::server-socket server))))))
             (multiple-value-bind (success message) (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object "name" "app") "id" "127.0.0.1" probe)
               (is-true success "Health/Check failed: ~A" message))
             (setf health 2)
             (is-false (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object "name" "app") "id" "127.0.0.1" probe))
             (is (equal '("application" "application") services))
             (is (every (lambda (agent) (equal "kube-probe/1.36" agent)) agents))))
      (ag-grpc:server-stop server)
      (when thread (bt:join-thread thread)))))

(test exec-probes-target-exact-attempt-and-honor-exit-status
  (let ((original (symbol-function 'gr8s::cri-exec-sync)) (calls nil) (code 0))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s::cri-exec-sync)
                 (lambda (socket id command &key timeout)
                   (declare (ignore socket)) (push (list id command timeout) calls)
                   (gr8s::make-runtime-exec-result :exit-code code)))
           (let ((probe (checked-probe "{\"exec\":{\"command\":[\"test\",\"$(VALUE)\"]}}"))
                 (container (gr8s::core-object "name" "app" "env" (vector (gr8s::core-object "name" "VALUE" "value" "literal")))))
             (is-true (gr8s::execute-container-probe (gr8s::make-containerd-runtime) container "current-attempt" "" probe))
             (setf code 7)
             (is-false (gr8s::execute-container-probe (gr8s::make-containerd-runtime) container "current-attempt" "" probe))
             (is (equal '(("current-attempt" ("test" "literal") 1) ("current-attempt" ("test" "literal") 1)) calls))))
      (setf (symbol-function 'gr8s::cri-exec-sync) original))))
