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

(defun call-with-probe-raw-server (function responder &key socket-path)
  "Own actual TCP/Unix peers and concurrent responders, including stalled handshakes and bodies."
  (let* ((host (or socket-path "127.0.0.1"))
         (listener (usocket:socket-listen host 0 :element-type '(unsigned-byte 8)))
         (target (or socket-path (usocket:get-local-port listener)))
         (lock (bt:make-lock "probe raw peers"))
         (sockets nil) (workers nil) (stopping nil)
         (acceptor
           (bt:make-thread
            (lambda ()
              (handler-case
                  (loop
                    (let ((socket (usocket:socket-accept listener)))
                      (when stopping (usocket:socket-close socket) (return))
                      (bt:with-lock-held (lock) (push socket sockets))
                      (let ((worker
                              (bt:make-thread
                               (lambda ()
                                 (unwind-protect
                                      (handler-case (funcall responder (usocket:socket-stream socket)) (error () nil))
                                   (ignore-errors (usocket:socket-close socket))))
                               :name "probe raw response")))
                        (bt:with-lock-held (lock) (push worker workers)))))
                (error () nil)))
            :name "probe raw acceptor")))
    (unwind-protect (funcall function target)
      (setf stopping t)
      (ignore-errors (usocket:socket-close (usocket:socket-connect host (if socket-path 0 target) :element-type '(unsigned-byte 8) :timeout 1)))
      (ignore-errors (usocket:socket-close listener))
      (unless (wait-until (lambda () (not (bt:thread-alive-p acceptor))) :timeout 1)
        (ignore-errors (bt:destroy-thread acceptor)))
      (ignore-errors (bt:join-thread acceptor))
      (dolist (socket sockets) (ignore-errors (usocket:socket-close socket)))
      (dolist (worker workers)
        (when (bt:thread-alive-p worker) (ignore-errors (bt:destroy-thread worker)))
        (ignore-errors (bt:join-thread worker))))))

(defun probe-request-lines (stream)
  "Read a complete real HTTP request header without consuming its target's state."
  (let ((text (flexi-streams:make-flexi-stream stream :external-format :latin-1)))
    (loop for line = (read-line text nil nil)
          while (and line (plusp (length (string-trim '(#\Return) line)))) collect line)))

(defun write-probe-http-response (stream status headers body)
  "Write controlled HTTP framing so tests can keep a complete or partial body open."
  (let ((text (flexi-streams:make-flexi-stream stream :external-format :latin-1)))
    (format text "HTTP/1.1 ~D Test~C~C" status #\Return #\Newline)
    (dolist (entry headers) (format text "~A: ~A~C~C" (car entry) (cdr entry) #\Return #\Newline))
    (format text "~C~C~A" #\Return #\Newline body)
    (force-output text)))

(defun probe-for-http-port (port &optional (path "/"))
  "Construct a validated one-second actual HTTP probe for a loopback fixture."
  (gr8s::validate-container-probe
   (gr8s::core-object "timeoutSeconds" 1 "httpGet" (gr8s::core-object "port" port "path" path)) "readinessProbe"))

(test probe-http-spec-defaults-empty-header-values-and-restricts-names
  (let* ((probe (checked-probe "{\"httpGet\":{\"port\":80,\"httpHeaders\":[{\"name\":\"Accept\"}]}}"))
         (http (gethash "httpGet" probe)))
    (is (equal "/" (gethash "path" http)))
    (is (equal "" (gethash "value" (aref (gethash "httpHeaders" http) 0)))))
  (signals gr8s:kubernetes-error (checked-probe "{\"httpGet\":{\"port\":\"a--b\"}}"))
  (signals gr8s:kubernetes-error (checked-probe "{\"httpGet\":{\"port\":80,\"httpHeaders\":[{\"name\":\"X_Test\",\"value\":\"x\"}]}}")))

(test probe-http-terminal-body-obeys-framing-and-the-10kib-limit
  (dolist (scenario '((200 (("Content-Length" . "0")) "")
                      (204 nil "")
                      (304 nil "")
                      (200 (("Content-Length" . "3")) "abc")
                      (200 (("Transfer-Encoding" . "chunked")) :chunked)
                      (200 (("Content-Length" . "20000")) :limit)))
    (destructuring-bind (code headers body) scenario
      (let ((release (bt:make-semaphore :name "probe completed before peer closes")))
        (call-with-probe-raw-server
         (lambda (port)
           (unwind-protect
                (multiple-value-bind (ok message)
                    (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1" (probe-for-http-port port))
                  (is-true ok "Framed HTTP status ~D should not read past its body: ~A" code message))
             (bt:signal-semaphore release)))
         (lambda (stream)
           (probe-request-lines stream)
           (write-probe-http-response
            stream code headers
            (cond ((eq body :limit) (make-string 10240 :initial-element #\x))
                  ((eq body :chunked)
                   (format nil "3~C~Cabc~C~C0~C~C~C~C" #\Return #\Newline #\Return #\Newline #\Return #\Newline #\Return #\Newline))
                  (t body)))
           (bt:wait-on-semaphore release))))))
  (call-with-probe-raw-server
   (lambda (port)
     (multiple-value-bind (success message kind)
         (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1" (probe-for-http-port port))
       (is-false success) (is (eq :error kind)) (is (search "Incomplete" message))))
   (lambda (stream) (probe-request-lines stream) (write-probe-http-response stream 200 '(("Content-Length" . "5")) "no"))))

(test probe-http-follows-redirect-before-reading-the-intermediate-body
  (let ((release (bt:make-semaphore :name "release ignored redirect body")) (requests nil) (lock (bt:make-lock "redirect requests")))
    (call-with-probe-raw-server
     (lambda (port)
       (unwind-protect
            (progn
              (is-true (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1" (probe-for-http-port port "/start")))
              (is (= 2 (length requests))))
         (bt:signal-semaphore release)))
     (lambda (stream)
       (let ((request (first (probe-request-lines stream))))
         (bt:with-lock-held (lock) (push request requests))
         (if (search "/start" request)
             (progn
               (write-probe-http-response stream 302 '(("Location" . "/ready") ("Content-Length" . "20000")) "")
               (bt:wait-on-semaphore release))
             (write-probe-http-response stream 200 '(("Content-Length" . "0")) "")))))))

(test probe-http-parses-absolute-path-authority-and-preserves-repeated-accept
  (let ((requests nil))
    (call-with-probe-http-server
     (lambda (port)
       (let ((probe (probe-for-http-port port "http://ignored.invalid/ready?check=yes")))
         (setf (gethash "httpHeaders" (gethash "httpGet" probe))
               (vector (gr8s::core-object "name" "Accept" "value" "application/a")
                       (gr8s::core-object "name" "Accept" "value" "application/b")
                       (gr8s::core-object "name" "Host" "value" "")
                       (gr8s::core-object "name" "Host" "value" "ignored.invalid")))
         (is-true (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1" probe))
         (is (search "GET /ready?check=yes HTTP/" (first requests)))
         (is (= 2 (count-if (lambda (line) (search "Accept:" line :test #'char-equal)) requests)))
         (is (= 1 (count-if (lambda (line) (search "Host:" line :test #'char-equal)) requests)))
         (is (find-if (lambda (line) (search (format nil "Host: 127.0.0.1:~D" port) line :test #'char-equal)) requests))))
     (lambda (lines) (setf requests lines) (values 200 nil "")))))

(test grpc-probe-constructor-timeouts-close-the-real-peer
  (let ((closed (bt:make-semaphore :name "gRPC constructor peer closed")))
    (call-with-probe-raw-server
     (lambda (port)
       (dotimes (attempt 3)
         (declare (ignore attempt))
         (is-false (gr8s::execute-container-probe
                    (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1"
                    (checked-probe (format nil "{\"grpc\":{\"port\":~D},\"timeoutSeconds\":1}" port))))
         (is (bt:wait-on-semaphore closed :timeout .5))))
     (lambda (stream)
       ;; Consume the actual client preface/SETTINGS, but never answer them.
       (loop while (read-byte stream nil nil))
       (bt:signal-semaphore closed)))))

#+sbcl
(test exec-probe-constructor-timeouts-close-the-real-unix-peer
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((gr8s::*cri-runtime-request-timeout* 0)
          (closed (bt:make-semaphore :name "Exec constructor peer closed"))
          (path (merge-pathnames "stalled-cri.sock" directory)))
      (call-with-probe-raw-server
       (lambda (socket-path)
         (let ((runtime (gr8s::make-containerd-runtime :socket-path (namestring socket-path))))
           (dotimes (attempt 2)
             (declare (ignore attempt))
             (is-false (gr8s::execute-container-probe runtime (gr8s::core-object) "exact-attempt" ""
                                                    (checked-probe "{\"exec\":{\"command\":[\"true\"]},\"timeoutSeconds\":1}")))
             (is (bt:wait-on-semaphore closed :timeout .5)))))
       (lambda (stream) (loop while (read-byte stream nil nil)) (bt:signal-semaphore closed))
       :socket-path path))))

(define-condition probe-test-cancelled (serious-condition) ())

(test cancelling-grpc-probe-during-constructor-closes-the-peer
  (let ((entered (bt:make-semaphore :name "probe constructor entered"))
        (closed (bt:make-semaphore :name "cancelled probe peer closed"))
        (cancelled nil) (worker nil))
    (call-with-probe-raw-server
     (lambda (port)
       (unwind-protect
            (progn
              (setf worker (bt:make-thread
                            (lambda ()
                              (handler-case
                                  (gr8s::execute-container-probe
                                   (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1"
                                   (checked-probe (format nil "{\"grpc\":{\"port\":~D},\"timeoutSeconds\":30}" port)))
                                (probe-test-cancelled () (setf cancelled t))))
                            :name "cancelled probe constructor"))
              (is (bt:wait-on-semaphore entered :timeout 2))
              (bt:interrupt-thread worker (lambda () (error 'probe-test-cancelled)))
              (bt:join-thread worker)
              (is-true cancelled)
              (is (bt:wait-on-semaphore closed :timeout .5)))
         (when (and worker (bt:thread-alive-p worker)) (ignore-errors (bt:destroy-thread worker)))
         (when worker (ignore-errors (bt:join-thread worker)))))
     (lambda (stream)
       (bt:signal-semaphore entered)
       (loop while (read-byte stream nil nil))
       (bt:signal-semaphore closed)))))

(test http-probe-redirect-warnings-preserve-real-body-and-warning-result
  (let ((requests 0))
    (call-with-probe-http-server
     (lambda (port)
       (multiple-value-bind (success output result)
           (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1" (probe-for-http-port port))
         (is-true success) (is (eq :warning result))
         (is (search "actual redirect body" output))
         (is (= 1 requests))))
     (lambda (lines) (declare (ignore lines))
       (incf requests)
       (values 302 '(("Location" . "http://unrelated.invalid/unreachable")) "actual redirect body")))))

(test exec-probe-output-keeps-captured-bytes-with-a-bound
  (let* ((original (symbol-function 'gr8s::cri-exec-sync))
         (result (gr8s::make-runtime-exec-result
                  :stdout (trivial-utf-8:string-to-utf-8-bytes "actual stdout ")
                  :stderr (trivial-utf-8:string-to-utf-8-bytes "actual stderr") :exit-code 7))
         (probe (checked-probe "{\"exec\":{\"command\":[\"check\"]}}")))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s::cri-exec-sync) (lambda (&rest args) (declare (ignore args)) result))
           (multiple-value-bind (success output)
               (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "" probe)
             (is-false success) (is (equal "actual stdout actual stderr" output)))
           (setf result (gr8s::make-runtime-exec-result
                         :stdout (make-array 20000 :element-type '(unsigned-byte 8) :initial-element 120)
                         :stderr (trivial-utf-8:string-to-utf-8-bytes "not included") :exit-code 7))
           (multiple-value-bind (success output)
               (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "" probe)
             (is-false success) (is (= 10240 (length output))))
           (setf result (gr8s::make-runtime-exec-result :stdout (make-array 1 :element-type '(unsigned-byte 8) :initial-element 255)))
           (multiple-value-bind (success output)
               (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "" probe)
             (is-true success) (is (equal (string (code-char #xfffd)) output))))
      (setf (symbol-function 'gr8s::cri-exec-sync) original))))

(test https-probes-ignore-an-untrusted-certificate-and-respect-empty-body-framing
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((pki (gr8s:ensure-cluster-pki (merge-pathnames "probe-pki/" directory))))
      (multiple-value-bind (certificate key) (gr8s::ensure-node-server-credentials pki)
        (call-with-probe-raw-server
         (lambda (port)
           (multiple-value-bind (success output)
               (gr8s::execute-container-probe
                (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1"
                (checked-probe (format nil "{\"httpGet\":{\"port\":~D,\"scheme\":\"HTTPS\"},\"timeoutSeconds\":1}" port)))
             (is-true success "Self-signed HTTPS with empty body failed: ~A" output)))
         (lambda (stream)
           (let ((tls (pure-tls:make-tls-server-stream stream :certificate (namestring certificate) :key (namestring key)
                                                            :verify pure-tls:+verify-none+)))
             (unwind-protect
                  (progn (probe-request-lines tls) (write-probe-http-response tls 200 '(("Content-Length" . "0")) ""))
               (ignore-errors (close tls :abort t))))))))))

(test probe-http-small-redirect-body-remains-inside-the-overall-deadline
  (let ((release (bt:make-semaphore :name "release small redirect body")) (requests 0))
    (call-with-probe-raw-server
     (lambda (port)
       (unwind-protect
            (progn
              (is-false (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1" (probe-for-http-port port "/start")))
              (is (= 1 requests)))
         (bt:signal-semaphore release)))
     (lambda (stream)
       (let ((request (first (probe-request-lines stream))))
         (incf requests)
         (if (search "/start" request)
             (progn
               (write-probe-http-response stream 302 '(("Location" . "/ready") ("Content-Length" . "1")) "")
               (bt:wait-on-semaphore release))
             (write-probe-http-response stream 200 '(("Content-Length" . "0")) "")))))))

(test unresolved-probe-ports-and-exec-infrastructure-are-errors
  (let ((container (gr8s::core-object "name" "app")) (runtime (gr8s::make-containerd-runtime)))
    (dolist (handler '("httpGet" "tcpSocket"))
      (multiple-value-bind (success message kind)
          (gr8s::execute-container-probe runtime container "id" "127.0.0.1"
            (checked-probe (format nil "{\"~A\":{\"port\":\"missing\"}}" handler)))
        (is-false success) (is (eq :error kind)) (is (search "not declared" message))))
    (with-temporary-store (store directory)
      (declare (ignore store))
      (multiple-value-bind (success message kind)
          (gr8s::execute-container-probe
           (gr8s::make-containerd-runtime :socket-path (namestring (merge-pathnames "absent-cri.sock" directory)))
           container "id" "" (checked-probe "{\"exec\":{\"command\":[\"true\"]}}"))
        (is-false success) (is (eq :error kind)) (is (plusp (length message)))))))

(test actual-http-body-errors-differ-from-negative-service-results
  (dolist (scenario '(:truncated :stalled))
    (let ((release (bt:make-semaphore)))
      (call-with-probe-raw-server
       (lambda (port)
         (unwind-protect
              (let ((start (get-internal-real-time)))
                (multiple-value-bind (success message kind result)
                    (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1" (probe-for-http-port port))
                  (is-false success) (is (eq :error kind)) (is (eq :failure result))
                  (is (plusp (length message)))
                  (is (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 1.7))))
           (bt:signal-semaphore release)))
       (lambda (stream)
         (probe-request-lines stream)
         (write-probe-http-response stream 200 '(("Content-Length" . "5")) (if (eq scenario :truncated) "no" ""))
         (when (eq scenario :stalled) (bt:wait-on-semaphore release))))))
  (call-with-probe-http-server
   (lambda (port)
     (multiple-value-bind (success message kind)
         (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1" (probe-for-http-port port))
       (is-false success) (is-false kind) (is (search "503" message))))
   (lambda (lines) (declare (ignore lines)) (values 503 nil "unhealthy")))
  (call-with-probe-raw-server
   (lambda (port)
     (multiple-value-bind (success message kind)
         (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1" (probe-for-http-port port))
       (is-false success) (is-false kind) (is (plusp (length message)))))
   (lambda (stream) (probe-request-lines stream) (loop while (read-byte stream nil nil)))))

(test real-tcp-refusal-is-a-failure-rather-than-a-prober-error
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener)))
    (usocket:socket-close listener)
    (multiple-value-bind (success message kind)
        (gr8s::execute-container-probe (gr8s::make-containerd-runtime) (gr8s::core-object) "id" "127.0.0.1"
          (checked-probe (format nil "{\"tcpSocket\":{\"port\":~D}}" port)))
      (is-false success) (is-false kind) (is (plusp (length message))))))

(test exec-probes-distinguish-real-cri-status-from-command-results
  (let* ((server (ag-grpc:make-grpc-server 0 :host "127.0.0.1")) (thread nil)
         (original (symbol-function 'gr8s::make-unix-grpc-channel))
         (status ag-grpc:+grpc-status-unavailable+) (exit-code 0) (commands nil) (delay 0) (timeouts nil))
    (ag-grpc:server-register-handler
     server "/runtime.v1.RuntimeService/ExecSync"
     (lambda (request context)
       (push (list (gr8s.cri.v1::timeout request)
                   (cdr (assoc "grpc-timeout" (ag-grpc::context-request-headers context) :test #'equal))) timeouts)
       (push (gr8s.cri.v1::cmd request) commands)
       (sleep delay)
       (if (= status ag-grpc:+grpc-status-ok+)
           (make-instance 'gr8s.cri.v1::exec-sync-response :exit-code exit-code)
           (error 'ag-grpc::grpc-status-error :code status :message "actual CRI execution status")))
     :request-type 'gr8s.cri.v1::exec-sync-request :response-type 'gr8s.cri.v1::exec-sync-response)
    (unwind-protect
         (progn
           (setf thread (bt:make-thread (lambda () (ag-grpc:server-start server))))
           (is-true (wait-until (lambda () (eq :running (ag-grpc::server-state server)))))
           ;; Change only the socket address family; run the actual generated
           ;; CRI method and decode its real gRPC status/ExecSync response.
           (setf (symbol-function 'gr8s::make-unix-grpc-channel)
                 (lambda (path &key timeout)
                   (declare (ignore path))
                   (ag-grpc:make-channel "127.0.0.1" (usocket:get-local-port (ag-grpc::server-socket server)) :timeout timeout)))
           (let ((probe (checked-probe "{\"exec\":{\"command\":[\"true\"]}}"))
                 (runtime (gr8s::make-containerd-runtime)))
             (multiple-value-bind (success message kind)
                 (gr8s::execute-container-probe runtime (gr8s::core-object) "id" "" probe)
               (is-false success) (is (eq :error kind)) (is (search "UNAVAILABLE" message)))
             (setf status ag-grpc:+grpc-status-deadline-exceeded+)
             (multiple-value-bind (success message kind)
                 (gr8s::execute-container-probe runtime (gr8s::core-object) "id" "" probe)
               (is-false success) (is-false kind) (is (search "actual CRI execution status" message)))
             (setf status ag-grpc:+grpc-status-ok+ exit-code 7)
             (multiple-value-bind (success message kind)
                 (gr8s::execute-container-probe runtime (gr8s::core-object) "id" "" probe)
               (is-false success) (is-false kind) (is (search "7" message)))
             (setf exit-code 0)
             (multiple-value-bind (success message kind)
                 (gr8s::execute-container-probe runtime (gr8s::core-object) "id" "" probe)
               (is-true success "Actual CRI execution failed: ~A" message) (is-false kind))
             (setf delay 1.1)
             (multiple-value-bind (success message kind)
                 (gr8s::execute-container-probe runtime (gr8s::core-object) "id" "" probe)
               (is-true success "CRI setup/cleanup time consumed the command's budget: ~A" message) (is-false kind)))
           (is (= 5 (length commands)))
           (is (every (lambda (entry) (= 1 (first entry))) timeouts))
           (is (every (lambda (entry) (equal "121S" (second entry))) timeouts)))
      (setf (symbol-function 'gr8s::make-unix-grpc-channel) original)
      (ag-grpc:server-stop server)
      (when thread (bt:join-thread thread)))))
