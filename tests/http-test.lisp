(in-package #:gr8s/tests)

(in-suite gr8s)

(defun request (path &rest arguments)
  (apply #'drakma:http-request
         (format nil "http://127.0.0.1:18080~A" path)
         arguments))

(defun response-object (body)
  (com.inuoe.jzon:parse body))

(test health-endpoints-cross-the-http-boundary
  (let ((server (start-server :address "127.0.0.1" :port 18080)))
    (unwind-protect
         (loop for path in '("/livez" "/readyz")
               do (multiple-value-bind (body status)
                      (request path)
                    (is (= 200 status))
                    (is (string= "ok" body))))
      (stop-server server))))

(test server-uses-the-callers-reconciler
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime))
           (server (start-server :address "127.0.0.1"
                                 :port 18080
                                 :store store
                                 :runtime runtime
                                 :reconciler reconciler)))
      (unwind-protect
           (is (eq reconciler (gr8s::acceptor-reconciler server)))
        (stop-server server)))))

(test kubernetes-discovery-and-pod-workflow
  (with-temporary-store (store path)
    (let* ((runtime (make-fake-runtime))
           (server (start-server :address "127.0.0.1"
                                 :port 18080
                                 :store store
                                 :runtime runtime)))
      (unwind-protect
           (progn
             (dolist (path '("/version" "/api" "/apis" "/api/v1"))
               (multiple-value-bind (body status) (request path)
                 (is (= 200 status))
                 (is (hash-table-p (response-object body)))))
             (multiple-value-bind (body status) (request "/api/v1")
               (is (= 200 status))
               (let* ((resources (gethash "resources" (response-object body)))
                      (exec (find "pods/exec" resources
                                  :key (lambda (resource)
                                         (gethash "name" resource))
                                  :test #'string=)))
                 (is (hash-table-p exec))
                 (is (find "create" (gethash "verbs" exec)
                           :test #'string=))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/events?limit=500")
               (is (= 200 status))
               (let ((events (response-object body)))
                 (is (string= "EventList" (gethash "kind" events)))
                 (is (zerop (length (gethash "items" events))))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/podsfoo")
               (declare (ignore body))
               (is (= 404 status)))
             (multiple-value-bind (body status) (request "/openapi/v2")
               (is (= 200 status))
               (let ((document (response-object body)))
                 (is (string= "2.0" (gethash "swagger" document)))
                 (is (gethash "io.k8s.api.core.v1.Pod"
                              (gethash "definitions" document)))))
             (multiple-value-bind (body status) (request "/openapi/v3")
               (is (= 200 status))
               (is (gethash "api/v1"
                            (gethash "paths" (response-object body)))))
             (multiple-value-bind (body status)
                 (request "/openapi/v3/api/v1")
               (is (= 200 status))
               (let ((document (response-object body)))
                 (is (string= "3.0.0" (gethash "openapi" document)))
                 (is (gethash "io.k8s.api.core.v1.Pod"
                              (gethash "schemas"
                                      (gethash "components" document))))
                 (let* ((paths (gethash "paths" document))
                        (collection (gethash
                                     "/api/v1/namespaces/{namespace}/pods"
                                     paths))
                        (post (and collection (gethash "post" collection))))
                   (is (hash-table-p post))
                   (is (string= "Pod"
                                (gethash
                                 "kind"
                                 (gethash "x-kubernetes-group-version-kind"
                                          post)))))
                 (let* ((paths (gethash "paths" document))
                        (resource (gethash
                                   "/api/v1/namespaces/{namespace}/pods/{name}"
                                   paths))
                        (patch (and resource (gethash "patch" resource))))
                   (is (hash-table-p patch))
                   (is (find "fieldValidation"
                             (gethash "parameters" patch)
                             :key (lambda (parameter)
                                    (gethash "name" parameter))
                             :test #'string=)))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods"
                          :method :post
                          :content "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"bad-policy\"},\"spec\":{\"restartPolicy\":7,\"containers\":[{\"name\":\"main\",\"image\":\"busybox\"}]}}"
                          :content-type "application/json")
               (is (= 422 status))
               (is (string= "Invalid"
                            (gethash "reason" (response-object body)))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods"
                          :method :post
                          :content *valid-pod-json*
                          :content-type "application/json")
               (is (= 201 status))
               (let ((pod (response-object body)))
                 (is (string= "Pod" (gethash "kind" pod)))
                 (is (string= "Running"
                              (gethash "phase" (gethash "status" pod))))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods"
                          :method :post
                          :content *valid-pod-json*
                          :content-type "application/json")
               (is (= 409 status))
               (is (string= "AlreadyExists"
                            (gethash "reason" (response-object body)))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods")
               (is (= 200 status))
               (let ((list (response-object body)))
                 (is (string= "PodList" (gethash "kind" list)))
                 (is (= 1 (length (gethash "items" list))))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods/hello"
                          :method :put
                          :content "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\",\"resourceVersion\":\"1\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"docker.io/library/busybox:latest\"}]}}"
                          :content-type "application/json")
               (is (= 200 status))
               (is (string= "2"
                            (gethash "resourceVersion"
                                     (gethash "metadata"
                                              (response-object body))))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods/hello"
                          :method :put
                          :content "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"hello\",\"resourceVersion\":\"1\"},\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"busybox\"}]}}"
                          :content-type "application/json")
               (is (= 409 status))
               (is (string= "Conflict"
                            (gethash "reason" (response-object body)))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods/hello"
                          :method :patch
                          :content "{\"metadata\":{\"annotations\":{\"deployed-by\":\"kubectl\"}}}"
                          :content-type "application/strategic-merge-patch+json")
               (is (= 200 status))
               (is (string= "3"
                            (gethash "resourceVersion"
                                     (gethash "metadata"
                                              (response-object body)))))
               (is (string= "kubectl"
                            (gethash "deployed-by"
                                     (gethash "annotations"
                                              (gethash "metadata"
                                                       (response-object body)))))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods/hello"
                          :method :patch
                          :content "{\"spec\":{\"containers\":[{\"name\":\"web\",\"image\":\"example.invalid/new:1\"}]}}"
                          :content-type "application/strategic-merge-patch+json")
               (is (= 200 status))
               (is (string= "example.invalid/new:1"
                            (gethash "image"
                                     (aref (gethash
                                            "containers"
                                            (gethash "spec"
                                                     (response-object body)))
                                           0)))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods/hello/log?container=typo")
               (is (= 400 status))
               (is (string= "BadRequest"
                            (gethash "reason" (response-object body)))))
             (set-fake-runtime-failure runtime "log transport failed")
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods/hello/log?container=web")
               (is (= 500 status))
               (is (string= "RuntimeError"
                            (gethash "reason" (response-object body)))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods/hello/log?container=web")
               (is (= 200 status))
               (is (string= "" (or body ""))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods/hello"
                          :method :delete)
               (is (= 200 status))
               (is (string= "Success"
                            (gethash "status" (response-object body)))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/default/pods/hello")
               (is (= 404 status))
               (let ((error (response-object body)))
                 (is (string= "Status" (gethash "kind" error)))
                 (is (string= "NotFound" (gethash "reason" error))))))
        (stop-server server)))))

(test exec-query-options-preserve-command-order-and-stream-flags
  (let ((options
          (gr8s::exec-options-from-parameters
           '(("command" . "sh")
             ("command" . "-c")
             ("command" . "printf ok")
             ("container" . "main")
             ("stdin" . "true")
             ("stdout" . "true")
             ("stderr" . "false")
             ("tty" . "true")))))
    (is (equal '("sh" "-c" "printf ok")
               (gr8s::exec-options-command options)))
    (is (string= "main" (gr8s::exec-options-container options)))
    (is (gr8s::exec-options-stdin options))
    (is (gr8s::exec-options-stdout options))
    (is (not (gr8s::exec-options-stderr options)))
    (is (gr8s::exec-options-tty options))))

(test runtime-stream-url-is-restricted-to-loopback-http
  (multiple-value-bind (host port target)
      (gr8s::parse-runtime-stream-url
       "http://127.0.0.1:41237/exec/token?stream=1")
    (is (string= "127.0.0.1" host))
    (is (= 41237 port))
    (is (string= "/exec/token?stream=1" target)))
  (signals runtime-error
    (gr8s::parse-runtime-stream-url "https://127.0.0.1:41237/exec/token"))
  (signals runtime-error
    (gr8s::parse-runtime-stream-url "http://example.com:41237/exec/token")))

(test upgrade-request-forwards-kubernetes-stream-negotiation
  (let ((request
          (gr8s::runtime-upgrade-request
           "/exec/token"
           "127.0.0.1"
           41237
           '((:connection . "Upgrade")
             (:upgrade . "websocket")
             (:sec-websocket-key . "key==")
             (:sec-websocket-version . "13")
             (:sec-websocket-protocol . "v5.channel.k8s.io")
             (:authorization . "must-not-be-forwarded")))))
    (is (search (format nil "POST /exec/token HTTP/1.1~C~C"
                        #\Return #\Linefeed)
                request))
    (is (search (format nil "Host: 127.0.0.1:41237~C~C"
                        #\Return #\Linefeed)
                request))
    (is (search (format nil "Sec-Websocket-Protocol: v5.channel.k8s.io~C~C"
                        #\Return #\Linefeed)
                request
                :test #'char-equal))
    (is (not (search "Authorization" request :test #'char-equal)))))

(test pod-exec-route-requires-an-upgraded-connection
  (with-temporary-store (store path)
    (create-pod store (parse-pod *valid-pod-json*))
    (let* ((runtime (make-fake-runtime))
           (server (start-server :address "127.0.0.1"
                                 :port 18080
                                 :store store
                                 :runtime runtime)))
      (unwind-protect
           (multiple-value-bind (body status)
               (request
                "/api/v1/namespaces/default/pods/hello/exec?command=sh&container=web&stdout=true&stderr=true"
                :method :post)
             (is (= 400 status))
             (is (string= "BadRequest"
                          (gethash "reason" (response-object body))))
             (is (null (gr8s::fake-runtime-last-exec runtime))))
        (stop-server server)))))

(defun read-exact-octets (stream count)
  (let ((result (make-array count :element-type '(unsigned-byte 8))))
    (loop with offset = 0
          while (< offset count)
          for next = (read-sequence result stream :start offset)
          do (when (= next offset)
               (error "stream ended after ~D of ~D octets" offset count))
             (setf offset next))
    result))

(defun read-test-websocket-frame (stream)
  (let* ((first (read-byte stream))
         (second (read-byte stream))
         (opcode (logand first #x0f))
         (masked-p (logbitp 7 second))
         (short-length (logand second #x7f))
         (length
           (case short-length
             (126 (+ (ash (read-byte stream) 8) (read-byte stream)))
             (127 (loop with value = 0
                        repeat 8
                        do (setf value (+ (ash value 8)
                                          (read-byte stream)))
                        finally (return value)))
             (otherwise short-length)))
         (mask (and masked-p (read-exact-octets stream 4)))
         (payload (read-exact-octets stream length)))
    (when mask
      (loop for index below length
            do (setf (aref payload index)
                     (logxor (aref payload index)
                             (aref mask (mod index 4))))))
    (values opcode payload)))

(test noninteractive-pod-exec-frames-sync-output
  (with-temporary-store (store path)
    (values path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (server nil)
           (client nil))
      (gr8s::set-fake-runtime-exec-result
       runtime
       (gr8s::make-runtime-exec-result
        :stdout (trivial-utf-8:string-to-utf-8-bytes "sync out\n")
        :stderr (trivial-utf-8:string-to-utf-8-bytes "sync err\n")
        :exit-code 0))
      (unwind-protect
           (progn
             (setf server (start-server :address "127.0.0.1" :port 18080
                                        :store store :runtime runtime)
                   client (usocket:socket-connect
                           "127.0.0.1" 18080
                           :element-type '(unsigned-byte 8)))
             (let ((stream (usocket:socket-stream client)))
               (write-sequence
                (gr8s::ascii-octets
                 (format nil
                         "POST /api/v1/namespaces/default/pods/hello/exec?command=sh&command=-c&command=printf&container=web&stdout=true&stderr=true HTTP/1.1~C~CHost: 127.0.0.1:18080~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-Websocket-Key: dGhlIHNhbXBsZSBub25jZQ==~C~CSec-Websocket-Version: 13~C~CSec-Websocket-Protocol: v5.channel.k8s.io~C~CContent-Length: 0~C~C~C~C"
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed))
                stream)
               (finish-output stream)
               (multiple-value-bind (status headers)
                   (gr8s::parse-http-response-head
                    (gr8s::read-http-response-head stream))
                 (is (= 101 status))
                 (is (string= "v5.channel.k8s.io"
                              (cdr (assoc :sec-websocket-protocol headers))))
                 (is (string= "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
                              (cdr (assoc :sec-websocket-accept headers)))))
               (multiple-value-bind (opcode payload)
                   (read-test-websocket-frame stream)
                 (is (= 2 opcode))
                 (is (= 1 (aref payload 0)))
                 (is (string= "sync out\n"
                              (trivial-utf-8:utf-8-bytes-to-string
                               (subseq payload 1)))))
               (multiple-value-bind (opcode payload)
                   (read-test-websocket-frame stream)
                 (is (= 2 opcode))
                 (is (= 2 (aref payload 0)))
                 (is (string= "sync err\n"
                              (trivial-utf-8:utf-8-bytes-to-string
                               (subseq payload 1)))))
               (multiple-value-bind (opcode payload)
                   (read-test-websocket-frame stream)
                 (is (= 8 opcode))
                 (is (zerop (length payload))))
               (is (equal (list (pod-uid pod) "web"
                                '("sh" "-c" "printf") :sync 30)
                          (gr8s::fake-runtime-last-exec runtime)))))
        (when client (ignore-errors (usocket:socket-close client)))
        (when server (stop-server server))))))

(test noninteractive-exec-exit-status-is-kubernetes-shaped
  (let* ((bytes (gr8s::exec-exit-status-bytes 23))
         (status
           (com.inuoe.jzon:parse
            (trivial-utf-8:utf-8-bytes-to-string bytes))))
    (is (string= "Failure" (gethash "status" status)))
    (is (string= "NonZeroExitCode" (gethash "reason" status)))
    (is (search "exit code 23" (gethash "message" status)))
    (let* ((details (gethash "details" status))
           (cause (aref (gethash "causes" details) 0)))
      (is (string= "ExitCode" (gethash "reason" cause)))
      (is (string= "23" (gethash "message" cause))))))

(test pod-exec-proxies-the-upgraded-stream-in-both-directions
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (listener
             (usocket:socket-listen
              "127.0.0.1" 18081 :reuse-address t
              :element-type '(unsigned-byte 8)))
           (upstream-request nil)
           (upstream-payload nil)
           (upstream-thread
             (bt:make-thread
              (lambda ()
                (let* ((socket (usocket:socket-accept listener
                                                      :element-type
                                                      '(unsigned-byte 8)))
                       (stream (usocket:socket-stream socket)))
                  (unwind-protect
                       (progn
                         (setf upstream-request
                               (gr8s::octets-as-ascii
                                (gr8s::read-http-response-head stream)))
                         (write-sequence
                          (gr8s::ascii-octets
                           (format nil
                                   "HTTP/1.1 101 Switching Protocols~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-Websocket-Protocol: v5.channel.k8s.io~C~C~C~C"
                                   #\Return #\Linefeed #\Return #\Linefeed
                                   #\Return #\Linefeed #\Return #\Linefeed
                                   #\Return #\Linefeed))
                          stream)
                         (finish-output stream)
                         (setf upstream-payload
                               (read-exact-octets stream 4))
                         (write-sequence (gr8s::ascii-octets "pong") stream)
                         (finish-output stream))
                    (ignore-errors (usocket:socket-close socket)))))
              :name "gr8s fake exec runtime"))
           (server nil)
           (client nil))
      (gr8s::set-fake-runtime-exec-url
       runtime "http://127.0.0.1:18081/exec/token")
      (unwind-protect
           (progn
             (setf server (start-server :address "127.0.0.1" :port 18080
                                        :store store :runtime runtime))
             (setf client
                   (usocket:socket-connect
                    "127.0.0.1" 18080 :element-type '(unsigned-byte 8)))
             (let ((stream (usocket:socket-stream client)))
               (write-sequence
                (gr8s::ascii-octets
                 (format nil
                         "POST /api/v1/namespaces/default/pods/hello/exec?command=sh&command=-i&container=web&stdin=true&stdout=true&tty=true HTTP/1.1~C~CHost: 127.0.0.1:18080~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-Websocket-Key: key==~C~CSec-Websocket-Version: 13~C~CSec-Websocket-Protocol: v5.channel.k8s.io~C~CContent-Length: 0~C~C~C~C"
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed))
                stream)
               (finish-output stream)
               (multiple-value-bind (status headers)
                   (gr8s::parse-http-response-head
                    (gr8s::read-http-response-head stream))
                 (declare (ignore headers))
                 (is (= 101 status))
                 (unless (= 101 status)
                   (error "interactive exec upgrade returned HTTP ~D" status)))
               (write-sequence (gr8s::ascii-octets "ping") stream)
               (finish-output stream)
               (is (equalp (gr8s::ascii-octets "pong")
                           (read-exact-octets stream 4))))
             (bt:join-thread upstream-thread)
             (is (search "POST /exec/token HTTP/1.1" upstream-request))
             (is (equalp (gr8s::ascii-octets "ping") upstream-payload))
             (is (equal (list (pod-uid pod) "web" '("sh" "-i")
                              t t nil t)
                        (gr8s::fake-runtime-last-exec runtime))))
        (when client (ignore-errors (usocket:socket-close client)))
        (when server (stop-server server))
        (ignore-errors (usocket:socket-close listener))))))

(test interactive-pod-exec-crosses-the-remote-agent-boundary
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "remote-exec-node" :name "worker-exec"
                                  :pod-cidr "10.88.6.0/24"))
    (let* ((node-server
             (gr8s:start-node-grpc-server
              store :host "127.0.0.1" :port 0))
           (fake-runtime (make-fake-runtime))
           (node-runtime
             (gr8s::make-node-runtime
              (merge-pathnames "worker-exec/runtime/" path) fake-runtime nil))
           (control-runtime
             (gr8s::make-control-plane-runtime store node-server))
           (reconciler (make-reconciler store control-runtime))
           (identity-path
             (merge-pathnames "worker-exec/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil)
           (listener
             (usocket:socket-listen
              "127.0.0.1" 0 :reuse-address t
              :element-type '(unsigned-byte 8)))
           (runtime-port (usocket:get-local-port listener))
           (upstream-frames nil)
           (upstream-error nil)
           (upstream-thread nil)
           (http-server nil)
           (client nil)
           (pod nil))
      (setf upstream-thread
            (bt:make-thread
             (lambda ()
               (handler-case
                   (let* ((socket
                            (usocket:socket-accept
                             listener :element-type '(unsigned-byte 8)))
                          (stream (usocket:socket-stream socket)))
                     (unwind-protect
                          (progn
                            (gr8s::read-http-response-head stream)
                            (write-sequence
                             (gr8s::ascii-octets
                              (format nil
                                      "HTTP/1.1 101 Switching Protocols~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-WebSocket-Protocol: v5.channel.k8s.io~C~C~C~C"
                                      #\Return #\Linefeed #\Return #\Linefeed
                                      #\Return #\Linefeed #\Return #\Linefeed
                                      #\Return #\Linefeed))
                             stream)
                            (finish-output stream)
                            (loop repeat 3
                                  do
                              (multiple-value-bind (opcode payload)
                                  (gr8s::read-websocket-frame stream)
                                (push (cons opcode payload) upstream-frames)))
                            (gr8s::write-websocket-frame
                             stream 2
                             (concatenate
                              '(vector (unsigned-byte 8)) #(1)
                              (trivial-utf-8:string-to-utf-8-bytes
                               "through remote agent\n")))
                            (gr8s::write-websocket-frame
                             stream 2
                             (concatenate
                              '(vector (unsigned-byte 8)) #(3)
                              (gr8s::exec-exit-status-bytes 7)))
                            (gr8s::write-websocket-frame stream 8 #()))
                       (ignore-errors (usocket:socket-close socket))))
                 (error (condition) (setf upstream-error condition))))
             :name "gr8s HTTP remote exec fake runtime"))
      (gr8s::set-fake-runtime-exec-url
       fake-runtime
       (format nil "http://127.0.0.1:~D/exec/token" runtime-port))
      (unwind-protect
           (progn
             (gr8s::start-node-runtime node-runtime)
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1"
                       (gr8s:node-grpc-server-port node-server)
                       "worker-exec" identity-path
                       (lambda (snapshot)
                         (gr8s::reconcile-node-snapshot
                          node-runtime snapshot))
                       :operation-handler
                       (lambda (variant payload emit)
                         (gr8s::dispatch-node-operation
                          node-runtime variant payload emit))
                       :reconnect-delay 0.01 :control control))
                    :name "gr8s HTTP remote exec agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-exec")))
               :timeout 5))
             (setf pod (create-pod store (parse-pod *valid-pod-json*)))
             (reconcile-pod reconciler "default" "hello")
             (is-true
              (wait-until
               (lambda () (runtime-observe fake-runtime (pod-uid pod)))
               :timeout 5))
             (setf http-server
                   (start-server :address "127.0.0.1" :port 18082
                                 :store store :runtime control-runtime
                                 :reconciler reconciler)
                   client
                   (usocket:socket-connect
                    "127.0.0.1" 18082 :element-type '(unsigned-byte 8)))
             (let ((stream (usocket:socket-stream client)))
               (write-sequence
                (gr8s::ascii-octets
                 (format nil
                         "POST /api/v1/namespaces/default/pods/hello/exec?command=sh&command=-i&container=web&stdin=true&stdout=true&tty=true HTTP/1.1~C~CHost: 127.0.0.1:18082~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==~C~CSec-WebSocket-Version: 13~C~CSec-WebSocket-Protocol: v5.channel.k8s.io~C~CContent-Length: 0~C~C~C~C"
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed))
                stream)
               (finish-output stream)
               (multiple-value-bind (status headers)
                   (gr8s::parse-http-response-head
                    (gr8s::read-http-response-head stream))
                 (declare (ignore headers))
                 (is (= 101 status)))
               (gr8s::write-websocket-frame
                stream 2
                (concatenate
                 '(vector (unsigned-byte 8)) #(0)
                 (trivial-utf-8:string-to-utf-8-bytes "echo remote\n"))
                :masked-p t)
               (gr8s::write-websocket-frame
                stream 2
                (concatenate
                 '(vector (unsigned-byte 8)) #(4)
                 (trivial-utf-8:string-to-utf-8-bytes
                  "{\"width\":100,\"height\":30}"))
                :masked-p t)
               (gr8s::write-websocket-frame stream 2 #(255 0) :masked-p t)
               (multiple-value-bind (opcode payload)
                   (gr8s::read-websocket-frame stream)
                 (is (= 2 opcode))
                 (is (= 1 (aref payload 0)))
                 (is (string= "through remote agent\n"
                              (trivial-utf-8:utf-8-bytes-to-string
                               (subseq payload 1)))))
               (multiple-value-bind (opcode payload)
                   (gr8s::read-websocket-frame stream)
                 (is (= 2 opcode))
                 (is (= 3 (aref payload 0)))
                 (let ((status
                         (com.inuoe.jzon:parse
                          (trivial-utf-8:utf-8-bytes-to-string
                           (subseq payload 1)))))
                   (is (string= "NonZeroExitCode"
                                (gethash "reason" status)))))
               (multiple-value-bind (opcode payload)
                   (gr8s::read-websocket-frame stream)
                 (is (= 8 opcode))
                 (is (zerop (length payload)))))
             (bt:join-thread upstream-thread)
             (is (null upstream-error) "~A" upstream-error)
             (let ((frames (nreverse upstream-frames)))
               (is (= 3 (length frames)))
               (is (= 0 (aref (cdr (first frames)) 0)))
               (is (= 4 (aref (cdr (second frames)) 0)))
               (is (equalp #(255 0) (cdr (third frames)))))
             (is (equal (list (pod-uid pod) "web" '("sh" "-i")
                              t t nil t)
                        (gr8s::fake-runtime-last-exec fake-runtime))))
        (when client (ignore-errors (usocket:socket-close client)))
        (when http-server (stop-server http-server))
        (gr8s::cancel-node-session control)
        (when agent-thread (ignore-errors (bt:join-thread agent-thread)))
        (gr8s::stop-node-runtime node-runtime)
        (gr8s:stop-node-grpc-server node-server)
        (ignore-errors (usocket:socket-close listener))))))

(test closing-kubectl-exec-cancels-the-remote-agent-operation
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "cancel-exec-node"
                                  :name "worker-cancel-exec"
                                  :pod-cidr "10.88.7.0/24"))
    (let* ((node-server
             (gr8s:start-node-grpc-server
              store :host "127.0.0.1" :port 0))
           (fake-runtime (make-fake-runtime))
           (node-runtime
             (gr8s::make-node-runtime
              (merge-pathnames "worker-cancel-exec/runtime/" path)
              fake-runtime nil))
           (control-runtime
             (gr8s::make-control-plane-runtime store node-server))
           (reconciler (make-reconciler store control-runtime))
           (identity-path
             (merge-pathnames "worker-cancel-exec/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil)
           (listener
             (usocket:socket-listen
              "127.0.0.1" 0 :reuse-address t
              :element-type '(unsigned-byte 8)))
           (runtime-port (usocket:get-local-port listener))
           (upstream-connected-p nil)
           (upstream-closed-p nil)
           (upstream-error nil)
           (upstream-thread nil)
           (http-server nil)
           (client nil)
           (pod nil))
      (setf upstream-thread
            (bt:make-thread
             (lambda ()
               (handler-case
                   (let* ((socket
                            (usocket:socket-accept
                             listener :element-type '(unsigned-byte 8)))
                          (stream (usocket:socket-stream socket)))
                     (unwind-protect
                          (progn
                            (gr8s::read-http-response-head stream)
                            (write-sequence
                             (gr8s::ascii-octets
                              (format nil
                                      "HTTP/1.1 101 Switching Protocols~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-WebSocket-Protocol: v5.channel.k8s.io~C~C~C~C"
                                      #\Return #\Linefeed #\Return #\Linefeed
                                      #\Return #\Linefeed #\Return #\Linefeed
                                      #\Return #\Linefeed))
                             stream)
                            (finish-output stream)
                            (setf upstream-connected-p t)
                            (handler-case (read-byte stream)
                              (end-of-file () nil)
                              (error () nil))
                            (setf upstream-closed-p t))
                       (ignore-errors (usocket:socket-close socket))))
                 (error (condition) (setf upstream-error condition))))
             :name "gr8s cancelled HTTP exec fake runtime"))
      (gr8s::set-fake-runtime-exec-url
       fake-runtime
       (format nil "http://127.0.0.1:~D/exec/token" runtime-port))
      (unwind-protect
           (progn
             (gr8s::start-node-runtime node-runtime)
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1"
                       (gr8s:node-grpc-server-port node-server)
                       "worker-cancel-exec" identity-path
                       (lambda (snapshot)
                         (gr8s::reconcile-node-snapshot
                          node-runtime snapshot))
                       :operation-handler
                       (lambda (variant payload emit)
                         (gr8s::dispatch-node-operation
                          node-runtime variant payload emit))
                       :reconnect-delay 0.01 :control control))
                    :name "gr8s cancelled HTTP exec agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-cancel-exec")))
               :timeout 5))
             (setf pod (create-pod store (parse-pod *valid-pod-json*)))
             (reconcile-pod reconciler "default" "hello")
             (is-true
              (wait-until
               (lambda () (runtime-observe fake-runtime (pod-uid pod)))
               :timeout 5))
             (setf http-server
                   (start-server :address "127.0.0.1" :port 18084
                                 :store store :runtime control-runtime
                                 :reconciler reconciler)
                   client
                   (usocket:socket-connect
                    "127.0.0.1" 18084 :element-type '(unsigned-byte 8)))
             (let ((stream (usocket:socket-stream client)))
               (write-sequence
                (gr8s::ascii-octets
                 (format nil
                         "POST /api/v1/namespaces/default/pods/hello/exec?command=sh&command=-i&container=web&stdin=true&stdout=true&tty=true HTTP/1.1~C~CHost: 127.0.0.1:18084~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==~C~CSec-WebSocket-Version: 13~C~CSec-WebSocket-Protocol: v5.channel.k8s.io~C~CContent-Length: 0~C~C~C~C"
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed #\Return #\Linefeed
                         #\Return #\Linefeed))
                stream)
               (finish-output stream)
               (multiple-value-bind (status headers)
                   (gr8s::parse-http-response-head
                    (gr8s::read-http-response-head stream))
                 (declare (ignore headers))
                 (is (= 101 status)))
               (is-true
                (wait-until (lambda () upstream-connected-p) :timeout 3))
               (is-true
                (wait-until
                 (lambda ()
                   (bt:with-lock-held
                       ((gr8s::node-runtime-operations-lock node-runtime))
                     (= 1 (hash-table-count
                           (gr8s::node-runtime-operations node-runtime)))))
                 :timeout 3))
               (gr8s::write-websocket-frame stream 8 #() :masked-p t))
             (is-true
              (wait-until (lambda () upstream-closed-p) :timeout 3))
             (is-true
              (wait-until
               (lambda ()
                 (bt:with-lock-held
                     ((gr8s::node-runtime-operations-lock node-runtime))
                   (zerop
                    (hash-table-count
                     (gr8s::node-runtime-operations node-runtime)))))
               :timeout 3))
             (is-true
              (wait-until
               (lambda ()
                 (bt:with-lock-held ((gr8s::node-grpc-server-lock node-server))
                   (zerop
                    (hash-table-count
                     (gr8s::node-grpc-server-operations node-server)))))
               :timeout 3))
             (bt:join-thread upstream-thread)
             (setf upstream-thread nil)
             (is (null upstream-error) "~A" upstream-error))
        (when client (ignore-errors (usocket:socket-close client)))
        (when http-server (stop-server http-server))
        (gr8s::cancel-node-session control)
        (when agent-thread (ignore-errors (bt:join-thread agent-thread)))
        (gr8s::stop-node-runtime node-runtime)
        (gr8s:stop-node-grpc-server node-server)
        (ignore-errors (usocket:socket-close listener))
        (when upstream-thread
          (ignore-errors (bt:join-thread upstream-thread)))))))
