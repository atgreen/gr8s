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

(test legacy-discovery-fallback-for-aggregated-discovery-clients
  (let ((server (start-server :address "127.0.0.1" :port 18080)))
    (unwind-protect
         (loop for (path kind) in '(("/api" "APIVersions")
                                   ("/apis" "APIGroupList")
                                   ("/api/v1" "APIResourceList"))
               do (multiple-value-bind (body status headers)
                      (request path :additional-headers
                               '(("Accept" . "application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList,application/json")))
                    (is (= 200 status))
                    ;; Sonobuoy's client-go requires the exact legacy media type.
                    (is (string= "application/json"
                                 (cdr (assoc :content-type headers))))
                    (is (string= kind (gethash "kind" (response-object body))))))
      (stop-server server))))

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
               (is (< 1
                      (parse-integer
                       (gethash "resourceVersion"
                                (gethash "metadata"
                                         (response-object body)))))))
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
               (is (< 2
                      (parse-integer
                       (gethash "resourceVersion"
                                (gethash "metadata"
                                         (response-object body))))))
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

(test noninteractive-pod-exec-websocket-get-frames-sync-output
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
                         "GET /api/v1/namespaces/default/pods/hello/exec?command=sh&command=-c&command=printf&container=web&stdout=true&stderr=true HTTP/1.1~C~CHost: 127.0.0.1:18080~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-Websocket-Key: dGhlIHNhbXBsZSBub25jZQ==~C~CSec-Websocket-Version: 13~C~CSec-Websocket-Protocol: v5.channel.k8s.io~C~CContent-Length: 0~C~C~C~C"
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
                 (is (= 2 opcode))
                 (is (= 3 (aref payload 0)))
                 (is (string= "Success"
                              (gethash "status" (com.inuoe.jzon:parse
                               (trivial-utf-8:utf-8-bytes-to-string (subseq payload 1)))))))
               (multiple-value-bind (opcode payload)
                   (read-test-websocket-frame stream)
                 (is (= 8 opcode))
                 (is (equalp #(3 232) payload)))
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
           (upstream-streams nil)
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
                            (let ((streams (fake-spdy-accept stream 4)))
                              (loop repeat 3
                                    do (push (fake-spdy-read-frame stream) upstream-frames))
                              (setf upstream-streams streams)
                              (fake-spdy-send stream (cdr (assoc "stdout" streams :test #'equal))
                                              "through remote agent\n" :fin t)
                              (fake-spdy-send stream (cdr (assoc "error" streams :test #'equal)) nil
                                              :octets (gr8s::exec-exit-status-bytes 7) :fin t)
                              (ignore-errors (loop while (fake-spdy-read-frame stream)))))
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
                 (is (equalp #(3 232) payload))))
             (bt:join-thread upstream-thread)
             (is (null upstream-error) "~A" upstream-error)
             (let ((frames (nreverse upstream-frames)))
               (is (= 3 (length frames)))
               (is (= (cdr (assoc "stdin" upstream-streams :test #'equal)) (second (first frames))))
               (is (= (cdr (assoc "resize" upstream-streams :test #'equal)) (second (second frames))))
               (is (= (cdr (assoc "stdin" upstream-streams :test #'equal)) (second (third frames))))
               (is-true (third (third frames))))
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
                            (fake-spdy-accept stream 4)
                            (setf upstream-connected-p t)
                            (handler-case (loop while (fake-spdy-read-frame stream))
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

(test pod-http-routes-isolate-namespaces-and-filter-cluster-lists
  (with-temporary-store (store directory)
    (let ((server (start-server :address "127.0.0.1" :port 18080 :store store
                                :runtime (make-fake-runtime))))
      (unwind-protect
           (progn
             (dolist (namespace '("default" "sonobuoy" "kube-system"))
               (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
                      (metadata (gethash "metadata" object)))
                 (setf (gethash "labels" metadata)
                       (gr8s::json-object "app" namespace))
                 (multiple-value-bind (body status)
                     (request (format nil "/api/v1/namespaces/~A/pods" namespace)
                              :method :post :content-type "application/json"
                              :content (com.inuoe.jzon:stringify object))
                   (is (= 201 status))
                   (is (string= namespace (gethash "namespace" (gethash "metadata" (response-object body))))))))
             (dolist (case '(("/api/v1/pods" 3)
                             ("/api/v1/pods?fieldSelector=status.phase%3DRunning" 3)
                             ("/api/v1/pods?fieldSelector=status.phase%3DSucceeded" 0)
                             ("/api/v1/namespaces/sonobuoy/pods" 1)
                             ("/api/v1/pods?labelSelector=app%3Dsonobuoy" 1)
                             ("/api/v1/pods?fieldSelector=metadata.namespace%3Dkube-system" 1)
                             ("/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dkube-dns" 0)))
               (multiple-value-bind (body status) (request (first case) :preserve-uri t)
                 (is (= 200 status))
                 (is (= (second case) (length (gethash "items" (response-object body)))))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/sonobuoy/pods/hello")
               (is (= 200 status))
               (is (string= "sonobuoy" (gethash "namespace" (gethash "metadata" (response-object body))))))
             (let ((object (com.inuoe.jzon:parse *valid-pod-json*)))
               (setf (gethash "namespace" (gethash "metadata" object)) "default")
               (multiple-value-bind (body status)
                   (request "/api/v1/namespaces/sonobuoy/pods" :method :post
                            :content-type "application/json" :content (com.inuoe.jzon:stringify object))
                 (declare (ignore body))
                 (is (= 400 status))))
             (multiple-value-bind (body status)
                 (request "/api/v1/namespaces/sonobuoy/pods/hello" :method :delete)
               (declare (ignore body))
               (is (= 200 status)))
             (is (string= "default" (pod-namespace (get-pod store "default" "hello"))))
             (is (string= "kube-system" (pod-namespace (get-pod (open-store directory) "kube-system" "hello")))))
        (stop-server server)))))

(test kubernetes-version-reports-the-conformance-target
  (let ((server (start-server :address "127.0.0.1" :port 18080)))
    (unwind-protect
         (multiple-value-bind (body status) (request "/version")
           (is (= 200 status))
           (let ((version (response-object body)))
             ;; Major/minor and gitVersion come from the single source of truth
             ;; (the ASDF :version via version-string), not a hardcoded string.
             (is (string= "1" (gethash "major" version)))
             (is (string= "36" (gethash "minor" version)))
             (is (string= (gr8s::kubernetes-git-version) (gethash "gitVersion" version)))
             (is (eql 0 (search "v1.36" (gethash "gitVersion" version)))
                 "gitVersion is the Kubernetes API version with our suffix")))
      (stop-server server))))

(test stopping-an-exec-input-reader-while-it-is-signalling-unwinds-it
  ;; podster-uqb.106: an error signalled from the interrupt landed while the thread was
  ;; already in SIGNAL for a stream error, found no handler, and aborted the image.
  (let* ((signalling nil) (handled nil) (unwound nil) (escaped nil)
         (reader
           (bt:make-thread
            (lambda ()
              (handler-case
                  (progn
                    (gr8s::with-exec-input-reader-stop
                     (handler-case
                         (handler-bind ((error (lambda (condition)
                                                 (declare (ignore condition))
                                                 ;; Wait inside the handler test, where the interrupt lands.
                                                 (setf signalling t)
                                                 (loop repeat 500 do (sleep 0.01)))))
                           (error "stream closed"))
                       (error () (setf handled t))))
                    (setf unwound t))
                (serious-condition (condition) (setf escaped condition))))
            :name "gr8s test exec input")))
    (is-true (wait-until (lambda () signalling) :timeout 5))
    (gr8s::stop-exec-input-reader reader)
    (bt:join-thread reader)
    (is-true unwound)
    (is-false handled)
    (is (null escaped))))

(test a-late-stop-of-an-exec-input-reader-does-nothing
  (let* ((release nil) (finished nil)
         (reader
           (bt:make-thread
            (lambda ()
              (gr8s::with-exec-input-reader-stop nil)
              (loop until release do (sleep 0.01))
              (setf finished t))
            :name "gr8s test exec input done")))
    (gr8s::stop-exec-input-reader reader)
    (setf release t)
    (bt:join-thread reader)
    (is-true finished)))

(defun connected-test-sockets (listener)
  "Return a new connection to LISTENER and its accepted other end."
  (let* ((near (usocket:socket-connect "127.0.0.1" (usocket:get-local-port listener)
                                       :element-type '(unsigned-byte 8)))
         (far (usocket:socket-accept listener :element-type '(unsigned-byte 8))))
    (values near far)))

(test a-finished-exec-relay-does-not-touch-a-connection-that-reuses-its-descriptor
  ;; podster-uqb.106: connections elsewhere in the process died with END-OF-FILE or
  ;; BROKEN-PIPE. A socket's numeric descriptor survives closing its stream, so a late
  ;; shutdown from the relay's other thread reached whoever had that number by then.
  (let ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :backlog 64
                                                        :element-type '(unsigned-byte 8)))
        (spares nil))
    (unwind-protect
         (multiple-value-bind (runtime runtime-far) (connected-test-sockets listener)
           (multiple-value-bind (client client-far) (connected-test-sockets listener)
             (let* ((descriptor (sb-bsd-sockets:socket-file-descriptor (usocket:socket runtime)))
                    (relay (bt:make-thread
                            (lambda ()
                              (gr8s::relay-runtime-stream (usocket:socket-stream client)
                                                          (usocket:socket-stream runtime) runtime))
                            :name "gr8s test exec relay")))
               ;; The runtime ends the stream, so the relay closes its side.
               (usocket:socket-close runtime-far)
               (bt:join-thread relay)
               ;; Take that descriptor number for a new, unrelated connection.
               (multiple-value-bind (fresh fresh-far)
                   (loop
                     (multiple-value-bind (near far) (connected-test-sockets listener)
                       (when (= descriptor (sb-bsd-sockets:socket-file-descriptor (usocket:socket near)))
                         (return (values near far)))
                       (push near spares)
                       (push far spares)
                       (when (> (length spares) 200) (error "descriptor ~D never came back" descriptor))))
                 (unwind-protect
                      (progn
                        ;; The client leaves, ending the relay's other thread.
                        (usocket:socket-close client-far)
                        (is-true (wait-until
                                  (lambda ()
                                    (notany (lambda (thread)
                                              (equal "gr8s exec client-to-runtime" (bt:thread-name thread)))
                                            (bt:all-threads)))
                                  :timeout 5))
                        (let ((out (usocket:socket-stream fresh-far)))
                          (write-byte 42 out)
                          (finish-output out))
                        (is (eql 42 (read-byte (usocket:socket-stream fresh) nil nil)))
                        (let ((out (usocket:socket-stream fresh)))
                          (write-byte 43 out)
                          (finish-output out))
                        (is (eql 43 (read-byte (usocket:socket-stream fresh-far) nil nil))))
                   (usocket:socket-close fresh)
                   (usocket:socket-close fresh-far))))
             (ignore-errors (usocket:socket-close client))))
      (dolist (socket spares) (ignore-errors (usocket:socket-close socket)))
      (usocket:socket-close listener))))
