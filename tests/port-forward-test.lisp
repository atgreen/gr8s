;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify Pod port forwarding. Compressed headers come from real zlib, the node
;;;; path runs through a real agent session to a scripted runtime stream, and, when
;;;; kubectl is available, a real kubectl forwards through a real API server, over
;;;; both the WebSocket tunnel and plain SPDY. Set GR8S_TEST_KUBECTL to its path.

(in-package #:gr8s/tests)
(def-suite port-forward :in gr8s)
(in-suite port-forward)

;;; Header blocks

(defparameter *zlib-spdy-header-blocks*
  '("78f9e3c6a7c202253a703a2b294a4dcc851625aca9a0808614cb45e01c6061606100a4398b20d198094ade8c0600000000ffff"
    "c2aa19540e2512d60b000000ffff"
    "ecd64b0a80300c84617782a7491f69d3e334690adec0e35bd7827b61d6c3b7fd994fbb5f2b3ae713d5630b4d230b170f1698ac4bca36a789f21a521f3ac88d923467718d5193965c8b50934114151e1e1e1e1e1e1e1efe5ffe751deb0d0000ffff")
  "One compression stream of three blocks, made by zlib with SPDY's dictionary and a sync flush each.")

(defun hex-octets (text)
  (coerce (loop for index from 0 below (length text) by 2
                collect (parse-integer text :start index :end (+ index 2) :radix 16))
          '(simple-array (unsigned-byte 8) (*))))

(test the-header-dictionary-is-the-one-spdy-names
  (is (= 1423 (length gr8s::+spdy-header-dictionary+)))
  (let ((a 1) (b 0))
    (loop for octet across gr8s::+spdy-header-dictionary+
          do (setf a (mod (+ a octet) 65521) b (mod (+ b a) 65521)))
    (is (= #xE3C6A7C2 (+ (* b 65536) a)))))

(test header-blocks-compressed-by-real-zlib-inflate
  (let ((inflater (gr8s::make-spdy-inflater))
        (noise (format nil "~{~A~}" (loop repeat 40 collect "19b25856e1c150ca834cffc8b59b23adbd0ec0389e58eb22b3b64768098d002b"))))
    (destructuring-bind (first second third) (mapcar #'hex-octets *zlib-spdy-header-blocks*)
      (is (equal '(("streamtype" . "error") ("port" . "8080") ("requestid" . "0"))
                 (gr8s::spdy-inflate-header-block inflater first)))
      (is (equal '(("streamtype" . "data") ("port" . "8080") ("requestid" . "0"))
                 (gr8s::spdy-inflate-header-block inflater second))
          "the second block refers back into the first")
      (is (equal `(("streamtype" . "data") ("x-noise" . ,noise) ("requestid" . "7"))
                 (gr8s::spdy-inflate-header-block inflater third))))))

(test corrupt-header-blocks-are-refused
  (flet ((refused (block)
           (signals error (gr8s::spdy-inflate-header-block (gr8s::make-spdy-inflater) block))))
    (refused (hex-octets "78f9deadbeef00"))
    (refused (hex-octets "78f9"))
    ;; A stored block whose length check is wrong.
    (refused (hex-octets "78f9e3c6a7c2000100000000"))
    ;; A distance reaching back further than anything sent, past the dictionary.
    (refused (concatenate '(simple-array (unsigned-byte 8) (*))
                          (hex-octets "78f9e3c6a7c2") (hex-octets "ffffffffffffffffffffffff")))))

;;; Authorization

(test opening-a-way-into-a-pod-takes-create-even-through-a-get
  (dolist (subresource '("portforward" "exec" "attach"))
    (let ((path (format nil "/api/v1/namespaces/default/pods/hello/~A" subresource)))
      (dolist (method '(:get :post))
        (is (equal (list "create" "" (format nil "pods/~A" subresource) "hello" "default")
                   (multiple-value-list (gr8s::kubernetes-authorization-target path method)))
            "~A ~A" method path))))
  ;; Reading a Pod, its log or its proxy is still a read.
  (is (equal "get" (gr8s::kubernetes-authorization-target "/api/v1/namespaces/default/pods/hello" :get)))
  (is (equal "get" (gr8s::kubernetes-authorization-target "/api/v1/namespaces/default/pods/hello/log" :get)))
  (is (equal "get" (gr8s::kubernetes-authorization-target "/api/v1/namespaces/default/pods/hello/proxy" :get))))

;;; The node path

(defun runtime-accept-forward (stream)
  "Answer the upgrade as the runtime would, returning the request head and an alist of stream types to IDs."
  (let ((head (map 'string #'code-char (gr8s::read-http-response-head stream))))
    (write-sequence
     (gr8s::ascii-octets
      (format nil "HTTP/1.1 101 Switching Protocols~C~CConnection: Upgrade~C~CUpgrade: SPDY/3.1~C~C~C~C"
              #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))
     stream)
    (finish-output stream)
    (values head (loop repeat 2
                       for frame = (fake-spdy-read-frame stream)
                       collect (cons (third frame) (second frame))))))

(defmacro with-forwarding-agent ((runtime pod stream-listener) &body body)
  "Run BODY with a real agent session behind control-plane RUNTIME, for assigned POD.
Forwarding URLs lead to STREAM-LISTENER, where the test plays the container runtime."
  (let ((store (gensym "STORE")) (path (gensym "PATH")) (node-server (gensym "SERVER")) (fake (gensym "FAKE"))
        (node-runtime (gensym "NODE")) (control (gensym "CONTROL")) (agent (gensym "AGENT")))
    `(with-temporary-store (,store ,path)
       (gr8s:register-node ,store (gr8s:make-node-record :id "forward-node" :name "worker-forward"
                                                         :pod-cidr "10.88.7.0/24"))
       (let* ((,node-server (gr8s:start-node-grpc-server ,store :host "127.0.0.1" :port 0))
              (,fake (make-fake-runtime))
              (,node-runtime (gr8s::make-node-runtime (merge-pathnames "worker-forward/runtime/" ,path) ,fake nil))
              (,runtime (gr8s::make-control-plane-runtime ,store ,node-server))
              (reconciler (make-reconciler ,store ,runtime))
              (,control (gr8s::make-node-session-control))
              (,stream-listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t
                                                                     :element-type '(unsigned-byte 8)))
              (,pod nil)
              (,agent nil))
         (gr8s::set-fake-runtime-exec-url
          ,fake (format nil "http://127.0.0.1:~D/portforward/token" (usocket:get-local-port ,stream-listener)))
         (unwind-protect
              (progn
                (gr8s::start-node-runtime ,node-runtime)
                (setf ,agent
                      (bt:make-thread
                       (lambda ()
                         (gr8s:run-node-session
                          "127.0.0.1" (gr8s:node-grpc-server-port ,node-server) "worker-forward"
                          (merge-pathnames "worker-forward/identity.json" ,path)
                          (lambda (snapshot) (gr8s::reconcile-node-snapshot ,node-runtime snapshot))
                          :operation-handler
                          (lambda (variant payload emit)
                            (gr8s::dispatch-node-operation ,node-runtime variant payload emit))
                          :reconnect-delay 0.01 :control ,control))
                       :name "gr8s test port-forward agent"))
                (is-true (wait-until (lambda () (gr8s:node-record-ready-p (gr8s:get-node ,store "worker-forward")))
                                     :timeout 5))
                (setf ,pod (create-pod ,store (parse-pod *valid-pod-json*)))
                (reconcile-pod reconciler "default" "hello")
                (is-true (wait-until (lambda () (runtime-observe ,fake (pod-uid ,pod))) :timeout 5))
                ,@body)
           (ignore-errors (gr8s::cancel-node-session ,control))
           (ignore-errors (gr8s::cancel-all-node-operations ,node-runtime "test over"))
           (when ,agent (ignore-errors (bt:join-thread ,agent)))
           (ignore-errors (gr8s:stop-node-grpc-server ,node-server))
           (ignore-errors (usocket:socket-close ,stream-listener)))))))

(test large-output-does-not-stall-the-node-session
  ;; The node's reading thread sends these logs itself, far past one flow-control window.
  (with-temporary-store (store path)
    (gr8s:register-node store (gr8s:make-node-record :id "large-node" :name "worker-large" :pod-cidr "10.88.8.0/24"))
    (let* ((node-server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0))
           (fake (make-fake-runtime))
           (node-runtime (gr8s::make-node-runtime (merge-pathnames "worker-large/runtime/" path) fake nil))
           (runtime (gr8s::make-control-plane-runtime store node-server))
           (reconciler (make-reconciler store runtime))
           (control (gr8s::make-node-session-control))
           (agent nil))
      (unwind-protect
           (progn
             (gr8s::start-node-runtime node-runtime)
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port node-server) "worker-large"
                       (merge-pathnames "worker-large/identity.json" path)
                       (lambda (snapshot) (gr8s::reconcile-node-snapshot node-runtime snapshot))
                       :operation-handler
                       (lambda (variant payload emit)
                         (gr8s::dispatch-node-operation node-runtime variant payload emit))
                       :reconnect-delay 0.01 :control control))
                    :name "gr8s test large output agent"))
             (is-true (wait-until (lambda () (gr8s:node-record-ready-p (gr8s:get-node store "worker-large"))) :timeout 5))
             (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
                    (container (container-spec-name (aref (pod-containers pod) 0)))
                    (logs (make-string 400000 :initial-element #\x)))
               (reconcile-pod reconciler "default" "hello")
               (is-true (wait-until (lambda () (runtime-observe fake (pod-uid pod))) :timeout 5))
               (setf (gethash container (gr8s::runtime-pod-logs (runtime-observe fake (pod-uid pod)))) logs)
               (is (equal logs (gr8s::runtime-logs runtime (pod-uid pod) container)))))
        (ignore-errors (gr8s::cancel-node-session control))
        (when agent (ignore-errors (bt:join-thread agent)))
        (ignore-errors (gr8s:stop-node-grpc-server node-server))))))

(defun runtime-accept-socket (listener)
  (usocket:socket-accept listener :element-type '(unsigned-byte 8)))

(defun forwarded-data (runtime session)
  "Return everything the Pod's side sends through SESSION, with any failure message."
  (let ((all (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop
      (multiple-value-bind (data done failure) (gr8s::runtime-port-forward-next runtime session)
        (when done (return (values all failure)))
        (loop for octet across data do (vector-push-extend octet all))))))

(test connections-forward-through-a-remote-agent
  (with-forwarding-agent (runtime pod listener)
    (let* ((session (gr8s::runtime-start-port-forward runtime (pod-uid pod) 8080))
           (socket (runtime-accept-socket listener))
           (stream (usocket:socket-stream socket)))
      (unwind-protect
           (multiple-value-bind (head streams) (runtime-accept-forward stream)
             (is (search "X-Stream-Protocol-Version: portforward.k8s.io" head))
             (is (search "/portforward/token" head))
             (is (equal '("error" "data") (mapcar #'car streams)))
             (let ((data-stream (cdr (assoc "data" streams :test #'equal)))
                   (error-stream (cdr (assoc "error" streams :test #'equal))))
               (is (equal (list :data error-stream t) (subseq (fake-spdy-read-frame stream) 0 3))
                   "the agent ends its side of the error stream at once, as kubectl does")
               (gr8s::runtime-port-forward-send runtime session (trivial-utf-8:string-to-utf-8-bytes "ping"))
               (let ((frame (fake-spdy-read-frame stream)))
                 (is (eql data-stream (second frame)))
                 (is (equal "ping" (trivial-utf-8:utf-8-bytes-to-string (fourth frame)))))
               ;; The client finishing its side must reach the Pod, which can still answer.
               (gr8s::runtime-port-forward-send runtime session (make-array 0 :element-type '(unsigned-byte 8)) :eof t)
               (let ((frame (fake-spdy-read-frame stream)))
                 (is (eql data-stream (second frame)))
                 (is-true (third frame)))
               (fake-spdy-send stream data-stream "pong" :fin t)
               (fake-spdy-send stream error-stream "" :fin t)
               (multiple-value-bind (data failure) (forwarded-data runtime session)
                 (is (equal "pong" (trivial-utf-8:utf-8-bytes-to-string (coerce data '(simple-array (unsigned-byte 8) (*))))))
                 (is (member failure '(nil "") :test #'equal)))))
        (gr8s::runtime-release-port-forward runtime session)
        (ignore-errors (usocket:socket-close socket))))))

(test the-runtimes-error-reaches-the-client
  (with-forwarding-agent (runtime pod listener)
    (let* ((session (gr8s::runtime-start-port-forward runtime (pod-uid pod) 9))
           (socket (runtime-accept-socket listener))
           (stream (usocket:socket-stream socket)))
      (unwind-protect
           (multiple-value-bind (head streams) (runtime-accept-forward stream)
             (declare (ignore head))
             (fake-spdy-send stream (cdr (assoc "error" streams :test #'equal))
                             "failed to connect to localhost:9 inside namespace" :fin t)
             (fake-spdy-send stream (cdr (assoc "data" streams :test #'equal)) "" :fin t)
             (multiple-value-bind (data failure) (forwarded-data runtime session)
               (is (zerop (length data)))
               (is (search "failed to connect to localhost:9" failure))))
        (gr8s::runtime-release-port-forward runtime session)
        (ignore-errors (usocket:socket-close socket))))))

(test invalid-ports-and-unforwardable-runtimes-fail-cleanly
  (with-forwarding-agent (runtime pod listener)
    (let ((session (gr8s::runtime-start-port-forward runtime (pod-uid pod) 70000)))
      (unwind-protect
           (multiple-value-bind (data failure) (forwarded-data runtime session)
             (is (zerop (length data)))
             (is (search "valid port" failure)))
        (gr8s::runtime-release-port-forward runtime session))))
  (signals gr8s:runtime-error (gr8s::runtime-start-port-forward (make-fake-runtime) "uid" 80)))

(test a-slow-client-pauses-the-pod-instead-of-filling-memory
  (with-forwarding-agent (runtime pod listener)
    (let* ((session (gr8s::runtime-start-port-forward runtime (pod-uid pod) 8080))
           (operation (gr8s::control-plane-port-forward-operation session))
           (socket (runtime-accept-socket listener))
           (stream (usocket:socket-stream socket))
           (chunk (make-array 65536 :element-type '(unsigned-byte 8) :initial-element 7))
           (total (* 4 gr8s::+port-forward-window-bytes+))
           (writer nil))
      (unwind-protect
           (multiple-value-bind (head streams) (runtime-accept-forward stream)
             (declare (ignore head))
             (let ((data-stream (cdr (assoc "data" streams :test #'equal)))
                   (error-stream (cdr (assoc "error" streams :test #'equal))))
               (setf writer (bt:make-thread
                             (lambda ()
                               (ignore-errors
                                (loop repeat (floor total 65536)
                                      do (fake-spdy-send stream data-stream nil :octets chunk))
                                (fake-spdy-send stream data-stream "" :fin t)
                                (fake-spdy-send stream error-stream "" :fin t)))
                             :name "gr8s test slow client writer"))
               ;; Nobody is taking the output, so what's waiting must stop at about one window.
               (flet ((queued ()
                        (bt:with-lock-held ((gr8s::pending-node-operation-lock operation))
                          (reduce #'+ (gr8s::pending-node-operation-stream-messages operation)
                                  :key (lambda (message) (length (slot-value message 'gr8s.node.v1::data)))))))
                 (is-true (wait-until (lambda () (>= (queued) gr8s::+port-forward-window-bytes+)) :timeout 10))
                 (sleep 0.5)
                 (is (<= (queued) (+ gr8s::+port-forward-window-bytes+ 65536))
                     "the node stops once the window is full"))
               ;; Taking the output releases the rest, and every byte arrives.
               (let ((data (forwarded-data runtime session)))
                 (is (= total (length data)))
                 (is (every (lambda (octet) (= 7 octet)) data)))
               (is (null (gr8s::pending-node-operation-stream-messages operation))
                   "what's been consumed isn't kept")))
        (gr8s::runtime-release-port-forward runtime session)
        (ignore-errors (usocket:socket-close socket))
        (when writer (ignore-errors (bt:join-thread writer)))))))

(test a-pod-that-stops-reading-holds-up-only-its-own-connection
  (with-forwarding-agent (runtime pod listener)
    (let* ((stalled (gr8s::runtime-start-port-forward runtime (pod-uid pod) 8080))
           (stalled-socket (runtime-accept-socket listener))
           (chunk (make-array 65536 :element-type '(unsigned-byte 8) :initial-element 1))
           (sender nil))
      (unwind-protect
           (progn
             ;; This runtime stream never reads again, so TCP soon stops taking input.
             (runtime-accept-forward (usocket:socket-stream stalled-socket))
             (setf sender (bt:make-thread
                           (lambda ()
                             (ignore-errors
                              (loop repeat 512 do (gr8s::runtime-port-forward-send runtime stalled chunk))))
                           :name "gr8s test stalled sender"))
             (is-true (wait-until (lambda ()
                                    (>= (gr8s::control-plane-port-forward-in-flight stalled)
                                        gr8s::+port-forward-window-bytes+))
                                  :timeout 10)
                      "the sender fills the window")
             (sleep 0.5)
             (is (bt:thread-alive-p sender) "and then waits")
             ;; The node's session must still serve another connection.
             (let* ((other (gr8s::runtime-start-port-forward runtime (pod-uid pod) 8081))
                    (socket (runtime-accept-socket listener))
                    (stream (usocket:socket-stream socket)))
               (unwind-protect
                    (multiple-value-bind (head streams) (runtime-accept-forward stream)
                      (declare (ignore head))
                      (fake-spdy-send stream (cdr (assoc "data" streams :test #'equal)) "alive" :fin t)
                      (fake-spdy-send stream (cdr (assoc "error" streams :test #'equal)) "" :fin t)
                      (is (equal "alive" (trivial-utf-8:utf-8-bytes-to-string
                                          (coerce (forwarded-data runtime other) '(simple-array (unsigned-byte 8) (*)))))))
                 (gr8s::runtime-release-port-forward runtime other)
                 (ignore-errors (usocket:socket-close socket))))
             ;; Cancelling frees whoever is waiting.
             (gr8s::runtime-cancel-port-forward runtime stalled "test over")
             (is-true (wait-until (lambda () (not (bt:thread-alive-p sender))) :timeout 10)))
        (gr8s::runtime-release-port-forward runtime stalled)
        (ignore-errors (usocket:socket-close stalled-socket))))))

;;; A real kubectl

(defun test-kubectl ()
  (let ((path (uiop:getenv "GR8S_TEST_KUBECTL")))
    (and path (plusp (length path)) (probe-file path) path)))

(defstruct (tcp-forward-runtime (:include gr8s::fake-runtime) (:constructor make-tcp-forward-runtime ()))
  "A fake runtime whose Pods' ports are simply this host's, so kubectl can exercise the API path.")

(defstruct tcp-forward-session socket stream)

(defmethod gr8s::runtime-start-port-forward ((runtime tcp-forward-runtime) uid port)
  (declare (ignore uid))
  (handler-case
      (let ((socket (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8))))
        (make-tcp-forward-session :socket socket :stream (usocket:socket-stream socket)))
    (usocket:socket-error ()
      (error 'gr8s:runtime-error :message (format nil "failed to connect to localhost:~D" port)))))

(defmethod gr8s::runtime-port-forward-send ((runtime tcp-forward-runtime) session data &key eof)
  (let ((stream (tcp-forward-session-stream session)))
    (write-sequence data stream)
    (finish-output stream)
    (when eof (usocket:socket-shutdown (tcp-forward-session-socket session) :output))))

(defmethod gr8s::runtime-port-forward-next ((runtime tcp-forward-runtime) session)
  (let* ((stream (tcp-forward-session-stream session))
         (first (ignore-errors (read-byte stream nil nil))))
    (if first
        (let ((buffer (make-array 16384 :element-type '(unsigned-byte 8))) (count 1))
          (setf (aref buffer 0) first)
          (loop while (and (< count (length buffer)) (listen stream))
                do (setf (aref buffer count) (read-byte stream))
                   (incf count))
          (values (subseq buffer 0 count) nil nil))
        (values nil t nil))))

(defmethod gr8s::runtime-cancel-port-forward ((runtime tcp-forward-runtime) session reason)
  (declare (ignore reason))
  (ignore-errors (usocket:socket-close (tcp-forward-session-socket session))))

(defmethod gr8s::runtime-release-port-forward ((runtime tcp-forward-runtime) session)
  (ignore-errors (usocket:socket-close (tcp-forward-session-socket session))))

(defun start-echo-server ()
  "Listen on a port and echo each connection until its client finishes, then close it."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
         (thread (bt:make-thread
                  (lambda ()
                    (ignore-errors
                     (loop
                       (let ((socket (usocket:socket-accept listener :element-type '(unsigned-byte 8))))
                         (bt:make-thread
                          (lambda ()
                            (unwind-protect
                                 (ignore-errors
                                  (let ((stream (usocket:socket-stream socket)))
                                    (loop for first = (read-byte stream nil nil)
                                          while first
                                          do (write-byte first stream)
                                             (loop while (listen stream)
                                                   do (write-byte (read-byte stream) stream))
                                             (finish-output stream))))
                              (ignore-errors (usocket:socket-close socket))))
                          :name "gr8s test echo connection")))))
                  :name "gr8s test echo")))
    (values listener thread)))

(defun exchange-through (port octets)
  "Send OCTETS to PORT, finish sending, and return all that comes back."
  (let* ((socket (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)))
         (stream (usocket:socket-stream socket))
         (sender (bt:make-thread
                  (lambda ()
                    (write-sequence octets stream)
                    (finish-output stream)
                    (usocket:socket-shutdown socket :output))
                  :name "gr8s test exchange sender"))
         (received (make-array (length octets) :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (unwind-protect
         (progn
           (loop for octet = (read-byte stream nil nil)
                 while octet do (vector-push-extend octet received))
           (bt:join-thread sender)
           (coerce received '(simple-array (unsigned-byte 8) (*))))
      (ignore-errors (usocket:socket-close socket)))))

(defun random-octets (count)
  (let ((octets (make-array count :element-type '(unsigned-byte 8))))
    (dotimes (index count octets) (setf (aref octets index) (random 256)))))

(defun check-kubectl-port-forward (kubectl kubeconfig echo-port &key environment)
  "Run kubectl port-forward with ENVIRONMENT and check real connections through it."
  (let* ((process (uiop:launch-program
                   (append (list "env") environment
                           (list kubectl "--kubeconfig" (namestring kubeconfig) "port-forward" "pod/hello"
                                 (format nil ":~D" echo-port)))
                   :output :stream :error-output :stream))
         (output (uiop:process-info-output process)))
    (unwind-protect
         (let* ((line (let ((result nil))
                        (bt:make-thread (lambda () (setf result (ignore-errors (read-line output nil nil))))
                                        :name "gr8s test kubectl output")
                        (wait-until (lambda () result) :timeout 30)
                        result))
                (start (and line (search "127.0.0.1:" line)))
                (local-port (and start (parse-integer line :start (+ start 10) :junk-allowed t))))
           (is (not (null local-port)) "kubectl starts forwarding: ~A" line)
           (when local-port
             (let ((message (trivial-utf-8:string-to-utf-8-bytes "hello through kubectl")))
               (is (equalp message (exchange-through local-port message)) "a short exchange"))
             ;; Several times the flow-control window, in both directions at once.
             (let ((large (random-octets (* 3 1024 1024))))
               (is (equalp large (exchange-through local-port large)) "a large exchange"))
             (let* ((results (make-array 8 :initial-element nil))
                    (messages (loop repeat 8 collect (random-octets 200000)))
                    (threads (loop for message in messages for index from 0
                                   collect (let ((message message) (index index))
                                             (bt:make-thread
                                              (lambda ()
                                                (setf (aref results index)
                                                      (ignore-errors (exchange-through local-port message))))
                                              :name "gr8s test concurrent exchange")))))
               (mapc #'bt:join-thread threads)
               (is (equalp (coerce messages 'vector) results) "concurrent connections stay separate"))
             ;; A quiet forward has to outlast the web server's default read timeout of 20 seconds.
             (let* ((socket (usocket:socket-connect "127.0.0.1" local-port :element-type '(unsigned-byte 8)))
                    (stream (usocket:socket-stream socket)))
               (unwind-protect
                    (flet ((round-trip (octet)
                             (write-byte octet stream)
                             (finish-output stream)
                             (read-byte stream nil nil)))
                      (is (= 1 (round-trip 1)))
                      (sleep 25)
                      (is (eql 2 (round-trip 2)) "the connection survives being idle"))
                 (ignore-errors (usocket:socket-close socket))))))
      (ignore-errors (uiop:terminate-process process :urgent t))
      (ignore-errors (uiop:wait-process process)))))

(defmacro with-kubectl-server ((kubectl kubeconfig echo-port) &body body)
  "Run BODY with an API server over a Running Pod \"hello\", whose ports are this host's."
  (let ((store (gensym "STORE")) (path (gensym "PATH")) (runtime (gensym "RUNTIME")) (server (gensym "SERVER"))
        (listener (gensym "LISTENER")) (thread (gensym "THREAD")) (reconciler (gensym "RECONCILER")))
    `(let ((,kubectl (test-kubectl)))
       (if (null ,kubectl)
           (skip "Set GR8S_TEST_KUBECTL to run port forwarding through a real kubectl")
           (with-temporary-store (,store ,path)
             (let* ((,runtime (make-tcp-forward-runtime))
                    (,reconciler (make-reconciler ,store ,runtime))
                    (,kubeconfig (merge-pathnames "kubeconfig" (uiop:ensure-directory-pathname ,path)))
                    (,server nil))
               (multiple-value-bind (,listener ,thread) (start-echo-server)
                 (declare (ignorable ,thread))
                 (let ((,echo-port (usocket:get-local-port ,listener)))
                   (unwind-protect
                        (progn
                          (create-pod ,store (parse-pod *valid-pod-json*))
                          (reconcile-pod ,reconciler "default" "hello")
                          (setf ,server (start-server :address "127.0.0.1" :port 0 :store ,store
                                                      :runtime ,runtime :reconciler ,reconciler))
                          (with-open-file (out ,kubeconfig :direction :output :if-exists :supersede)
                            (format out "apiVersion: v1~%kind: Config~%clusters:~%- name: c~%  cluster: {server: \"http://127.0.0.1:~D\"}~%contexts:~%- name: x~%  context: {cluster: c, user: u, namespace: default}~%current-context: x~%users:~%- name: u~%  user: {}~%"
                                    (hunchentoot:acceptor-port ,server)))
                          ,@body)
                     (when ,server (ignore-errors (gr8s:stop-server ,server)))
                     (ignore-errors (usocket:socket-close ,listener)))))))))))

(test kubectl-forwards-over-the-websocket-tunnel
  (with-kubectl-server (kubectl kubeconfig echo-port)
    (check-kubectl-port-forward kubectl kubeconfig echo-port)))

(test kubectl-forwards-over-plain-spdy
  (with-kubectl-server (kubectl kubeconfig echo-port)
    (check-kubectl-port-forward kubectl kubeconfig echo-port
                                :environment '("KUBECTL_PORT_FORWARD_WEBSOCKETS=false"))))

(test kubectl-reports-a-port-nothing-is-listening-on
  (with-kubectl-server (kubectl kubeconfig echo-port)
    (let* ((ignored echo-port)
           (closed (let ((listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8))))
                     (prog1 (usocket:get-local-port listener) (usocket:socket-close listener))))
           (process (uiop:launch-program
                     (list kubectl "--kubeconfig" (namestring kubeconfig) "port-forward" "pod/hello"
                           (format nil ":~D" closed))
                     :output :stream :error-output :stream))
           (line nil))
      (declare (ignore ignored))
      (unwind-protect
           (progn
             (bt:make-thread (lambda () (setf line (ignore-errors (read-line (uiop:process-info-output process) nil nil))))
                             :name "gr8s test kubectl output")
             (is-true (wait-until (lambda () line) :timeout 30))
             (let* ((start (search "127.0.0.1:" line))
                    (socket (usocket:socket-connect "127.0.0.1" (parse-integer line :start (+ start 10) :junk-allowed t)
                                                    :element-type '(unsigned-byte 8))))
               (unwind-protect
                    (is (null (ignore-errors (read-byte (usocket:socket-stream socket) nil nil)))
                        "the local connection is closed")
                 (ignore-errors (usocket:socket-close socket))))
             (let ((report (make-string-output-stream)))
               (ignore-errors (uiop:terminate-process process :urgent t))
               (ignore-errors (uiop:wait-process process))
               (ignore-errors (uiop:copy-stream-to-stream (uiop:process-info-error-output process) report))
               (is (search (format nil "failed to connect to localhost:~D" closed)
                           (get-output-stream-string report))
                   "kubectl shows the reason")))
        (ignore-errors (uiop:terminate-process process :urgent t))))))
