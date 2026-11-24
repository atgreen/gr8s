;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the debug server stays off by default, always requires a fresh private
;;;; secret over a real socket even with no ~/.sly-secret, and evaluates forms
;;;; without ever leaving a remote client in a debugger.

(in-package #:gr8s/tests)
(def-suite debug-server :in gr8s)
(in-suite debug-server)

(defun slynk-frame (text)
  "Encode TEXT as one length-prefixed Slynk protocol message."
  (let ((payload (trivial-utf-8:string-to-utf-8-bytes text)))
    (concatenate '(vector (unsigned-byte 8))
                 (trivial-utf-8:string-to-utf-8-bytes (format nil "~(~6,'0X~)" (length payload)))
                 payload)))

(defun slynk-read-frame (stream)
  "Read one message from STREAM, returning NIL once the server closes the connection."
  (let ((header (make-array 6 :element-type '(unsigned-byte 8))))
    (when (= 6 (read-sequence header stream))
      (let ((payload (make-array (parse-integer (trivial-utf-8:utf-8-bytes-to-string header) :radix 16)
                                 :element-type '(unsigned-byte 8))))
        (read-sequence payload stream)
        (trivial-utf-8:utf-8-bytes-to-string payload)))))

(defun slynk-exchange (port &key secret (form "(+ 1 2)"))
  "Connect, optionally authenticate, request FORM, and return the frames received until close or reply."
  (let* ((socket (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)))
         (stream (usocket:socket-stream socket)))
    (unwind-protect
         (sb-sys:with-deadline (:seconds 10)
           (handler-case
               (progn
                 (when secret
                   (write-sequence (slynk-frame secret) stream)
                   (finish-output stream))
                 (write-sequence (slynk-frame (format nil "(:emacs-rex (gr8s.apiserver::debug-eval ~S) \"GR8S.APISERVER\" t 1)" form)) stream)
                 (finish-output stream)
                 (loop for frame = (slynk-read-frame stream)
                       while frame
                       collect frame into frames
                       when (uiop:string-prefix-p "(:return " frame)
                         return frames
                       finally (return frames)))
             (stream-error () nil)
             (usocket:socket-error () nil)))
      (usocket:socket-close socket))))

(defmacro with-debug-server ((port secret directory) &body body)
  "Run BODY with a real debug server on PORT, restoring Slynk's original secret function."
  (let ((original (gensym "ORIGINAL")))
    `(with-temporary-store (store ,directory)
       (let ((,original (symbol-function 'slynk::sly-secret)))
         (unwind-protect
              (let* ((,port (gr8s.apiserver::start-debug-server 0 ,directory :store store))
                     (,secret (uiop:read-file-string (gr8s.apiserver::debug-secret-path ,directory))))
                (unwind-protect (progn ,@body)
                  (gr8s.apiserver::stop-debug-server ,port)))
           (setf (symbol-function 'slynk::sly-secret) ,original))))))

(test debug-server-is-off-unless-a-port-is-requested
  (is (null (getf (parse-cli-options '("serve")) :debug-slynk-port)))
  (is (= 4105 (getf (parse-cli-options '("serve" "--debug-slynk-port" "4105")) :debug-slynk-port)))
  (signals error (parse-cli-options '("serve" "--debug-slynk-port" "nope"))))

(test each-start-writes-a-new-private-secret
  (with-temporary-store (store directory)
    (declare (ignorable store))
    (let ((original (symbol-function 'slynk::sly-secret)))
      (unwind-protect
           (let* ((first (gr8s.apiserver::install-debug-secret directory))
                  (path (gr8s.apiserver::debug-secret-path directory))
                  (mode (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring path))))))
             (is (= 64 (length first)))
             (is (every (lambda (character) (digit-char-p character 16)) first))
             (is (= #o600 mode))
             (is (equal first (uiop:read-file-string path)))
             (is (equal first (slynk::sly-secret)))
             (is (not (equal first (gr8s.apiserver::install-debug-secret directory)))))
        (setf (symbol-function 'slynk::sly-secret) original)))))

(test clients-must-present-the-secret-on-a-real-socket
  (with-debug-server (port secret directory)
    (values directory)
    ;; This is the case Slynk alone leaves open when no ~/.sly-secret exists.
    (is (notany (lambda (frame) (search ":ok" frame)) (slynk-exchange port)))
    (is (notany (lambda (frame) (search ":ok" frame)) (slynk-exchange port :secret "wrong")))
    ;; Rejections leave the server accepting; only the right secret evaluates.
    (dotimes (attempt 3)
      (is (notany (lambda (frame) (search ":ok" frame)) (slynk-exchange port :secret "wrong"))))
    (let* ((hook sb-ext:*invoke-debugger-hook*)
           (frames (slynk-exchange port :secret secret)))
      (is (some (lambda (frame) (and (search ":ok" frame) (search "3" frame))) frames))
      ;; A connected client must leave process-wide error handling alone.
      (is (eq hook sb-ext:*invoke-debugger-hook*)))))

(test the-server-binds-to-loopback-only
  (with-debug-server (port secret directory)
    (values secret directory)
    (let ((listening (with-open-file (in "/proc/net/tcp")
                       (loop for line = (read-line in nil) while line
                             when (search (format nil ":~4,'0X " port) line) collect line))))
      (is (plusp (length listening)))
      ;; Little-endian 127.0.0.1 in the local-address column.
      (is (every (lambda (line) (search "0100007F:" line)) listening)))))

(test on-demand-debug-session-is-exclusive-and-restores-process-state
  (with-temporary-store (store directory)
    (let* ((original-secret-function (symbol-function 'slynk::sly-secret))
           (session (gr8s.apiserver::start-on-demand-debug-session directory :store store)))
      (unwind-protect
           (progn
             (is (plusp (gr8s.apiserver::on-demand-debug-session-port session)))
             (is (= 64 (length (gr8s.apiserver::on-demand-debug-session-secret session))))
             (signals gr8s.apiserver::debug-session-conflict
               (gr8s.apiserver::start-on-demand-debug-session directory :store store)))
        (gr8s.apiserver::stop-on-demand-debug-session session))
      (is (eq original-secret-function (symbol-function 'slynk::sly-secret)))
      ;; A disconnected session releases ownership for the next tunnel.
      (let ((next (gr8s.apiserver::start-on-demand-debug-session directory :store store)))
        (gr8s.apiserver::stop-on-demand-debug-session next)))))

(test on-demand-bridge-authenticates-before-relaying-slynk-protocol
  (with-temporary-store (store directory)
    (let ((session (gr8s.apiserver::start-on-demand-debug-session directory :store store)))
      (unwind-protect
           (multiple-value-bind (stream socket)
               (gr8s.apiserver::open-on-demand-debug-stream session)
             (unwind-protect
                  (progn
                    ;; The caller sends ordinary Slynk protocol immediately;
                    ;; OPEN-ON-DEMAND-DEBUG-STREAM already sent the secret.
                    (write-sequence
                     (slynk-frame "(:emacs-rex (gr8s.apiserver::debug-eval \"(+ 20 22)\") \"GR8S.APISERVER\" t 1)")
                     stream)
                    (finish-output stream)
                    (is (loop repeat 20
                              for frame = (slynk-read-frame stream)
                              thereis (and frame (search ":ok" frame) (search "42" frame)))))
               (usocket:socket-close socket)))
        (gr8s.apiserver::stop-on-demand-debug-session session)))))

(test node-slynk-operation-relays-bytes-and-cancel-tears-it-down
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((runtime (gr8s.agent::make-node-runtime
                     (merge-pathnames "agent/" directory) (make-fake-runtime) nil))
           (request (make-instance 'gr8s.node.v1::operation-request
                                   :operation-id "debug-1"
                                   :kind gr8s.node.v1::+operationkind-operation_kind_slynk+))
           (messages nil)
           (lock (bt:make-lock "node Slynk test messages")))
      (flet ((emit (variant payload)
               (bt:with-lock-held (lock) (push (cons variant payload) messages))))
        (gr8s.agent::dispatch-node-operation runtime :operation-request request #'emit)
        (is-true (wait-until
                  (lambda () (bt:with-lock-held (lock)
                               (find :operation-response messages :key #'car)))
                  :timeout 5))
        (gr8s.agent::dispatch-node-operation
         runtime :operation-input
         (make-instance 'gr8s.node.v1::operation-input
                        :operation-id "debug-1" :sequence 1
                        :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                        :data (slynk-frame
                               "(:emacs-rex (gr8s.apiserver::debug-eval \"(+ 5 6)\") \"GR8S.APISERVER\" t 1)"))
         #'emit)
        (let ((relayed
                (wait-until
          (lambda ()
            (bt:with-lock-held (lock)
              (let ((octets
                      (apply #'concatenate '(vector (unsigned-byte 8))
                             (loop for message in (reverse messages)
                                   when (eq :operation-stream (car message))
                                     collect (slot-value (cdr message) 'gr8s.node.v1::data)))))
                (and (plusp (length octets))
                     (search "(:return " (trivial-utf-8:utf-8-bytes-to-string octets))
                     (search "11" (trivial-utf-8:utf-8-bytes-to-string octets))))))
          :timeout 5)))
          (unless relayed
            (bt:with-lock-held (lock)
              (format t "~&node Slynk messages: ~S~%"
                      (mapcar (lambda (message)
                                (list (car message)
                                      (and (eq :operation-response (car message))
                                           (slot-value (cdr message) 'gr8s.node.v1::error-message))
                                      (and (eq :operation-stream (car message))
                                           (length (slot-value (cdr message) 'gr8s.node.v1::data)))))
                              (reverse messages)))))
          (is-true relayed))
        (gr8s.agent::dispatch-node-operation
         runtime :operation-cancel
         (make-instance 'gr8s.node.v1::operation-cancel
                        :operation-id "debug-1" :reason "client disconnected")
         #'emit)
        (is-true (wait-until (lambda () (null gr8s.apiserver::*on-demand-debug-session*)) :timeout 5))
        (is (null (gr8s.agent::find-node-exec-operation runtime "debug-1")))))))

(test member-slynk-operation-relays-bytes-without-blocking-the-mtls-handler
  (with-temporary-store (store directory)
    (let ((messages nil)
          (lock (bt:make-lock "member Slynk test messages")))
      (flet ((emit (variant payload)
               (bt:with-lock-held (lock) (push (cons variant payload) messages))))
        (is-true
         (gr8s.apiserver::dispatch-member-slynk-operation
          directory store nil "cp-1" :operation-request
          (make-instance 'gr8s.node.v1::operation-request
                         :operation-id "member-debug-1"
                         :kind gr8s.node.v1::+operationkind-operation_kind_slynk+)
          #'emit))
        (is-true
         (gr8s.apiserver::dispatch-member-slynk-operation
          directory store nil "cp-1" :operation-input
          (make-instance 'gr8s.node.v1::operation-input
                         :operation-id "member-debug-1" :sequence 1
                         :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                         :data (slynk-frame
                                "(:emacs-rex (gr8s.apiserver::debug-eval \"(+ 20 23)\") \"GR8S.APISERVER\" t 1)"))
          #'emit))
        (is-true
         (wait-until
          (lambda ()
            (bt:with-lock-held (lock)
              (let ((octets
                      (apply #'concatenate '(vector (unsigned-byte 8))
                             (loop for message in (reverse messages)
                                   when (eq :operation-stream (car message))
                                     collect (slot-value (cdr message) 'gr8s.node.v1::data)))))
                (and (plusp (length octets))
                     (search "(:return " (trivial-utf-8:utf-8-bytes-to-string octets))
                     (search "43" (trivial-utf-8:utf-8-bytes-to-string octets))))))
          :timeout 5))
        (is-true
         (gr8s.apiserver::dispatch-member-slynk-operation
          directory store nil "cp-1" :operation-cancel
          (make-instance 'gr8s.node.v1::operation-cancel
                         :operation-id "member-debug-1" :reason "client disconnected")
          #'emit))
        (is-true (wait-until (lambda () (null gr8s.apiserver::*on-demand-debug-session*)) :timeout 5))
        (is (null (bt:with-lock-held (gr8s.apiserver::*member-slynk-operations-lock*)
                    (gethash "member-debug-1" gr8s.apiserver::*member-slynk-operations*))))))))

(test member-slynk-operation-ends-when-its-origin-no-longer-holds-it
  ;; The origin gave the operation up and no cancel came: without this, the member's
  ;; one Slynk session stays taken and every later client is refused (podster-bkm).
  (with-temporary-store (store directory)
    (let ((probe-seconds gr8s.apiserver::*member-slynk-origin-probe-seconds*)
          (response nil))
      (setf gr8s.apiserver::*member-slynk-origin-probe-seconds* 0.05)
      (unwind-protect
           (flet ((emit (variant payload)
                    (when (eq variant :operation-response) (setf response payload))
                    ;; The origin takes nothing: it no longer holds the operation.
                    (eq variant :operation-response)))
             (is-true
              (gr8s.apiserver::dispatch-member-slynk-operation
               directory store nil "cp-1" :operation-request
               (make-instance 'gr8s.node.v1::operation-request
                              :operation-id "member-debug-orphan"
                              :kind gr8s.node.v1::+operationkind-operation_kind_slynk+)
               #'emit))
             (is-true (wait-until (lambda () (null gr8s.apiserver::*on-demand-debug-session*)) :timeout 5))
             (is (search "no longer holds it" (slot-value response 'gr8s.node.v1::error-message))))
        (setf gr8s.apiserver::*member-slynk-origin-probe-seconds* probe-seconds)
        (let ((session gr8s.apiserver::*on-demand-debug-session*))
          (when session (gr8s.apiserver::stop-on-demand-debug-session session)))))))

(test member-slynk-tunnel-routes-to-the-exact-selected-member
  (with-temporary-store (store directory)
    (let* ((origin (gr8s.apiserver::%make-node-grpc-server :store store))
           (target (gr8s.apiserver::%make-node-grpc-server :store store))
           (runtime (gr8s.controllers::make-control-plane-runtime store origin))
           (routes nil)
           (route-lock (bt:make-lock "member Slynk route test")))
      (setf (gr8s.apiserver::node-grpc-server-operation-router target)
            (lambda (variant target-member node-name payload)
              (declare (ignore node-name))
              (bt:with-lock-held (route-lock)
                (push (list :target variant target-member) routes))
              (gr8s.apiserver::deliver-routed-node-operation origin variant payload)
              "cp-1"))
      (gr8s.apiserver::install-member-slynk-handler target directory store nil)
      (setf (gr8s.apiserver::node-grpc-server-operation-router origin)
            (lambda (variant target-member node-name payload)
              (bt:with-lock-held (route-lock)
                (push (list :origin variant target-member node-name) routes))
              (when (and (equal "cp-2" target-member)
                         (uiop:string-prefix-p "@control-plane/cp-2" node-name)
                         (gr8s.apiserver::accept-routed-node-operation
                          target "cp-1" node-name variant payload))
                "cp-2")))
      (let* ((operation
               (gr8s.apiserver::queue-member-operation
                origin "cp-2"
                (make-instance 'gr8s.node.v1::operation-request
                               :operation-id "member-route-1"
                               :kind gr8s.node.v1::+operationkind-operation_kind_slynk+)))
             (session (gr8s.controllers::make-control-plane-port-forward operation))
             (text ""))
        (unwind-protect
             (progn
               (gr8s.runtime::runtime-port-forward-send
                runtime session
                (slynk-frame
                 "(:emacs-rex (gr8s.apiserver::debug-eval \"(+ 40 4)\") \"GR8S.APISERVER\" t 1)"))
               (loop repeat 20
                     until (search "44" text)
                     do (multiple-value-bind (data done error)
                            (gr8s.runtime::runtime-port-forward-next runtime session)
                          (is-false done)
                          (is-false error)
                          (when data
                            (setf text
                                  (concatenate 'string text
                                               (trivial-utf-8:utf-8-bytes-to-string data))))))
               (is (search "(:return " text))
               (is (search "44" text)))
          (ignore-errors
           (gr8s.runtime::runtime-cancel-port-forward runtime session "test complete"))
          (gr8s.runtime::runtime-release-port-forward runtime session))
        (is-true (wait-until (lambda () (null gr8s.apiserver::*on-demand-debug-session*))
                             :timeout 5))
        (let ((observed (bt:with-lock-held (route-lock) (copy-list routes))))
          (is-true (find :origin observed :key #'first))
          (is-true (find :target observed :key #'first))
          (is (every (lambda (route)
                       (equal (if (eq :origin (first route)) "cp-2" "cp-1")
                              (third route)))
                     observed)))))))

(test slynk-api-uses-dedicated-create-subresource-authorization
  (dolist (case '(("/apis/gr8s.io/v1/nodes/worker-a/slynk" "nodes/slynk" "worker-a")
                  ("/apis/gr8s.io/v1/controlplanemembers/cp-2/slynk"
                   "controlplanemembers/slynk" "cp-2")))
    (multiple-value-bind (verb group resource name namespace)
        (gr8s.apiserver::kubernetes-authorization-target (first case) :get)
      (is (equal "create" verb))
      (is (equal "gr8s.io" group))
      (is (equal (second case) resource))
      (is (equal (third case) name))
      (is (null namespace)))))

(test debug-slynk-cli-requires-one-target-kind
  (let ((node (parse-cli-options '("debug" "slynk" "--node" "worker-a")))
        (selector (parse-cli-options '("debug" "slynk" "--selector" "role=worker")))
        (member (parse-cli-options '("debug" "slynk" "--member" "cp-2"
                                    "--kubeconfig" "/tmp/config" "--local-port" "4105"))))
    (is (eq :debug-slynk (getf node :command)))
    (is (equal "worker-a" (getf node :node)))
    (is (equal "role=worker" (getf selector :selector)))
    (is (equal "cp-2" (getf member :member)))
    (is (= 4105 (getf member :local-port)))
    (is (equal "/tmp/config" (getf member :kubeconfig))))
  (signals error (parse-cli-options '("debug" "slynk")))
  (signals error (parse-cli-options '("debug" "slynk" "--node" "a" "--member" "b")))
  (signals error (parse-cli-options '("debug" "slynk" "--node" "a" "--local-port" "0"))))

(test selector-target-must-be-exactly-one-ready-node
  (flet ((node (name ready)
           (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" name)
                              "status" (gr8s.resources::core-object
                                        "conditions"
                                        (vector (gr8s.resources::core-object
                                                 "type" "Ready"
                                                 "status" (if ready "True" "False")))))))
    (is (equal "a" (gr8s.server::selected-ready-node-name (vector (node "a" t)) "x=y")))
    (signals error (gr8s.server::selected-ready-node-name #() "x=y"))
    (signals error (gr8s.server::selected-ready-node-name (vector (node "a" nil)) "x=y"))
    (signals error (gr8s.server::selected-ready-node-name (vector (node "a" t) (node "b" t)) "x=y"))))

(test debug-eval-returns-text-and-never-enters-a-debugger
  (is (equal (format nil "3~%") (gr8s.apiserver::debug-eval "(+ 1 2)")))
  (is (search "printed" (gr8s.apiserver::debug-eval "(progn (princ \"printed\") nil)")))
  (let ((failure (gr8s.apiserver::debug-eval "(error \"boom ~A\" 1)")))
    (is (uiop:string-prefix-p "ERROR: boom 1" failure))
    (is (search "DEBUG-EVAL" failure)))
  (is (uiop:string-prefix-p "ERROR: " (gr8s.apiserver::debug-eval "(unclosed"))))

(test debug-helpers-read-live-state
  (with-temporary-store (store directory)
    (declare (ignorable directory))
    (let ((gr8s.apiserver::*debug-store* store)
          (pod (create-pod store (parse-pod *valid-pod-json*))))
      (is (member "main thread" (gr8s.apiserver::debug-threads) :test #'equal))
      (let ((text (gr8s.apiserver::debug-eval "(debug-pod \"default\" \"hello\")")))
        (is (search (pod-uid pod) text))
        (is (search "\"observed\"" text)))
      (is (search "no Pod" (gr8s.apiserver::debug-eval "(debug-pod \"default\" \"missing\")")))
      (is (search "ADDED default/hello" (gr8s.apiserver::debug-eval "(debug-journal)")))
      ;; Output stays machine-readable: no trailing printed value.
      (is (com.inuoe.jzon:parse (gr8s.apiserver::debug-eval "(debug-pod \"default\" \"hello\")"))))))

(test thread-backtraces-come-back-even-from-a-blocked-thread
  (let* ((gate (sb-thread:make-semaphore))
         (thread (sb-thread:make-thread (lambda () (sb-thread:wait-on-semaphore gate)) :name "gr8s-blocked-for-test")))
    (sleep 0.5) ; Let the new thread reach its wait before interrupting it.
    (unwind-protect
         (let ((text (gr8s.apiserver::debug-eval "(debug-backtraces \"gr8s-blocked-for-test\")")))
           (is (search "gr8s-blocked-for-test" text))
           (is (search "WAIT-ON-SEMAPHORE" (string-upcase text))))
      (sb-thread:signal-semaphore gate)
      (sb-thread:join-thread thread))))
