(in-package #:gr8s/tests)

(in-suite gr8s)

(defun wait-until (predicate &key (timeout 3))
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (loop until (funcall predicate)
          when (>= (get-internal-real-time) deadline) return nil
          do (sleep 0.02)
          finally (return t))))

(defun empty-desired-snapshot ()
  (make-instance 'gr8s.node.v1::desired-state-snapshot))

(defun send-stale-node-ack (port node-name revision)
  (let ((channel (ag-grpc:make-channel "127.0.0.1" port :timeout 3)))
    (unwind-protect
         (let* ((stub (gr8s.node.v1::make-node-service-stub channel))
                (stream (gr8s.node.v1::node-service-connect stub :timeout 3)))
           (ag-grpc:stream-send
            stream
            (gr8s:make-agent-envelope
             :hello
             (make-instance 'gr8s.node.v1::node-hello
                            :node-name node-name
                            :boot-id "stale-ack-test"
                            :agent-version "test"
                            :last-applied-revision revision)
             :sequence 1))
           (ag-grpc:stream-read-message stream)
           (ag-grpc:stream-read-message stream)
           (ag-grpc:stream-send
            stream
            (gr8s:make-agent-envelope
             :snapshot-ack
             (make-instance 'gr8s.node.v1::snapshot-ack
                            :revision (max 0 (1- revision))
                            :applied t)
             :sequence 2))
           (ag-grpc:stream-close-send stream)
           (loop while (ag-grpc:stream-read-message stream)))
      (ignore-errors (ag-grpc:channel-close channel)))))

(defun malformed-session-is-rejected (port)
  (let ((channel (ag-grpc:make-channel "127.0.0.1" port :timeout 3)))
    (unwind-protect
         (let* ((stub (gr8s.node.v1::make-node-service-stub channel))
                (stream (gr8s.node.v1::node-service-connect stub :timeout 3)))
           (ag-grpc:stream-send
            stream
            (gr8s:make-agent-envelope
             :heartbeat (make-instance 'gr8s.node.v1::heartbeat) :sequence 1))
           (ag-grpc:stream-close-send stream)
           (let ((response (ag-grpc:stream-read-message stream)))
             (and response
                  (eq :protocol-error
                      (slot-value response 'gr8s.node.v1::payload-case)))))
      (ignore-errors (ag-grpc:channel-close channel)))))

(test revisioned-node-session-reconnects-acknowledges-and-expires-heartbeats
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-1" :name "worker-a"
                                  :pod-cidr "10.88.0.0/20"))
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0
                    :heartbeat-timeout-seconds 1))
           (applied nil))
      (unwind-protect
           (progn
             (is (= 1 (gr8s:publish-node-desired-state
                       server "worker-a" (empty-desired-snapshot))))
             (gr8s:run-node-session
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-a" identity-path
              (lambda (snapshot)
                (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
              :max-sessions 1 :reconnect-delay 0.01)
             (is (equal '(1) applied))
             (is (= 1 (gr8s:node-session-acknowledged-revision
                       server "worker-a")))
             (is (probe-file identity-path))
             (is (gr8s:node-record-ready-p (gr8s:get-node store "worker-a")))

             (send-stale-node-ack
              (gr8s:node-grpc-server-port server) "worker-a" 1)
             (is (= 1 (gr8s:node-session-acknowledged-revision
                       server "worker-a")))

             (is (= 2 (gr8s:publish-node-desired-state
                       server "worker-a" (empty-desired-snapshot))))
             (gr8s:run-node-session
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-a" identity-path
              (lambda (snapshot)
                (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
              :max-sessions 1 :reconnect-delay 0.01)
             (is (equal '(2 1) applied))
             (is (= 2 (gr8s:node-session-acknowledged-revision
                       server "worker-a")))

             (is-true (malformed-session-is-rejected
                       (gr8s:node-grpc-server-port server)))
             ;; A bad stream must not poison the listener or a later session.
             (gr8s:run-node-session
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-a" identity-path (lambda (snapshot) (declare (ignore snapshot)))
              :max-sessions 1 :reconnect-delay 0.01)

             (is-true
              (wait-until
               (lambda ()
                 (not (gr8s:node-record-ready-p
                       (gr8s:get-node store "worker-a"))))
               :timeout 3)))
        (gr8s:stop-node-grpc-server server)))))

(test persistent-node-session-renews-its-heartbeat-lease
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-heartbeat" :name "worker-heartbeat"
                                  :pod-cidr "10.88.2.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0
                    :heartbeat-timeout-seconds 2))
           (identity-path (merge-pathnames "agent/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil))
      (unwind-protect
           (progn
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "worker-heartbeat" identity-path
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :reconnect-delay 0.01
                       :control control))
                    :name "gr8s persistent heartbeat test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-heartbeat")))
               :timeout 3))
             (sleep 3)
             (is-true
              (gr8s:node-record-ready-p
               (gr8s:get-node store "worker-heartbeat"))))
        (gr8s::cancel-node-session control)
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s:stop-node-grpc-server server)))))

(test cancelling-persistent-node-session-wakes-blocked-read
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-cancel" :name "worker-cancel"
                                  :pod-cidr "10.88.3.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "agent/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil))
      (unwind-protect
           (progn
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "worker-cancel" identity-path
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :control control :reconnect-delay 0.01))
                    :name "gr8s cancellable persistent session test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-cancel")))
               :timeout 3))
             (gr8s::cancel-node-session control)
             (is-true
              (wait-until (lambda () (not (bt:thread-alive-p agent-thread)))
                          :timeout 2)))
        (when (and agent-thread (bt:thread-alive-p agent-thread))
          (ignore-errors (bt:destroy-thread agent-thread)))
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s:stop-node-grpc-server server)))))

(test standalone-agent-enrolls-registers-and-connects-over-grpc
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (token (gr8s:create-join-token pki "worker-b"))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki
                    :cluster-pod-cidr "10.96.0.0/12" :node-prefix 20))
           (agent-directory (merge-pathnames "worker-b/" path))
           (private-key (merge-pathnames "node.key" agent-directory))
           (certificate (merge-pathnames "node.crt" agent-directory))
           (ca-certificate (merge-pathnames "ca.crt" agent-directory))
           (identity (merge-pathnames "identity.json" agent-directory)))
      (unwind-protect
           (let ((node-id
                   (gr8s:enroll-node-over-grpc
                    "127.0.0.1" (gr8s:node-grpc-server-port server)
                    "worker-b" token (gr8s:cluster-pki-ca-fingerprint pki)
                    private-key certificate ca-certificate)))
             (is (string= node-id (gr8s:node-record-id
                                   (gr8s:get-node store "worker-b"))))
             (is (string= "10.96.0.0/20"
                          (gr8s:node-record-pod-cidr
                           (gr8s:get-node store "worker-b"))))
             (is (probe-file private-key))
             (is (probe-file certificate))
             (is (probe-file ca-certificate))
             (gr8s:publish-node-desired-state
              server "worker-b" (empty-desired-snapshot))
             (gr8s:run-node-session
              "127.0.0.1" (gr8s:node-grpc-server-port server)
              "worker-b" identity (lambda (snapshot) (declare (ignore snapshot)))
              :max-sessions 1 :reconnect-delay 0.01)
             (is (gr8s:node-record-ready-p (gr8s:get-node store "worker-b"))))
        (gr8s:stop-node-grpc-server server)))))

(test local-agent-starts-through-grpc-and-stops-cleanly
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki))
           (worker nil))
      (unwind-protect
           (progn
             (setf worker
                   (gr8s::start-local-node-agent
                    server pki "gr8s-local" (merge-pathnames "agent/" path)))
             (is-true
              (wait-until
               (lambda ()
                 (handler-case
                     (gr8s:node-record-ready-p
                      (gr8s:get-node store "gr8s-local"))
                   (gr8s:kubernetes-error () nil)))
               :timeout 5))
             (gr8s::stop-local-node-agent worker)
             (is-false
              (bt:thread-alive-p (gr8s::local-node-agent-thread worker))))
        (when (and worker
                   (bt:thread-alive-p (gr8s::local-node-agent-thread worker)))
          (gr8s::stop-local-node-agent worker))
        (gr8s:stop-node-grpc-server server)))))

(test local-agent-executes-control-plane-snapshots-and-reports-status
  (with-temporary-store (store path)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki))
           (agent-directory (merge-pathnames "agent/" path))
           (worker nil)
           (runtime (gr8s::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (unwind-protect
           (progn
             (setf worker
                   (gr8s::start-local-node-agent
                    server pki "gr8s-local" agent-directory
                    (list :runtime "fake")))
             (is-true
              (wait-until
               (lambda ()
                 (handler-case
                     (gr8s:node-record-ready-p
                      (gr8s:get-node store "gr8s-local"))
                   (gr8s:kubernetes-error () nil)))
               :timeout 5))

             (reconcile-pod reconciler "default" "hello")
             (is-true
              (wait-until
               (lambda ()
                 (string= "Running" (gr8s:pod-scheduling-phase store pod)))
               :timeout 5))

             (gr8s::delete-reconciled-pod reconciler "default" "hello")
             (let ((deletion-revision
                     (slot-value (gr8s::current-node-snapshot server "gr8s-local")
                                 'gr8s.node.v1::revision)))
               (is-true
                (wait-until
                 (lambda ()
                   (>= (gr8s:node-session-acknowledged-revision
                        server "gr8s-local")
                       deletion-revision))
                 :timeout 5)))
             (is (null
                  (list-pods
                   (gr8s:open-store
                    (merge-pathnames "runtime/desired/" agent-directory))
                   "default"))))
        (when worker (gr8s::stop-local-node-agent worker))
        (gr8s:stop-node-grpc-server server)))))

(test control-plane-logs-come-from-the-assigned-remote-agent
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-remote" :name "worker-a"
                                  :pod-cidr "10.88.1.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (fake-runtime (make-fake-runtime))
           (node-runtime
             (gr8s::make-node-runtime
              (merge-pathnames "worker-a/runtime/" path) fake-runtime nil))
           (identity-path
             (merge-pathnames "worker-a/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil)
           (control-runtime
             (gr8s::make-control-plane-runtime store server))
           (reconciler (make-reconciler store control-runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (unwind-protect
           (progn
             (gr8s::start-node-runtime node-runtime)
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "worker-a" identity-path
                       (lambda (snapshot)
                         (gr8s::reconcile-node-snapshot
                          node-runtime snapshot))
                       :operation-handler
                       (lambda (variant payload emit)
                         (unless (eq variant :operation-request)
                           (error "Unexpected operation payload ~S" variant))
                         (dolist (reply
                                  (gr8s::handle-node-operation
                                   node-runtime payload))
                           (funcall emit (car reply) (cdr reply))))
                       :reconnect-delay 0.01
                       :control control))
                    :name "gr8s remote log test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-a")))
               :timeout 5))
             (reconcile-pod reconciler "default" "hello")
             (is-true
              (wait-until
               (lambda ()
                 (runtime-observe fake-runtime (pod-uid pod)))
               :timeout 5))
             (setf (gethash "web"
                            (gr8s::runtime-pod-logs
                             (runtime-observe fake-runtime (pod-uid pod))))
                   "hello from worker-a\n")
             (is (string= "hello from worker-a\n"
                          (runtime-logs control-runtime (pod-uid pod) "web")))
             (gr8s::set-fake-runtime-exec-result
              fake-runtime
              (gr8s::make-runtime-exec-result
               :stdout (trivial-utf-8:string-to-utf-8-bytes "remote stdout\n")
               :stderr (trivial-utf-8:string-to-utf-8-bytes "remote stderr\n")
               :exit-code 7))
             (let ((result
                     (gr8s::runtime-exec-sync
                      control-runtime (pod-uid pod) "web"
                      '("sh" "-c" "printf remote") :timeout 4)))
               (is (equalp
                    (trivial-utf-8:string-to-utf-8-bytes "remote stdout\n")
                    (gr8s::runtime-exec-result-stdout result)))
               (is (equalp
                    (trivial-utf-8:string-to-utf-8-bytes "remote stderr\n")
                    (gr8s::runtime-exec-result-stderr result)))
               (is (= 7 (gr8s::runtime-exec-result-exit-code result)))))
        (gr8s::cancel-node-session control)
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s::stop-node-runtime node-runtime)
        (gr8s:stop-node-grpc-server server)))))

(test operation-input-and-cancel-follow-the-correlated-node-session
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-interactive" :name "worker-interactive"
                                  :pod-cidr "10.88.4.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "interactive/identity.json" path))
           (control (gr8s::make-node-session-control))
           (agent-thread nil)
           (seen nil)
           (seen-lock (bt:make-lock "gr8s interactive operation test"))
           (request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id "interactive-1"
              :kind gr8s.node.v1::+operationkind-operation_kind_exec+
              :namespace "default" :pod "shell" :pod-uid "pod-1"
              :container "main" :command '("sh")
              :stdin t :stdout t :stderr t :tty t))
           (operation nil))
      (labels ((remember (variant payload)
                 (bt:with-lock-held (seen-lock)
                   (setf seen (nconc seen (list (cons variant payload))))))
               (seen-variant-p (variant)
                 (bt:with-lock-held (seen-lock)
                   (find variant seen :key #'car))))
        (unwind-protect
             (progn
               (setf agent-thread
                     (bt:make-thread
                      (lambda ()
                        (gr8s:run-node-session
                         "127.0.0.1" (gr8s:node-grpc-server-port server)
                         "worker-interactive" identity-path
                         (lambda (snapshot) (declare (ignore snapshot)))
                         :operation-handler
                         (lambda (variant payload emit)
                           (remember variant payload)
                           (case variant
                             (:operation-request
                              (funcall
                               emit :operation-response
                               (make-instance
                                'gr8s.node.v1::operation-response
                                :operation-id "interactive-1"
                                :status
                                gr8s.node.v1::+operationstatus-operation_status_accepted+)))
                             (:operation-cancel
                              (funcall
                               emit :operation-response
                               (make-instance
                                'gr8s.node.v1::operation-response
                                :operation-id "interactive-1"
                                :status
                                gr8s.node.v1::+operationstatus-operation_status_complete+)))))
                         :reconnect-delay 0.01 :control control))
                      :name "gr8s interactive operation test agent"))
               (is-true
                (wait-until
                 (lambda ()
                   (gr8s:node-record-ready-p
                    (gr8s:get-node store "worker-interactive")))
                 :timeout 5))
               (setf operation
                     (gr8s::queue-node-operation
                      server "worker-interactive" request))
               (is-true
                (wait-until (lambda () (seen-variant-p :operation-request))
                            :timeout 3))
               (gr8s::send-node-operation-input
                server operation
                (make-instance
                 'gr8s.node.v1::operation-input
                 :operation-id "interactive-1" :sequence 1
                 :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                 :data (trivial-utf-8:string-to-utf-8-bytes "echo hi\n")))
               (gr8s::cancel-node-operation server operation "client closed")
               (gr8s::wait-for-node-operation server operation :timeout 3)
               (is-true (seen-variant-p :operation-input))
               (let ((cancel (cdr (seen-variant-p :operation-cancel))))
                 (is (string= "client closed"
                              (slot-value cancel 'gr8s.node.v1::reason)))))
          (gr8s::cancel-node-session control)
          (when agent-thread
            (ignore-errors (bt:join-thread agent-thread)))
          (gr8s:stop-node-grpc-server server))))))

(test ending-node-session-notifies-its-operation-handler
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-session-close"
                                  :name "worker-session-close"
                                  :pod-cidr "10.88.6.0/24"))
    (let* ((server (gr8s:start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "session-close/identity.json" path))
           (control (gr8s::make-node-session-control))
           (events nil)
           (events-lock (bt:make-lock "gr8s session close events"))
           (agent-thread nil)
           (operation nil)
           (waiter nil)
           (waiter-error nil))
      (unwind-protect
           (progn
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "worker-session-close" identity-path
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :operation-handler
                       (lambda (variant payload emit)
                         (bt:with-lock-held (events-lock)
                           (push variant events))
                         (when (eq variant :operation-request)
                           (funcall
                            emit :operation-response
                            (make-instance
                             'gr8s.node.v1::operation-response
                             :operation-id
                             (slot-value payload 'gr8s.node.v1::operation-id)
                             :status
                             gr8s.node.v1::+operationstatus-operation_status_accepted+))))
                       :reconnect-delay 0.01 :control control))
                    :name "gr8s session close notification test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s:node-record-ready-p
                  (gr8s:get-node store "worker-session-close")))
               :timeout 5))
             (setf operation
                   (gr8s::queue-node-operation
                    server "worker-session-close"
                    (make-instance
                     'gr8s.node.v1::operation-request
                     :operation-id "disconnect-wakes-caller"
                     :kind gr8s.node.v1::+operationkind-operation_kind_exec+)))
             (is-true
              (wait-until
               (lambda ()
                 (bt:with-lock-held (events-lock)
                   (member :operation-request events)))
               :timeout 3))
             (setf waiter
                   (bt:make-thread
                    (lambda ()
                      (handler-case
                          (gr8s::wait-for-node-operation
                           server operation :timeout 5)
                        (runtime-error (condition)
                          (setf waiter-error
                                (runtime-error-message condition)))))
                    :name "gr8s disconnected operation waiter"))
             (gr8s::cancel-node-session control)
             (is-true
              (wait-until
               (lambda ()
                 (bt:with-lock-held (events-lock)
                   (member :session-closed events)))
               :timeout 3))
             (bt:join-thread waiter)
             (setf waiter nil)
             (is (string= "Node disconnected" waiter-error))
             (bt:join-thread agent-thread)
             (setf agent-thread nil)
             (bt:with-lock-held (events-lock)
               (is (= 1 (count :session-closed events)))))
        (gr8s::cancel-node-session control)
        (when waiter
          (ignore-errors (bt:join-thread waiter)))
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s:stop-node-grpc-server server)))))

(test pending-node-operation-wakes-for-stream-data-before-completion
  (with-temporary-store (store path)
    (values path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-stream" :name "worker-stream"
                                  :pod-cidr "10.88.5.0/24"))
    (let* ((server (gr8s::%make-node-grpc-server :store store))
           (request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id "stream-before-complete"
              :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
           (operation
             (gr8s::queue-node-operation server "worker-stream" request))
           (message
             (make-instance
              'gr8s.node.v1::operation-stream
              :operation-id "stream-before-complete" :sequence 1
              :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+
              :data (trivial-utf-8:string-to-utf-8-bytes "first")))
           (result nil)
           (waiter
             (bt:make-thread
              (lambda ()
                (setf result
                      (multiple-value-list
                       (gr8s::wait-for-next-node-operation-message
                        operation 0 :timeout 2))))
              :name "gr8s pending stream waiter")))
      (sleep 0.05)
      (gr8s::note-node-operation-stream server message)
      (bt:join-thread waiter)
      (is (eq message (first result)))
      (is (= 1 (second result)))
      (is-false (third result))
      (gr8s::finish-node-operation
       operation
       :response
       (make-instance
        'gr8s.node.v1::operation-response
        :operation-id "stream-before-complete"
        :status gr8s.node.v1::+operationstatus-operation_status_complete+))
      (multiple-value-bind (next cursor done-p)
          (gr8s::wait-for-next-node-operation-message
           operation 1 :timeout 1)
        (is (null next))
        (is (= 1 cursor))
        (is-true done-p))
      (gr8s::release-node-operation server operation)
      (is (null
           (gr8s::find-node-operation server "stream-before-complete"))))))

(test restarted-control-plane-rebuilds-snapshot-above-agent-revision
  (with-temporary-store (store path)
    (gr8s:register-node
     store (gr8s:make-node-record :id "node-recovery" :name "worker-a"
                                  :pod-cidr "10.88.7.0/24"))
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (server (gr8s::%make-node-grpc-server
                    :store store :port 0
                    :heartbeat-timeout-seconds 5
                    :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24)))
      (gr8s:mark-node-ready store "worker-a" (get-universal-time))
      (gr8s:schedule-pod store pod)
      (let* ((snapshot (gr8s::prepare-node-connect-snapshot server "worker-a" 42))
             (network (slot-value snapshot 'gr8s.node.v1::network)))
        (is (= 43 (slot-value snapshot 'gr8s.node.v1::revision)))
        (is (= 1 (length (slot-value snapshot 'gr8s.node.v1::pods))))
        (is (string= "10.88.7.0/24"
                     (slot-value network 'gr8s.node.v1::node-pod-cidr)))
        (is (string= "169.254.1.1"
                     (slot-value network 'gr8s.node.v1::dns-address)))
        (is (eq snapshot (gr8s::prepare-node-connect-snapshot server "worker-a" 43)))))))

(test cancelling-agent-during-server-hello-wait-unwinds-the-session
  (with-temporary-store (store path)
    (let* ((server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0))
           (control (gr8s::make-node-session-control))
           (received-hello nil)
           (agent nil))
      (unwind-protect
           (progn
             ;; A live peer accepts the RPC and reads requests but never sends
             ;; ServerHello. Cancellation must cover this handshake phase.
             (gr8s.node.v1::register-node-service-service
              (gr8s::node-grpc-server-grpc-server server)
              :connect-handler
              (lambda (context stream)
                (declare (ignore context))
                (setf received-hello (not (null (ag-grpc:stream-recv stream))))
                (loop while (ag-grpc:stream-recv stream))))
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s:run-node-session
                       "127.0.0.1" (gr8s:node-grpc-server-port server)
                       "stalled-worker" (merge-pathnames "stalled/identity.json" path)
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :control control :reconnect-delay 0.01))))
             (is-true (wait-until (lambda () received-hello) :timeout 3))
             (gr8s::cancel-node-session control)
             (is-true (wait-until (lambda () (not (bt:thread-alive-p agent)))
                                 :timeout 3)))
        (gr8s::cancel-node-session control)
        (when agent
          (when (bt:thread-alive-p agent) (bt:destroy-thread agent))
          (ignore-errors (bt:join-thread agent)))
        (gr8s:stop-node-grpc-server server)))))

(test node-underlay-identity-is-durable-and-cannot-overlap-another-node
  (with-temporary-store (store path)
    (dolist (entry '(("node-a" "worker-a" "10.88.1.0/24")
                     ("node-b" "worker-b" "10.88.2.0/24")))
      (gr8s:register-node store (gr8s:make-node-record
                                :id (first entry) :name (second entry)
                                :pod-cidr (third entry))))
    (is-true (gr8s::update-node-underlay-address store "worker-a" "192.0.2.10"))
    (is-false (gr8s::update-node-underlay-address store "worker-a" "192.0.2.10"))
    (signals gr8s:kubernetes-error
      (gr8s::update-node-underlay-address store "worker-b" "192.0.2.10"))
    (is (string= "192.0.2.10"
                 (gr8s::node-record-underlay-address
                  (gr8s:get-node (gr8s:open-store path) "worker-a"))))))

(test live-node-sessions-publish-peer-address-changes-and-withdrawals
  (with-temporary-store (store path)
    (dolist (entry '(("node-a" "worker-a" "10.88.1.0/24")
                     ("node-b" "worker-b" "10.88.2.0/24")))
      (gr8s:register-node store (gr8s:make-node-record
                                :id (first entry) :name (second entry)
                                :pod-cidr (third entry))))
    (let* ((server (gr8s:start-node-grpc-server store :host "127.0.0.1" :port 0))
           (control (gr8s::make-node-session-control))
           (agent nil) (snapshots nil)
           (lock (bt:make-lock "peer snapshot observations")))
      (labels ((latest-peer-address ()
                 (bt:with-lock-held (lock)
                   (let* ((snapshot (first snapshots))
                          (peer (and snapshot (first (slot-value snapshot 'gr8s.node.v1::routes)))))
                     (and peer (slot-value peer 'gr8s.node.v1::underlay-address)))))
               (connect-peer (address)
                 (gr8s:run-node-session
                  "127.0.0.1" (gr8s:node-grpc-server-port server) "worker-b"
                  (merge-pathnames "peer-b/identity.json" path)
                  (lambda (snapshot)
                    (is (string= address (slot-value (slot-value snapshot 'gr8s.node.v1::network)
                                                     'gr8s.node.v1::underlay-address))))
                  :underlay-address address :max-sessions 1)))
        (unwind-protect
             (progn
               (setf agent
                     (bt:make-thread
                      (lambda ()
                        (gr8s:run-node-session
                         "127.0.0.1" (gr8s:node-grpc-server-port server) "worker-a"
                         (merge-pathnames "peer-a/identity.json" path)
                         (lambda (snapshot)
                           (bt:with-lock-held (lock) (push snapshot snapshots)) nil)
                         :underlay-address "192.0.2.10" :control control
                         :reconnect-delay 0.01))))
               (is-true (wait-until (lambda () (bt:with-lock-held (lock) snapshots)) :timeout 5))
               (connect-peer "192.0.2.11")
               (is-true (wait-until (lambda () (equal "192.0.2.11" (latest-peer-address))) :timeout 5))
               (connect-peer "192.0.2.12")
               (is-true (wait-until (lambda () (equal "192.0.2.12" (latest-peer-address))) :timeout 5))
               (connect-peer "")
               (is-true (wait-until (lambda () (null (latest-peer-address))) :timeout 5)))
          (gr8s::cancel-node-session control)
          (when agent
            (unless (wait-until (lambda () (not (bt:thread-alive-p agent))) :timeout 3)
              (bt:destroy-thread agent))
            (ignore-errors (bt:join-thread agent)))
          (gr8s:stop-node-grpc-server server))))))
