(in-package #:gr8s/tests)

(in-suite gr8s)

(defun pod-assignment-for-test (pod)
  (make-instance
   'gr8s.node.v1::pod-assignment
   :namespace (pod-namespace pod)
   :name (pod-name pod)
   :uid (pod-uid pod)
   :resource-version (pod-resource-version pod)
   :pod-json
   (trivial-utf-8:string-to-utf-8-bytes
    (with-output-to-string (stream)
      (com.inuoe.jzon:stringify (pod-to-object pod) :stream stream)))))

(defun desired-snapshot-for-test (&rest pods)
  (make-instance
   'gr8s.node.v1::desired-state-snapshot
   :revision 1
   :pods (mapcar #'pod-assignment-for-test pods)))

(test node-runtime-owns-the-local-cni-service-lifecycle
  (let* ((directory
           (merge-pathnames
            (format nil "gr8s-node-cni-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (manager
           (gr8s::make-managed-containerd
            :state-directory directory
            :executable "/opt/gr8s/containerd"
            :oci-runtime "/opt/gr8s/runc"
            :cni-bin-directory "/opt/gr8s/cni/"))
         (runtime (gr8s::make-containerd-runtime))
         (node-runtime (gr8s::make-node-runtime directory runtime manager))
         (socket-path
           (gr8s::managed-containerd-agent-cni-socket-path manager))
         (add-called nil))
    (unwind-protect
         (progn
           (gr8s::call-with-agent-cni-server
            node-runtime
            (lambda ()
              (is (probe-file socket-path))
              (let ((response
                      (gr8s::call-agent-cni
                       socket-path
                       (agent-cni-request-for-test "ADD")
                       :timeout 1)))
                (is-true
                 (slot-value response 'gr8s.node.v1::success))))
            :operations
            (gr8s::make-cni-operations
             :add (lambda (&rest arguments)
                    (declare (ignore arguments))
                    (setf add-called t))))
           (is-true add-called)
           (is-false (probe-file socket-path)))
      (when (probe-file directory)
        (uiop:delete-directory-tree directory :validate t)))))

(test node-runtime-lifecycle-and-snapshot-reconciliation-are-idempotent
  (with-temporary-store (control-store path)
    (let* ((pod (create-pod control-store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (state (merge-pathnames "agent-runtime/" path))
           (first (gr8s::make-node-runtime state runtime nil)))
      (is (eq first (gr8s::start-node-runtime first)))
      (is (eq first (gr8s::start-node-runtime first)))
      (let ((statuses
              (gr8s::reconcile-node-snapshot
               first (desired-snapshot-for-test pod))))
        (is (= 1 (length statuses)))
        (is (string= "Running"
                     (slot-value (first statuses)
                                 'gr8s.node.v1::phase))))
      (is (= 1 (fake-runtime-ensure-count runtime)))
      (gr8s::reconcile-node-snapshot first (desired-snapshot-for-test pod))
      (is (= 1 (fake-runtime-ensure-count runtime)))
      (is (null (gr8s::stop-node-runtime first)))
      (is (null (gr8s::stop-node-runtime first)))

      ;; A fresh agent runtime opens the durable assignment store and adopts
      ;; the runtime Pod already carrying this UID/resource version.
      (let ((second (gr8s::make-node-runtime state runtime nil)))
        (gr8s::start-node-runtime second)
        (gr8s::reconcile-node-snapshot second (desired-snapshot-for-test pod))
        (is (= 1 (fake-runtime-ensure-count runtime)))
        (gr8s::reconcile-node-snapshot second (desired-snapshot-for-test))
        (is (null (runtime-observe runtime (pod-uid pod))))
        (gr8s::stop-node-runtime second)))))

(test control-plane-runtime-schedules-and-publishes-authoritative-snapshots
  (with-temporary-store (store path)
    (values path)
    (let* ((node (gr8s:make-node-record
                  :id "node-1" :name "worker-a" :pod-cidr "10.88.0.0/24"))
           (server (gr8s::%make-node-grpc-server :store store))
           (runtime (gr8s::make-control-plane-runtime store server))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s:register-node store node)
      (gr8s:mark-node-ready store "worker-a" (get-universal-time))

      (let ((observed (runtime-ensure runtime pod)))
        (is (string= "worker-a" (gr8s::pod-node-name pod)))
        (is (string= "Pending" (runtime-pod-phase observed)))
        (let* ((snapshot (gr8s::current-node-snapshot server "worker-a"))
               (assignments
                 (slot-value snapshot 'gr8s.node.v1::pods))
               (assignment (first assignments)))
          (is (= 1 (length assignments)))
          (is (string= (pod-uid pod)
                       (slot-value assignment 'gr8s.node.v1::uid)))
          (is (string= (pod-resource-version pod)
                       (slot-value assignment
                                   'gr8s.node.v1::resource-version)))
          (is (string= "worker-a"
                       (gr8s::pod-node-name
                        (gr8s::assignment-pod assignment))))))

      (runtime-delete runtime (pod-uid pod))
      (is (null (slot-value
                 (gr8s::current-node-snapshot server "worker-a")
                 'gr8s.node.v1::pods))))))

(test interactive-node-exec-bridges-runtime-websocket-streams
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (node-runtime
             (gr8s::make-node-runtime
              (merge-pathnames "interactive-agent/" path) runtime nil))
           (listener
             (usocket:socket-listen
              "127.0.0.1" 0 :reuse-address t
              :element-type '(unsigned-byte 8)))
           (port (usocket:get-local-port listener))
           (received nil)
           (upstream-error nil)
           (upstream-thread nil)
           (emitted nil)
           (emitted-lock (bt:make-lock "gr8s interactive emitted messages"))
           (request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id "interactive-agent-1"
              :kind gr8s.node.v1::+operationkind-operation_kind_exec+
              :namespace "default" :pod (pod-name pod) :pod-uid (pod-uid pod)
              :container "web" :command '("sh" "-i")
              :stdin t :stdout t :stderr t :tty t)))
      (labels ((emit (variant payload)
                 (bt:with-lock-held (emitted-lock)
                   (setf emitted
                         (nconc emitted (list (cons variant payload))))))
               (emitted-status-p (status)
                 (bt:with-lock-held (emitted-lock)
                   (find status emitted
                         :key (lambda (entry)
                                (and (eq :operation-response (car entry))
                                     (slot-value (cdr entry)
                                                 'gr8s.node.v1::status)))))))
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
                              (dotimes (index 3)
                                (multiple-value-bind (opcode payload)
                                    (gr8s::read-websocket-frame stream)
                                  (assert (< index 3))
                                  (push (cons opcode payload) received)))
                              (gr8s::write-websocket-frame
                               stream 2
                               (concatenate
                                '(vector (unsigned-byte 8))
                                #(1)
                                (trivial-utf-8:string-to-utf-8-bytes
                                 "remote shell\n")))
                              (gr8s::write-websocket-frame
                               stream 2
                               (concatenate
                                '(vector (unsigned-byte 8))
                                #(2)
                                (trivial-utf-8:string-to-utf-8-bytes
                                 "remote error\n")))
                              (gr8s::write-websocket-frame
                               stream 2
                               (concatenate
                                '(vector (unsigned-byte 8)) #(3)
                                (gr8s::exec-exit-status-bytes 7)))
                              (gr8s::write-websocket-frame
                               stream 8
                               (make-array 0 :element-type '(unsigned-byte 8))))
                         (ignore-errors (usocket:socket-close socket))))
                   (error (condition)
                     (setf upstream-error condition))))
               :name "gr8s fake interactive runtime websocket"))
        (gr8s::set-fake-runtime-exec-url
         runtime (format nil "http://127.0.0.1:~D/exec/token" port))
        (unwind-protect
             (progn
               (gr8s::start-node-runtime node-runtime)
               (gr8s::reconcile-node-snapshot
                node-runtime (desired-snapshot-for-test pod))
               (gr8s::dispatch-node-operation
                node-runtime :operation-request request #'emit)
               (is-true
                (wait-until
                 (lambda ()
                   (emitted-status-p
                    gr8s.node.v1::+operationstatus-operation_status_accepted+))
                 :timeout 3))
               (gr8s::dispatch-node-operation
                node-runtime :operation-input
                (make-instance
                 'gr8s.node.v1::operation-input
                 :operation-id "interactive-agent-1" :sequence 1
                 :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                 :data (trivial-utf-8:string-to-utf-8-bytes "echo hi\n"))
                #'emit)
               (gr8s::dispatch-node-operation
                node-runtime :operation-input
                (make-instance
                 'gr8s.node.v1::operation-input
                 :operation-id "interactive-agent-1" :sequence 2
                 :channel
                 gr8s.node.v1::+streamchannel-stream_channel_terminal_resize+
                 :rows 24 :columns 80)
                #'emit)
               (gr8s::dispatch-node-operation
                node-runtime :operation-input
                (make-instance
                 'gr8s.node.v1::operation-input
                 :operation-id "interactive-agent-1" :sequence 3
                 :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                 :eof t)
                #'emit)
               (is-true
                (wait-until
                 (lambda ()
                   (emitted-status-p
                    gr8s.node.v1::+operationstatus-operation_status_complete+))
                 :timeout 3))
               (bt:join-thread upstream-thread)
               (is (null upstream-error) "~A" upstream-error)
               (let ((frames (nreverse received)))
                 (is (= 3 (length frames)))
                 (is (every (lambda (frame) (= 2 (car frame))) frames))
                 (is (= 0 (aref (cdr (first frames)) 0)))
                 (is (string= "echo hi\n"
                              (trivial-utf-8:utf-8-bytes-to-string
                               (subseq (cdr (first frames)) 1))))
                 (is (= 4 (aref (cdr (second frames)) 0)))
                 (let ((size
                         (com.inuoe.jzon:parse
                          (trivial-utf-8:utf-8-bytes-to-string
                           (subseq (cdr (second frames)) 1)))))
                   (is (= 80 (gethash "width" size)))
                   (is (= 24 (gethash "height" size))))
                 (is (equalp #(255 0) (cdr (third frames)))))
               (let ((stdout
                       (bt:with-lock-held (emitted-lock)
                         (find
                          gr8s.node.v1::+streamchannel-stream_channel_stdout+
                          emitted
                          :key (lambda (entry)
                                 (and (eq :operation-stream (car entry))
                                      (slot-value (cdr entry)
                                                  'gr8s.node.v1::channel)))))))
                 (is (string= "remote shell\n"
                              (trivial-utf-8:utf-8-bytes-to-string
                               (slot-value (cdr stdout)
                                           'gr8s.node.v1::data)))))
               (let ((complete
                       (bt:with-lock-held (emitted-lock)
                         (find
                          gr8s.node.v1::+operationstatus-operation_status_complete+
                          emitted
                          :key (lambda (entry)
                                 (and (eq :operation-response (car entry))
                                      (slot-value (cdr entry)
                                                  'gr8s.node.v1::status)))))))
                 (is (= 7 (slot-value (cdr complete)
                                      'gr8s.node.v1::exit-code))))
               (let ((stderr
                       (bt:with-lock-held (emitted-lock)
                         (find
                          gr8s.node.v1::+streamchannel-stream_channel_stderr+
                          emitted
                          :key (lambda (entry)
                                 (and (eq :operation-stream (car entry))
                                      (slot-value (cdr entry)
                                                  'gr8s.node.v1::channel)))))))
                 (is (string= "remote error\n"
                              (trivial-utf-8:utf-8-bytes-to-string
                               (slot-value (cdr stderr)
                                           'gr8s.node.v1::data))))))
          (gr8s::stop-node-runtime node-runtime)
          (ignore-errors (usocket:socket-close listener)))))))

(test ending-agent-session-abandons-its-interactive-exec-operations
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (node-runtime
             (gr8s::make-node-runtime
              (merge-pathnames "abandoned-exec-agent/" path) runtime nil))
           (listener
             (usocket:socket-listen
              "127.0.0.1" 0 :reuse-address t
              :element-type '(unsigned-byte 8)))
           (port (usocket:get-local-port listener))
           (upstream-connected-p nil)
           (upstream-closed-p nil)
           (upstream-error nil)
           (upstream-thread nil)
           (emitted nil)
           (request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id "abandoned-agent-exec"
              :kind gr8s.node.v1::+operationkind-operation_kind_exec+
              :namespace "default" :pod (pod-name pod) :pod-uid (pod-uid pod)
              :container "web" :command '("sh" "-i")
              :stdin t :stdout t :stderr t :tty t)))
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
                 (error (condition)
                   (setf upstream-error condition))))
             :name "gr8s abandoned exec fake runtime"))
      (gr8s::set-fake-runtime-exec-url
       runtime (format nil "http://127.0.0.1:~D/exec/token" port))
      (unwind-protect
           (progn
             (gr8s::start-node-runtime node-runtime)
             (gr8s::reconcile-node-snapshot
              node-runtime (desired-snapshot-for-test pod))
             (gr8s::dispatch-node-operation
              node-runtime :operation-request request
              (lambda (variant payload)
                (push (cons variant payload) emitted)))
             (is-true
              (wait-until (lambda () upstream-connected-p) :timeout 3))
             (is-true
              (gr8s::find-node-exec-operation
               node-runtime "abandoned-agent-exec"))
             (gr8s::dispatch-node-operation
              node-runtime :session-closed nil nil)
             (is-true
              (wait-until (lambda () upstream-closed-p) :timeout 3))
             (is-false
              (gr8s::find-node-exec-operation
               node-runtime "abandoned-agent-exec"))
             ;; The session is gone, so cleanup must not emit a terminal reply
             ;; through the stale gRPC callback.
             (is (= 1 (length emitted)))
             (is (= gr8s.node.v1::+operationstatus-operation_status_accepted+
                    (slot-value (cdar emitted) 'gr8s.node.v1::status)))
             (bt:join-thread upstream-thread)
             (setf upstream-thread nil)
             (is (null upstream-error) "~A" upstream-error))
        (gr8s::stop-node-runtime node-runtime)
        (ignore-errors (usocket:socket-close listener))
        (when upstream-thread
          (ignore-errors (bt:join-thread upstream-thread)))))))

(defun node-network-for-test (&optional (cidr "10.88.8.0/24"))
  (make-instance 'gr8s.node.v1::node-network-config
                 :cluster-pod-cidr "10.88.0.0/16" :node-pod-cidr cidr
                 :dns-address "169.254.1.1" :mtu 1450 :vni 42))

(test assigned-network-and-ipam-restore-before-agent-reconciliation
  (with-temporary-store (store path)
    (assert store)
    (let* ((state (merge-pathnames "network-agent/" path))
           (runtime (gr8s::make-node-runtime state (make-fake-runtime) nil))
           (network (gr8s::node-network-object (node-network-for-test))))
      (gr8s::configure-node-runtime-network runtime network)
      (is (string= "10.88.8.1"
                   (gr8s::allocate-pod-address
                    (gr8s::node-runtime-ipam runtime) "sandbox-a" "eth0")))
      (let ((restored (gr8s::make-node-runtime state (make-fake-runtime) nil)))
        (is-true (gr8s::node-runtime-cni-operations restored))
        (is (string= "10.88.8.1"
                     (gr8s::check-pod-address
                      (gr8s::node-runtime-ipam restored) "sandbox-a" "eth0")))
        (signals gr8s::cni-error
          (gr8s::configure-node-runtime-network
           restored (gr8s::node-network-object
                     (node-network-for-test "10.88.9.0/24")))))
      (is (= #o600 (logand #o777 (sb-posix:stat-mode
                                 (sb-posix:stat
                                  (gr8s::node-runtime-network-path runtime)))))))))

(test managed-agent-refuses-cni-before-network-assignment
  (with-temporary-store (store path)
    (assert store)
    (let* ((runtime (gr8s::make-node-runtime path (make-fake-runtime) nil))
           (response (gr8s::handle-node-runtime-cni
                      runtime (agent-cni-request-for-test "ADD"))))
      (is-false (slot-value response 'gr8s.node.v1::success))
      (is (search "assignment is not ready"
                  (slot-value response 'gr8s.node.v1::error-message))))))

(test node-network-rejects-invalid-subnets-before-persistence
  (with-temporary-store (store path)
    (assert store)
    (let ((runtime (gr8s::make-node-runtime path (make-fake-runtime) nil)))
      (dolist (cidr '("192.0.2.0/24" "10.88.1.1/24" "10.88.0.0/31"))
        (signals gr8s::cni-error
          (gr8s::configure-node-runtime-network
           runtime (gr8s::node-network-object (node-network-for-test cidr)))))
      (is-false (probe-file (gr8s::node-runtime-network-path runtime))))))

(defun node-network-with-routes-for-test (routes)
  (let ((network (gr8s::node-network-object (node-network-for-test))))
    (setf (gethash "underlayAddress" network) "192.0.2.1"
          (gethash "routes" network)
          (coerce (loop for (id cidr address) in routes
                        collect (gr8s::json-object "nodeID" id "podCIDR" cidr
                                                   "underlayAddress" address)) 'vector))
    network))

(test partial-node-network-update-is-replayed-from-the-durable-journal
  (with-temporary-store (store path)
    (assert store)
    (let* ((state (merge-pathnames "journal-agent/" path))
           (fail-p nil)
           (attempts nil)
           (reconciler (lambda (network previous)
                         (push (cons network previous) attempts)
                         (when fail-p (error "injected partial FDB update failure"))))
           (runtime (gr8s::make-node-runtime state (make-fake-runtime) nil
                                             :network-reconciler reconciler))
           (old (node-network-with-routes-for-test
                 '(("node-a" "10.88.9.0/24" "192.0.2.2"))))
           (new (node-network-with-routes-for-test
                 '(("node-a" "10.88.9.0/24" "192.0.2.3")
                   ("node-b" "10.88.10.0/24" "192.0.2.4")))))
      (gr8s::configure-node-runtime-network runtime old)
      (gr8s::allocate-pod-address (gr8s::node-runtime-ipam runtime) "existing-pod" "eth0")
      (setf fail-p t)
      (signals error (gr8s::configure-node-runtime-network runtime new))
      (is (eq old (gr8s::node-runtime-network runtime)))
      (is (equalp old (com.inuoe.jzon:parse (gr8s::node-runtime-network-path runtime))))
      (is (equalp new (com.inuoe.jzon:parse (gr8s::node-runtime-network-pending-path runtime))))
      (setf fail-p nil attempts nil)
      (let* ((restarted (gr8s::make-node-runtime state (make-fake-runtime) nil
                                               :network-reconciler reconciler))
             (previous (cdr (first attempts)))
             (old-routes (mapcan #'gr8s::node-vxlan-route-pairs previous)))
        ;; Both the old kernel entries and partially installed new entries are
        ;; available to cleanup on restart, while Pod addresses remain stable.
        (is (member '("10.88.9.0/24" . "192.0.2.2") old-routes :test #'equal))
        (is (member '("10.88.9.0/24" . "192.0.2.3") old-routes :test #'equal))
        (is (equalp new (gr8s::node-runtime-network restarted)))
        (is-false (probe-file (gr8s::node-runtime-network-pending-path restarted)))
        (is (string= "10.88.8.1"
                     (gr8s::check-pod-address
                      (gr8s::node-runtime-ipam restarted) "existing-pod" "eth0")))))))

(test node-network-rejects-conflicting-peer-routes
  (dolist (routes '((("a" "10.88.8.0/24" "192.0.2.2"))
                    (("a" "192.0.2.0/24" "192.0.2.2"))
                    (("a" "10.88.9.1/24" "192.0.2.2"))
                    (("a" "10.88.9.0/24" "127.0.0.1"))
                    (("a" "10.88.9.0/24" "192.0.2.1"))
                    (("a" "10.88.9.0/24" "192.0.2.2")
                     ("a" "10.88.10.0/24" "192.0.2.3"))
                    (("a" "10.88.9.0/24" "192.0.2.2")
                     ("b" "10.88.9.128/25" "192.0.2.3"))))
    (signals gr8s::cni-error
      (gr8s::validate-node-network-object (node-network-with-routes-for-test routes)))))
