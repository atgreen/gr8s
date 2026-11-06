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

(defun fake-spdy-read-frame (stream)
  "Read one frame a client sent: (:syn id type), (:data id fin octets), or NIL at the end."
  (let ((head (gr8s::spdy-read-octets stream 8)))
    (when head
      (let* ((size (logand (gr8s::spdy-read-u32 head 4) #xFFFFFF))
             (payload (if (plusp size) (gr8s::spdy-read-octets stream size) (make-array 0 :element-type '(unsigned-byte 8)))))
        (if (logbitp 7 (aref head 0))
            (let* ((text (map 'string #'code-char payload))
                   (position (+ (search "streamtype" text) (length "streamtype") 4)))
              ;; Five octets of sync flush follow the value.
              (list :syn (gr8s::spdy-read-u32 payload 0) (subseq text position (- (length text) 5))))
            (list :data (gr8s::spdy-read-u32 head 0) (logbitp 0 (aref head 4)) payload))))))

(defun fake-spdy-accept (stream count)
  "Answer the upgrade on STREAM and return an alist of channel name to stream ID for COUNT streams."
  (gr8s::read-http-response-head stream)
  (write-sequence
   (gr8s::ascii-octets
    (format nil "HTTP/1.1 101 Switching Protocols~C~CConnection: Upgrade~C~CUpgrade: SPDY/3.1~C~C~C~C"
            #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))
   stream)
  (finish-output stream)
  (loop repeat count
        for frame = (fake-spdy-read-frame stream)
        collect (cons (third frame) (second frame))))

(defun fake-spdy-send (stream id text &key fin octets)
  "Send TEXT, or OCTETS, on stream ID as the runtime would."
  (let ((data (or octets (trivial-utf-8:string-to-utf-8-bytes text)))
        (session (gr8s::make-spdy-session stream)))
    (gr8s::spdy-write-data session id data :fin fin)))

(test interactive-node-exec-bridges-runtime-spdy-streams
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
           (opened nil)
           (stream-ids nil)
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
                              (let ((streams (fake-spdy-accept stream 5)))
                                (setf opened (mapcar #'car streams))
                                (dotimes (index 3)
                                  (push (fake-spdy-read-frame stream) received))
                                (fake-spdy-send stream (cdr (assoc "stdout" streams :test #'equal))
                                                "remote shell\n" :fin t)
                                (fake-spdy-send stream (cdr (assoc "stderr" streams :test #'equal))
                                                "remote error\n" :fin t)
                                (fake-spdy-send stream (cdr (assoc "error" streams :test #'equal)) nil
                                                :octets (gr8s::exec-exit-status-bytes 7) :fin t)
                                (setf stream-ids streams)
                                ;; Wait for the client to go away, as the real server's handler returns first.
                                (ignore-errors (loop while (fake-spdy-read-frame stream)))))
                         (ignore-errors (usocket:socket-close socket))))
                   (error (condition)
                     (setf upstream-error condition))))
               :name "gr8s fake interactive runtime stream"))
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
               (is (equal '("error" "stdin" "stdout" "stderr" "resize") opened))
               (let ((frames (reverse received))
                     (stdin (cdr (assoc "stdin" stream-ids :test #'equal)))
                     (resize (cdr (assoc "resize" stream-ids :test #'equal))))
                 (is (= 3 (length frames)))
                 (is (equal (list :data stdin nil) (subseq (first frames) 0 3)))
                 (is (string= "echo hi\n"
                              (trivial-utf-8:utf-8-bytes-to-string (fourth (first frames)))))
                 (is (equal (list :data resize nil) (subseq (second frames) 0 3)))
                 (let ((size (com.inuoe.jzon:parse
                              (trivial-utf-8:utf-8-bytes-to-string (fourth (second frames))))))
                   (is (= 80 (gethash "Width" size)))
                   (is (= 24 (gethash "Height" size))))
                 ;; Ending stdin ends that stream alone, leaving the output to come.
                 (is (equal (list :data stdin t) (subseq (third frames) 0 3))))
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

(test node-attach-streams-the-container-without-stdin-or-a-command
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (node-runtime (gr8s::make-node-runtime (merge-pathnames "attach-agent/" path) runtime nil))
           (listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
           (emitted nil)
           (emitted-lock (bt:make-lock "gr8s attach emitted messages"))
           (opened nil)
           (request (make-instance 'gr8s.node.v1::operation-request
                                   :operation-id "attach-agent-1"
                                   :kind gr8s.node.v1::+operationkind-operation_kind_attach+
                                   :namespace "default" :pod (pod-name pod) :pod-uid (pod-uid pod)
                                   :container "web" :stdout t :stderr t))
           (upstream
             (bt:make-thread
              (lambda ()
                (let* ((socket (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
                       (stream (usocket:socket-stream socket)))
                  (unwind-protect
                       (progn
                         (let ((streams (fake-spdy-accept stream 3)))
                           (setf opened (mapcar #'car streams))
                           (fake-spdy-send stream (cdr (assoc "stdout" streams :test #'equal)) (format nil "attached~%") :fin t)
                           (fake-spdy-send stream (cdr (assoc "stderr" streams :test #'equal)) nil
                                           :octets (make-array 0 :element-type '(unsigned-byte 8)) :fin t)
                           (fake-spdy-send stream (cdr (assoc "error" streams :test #'equal)) nil
                                           :octets (gr8s::exec-exit-status-bytes 0) :fin t)
                           (ignore-errors (loop while (fake-spdy-read-frame stream)))))
                    (ignore-errors (usocket:socket-close socket)))))
              :name "gr8s fake attach stream")))
      (labels ((emit (variant payload)
                 (bt:with-lock-held (emitted-lock)
                   (setf emitted (nconc emitted (list (cons variant payload))))))
               (response (status)
                 (bt:with-lock-held (emitted-lock)
                   (cdr (find-if (lambda (entry)
                                   (and (eq :operation-response (car entry))
                                        (= status (slot-value (cdr entry) 'gr8s.node.v1::status))))
                                 emitted)))))
        (gr8s::set-fake-runtime-exec-url
         runtime (format nil "http://127.0.0.1:~D/attach/token" (usocket:get-local-port listener)))
        (unwind-protect
             (progn
               (gr8s::start-node-runtime node-runtime)
               (gr8s::reconcile-node-snapshot node-runtime (desired-snapshot-for-test pod))
               (gr8s::dispatch-node-operation node-runtime :operation-request request #'emit)
               (is-true (wait-until
                         (lambda () (response gr8s.node.v1::+operationstatus-operation_status_complete+))
                         :timeout 3))
               (bt:join-thread upstream)
               (is (equal '("error" "stdout" "stderr") opened))
               (is (= 0 (slot-value (response gr8s.node.v1::+operationstatus-operation_status_complete+)
                                    'gr8s.node.v1::exit-code)))
               (let ((stdout (bt:with-lock-held (emitted-lock)
                               (cdr (find :operation-stream emitted :key #'car)))))
                 (is (string= (format nil "attached~%") (trivial-utf-8:utf-8-bytes-to-string
                                            (slot-value stdout 'gr8s.node.v1::data))))))
          (gr8s::stop-node-runtime node-runtime)
          (ignore-errors (usocket:socket-close listener)))))))

(test node-exec-output-waits-for-a-control-plane-that-acknowledges-it
  (flet ((operation (acknowledges)
           (gr8s::make-node-exec-operation
            nil (make-instance 'gr8s.node.v1::operation-request :operation-id "window" :acknowledges-output acknowledges)
            nil nil nil))
         (acknowledge (operation sequence count)
           (gr8s::write-node-exec-input
            operation (make-instance 'gr8s.node.v1::operation-input
                                     :operation-id "window" :sequence sequence
                                     :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                                     :data (make-array 0 :element-type '(unsigned-byte 8))
                                     :acknowledged-bytes count))))
    ;; An older control plane never acknowledges, so its node sends as before.
    (let ((legacy (operation nil)))
      (setf (gr8s::node-exec-operation-unacknowledged-output legacy) (* 10 gr8s::+exec-output-window-bytes+))
      (is-true (gr8s::wait-for-node-exec-output-window legacy 100)))
    (let* ((windowed (operation t)) (sent nil)
           (sender (progn
                     (setf (gr8s::node-exec-operation-unacknowledged-output windowed) gr8s::+exec-output-window-bytes+)
                     (bt:make-thread (lambda () (setf sent (gr8s::wait-for-node-exec-output-window windowed 100)))
                                     :name "gr8s exec window test sender"))))
      ;; A full window holds the output back until the client has taken some.
      (is (not (wait-until (lambda () sent) :timeout 0.5)))
      (acknowledge windowed 1 4096)
      (is-true (wait-until (lambda () sent) :timeout 5))
      (bt:join-thread sender)
      (is (= (+ (- gr8s::+exec-output-window-bytes+ 4096) 100)
             (gr8s::node-exec-operation-unacknowledged-output windowed)))
      ;; A finished operation stops waiting.
      (setf (gr8s::node-exec-operation-unacknowledged-output windowed) gr8s::+exec-output-window-bytes+
            (gr8s::node-exec-operation-finished-p windowed) t)
      (is (null (gr8s::wait-for-node-exec-output-window windowed 100))))))

(test node-exec-status-reads-the-exit-code-of-a-status-frame
  (flet ((frame (text) (trivial-utf-8:string-to-utf-8-bytes text)))
    (is (= 0 (gr8s::node-exec-status-exit-code (gr8s::exec-exit-status-bytes 0))))
    (is (= 7 (gr8s::node-exec-status-exit-code (gr8s::exec-exit-status-bytes 7))))
    (is (= 0 (gr8s::node-exec-status-exit-code (frame "{\"status\":\"Success\"}"))))
    (is (= 1 (gr8s::node-exec-status-exit-code (frame "{\"status\":\"Failure\"}"))))))

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
                            (fake-spdy-accept stream 5)
                            (setf upstream-connected-p t)
                            (handler-case (loop while (fake-spdy-read-frame stream))
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

(test node-runtime-repairs-cached-topology-without-pods-or-a-control-connection
  (with-temporary-store (store path)
    (assert store)
    (let* ((state (merge-pathnames "offline-network/" path))
           (lock (bt:make-lock "simulated kernel topology"))
           (installed nil)
           (runtime
             (gr8s::make-node-runtime
              state (make-fake-runtime) nil
              :network-reconciler
              (lambda (network previous)
                (declare (ignore previous))
                (bt:with-lock-held (lock) (setf installed network)))))
           (network (node-network-with-routes-for-test
                     '(("peer" "10.88.9.0/24" "192.0.2.2")))))
      (gr8s::configure-node-runtime-network runtime network)
      (let ((journal (uiop:read-file-string (gr8s::node-runtime-network-path runtime))))
        ;; Simulate loss of the tunnel FDB without changing desired state.
        (bt:with-lock-held (lock) (setf installed nil))
        (unwind-protect
             (progn
               (gr8s::start-node-runtime runtime)
               (is-true (wait-until (lambda () (bt:with-lock-held (lock) installed))))
               (is (string= journal (uiop:read-file-string (gr8s::node-runtime-network-path runtime)))))
          (gr8s::stop-node-runtime runtime))))))

(test withdrawn-assignment-persists-deletion-intent-before-runtime-removal
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (node (gr8s::make-node-runtime (merge-pathnames "withdrawn/" path) runtime nil)))
      (gr8s::put-assigned-pod (gr8s::node-runtime-store node) pod)
      (gr8s::reconcile-pod (gr8s::node-runtime-reconciler node) "default" (pod-name pod))
      (set-fake-runtime-failure runtime "transient sandbox deletion failure")
      (signals gr8s::runtime-error (gr8s::remove-unassigned-pods node nil))
      (is-true (gr8s::deletion-requested-p
                (get-pod (gr8s::node-runtime-store node) "default" (pod-name pod))))
      ;; Reopening the local desired store still converges deletion, not create.
      (let ((restored (gr8s::make-node-runtime (merge-pathnames "withdrawn/" path) runtime nil)))
        (gr8s::reconcile-pod (gr8s::node-runtime-reconciler restored) "default" (pod-name pod))
        (signals gr8s:kubernetes-error
          (get-pod (gr8s::node-runtime-store restored) "default" (pod-name pod))))
      (is (= 1 (fake-runtime-ensure-count runtime))))))

(test namespaced-pods-survive-control-plane-and-agent-snapshots
  (with-temporary-store (store directory)
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
           (fake (make-fake-runtime))
           (agent (gr8s::make-node-runtime (merge-pathnames "agent/" directory) fake nil)))
      (gr8s::start-node-runtime agent)
      (setf (gethash "namespace" (gethash "metadata" object)) "sonobuoy")
      (let ((pod (create-pod store (parse-pod object))))
        (gr8s::persist-pod-assignment store pod "worker-a")
        (let ((snapshot (gr8s::node-desired-state-snapshot store "worker-a")))
          (is (= 1 (length (slot-value snapshot 'gr8s.node.v1::pods))))
          (gr8s::reconcile-node-snapshot agent snapshot)
          (is (= 1 (length (list-pods (gr8s::node-runtime-store agent)))))
          (is (string= "sonobuoy" (pod-namespace
                                  (get-pod (gr8s::node-runtime-store agent) "sonobuoy" "hello"))))
          (gr8s::reconcile-all (gr8s::node-runtime-reconciler agent))
          (is (= 1 (fake-runtime-ensure-count fake)))
          (gr8s::reconcile-node-snapshot agent (desired-snapshot-for-test))
          (is (null (list-pods (gr8s::node-runtime-store agent))))
          (gr8s::stop-node-runtime agent))))))

(test spdy-header-blocks-announce-the-dictionary-once-and-store-their-names
  (let* ((session (gr8s::make-spdy-session nil))
         (first (gr8s::spdy-header-block session '(("streamtype" . "error"))))
         (second (gr8s::spdy-header-block session '(("streamtype" . "stdin")))))
    (is (equalp #(#x78 #xF9 #xE3 #xC6 #xA7 #xC2) (subseq first 0 6)))
    (is (= 0 (aref first 6)))
    (let ((size (+ (aref first 7) (* 256 (aref first 8)))))
      (is (= size (- (length first) 16)))
      (is (equalp #(0 0 0 #xFF #xFF) (subseq first (- (length first) 5))))
      (is (= (logxor size #xFFFF) (+ (aref first 9) (* 256 (aref first 10))))))
    ;; The stream continues, so only the first block has a zlib header.
    (is (= 0 (aref second 0)))
    (is (search "stdin" (map 'string #'code-char second)))))
