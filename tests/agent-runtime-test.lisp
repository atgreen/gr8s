(in-package #:gr8s/tests)

(in-suite gr8s)

(test network-explain-node-operation-does-not-require-a-pod
  (with-temporary-store (ignored directory)
    (declare (ignore ignored))
    (let* ((runtime (gr8s.agent::make-node-runtime directory (make-fake-runtime) nil))
           (state (gr8s.agent::node-runtime-wireguard-path-state runtime))
           (peer (gr8s.network::record-wireguard-path-decision
                  state "peer-a" '("lan" "10.0.0.9" 51820)
                  '("underlay" "192.0.2.9" 51820) :current-unhealthy 1000))
           (request (make-instance 'gr8s.node.v1::operation-request
                                   :operation-id "explain-1"
                                   :kind gr8s.node.v1::+operationkind-operation_kind_network_explain+
                                   :peer-id "destination-b"))
           (replies nil))
      (setf (gr8s.agent::node-runtime-network runtime)
            (gr8s.foundation::json-object
             "overlayBackend" "wireguard"
             "routes"
             (vector
              (gr8s.foundation::json-object
               "nodeID" "destination-b" "nodeName" "destination-b"
               "nextHop" (gr8s.foundation::json-object "nodeID" "peer-a"
                                              "nodeName" "peer-a")))))
      (setf (cl-wireguard-overlay::wireguard-peer-path-state-observations peer)
            (list (cl-wireguard-overlay::make-wireguard-path-observation
                   :name "lan" :address "10.0.0.9" :port 51820
                   :handshake-age-seconds 1)))
      (setf replies (gr8s.agent::handle-node-operation runtime request))
      (is (= 2 (length replies)))
      (is (eq :operation-stream (caar replies)))
      (is (search "\"peerID\":\"peer-a\""
                  (trivial-utf-8:utf-8-bytes-to-string
                   (slot-value (cdar replies) 'gr8s.node.v1::data))))
      (is (search "\"destinationPeerID\":\"destination-b\""
                  (trivial-utf-8:utf-8-bytes-to-string
                   (slot-value (cdar replies) 'gr8s.node.v1::data))))
      (is (search "\"topologyReason\":\"sparse-next-hop\""
                  (trivial-utf-8:utf-8-bytes-to-string
                   (slot-value (cdar replies) 'gr8s.node.v1::data)))))))

(test node-runtime-lazily-starts-and-applies-wireguard-path-telemetry
  (let* ((runtime (gr8s.agent::%make-node-runtime
                   :wireguard-path-state (cl-wireguard-overlay::make-wireguard-path-state)))
         (network (gr8s.foundation::json-object "overlayBackend" "wireguard"))
         (peer (cl-wireguard-overlay::make-wireguard-peer-path-state
                :peer-id "peer-a" :selected '("lan" "10.0.0.9" 51820)
                :observations
                (list (cl-wireguard-overlay::make-wireguard-path-observation
                       :name "lan" :address "10.0.0.9" :port 51820))))
         (dataplane :telemetry)
         (starts 0))
    (setf (gethash "peer-a"
                   (cl-wireguard-overlay::wireguard-path-state-peers
                    (gr8s.agent::node-runtime-wireguard-path-state runtime)))
          peer)
    (flet ((start () (incf starts) dataplane)
           (poll (actual network)
             (declare (ignore network))
             (is (eq dataplane actual))
             (let ((samples (make-hash-table :test #'equal)))
               (setf (gethash "peer-a" samples)
                     (cl-wireguard-overlay::make-wireguard-path-telemetry
                      :rtt-microseconds 1700 :tcp-samples 1))
               samples)))
      (gr8s.agent::update-node-runtime-wireguard-path-telemetry
       runtime network :start #'start :poll #'poll)
      (gr8s.agent::update-node-runtime-wireguard-path-telemetry
       runtime network :start #'start :poll #'poll))
    (is (= 1 starts))
    (is (= 1700
           (cl-wireguard-overlay::wireguard-path-observation-passive-rtt-microseconds
            (first (cl-wireguard-overlay::wireguard-peer-path-state-observations peer)))))))

(test nat-observations-report-only-fresh-authenticated-wireguard-sessions
  (let* ((now 1700000200)
         (key-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (key-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (messages
           (gr8s.agent::wireguard-peer-observation-messages
            (list
             (gr8s.network::make-wireguard-peer-status
              :public-key key-a :endpoint-address "198.51.100.8" :endpoint-port 41000
              :latest-handshake-seconds (- now 30) :received-bytes 80)
             (gr8s.network::make-wireguard-peer-status
              :public-key key-b :endpoint-address "198.51.100.9" :endpoint-port 41001
              :latest-handshake-seconds (- now 500) :received-bytes 90))
            :now now :fresh-seconds 180)))
    (is (= 1 (length messages)))
    (let ((message (first messages)))
      (is (equalp key-a (slot-value message 'gr8s.node.v1::peer-public-key)))
      (is (string= "198.51.100.8" (slot-value message 'gr8s.node.v1::address)))
      (is (= 41000 (slot-value message 'gr8s.node.v1::port)))
      (is (= 80 (slot-value message 'gr8s.node.v1::received-bytes))))))

(test wireguard-status-projects-bounded-kernel-path-quality
  (let* ((now 1700000200)
         (key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (network (gr8s.foundation::json-object
                   "routes" (vector (gr8s.foundation::json-object
                                     "nodeID" "peer-a"
                                     "wireguardPublicKey" (ag-grpc:base64-encode key)))))
         (observation (cl-wireguard-overlay::make-wireguard-path-observation
                       :name "underlay" :address "198.51.100.8" :port 41000
                       :handshake-age-seconds 3 :trial-latency-milliseconds 20
                       :passive-active-flows 12))
         (peer (cl-wireguard-overlay::make-wireguard-peer-path-state
                :peer-id "peer-a" :selected '("underlay" "198.51.100.8" 41000)
                :observations (list observation)))
         (state (cl-wireguard-overlay::make-wireguard-path-state)))
    (setf (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state)) peer)
    (let ((message
            (first
             (gr8s.agent::wireguard-peer-observation-messages
              (list (gr8s.network::make-wireguard-peer-status
                     :public-key key :endpoint-address "198.51.100.8"
                     :endpoint-port 41000 :latest-handshake-seconds (- now 3)
                     :received-bytes 80))
              :network network :path-state state :now now))))
      (is-true (slot-value message 'gr8s.node.v1::healthy))
      (is (< 0 (slot-value message 'gr8s.node.v1::path-score) 10001))
      (is (= 12 (slot-value message 'gr8s.node.v1::active-flows))))))

(test service-steering-prefers-local-and-diversifies-a-bounded-set
  (let* ((network
           (gr8s.foundation::json-object
            "podCIDR" "10.88.0.0/24"
            "routes"
            (vector
             (gr8s.foundation::json-object "nodeID" "a" "nodeName" "a"
                                "podCIDR" "10.88.1.0/24" "region" "r" "zone" "z1"
                                "capacityScore" 4000 "linkCost" 1)
             (gr8s.foundation::json-object "nodeID" "b" "nodeName" "b"
                                "podCIDR" "10.88.2.0/24" "region" "r" "zone" "z2"
                                "capacityScore" 4000 "linkCost" 10)
             (gr8s.foundation::json-object "nodeID" "c" "nodeName" "c"
                                "podCIDR" "10.88.3.0/24" "region" "r" "zone" "z1"
                                "capacityScore" 8000 "linkCost" 1))))
         (runtime (gr8s.agent::%make-node-runtime
                   :network network :wireguard-path-state
                   (cl-wireguard-overlay::make-wireguard-path-state)))
         (ranked (gr8s.agent::steer-service-endpoints
                  runtime '(("10.88.1.2" 80) ("10.88.0.2" 80)
                            ("10.88.3.2" 80) ("10.88.2.2" 80))
                  :maximum 3)))
    (is (equal '("10.88.0.2" 80) (first ranked)))
    (is (equal '("10.88.2.2" 80) (second ranked)))
    (is (= 3 (length ranked)))))

(test sparse-service-steering-uses-gateway-path-health
  (let* ((route-a (gr8s.foundation::json-object
                   "nodeID" "a" "nodeName" "a" "podCIDR" "10.88.1.0/24"
                   "region" "r" "zone" "z1" "capacityScore" 4000 "linkCost" 1
                   "nextHop" (gr8s.foundation::json-object "nodeID" "gateway")))
         (route-b (gr8s.foundation::json-object
                   "nodeID" "b" "nodeName" "b" "podCIDR" "10.88.2.0/24"
                   "region" "r" "zone" "z2" "capacityScore" 4000 "linkCost" 10))
         (state (cl-wireguard-overlay::make-wireguard-path-state))
         (failed (cl-wireguard-overlay::make-wireguard-path-observation
                  :name "underlay" :address "192.0.2.20" :port 51820
                  :handshake-age-seconds 2 :consecutive-failures 2))
         (peer (cl-wireguard-overlay::make-wireguard-peer-path-state
                :peer-id "gateway" :selected '("underlay" "192.0.2.20" 51820)
                :observations (list failed)))
         (runtime (gr8s.agent::%make-node-runtime
                   :network (gr8s.foundation::json-object "routes" (vector route-a route-b))
                   :wireguard-path-state state)))
    (setf (gethash "gateway" (cl-wireguard-overlay::wireguard-path-state-peers state)) peer)
    (is (equal '("10.88.2.2" 80)
               (first (gr8s.agent::steer-service-endpoints
                       runtime '(("10.88.1.2" 80) ("10.88.2.2" 80))))))))

(test node-agent-has-an-explicit-package-boundary
  (let ((agent (find-package '#:gr8s.agent)))
    (is-true agent)
    (dolist (name '("NODE-RUNTIME"
                    "MAKE-NODE-RUNTIME"
                    "START-NODE-RUNTIME"
                    "STOP-NODE-RUNTIME"
                    "RECONCILE-NODE-SNAPSHOT"
                    "DISPATCH-NODE-OPERATION"
                    "START-NODE-PORT-FORWARD-OPERATION"))
      (multiple-value-bind (implementation status)
          (find-symbol name agent)
        (declare (ignore implementation))
        (is (eq :external status))))
    (is (not (eq :external
                 (nth-value 1 (find-symbol "FOR" agent)))))))

(test cached-network-reconciliation-does-not-reprogram-firewalld
  (let ((runtime (gr8s.agent::%make-node-runtime :manager t))
        (network (gr8s.agent::node-network-object (node-network-for-test)))
        (calls 0))
    (setf (gethash "underlayAddress" network) "192.0.2.1")
    (flet ((ensure (cidr &key interface port)
             (declare (ignore cidr interface port))
             (incf calls)
             t))
      (gr8s.agent::ensure-node-runtime-overlay-firewall runtime network :ensure #'ensure)
      (gr8s.agent::ensure-node-runtime-overlay-firewall runtime network :ensure #'ensure))
    (is (= 1 calls))))

(test overlay-backend-transition-replaces-firewalld-ownership
  (let* ((runtime (gr8s.agent::%make-node-runtime :manager t))
         (vxlan (gr8s.agent::node-network-object (node-network-for-test)))
         (wireguard (alexandria:copy-hash-table vxlan))
         (ensured nil)
         (removed nil))
    (setf (gethash "underlayAddress" vxlan) "192.0.2.1"
          (gethash "underlayAddress" wireguard) "192.0.2.1"
          (gethash "overlayBackend" wireguard) "wireguard"
          (gethash "wireguardListenPort" wireguard) 51820)
    (flet ((ensure (cidr &key interface port)
             (push (list cidr interface port) ensured)
             t)
           (withdraw (cidr &key interface port)
             (push (list cidr interface port) removed)
             t))
      (gr8s.agent::ensure-node-runtime-overlay-firewall
       runtime vxlan :ensure #'ensure :remove #'withdraw)
      (gr8s.agent::ensure-node-runtime-overlay-firewall
       runtime wireguard :ensure #'ensure :remove #'withdraw))
    (is (equal '(("10.88.8.0/24" "gr8s-wg" 51820)
                 ("10.88.8.0/24" "gr8s-vxlan" 4789))
               ensured))
    (is (equal '(("10.88.8.0/24" "gr8s-vxlan" 4789)) removed))))

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
           (gr8s.kubelet::make-managed-containerd
            :state-directory directory
            :executable "/opt/gr8s/containerd"
            :oci-runtime "/opt/gr8s/runc"
            :cni-bin-directory "/opt/gr8s/cni/"))
         (runtime (gr8s.runtime.containerd::make-containerd-runtime))
         (node-runtime (gr8s.agent::make-node-runtime directory runtime manager))
         (socket-path
           (gr8s.kubelet::managed-containerd-agent-cni-socket-path manager))
         (add-called nil))
    (unwind-protect
         (progn
           (gr8s.agent::call-with-agent-cni-server
            node-runtime
            (lambda ()
              (is (probe-file socket-path))
              (let ((response
                      (gr8s.network::call-agent-cni
                       socket-path
                       (agent-cni-request-for-test "ADD")
                       :timeout 1)))
                (is-true
                 (slot-value response 'gr8s.node.v1::success))))
            :operations
            (gr8s.network::make-cni-operations
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
           (first (gr8s.agent::make-node-runtime state runtime nil)))
      (is (eq first (gr8s.agent::start-node-runtime first)))
      (is (eq first (gr8s.agent::start-node-runtime first)))
      (let ((statuses
              (gr8s.agent::reconcile-node-snapshot
               first (desired-snapshot-for-test pod))))
        (is (= 1 (length statuses)))
        (is (string= "Running"
                     (slot-value (first statuses)
                                 'gr8s.node.v1::phase))))
      (is (= 1 (fake-runtime-ensure-count runtime)))
      (gr8s.agent::reconcile-node-snapshot first (desired-snapshot-for-test pod))
      (is (= 1 (fake-runtime-ensure-count runtime)))
      (is (null (gr8s.agent::stop-node-runtime first)))
      (is (null (gr8s.agent::stop-node-runtime first)))

      ;; A fresh agent runtime opens the durable assignment store and adopts
      ;; the runtime Pod already carrying this UID/resource version.
      (let ((second (gr8s.agent::make-node-runtime state runtime nil)))
        (gr8s.agent::start-node-runtime second)
        (gr8s.agent::reconcile-node-snapshot second (desired-snapshot-for-test pod))
        (is (= 1 (fake-runtime-ensure-count runtime)))
        (gr8s.agent::reconcile-node-snapshot second (desired-snapshot-for-test))
        (is (null (runtime-observe runtime (pod-uid pod))))
        (gr8s.agent::stop-node-runtime second)))))

(test control-plane-runtime-schedules-and-publishes-authoritative-snapshots
  (with-temporary-store (store path)
    (values path)
    (let* ((node (gr8s.model::make-node-record
                  :id "node-1" :name "worker-a" :pod-cidr "10.88.0.0/24"))
           (server (gr8s.apiserver::%make-node-grpc-server :store store))
           (runtime (gr8s.controllers::make-control-plane-runtime store server))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (gr8s.controllers::register-node store node)
      (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time))

      (let ((observed (runtime-ensure runtime pod)))
        (is (string= "worker-a" (gr8s.model::pod-node-name pod)))
        (is (string= "Pending" (runtime-pod-phase observed)))
        (let* ((snapshot (gr8s.apiserver::current-node-snapshot server "worker-a"))
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
                       (gr8s.model::pod-node-name
                        (gr8s.kubelet::assignment-pod assignment))))))

      (runtime-delete runtime (pod-uid pod))
      (is (null (slot-value
                 (gr8s.apiserver::current-node-snapshot server "worker-a")
                 'gr8s.node.v1::pods))))))

(defun fake-spdy-read-frame (stream)
  "Read one frame a client sent: (:syn id type), (:data id fin octets), or NIL at the end."
  (let ((head (gr8s.protocol::spdy-read-octets stream 8)))
    (when head
      (let* ((size (logand (gr8s.protocol::spdy-read-u32 head 4) #xFFFFFF))
             (payload (if (plusp size) (gr8s.protocol::spdy-read-octets stream size) (make-array 0 :element-type '(unsigned-byte 8)))))
        (if (logbitp 7 (aref head 0))
            (let* ((text (map 'string #'code-char payload))
                   (position (+ (search "streamtype" text) (length "streamtype") 4)))
              ;; Five octets of sync flush follow the value.
              (list :syn (gr8s.protocol::spdy-read-u32 payload 0) (subseq text position (- (length text) 5))))
            (list :data (gr8s.protocol::spdy-read-u32 head 0) (logbitp 0 (aref head 4)) payload))))))

(defun fake-spdy-accept (stream count)
  "Answer the upgrade on STREAM and return an alist of channel name to stream ID for COUNT streams."
  (gr8s.protocol::read-http-response-head stream)
  (write-sequence
   (gr8s.protocol::ascii-octets
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
        (session (gr8s.protocol::make-spdy-session stream)))
    (gr8s.protocol::spdy-write-data session id data :fin fin)))

(test interactive-node-exec-bridges-runtime-spdy-streams
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (node-runtime
             (gr8s.agent::make-node-runtime
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
                                                :octets (gr8s.apiserver::exec-exit-status-bytes 7) :fin t)
                                (setf stream-ids streams)
                                ;; Wait for the client to go away, as the real server's handler returns first.
                                (ignore-errors (loop while (fake-spdy-read-frame stream)))))
                         (ignore-errors (usocket:socket-close socket))))
                   (error (condition)
                     (setf upstream-error condition))))
               :name "gr8s fake interactive runtime stream"))
        (gr8s.runtime::set-fake-runtime-exec-url
         runtime (format nil "http://127.0.0.1:~D/exec/token" port))
        (unwind-protect
             (progn
               (gr8s.agent::start-node-runtime node-runtime)
               (gr8s.agent::reconcile-node-snapshot
                node-runtime (desired-snapshot-for-test pod))
               (gr8s.agent::dispatch-node-operation
                node-runtime :operation-request request #'emit)
               (is-true
                (wait-until
                 (lambda ()
                   (emitted-status-p
                    gr8s.node.v1::+operationstatus-operation_status_accepted+))
                 :timeout 3))
               (gr8s.agent::dispatch-node-operation
                node-runtime :operation-input
                (make-instance
                 'gr8s.node.v1::operation-input
                 :operation-id "interactive-agent-1" :sequence 1
                 :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                 :data (trivial-utf-8:string-to-utf-8-bytes "echo hi\n"))
                #'emit)
               (gr8s.agent::dispatch-node-operation
                node-runtime :operation-input
                (make-instance
                 'gr8s.node.v1::operation-input
                 :operation-id "interactive-agent-1" :sequence 2
                 :channel
                 gr8s.node.v1::+streamchannel-stream_channel_terminal_resize+
                 :rows 24 :columns 80)
                #'emit)
               (gr8s.agent::dispatch-node-operation
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
          (gr8s.agent::stop-node-runtime node-runtime)
          (ignore-errors (usocket:socket-close listener)))))))

(test node-attach-streams-the-container-without-stdin-or-a-command
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (node-runtime (gr8s.agent::make-node-runtime (merge-pathnames "attach-agent/" path) runtime nil))
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
                                           :octets (gr8s.apiserver::exec-exit-status-bytes 0) :fin t)
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
        (gr8s.runtime::set-fake-runtime-exec-url
         runtime (format nil "http://127.0.0.1:~D/attach/token" (usocket:get-local-port listener)))
        (unwind-protect
             (progn
               (gr8s.agent::start-node-runtime node-runtime)
               (gr8s.agent::reconcile-node-snapshot node-runtime (desired-snapshot-for-test pod))
               (gr8s.agent::dispatch-node-operation node-runtime :operation-request request #'emit)
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
          (gr8s.agent::stop-node-runtime node-runtime)
          (ignore-errors (usocket:socket-close listener)))))))

(test node-exec-output-waits-for-a-control-plane-that-acknowledges-it
  (flet ((operation (acknowledges)
           (gr8s.agent::make-node-exec-operation
            nil (make-instance 'gr8s.node.v1::operation-request :operation-id "window" :acknowledges-output acknowledges)
            nil nil nil))
         (acknowledge (operation sequence count)
           (gr8s.agent::write-node-exec-input
            operation (make-instance 'gr8s.node.v1::operation-input
                                     :operation-id "window" :sequence sequence
                                     :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                                     :data (make-array 0 :element-type '(unsigned-byte 8))
                                     :acknowledged-bytes count))))
    ;; An older control plane never acknowledges, so its node sends as before.
    (let ((legacy (operation nil)))
      (setf (gr8s.agent::node-exec-operation-unacknowledged-output legacy) (* 10 gr8s.runtime::+exec-output-window-bytes+))
      (is-true (gr8s.agent::wait-for-node-exec-output-window legacy 100)))
    (let* ((windowed (operation t)) (sent nil)
           (sender (progn
                     (setf (gr8s.agent::node-exec-operation-unacknowledged-output windowed) gr8s.runtime::+exec-output-window-bytes+)
                     (bt:make-thread (lambda () (setf sent (gr8s.agent::wait-for-node-exec-output-window windowed 100)))
                                     :name "gr8s exec window test sender"))))
      ;; A full window holds the output back until the client has taken some.
      (is (not (wait-until (lambda () sent) :timeout 0.5)))
      (acknowledge windowed 1 4096)
      (is-true (wait-until (lambda () sent) :timeout 5))
      (bt:join-thread sender)
      (is (= (+ (- gr8s.runtime::+exec-output-window-bytes+ 4096) 100)
             (gr8s.agent::node-exec-operation-unacknowledged-output windowed)))
      ;; A finished operation stops waiting.
      (setf (gr8s.agent::node-exec-operation-unacknowledged-output windowed) gr8s.runtime::+exec-output-window-bytes+
            (gr8s.agent::node-exec-operation-finished-p windowed) t)
      (is (null (gr8s.agent::wait-for-node-exec-output-window windowed 100))))))

(test replayed-node-exec-input-is-idempotent
  ;; A peer RPC can deliver an input frame and lose only its reply. Retrying the
  ;; same sequence must not apply its data or output acknowledgement twice.
  (let* ((operation
           (gr8s.agent::make-node-exec-operation
            nil (make-instance 'gr8s.node.v1::operation-request
                               :operation-id "replayed-input"
                               :acknowledges-output t)
            nil nil nil))
         (input
           (make-instance 'gr8s.node.v1::operation-input
                          :operation-id "replayed-input" :sequence 1
                          :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                          :data (make-array 0 :element-type '(unsigned-byte 8))
                          :acknowledged-bytes 1024)))
    (setf (gr8s.agent::node-exec-operation-unacknowledged-output operation) 2048)
    (gr8s.agent::write-node-exec-input operation input)
    (gr8s.agent::write-node-exec-input operation input)
    (is (= 1 (gr8s.agent::node-exec-operation-last-input-sequence operation)))
    (is (= 1024 (gr8s.agent::node-exec-operation-unacknowledged-output operation)))))

(test node-exec-status-reads-the-exit-code-of-a-status-frame
  (flet ((frame (text) (trivial-utf-8:string-to-utf-8-bytes text)))
    (is (= 0 (gr8s.agent::node-exec-status-exit-code (gr8s.apiserver::exec-exit-status-bytes 0))))
    (is (= 7 (gr8s.agent::node-exec-status-exit-code (gr8s.apiserver::exec-exit-status-bytes 7))))
    (is (= 0 (gr8s.agent::node-exec-status-exit-code (frame "{\"status\":\"Success\"}"))))
    (is (= 1 (gr8s.agent::node-exec-status-exit-code (frame "{\"status\":\"Failure\"}"))))))

(test ending-agent-session-abandons-its-interactive-exec-operations
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (node-runtime
             (gr8s.agent::make-node-runtime
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
      (gr8s.runtime::set-fake-runtime-exec-url
       runtime (format nil "http://127.0.0.1:~D/exec/token" port))
      (unwind-protect
           (progn
             (gr8s.agent::start-node-runtime node-runtime)
             (gr8s.agent::reconcile-node-snapshot
              node-runtime (desired-snapshot-for-test pod))
             (gr8s.agent::dispatch-node-operation
              node-runtime :operation-request request
              (lambda (variant payload)
                (push (cons variant payload) emitted)))
             (is-true
              (wait-until (lambda () upstream-connected-p) :timeout 3))
             (is-true
              (gr8s.agent::find-node-exec-operation
               node-runtime "abandoned-agent-exec"))
             (gr8s.agent::dispatch-node-operation
              node-runtime :session-closed nil nil)
             (is-true
              (wait-until (lambda () upstream-closed-p) :timeout 3))
             (is-false
              (gr8s.agent::find-node-exec-operation
               node-runtime "abandoned-agent-exec"))
             ;; The session is gone, so cleanup must not emit a terminal reply
             ;; through the stale gRPC callback.
             (is (= 1 (length emitted)))
             (is (= gr8s.node.v1::+operationstatus-operation_status_accepted+
                    (slot-value (cdar emitted) 'gr8s.node.v1::status)))
             (bt:join-thread upstream-thread)
             (setf upstream-thread nil)
             (is (null upstream-error) "~A" upstream-error))
        (gr8s.agent::stop-node-runtime node-runtime)
        (ignore-errors (usocket:socket-close listener))
        (when upstream-thread
          (ignore-errors (bt:join-thread upstream-thread)))))))

(defun node-network-for-test (&optional (cidr "10.88.8.0/24"))
  (make-instance 'gr8s.node.v1::node-network-config
                 :cluster-pod-cidr "10.88.0.0/16" :node-pod-cidr cidr
                 :dns-address "169.254.1.1" :mtu 1450 :vni 42))

(defun dual-node-network-for-test ()
  (make-instance 'gr8s.node.v1::node-network-config
                 :cluster-pod-cidr "10.88.0.0/16"
                 :node-pod-cidr "10.88.8.0/24"
                 :cluster-pod-cidrs '("10.88.0.0/16" "fd88::/48")
                 :node-pod-cidrs '("10.88.8.0/24" "fd88:0:0:8::/64")
                 :dns-address "169.254.1.1" :mtu 1450 :vni 42))

(test assigned-wireguard-endpoint-candidates-reach-the-agent-network-model
  (let* ((endpoint (make-instance 'gr8s.node.v1::wireguard-endpoint
                                  :name "private" :address "10.0.0.2"
                                  :port 51820))
         (route (make-instance
                 'gr8s.node.v1::node-route
                 :node-id "peer" :pod-cidr "10.88.9.0/24"
                 :underlay-address "192.0.2.2"
                 :wireguard-public-key
                 (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 7)
                 :wireguard-listen-port 51820
                 :wireguard-endpoints (list endpoint)
                 :next-hop
                 (make-instance
                  'gr8s.node.v1::wireguard-next-hop
                  :node-id "gateway" :node-name "gateway-a"
                  :underlay-address "192.0.2.3"
                  :wireguard-public-key
                  (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 8)
                  :wireguard-listen-port 51821
                  :wireguard-endpoints (list endpoint))))
         (network-message (node-network-for-test))
         (network nil))
    (setf (slot-value network-message 'gr8s.node.v1::underlay-address) "192.0.2.1"
          (slot-value network-message 'gr8s.node.v1::overlay-backend) "wireguard"
          (slot-value network-message 'gr8s.node.v1::wireguard-listen-port) 51820
          network (gr8s.agent::node-network-object network-message (list route)))
    (gr8s.agent::validate-node-network-object network)
    (let* ((route (aref (gethash "routes" network) 0))
           (candidate (aref (gethash "wireguardEndpoints" route) 0))
           (hop (gethash "nextHop" route)))
      (is (string= "private" (gethash "name" candidate)))
      (is (string= "10.0.0.2" (gethash "address" candidate)))
      (is (= 51820 (gethash "port" candidate)))
      (is (string= "gateway-a" (gethash "nodeName" hop)))
      (is (string= "192.0.2.3" (gethash "underlayAddress" hop)))
      (is (= 51821 (gethash "wireguardListenPort" hop)))
      (setf (gethash "wireguardPublicKey" hop) "not-a-key")
      (signals gr8s.network::cni-error
        (gr8s.agent::validate-node-network-object network)))))

(test assigned-network-and-ipam-restore-before-agent-reconciliation
  (with-temporary-store (store path)
    (assert store)
    (let* ((state (merge-pathnames "network-agent/" path))
           (runtime (gr8s.agent::make-node-runtime state (make-fake-runtime) nil))
           (network (gr8s.agent::node-network-object (node-network-for-test))))
      (gr8s.agent::configure-node-runtime-network runtime network)
      (is (string= "10.88.8.1"
                   (gr8s.network::allocate-pod-address
                    (gr8s.agent::node-runtime-ipam runtime) "sandbox-a" "eth0")))
      (let ((restored (gr8s.agent::make-node-runtime state (make-fake-runtime) nil)))
        (is-true (gr8s.agent::node-runtime-cni-operations restored))
        (is (string= "10.88.8.1"
                     (gr8s.network::check-pod-address
                      (gr8s.agent::node-runtime-ipam restored) "sandbox-a" "eth0")))
        (signals gr8s.network::cni-error
          (gr8s.agent::configure-node-runtime-network
           restored (gr8s.agent::node-network-object
                     (node-network-for-test "10.88.9.0/24")))))
      (is (= #o600 (logand #o777 (sb-posix:stat-mode
                                 (sb-posix:stat
                                  (gr8s.agent::node-runtime-network-path runtime)))))))))

(test dual-node-network-opens-and-restores-dual-family-ipam
  (with-temporary-store (store path)
    (assert store)
    (let* ((state (merge-pathnames "dual-network-agent/" path))
           (runtime (gr8s.agent::make-node-runtime state (make-fake-runtime) nil))
           (network (gr8s.agent::node-network-object (dual-node-network-for-test))))
      (is (equal '("10.88.0.0/16" "fd88::/48")
                 (coerce (gethash "clusterPodCIDRs" network) 'list)))
      (is (equal '("10.88.8.0/24" "fd88:0:0:8::/64")
                 (coerce (gethash "nodePodCIDRs" network) 'list)))
      (gr8s.agent::configure-node-runtime-network runtime network)
      (is (equal '("10.88.8.1" "fd88:0:0:8::1")
                 (gr8s.network::allocate-pod-addresses
                  (gr8s.agent::node-runtime-ipam runtime) "sandbox-a" "eth0")))
      (let ((restored (gr8s.agent::make-node-runtime state (make-fake-runtime) nil)))
        (is (equal '("10.88.8.1" "fd88:0:0:8::1")
                   (gr8s.network::check-pod-addresses
                    (gr8s.agent::node-runtime-ipam restored) "sandbox-a" "eth0")))))))

(test managed-agent-refuses-cni-before-network-assignment
  (with-temporary-store (store path)
    (assert store)
    (let* ((runtime (gr8s.agent::make-node-runtime path (make-fake-runtime) nil))
           (response (gr8s.agent::handle-node-runtime-cni
                      runtime (agent-cni-request-for-test "ADD"))))
      (is-false (slot-value response 'gr8s.node.v1::success))
      (is (search "assignment is not ready"
                  (slot-value response 'gr8s.node.v1::error-message))))))

(test external-cni-chaining-does-not-wait-for-native-network-assignment
  (with-temporary-store (store path)
    (assert store)
    (let* ((manager
             (gr8s.kubelet::make-managed-containerd
              :state-directory path :executable "/opt/containerd" :oci-runtime "/opt/runc"
              :cni-bin-directory "/opt/cni/bin" :cni-mode "external"
              :cni-config-directory "/etc/cni/net.d"))
           (runtime (gr8s.agent::make-node-runtime path (make-fake-runtime) manager))
           (seen nil)
           (operations
             (gr8s.network::make-cni-operations
              :add (lambda (configuration context map-path link-path)
                     (declare (ignore context map-path link-path))
                     (setf seen (gr8s.network::cni-configuration-endpoint-address configuration)))))
           (config
             (com.inuoe.jzon:stringify
              (gr8s.foundation::json-object
               "cniVersion" "1.0.0" "mapPinRoot" "/run/gr8s/bpf"
               "prevResult"
               (gr8s.foundation::json-object "cniVersion" "1.0.0"
                                  "ips" (vector (gr8s.foundation::json-object "address" "10.244.1.9/24"))))))
           (response
             (gr8s.agent::handle-node-runtime-cni
              runtime (agent-cni-request-for-test "ADD" config)
              :chained-operations (gr8s.network::make-chained-cni-operations :policy operations))))
      (is-true (slot-value response 'gr8s.node.v1::success))
      (is (string= "10.244.1.9" seen)))))

(test external-cni-endpoints-survive-agent-restart-and-delete
  (with-temporary-store (store path)
    (assert store)
    (let* ((manager
             (gr8s.kubelet::make-managed-containerd
              :state-directory path :executable "/opt/containerd" :oci-runtime "/opt/runc"
              :cni-bin-directory "/opt/cni/bin" :cni-mode "external"
              :cni-config-directory "/etc/cni/net.d"))
           (runtime (gr8s.agent::make-node-runtime path (make-fake-runtime) manager))
           (operations
             (gr8s.network::make-cni-operations
              :add (lambda (&rest arguments) (declare (ignore arguments)))
              :delete (lambda (&rest arguments) (declare (ignore arguments)))))
           (chained (gr8s.network::make-chained-cni-operations :policy operations))
           (config
             (com.inuoe.jzon:stringify
              (gr8s.foundation::json-object
               "cniVersion" "1.0.0" "mapPinRoot" "/run/gr8s/bpf"
               "prevResult"
               (gr8s.foundation::json-object "cniVersion" "1.0.0"
                                  "ips" (vector (gr8s.foundation::json-object "address" "10.244.1.9/24")))))))
      (is-true (slot-value
                (gr8s.agent::handle-node-runtime-cni
                 runtime (agent-cni-request-for-test "ADD" config)
                 :chained-operations chained)
                'gr8s.node.v1::success))
      (is (equal '(("sandbox-agent" "eth0" "10.244.1.9"))
                 (gr8s.agent::node-runtime-external-cni-endpoint-list runtime)))
      (let ((seen nil))
        (gr8s.agent::converge-node-network-policies-unlocked
         runtime :policy-converger
         (lambda (specs endpoints &rest arguments)
           (declare (ignore specs arguments))
           (setf seen endpoints)))
        (is (equal '(("sandbox-agent" "eth0" "10.244.1.9")) seen)))
      (let ((restored (gr8s.agent::make-node-runtime path (make-fake-runtime) manager)))
        (is (equal '(("sandbox-agent" "eth0" "10.244.1.9"))
                   (gr8s.agent::node-runtime-external-cni-endpoint-list restored)))
        (is-true (slot-value
                  (gr8s.agent::handle-node-runtime-cni
                   restored (agent-cni-request-for-test "DEL" config)
                   :chained-operations chained)
                  'gr8s.node.v1::success))
        (is-false (gr8s.agent::node-runtime-external-cni-endpoint-list restored))))))

(test external-cni-mode-does-not-apply-the-native-overlay-or-ipam
  (with-temporary-store (store path)
    (assert store)
    (let* ((manager
             (gr8s.kubelet::make-managed-containerd
              :state-directory path :executable "/opt/containerd" :oci-runtime "/opt/runc"
              :cni-bin-directory "/opt/cni/bin" :cni-mode "external"
              :cni-config-directory "/etc/cni/net.d"))
           (native-reconciliations 0)
           (runtime
             (gr8s.agent::make-node-runtime
              path (make-fake-runtime) manager
              :network-reconciler
              (lambda (network previous)
                (declare (ignore network previous))
                (incf native-reconciliations))))
           (snapshot
             (make-instance 'gr8s.node.v1::desired-state-snapshot
                            :revision 1 :network (node-network-for-test))))
      (gr8s.agent::apply-node-runtime-network runtime snapshot)
      (is (= 0 native-reconciliations))
      (is-false (gr8s.agent::node-runtime-ipam runtime))
      (is-false (gr8s.agent::node-runtime-cni-operations runtime)))))

(test external-cni-mode-owns-only-the-node-local-dns-gateway
  (with-temporary-store (store path)
    (assert store)
    (let* ((manager
             (gr8s.kubelet::make-managed-containerd
              :state-directory path :executable "/opt/containerd" :oci-runtime "/opt/runc"
              :cni-bin-directory "/opt/cni/bin" :cni-mode "external"
              :cni-config-directory "/etc/cni/net.d"))
           (runtime (gr8s.agent::make-node-runtime path (make-fake-runtime) manager))
           (events nil))
      (signals error
        (gr8s.agent::call-with-external-cni-dns-gateway
         runtime
         (lambda ()
           (push :body events)
           (error "injected agent failure"))
         :ensure (lambda () (push :ensure events))
         :remove (lambda () (push :remove events))))
      (is (equal '(:ensure :body :remove) (nreverse events))))))

(test node-network-rejects-invalid-subnets-before-persistence
  (with-temporary-store (store path)
    (assert store)
    (let ((runtime (gr8s.agent::make-node-runtime path (make-fake-runtime) nil)))
      (dolist (cidr '("192.0.2.0/24" "10.88.1.1/24" "10.88.0.0/31"))
        (signals gr8s.network::cni-error
          (gr8s.agent::configure-node-runtime-network
           runtime (gr8s.agent::node-network-object (node-network-for-test cidr)))))
      (is-false (probe-file (gr8s.agent::node-runtime-network-path runtime))))))

(defun node-network-with-routes-for-test (routes)
  (let ((network (gr8s.agent::node-network-object (node-network-for-test))))
    (setf (gethash "underlayAddress" network) "192.0.2.1"
          (gethash "routes" network)
          (coerce (loop for (id cidr address) in routes
                        collect (gr8s.foundation::json-object "nodeID" id "podCIDR" cidr
                                                   "underlayAddress" address)) 'vector))
    network))

(test dual-stack-peer-routes-survive-the-agent-network-boundary
  (let* ((route (make-instance 'gr8s.node.v1::node-route
                               :node-id "peer"
                               :pod-cidr "10.88.9.0/24"
                               :pod-cidrs '("10.88.9.0/24" "fd88:0:0:9::/64")
                               :underlay-address "192.0.2.2"))
         (network (gr8s.agent::node-network-object (dual-node-network-for-test)
                                             (list route)))
         (persisted-route (aref (gethash "routes" network) 0)))
    (setf (gethash "underlayAddress" network) "192.0.2.1")
    (is (equal '("10.88.9.0/24" "fd88:0:0:9::/64")
               (coerce (gethash "podCIDRs" persisted-route) 'list)))
    (is (equal '(("10.88.9.0/24" . "192.0.2.2")
                 ("fd88:0:0:9::/64" . "192.0.2.2"))
               (gr8s.network::node-vxlan-route-pairs network)))
    (is (eq network (gr8s.agent::validate-node-network-object network)))
    (setf (gethash "podCIDRs" persisted-route)
          (vector "10.88.9.0/24" "fd88::/32"))
    (signals gr8s.network::cni-error (gr8s.agent::validate-node-network-object network))))

(test partial-node-network-update-is-replayed-from-the-durable-journal
  (with-temporary-store (store path)
    (assert store)
    (let* ((state (merge-pathnames "journal-agent/" path))
           (fail-p nil)
           (attempts nil)
           (reconciler (lambda (network previous)
                         (push (cons network previous) attempts)
                         (when fail-p (error "injected partial FDB update failure"))))
           (runtime (gr8s.agent::make-node-runtime state (make-fake-runtime) nil
                                             :network-reconciler reconciler))
           (old (node-network-with-routes-for-test
                 '(("node-a" "10.88.9.0/24" "192.0.2.2"))))
           (new (node-network-with-routes-for-test
                 '(("node-a" "10.88.9.0/24" "192.0.2.3")
                   ("node-b" "10.88.10.0/24" "192.0.2.4")))))
      (gr8s.agent::configure-node-runtime-network runtime old)
      (gr8s.network::allocate-pod-address (gr8s.agent::node-runtime-ipam runtime) "existing-pod" "eth0")
      (setf fail-p t)
      (signals error (gr8s.agent::configure-node-runtime-network runtime new))
      (is (eq old (gr8s.agent::node-runtime-network runtime)))
      (is (equalp old (com.inuoe.jzon:parse (gr8s.agent::node-runtime-network-path runtime))))
      (is (equalp new (com.inuoe.jzon:parse (gr8s.agent::node-runtime-network-pending-path runtime))))
      (setf fail-p nil attempts nil)
      (let* ((restarted (gr8s.agent::make-node-runtime state (make-fake-runtime) nil
                                               :network-reconciler reconciler))
             (previous (cdr (first attempts)))
             (old-routes (mapcan #'gr8s.network::node-vxlan-route-pairs previous)))
        ;; Both the old kernel entries and partially installed new entries are
        ;; available to cleanup on restart, while Pod addresses remain stable.
        (is (member '("10.88.9.0/24" . "192.0.2.2") old-routes :test #'equal))
        (is (member '("10.88.9.0/24" . "192.0.2.3") old-routes :test #'equal))
        (is (equalp new (gr8s.agent::node-runtime-network restarted)))
        (is-false (probe-file (gr8s.agent::node-runtime-network-pending-path restarted)))
        (is (string= "10.88.8.1"
                     (gr8s.network::check-pod-address
                      (gr8s.agent::node-runtime-ipam restarted) "existing-pod" "eth0")))))))

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
    (signals gr8s.network::cni-error
      (gr8s.agent::validate-node-network-object (node-network-with-routes-for-test routes)))))

(test node-runtime-repairs-cached-topology-without-pods-or-a-control-connection
  (with-temporary-store (store path)
    (assert store)
    (let* ((state (merge-pathnames "offline-network/" path))
           (lock (bt:make-lock "simulated kernel topology"))
           (installed nil)
           (runtime
             (gr8s.agent::make-node-runtime
              state (make-fake-runtime) nil
              :network-reconciler
              (lambda (network previous)
                (declare (ignore previous))
                (bt:with-lock-held (lock) (setf installed network)))))
           (network (node-network-with-routes-for-test
                     '(("peer" "10.88.9.0/24" "192.0.2.2")))))
      (gr8s.agent::configure-node-runtime-network runtime network)
      (let ((journal (uiop:read-file-string (gr8s.agent::node-runtime-network-path runtime))))
        ;; Simulate loss of the tunnel FDB without changing desired state.
        (bt:with-lock-held (lock) (setf installed nil))
        (unwind-protect
             (progn
               (gr8s.agent::start-node-runtime runtime)
               (is-true (wait-until (lambda () (bt:with-lock-held (lock) installed))))
               (is (string= journal (uiop:read-file-string (gr8s.agent::node-runtime-network-path runtime)))))
          (gr8s.agent::stop-node-runtime runtime))))))

(test withdrawn-assignment-persists-deletion-intent-before-runtime-removal
  (with-temporary-store (store path)
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (runtime (make-fake-runtime))
           (node (gr8s.agent::make-node-runtime (merge-pathnames "withdrawn/" path) runtime nil)))
      (gr8s.agent::put-assigned-pod (gr8s.agent::node-runtime-store node) pod)
      (gr8s.kubelet::reconcile-pod (gr8s.agent::node-runtime-reconciler node) "default" (pod-name pod))
      (set-fake-runtime-failure runtime "transient sandbox deletion failure")
      (signals gr8s.runtime::runtime-error (gr8s.agent::remove-unassigned-pods node nil))
      (is-true (gr8s.kubelet::deletion-requested-p
                (get-pod (gr8s.agent::node-runtime-store node) "default" (pod-name pod))))
      ;; Reopening the local desired store still converges deletion, not create.
      (let ((restored (gr8s.agent::make-node-runtime (merge-pathnames "withdrawn/" path) runtime nil)))
        (gr8s.kubelet::reconcile-pod (gr8s.agent::node-runtime-reconciler restored) "default" (pod-name pod))
        (signals gr8s.model::kubernetes-error
          (get-pod (gr8s.agent::node-runtime-store restored) "default" (pod-name pod))))
      (is (= 1 (fake-runtime-ensure-count runtime))))))

(test namespaced-pods-survive-control-plane-and-agent-snapshots
  (with-temporary-store (store directory)
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*))
           (fake (make-fake-runtime))
           (agent (gr8s.agent::make-node-runtime (merge-pathnames "agent/" directory) fake nil)))
      (gr8s.agent::start-node-runtime agent)
      (setf (gethash "namespace" (gethash "metadata" object)) "sonobuoy")
      (let ((pod (create-pod store (parse-pod object))))
        (gr8s.controllers::persist-pod-assignment store pod "worker-a")
        (let ((snapshot (gr8s.controllers::node-desired-state-snapshot store "worker-a")))
          (is (= 1 (length (slot-value snapshot 'gr8s.node.v1::pods))))
          (gr8s.agent::reconcile-node-snapshot agent snapshot)
          (is (= 1 (length (list-pods (gr8s.agent::node-runtime-store agent)))))
          (is (string= "sonobuoy" (pod-namespace
                                  (get-pod (gr8s.agent::node-runtime-store agent) "sonobuoy" "hello"))))
          (gr8s.kubelet::reconcile-all (gr8s.agent::node-runtime-reconciler agent))
          (is (= 1 (fake-runtime-ensure-count fake)))
          (gr8s.agent::reconcile-node-snapshot agent (desired-snapshot-for-test))
          (is (null (list-pods (gr8s.agent::node-runtime-store agent))))
          (gr8s.agent::stop-node-runtime agent))))))

(test spdy-header-blocks-announce-the-dictionary-once-and-store-their-names
  (let* ((session (gr8s.protocol::make-spdy-session nil))
         (first (gr8s.protocol::spdy-header-block session '(("streamtype" . "error"))))
         (second (gr8s.protocol::spdy-header-block session '(("streamtype" . "stdin")))))
    (is (equalp #(#x78 #xF9 #xE3 #xC6 #xA7 #xC2) (subseq first 0 6)))
    (is (= 0 (aref first 6)))
    (let ((size (+ (aref first 7) (* 256 (aref first 8)))))
      (is (= size (- (length first) 16)))
      (is (equalp #(0 0 0 #xFF #xFF) (subseq first (- (length first) 5))))
      (is (= (logxor size #xFFFF) (+ (aref first 9) (* 256 (aref first 10))))))
    ;; The stream continues, so only the first block has a zlib header.
    (is (= 0 (aref second 0)))
    (is (search "stdin" (map 'string #'code-char second)))))

(test agent-heartbeat-reports-memory-pressure-from-the-eviction-signal
  "The heartbeat's memory-pressure flag follows the same available-memory signal
the reconciler evicts on, so the control plane can raise MemoryPressure."
  (let ((gr8s.kubelet::*node-memory-available-fn*
          (lambda () (1- gr8s.kubelet::+memory-eviction-threshold-bytes+))))
    (is-true (gr8s.agent::agent-node-memory-pressure-p))
    (is-true (slot-value (gr8s.agent::agent-heartbeat nil)
                         'gr8s.node.v1::memory-pressure)))
  (let ((gr8s.kubelet::*node-memory-available-fn*
          (lambda () (* 10 gr8s.kubelet::+memory-eviction-threshold-bytes+))))
    (is-false (gr8s.agent::agent-node-memory-pressure-p))
    (is-false (slot-value (gr8s.agent::agent-heartbeat nil)
                          'gr8s.node.v1::memory-pressure))))

(test agent-heartbeat-reports-disk-and-pid-pressure
  "Disk pressure follows free bytes or free inodes; PID pressure follows the
process count against the kernel ceiling; and the heartbeat carries all three."
  (let ((gr8s.kubelet::*node-disk-available-fn*
          (lambda () (values (1- gr8s.kubelet::+disk-eviction-threshold-bytes+) 1000000))))
    (is-true (gr8s.agent::agent-node-disk-pressure-p)))
  (let ((gr8s.kubelet::*node-disk-available-fn*
          (lambda () (values (* 100 gr8s.kubelet::+disk-eviction-threshold-bytes+)
                             (1- gr8s.kubelet::+disk-eviction-threshold-inodes+)))))
    (is-true (gr8s.agent::agent-node-disk-pressure-p)))
  (let ((gr8s.kubelet::*node-disk-available-fn*
          (lambda () (values (* 100 gr8s.kubelet::+disk-eviction-threshold-bytes+) 1000000))))
    (is-false (gr8s.agent::agent-node-disk-pressure-p)))
  (let ((gr8s.kubelet::*node-pid-usage-fn* (lambda () (values 95 100))))
    (is-true (gr8s.agent::agent-node-pid-pressure-p)))
  (let ((gr8s.kubelet::*node-pid-usage-fn* (lambda () (values 50 100))))
    (is-false (gr8s.agent::agent-node-pid-pressure-p)))
  (let ((gr8s.kubelet::*node-memory-available-fn* (lambda () 0))
        (gr8s.kubelet::*node-disk-available-fn* (lambda () (values 0 0)))
        (gr8s.kubelet::*node-pid-usage-fn* (lambda () (values 100 100))))
    (let ((heartbeat (gr8s.agent::agent-heartbeat nil)))
      (is-true (slot-value heartbeat 'gr8s.node.v1::memory-pressure))
      (is-true (slot-value heartbeat 'gr8s.node.v1::disk-pressure))
      (is-true (slot-value heartbeat 'gr8s.node.v1::pid-pressure)))))
