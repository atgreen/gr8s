(in-package #:gr8s/tests)

(in-suite gr8s)

(defun roundtrip-node-message (message type)
  (ag-proto:deserialize-from-bytes
   type (ag-proto:serialize-to-bytes message)))

(test node-protocol-version-is-explicit-and-rejected-when-unsupported
  (is (= 2 gr8s::+node-protocol-version+))
  (is (= 2 (gr8s::ensure-node-protocol-version 2)))
  (handler-case
      (progn
        (gr8s::ensure-node-protocol-version 1)
        (fail "version 1 must be rejected"))
    (gr8s::unsupported-node-protocol-version (condition)
      (is (= 1 (gr8s::unsupported-node-protocol-version-received condition)))
      (is (= 2 (gr8s::unsupported-node-protocol-version-supported condition))))))

(test enrollment-messages-roundtrip-node-identity-material
  (let* ((request
           (make-instance 'gr8s.node.v1::enroll-request
                          :protocol-version 2
                          :node-name "worker-a"
                          :join-token "secret"
                          :certificate-request #(1 2 3)))
         (restored
           (roundtrip-node-message request 'gr8s.node.v1::enroll-request)))
    (is (= 2 (slot-value restored 'gr8s.node.v1::protocol-version)))
    (is (string= "worker-a" (slot-value restored 'gr8s.node.v1::node-name)))
    (is (string= "secret" (slot-value restored 'gr8s.node.v1::join-token)))
    (is (equalp #(1 2 3)
                (slot-value restored 'gr8s.node.v1::certificate-request))))
  (let* ((response
           (make-instance 'gr8s.node.v1::enroll-response
                          :protocol-version 2
                          :node-id "node-1"
                          :node-certificate #(4 5)
                          :ca-certificate #(6 7)))
         (restored
           (roundtrip-node-message response 'gr8s.node.v1::enroll-response)))
    (is (string= "node-1" (slot-value restored 'gr8s.node.v1::node-id)))
    (is (equalp #(4 5)
                (slot-value restored 'gr8s.node.v1::node-certificate)))
    (is (equalp #(6 7)
                (slot-value restored 'gr8s.node.v1::ca-certificate)))))

(test every-agent-envelope-variant-roundtrips
  (dolist (spec '((:hello gr8s.node.v1::node-hello)
                  (:heartbeat gr8s.node.v1::heartbeat)
                  (:snapshot-ack gr8s.node.v1::snapshot-ack)
                  (:status gr8s.node.v1::node-status)
                  (:operation-response gr8s.node.v1::operation-response)
                  (:operation-stream gr8s.node.v1::operation-stream)
                  (:credential-token-request gr8s.node.v1::credential-token-request)))
    (destructuring-bind (variant payload-type) spec
      (let* ((payload (make-instance payload-type))
             (envelope
               (gr8s::make-agent-envelope variant payload :sequence 42))
             (restored
               (roundtrip-node-message
                envelope 'gr8s.node.v1::agent-envelope)))
        (is (= 2 (slot-value restored 'gr8s.node.v1::protocol-version)))
        (is (= 42 (slot-value restored 'gr8s.node.v1::proto-sequence)))
        (is (eq variant (slot-value restored 'gr8s.node.v1::payload-case)))
        (is (typep (slot-value restored
                               (find-symbol (symbol-name variant)
                                            :gr8s.node.v1))
                   payload-type))))))

(test every-server-envelope-variant-roundtrips
  (dolist (spec '((:hello gr8s.node.v1::server-hello)
                  (:desired-state gr8s.node.v1::desired-state-snapshot)
                  (:operation-request gr8s.node.v1::operation-request)
                  (:operation-input gr8s.node.v1::operation-input)
                  (:operation-cancel gr8s.node.v1::operation-cancel)
                  (:protocol-error gr8s.node.v1::protocol-error)
                  (:credential-token-response gr8s.node.v1::credential-token-response)))
    (destructuring-bind (variant payload-type) spec
      (let* ((payload (make-instance payload-type))
             (envelope
               (gr8s::make-server-envelope variant payload :sequence 77))
             (restored
               (roundtrip-node-message
                envelope 'gr8s.node.v1::server-envelope)))
        (is (= 2 (slot-value restored 'gr8s.node.v1::protocol-version)))
        (is (= 77 (slot-value restored 'gr8s.node.v1::proto-sequence)))
        (is (eq variant (slot-value restored 'gr8s.node.v1::payload-case)))
        (is (typep (slot-value restored
                               (find-symbol (symbol-name variant)
                                            :gr8s.node.v1))
                   payload-type))))))

(test generated-node-services-have-the-required-rpc-shapes
  (is (fboundp 'gr8s.node.v1::enrollment-service-enroll))
  (is (fboundp 'gr8s.node.v1::node-service-connect))
  (let ((server (ag-grpc:make-grpc-server 0)))
    (gr8s.node.v1::register-enrollment-service-service
     server :enroll-handler (lambda (request context)
                              (declare (ignore request context))))
    (gr8s.node.v1::register-node-service-service
     server :connect-handler (lambda (context stream)
                               (declare (ignore context stream))))
    (let ((enroll
            (ag-grpc::server-get-handler
             server "/gr8s.node.v1.EnrollmentService/Enroll"))
          (connect
            (ag-grpc::server-get-handler
             server "/gr8s.node.v1.NodeService/Connect")))
      (is (not (null enroll)))
      (is-false (ag-grpc::handler-client-streaming-p enroll))
      (is-false (ag-grpc::handler-server-streaming-p enroll))
      (is (not (null connect)))
      (is-true (ag-grpc::handler-client-streaming-p connect))
      (is-true (ag-grpc::handler-server-streaming-p connect)))))

(test node-underlay-and-peer-route-fields-survive-protobuf-roundtrips
  (let* ((public-key (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 17))
         (hello (make-instance 'gr8s.node.v1::node-hello
                               :node-name "worker-a" :underlay-address "192.0.2.10"
                               :wireguard-public-key public-key))
         (restored (roundtrip-node-message hello 'gr8s.node.v1::node-hello)))
    (is (string= "192.0.2.10" (slot-value restored 'gr8s.node.v1::underlay-address)))
    (is (equalp public-key
                (slot-value restored 'gr8s.node.v1::wireguard-public-key))))
  (let* ((peer-key (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 29))
         (snapshot
           (make-instance
            'gr8s.node.v1::desired-state-snapshot
            :network (make-instance 'gr8s.node.v1::node-network-config
                                     :node-pod-cidr "10.88.1.0/24"
                                     :underlay-address "192.0.2.10"
                                     :overlay-backend "wireguard"
                                     :wireguard-listen-port 51820)
            :routes (list (make-instance 'gr8s.node.v1::node-route
                                         :node-id "node-b" :pod-cidr "10.88.2.0/24"
                                         :underlay-address "192.0.2.11"
                                         :wireguard-public-key peer-key
                                         :wireguard-listen-port 51820))))
         (restored (roundtrip-node-message snapshot 'gr8s.node.v1::desired-state-snapshot)))
    (is (string= "192.0.2.10"
                 (slot-value (slot-value restored 'gr8s.node.v1::network)
                             'gr8s.node.v1::underlay-address)))
    (is (string= "10.88.2.0/24"
                 (slot-value (first (slot-value restored 'gr8s.node.v1::routes))
                             'gr8s.node.v1::pod-cidr)))
    (is (string= "wireguard"
                 (slot-value (slot-value restored 'gr8s.node.v1::network)
                             'gr8s.node.v1::overlay-backend)))
    (is (= 51820
           (slot-value (slot-value restored 'gr8s.node.v1::network)
                       'gr8s.node.v1::wireguard-listen-port)))
    (let ((route (first (slot-value restored 'gr8s.node.v1::routes))))
      (is (equalp peer-key
                  (slot-value route 'gr8s.node.v1::wireguard-public-key)))
      (is (= 51820
             (slot-value route 'gr8s.node.v1::wireguard-listen-port))))))
