(in-package #:gr8s/tests)

(in-suite gr8s)

(defun topology-node (name region zone)
  (gr8s.model::make-node-record
   :id name :name name :pod-cidr "10.88.0.0/24" :underlay-address "192.0.2.1"
   :labels (gr8s.resources::core-object "topology.kubernetes.io/region" region
                              "topology.kubernetes.io/zone" zone)))

(defun topology-overlay-nodes (nodes)
  "Project test node-records into the planner's overlay nodes, as production does."
  (mapcar #'gr8s.apiserver::node-record->overlay-node nodes))

(defun topology-fixture ()
  (loop for region in '("east" "west" "north")
        append (loop for zone in '("a" "b")
                     append (loop for index below 3
                                  collect (topology-node
                                           (format nil "~A-~A-~D" region zone index)
                                           region zone)))))

(test node-ready-stability-window-survives-restart-and-resets-after-expiry
  (with-temporary-store (store path)
    (let* ((now (get-universal-time))
           (node (gr8s.model::make-node-record :id "stable-id" :name "stable-node"
                                        :pod-cidr "10.88.1.0/24")))
      (gr8s.controllers::register-node store node)
      (gr8s.controllers::mark-node-ready store "stable-node" now :lease-duration 10)
      (is (= now (gr8s.model::node-record-ready-since
                  (gr8s.controllers::get-node store "stable-node"))))
      ;; Renewing a healthy lease does not restart the stability interval.
      (gr8s.controllers::mark-node-ready store "stable-node" (1+ now) :lease-duration 10)
      (is (= now (gr8s.model::node-record-ready-since
                  (gr8s.controllers::get-node store "stable-node"))))
      (let ((reopened (gr8s.store::open-store path)))
        (is (= now (gr8s.model::node-record-ready-since
                    (gr8s.controllers::get-node reopened "stable-node"))))
        (gr8s.controllers::expire-node-heartbeats reopened now :now (+ now 12))
        (is-false (gr8s.model::node-record-ready-since
                   (gr8s.controllers::get-node reopened "stable-node")))
        (gr8s.controllers::mark-node-ready reopened "stable-node" (+ now 13)
                              :lease-duration 10)
        (is (= (+ now 13)
               (gr8s.model::node-record-ready-since
                (gr8s.controllers::get-node reopened "stable-node"))))
        ;; A control plane that was down past the lease deadline must not reuse
        ;; the old stability epoch when the node returns.
        (gr8s.controllers::mark-node-ready reopened "stable-node" (- now 100)
                              :lease-duration 1)
        (let ((expired-reopen (gr8s.store::open-store path)))
          (is-false (gr8s.model::node-record-ready-p
                     (gr8s.controllers::get-node expired-reopen "stable-node")))
          (is-false (gr8s.model::node-record-ready-since
                     (gr8s.controllers::get-node expired-reopen "stable-node")))
          (gr8s.controllers::mark-node-ready expired-reopen "stable-node" now
                                :lease-duration 10)
          (is (= now (gr8s.model::node-record-ready-since
                      (gr8s.controllers::get-node expired-reopen "stable-node")))))))))

(test wireguard-topology-planner-keeps-small-clusters-direct
  (let* ((nodes (loop for index below 4
                      collect (topology-node (format nil "node-~D" index) "r" "z")))
         (plan (cl-wireguard-overlay::plan-wireguard-topology
                (topology-overlay-nodes nodes) :full-mesh-limit 8)))
    (is (eq :full-mesh (cl-wireguard-overlay::wireguard-topology-plan-mode plan)))
    (is-false (getf (cl-wireguard-overlay::wireguard-topology-plan-object plan)
                    :degraded-domains))
    (dolist (node nodes)
      (is (= 3 (length (cl-wireguard-overlay::wireguard-topology-neighbors
                        plan (gr8s.model::node-record-name node))))))))

(test recovering-node-is-reachable-but-never-used-as-sparse-transit
  (let* ((nodes (loop for index below 9
                      collect (topology-node (format nil "node-~D" index) "r" "z")))
         (stable (loop for index from 1 below 9 collect (format nil "node-~D" index)))
         (plan (cl-wireguard-overlay::plan-wireguard-topology
                (topology-overlay-nodes nodes) :full-mesh-limit 8
                :transit-node-names stable)))
    (is (eq :sparse (cl-wireguard-overlay::wireguard-topology-plan-mode plan)))
    (is (<= (length (cl-wireguard-overlay::wireguard-topology-neighbors plan "node-0")) 2))
    (dolist (source stable)
      (dolist (destination stable)
        (unless (string= source destination)
          (let ((current source))
            (loop repeat (length nodes)
                  until (string= current destination)
                  do (setf current
                           (cl-wireguard-overlay::wireguard-topology-next-hop
                            plan current destination))
                     (is (and current (not (string= current "node-0"))))
                  finally (is (string= current destination)))))))
    ;; The recovering node is still a destination and has a direct stable hop.
    (is (member (cl-wireguard-overlay::wireguard-topology-next-hop plan "node-4" "node-0")
                stable :test #'string=))))

(test recovering-leaf-cannot-shortcut-between-stable-failure-domains
  (let* ((stable
           (append (loop for index below 5
                         collect (topology-node (format nil "a-~D" index) "r" "a"))
                   (loop for index below 5
                         collect (topology-node (format nil "b-~D" index) "r" "b"))))
         (leaf (topology-node "recovering" "r" "new-zone"))
         (plan (cl-wireguard-overlay::plan-wireguard-topology
                (topology-overlay-nodes (cons leaf stable)) :full-mesh-limit 8
                :transit-node-names (mapcar #'gr8s.model::node-record-name stable)))
         (current "a-4")
         (visited nil))
    (loop repeat 20
          until (string= current "b-4")
          do (setf current (cl-wireguard-overlay::wireguard-topology-next-hop plan current "b-4"))
             (push current visited))
    (is (string= current "b-4"))
    (is-false (member "recovering" visited :test #'string=))))

(test recovering-leaf-attachments-balance-across-stable-gateways
  (let* ((stable
           (loop for index below 18
                 collect (topology-node
                          (format nil "stable-~2,'0D" index) "r"
                          (format nil "z~D" (mod index 3)))))
         (leaves
           (loop for index below 9
                 collect (topology-node
                          (format nil "recovering-~2,'0D" index) "r" "new-zone")))
         (plan (cl-wireguard-overlay::plan-wireguard-topology
                (topology-overlay-nodes (append stable leaves)) :full-mesh-limit 8
                :transit-node-names (mapcar #'gr8s.model::node-record-name stable)))
         (used nil))
    (dolist (leaf leaves)
      (dolist (neighbor (cl-wireguard-overlay::wireguard-topology-neighbors
                         plan (gr8s.model::node-record-name leaf)))
        (pushnew neighbor used :test #'string=)))
    (is (>= (length used) 12))
    (is (<= (loop for node in stable
                  maximize (length (cl-wireguard-overlay::wireguard-topology-neighbors
                                    plan (gr8s.model::node-record-name node))))
            6))))

(test gateway-expiry-fails-over-fast-and-recovery-enters-transit-slowly
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((now 4000000000))
      (dotimes (index 9)
        (let ((node (topology-node (format nil "node-~D" index) "r" "z")))
          (setf (gr8s.model::node-record-pod-cidr node) (format nil "10.88.~D.0/24" index)
                (gr8s.model::node-record-underlay-address node) (format nil "192.0.2.~D" (+ 10 index))
                (gr8s.model::node-record-wireguard-public-key node)
                (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element (1+ index)))
          (gr8s.controllers::register-node store node)
          (gr8s.controllers::mark-node-ready store (gr8s.model::node-record-name node) (- now 100)
                                :lease-duration (if (zerop index) 50 1000))))
      (let ((server (gr8s.apiserver::%make-node-grpc-server
                     :store store :heartbeat-timeout-seconds 15
                     :overlay-backend "wireguard" :clock (lambda () now)
                     :gateway-stability-seconds 30)))
        (labels ((effective-hop (route)
                   (let ((hop (slot-value route 'gr8s.node.v1::next-hop)))
                     (if hop (slot-value hop 'gr8s.node.v1::node-name)
                         (slot-value route 'gr8s.node.v1::node-name))))
                 (uses-node-0-as-transit-p ()
                   (loop for source-index from 1 below 9
                         thereis
                         (loop for route in (gr8s.apiserver::assigned-node-routes
                                             server (format nil "node-~D" source-index))
                               thereis (and (string= "node-0" (effective-hop route))
                                            (not (string= "node-0"
                                                          (slot-value route
                                                                      'gr8s.node.v1::node-name))))))))
          (is-true (uses-node-0-as-transit-p))
          (gr8s.apiserver::reconcile-node-heartbeats server now)
          (let* ((snapshot (gr8s.apiserver::current-node-snapshot server "node-4"))
                 (revision (slot-value snapshot 'gr8s.node.v1::revision)))
            (is (= 7 (length (slot-value snapshot 'gr8s.node.v1::routes))))
            (gr8s.apiserver::reconcile-node-heartbeats server now)
            (is (= revision
                   (slot-value (gr8s.apiserver::current-node-snapshot server "node-4")
                               'gr8s.node.v1::revision))))
          (is-false (find "node-0" (gr8s.apiserver::assigned-node-routes server "node-4")
                          :key (lambda (route)
                                 (slot-value route 'gr8s.node.v1::node-name))
                          :test #'string=))
          (gr8s.controllers::mark-node-ready store "node-0" (incf now) :lease-duration 1000)
          (is (find "node-0" (gr8s.apiserver::assigned-node-routes server "node-4")
                    :key (lambda (route)
                           (slot-value route 'gr8s.node.v1::node-name))
                    :test #'string=))
          (is-false (uses-node-0-as-transit-p))
          (incf now 30)
          (gr8s.apiserver::reconcile-node-heartbeats server now)
          (is-true (uses-node-0-as-transit-p))
          (is (= 8 (length
                    (slot-value (gr8s.apiserver::current-node-snapshot server "node-4")
                                'gr8s.node.v1::routes))))
          (let ((reasons (mapcar (lambda (decision) (getf decision :reason))
                                 (gr8s.apiserver::node-grpc-server-topology-decisions server))))
            (is (member :lease-expired reasons))
            (is (member :stability-window-satisfied reasons))))))))

(test sparse-steering-evidence-is-next-hop-bound-fresh-deduplicated-and-clamped
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((now 1700000200))
      (dotimes (index 9)
        (let ((node (topology-node (format nil "node-~D" index) "r" "z")))
          (setf (gr8s.model::node-record-pod-cidr node) (format nil "10.88.~D.0/24" index)
                (gr8s.model::node-record-underlay-address node) (format nil "192.0.2.~D" (+ 10 index))
                (gr8s.model::node-record-wireguard-public-key node)
                (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element (1+ index)))
          (gr8s.controllers::register-node store node)
          (gr8s.controllers::mark-node-ready store (gr8s.model::node-record-name node)
                                (+ now 2208988800) :lease-duration 1000)))
      (let* ((server (gr8s.apiserver::%make-node-grpc-server
                      :store store :overlay-backend "wireguard"
                      :clock (lambda () now)))
             (route (find-if (lambda (candidate)
                               (slot-value candidate 'gr8s.node.v1::next-hop))
                             (gr8s.apiserver::assigned-node-routes server "node-0")))
             (hop-key (gr8s.apiserver::effective-route-peer-key route))
             (other-route
               (find-if (lambda (candidate)
                          (not (equalp hop-key
                                       (gr8s.apiserver::effective-route-peer-key candidate))))
                        (gr8s.apiserver::assigned-node-routes server "node-0")))
             (destination-key (slot-value route 'gr8s.node.v1::wireguard-public-key))
             (fresh (lambda (key score flows &optional (handshake (- now 3)))
                      (make-instance 'gr8s.node.v1::wireguard-peer-observation
                                     :peer-public-key key :address "192.0.2.20"
                                     :port 51820 :latest-handshake-unix-seconds handshake
                                     :received-bytes 1 :healthy t
                                     :path-score score :active-flows flows)))
             (canonical
               (gr8s.apiserver::canonical-node-wireguard-observations
                server "node-0"
                (list (funcall fresh hop-key 999999 999999)
                      (funcall fresh hop-key 1 1)
                      (funcall fresh destination-key 1 1)
                      (funcall fresh hop-key 1 1 (- now 500))))))
        (is-true route)
        (is (= 1 (length canonical)))
        (is (equalp hop-key
                    (slot-value (first canonical) 'gr8s.node.v1::peer-public-key)))
        (is (= 10000 (slot-value (first canonical) 'gr8s.node.v1::path-score)))
        (is (= 1000 (slot-value (first canonical) 'gr8s.node.v1::active-flows)))
        (let* ((status (make-instance
                        'gr8s.node.v1::node-status
                        :wireguard-peer-observations
                        (list (make-instance
                               'gr8s.node.v1::wireguard-peer-observation
                               :peer-public-key hop-key :healthy nil :path-score 1
                               :latest-handshake-unix-seconds (- now 2))
                              (make-instance
                               'gr8s.node.v1::wireguard-peer-observation
                               :peer-public-key (gr8s.apiserver::effective-route-peer-key other-route)
                               :healthy t :path-score 9999
                               :latest-handshake-unix-seconds (- now 2)))))
               (bad-name (slot-value route 'gr8s.node.v1::node-name))
               (good-name (slot-value other-route 'gr8s.node.v1::node-name))
               (bad (gr8s.image-distribution::make-tracker-peer :node-name bad-name))
               (good (gr8s.image-distribution::make-tracker-peer :node-name good-name)))
          (setf (gethash "node-0" (gr8s.apiserver::node-grpc-server-statuses server)) status)
          (is (string= good-name
                       (gr8s.image-distribution::tracker-peer-node-name
                        (first (gr8s.apiserver::rank-image-tracker-peers
                                server "node-0" (list bad good)))))))))))

(test wireguard-topology-planner-is-local-bounded-deterministic-and-resilient
  (let* ((nodes (topology-fixture))
         (plan (cl-wireguard-overlay::plan-wireguard-topology
                (topology-overlay-nodes nodes) :full-mesh-limit 8))
         (again (cl-wireguard-overlay::plan-wireguard-topology
                 (topology-overlay-nodes (reverse nodes)) :full-mesh-limit 8)))
    (is (eq :sparse (cl-wireguard-overlay::wireguard-topology-plan-mode plan)))
    (is (equal (cl-wireguard-overlay::wireguard-topology-plan-object plan)
               (cl-wireguard-overlay::wireguard-topology-plan-object again)))
    (is (equal '("east-a-0" "east-a-1")
               (second (find '("east" "a")
                             (getf (cl-wireguard-overlay::wireguard-topology-plan-object plan)
                                   :zone-gateways)
                             :key #'first :test #'equal))))
    (is-false (getf (cl-wireguard-overlay::wireguard-topology-plan-object plan)
                    :degraded-domains))
    (dolist (source nodes)
      (let* ((source-name (gr8s.model::node-record-name source))
             (neighbors (cl-wireguard-overlay::wireguard-topology-neighbors plan source-name)))
        (is (<= (length neighbors) 6))
        (dolist (destination nodes)
          (unless (eq source destination)
            (let ((hop (cl-wireguard-overlay::wireguard-topology-next-hop
                        plan source-name (gr8s.model::node-record-name destination))))
              (is-true hop)
              (is (member hop neighbors :test #'string=)))))
        ;; A route within one zone must not leave its failure domain first.
        (let* ((same-zone (find-if
                           (lambda (candidate)
                             (and (not (eq candidate source))
                                  (string= (nth-value 0 (gr8s.apiserver::node-network-domain source))
                                           (nth-value 0 (gr8s.apiserver::node-network-domain candidate)))
                                  (string= (nth-value 1 (gr8s.apiserver::node-network-domain source))
                                           (nth-value 1 (gr8s.apiserver::node-network-domain candidate)))))
                           nodes))
               (hop (and same-zone
                         (cl-wireguard-overlay::wireguard-topology-next-hop
                          plan source-name (gr8s.model::node-record-name same-zone))))
               (hop-node (find hop nodes :key #'gr8s.model::node-record-name :test #'string=)))
          (is (string= (nth-value 1 (gr8s.apiserver::node-network-domain source))
                       (nth-value 1 (gr8s.apiserver::node-network-domain hop-node)))))))
    ;; Replanning without any one node retains all-pairs reachability. Domains
    ;; in this fixture have enough redundancy to make that guarantee possible.
    (dolist (removed nodes)
      (let* ((survivors (remove removed nodes))
             (survivor-plan
               (cl-wireguard-overlay::plan-wireguard-topology
                (topology-overlay-nodes survivors) :full-mesh-limit 8)))
        (dolist (source survivors)
          (dolist (destination survivors)
            (unless (eq source destination)
              (is (cl-wireguard-overlay::wireguard-topology-next-hop
                   survivor-plan (gr8s.model::node-record-name source)
                   (gr8s.model::node-record-name destination))))))))))

(test wireguard-topology-planner-explains-unavoidable-single-gateway-domains
  (let* ((nodes (loop for index below 9
                      collect (topology-node
                               (format nil "node-~D" index)
                               (format nil "region-~D" index)
                               "only-zone")))
         (plan (cl-wireguard-overlay::plan-wireguard-topology
                (topology-overlay-nodes nodes) :full-mesh-limit 8))
         (degraded (getf (cl-wireguard-overlay::wireguard-topology-plan-object plan)
                         :degraded-domains)))
    (is (= 18 (length degraded)))
    (is (member '(:zone "region-0" "only-zone") degraded :test #'equal))
    (is (member '(:region "region-0") degraded :test #'equal))))

(test node-session-packages-own-their-public-entry-points
  (dolist (name '("START-NODE-GRPC-SERVER"
                  "STOP-NODE-GRPC-SERVER"
                  "PUBLISH-NODE-DESIRED-STATE"))
    (multiple-value-bind (implementation implementation-status)
        (find-symbol name '#:gr8s.apiserver)
      (is (eq implementation-status :external))
      (is (eq (symbol-package implementation) (find-package '#:gr8s.apiserver)))))
  (dolist (name '("RUN-NODE-SESSION"
                  "MAKE-NODE-SESSION-CONTROL"
                  "CANCEL-NODE-SESSION"))
    (multiple-value-bind (implementation implementation-status)
        (find-symbol name '#:gr8s.agent)
      (is (eq implementation-status :external))
      (is (eq (symbol-package implementation) (find-package '#:gr8s.agent))))))

(test node-status-merge-preserves-authenticated-additional-pod-addresses
  (let* ((object (gr8s.resources::core-object
                  "phase" "Running" "podIP" "10.88.1.2"
                  "podIPs" (vector (gr8s.resources::core-object "ip" "10.88.1.2")
                                   (gr8s.resources::core-object "ip" "fd88::2"))))
         (message (make-instance 'gr8s.node.v1::pod-observed-status
                                 :phase "Running" :pod-ip "10.88.1.2")))
    (gr8s.apiserver::merge-node-pod-address-status object message)
    (is (equalp #("10.88.1.2" "fd88::2")
                (map 'vector (lambda (item) (gethash "ip" item))
                     (gethash "podIPs" object))))))

(defun wait-until (predicate &key (timeout 3))
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (loop until (funcall predicate)
          when (>= (get-internal-real-time) deadline) return nil
          do (sleep 0.02)
          finally (return t))))

(defun empty-desired-snapshot ()
  (make-instance 'gr8s.node.v1::desired-state-snapshot))

(test credential-token-requests-are-bound-to-the-authenticated-nodes-pod
  (with-temporary-store (store path)
    (declare (ignore path))
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "token-node" :name "worker-a" :pod-cidr "10.88.7.0/24"))
    (gr8s.resources::create-core-resource
     store "serviceaccounts"
     (gr8s.resources::core-object
      "metadata" (gr8s.resources::core-object "name" "builder" "uid" "builder-uid"
                                     "annotations" (gr8s.resources::core-object "tenant.example/id" "acme"
                                                                      "tenant.example/region" "ca")))
     "default")
    (let* ((pod (create-pod
                 store
                 (parse-pod
                  "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"puller\",\"namespace\":\"default\"},\"spec\":{\"serviceAccountName\":\"builder\",\"containers\":[{\"name\":\"c\",\"image\":\"private.example/a\"}]}}")))
           (version (pod-resource-version pod)))
      (setf (gr8s.model::pod-node-name pod) "worker-a")
      (setf pod (gr8s.store::update-pod store pod version))
      (let* ((request
               (make-instance
                'gr8s.node.v1::credential-token-request
                :request-id "request-1" :namespace "default" :pod-name "puller"
                :pod-uid (pod-uid pod) :service-account-name "builder"
                :audience "private.example"
                :required-annotation-keys '("tenant.example/id")
                :optional-annotation-keys '("tenant.example/region" "tenant.example/missing")))
             (response (gr8s.apiserver::credential-token-response store "worker-a" request)))
        (is (equal "request-1" (slot-value response 'gr8s.node.v1::request-id)))
        (is (plusp (length (slot-value response 'gr8s.node.v1::token))))
        (is (equal (gethash "uid" (gethash "metadata"
                                            (gr8s.resources::get-core-resource store "serviceaccounts"
                                                                      "default" "builder")))
                   (slot-value response 'gr8s.node.v1::service-account-uid)))
        (is (equal "acme" (gethash "tenant.example/id"
                                    (slot-value response 'gr8s.node.v1::service-account-annotations))))
        (is (equal "ca" (gethash "tenant.example/region"
                                  (slot-value response 'gr8s.node.v1::service-account-annotations))))
        (is (null (gr8s.resources::verify-service-account-jwt store
                                                     (slot-value response 'gr8s.node.v1::token)
                                                     '("another-audience"))))
        (is (not (null (gr8s.resources::verify-service-account-jwt
                        store (slot-value response 'gr8s.node.v1::token) '("private.example")))))
        (setf (slot-value request 'gr8s.node.v1::pod-uid) "another-pod")
        (signals error (gr8s.apiserver::credential-token-response store "worker-a" request))))))

(defun send-stale-node-ack (port node-name revision)
  (let ((channel (ag-grpc:make-channel "127.0.0.1" port :timeout 3)))
    (unwind-protect
         (let* ((stub (gr8s.node.v1::make-node-service-stub channel))
                (stream (gr8s.node.v1::node-service-connect stub :timeout 3)))
           (ag-grpc:stream-send
            stream
            (gr8s.protocol::make-agent-envelope
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
            (gr8s.protocol::make-agent-envelope
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
            (gr8s.protocol::make-agent-envelope
             :heartbeat (make-instance 'gr8s.node.v1::heartbeat) :sequence 1))
           (ag-grpc:stream-close-send stream)
           (let ((response (ag-grpc:stream-read-message stream)))
             (and response
                  (eq :protocol-error
                      (slot-value response 'gr8s.node.v1::payload-case)))))
      (ignore-errors (ag-grpc:channel-close channel)))))

(test cluster-service-risk-publication-requires-matching-current-acks
  (with-temporary-store (store path)
    (declare (ignore path))
    (dolist (entry '(("worker-a" "10.88.0.0/24")
                     ("worker-b" "10.88.1.0/24")))
      (gr8s.controllers::register-node
       store (gr8s.model::make-node-record :id (first entry) :name (first entry)
                                    :pod-cidr (second entry))))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server
                    :store store :cluster-pod-cidr "10.88.0.0/16"))
           (projection (gr8s.kubelet::service-discovery-projection store))
           (sessions (gr8s.apiserver::node-grpc-server-sessions server))
           (snapshots (gr8s.apiserver::node-grpc-server-snapshots server))
           (acks (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)))
      (is-false (gr8s.apiserver::cluster-service-risk-published-p server))
      (dolist (name '("worker-a" "worker-b"))
        (let ((session (gr8s.apiserver::make-node-agent-session nil))
              (snapshot (make-instance 'gr8s.node.v1::desired-state-snapshot
                                       :revision 1
                                       :service-discovery-objects-json projection)))
          (gr8s.apiserver::attach-node-topology server name snapshot)
          (setf (gr8s.apiserver::node-agent-session-node-id session) name
                (gr8s.apiserver::node-agent-session-service-risk-v2-p session) t
                (gethash name sessions) session
                (gethash name snapshots) snapshot
                (gethash name acks) 1)))
      (is-true (gr8s.apiserver::cluster-service-risk-published-p server))
      (let ((network (slot-value (gethash "worker-b" snapshots)
                                 'gr8s.node.v1::network)))
        (setf (slot-value (gethash "worker-b" snapshots)
                          'gr8s.node.v1::network) nil)
        (is-false (gr8s.apiserver::cluster-service-risk-published-p server))
        (setf (slot-value (gethash "worker-b" snapshots)
                          'gr8s.node.v1::network) network)
        (let ((owners (slot-value network 'gr8s.node.v1::service-translations)))
          (setf (slot-value network 'gr8s.node.v1::service-translations)
                (list (make-instance 'gr8s.node.v1::service-translation-identity
                                     :pod-uid "unexpected")))
          (is-false (gr8s.apiserver::cluster-service-risk-published-p server))
          (setf (slot-value network 'gr8s.node.v1::service-translations) owners)))
      (setf (gr8s.apiserver::node-agent-session-node-id
             (gethash "worker-b" sessions)) "replaced-node-id")
      (is-false (gr8s.apiserver::cluster-service-risk-published-p server))
      (setf (gr8s.apiserver::node-agent-session-node-id
             (gethash "worker-b" sessions)) "worker-b")
      (setf (gethash "worker-b" acks) 0)
      (is-false (gr8s.apiserver::cluster-service-risk-published-p server))
      (setf (gethash "worker-b" acks) 1
            (gr8s.apiserver::node-agent-session-service-risk-v2-p
             (gethash "worker-b" sessions)) nil)
      (is-false (gr8s.apiserver::cluster-service-risk-published-p server))
      (setf (gr8s.apiserver::node-agent-session-service-risk-v2-p
             (gethash "worker-b" sessions)) t
            (slot-value (gethash "worker-b" snapshots) 'gr8s.node.v1::revision) 2)
      (is-false (gr8s.apiserver::cluster-service-risk-published-p server))
      (setf (slot-value (gethash "worker-b" snapshots) 'gr8s.node.v1::revision) 1
            (slot-value (gethash "worker-b" snapshots)
                        'gr8s.node.v1::service-discovery-objects-json)
            (list (make-array 1 :element-type '(unsigned-byte 8)
                              :initial-element 1)))
      (is-false (gr8s.apiserver::cluster-service-risk-published-p server))
      (setf (slot-value (gethash "worker-b" snapshots)
                        'gr8s.node.v1::service-discovery-objects-json) projection)
      (remhash "worker-b" sessions)
      (is-false (gr8s.apiserver::cluster-service-risk-published-p server)))))

(test cluster-service-risk-grant-requires-all-acks-and-revokes-on-session-change
  ;; This test supplies synthetic sessions; model successful transport explicitly.
  (let ((send (symbol-function 'ag-grpc:stream-send)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ag-grpc:stream-send)
                 (lambda (stream envelope) (declare (ignore stream envelope))))
           (with-temporary-store (store path)
             (declare (ignore path))
             (dolist (entry '(("worker-a" "10.88.0.0/24")
                              ("worker-b" "10.88.1.0/24")))
               (gr8s.controllers::register-node
                store (gr8s.model::make-node-record :id (first entry) :name (first entry)
                                             :pod-cidr (second entry))))
             (let* ((server (gr8s.apiserver::%make-node-grpc-server
                             :store store :cluster-pod-cidr "10.88.0.0/16"))
                    (runtime (gr8s.controllers::make-control-plane-runtime store server))
                    (sessions (gr8s.apiserver::node-grpc-server-sessions server))
                    (acks (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)))
               (dolist (name '("worker-a" "worker-b"))
                 (let ((session (gr8s.apiserver::make-node-agent-session nil)))
                   (setf (gr8s.apiserver::node-agent-session-node-id session) name
                         (gr8s.apiserver::node-agent-session-service-risk-v2-p session) t
                         (gethash name sessions) session)))
               (gr8s.controllers::publish-service-discovery-snapshots runtime)
               (let ((first (gr8s.apiserver::current-node-snapshot server "worker-a"))
                     (second (gr8s.apiserver::current-node-snapshot server "worker-b")))
                 (is (= 0 (length (slot-value first 'gr8s.node.v1::service-risk-grant-digest))))
                 (is (= 0 (length (slot-value second 'gr8s.node.v1::service-risk-grant-digest))))
                 (setf (gethash "worker-a" acks) (slot-value first 'gr8s.node.v1::revision))
                 (gr8s.apiserver::note-node-service-receiver-status
                  server "worker-a"
                  (make-instance 'gr8s.node.v1::node-status
                                 :service-receiver-report-present t
                                 :service-receiver-revision (slot-value first 'gr8s.node.v1::revision))
                  (gethash "worker-a" sessions)))
               (gr8s.controllers::publish-service-discovery-snapshots runtime)
               (is-false (gr8s.apiserver::node-grpc-server-service-risk-grant-digest server))
               (let ((second (gr8s.apiserver::current-node-snapshot server "worker-b")))
                 (setf (gethash "worker-b" acks) (slot-value second 'gr8s.node.v1::revision))
                 (gr8s.apiserver::note-node-service-receiver-status
                  server "worker-b"
                  (make-instance 'gr8s.node.v1::node-status
                                 :service-receiver-report-present t
                                 :service-receiver-revision (slot-value second 'gr8s.node.v1::revision))
                  (gethash "worker-b" sessions)))
               (gr8s.controllers::publish-service-discovery-snapshots runtime)
               (let ((digest (gr8s.apiserver::node-grpc-server-service-risk-grant-digest server)))
                 (is (= 32 (length digest)))
                 (dolist (name '("worker-a" "worker-b"))
                   (let ((snapshot (gr8s.apiserver::current-node-snapshot server name)))
                     (is (= 2 (slot-value snapshot 'gr8s.node.v1::revision)))
                     (is (equalp digest
                                 (slot-value snapshot 'gr8s.node.v1::service-risk-grant-digest)))))
                 (let* ((snapshot (gr8s.apiserver::current-node-snapshot server "worker-a"))
                        (network (slot-value snapshot 'gr8s.node.v1::network))
                        (owners (slot-value network 'gr8s.node.v1::service-translations)))
                   (setf (slot-value network 'gr8s.node.v1::service-translations)
                         (list (make-instance 'gr8s.node.v1::service-translation-identity
                                              :pod-uid "unexpected")))
                   (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                     (is-false (gr8s.apiserver::service-risk-grant-for-snapshot-locked
                                server "worker-a" snapshot)))
                   (setf (slot-value network 'gr8s.node.v1::service-translations) owners))
                 ;; A grant revision leaves the old ACK behind; the grant remains valid
                 ;; for the same digest and authenticated sessions.
                 (gr8s.controllers::publish-service-discovery-snapshots runtime)
                 (is (equalp digest (gr8s.apiserver::node-grpc-server-service-risk-grant-digest server)))
                 (let ((replacement (gr8s.apiserver::make-node-agent-session nil)))
                   (setf (gr8s.apiserver::node-agent-session-node-id replacement) "worker-b"
                         (gr8s.apiserver::node-agent-session-service-risk-v2-p replacement) t
                         (gethash "worker-b" sessions) replacement)
                   (gr8s.controllers::publish-service-discovery-snapshots runtime)
                   (is-false (gr8s.apiserver::node-grpc-server-service-risk-grant-digest server))
                   (dolist (name '("worker-a" "worker-b"))
                     (let ((snapshot (gr8s.apiserver::current-node-snapshot server name)))
                       (is (= 3 (slot-value snapshot 'gr8s.node.v1::revision)))
                       (is (= 0 (length
                                  (slot-value snapshot 'gr8s.node.v1::service-risk-grant-digest)))))
                     (setf (gethash name acks)
                           (slot-value (gr8s.apiserver::current-node-snapshot server name)
                                       'gr8s.node.v1::revision)))
                   (gr8s.apiserver::note-node-service-receiver-status
                    server "worker-b"
                    (make-instance 'gr8s.node.v1::node-status
                                   :service-receiver-report-present t
                                   :service-receiver-revision
                                   (gethash "worker-b" acks))
                    replacement)
                   (gr8s.controllers::publish-service-discovery-snapshots runtime)
                   (is (= 32 (length (gr8s.apiserver::node-grpc-server-service-risk-grant-digest server))))
                   ;; A newly registered node invalidates the old cluster grant even
                   ;; before the next full discovery reconciliation tick.
                   (gr8s.controllers::register-node
                    store (gr8s.model::make-node-record :id "worker-c" :name "worker-c"
                                                 :pod-cidr "10.88.2.0/24"))
                   (gr8s.controllers::publish-node-snapshot runtime "worker-a")
                   (is (= 0 (length
                              (slot-value (gr8s.apiserver::current-node-snapshot server "worker-a")
                                          'gr8s.node.v1::service-risk-grant-digest)))))))))
      (setf (symbol-function 'ag-grpc:stream-send) send))))

(test receiver-status-proofs-bind-to-current-acked-owner-and-session
  (let* ((server (gr8s.apiserver::%make-node-grpc-server))
         (session (gr8s.apiserver::make-node-agent-session nil))
         (record (make-instance 'gr8s.node.v1::service-translation-identity
                                :pod-uid "pod-a" :node-name "worker-a" :node-id "node-a"
                                :sandbox-id "sandbox-a" :interface-name "eth0"
                                :pod-ip "10.88.1.2" :translation-ip "10.88.1.9"
                                :incarnation-generation "0123456789abcdef0123456789abcdef"))
         (network (make-instance 'gr8s.node.v1::node-network-config
                                 :service-translations (list record)))
         (snapshot (make-instance 'gr8s.node.v1::desired-state-snapshot
                                  :revision 3 :network network))
         (epoch (gr8s.network::service-translation-incarnation-token
                 "node-a" "sandbox-a" "eth0" "10.88.1.2" "10.88.1.9"
                 "0123456789abcdef0123456789abcdef"))
         (proof (make-instance 'gr8s.node.v1::service-receiver-proof
                               :pod-uid "pod-a" :incarnation epoch))
         (status (make-instance 'gr8s.node.v1::node-status
                                :service-receiver-revision 3
                                :service-receiver-report-present t
                                :service-receivers (list proof))))
    (setf (gr8s.apiserver::node-agent-session-node-id session) "node-a"
          (gethash "worker-a" (gr8s.apiserver::node-grpc-server-sessions server)) session
          (gethash "worker-a" (gr8s.apiserver::node-grpc-server-snapshots server)) snapshot
          (gethash "worker-a" (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 3)
    (multiple-value-bind (accepted valid-p)
        (gr8s.apiserver::canonical-node-service-receiver-proofs
         server "worker-a" status session)
      (is-true valid-p)
      (is (= 1 (length accepted))))
    (setf (slot-value status 'gr8s.node.v1::service-receivers) nil)
    (multiple-value-bind (accepted valid-p)
        (gr8s.apiserver::canonical-node-service-receiver-proofs
         server "worker-a" status session)
      (is-true valid-p)
      (is (null accepted)))
    (setf (slot-value status 'gr8s.node.v1::service-receivers) (list proof proof))
    (is-false (nth-value 1 (gr8s.apiserver::canonical-node-service-receiver-proofs
                            server "worker-a" status session)))
    (setf (slot-value status 'gr8s.node.v1::service-receivers) (list proof))
    (let ((stale (copy-seq epoch)))
      (setf (aref stale 0) (logxor 1 (aref stale 0))
            (slot-value proof 'gr8s.node.v1::incarnation) stale))
    (is-false (nth-value 1 (gr8s.apiserver::canonical-node-service-receiver-proofs
                            server "worker-a" status session)))
    (setf (slot-value proof 'gr8s.node.v1::incarnation) epoch
          (gethash "worker-a" (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 2)
    (is-false (nth-value 1 (gr8s.apiserver::canonical-node-service-receiver-proofs
                            server "worker-a" status session)))
    (setf (gethash "worker-a" (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 3)
    (gr8s.apiserver::note-node-service-receiver-status server "worker-a" status session)
    (is (= 1 (length (third (gethash "worker-a"
                                    (gr8s.apiserver::node-grpc-server-service-receiver-reports server))))))
    (gr8s.apiserver::note-node-service-receiver-status
     server "worker-a" (make-instance 'gr8s.node.v1::node-status) session)
    (is (= 1 (length (third (gethash "worker-a"
                                    (gr8s.apiserver::node-grpc-server-service-receiver-reports server))))))
    (gr8s.apiserver::note-node-service-receiver-status
     server "worker-a" (make-instance 'gr8s.node.v1::node-status
                                       :service-receiver-report-present t) session)
    (is-false (gethash "worker-a" (gr8s.apiserver::node-grpc-server-service-receiver-reports server)))
    (gr8s.apiserver::note-node-service-receiver-status server "worker-a" status session)
    (setf (slot-value snapshot 'gr8s.node.v1::revision) 4
          (slot-value status 'gr8s.node.v1::service-receiver-revision) 4)
    (gr8s.apiserver::note-node-service-receiver-status server "worker-a" status session)
    (is (= 3 (second (gethash "worker-a"
                             (gr8s.apiserver::node-grpc-server-service-receiver-reports server))))
        "A status racing ahead of its ACK must retain the prior proof")
    (setf (gethash "worker-a" (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 4)
    (gr8s.apiserver::note-node-service-receiver-status server "worker-a" status session)
    (is (= 4 (second (gethash "worker-a"
                             (gr8s.apiserver::node-grpc-server-service-receiver-reports server)))))
    (setf (slot-value proof 'gr8s.node.v1::pod-uid) "foreign-pod")
    (gr8s.apiserver::note-node-service-receiver-status server "worker-a" status session)
    (is-false (gethash "worker-a" (gr8s.apiserver::node-grpc-server-service-receiver-reports server)))))

(test service-grant-requires-current-complete-receiver-reports
  (let* ((server (gr8s.apiserver::%make-node-grpc-server))
         (session (gr8s.apiserver::make-node-agent-session nil))
         (record (make-instance 'gr8s.node.v1::service-translation-identity
                                :pod-uid "pod-a" :node-name "worker-a" :node-id "node-a"
                                :sandbox-id "sandbox-a" :interface-name "eth0"
                                :pod-ip "10.88.1.2" :translation-ip "10.88.1.9"
                                :incarnation-generation "0123456789abcdef0123456789abcdef"))
         (projection (list (ag-proto:serialize-to-bytes record)))
         (snapshot (make-instance 'gr8s.node.v1::desired-state-snapshot
                                  :revision 3
                                  :network (make-instance 'gr8s.node.v1::node-network-config
                                                          :service-translations (list record))))
         (proof (make-instance 'gr8s.node.v1::service-receiver-proof
                               :pod-uid "pod-a"
                               :incarnation (gr8s.network::service-translation-incarnation-token
                                             "node-a" "sandbox-a" "eth0"
                                             "10.88.1.2" "10.88.1.9"
                                             "0123456789abcdef0123456789abcdef")))
         (reports (gr8s.apiserver::node-grpc-server-service-receiver-reports server)))
    (setf (gr8s.apiserver::node-agent-session-node-id session) "node-a"
          (gethash "worker-a" (gr8s.apiserver::node-grpc-server-sessions server)) session
          (gethash "worker-a" (gr8s.apiserver::node-grpc-server-snapshots server)) snapshot
          (gethash "worker-a" (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 3)
    (labels ((published ()
               (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                 (gr8s.apiserver::service-risk-receivers-published-locked-p
                  server projection '(("worker-a" . "node-a")))))
             (ready ()
               (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                 (gr8s.apiserver::cluster-service-ready-receivers-locked
                  server projection '(("worker-a" . "node-a")))))
             (distributed (receiver-projection)
               (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                 (gr8s.apiserver::service-risk-receiver-projection-published-locked-p
                  server receiver-projection '(("worker-a" . "node-a"))))))
      (is-false (published))
      (is-false (ready))
      (setf (gethash "worker-a" reports) (list session 3 (list proof) projection))
      (is-true (published))
      (let* ((ready (ready))
             (receiver-projection (mapcar #'ag-proto:serialize-to-bytes ready)))
        (is (= 1 (length ready)))
        (is (equalp (slot-value proof 'gr8s.node.v1::incarnation)
                    (slot-value (first ready) 'gr8s.node.v1::incarnation)))
        (is-false (distributed receiver-projection)
                  "A local status cannot stand in for a distributed snapshot")
        (setf (slot-value snapshot 'gr8s.node.v1::service-receivers) ready)
        (is-true (distributed receiver-projection)))
      (setf (third (gethash "worker-a" reports)) nil)
      (is-false (published))
      (is-false (ready))
      (setf (gethash "worker-a" reports)
            (list session 3 (list proof) (list (make-array 1 :element-type '(unsigned-byte 8)
                                                           :initial-element 0))))
      (is-false (published))
      (setf (gethash "worker-a" reports) (list session 3 (list proof) projection)
            (gethash "worker-a" (gr8s.apiserver::node-grpc-server-sessions server))
            (gr8s.apiserver::make-node-agent-session nil))
      (is-false (published)))))

(test retained-service-grant-requires-old-owner-and-current-session-proof
  (let* ((server (gr8s.apiserver::%make-node-grpc-server))
         (session (gr8s.apiserver::make-node-agent-session nil))
         (old (make-instance 'gr8s.node.v1::service-translation-identity
                             :pod-uid "old" :node-name "worker-a" :node-id "node-a"
                             :sandbox-id "sandbox-old" :interface-name "eth0"
                             :pod-ip "10.88.1.2" :translation-ip "10.88.1.9"))
         (added (make-instance 'gr8s.node.v1::service-translation-identity
                               :pod-uid "new" :node-name "worker-a" :node-id "node-a"
                               :sandbox-id "sandbox-new" :interface-name "eth0"
                               :pod-ip "10.88.1.3" :translation-ip "10.88.1.10"))
         (old-bytes (ag-proto:serialize-to-bytes old))
         (new-bytes (ag-proto:serialize-to-bytes added))
         (proof (make-instance 'gr8s.node.v1::service-receiver-proof
                               :pod-uid "old"
                               :incarnation
                               (gr8s.network::service-translation-incarnation-token
                                "node-a" "sandbox-old" "eth0" "10.88.1.2" "10.88.1.9")))
         (reports (gr8s.apiserver::node-grpc-server-service-receiver-reports server)))
    (setf (gr8s.apiserver::node-agent-session-node-id session) "node-a"
          (gr8s.apiserver::node-agent-session-service-risk-v2-p session) t
          (gethash "worker-a" (gr8s.apiserver::node-grpc-server-sessions server)) session
          (gethash "worker-a" (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 3
          (gethash "worker-a" reports) (list session 3 (list proof) (list old-bytes))
          (gr8s.apiserver::node-grpc-server-service-risk-grant-digest server)
          (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
          (gr8s.apiserver::node-grpc-server-service-risk-grant-owner-projection server)
          (list old-bytes)
          (gr8s.apiserver::node-grpc-server-service-risk-grant-receiver-projection server)
          (list (ag-proto:serialize-to-bytes proof))
          (gr8s.apiserver::node-grpc-server-service-risk-grant-identities server)
          '( ("worker-a" . "node-a"))
          (gr8s.apiserver::node-grpc-server-service-risk-grant-sessions server) (list session))
    (labels ((retained (owners)
               (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                 (gr8s.apiserver::service-risk-retained-grant-locked-p
                  server owners '(("worker-a" . "node-a"))))))
      (is-true (retained (list old-bytes new-bytes)))
      (setf (gethash "worker-a" reports)
            (list session 3 (list proof) (list old-bytes new-bytes)))
      (is-true (retained (list old-bytes new-bytes)))
      (is-false (retained (list new-bytes)))
      (is-false (retained (list old-bytes old-bytes new-bytes)))
      (setf (gethash "worker-a" reports)
            (list session 3 nil (list old-bytes new-bytes)))
      (is-false (retained (list old-bytes new-bytes)))
      (setf (gethash "worker-a" reports)
            (list session 3 (list proof) (list old-bytes new-bytes))
            (gethash "worker-a" (gr8s.apiserver::node-grpc-server-sessions server))
            (gr8s.apiserver::make-node-agent-session nil))
      (is-false (retained (list old-bytes new-bytes))))))

(test two-node-service-receiver-set-must-reach-both-snapshots
  (let* ((server (gr8s.apiserver::%make-node-grpc-server))
         (identities '(("worker-a" . "node-a") ("worker-b" . "node-b")))
         (owners (loop for (name . id) in identities
                       for index from 1
                       collect (make-instance 'gr8s.node.v1::service-translation-identity
                                              :pod-uid (format nil "pod-~D" index)
                                              :node-name name :node-id id
                                              :sandbox-id (format nil "sandbox-~D" index)
                                              :interface-name "eth0"
                                              :pod-ip (format nil "10.88.~D.2" index)
                                              :translation-ip (format nil "10.88.~D.9" index))))
         (projection (mapcar #'ag-proto:serialize-to-bytes owners))
         (proofs (mapcar (lambda (owner)
                           (make-instance 'gr8s.node.v1::service-receiver-proof
                                          :pod-uid (slot-value owner 'gr8s.node.v1::pod-uid)
                                          :incarnation
                                          (gr8s.network::service-translation-incarnation-token
                                           (slot-value owner 'gr8s.node.v1::node-id)
                                           (slot-value owner 'gr8s.node.v1::sandbox-id)
                                           (slot-value owner 'gr8s.node.v1::interface-name)
                                           (slot-value owner 'gr8s.node.v1::pod-ip)
                                           (slot-value owner 'gr8s.node.v1::translation-ip))))
                         owners))
         (reports (gr8s.apiserver::node-grpc-server-service-receiver-reports server))
         (snapshots (gr8s.apiserver::node-grpc-server-snapshots server)))
    (loop for (name . id) in identities
          for proof in proofs
          do (let ((session (gr8s.apiserver::make-node-agent-session nil)))
               (setf (gr8s.apiserver::node-agent-session-node-id session) id
                     (gethash name (gr8s.apiserver::node-grpc-server-sessions server)) session
                     (gethash name (gr8s.apiserver::node-grpc-server-acknowledged-revisions server)) 3
                     (gethash name snapshots)
                     (make-instance 'gr8s.node.v1::desired-state-snapshot
                                    :revision 3
                                    :network (make-instance 'gr8s.node.v1::node-network-config
                                                            :service-translations owners)))
               (when (string= name "worker-a")
                 (setf (gethash name reports) (list session 3 (list proof) projection)))))
    (labels ((ready ()
               (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                 (gr8s.apiserver::cluster-service-ready-receivers-locked
                  server projection identities)))
             (distributed (receiver-projection)
               (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                 (gr8s.apiserver::service-risk-receiver-projection-published-locked-p
                  server receiver-projection identities))))
      (is-false (ready) "One node's proof cannot release a partial set")
      (let ((session (gethash "worker-b" (gr8s.apiserver::node-grpc-server-sessions server))))
        (setf (gethash "worker-b" reports) (list session 3 (list (second proofs)) projection)))
      (let* ((ready (ready))
             (receiver-projection (mapcar #'ag-proto:serialize-to-bytes ready)))
        (is (= 2 (length ready)))
        (setf (slot-value (gethash "worker-a" snapshots) 'gr8s.node.v1::service-receivers)
              ready)
        (is-false (distributed receiver-projection)
                  "The second node must receive the same complete projection")
        (setf (slot-value (gethash "worker-b" snapshots) 'gr8s.node.v1::service-receivers)
              ready)
        (is-true (distributed receiver-projection))
        (setf (third (gethash "worker-b" reports)) nil)
        (is-false (ready) "Withdrawal invalidates the complete set")))))

(test snapshot-ack-from-replaced-node-session-is-ignored
  (let* ((server (gr8s.apiserver::%make-node-grpc-server))
         (old (gr8s.apiserver::make-node-agent-session nil))
         (current (gr8s.apiserver::make-node-agent-session nil))
         (ack (make-instance 'gr8s.node.v1::snapshot-ack
                             :revision 3 :applied t)))
    (setf (gethash "worker" (gr8s.apiserver::node-grpc-server-revisions server)) 3
          (gethash "worker" (gr8s.apiserver::node-grpc-server-sessions server)) current)
    (gr8s.apiserver::note-node-snapshot-ack server "worker" ack old)
    (is (= 0 (gr8s.apiserver::node-session-acknowledged-revision server "worker")))
    (gr8s.apiserver::note-node-snapshot-ack server "worker" ack current)
    (is (= 3 (gr8s.apiserver::node-session-acknowledged-revision server "worker")))))

(test revisioned-node-session-reconnects-acknowledges-and-expires-heartbeats
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-1" :name "worker-a"
                                  :pod-cidr "10.88.0.0/20"))
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0
                    :heartbeat-timeout-seconds 1))
           (applied nil)
           (risk-capability-observed nil)
           (ack-before-replay nil))
      (unwind-protect
           (progn
             (is (= 1 (gr8s.apiserver::publish-node-desired-state
                       server "worker-a" (empty-desired-snapshot))))
             (gr8s.agent::run-node-session
              "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
              "worker-a" identity-path
              (lambda (snapshot)
                (push (slot-value snapshot 'gr8s.node.v1::revision) applied)
                (setf risk-capability-observed
                      (gr8s.apiserver::node-agent-session-service-risk-v2-p
                       (gethash "worker-a"
                                (gr8s.apiserver::node-grpc-server-sessions server)))))
              :capabilities '("service-risk-v2")
              :max-sessions 1 :reconnect-delay 0.01)
             (is (equal '(1) applied))
             (is-true risk-capability-observed)
             (is (= 1 (gr8s.apiserver::node-session-acknowledged-revision
                       server "worker-a")))
             (is (probe-file identity-path))
             (is (string= "10.88.0.0/20"
                          (gethash "assignedPodCIDR" (com.inuoe.jzon:parse identity-path))))
             (is (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "worker-a")))

             (send-stale-node-ack
              (gr8s.apiserver::node-grpc-server-port server) "worker-a" 1)
             (is (= 0 (gr8s.apiserver::node-session-acknowledged-revision
                       server "worker-a")))

             (is (= 2 (gr8s.apiserver::publish-node-desired-state
                       server "worker-a" (empty-desired-snapshot))))
             (gr8s.agent::run-node-session
              "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
              "worker-a" identity-path
              (lambda (snapshot)
                (push (slot-value snapshot 'gr8s.node.v1::revision) applied))
              :max-sessions 1 :reconnect-delay 0.01)
             (is (equal '(2 1) applied))
             (is (= 2 (gr8s.apiserver::node-session-acknowledged-revision
                       server "worker-a")))

             (is-true (malformed-session-is-rejected
                       (gr8s.apiserver::node-grpc-server-port server)))
             ;; A bad stream must not poison the listener or a later session.
             (gr8s.agent::run-node-session
              "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
              "worker-a" identity-path
              (lambda (snapshot)
                (declare (ignore snapshot))
                (setf ack-before-replay
                      (gr8s.apiserver::node-session-acknowledged-revision server "worker-a")))
              :max-sessions 1 :reconnect-delay 0.01)
             (is (= 0 ack-before-replay))

             (is-true
              (wait-until
               (lambda ()
                 (not (gr8s.model::node-record-ready-p
                       (gr8s.controllers::get-node store "worker-a"))))
               :timeout 3)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test persistent-node-session-renews-its-heartbeat-lease
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-heartbeat" :name "worker-heartbeat"
                                  :pod-cidr "10.88.2.0/24"))
    (let* ((server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0
                    :heartbeat-timeout-seconds 2))
           (identity-path (merge-pathnames "agent/identity.json" path))
           (control (gr8s.agent::make-node-session-control))
           (agent-thread nil))
      (unwind-protect
           (progn
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                       "worker-heartbeat" identity-path
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :reconnect-delay 0.01
                       :control control))
                    :name "gr8s persistent heartbeat test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s.model::node-record-ready-p
                  (gr8s.controllers::get-node store "worker-heartbeat")))
               :timeout 3))
             (sleep 3)
             (is-true
              (gr8s.model::node-record-ready-p
               (gr8s.controllers::get-node store "worker-heartbeat"))))
        (gr8s.agent::cancel-node-session control)
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

;; Runs a persistent agent against a real server, and tears both down.
(defun call-with-persistent-node-session (node-name function &key status-provider)
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id node-name :name node-name :pod-cidr "10.88.3.0/24"))
    (let* ((server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2))
           (control (gr8s.agent::make-node-session-control))
           (agent-thread
             (bt:make-thread
              (lambda ()
                (gr8s.agent::run-node-session
                 "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                 node-name (merge-pathnames "agent/identity.json" path)
                 (lambda (snapshot) (declare (ignore snapshot)))
                 :reconnect-delay 0.01 :control control
                 :status-provider status-provider))
              :name "gr8s watchdog test agent")))
      (unwind-protect
           (flet ((ready-p ()
                    (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store node-name)))
                  (session ()
                    (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                      (gethash node-name (gr8s.apiserver::node-grpc-server-sessions server)))))
             (is-true (wait-until #'ready-p :timeout 5))
             (funcall function #'ready-p #'session server))
        (gr8s.agent::cancel-node-session control)
        (ignore-errors (bt:join-thread agent-thread))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test blocked-status-provider-does-not-stop-node-heartbeats
  (let ((release (bt:make-semaphore)))
    (call-with-persistent-node-session
     "worker-blocked-status"
     (lambda (ready-p session server)
       (declare (ignore session server))
       (sleep 4)
       (is-true (funcall ready-p))
       (bt:signal-semaphore release :count 100))
     :status-provider (lambda () (bt:wait-on-semaphore release) nil))))

(test blocked-heartbeat-send-reconnects-the-session
  (let ((saved gr8s.apiserver::*node-session-stall-seconds*)
        (block-next nil))
    (let ((*error-output* (make-broadcast-stream)))
      ;; Other threads see only the global value, so this cannot be a LET.
      (setf gr8s.apiserver::*node-session-stall-seconds* 1)
      (sb-int:encapsulate
       'gr8s.agent::send-agent-session-envelope 'block-heartbeat
       (lambda (function session variant payload)
         (when (and block-next (eq variant :heartbeat))
           (setf block-next nil)
           (sleep 3600))
         (funcall function session variant payload)))
      (unwind-protect
           (call-with-persistent-node-session
            "worker-blocked-heartbeat"
            (lambda (ready-p session server)
              (declare (ignore server))
              (let ((first (funcall session)))
                (setf block-next t)
                (is-true (wait-until (lambda () (not (eq first (funcall session)))) :timeout 10))
                (is-true (wait-until ready-p :timeout 5)))))
        (sb-int:unencapsulate 'gr8s.agent::send-agent-session-envelope 'block-heartbeat)
        (setf gr8s.apiserver::*node-session-stall-seconds* saved)))))

;; podster-uqb.121: closing the channel did not reliably wake the thread reading it, and a
;; quiet server had nothing else to wake it with. No Pod started until something did, which
;; took 5 minutes once. Over TLS, as every real agent's session is, and repeatedly, since
;; the first failure can get away with it.
(test failed-snapshots-reconnect-without-waiting-for-the-server-to-speak
  (with-temporary-store (store path)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (token (gr8s.security::create-join-token pki "worker-failed"))
           (server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki
                    :cluster-pod-cidr "10.96.0.0/12" :node-prefix 20))
           (agent-directory (merge-pathnames "worker-failed/" path))
           (private-key (merge-pathnames "node.key" agent-directory))
           (certificate (merge-pathnames "node.crt" agent-directory))
           (ca-certificate (merge-pathnames "ca.crt" agent-directory))
           (control (gr8s.agent::make-node-session-control))
           (lock (bt:make-lock))
           (fail-next nil) (failed nil) (recovered 0) (revision 0)
           (*error-output* (make-broadcast-stream))
           (agent nil))
      (unwind-protect
           (progn
             (gr8s.agent::enroll-node-over-grpc
              "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
              "worker-failed" token (gr8s.security::cluster-pki-ca-fingerprint pki)
              private-key certificate ca-certificate)
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                       "worker-failed" (merge-pathnames "identity.json" agent-directory)
                       (lambda (snapshot)
                         (declare (ignore snapshot))
                         (bt:with-lock-held (lock)
                           (when failed (setf failed nil) (incf recovered))
                           (when fail-next
                             (setf fail-next nil failed t)
                             (error "Injected snapshot failure")))
                         nil)
                       :ca-certificate-path ca-certificate
                       :certificate-path certificate :private-key-path private-key
                       :status-provider (lambda () (make-instance 'gr8s.node.v1::node-status))
                       :control control :reconnect-delay 0.01))
                    :name "gr8s failed snapshot test agent"))
             (is-true (wait-until (lambda () (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "worker-failed")))
                                  :timeout 10))
             ;; Once the snapshot fails, the server stays quiet until the agent is back.
             (loop for attempt from 1 to 8
                   do (bt:with-lock-held (lock) (setf fail-next t))
                      (gr8s.apiserver::publish-node-desired-state
                       server "worker-failed"
                       (make-instance 'gr8s.node.v1::desired-state-snapshot :revision (incf revision)))
                      (is-true (wait-until (lambda () (>= recovered attempt)) :timeout 10)
                               "the agent did not come back after failure ~D" attempt)
                      (unless (>= recovered attempt) (return))))
        (gr8s.agent::cancel-node-session control)
        (when agent (ignore-errors (bt:join-thread agent)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

;; podster-uqb.104: the reading thread can reach its next read before it is interrupted.
(test closing-a-session-leaves-the-reading-thread-a-closed-connection-to-find
  (with-temporary-store (store path)
    (values path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "worker-closed" :name "worker-closed" :pod-cidr "10.88.3.0/24"))
    (let* ((server (gr8s.apiserver::start-node-grpc-server store :host "127.0.0.1" :port 0))
           (channel (ag-grpc:make-channel "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server) :timeout 3)))
      (unwind-protect
           (let* ((stub (gr8s.node.v1::make-node-service-stub channel))
                  (stream (gr8s.node.v1::node-service-connect stub :timeout 3)))
             (gr8s.agent::close-agent-session-connection channel)
             (is-true (ag-grpc:channel-connection channel))
             (is (eq :closed (ag-http2:connection-state (ag-grpc:channel-connection channel))))
             (handler-case (ag-grpc:stream-read-message stream)
               (error (condition)
                 (is-false (search "no applicable method" (string-downcase (princ-to-string condition)))
                           "~A" condition))))
        (ignore-errors (ag-grpc:channel-close channel))
        (gr8s.apiserver::stop-node-grpc-server server)))))

;; podster-uqb.109: the interrupt found the session thread in %SIGNAL for a stream
;; error. A handler function runs with the clusters rebound to those outside it, as
;; a handler test does, and with none outside an ERROR killed the thread.
(test node-session-interrupt-during-signal-still-unwinds
  (let* ((tag (list :test))
         (signalling (bt:make-semaphore))
         (cleaned-up nil)
         (thread (bt:make-thread
                  (lambda ()
                    (gr8s.agent::with-node-session-interruption (tag)
                      (unwind-protect
                           (handler-bind
                               ((error (lambda (condition)
                                         (declare (ignore condition))
                                         (bt:signal-semaphore signalling)
                                         (sleep 3600))))
                             (error "read failed"))
                        (setf cleaned-up t))))
                  :name "gr8s interrupted session test")))
    (bt:wait-on-semaphore signalling)
    (gr8s.agent::interrupt-node-session-thread thread tag)
    (is (eq :interrupted (bt:join-thread thread)))
    (is-true cleaned-up)))

(test node-session-interrupt-passes-handlers-that-recover-from-errors
  (let* ((tag (list :test))
         (blocked (bt:make-semaphore))
         (swallowed nil)
         (thread (bt:make-thread
                  (lambda ()
                    (gr8s.agent::with-node-session-interruption (tag)
                      (handler-case (progn (bt:signal-semaphore blocked) (sleep 3600))
                        (serious-condition () (setf swallowed t))))))))
    (bt:wait-on-semaphore blocked)
    (gr8s.agent::interrupt-node-session-thread thread tag)
    (is (eq :interrupted (bt:join-thread thread)))
    (is-false swallowed)))

(test node-session-interrupt-outside-its-scope-is-ignored
  (let* ((tag (list :old-session))
         (left (bt:make-semaphore))
         (received (bt:make-semaphore))
         (thread (bt:make-thread
                  (lambda ()
                    (gr8s.agent::with-node-session-interruption (tag) nil)
                    (bt:signal-semaphore left)
                    ;; Cleanup after the scope, then a newer session on the same
                    ;; thread: neither may be unwound by the old session's interrupt.
                    (bt:wait-on-semaphore received)
                    (gr8s.agent::with-node-session-interruption ((list :new-session))
                      (bt:signal-semaphore left)
                      (bt:wait-on-semaphore received)
                      :finished)))))
    (bt:wait-on-semaphore left)
    (gr8s.agent::interrupt-node-session-thread thread tag)
    (bt:signal-semaphore received)
    (bt:wait-on-semaphore left)
    (gr8s.agent::interrupt-node-session-thread thread tag)
    (bt:signal-semaphore received)
    (is (eq :finished (bt:join-thread thread)))))

(test stopping-a-snapshot-worker-passes-handlers-that-recover-from-errors
  (let* ((blocked (bt:make-semaphore))
         (swallowed nil)
         (worker (gr8s.agent::start-agent-snapshot-worker
                  (lambda (snapshot replay)
                    (declare (ignore snapshot replay))
                    (handler-case (progn (bt:signal-semaphore blocked) (sleep 3600))
                      (serious-condition () (setf swallowed t))))
                  (lambda ()))))
    (gr8s.agent::queue-agent-snapshot-work
     worker (make-instance 'gr8s.node.v1::desired-state-snapshot :revision 1))
    (bt:wait-on-semaphore blocked)
    (gr8s.agent::stop-agent-snapshot-worker worker)
    (is-false swallowed)
    (is-false (bt:thread-alive-p (gr8s.agent::agent-snapshot-worker-thread worker)))))

(test silent-node-session-is-evicted-so-the-agent-reconnects
  (let ((*error-output* (make-broadcast-stream)))
    (call-with-persistent-node-session
     "worker-silent"
     (lambda (ready-p session server)
       (let ((first (funcall session)))
         ;; Pass a later clock instead of aging the session: its next heartbeat
         ;; can overwrite any timestamp written here.
         (gr8s.apiserver::evict-silent-node-sessions server (+ (get-universal-time) 3600))
         (is-true (wait-until (lambda () (not (eq first (funcall session)))) :timeout 10))
         (is-true (wait-until ready-p :timeout 5)))))))

(test cancelling-persistent-node-session-wakes-blocked-read
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-cancel" :name "worker-cancel"
                                  :pod-cidr "10.88.3.0/24"))
    (let* ((server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "agent/identity.json" path))
           (control (gr8s.agent::make-node-session-control))
           (agent-thread nil))
      (unwind-protect
           (progn
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                       "worker-cancel" identity-path
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :control control :reconnect-delay 0.01))
                    :name "gr8s cancellable persistent session test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s.model::node-record-ready-p
                  (gr8s.controllers::get-node store "worker-cancel")))
               :timeout 3))
             (gr8s.agent::cancel-node-session control)
             (is-true
              (wait-until (lambda () (not (bt:thread-alive-p agent-thread)))
                          :timeout 2)))
        (when (and agent-thread (bt:thread-alive-p agent-thread))
          (ignore-errors (bt:destroy-thread agent-thread)))
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test standalone-agent-enrolls-registers-and-connects-over-grpc
  (with-temporary-store (store path)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (token (gr8s.security::create-join-token pki "worker-b"))
           (server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki
                    :cluster-pod-cidr "10.96.0.0/12" :node-prefix 20
                    :overlay-backend "wireguard" :wireguard-listen-port 51820))
           (agent-directory (merge-pathnames "worker-b/" path))
           (private-key (merge-pathnames "node.key" agent-directory))
           (certificate (merge-pathnames "node.crt" agent-directory))
           (ca-certificate (merge-pathnames "ca.crt" agent-directory))
           (identity (merge-pathnames "identity.json" agent-directory)))
      (unwind-protect
           (multiple-value-bind (wireguard-private-key wireguard-public-key)
               (gr8s.security::ensure-wireguard-key-pair agent-directory)
             (declare (ignore wireguard-private-key))
             (let ((node-id
                   (gr8s.agent::enroll-node-over-grpc
                    "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                    "worker-b" token (gr8s.security::cluster-pki-ca-fingerprint pki)
                    private-key certificate ca-certificate)))
             (is (string= node-id (gr8s.model::node-record-id
                                   (gr8s.controllers::get-node store "worker-b"))))
             (is (string= "10.96.0.0/20"
                          (gr8s.model::node-record-pod-cidr
                           (gr8s.controllers::get-node store "worker-b"))))
             (is (probe-file private-key))
             (is (probe-file certificate))
             (is (probe-file ca-certificate))
             (gr8s.apiserver::publish-node-desired-state
              server "worker-b" (empty-desired-snapshot))
             (gr8s.agent::run-node-session
              "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
              "worker-b" identity (lambda (snapshot) (declare (ignore snapshot)))
              :ca-certificate-path ca-certificate
              :certificate-path certificate :private-key-path private-key
              :wireguard-public-key wireguard-public-key
              :max-sessions 1 :reconnect-delay 0.01)
             (is (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "worker-b")))
             (is (equalp wireguard-public-key
                         (gr8s.model::node-record-wireguard-public-key
                          (gr8s.controllers::get-node store "worker-b"))))))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test repeated-node-enrollment-preserves-the-committed-identity
  (with-temporary-store (store path)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s.apiserver::start-node-grpc-server store :host "127.0.0.1" :port 0 :pki pki))
           (directory (merge-pathnames "worker-retry/" path))
           (private-key (merge-pathnames "node.key" directory))
           (certificate (merge-pathnames "node.crt" directory))
           (ca-certificate (merge-pathnames "ca.crt" directory)))
      (unwind-protect
           (let* ((first-id
                    (gr8s.agent::enroll-node-over-grpc
                     "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                     "worker-retry" (gr8s.security::create-join-token pki "worker-retry")
                     (gr8s.security::cluster-pki-ca-fingerprint pki)
                     private-key certificate ca-certificate))
                  ;; A control-plane response can be lost after the replicated
                  ;; node record commits.  A fresh, name-bound token and the
                  ;; same persisted key must recover that committed identity.
                  (retry-id
                    (gr8s.agent::enroll-node-over-grpc
                     "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                     "worker-retry" (gr8s.security::create-join-token pki "worker-retry")
                     (gr8s.security::cluster-pki-ca-fingerprint pki)
                     private-key certificate ca-certificate)))
             (is (string= first-id retry-id))
             (is (string= retry-id
                          (gr8s.model::node-record-id (gr8s.controllers::get-node store "worker-retry")))))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test image-tracker-rpc-binds-node-name-to-the-mtls-certificate
  (with-temporary-store (store path)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki))
           (directory (merge-pathnames "tracker-node/" path))
           (private-key (merge-pathnames "node.key" directory))
           (certificate (merge-pathnames "node.crt" directory))
           (ca-certificate (merge-pathnames "ca.crt" directory))
           (channel nil))
      (unwind-protect
           (progn
             (gr8s.agent::enroll-node-over-grpc
              "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
              "tracker-node" (gr8s.security::create-join-token pki "tracker-node")
              (gr8s.security::cluster-pki-ca-fingerprint pki)
              private-key certificate ca-certificate)
             (setf channel
                   (gr8s.security::make-node-tls-channel
                    "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                    :timeout 5 :ca-certificate-path ca-certificate
                    :certificate-path certificate :private-key-path private-key))
             (let ((stub (gr8s.node.v1::make-node-service-stub channel)))
               (multiple-value-bind (response status)
                   (gr8s.node.v1::node-service-track-image
                    stub
                    (make-instance
                     'gr8s.node.v1::image-tracker-request
                     :node-name "tracker-node" :action "acquire"
                     :digest
                     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    :timeout 5)
                 (declare (ignore status))
                 (is (string= "granted"
                              (slot-value response 'gr8s.node.v1::status))))
               (signals ag-grpc:grpc-status-error
                   (gr8s.node.v1::node-service-track-image
                  stub
                  (make-instance
                   'gr8s.node.v1::image-tracker-request
                   :node-name "different-node" :action "lookup"
                   :digest
                   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                  :timeout 5))))
        (when channel (ignore-errors (ag-grpc:channel-close channel)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test ha-enrollment-replicates-an-ordered-node-operation
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "existing-id" :name "existing"
                                  :pod-cidr "10.80.0.0/20"))
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (commits nil)
           (server nil)
           (directory (merge-pathnames "worker-ordered/" path)))
      (setf (gr8s.store::pod-store-consensus-commit-fn store)
            (lambda (tag payload)
              (push tag commits)
              (ecase tag
                (:node-state (gr8s.store::install-node-state-blob store payload))
                (:node-delta (gr8s.store::install-node-state-delta store payload))
                (:node-enrollment
                 (apply #'gr8s.controllers::install-node-enrollment-command store payload)))))
      (setf server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki
                    :session-admission-fn (constantly nil)
                    :cluster-pod-cidr "10.80.0.0/12" :node-prefix 20))
      (unwind-protect
           (progn
             (gr8s.agent::enroll-node-over-grpc
              "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
              "worker-ordered" (gr8s.security::create-join-token pki "worker-ordered")
              (gr8s.security::cluster-pki-ca-fingerprint pki)
              (merge-pathnames "node.key" directory)
              (merge-pathnames "node.crt" directory)
              (merge-pathnames "ca.crt" directory))
             (is (equal '(:node-enrollment) commits))
             (is (string= "10.80.16.0/20"
                          (gr8s.model::node-record-pod-cidr
                           (gr8s.controllers::get-node store "worker-ordered"))))
             (is (gr8s.controllers::get-node store "existing")))
        (when server (gr8s.apiserver::stop-node-grpc-server server))))))

(test agent-enrollment-falls-through-to-a-live-control-plane-endpoint
  (with-temporary-store (store path)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (token (gr8s.security::create-join-token pki "worker-failover"))
           (server (gr8s.apiserver::start-node-grpc-server store :host "127.0.0.1" :port 0 :pki pki))
           (dead-listener (make-instance 'hunchentoot:easy-acceptor :address "127.0.0.1" :port 0))
           (dead-port (progn (hunchentoot:start dead-listener)
                             (prog1 (hunchentoot:acceptor-port dead-listener)
                               (hunchentoot:stop dead-listener))))
           (directory (merge-pathnames "worker-failover/" path)))
      (unwind-protect
           (let ((node-id
                   (gr8s.agent::enroll-node-over-endpoints
                    (list (list "127.0.0.1" dead-port)
                          (list "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)))
                    "worker-failover" token (gr8s.security::cluster-pki-ca-fingerprint pki)
                    (merge-pathnames "node.key" directory)
                    (merge-pathnames "node.crt" directory)
                    (merge-pathnames "ca.crt" directory))))
             (is (string= node-id
                          (gr8s.model::node-record-id (gr8s.controllers::get-node store "worker-failover")))))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test local-agent-starts-through-grpc-and-stops-cleanly
  (with-temporary-store (store path)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki))
           (worker nil))
      (unwind-protect
           (progn
             ;; Real RSA key generation can exceed the handshake's five-second
             ;; assertion window. Prepare it before starting that timed work;
             ;; enrollment still builds/verifies the CSR and negotiates mTLS.
             (gr8s.security::generate-node-key-and-csr "gr8s-local" (merge-pathnames "agent/node.key" path))
             (setf worker
                   (gr8s.server::start-local-node-agent
                    server pki "gr8s-local" (merge-pathnames "agent/" path)))
             (is-true
              (wait-until
               (lambda ()
                 (handler-case
                     (gr8s.model::node-record-ready-p
                      (gr8s.controllers::get-node store "gr8s-local"))
                   (gr8s.model::kubernetes-error () nil)))
               :timeout 5))
             (gr8s.server::stop-local-node-agent worker)
             (is-false
              (bt:thread-alive-p (gr8s.server::local-node-agent-thread worker))))
        (when (and worker
                   (bt:thread-alive-p (gr8s.server::local-node-agent-thread worker)))
          (gr8s.server::stop-local-node-agent worker))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test local-agent-executes-control-plane-snapshots-and-reports-status
  (with-temporary-store (store path)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :pki pki))
           (agent-directory (merge-pathnames "agent/" path))
           (worker nil)
           (runtime (gr8s.controllers::make-control-plane-runtime store server))
           (reconciler (make-reconciler store runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (unwind-protect
           (progn
             ;; Real RSA key generation can exceed the handshake's five-second
             ;; assertion window. Prepare it before starting that timed work;
             ;; enrollment still builds/verifies the CSR and negotiates mTLS.
             (gr8s.security::generate-node-key-and-csr "gr8s-local" (merge-pathnames "agent/node.key" path))
             (setf worker
                   (gr8s.server::start-local-node-agent
                    server pki "gr8s-local" agent-directory
                    (list :runtime "fake")))
             (is-true
              (wait-until
               (lambda ()
                 (handler-case
                     (gr8s.model::node-record-ready-p
                      (gr8s.controllers::get-node store "gr8s-local"))
                   (gr8s.model::kubernetes-error () nil)))
               :timeout 5))

             (reconcile-pod reconciler "default" "hello")
             (is-true
              (wait-until
               (lambda ()
                 (string= "Running" (gr8s.controllers::pod-scheduling-phase store pod)))
               :timeout 5))

             (gr8s.kubelet::delete-reconciled-pod reconciler "default" "hello")
             (let ((deletion-revision
                     (slot-value (gr8s.apiserver::current-node-snapshot server "gr8s-local")
                                 'gr8s.node.v1::revision)))
               (is-true
                (wait-until
                 (lambda ()
                   (>= (gr8s.apiserver::node-session-acknowledged-revision
                        server "gr8s-local")
                       deletion-revision))
                 :timeout 5)))
             (is (null
                  (list-pods
                   (gr8s.store::open-store
                    (merge-pathnames "runtime/desired/" agent-directory))
                   "default"))))
        (when worker (gr8s.server::stop-local-node-agent worker))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test control-plane-logs-come-from-the-assigned-remote-agent
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-remote" :name "worker-a"
                                  :pod-cidr "10.88.1.0/24"))
    (let* ((server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (fake-runtime (make-fake-runtime))
           (node-runtime
             (gr8s.agent::make-node-runtime
              (merge-pathnames "worker-a/runtime/" path) fake-runtime nil))
           (identity-path
             (merge-pathnames "worker-a/identity.json" path))
           (control (gr8s.agent::make-node-session-control))
           (agent-thread nil)
           (control-runtime
             (gr8s.controllers::make-control-plane-runtime store server))
           (reconciler (make-reconciler store control-runtime))
           (pod (create-pod store (parse-pod *valid-pod-json*))))
      (unwind-protect
           (progn
             (gr8s.agent::start-node-runtime node-runtime)
             (setf agent-thread
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                       "worker-a" identity-path
                       (lambda (snapshot)
                         (gr8s.agent::reconcile-node-snapshot
                          node-runtime snapshot))
                       :operation-handler
                       (lambda (variant payload emit)
                         (unless (eq variant :operation-request)
                           (error "Unexpected operation payload ~S" variant))
                         (dolist (reply
                                  (gr8s.agent::handle-node-operation
                                   node-runtime payload))
                           (funcall emit (car reply) (cdr reply))))
                       :reconnect-delay 0.01
                       :control control))
                    :name "gr8s remote log test agent"))
             (is-true
              (wait-until
               (lambda ()
                 (gr8s.model::node-record-ready-p
                  (gr8s.controllers::get-node store "worker-a")))
               :timeout 5))
             (reconcile-pod reconciler "default" "hello")
             (is-true
              (wait-until
               (lambda ()
                 (runtime-observe fake-runtime (pod-uid pod)))
               :timeout 5))
             (setf (gethash "web"
                            (gr8s.runtime::runtime-pod-logs
                             (runtime-observe fake-runtime (pod-uid pod))))
                   "hello from worker-a\n")
             (is (string= "hello from worker-a\n"
                          (runtime-logs control-runtime (pod-uid pod) "web")))
             (gr8s.runtime::set-fake-runtime-exec-result
              fake-runtime
              (gr8s.runtime::make-runtime-exec-result
               :stdout (trivial-utf-8:string-to-utf-8-bytes "remote stdout\n")
               :stderr (trivial-utf-8:string-to-utf-8-bytes "remote stderr\n")
               :exit-code 7))
             (let ((result
                     (gr8s.runtime::runtime-exec-sync
                      control-runtime (pod-uid pod) "web"
                      '("sh" "-c" "printf remote") :timeout 4)))
               (is (equalp
                    (trivial-utf-8:string-to-utf-8-bytes "remote stdout\n")
                    (gr8s.runtime::runtime-exec-result-stdout result)))
               (is (equalp
                    (trivial-utf-8:string-to-utf-8-bytes "remote stderr\n")
                    (gr8s.runtime::runtime-exec-result-stderr result)))
               (is (= 7 (gr8s.runtime::runtime-exec-result-exit-code result)))))
        (gr8s.agent::cancel-node-session control)
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s.agent::stop-node-runtime node-runtime)
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test node-operation-crosses-the-control-plane-member-owning-the-agent-session
  (with-temporary-store (origin-store origin-path)
    (with-temporary-store (owner-store owner-path)
      (declare (ignore origin-path))
      (dolist (store (list origin-store owner-store))
        (gr8s.controllers::register-node
         store (gr8s.model::make-node-record :id "node-relayed" :name "worker-relayed"
                                      :pod-cidr "10.88.9.0/24")))
      (let* ((origin (gr8s.apiserver::start-node-grpc-server origin-store :host "127.0.0.1" :port 0
                                                              :session-admission-fn (constantly nil)))
             (owner (gr8s.apiserver::start-node-grpc-server owner-store :host "127.0.0.1" :port 0))
             (origin-member (gr8s.raft.transport::start-raft-member "origin" :port 0))
             (owner-member (gr8s.raft.transport::start-raft-member "owner" :port 0))
             (control (gr8s.agent::make-node-session-control))
             (agent nil))
        (unwind-protect
             (progn
               (gr8s.raft.transport::raft-member-set-peers
                origin-member
                (list (list "owner" "127.0.0.1"
                            (gr8s.raft.transport::raft-member-port owner-member))))
               (gr8s.raft.transport::raft-member-set-peers
                owner-member
                (list (list "origin" "127.0.0.1"
                            (gr8s.raft.transport::raft-member-port origin-member))))
               (gr8s.raft.transport::configure-raft-node-operation-routing origin-member origin)
               (gr8s.raft.transport::configure-raft-node-operation-routing owner-member owner)
               (setf agent
                     (bt:make-thread
                      (lambda ()
                        (gr8s.agent::run-node-session
                         "127.0.0.1" (gr8s.apiserver::node-grpc-server-port owner)
                         "worker-relayed"
                         (merge-pathnames "worker-relayed/identity.json" owner-path)
                         (lambda (snapshot) (declare (ignore snapshot)))
                         :operation-handler
                         (lambda (variant payload emit)
                           (when (eq variant :operation-request)
                             (let ((id (slot-value payload 'gr8s.node.v1::operation-id)))
                               (funcall emit :operation-stream
                                        (make-instance 'gr8s.node.v1::operation-stream
                                                       :operation-id id :sequence 1
                                                       :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+
                                                       :data (gr8s.protocol::ascii-octets "relayed")))
                               (funcall emit :operation-response
                                        (make-instance 'gr8s.node.v1::operation-response
                                                       :operation-id id
                                                       :status gr8s.node.v1::+operationstatus-operation_status_complete+
                                                       :exit-code 0)))))
                         :control control :reconnect-delay 0.01))
                      :name "gr8s relayed operation agent"))
               (is-true
                (wait-until
                 (lambda ()
                   (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock owner))
                     (gethash "worker-relayed"
                              (gr8s.apiserver::node-grpc-server-sessions owner))))
                 :timeout 5))
               (let* ((request
                        (make-instance 'gr8s.node.v1::operation-request
                                       :operation-id "relayed-operation"
                                       :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
                      (operation
                        (gr8s.apiserver::request-node-operation
                         origin "worker-relayed" request :timeout 3)))
                 (is (string= "owner"
                              (gr8s.apiserver::pending-node-operation-remote-member operation)))
                 (is (equalp (gr8s.protocol::ascii-octets "relayed")
                             (gr8s.controllers::node-operation-channel-data
                              operation gr8s.node.v1::+streamchannel-stream_channel_stdout+)))
                 (is (= 0 (slot-value (gr8s.apiserver::pending-node-operation-response operation)
                                      'gr8s.node.v1::exit-code)))))
          (gr8s.agent::cancel-node-session control)
          (when agent (ignore-errors (bt:join-thread agent)))
          (gr8s.raft.transport::stop-raft-member owner-member)
          (gr8s.raft.transport::stop-raft-member origin-member)
          (gr8s.apiserver::stop-node-grpc-server owner)
          (gr8s.apiserver::stop-node-grpc-server origin))))))

(test a-request-to-a-node-that-is-not-connected-says-so
  ;; "Node operation timed out" named neither the node nor why (podster-xbf).
  (with-temporary-store (store path)
    (declare (ignore path))
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-away" :name "worker-away" :pod-cidr "10.88.11.0/24"))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (request (make-instance 'gr8s.node.v1::operation-request
                                   :operation-id "logs-while-away"
                                   :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
           (operation (gr8s.apiserver::queue-node-operation server "worker-away" request))
           (message (handler-case (progn (gr8s.apiserver::wait-for-node-operation server operation :timeout 1) nil)
                      (runtime-error (condition) (runtime-error-message condition)))))
      (is (search "Node worker-away did not answer within 1 second" message))
      (is (search "its agent is not connected to the control plane" message)))))

(test a-transient-peer-routing-miss-does-not-strand-a-node-operation-locally
  (with-temporary-store (store path)
    (declare (ignore path))
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-rerouted" :name "worker-rerouted"
                                  :pod-cidr "10.88.10.0/24"))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (attempts 0)
           (seen-variants nil)
           (seen-node-names nil)
           (request
             (make-instance 'gr8s.node.v1::operation-request
                            :operation-id "reroute-after-miss"
                            :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
           (operation nil))
      (setf (gr8s.apiserver::node-grpc-server-operation-router server)
            (lambda (variant target-member node-name payload)
              (declare (ignore target-member payload))
              (push variant seen-variants)
              (push node-name seen-node-names)
              (when (> (incf attempts) 1) "owner")))
      (unwind-protect
           (progn
             (setf operation
                   (gr8s.apiserver::queue-node-operation server "worker-rerouted" request))
             (is-true
              (wait-until
               (lambda ()
                 (equal "owner"
                        (gr8s.apiserver::pending-node-operation-remote-member operation)))
               :timeout 1))
             (is (>= attempts 2))
             (is (every (lambda (variant) (eq :operation-request variant))
                        seen-variants))
             (is (every (lambda (node-name)
                          (string= "worker-rerouted" node-name))
                        seen-node-names))
             (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
               (is (null (gethash "worker-rerouted"
                                  (gr8s.apiserver::node-grpc-server-operation-queues server))))))
        (setf (gr8s.apiserver::node-grpc-server-stopping-p server) t)
        (when operation
          (gr8s.apiserver::finish-node-operation operation :error "test cleanup")
          (gr8s.apiserver::release-node-operation server operation))))))

(test a-transient-directed-peer-miss-does-not-fail-an-active-node-operation
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (request
             (make-instance 'gr8s.node.v1::operation-request
                            :operation-id "directed-retry"
                            :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
           (operation (gr8s.apiserver::make-pending-node-operation "worker" request))
           (attempts 0))
      (setf (gr8s.apiserver::pending-node-operation-remote-member operation) "owner"
            (gethash "directed-retry" (gr8s.apiserver::node-grpc-server-operations server)) operation
            (gr8s.apiserver::node-grpc-server-operation-router server)
            (lambda (variant target-member node-name payload)
              (declare (ignore payload))
              (is (eq :operation-input variant))
              (is (string= "owner" target-member))
              (is (string= "worker" node-name))
              (when (> (incf attempts) 1) "owner")))
      (unwind-protect
           (progn
             (gr8s.apiserver::send-node-operation-input
              server operation
              (make-instance 'gr8s.node.v1::operation-input
                             :operation-id "directed-retry" :sequence 1
                             :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                             :data (gr8s.protocol::ascii-octets "input")))
             (is (= 2 attempts))
             (is-false (gr8s.apiserver::pending-node-operation-done-p operation)))
        (gr8s.apiserver::release-node-operation server operation)))))

(test operation-input-and-cancel-follow-the-correlated-node-session
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-interactive" :name "worker-interactive"
                                  :pod-cidr "10.88.4.0/24"))
    (let* ((server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "interactive/identity.json" path))
           (control (gr8s.agent::make-node-session-control))
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
                        (gr8s.agent::run-node-session
                         "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
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
                   (gr8s.model::node-record-ready-p
                    (gr8s.controllers::get-node store "worker-interactive")))
                 :timeout 5))
               (setf operation
                     (gr8s.apiserver::queue-node-operation
                      server "worker-interactive" request))
               (is-true
                (wait-until (lambda () (seen-variant-p :operation-request))
                            :timeout 3))
               (gr8s.apiserver::send-node-operation-input
                server operation
                (make-instance
                 'gr8s.node.v1::operation-input
                 :operation-id "interactive-1" :sequence 1
                 :channel gr8s.node.v1::+streamchannel-stream_channel_stdin+
                 :data (trivial-utf-8:string-to-utf-8-bytes "echo hi\n")))
               (gr8s.apiserver::cancel-node-operation server operation "client closed")
               (gr8s.apiserver::wait-for-node-operation server operation :timeout 3)
               (is-true (seen-variant-p :operation-input))
               (let ((cancel (cdr (seen-variant-p :operation-cancel))))
                 (is (string= "client closed"
                              (slot-value cancel 'gr8s.node.v1::reason)))))
          (gr8s.agent::cancel-node-session control)
          (when agent-thread
            (ignore-errors (bt:join-thread agent-thread)))
          (gr8s.apiserver::stop-node-grpc-server server))))))

(test ending-node-session-notifies-its-operation-handler
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-session-close"
                                  :name "worker-session-close"
                                  :pod-cidr "10.88.6.0/24"))
    (let* ((server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0))
           (identity-path (merge-pathnames "session-close/identity.json" path))
           (control (gr8s.agent::make-node-session-control))
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
                      (gr8s.agent::run-node-session
                       "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
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
                 (gr8s.model::node-record-ready-p
                  (gr8s.controllers::get-node store "worker-session-close")))
               :timeout 5))
             (setf operation
                   (gr8s.apiserver::queue-node-operation
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
                          (gr8s.apiserver::wait-for-node-operation
                           server operation :timeout 5)
                        (runtime-error (condition)
                          (setf waiter-error
                                (runtime-error-message condition)))))
                    :name "gr8s disconnected operation waiter"))
             (gr8s.agent::cancel-node-session control)
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
        (gr8s.agent::cancel-node-session control)
        (when waiter
          (ignore-errors (bt:join-thread waiter)))
        (when agent-thread
          (ignore-errors (bt:join-thread agent-thread)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test node-operation-response-and-stream-are-bound-to-the-owning-node
  (with-temporary-store (store path)
    (values path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-own" :name "owner"
                                         :pod-cidr "10.88.6.0/24"))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (request (make-instance 'gr8s.node.v1::operation-request
                                   :operation-id "bound-op"
                                   :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
           (operation (gr8s.apiserver::queue-node-operation server "owner" request))
           (stream-msg (make-instance 'gr8s.node.v1::operation-stream
                                      :operation-id "bound-op" :sequence 1
                                      :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+
                                      :data (trivial-utf-8:string-to-utf-8-bytes "x")))
           (response (make-instance 'gr8s.node.v1::operation-response
                                    :operation-id "bound-op"
                                    :status gr8s.node.v1::+operationstatus-operation_status_complete+)))
      ;; A node that does not own the operation cannot inject a stream or finish it.
      (gr8s.apiserver::note-node-operation-stream server "attacker" stream-msg)
      (gr8s.apiserver::note-node-operation-response server "attacker" response)
      (is-false (gr8s.apiserver::pending-node-operation-done-p operation))
      ;; The addressed node is accepted and finishes it.
      (gr8s.apiserver::note-node-operation-response server "owner" response)
      (is-true (gr8s.apiserver::pending-node-operation-done-p operation)))))

(test pending-node-operation-wakes-for-stream-data-before-completion
  (with-temporary-store (store path)
    (values path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-stream" :name "worker-stream"
                                  :pod-cidr "10.88.5.0/24"))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (request
             (make-instance
              'gr8s.node.v1::operation-request
              :operation-id "stream-before-complete"
              :kind gr8s.node.v1::+operationkind-operation_kind_exec+))
           (operation
             (gr8s.apiserver::queue-node-operation server "worker-stream" request))
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
                       (gr8s.apiserver::wait-for-next-node-operation-message
                        operation 0 :timeout 2))))
              :name "gr8s pending stream waiter")))
      (sleep 0.05)
      (gr8s.apiserver::note-node-operation-stream server "worker-stream" message)
      (bt:join-thread waiter)
      (is (eq message (first result)))
      (is (= 1 (second result)))
      (is-false (third result))
      (gr8s.apiserver::finish-node-operation
       operation
       :response
       (make-instance
        'gr8s.node.v1::operation-response
        :operation-id "stream-before-complete"
        :status gr8s.node.v1::+operationstatus-operation_status_complete+))
      (multiple-value-bind (next cursor done-p)
          (gr8s.apiserver::wait-for-next-node-operation-message
           operation 1 :timeout 1)
        (is (null next))
        (is (= 1 cursor))
        (is-true done-p))
      (gr8s.apiserver::release-node-operation server operation)
      (is (null
           (gr8s.apiserver::find-node-operation server "stream-before-complete"))))))

(test restarted-control-plane-rebuilds-snapshot-above-agent-revision
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-recovery" :name "worker-a"
                                  :pod-cidr "10.88.7.0/24"))
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (server (gr8s.apiserver::%make-node-grpc-server
                    :store store :port 0
                    :heartbeat-timeout-seconds 5
                    :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24)))
      (gr8s.controllers::mark-node-ready store "worker-a" (get-universal-time))
      (gr8s.controllers::schedule-pod store pod)
      (let* ((snapshot (gr8s.apiserver::prepare-node-connect-snapshot server "worker-a" 42))
             (network (slot-value snapshot 'gr8s.node.v1::network)))
        (is (= 43 (slot-value snapshot 'gr8s.node.v1::revision)))
        (is (= 1 (length (slot-value snapshot 'gr8s.node.v1::pods))))
        (is (string= "10.88.7.0/24"
                     (slot-value network 'gr8s.node.v1::node-pod-cidr)))
        (is (string= "169.254.1.1"
                     (slot-value network 'gr8s.node.v1::dns-address)))
        (is (eq snapshot (gr8s.apiserver::prepare-node-connect-snapshot server "worker-a" 43)))))))

(test cancelling-agent-during-server-hello-wait-unwinds-the-session
  (with-temporary-store (store path)
    (let* ((server (gr8s.apiserver::start-node-grpc-server store :host "127.0.0.1" :port 0))
           (control (gr8s.agent::make-node-session-control))
           (received-hello nil)
           (agent nil))
      (unwind-protect
           (progn
             ;; A live peer accepts the RPC and reads requests but never sends
             ;; ServerHello. Cancellation must cover this handshake phase.
             (gr8s.node.v1::register-node-service-service
              (gr8s.apiserver::node-grpc-server-grpc-server server)
              :connect-handler
              (lambda (context stream)
                (declare (ignore context))
                (setf received-hello (not (null (ag-grpc:stream-recv stream))))
                (loop while (ag-grpc:stream-recv stream))))
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                       "stalled-worker" (merge-pathnames "stalled/identity.json" path)
                       (lambda (snapshot) (declare (ignore snapshot)))
                       :control control :reconnect-delay 0.01))))
             (is-true (wait-until (lambda () received-hello) :timeout 3))
             (gr8s.agent::cancel-node-session control)
             (is-true (wait-until (lambda () (not (bt:thread-alive-p agent)))
                                 :timeout 3)))
        (gr8s.agent::cancel-node-session control)
        (when agent
          (when (bt:thread-alive-p agent) (bt:destroy-thread agent))
          (ignore-errors (bt:join-thread agent)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test node-underlay-identity-is-durable-and-cannot-overlap-another-node
  (with-temporary-store (store path)
    (dolist (entry '(("node-a" "worker-a" "10.88.1.0/24")
                     ("node-b" "worker-b" "10.88.2.0/24")))
      (gr8s.controllers::register-node store (gr8s.model::make-node-record
                                :id (first entry) :name (second entry)
                                :pod-cidr (third entry))))
    (is-true (gr8s.controllers::update-node-underlay-address store "worker-a" "192.0.2.10"))
    (is-false (gr8s.controllers::update-node-underlay-address store "worker-a" "192.0.2.10"))
    (signals gr8s.model::kubernetes-error
      (gr8s.controllers::update-node-underlay-address store "worker-b" "192.0.2.10"))
    (is (string= "192.0.2.10"
                 (gr8s.model::node-record-underlay-address
                  (gr8s.controllers::get-node (gr8s.store::open-store path) "worker-a"))))))

(test wireguard-peer-keys-are-durable-and-projected-only-into-peer-routes
  (with-temporary-store (store path)
    (let ((key-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10))
          (key-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 11)))
      (gr8s.controllers::register-node
       store (gr8s.model::make-node-record :id "node-a" :name "worker-a"
                                    :pod-cidr "10.88.1.0/24"
                                    :underlay-address "192.0.2.10"
                                    :wireguard-public-key key-a))
      (gr8s.controllers::register-node
       store (gr8s.model::make-node-record :id "node-b" :name "worker-b"
                                    :pod-cidr "10.88.2.0/24"
                                    :underlay-address "192.0.2.11"
                                    :wireguard-public-key key-b
                                    :wireguard-reflexive-observed-at 1234
                                    :wireguard-endpoints
                                    '(("private" "10.0.0.11" 51820)
                                      ("public" "192.0.2.11" 51820))))
      (let* ((reopened (gr8s.store::open-store path))
             (server (gr8s.apiserver::%make-node-grpc-server
                      :store reopened :port 0 :heartbeat-timeout-seconds 5
                      :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24
                      :overlay-backend "wireguard" :wireguard-listen-port 51820))
             (network (gr8s.apiserver::assigned-node-network server "worker-a"))
             (routes (gr8s.apiserver::assigned-node-routes server "worker-a")))
        (is (equalp key-a
                    (gr8s.model::node-record-wireguard-public-key
                     (gr8s.controllers::get-node reopened "worker-a"))))
        (is (= 1234
               (gr8s.model::node-record-wireguard-reflexive-observed-at
                (gr8s.controllers::get-node reopened "worker-b"))))
        (is (string= "wireguard"
                     (slot-value network 'gr8s.node.v1::overlay-backend)))
        (is (= 51820
               (slot-value network 'gr8s.node.v1::wireguard-listen-port)))
        (is (= 1 (length routes)))
        (is (string= "worker-b"
                     (slot-value (first routes) 'gr8s.node.v1::node-name)))
        (is (equalp key-b
                    (slot-value (first routes)
                                'gr8s.node.v1::wireguard-public-key)))
        (is (= 51820
               (slot-value (first routes)
                           'gr8s.node.v1::wireguard-listen-port)))
        (is (equal '("private" "public")
                   (mapcar (lambda (endpoint)
                             (slot-value endpoint 'gr8s.node.v1::name))
                           (slot-value (first routes)
                                       'gr8s.node.v1::wireguard-endpoints))))))))

(test sparse-wireguard-routes-separate-destination-from-authenticated-next-hop
  (with-temporary-store (store path)
    (declare (ignore path))
    (dotimes (index 9)
      (let ((node (topology-node (format nil "node-~D" index) "region" "zone")))
        (setf (gr8s.model::node-record-id node) (format nil "id-~D" index)
              (gr8s.model::node-record-pod-cidr node) (format nil "10.88.~D.0/24" index)
              (gr8s.model::node-record-underlay-address node) (format nil "192.0.2.~D" (+ 10 index))
              (gr8s.model::node-record-wireguard-public-key node)
              (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element (1+ index)))
        (gr8s.controllers::register-node store node)))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server
                    :store store :port 0 :heartbeat-timeout-seconds 5
                    :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24
                    :overlay-backend "wireguard" :wireguard-listen-port 51820))
           (routes (gr8s.apiserver::assigned-node-routes server "node-0"))
           (effective-peers nil))
      (is (= 8 (length routes)))
      (dolist (route routes)
        (let ((hop (slot-value route 'gr8s.node.v1::next-hop)))
          (pushnew (if hop
                       (slot-value hop 'gr8s.node.v1::node-name)
                       (slot-value route 'gr8s.node.v1::node-name))
                   effective-peers :test #'string=)))
      (is (<= (length effective-peers) 2))
      (let* ((route (find "node-4" routes
                          :key (lambda (candidate)
                                 (slot-value candidate 'gr8s.node.v1::node-name))
                          :test #'string=))
             (hop (slot-value route 'gr8s.node.v1::next-hop))
             (hop-node (gr8s.controllers::get-node store
                                      (slot-value hop 'gr8s.node.v1::node-name))))
        (is-true hop)
        (is (not (string= "node-4"
                          (slot-value hop 'gr8s.node.v1::node-name))))
        (is (equalp (gr8s.model::node-record-wireguard-public-key hop-node)
                    (slot-value hop 'gr8s.node.v1::wireguard-public-key)))))))

(test nat-rendezvous-replaces-only-the-reflexive-candidate
  (is (equal '(("lan" "10.0.0.9" 51820)
               ("nat-reflexive" "198.51.100.9" 41002))
             (gr8s.apiserver::merge-wireguard-reflexive-endpoint
              '(("lan" "10.0.0.9" 51820)
                ("nat-reflexive" "198.51.100.9" 41001))
              "198.51.100.9" 41002)))

  (is (equal '(("public" "192.0.2.9" 51820)
               ("nat-reflexive" "198.51.100.9" 41002))
             (gr8s.apiserver::merge-wireguard-advertised-endpoints
              '(("public" "192.0.2.9" 51820))
              '(("lan" "10.0.0.9" 51820)
                ("nat-reflexive" "198.51.100.9" 41002)))))
  (signals error
    (gr8s.apiserver::merge-wireguard-advertised-endpoints
     '(("nat-reflexive" "203.0.113.8" 9)) nil))
  (signals error
    (gr8s.apiserver::merge-wireguard-advertised-endpoints
     '(("relay" "203.0.113.8" 9)) nil)))

(test authenticated-topology-appends-pair-specific-relay-candidates
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((key-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21))
           (key-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 22))
           (relay (gr8s.network::start-wireguard-relay-server
                   :address "127.0.0.1" :port-start 46000 :max-channels 1)))
      (unwind-protect
           (progn
             (gr8s.controllers::register-node
              store (gr8s.model::make-node-record
                     :id "node-a" :name "worker-a" :pod-cidr "10.88.1.0/24"
                     :underlay-address "192.0.2.10" :wireguard-public-key key-a
                     :wireguard-reflexive-observed-at
                     (- (get-universal-time) 2208988800)
                     :wireguard-endpoints
                     '(("nat-reflexive" "198.51.100.10" 41000))))
             (gr8s.controllers::register-node
              store (gr8s.model::make-node-record
                     :id "node-b" :name "worker-b" :pod-cidr "10.88.2.0/24"
                     :underlay-address "192.0.2.11" :wireguard-public-key key-b
                     :wireguard-reflexive-observed-at
                     (- (get-universal-time) 2208988800)
                     :wireguard-endpoints
                     '(("public" "198.51.100.11" 51820)
                       ("nat-reflexive" "198.51.100.11" 41001))))
             (let* ((server
                      (gr8s.apiserver::%make-node-grpc-server
                       :store store :port 0 :heartbeat-timeout-seconds 5
                       :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24
                       :overlay-backend "wireguard" :wireguard-listen-port 51820
                       :wireguard-relay-server relay
                       :wireguard-relay-address "203.0.113.9"))
                    (route-a (first (gr8s.apiserver::assigned-node-routes server "worker-a")))
                    (route-b (first (gr8s.apiserver::assigned-node-routes server "worker-b")))
                    (endpoints-a (slot-value route-a 'gr8s.node.v1::wireguard-endpoints))
                    (endpoints-b (slot-value route-b 'gr8s.node.v1::wireguard-endpoints)))
               (is (equal '("public" "nat-reflexive" "relay")
                          (mapcar (lambda (endpoint)
                                    (slot-value endpoint 'gr8s.node.v1::name))
                                  endpoints-a)))
               (is (equal '("nat-reflexive" "relay")
                          (mapcar (lambda (endpoint)
                                    (slot-value endpoint 'gr8s.node.v1::name))
                                  endpoints-b)))
               (is (= 46000 (slot-value (third endpoints-a)
                                        'gr8s.node.v1::port)))
               (is (= 46001 (slot-value (second endpoints-b)
                                        'gr8s.node.v1::port)))))
        (gr8s.network::stop-wireguard-relay-server relay)))))

(test nat-rendezvous-binds-peer-keys-to-registered-nodes-and-rejects-stale-evidence
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((reporter-key (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 7))
           (target-key (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 8))
           (server (gr8s.apiserver::%make-node-grpc-server
                    :store store :overlay-backend "wireguard"
                    :cluster-pod-cidr "10.88.0.0/16")))
      (gr8s.controllers::register-node
       store (gr8s.model::make-node-record :id "reporter" :name "reporter"
                                    :pod-cidr "10.88.1.0/24"
                                    :underlay-address "192.0.2.1"
                                    :wireguard-public-key reporter-key))
      (gr8s.controllers::register-node
       store (gr8s.model::make-node-record :id "target" :name "target"
                                    :pod-cidr "10.88.2.0/24"
                                    :underlay-address "192.0.2.2"
                                    :wireguard-public-key target-key
                                    :wireguard-endpoints
                                    '(("lan" "10.0.0.2" 51820))))
      (flet ((observation (key handshake &optional (address "198.51.100.2"))
               (make-instance
                'gr8s.node.v1::wireguard-peer-observation
                :peer-public-key key :address address :port 41000
                :latest-handshake-unix-seconds handshake :received-bytes 20)))
        (gr8s.apiserver::record-authenticated-wireguard-observations
         server "reporter" (list (observation target-key 970))
         :now 1000 :fresh-seconds 60)
        (is (equal '(("lan" "10.0.0.2" 51820)
                     ("nat-reflexive" "198.51.100.2" 41000))
                   (gr8s.model::node-record-wireguard-endpoints
                    (gr8s.controllers::get-node store "target"))))
        (is (= 1000
               (gr8s.model::node-record-wireguard-reflexive-observed-at
                (gr8s.controllers::get-node store "target"))))
        (gr8s.apiserver::record-authenticated-wireguard-observations
         server "reporter" (list (observation target-key 100))
         :now 1000 :fresh-seconds 60)
        (is (= 41000
               (third (find "nat-reflexive"
                            (gr8s.model::node-record-wireguard-endpoints
                             (gr8s.controllers::get-node store "target"))
                            :key #'first :test #'string=))))
        (gr8s.apiserver::record-authenticated-wireguard-observations
         server "reporter" (list (observation target-key 1005 "198.51.100.3"))
         :now 1010 :fresh-seconds 60)
        (is (string= "198.51.100.2"
                     (second (find "nat-reflexive"
                                   (gr8s.model::node-record-wireguard-endpoints
                                    (gr8s.controllers::get-node store "target"))
                                   :key #'first :test #'string=))))
        (gr8s.apiserver::record-authenticated-wireguard-observations
         server "reporter" (list (observation target-key 1025 "198.51.100.3"))
         :now 1031 :fresh-seconds 60)
        (is (string= "198.51.100.3"
                     (second (find "nat-reflexive"
                                   (gr8s.model::node-record-wireguard-endpoints
                                    (gr8s.controllers::get-node store "target"))
                                   :key #'first :test #'string=))))
        (is (= 1031
               (gr8s.model::node-record-wireguard-reflexive-observed-at
                (gr8s.controllers::get-node store "target"))))))))

(test live-node-sessions-publish-peer-address-and-key-changes-and-withdrawals
  (with-temporary-store (store path)
    (dolist (entry '(("node-a" "worker-a" "10.88.1.0/24")
                     ("node-b" "worker-b" "10.88.2.0/24")))
      (gr8s.controllers::register-node store (gr8s.model::make-node-record
                                :id (first entry) :name (second entry)
                                :pod-cidr (third entry))))
    (let* ((key-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10))
           (key-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 11))
           (key-c (make-array 32 :element-type '(unsigned-byte 8) :initial-element 12))
           (server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0
                    :overlay-backend "wireguard" :wireguard-listen-port 51820))
           (control (gr8s.agent::make-node-session-control))
           (agent nil) (snapshots nil)
           (lock (bt:make-lock "peer snapshot observations")))
      (labels ((latest-peer-address ()
                 (bt:with-lock-held (lock)
                   (let* ((snapshot (first snapshots))
                          (peer (and snapshot (first (slot-value snapshot 'gr8s.node.v1::routes)))))
                     (and peer (slot-value peer 'gr8s.node.v1::underlay-address)))))
               (latest-peer-key ()
                 (bt:with-lock-held (lock)
                   (let* ((snapshot (first snapshots))
                          (peer (and snapshot (first (slot-value snapshot 'gr8s.node.v1::routes)))))
                     (and peer (slot-value peer 'gr8s.node.v1::wireguard-public-key)))))
               (latest-peer-endpoint-names ()
                 (bt:with-lock-held (lock)
                   (let* ((snapshot (first snapshots))
                          (peer (and snapshot
                                     (first (slot-value snapshot
                                                        'gr8s.node.v1::routes)))))
                     (and peer
                          (mapcar
                           (lambda (endpoint)
                             (slot-value endpoint 'gr8s.node.v1::name))
                           (slot-value peer
                                       'gr8s.node.v1::wireguard-endpoints))))))
               (connect-peer (address key &optional endpoints)
                 (gr8s.agent::run-node-session
                  "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server) "worker-b"
                  (merge-pathnames "peer-b/identity.json" path)
                  (lambda (snapshot)
                    (is (string= address (slot-value (slot-value snapshot 'gr8s.node.v1::network)
                                                     'gr8s.node.v1::underlay-address))))
                  :underlay-address address :wireguard-public-key key
                  :wireguard-endpoints endpoints
                  :max-sessions 1)))
        (unwind-protect
             (progn
               (setf agent
                     (bt:make-thread
                      (lambda ()
                        (gr8s.agent::run-node-session
                         "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server) "worker-a"
                         (merge-pathnames "peer-a/identity.json" path)
                         (lambda (snapshot)
                           (bt:with-lock-held (lock) (push snapshot snapshots)) nil)
                         :underlay-address "192.0.2.10"
                         :wireguard-public-key key-a :control control
                         :reconnect-delay 0.01))))
               (is-true (wait-until (lambda () (bt:with-lock-held (lock) snapshots)) :timeout 5))
               (connect-peer "192.0.2.11" key-b
                             '(("private" "10.0.0.11" 51820)
                               ("public" "192.0.2.11" 51820)))
               (is-true (wait-until (lambda () (equal "192.0.2.11" (latest-peer-address))) :timeout 5))
               (is-true (equalp key-b (latest-peer-key)))
               (is-true (wait-until
                         (lambda ()
                           (equal '("private" "public")
                                  (latest-peer-endpoint-names)))
                         :timeout 5))
               (connect-peer "192.0.2.12" key-b)
               (is-true (wait-until (lambda () (equal "192.0.2.12" (latest-peer-address))) :timeout 5))
               (connect-peer "192.0.2.12" key-c)
               (is-true (wait-until (lambda () (equalp key-c (latest-peer-key))) :timeout 5))
               (is (equalp key-c
                           (gr8s.model::node-record-wireguard-public-key
                            (gr8s.controllers::get-node store "worker-b"))))
               (connect-peer "" key-c)
               (is-true (wait-until (lambda () (null (latest-peer-address))) :timeout 5)))
          (gr8s.agent::cancel-node-session control)
          (when agent
            (unless (wait-until (lambda () (not (bt:thread-alive-p agent))) :timeout 3)
              (bt:destroy-thread agent))
            (ignore-errors (bt:join-thread agent)))
          (gr8s.apiserver::stop-node-grpc-server server))))))

(test server-hello-cannot-reassign-a-durable-node-cidr
  (with-temporary-store (store path)
    (values store)
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (identity (gr8s.agent::make-agent-identity "worker-a" :node-id "node-1"))
           (hello (make-instance 'gr8s.node.v1::server-hello
                                :node-id "node-1" :assigned-pod-cidr "10.88.0.0/20")))
      (gr8s.agent::accept-agent-server-hello identity identity-path hello)
      (let ((original (uiop:read-file-string identity-path)))
        (setf (slot-value hello 'gr8s.node.v1::assigned-pod-cidr) "10.88.16.0/20")
        (signals error (gr8s.agent::accept-agent-server-hello identity identity-path hello))
        (is (string= "10.88.0.0/20" (gethash "assignedPodCIDR" identity)))
        (is (string= original (uiop:read-file-string identity-path)))
        (setf (slot-value hello 'gr8s.node.v1::assigned-pod-cidr) "10.88.0.1/20")
        (signals error (gr8s.agent::accept-agent-server-hello identity identity-path hello))
        (is (string= original (uiop:read-file-string identity-path)))))))

(test server-hello-persists-and-protects-the-complete-dual-stack-allocation
  (with-temporary-store (store path)
    (values store)
    (let* ((identity-path (merge-pathnames "agent/identity.json" path))
           (identity (gr8s.agent::make-agent-identity "worker-a" :node-id "node-1"))
           (hello (make-instance
                   'gr8s.node.v1::server-hello
                   :node-id "node-1" :assigned-pod-cidr "10.88.0.0/20"
                   :assigned-pod-cidrs '("10.88.0.0/20" "fd88::/64"))))
      (gr8s.agent::accept-agent-server-hello identity identity-path hello)
      (is (equalp #("10.88.0.0/20" "fd88::/64")
                  (gethash "assignedPodCIDRs" identity)))
      (let ((original (uiop:read-file-string identity-path)))
        (setf (slot-value hello 'gr8s.node.v1::assigned-pod-cidrs)
              '("10.88.0.0/20" "fd88:0:0:1::/64"))
        (signals error (gr8s.agent::accept-agent-server-hello identity identity-path hello))
        (is (string= original (uiop:read-file-string identity-path)))))))

(test dual-stack-enrollment-allocates-both-families-from-committed-node-state
  (with-temporary-store (store path)
    (values path)
    (let ((first (gr8s.controllers::install-node-enrollment-command
                  store "id-a" "worker-a" '("10.88.0.0/16" "fd88::/48")
                  '(24 64) "2026-11-08T00:00:00Z"))
          (second nil))
      (setf second (gr8s.controllers::install-node-enrollment-command
                    store "id-b" "worker-b" '("10.88.0.0/16" "fd88::/48")
                    '(24 64) "2026-11-08T00:00:01Z"))
      (is (equalp #("10.88.0.0/24" "fd88::/64")
                  (gr8s.model::node-record-all-pod-cidrs first)))
      (is (equalp #("10.88.1.0/24" "fd88:0:0:1::/64")
                  (gr8s.model::node-record-all-pod-cidrs second))))))

(test snapshot-cidr-is-checked-before-runtime-application-or-acknowledgement
  (let ((identity (gr8s.agent::make-agent-identity "worker-a"))
        (snapshot (empty-desired-snapshot)))
    (setf (gethash "assignedPodCIDR" identity) "10.88.0.0/20"
          (slot-value snapshot 'gr8s.node.v1::revision) 1
          (slot-value snapshot 'gr8s.node.v1::network)
          (make-instance 'gr8s.node.v1::node-network-config :node-pod-cidr "10.88.16.0/20"))
    (signals error
      (gr8s.agent::apply-node-snapshot-and-respond
       nil identity #P"/must-not-write-node-identity" snapshot
       (lambda (snapshot) (declare (ignore snapshot))
         (fail "mismatched snapshot reached the runtime"))))
    (is (= 0 (gethash "lastAppliedRevision" identity)))))

(test legacy-snapshot-singular-cidr-matches-a-new-vector-identity
  (let ((identity (gr8s.agent::make-agent-identity "worker-a"))
        (snapshot (empty-desired-snapshot)))
    (setf (gethash "assignedPodCIDR" identity) "10.88.0.0/20"
          (gethash "assignedPodCIDRs" identity) #("10.88.0.0/20")
          (slot-value snapshot 'gr8s.node.v1::network)
          (make-instance 'gr8s.node.v1::node-network-config
                         :node-pod-cidr "10.88.0.0/20"))
    (finishes (gr8s.agent::validate-node-snapshot-identity identity snapshot))))

(test tls-enrollment-verifies-the-server-before-consuming-its-token
  (with-temporary-store (store path)
    (let* ((pki (gr8s.security::ensure-cluster-pki path))
           (token (gr8s.security::create-join-token pki "tls-worker"))
           (server (gr8s.apiserver::start-node-grpc-server store :pki pki :port 0))
           (key (merge-pathnames "worker/node.key" path))
           (cert (merge-pathnames "worker/node.crt" path))
           (ca (merge-pathnames "worker/ca.crt" path)))
      (unwind-protect
           (progn
             (signals error
               (gr8s.agent::enroll-node-over-grpc
                "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server) "tls-worker" token
                (make-string 64 :initial-element #\0) key cert ca))
             (signals gr8s.model::kubernetes-error (gr8s.controllers::get-node store "tls-worker"))
             ;; The same token still works: it never crossed the rejected TLS connection.
             (gr8s.agent::enroll-node-over-grpc
              "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server) "tls-worker" token
              (gr8s.security::cluster-pki-ca-fingerprint pki) key cert ca)
             (is (probe-file cert))
             (let ((port (gr8s.apiserver::node-grpc-server-port server)))
               (signals error
                 (gr8s.agent::run-node-session
                  "127.0.0.1" port "tls-worker" (merge-pathnames "no-cert.json" path)
                  (lambda (snapshot) (declare (ignore snapshot)) (fail "Unauthenticated snapshot"))
                  :ca-certificate-path ca :max-sessions 1))
               (is-false (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "tls-worker")))
               (signals error
                 (gr8s.agent::run-node-session
                  "127.0.0.1" port "other-worker" (merge-pathnames "wrong-name.json" path)
                  (lambda (snapshot) (declare (ignore snapshot)) (fail "Mismatched certificate snapshot"))
                  :ca-certificate-path ca :certificate-path cert :private-key-path key :max-sessions 1))
               (is-false (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "tls-worker")))
               (gr8s.apiserver::publish-node-desired-state server "tls-worker" (empty-desired-snapshot))
               (gr8s.agent::run-node-session
                "127.0.0.1" port "tls-worker" (merge-pathnames "good-identity.json" path)
                (lambda (snapshot) (declare (ignore snapshot)))
                :ca-certificate-path ca :certificate-path cert :private-key-path key :max-sessions 1)
               (is (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "tls-worker")))))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test node-runtime-outage-makes-the-node-not-ready-without-dropping-its-lease
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-runtime" :name "worker-a"
                                  :pod-cidr "10.88.7.0/24"))
    (let ((server (gr8s.apiserver::%make-node-grpc-server
                   :store store :port 0 :heartbeat-timeout-seconds 5
                   :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24)))
      (flet ((heartbeat (message)
               (let ((envelope (make-instance 'gr8s.node.v1::agent-envelope
                                              :protocol-version gr8s.protocol::+node-protocol-version+
                                              :heartbeat (make-instance 'gr8s.node.v1::heartbeat
                                                                        :runtime-down-message message))))
                 (setf (gr8s.node.v1::payload-case envelope) :heartbeat)
                 ;; Through the wire, as the agent sends it.
                 (gr8s.apiserver::handle-node-agent-envelope
                  server "worker-a"
                  (ag-proto:deserialize-from-bytes 'gr8s.node.v1::agent-envelope
                                                   (ag-proto:serialize-to-bytes envelope)))))
             (ready-condition ()
               (aref (gethash "conditions" (gethash "status" (gr8s.resources::node-api-object (gr8s.controllers::get-node store "worker-a")))) 0)))
        (heartbeat "")
        (is (string= "True" (gethash "status" (ready-condition))))
        (heartbeat "container runtime is down: managed containerd exited (exit status 2)")
        (let ((node (gr8s.controllers::get-node store "worker-a")))
          (is (gr8s.model::node-record-ready-p node))
          (is (not (gr8s.model::node-record-runtime-ready-p node))))
        (is (string= "False" (gethash "status" (ready-condition))))
        (is (string= "KubeletNotReady" (gethash "reason" (ready-condition))))
        (is (search "container runtime is down" (gethash "message" (ready-condition))))
        (heartbeat "")
        (is (string= "True" (gethash "status" (ready-condition))))
        (is (gr8s.model::node-record-runtime-ready-p (gr8s.controllers::get-node store "worker-a")))))))
(defun delta-test-assignment (name &key (version "1") (body "a") deleting objects)
  (make-instance 'gr8s.node.v1::pod-assignment
                 :namespace "default" :name name :uid (format nil "uid-~A" name)
                 :resource-version version :deleting deleting
                 :pod-json (trivial-utf-8:string-to-utf-8-bytes (format nil "{\"name\":\"~A\",\"body\":\"~A\"}" name body))
                 :resource-objects-json (mapcar #'trivial-utf-8:string-to-utf-8-bytes objects)))

(defun delta-test-snapshot
    (revision pods &optional (discovery '("svc-a"))
                            (grant (make-array 0 :element-type '(unsigned-byte 8)))
                            receivers)
  (make-instance 'gr8s.node.v1::desired-state-snapshot
                 :revision revision
                 :network (make-instance 'gr8s.node.v1::node-network-config :node-pod-cidr "10.88.3.0/24")
                 :service-discovery-objects-json (mapcar #'trivial-utf-8:string-to-utf-8-bytes discovery)
                 :service-risk-grant-digest grant
                 :service-receivers receivers
                 :pods (sort (copy-list pods) #'string< :key #'gr8s.agent::pod-assignment-sort-key)))

;; podster-uqb.139: a change sends what changed, and the agent rebuilds exactly
;; the snapshot the server holds.
(test desired-state-deltas-rebuild-the-servers-snapshot
  (let* ((receiver (make-instance 'gr8s.node.v1::service-receiver-proof
                                  :pod-uid "pod-a"
                                  :incarnation (make-array 16 :element-type '(unsigned-byte 8)
                                                           :initial-element 3)))
         (base (delta-test-snapshot 4 (list (delta-test-assignment "kept")
                                            (delta-test-assignment "changed")
                                            (delta-test-assignment "objects" :objects '("{\"cm\":1}"))
                                            (delta-test-assignment "removed"))))
         (next (delta-test-snapshot 5 (list (delta-test-assignment "kept")
                                            (delta-test-assignment "changed" :version "2" :body "b")
                                            (delta-test-assignment "objects" :objects '("{\"cm\":2}"))
                                            (delta-test-assignment "added")
                                            (delta-test-assignment "aardvark" :deleting t))
                                    '("svc-a")
                                    (make-array 32 :element-type '(unsigned-byte 8)
                                                :initial-element 7)
                                    (list receiver)))
         (later (delta-test-snapshot 6 (slot-value next 'gr8s.node.v1::pods)
                                     '("svc-a" "svc-b")
                                     (make-array 0 :element-type '(unsigned-byte 8))
                                     (list receiver)))
         (delta (gr8s.apiserver::node-snapshot-delta base next))
         (agent (gr8s.agent::make-agent-node-session nil)))
    (is (= 4 (slot-value delta 'gr8s.node.v1::base-revision)))
    (is (equal '("uid-aardvark" "uid-added" "uid-changed" "uid-objects")
               (sort (mapcar (lambda (pod) (slot-value pod 'gr8s.node.v1::uid)) (slot-value delta 'gr8s.node.v1::pods))
                     #'string<)))
    (is (equal '("uid-removed") (slot-value delta 'gr8s.node.v1::removed-pod-uids)))
    (is-false (slot-value delta 'gr8s.node.v1::service-discovery-changed))
    (is (equalp (slot-value next 'gr8s.node.v1::service-risk-grant-digest)
                (slot-value delta 'gr8s.node.v1::service-risk-grant-digest)))
    (is (null (slot-value delta 'gr8s.node.v1::service-discovery-objects-json)))
    ;; Over the wire, as the agent receives them.
    (flet ((wire (snapshot)
             (ag-proto:deserialize-from-bytes 'gr8s.node.v1::desired-state-snapshot
                                              (ag-proto:serialize-to-bytes snapshot))))
      (is (eq (gr8s.agent::assemble-node-snapshot agent (wire base)) (gr8s.agent::agent-node-session-received agent)))
      (is (equalp (ag-proto:serialize-to-bytes next)
                  (ag-proto:serialize-to-bytes (gr8s.agent::assemble-node-snapshot agent (wire delta)))))
      (let ((discovery (gr8s.apiserver::node-snapshot-delta next later)))
        (is (null (slot-value discovery 'gr8s.node.v1::pods)))
        (is-true (slot-value discovery 'gr8s.node.v1::service-discovery-changed))
        (is (equalp (ag-proto:serialize-to-bytes later)
                    (ag-proto:serialize-to-bytes (gr8s.agent::assemble-node-snapshot agent (wire discovery))))))
      ;; A delta that does not follow what this session received is refused.
      (signals error (gr8s.agent::assemble-node-snapshot agent (wire delta)))
      (signals error (gr8s.agent::assemble-node-snapshot (gr8s.agent::make-agent-node-session nil) (wire delta))))))

(test service-grant-alone-changes-snapshot-revision-content
  (let* ((base (delta-test-snapshot 4 nil))
         (grant (make-array 32 :element-type '(unsigned-byte 8)
                            :initial-element 9))
         (granted (delta-test-snapshot 5 nil '("svc-a") grant))
         (delta (gr8s.apiserver::node-snapshot-delta base granted)))
    (is-false (gr8s.apiserver::same-node-desired-content-p base granted))
    (is-false (slot-value delta 'gr8s.node.v1::service-discovery-changed))
    (is (equalp grant (slot-value delta 'gr8s.node.v1::service-risk-grant-digest)))))

(test persistent-agent-applies-deltas-and-resyncs-after-reconnecting
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-delta" :name "worker-delta" :pod-cidr "10.88.3.0/24"))
    (let* ((server (gr8s.apiserver::start-node-grpc-server
                    store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2))
           (identity (merge-pathnames "agent/identity.json" path))
           (applied nil) (lock (bt:make-lock)) (control nil) (agent-thread nil)
           (deltas 0) (delta-function (symbol-function 'gr8s.apiserver::node-snapshot-delta)))
      (labels ((start-agent ()
                 (setf control (gr8s.agent::make-node-session-control)
                       agent-thread
                       (bt:make-thread
                        (lambda ()
                          (gr8s.agent::run-node-session
                           "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server) "worker-delta" identity
                           (lambda (snapshot) (bt:with-lock-held (lock) (setf applied snapshot)))
                           :reconnect-delay 0.01 :control control))
                        :name "gr8s delta test agent")))
               (stop-agent ()
                 (gr8s.agent::cancel-node-session control)
                 (bt:join-thread agent-thread))
               (session ()
                 (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                   (gethash "worker-delta" (gr8s.apiserver::node-grpc-server-sessions server))))
               (publish (revision pods)
                 (declare (ignore revision))
                 (gr8s.apiserver::publish-node-desired-state server "worker-delta" (delta-test-snapshot 0 pods)))
               (converged-p ()
                 (let ((current (gr8s.apiserver::current-node-snapshot server "worker-delta")))
                   (bt:with-lock-held (lock)
                     (and applied (= (slot-value applied 'gr8s.node.v1::revision)
                                     (slot-value current 'gr8s.node.v1::revision))
                          (equalp (mapcar #'ag-proto:serialize-to-bytes (slot-value applied 'gr8s.node.v1::pods))
                                  (mapcar #'ag-proto:serialize-to-bytes (slot-value current 'gr8s.node.v1::pods)))
                          (equalp (slot-value applied 'gr8s.node.v1::service-discovery-objects-json)
                                  (slot-value current 'gr8s.node.v1::service-discovery-objects-json)))))))
        ;; Count the deltas the server actually sends.
        (setf (symbol-function 'gr8s.apiserver::node-snapshot-delta)
              (lambda (base snapshot) (incf deltas) (funcall delta-function base snapshot)))
        (unwind-protect
             (progn
               (publish 1 (list (delta-test-assignment "a") (delta-test-assignment "b")))
               (start-agent)
               (is-true (wait-until #'converged-p :timeout 5))
               (is-true (gr8s.apiserver::node-agent-session-deltas-p (session)))
               (publish 2 (list (delta-test-assignment "a" :version "2") (delta-test-assignment "c")))
               (is-true (wait-until #'converged-p :timeout 5))
               (publish 3 (list (delta-test-assignment "c")))
               (is-true (wait-until #'converged-p :timeout 5))
               ;; Changes made while no session is open arrive as a complete snapshot.
               (stop-agent)
               (publish 4 (list (delta-test-assignment "c" :version "2") (delta-test-assignment "d")))
               (start-agent)
               (is-true (wait-until #'converged-p :timeout 5))
               (publish 5 (list (delta-test-assignment "d")))
               (is-true (wait-until #'converged-p :timeout 5))
               ;; Revisions 2, 3 and 5 followed one the session had delivered.
               (is (= 3 deltas)))
          (setf (symbol-function 'gr8s.apiserver::node-snapshot-delta) delta-function)
          (ignore-errors (stop-agent))
          (gr8s.apiserver::stop-node-grpc-server server))))))

(test vxlan-peer-routes-survive-agent-lease-expiry
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((now 4000000000))
      (dotimes (index 2)
        (gr8s.controllers::register-node
         store (gr8s.model::make-node-record :id (format nil "vxlan-~D" index)
                                      :name (format nil "worker-~D" index)
                                      :pod-cidr (format nil "10.88.~D.0/24" index)
                                      :underlay-address (format nil "192.0.2.~D" (+ index 10))))
        (gr8s.controllers::mark-node-ready store (format nil "worker-~D" index) now
                              :lease-duration (if (zerop index) 1000 1)))
      (let* ((server (gr8s.apiserver::%make-node-grpc-server
                      :store store :overlay-backend "vxlan" :clock (lambda () now)
                      :gateway-stability-seconds 30 :heartbeat-timeout-seconds 15))
             (before (gr8s.apiserver::assigned-node-routes server "worker-0")))
        (is (= 1 (length before)))
        (incf now 2)
        (gr8s.apiserver::reconcile-node-heartbeats server now)
        ;; Readiness still expires for scheduling and endpoint selection.
        ;; Existing Pod traffic must retain the authenticated direct peer.
        (is-false (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "worker-1")))
        (let ((after (gr8s.apiserver::assigned-node-routes server "worker-0")))
          (is (= 1 (length after)))
          (when after
            (is (string= "worker-1" (slot-value (first after) 'gr8s.node.v1::node-name)))
            (is (string= "10.88.1.0/24" (slot-value (first after) 'gr8s.node.v1::pod-cidr)))
            (is (string= "192.0.2.11" (slot-value (first after) 'gr8s.node.v1::underlay-address)))
            (is-false (slot-value (first after) 'gr8s.node.v1::next-hop))))))))

(test node-listener-caps-connections-per-source-ip
  "The node control-plane listener bounds concurrent connections per source
   address, so one unauthenticated peer cannot open connections up to the global
   pool limit and starve every other node during the pre-handshake window.
   The cap itself is enforced and tested in ag-grpc; here we verify gr8s wires a
   sane default through and honours an explicit override. 83n.11 / spot-check N2."
  (with-temporary-store (store path)
    (flet ((listener-cap (server)
             (ag-grpc::server-max-connections-per-ip
              (gr8s.apiserver::node-grpc-server-grpc-server server))))
      ;; Default: a per-source cap well below ag-grpc's 128-connection pool.
      (let ((server (gr8s.apiserver::start-node-grpc-server
                     store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2)))
        (unwind-protect
             (is (= gr8s.apiserver::+default-node-max-connections-per-ip+
                    (listener-cap server)))
          (gr8s.apiserver::stop-node-grpc-server server)))
      ;; An explicit cap threads through to the underlying gRPC server.
      (let ((server (gr8s.apiserver::start-node-grpc-server
                     store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2
                     :max-connections-per-ip 4)))
        (unwind-protect
             (is (= 4 (listener-cap server)))
          (gr8s.apiserver::stop-node-grpc-server server)))
      ;; NIL opts out of the per-source cap for deliberately trusted deployments.
      (let ((server (gr8s.apiserver::start-node-grpc-server
                     store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2
                     :max-connections-per-ip nil)))
        (unwind-protect
             (is-false (listener-cap server))
          (gr8s.apiserver::stop-node-grpc-server server))))))

(test forged-peer-observation-cannot-redirect-another-nodes-relay-source
  "N1 regression (podster-83n.1): an authenticated node's self-asserted
   observation about a PEER must never redirect that peer's relay source. The
   relay is the sole authority on a node's source and learns it first-hand from
   the node's own traffic; a cross-node observation is only a data-path candidate
   hint that agents re-gate with their own WireGuard handshake probe."
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((key-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21))
           (key-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 22))
           (relay (gr8s.network::start-wireguard-relay-server
                   :address "127.0.0.1" :port-start 48000 :max-channels 1)))
      (unwind-protect
           (progn
             (gr8s.controllers::register-node
              store (gr8s.model::make-node-record
                     :id "node-a" :name "worker-a" :pod-cidr "10.88.1.0/24"
                     :underlay-address "192.0.2.10" :wireguard-public-key key-a
                     :wireguard-endpoints '(("nat-reflexive" "198.51.100.10" 41000))))
             (gr8s.controllers::register-node
              store (gr8s.model::make-node-record
                     :id "node-b" :name "worker-b" :pod-cidr "10.88.2.0/24"
                     :underlay-address "192.0.2.11" :wireguard-public-key key-b
                     :wireguard-endpoints '(("nat-reflexive" "198.51.100.11" 41001))))
             (let* ((server (gr8s.apiserver::%make-node-grpc-server
                             :store store :port 0 :heartbeat-timeout-seconds 5
                             :cluster-pod-cidr "10.88.0.0/16" :node-prefix 24
                             :overlay-backend "wireguard" :wireguard-listen-port 51820
                             :wireguard-relay-server relay
                             :wireguard-relay-address "203.0.113.9"))
                    (coord (gr8s.network::wireguard-relay-server-coordinator relay))
                    (channel (gr8s.network::ensure-wireguard-relay-channel
                              coord "worker-b" "worker-a" 1000)))
               ;; worker-b establishes a live relay session: the relay learns its
               ;; real source first-hand from worker-b's own traffic.
               (is-true (gr8s.network::note-wireguard-relay-source
                         coord channel "worker-b" "198.51.100.11" 41001 1000))
               ;; ATTACK: authenticated worker-a forges an observation claiming
               ;; worker-b's reflexive endpoint is an attacker-chosen address.
               (gr8s.apiserver::record-authenticated-wireguard-observations
                server "worker-a"
                (list (make-instance 'gr8s.node.v1::wireguard-peer-observation
                                     :peer-public-key key-b
                                     :address "203.0.113.66" :port 41999
                                     :latest-handshake-unix-seconds 999
                                     :received-bytes 100))
                :now 1000 :fresh-seconds 180)
               ;; The relay source for worker-b is UNCHANGED: the observation can
               ;; no longer redirect it (the N1 poisoning is gone).
               (is (equal '("198.51.100.11" . 41001)
                          (gethash "worker-b"
                                   (gr8s.network::wireguard-relay-channel-sources
                                    channel))))
               ;; And a datagram claiming to be worker-b from the attacker address
               ;; is rejected while the genuine source is live (sticky damping).
               (is-false (gr8s.network::note-wireguard-relay-source
                          coord channel "worker-b" "203.0.113.66" 41999 1005))
               ;; The observation is still honoured as a data-path candidate hint
               ;; (downstream-re-gated by the peer's own handshake probe), so NAT
               ;; reflexive-endpoint discovery keeps working.
               (is (string= "203.0.113.66"
                            (second (find "nat-reflexive"
                                          (gr8s.model::node-record-wireguard-endpoints
                                           (gr8s.controllers::get-node store "worker-b"))
                                          :key #'first :test #'string=))))))
        (gr8s.network::stop-wireguard-relay-server relay)))))

;;; podster-cm3: over a tunneled underlay (WireGuard, 1420) the fixed overlay
;;; MTU of 1450 overflows and fragments every full-size frame. serve --mtu
;;; makes the assigned Pod MTU explicit; the defaults stay as they were.

(test assigned-node-network-mtu-is-configurable-for-tunneled-underlays
  (with-temporary-store (store path)
    (declare (ignorable path))
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record
            :id "n1" :name "n1" :pod-cidr "10.88.1.0/24"
            :underlay-address "10.77.77.20"))
    (flet ((assigned-mtu (&rest args)
             (slot-value
              (gr8s.apiserver::assigned-node-network
               (apply #'gr8s.apiserver::%make-node-grpc-server :store store
                      :cluster-pod-cidr "10.88.0.0/16"
                      :cluster-pod-cidrs '("10.88.0.0/16") args)
               "n1")
              'gr8s.node.v1::mtu)))
      (is (= 1450 (assigned-mtu)) "the vxlan default is unchanged")
      (is (= 1420 (assigned-mtu :overlay-backend "wireguard"))
          "the wireguard-backend default is unchanged")
      (is (= 1370 (assigned-mtu :mtu 1370))
          "an explicit MTU reaches the node network config")
      (is (= 1370 (assigned-mtu :mtu 1370 :overlay-backend "wireguard"))
          "an explicit MTU overrides either backend's default"))))

;;; podster-ddc: a protocol-error carries the server's explanation, but the
;;; handshake's payload check used to discard it and log only ":PROTOCOL-ERROR"
;;; -- root-causing a session refusal took live-image surgery. The mismatch
;;; error must quote the peer's own message.

(test envelope-payload-mismatch-reports-the-peers-explanation
  (let ((envelope (gr8s.protocol::make-server-envelope
                   :protocol-error
                   (make-instance 'gr8s.node.v1::protocol-error
                                  :supported-version 1 :received-version 1
                                  :message "Conflict: Node changed before its consensus transaction committed")
                   :sequence 1)))
    (handler-case
        (progn (gr8s.apiserver::node-envelope-payload envelope :hello)
               (fail "a payload mismatch must signal"))
      (error (condition)
        (let ((text (princ-to-string condition)))
          (is (search "the peer reported" text))
          (is (search "Node changed before its consensus transaction" text)
              "the server's explanation survives into the client error")))))
  (let ((envelope (gr8s.protocol::make-server-envelope
                   :hello (make-instance 'gr8s.node.v1::server-hello) :sequence 1)))
    (handler-case
        (progn (gr8s.apiserver::node-envelope-payload envelope :desired-state)
               (fail "a payload mismatch must signal"))
      (error (condition)
        (is (search "HELLO" (princ-to-string condition))
            "other mismatches keep naming the payload case")))
    (finishes (gr8s.apiserver::node-envelope-payload envelope :hello))))

;;; podster-ao6: after a suspend the agent wrote heartbeats into a dead TCP
;;; connection for 2m22s before EOF surfaced -- buffered sends count as
;;; "success" until the kernel's retransmission patience runs out. Every node
;;; channel now bounds dead-peer detection with TCP_USER_TIMEOUT and
;;; keep-alive probes, verified here against the kernel with getsockopt.

(test node-channels-bound-dead-peer-detection
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener)))
    (unwind-protect
         (let ((socket (usocket:socket-connect "127.0.0.1" port
                                               :element-type '(unsigned-byte 8))))
           (unwind-protect
                (progn
                  (is (eq socket (gr8s.security::harden-node-channel-socket socket))
                      "hardening returns the socket for inline use")
                  (let ((fd (sb-bsd-sockets:socket-file-descriptor (usocket:socket socket))))
                    (flet ((option (level name)
                             (cffi:with-foreign-objects ((value :int) (len :unsigned-int))
                               (setf (cffi:mem-ref value :int) 0
                                     (cffi:mem-ref len :unsigned-int) 4)
                               (cffi:foreign-funcall "getsockopt" :int fd :int level :int name
                                                     :pointer value :pointer len :int)
                               (cffi:mem-ref value :int))))
                      (is (= (* 1000 gr8s.security::+node-channel-dead-peer-timeout-seconds+)
                             (option 6 18))
                          "TCP_USER_TIMEOUT bounds unacknowledged sends")
                      (is (plusp (option 1 9)) "SO_KEEPALIVE probes idle connections")
                      (is (= 5 (option 6 4)) "keep-alive idle threshold")
                      (is (= 3 (option 6 6)) "keep-alive probe count"))))
             (usocket:socket-close socket)))
      (usocket:socket-close listener))))

(test socket-hardening-tolerates-unsupported-sockets
  ;; Best-effort by contract: a closed or odd socket must not signal.
  (finishes (gr8s.security::harden-node-channel-socket nil)))

(test follower-rejects-node-connect-before-applying-a-snapshot
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-follower" :name "worker-follower"
                                       :pod-cidr "10.88.3.0/24"))
    (let ((server (gr8s.apiserver::start-node-grpc-server
                   store :port 0 :session-admission-fn (constantly nil)))
          (applied nil))
      (unwind-protect
           (progn
             (signals error
               (gr8s.agent::run-node-session
                "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                "worker-follower" (merge-pathnames "agent/identity.json" path)
                (lambda (snapshot) (declare (ignore snapshot)) (setf applied t))
                :max-sessions 1))
             (is (null applied)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test demotion-evicts-live-node-session-and-reconnect-replays-snapshot
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-demoted" :name "worker-demoted"
                                       :pod-cidr "10.88.3.0/24"))
    (gwc-seed store)
    (let* ((leader-p t)
           (server (gr8s.apiserver::start-node-grpc-server
                    store :port 0 :session-admission-fn (lambda () leader-p)))
           (control (gr8s.agent::make-node-session-control))
           (applied nil)
           (agent nil))
      (unwind-protect
           (labels ((session ()
                      (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
                        (gethash "worker-demoted" (gr8s.apiserver::node-grpc-server-sessions server)))))
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                       "worker-demoted" (merge-pathnames "agent/identity.json" path)
                       (lambda (snapshot) (push snapshot applied))
                       :control control :reconnect-delay 0.1))))
             (is-true (wait-until (lambda () (and (session) applied)) :timeout 5))
             (let ((old (session)))
               (setf leader-p nil)
               (is-true (wait-until (lambda () (gr8s.apiserver::node-agent-session-evicted-p old))
                                   :timeout 2))
               (is-true (wait-until (lambda () (null (session))) :timeout 2))
               (change-published-route-host store "after-demotion.example.com")
               (setf leader-p t)
               (is-true (wait-until (lambda () (and (session) (not (eq old (session)))
                                                   (>= (length applied) 2))) :timeout 5))
               (let* ((entries (mapcar #'gr8s.kubelet::decode-service-discovery-entry
                                      (slot-value (first applied) 'gr8s.node.v1::service-discovery-objects-json)))
                      (route (cdr (assoc '("httproutes" "default" "app") entries :test #'equal))))
                 (is (equalp #("after-demotion.example.com") (gethash "hostnames" (gethash "spec" route)))))
               ;; Later edits must also reach the reconnected stream.
               (change-published-route-host store "after-reconnect.example.com")
               (gr8s.controllers::publish-node-snapshot
                (gr8s.controllers::make-control-plane-runtime store server) "worker-demoted")
               (is-true (wait-until (lambda () (>= (length applied) 3)) :timeout 5))
               (let* ((entries (mapcar #'gr8s.kubelet::decode-service-discovery-entry
                                      (slot-value (first applied) 'gr8s.node.v1::service-discovery-objects-json)))
                      (route (cdr (assoc '("httproutes" "default" "app") entries :test #'equal))))
                 (is (equalp #("after-reconnect.example.com") (gethash "hostnames" (gethash "spec" route)))))))
        (gr8s.agent::cancel-node-session control)
        (when agent (ignore-errors (bt:join-thread agent)))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test demotion-during-registration-fails-drained-node-operations
  (with-temporary-store (store path)
    (gr8s.controllers::register-node
     store (gr8s.model::make-node-record :id "node-race" :name "worker-race"
                                       :pod-cidr "10.88.3.0/24"))
    (let ((server nil) (checks 0) (operation nil))
      (setf server
            (gr8s.apiserver::start-node-grpc-server
             store :port 0
             :session-admission-fn
             (lambda ()
               ;; The heartbeat monitor must not consume handshake decisions.
               (or (null server)
                   (eq (bt:current-thread) (gr8s.apiserver::node-grpc-server-monitor-thread server))
                   (< (incf checks) 3)))))
      (unwind-protect
           (progn
             (setf operation
                   (gr8s.apiserver::queue-node-operation
                    server "worker-race"
                    (make-instance 'gr8s.node.v1::operation-request
                                   :operation-id "registration-race"
                                   :kind gr8s.node.v1::+operationkind-operation_kind_exec+)))
             (signals error
               (gr8s.agent::run-node-session
                "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server)
                "worker-race" (merge-pathnames "agent/identity.json" path)
                (lambda (snapshot) (declare (ignore snapshot))) :max-sessions 1))
             (is (= 3 checks))
             (is-true (wait-until (lambda () (gr8s.apiserver::pending-node-operation-done-p operation))
                                 :timeout 1))
             (is (equal "Node disconnected" (gr8s.apiserver::pending-node-operation-error operation))))
        (when operation (gr8s.apiserver::release-node-operation server operation))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(defun make-routed-test-operation (server operation-id)
  "Register a shadow operation that member \"origin\" started on node \"worker\"."
  (let ((operation (gr8s.apiserver::make-pending-node-operation
                    "worker" (make-instance 'gr8s.node.v1::operation-request
                                            :operation-id operation-id
                                            :kind gr8s.node.v1::+operationkind-operation_kind_exec+))))
    (setf (gr8s.apiserver::pending-node-operation-origin-member operation) "origin")
    (bt:with-lock-held ((gr8s.apiserver::node-grpc-server-lock server))
      (setf (gethash operation-id (gr8s.apiserver::node-grpc-server-operations server)) operation))
    operation))

(defun routed-test-stream (operation-id sequence text)
  (make-instance 'gr8s.node.v1::operation-stream
                 :operation-id operation-id :sequence sequence
                 :channel gr8s.node.v1::+streamchannel-stream_channel_stdout+
                 :data (trivial-utf-8:string-to-utf-8-bytes text)))

(defun routed-test-response (operation-id)
  (make-instance 'gr8s.node.v1::operation-response
                 :operation-id operation-id
                 :status gr8s.node.v1::+operationstatus-operation_status_complete+))

(test a-slow-origin-member-does-not-hold-up-the-agent-session
  ;; Relaying a frame took an RPC inside the agent's envelope loop, so a busy flow stream
  ;; held back every node's heartbeats until their leases expired (podster-8kl).
  (let* ((server (gr8s.apiserver::%make-node-grpc-server))
         (operation (make-routed-test-operation server "routed-slow"))
         (gate (bt:make-lock)) (open nil) (opened (bt:make-condition-variable))
         (seen nil) (targets nil) (seen-lock (bt:make-lock)))
    (setf (gr8s.apiserver::node-grpc-server-operation-router server)
          (lambda (variant target-member node-name payload)
            (bt:with-lock-held (seen-lock) (push (list target-member node-name) targets))
            (bt:with-lock-held (gate)
              (loop until open do (bt:condition-wait opened gate :timeout 0.1)))
            (bt:with-lock-held (seen-lock)
              (push (if (eq variant :operation-stream)
                        (trivial-utf-8:utf-8-bytes-to-string (slot-value payload 'gr8s.node.v1::data))
                        variant)
                    seen))
            "origin"))
    (unwind-protect
         (let ((start (get-internal-real-time)))
           (dolist (text '("one" "two" "three"))
             (gr8s.apiserver::note-node-operation-stream
              server "worker" (routed-test-stream "routed-slow" 1 text)))
           (gr8s.apiserver::note-node-operation-response server "worker" (routed-test-response "routed-slow"))
           (is (< (- (get-internal-real-time) start) (* 0.5 internal-time-units-per-second)))
           (bt:with-lock-held (gate) (setf open t) (bt:condition-notify opened))
           ;; In the agent's order, and the response releases the operation once it is sent.
           (is-true (wait-until (lambda () (bt:with-lock-held (seen-lock) (= 4 (length seen)))) :timeout 5))
           (is (equal '("one" "two" "three" :operation-response) (reverse seen)))
           (is (every (lambda (target) (equal '("origin" "worker") target)) targets))
           (is-true (wait-until (lambda () (null (gr8s.apiserver::find-node-operation server "routed-slow")))
                                :timeout 5))
           (is-false (gr8s.apiserver::pending-node-operation-done-p operation)))
      (bt:with-lock-held (gate) (setf open t) (bt:condition-notify opened))
      (setf (gr8s.apiserver::node-grpc-server-stopping-p server) t))))

(test routed-output-that-cannot-reach-its-origin-fails-the-operation
  (let* ((server (gr8s.apiserver::%make-node-grpc-server))
         (lost (make-routed-test-operation server "routed-lost"))
         (seen nil) (seen-lock (bt:make-lock)))
    (setf (gr8s.apiserver::node-grpc-server-operation-router server)
          (lambda (variant target-member node-name payload)
            (declare (ignore target-member node-name))
            (let ((text (and (eq variant :operation-stream)
                             (trivial-utf-8:utf-8-bytes-to-string (slot-value payload 'gr8s.node.v1::data)))))
              (bt:with-lock-held (seen-lock) (push (or text variant) seen))
              ;; The first frame is lost.
              (and (not (equal text "one")) "origin"))))
    (unwind-protect
         (progn
           (dolist (text '("one" "two"))
             (gr8s.apiserver::note-node-operation-stream server "worker" (routed-test-stream "routed-lost" 1 text)))
           (gr8s.apiserver::note-node-operation-response server "worker" (routed-test-response "routed-lost"))
           (is-true (wait-until (lambda () (null (gr8s.apiserver::find-node-operation server "routed-lost")))
                                :timeout 5))
           ;; Output after a lost frame means nothing to its reader; the end still goes.
           (is (equal '("one" :operation-response) (bt:with-lock-held (seen-lock) (reverse seen))))
           (is (equal "Operation origin is unavailable" (gr8s.apiserver::pending-node-operation-error lost))))
      (setf (gr8s.apiserver::node-grpc-server-stopping-p server) t))))

(test routed-output-past-the-outbox-limit-fails-its-operation
  (let* ((server (gr8s.apiserver::%make-node-grpc-server))
         (operation (make-routed-test-operation server "routed-full"))
         (gate (bt:make-lock)) (open nil)
         (seen nil) (seen-lock (bt:make-lock)))
    (setf (gr8s.apiserver::node-grpc-server-operation-router server)
          (lambda (variant target-member node-name payload)
            (declare (ignore target-member node-name payload))
            (loop until (bt:with-lock-held (gate) open) do (sleep 0.01))
            (bt:with-lock-held (seen-lock) (push variant seen))
            "origin"))
    (unwind-protect
         (let ((gr8s.apiserver::*routed-outbox-limit-bytes* 10))
           ;; The sender may already hold the first frame; the later ones overflow.
           (dolist (text '("0123456789" "0123456789" "0123456789"))
             (gr8s.apiserver::note-node-operation-stream server "worker" (routed-test-stream "routed-full" 1 text)))
           (is (search "not keeping up" (gr8s.apiserver::pending-node-operation-error operation)))
           (gr8s.apiserver::note-node-operation-response server "worker" (routed-test-response "routed-full"))
           (bt:with-lock-held (gate) (setf open t))
           (is-true (wait-until (lambda () (null (gr8s.apiserver::find-node-operation server "routed-full")))
                                :timeout 5))
           (is (eq :operation-response (bt:with-lock-held (seen-lock) (first seen))))
           (is (<= (bt:with-lock-held (seen-lock) (count :operation-stream seen)) 2)))
      (bt:with-lock-held (gate) (setf open t))
      (setf (gr8s.apiserver::node-grpc-server-stopping-p server) t))))

(defun tcp-nodelay-p (socket)
  "Whether SOCKET, a usocket, sends its writes at once."
  (cffi:with-foreign-objects ((value :int) (size :unsigned-int))
    (setf (cffi:mem-ref size :unsigned-int) 4)
    (cffi:foreign-funcall "getsockopt" :int (sb-bsd-sockets:socket-file-descriptor (usocket:socket socket))
                          :int 6 :int 1 :pointer value :pointer size :int)
    (= 1 (cffi:mem-ref value :int))))

(test node-and-member-channels-send-their-writes-at-once
  ;; podster-1wk: Nagle and delayed ACKs cost every relayed gRPC call about 45ms.
  (let ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8))))
    (unwind-protect
         (progn
           (is-false (tcp-nodelay-p listener))
           (gr8s.security::set-tcp-nodelay listener)
           (is-true (tcp-nodelay-p listener))
           (let* ((client (gr8s.security::harden-node-channel-socket
                           (usocket:socket-connect "127.0.0.1" (usocket:get-local-port listener)
                                                   :element-type '(unsigned-byte 8))))
                  (accepted (usocket:socket-accept listener)))
             (unwind-protect
                  (progn (is-true (tcp-nodelay-p client))
                         ;; An accepted connection inherits its listener's.
                         (is-true (tcp-nodelay-p accepted)))
               (usocket:socket-close accepted)
               (usocket:socket-close client))))
      (usocket:socket-close listener)))
  (with-temporary-store (store path)
    (declare (ignore path))
    (let ((server (gr8s.apiserver::start-node-grpc-server store :host "127.0.0.1" :port 0)))
      (unwind-protect
           (is-true (tcp-nodelay-p (ag-grpc::server-socket (gr8s.apiserver::node-grpc-server-grpc-server server))))
        (gr8s.apiserver::stop-node-grpc-server server))))
  (let ((member (gr8s.raft.transport::start-raft-member "nodelay" :port 0)))
    (unwind-protect
         (is-true (tcp-nodelay-p (ag-grpc::server-socket (gr8s.raft.transport::raft-member-grpc-server member))))
      (gr8s.raft.transport::stop-raft-member member))))
