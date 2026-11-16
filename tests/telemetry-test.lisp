(in-package #:gr8s/tests)
(in-suite gr8s)

(test endpoint-telemetry-preserves-ipam-identity-and-reports-map-read-failures
  (with-temporary-store (store path)
    (assert store)
    (let* ((manager (gr8s.kubelet::make-managed-containerd
                     :state-directory path :executable "/unused/containerd"
                     :oci-runtime "/unused/runc" :cni-bin-directory "/unused/"))
           (runtime (gr8s.agent::make-node-runtime path (make-fake-runtime) manager
                                            :network-reconciler nil)))
      (gr8s.agent::configure-node-runtime-network runtime (gr8s.agent::node-network-object (node-network-for-test)))
      (gr8s.network::allocate-pod-address (gr8s.agent::node-runtime-ipam runtime) "sandbox-telemetry" "eth0")
      (let* ((status (gr8s.agent::node-runtime-status
                      runtime :counter-reader
                      (lambda (root sandbox)
                        (is (search "containerd/bpf" root))
                        (is (string= "sandbox-telemetry" sandbox))
                        (gr8s.foundation::json-object "allowedPackets" 42 "droppedPackets" 3 "rejectedSpoofs" 2
                                                      "policyDrops" 5))))
             (endpoint (first (slot-value status 'gr8s.node.v1::endpoints))))
        (is (string= "10.88.8.1" (slot-value endpoint 'gr8s.node.v1::pod-ip)))
        (is (= 42 (slot-value endpoint 'gr8s.node.v1::allowed-packets)))
        (is (= 3 (slot-value endpoint 'gr8s.node.v1::dropped-packets)))
        (is (= 5 (slot-value endpoint 'gr8s.node.v1::policy-drops)) "policy drops reach the control plane")
        (is (= 2 (slot-value endpoint 'gr8s.node.v1::rejected-spoofs))))
      (let* ((status (gr8s.agent::node-runtime-status
                      runtime :counter-reader (lambda (&rest args)
                                                (declare (ignore args))
                                                (error "pinned map is unavailable"))))
             (endpoint (first (slot-value status 'gr8s.node.v1::endpoints))))
        (is (search "unavailable" (slot-value endpoint 'gr8s.node.v1::error-message)))))))

(test the-policy-drop-counter-is-read-from-its-pinned-map
  ;; Index 6 of traffic_stats is the guards' NetworkPolicy counter, which was never read.
  (let* ((reads nil) (closed nil)
         (counters (gr8s.network::read-cni-policy-counters
                    "/root" "sandbox"
                    :open-pinned (lambda (path) (declare (ignore path)) 99)
                    :map-info (lambda (fd name) (declare (ignore fd)) name)
                    :lookup (lambda (map index) (push (list map index) reads) (+ 100 index))
                    :close-fd (lambda (fd) (push fd closed)))))
    (is (= 106 (gethash "policyDrops" counters)))
    (is (= 102 (gethash "droppedPackets" counters)))
    (is (member '("traffic_stats" 6) reads :test #'equal))
    (is (equal '(99 99) closed) "both maps are closed")))

(test both-guard-directions-count-policy-drops-as-drops
  ;; Egress always did; ingress counted only the policy counter, so inbound
  ;; refusals were missing from dropped_packets.
  (labels ((policy-drop-sites (tree)
             (cond ((atom tree) 0)
                   ((equal tree '(whistler::drop-pod-packet :policy)) 1)
                   (t (reduce #'+ (mapcar #'policy-drop-sites tree)))))
           (bare-policy-counts (tree)
             (cond ((atom tree) 0)
                   ((equal tree '(whistler::add-pod-counter whistler::policy-drops 1)) 1)
                   (t (reduce #'+ (mapcar #'bare-policy-counts tree))))))
    (destructuring-bind (egress ingress) gr8s.network::*egress-guard-program-forms*
      (is (= 4 (policy-drop-sites egress)))
      (is (= 4 (policy-drop-sites ingress)))
      (is (zerop (bare-policy-counts ingress)) "no inbound refusal skips the general drop counters")))
  (finishes (gr8s.network::compile-egress-guard))
  (finishes (gr8s.network::compile-egress-guard :service-packets t)))

(test endpoint-counters-roundtrip-with-64-bit-values
  (let* ((message (make-instance 'gr8s.node.v1::node-status
                                 :endpoints (list (make-instance 'gr8s.node.v1::endpoint-telemetry
                                                                :sandbox-id "sandbox-a"
                                                                :allowed-bytes (ash 1 40)
                                                                :rejected-spoofs 9))))
         (restored (roundtrip-node-message message 'gr8s.node.v1::node-status))
         (endpoint (first (slot-value restored 'gr8s.node.v1::endpoints))))
    (is (= (ash 1 40) (slot-value endpoint 'gr8s.node.v1::allowed-bytes)))
    (is (= 9 (slot-value endpoint 'gr8s.node.v1::rejected-spoofs)))))

(test periodic-agent-status-updates-pods-and-http-metrics-without-new-desired-state
  (with-temporary-store (store path)
    (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "node-metrics" :name "worker-a"
                                                  :pod-cidr "10.88.1.0/24"))
    (let* ((node-server (gr8s.apiserver::start-node-grpc-server
                         store :host "127.0.0.1" :port 0 :heartbeat-timeout-seconds 2))
           (fake (make-fake-runtime))
           (node-runtime (gr8s.agent::make-node-runtime (merge-pathnames "agent/" path) fake nil))
           (control-runtime (gr8s.controllers::make-control-plane-runtime store node-server))
           (document (com.inuoe.jzon:parse *valid-pod-json*))
           (pod nil) (http nil) (agent nil)
           (control (gr8s.agent::make-node-session-control))
           (sample 7) (available t)
           (lock (bt:make-lock "metrics samples")))
      (setf (gethash "restartPolicy" (gethash "spec" document)) "Never"
            pod (create-pod store (parse-pod document)))
      (unwind-protect
           (progn
             (gr8s.agent::start-node-runtime node-runtime)
             (setf http (start-http-test-server :store store :runtime control-runtime))
             (setf agent
                   (bt:make-thread
                    (lambda ()
                      (gr8s.agent::run-node-session
                       "127.0.0.1" (gr8s.apiserver::node-grpc-server-port node-server) "worker-a"
                       (merge-pathnames "agent/identity.json" path)
                       (lambda (snapshot) (gr8s.agent::reconcile-node-snapshot node-runtime snapshot))
                       :status-provider
                       (lambda ()
                         (let ((status (gr8s.agent::node-runtime-status node-runtime)))
                           (bt:with-lock-held (lock)
                             (setf (slot-value status 'gr8s.node.v1::endpoints)
                                   (list (make-instance 'gr8s.node.v1::endpoint-telemetry
                                                        :sandbox-id "sandbox-metrics"
                                                        :interface-name "eth0" :pod-ip "10.88.1.1"
                                                        :allowed-packets sample
                                                        :policy-drops 4
                                                        :error-message (if available "" "map unavailable")))))
                           status))
                       :control control :reconnect-delay 0.01))))
             (is-true (wait-until (lambda () (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "worker-a")))
                                 :timeout 5))
             (runtime-ensure control-runtime pod)
             (is-true (wait-until (lambda () (string= "Running" (gr8s.controllers::pod-scheduling-phase store pod)))
                                 :timeout 5))
             (let ((revision (slot-value (gr8s.apiserver::current-node-snapshot node-server "worker-a")
                                         'gr8s.node.v1::revision)))
               (setf (runtime-pod-phase (runtime-observe fake (pod-uid pod))) "Succeeded"
                     (gr8s.runtime::runtime-pod-pod-ip (runtime-observe fake (pod-uid pod))) "10.88.1.1")
               (bt:with-lock-held (lock) (setf sample 12))
               (is-true (wait-until (lambda () (string= "Succeeded" (gr8s.controllers::pod-scheduling-phase store pod)))
                                   :timeout 5))
               (is (= revision (slot-value (gr8s.apiserver::current-node-snapshot node-server "worker-a")
                                           'gr8s.node.v1::revision)))
               (multiple-value-bind (body code) (request "/api/v1/namespaces/default/pods/hello")
                 (is (= 200 code))
                 (is (string= "10.88.1.1" (gethash "podIP" (gethash "status" (response-object body))))))
               (multiple-value-bind (body code headers) (request "/metrics")
                 (is (= 200 code))
                 (is (search "text/plain" (cdr (assoc :content-type headers))))
                 (is (search "gr8s_endpoint_allowed_packets_total{node=\"worker-a\",sandbox=\"sandbox-metrics\",interface=\"eth0\",pod_ip=\"10.88.1.1\"} 12" body))
                 (is (search "gr8s_endpoint_policy_drops_total{node=\"worker-a\",sandbox=\"sandbox-metrics\",interface=\"eth0\",pod_ip=\"10.88.1.1\"} 4" body)))
               (bt:with-lock-held (lock) (setf available nil))
               (is-true (wait-until
                         (lambda ()
                           (search "gr8s_endpoint_telemetry_available{node=\"worker-a\",sandbox=\"sandbox-metrics\",interface=\"eth0\",pod_ip=\"10.88.1.1\"} 0"
                                   (request "/metrics"))) :timeout 5))
               (is-false (search "gr8s_endpoint_allowed_packets_total" (request "/metrics")))))
        (gr8s.agent::cancel-node-session control)
        (when agent
          (unless (wait-until (lambda () (not (bt:thread-alive-p agent))) :timeout 3)
            (bt:destroy-thread agent))
          (ignore-errors (bt:join-thread agent)))
        (gr8s.agent::stop-node-runtime node-runtime)
        (when http (stop-server http))
        (gr8s.apiserver::stop-node-grpc-server node-server)))))
