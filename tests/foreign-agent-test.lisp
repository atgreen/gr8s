;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the foreign-cluster CNI agent end to end without privileges:
;;;; against gr8s's own API server it must find its Node's podCIDR, serve a CNI
;;;; ADD/CHECK/DEL over the real Unix socket protocol with addresses from that
;;;; CIDR, and converge NetworkPolicy for its endpoints when policies change --
;;;; with the link and map writes stubbed, since those need root.

(in-package #:gr8s/tests)
(def-suite foreign-cni-agent :in gr8s)
(in-suite foreign-cni-agent)

(defun foreign-agent-test-node (store name cidr)
  "Register NAME as a schedulable node whose API view carries CIDR."
  (gr8s.controllers::register-node
   store (gr8s.model::make-node-record :id name :name name :pod-cidr cidr
                                       :underlay-address "192.0.2.80")))

(defun foreign-agent-test-config (root)
  "The sole-plugin CNI configuration the foreign conflist carries: no prevResult,
since gr8s itself creates the interface."
  (com.inuoe.jzon:stringify
   (gr8s.resources::core-object
    "cniVersion" "1.0.0" "name" "gr8s" "type" "gr8s"
    "mapPinRoot" (namestring root))))

(defun foreign-agent-cni-call (socket-path command config container)
  "One CNI command through the real agent socket protocol."
  (gr8s.network::call-agent-cni
   socket-path
   (make-instance 'gr8s.node.v1::cni-request
                  :protocol-version gr8s.protocol::+node-protocol-version+
                  :command command
                  :container-id container
                  :network-namespace "/proc/self/ns/net"
                  :interface-name "eth0"
                  :network-configuration
                  (trivial-utf-8:string-to-utf-8-bytes config))))

(test foreign-cni-agent-serves-add-check-del-from-the-nodes-pod-cidr
  (with-core-api (store path)
    (foreign-agent-test-node store "worker-f" "10.88.7.0/24")
    (let* ((cluster (kube-test-cluster))
           (socket-path (namestring (merge-pathnames "cni.sock" path)))
           (root (merge-pathnames "bpf/" path))
           (links (make-hash-table :test 'equal))
           (converged nil) (converged-lock (bt:make-lock))
           (agent nil))
      (ensure-directories-exist root)
      (setf agent
            (gr8s.network::start-foreign-cni-agent
             cluster :node-name "worker-f"
             :state-directory (merge-pathnames "cni-agent/" path)
             :bpf-root (namestring root)
             :socket-path socket-path
             :operations-factory
             (lambda (ipam)
               (gr8s.network::make-routed-cni-operations
                ipam :node-id "worker-f"
                ;; The dataplane pieces that need root are stubbed; address
                ;; allocation, dispatch and result shaping stay real.
                :install-link (lambda (context addresses)
                                (setf (gethash (gr8s.network::cni-context-container-id context)
                                               links)
                                      addresses)
                                7)
                :host-index (constantly 7)
                :check-link (lambda (context address) (declare (ignore context address)) t)
                :remove-link (lambda (context)
                               (remhash (gr8s.network::cni-context-container-id context) links))
                :install-service-return (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :check-service-return (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :publish-service-owner (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :check-service-owner (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :withdraw-service-owner (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :policy (gr8s.network::make-cni-operations
                         :add (lambda (&rest arguments) (declare (ignore arguments)) nil)
                         :check (lambda (&rest arguments) (declare (ignore arguments)) nil)
                         :delete (lambda (&rest arguments) (declare (ignore arguments)) nil))))
             :policy-converger
             (lambda (specs endpoints &key pod-finder directory-fn writer)
               (declare (ignore pod-finder directory-fn writer))
               (bt:with-lock-held (converged-lock)
                 (push (list (length specs) (mapcar #'first endpoints)) converged))
               nil)))
      (is (not (null agent)))
      (unwind-protect
           (let ((config (foreign-agent-test-config root)))
             ;; The agent's IPAM must be bound to the node's own CIDR.
             (let* ((response (foreign-agent-cni-call socket-path "ADD" config "sandbox-1"))
                    (result (com.inuoe.jzon:parse
                             (trivial-utf-8:utf-8-bytes-to-string
                              (slot-value response 'gr8s.node.v1::result-json))))
                    (address (gethash "address"
                                      (aref (gethash "ips" result) 0))))
               (is (slot-value response 'gr8s.node.v1::success))
               (is (uiop:string-prefix-p "10.88.7." address))
               (is (equal (first (gethash "sandbox-1" links))
                          (subseq address 0 (position #\/ address)))))
             (let ((response (foreign-agent-cni-call socket-path "CHECK" config "sandbox-1")))
               (is (slot-value response 'gr8s.node.v1::success)))
             ;; A NetworkPolicy arriving over the watch nudges convergence with
             ;; the live endpoint.
             (gr8s.kube-client:kube-create
              cluster (gr8s.kube-client:resource-path
                       "networking.k8s.io" "v1" "networkpolicies" :namespace "default")
              (gr8s.resources::core-object
               "apiVersion" "networking.k8s.io/v1" "kind" "NetworkPolicy"
               "metadata" (gr8s.resources::core-object "name" "deny-all")
               "spec" (gr8s.resources::core-object
                       "podSelector" (gr8s.resources::core-object)
                       "policyTypes" #("Ingress"))))
             (is (poll-until
                  (lambda ()
                    (bt:with-lock-held (converged-lock)
                      (member '(1 ("sandbox-1")) converged :test #'equal)))))
             (let ((response (foreign-agent-cni-call socket-path "DEL" config "sandbox-1")))
               (is (slot-value response 'gr8s.node.v1::success)))
             (is (null (gethash "sandbox-1" links))))
        (gr8s.network::stop-foreign-cni-agent agent)))))

(test foreign-cni-agent-waits-for-its-node-and-stops-cleanly-without-one
  (with-core-api (store path)
    (values store)
    (let* ((cluster (kube-test-cluster))
           (stop nil)
           (result :pending)
           (thread (bt:make-thread
                    (lambda ()
                      (setf result
                            (gr8s.network::start-foreign-cni-agent
                             cluster :node-name "never-arrives"
                             :state-directory (merge-pathnames "cni-agent/" path)
                             :bpf-root (namestring path)
                             :socket-path (namestring (merge-pathnames "cni.sock" path))
                             :stop-predicate (lambda () stop))))
                    :name "foreign agent waiting for node")))
      (sleep 1)
      (is (eq :pending result))
      (setf stop t)
      (bt:join-thread thread)
      (is (null result)))))

(defun foreign-gateway-test-origin ()
  "A one-reply-per-connection HTTP origin; returns (values port stopper)."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t
                                          :element-type '(unsigned-byte 8)))
         (stopping nil)
         (thread
           (bt:make-thread
            (lambda ()
              (loop
                (let ((client (handler-case (usocket:socket-accept listener)
                                (error () (return)))))
                  (when stopping
                    (ignore-errors (usocket:socket-close client))
                    (return))
                  (ignore-errors
                    (let* ((stream (usocket:socket-stream client))
                           (text (flexi-streams:make-flexi-stream stream)))
                      (loop for line = (read-line text nil "")
                            until (zerop (length (string-trim '(#\Return) line))))
                      (write-sequence
                       (trivial-utf-8:string-to-utf-8-bytes
                        (format nil "HTTP/1.1 200 OK~C~CContent-Length: 9~C~CConnection: close~C~C~C~Corigin-ok"
                                #\Return #\Linefeed #\Return #\Linefeed
                                #\Return #\Linefeed #\Return #\Linefeed))
                       stream)
                      (force-output stream)))
                  (ignore-errors (usocket:socket-close client)))))
            :name "foreign gateway test origin")))
    (values (usocket:get-local-port listener)
            (lambda ()
              (setf stopping t)
              (ignore-errors (usocket:socket-close
                              (usocket:socket-connect "127.0.0.1"
                                                      (usocket:get-local-port listener))))
              (ignore-errors (bt:join-thread thread))
              (ignore-errors (usocket:socket-close listener))))))

(defun foreign-gateway-free-port ()
  (let ((probe (usocket:socket-listen "127.0.0.1" 0 :reuse-address t)))
    (prog1 (usocket:get-local-port probe)
      (usocket:socket-close probe))))

(test foreign-gateway-routes-httproute-traffic-to-service-backends
  (with-core-api (store path)
    (foreign-agent-test-node store "worker-f" "10.88.8.0/24")
    (multiple-value-bind (origin-port stop-origin) (foreign-gateway-test-origin)
      (let* ((cluster (kube-test-cluster))
             (gateway-port (foreign-gateway-free-port))
             (resolved-address nil)
             (agent
               (gr8s.network::start-foreign-cni-agent
                cluster :node-name "worker-f"
                :state-directory (merge-pathnames "cni-agent/" path)
                :bpf-root (namestring path)
                :socket-path (namestring (merge-pathnames "cni.sock" path))
                :policy-converger (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :extra-factory
                (lambda (view)
                  ;; Slice resolution runs for real; the documented TEST-NET
                  ;; address is then dialed as the local origin, since the API
                  ;; (rightly) refuses loopback endpoint addresses.
                  (let ((real (gr8s.controllers::make-service-backend-resolver view)))
                    (gr8s.controllers:start-foreign-gateway
                     view :cert-dir (merge-pathnames "gateway-certs/" path)
                     :cluster cluster :node-name "worker-f" :lease-namespace "default"
                     :resolver (lambda (backend)
                                 (multiple-value-bind (address port) (funcall real backend)
                                   (when address (setf resolved-address address))
                                   (values (and address "127.0.0.1") port)))))))))
        (is (not (null agent)))
        (unwind-protect
             (progn
               (gr8s.kube-client:kube-create
                cluster "/api/v1/namespaces/default/services"
                (gr8s.resources::core-object
                 "apiVersion" "v1" "kind" "Service"
                 "metadata" (gr8s.resources::core-object "name" "app-svc")
                 "spec" (gr8s.resources::core-object
                         "ports" (vector (gr8s.resources::core-object "port" 80)))))
               (gr8s.kube-client:kube-create
                cluster (gr8s.kube-client:resource-path
                         "discovery.k8s.io" "v1" "endpointslices" :namespace "default")
                (gr8s.resources::core-object
                 "apiVersion" "discovery.k8s.io/v1" "kind" "EndpointSlice"
                 "metadata" (gr8s.resources::core-object
                             "name" "app-svc-1"
                             "labels" (gr8s.resources::core-object
                                       "kubernetes.io/service-name" "app-svc"))
                 "addressType" "IPv4"
                 "endpoints" (vector (gr8s.resources::core-object
                                      "addresses" #("192.0.2.9")
                                      "conditions" (gr8s.resources::core-object "ready" t)))
                 "ports" (vector (gr8s.resources::core-object "port" origin-port))))
               (gr8s.kube-client:kube-create
                cluster (gr8s.kube-client:resource-path
                         "gateway.networking.k8s.io" "v1" "gatewayclasses")
                (com.inuoe.jzon:parse
                 "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",
\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}"))
               (gr8s.kube-client:kube-create
                cluster (gr8s.kube-client:resource-path
                         "gateway.networking.k8s.io" "v1" "gateways" :namespace "default")
                (com.inuoe.jzon:parse
                 (format nil "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",~
\"metadata\":{\"name\":\"web\",\"namespace\":\"default\"},~
\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"http\",\"port\":~D,\"protocol\":\"HTTP\"}]}}"
                         gateway-port)))
               (gr8s.kube-client:kube-create
                cluster (gr8s.kube-client:resource-path
                         "gateway.networking.k8s.io" "v1" "httproutes" :namespace "default")
                (com.inuoe.jzon:parse
                 "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",
\"metadata\":{\"name\":\"app\",\"namespace\":\"default\"},
\"spec\":{\"parentRefs\":[{\"name\":\"web\"}],\"rules\":[{\"backendRefs\":[{\"name\":\"app-svc\",\"port\":80}]}]}}"))
               (is (poll-until
                    (lambda ()
                      (ignore-errors
                        (equal "origin-ok"
                               (map 'string #'code-char
                                    (drakma:http-request
                                     (format nil "http://127.0.0.1:~D/" gateway-port)
                                     :force-binary t)))))
                    :timeout 30)
                   "the gateway listener routes to the Service's endpoint")
               (is (equal "192.0.2.9" resolved-address)
                   "the backend resolved through the Service's EndpointSlice")
               ;; The lease-holder publishes statuses and the fronting Service.
               (flet ((condition-true-p (conditions type)
                        (find-if (lambda (entry)
                                   (and (equal type (gethash "type" entry))
                                        (equal "True" (gethash "status" entry))))
                                 (coerce (or conditions #()) 'list))))
                 (is (poll-until
                      (lambda ()
                        (ignore-errors
                          (let ((gateway (gr8s.kube-client:kube-get
                                          cluster (gr8s.kube-client:resource-path
                                                   "gateway.networking.k8s.io" "v1" "gateways"
                                                   :namespace "default" :name "web"))))
                            (and (condition-true-p
                                  (gethash "conditions" (gethash "status" gateway)) "Programmed")
                                 (plusp (length (gethash "addresses"
                                                         (gethash "status" gateway) #())))))))
                      :timeout 30)
                     "the lease-holder programs Gateway status with node addresses")
                 (is (poll-until
                      (lambda ()
                        (ignore-errors
                          (let ((route (gr8s.kube-client:kube-get
                                        cluster (gr8s.kube-client:resource-path
                                                 "gateway.networking.k8s.io" "v1" "httproutes"
                                                 :namespace "default" :name "app"))))
                            (condition-true-p
                             (gethash "conditions"
                                      (aref (gethash "parents" (gethash "status" route)) 0))
                             "Accepted"))))
                      :timeout 30)
                     "the HTTPRoute's parent is accepted")
                 (is (poll-until
                      (lambda ()
                        (ignore-errors
                          (equal "LoadBalancer"
                                 (gethash "type"
                                          (gethash "spec"
                                                   (gr8s.kube-client:kube-get
                                                    cluster (gr8s.kube-client:resource-path
                                                             nil "v1" "services"
                                                             :namespace "default"
                                                             :name "gr8s-gateway-web")))))))
                      :timeout 30)
                     "the lease-holder provisions the fronting LoadBalancer Service")))
          (gr8s.network::stop-foreign-cni-agent agent)
          (funcall stop-origin))))))

(defun foreign-lb-fake-map (name fd)
  (cons name (whistler/loader::make-map-info
              :name name :type 2 :key-size 8 :value-size 8
              :max-entries 1 :flags 0 :fd fd)))

(test foreign-service-lb-plans-cluster-ips-from-watched-services
  (with-core-api (store path)
    (values store path)
    (let* ((cluster (kube-test-cluster))
           (view (gr8s.resources::make-foreign-resource-view cluster)))
      (unwind-protect
           (progn
             (gr8s.kube-client:kube-create
              cluster "/api/v1/namespaces/default/services"
              (gr8s.resources::core-object
               "apiVersion" "v1" "kind" "Service"
               "metadata" (gr8s.resources::core-object "name" "lb-svc")
               "spec" (gr8s.resources::core-object
                       "ports" (vector (gr8s.resources::core-object "port" 80)))))
             (gr8s.kube-client:kube-create
              cluster (gr8s.kube-client:resource-path
                       "discovery.k8s.io" "v1" "endpointslices" :namespace "default")
              (gr8s.resources::core-object
               "apiVersion" "discovery.k8s.io/v1" "kind" "EndpointSlice"
               "metadata" (gr8s.resources::core-object
                           "name" "lb-svc-1"
                           "labels" (gr8s.resources::core-object
                                     "kubernetes.io/service-name" "lb-svc"))
               "addressType" "IPv4"
               "endpoints" (vector (gr8s.resources::core-object
                                    "addresses" #("192.0.2.31")
                                    "conditions" (gr8s.resources::core-object "ready" t)))
               "ports" (vector (gr8s.resources::core-object "port" 9999))))
             ;; The kube-proxy replacement's own planner, fed by the watch
             ;; caches through the seam's default readers, writing the fake maps.
             (let* ((dataplane (gr8s.network::%make-service-lb-dataplane
                                :maps (list (foreign-lb-fake-map "gr8s_service_v4" 1)
                                            (foreign-lb-fake-map "gr8s_backend_v4" 2))))
                    (controller (gr8s.controllers::make-service-lb-controller
                                 view dataplane "worker-f"))
                    (writes nil))
               (gr8s.controllers::converge-service-lb-controller
                controller
                :update (lambda (map key value)
                          (declare (ignore key value))
                          (push (whistler/loader:map-info-fd map) writes))
                :delete (lambda (map key) (declare (ignore map key)) nil))
               ;; The slice's one backend lands before its one service entry.
               (is (equal '(2 1) (nreverse writes))
                   "watched Service and EndpointSlice became LB map writes")))
        (gr8s.resources::stop-foreign-resource-view view)))))

(test foreign-fabric-projects-peer-nodes-into-vxlan-intent
  (with-core-api (store path)
    (values path)
    (foreign-agent-test-node store "worker-f" "10.88.7.0/24")
    (let* ((cluster (kube-test-cluster))
           (fabric-calls nil) (fabric-lock (bt:make-lock))
           (agent
             (gr8s.network::start-foreign-cni-agent
              cluster :node-name "worker-f"
              :state-directory (merge-pathnames "cni-agent/" path)
              :bpf-root (namestring path)
              :socket-path (namestring (merge-pathnames "cni-fabric.sock" path))
              :policy-converger (lambda (&rest arguments) (declare (ignore arguments)) nil)
              :fabric-reconciler
              (lambda (network previous)
                (bt:with-lock-held (fabric-lock)
                  (push (list network previous) fabric-calls))))))
      (is (not (null agent)))
      (unwind-protect
           (progn
             ;; A lone node never creates the overlay device.
             (sleep 1)
             (is (null (bt:with-lock-held (fabric-lock) fabric-calls)))
             ;; A peer joining the cluster produces the fabric intent: this
             ;; node's underlay plus the peer's route.
             (foreign-agent-test-node store "worker-g" "10.88.9.0/24")
             (is (poll-until
                  (lambda () (bt:with-lock-held (fabric-lock) fabric-calls))))
             (destructuring-bind (network previous)
                 (first (bt:with-lock-held (fabric-lock) (last fabric-calls)))
               (is (null previous))
               (is (equal "192.0.2.80" (gethash "underlayAddress" network)))
               (is (equal "10.88.7.0/24" (gethash "nodePodCIDR" network)))
               (is (= 42 (gethash "vni" network)))
               (let ((route (aref (gethash "routes" network) 0)))
                 (is (equal "worker-g" (gethash "nodeID" route)))
                 (is (equal "10.88.9.0/24" (gethash "podCIDR" route)))
                 (is (equal "192.0.2.80" (gethash "underlayAddress" route))))))
        (gr8s.network::stop-foreign-cni-agent agent)))))

(test foreign-fabric-encrypts-with-wireguard-and-publishes-its-key
  (with-core-api (store path)
    (values path)
    (foreign-agent-test-node store "worker-f" "10.88.7.0/24")
    (multiple-value-bind (private-key public-key)
        (gr8s.security::write-wireguard-key-pair (merge-pathnames "wg-keys/" path))
      (let* ((cluster (kube-test-cluster))
             (peer-key (multiple-value-bind (ignored peer-public)
                           (gr8s.security::write-wireguard-key-pair
                            (merge-pathnames "wg-peer-keys/" path))
                         (declare (ignore ignored))
                         (ag-grpc:base64-encode peer-public)))
             (fabric-calls nil) (fabric-lock (bt:make-lock))
             (agent
               (gr8s.network::start-foreign-cni-agent
                cluster :node-name "worker-f"
                :overlay-backend "wireguard"
                :wireguard-private-key private-key
                :wireguard-public-key public-key
                :wireguard-listen-port 51999
                :state-directory (merge-pathnames "wg-cni-agent/" path)
                :bpf-root (namestring path)
                :socket-path (namestring (merge-pathnames "cni-wg.sock" path))
                :policy-converger (lambda (&rest arguments) (declare (ignore arguments)) nil)
                :fabric-reconciler
                (lambda (network previous)
                  (bt:with-lock-held (fabric-lock)
                    (push (list network previous) fabric-calls))))))
        (is (not (null agent)))
        (unwind-protect
             (progn
               ;; The agent advertises its own public key on its own Node, so
               ;; peers can discover and authenticate it from the host API.
               (is (poll-until
                    (lambda ()
                      (ignore-errors
                        (equal (ag-grpc:base64-encode public-key)
                               (gethash "gr8s.io/wireguard-public-key"
                                        (gethash "annotations"
                                                 (gethash "metadata"
                                                          (gr8s.kube-client:kube-get
                                                           cluster (gr8s.kube-client:resource-path
                                                                    nil "v1" "nodes" :name "worker-f"))))))))
                    :timeout 20)
                   "the agent publishes its WireGuard public key annotation")
               ;; A peer that has published its key joins the encrypted fabric;
               ;; the projected intent carries the peer's authenticated identity.
               (gr8s.controllers::register-node
                store (gr8s.model::make-node-record
                       :id "worker-g" :name "worker-g" :pod-cidr "10.88.9.0/24"
                       :underlay-address "192.0.2.90"
                       :annotations (gr8s.resources::core-object
                                     "gr8s.io/wireguard-public-key" peer-key)))
               (flet ((routed-call ()
                        (bt:with-lock-held (fabric-lock)
                          (find-if (lambda (call)
                                     (plusp (length (gethash "routes" (first call)))))
                                   (reverse fabric-calls)))))
                 (is (poll-until #'routed-call))
                 (destructuring-bind (network previous) (routed-call)
                   (declare (ignore previous))
                   (is (equal "wireguard" (gethash "overlayBackend" network)))
                   (is (equal "192.0.2.80" (gethash "underlayAddress" network)))
                   (is (equal "10.88.7.0/24" (gethash "nodePodCIDR" network)))
                   (is (= 51999 (gethash "wireguardListenPort" network)))
                   ;; No VXLAN VNI: this is the encrypted backend.
                   (is (null (gethash "vni" network)))
                   (let ((route (aref (gethash "routes" network) 0)))
                     (is (equal "worker-g" (gethash "nodeID" route)))
                     (is (equal "10.88.9.0/24" (gethash "podCIDR" route)))
                     (is (equal "192.0.2.90" (gethash "underlayAddress" route)))
                     (is (equal peer-key (gethash "wireguardPublicKey" route)))
                     (is (= 51999 (gethash "wireguardListenPort" route)))))))
          (gr8s.network::stop-foreign-cni-agent agent))))))

(test host-port-targets-filter-by-node-and-read-through-the-seam
  ;; The host-port path now reads status through the desired-state seam and can
  ;; restrict to one node's Pods, so the foreign agent serves only its own.
  (with-core-api (store path)
    (values path)
    (flet ((host-port-pod (name node ip proto address)
             (let ((pod (create-pod store
                         (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",~
\"metadata\":{\"name\":\"~A\",\"uid\":\"~A-uid\"},~
\"spec\":{\"nodeName\":\"~A\",\"containers\":[{\"name\":\"c\",\"image\":\"busybox\",~
\"ports\":[{\"containerPort\":8080,\"hostPort\":30080,\"hostIP\":\"~A\",\"protocol\":\"~A\"}]}]}}"
                                             name name node ip proto)))))
               (gr8s.kubelet::save-pod-observation
                store pod (gr8s.resources::core-object "phase" "Running" "podIP" address)))))
      (host-port-pod "aaa" "worker-f" "127.0.0.1" "TCP" "10.42.0.1")
      (host-port-pod "bb" "worker-f" "192.0.2.50" "UDP" "10.42.0.2")
      ;; The peer-node Pod shares this node's (TCP 127.0.0.1 30080) key exactly,
      ;; which is why each agent must filter to its own node before binding.
      (host-port-pod "c" "other-node" "127.0.0.1" "TCP" "10.42.1.1"))
    ;; Only this node's two Pods, disambiguated by (protocol hostIP . port);
    ;; the peer-node Pod shares (TCP 127.0.0.1 30080) but is excluded.
    (let ((targets (gr8s.network::desired-host-port-targets store :node-name "worker-f")))
      (is (= 2 (hash-table-count targets)))
      (is (equal "10.42.0.1" (car (gethash (list* "TCP" "127.0.0.1" 30080) targets))))
      (is (gethash (list* "UDP" "192.0.2.50" 30080) targets)))
    ;; Without a node filter (the native path, one node's own Pods) the two
    ;; same-keyed Pods would collide -- the filter is what keeps them apart.
    (let ((unfiltered (gr8s.network::desired-host-port-targets store)))
      (is (= 2 (hash-table-count unfiltered)))
      (is (gethash (list* "TCP" "127.0.0.1" 30080) unfiltered)))))

(test foreign-gateway-serializes-periodic-and-nudged-listener-passes
  ;; Hold the periodic HTTP pass open while the agent nudges the same controller.
  ;; The nudge must wait for the complete HTTP/L4 pair, rather than touch its maps.
  (let* ((http-symbol 'gr8s.controllers::converge-gateway-listeners)
         (l4-symbol 'gr8s.controllers::converge-gateway-l4-listeners)
         (old-http (symbol-function http-symbol))
         (old-l4 (symbol-function l4-symbol))
         (lock (bt:make-lock "foreign gateway test"))
         (wake (bt:make-condition-variable))
         (events nil) (release nil) (nudge-started nil)
         (stop nil) (nudge nil))
    (labels ((await (predicate)
               (loop repeat 1000 when (funcall predicate) return t do (sleep .001)
                     finally (error "Foreign Gateway test did not reach its barrier"))))
      (unwind-protect
           (progn
             (setf (symbol-function http-symbol)
                   (lambda (controller)
                     (declare (ignore controller))
                     (bt:with-lock-held (lock)
                       (push :http events)
                       (when (= 1 (length events))
                         (loop until release do (bt:condition-wait wake lock)))))
                   (symbol-function l4-symbol)
                   (lambda (controller)
                     (declare (ignore controller))
                     (bt:with-lock-held (lock) (push :l4 events))))
             (multiple-value-bind (converge stopper)
                 (gr8s.controllers:start-foreign-gateway nil)
               (setf stop stopper)
               (await (lambda () (bt:with-lock-held (lock) events)))
               (setf nudge
                     (bt:make-thread
                      (lambda ()
                        (bt:with-lock-held (lock) (setf nudge-started t))
                        (funcall converge))))
               (await (lambda () (bt:with-lock-held (lock) nudge-started)))
               (sleep .1)
               (bt:with-lock-held (lock)
                 (is (equal '(:http) events))
                 (setf release t)
                 (bt:condition-notify wake))
               (bt:join-thread nudge)
               (setf nudge nil)
               (funcall stop)
               (setf stop nil)
               (is (equal '(:http :l4 :http :l4) (reverse events)))))
        (bt:with-lock-held (lock)
          (setf release t)
          (bt:condition-notify wake))
        (when nudge (bt:join-thread nudge))
        (when stop (funcall stop))
        (setf (symbol-function http-symbol) old-http
              (symbol-function l4-symbol) old-l4)))))
