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
(def-suite foreign-net-agent :in gr8s)
(in-suite foreign-net-agent)

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

(test foreign-net-agent-serves-add-check-del-from-the-nodes-pod-cidr
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
            (gr8s.network::start-foreign-net-agent
             cluster :node-name "worker-f"
             :state-directory (merge-pathnames "net-agent/" path)
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
        (gr8s.network::stop-foreign-net-agent agent)))))

(test foreign-net-agent-waits-for-its-node-and-stops-cleanly-without-one
  (with-core-api (store path)
    (values store)
    (let* ((cluster (kube-test-cluster))
           (stop nil)
           (result :pending)
           (thread (bt:make-thread
                    (lambda ()
                      (setf result
                            (gr8s.network::start-foreign-net-agent
                             cluster :node-name "never-arrives"
                             :state-directory (merge-pathnames "net-agent/" path)
                             :bpf-root (namestring path)
                             :socket-path (namestring (merge-pathnames "cni.sock" path))
                             :stop-predicate (lambda () stop))))
                    :name "foreign agent waiting for node")))
      (sleep 1)
      (is (eq :pending result))
      (setf stop t)
      (bt:join-thread thread)
      (is (null result)))))

(test foreign-net-agent-runs-extra-layers-without-the-cni-feature
  ;; With :cni NIL the agent must not wait for a podCIDR, serve a CNI socket,
  ;; or open IPAM -- the node here never exists -- yet the extra layers
  ;; (gateway, service LB) still converge over the watch view.
  (with-core-api (store path)
    (values store)
    (let* ((cluster (kube-test-cluster))
           (converged 0) (converged-lock (bt:make-lock))
           (stopped nil)
           (agent (gr8s.network::start-foreign-net-agent
                   cluster :cni nil :node-name "never-arrives"
                   :state-directory (merge-pathnames "net-agent/" path)
                   :extra-factory
                   (lambda (view)
                     (values (lambda ()
                               ;; Prove the layer shares the live watch view.
                               (gr8s.resources::list-core-resources view "nodes")
                               (bt:with-lock-held (converged-lock)
                                 (incf converged)))
                             (lambda () (setf stopped t)))))))
      (is (not (null agent)))
      (unwind-protect
           (progn
             (is (null (gr8s.network::foreign-net-agent-server agent)))
             (is (null (gr8s.network::foreign-net-agent-ipam agent)))
             (is (poll-until (lambda ()
                               (bt:with-lock-held (converged-lock)
                                 (plusp converged))))))
        (gr8s.network::stop-foreign-net-agent agent))
      (is-true stopped))))

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
             (resolved-address nil) (front-port nil)
             (agent
               (gr8s.network::start-foreign-net-agent
                cluster :node-name "worker-f"
                :state-directory (merge-pathnames "net-agent/" path)
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
                      (let ((slice (find "gr8s-gateway-web"
                                         (gr8s.resources::list-core-resources store "endpointslices" "default")
                                         :test #'equal
                                         :key (lambda (object)
                                                (gethash "kubernetes.io/service-name"
                                                         (gethash "labels" (gethash "metadata" object)
                                                                  (make-hash-table :test #'equal)))))))
                        (when slice
                          (setf front-port (gethash "port" (aref (gethash "ports" slice) 0))))))
                    :timeout 5)
                   "the Gateway Service points to this node's isolated listener")
               (let ((ledger
                       (find "worker-f" (gr8s.resources::list-core-resources store "configmaps" "default")
                             :test #'equal
                             :key (lambda (object)
                                    (gethash "gr8s.io/gateway-node"
                                             (gethash "annotations" (gethash "metadata" object)
                                                      (make-hash-table)))))))
                 (is (not (null ledger)) "The advertised socket has a durable port lease")
                 (when ledger
                   (is (find (write-to-string front-port)
                             (loop for key being the hash-keys of (gethash "data" ledger)
                                     using (hash-value value)
                                   unless (equal key "next-port") collect value)
                             :test #'equal))
                   (is (equal (gethash "uid" (gethash "metadata" ledger))
                              (uiop:read-file-string
                               (merge-pathnames "gateway-certs/port-ledger.uid" path))))))
               (is (poll-until
                    (lambda ()
                      (ignore-errors
                        (equal "origin-ok"
                               (map 'string #'code-char
                                    (drakma:http-request
                                     (format nil "http://127.0.0.1:~D/" (or front-port gateway-port))
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
                     "the lease-holder programs Gateway status with its Service address")
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
                     "the lease-holder provisions the fronting LoadBalancer Service"))
               (gr8s.network::stop-foreign-net-agent agent)
               (setf agent nil)
               (let ((remaining (gr8s.resources::list-core-resources store "endpointslices" "default")))
                 (is (= 1 (length remaining)) "Shutdown withdraws the Gateway endpoint only")
                 (is (equal "app-svc-1" (gethash "name" (gethash "metadata" (first remaining)))))))
          (when agent (gr8s.network::stop-foreign-net-agent agent))
          (funcall stop-origin))))))

(test foreign-gateways-on-the-same-port-have-separate-routing-tables
  (with-temporary-store (store path)
    (gwc-seed store)
    (dolist (resource '("gateways" "httproutes"))
      (let* ((name (if (equal resource "gateways") "web" "app"))
             (object (gr8s.resources::get-core-resource store resource "default" name)))
        (setf (gethash "metadata" object)
              (gr8s.resources::core-object "name" name "namespace" "tenant-b"))
        (gr8s.resources::create-core-resource store resource object "tenant-b")))
    (let ((original (symbol-function 'gr8s.controllers::start-gateway-listener))
          (handles nil) (stop nil))
      (unwind-protect
           (progn
             ;; Bind real sockets on free test ports; retain the production routers.
             (setf (symbol-function 'gr8s.controllers::start-gateway-listener)
                   (lambda (&rest arguments)
                     (setf (getf arguments :port) 0 (getf arguments :address) "127.0.0.1")
                     (let ((handle (apply original arguments)))
                       (push handle handles)
                       handle)))
             (multiple-value-bind (converge stopper)
                 (gr8s.controllers:start-foreign-gateway
                  store :cert-dir (merge-pathnames "certs/" path))
               (setf stop stopper)
               (funcall converge)
               (is (= 2 (length handles))
                   "same-port Gateways must own separate listener/router instances")
               (is (equal '("default" "tenant-b")
                          (sort (mapcar
                                 (lambda (handle)
                                   (let ((dispatch (funcall (gr8s.controllers::gateway-acceptor-router handle)
                                                            "app.example.com" "/" "GET" nil)))
                                     (gr8s.controllers::gw-backend-namespace
                                      (gr8s.controllers::gw-dispatch-backend dispatch))))
                                 handles)
                                #'string<))
                   "each Gateway's identical hostname resolves within its own route namespace")))
        (when stop (funcall stop))
        (setf (symbol-function 'gr8s.controllers::start-gateway-listener) original)))))

(test foreign-gateway-refuses-an-unowned-fronting-service
  (with-temporary-store (store path)
    (declare (ignore path))
    (gwc-seed store)
    (let ((original (symbol-function 'gr8s.kube-client:kube-get))
          (gateway (gr8s.resources::get-core-resource store "gateways" "default" "web")))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kube-client:kube-get)
                   (lambda (&rest arguments)
                     (declare (ignore arguments))
                     (gr8s.resources::core-object
                      "metadata" (gr8s.resources::core-object "name" "gr8s-gateway-web" "uid" "unowned")
                      "spec" (gr8s.resources::core-object "type" "LoadBalancer"))))
             (signals error (gr8s.controllers::foreign-gateway-provision-service nil gateway)))
        (setf (symbol-function 'gr8s.kube-client:kube-get) original)))))

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
             (gr8s.network::start-foreign-net-agent
              cluster :node-name "worker-f"
              :state-directory (merge-pathnames "net-agent/" path)
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
        (gr8s.network::stop-foreign-net-agent agent)))))

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
               (gr8s.network::start-foreign-net-agent
                cluster :node-name "worker-f"
                :overlay-backend "wireguard"
                :wireguard-private-key private-key
                :wireguard-public-key public-key
                :wireguard-listen-port 51999
                :state-directory (merge-pathnames "wg-net-agent/" path)
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
          (gr8s.network::stop-foreign-net-agent agent))))))

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
  (with-temporary-store (view path)
    (declare (ignore path))
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
                 (gr8s.controllers:start-foreign-gateway view)
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
              (symbol-function l4-symbol) old-l4))))))
(in-package #:gr8s/tests)
(in-suite foreign-net-agent)

(test foreign-gateway-service-reconciliation-preserves-allocated-fields
  (with-temporary-store (store path)
    (declare (ignore path))
    (gwc-seed store)
    (let* ((gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (current (gr8s.resources::core-object
                     "apiVersion" "v1" "kind" "Service"
                     "metadata" (gr8s.resources::core-object
                                 "name" "gr8s-gateway-web" "namespace" "default" "uid" "service-uid"
                                 "resourceVersion" "7"
                                 "ownerReferences" (vector (gr8s.controllers::foreign-gateway-owner-reference gateway)))
                     "spec" (gr8s.resources::core-object
                             "type" "LoadBalancer" "clusterIP" "10.43.0.17"
                             "ports" (vector (gr8s.resources::core-object
                                              "name" "old" "port" 8080 "nodePort" 31000)))))
           (get (symbol-function 'gr8s.kube-client:kube-get))
           (put (symbol-function 'gr8s.kube-client:kube-replace))
           (writes 0))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kube-client:kube-get)
                   (lambda (&rest args) (declare (ignore args)) (gr8s.resources::copy-core-object current))
                   (symbol-function 'gr8s.kube-client:kube-replace)
                   (lambda (cluster uri object &rest args)
                     (declare (ignore cluster uri args)) (incf writes) (setf current object)))
             (gr8s.controllers::foreign-gateway-provision-service nil gateway)
             (is (= 1 writes))
             (is (equal "10.43.0.17" (gethash "clusterIP" (gethash "spec" current))))
             (is (= 31000 (gethash "nodePort" (aref (gethash "ports" (gethash "spec" current)) 0))))
             (is (equal "7" (gethash "resourceVersion" (gethash "metadata" current))))
             (gr8s.controllers::foreign-gateway-provision-service nil gateway)
             (is (= 1 writes))
             (is (equal '("10.43.0.17") (gr8s.controllers::foreign-gateway-service-addresses current))))
        (setf (symbol-function 'gr8s.kube-client:kube-get) get
              (symbol-function 'gr8s.kube-client:kube-replace) put)))))

(test foreign-gateway-replacement-retires-old-private-sockets
  (with-temporary-store (store path)
    (gwc-seed store)
    (let* ((controllers (gr8s.controllers::make-foreign-gateway-controllers
                         :view store :cert-dir path
                         :ingress (gr8s.controllers::make-foreign-gateway-listener-controller
                                   (gr8s.controllers::make-foreign-gateway-view :source store) nil path)))
           (old nil))
      (unwind-protect
           (progn
             (gr8s.controllers::converge-foreign-gateway-listeners controllers)
             (let* ((snapshots (gr8s.controllers::foreign-gateway-listener-snapshots controllers))
                    (gateway (first (first snapshots)))
                    (key (gr8s.controllers::foreign-gateway-key gateway))
                    (controller (gethash key (gr8s.controllers::foreign-gateway-controllers-gateways controllers)))
                    (ports (second (first snapshots))))
               (setf old (car (gethash 8080 (gr8s.controllers::gateway-controller-listeners controller))))
               (is (= 1 (length snapshots)))
               (is (equal "p-8080" (gethash "name" (aref ports 0))))
               (is (= (hunchentoot:acceptor-port old) (gethash "port" (aref ports 0))))
               (gr8s.resources::delete-core-resource store "gateways" "default" "web")
               (gr8s.controllers::converge-foreign-gateway-listeners controllers)
               (is (null (hunchentoot::acceptor-listen-socket old)))
               (is (null (gr8s.controllers::foreign-gateway-listener-snapshots controllers)))
               (setf (gethash "metadata" gateway)
                     (gr8s.resources::core-object "name" "web" "namespace" "default"))
               (gr8s.resources::create-core-resource store "gateways" gateway "default")
               (gr8s.controllers::converge-foreign-gateway-listeners controllers)
               (is (not (equal key (gr8s.controllers::foreign-gateway-key
                                   (first (first (gr8s.controllers::foreign-gateway-listener-snapshots controllers)))))))))
        (gr8s.controllers::stop-foreign-gateway-listeners controllers)))))

(test foreign-gateway-failure-does-not-block-neighbors-or-retirement
  (with-temporary-store (store path)
    (declare (ignore path))
    (gwc-seed store)
    (let ((second (gr8s.resources::get-core-resource store "gateways" "default" "web")))
      (setf (gethash "metadata" second)
            (gr8s.resources::core-object "name" "second" "namespace" "default"))
      (gr8s.resources::create-core-resource store "gateways" second "default"))
    (let* ((ingress (gr8s.controllers::make-gateway-controller store))
           (retired (gr8s.controllers::make-gateway-controller store))
           (manager (gr8s.controllers::make-foreign-gateway-controllers :view store :ingress ingress))
           (http (symbol-function 'gr8s.controllers::converge-gateway-listeners))
           (l4 (symbol-function 'gr8s.controllers::converge-gateway-l4-listeners))
           (stop (symbol-function 'gr8s.controllers::stop-gateway-controller))
           (attempts nil) (completed nil) (stopped nil))
      (setf (gethash '("default" "deleted" "old-uid")
                     (gr8s.controllers::foreign-gateway-controllers-gateways manager)) retired)
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.controllers::converge-gateway-listeners)
                   (lambda (controller)
                     (push controller attempts)
                     (when (= 1 (length attempts)) (error "Invalid tenant certificate")))
                   (symbol-function 'gr8s.controllers::converge-gateway-l4-listeners)
                   (lambda (controller) (push controller completed))
                   (symbol-function 'gr8s.controllers::stop-gateway-controller)
                   (lambda (controller) (push controller stopped)))
             (gr8s.controllers::converge-foreign-gateway-listeners manager)
             (is (= 3 (length attempts)) "Both Gateways and Ingress were attempted")
             (is (= 2 (length completed)) "Healthy Gateway and Ingress completed")
             (is (member ingress completed))
             (is (member retired stopped))
             (is (= 2 (hash-table-count (gr8s.controllers::foreign-gateway-controllers-gateways manager)))))
        (setf (symbol-function 'gr8s.controllers::converge-gateway-listeners) http
              (symbol-function 'gr8s.controllers::converge-gateway-l4-listeners) l4
              (symbol-function 'gr8s.controllers::stop-gateway-controller) stop)))))

(test foreign-gateway-service-names-are-bounded-and-distinct
  (flet ((name (value) (gr8s.controllers::foreign-gateway-service-name value)))
    (is (equal "gr8s-gateway-web" (name "web")))
    (dolist (gateway (list "tenant.gateway" (make-string 253 :initial-element #\a)))
      (let ((service (name gateway)))
        (is (<= (length service) 63))
        (is (every (lambda (char) (or (find char "abcdefghijklmnopqrstuvwxyz0123456789")
                                    (char= char #\-))) service))
        (is (equal service (name gateway)))))
    (is (not (equal (name "tenant.gateway") (name "tenant-gateway"))))
    (is (not (equal (name (concatenate 'string (make-string 100 :initial-element #\a) "x"))
                    (name (concatenate 'string (make-string 100 :initial-element #\a) "y")))))))

(test foreign-gateway-port-leases-survive-restart-and-do-not-recycle
  (let ((current nil) (writes 0)
        (get (symbol-function 'gr8s.kube-client:kube-get))
        (create (symbol-function 'gr8s.kube-client:kube-create))
        (replace (symbol-function 'gr8s.kube-client:kube-replace)))
    (labels ((persist (cluster path object &rest options)
               (declare (ignore cluster path options))
               (incf writes)
               (setf current (gr8s.resources::copy-core-object object))
               (setf (gethash "resourceVersion" (gethash "metadata" current)) (write-to-string writes))
               current)
             (leases ()
               (gr8s.controllers::make-foreign-gateway-port-leases
                :cluster :test :node-name "worker-a" :first-port 22000 :last-port 22002)))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kube-client:kube-get)
                   (lambda (&rest args)
                     (declare (ignore args))
                     (if current (gr8s.resources::copy-core-object current)
                         (error 'gr8s.kube-client:kube-error :status 404 :body "missing")))
                   (symbol-function 'gr8s.kube-client:kube-create) #'persist
                   (symbol-function 'gr8s.kube-client:kube-replace) #'persist)
             (let* ((first (leases))
                    (a (gr8s.controllers::foreign-gateway-port-for first '("ns" "a" "uid-a") 80)))
               (is (= 22000 a))
               (is (= a (gr8s.controllers::foreign-gateway-port-for first '("ns" "a" "uid-a") 80)))
               (is (= 1 writes) "Reusing a lease performs no write")
               ;; A new allocator represents a fresh agent process. The old
               ;; Gateway may be gone; its port must not be recycled for B.
               (let ((restarted (leases)))
                 (is (= 22001 (gr8s.controllers::foreign-gateway-port-for restarted '("ns" "b" "uid-b") 80)))
                 (is (= a (gr8s.controllers::foreign-gateway-port-for restarted '("ns" "a" "uid-a") 80)))
                 (is (= 22002 (gr8s.controllers::foreign-gateway-port-for restarted '("ns" "a" "new-uid-a") 80)))
                 (signals error (gr8s.controllers::foreign-gateway-port-for restarted '("ns" "c" "uid-c") 80))
                 (is (= 3 writes)))))
        (setf (symbol-function 'gr8s.kube-client:kube-get) get
              (symbol-function 'gr8s.kube-client:kube-create) create
              (symbol-function 'gr8s.kube-client:kube-replace) replace)))))

(test foreign-gateway-port-leases-retry-conflicts-and-reject-foreign-state
  (let ((current nil) (writes 0) (conflict nil)
        (get (symbol-function 'gr8s.kube-client:kube-get))
        (create (symbol-function 'gr8s.kube-client:kube-create))
        (replace (symbol-function 'gr8s.kube-client:kube-replace))
        (leases (gr8s.controllers::make-foreign-gateway-port-leases
                 :cluster :test :node-name "worker-a" :first-port 22000 :last-port 22005)))
    (labels ((persist (cluster path object &rest options)
               (declare (ignore cluster path options))
               (incf writes)
               (setf current (gr8s.resources::copy-core-object object))
               (setf (gethash "resourceVersion" (gethash "metadata" current)) (write-to-string writes))
               current))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kube-client:kube-get)
                   (lambda (&rest args)
                     (declare (ignore args))
                     (if current (gr8s.resources::copy-core-object current)
                         (error 'gr8s.kube-client:kube-error :status 404 :body "missing")))
                   (symbol-function 'gr8s.kube-client:kube-create) #'persist
                   (symbol-function 'gr8s.kube-client:kube-replace)
                   (lambda (cluster path object &rest options)
                     (when conflict
                       (setf conflict nil)
                       (gr8s.controllers::foreign-gateway-port-for leases '("ns" "b" "uid-b") 80)
                       (error 'gr8s.kube-client:kube-error :status 409 :body "version changed"))
                     (apply #'persist cluster path object options)))
             (is (= 22000 (gr8s.controllers::foreign-gateway-port-for leases '("ns" "a" "uid-a") 80)))
             (setf conflict t)
             (is (= 22002 (gr8s.controllers::foreign-gateway-port-for leases '("ns" "c" "uid-c") 80)))
             (is (= 22001 (gr8s.controllers::foreign-gateway-port-for leases '("ns" "b" "uid-b") 80)))
             (setf (gethash "gr8s.io/gateway-node" (gethash "annotations" (gethash "metadata" current))) "other-node")
             (signals error (gr8s.controllers::foreign-gateway-port-for leases '("ns" "d" "uid-d") 80))
             (is (= 3 writes) "Foreign state must not be overwritten")
             (setf (gethash "gr8s.io/gateway-node" (gethash "annotations" (gethash "metadata" current))) "worker-a")
             (maphash (lambda (key value)
                        (when (equal value "22000") (setf (gethash key (gethash "data" current)) "99999")))
                      (gethash "data" current))
             (signals error (gr8s.controllers::foreign-gateway-port-for leases '("ns" "a" "uid-a") 80)))
        (setf (symbol-function 'gr8s.kube-client:kube-get) get
              (symbol-function 'gr8s.kube-client:kube-create) create
              (symbol-function 'gr8s.kube-client:kube-replace) replace)))))

(test foreign-gateway-port-leases-refuse-lost-or-replaced-ledger
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((current nil) (writes 0)
          (marker (merge-pathnames "gateway-lease.uid" directory))
          (get (symbol-function 'gr8s.kube-client:kube-get))
          (create (symbol-function 'gr8s.kube-client:kube-create)))
      (labels ((leases ()
                 (gr8s.controllers::make-foreign-gateway-port-leases
                  :cluster :test :node-name "worker-a" :identity-path marker)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.kube-client:kube-get)
                     (lambda (&rest args)
                       (declare (ignore args))
                       (if current (gr8s.resources::copy-core-object current)
                           (error 'gr8s.kube-client:kube-error :status 404 :body "missing")))
                     (symbol-function 'gr8s.kube-client:kube-create)
                     (lambda (cluster path object &rest options)
                       (declare (ignore cluster path options))
                       (incf writes)
                       (setf current (gr8s.resources::copy-core-object object)
                             (gethash "uid" (gethash "metadata" current)) "ledger-uid")
                       current))
               (is (= 20000 (gr8s.controllers::foreign-gateway-port-for (leases) '("ns" "a" "uid-a") 80)))
               (is (probe-file marker))
               (is (equal "ledger-uid" (uiop:read-file-string marker)))
               (is (= 20000 (gr8s.controllers::foreign-gateway-port-for (leases) '("ns" "a" "uid-a") 80)))
               (setf (gethash "uid" (gethash "metadata" current)) "replacement-uid")
               (signals error (gr8s.controllers::foreign-gateway-port-for (leases) '("ns" "a" "uid-a") 80))
               (setf current nil)
               (signals error (gr8s.controllers::foreign-gateway-port-for (leases) '("ns" "b" "uid-b") 80))
               (is (= 1 writes) "A missing ledger must not reset allocation"))
          (setf (symbol-function 'gr8s.kube-client:kube-get) get
                (symbol-function 'gr8s.kube-client:kube-create) create))))))

(test foreign-gateway-private-range-excludes-ephemeral-and-ingress-ports
  (is (gr8s.controllers::validate-foreign-gateway-port-range "32768 60999"))
  (signals error (gr8s.controllers::validate-foreign-gateway-port-range "1024 65535"))
  (signals error (gr8s.controllers::validate-foreign-gateway-port-range "20000 20001"))
  (signals error (gr8s.controllers::validate-foreign-gateway-port-range "invalid")))

(test foreign-gateway-ingress-cannot-bind-private-range
  (let* ((start (symbol-function 'gr8s.controllers::start-gateway-listener))
         (started nil)
         (controller (gr8s.controllers::make-foreign-gateway-listener-controller nil nil nil)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.controllers::start-gateway-listener)
                 (lambda (&rest args) (declare (ignore args)) (setf started t)))
           (signals error (funcall (gr8s.controllers::gateway-controller-start-fn controller) 20000 nil nil nil))
           (is (not started)))
      (setf (symbol-function 'gr8s.controllers::start-gateway-listener) start))))

(test foreign-gateway-port-leases-reject-regressed-counter-and-printer-collisions
  (let* ((current (gr8s.resources::core-object
                   "metadata" (gr8s.resources::core-object
                               "annotations" (gr8s.resources::core-object "gr8s.io/gateway-node" "worker-a"))
                   "data" (gr8s.resources::core-object "g-existing" "20000" "next-port" "20000")))
         (writes 0)
         (leases (gr8s.controllers::make-foreign-gateway-port-leases :cluster :test :node-name "worker-a"))
         (get (symbol-function 'gr8s.kube-client:kube-get))
         (replace (symbol-function 'gr8s.kube-client:kube-replace)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.kube-client:kube-get)
                 (lambda (&rest args) (declare (ignore args)) (gr8s.resources::copy-core-object current))
                 (symbol-function 'gr8s.kube-client:kube-replace)
                 (lambda (cluster path object &rest args)
                   (declare (ignore cluster path args))
                   (incf writes) (setf current (gr8s.resources::copy-core-object object))))
           (signals error (gr8s.controllers::foreign-gateway-port-for leases '("ns" "a" "uid-a") 80))
           (is (= 0 writes))
           (setf (gethash "next-port" (gethash "data" current)) "20001")
           (let* ((*print-length* 0)
                  (a (gr8s.controllers::foreign-gateway-port-for leases '("ns" "a" "uid-a") 443))
                  (b (gr8s.controllers::foreign-gateway-port-for leases '("ns" "b" "uid-b") 443)))
             (is (not (= a b)))))
      (setf (symbol-function 'gr8s.kube-client:kube-get) get
            (symbol-function 'gr8s.kube-client:kube-replace) replace))))

(test foreign-gateway-slice-cleanup-requires-exact-service-ownership
  (let* ((gateway (gr8s.resources::core-object
                   "apiVersion" "gateway.networking.k8s.io/v1" "kind" "Gateway"
                   "metadata" (gr8s.resources::core-object "name" "web" "namespace" "default" "uid" "gateway-uid")))
         (service (gr8s.resources::core-object
                   "apiVersion" "v1" "kind" "Service"
                   "metadata" (gr8s.resources::core-object
                               "name" "gr8s-gateway-web" "namespace" "default" "uid" "service-uid"
                               "ownerReferences" (vector (gr8s.controllers::foreign-gateway-owner-reference gateway)))))
         (slice (gr8s.controllers::foreign-gateway-endpoint-slice service "worker-a" "IPv4" '("192.0.2.9") #()))
         (unowned (gr8s.resources::copy-core-object slice)))
    (remhash "ownerReferences" (gethash "metadata" unowned))
    (is (not (gr8s.controllers::foreign-gateway-local-slice-p unowned "worker-a")))
    (is (gr8s.controllers::foreign-gateway-local-slice-p slice "worker-a" service))
    (is (not (gr8s.controllers::foreign-gateway-local-slice-p unowned "worker-a" service)))
    (is (not (gr8s.controllers::foreign-gateway-local-slice-p slice "worker-b" service)))
    (setf (gethash "uid" (gethash "metadata" service)) "replacement-service")
    (is (not (gr8s.controllers::foreign-gateway-local-slice-p slice "worker-a" service)))
    (setf (gethash "uid" (gethash "metadata" service)) "service-uid"
          (gethash "name" (gethash "metadata" slice)) "unrelated-slice")
    (is (not (gr8s.controllers::foreign-gateway-local-slice-p slice "worker-a" service)))))

(test foreign-gateway-service-failure-does-not-block-other-statuses
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gwc-seed store)
    (let ((second (gr8s.resources::get-core-resource store "gateways" "default" "web")))
      (setf (gethash "metadata" second) (gr8s.resources::core-object "name" "second" "namespace" "default"))
      (gr8s.resources::create-core-resource store "gateways" second "default"))
    (let* ((symbols '(gr8s.controllers::foreign-gateway-publish-class-status
                      gr8s.controllers::foreign-gateway-provision-service
                      gr8s.controllers::foreign-gateway-publish-gateway-status
                      gr8s.controllers::foreign-gateway-publish-route-status))
           (functions (mapcar #'symbol-function symbols))
           (attempts 0) (published 0) (routes 0))
      (unwind-protect
           (progn
             (setf (symbol-function (first symbols)) (lambda (&rest args) (declare (ignore args)))
                   (symbol-function (second symbols))
                   (lambda (&rest args)
                     (declare (ignore args))
                     (when (= 1 (incf attempts)) (error "Conflicting Service owner"))
                     (gr8s.resources::core-object "spec" (make-hash-table) "status" (make-hash-table)))
                   (symbol-function (third symbols)) (lambda (&rest args) (declare (ignore args)) (incf published))
                   (symbol-function (fourth symbols)) (lambda (&rest args) (declare (ignore args)) (incf routes)))
             (gr8s.controllers::foreign-gateway-publish store nil)
             (is (= 2 attempts))
             (is (= 1 published))
             (is (= 1 routes)))
        (loop for symbol in symbols for function in functions do (setf (symbol-function symbol) function))))))

(test foreign-gateway-endpoint-failure-does-not-block-healthy-publication
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (foreign-agent-test-node store "worker-a" "10.88.8.0/24")
    (gwc-seed store)
    (let* ((a (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (b (gr8s.resources::copy-core-object a))
           (ports (vector (gr8s.resources::core-object "name" "p-8080" "protocol" "TCP" "port" 20001)))
           (get (symbol-function 'gr8s.kube-client:kube-get))
           (upsert (symbol-function 'gr8s.controllers::foreign-gateway-upsert-slice))
           (delete (symbol-function 'gr8s.controllers::foreign-gateway-delete-slice))
           (lookup (symbol-function 'gr8s.resources::get-core-resource))
           (published nil) (deleted nil))
      (setf (gethash "metadata" b) (gr8s.resources::core-object "name" "healthy" "namespace" "default" "uid" "healthy-uid"))
      (let* ((service (gr8s.resources::create-core-resource
                       store "services"
                       (gr8s.resources::core-object
                        "apiVersion" "v1" "kind" "Service"
                        "metadata" (gr8s.resources::core-object
                                    "name" "gr8s-gateway-web" "namespace" "default"
                                    "ownerReferences" (vector (gr8s.controllers::foreign-gateway-owner-reference a)))
                        "spec" (gr8s.resources::core-object
                                "ports" (vector (gr8s.resources::core-object "port" 8080)))) "default"))
             (slice (gr8s.controllers::foreign-gateway-endpoint-slice
                     service "worker-a" "IPv4" '("192.0.2.80") ports)))
        (gr8s.resources::create-core-resource store "endpointslices" slice "default"))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.kube-client:kube-get)
                   (lambda (cluster path &rest args)
                     (declare (ignore cluster args))
                     (when (search "gr8s-gateway-web" path) (error "Temporary Service API failure"))
                     (gr8s.resources::core-object
                      "apiVersion" "v1" "kind" "Service"
                      "metadata" (gr8s.resources::core-object
                                  "name" "gr8s-gateway-healthy" "namespace" "default" "uid" "healthy-service"
                                  "ownerReferences" (vector (gr8s.controllers::foreign-gateway-owner-reference b)))))
                   (symbol-function 'gr8s.controllers::foreign-gateway-upsert-slice)
                   (lambda (cluster service slice) (declare (ignore cluster service)) (push slice published))
                   (symbol-function 'gr8s.controllers::foreign-gateway-delete-slice)
                   (lambda (cluster slice) (declare (ignore cluster)) (push slice deleted))
                   (symbol-function 'gr8s.resources::get-core-resource)
                   (lambda (view resource namespace name)
                     (if (equal resource "nodes")
                         (gr8s.resources::core-object
                          "status" (gr8s.resources::core-object
                                    "addresses" (vector (gr8s.resources::core-object "type" "InternalIP" "address" "192.0.2.80"))))
                         (funcall lookup view resource namespace name))))
             (gr8s.controllers::foreign-gateway-publish-local-endpoints
              store nil "worker-a" (list (list a ports) (list b ports)))
             (is (= 1 (length published)))
             (is (null deleted) "An API failure must preserve that Gateway's previous endpoint")
             (is (equal "gr8s-gateway-healthy"
                        (gethash "kubernetes.io/service-name" (gethash "labels" (gethash "metadata" (first published)))))))
        (setf (symbol-function 'gr8s.kube-client:kube-get) get
              (symbol-function 'gr8s.controllers::foreign-gateway-upsert-slice) upsert
              (symbol-function 'gr8s.controllers::foreign-gateway-delete-slice) delete
              (symbol-function 'gr8s.resources::get-core-resource) lookup)))))

(test foreign-gateway-protocol-changes-reuse-the-lease-without-bind-deadlock
  (with-temporary-store (store directory)
    (gwc-seed store)
    (let* ((port (foreign-gateway-free-port))
           (allocator (symbol-function 'gr8s.controllers::foreign-gateway-port-for))
           (manager (gr8s.controllers::make-foreign-gateway-controllers
                     :view store :cert-dir directory :leases :test
                     :ingress (gr8s.controllers::make-foreign-gateway-listener-controller
                               (gr8s.controllers::make-foreign-gateway-view :source store) nil directory))))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.controllers::foreign-gateway-port-for)
                   (lambda (&rest args) (declare (ignore args)) port))
             (dolist (protocol '("HTTP" "TCP" "HTTP"))
               (gr8s.resources::update-core-resource
                store "gateways" "default" "web"
                (lambda (gateway)
                  (setf (gethash "protocol" (aref (gethash "listeners" (gethash "spec" gateway)) 0)) protocol)
                  gateway))
               (gr8s.controllers::converge-foreign-gateway-listeners manager)
               (let* ((controller (first (loop for value being the hash-values
                                               of (gr8s.controllers::foreign-gateway-controllers-gateways manager)
                                             collect value)))
                      (http (gr8s.controllers::gateway-controller-listeners controller))
                      (l4 (gr8s.controllers::gateway-controller-l4-listeners controller)))
                 (is (= (if (equal protocol "HTTP") 1 0) (hash-table-count http)))
                 (is (= (if (equal protocol "TCP") 1 0) (hash-table-count l4)))
                 (let ((snapshot (first (gr8s.controllers::foreign-gateway-listener-snapshots manager))))
                   (is (= port (gethash "port" (aref (second snapshot) 0))))))))
        (gr8s.controllers::stop-foreign-gateway-listeners manager)
        (setf (symbol-function 'gr8s.controllers::foreign-gateway-port-for) allocator)))))

(test foreign-gateway-supported-kinds-require-the-gateway-api-group
  (flet ((resolve (kinds)
           (gr8s.controllers::foreign-gateway-listener-route-kinds
            (gr8s.resources::core-object
             "protocol" "HTTP" "allowedRoutes"
             (gr8s.resources::core-object "kinds" kinds)))))
    (multiple-value-bind (kinds valid)
        (resolve (vector (gr8s.resources::core-object "kind" "HTTPRoute" "group" "example.com")))
      (is (null kinds))
      (is (null valid)))
    (multiple-value-bind (kinds valid)
        (resolve (vector (gr8s.resources::core-object "kind" "HTTPRoute")
                         (gr8s.resources::core-object "kind" "InvalidRoute")))
      (is (= 1 (length kinds)))
      (is (equal "gateway.networking.k8s.io" (gethash "group" (first kinds))))
      (is (null valid)))
    (multiple-value-bind (kinds valid)
        (resolve (vector (gr8s.resources::core-object "kind" "HTTPRoute")))
      (is (= 1 (length kinds)))
      (is (eq t valid)))))

(test foreign-gateway-attached-route-count-respects-listener-hostname-and-section
  (let* ((gateway (com.inuoe.jzon:parse
                   "{\"metadata\":{\"name\":\"web\",\"namespace\":\"infra\",\"generation\":1},\"spec\":{\"listeners\":[{\"name\":\"foo\",\"port\":80,\"protocol\":\"HTTP\",\"hostname\":\"foo.example.com\"},{\"name\":\"bar\",\"port\":8080,\"protocol\":\"HTTP\",\"hostname\":\"bar.example.com\"}]}}"))
         (routes (loop for (name host section) in '(("any" nil nil)
                                                   ("foo" "foo.example.com" nil)
                                                   ("wrong" "other.example.com" nil)
                                                   ("bar-only" nil "bar"))
                       collect (gr8s.resources::core-object
                                "metadata" (gr8s.resources::core-object "name" name "namespace" "infra")
                                "spec" (gr8s.resources::core-object
                                        "hostnames" (if host (vector host) #())
                                        "parentRefs" (vector
                                                      (let ((parent (gr8s.resources::core-object "name" "web")))
                                                        (when section (setf (gethash "sectionName" parent) section))
                                                        parent))))))
         (publish (symbol-function 'gr8s.controllers::foreign-gateway-put-status))
         (status nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status)
                 (lambda (cluster group version resource namespace name value)
                   (declare (ignore cluster group version resource namespace name))
                   (setf status value)))
           (gr8s.controllers::foreign-gateway-publish-gateway-status nil gateway routes nil)
           (is (= 2 (gethash "attachedRoutes" (aref (gethash "listeners" status) 0))))
           (is (= 2 (gethash "attachedRoutes" (aref (gethash "listeners" status) 1)))))
      (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status) publish))))

(test foreign-route-status-matches-listener-admission
  (let* ((gateway (com.inuoe.jzon:parse
                   "{\"metadata\":{\"name\":\"web\",\"namespace\":\"infra\"},\"spec\":{\"listeners\":[{\"name\":\"http\",\"port\":80,\"protocol\":\"HTTP\",\"hostname\":\"app.example.com\"}]}}"))
         (publish (symbol-function 'gr8s.controllers::foreign-gateway-put-status))
         (status nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status)
                 (lambda (&rest args) (setf status (car (last args)))))
           (dolist (case '(("infra" "http" "app.example.com" "True" "Accepted")
                           ("infra" "absent" "app.example.com" "False" "NoMatchingParent")
                           ("infra" "http" "other.example.com" "False" "NoMatchingListenerHostname")
                           ("tenant" "http" "app.example.com" "False" "NotAllowedByListeners")))
             (destructuring-bind (namespace section host accepted reason) case
               (let ((route (gr8s.resources::core-object
                             "metadata" (gr8s.resources::core-object "name" "app" "namespace" namespace "generation" 3)
                             "spec" (gr8s.resources::core-object
                                     "hostnames" (vector host)
                                     "parentRefs" (vector (gr8s.resources::core-object
                                                           "name" "web" "namespace" "infra" "sectionName" section))))))
                 (gr8s.controllers::foreign-gateway-publish-route-status nil route (list gateway))
                 (let ((condition (find "Accepted" (gethash "conditions" (aref (gethash "parents" status) 0))
                                        :test #'equal :key (lambda (value) (gethash "type" value)))))
                   (is (equal accepted (gethash "status" condition)))
                   (is (equal reason (gethash "reason" condition)))
                   (is (= 3 (gethash "observedGeneration" condition))))))))
      (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status) publish))))

(test foreign-route-resolved-refs-reflects-backend-validation
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "services" (com.inuoe.jzon:parse
                       "{\"metadata\":{\"name\":\"web\",\"namespace\":\"default\"},\"spec\":{\"ports\":[{\"port\":80}]}}") "default")
    (let ((publish (symbol-function 'gr8s.controllers::foreign-gateway-put-status))
          (status nil)
          (gateway (gr8s.resources::get-core-resource store "gateways" "default" "web")))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status)
                   (lambda (&rest args) (setf status (car (last args)))))
             (dolist (case '(("{\"name\":\"web\",\"port\":80,\"kind\":\"Other\"}" "InvalidKind")
                             ("{\"name\":\"missing\",\"port\":80}" "BackendNotFound")
                             ("{\"name\":\"web\",\"port\":81}" "BackendNotFound")
                             ("{\"name\":\"web\",\"port\":80}" "ResolvedRefs")))
               (destructuring-bind (reference reason) case
                 (let ((route (gr8s.resources::get-core-resource store "httproutes" "default" "app")))
                   (setf (gethash "backendRefs" (aref (gethash "rules" (gethash "spec" route)) 0))
                         (vector (com.inuoe.jzon:parse reference)))
                   (gr8s.controllers::foreign-gateway-publish-route-status nil route (list gateway) store)
                   (let ((condition (find "ResolvedRefs" (gethash "conditions" (aref (gethash "parents" status) 0))
                                          :test #'equal :key (lambda (value) (gethash "type" value)))))
                     (is (equal reason (gethash "reason" condition)))
                     (is (equal (if (equal reason "ResolvedRefs") "True" "False")
                                (gethash "status" condition))))))))
        (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status) publish)))))

(test foreign-gateway-unsupported-listeners-are-rejected
  (let ((publish (symbol-function 'gr8s.controllers::foreign-gateway-put-status)) (status nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status)
                 (lambda (&rest args) (setf status (car (last args)))))
           (dolist (mixed '(nil t))
             (let* ((invalid (gr8s.resources::core-object "name" "invalid" "port" 1111 "protocol" "INVALID"))
                    (gateway (gr8s.resources::core-object
                              "metadata" (gr8s.resources::core-object "name" "web" "namespace" "infra" "generation" 2)
                              "spec" (gr8s.resources::core-object
                                      "listeners" (if mixed
                                                      (vector invalid (gr8s.resources::core-object "name" "http" "port" 80 "protocol" "HTTP"))
                                                      (vector invalid))))))
               (gr8s.controllers::foreign-gateway-publish-gateway-status nil gateway nil nil)
               (let* ((accepted (find "Accepted" (gethash "conditions" status) :test #'equal
                                      :key (lambda (c) (gethash "type" c))))
                      (listener (aref (gethash "listeners" status) 0))
                      (condition (find "Accepted" (gethash "conditions" listener) :test #'equal
                                       :key (lambda (c) (gethash "type" c)))))
                 (is (equal (if mixed "True" "False") (gethash "status" accepted)))
                 (is (equal "ListenersNotValid" (gethash "reason" accepted)))
                 (is (equal "False" (gethash "status" condition)))
                 (is (equal "UnsupportedProtocol" (gethash "reason" condition)))
                 (is (= 0 (length (gethash "supportedKinds" listener))))))))
      (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status) publish))))

(test foreign-gateway-invalid-listener-status-does-not-require-a-service
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gwc-seed store)
    (gr8s.resources::update-core-resource
     store "gateways" "default" "web"
     (lambda (object)
       (setf (gethash "protocol" (aref (gethash "listeners" (gethash "spec" object)) 0)) "INVALID") object))
    (let ((publish (symbol-function 'gr8s.controllers::foreign-gateway-put-status)) (status nil))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status)
                   (lambda (cluster group version resource namespace name value)
                     (declare (ignore cluster group version namespace name))
                     (when (equal resource "gateways") (setf status value))))
             (gr8s.controllers::foreign-gateway-publish store nil)
             (is (not (null status)))
             (when status
               (is (= 0 (gethash "attachedRoutes" (aref (gethash "listeners" status) 0))))))
        (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status) publish)))))

(test foreign-gateway-tls-reference-errors-are-published
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let ((publish (symbol-function 'gr8s.controllers::foreign-gateway-put-status))
          (status nil))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status)
                   (lambda (&rest args) (setf status (car (last args)))))
             (dolist (case '(("" "Secret" "infra" "InvalidCertificateRef")
                             ("wrong.group" "Secret" "infra" "InvalidCertificateRef")
                             ("" "WrongKind" "infra" "InvalidCertificateRef")
                             ("" "Secret" "other" "RefNotPermitted")))
               (destructuring-bind (group kind namespace reason) case
                 (let* ((listener (gr8s.resources::core-object
                                   "name" "https" "port" 443 "protocol" "HTTPS"
                                   "tls" (gr8s.resources::core-object
                                          "certificateRefs" (vector (gr8s.resources::core-object
                                                                     "name" "missing" "namespace" namespace
                                                                     "group" group "kind" kind)))))
                        (gateway (gr8s.resources::core-object
                                  "metadata" (gr8s.resources::core-object "name" "web" "namespace" "infra" "generation" 3)
                                  "spec" (gr8s.resources::core-object "listeners" (vector listener)))))
                   (gr8s.controllers::foreign-gateway-publish-gateway-status nil gateway nil nil store)
                   (let* ((conditions (gethash "conditions" (aref (gethash "listeners" status) 0)))
                          (resolved (find "ResolvedRefs" conditions :test #'equal :key (lambda (c) (gethash "type" c))))
                          (programmed (find "Programmed" conditions :test #'equal :key (lambda (c) (gethash "type" c)))))
                     (is (equal "False" (gethash "status" resolved)))
                     (is (equal reason (gethash "reason" resolved)))
                     (is (equal "False" (gethash "status" programmed)))
                     (is (equal "False"
                                (gethash "status" (find "Programmed" (gethash "conditions" status)
                                                        :test #'equal :key (lambda (c) (gethash "type" c)))))))))))
        (setf (symbol-function 'gr8s.controllers::foreign-gateway-put-status) publish)))))
