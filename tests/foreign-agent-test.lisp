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
