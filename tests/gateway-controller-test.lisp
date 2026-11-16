;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the Gateway controller: GatewayClass ownership, parentRef-based
;;;; HTTPRoute attachment, the pure port->routes planner, and the start/hot-swap
;;;; /stop convergence of L7 proxy listeners (with injected lifecycle to avoid
;;;; binding real ports).

(in-package #:gr8s/tests)
(def-suite gateway-controller :in gr8s)
(in-suite gateway-controller)

(defun gateway-test-tls-secret (name)
  (let ((root (asdf:system-relative-pathname "gr8s" "tests/fixtures/gateway-tls/")))
    (gr8s.resources::core-object
     "apiVersion" "v1" "kind" "Secret" "metadata" (gr8s.resources::core-object "name" name)
     "type" "kubernetes.io/tls"
     "data" (gr8s.resources::core-object
             "tls.crt" (ag-grpc:base64-encode (alexandria:read-file-into-byte-vector (merge-pathnames "server.crt" root)))
             "tls.key" (ag-grpc:base64-encode (alexandria:read-file-into-byte-vector (merge-pathnames "server.key" root)))))))

(defun gwc-seed (store)
  "Seed a store with an owned and an unowned GatewayClass, two Gateways and one
   attached HTTPRoute."
  (flet ((create (resource namespace json)
           (gr8s.resources::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
    (create "gatewayclasses" nil
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}")
    (create "gatewayclasses" nil
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"other\"},\"spec\":{\"controllerName\":\"someone.else/controller\"}}")
    (create "gateways" "default"
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"web\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"http\",\"port\":8080,\"protocol\":\"HTTP\"}]}}")
    (create "gateways" "default"
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"unmanaged\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"other\",\"listeners\":[{\"name\":\"http\",\"port\":9090,\"protocol\":\"HTTP\"}]}}")
    (create "httproutes" "default"
            "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",\"metadata\":{\"name\":\"app\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"web\"}],\"hostnames\":[\"app.example.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"app-svc\",\"port\":80}]}]}}")))

(test gateway-controller-ownership-and-attachment
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (is (gr8s.controllers::gateway-controlled-p store (gr8s.resources::get-core-resource store "gateways" "default" "web")))
    (is (not (gr8s.controllers::gateway-controlled-p store (gr8s.resources::get-core-resource store "gateways" "default" "unmanaged"))))
    ;; A parentRef naming a different Gateway does not attach.
    (let ((route (gr8s.resources::get-core-resource store "httproutes" "default" "app")))
      (is (gr8s.controllers::gateway-route-attaches-p route "default" "web" "http" 8080))
      (is (not (gr8s.controllers::gateway-route-attaches-p route "default" "other-gw" "http" 8080)))
      ;; No sectionName -> attaches to every listener on the Gateway.
      (is (gr8s.controllers::gateway-route-attaches-p route "default" "web" "any-listener" 8080)))
    ;; An explicit sectionName/port must equal the listener's.
    (let ((pinned (com.inuoe.jzon:parse
                   "{\"metadata\":{\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"web\",\"sectionName\":\"https\",\"port\":8443}],\"rules\":[]}}")))
      (is (gr8s.controllers::gateway-route-attaches-p pinned "default" "web" "https" 8443))
      (is (not (gr8s.controllers::gateway-route-attaches-p pinned "default" "web" "http" 8080))))))

(test gateway-controller-plans-port-to-routes
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let ((plan (gr8s.controllers::gateway-listener-plan
                 (gr8s.resources::list-core-resources store "gateways")
                 (gr8s.resources::list-core-resources store "httproutes")
                 (lambda (gw) (gr8s.controllers::gateway-controlled-p store gw)))))
      ;; Only the owned Gateway's HTTP port is planned.
      (is (= 1 (length plan)))
      (is (equal 8080 (getf (first plan) :port)))
      (is (equal "HTTP" (getf (first plan) :protocol)))
      (is (null (getf (first plan) :tls)))
      (is (= 1 (length (getf (first plan) :routes))))
      (is (equal '("app.example.com") (gr8s.controllers::gw-route-hostnames (first (getf (first plan) :routes))))))))

(test gateway-controller-converges-start-swap-stop
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((actions '())
           (controller (gr8s.controllers::make-gateway-controller
                        store
                        :resolver (lambda (b) (declare (ignore b)) nil)
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore router resolver tls))
                                    (push (list :start port) actions)
                                    (list :handle port))
                        :stop-fn (lambda (handle) (push (list :stop handle) actions))
                        :swap-fn (lambda (handle router)
                                   (declare (ignore router))
                                   (push (list :swap handle) actions)))))
      ;; First convergence starts the listener on 8080.
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (equal '((:start 8080)) actions))
      ;; An unchanged plan leaves the published router untouched.
      (setf actions '())
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (null actions))
      ;; Removing the Gateway stops the listener.
      (setf actions '())
      (gr8s.resources::delete-core-resource store "gateways" "default" "web")
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (equal '((:stop (:handle 8080))) actions))
      (is (zerop (hash-table-count (gr8s.controllers::gateway-controller-listeners controller)))))))

(test gateway-listeners-exist-without-attached-routes
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
    (let ((plan (gr8s.controllers::gateway-listener-plan
                 (gr8s.resources::list-core-resources store "gateways") nil
                 (lambda (gateway) (gr8s.controllers::gateway-controlled-p store gateway)))))
      (is (= 1 (length plan)))
      (is (eql 8080 (getf (first plan) :port)))
      (is (null (getf (first plan) :routes))))
    (let* ((starts 0) (stops 0)
           (controller (gr8s.controllers::make-gateway-controller
                        store :start-fn (lambda (&rest ignored)
                                          (declare (ignore ignored)) (incf starts))
                        :stop-fn (lambda (handle) (declare (ignore handle)) (incf stops))
                        :swap-fn (lambda (&rest ignored) (declare (ignore ignored))))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 starts))
      (gr8s.resources::create-core-resource store "httproutes"
                                           (com.inuoe.jzon:parse *httproute-json*) "default")
      (gr8s.controllers::converge-gateway-listeners controller)
      (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 starts))
      (is (zerop stops)))))

(test gateway-empty-tcp-listener-retains-its-protocol
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (gr8s.resources::update-core-resource
     store "gateways" "default" "web"
     (lambda (gateway)
       (setf (gethash "protocol" (aref (gethash "listeners" (gethash "spec" gateway)) 0)) "TCP")
       gateway))
    (let ((plan (gr8s.controllers::gateway-l4-plan
                 (gr8s.resources::list-core-resources store "gateways") nil nil nil
                 (lambda (gateway) (gr8s.controllers::gateway-controlled-p store gateway)))))
      (is (= 1 (length plan)))
      (is (eq :tcp (getf (first plan) :mode)))
      (is (null (getf (first plan) :tcp-routes))))))

(test gateway-listener-observations-reflect-current-running-listeners
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((controller (gr8s.controllers::make-gateway-controller
                        store :start-fn (lambda (&rest ignored) (declare (ignore ignored)) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)))
                        :swap-fn (lambda (&rest ignored) (declare (ignore ignored)))))
           (before (first (gr8s.controllers::gateway-controller-observations controller))))
      (is (equal "web" (slot-value before 'gr8s.node.v1::name)))
      (is-false (slot-value (first (slot-value before 'gr8s.node.v1::listeners))
                            'gr8s.node.v1::programmed))
      (gr8s.controllers::converge-gateway-listeners controller)
      (let* ((after (first (gr8s.controllers::gateway-controller-observations controller)))
             (roundtrip (roundtrip-node-message
                         (make-instance 'gr8s.node.v1::node-status
                                        :gateway-report-present t :gateways (list after))
                         'gr8s.node.v1::node-status)))
        (is (slot-value roundtrip 'gr8s.node.v1::gateway-report-present))
        (is (= 1 (length (slot-value roundtrip 'gr8s.node.v1::gateways))))
        (is (slot-value (first (slot-value after 'gr8s.node.v1::listeners))
                        'gr8s.node.v1::programmed)))
      (gr8s.controllers::stop-gateway-controller controller)
      (is-false (slot-value
                 (first (slot-value
                         (first (gr8s.controllers::gateway-controller-observations controller))
                         'gr8s.node.v1::listeners)) 'gr8s.node.v1::programmed)))))

(defun gateway-test-condition (object type)
  (find type (gethash "conditions" (gethash "status" object) #())
        :test #'equal :key (lambda (condition) (gethash "type" condition))))

(test gateway-attached-route-counts-follow-listener-selection
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "namespaces"
     (gw-parse "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"tenant\",\"labels\":{\"team\":\"blue\"}}}") nil)
    (let ((route (gw-parse *httproute-json*)))
      (setf (gethash "parentRefs" (gethash "spec" route))
            (vector (gr8s.resources::core-object "name" "web" "namespace" "default")
                    (gr8s.resources::core-object "name" "web" "namespace" "default")))
      (gr8s.resources::create-core-resource store "httproutes" route "tenant"))
    (let* ((gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (listener (aref (gethash "listeners" (gethash "spec" gateway)) 0)))
      (labels ((count-routes ()
                 (gr8s.apiserver::gateway-listener-attached-routes
                  store gateway listener (gr8s.apiserver::gateway-listener-supported-kinds listener))))
        (is (= 1 (count-routes)))
        (setf (gethash "allowedRoutes" listener)
              (gw-parse "{\"namespaces\":{\"from\":\"All\"}}"))
        (is (= 2 (count-routes)))
        (setf (gethash "allowedRoutes" listener)
              (gw-parse "{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchLabels\":{\"team\":\"blue\"}}}}"))
        (is (= 1 (count-routes)))
        (setf (gethash "kinds" (gethash "allowedRoutes" listener))
              (vector (gr8s.resources::core-object "kind" "TCPRoute")))
        (is (zerop (count-routes)))))))

(test gateway-status-rejects-unsupported-route-kind-references
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((gateway (gr8s.resources::get-core-resource store "gateways" "default" "web"))
           (listener (aref (gethash "listeners" (gethash "spec" gateway)) 0)))
      (setf (gethash "allowedRoutes" listener)
            (gw-parse "{\"kinds\":[{\"group\":\"gateway.networking.k8s.io\",\"kind\":\"TCPRoute\"}]}"))
      (let* ((status (gr8s.apiserver::gateway-listener-status-object
                      store gateway listener nil (gr8s.resources::core-object)))
             (condition (find "ResolvedRefs" (gethash "conditions" status) :test #'equal
                              :key (lambda (entry) (gethash "type" entry)))))
        (is (equal "False" (gethash "status" condition)))
        (is (equal "InvalidRouteKinds" (gethash "reason" condition)))
        (is (zerop (length (gethash "supportedKinds" status))))))))

(test malformed-gateway-status-input-does-not-starve-other-gateways
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "gateways" (gw-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"malformed\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"http\",\"port\":8181,\"protocol\":\"HTTP\",\"allowedRoutes\":\"invalid\"}]}}") "default")
    (gr8s.apiserver::reconcile-gateway-status (gr8s.apiserver::%make-node-grpc-server :store store))
    (dolist (name '("web" "malformed"))
      (let ((gateway (gr8s.resources::get-core-resource store "gateways" "default" name)))
        (is (equal "False" (gethash "status" (gateway-test-condition gateway "Programmed"))))))))

(test gateway-observations-do-not-reuse-a-replaced-tls-secret
  (with-temporary-store (store directory)
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "secrets" (gateway-test-tls-secret "tls") "default")
    (gr8s.resources::update-core-resource
     store "gateways" "default" "web"
     (lambda (gateway)
       (let ((listener (aref (gethash "listeners" (gethash "spec" gateway)) 0)))
         (setf (gethash "protocol" listener) "HTTPS"
               (gethash "tls" listener)
               (gr8s.resources::core-object "certificateRefs"
                                            (vector (gr8s.resources::core-object "name" "tls")))))
       gateway))
    (let ((controller (gr8s.controllers::make-gateway-controller
                       store :cert-dir directory
                       :start-fn (lambda (&rest ignored) (declare (ignore ignored)) :tls-listener)
                       :stop-fn (lambda (handle) (declare (ignore handle)))
                       :swap-fn (lambda (&rest ignored) (declare (ignore ignored))))))
      (labels ((programmed ()
                 (slot-value (first (slot-value (first (gr8s.controllers::gateway-controller-observations controller))
                                                'gr8s.node.v1::listeners)) 'gr8s.node.v1::programmed)))
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (programmed))
        (gr8s.resources::update-core-resource
         store "secrets" "default" "tls"
         (lambda (secret)
           (setf (gethash "tls.crt" (gethash "data" secret))
                 (ag-grpc:base64-encode
                  (concatenate '(vector (unsigned-byte 8))
                               (ag-grpc:base64-decode (gethash "tls.crt" (gethash "data" secret)))
                               #(10))))
           secret))
        (is-false (programmed))
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (programmed))))))

(test gateway-failed-registration-closes-the-unpublished-listener
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((stops 0)
           (controller (gr8s.controllers::make-gateway-controller
                        store :start-fn (lambda (&rest ignored) (declare (ignore ignored)) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)) (incf stops))
                        :register-fn (lambda (&rest ignored) (declare (ignore ignored)) (error "injected registration failure")))))
      (signals error (gr8s.controllers::converge-gateway-listeners controller))
      (is (= 1 stops))
      (is (zerop (hash-table-count (gr8s.controllers::gateway-controller-listeners controller)))))))

(test gateway-status-requires-fresh-current-session-listener-evidence
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((now 1000)
           (server (gr8s.apiserver::%make-node-grpc-server
                    :store store :clock (lambda () now) :heartbeat-timeout-seconds 30))
           (session (gr8s.apiserver::make-node-agent-session nil))
           (controller (gr8s.controllers::make-gateway-controller
                        store :start-fn (lambda (&rest ignored) (declare (ignore ignored)) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)))
                        :swap-fn (lambda (&rest ignored) (declare (ignore ignored))))))
      (gr8s.controllers::register-node
       store (gr8s.model::make-node-record :id "worker" :name "worker"
                                          :underlay-address "192.0.2.10" :pod-cidr "10.88.0.0/24"))
      (gr8s.controllers::mark-node-ready store "worker" now :lease-duration 1000)
      (setf (gr8s.apiserver::node-agent-session-node-id session) "worker"
            (gethash "worker" (gr8s.apiserver::node-grpc-server-sessions server)) session)
      (labels ((gateway () (gr8s.resources::get-core-resource store "gateways" "default" "web"))
               (reconcile () (gr8s.apiserver::reconcile-gateway-status server))
               (report (&optional (sender session))
                 (gr8s.apiserver::note-node-gateway-status
                  server "worker" (make-instance
                                   'gr8s.node.v1::node-status :gateway-report-present t
                                   :gateways (gr8s.controllers::gateway-controller-observations controller)) sender))
               (programmed () (gethash "status" (gateway-test-condition (gateway) "Programmed"))))
        (let ((projection (gr8s.kubelet::service-discovery-projection store)))
          (reconcile)
          (is (equalp projection (gr8s.kubelet::service-discovery-projection store))
              "Controller status changes must not invalidate the node's desired projection"))
        (is (equal "False" (programmed)))
        (is (zerop (length (gethash "addresses" (gethash "status" (gateway))))))
        (gr8s.controllers::converge-gateway-listeners controller)
        (report)
        (reconcile)
        (is (equal "True" (programmed)))
        (is (equal "192.0.2.10" (gethash "value" (aref (gethash "addresses" (gethash "status" (gateway))) 0))))
        (is (= 1 (gethash "attachedRoutes" (aref (gethash "listeners" (gethash "status" (gateway))) 0))))
        (let ((revision (gr8s.resources::pod-store-resource-revision store)))
          (reconcile)
          (is (= revision (gr8s.resources::pod-store-resource-revision store))))
        (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
        (reconcile)
        (is (= 0 (gethash "attachedRoutes" (aref (gethash "listeners" (gethash "status" (gateway))) 0))))
        (is (equal "True" (programmed)))
        ;; A spec change cannot inherit an older generation's programmed report.
        (gr8s.resources::update-core-resource
         store "gateways" "default" "web"
         (lambda (current)
           (setf (gethash "port" (aref (gethash "listeners" (gethash "spec" current)) 0)) 8081)
           current))
        (reconcile)
        (is (equal "False" (programmed)))
        (gr8s.controllers::converge-gateway-listeners controller)
        (report)
        (reconcile)
        (is (equal "True" (programmed)))
        (incf now 31)
        (reconcile)
        (is (equal "False" (programmed)))
        (report)
        (reconcile)
        (is (equal "True" (programmed)))
        ;; An old connection cannot refresh readiness after a reconnect.
        (setf (gethash "worker" (gr8s.apiserver::node-grpc-server-sessions server))
              (gr8s.apiserver::make-node-agent-session nil))
        (report session)
        (reconcile)
        (is (equal "False" (programmed)))
        (is-false (gethash "status" (gr8s.resources::get-core-resource store "gateways" "default" "unmanaged")))))))

(test gateway-controller-plans-and-converges-l4-listeners
  (with-temporary-store (store directory)
    (values directory)
    (flet ((create (resource namespace json)
             (gr8s.resources::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
      (create "gatewayclasses" nil
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}")
      (create "gateways" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"l4gw\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"db\",\"port\":3306,\"protocol\":\"TCP\"},{\"name\":\"sni\",\"port\":8443,\"protocol\":\"TLS\"}]}}")
      (create "tcproutes" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"TCPRoute\",\"metadata\":{\"name\":\"db\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"l4gw\",\"sectionName\":\"db\"}],\"rules\":[{\"backendRefs\":[{\"name\":\"mysql\",\"port\":3306}]}]}}")
      (create "tlsroutes" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"TLSRoute\",\"metadata\":{\"name\":\"edge\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"l4gw\",\"sectionName\":\"sni\"}],\"hostnames\":[\"secure.example.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"tls-svc\",\"port\":8443}]}]}}"))
    (let ((plan (gr8s.controllers::gateway-l4-plan
                 (gr8s.resources::list-core-resources store "gateways")
                 (gr8s.resources::list-core-resources store "tcproutes")
                 (gr8s.resources::list-core-resources store "tlsroutes")
                 (gr8s.resources::list-core-resources store "grpcroutes")
                 (lambda (gw) (gr8s.controllers::gateway-controlled-p store gw)))))
      (is (= 2 (length plan)))
      (let ((tcp (find :tcp plan :key (lambda (e) (getf e :mode))))
            (tls (find :tls plan :key (lambda (e) (getf e :mode)))))
        (is (equal 3306 (getf tcp :port)))
        (is (= 1 (length (getf tcp :tcp-routes))))
        (is (equal 8443 (getf tls :port)))
        (is (= 1 (length (getf tls :sni-routes))))
        (is (equal '("secure.example.com")
                   (gr8s.controllers::l4-sni-route-hostnames (first (getf tls :sni-routes)))))))
    (let* ((actions '())
           (controller (gr8s.controllers::make-gateway-controller
                        store :resolver (lambda (b) (declare (ignore b)) nil)
                        :l4-start-fn (lambda (port mode dispatcher resolver)
                                       (declare (ignore dispatcher resolver))
                                       (push (list :start port mode) actions) (list :l4 port))
                        :l4-stop-fn (lambda (handle) (push (list :stop handle) actions))
                        :l4-swap-fn (lambda (handle dispatcher)
                                      (declare (ignore dispatcher))
                                      (push (list :swap handle) actions)))))
      (gr8s.controllers::converge-gateway-l4-listeners controller)
      (is (= 2 (count :start actions :key #'first)))
      ;; Second convergence hot-swaps both dispatchers (no new starts).
      (setf actions '())
      (gr8s.controllers::converge-gateway-l4-listeners controller)
      (is (= 2 (count :swap actions :key #'first)))
      (is (= 0 (count :start actions :key #'first))))))

(test gateway-controller-starts-https-listener-with-secret-cert
  (with-temporary-store (store directory)
    (flet ((create (resource namespace json)
             (gr8s.resources::create-core-resource store resource (com.inuoe.jzon:parse json) namespace)))
      (create "gatewayclasses" nil
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",\"metadata\":{\"name\":\"gr8s\"},\"spec\":{\"controllerName\":\"gr8s.io/gateway-controller\"}}")
      (gr8s.resources::create-core-resource store "secrets"
                                            (gateway-test-tls-secret "web-cert") "default")
      (create "gateways" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",\"metadata\":{\"name\":\"tls-gw\",\"namespace\":\"default\"},\"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[{\"name\":\"https\",\"port\":8443,\"protocol\":\"HTTPS\",\"tls\":{\"certificateRefs\":[{\"kind\":\"Secret\",\"name\":\"web-cert\"}]}}]}}")
      (create "httproutes" "default"
              "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"HTTPRoute\",\"metadata\":{\"name\":\"secure\",\"namespace\":\"default\"},\"spec\":{\"parentRefs\":[{\"name\":\"tls-gw\"}],\"hostnames\":[\"secure.example.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"app-svc\",\"port\":443}]}]}}"))
    (let ((plan (gr8s.controllers::gateway-listener-plan
                 (gr8s.resources::list-core-resources store "gateways")
                 (gr8s.resources::list-core-resources store "httproutes")
                 (lambda (gw) (gr8s.controllers::gateway-controlled-p store gw)))))
      (is (equal 8443 (getf (first plan) :port)))
      (is (equal "HTTPS" (getf (first plan) :protocol)))
      (is (equal '("default" . "web-cert") (getf (first plan) :tls))))
    (let* ((started '())
           (cert-dir (merge-pathnames "certs/" directory))
           (controller (gr8s.controllers::make-gateway-controller
                        store :cert-dir cert-dir
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore router resolver))
                                    (push (cons port tls) started) (list :handle port))
                        :stop-fn (lambda (handle) (declare (ignore handle)))
                        :swap-fn (lambda (handle router) (declare (ignore handle router))))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 (length started)))
      (is (equal 8443 (car (first started))))
      (let ((tls (cdr (first started))))
        (is (stringp (getf tls :certificate)))
        (is (probe-file (getf tls :certificate)))        ; cert materialized on disk
        (is (probe-file (getf tls :key)))))))

(test gateway-controller-reuses-only-unchanged-routing-content
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((published nil) (swaps 0)
           (controller (gr8s.controllers::make-gateway-controller
                        store
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore port resolver tls))
                                    (setf published router) :listener)
                        :swap-fn (lambda (handle router)
                                   (declare (ignore handle))
                                   (incf swaps) (setf published router))
                        :stop-fn (lambda (handle) (declare (ignore handle))))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (let ((old published))
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (= 0 swaps))
        (is (eq old published))
        ;; Resource metadata changes do not change matching content.
        (gr8s.resources::update-core-resource
         store "httproutes" "default" "app"
         (lambda (route) (setf (gethash "status" route) (make-hash-table)) route))
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (= 0 swaps))
        (flet ((set-path (path)
                 (gr8s.resources::update-core-resource
                  store "httproutes" "default" "app"
                  (lambda (route)
                    (setf (gethash "matches" (aref (gethash "rules" (gethash "spec" route)) 0))
                          (vector (let ((match (make-hash-table)) (value (make-hash-table)))
                                    (setf (gethash "type" value) "Exact"
                                          (gethash "value" value) path
                                          (gethash "path" match) value)
                                    match)))
                    route))))
          (set-path "/UP")
          (gr8s.controllers::converge-gateway-listeners controller)
          (is (= 1 swaps))
          (is (not (eq old published)))
          (is (null (funcall published "app.example.com" "/up" "GET" nil)))
          (is (funcall old "app.example.com" "/up" "GET" nil))
          ;; EQUALP on normalized structs would incorrectly reuse this table.
          (set-path "/up")
          (gr8s.controllers::converge-gateway-listeners controller)
          (is (= 2 swaps))
          (is (funcall published "app.example.com" "/up" "GET" nil))
          (is (null (funcall published "app.example.com" "/UP" "GET" nil))))))))

(test gateway-controller-retries-failed-router-publication
  (with-temporary-store (store directory)
    (values directory)
    (gwc-seed store)
    (let* ((fail t) (attempts 0) (published nil)
           (controller (gr8s.controllers::make-gateway-controller
                        store
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore port resolver tls))
                                    (setf published router) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)))
                        :swap-fn (lambda (handle router)
                                   (declare (ignore handle))
                                   (incf attempts)
                                   (when fail (error "injected publication failure"))
                                   (setf published router)))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (let ((old published))
        (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
        (signals error (gr8s.controllers::converge-gateway-listeners controller))
        (is (eq old published))
        (setf fail nil)
        (gr8s.controllers::converge-gateway-listeners controller)
        (is (= 2 attempts))
        (is (null (funcall published "app.example.com" "/" "GET" nil)))))))

(test gateway-planner-intersects-route-and-listener-hostnames
  (dolist (case '(("foo.example.com" nil "foo.example.com" "bar.example.com")
                  ("*.example.com" ("foo.example.com") "foo.example.com" "bar.example.com")
                  ("foo.example.com" ("*.example.com") "foo.example.com" "bar.example.com")
                  ("*.example.com" ("*.sub.example.com") "a.sub.example.com" "a.example.com")
                  ("*.sub.example.com" ("*.example.com") "a.sub.example.com" "a.example.com")))
    (destructuring-bind (hostname route-hosts accepted denied) case
      (let* ((gateway (gr8s.resources::core-object
                       "metadata" (gr8s.resources::core-object "namespace" "infra" "name" "web")
                       "spec" (gr8s.resources::core-object
                               "listeners" (vector (gr8s.resources::core-object
                                                    "name" "http" "protocol" "HTTP" "port" 8080
                                                    "hostname" hostname)))))
             (route (gr8s.resources::core-object
                     "metadata" (gr8s.resources::core-object "namespace" "infra" "name" "app")
                     "spec" (gr8s.resources::core-object
                             "hostnames" (coerce route-hosts 'vector)
                             "parentRefs" (vector (gr8s.resources::core-object "name" "web"))
                             "rules" (vector (gr8s.resources::core-object
                                              "backendRefs" (vector (gr8s.resources::core-object "name" "backend" "port" 80)))))))
             (plan (gr8s.controllers::gateway-listener-plan (list gateway) (list route) (constantly t)))
             (router (gr8s.controllers::build-gateway-router (getf (first plan) :routes))))
        (is (not (null (funcall router accepted "/" "GET" nil))))
        (is (null (funcall router denied "/" "GET" nil)))))))

(test gateway-allowed-routes-controls-namespace-and-kind-admission
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gwc-seed store)
    (gr8s.resources::create-core-resource
     store "namespaces" (com.inuoe.jzon:parse
                         "{\"metadata\":{\"name\":\"tenant\",\"labels\":{\"team\":\"blue\"}}}") nil)
    (let ((route (gr8s.resources::copy-core-object
                  (gr8s.resources::get-core-resource store "httproutes" "default" "app"))))
      (setf (gethash "namespace" (gethash "metadata" route)) "tenant"
            (gethash "namespace" (aref (gethash "parentRefs" (gethash "spec" route)) 0)) "default")
      (remhash "resourceVersion" (gethash "metadata" route))
      (remhash "uid" (gethash "metadata" route))
      (gr8s.resources::create-core-resource store "httproutes" route "tenant"))
    (gr8s.resources::delete-core-resource store "httproutes" "default" "app")
    (let ((controller (gr8s.controllers::make-gateway-controller
                       store :start-fn (lambda (&rest args) (declare (ignore args)) :listener)
                       :swap-fn (lambda (&rest args) (declare (ignore args)))
                       :stop-fn (lambda (&rest args) (declare (ignore args))))))
      (dolist (case '(("{}" nil)
                      ("{\"namespaces\":{\"from\":\"All\"}}" t)
                      ("{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchLabels\":{\"team\":\"blue\"}}}}" t)
                      ("{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchLabels\":{\"team\":\"red\"}}}}" nil)
                      ("{\"namespaces\":{\"from\":\"Selector\",\"selector\":{\"matchExpressions\":[{\"key\":\"team\",\"operator\":\"In\",\"values\":[\"blue\"]}]}}}" t)
                      ("{\"namespaces\":{\"from\":\"All\"},\"kinds\":[{\"kind\":\"TCPRoute\"}]}" nil)
                      ("{\"namespaces\":{\"from\":\"All\"},\"kinds\":[{\"kind\":\"HTTPRoute\",\"group\":\"example.com\"}]}" nil)
                      ("{\"namespaces\":{\"from\":\"All\"},\"kinds\":[{\"kind\":\"HTTPRoute\"}]}" t)))
        (destructuring-bind (policy expected) case
          (gr8s.resources::update-core-resource
           store "gateways" "default" "web"
           (lambda (gateway)
             (setf (gethash "allowedRoutes" (aref (gethash "listeners" (gethash "spec" gateway)) 0))
                   (com.inuoe.jzon:parse policy))
             gateway))
          (gr8s.controllers::converge-gateway-listeners controller)
          (let ((router (gethash 8080 (gr8s.controllers::gateway-controller-routing-bases controller))))
            (is (eq expected (not (null (funcall router "app.example.com" "/" "GET" nil)))))))))))

(test gateway-tls-secret-grant-controls-planning-and-projection
  (let* ((objects (make-hash-table :test #'equal))
         (gateway (com.inuoe.jzon:parse
                   "{\"metadata\":{\"name\":\"web\",\"namespace\":\"source\"},\"spec\":{\"listeners\":[{\"name\":\"https\",\"protocol\":\"HTTPS\",\"port\":443,\"tls\":{\"certificateRefs\":[{\"name\":\"cert\",\"namespace\":\"target\"}]}}]}}"))
         (grant (com.inuoe.jzon:parse
                 "{\"spec\":{\"from\":[{\"group\":\"gateway.networking.k8s.io\",\"kind\":\"Gateway\",\"namespace\":\"source\"}],\"to\":[{\"group\":\"\",\"kind\":\"Secret\",\"name\":\"cert\"}]}}")))
    (setf (gethash '("gateways" "source" "web") objects) gateway
          (gethash '("secrets" "target" "cert") objects)
          (com.inuoe.jzon:parse "{\"kind\":\"Secret\",\"metadata\":{\"name\":\"cert\",\"namespace\":\"target\"},\"type\":\"kubernetes.io/tls\",\"data\":{\"tls.crt\":\"Y2VydA==\",\"tls.key\":\"a2V5\"}}"))
    (dolist (allowed '(nil t nil))
      (if allowed
          (setf (gethash '("referencegrants" "target" "allow") objects) grant)
          (remhash '("referencegrants" "target" "allow") objects))
      (let* ((view (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index objects)))
             (plan (gr8s.controllers::gateway-listener-plan (list gateway) nil (constantly t) view)))
        (is (eq allowed (not (null (getf (first plan) :tls)))))
        (is (= (if allowed 1 0) (length (gr8s.kubelet::gateway-referenced-tls-secrets view))))))))

(test gateway-tls-material-requires-a-usable-matching-key
  (let* ((root (asdf:system-relative-pathname "gr8s" "tests/fixtures/gateway-tls/"))
         (cert (uiop:read-file-string (merge-pathnames "server.crt" root)))
         (key (uiop:read-file-string (merge-pathnames "server.key" root)))
         (other (uiop:read-file-string (merge-pathnames "other.key" root))))
    (flet ((valid (certificate private-key)
             (gr8s.controllers::gateway-tls-material-valid-p
              (ag-grpc:base64-encode (babel:string-to-octets certificate :encoding :utf-8))
              (ag-grpc:base64-encode (babel:string-to-octets private-key :encoding :utf-8)))))
      (is (valid cert key))
      (is (not (valid cert other)))
      (is (not (valid "Hello world" key)))
      (is (not (valid cert "Hello world")))
      (is (not (valid (concatenate 'string cert (format nil "-----BEGIN CERTIFICATE-----~%broken~%-----END CERTIFICATE-----~%")) key)))
      (is (not (valid "-----BEGIN CERTIFICATE-----" key)))
      (is (valid cert key)))))

(test gateway-invalid-tls-material-is-neither-ready-nor-materialized
  (with-temporary-store (store directory)
    (let* ((secret (gw-parse "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"tls\"},\"type\":\"kubernetes.io/tls\",\"data\":{\"tls.crt\":\"SGVsbG8gd29ybGQK\",\"tls.key\":\"SGVsbG8gd29ybGQK\"}}"))
           (listener (gw-parse "{\"name\":\"https\",\"protocol\":\"HTTPS\",\"port\":443,\"tls\":{\"certificateRefs\":[{\"name\":\"tls\"}]}}")))
      (gr8s.resources::create-core-resource store "secrets" secret "default")
      (is (equal "InvalidCertificateRef"
                 (gr8s.controllers::foreign-gateway-listener-tls-error store "default" listener)))
      (is (null (gr8s.controllers::gateway-resolve-listener-tls store '("default" . "tls") directory)))
      (is (not (probe-file (merge-pathnames "default-tls.crt" directory)))))))

(test gateway-invalid-tls-replacement-stops-the-old-listener
  (with-temporary-store (store directory)
    (gwc-seed store)
    (gr8s.resources::create-core-resource store "secrets" (gateway-test-tls-secret "tls") "default")
    (gr8s.resources::update-core-resource
     store "gateways" "default" "web"
     (lambda (gateway)
       (let ((listener (aref (gethash "listeners" (gethash "spec" gateway)) 0)))
         (setf (gethash "protocol" listener) "HTTPS"
               (gethash "tls" listener) (gr8s.resources::core-object
                                        "certificateRefs" (vector (gr8s.resources::core-object "name" "tls")))))
       gateway))
    (let* ((starts 0) (stops 0)
           (controller (gr8s.controllers::make-gateway-controller
                        store :cert-dir directory
                        :start-fn (lambda (&rest args) (declare (ignore args)) (incf starts) :listener)
                        :stop-fn (lambda (handle) (declare (ignore handle)) (incf stops))
                        :swap-fn (lambda (&rest args) (declare (ignore args))))))
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 starts))
      (gr8s.resources::update-core-resource
       store "secrets" "default" "tls"
       (lambda (secret) (setf (gethash "tls.key" (gethash "data" secret)) "SGVsbG8=") secret))
      (gr8s.controllers::converge-gateway-listeners controller)
      (is (= 1 stops))
      (is (= 1 starts))
      (is (= 0 (hash-table-count (gr8s.controllers::gateway-controller-listeners controller)))))))

(test gateway-tls-material-cache-skips-repeated-crypto
  (let* ((secret (gateway-test-tls-secret "tls"))
         (data (gethash "data" secret))
         (check (symbol-function 'gr8s.controllers::gateway-check-tls-material))
         (calls 0)
         (gr8s.controllers::*gateway-tls-material-cache* (make-hash-table :test 'equal)))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.controllers::gateway-check-tls-material)
                 (lambda (&rest args) (incf calls) (apply check args)))
           (dotimes (i 3)
             (is (gr8s.controllers::gateway-tls-material-valid-p (gethash "tls.crt" data) (gethash "tls.key" data))))
           (is (= 1 calls)))
      (setf (symbol-function 'gr8s.controllers::gateway-check-tls-material) check))))

(test gateway-l4-planning-respects-route-admission
  (dolist (protocol '("TCP" "TLS"))
    (let* ((kind (if (equal protocol "TCP") "TCPRoute" "TLSRoute"))
           (listener (gr8s.resources::core-object "name" "listener" "port" 8443 "protocol" protocol))
           (gateway (gr8s.resources::core-object
                     "metadata" (gr8s.resources::core-object "name" "web" "namespace" "infra")
                     "spec" (gr8s.resources::core-object "listeners" (vector listener))))
           (route (gr8s.resources::core-object
                   "kind" kind "metadata" (gr8s.resources::core-object "name" "route" "namespace" "apps")
                   "spec" (gr8s.resources::core-object
                           "parentRefs" (vector (gr8s.resources::core-object "name" "web" "namespace" "infra"))
                           "hostnames" (vector "example.test") "rules" #()))))
      (flet ((routes ()
               (let ((plan (gr8s.controllers::gateway-l4-plan
                            (list gateway) (when (equal protocol "TCP") (list route))
                            (when (equal protocol "TLS") (list route)) nil (constantly t))))
                 (getf (first plan) (if (equal protocol "TCP") :tcp-routes :sni-routes)))))
        (is (null (routes)))
        (setf (gethash "allowedRoutes" listener)
              (gr8s.resources::core-object "namespaces" (gr8s.resources::core-object "from" "All")))
        (is (= 1 (length (routes))))
        (setf (gethash "kinds" (gethash "allowedRoutes" listener))
              (vector (gr8s.resources::core-object "kind" "HTTPRoute")))
        (is (null (routes)))
        (setf (gethash "kinds" (gethash "allowedRoutes" listener))
              (vector (gr8s.resources::core-object "kind" kind)))
        (is (= 1 (length (routes))))))))

(test gateway-full-reconciliation-refreshes-backend-validity
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gwc-seed store)
    (let* ((published nil)
           (controller (gr8s.controllers::make-gateway-controller
                        store
                        :start-fn (lambda (port router resolver tls)
                                    (declare (ignore port resolver tls)) (setf published router) :listener)
                        :swap-fn (lambda (handle router) (declare (ignore handle)) (setf published router))
                        :stop-fn (lambda (handle) (declare (ignore handle))))))
      (dolist (kind '("Service" "WrongKind" "Service"))
        (gr8s.resources::update-core-resource
         store "httproutes" "default" "app"
         (lambda (route)
           (setf (gethash "kind" (aref (gethash "backendRefs" (aref (gethash "rules" (gethash "spec" route)) 0)) 0)) kind)
           route))
        (gr8s.controllers::converge-gateway-listeners controller)
        (let* ((action (funcall published "app.example.com" "/up" "GET" nil))
               (backend (gr8s.controllers::gw-dispatch-backend action)))
          (is (not (null backend)))
          (is (equal (unless (equal kind "Service") "InvalidKind")
                     (gr8s.controllers::gw-backend-invalid-reason backend))))))))
