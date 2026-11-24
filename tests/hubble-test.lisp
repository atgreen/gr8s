;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify `gr8s doctor observe --serve': gr8s flow events as Hubble flow.Flow messages, the
;;;; request's FlowFilters applied as Hubble applies them, and GetFlows served over
;;;; real gRPC from a real API server and agent session, read by Hubble's own
;;;; Observer client stub.

(in-package #:gr8s/tests)
(def-suite hubble :in gr8s)
(in-suite hubble)

(defun hubble-test-flow (&rest pairs)
  "A flow event with PAIRS in place of the defaults."
  (apply #'gr8s.resources::core-object
         (append (list "time" "2026-11-22T01:02:03.456Z" "node" "worker-a" "verdict" "DROPPED" "reason" "policy"
                       "direction" "egress" "protocol" "TCP" "namespace" "shop" "pod" "cart-0"
                       "podAddress" "10.88.7.4" "podPort" 41000 "peerAddress" "10.88.9.3" "peerPort" 443
                       "peerNamespace" "data" "peerPod" "db-0" "policies" #("deny-egress")
                       "podLabels" (gr8s.resources::core-object "app" "cart"))
                 pairs)))

(defun hubble-endpoint-of (flow slot)
  (let ((endpoint (slot-value flow slot)))
    (list (slot-value endpoint 'gr8s.hubble.observer::namespace)
          (slot-value endpoint 'gr8s.hubble.observer::pod-name))))

(test a-flow-of-a-protocol-gr8s-cannot-name-still-becomes-a-hubble-flow
  ;; An agent gives the number of a protocol it can't name, such as IGMP's 2; the
  ;; dashboard died serializing it as the flow's summary (podster-atf).
  (let ((flow (gr8s.server::hubble-flow (hubble-test-flow "protocol" 2))))
    (is (equal "2" (slot-value flow 'gr8s.hubble.observer::summary)))
    (is (plusp (length (ag-proto:serialize-to-bytes flow))))))

(test gr8s-flows-become-hubble-flows
  (let* ((flow (gr8s.server::hubble-flow (hubble-test-flow)))
         (ip (slot-value flow 'gr8s.hubble.observer::ip))
         (tcp (slot-value (slot-value flow 'gr8s.hubble.observer::l4) 'gr8s.hubble.observer::tcp)))
    (is (= gr8s.hubble.observer::+verdict-dropped+ (slot-value flow 'gr8s.hubble.observer::verdict)))
    (is (= gr8s.hubble.observer::+dropreason-policy_denied+ (slot-value flow 'gr8s.hubble.observer::drop-reason-desc)))
    (is (= gr8s.hubble.observer::+trafficdirection-egress+ (slot-value flow 'gr8s.hubble.observer::traffic-direction)))
    ;; Traffic from the Pod has the Pod as its source.
    (is (equal '("shop" "cart-0") (hubble-endpoint-of flow 'gr8s.hubble.observer::source)))
    (is (equal '("data" "db-0") (hubble-endpoint-of flow 'gr8s.hubble.observer::destination)))
    (is (equal '("10.88.7.4" "10.88.9.3") (list (slot-value ip 'gr8s.hubble.observer::source)
                                                (slot-value ip 'gr8s.hubble.observer::destination))))
    (is (equal '(41000 443) (list (slot-value tcp 'gr8s.hubble.observer::source-port)
                                  (slot-value tcp 'gr8s.hubble.observer::destination-port))))
    (is (equal '("deny-egress") (mapcar (lambda (policy) (slot-value policy 'gr8s.hubble.observer::name))
                                        (slot-value flow 'gr8s.hubble.observer::egress-denied-by))))
    (is (null (slot-value flow 'gr8s.hubble.observer::ingress-denied-by)))
    ;; A drop notification with its reason, never a reply, as the hubble CLI prints it.
    (is (equal '(1 133) (list (slot-value (slot-value flow 'gr8s.hubble.observer::event-type) 'gr8s.hubble.observer::proto-type)
                             (slot-value (slot-value flow 'gr8s.hubble.observer::event-type) 'gr8s.hubble.observer::sub-type))))
    (is (slot-value flow 'gr8s.hubble.observer::is-reply))
    (is (null (slot-value (slot-value flow 'gr8s.hubble.observer::is-reply) 'gr8s.hubble.observer::value)))
    (is (equal '("k8s:app=cart" "k8s:io.kubernetes.pod.namespace=shop")
               (slot-value (slot-value flow 'gr8s.hubble.observer::source) 'gr8s.hubble.observer::labels)))
    (is (= 1795309323 (slot-value (slot-value flow 'gr8s.hubble.observer::proto-time) 'gr8s.hubble.observer::seconds)))
    (is (= 456000000 (slot-value (slot-value flow 'gr8s.hubble.observer::proto-time) 'gr8s.hubble.observer::nanos)))
    (is (= 456789000 (slot-value (gr8s.server::hubble-timestamp "2026-11-22T01:02:03.456789Z")
                                 'gr8s.hubble.observer::nanos)))
    ;; The message survives a protobuf round trip, as the hubble CLI will read it.
    (let ((read (ag-proto:deserialize-from-bytes 'gr8s.hubble.observer::flow (ag-proto:serialize-to-bytes flow))))
      (is (equal "cart-0" (slot-value (slot-value read 'gr8s.hubble.observer::source) 'gr8s.hubble.observer::pod-name)))
      (is (= 443 (slot-value (slot-value (slot-value read 'gr8s.hubble.observer::l4) 'gr8s.hubble.observer::tcp)
                             'gr8s.hubble.observer::destination-port)))))
  ;; Traffic to the Pod has the peer as its source.
  (let* ((flow (gr8s.server::hubble-flow (hubble-test-flow "direction" "ingress" "podPort" 80 "peerPort" 5555)))
         (tcp (slot-value (slot-value flow 'gr8s.hubble.observer::l4) 'gr8s.hubble.observer::tcp)))
    (is (equal '("data" "db-0") (hubble-endpoint-of flow 'gr8s.hubble.observer::source)))
    (is (equal '(5555 80) (list (slot-value tcp 'gr8s.hubble.observer::source-port)
                                (slot-value tcp 'gr8s.hubble.observer::destination-port))))
    (is (slot-value flow 'gr8s.hubble.observer::ingress-denied-by)))
  (let ((flow (gr8s.server::hubble-flow (hubble-test-flow "verdict" "FORWARDED" "reason" nil "policies" #()))))
    (is (= gr8s.hubble.observer::+verdict-forwarded+ (slot-value flow 'gr8s.hubble.observer::verdict)))
    (is (null (slot-value flow 'gr8s.hubble.observer::egress-denied-by)))))

(defun hubble-request (&rest arguments)
  (apply #'make-instance 'gr8s.hubble.observer::get-flows-request arguments))

(defun hubble-filter (&rest arguments)
  (apply #'make-instance 'gr8s.hubble.observer::flow-filter arguments))

(test gateway-requests-become-hubble-l7-flows
  (let* ((flow (gr8s.server::hubble-flow
                (hubble-test-flow "verdict" "FORWARDED" "reason" nil "policies" #() "direction" "ingress"
                                  "podPort" 8080 "peerPod" nil "peerNamespace" nil "peerAddress" "192.0.2.7"
                                  "peerPort" 5555
                                  "l7" (gr8s.resources::core-object "type" "http" "method" "GET" "host" "app.example.com"
                                                                    "path" "/cart" "code" 503 "latencyNs" 12500000))))
         (l7 (slot-value flow 'gr8s.hubble.observer::l7))
         (http (slot-value l7 'gr8s.hubble.observer::http)))
    (is (= gr8s.hubble.observer::+flowtype-l7+ (slot-value flow 'gr8s.hubble.observer::proto-type)))
    (is (= 129 (slot-value (slot-value flow 'gr8s.hubble.observer::event-type) 'gr8s.hubble.observer::proto-type)))
    (is (= gr8s.hubble.observer::+l7flowtype-response+ (slot-value l7 'gr8s.hubble.observer::proto-type)))
    (is (= 12500000 (slot-value l7 'gr8s.hubble.observer::latency-ns)))
    (is (equal "HTTP/1.1 503 12ms (GET http://app.example.com/cart)" (slot-value flow 'gr8s.hubble.observer::summary)))
    (is (equal '(503 "GET" "http://app.example.com/cart")
               (list (slot-value http 'gr8s.hubble.observer::code) (slot-value http 'gr8s.hubble.observer::proto-method)
                     (slot-value http 'gr8s.hubble.observer::url))))
    ;; It survives the wire, oneof and all.
    (let ((decoded (ag-proto:deserialize-from-bytes 'gr8s.hubble.observer::flow (ag-proto:serialize-to-bytes flow))))
      (is (= 503 (slot-value (slot-value (slot-value decoded 'gr8s.hubble.observer::l7) 'gr8s.hubble.observer::http)
                             'gr8s.hubble.observer::code))))
    (flet ((selects (&rest arguments)
             (gr8s.server::hubble-request-selects-p (apply #'hubble-request arguments) flow)))
      (is-true (selects :whitelist (list (hubble-filter :http-status-code '("5+")))))
      (is-true (selects :whitelist (list (hubble-filter :http-status-code '("503")))))
      (is-false (selects :whitelist (list (hubble-filter :http-status-code '("2+")))))
      (is-true (selects :whitelist (list (hubble-filter :http-method '("get")))))
      (is-false (selects :whitelist (list (hubble-filter :http-method '("POST")))))
      (is-true (selects :whitelist (list (hubble-filter :http-path '("^/ca")))))
      (is-false (selects :whitelist (list (hubble-filter :http-path '("^/api"))))))
    ;; A backend known only as a Service is that Service in its namespace, not the world.
    (let* ((service-flow (gr8s.server::hubble-flow
                          (hubble-test-flow "verdict" "FORWARDED" "reason" nil "policies" #() "direction" "ingress"
                                            "pod" nil "podLabels" nil "namespace" "gvision" "service" "gvision"
                                            "peerPod" nil "peerNamespace" nil
                                            "l7" (gr8s.resources::core-object "method" "GET" "code" 200))))
           (destination (slot-value service-flow 'gr8s.hubble.observer::destination)))
      (is (equal "gvision" (slot-value destination 'gr8s.hubble.observer::namespace)))
      (is (/= 2 (slot-value destination 'gr8s.hubble.observer::identity)))
      (is (equal "gvision" (gr8s.server::hubble-ui-service-name destination "id"))))
    (signals error (gr8s.server::check-hubble-filter (hubble-filter :http-status-code '("2xx"))))
    (signals error (gr8s.server::check-hubble-filter (hubble-filter :http-path '("(unclosed"))))))

(test packed-repeated-enums-decode-as-go-sends-them
  ;; FlowFilter.verdict [DROPPED, FORWARDED] as Go encodes it: field 5, wire type 2.
  (let ((filter (ag-proto:deserialize-from-bytes 'gr8s.hubble.observer::flow-filter
                                                 (coerce '(42 2 2 1) '(simple-array (unsigned-byte 8) (*))))))
    (is (equal '(2 1) (slot-value filter 'gr8s.hubble.observer::verdict))))
  ;; FlowFilter.reply [false] packed, as Hubble UI sends it: field 15, wire type 2.
  (let ((filter (ag-proto:deserialize-from-bytes 'gr8s.hubble.observer::flow-filter
                                                 (coerce '(122 1 0) '(simple-array (unsigned-byte 8) (*))))))
    (is (equal '(nil) (slot-value filter 'gr8s.hubble.observer::reply))))
  ;; One value per tag still decodes.
  (let ((filter (ag-proto:deserialize-from-bytes 'gr8s.hubble.observer::flow-filter
                                                 (coerce '(40 2 40 1) '(simple-array (unsigned-byte 8) (*))))))
    (is (equal '(2 1) (slot-value filter 'gr8s.hubble.observer::verdict)))))

(test hubble-filters-select-as-hubble-does
  (let ((flow (gr8s.server::hubble-flow (hubble-test-flow))))
    (flet ((selects (&rest arguments)
             (gr8s.server::hubble-request-selects-p (apply #'hubble-request arguments) flow)))
      (is-true (selects))
      (is-true (selects :whitelist (list (hubble-filter :source-pod '("shop/cart")))))
      (is-true (selects :whitelist (list (hubble-filter :destination-pod '("data/")))))
      (is-false (selects :whitelist (list (hubble-filter :source-pod '("data/")))))
      ;; Every field of one filter must match; any one filter may.
      (is-false (selects :whitelist (list (hubble-filter :source-pod '("shop/cart")
                                                         :verdict (list gr8s.hubble.observer::+verdict-forwarded+)))))
      (is-true (selects :whitelist (list (hubble-filter :verdict (list gr8s.hubble.observer::+verdict-forwarded+))
                                         (hubble-filter :protocol '("TCP") :destination-port '("443")))))
      (is-true (selects :whitelist (list (hubble-filter :source-ip '("10.88.0.0/16")))))
      (is-false (selects :whitelist (list (hubble-filter :destination-ip '("10.88.7.4")))))
      (is-true (selects :whitelist (list (hubble-filter :node-name '("cluster/worker-*")))))
      (is-false (selects :blacklist (list (hubble-filter :protocol '("tcp")))))
      (is-false (selects :since (make-instance 'gr8s.hubble.observer::timestamp :seconds 1795309324)))
      (is-true (selects :until (make-instance 'gr8s.hubble.observer::timestamp :seconds 1795309324)))))
  (let ((flow (gr8s.server::hubble-flow (hubble-test-flow))))
    (flet ((selects (&rest arguments)
             (gr8s.server::hubble-request-selects-p (apply #'hubble-request arguments) flow)))
      ;; Label selectors, as Hubble UI and hubble --label send them.
      (is-true (selects :whitelist (list (hubble-filter :source-label '("k8s:app=cart")))))
      (is-true (selects :whitelist (list (hubble-filter :source-label '("app=cart,k8s:io.kubernetes.pod.namespace=shop")))))
      (is-false (selects :whitelist (list (hubble-filter :source-label '("app=cart,app!=cart")))))
      (is-true (selects :whitelist (list (hubble-filter :source-label '("!reserved:host")))))
      ;; Hubble UI's standing blacklist and its reply:[false] whitelist pass gr8s flows.
      (is-true (selects :whitelist (list (hubble-filter :source-pod '("shop/") :reply '(nil)))
                        :blacklist (list (hubble-filter :source-label '("reserved:unknown"))
                                         (hubble-filter :source-fqdn '("*.cluster.local*")))))
      (is-false (selects :whitelist (list (hubble-filter :reply '(t)))))
      ;; A flow with no HTTP record passes no HTTP filter.
      (is-false (selects :whitelist (list (hubble-filter :http-method '("GET")))))))
  ;; An address gr8s doesn't know as a Pod is Cilium's world.
  (let ((peer (slot-value (gr8s.server::hubble-flow (hubble-test-flow "peerPod" nil "peerNamespace" nil))
                          'gr8s.hubble.observer::destination)))
    (is (= 2 (slot-value peer 'gr8s.hubble.observer::identity)))
    (is (equal '("reserved:world") (slot-value peer 'gr8s.hubble.observer::labels))))
  (signals gr8s.server::hubble-unsupported-filter
    (gr8s.server::check-hubble-filter (hubble-filter :destination-service '("default/web")))))

(test hubble-serves-the-clusters-flows-over-grpc
  (with-forwarding-agent (runtime pod listener node-runtime)
    (values pod listener)
    (let ((collector (gr8s.agent::%make-flow-collector
                      nil "worker-forward"
                      (lambda (address) (and (equal address "10.88.7.4") (values "shop" "cart-0")))))
          (api nil) (grpc nil) (channel nil))
      (setf (gr8s.agent::node-runtime-flow-collector node-runtime) collector)
      (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 3001))
      (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 3002 :peer-port 80))
      (unwind-protect
           (let ((config (list :server nil)))
             (setf api (start-http-test-server
                        :store (gr8s.controllers::control-plane-runtime-store runtime) :runtime runtime)
                   (getf config :server) (format nil "http://127.0.0.1:~D" *http-test-port*)
                   grpc (ag-grpc:make-grpc-server 0 :host "127.0.0.1"))
             (gr8s.server::register-hubble-observer grpc config nil)
             (bt:make-thread (lambda () (ag-grpc:server-start grpc)) :name "gr8s test hubble")
             (is-true (wait-until (lambda () (ag-grpc::server-socket grpc)) :timeout 10))
             (setf channel (ag-grpc:make-channel "127.0.0.1" (usocket:get-local-port (ag-grpc::server-socket grpc))))
             (let* ((stub (gr8s.hubble.observer::make-observer-stub channel))
                    (stream (gr8s.hubble.observer::observer-get-flows
                             stub (hubble-request :whitelist (list (hubble-filter :destination-port '("443"))))))
                    (flows (loop for response = (ag-grpc:stream-receive-message stream)
                                 while response
                                 collect (slot-value response 'gr8s.hubble.observer::flow))))
               ;; The second flow, to port 80, doesn't pass the filter.
               (is (= 1 (length flows)))
               (is (equal '("shop" "cart-0") (hubble-endpoint-of (first flows) 'gr8s.hubble.observer::source)))
               (is (equal "worker-forward" (slot-value (first flows) 'gr8s.hubble.observer::node-name)))))
        (when channel (ignore-errors (ag-grpc:channel-close channel)))
        (when grpc (ignore-errors (ag-grpc:server-stop grpc)))
        (when api (stop-server api))))))

;;; The dashboard's Hubble tab: Hubble UI's backend

(test hubble-ui-derives-cards-and-arrows-as-its-backend-does
  (let* ((map (gr8s.server::make-hubble-ui-map))
         (dropped (gr8s.server::hubble-flow (hubble-test-flow)))
         (forwarded (gr8s.server::hubble-flow (hubble-test-flow "verdict" "FORWARDED" "reason" nil "policies" #())))
         (outside (gr8s.server::hubble-flow (hubble-test-flow "peerPod" nil "peerNamespace" nil "peerAddress" "192.0.2.7"))))
    (flet ((kinds (events) (mapcar (lambda (event) (gr8s.hubble.observer::event-case event)) events))
           (link (events)
             (slot-value (slot-value (find :service-link-state events :key #'gr8s.hubble.observer::event-case)
                                     'gr8s.hubble.observer::service-link-state)
                         'gr8s.hubble.observer::service-link)))
      (let ((events (gr8s.server::hubble-ui-map-changes map dropped)))
        ;; Two new cards and their arrow.
        (is (equal '(:service-state :service-state :service-link-state) (kinds events)))
        (let ((cart (slot-value (slot-value (first events) 'gr8s.hubble.observer::service-state)
                                'gr8s.hubble.observer::service)))
          (is (equal "cart" (slot-value cart 'gr8s.hubble.observer::name)))
          (is (equal (princ-to-string (gr8s.server::hubble-identity "shop" "cart-0"))
                     (slot-value cart 'gr8s.hubble.observer::id))))
        (is (equal (format nil "~D TCP ~D:443" (gr8s.server::hubble-identity "shop" "cart-0")
                           (gr8s.server::hubble-identity "data" "db-0"))
                   (slot-value (link events) 'gr8s.hubble.observer::id))))
      ;; Seen again, nothing changes; a new verdict modifies the arrow.
      (is (null (gr8s.server::hubble-ui-map-changes map dropped)))
      (let ((events (gr8s.server::hubble-ui-map-changes map forwarded)))
        (is (equal '(:service-link-state) (kinds events)))
        (is (= gr8s.hubble.observer::+statechange-modified+
               (slot-value (slot-value (first events) 'gr8s.hubble.observer::service-link-state)
                           'gr8s.hubble.observer::proto-type))))
      ;; The world has its own card for each side.
      (is (equal "world-receiver" (slot-value (link (gr8s.server::hubble-ui-map-changes map outside))
                                              'gr8s.hubble.observer::destination-id))))))

(defun hubble-ui-post (backend route &key channel body terminate)
  "Send one Message to ROUTE as Hubble UI does, returning the reply Message."
  (let ((reply (gr8s.server::answer-hubble-ui-request
                backend route
                (ag-proto:serialize-to-bytes
                 (make-instance 'gr8s.hubble.observer::message
                                :meta (make-instance 'gr8s.hubble.observer::meta
                                                     :trace-id "t1" :route-name route
                                                     :channel-id (or channel "")
                                                     :is-not-ready (and channel (not terminate) t)
                                                     :is-terminated terminate)
                                :body (make-instance 'gr8s.hubble.observer::body
                                                     :content (or body (make-array 0 :element-type '(unsigned-byte 8)))))))))
    (and reply (ag-proto:deserialize-from-bytes 'gr8s.hubble.observer::message reply))))

(defun hubble-ui-meta (message slot)
  (slot-value (slot-value message 'gr8s.hubble.observer::meta) slot))

(defun hubble-ui-payload (message)
  (let ((body (slot-value message 'gr8s.hubble.observer::body)))
    (and body (plusp (length (slot-value body 'gr8s.hubble.observer::content)))
         (slot-value body 'gr8s.hubble.observer::content))))

(defun hubble-ui-poll-until (backend route channel predicate)
  "Poll CHANNEL until a payload satisfies PREDICATE, returning that payload's bytes, or NIL."
  (loop repeat 100
        for reply = (hubble-ui-post backend route :channel channel)
        for payload = (hubble-ui-payload reply)
        do (is (plusp (hubble-ui-meta reply 'gr8s.hubble.observer::poll-delay-ms)))
        when (and payload (funcall predicate payload)) return payload
        do (sleep 0.05)))

(test hubble-ui-streams-namespaces-and-the-service-map-over-its-protocol
  (with-forwarding-agent (runtime pod listener node-runtime)
    (values pod listener)
    (let ((collector (gr8s.agent::%make-flow-collector
                      nil "worker-forward"
                      (lambda (address) (and (equal address "10.88.7.4") (values "default" "hello")))))
          (api nil))
      (setf (gr8s.agent::node-runtime-flow-collector node-runtime) collector)
      (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 4001))
      (unwind-protect
           (let* ((store (gr8s.controllers::control-plane-runtime-store runtime))
                  (backend (gr8s.server::make-hubble-ui-backend nil)))
             (gr8s.resources::create-core-resource
              store "namespaces"
              (gr8s.resources::core-object "apiVersion" "v1" "kind" "Namespace"
                                           "metadata" (gr8s.resources::core-object "name" "default"))
              nil)
             (setf api (start-http-test-server :store store :runtime runtime)
                   (gr8s.server::hubble-ui-backend-config backend)
                   (list :server (format nil "http://127.0.0.1:~D" *http-test-port*)))
             ;; control-stream: the server names the channel, then sends the namespaces.
             (let* ((opened (hubble-ui-post backend "control-stream"))
                    (channel (hubble-ui-meta opened 'gr8s.hubble.observer::channel-id)))
               (is (cl-ppcre:scan "^[0-9a-f]{16}$" channel))
               (is (equal "t1" (hubble-ui-meta opened 'gr8s.hubble.observer::trace-id)))
               (let* ((payload (or (hubble-ui-payload opened)
                                   (hubble-ui-poll-until backend "control-stream" channel (constantly t))))
                      (response (ag-proto:deserialize-from-bytes
                                 'gr8s.hubble.observer::get-control-stream-response payload))
                      (namespaces (slot-value (slot-value response 'gr8s.hubble.observer::namespaces)
                                              'gr8s.hubble.observer::namespaces)))
                 (is (find "default" namespaces :test #'equal
                                                :key (lambda (state)
                                                       (slot-value (slot-value state 'gr8s.hubble.observer::namespace)
                                                                   'gr8s.hubble.observer::name))))
                 ;; Hubble UI lists only a namespace with an id.
                 (is (every (lambda (state)
                              (plusp (length (slot-value (slot-value state 'gr8s.hubble.observer::namespace)
                                                         'gr8s.hubble.observer::id))))
                            namespaces)))
               (is (hubble-ui-meta (hubble-ui-post backend "control-stream" :channel channel :terminate t)
                                   'gr8s.hubble.observer::is-terminated)))
             ;; service-map-stream: Hubble UI's own request for namespace default.
             (let* ((request (make-instance
                              'gr8s.hubble.observer::get-events-request
                              :event-types (list 5 3 4)
                              :whitelist (mapcar (lambda (filter)
                                                   (let ((event (make-instance 'gr8s.hubble.observer::event-filter
                                                                               :flow-filter filter)))
                                                     (setf (gr8s.hubble.observer::filter-case event) :flow-filter)
                                                     event))
                                                 (list (hubble-filter :source-pod '("default/") :reply '(nil))
                                                       (hubble-filter :destination-pod '("default/") :reply '(nil))))))
                    (opened (hubble-ui-post backend "service-map-stream"
                                            :body (ag-proto:serialize-to-bytes request)))
                    (channel (hubble-ui-meta opened 'gr8s.hubble.observer::channel-id))
                    (payload (or (hubble-ui-payload opened)
                                 (hubble-ui-poll-until backend "service-map-stream" channel (constantly t))))
                    (response (and payload (ag-proto:deserialize-from-bytes
                                            'gr8s.hubble.observer::get-events-response payload)))
                    (kinds (mapcar #'gr8s.hubble.observer::event-case
                                   (and response (slot-value response 'gr8s.hubble.observer::events)))))
               (is (equal :flows (first kinds)))
               (is (= 2 (count :service-state kinds)))
               (is (= 1 (count :service-link-state kinds)))
               (hubble-ui-post backend "service-map-stream" :channel channel :terminate t))
             (is (null (hubble-ui-post backend "no-such-stream"))))
        (when api (stop-server api))))))

(test hubble-ui-serves-its-app-under-the-session-path
  (if (not (gr8s.apiserver::hubble-ui-assets-present-p))
      (skip "Hubble UI assets aren't vendored; run make hubble-ui-assets")
      (let ((acceptor (make-instance 'gr8s.server::hubble-ui-acceptor
                                     :address "127.0.0.1" :port 0 :base "/hubble/abc/"
                                     :backend (gr8s.server::make-hubble-ui-backend nil))))
        (hunchentoot:start acceptor)
        (unwind-protect
             (flet ((get-path (path)
                      (drakma:http-request (format nil "http://127.0.0.1:~D~A" (hunchentoot:acceptor-port acceptor) path)
                                           :proxy nil :force-binary t)))
               (let ((index (trivial-utf-8:utf-8-bytes-to-string (get-path "/hubble/abc/"))))
                 (is (search "<base href=\"/hubble/abc/\">" index))
                 (is (search "Hubble UI" index)))
               ;; The app's own routes fall back to index.html; other paths aren't served.
               (is (search "Hubble UI" (trivial-utf-8:utf-8-bytes-to-string (get-path "/hubble/abc/somewhere"))))
               (is (= 404 (nth-value 1 (get-path "/other")))))
          (hunchentoot:stop acceptor)))))

(test the-dashboard-serves-headlamp-and-hubble-as-tabs-of-one-page
  (let ((acceptor (make-instance 'gr8s.server::gr8s-dashboard-acceptor
                                 :address "127.0.0.1" :port 0
                                 :shell-path "/ui/tok/"
                                 :tabs '(("headlamp" "/dashboard/tok/" "Headlamp") ("hubble" "/hubble/tok/" "Hubble"))
                                 :hubble-backend (gr8s.server::make-hubble-ui-backend nil) :hubble-base "/hubble/tok/"
                                 :proxy-fn (lambda (&rest arguments) (declare (ignore arguments)) "proxied")
                                 :multiplexer-fn nil
                                 :access-log-destination nil :message-log-destination nil))
        (base gr8s.apiserver::*dashboard-base*))
    ;; Acceptor threads read the global value, as `gr8s dashboard' sets it.
    (setf gr8s.apiserver::*dashboard-base* "/dashboard/tok")
    (hunchentoot:start acceptor)
    (unwind-protect
         (flet ((get-path (path)
                  (multiple-value-bind (body status)
                      (drakma:http-request (format nil "http://127.0.0.1:~D~A" (hunchentoot:acceptor-port acceptor) path)
                                           :proxy nil :force-binary t)
                    (values (trivial-utf-8:utf-8-bytes-to-string body) status))))
           (let ((page (get-path "/ui/tok/")))
             (is (search "data-src=\"/dashboard/tok/\">Headlamp</button>" page))
             (is (search "data-src=\"/hubble/tok/\">Hubble</button>" page))
             (is (search "id=\"frame-hubble\" title=\"Hubble\"" page))
             (is (search "show(location.hash.slice(1) || 'headlamp')" page))
             ;; Its browser tab has the gr8s icon, inline, so no other request serves it.
             (is (search "<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml," page)))
           (is (= 200 (nth-value 1 (get-path "/ui/tok"))))
           ;; Each tab's app answers under the same token.
           (is (search "\"clusters\"" (get-path "/dashboard/tok/config")))
           (when (gr8s.apiserver::hubble-ui-assets-present-p)
             (is (search "<base href=\"/hubble/tok/\">" (get-path "/hubble/tok/"))))
           (is (= 404 (nth-value 1 (get-path "/ui/other/")))))
      (hunchentoot:stop acceptor)
      (setf gr8s.apiserver::*dashboard-base* base))))

(test the-dashboard-answers-an-unreachable-cluster-api-with-a-502
  (let* ((closed (let ((listener (usocket:socket-listen "127.0.0.1" 0)))
                   (prog1 (usocket:get-local-port listener) (usocket:socket-close listener))))
         (config (list :server (format nil "http://127.0.0.1:~D" closed)))
         (acceptor (make-instance 'gr8s.server::gr8s-dashboard-acceptor
                                  :address "127.0.0.1" :port 0 :shell-path "/ui/tok/"
                                  :tabs '(("headlamp" "/dashboard/tok/" "Headlamp"))
                                  :proxy-fn (lambda (method target request)
                                              (gr8s.server::dashboard-proxy-forward config method target request))
                                  :multiplexer-fn nil
                                  :access-log-destination nil :message-log-destination nil))
         (base gr8s.apiserver::*dashboard-base*))
    (setf gr8s.apiserver::*dashboard-base* "/dashboard/tok")
    (hunchentoot:start acceptor)
    (unwind-protect
         (multiple-value-bind (body status)
             (drakma:http-request (format nil "http://127.0.0.1:~D/dashboard/tok/clusters/gr8s/api/v1/nodes"
                                          (hunchentoot:acceptor-port acceptor))
                                  :proxy nil)
           (is (= 502 status))
           (is (search "cluster API" body))
           (is (search (format nil "127.0.0.1:~D" closed) body)))
      (hunchentoot:stop acceptor)
      (setf gr8s.apiserver::*dashboard-base* base))))

;;; DashboardTabs: the cluster's apps as dashboard tabs (podster-ckt).

(defvar *dashboard-app-upstream-seen* nil)

(defclass dashboard-app-upstream (hunchentoot:acceptor) ()
  (:default-initargs :access-log-destination nil :message-log-destination nil))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor dashboard-app-upstream) request)
  ;; Plays the cluster API's services/proxy: records what came, answers like an app.
  (push (list (hunchentoot:request-uri request) (hunchentoot:header-in :cookie request)
              (hunchentoot:header-in :authorization request))
        *dashboard-app-upstream-seen*)
  (setf (hunchentoot:header-out :x-frame-options) "deny"
        (hunchentoot:header-out :content-security-policy) "default-src 'self'; frame-ancestors 'none'"
        (hunchentoot:content-type*) "text/plain")
  (hunchentoot:set-cookie "grafana_session" :value "abc" :path "/")
  "grafana")

(test dashboard-tabs-come-from-the-clusters-dashboardtabs
  (let ((app (gr8s.server::dashboard-tab-object-app
              (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"grafana\"},\"spec\":{\"title\":\"Grafana\",\"service\":{\"namespace\":\"monitoring\",\"name\":\"grafana\",\"port\":80}}}"))))
    (is (equal '("grafana" "Grafana" "monitoring" "grafana" 80 "/")
               (list (gr8s.server::dashboard-app-name app) (gr8s.server::dashboard-app-title app)
                     (gr8s.server::dashboard-app-namespace app) (gr8s.server::dashboard-app-service app)
                     (gr8s.server::dashboard-app-port app) (gr8s.server::dashboard-app-path app))))
    (is (equal "/api/v1/namespaces/monitoring/services/grafana:80/proxy/login?x=1"
               (gr8s.server::dashboard-app-target app "/login?x=1")))
    ;; The proxy already points links through itself; those go as they are.
    (is (equal "/api/v1/namespaces/monitoring/services/grafana:80/proxy/public/a.js"
               (gr8s.server::dashboard-app-target app "/api/v1/namespaces/monitoring/services/grafana:80/proxy/public/a.js"))))
  (let ((app (gr8s.server::dashboard-tab-object-app
              (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"g\"},\"spec\":{\"service\":{\"namespace\":\"m\",\"name\":\"g\",\"port\":80}}}"))))
    ;; A redirect keeps the browser on the app's own paths, where its router looks.
    (is (equal "/login" (gr8s.server::dashboard-app-location app "/api/v1/namespaces/m/services/g:80/proxy/login")))
    (is (equal "/" (gr8s.server::dashboard-app-location app "/api/v1/namespaces/m/services/g:80/proxy")))
    (is (equal "https://elsewhere/" (gr8s.server::dashboard-app-location app "https://elsewhere/"))))
  (is (null (gr8s.server::dashboard-tab-object-app (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"x\"},\"spec\":{}}"))))
  ;; A follower's 307 to the leader is followed by the dashboard, to the same path there.
  (multiple-value-bind (member target)
      (gr8s.server::dashboard-app-redirect-member
       (list :server "https://10.77.77.21:6443" :ca-file "/ca")
       307 '((:location . "https://10.77.77.20:6443/api/v1/namespaces/m/services/g:80/proxy/ofrep?x=1")))
    (is (equal "https://10.77.77.20:6443" (getf member :server)))
    (is (equal "/ca" (getf member :ca-file)))
    (is (equal "/api/v1/namespaces/m/services/g:80/proxy/ofrep?x=1" target)))
  (is (null (gr8s.server::dashboard-app-redirect-member nil 302 '((:location . "https://elsewhere/")))))
  (is (null (gr8s.server::dashboard-app-redirect-member nil 307 '((:location . "/relative")))))
  (is (equal "default-src 'self'" (gr8s.server::dashboard-app-csp "default-src 'self'; frame-ancestors 'none'")))
  ;; Hunchentoot interns only names already known, so an app's own header comes as a string.
  (is (equal '(("accept" . "*/*") ("x-grafana-device-id" . "abc"))
             (gr8s.server::dashboard-app-request-headers
              nil '((:accept . "*/*") ("X-Grafana-Device-Id" . "abc") (:authorization . "Bearer t")
                    (:origin . "http://127.0.0.1:42021"))))))

(test a-dashboard-app-tab-is-its-own-origin-behind-a-secret
  (let* ((upstream (hunchentoot:start (make-instance 'dashboard-app-upstream :address "127.0.0.1" :port 0)))
         (config (list :server (format nil "http://127.0.0.1:~D" (hunchentoot:acceptor-port upstream))))
         (apps (gr8s.server::make-dashboard-apps config)))
    ;; The upstream's threads see the global value, not a binding.
    (setf *dashboard-app-upstream-seen* nil)
    (unwind-protect
         (let* ((tabs (gr8s.server::dashboard-apps-tabs
                       apps :list-tabs (constantly (com.inuoe.jzon:parse "{\"items\":[{\"metadata\":{\"name\":\"grafana\"},\"spec\":{\"title\":\"Grafana\",\"service\":{\"namespace\":\"monitoring\",\"name\":\"grafana\",\"port\":80}}}]}"))))
                (tab (first tabs))
                (bootstrap (second tab))
                (origin (subseq bootstrap 0 (search "/.gr8s-tab/" bootstrap)))
                (jar (make-instance 'drakma:cookie-jar)))
           (is (equal "app-grafana" (first tab)))
           (is (equal "Grafana" (third tab)))
           ;; Without the secret, nothing is proxied.
           (is (= 403 (nth-value 1 (drakma:http-request (concatenate 'string origin "/") :proxy nil))))
           (is (null *dashboard-app-upstream-seen*))
           ;; The frame's first load sets the secret cookie, then shows the app.
           (multiple-value-bind (body status headers)
               (drakma:http-request bootstrap :proxy nil :cookie-jar jar
                                    :additional-headers '(("Authorization" . "Bearer not-for-the-app")))
             (is (= 200 status))
             (is (equal "grafana" body))
             (is (null (assoc :x-frame-options headers)))
             (is (equal "default-src 'self'" (cdr (assoc :content-security-policy headers)))))
           (destructuring-bind (uri cookie authorization) (first *dashboard-app-upstream-seen*)
             (is (equal "/api/v1/namespaces/monitoring/services/grafana:80/proxy/" uri))
             ;; The tab's secret and the reader's Authorization stay here.
             (is (not (search "gr8s-tab-" (or cookie ""))))
             (is (null authorization)))
           (drakma:http-request (concatenate 'string origin "/api/health") :proxy nil :cookie-jar jar)
           (destructuring-bind (uri cookie authorization) (first *dashboard-app-upstream-seen*)
             (declare (ignore authorization))
             (is (equal "/api/v1/namespaces/monitoring/services/grafana:80/proxy/api/health" uri))
             ;; The app's own cookie goes back to it.
             (is (search "grafana_session=abc" cookie))
             (is (not (search "gr8s-tab-" cookie))))
           ;; Another local page carries the cookie too, but not this tab's Origin.
           (is (= 403 (nth-value 1 (drakma:http-request (concatenate 'string origin "/api/health") :proxy nil :cookie-jar jar
                                                        :additional-headers '(("Origin" . "http://127.0.0.1:1"))))))
           ;; The tab's own Origin is welcome, and stays here: the app sees another Host.
           (is (= 200 (nth-value 1 (drakma:http-request (concatenate 'string origin "/public/a.js") :proxy nil :cookie-jar jar
                                                        :additional-headers (list (cons "Origin" origin))))))
           (is (equal "/api/v1/namespaces/monitoring/services/grafana:80/proxy/public/a.js"
                      (first (first *dashboard-app-upstream-seen*))))
           ;; A DashboardTab that's gone takes its server with it.
           (is (null (gr8s.server::dashboard-apps-tabs apps :list-tabs (constantly (com.inuoe.jzon:parse "{\"items\":[]}")))))
           (signals error (drakma:http-request (concatenate 'string origin "/") :proxy nil :connection-timeout 2)))
      (gr8s.server::stop-dashboard-apps apps)
      (hunchentoot:stop upstream))))

(defun agent-test-websocket (port path &key (origin (format nil "http://127.0.0.1:~D" port)))
  "Open a WebSocket to PATH on the loopback PORT, returning (values stream status)."
  (let* ((socket (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)))
         (stream (usocket:socket-stream socket)))
    (write-sequence (trivial-utf-8:string-to-utf-8-bytes
                     (format nil "GET ~A HTTP/1.1~C~CHost: 127.0.0.1:~D~C~COrigin: ~A~C~CUpgrade: websocket~C~CConnection: Upgrade~C~CSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==~C~CSec-WebSocket-Version: 13~C~C~C~C"
                             path #\Return #\Linefeed port #\Return #\Linefeed origin #\Return #\Linefeed
                             #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed
                             #\Return #\Linefeed))
                    stream)
    (finish-output stream)
    ;; The response head, up to its blank line.
    (let ((head (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
      (loop for byte = (read-byte stream nil)
            while byte
            do (vector-push-extend byte head)
            until (and (>= (length head) 4) (equalp (subseq head (- (length head) 4)) #(13 10 13 10))))
      (values stream (parse-integer (trivial-utf-8:utf-8-bytes-to-string head) :start 9 :end 12)))))

(test the-dashboard-agent-tab-runs-an-agent-on-a-terminal
  ;; podster-2ry: a pseudo-terminal behind a WebSocket, running only an agent the tab offers.
  (let* ((directory (uiop:ensure-directory-pathname
                     (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-agents-XXXXXX" (uiop:temporary-directory))))))
         (agents-file (merge-pathnames "dashboard-agents.json" directory))
         (agent (gr8s.server::make-dashboard-agent
                 "/tmp/kubeconfig-for-test"
                 :agents-file agents-file
                 :choices-function
                 (lambda ()
                   (list (list :id "echo" :label "Echo" :program "/bin/sh" :builtin nil
                               :command '("sh" "-c" "read go; stty size; echo kube=$KUBECONFIG; read line; echo got:$line; exit 3"))
                         (list :id "absent" :label "Absent" :program nil :builtin t :command '("absent"))))))
         (acceptor (make-instance 'gr8s.server::gr8s-dashboard-acceptor
                                  :address "127.0.0.1" :port 0 :shell-path "/ui/tok/"
                                  :tabs '(("agent" "/agent/tok/" "Agent"))
                                  :agent agent :agent-base "/agent/tok/"
                                  :proxy-fn (lambda (&rest arguments) (declare (ignore arguments)) "proxied")
                                  :multiplexer-fn nil
                                  :access-log-destination nil :message-log-destination nil)))
    (hunchentoot:start acceptor)
    (unwind-protect
         (let ((port (hunchentoot:acceptor-port acceptor)))
           (flet ((get-path (path)
                    (multiple-value-bind (body status)
                        (drakma:http-request (format nil "http://127.0.0.1:~D~A" port path) :proxy nil :force-binary t)
                      (values (trivial-utf-8:utf-8-bytes-to-string body) status)))
                  (send (stream opcode text)
                    (gr8s.protocol::write-websocket-frame stream opcode (trivial-utf-8:string-to-utf-8-bytes text)
                                                          :masked-p t)))
             (is (search "<script src=\"xterm.js\"></script>" (get-path "/agent/tok/")))
             (let ((offered (com.inuoe.jzon:parse (get-path "/agent/tok/agents"))))
               (is (equal '("echo" "absent") (map 'list (lambda (entry) (gethash "id" entry)) offered)))
               (is (eq t (gethash "installed" (aref offered 0))))
               (is (eq nil (gethash "installed" (aref offered 1))))
               (is (equalp #("sh" "-c" "read go; stty size; echo kube=$KUBECONFIG; read line; echo got:$line; exit 3")
                           (gethash "command" (aref offered 0)))))
             ;; podster-9et: the reader's own agents are saved from this dashboard's page alone.
             (flet ((post-agents (body &optional (origin (format nil "http://127.0.0.1:~D" port)))
                      (nth-value 1 (drakma:http-request (format nil "http://127.0.0.1:~D/agent/tok/agents" port)
                                                        :method :post :proxy nil :content body
                                                        :content-type "application/json"
                                                        :additional-headers (list (cons "Origin" origin))))))
               (let ((mine "[{\"id\":\"mine\",\"label\":\"Mine\",\"command\":[\"mine\",\"{guide-file}\"]}]"))
                 (is (= 403 (post-agents mine "http://evil.example")))
                 (is (null (probe-file agents-file)))
                 (is (= 400 (post-agents "[{\"id\":\"claude\",\"label\":\"x\",\"command\":[\"x\"]}]")))
                 (is (= 400 (post-agents "{\"not\":\"a list\"}")))
                 (is (= 200 (post-agents mine)))
                 (is (equal '(("mine" "Mine" ("mine" "{guide-file}"))) (gr8s.server::read-custom-agents agents-file)))))
             (when (third (assoc "xterm.js" gr8s.server::+dashboard-agent-assets+ :test #'equal))
               (is (= 200 (nth-value 1 (get-path "/agent/tok/xterm.js")))))
             ;; Another site's page can't open a terminal, and only the catalogue runs.
             (is (= 403 (nth-value 1 (agent-test-websocket port "/agent/tok/pty?agent=echo" :origin "http://evil.example"))))
             (is (= 404 (nth-value 1 (agent-test-websocket port "/agent/tok/pty?agent=sh"))))
             (is (= 404 (nth-value 1 (agent-test-websocket port "/agent/tok/pty?agent=absent"))))
             (multiple-value-bind (stream status) (agent-test-websocket port "/agent/tok/pty?agent=echo")
               (is (= 101 status))
               (send stream 1 "{\"type\":\"resize\",\"cols\":99,\"rows\":33}")
               (sleep 0.2)
               (send stream 2 (format nil "go~C" #\Return))
               (send stream 2 (format nil "hello~C" #\Return))
               (let ((output (make-string-output-stream)) (exit nil))
                 (loop (multiple-value-bind (opcode payload) (gr8s.protocol::read-websocket-frame stream)
                         (case opcode
                           (2 (write-string (sb-ext:octets-to-string payload :external-format :latin-1) output))
                           (1 (setf exit (com.inuoe.jzon:parse payload)))
                           (8 (return)))))
                 (let ((text (get-output-stream-string output)))
                   ;; The terminal echoes what's typed, as it arrives.
                   (is (search (format nil "go~C~Chello~C~C" #\Return #\Newline #\Return #\Newline) text))
                   (is (search "33 99" text))
                   (is (search "kube=/tmp/kubeconfig-for-test" text))
                   (is (search "got:hello" text)))
                 (is (equal "exit" (gethash "type" exit)))
                 (is (= 3 (gethash "code" exit))))
               (close stream))
             (is-true (wait-until (lambda () (null (gr8s.server::dashboard-agent-sessions agent))) :timeout 5))))
      (hunchentoot:stop acceptor)
      (uiop:delete-directory-tree directory :validate t))))

(defun agent-test-frames (stream &key (until (lambda (text exits) (declare (ignore text exits)) nil)))
  "Read STREAM's frames until it closes or UNTIL, given the output so far and the control
messages, says so; return (values output control-messages)."
  (let ((output (make-string-output-stream)) (text "") (controls nil))
    (loop (multiple-value-bind (opcode payload) (gr8s.protocol::read-websocket-frame stream)
            (case opcode
              (2 (write-string (sb-ext:octets-to-string payload :external-format :latin-1) output)
                 (setf text (concatenate 'string text (get-output-stream-string output))))
              (1 (push (com.inuoe.jzon:parse payload) controls))
              (8 (return))))
          (when (funcall until text controls) (return)))
    (values text (reverse controls))))

(test the-dashboard-agent-outlives-its-page
  ;; An agent runs on when its page goes, shows its latest output to the next, and ends when stopped.
  (let* ((agent (gr8s.server::make-dashboard-agent
                 "/tmp/kubeconfig-for-test"
                 :choices-function
                 (lambda () (list (list :id "loop" :label "Loop" :program "/bin/sh" :builtin nil
                                        :command '("sh" "-c" "echo started; while read line; do echo got:$line; done"))))))
         (acceptor (make-instance 'gr8s.server::gr8s-dashboard-acceptor
                                  :address "127.0.0.1" :port 0 :shell-path "/ui/tok/"
                                  :tabs '(("agent" "/agent/tok/" "Agent"))
                                  :agent agent :agent-base "/agent/tok/"
                                  :proxy-fn (lambda (&rest arguments) (declare (ignore arguments)) "proxied")
                                  :multiplexer-fn nil
                                  :access-log-destination nil :message-log-destination nil)))
    (hunchentoot:start acceptor)
    (unwind-protect
         (let ((port (hunchentoot:acceptor-port acceptor)) (id nil))
           (flet ((type-line (stream text)
                    (gr8s.protocol::write-websocket-frame
                     stream 2 (trivial-utf-8:string-to-utf-8-bytes (format nil "~A~C" text #\Return)) :masked-p t))
                  (sessions ()
                    (com.inuoe.jzon:parse (drakma:http-request (format nil "http://127.0.0.1:~D/agent/tok/sessions" port)
                                                               :proxy nil))))
             (let ((stream (agent-test-websocket port "/agent/tok/pty?agent=loop")))
               (multiple-value-bind (text controls)
                   (agent-test-frames stream :until (lambda (text controls) (and controls (search "started" text))))
                 (declare (ignore text))
                 (is (equal "session" (gethash "type" (first controls))))
                 (setf id (gethash "id" (first controls))))
               (type-line stream "one")
               (agent-test-frames stream :until (lambda (text controls) (declare (ignore controls)) (search "got:one" text)))
               ;; The page goes; the agent doesn't.
               (close stream))
             (sleep 0.3)
             (is (equal (list id) (map 'list (lambda (session) (gethash "id" session)) (sessions))))
             (let ((stream (agent-test-websocket port (format nil "/agent/tok/pty?session=~A" id))))
               ;; The next page sees what it missed, then the live terminal.
               (multiple-value-bind (text controls)
                   (agent-test-frames stream :until (lambda (text controls) (and controls (search "got:one" text))))
                 (is (equal id (gethash "id" (first controls))))
                 (is (search "started" text)))
               (type-line stream "two")
               (agent-test-frames stream :until (lambda (text controls) (declare (ignore controls)) (search "got:two" text)))
               ;; Stop ends it, by hanging up its terminal.
               (gr8s.protocol::write-websocket-frame stream 1 (trivial-utf-8:string-to-utf-8-bytes "{\"type\":\"stop\"}")
                                                     :masked-p t)
               (multiple-value-bind (text controls) (agent-test-frames stream)
                 (declare (ignore text))
                 (let ((exit (find "exit" controls :key (lambda (c) (gethash "type" c)) :test #'equal)))
                   ;; The shell's read ends when its terminal hangs up, and so does the shell.
                   (is-true exit)))
               (close stream))
             (is-true (wait-until (lambda () (zerop (length (sessions)))) :timeout 5))
             (is (= 404 (nth-value 1 (agent-test-websocket port (format nil "/agent/tok/pty?session=~A" id)))))))
      (hunchentoot:stop acceptor))))

(test the-dashboard-lisp-tab-starts-icl-on-a-tunnel
  ;; ICL's browser REPL, connected to a gr8s process, in a frame the dashboard's origin may show.
  (is (equal "http://127.0.0.1:41234/icl/C6D18548DFC69F93F6F00515500A7367"
             (gr8s.server::icl-browser-url "Direct your browser to http://127.0.0.1:41234/icl/C6D18548DFC69F93F6F00515500A7367")))
  (is (null (gr8s.server::icl-browser-url "; Browser-only mode (connected to 127.0.0.1:4005)")))
  ;; SBCL, whatever the reader's ICL configuration names.
  (is (equal '("-b" "--no-open" "--no-banner" "--lisp" "sbcl" "--embed-origin" "http://127.0.0.1:8080"
               "--connect" "127.0.0.1:4005")
             (gr8s.server::icl-arguments 4005 "http://127.0.0.1:8080")))
  (let ((directory (uiop:ensure-directory-pathname
                    (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-icl-XXXXXX" (uiop:temporary-directory)))))))
    (unwind-protect
         (flet ((fake (name help)
                  (let ((path (merge-pathnames name directory)))
                    (alexandria:write-string-into-file (format nil "#!/bin/sh~%echo '~A'~%" help) path)
                    (sb-posix:chmod (namestring path) #o755)
                    (namestring path))))
           (is-true (gr8s.server::icl-embeds-p (fake "new" "      --embed-origin <ITEM>  Let a page ...")))
           (is-false (gr8s.server::icl-embeds-p (fake "old" "      --no-open  Don't open")))
           (is-false (gr8s.server::icl-embeds-p nil)))
      (uiop:delete-directory-tree directory :validate t)))
  (let* ((started nil)
         (lisp (gr8s.server::make-dashboard-lisp
                nil :icl "/usr/bin/icl"
                    :start (lambda (lisp target origin)
                             (declare (ignore lisp))
                             (push (list target origin) started)
                             (let ((session (gr8s.server::%make-lisp-session target)))
                               (setf (gr8s.server::lisp-session-url session) "http://127.0.0.1:5/icl/AB")
                               session))))
         (acceptor (make-instance 'gr8s.server::gr8s-dashboard-acceptor
                                  :address "127.0.0.1" :port 0 :shell-path "/ui/tok/"
                                  :tabs '(("repl" "/lisp/tok/" "REPL"))
                                  :lisp lisp :lisp-base "/lisp/tok/"
                                  :proxy-fn (lambda (&rest arguments) (declare (ignore arguments)) "proxied")
                                  :multiplexer-fn nil
                                  :access-log-destination nil :message-log-destination nil)))
    (hunchentoot:start acceptor)
    (unwind-protect
         (let* ((port (hunchentoot:acceptor-port acceptor))
                (origin (format nil "http://127.0.0.1:~D" port)))
           (flet ((call (path &key (method :post) (from origin))
                    (multiple-value-bind (body status)
                        (drakma:http-request (format nil "http://127.0.0.1:~D/lisp/tok/~A" port path)
                                             :method method :proxy nil
                                             :additional-headers (when from (list (cons "Origin" from))))
                      (values (if (stringp body) body (trivial-utf-8:utf-8-bytes-to-string body)) status))))
             (is (search "<title>gr8s REPL</title>" (call "" :method :get)))
             ;; Only this dashboard's page, by POST, starts a REPL, in a member or a node.
             (is (= 405 (nth-value 1 (call "connect?kind=member&name=gr8s2" :method :get))))
             (is (= 403 (nth-value 1 (call "connect?kind=member&name=gr8s2" :from "http://evil.example"))))
             (is (= 400 (nth-value 1 (call "connect?kind=pod&name=gr8s2"))))
             (is (= 400 (nth-value 1 (call "connect?kind=member&name=../etc"))))
             (let ((session (com.inuoe.jzon:parse (call "connect?kind=member&name=gr8s2"))))
               (is (equal "http://127.0.0.1:5/icl/AB" (gethash "url" session)))
               (is (equal (list (list '("member" "gr8s2") origin)) started)))
             ;; Asking again finds the one running.
             (call "connect?kind=member&name=gr8s2")
             (is (= 1 (length started)))
             (let ((targets (com.inuoe.jzon:parse (call "targets" :method :get))))
               (is (= 1 (length (gethash "sessions" targets)))))
             (is (eq t (gethash "stopped" (com.inuoe.jzon:parse (call "disconnect?kind=member&name=gr8s2")))))
             (is (zerop (length (gethash "sessions" (com.inuoe.jzon:parse (call "targets" :method :get)))))))
           ;; Without ICL the page says so.
           (setf (gr8s.server::dashboard-lisp-icl lisp) nil)
           (multiple-value-bind (body status)
               (drakma:http-request (format nil "http://127.0.0.1:~D/lisp/tok/connect?kind=node&name=n1" port)
                                    :method :post :proxy nil :additional-headers (list (cons "Origin" origin)))
             (is (= 409 status))
             (is (search "ICL is not installed" (if (stringp body) body (trivial-utf-8:utf-8-bytes-to-string body))))))
      (hunchentoot:stop acceptor))))
