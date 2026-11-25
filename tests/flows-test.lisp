;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify flow collection without CAP_BPF: the agent's recent-event buffer, the
;;;; JSON it sends for an event, the control plane naming peers and isolating
;;;; NetworkPolicies, and a FLOWS operation streamed over a real agent session,
;;;; once and followed.

(in-package #:gr8s/tests)
(def-suite flows :in gr8s)
(in-suite flows)

(defun test-flow-record (&rest fields)
  (apply #'gr8s.network::make-flow-record
         (append fields
                 (list :ifindex 7 :endpoint "10.88.7.4" :kind :drop :reason :policy :direction :egress
                       :family :ipv4 :protocol 6 :pod-port 41000 :peer "10.88.9.3" :peer-port 443 :length 60))))

(test the-collector-keeps-only-the-most-recent-events
  (let ((collector (gr8s.agent::%make-flow-collector nil "worker-a" (constantly nil))))
    (dotimes (index (+ 10 gr8s.agent::+recent-flow-capacity+))
      (gr8s.agent::note-flow-record collector (test-flow-record :pod-port (1+ index))))
    (multiple-value-bind (lines next) (gr8s.agent::flow-records-since collector 0)
      (is (= gr8s.agent::+recent-flow-capacity+ (length lines)))
      (is (= (+ 10 gr8s.agent::+recent-flow-capacity+) next))
      ;; The oldest kept is the eleventh recorded.
      (is (= 11 (gethash "podPort" (com.inuoe.jzon:parse (first lines)))))
      (is (= 10 (car (last (coerce (first lines) 'list))))))
    (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 9))
    (multiple-value-bind (lines next)
        (gr8s.agent::flow-records-since collector (+ 10 gr8s.agent::+recent-flow-capacity+))
      (is (= 1 (length lines)))
      (is (= (+ 11 gr8s.agent::+recent-flow-capacity+) next)))))

(test flow-lines-go-to-a-reader-in-batches-of-whole-lines
  ;; One frame per line meant one relay RPC per flow event (podster-8kl).
  (let* ((line (coerce (append (make-list 99 :initial-element 65) '(10)) '(simple-array (unsigned-byte 8) (*))))
         (lines (make-list 1000 :initial-element line))
         (batches (gr8s.agent::flow-record-batches lines)))
    (is (< 1 (length batches) 10))
    (is (equalp (apply #'concatenate '(vector (unsigned-byte 8)) lines)
                (apply #'concatenate '(vector (unsigned-byte 8)) batches)))
    (is (every (lambda (batch) (and (<= (length batch) gr8s.agent::+flow-batch-bytes+)
                                    (zerop (mod (length batch) 100))))
               batches))
    (is (null (gr8s.agent::flow-record-batches nil)))))

(test an-agent-flow-names-its-local-pod
  (let ((object (gr8s.agent::flow-record-object
                 (test-flow-record) "worker-a"
                 (lambda (address) (and (equal address "10.88.7.4") (values "shop" "cart-0"))))))
    (is (equal "worker-a" (gethash "node" object)))
    (is (equal "DROPPED" (gethash "verdict" object)))
    (is (equal "policy" (gethash "reason" object)))
    (is (equal "egress" (gethash "direction" object)))
    (is (equal "TCP" (gethash "protocol" object)))
    (is (equal '("shop" "cart-0") (list (gethash "namespace" object) (gethash "pod" object))))
    (is (equal "10.88.9.3" (gethash "peerAddress" object)))
    (is (= 443 (gethash "peerPort" object)))
    (is (= 41000 (gethash "podPort" object))))
  ;; An event before the packet was parsed names nothing it doesn't know.
  (let ((object (gr8s.agent::flow-record-object
                 (gr8s.network::make-flow-record :ifindex 7 :kind :drop :reason :malformed
                                                 :pod-port 0 :peer-port 0 :length 9)
                 "worker-a" (constantly nil))))
    (is (equal "malformed" (gethash "reason" object)))
    (dolist (key '("protocol" "podAddress" "podPort" "peerAddress" "peerPort" "pod" "namespace" "direction"))
      (is (null (nth-value 1 (gethash key object))) key))))

(test an-ipv6-drop-names-its-pod-by-the-interface-it-was-seen-on
  ;; The guard has no IPv4 address to record for an IPv6 Pod's drop; the agent
  ;; finds the Pod's address from the host veth the event names.
  (let ((object (gr8s.agent::flow-record-object
                 (gr8s.network::make-flow-record :ifindex 12 :kind :drop :reason :policy :direction :ingress
                                                 :family :ipv6 :protocol 6 :pod-port 8080
                                                 :peer "fd00:0:0:0:0:0:0:9" :peer-port 50000 :length 80)
                 "worker-a"
                 (lambda (address) (and (equal address "fd00:10::4") (values "shop" "db-0")))
                 :interface-address (lambda (ifindex) (and (= ifindex 12) "fd00:10::4")))))
    (is (equal "fd00:10::4" (gethash "podAddress" object)))
    (is (equal '("shop" "db-0") (list (gethash "namespace" object) (gethash "pod" object)))))
  ;; A recorded endpoint wins over the interface.
  (let ((object (gr8s.agent::flow-record-object
                 (test-flow-record) "worker-a" (constantly nil)
                 :interface-address (constantly "192.0.2.1"))))
    (is (equal "10.88.7.4" (gethash "podAddress" object)))))

(test the-agent-finds-a-pod-by-any-of-its-addresses
  (let ((status (make-hash-table :test 'equal)))
    (setf (gethash "podIP" status) "10.88.7.4"
          (gethash "podIPs" status) (vector (gr8s.agent::json-object "ip" "10.88.7.4")
                                            (gr8s.agent::json-object "ip" "fd00:10::4")))
    (is-true (gr8s.agent::pod-status-has-address-p status "10.88.7.4"))
    (is-true (gr8s.agent::pod-status-has-address-p status "fd00:10::4"))
    (is-false (gr8s.agent::pod-status-has-address-p status "fd00:10::5"))))

(defun test-flow-policy (name namespace selector &rest types)
  (com.inuoe.jzon:parse
   (format nil "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",~
\"metadata\":{\"name\":~S,\"namespace\":~S},\"spec\":{\"podSelector\":{\"matchLabels\":{\"app\":~S}}~
~@[,\"policyTypes\":[~{~S~^,~}]~]}}"
           name namespace selector types)))

(test the-control-plane-names-peers-and-isolating-policies
  (let* ((pods (list (gr8s.network::make-np-pod :name "cart-0" :namespace "shop"
                                                :labels (gr8s.network::np-labels "app" "cart")
                                                :ip "10.88.7.4" :ips '("10.88.7.4"))
                     (gr8s.network::make-np-pod :name "db-0" :namespace "data"
                                                :labels (gr8s.network::np-labels "app" "db")
                                                :ip "10.88.9.3" :ips '("10.88.9.3"))))
         (policies (gr8s.network::network-policy-specs-from-objects
                    (list (test-flow-policy "deny-egress" "shop" "cart" "Egress")
                          (test-flow-policy "ingress-only" "shop" "cart")
                          (test-flow-policy "all-cart" "shop" "cart" "Ingress" "Egress")
                          (test-flow-policy "other-app" "shop" "web" "Egress")
                          (test-flow-policy "other-namespace" "data" "cart" "Egress"))))
         (context (gr8s.controllers::%make-flow-context pods policies))
         (flow (gr8s.controllers::enrich-flow
                context (gr8s.resources::core-object "namespace" "shop" "pod" "cart-0" "reason" "policy"
                                                     "direction" "egress" "peerAddress" "10.88.9.3"))))
    (is (equal '("data" "db-0") (list (gethash "peerNamespace" flow) (gethash "peerPod" flow))))
    (is (equal "db" (gethash "app" (gethash "peerLabels" flow))))
    (is (equal "cart" (gethash "app" (gethash "podLabels" flow))))
    (is (equalp #("all-cart" "deny-egress") (gethash "policies" flow)))
    (is (equalp #("all-cart" "ingress-only")
                (gethash "policies" (gr8s.controllers::enrich-flow
                                     context (gr8s.resources::core-object "namespace" "shop" "pod" "cart-0"
                                                                          "reason" "policy" "direction" "ingress")))))
    ;; Only policy drops are explained, and an unknown peer is left as an address.
    (let ((allowed (gr8s.controllers::enrich-flow
                    context (gr8s.resources::core-object "namespace" "shop" "pod" "cart-0"
                                                         "direction" "egress" "peerAddress" "192.0.2.1"))))
      (is (null (nth-value 1 (gethash "policies" allowed))))
      (is (null (nth-value 1 (gethash "peerPod" allowed)))))))

(test flows-stream-from-a-node-over-its-session
  (with-forwarding-agent (runtime pod listener node-runtime)
    (values pod listener)
    (let ((collector (gr8s.agent::%make-flow-collector nil "worker-forward" (constantly nil)))
          (seen nil) (seen-lock (bt:make-lock)))
      (setf (gr8s.agent::node-runtime-flow-collector node-runtime) collector)
      (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 1001))
      (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 1002))
      ;; Without FOLLOW the recent events arrive and the stream ends.
      (is (= 1 (gr8s.controllers::observe-cluster-flows
                runtime (lambda (flow) (push flow seen)) :nodes '("worker-forward"))))
      (is (equal '(1001 1002) (reverse (mapcar (lambda (flow) (gethash "podPort" flow)) seen))))
      (is (every (lambda (flow) (equal "worker-forward" (gethash "node" flow))) seen))
      ;; With FOLLOW, an event recorded later arrives too, until the observer stops.
      (setf seen nil)
      (let* ((stop nil)
             (observer (bt:make-thread
                        (lambda ()
                          (gr8s.controllers::observe-cluster-flows
                           runtime (lambda (flow) (bt:with-lock-held (seen-lock) (push flow seen)))
                           :nodes '("worker-forward") :follow t :stop-p (lambda () stop))))))
        (is-true (wait-until (lambda () (bt:with-lock-held (seen-lock) (= 2 (length seen)))) :timeout 10))
        ;; A followed stream outlasts quiet spells longer than its polling.
        (sleep 2)
        (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 1003))
        (is-true (wait-until (lambda () (bt:with-lock-held (seen-lock)
                                          (find 1003 seen :key (lambda (flow) (gethash "podPort" flow)))))
                             :timeout 10))
        (setf stop t)
        (is-true (wait-until (lambda () (not (bt:thread-alive-p observer))) :timeout 10)))
      ;; A node without a collector says so once.
      (setf (gr8s.agent::node-runtime-flow-collector node-runtime) nil seen nil)
      (gr8s.controllers::observe-cluster-flows runtime (lambda (flow) (push flow seen))
                                               :nodes '("worker-forward"))
      (is (= 1 (length seen)))
      (is (search "doesn't collect flow events" (gethash "error" (first seen)))))))

(test doctor-observe-parses-its-options-and-asks-for-the-right-path
  (let ((options (gr8s.server::parse-doctor-observe-options
                  '("-n" "shop" "-f" "--verdict" "dropped" "--pod" "cart-0" "--json"))))
    (is (eq :doctor-observe (getf options :command)))
    (is (equal "/apis/gr8s.io/v1/namespaces/shop/flows?watch=true"
               (gr8s.server::doctor-observe-path options)))
    (is (equal "DROPPED" (getf options :verdict)))
    (is-true (getf options :json)))
  (is (equal "/apis/gr8s.io/v1/flows" (gr8s.server::doctor-observe-path
                                       (gr8s.server::parse-doctor-observe-options nil))))
  (is (eq :doctor-observe (getf (gr8s.server::parse-doctor-options '("observe")) :command)))
  (signals error (gr8s.server::parse-doctor-observe-options '("--verdict" "lost")))
  (signals error (gr8s.server::parse-doctor-observe-options '("-n" "Not/A/Name")))
  (signals error (gr8s.server::parse-doctor-observe-options '("--bogus")))
  ;; --serve serves them as Hubble's Observer API, where the hubble CLI looks unless told.
  (let ((options (gr8s.server::parse-doctor-options '("observe" "--serve" "-n" "shop"))))
    (is (eq :hubble-serve (getf options :command)))
    (is (equal '("127.0.0.1" 4245 "shop")
               (list (getf options :host) (getf options :port) (getf options :namespace)))))
  (is (= 9000 (getf (gr8s.server::parse-doctor-observe-options '("--serve" "--listen" "0.0.0.0:9000")) :port)))
  (signals error (gr8s.server::parse-doctor-observe-options '("--serve" "--listen" "nowhere")))
  ;; gr8s hubble is gone: the dashboard has the Network view, and observe --serve the Hubble API.
  (signals error (gr8s.server::parse-cli-options '("hubble" "serve"))))

(test doctor-observe-prints-the-pods-side-first-for-its-own-traffic
  (flet ((flow (&rest pairs) (apply #'gr8s.resources::core-object "time" "2026-11-22T01:02:03.456Z"
                                    "node" "worker-a" pairs)))
    (is (equal "01:02:03.456 worker-a: shop/cart-0:41000 -> data/db-0:443 TCP DROPPED by policy (shop/all-cart, shop/deny-egress)"
               (gr8s.server::format-flow-line
                (flow "namespace" "shop" "pod" "cart-0" "podPort" 41000 "direction" "egress"
                      "peerNamespace" "data" "peerPod" "db-0" "peerAddress" "10.88.9.3" "peerPort" 443
                      "protocol" "TCP" "verdict" "DROPPED" "reason" "policy"
                      "policies" #("all-cart" "deny-egress")))))
    (is (equal "01:02:03.456 worker-a: 192.0.2.7:5555 -> shop/cart-0:80 TCP FORWARDED"
               (gr8s.server::format-flow-line
                (flow "namespace" "shop" "pod" "cart-0" "podPort" 80 "direction" "ingress"
                      "peerAddress" "192.0.2.7" "peerPort" 5555 "protocol" "TCP" "verdict" "FORWARDED"))))
    (is (equal "01:02:03.456 worker-a: 10.88.7.4 -> ? DROPPED malformed"
               (gr8s.server::format-flow-line
                (flow "podAddress" "10.88.7.4" "verdict" "DROPPED" "reason" "malformed"))))
    (is (equal "worker-b: unavailable: no collector"
               (gr8s.server::format-flow-line (gr8s.resources::core-object "node" "worker-b" "error" "no collector"))))
    (let ((options (list :pod "cart-0" :verdict "DROPPED")))
      (is-true (gr8s.server::flow-matches-options-p (flow "pod" "cart-0" "verdict" "DROPPED") options))
      (is-true (gr8s.server::flow-matches-options-p (flow "peerPod" "cart-0" "verdict" "DROPPED") options))
      (is-false (gr8s.server::flow-matches-options-p (flow "pod" "cart-0" "verdict" "FORWARDED") options))
      (is-false (gr8s.server::flow-matches-options-p (flow "pod" "web-0" "verdict" "DROPPED") options)))
    (is-true (gr8s.apiserver::flow-in-namespace-p (flow "peerNamespace" "shop") "shop"))
    (is-false (gr8s.apiserver::flow-in-namespace-p (flow "namespace" "data") "shop"))
    (is-true (gr8s.apiserver::flow-in-namespace-p (flow "namespace" "data") nil))))

(test doctor-observe-reads-a-chunked-body-line-by-line
  (let* ((body (format nil "{\"a\":1}~%{\"b\":2}~%"))
         (octets (trivial-utf-8:string-to-utf-8-bytes
                  (format nil "5~C~C~A~C~C~X~C~C~A~C~C0~C~C~C~C"
                          #\Return #\Linefeed (subseq body 0 5) #\Return #\Linefeed
                          (- (length body) 5) #\Return #\Linefeed (subseq body 5) #\Return #\Linefeed
                          #\Return #\Linefeed #\Return #\Linefeed)))
         (lines nil))
    (gr8s.server::call-with-flow-lines
     (flexi-streams:make-in-memory-input-stream octets) '((:transfer-encoding . "chunked"))
     (lambda (line) (push line lines)))
    (is (equal '("{\"a\":1}" "{\"b\":2}") (reverse lines)))))

(test the-api-serves-every-nodes-flows-to-a-reader
  (with-forwarding-agent (runtime pod listener node-runtime)
    (values pod listener)
    (let ((collector (gr8s.agent::%make-flow-collector
                      nil "worker-forward"
                      (lambda (address) (and (equal address "10.88.7.4") (values "shop" "cart-0")))))
          (server nil))
      (setf (gr8s.agent::node-runtime-flow-collector node-runtime) collector)
      (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 2001))
      (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 2002 :endpoint "10.88.7.99"))
      (unwind-protect
           (progn
             (setf server (start-http-test-server
                           :store (gr8s.controllers::control-plane-runtime-store runtime) :runtime runtime))
             (multiple-value-bind (body code) (request "/apis/gr8s.io/v1/flows" :force-binary t)
               (is (= 200 code))
               (setf body (trivial-utf-8:utf-8-bytes-to-string body))
               (let ((flows (mapcar #'com.inuoe.jzon:parse
                                    (remove "" (uiop:split-string body :separator '(#\Newline)) :test #'equal))))
                 (is (equal '(2001 2002) (mapcar (lambda (flow) (gethash "podPort" flow)) flows)))
                 (is (equal "cart-0" (gethash "pod" (first flows))))))
             ;; A namespaced reader sees only the flows with a Pod of its namespace.
             (multiple-value-bind (body code) (request "/apis/gr8s.io/v1/namespaces/shop/flows" :force-binary t)
               (is (= 200 code))
               (setf body (trivial-utf-8:utf-8-bytes-to-string body))
               (is (= 1 (count #\Newline body)))
               (is (search "\"podPort\":2001" body))))
        (when server (stop-server server))))))

(test net-agent-serves-flows-on-loopback
  (let* ((collector (gr8s.agent::%make-flow-collector nil "foreign-a" (constantly nil)))
         (listener (gr8s.agent::start-flow-listener collector :port 0))
         (port (usocket:get-local-port (gr8s.agent::flow-listener-socket listener))))
    (unwind-protect
         (flet ((connect (request)
                  (let ((socket (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8))))
                    (write-sequence (trivial-utf-8:string-to-utf-8-bytes (format nil "~A~%" request))
                                    (usocket:socket-stream socket))
                    (finish-output (usocket:socket-stream socket))
                    socket))
                (next-port (socket)
                  (let ((line (loop for byte = (read-byte (usocket:socket-stream socket) nil)
                                    while (and byte (/= byte 10)) collect byte)))
                    (and line (gethash "podPort" (com.inuoe.jzon:parse
                                                  (coerce line '(vector (unsigned-byte 8)))))))))
           (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 2001))
           (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 2002))
           ;; Followed: the recent events, then new ones as they come.
           (let ((socket (connect "{\"follow\":true}")))
             (unwind-protect
                  (progn
                    (is (= 2001 (next-port socket)))
                    (is (= 2002 (next-port socket)))
                    (gr8s.agent::note-flow-record collector (test-flow-record :pod-port 2003))
                    (is (= 2003 (next-port socket))))
               (usocket:socket-close socket)))
           ;; Once: the recent events, then the end of the stream.
           (let ((socket (connect "{}")))
             (unwind-protect
                  (progn
                    (is (equal '(2001 2002 2003) (loop repeat 3 collect (next-port socket))))
                    ;; An empty line, then the end.
                    (is (equal '(10) (list (read-byte (usocket:socket-stream socket) nil))))
                    (is (null (read-byte (usocket:socket-stream socket) nil))))
               (usocket:socket-close socket)))
           (is (string= "127.0.0.1" (usocket:host-to-hostname
                                     (usocket:get-local-address (gr8s.agent::flow-listener-socket listener))))))
      (gr8s.agent::stop-flow-listener listener))))

(defun port-forward-frames (&rest frames)
  "An input stream of unmasked WebSocket FRAMES, each (opcode . octets), as a server sends them."
  (flexi-streams:make-in-memory-input-stream
   (flexi-streams:with-output-to-sequence (out)
     (loop for (opcode . octets) in frames
           do (gr8s.protocol::write-websocket-frame out opcode (coerce octets '(vector (unsigned-byte 8))))))))

(defun channel-frame (channel text &optional prefix)
  (cons 2 (append (list channel) prefix (coerce (trivial-utf-8:string-to-utf-8-bytes text) 'list))))

(test a-reader-takes-net-agent-lines-from-a-port-forward
  (let ((lines nil))
    ;; Each channel opens with the port (4246, little-endian); a line may span frames.
    (gr8s.server::read-port-forward-flow-lines
     (port-forward-frames (channel-frame 0 "" '(150 16)) (channel-frame 1 "" '(150 16))
                          (channel-frame 0 (format nil "{\"a\":1}~%{\"b\"")) (channel-frame 0 (format nil ":2}~%~%"))
                          (channel-frame 0 (format nil "{\"never\":3}~%")))
     (lambda (line) (push (trivial-utf-8:utf-8-bytes-to-string line) lines))
     (lambda (opcode payload) (declare (ignore opcode payload))))
    (is (equal '("{\"a\":1}" "{\"b\":2}") (reverse lines))))
  ;; The prefix may share its frame with data.
  (let ((lines nil))
    (gr8s.server::read-port-forward-flow-lines
     (port-forward-frames (channel-frame 0 (format nil "{\"c\":1}~%~%") '(150 16)))
     (lambda (line) (push (trivial-utf-8:utf-8-bytes-to-string line) lines))
     (lambda (opcode payload) (declare (ignore opcode payload))))
    (is (equal '("{\"c\":1}") lines)))
  ;; What the error channel says is the failure; pings are answered.
  (let ((pongs nil))
    (signals error
      (gr8s.server::read-port-forward-flow-lines
       (port-forward-frames (channel-frame 1 "" '(150 16)) (cons 9 '(7))
                            (channel-frame 1 "connection refused") (cons 8 '()))
       (constantly nil)
       (lambda (opcode payload) (push (cons opcode (coerce payload 'list)) pongs))))
    (is (equal '((10 7)) pongs))))

(test net-agent-flow-requests-ask-to-follow-or-not
  (is (equal (format nil "{\"follow\":true}~%")
             (trivial-utf-8:utf-8-bytes-to-string (gr8s.server::net-agent-flow-request t))))
  (is (equal (format nil "{}~%")
             (trivial-utf-8:utf-8-bytes-to-string (gr8s.server::net-agent-flow-request nil)))))

(test a-flow-context-can-come-from-api-objects
  (let* ((pods (vector (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"db\",\"namespace\":\"shop\",\"labels\":{\"app\":\"db\"}},\"spec\":{\"containers\":[]},\"status\":{\"phase\":\"Running\",\"podIP\":\"10.1.0.5\",\"podIPs\":[{\"ip\":\"10.1.0.5\"}]}}")
                       (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"cart\",\"namespace\":\"shop\",\"labels\":{\"app\":\"cart\"}},\"spec\":{\"containers\":[]},\"status\":{\"phase\":\"Running\",\"podIP\":\"10.1.0.6\"}}")
                       (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"done\",\"namespace\":\"shop\"},\"spec\":{\"containers\":[]},\"status\":{\"phase\":\"Succeeded\",\"podIP\":\"10.1.0.7\"}}")))
         (context (gr8s.controllers::make-flow-context-from-objects
                   pods (vector (test-flow-policy "deny-egress" "shop" "cart" "Egress"))))
         (flow (com.inuoe.jzon:parse "{\"namespace\":\"shop\",\"pod\":\"cart\",\"reason\":\"policy\",\"direction\":\"egress\",\"peerAddress\":\"10.1.0.5\"}")))
    (gr8s.controllers::enrich-flow context flow)
    (is (equal "db" (gethash "peerPod" flow)))
    (is (equalp #("deny-egress") (gethash "policies" flow)))
    (is (null (gr8s.controllers::flow-context-pod-at context "10.1.0.7")))))

(test a-gateway-request-is-kept-as-a-flow-of-its-backend-pod
  (let ((collector (gr8s.agent::%make-flow-collector
                    nil "worker-a" (lambda (address) (and (equal address "10.88.7.4") (values "shop" "web-0"))))))
    (funcall (gr8s.agent::gateway-flow-sink collector)
             (gr8s.resources::core-object "verdict" "FORWARDED" "direction" "ingress" "podAddress" "10.88.7.4"
                                          "l7" (gr8s.resources::core-object "method" "GET" "code" 200)))
    (let ((flow (com.inuoe.jzon:parse (first (gr8s.agent::flow-records-since collector 0)))))
      (is (equal '("worker-a" "shop" "web-0") (list (gethash "node" flow) (gethash "namespace" flow) (gethash "pod" flow))))
      (is (stringp (gethash "time" flow)))
      (is (= 200 (gethash "code" (gethash "l7" flow)))))))

(test doctor-observe-prints-a-gateway-request
  (is (equal "01:02:03.456 worker-a: 192.0.2.7:5555 -> shop/web-0:8080 HTTP GET app.example.com/cart 200 12.5ms (shop/web)"
             (gr8s.server::format-flow-line
              (gr8s.resources::core-object
               "time" "2026-11-22T01:02:03.456Z" "node" "worker-a" "namespace" "shop" "pod" "web-0" "podPort" 8080
               "direction" "ingress" "peerAddress" "192.0.2.7" "peerPort" 5555 "verdict" "FORWARDED"
               "l7" (gr8s.resources::core-object "method" "GET" "host" "app.example.com" "path" "/cart"
                                                 "code" 200 "latencyNs" 12500000 "route" "shop/web"))))))

(test a-host-network-pod-is-never-named-by-its-address
  (let* ((pods (vector (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"exporter\",\"namespace\":\"monitoring\"},\"spec\":{\"hostNetwork\":true,\"containers\":[]},\"status\":{\"phase\":\"Running\",\"podIP\":\"10.77.77.10\"}}")
                       (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"web\",\"namespace\":\"shop\",\"labels\":{\"app\":\"web\"}},\"spec\":{\"containers\":[]},\"status\":{\"phase\":\"Running\",\"podIP\":\"10.80.0.9\"}}")))
         (context (gr8s.controllers::make-flow-context-from-objects pods #()))
         ;; A Gateway request from the node's own address to a Pod another node runs.
         (flow (com.inuoe.jzon:parse "{\"podAddress\":\"10.80.0.9\",\"peerAddress\":\"10.77.77.10\",\"namespace\":\"shop\",\"service\":\"web\"}")))
    (gr8s.controllers::enrich-flow context flow)
    (is (null (nth-value 1 (gethash "peerPod" flow))))
    (is (equal '("shop" "web") (list (gethash "namespace" flow) (gethash "pod" flow))))
    (is (equalp (gr8s.resources::core-object "app" "web") (gethash "podLabels" flow)))))

(test a-gateways-host-network-backend-is-named-within-its-namespace
  (flet ((pod (namespace name ip &optional host)
           (com.inuoe.jzon:parse
            (format nil "{\"metadata\":{\"name\":~S,\"namespace\":~S,\"labels\":{\"app\":~S}},~
\"spec\":{\"hostNetwork\":~:[false~;true~],\"containers\":[]},\"status\":{\"phase\":\"Running\",\"podIP\":~S}}"
                    name namespace name host ip))))
    (let ((context (gr8s.controllers::make-flow-context-from-objects
                    (vector (pod "gvision" "gvision-abc" "10.77.77.21" t)
                            (pod "monitoring" "node-exporter-1" "10.77.77.21" t)
                            (pod "monitoring" "node-exporter-2" "10.77.77.21" t))
                    #())))
      ;; One Pod of the flow's namespace at its address: that's the backend.
      (let ((flow (com.inuoe.jzon:parse "{\"podAddress\":\"10.77.77.21\",\"namespace\":\"gvision\",\"service\":\"gvision\"}")))
        (gr8s.controllers::enrich-flow context flow)
        (is (equal "gvision-abc" (gethash "pod" flow)))
        (is (equalp (gr8s.resources::core-object "app" "gvision-abc") (gethash "podLabels" flow))))
      ;; Two in the namespace: ambiguous, so none.
      (let ((flow (com.inuoe.jzon:parse "{\"podAddress\":\"10.77.77.21\",\"namespace\":\"monitoring\"}")))
        (gr8s.controllers::enrich-flow context flow)
        (is (null (nth-value 1 (gethash "pod" flow)))))
      ;; Without a namespace, a host-network address names nobody.
      (let ((flow (com.inuoe.jzon:parse "{\"podAddress\":\"10.77.77.21\"}")))
        (gr8s.controllers::enrich-flow context flow)
        (is (null (nth-value 1 (gethash "pod" flow))))))))
