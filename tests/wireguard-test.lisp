;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)
(in-suite gr8s)

(test shared-network-steering-is-bounded-local-and-failure-domain-aware
  (let* ((local (list :node-name "local" :same-node t :healthy t
                      :path-score 100 :capacity 2000 :link-cost 1
                      :failure-domain '("r" "z1")))
         (same-zone (list :node-name "zone" :same-zone t :healthy t
                          :path-score 50 :capacity 8000 :link-cost 1
                          :failure-domain '("r" "z1")))
         (other-zone (list :node-name "other" :same-region t :healthy t
                           :path-score 100 :capacity 4000 :link-cost 10
                           :failure-domain '("r" "z2")))
         (faulty (list :node-name "faulty" :healthy t
                       :path-score most-positive-fixnum :capacity most-positive-fixnum
                       :link-cost most-positive-fixnum
                       :failure-domain '("x" "z")))
         (ranked (gr8s.foundation::rank-network-steering-candidates
                  (list other-zone faulty same-zone local))))
    (is (string= "local" (getf (first ranked) :node-name)))
    ;; Second choice crosses the first choice's failure domain before returning
    ;; to an otherwise cheaper same-zone candidate.
    (is (string= "other" (getf (second ranked) :node-name)))
    (is (< (gr8s.foundation::network-steering-score local) 100000))
    (is (< (gr8s.foundation::network-steering-score faulty) 100000000))))

(test node-steering-capacity-score-parses-and-clamps-cpu
  (is (= 4000 (gr8s.foundation::node-steering-capacity-score
               (gr8s.foundation::json-object "cpu" "4"))))
  (is (= 2500 (gr8s.foundation::node-steering-capacity-score
               (gr8s.foundation::json-object "cpu" "2500m"))))
  (is (= 100000 (gr8s.foundation::node-steering-capacity-score
                 (gr8s.foundation::json-object "cpu" "999999999"))))
  (is (= 0 (gr8s.foundation::node-steering-capacity-score
            (gr8s.foundation::json-object "cpu" "garbage")))))

(defun wireguard-route-fixture (&key (key-byte 7) (port 51820) pod-cidrs)
  (let ((route
          (gr8s.foundation::json-object
           "nodeID" "peer-a" "nodeName" "peer-a" "podCIDR" "10.88.9.0/24"
           "underlayAddress" "192.0.2.9"
           "wireguardPublicKey"
           (ag-grpc:base64-encode
            (make-array 32 :element-type '(unsigned-byte 8) :initial-element key-byte))
           "wireguardListenPort" port)))
    (when pod-cidrs
      (setf (gethash "podCIDRs" route) (coerce pod-cidrs 'vector)))
    route))

(defun wireguard-next-hop-fixture (&key (key-byte 9) (name "gateway-a"))
  (gr8s.foundation::json-object
   "nodeID" name "nodeName" name "underlayAddress" "192.0.2.20"
   "wireguardPublicKey"
   (ag-grpc:base64-encode
    (make-array 32 :element-type '(unsigned-byte 8) :initial-element key-byte))
   "wireguardListenPort" 51820
   "wireguardEndpoints" #()))

(test wireguard-peer-group-preserves-every-pod-address-family
  (let* ((route (wireguard-route-fixture
                 :pod-cidrs '("10.88.9.0/24" "fd88:0:0:9::/64")))
         (network (gr8s.foundation::json-object "routes" (vector route)))
         (peer (first (gr8s.network::wireguard-peer-routes network))))
    (is (equal '("10.88.9.0/24" "fd88:0:0:9::/64")
               (coerce (gethash "podCIDRs" peer) 'list)))))

(test sparse-wireguard-destinations-group-by-authenticated-next-hop
  (let* ((first (wireguard-route-fixture :key-byte 1))
         (second (wireguard-route-fixture :key-byte 2))
         (direct (wireguard-route-fixture :key-byte 3))
         (hop (wireguard-next-hop-fixture))
         (network (gr8s.foundation::json-object "routes" (vector first second direct))))
    (setf (gethash "nodeID" first) "destination-a"
          (gethash "nodeName" first) "destination-a"
          (gethash "podCIDR" first) "10.88.1.0/24"
          (gethash "nextHop" first) hop
          (gethash "nodeID" second) "destination-b"
          (gethash "nodeName" second) "destination-b"
          (gethash "podCIDR" second) "10.88.2.0/24"
          (gethash "nextHop" second) hop
          (gethash "nodeID" direct) "direct-c"
          (gethash "nodeName" direct) "direct-c"
          (gethash "podCIDR" direct) "10.88.3.0/24")
    (let* ((peers (gr8s.network::wireguard-peer-routes network))
           (gateway (find "gateway-a" peers :key (lambda (peer)
                                                    (gethash "nodeID" peer))
                          :test #'string=)))
      (is (= 2 (length peers)))
      (is (equal '("10.88.1.0/24" "10.88.2.0/24")
                 (coerce (gethash "podCIDRs" gateway) 'list)))
      (is (= 2 (length (gr8s.network::wireguard-desired-peer-keys network))))
      (let* ((attributes
               (cl-rtnetlink::netlink-attributes
                (gr8s.network::wireguard-peer-attributes gateway) 0))
             (allowed
               (gr8s.network::wireguard-nested-attribute-payloads
                (gethash 9 attributes))))
        (is (= 2 (length allowed))))
      (setf (gethash "nextHop" second)
            (wireguard-next-hop-fixture :key-byte 10 :name "gateway-a"))
      (signals gr8s.network::cni-error
        (gr8s.network::wireguard-peer-routes network)))))

(test sparse-wireguard-path-state-observes-next-hops-not-destinations
  (let* ((first (wireguard-route-fixture :key-byte 1))
         (second (wireguard-route-fixture :key-byte 2))
         (hop (wireguard-next-hop-fixture :key-byte 9))
         (network (gr8s.foundation::json-object "routes" (vector first second)))
         (state (cl-wireguard-overlay::make-wireguard-path-state))
         (hop-key (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 9)))
    (setf (gethash "nodeID" first) "destination-a"
          (gethash "nodeName" first) "destination-a"
          (gethash "podCIDR" first) "10.88.1.0/24"
          (gethash "nextHop" first) hop
          (gethash "nodeID" second) "destination-b"
          (gethash "nodeName" second) "destination-b"
          (gethash "podCIDR" second) "10.88.2.0/24"
          (gethash "nextHop" second) hop)
    (gr8s.network::reconcile-wireguard-path-state
     state network :now 1000
     :status-reader
     (lambda ()
       (list (gr8s.network::make-wireguard-peer-status
              :public-key hop-key :endpoint-address "192.0.2.20"
              :endpoint-port 51820 :latest-handshake-seconds 999
              :received-bytes 10)))
     :endpoint-setter (lambda (&rest ignored) (declare (ignore ignored))))
    (is (= 1 (hash-table-count (cl-wireguard-overlay::wireguard-path-state-peers state))))
    (is (gethash "gateway-a" (cl-wireguard-overlay::wireguard-path-state-peers state)))
    (is-false (gethash "destination-a" (cl-wireguard-overlay::wireguard-path-state-peers state)))))

(test sparse-next-hop-trial-verifies-gateway-before-allowed-ip-migration
  (let* ((peer (wireguard-next-hop-fixture))
         (events nil))
    (setf (gethash "probeCIDR" peer) "10.88.20.0/24")
    (is-true
     (gr8s.network::trial-wireguard-next-hop
      peer
      :configurer (lambda (candidate probe-cidr)
                    (push (list :configure (gethash "nodeID" candidate) probe-cidr)
                          events))
      :route-adder (lambda (address prefix interface &key source)
                     (declare (ignore source))
                     (push (list :route-add address prefix interface) events))
      :route-remover (lambda (&rest arguments)
                       (push (cons :route-remove arguments) events))
      :peer-remover (lambda (&rest arguments)
                      (push (cons :peer-remove arguments) events))
      :status-reader (lambda () nil)
      :round-trip-verifier
      (lambda (key endpoint baseline probe &key timeout-milliseconds)
        (declare (ignore key baseline timeout-milliseconds))
        (push (list :verify endpoint) events)
        (funcall probe)
        t)
      :probe-sender (lambda (route)
                      (push (list :probe (gethash "podCIDR" route)) events))))
    (is (equal '(:configure :route-add :verify :probe)
               (mapcar #'first (reverse events))))
    (setf events nil)
    (signals gr8s.network::cni-error
      (gr8s.network::trial-wireguard-next-hop
       peer
       :configurer (lambda (&rest arguments)
                     (declare (ignore arguments)) (push '(:configure) events))
       :route-adder (lambda (&rest arguments)
                      (declare (ignore arguments)) (push '(:route-add) events))
       :route-remover (lambda (&rest arguments)
                        (declare (ignore arguments)) (push '(:route-remove) events))
       :peer-remover (lambda (&rest arguments)
                       (declare (ignore arguments)) (push '(:peer-remove) events))
       :status-reader (lambda () nil)
       :round-trip-verifier (lambda (&rest arguments)
                              (declare (ignore arguments)) nil)
       :probe-sender (lambda (&rest arguments) (declare (ignore arguments)))))
    (is (equal '(:configure :route-add :route-remove :peer-remove)
               (mapcar #'first (reverse events))))))

(test sparse-topology-migration-trials-peer-that-gains-a-destination
  (let* ((gateway (wireguard-route-fixture :key-byte 9))
         (destination (wireguard-route-fixture :key-byte 7))
         (previous (gr8s.foundation::json-object "routes" (vector gateway destination)))
         (next-hop (wireguard-next-hop-fixture :key-byte 9 :name "gateway-a"))
         (calls nil))
    (setf (gethash "nodeID" gateway) "gateway-a"
          (gethash "nodeName" gateway) "gateway-a"
          (gethash "podCIDR" gateway) "10.88.20.0/24"
          (gethash "underlayAddress" gateway) "192.0.2.20"
          (gethash "wireguardEndpoints" gateway) #()
          (gethash "nodeID" destination) "destination-b"
          (gethash "nodeName" destination) "destination-b"
          (gethash "podCIDR" destination) "10.88.30.0/24")
    (let ((current (gr8s.foundation::json-object
                    "routes" (vector gateway
                                     (let ((route (wireguard-route-fixture :key-byte 7)))
                                       (setf (gethash "nodeID" route) "destination-b"
                                             (gethash "nodeName" route) "destination-b"
                                             (gethash "podCIDR" route) "10.88.30.0/24"
                                             (gethash "nextHop" route) next-hop)
                                       route)))))
      (is (equal '("10.88.20.0")
                 (gr8s.network::trial-wireguard-topology-migrations
                  previous current
                  :trial-function
                  (lambda (peer &key previous-cidrs)
                    (push (list (gethash "nodeID" peer) previous-cidrs) calls)
                    t))))
      (is (equal '(("gateway-a" ("10.88.20.0/24"))) calls)))))

(test sparse-topology-migration-cleans-earlier-probes-when-later-trial-fails
  (labels ((route (id cidr key-byte address)
             (let ((route (wireguard-route-fixture :key-byte key-byte)))
               (setf (gethash "nodeID" route) id
                     (gethash "nodeName" route) id
                     (gethash "podCIDR" route) cidr
                     (gethash "underlayAddress" route) address
                     (gethash "wireguardEndpoints" route) #())
               route))
           (hop (id key-byte address)
             (let ((hop (wireguard-next-hop-fixture :name id :key-byte key-byte)))
               (setf (gethash "underlayAddress" hop) address)
               hop)))
    (let* ((gateway-a (route "gateway-a" "10.88.20.0/24" 9 "192.0.2.20"))
           (gateway-b (route "gateway-b" "10.88.21.0/24" 10 "192.0.2.21"))
           (destination-a (route "destination-a" "10.88.30.0/24" 1 "192.0.2.30"))
           (destination-b (route "destination-b" "10.88.31.0/24" 2 "192.0.2.31"))
           (previous (gr8s.foundation::json-object
                      "routes" (vector gateway-a gateway-b destination-a destination-b)))
           (current-a (route "destination-a" "10.88.30.0/24" 1 "192.0.2.30"))
           (current-b (route "destination-b" "10.88.31.0/24" 2 "192.0.2.31"))
           (trials 0)
           (removed nil))
      (setf (gethash "nextHop" current-a) (hop "gateway-a" 9 "192.0.2.20")
            (gethash "nextHop" current-b) (hop "gateway-b" 10 "192.0.2.21"))
      (signals error
        (gr8s.network::trial-wireguard-topology-migrations
         previous
         (gr8s.foundation::json-object
          "routes" (vector gateway-a gateway-b current-a current-b))
         :trial-function
         (lambda (peer &key previous-cidrs)
           (declare (ignore peer previous-cidrs))
           (when (= 2 (incf trials)) (error "second trial failed"))
           t)
         :route-remover
         (lambda (address prefix interface)
           (push (list address prefix interface) removed))))
      (is (equal '(("10.88.20.0" 32 "gr8s-wg")) removed)))))

(test wireguard-relay-channels-are-bounded-rate-limited-and-cross-forwarded
  (let* ((relay (gr8s.network::make-wireguard-relay-coordinator
                 :port-start 42000 :max-channels 1
                 :source-change-seconds 30 :idle-seconds 60))
         (channel (gr8s.network::ensure-wireguard-relay-channel relay "node-b" "node-a" 100)))
    (is (equal '("node-a" "node-b")
               (gr8s.network::wireguard-relay-channel-nodes channel)))
    (is (= 42000 (gr8s.network::wireguard-relay-channel-port-for channel "node-a")))
    (is (= 42001 (gr8s.network::wireguard-relay-channel-port-for channel "node-b")))
    (gr8s.network::authorize-wireguard-relay-node
     relay channel "node-a" "198.51.100.1" 100)
    (gr8s.network::authorize-wireguard-relay-node
     relay channel "node-b" "198.51.100.2" 100)
    (is-true (gr8s.network::note-wireguard-relay-source
              relay channel "node-a" "198.51.100.1" 51000 100))
    (is-true (gr8s.network::note-wireguard-relay-source
              relay channel "node-b" "198.51.100.2" 52000 100))
    (multiple-value-bind (address port source-port)
        (gr8s.network::wireguard-relay-forward-target channel "node-a")
      (is (string= "198.51.100.2" address))
      (is (= 52000 port))
      (is (= 42001 source-port)))
    (is-false (gr8s.network::note-wireguard-relay-source
               relay channel "node-a" "203.0.113.1" 53000 110))
    (gr8s.network::authorize-wireguard-relay-node
     relay channel "node-a" "203.0.113.1" 131)
    (is-true (gr8s.network::note-wireguard-relay-source
              relay channel "node-a" "203.0.113.1" 53000 131))
    (signals error
      (gr8s.network::ensure-wireguard-relay-channel relay "node-c" "node-d" 131))
    (is (= 1 (gr8s.network::expire-wireguard-relay-channels relay 192)))
    (is (gr8s.network::ensure-wireguard-relay-channel relay "node-c" "node-d" 192))))

(test wireguard-relay-reuses-only-free-port-pairs
  (let* ((relay (gr8s.network::make-wireguard-relay-coordinator
                 :port-start 43000 :max-channels 2 :idle-seconds 10))
         (first (gr8s.network::ensure-wireguard-relay-channel relay "a" "b" 0))
         (second (gr8s.network::ensure-wireguard-relay-channel relay "c" "d" 9)))
    (is (equal '(43000 43001) (gr8s.network::wireguard-relay-channel-ports first)))
    (is (equal '(43002 43003) (gr8s.network::wireguard-relay-channel-ports second)))
    (is (= 1 (gr8s.network::expire-wireguard-relay-channels relay 10)))
    (is (equal '(43000 43001)
               (gr8s.network::wireguard-relay-channel-ports
                (gr8s.network::ensure-wireguard-relay-channel relay "e" "f" 10))))))

(test wireguard-relay-datagrams-cross-forward-without-amplification
  (let* ((relay (gr8s.network::make-wireguard-relay-coordinator :port-start 44000))
         (channel (gr8s.network::ensure-wireguard-relay-channel relay "a" "b" 0))
         (sent nil)
         (send (lambda (source-port data length address port)
                 (push (list source-port (subseq data 0 length) address port) sent))))
    (gr8s.network::authorize-wireguard-relay-node relay channel "a" "198.51.100.1" 0)
    (gr8s.network::authorize-wireguard-relay-node relay channel "b" "198.51.100.2" 0)
    (gr8s.network::relay-wireguard-datagram
     relay channel "a" #(1 2 3) 3 "198.51.100.1" 51000 1 send)
    (is (null sent))
    (gr8s.network::relay-wireguard-datagram
     relay channel "b" #(4 5) 2 "198.51.100.2" 52000 2 send)
    (is (equalp '((44000 #(4 5) "198.51.100.1" 51000)) sent))
    (gr8s.network::relay-wireguard-datagram
     relay channel "a" #(6 7 8 9) 3 "198.51.100.1" 51000 3 send)
    (is (equalp '(44001 #(6 7 8) "198.51.100.2" 52000) (first sent)))
    (is (= 2 (length sent)))))

(test wireguard-relay-requires-fresh-authenticated-sources-and-rate-limits
  (let* ((relay (gr8s.network::make-wireguard-relay-coordinator
                 :port-start 44500 :authorization-seconds 10
                 :max-packets-per-second 1 :max-bytes-per-second 16))
         (channel (gr8s.network::ensure-wireguard-relay-channel relay "a" "b" 0))
         (sent 0)
         (send (lambda (&rest ignored) (declare (ignore ignored)) (incf sent))))
    (is-false (gr8s.network::note-wireguard-relay-source
               relay channel "a" "198.51.100.1" 51000 0))
    (gr8s.network::authorize-wireguard-relay-node relay channel "a" "198.51.100.1" 0)
    (gr8s.network::authorize-wireguard-relay-node relay channel "b" "198.51.100.2" 0)
    (is-false (gr8s.network::note-wireguard-relay-source
               relay channel "a" "203.0.113.1" 51000 0))
    (is-true (gr8s.network::note-wireguard-relay-source
              relay channel "a" "198.51.100.1" 51000 0))
    (is-true (gr8s.network::note-wireguard-relay-source
              relay channel "b" "198.51.100.2" 52000 0))
    (is-true (gr8s.network::relay-wireguard-datagram
              relay channel "a" #(1 2 3) 3 "198.51.100.1" 51000 1 send))
    (is-false (gr8s.network::relay-wireguard-datagram
               relay channel "b" #(4 5) 2 "198.51.100.2" 52000 1 send))
    (is (= 1 sent))
    (is-false (gr8s.network::note-wireguard-relay-source
               relay channel "a" "198.51.100.1" 51000 11))))

(test wireguard-relay-server-forwards-opaque-udp-from-the-opposite-port
  (let ((server nil) (channel nil) (client-a nil) (client-b nil))
    (unwind-protect
         (progn
           (loop for port from 45000 below 60000 by 2
                 do (let ((candidate
                            (gr8s.network::start-wireguard-relay-server
                             :address "127.0.0.1" :port-start port :max-channels 1)))
                      (handler-case
                          (progn
                            (setf channel
                                  (gr8s.network::ensure-wireguard-relay-server-channel
                                   candidate "a" "b" 0)
                                  server candidate)
                            (return))
                        (error () (gr8s.network::stop-wireguard-relay-server candidate)))))
           (is-true server)
           (gr8s.network::authorize-wireguard-relay-node
            (gr8s.network::wireguard-relay-server-coordinator server)
            channel "a" "127.0.0.1" (get-universal-time))
           (gr8s.network::authorize-wireguard-relay-node
            (gr8s.network::wireguard-relay-server-coordinator server)
            channel "b" "127.0.0.1" (get-universal-time))
           (setf client-a (make-instance 'sb-bsd-sockets:inet-socket
                                         :type :datagram :protocol :udp)
                 client-b (make-instance 'sb-bsd-sockets:inet-socket
                                         :type :datagram :protocol :udp))
           (sb-bsd-sockets:socket-bind
            client-a (sb-bsd-sockets:make-inet-address "127.0.0.1") 0)
           (sb-bsd-sockets:socket-bind
            client-b (sb-bsd-sockets:make-inet-address "127.0.0.1") 0)
           (flet ((send (socket octets port)
                    (let ((payload (coerce octets '(simple-array (unsigned-byte 8) (*)))))
                      (sb-bsd-sockets:socket-send
                       socket payload (length payload)
                       :address
                       (list (sb-bsd-sockets:make-inet-address "127.0.0.1") port))))
                  (receive (socket)
                    (let ((buffer (make-array 32 :element-type '(unsigned-byte 8))))
                      (is-true (sb-sys:wait-until-fd-usable
                                (sb-bsd-sockets:socket-file-descriptor socket)
                                :input 2))
                      (multiple-value-bind (ignored length address port)
                          (sb-bsd-sockets:socket-receive socket buffer (length buffer))
                        (declare (ignore ignored address))
                        (values (subseq buffer 0 length) port)))))
             (send client-a #(1 2 3) (gr8s.network::wireguard-relay-channel-port-for channel "a"))
             (sleep 0.05)
             (send client-b #(4 5) (gr8s.network::wireguard-relay-channel-port-for channel "b"))
             (multiple-value-bind (data port) (receive client-a)
               (is (equalp #(4 5) data))
               (is (= (gr8s.network::wireguard-relay-channel-port-for channel "a") port)))
             (send client-a #(6 7 8) (gr8s.network::wireguard-relay-channel-port-for channel "a"))
             (multiple-value-bind (data port) (receive client-b)
               (is (equalp #(6 7 8) data))
               (is (= (gr8s.network::wireguard-relay-channel-port-for channel "b") port)))))
      (when client-a (ignore-errors (sb-bsd-sockets:socket-close client-a)))
      (when client-b (ignore-errors (sb-bsd-sockets:socket-close client-b)))
      (when server (gr8s.network::stop-wireguard-relay-server server)))))

(test wireguard-relay-server-reaps-idle-listeners-and-reuses-their-ports
  (let ((server (gr8s.network::start-wireguard-relay-server
                 :address "127.0.0.1" :port-start 47000
                 :max-channels 1 :idle-seconds 10)))
    (unwind-protect
         (let ((first (gr8s.network::ensure-wireguard-relay-server-channel
                       server "a" "b" 0)))
           (is (= 2 (hash-table-count
                     (gr8s.network::wireguard-relay-server-listeners server))))
           (is (= 1 (gr8s.network::reap-wireguard-relay-server server 10)))
           (is (= 0 (hash-table-count
                     (gr8s.network::wireguard-relay-server-listeners server))))
           (is (equal (gr8s.network::wireguard-relay-channel-ports first)
                      (gr8s.network::wireguard-relay-channel-ports
                       (gr8s.network::ensure-wireguard-relay-server-channel
                        server "c" "d" 10)))))
      (gr8s.network::stop-wireguard-relay-server server))))

(test authenticated-live-node-heartbeats-keep-advertised-relay-listeners-open
  (let ((server (gr8s.network::start-wireguard-relay-server
                 :address "127.0.0.1" :port-start 47500
                 :max-channels 1 :authorization-seconds 2 :idle-seconds 10)))
    (unwind-protect
         (let* ((channel (gr8s.network::ensure-wireguard-relay-server-channel
                          server "a" "b" 0))
                (coordinator (gr8s.network::wireguard-relay-server-coordinator server)))
           (gr8s.network::authorize-wireguard-relay-node
            coordinator channel "a" "198.51.100.1" 0)
           (gr8s.network::authorize-wireguard-relay-node
            coordinator channel "b" "198.51.100.2" 0)
           (is-false (gr8s.network::note-wireguard-relay-source
                      coordinator channel "a" "198.51.100.1" 51000 3))
           (gr8s.network::refresh-wireguard-relay-node server "a" 9)
           (is (= 0 (gr8s.network::reap-wireguard-relay-server server 10)))
           (is (= 2 (hash-table-count
                     (gr8s.network::wireguard-relay-server-listeners server))))
           (is (= 1 (gr8s.network::reap-wireguard-relay-server server 20))))
      (gr8s.network::stop-wireguard-relay-server server))))

(test wireguard-peer-uapi-carries-identity-endpoint-and-allowed-prefix
  (let* ((attributes
           (cl-rtnetlink::netlink-attributes
            (gr8s.network::wireguard-peer-attributes (wireguard-route-fixture)) 0))
         (endpoint (gethash 4 attributes))
         (allowed-entry
           (gethash 0 (cl-rtnetlink::netlink-attributes (gethash 9 attributes) 0)))
         (allowed (cl-rtnetlink::netlink-attributes allowed-entry 0)))
    (is (equalp (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)
                (gethash 1 attributes)))
    (is (= 2 (cl-rtnetlink::netlink-read-integer (gethash 3 attributes) 0 4)))
    (is (= 25 (cl-rtnetlink::netlink-read-integer (gethash 5 attributes) 0 2)))
    (is (= 2 (cl-rtnetlink::netlink-read-integer endpoint 0 2)))
    (is (equalp #(202 108) (subseq endpoint 2 4)))
    (is (equalp #(192 0 2 9) (subseq endpoint 4 8)))
    (is (= 2 (cl-rtnetlink::netlink-read-integer (gethash 1 allowed) 0 2)))
    (is (equalp #(10 88 9 0) (gethash 2 allowed)))
    (is (= 24 (aref (gethash 3 allowed) 0)))))

(test wireguard-peer-uapi-carries-every-pod-address-family
  (let* ((route (wireguard-route-fixture
                 :pod-cidrs '("10.88.9.0/24" "fd88:0:0:9::/64")))
         (attributes
           (cl-rtnetlink::netlink-attributes
            (gr8s.network::wireguard-peer-attributes route) 0))
         (entries (cl-rtnetlink::netlink-attributes (gethash 9 attributes) 0))
         (ipv4 (cl-rtnetlink::netlink-attributes (gethash 0 entries) 0))
         (ipv6 (cl-rtnetlink::netlink-attributes (gethash 1 entries) 0)))
    (is (= 2 (hash-table-count entries)))
    (is (= 2 (cl-rtnetlink::netlink-read-integer (gethash 1 ipv4) 0 2)))
    (is (equalp #(10 88 9 0) (gethash 2 ipv4)))
    (is (= 24 (aref (gethash 3 ipv4) 0)))
    (is (= 10 (cl-rtnetlink::netlink-read-integer (gethash 1 ipv6) 0 2)))
    (is (equalp (0conf:parse-ipv6 "fd88:0:0:9::") (gethash 2 ipv6)))
    (is (= 64 (aref (gethash 3 ipv6) 0)))))

(test wireguard-device-uapi-never-confuses-private-and-peer-keys
  (let* ((private-key
           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (network
           (gr8s.foundation::json-object
            "wireguardListenPort" 51820
            "routes" (vector (wireguard-route-fixture))))
         (attributes
           (cl-rtnetlink::netlink-attributes
            (gr8s.network::wireguard-device-attributes "gr8s-wg" private-key network) 0)))
    (is (equalp (cl-rtnetlink::netlink-string "gr8s-wg") (gethash 2 attributes)))
    (is (equalp private-key (gethash 3 attributes)))
    (is (= 1 (cl-rtnetlink::netlink-read-integer (gethash 5 attributes) 0 4)))
    (is (= 51820 (cl-rtnetlink::netlink-read-integer (gethash 6 attributes) 0 2)))
    (is-false (search (ag-grpc:base64-encode private-key)
                      (com.inuoe.jzon:stringify network)))))

(test wireguard-single-peer-endpoint-update-preserves-key-and-allowed-ips
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element 19))
         (device
           (cl-rtnetlink::netlink-attributes
            (gr8s.network::wireguard-peer-endpoint-device-attributes
             "gr8s-wg" key "10.0.0.9" 51821)
            0))
         (peer-payload
           (first (gr8s.network::wireguard-nested-attribute-payloads
                   (gethash 8 device))))
         (peer (cl-rtnetlink::netlink-attributes peer-payload 0))
         (endpoint (gethash 4 peer)))
    (is (equalp (cl-rtnetlink::netlink-string "gr8s-wg") (gethash 2 device)))
    (is-false (gethash 5 device))
    (is (equalp key (gethash 1 peer)))
    (is-false (gethash 3 peer))
    (is-false (gethash 9 peer))
    (is (equalp #(10 0 0 9) (subseq endpoint 4 8)))
    (is (= 51821 (+ (ash (aref endpoint 2) 8) (aref endpoint 3))))))

(test wireguard-session-reset-expires-only-the-named-peers-keypair
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element 21))
         (device
           (cl-rtnetlink::netlink-attributes
            (gr8s.network::wireguard-peer-session-reset-device-attributes "gr8s-wg" key)
            0))
         (peer-payload
           (first (gr8s.network::wireguard-nested-attribute-payloads
                   (gethash 8 device))))
         (peer (cl-rtnetlink::netlink-attributes peer-payload 0)))
    (is (equalp (cl-rtnetlink::netlink-string "gr8s-wg") (gethash 2 device)))
    (is-false (gethash 3 device))
    (is-false (gethash 5 device))
    (is (equalp key (gethash 1 peer)))
    ;; Re-applying the all-zero (disabled) PSK makes Linux expire this peer's
    ;; current keypair without removing its endpoint, identity, or allowed IPs.
    (is (equalp (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 0)
                (gethash 2 peer)))
    (is-false (gethash 3 peer))
    (is-false (gethash 4 peer))
    (is-false (gethash 9 peer))))

(test wireguard-endpoint-trials-require-a-fresh-authenticated-handshake-or-roll-back
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element 23))
         (current '("public" "192.0.2.9" 51820))
         (candidate '("private" "10.0.0.9" 51820))
         (sets nil)
         (probes 0)
         (resets 0)
         (statuses
           (list
            (gr8s.network::make-wireguard-peer-status
             :public-key key :endpoint-address "10.0.0.9" :endpoint-port 51820
             :latest-handshake-seconds 100 :received-bytes 11 :transmitted-bytes 20)
            (gr8s.network::make-wireguard-peer-status
             :public-key key :endpoint-address "10.0.0.9" :endpoint-port 51820
             :latest-handshake-seconds 101 :received-bytes 11 :transmitted-bytes 20)))
         (times (list 1000 1005 1012)))
    (multiple-value-bind (success latency)
        (gr8s.network::trial-wireguard-peer-endpoint
         key current candidate
         :baseline-handshake-seconds 100
         :baseline-received-bytes 10
         :endpoint-setter (lambda (peer-key address port)
                            (declare (ignore peer-key))
                            (push (list address port) sets))
         :probe (lambda () (incf probes))
         :session-resetter (lambda (peer-key)
                             (is (equalp key peer-key))
                             (incf resets))
         :status-reader
         (lambda ()
           (list (or (pop statuses)
                     (gr8s.network::make-wireguard-peer-status
                      :public-key key :endpoint-address "10.0.0.9" :endpoint-port 51820
                      :latest-handshake-seconds 101 :received-bytes 11))))
         :clock-milliseconds (lambda () (pop times))
         :sleep-function (constantly nil))
      (is-true success)
      (is (= 12 latency))
      (is (equal '(("10.0.0.9" 51820)) (nreverse sets)))
      (is (= 2 probes))
      (is (= 1 resets))))
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element 27))
         (resets 0)
         (ticks (list 0 4)))
    (multiple-value-bind (success latency)
        (gr8s.network::trial-wireguard-peer-endpoint
         key '("underlay" "192.0.2.9" 51820)
         '("private" "10.0.0.9" 51820)
         :baseline-handshake-seconds 100 :baseline-received-bytes 10
         :endpoint-setter (lambda (&rest ignored) (declare (ignore ignored)))
         :probe (constantly nil)
         :session-resetter (lambda (&rest ignored)
                             (declare (ignore ignored))
                             (incf resets))
         :status-reader
         (lambda ()
           (list (gr8s.network::make-wireguard-peer-status
                  :public-key key :endpoint-address "10.0.0.9" :endpoint-port 51820
                  :latest-handshake-seconds 101 :received-bytes 11)))
         :clock-milliseconds (lambda () (pop ticks))
         :sleep-function (constantly nil))
      (is-true success)
      (is (= 4 latency))
      (is (zerop resets))))
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element 29))
         (sets nil)
         (resets 0)
         (ticks (list 0 10 20 30 40 50 60)))
    (multiple-value-bind (success reason)
        (gr8s.network::trial-wireguard-peer-endpoint
         key '("public" "192.0.2.9" 51820)
         '("private" "10.0.0.9" 51820)
         :baseline-handshake-seconds 100 :baseline-received-bytes 10
         :timeout-milliseconds 50
         :endpoint-setter (lambda (peer-key address port)
                            (declare (ignore peer-key))
                            (push (list address port) sets))
         :probe (constantly nil)
         :session-resetter (lambda (peer-key)
                             (declare (ignore peer-key))
                             (incf resets))
         :status-reader
         (lambda ()
           (list (gr8s.network::make-wireguard-peer-status
                  :public-key key :endpoint-address "10.0.0.9" :endpoint-port 51820
                  :latest-handshake-seconds 100
                  :received-bytes 10 :transmitted-bytes 999)))
         :clock-milliseconds (lambda () (pop ticks))
         :sleep-function (constantly nil))
      (is-false success)
      (is (eq :handshake-timeout reason))
      ;; Configuring an endpoint and transmitting toward it are not proof that
      ;; the replacement is reachable. Never destroy the working session until
      ;; authenticated traffic has returned over the exact candidate path.
      (is (zerop resets))
      (is (equal '(("10.0.0.9" 51820) ("192.0.2.9" 51820))
                 (nreverse sets))))))

(test wireguard-path-decisions-survive-restart-and-bound-history-and-trials
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((path (merge-pathnames "wireguard-paths.json" directory))
           (state (cl-wireguard-overlay::make-wireguard-path-state)))
      (dotimes (index 70)
        (gr8s.network::record-wireguard-path-decision
         state "peer-a"
         (list "private" "10.0.0.9" 51820)
         (list "public" "192.0.2.9" 51820)
         :sustained-improvement (+ 100 index)))
      (let ((peer (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state))))
        (setf (cl-wireguard-overlay::wireguard-peer-path-state-observations peer)
              (list (cl-wireguard-overlay::make-wireguard-path-observation
                     :name "private" :address "10.0.0.9" :port 51820
                     :last-mtu-probe-at 123
                     :safe-mtu 1280 :mtu-upgrade-candidate 1400
                     :mtu-upgrade-successes 2
                     :mtu-reason :packet-size-black-hole
                     :mtu-changed-at 122))))
      (gr8s.network::persist-wireguard-path-state path state)
      (let* ((restored (gr8s.network::load-wireguard-path-state path))
             (peer (gethash "peer-a"
                            (cl-wireguard-overlay::wireguard-path-state-peers restored))))
        (is (equal '("private" "10.0.0.9" 51820)
                   (cl-wireguard-overlay::wireguard-peer-path-state-selected peer)))
        (is (equal '("public" "192.0.2.9" 51820)
                   (cl-wireguard-overlay::wireguard-peer-path-state-previous peer)))
        (is (eq :sustained-improvement
                (cl-wireguard-overlay::wireguard-peer-path-state-reason peer)))
        (is (= 169 (cl-wireguard-overlay::wireguard-peer-path-state-changed-at peer)))
        (let ((observation (first (cl-wireguard-overlay::wireguard-peer-path-state-observations peer))))
          (is (= 123 (cl-wireguard-overlay::wireguard-path-observation-last-mtu-probe-at observation)))
          (is (= 1280 (cl-wireguard-overlay::wireguard-path-observation-safe-mtu observation)))
          (is (eq :packet-size-black-hole
                  (cl-wireguard-overlay::wireguard-path-observation-mtu-reason observation)))
          (is (= 122 (cl-wireguard-overlay::wireguard-path-observation-mtu-changed-at observation)))
          (is (= 1400 (cl-wireguard-overlay::wireguard-path-observation-mtu-upgrade-candidate observation)))
          (is (= 2 (cl-wireguard-overlay::wireguard-path-observation-mtu-upgrade-successes observation))))
        (is (= 64 (length (cl-wireguard-overlay::wireguard-path-state-history restored))))
        (setf (cl-wireguard-overlay::wireguard-peer-path-state-last-trial-at peer) 200)
        (is-false (cl-wireguard-overlay::wireguard-path-trial-allowed-p peer 229))
        (is-true (cl-wireguard-overlay::wireguard-path-trial-allowed-p peer 230))
        (is (= #o600
               (logand #o777
                       (sb-posix:stat-mode (sb-posix:stat path)))))))))

(test passive-ebpf-telemetry-is-bounded-and-cannot-declare-a-path-healthy
  (let* ((observation
           (cl-wireguard-overlay::make-wireguard-path-observation
            :name "lan" :address "10.0.0.9" :port 51820
            :handshake-age-seconds 999
            :consecutive-failures 2))
         (sample
           (cl-wireguard-overlay::make-wireguard-path-telemetry
            :rtt-microseconds 2400
            :tcp-samples 100
            :retransmits 4
            :congestion-window 18
            :active-flows 7
            :bytes 125000
            :interval-milliseconds 1000)))
    (cl-wireguard-overlay::apply-wireguard-path-telemetry observation sample)
    (is (= 2400 (cl-wireguard-overlay::wireguard-path-observation-passive-rtt-microseconds
                 observation)))
    (is (= 4 (cl-wireguard-overlay::wireguard-path-observation-passive-retransmits observation)))
    (is (= 18 (cl-wireguard-overlay::wireguard-path-observation-passive-congestion-window
               observation)))
    (is (= 7 (cl-wireguard-overlay::wireguard-path-observation-passive-active-flows observation)))
    (is (= 125000 (cl-wireguard-overlay::wireguard-path-observation-passive-bytes-per-second
                   observation)))
    ;; Passive evidence improves ranking, but cannot replace the fresh
    ;; authenticated handshake and active round-trip safety gates.
    (is-false (cl-wireguard-overlay::wireguard-path-healthy-p observation))
    ;; A faulty or overloaded peer cannot make arithmetic unbounded: every
    ;; passive penalty is clamped before it enters the conservative score.
    (let ((ordinary (cl-wireguard-overlay::wireguard-path-score observation)))
      (cl-wireguard-overlay::apply-wireguard-path-telemetry
       observation
       (cl-wireguard-overlay::make-wireguard-path-telemetry
        :rtt-microseconds most-positive-fixnum
        :tcp-samples most-positive-fixnum
        :retransmits most-positive-fixnum
        :congestion-window 0
        :active-flows most-positive-fixnum
        :bytes most-positive-fixnum
        :interval-milliseconds 1))
      (is (< (- (cl-wireguard-overlay::wireguard-path-score observation) ordinary) 10000)))))

(test wireguard-path-telemetry-is-jit-compiled-and-cardinality-bounded
  (multiple-value-bind (maps programs)
      (gr8s.network::compile-wireguard-path-telemetry
       :probe-offsets '(:destination 40 :family 68 :bytes 76 :cwnd 88 :ssthresh 92
                        :rtt 100 :cookie 112)
       :retransmit-offsets '(:destination 38 :family 32))
    (is (equal '("gr8s_path_tcp_v4" "gr8s_path_flows_v4")
               (mapcar (lambda (spec) (getf spec :name)) maps)))
    (is (every (lambda (spec)
                 (and (eq :lru-hash (getf spec :type))
                      (<= (getf spec :max-entries) 65536)))
               maps))
    (is (equal '("tracepoint/tcp/tcp_probe"
                 "tracepoint/tcp/tcp_retransmit_skb")
               (mapcar (lambda (spec) (getf spec :section)) programs)))
    (is (every (lambda (spec) (plusp (length (getf spec :insns)))) programs))))

(test wireguard-path-telemetry-materializes-map-update-keys-on-the-bpf-stack
  (labels ((contains-symbol-p (tree symbol)
             (cond ((eq tree symbol) t)
                   ((consp tree)
                    (or (contains-symbol-p (car tree) symbol)
                        (contains-symbol-p (cdr tree) symbol))))))
    (let ((forms (gr8s.network::wireguard-path-telemetry-program-forms
                  '(:destination 40 :family 68 :bytes 76 :cwnd 88 :ssthresh 92
                    :rtt 100 :cookie 112)
                  '(:destination 38 :family 32))))
      (is-true (contains-symbol-p forms 'whistler::make-gr8s-path-ipv4-key))
      (is-true (contains-symbol-p forms 'whistler::make-gr8s-path-cookie-key)))))

(test wireguard-path-telemetry-loads-unaligned-ipv4-addresses-bytewise
  (labels ((contains-form-p (tree form)
             (cond ((equal tree form) t)
                   ((consp tree)
                    (or (contains-form-p (car tree) form)
                        (contains-form-p (cdr tree) form))))))
    (let ((forms (gr8s.network::wireguard-path-telemetry-program-forms
                  '(:destination 40 :family 68 :bytes 76 :cwnd 88 :ssthresh 92
                    :rtt 100 :cookie 112)
                  '(:destination 38 :family 32))))
      (is-false (contains-form-p forms '(whistler::ctx-load whistler::u32 38)))
      (loop for offset from 38 to 41
            do (is-true
                (contains-form-p
                 forms `(whistler::ctx-load whistler::u8 ,offset)))))))

(test tcp-probe-sockaddr-offset-is-normalized-to-the-ipv4-bytes
  (is (= 40 (getf (gr8s.network::wireguard-tcp-probe-ipv4-offsets
                    '(:destination 36 :family 68 :bytes 76))
                   :destination))))

(test ebpf-counters-are-attributed-to-authenticated-peer-cidrs-as-deltas
  (let* ((route (wireguard-route-fixture))
         (network (gr8s.foundation::json-object "routes" (vector route)))
         (previous (make-hash-table :test #'equal)))
    (setf (gethash "peer-a" previous)
          (gr8s.network::make-wireguard-path-telemetry-counters
           :bytes 1000 :samples 10 :rtt-sum-microseconds 20000
           :retransmits 1 :sampled-at-milliseconds 1000))
    (let ((samples
            (gr8s.network::wireguard-path-telemetry-samples
             network
             (list
              (cons "10.88.9.2"
                    (gr8s.network::make-wireguard-path-telemetry-counters
                     :bytes 3000 :samples 20 :rtt-sum-microseconds 45000
                     :retransmits 2 :congestion-window 24))
              (cons "10.88.9.3"
                    (gr8s.network::make-wireguard-path-telemetry-counters
                     :bytes 2000 :samples 10 :rtt-sum-microseconds 25000
                     :retransmits 1 :congestion-window 18)))
             '("10.88.9.2" "10.88.9.3" "192.0.2.5")
             previous 3000)))
      (is (= 1 (hash-table-count samples)))
      (let ((sample (gethash "peer-a" samples)))
        (is (= 2500 (cl-wireguard-overlay::wireguard-path-telemetry-rtt-microseconds sample)))
        (is (= 20 (cl-wireguard-overlay::wireguard-path-telemetry-tcp-samples sample)))
        (is (= 2 (cl-wireguard-overlay::wireguard-path-telemetry-retransmits sample)))
        (is (= 18 (cl-wireguard-overlay::wireguard-path-telemetry-congestion-window sample)))
        (is (= 2 (cl-wireguard-overlay::wireguard-path-telemetry-active-flows sample)))
        (is (= 4000 (cl-wireguard-overlay::wireguard-path-telemetry-bytes sample)))
        (is (= 2000 (cl-wireguard-overlay::wireguard-path-telemetry-interval-milliseconds sample)))))))

(test sparse-ebpf-counters-aggregate-all-cidrs-for-the-next-hop
  (let* ((first (wireguard-route-fixture :key-byte 1))
         (second (wireguard-route-fixture :key-byte 2))
         (hop (wireguard-next-hop-fixture :key-byte 9))
         (network (gr8s.foundation::json-object "routes" (vector first second)))
         (previous (make-hash-table :test #'equal)))
    (setf (gethash "nodeID" first) "destination-a"
          (gethash "podCIDR" first) "10.88.1.0/24"
          (gethash "nextHop" first) hop
          (gethash "nodeID" second) "destination-b"
          (gethash "podCIDR" second) "10.88.2.0/24"
          (gethash "nextHop" second) hop)
    (let* ((samples
             (gr8s.network::wireguard-path-telemetry-samples
              network
              (list
               (cons "10.88.1.2"
                     (gr8s.network::make-wireguard-path-telemetry-counters
                      :bytes 100 :samples 2 :rtt-sum-microseconds 2000
                      :retransmits 1 :congestion-window 20))
               (cons "10.88.2.2"
                     (gr8s.network::make-wireguard-path-telemetry-counters
                      :bytes 300 :samples 3 :rtt-sum-microseconds 6000
                      :retransmits 2 :congestion-window 10)))
              '("10.88.1.2" "10.88.2.2") previous 1000))
           (sample (gethash "gateway-a" samples)))
      (is (= 1 (hash-table-count samples)))
      (is (= 400 (cl-wireguard-overlay::wireguard-path-telemetry-bytes sample)))
      (is (= 5 (cl-wireguard-overlay::wireguard-path-telemetry-tcp-samples sample)))
      (is (= 1600 (cl-wireguard-overlay::wireguard-path-telemetry-rtt-microseconds sample)))
      (is (= 3 (cl-wireguard-overlay::wireguard-path-telemetry-retransmits sample)))
      (is (= 10 (cl-wireguard-overlay::wireguard-path-telemetry-congestion-window sample)))
      (is (= 2 (cl-wireguard-overlay::wireguard-path-telemetry-active-flows sample))))))

(test wireguard-path-telemetry-dataplane-attaches-and-releases-every-resource
  (let* ((map-a (whistler/loader::make-map-info :name "gr8s_path_tcp_v4" :fd 11))
         (map-b (whistler/loader::make-map-info :name "gr8s_path_flows_v4" :fd 12))
         (prog-a (whistler/loader::make-prog-info
                  :name "sample" :section-name "tracepoint/tcp/tcp_probe" :fd 21))
         (prog-b (whistler/loader::make-prog-info
                  :name "retransmit"
                  :section-name "tracepoint/tcp/tcp_retransmit_skb" :fd 22))
         (attached nil)
         (detached nil)
         (closed nil)
         (dataplane
           (gr8s.network::start-wireguard-path-telemetry-dataplane
            :compile (lambda () (values '(:maps) '(:programs)))
            :create-maps (lambda (specs)
                           (is (equal '(:maps) specs))
                           (list (cons "gr8s_path_tcp_v4" map-a)
                                 (cons "gr8s_path_flows_v4" map-b)))
            :load-programs (lambda (specs maps)
                             (is (equal '(:programs) specs))
                             (is (= 2 (length maps)))
                             (list (cons "sample" prog-a)
                                   (cons "retransmit" prog-b)))
            :attach (lambda (fd section)
                      (push (list fd section) attached)
                      (list :attachment fd)))))
    (is (equal '((21 "tracepoint/tcp/tcp_probe")
                 (22 "tracepoint/tcp/tcp_retransmit_skb"))
               (nreverse attached)))
    (gr8s.network::stop-wireguard-path-telemetry-dataplane
     dataplane
     :detach (lambda (attachment) (push attachment detached))
     :close (lambda (fd) (push fd closed)))
    (is (= 2 (length detached)))
    (is (equal '(11 12 21 22) (sort closed #'<)))))

(test wireguard-path-telemetry-map-abi-preserves-ip-and-counter-byte-order
  (let ((key #(10 88 9 2))
        (value (make-array 48 :element-type '(unsigned-byte 8) :initial-element 0))
        (flow (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace value (gr8s.network::service-lb-bytes 5000 8) :start1 0)
    (replace value (gr8s.network::service-lb-bytes 20 8) :start1 8)
    (replace value (gr8s.network::service-lb-bytes 45000 8) :start1 16)
    (replace value (gr8s.network::service-lb-bytes 3 8) :start1 24)
    (replace value (gr8s.network::service-lb-bytes 18 4) :start1 32)
    (replace flow key :start1 0)
    (replace flow (gr8s.network::service-lb-bytes 99000000000 8) :start1 8)
    (let* ((entry (gr8s.network::decode-wireguard-path-telemetry-entry key value))
           (counters (cdr entry)))
      (is (equal "10.88.9.2" (car entry)))
      (is (= 5000 (gr8s.network::wireguard-path-telemetry-counters-bytes counters)))
      (is (= 20 (gr8s.network::wireguard-path-telemetry-counters-samples counters)))
      (is (= 45000
             (gr8s.network::wireguard-path-telemetry-counters-rtt-sum-microseconds counters)))
      (is (= 3 (gr8s.network::wireguard-path-telemetry-counters-retransmits counters)))
      (is (= 18 (gr8s.network::wireguard-path-telemetry-counters-congestion-window counters))))
    (is (equal "10.88.9.2"
               (gr8s.network::decode-wireguard-path-flow-entry
                flow 100000000000 :maximum-age-nanoseconds 2000000000)))
    (is-false
     (gr8s.network::decode-wireguard-path-flow-entry
      flow 102000000001 :maximum-age-nanoseconds 2000000000))))

(test passive-telemetry-is-applied-only-to-the-selected-endpoint
  (let* ((selected (cl-wireguard-overlay::make-wireguard-path-observation
                    :name "lan" :address "10.0.0.9" :port 51820))
         (standby (cl-wireguard-overlay::make-wireguard-path-observation
                   :name "underlay" :address "192.0.2.9" :port 51820))
         (peer (cl-wireguard-overlay::make-wireguard-peer-path-state
                :peer-id "peer-a" :selected '("lan" "10.0.0.9" 51820)
                :previous '("underlay" "192.0.2.9" 51820)
                :observations (list selected standby)))
         (state (cl-wireguard-overlay::make-wireguard-path-state))
         (samples (make-hash-table :test #'equal)))
    (setf (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state)) peer
          (gethash "peer-a" samples)
          (cl-wireguard-overlay::make-wireguard-path-telemetry
           :rtt-microseconds 2200 :tcp-samples 10 :retransmits 1
           :congestion-window 20 :active-flows 2 :bytes 4000
           :interval-milliseconds 1000))
    (gr8s.network::apply-wireguard-path-telemetry-samples state samples)
    (is (= 2200
           (cl-wireguard-overlay::wireguard-path-observation-passive-rtt-microseconds selected)))
    (is-false
     (cl-wireguard-overlay::wireguard-path-observation-passive-rtt-microseconds standby))))

(test wireguard-path-telemetry-poll-reads-bounded-maps-and-keeps-deltas
  (let* ((stats-map :stats)
         (flows-map :flows)
         (dataplane
           (gr8s.network::%make-wireguard-path-telemetry-dataplane
            :maps (list (cons "gr8s_path_tcp_v4" stats-map)
                        (cons "gr8s_path_flows_v4" flows-map))))
         (network
           (gr8s.foundation::json-object
            "routes" (vector (wireguard-route-fixture))))
         (stats-key #(10 88 9 2))
         (flow-key (gr8s.network::service-lb-bytes 42 8))
         (stats-value (make-array 48 :element-type '(unsigned-byte 8)
                                  :initial-element 0))
         (flow-value (make-array 16 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
    (replace stats-value (gr8s.network::service-lb-bytes 9000 8) :start1 0)
    (replace stats-value (gr8s.network::service-lb-bytes 3 8) :start1 8)
    (replace stats-value (gr8s.network::service-lb-bytes 6000 8) :start1 16)
    (replace flow-value stats-key :start1 0)
    (replace flow-value (gr8s.network::service-lb-bytes 99000000000 8) :start1 8)
    (flet ((keys (map) (if (eq map stats-map) (list stats-key) (list flow-key)))
           (lookup (map key)
             (declare (ignore key))
             (if (eq map stats-map) stats-value flow-value)))
      (let ((first (gr8s.network::poll-wireguard-path-telemetry
                    dataplane network :keys #'keys :lookup #'lookup
                    :now-milliseconds 1000 :now-nanoseconds 100000000000)))
        (is (= 3 (cl-wireguard-overlay::wireguard-path-telemetry-tcp-samples
                  (gethash "peer-a" first))))
        (is (= 1 (cl-wireguard-overlay::wireguard-path-telemetry-active-flows
                  (gethash "peer-a" first)))))
      (let ((second (gr8s.network::poll-wireguard-path-telemetry
                     dataplane network :keys #'keys :lookup #'lookup
                     :now-milliseconds 2000 :now-nanoseconds 100000000000)))
        (is (= 0 (cl-wireguard-overlay::wireguard-path-telemetry-tcp-samples
                  (gethash "peer-a" second))))
        (is (= 0 (cl-wireguard-overlay::wireguard-path-telemetry-bytes
                  (gethash "peer-a" second))))))))

(test wireguard-path-reconcile-trials-without-committing-unproven-candidates
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 41))
         (route (wireguard-route-fixture :key-byte 41))
         (private (gr8s.foundation::json-object "name" "lan" "address" "10.0.0.9" "port" 51820))
         (network (gr8s.foundation::json-object "routes" (vector route)))
         (state (cl-wireguard-overlay::make-wireguard-path-state))
         (sets nil))
    (setf (gethash "wireguardEndpoints" route) (vector private))
    (gr8s.network::reconcile-wireguard-path-state
     state network
     :now 1000
     :status-reader
     (lambda ()
       (list (gr8s.network::make-wireguard-peer-status
              :public-key key :endpoint-address "192.0.2.9" :endpoint-port 51820
              :latest-handshake-seconds 990 :received-bytes 100 :transmitted-bytes 200)))
     :trial-function
     (lambda (peer-key current candidate &rest arguments)
       (declare (ignore peer-key current arguments))
       (push candidate sets)
       (values t 12))
     :endpoint-setter
     (lambda (peer-key address port)
       (declare (ignore peer-key))
       (push (list "restore" address port) sets)))
    (let ((peer (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state))))
      (is (equal '("underlay" "192.0.2.9" 51820)
                 (cl-wireguard-overlay::wireguard-peer-path-state-selected peer)))
      (is (= 1 (cl-wireguard-overlay::wireguard-path-observation-consecutive-successes
                (find "lan" (cl-wireguard-overlay::wireguard-peer-path-state-observations peer)
                      :key #'cl-wireguard-overlay::wireguard-path-observation-name :test #'string=))))
      (is (member '("restore" "192.0.2.9" 51820) sets :test #'equal)))))

(test wireguard-path-reconcile-fails-over-from-an-unhealthy-current-path
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 43))
         (route (wireguard-route-fixture :key-byte 43))
         (private (gr8s.foundation::json-object "name" "lan" "address" "10.0.0.9" "port" 51820))
         (network (gr8s.foundation::json-object "routes" (vector route)))
         (state (cl-wireguard-overlay::make-wireguard-path-state)))
    (setf (gethash "wireguardEndpoints" route) (vector private))
    (gr8s.network::reconcile-wireguard-path-state
     state network :now 1000
     :status-reader
     (lambda ()
       (list (gr8s.network::make-wireguard-peer-status
              :public-key key :endpoint-address "192.0.2.9" :endpoint-port 51820
              :latest-handshake-seconds 700)))
     :trial-function (lambda (&rest ignored) (declare (ignore ignored)) (values t 8))
     :endpoint-setter (lambda (&rest ignored) (declare (ignore ignored))))
    (let ((peer (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state))))
      (is (equal '("lan" "10.0.0.9" 51820)
                 (cl-wireguard-overlay::wireguard-peer-path-state-selected peer)))
      (is (eq :current-unhealthy (cl-wireguard-overlay::wireguard-peer-path-state-reason peer)))
      (is (= 1 (length (cl-wireguard-overlay::wireguard-path-state-history state)))))))

(test active-round-trip-failure-prefers-the-durable-previous-path
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 44))
         (route (wireguard-route-fixture :key-byte 44))
         (alternate (gr8s.foundation::json-object "name" "lan" "address" "10.0.0.9" "port" 51820))
         (network (gr8s.foundation::json-object "routes" (vector route)))
         (state (cl-wireguard-overlay::make-wireguard-path-state))
         (peer (cl-wireguard-overlay::make-wireguard-peer-path-state
                :peer-id "peer-a" :selected '("lan" "10.0.0.9" 51820)
                :previous '("underlay" "192.0.2.9" 51820)))
         (current (cl-wireguard-overlay::make-wireguard-path-observation
                   :name "lan" :address "10.0.0.9" :port 51820
                   :consecutive-successes 5 :consecutive-failures 2))
         (trialled nil)
         (sets nil))
    (setf (gethash "wireguardEndpoints" route) (vector alternate)
          (cl-wireguard-overlay::wireguard-peer-path-state-observations peer) (list current)
          (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state)) peer)
    (gr8s.network::reconcile-wireguard-path-state
     state network :now 1000
     :status-reader
     (lambda ()
       (list (gr8s.network::make-wireguard-peer-status
              :public-key key :endpoint-address "192.0.2.9" :endpoint-port 51820
              :latest-handshake-seconds 999 :received-bytes 20)))
     :probe-function (constantly nil)
     :health-function (lambda (&rest ignored) (declare (ignore ignored)) nil)
     :trial-function
     (lambda (peer-key selected candidate &rest arguments)
       (declare (ignore peer-key selected arguments))
       (setf trialled candidate)
       (values t 4))
     :endpoint-setter (lambda (peer-key address port)
                        (declare (ignore peer-key))
                        (push (list address port) sets)))
    (is (equal '("underlay" "192.0.2.9" 51820) trialled))
    (is (equal trialled (cl-wireguard-overlay::wireguard-peer-path-state-selected peer)))
    (is-false sets)
    (is (eq :current-unhealthy (cl-wireguard-overlay::wireguard-peer-path-state-reason peer)))))

(test an-early-wireguard-roam-cannot-replace-the-authenticated-initial-lkg
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 45))
         (route (wireguard-route-fixture :key-byte 45))
         (alternate (gr8s.foundation::json-object "name" "lan" "address" "10.0.0.9" "port" 51820))
         (network (gr8s.foundation::json-object "routes" (vector route)))
         (state (cl-wireguard-overlay::make-wireguard-path-state))
         (sets nil))
    (setf (gethash "wireguardEndpoints" route) (vector alternate))
    (gr8s.network::reconcile-wireguard-path-state
     state network :now 1000
     :status-reader
     (lambda ()
       (list (gr8s.network::make-wireguard-peer-status
              :public-key key :endpoint-address "10.0.0.9" :endpoint-port 51820
              :latest-handshake-seconds 999)))
     :trial-function (lambda (&rest ignored)
                       (declare (ignore ignored))
                       (values nil :handshake-timeout))
     :endpoint-setter
     (lambda (peer-key address port)
       (declare (ignore peer-key))
       (push (list address port) sets)))
    (let ((peer (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state))))
      (is (equal '("underlay" "192.0.2.9" 51820)
                 (cl-wireguard-overlay::wireguard-peer-path-state-selected peer)))
      (is (equal '("underlay" "192.0.2.9" 51820)
                 (cl-wireguard-overlay::wireguard-peer-path-state-previous peer)))
      ;; The authenticated roam may remain live for transactional verification,
      ;; but it does not become either durable choice merely by arriving first.
      (is-false sets))))

(test fresh-current-handshake-clears-a-startup-failure-streak
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 47))
         (network (gr8s.foundation::json-object "routes" (vector (wireguard-route-fixture :key-byte 47))))
         (state (cl-wireguard-overlay::make-wireguard-path-state))
         (peer (cl-wireguard-overlay::make-wireguard-peer-path-state
                :peer-id "peer-a" :selected '("underlay" "192.0.2.9" 51820)
                :previous '("underlay" "192.0.2.9" 51820)))
         (observation (cl-wireguard-overlay::make-wireguard-path-observation
                       :name "underlay" :address "192.0.2.9" :port 51820
                       :consecutive-failures 2)))
    (setf (cl-wireguard-overlay::wireguard-peer-path-state-observations peer) (list observation)
          (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state)) peer)
    (gr8s.network::reconcile-wireguard-path-state
     state network :now 1000
     :status-reader (lambda ()
                      (list (gr8s.network::make-wireguard-peer-status
                             :public-key key :endpoint-address "192.0.2.9"
                             :endpoint-port 51820 :latest-handshake-seconds 999))))
    (is (= 0 (cl-wireguard-overlay::wireguard-path-observation-consecutive-failures observation)))
    (is (= 1 (cl-wireguard-overlay::wireguard-path-observation-consecutive-successes observation)))))

(test wireguard-path-explanation-names-the-choice-and-ranks-evidence
  (let* ((state (cl-wireguard-overlay::make-wireguard-path-state))
         (peer (gr8s.network::record-wireguard-path-decision
                state "peer-a" '("lan" "10.0.0.9" 51820)
                '("underlay" "192.0.2.9" 51820) :sustained-improvement 1000)))
    (setf (cl-wireguard-overlay::wireguard-peer-path-state-observations peer)
          (list (cl-wireguard-overlay::make-wireguard-path-observation
                 :name "lan" :address "10.0.0.9" :port 51820
                 :handshake-age-seconds 2 :trial-latency-milliseconds 7
                 :consecutive-successes 3)))
    (let* ((object (gr8s.network::wireguard-path-explanation-object state "peer-a"))
           (candidate (aref (gethash "candidates" object) 0)))
      (is (equal "lan" (gethash "name" (gethash "selected" object))))
      (is (equal "sustained-improvement" (gethash "reason" object)))
      (is-true (gethash "healthy" candidate))
      (is (plusp (gethash "score" candidate))))
    (signals error (gr8s.network::wireguard-path-explanation-object state "missing"))))

(test wireguard-get-device-request-is-a-netlink-dump
  (let ((message
          (gr8s.network::generic-netlink-request-message
           41 0 1
           (cl-rtnetlink::netlink-attribute 2 (cl-rtnetlink::netlink-string "gr8s-wg"))
           :flags #x300)))
    (is (= #x305 (cl-rtnetlink::netlink-read-integer message 6 2)))))

(test wireguard-network-intent-requires-complete-authenticated-peer-data
  (let ((network (node-network-with-routes-for-test nil)))
    (setf (gethash "overlayBackend" network) "wireguard"
          (gethash "wireguardListenPort" network) 51820
          (gethash "routes" network) (vector (wireguard-route-fixture)))
    (is (eq network (gr8s.agent::validate-node-network-object network)))
    (remhash "wireguardPublicKey" (aref (gethash "routes" network) 0))
    (signals gr8s.network::cni-error (gr8s.agent::validate-node-network-object network))))

(test wireguard-peer-status-parses-kernel-handshake-and-counters
  (let* ((key (ironclad:hex-string-to-byte-array
               "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
         (peer (cl-rtnetlink::netlink-octets
                (cl-rtnetlink::netlink-attribute 1 key)
                (cl-rtnetlink::netlink-attribute
                 4 (gr8s.network::wireguard-endpoint "192.0.2.9" 51820))
                (cl-rtnetlink::netlink-attribute
                 6 (cl-rtnetlink::netlink-octets (cl-rtnetlink::netlink-integer 1700000000 8)
                                          (cl-rtnetlink::netlink-integer 123456789 8)))
                (cl-rtnetlink::netlink-attribute 7 (cl-rtnetlink::netlink-integer 4294967301 8))
                (cl-rtnetlink::netlink-attribute 8 (cl-rtnetlink::netlink-integer 8589934601 8))))
         (message (cl-rtnetlink::netlink-octets
                   (make-array 20 :element-type '(unsigned-byte 8) :initial-element 0)
                   (cl-rtnetlink::netlink-attribute #x8008
                                            (cl-rtnetlink::netlink-attribute #x8000 peer))))
         (status (first (gr8s.network::wireguard-peer-statuses-from-messages (list message)))))
    (is (equalp key (gr8s.network::wireguard-peer-status-public-key status)))
    (is (string= "192.0.2.9"
                 (gr8s.network::wireguard-peer-status-endpoint-address status)))
    (is (= 51820 (gr8s.network::wireguard-peer-status-endpoint-port status)))
    (is (= 1700000000 (gr8s.network::wireguard-peer-status-latest-handshake-seconds status)))
    (is (= 123456789 (gr8s.network::wireguard-peer-status-latest-handshake-nanoseconds status)))
    (is (= 4294967301 (gr8s.network::wireguard-peer-status-received-bytes status)))
    (is (= 8589934601 (gr8s.network::wireguard-peer-status-transmitted-bytes status)))))

(test wireguard-unchanged-live-peers-do-not-require-destructive-replacement
  (let* ((route (wireguard-route-fixture))
         (network (node-network-with-routes-for-test nil))
         (status (gr8s.network::make-wireguard-peer-status
                  :public-key (gr8s.network::wireguard-decode-key
                               (gethash "wireguardPublicKey" route) "test key"))))
    (setf (gethash "overlayBackend" network) "wireguard"
          (gethash "wireguardListenPort" network) 51820
          (gethash "routes" network) (vector route))
    (is-true (gr8s.network::wireguard-live-peer-keys-match-p
              network :status-reader (lambda () (list status))))
    (setf (gethash "wireguardPublicKey" route)
          (ag-grpc:base64-encode
           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8)))
    (is-false (gr8s.network::wireguard-live-peer-keys-match-p
               network :status-reader (lambda () (list status))))))

(test wireguard-topology-identity-detects-config-changes-with-the-same-peer-key
  (let* ((before (node-network-with-routes-for-test nil))
         (after (node-network-with-routes-for-test nil))
         (route-before (wireguard-route-fixture))
         (route-after (wireguard-route-fixture)))
    (setf (gethash "overlayBackend" before) "wireguard"
          (gethash "overlayBackend" after) "wireguard"
          (gethash "wireguardListenPort" before) 51820
          (gethash "wireguardListenPort" after) 51820
          (gethash "routes" before) (vector route-before)
          (gethash "routes" after) (vector route-after))
    (is (equal (gr8s.network::wireguard-topology-identity before)
               (gr8s.network::wireguard-topology-identity after)))
    (setf (gethash "underlayAddress" route-after) "192.0.2.10")
    (is-false (equal (gr8s.network::wireguard-topology-identity before)
                     (gr8s.network::wireguard-topology-identity after)))))

(test wireguard-prometheus-metrics-identify-authenticated-peer-and-key-age
  (let* ((route (wireguard-route-fixture))
         (network (node-network-with-routes-for-test nil))
         (status (gr8s.network::make-wireguard-peer-status
                  :public-key (gr8s.network::wireguard-decode-key
                               (gethash "wireguardPublicKey" route) "test key")
                  :latest-handshake-seconds 1700000000
                  :latest-handshake-nanoseconds 0
                  :received-bytes 41 :transmitted-bytes 43)))
    (setf (gethash "overlayBackend" network) "wireguard"
          (gethash "wireguardListenPort" network) 51820
          (gethash "routes" network) (vector route))
    (let ((text (gr8s.kubelet::wireguard-metrics-text
                 network "worker-a" :status-reader (lambda () (list status))
                 :key-age-reader (constantly 17))))
      (is (search "gr8s_wireguard_peer_latest_handshake_seconds{node=\"worker-a\",peer=\"peer-a\"} 1.7e+09" text))
      (is (search "gr8s_wireguard_peer_received_bytes_total{node=\"worker-a\",peer=\"peer-a\"} 41" text))
      (is (search "gr8s_wireguard_peer_transmitted_bytes_total{node=\"worker-a\",peer=\"peer-a\"} 43" text))
      (is (search "gr8s_wireguard_private_key_age_seconds{node=\"worker-a\"} 17" text))
      (is (search "gr8s_wireguard_telemetry_available{node=\"worker-a\"} 1" text)))))

(test wireguard-path-metrics-expose-selection-health-score-and-failures
  (let* ((state (cl-wireguard-overlay::make-wireguard-path-state))
         (peer (gr8s.network::record-wireguard-path-decision
                state "peer-a" '("lan" "10.0.0.9" 51820)
                '("underlay" "192.0.2.9" 51820) :current-unhealthy 1000)))
    (setf (cl-wireguard-overlay::wireguard-peer-path-state-observations peer)
          (list (cl-wireguard-overlay::make-wireguard-path-observation
                 :name "lan" :address "10.0.0.9" :port 51820
                 :handshake-age-seconds 1 :trial-latency-milliseconds 5
                 :passive-rtt-microseconds 1700 :passive-tcp-samples 12
                 :passive-retransmits 2 :passive-congestion-window 31
                 :passive-active-flows 4 :passive-bytes-per-second 9000)))
    (let ((text (gr8s.kubelet::wireguard-path-metrics-text state "worker-a")))
      (is (search "gr8s_wireguard_path_selected{node=\"worker-a\",peer=\"peer-a\",endpoint=\"lan\"} 1" text))
      (is (search "gr8s_wireguard_path_healthy{node=\"worker-a\",peer=\"peer-a\",endpoint=\"lan\"} 1" text))
      (is (search "gr8s_wireguard_path_score{" text))
      (is (search "gr8s_wireguard_path_consecutive_failures{" text))
      (is (search "gr8s_wireguard_path_passive_rtt_microseconds{" text))
      (is (search "gr8s_wireguard_path_passive_retransmits{" text))
      (is (search "gr8s_wireguard_path_passive_congestion_window{" text))
      (is (search "gr8s_wireguard_path_passive_active_flows{" text))
      (is (search "gr8s_wireguard_path_passive_bytes_per_second{" text))
      (is (search "gr8s_wireguard_path_safe_mtu_bytes{" text)))))

(test wireguard-path-selection-fails-over-fast-and-optimizes-slowly
  (labels ((observation (name age latency successes &key (bytes 0) (failures 0))
             (cl-wireguard-overlay::make-wireguard-path-observation
              :name name :address "192.0.2.1" :port 51820
              :handshake-age-seconds age :trial-latency-milliseconds latency
              :transferred-bytes-delta bytes
              :consecutive-successes successes
              :consecutive-failures failures)))
    (let* ((stale (observation "public" 181 80 20 :bytes 1000))
           (private (observation "private" 2 10 1 :bytes 1000)))
      (multiple-value-bind (selected reason)
          (cl-wireguard-overlay::select-wireguard-path stale (list stale private))
        (is (eq private selected))
        (is (eq :current-unhealthy reason))))
    (let* ((current (observation "public" 2 80 20 :bytes 1000))
           (unproven (observation "private" 2 10 2 :bytes 1000))
           (proven (observation "private" 2 10 3 :bytes 1000)))
      (multiple-value-bind (selected reason)
          (cl-wireguard-overlay::select-wireguard-path current (list current unproven))
        (is (eq current selected))
        (is (eq :candidate-unproven reason)))
      (multiple-value-bind (selected reason)
          (cl-wireguard-overlay::select-wireguard-path current (list current proven))
        (is (eq proven selected))
        (is (eq :sustained-improvement reason)))))
  (let* ((current (cl-wireguard-overlay::make-wireguard-path-observation
                   :name "public" :address "192.0.2.1" :port 51820
                   :handshake-age-seconds 2 :trial-latency-milliseconds 10
                   :consecutive-successes 20))
         (worse (cl-wireguard-overlay::make-wireguard-path-observation
                 :name "private" :address "10.0.0.1" :port 51820
                 :handshake-age-seconds 2 :trial-latency-milliseconds 30
                 :consecutive-successes 20)))
    (multiple-value-bind (selected reason)
        (cl-wireguard-overlay::select-wireguard-path current (list current worse))
      (is (eq current selected))
      (is (eq :current-preferred reason)))))

(test healthy-direct-paths-outrank-relay-fallbacks
  (labels ((observation (name age latency failures)
             (cl-wireguard-overlay::make-wireguard-path-observation
              :name name :address "192.0.2.1" :port 51820
              :handshake-age-seconds age :trial-latency-milliseconds latency
              :consecutive-successes 10 :consecutive-failures failures)))
    (let ((direct (observation "public" 2 5000 0))
          (relay (observation "relay" 1 1 0)))
      (multiple-value-bind (selected reason)
          (cl-wireguard-overlay::select-wireguard-path direct (list relay direct))
        (is (eq direct selected))
        (is (eq :current-preferred reason)))
      (setf (cl-wireguard-overlay::wireguard-path-observation-consecutive-failures direct) 2)
      (multiple-value-bind (selected reason)
          (cl-wireguard-overlay::select-wireguard-path direct (list relay direct))
        (is (eq relay selected))
        (is (eq :current-unhealthy reason))))))

(test wireguard-path-mtu-discovery-finds-black-holes-with-bounded-probes
  (let ((probes nil))
    (multiple-value-bind (mtu reason)
        (cl-wireguard-overlay::discover-wireguard-path-mtu
         (lambda (size) (push size probes) (<= size 1280))
         :minimum 576 :maximum 1420)
      (is (= 1280 mtu))
      (is (eq :packet-size-black-hole reason))
      (is (<= (length probes) 12))))
  (multiple-value-bind (mtu reason)
      (cl-wireguard-overlay::discover-wireguard-path-mtu (constantly nil)
                                         :minimum 576 :maximum 1420)
    (is (null mtu))
    (is (eq :path-unreachable reason))))

(test wireguard-path-mtu-downgrades-immediately-and-upgrades-slowly
  (let ((observation (cl-wireguard-overlay::make-wireguard-path-observation
                      :name "public" :address "192.0.2.1" :port 51820
                      :safe-mtu 1420)))
    (is (= 1280 (cl-wireguard-overlay::update-wireguard-path-mtu
                 observation 1280 :reason :packet-size-black-hole :now 100)))
    (is (eq :packet-size-black-hole
            (cl-wireguard-overlay::wireguard-path-observation-mtu-reason observation)))
    (is (= 100 (cl-wireguard-overlay::wireguard-path-observation-mtu-changed-at observation)))
    (dotimes (attempt 2)
      (declare (ignore attempt))
      (is (= 1280 (cl-wireguard-overlay::update-wireguard-path-mtu
                   observation 1400 :reason :maximum-verified :now 200))))
    (is (= 1400 (cl-wireguard-overlay::update-wireguard-path-mtu
                 observation 1400 :reason :maximum-verified :now 202)))
    (is (eq :maximum-verified
            (cl-wireguard-overlay::wireguard-path-observation-mtu-reason observation)))
    (is (= 202 (cl-wireguard-overlay::wireguard-path-observation-mtu-changed-at observation)))
    (is (= 1200 (cl-wireguard-overlay::update-wireguard-path-mtu
                 observation 1200 :reason :packet-size-black-hole :now 203)))))

(test cached-wireguard-repair-does-not-reset-an-existing-tuned-mtu
  (let ((original-index (symbol-function 'gr8s.network::native-interface-index))
        (original-owned (symbol-function 'gr8s.network::node-wireguard-owned-p))
        (original-mtu (symbol-function 'cl-rtnetlink::set-network-link-mtu))
        (original-address (symbol-function 'cl-rtnetlink::add-network-address))
        (original-up (symbol-function 'cl-rtnetlink::set-network-link-up))
        (original-forwarding (symbol-function 'gr8s.network::enable-node-ipv4-forwarding))
        (mtus nil)
        (forwarding 0))
    (unwind-protect
         (progn
           (setf (symbol-function 'gr8s.network::native-interface-index) (constantly 7)
                 (symbol-function 'gr8s.network::node-wireguard-owned-p) (constantly t)
                 (symbol-function 'cl-rtnetlink::set-network-link-mtu)
                 (lambda (name mtu) (push (list name mtu) mtus))
                 (symbol-function 'cl-rtnetlink::add-network-address)
                 (lambda (&rest arguments) (declare (ignore arguments)))
                 (symbol-function 'cl-rtnetlink::set-network-link-up)
                 (lambda (&rest arguments) (declare (ignore arguments)))
                 (symbol-function 'gr8s.network::enable-node-ipv4-forwarding)
                 (lambda () (incf forwarding)))
           (gr8s.network::ensure-node-wireguard
            (gr8s.foundation::json-object "mtu" 1420 "nodePodCIDR" "10.88.1.0/24"))
           (is-false mtus)
           (is (= 1 forwarding)))
      (setf (symbol-function 'gr8s.network::native-interface-index) original-index
            (symbol-function 'gr8s.network::node-wireguard-owned-p) original-owned
            (symbol-function 'cl-rtnetlink::set-network-link-mtu) original-mtu
            (symbol-function 'cl-rtnetlink::add-network-address) original-address
            (symbol-function 'cl-rtnetlink::set-network-link-up) original-up
            (symbol-function 'gr8s.network::enable-node-ipv4-forwarding)
            original-forwarding))))

(test wireguard-path-inventory-prunes-withdrawn-peers-and-endpoints
  (let* ((state (cl-wireguard-overlay::make-wireguard-path-state))
         (route (wireguard-route-fixture))
         (network (gr8s.foundation::json-object "routes" (vector route)))
         (peer (cl-wireguard-overlay::make-wireguard-peer-path-state
                :peer-id "peer-a" :selected '("relay" "198.51.100.9" 52000)
                :previous '("relay" "198.51.100.9" 52000)
                :observations
                (list (cl-wireguard-overlay::make-wireguard-path-observation
                       :name "underlay" :address "192.0.2.9" :port 51820)
                      (cl-wireguard-overlay::make-wireguard-path-observation
                       :name "relay" :address "198.51.100.9" :port 52000
                       :safe-mtu 1180))))
         (departed (cl-wireguard-overlay::make-wireguard-peer-path-state
                    :peer-id "departed" :selected '("underlay" "192.0.2.8" 51820))))
    (setf (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state)) peer
          (gethash "departed" (cl-wireguard-overlay::wireguard-path-state-peers state)) departed)
    (gr8s.network::reconcile-wireguard-path-inventory state network 500)
    (is-false (gethash "departed" (cl-wireguard-overlay::wireguard-path-state-peers state)))
    (is (equal '("underlay" "192.0.2.9" 51820)
               (cl-wireguard-overlay::wireguard-peer-path-state-selected peer)))
    (is (= 1 (length (cl-wireguard-overlay::wireguard-peer-path-state-observations peer))))
    (is (eq :endpoint-withdrawn (cl-wireguard-overlay::wireguard-peer-path-state-reason peer)))))

(test persisted-wireguard-mtu-evidence-rejects-poisoned-fields
  (flet ((observation (&rest pairs)
           (apply #'gr8s.foundation::json-object
                  "name" "underlay" "address" "192.0.2.9" "port" 51820 pairs)))
    (signals error
      (gr8s.network::wireguard-path-observation-from-object
       (observation "safeMTU" "1280")))
    (signals error
      (gr8s.network::wireguard-path-observation-from-object
       (observation "safeMTU" 120 "lastMTUProbeAt" 10)))
    (signals error
      (gr8s.network::wireguard-path-observation-from-object
       (observation "safeMTU" 1280 "mtuReason" "invent-a-symbol")))
    (signals error
      (gr8s.network::wireguard-path-observation-from-object
       (observation "safeMTU" 1280 "mtuUpgradeSuccesses" -1)))))

(test wireguard-mtu-probes-use-df-and-selected-paths-drive-device-minimum
  (let ((argv nil)
        (route (wireguard-route-fixture)))
    (is-true
     (gr8s.network::probe-wireguard-route-mtu
      route 1280 :runner (lambda (command) (setf argv command) t)))
    (is (equal '("ping" "-4" "-n" "-q" "-c" "1" "-W" "1"
                 "-M" "do" "-I" "gr8s-wg" "-s" "1252" "10.88.9.0")
               argv)))
  (let* ((state (cl-wireguard-overlay::make-wireguard-path-state))
         (route-a (wireguard-route-fixture))
         (route-b (wireguard-route-fixture :key-byte 8))
         (network (gr8s.foundation::json-object "mtu" 1420
                                    "routes" (vector route-a route-b)))
         (peer-a (cl-wireguard-overlay::make-wireguard-peer-path-state
                  :peer-id "peer-a" :selected '("underlay" "192.0.2.9" 51820)))
         (peer-b (cl-wireguard-overlay::make-wireguard-peer-path-state
                  :peer-id "peer-b" :selected '("underlay" "192.0.2.9" 51820))))
    (setf (gethash "nodeName" route-b) "peer-b"
          (gethash "nodeID" route-b) "peer-b"
          (cl-wireguard-overlay::wireguard-peer-path-state-observations peer-a)
          (list (cl-wireguard-overlay::make-wireguard-path-observation
                 :name "underlay" :address "192.0.2.9" :port 51820)
                (cl-wireguard-overlay::make-wireguard-path-observation
                 :name "relay" :address "198.51.100.9" :port 52000))
          (cl-wireguard-overlay::wireguard-peer-path-state-observations peer-b)
          (list (cl-wireguard-overlay::make-wireguard-path-observation
                 :name "underlay" :address "192.0.2.9" :port 51820))
          (gethash "peer-a" (cl-wireguard-overlay::wireguard-path-state-peers state)) peer-a
          (gethash "peer-b" (cl-wireguard-overlay::wireguard-path-state-peers state)) peer-b)
    (is (= 1280
           (gr8s.network::reconcile-wireguard-path-mtus
            state network :now 300
            :probe-function
            (lambda (route size)
              (<= size (if (string= "peer-a" (gethash "nodeName" route))
                           1280 1180))))))
    (is (= 1180
           (gr8s.network::reconcile-wireguard-path-mtus
            state network :now 301
            :probe-function
            (lambda (route size)
              (<= size (if (string= "peer-a" (gethash "nodeName" route))
                           1280 1180))))))
    ;; Probe cadence belongs to the endpoint observation. Selecting a path that
    ;; has never been measured must probe it immediately, even if the old path
    ;; was measured seconds ago.
    (setf (cl-wireguard-overlay::wireguard-peer-path-state-selected peer-a)
          '("relay" "198.51.100.9" 52000))
    (let ((probes 0))
      (gr8s.network::reconcile-wireguard-path-mtus
       state network :now 302
       :probe-function (lambda (route size)
                         (declare (ignore route size))
                         (incf probes)
                         t))
      (is (plusp probes))
      (is (= 302
             (cl-wireguard-overlay::wireguard-path-observation-last-mtu-probe-at
              (second (cl-wireguard-overlay::wireguard-peer-path-state-observations peer-a))))))
    (let ((applied nil))
      (is (= 1180
             (gr8s.network::apply-wireguard-selected-safe-mtu
              state network
              :setter (lambda (name mtu) (setf applied (list name mtu))))))
      (is (equal '("gr8s-wg" 1180) applied)))))
