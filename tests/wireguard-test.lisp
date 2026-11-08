;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)
(in-suite gr8s)

(defun wireguard-route-fixture (&key (key-byte 7) (port 51820))
  (gr8s::json-object
   "nodeID" "peer-a" "podCIDR" "10.88.9.0/24"
   "underlayAddress" "192.0.2.9"
   "wireguardPublicKey"
   (ag-grpc:base64-encode
    (make-array 32 :element-type '(unsigned-byte 8) :initial-element key-byte))
   "wireguardListenPort" port))

(test wireguard-peer-uapi-carries-identity-endpoint-and-allowed-prefix
  (let* ((attributes
           (gr8s::netlink-attributes
            (gr8s::wireguard-peer-attributes (wireguard-route-fixture)) 0))
         (endpoint (gethash 4 attributes))
         (allowed-entry
           (gethash 0 (gr8s::netlink-attributes (gethash 9 attributes) 0)))
         (allowed (gr8s::netlink-attributes allowed-entry 0)))
    (is (equalp (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)
                (gethash 1 attributes)))
    (is (= 2 (gr8s::netlink-read-integer (gethash 3 attributes) 0 4)))
    (is (= 2 (gr8s::netlink-read-integer endpoint 0 2)))
    (is (equalp #(202 108) (subseq endpoint 2 4)))
    (is (equalp #(192 0 2 9) (subseq endpoint 4 8)))
    (is (= 2 (gr8s::netlink-read-integer (gethash 1 allowed) 0 2)))
    (is (equalp #(10 88 9 0) (gethash 2 allowed)))
    (is (= 24 (aref (gethash 3 allowed) 0)))))

(test wireguard-device-uapi-never-confuses-private-and-peer-keys
  (let* ((private-key
           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (network
           (gr8s::json-object
            "wireguardListenPort" 51820
            "routes" (vector (wireguard-route-fixture))))
         (attributes
           (gr8s::netlink-attributes
            (gr8s::wireguard-device-attributes "gr8s-wg" private-key network) 0)))
    (is (equalp (gr8s::netlink-string "gr8s-wg") (gethash 2 attributes)))
    (is (equalp private-key (gethash 3 attributes)))
    (is (= 1 (gr8s::netlink-read-integer (gethash 5 attributes) 0 4)))
    (is (= 51820 (gr8s::netlink-read-integer (gethash 6 attributes) 0 2)))
    (is-false (search (ag-grpc:base64-encode private-key)
                      (com.inuoe.jzon:stringify network)))))

(test wireguard-get-device-request-is-a-netlink-dump
  (let ((message
          (gr8s::generic-netlink-request-message
           41 0 1
           (gr8s::netlink-attribute 2 (gr8s::netlink-string "gr8s-wg"))
           :flags #x300)))
    (is (= #x305 (gr8s::netlink-read-integer message 6 2)))))

(test wireguard-network-intent-requires-complete-authenticated-peer-data
  (let ((network (node-network-with-routes-for-test nil)))
    (setf (gethash "overlayBackend" network) "wireguard"
          (gethash "wireguardListenPort" network) 51820
          (gethash "routes" network) (vector (wireguard-route-fixture)))
    (is (eq network (gr8s::validate-node-network-object network)))
    (remhash "wireguardPublicKey" (aref (gethash "routes" network) 0))
    (signals gr8s::cni-error (gr8s::validate-node-network-object network))))

(test wireguard-peer-status-parses-kernel-handshake-and-counters
  (let* ((key (ironclad:hex-string-to-byte-array
               "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
         (peer (gr8s::netlink-octets
                (gr8s::netlink-attribute 1 key)
                (gr8s::netlink-attribute
                 6 (gr8s::netlink-octets (gr8s::netlink-integer 1700000000 8)
                                          (gr8s::netlink-integer 123456789 8)))
                (gr8s::netlink-attribute 7 (gr8s::netlink-integer 4294967301 8))
                (gr8s::netlink-attribute 8 (gr8s::netlink-integer 8589934601 8))))
         (message (gr8s::netlink-octets
                   (make-array 20 :element-type '(unsigned-byte 8) :initial-element 0)
                   (gr8s::netlink-attribute #x8008
                                            (gr8s::netlink-attribute #x8000 peer))))
         (status (first (gr8s::wireguard-peer-statuses-from-messages (list message)))))
    (is (equalp key (gr8s::wireguard-peer-status-public-key status)))
    (is (= 1700000000 (gr8s::wireguard-peer-status-latest-handshake-seconds status)))
    (is (= 123456789 (gr8s::wireguard-peer-status-latest-handshake-nanoseconds status)))
    (is (= 4294967301 (gr8s::wireguard-peer-status-received-bytes status)))
    (is (= 8589934601 (gr8s::wireguard-peer-status-transmitted-bytes status)))))

(test wireguard-unchanged-live-peers-do-not-require-destructive-replacement
  (let* ((route (wireguard-route-fixture))
         (network (node-network-with-routes-for-test nil))
         (status (gr8s::make-wireguard-peer-status
                  :public-key (gr8s::wireguard-decode-key
                               (gethash "wireguardPublicKey" route) "test key"))))
    (setf (gethash "overlayBackend" network) "wireguard"
          (gethash "wireguardListenPort" network) 51820
          (gethash "routes" network) (vector route))
    (is-true (gr8s::wireguard-live-peer-keys-match-p
              network :status-reader (lambda () (list status))))
    (setf (gethash "wireguardPublicKey" route)
          (ag-grpc:base64-encode
           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8)))
    (is-false (gr8s::wireguard-live-peer-keys-match-p
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
    (is (equal (gr8s::wireguard-topology-identity before)
               (gr8s::wireguard-topology-identity after)))
    (setf (gethash "underlayAddress" route-after) "192.0.2.10")
    (is-false (equal (gr8s::wireguard-topology-identity before)
                     (gr8s::wireguard-topology-identity after)))))

(test wireguard-prometheus-metrics-identify-authenticated-peer-and-key-age
  (let* ((route (wireguard-route-fixture))
         (network (node-network-with-routes-for-test nil))
         (status (gr8s::make-wireguard-peer-status
                  :public-key (gr8s::wireguard-decode-key
                               (gethash "wireguardPublicKey" route) "test key")
                  :latest-handshake-seconds 1700000000
                  :latest-handshake-nanoseconds 0
                  :received-bytes 41 :transmitted-bytes 43)))
    (setf (gethash "overlayBackend" network) "wireguard"
          (gethash "wireguardListenPort" network) 51820
          (gethash "routes" network) (vector route))
    (let ((text (gr8s::wireguard-metrics-text
                 network "worker-a" :status-reader (lambda () (list status))
                 :key-age-reader (constantly 17))))
      (is (search "gr8s_wireguard_peer_latest_handshake_seconds{node=\"worker-a\",peer=\"peer-a\"} 1.7e+09" text))
      (is (search "gr8s_wireguard_peer_received_bytes_total{node=\"worker-a\",peer=\"peer-a\"} 41" text))
      (is (search "gr8s_wireguard_peer_transmitted_bytes_total{node=\"worker-a\",peer=\"peer-a\"} 43" text))
      (is (search "gr8s_wireguard_private_key_age_seconds{node=\"worker-a\"} 17" text))
      (is (search "gr8s_wireguard_telemetry_available{node=\"worker-a\"} 1" text)))))
