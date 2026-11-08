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

(test wireguard-network-intent-requires-complete-authenticated-peer-data
  (let ((network (node-network-with-routes-for-test nil)))
    (setf (gethash "overlayBackend" network) "wireguard"
          (gethash "wireguardListenPort" network) 51820
          (gethash "routes" network) (vector (wireguard-route-fixture)))
    (is (eq network (gr8s::validate-node-network-object network)))
    (remhash "wireguardPublicKey" (aref (gethash "routes" network) 0))
    (signals gr8s::cni-error (gr8s::validate-node-network-object network))))
