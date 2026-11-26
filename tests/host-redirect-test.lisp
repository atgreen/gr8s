;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Pod->host delivery (podster-9b1): the host_redirect_v4 key byte layout must
;;;; match what the egress-guard program spills as its scalar key, and the
;;;; reconcile converge must write the node's host-local set into every local Pod.

(in-package #:gr8s/tests)
(in-suite gr8s)

(test host-redirect-key-is-the-network-order-destination
  ;; The program's (load u32 ip 16) spills the dst as network-order bytes; the
  ;; agent must write the same 4 bytes.
  (is (equalp #(10 96 0 1) (gr8s.network::host-redirect-key "10.96.0.1")))
  (is (equalp #(192 168 1 20) (gr8s.network::host-redirect-key "192.168.1.20"))))

(test host-redirect-table-always-holds-the-api-server-and-adds-the-node-ip
  ;; The API server ClusterIP is always present; the node's own IP is added when
  ;; known. Each entry is a 4-byte key -> a 1-byte presence value.
  (let ((without (gr8s.network::node-host-redirect-table nil))
        (with (gr8s.network::node-host-redirect-table "192.168.1.20")))
    ;; The egress proxy address is always present too (podster-wv1w.2).
    (is (= 2 (length without)))
    (is (member #(10 96 0 1) (mapcar #'car without) :test #'equalp))
    (is (member #(169 254 1 2) (mapcar #'car without) :test #'equalp))
    (is (equalp #(1) (cdr (first without))))
    (is (= 3 (length with)))
    (is (member #(10 96 0 1) (mapcar #'car with) :test #'equalp))
    (is (member #(192 168 1 20) (mapcar #'car with) :test #'equalp))))

(test host-redirect-table-does-not-duplicate-a-node-ip-equal-to-the-api-server
  ;; Defensive: a node address that equals the API server VIP must not appear twice.
  (let ((table (gr8s.network::node-host-redirect-table "10.96.0.1")))
    (is (= 2 (length table)))))

(test converge-writes-the-host-redirect-table-into-every-local-pod
  (let ((writes '()))
    (gr8s.network::converge-node-host-redirect
     '("sandboxA" "sandboxB") "192.168.1.20"
     :directory-fn (lambda (sandbox) (format nil "/pins/~A/" sandbox))
     :writer (lambda (directory table) (push (cons directory table) writes)))
    (is (= 2 (length writes)))
    ;; Each Pod received the full node table (API server + node IP).
    (dolist (w writes)
      (let ((keys (mapcar #'car (cdr w))))
        (is (member #(10 96 0 1) keys :test #'equalp))
        (is (member #(192 168 1 20) keys :test #'equalp))))))
