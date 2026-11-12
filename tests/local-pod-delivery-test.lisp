;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Same-node Pod->Pod delivery (podster-3yi): the local_pod_v4 value/key byte
;;;; layout must match exactly what the egress-guard program loads, and the
;;;; reconcile converge must write the whole node table into every local Pod.

(in-package #:gr8s/tests)
(in-suite gr8s)

(test local-pod-value-layout-matches-the-egress-guard-loads
  ;; ifindex is a native-order u32 at offset 0 (the program redirects to it);
  ;; Pod MAC is 6 wire bytes at offset 4, veth MAC 6 wire bytes at offset 10
  ;; (the program copies them verbatim into the frame's dst/src MAC).
  (let ((v (gr8s.network::encode-local-pod-value #x12345678
                                         #(1 2 3 4 5 6)
                                         #(7 8 9 10 11 12))))
    (is (= 16 (length v)))
    (is (equalp #(#x78 #x56 #x34 #x12) (subseq v 0 4)))   ; ifindex little-endian
    (is (equalp #(1 2 3 4 5 6) (subseq v 4 10)))          ; dest Pod MAC, wire order
    (is (equalp #(7 8 9 10 11 12) (subseq v 10 16)))))    ; dest veth MAC, wire order

(test local-pod-key-is-the-lpm-slash32-destination
  ;; An LPM /32 key: prefixlen 32 (host order, little-endian u32) then the
  ;; destination address in network byte order -- same shape as netpol-cidr-lpm-key.
  (is (equalp #(32 0 0 0 1 2 3 4) (gr8s.network::local-pod-ipv4-key "1.2.3.4")))
  (is (equalp #(32 0 0 0 10 96 0 1) (gr8s.network::local-pod-ipv4-key "10.96.0.1"))))

(test local-pod-mac-round-trips-through-the-pinned-identity-value
  ;; The agent reads a Pod's own MAC back from its pinned endpoint_identity map;
  ;; decode must invert the encoder the CNI used to write it.
  (let* ((mac #(#xaa #xbb #xcc #xdd #xee #xff))
         (identity (gr8s.network::encode-cni-endpoint-identity "10.80.1.7" mac)))
    (is (equalp mac (gr8s.network::decode-endpoint-identity-mac identity)))))

(test converge-writes-the-whole-node-table-into-every-local-pod
  ;; Two local Pods: each Pod's local_pod_v4 must end up with both Pods' entries.
  (let ((endpoints '(("sandboxA" "eth0" "10.80.0.2")
                     ("sandboxB" "eth0" "10.80.0.3")))
        (writes '()))
    (gr8s.network::converge-node-local-pod-delivery
     endpoints
     :directory-fn (lambda (sandbox) (format nil "/pins/~A/" sandbox))
     :value-fn (lambda (sandbox interface directory)
                 (declare (ignore interface directory))
                 ;; distinct 16-byte value per sandbox so we can see both land
                 (make-array 16 :element-type '(unsigned-byte 8)
                               :initial-element (if (string= sandbox "sandboxA") 1 2)))
     :writer (lambda (directory table)
               (push (cons directory table) writes)))
    ;; Both Pods were written.
    (is (= 2 (length writes)))
    ;; Each write carried the full 2-entry table (both destination keys).
    (dolist (w writes)
      (let ((keys (mapcar #'car (cdr w))))
        (is (= 2 (length keys)))
        (is (member #(32 0 0 0 10 80 0 2) keys :test #'equalp))
        (is (member #(32 0 0 0 10 80 0 3) keys :test #'equalp))))))
