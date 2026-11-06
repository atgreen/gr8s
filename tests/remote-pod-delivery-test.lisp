;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Cross-node Pod->Pod send path (podster-xuc): the remote_pod_v4 key must be
;;;; the peer CIDR's LPM key (as the egress-guard program resolves the dst), and
;;;; the value must carry the gr8s-vxlan ifindex + the peer's VXLAN router MAC +
;;;; the local gr8s-vxlan MAC, so the redirected frame FDB-resolves the peer VTEP.

(in-package #:gr8s/tests)
(in-suite gr8s)

(defun %fake-link-attrs (mac)
  (let ((h (make-hash-table))) (setf (gethash 1 h) mac) h))

(test remote-pod-key-is-the-peer-cidr-lpm-key
  ;; The key the agent writes must equal the netpol CIDR LPM key the egress guard
  ;; looks up with (prefixlen 32 + dst addr); LPM longest-prefix matches the CIDR.
  (is (equalp (gr8s::netpol-cidr-lpm-key "10.80.16.0/20")
              (car (first (gr8s::node-remote-pod-table
                           '("10.80.16.0/20")
                           :interface-index (lambda (name) (declare (ignore name)) 42)
                           :link-attributes (lambda (name) (declare (ignore name))
                                              (%fake-link-attrs #(2 3 4 5 6 7)))))))))

(test remote-pod-value-carries-vxlan-ifindex-router-mac-and-vxlan-mac
  (let* ((vxlan-mac #(2 3 4 5 6 7))
         (table (gr8s::node-remote-pod-table
                 '("10.80.16.0/20")
                 :interface-index (lambda (name) (declare (ignore name)) 42)
                 :link-attributes (lambda (name) (declare (ignore name))
                                    (%fake-link-attrs vxlan-mac))))
         (value (cdr (first table))))
    (is (= 16 (length value)))
    (is (equalp #(42 0 0 0) (subseq value 0 4)))                      ; ifindex, little-endian
    (is (equalp (gr8s::vxlan-router-mac "10.80.16.0/20") (subseq value 4 10))) ; dst = peer router MAC
    (is (equalp vxlan-mac (subseq value 10 16)))))                    ; src = local gr8s-vxlan MAC

(test remote-pod-table-is-nil-before-the-vxlan-device-exists
  ;; A reconcile before gr8s-vxlan is up (ifindex 0) must produce no table.
  (is (null (gr8s::node-remote-pod-table
             '("10.80.16.0/20")
             :interface-index (lambda (name) (declare (ignore name)) 0)
             :link-attributes (lambda (name) (declare (ignore name)) (%fake-link-attrs nil))))))

(test converge-writes-the-remote-table-into-every-local-pod
  (let ((writes '()))
    (gr8s::converge-node-remote-pod-delivery
     '("sandboxA" "sandboxB") '("10.80.16.0/20" "10.80.32.0/20")
     :directory-fn (lambda (sandbox) (format nil "/pins/~A/" sandbox))
     :table-fn (lambda (cidrs)
                 (loop for c in cidrs
                       collect (cons (gr8s::netpol-cidr-lpm-key c)
                                     (make-array 16 :element-type '(unsigned-byte 8)))))
     :writer (lambda (directory table) (push (cons directory table) writes)))
    (is (= 2 (length writes)))
    (dolist (w writes)
      (let ((keys (mapcar #'car (cdr w))))
        (is (= 2 (length keys)))
        (is (member (gr8s::netpol-cidr-lpm-key "10.80.16.0/20") keys :test #'equalp))
        (is (member (gr8s::netpol-cidr-lpm-key "10.80.32.0/20") keys :test #'equalp))))))
