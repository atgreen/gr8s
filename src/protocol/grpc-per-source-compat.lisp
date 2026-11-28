;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Let a gRPC server leave sources it trusts out of the pinned ag-gRPC's per-source
;;;; connection cap (podster-7op6). The cap keeps one unauthenticated peer from filling
;;;; the node listener's pool, but some sources hold a connection per node by design: a
;;;; server hosting browser nodes runs an agent for each, and each dials the node
;;;; listener from the server's own address, loopback or, on an HA follower, the
;;;; member's. At 32 per source, a server hosted 31 browser nodes and no more.

(in-package #:gr8s.protocol)

(defvar *grpc-uncapped-sources* (make-hash-table :test #'eq :weakness :key :synchronized t)
  "For each gRPC server given one, a function of a peer's address key (as ag-gRPC makes
it) that is true for a source its per-source cap leaves alone.")

(defun grpc-address-key (address)
  "The peer key ag-gRPC files a connection from ADDRESS (a dotted quad, or an IPv6
address in text) under, or NIL when ADDRESS isn't one."
  (ignore-errors (princ-to-string (usocket::host-to-vector-quad address))))

(defun grpc-loopback-key-p (key)
  "Whether KEY, a peer address key, is a loopback address."
  (or (uiop:string-prefix-p "#(127 " key)
      (equal key (grpc-address-key "::1"))))

(defun grpc-server-uncap-sources (server predicate)
  "Leave SERVER's sources for which PREDICATE (of a peer address key) is true out of its
per-source cap, or, with PREDICATE NIL, cap them all again."
  (if predicate
      (setf (gethash server *grpc-uncapped-sources*) predicate)
      (remhash server *grpc-uncapped-sources*))
  server)

(defun grpc-capped-source-p (server ip)
  "Whether SERVER's per-source cap applies to the connection from IP, a peer key."
  (and (ag-grpc::server-max-connections-per-ip server)
       ip
       (let ((uncapped (gethash server *grpc-uncapped-sources*)))
         (not (and uncapped (ignore-errors (funcall uncapped ip)))))))

(defun ag-grpc::server-try-reserve-ip-slot (server ip)
  "Reserve a per-source connection slot for IP, returning T when granted. Returns T
with no accounting when no per-IP cap is configured, IP is unknown, or the server leaves
IP uncapped, and NIL when IP already holds MAX-CONNECTIONS-PER-IP live connections. A
slot granted here is released by SERVER-RELEASE-IP-SLOT when its connection ends."
  (if (grpc-capped-source-p server ip)
      (bt:with-lock-held ((ag-grpc::server-per-ip-connection-lock server))
        (let ((n (gethash ip (ag-grpc::server-per-ip-connection-counts server) 0)))
          (when (< n (ag-grpc::server-max-connections-per-ip server))
            (setf (gethash ip (ag-grpc::server-per-ip-connection-counts server)) (1+ n))
            t)))
      t))

(defun ag-grpc::server-release-ip-slot (server ip)
  "Release a per-source slot previously reserved by SERVER-TRY-RESERVE-IP-SLOT. A source
uncapped since it reserved one has its count dropped once its connections are all gone."
  (when (and (ag-grpc::server-max-connections-per-ip server) ip)
    (bt:with-lock-held ((ag-grpc::server-per-ip-connection-lock server))
      (let ((n (gethash ip (ag-grpc::server-per-ip-connection-counts server) 0)))
        (if (<= n 1)
            (remhash ip (ag-grpc::server-per-ip-connection-counts server))
            (setf (gethash ip (ag-grpc::server-per-ip-connection-counts server)) (1- n)))))))
