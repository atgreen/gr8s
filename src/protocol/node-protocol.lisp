;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Framing for the node <-> control-plane protocol (gr8s.node.v1).
;;;;
;;;; A node agent and the control plane exchange protobuf envelopes: an
;;;; agent-envelope (hello, heartbeat, status, operation responses) upstream and a
;;;; server-envelope (hello, desired-state, operation requests) downstream. Each
;;;; envelope carries a protocol version, a sequence number, and exactly one
;;;; payload variant. This file is the one place that version is checked and that
;;;; a keyword variant is mapped to its protobuf payload class and type-checked,
;;;; so a mismatched version or a wrong-typed payload is rejected at construction
;;;; rather than on the wire. Only +node-protocol-version+ is supported; any other
;;;; version signals UNSUPPORTED-NODE-PROTOCOL-VERSION.

(in-package #:gr8s.protocol)

(defconstant +node-protocol-version+ 2)

(defun service-risk-projection-digest (objects)
  "SHA-256 of the ordered, length-framed discovery bytes carried by a snapshot.
Framing keeps different object boundaries from sharing the same digest input."
  (let ((digest (ironclad:make-digest :sha256))
        (length-bytes (make-array 8 :element-type '(unsigned-byte 8))))
    (dolist (bytes objects)
      (unless (typep bytes '(vector (unsigned-byte 8)))
        (error "Service discovery entry is not an octet vector"))
      (dotimes (index 8)
        (setf (aref length-bytes index)
              (ldb (byte 8 (* 8 index)) (length bytes))))
      (ironclad:update-digest digest length-bytes)
      (ironclad:update-digest digest bytes))
    (ironclad:produce-digest digest)))

(define-condition unsupported-node-protocol-version (error)
  ((received
    :initarg :received
    :reader unsupported-node-protocol-version-received)
   (supported
    :initarg :supported
    :reader unsupported-node-protocol-version-supported))
  (:report
   (lambda (condition stream)
     (format stream "Unsupported gr8s node protocol version ~D (supported: ~D)"
             (unsupported-node-protocol-version-received condition)
             (unsupported-node-protocol-version-supported condition)))))

(defun ensure-node-protocol-version (version)
  "Return VERSION when it is the supported node protocol version, else signal
   UNSUPPORTED-NODE-PROTOCOL-VERSION."
  (unless (= version +node-protocol-version+)
    (error 'unsupported-node-protocol-version
           :received version
           :supported +node-protocol-version+))
  version)

(defparameter +agent-envelope-variants+
  '((:hello . gr8s.node.v1::node-hello)
    (:heartbeat . gr8s.node.v1::heartbeat)
    (:snapshot-ack . gr8s.node.v1::snapshot-ack)
    (:status . gr8s.node.v1::node-status)
    (:operation-response . gr8s.node.v1::operation-response)
    (:operation-stream . gr8s.node.v1::operation-stream)
    (:credential-token-request . gr8s.node.v1::credential-token-request)
    (:gateway-config-ack . gr8s.node.v1::gateway-config-ack)
    (:credential-rotation . gr8s.node.v1::credential-rotation)))

(defparameter +server-envelope-variants+
  '((:hello . gr8s.node.v1::server-hello)
    (:desired-state . gr8s.node.v1::desired-state-snapshot)
    (:operation-request . gr8s.node.v1::operation-request)
    (:operation-input . gr8s.node.v1::operation-input)
    (:operation-cancel . gr8s.node.v1::operation-cancel)
    (:protocol-error . gr8s.node.v1::protocol-error)
    (:credential-token-response . gr8s.node.v1::credential-token-response)
    (:gateway-config . gr8s.node.v1::gateway-config-update)))

(defun make-node-envelope (class variants variant payload sequence protocol-version)
  "Build an envelope of CLASS carrying VARIANT's PAYLOAD at PROTOCOL-VERSION and
   SEQUENCE. VARIANTS maps each variant keyword to its protobuf payload class.
   Signals on an unsupported protocol version, an unknown VARIANT, or a PAYLOAD
   whose type does not match the variant. Returns the envelope with its
   payload-case set."
  (ensure-node-protocol-version protocol-version)
  (let ((payload-type (cdr (assoc variant variants))))
    (unless payload-type
      (error "Unknown ~A payload variant ~S" class variant))
    (unless (typep payload payload-type)
      (error "Payload for ~S must be a ~S, not ~S"
             variant payload-type (type-of payload)))
    (let ((envelope
            (apply #'make-instance class
                   :protocol-version protocol-version
                   :sequence sequence
                   (list variant payload))))
      (setf (slot-value envelope 'gr8s.node.v1::payload-case) variant)
      envelope)))

(defun make-agent-envelope (variant payload
                            &key
                              (sequence 0)
                              (protocol-version +node-protocol-version+))
  "Build an upstream agent-envelope for VARIANT and PAYLOAD (a variant of
   +agent-envelope-variants+), defaulting SEQUENCE to 0 and the protocol version
   to the current one. Signals as MAKE-NODE-ENVELOPE does."
  (make-node-envelope 'gr8s.node.v1::agent-envelope
                      +agent-envelope-variants+
                      variant payload sequence protocol-version))

(defun make-server-envelope (variant payload
                             &key
                               (sequence 0)
                               (protocol-version +node-protocol-version+))
  "Build a downstream server-envelope for VARIANT and PAYLOAD (a variant of
   +server-envelope-variants+), defaulting SEQUENCE to 0 and the protocol version
   to the current one. Signals as MAKE-NODE-ENVELOPE does."
  (make-node-envelope 'gr8s.node.v1::server-envelope
                      +server-envelope-variants+
                      variant payload sequence protocol-version))
