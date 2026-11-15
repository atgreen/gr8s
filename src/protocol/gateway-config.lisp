;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.protocol)

(defparameter +gateway-config-delta-capability+ "gateway-config-delta-v1")

(defparameter +gateway-config-resources+
  '("gatewayclasses" "gateways" "httproutes" "tcproutes" "tlsroutes" "grpcroutes"
    "services" "endpointslices" "secrets" "ingressclasses" "ingresses"))

(defun gateway-resource-change-key (change)
  "Validate a public Gateway resource key and return (resource namespace name)."
  (let ((resource (slot-value change 'gr8s.node.v1::resource))
        (namespace (slot-value change 'gr8s.node.v1::namespace))
        (name (slot-value change 'gr8s.node.v1::name)))
    (flet ((name-p (value &optional dots)
             (and (stringp value) (plusp (length value))
                  (every (lambda (character)
                           (or (find character "abcdefghijklmnopqrstuvwxyz0123456789-")
                               (and dots (char= character #\.)))) value))))
      (unless (and (member resource +gateway-config-resources+ :test #'equal)
                   (name-p name t)
                   (if (member resource '("gatewayclasses" "ingressclasses") :test #'equal)
                       (equal namespace "")
                       (name-p namespace)))
        (error "Invalid Gateway resource identity ~S/~S/~S" resource namespace name)))
    (list resource (unless (equal namespace "") namespace) name)))

(defun validate-gateway-config-update (update node-revision gateway-revision)
  "Require an ordered batch on this session's exact full-node baseline."
  (let ((base-node (slot-value update 'gr8s.node.v1::base-node-revision))
        (base (slot-value update 'gr8s.node.v1::base-revision))
        (revision (slot-value update 'gr8s.node.v1::revision))
        (changes (slot-value update 'gr8s.node.v1::changes))
        (seen (make-hash-table :test #'equal)))
    (unless (and (typep base-node '(unsigned-byte 64)) (plusp base-node)
                 (typep base '(unsigned-byte 64)) (typep revision '(unsigned-byte 64))
                 (= base-node node-revision) (= base gateway-revision) (> revision base)
                 changes)
      (error "Gateway delta ~S -> ~S has no matching node/Gateway baseline (~S/~S)"
             base revision node-revision gateway-revision))
    (dolist (change changes)
      (let ((key (gateway-resource-change-key change))
            (bytes (slot-value change 'gr8s.node.v1::object-json)))
        (when (gethash key seen) (error "Duplicate Gateway change ~S" key))
        (unless (and (typep bytes '(vector (unsigned-byte 8)))
                     (if (slot-value change 'gr8s.node.v1::deleted)
                         (zerop (length bytes)) (plusp (length bytes))))
          (error "Gateway change ~S has ambiguous object/deletion data" key))
        (setf (gethash key seen) t))))
  update)

(defun coalesce-gateway-config-updates (first second)
  "Compose adjacent batches without expanding their full discovery projection."
  (let ((node (slot-value first 'gr8s.node.v1::base-node-revision))
        (base (slot-value first 'gr8s.node.v1::base-revision))
        (changes (make-hash-table :test #'equal)))
    (validate-gateway-config-update first node base)
    (validate-gateway-config-update second node (slot-value first 'gr8s.node.v1::revision))
    (dolist (update (list first second))
      (dolist (change (slot-value update 'gr8s.node.v1::changes))
        (setf (gethash (gateway-resource-change-key change) changes) change)))
    (make-instance 'gr8s.node.v1::gateway-config-update
                   :base-node-revision node :base-revision base
                   :revision (slot-value second 'gr8s.node.v1::revision)
                   :changes (loop for key in (sort (loop for key being the hash-keys of changes collect key)
                                                  #'string< :key (lambda (key) (format nil "~{~A~^/~}" key)))
                                  collect (gethash key changes)))))
