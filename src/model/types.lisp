;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Kubernetes domain values shared by parsing, persistence, scheduling, and
;;;; runtime adapters.

(in-package #:gr8s.model)

(define-condition kubernetes-error (error)
  ((status-code
    :initarg :status-code
    :reader kubernetes-error-status-code)
   (reason
    :initarg :reason
    :reader kubernetes-error-reason)
   (message
    :initarg :message
    :reader kubernetes-error-message)
   (details
    :initarg :details
    :initform nil
    :reader kubernetes-error-details))
  (:report (lambda (condition stream)
             (format stream "~A: ~A"
                     (kubernetes-error-reason condition)
                     (kubernetes-error-message condition))))
  (:documentation "Describe an HTTP-facing Kubernetes API failure."))

(defparameter *pod-resize-update* nil
  "True while the resize subresource writes, the only way to change container resources.")

(defstruct container-spec
  "Represent the supported, runtime-relevant portion of a Pod container."
  name
  image
  command
  args
  env
  ports)

(defstruct pod
  "Represent a validated Kubernetes Pod and its authoritative JSON object."
  name
  namespace
  containers
  (init-containers #())
  (ephemeral-containers #())
  (restart-policy "Always")
  uid
  resource-version
  node-name
  object
  ;; Newer client-visible revision from status alone, never acknowledged by agents.
  status-revision)

(defun pod-all-containers (pod)
  "Return every declared container, for shared credentials, mounts and named operations."
  (concatenate 'vector (pod-init-containers pod) (pod-containers pod)
               (pod-ephemeral-containers pod)))

(defstruct node-record
  "Represent a registered worker node and its control-plane lease state."
  id
  name
  pod-cidr
  ;; Every assigned family, primary first. POD-CIDR remains the compatibility
  ;; accessor for older state and callers while the dataplane is migrated.
  (pod-cidrs #())
  (underlay-address "")
  ;; Public half of the node-local WireGuard identity. The private half never
  ;; enters the control-plane store.
  (wireguard-public-key #())
  ;; Authenticated candidate endpoints as (NAME IPV4 PORT) tuples. The legacy
  ;; underlay address and cluster listen port remain the implicit default.
  (wireguard-endpoints nil)
  ;; Unix time of the last authenticated fresh-handshake observation that
  ;; established the server-owned nat-reflexive endpoint.
  wireguard-reflexive-observed-at
  ;; The port of the node's authenticated kubelet endpoints, or 0 when it serves none.
  (kubelet-port 0)
  (ready-p nil)
  ;; Why the node's container runtime is down while its agent still holds the
  ;; lease, or NIL. Not persisted: the next heartbeat reports it again.
  runtime-down-message
  ;; Node-pressure signals from the agent's most recent heartbeat, surfaced as
  ;; the standard kubelet Node conditions. Transient like RUNTIME-DOWN-MESSAGE:
  ;; the next heartbeat reports them again, so they are not persisted.
  (memory-pressure nil)
  (disk-pressure nil)
  (pid-pressure nil)
  last-heartbeat
  lease-deadline
  ;; First heartbeat of the current uninterrupted ready lease. Unlike
  ;; LAST-HEARTBEAT this does not advance on renewal, so gateway recovery
  ;; hysteresis survives control-plane restart.
  ready-since
  (labels nil)
  (annotations nil)
  ;; SHA-256 fingerprint of the CA that signed the client certificate used by
  ;; the node's most recent authenticated session. Internal rotation evidence,
  ;; not user-editable Node metadata.
  certificate-issuer-fingerprint
  (resource-version "1")
  ;; Quantity strings the node's agent measured about itself.
  capacity
  allocatable
  ;; Quantity strings clients advertised through the Node status subresource.
  extended-resources
  ;; Written through the API and enforced by the scheduler and the eviction pass.
  (taints #())
  unschedulable
  ;; A Node created through the API has no agent: its status is whatever was written.
  api-only
  api-status
  ;; When the node was first registered, as an RFC 3339 timestamp; NIL for a node an older
  ;; gr8s registered until its agent registers again.
  creation-timestamp)

(defun node-record-all-pod-cidrs (node)
  "Return NODE's assigned Pod CIDRs, accepting records from before dual-stack storage."
  (let ((cidrs (node-record-pod-cidrs node)))
    (if (plusp (length cidrs)) cidrs
        (let ((primary (node-record-pod-cidr node)))
          (if (and (stringp primary) (plusp (length primary))) (vector primary) #())))))

(defun node-record-runtime-ready-p (node)
  "Return whether NODE's agent holds its lease and its container runtime can run Pods."
  (and (node-record-ready-p node) (null (node-record-runtime-down-message node))))
