;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Publish each node's heartbeat as a coordination.k8s.io Lease in the
;;;; kube-node-lease namespace, as a kubelet does. Clients and controllers read a
;;;; node's liveness there: the Lease names its node as holder and owner, and its
;;;; renewTime advances with the node's actual heartbeats, at most every renewal
;;;; interval, so a node that stops beating leaves a Lease that stops renewing.

(in-package #:gr8s)

(defparameter +node-lease-namespace+ "kube-node-lease"
  "The namespace upstream nodes publish their Leases in.")

(defparameter *node-lease-duration-seconds* 40
  "The leaseDurationSeconds a node's Lease declares, the kubelet's default.")

(defparameter *node-lease-renew-interval-seconds* 10
  "How old a node's Lease renewTime may grow before a heartbeat renews it, as the kubelet's
renew interval: a quarter of the lease duration.")

(defun node-lease-micro-time (time)
  "Format universal TIME as a Kubernetes MicroTime."
  (multiple-value-bind (second minute hour day month year) (decode-universal-time time 0)
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0D.000000Z" year month day hour minute second)))

(defun node-lease-object (node now)
  "Return the Lease NODE holds, renewed at universal time NOW."
  (core-object "apiVersion" "coordination.k8s.io/v1" "kind" "Lease"
               "metadata" (core-object "name" (node-record-name node) "namespace" +node-lease-namespace+
                                       "ownerReferences" (vector (core-object "apiVersion" "v1" "kind" "Node"
                                                                              "name" (node-record-name node)
                                                                              "uid" (node-record-id node))))
               "spec" (core-object "holderIdentity" (node-record-name node)
                                   "leaseDurationSeconds" *node-lease-duration-seconds*
                                   "renewTime" (node-lease-micro-time now))))

(defun renew-node-lease (store name now)
  "Create or renew node NAME's Lease for a heartbeat at universal time NOW. A Lease renewed
within the renew interval is left alone, so frequent heartbeats do not rewrite it each time."
  (let ((node (with-store-lock (store) (get-node-unlocked store name))))
    (when node
      (let ((existing (handler-case (get-core-resource store "leases" +node-lease-namespace+ name)
                        (kubernetes-error (condition)
                          (unless (= 404 (kubernetes-error-status-code condition)) (error condition))
                          nil)))
            (desired (node-lease-object node now)))
        (if (null existing)
            (create-core-resource store "leases" desired +node-lease-namespace+)
            (let ((renewed (ignore-errors (pod-deletion-time (gethash "renewTime" (gethash "spec" existing))))))
              (when (or (null renewed) (>= (- now renewed) *node-lease-renew-interval-seconds*)
                        (not (equal name (gethash "holderIdentity" (gethash "spec" existing)))))
                (update-core-resource store "leases" +node-lease-namespace+ name
                                      (lambda (current)
                                        (setf (gethash "spec" current) (gethash "spec" desired)
                                              (gethash "ownerReferences" (gethash "metadata" current))
                                              (gethash "ownerReferences" (gethash "metadata" desired)))
                                        current)))))))))

(defun note-node-heartbeat-lease (store name now)
  "Renew NAME's Lease after a heartbeat. The heartbeat itself has already counted, so a
failure to write the Lease is reported and retried by the next heartbeat."
  (handler-case (renew-node-lease store name now)
    (error (condition)
      (format *error-output* "gr8s node Lease ~A/~A renewal failed: ~A~%" +node-lease-namespace+ name condition))))
