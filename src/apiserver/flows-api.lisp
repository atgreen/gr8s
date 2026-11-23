;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve the cluster's flow events (podster-e9a.3) at /apis/gr8s.io/v1/flows, or
;;;; for one namespace at /apis/gr8s.io/v1/namespaces/NAMESPACE/flows, as one JSON
;;;; object per line: every node's recent events, and with ?watch=true new ones
;;;; until the client goes. RBAC authorizes it like any list or watch of the
;;;; gr8s.io "flows" resource; a namespaced reader sees the flows either side of
;;;; which is in its namespace.

(in-package #:gr8s.apiserver)

(defun flow-in-namespace-p (flow namespace)
  "Whether FLOW's Pod or its peer is in NAMESPACE; any flow, without one."
  (or (null namespace)
      (equal namespace (gethash "namespace" flow))
      (equal namespace (gethash "peerNamespace" flow))))

(defun serve-flows (store reconciler namespace)
  "Stream the flow events NAMESPACE's reader may see, or every one without NAMESPACE."
  (declare (ignore store))
  (let ((runtime (reconciler-runtime reconciler))
        (follow (true-parameter-p (hunchentoot:get-parameter "watch")))
        (fd (request-client-fd))
        (gone nil))
    (unless (typep runtime 'control-plane-runtime)
      (core-resource-error 503 "ServiceUnavailable" "Flow events need a control plane with nodes"))
    (setf (hunchentoot:return-code*) 200
          (hunchentoot:content-type*) "application/json")
    (let ((out (hunchentoot:send-headers))
          (watcher nil))
      ;; Flows stream for as long as the reader watches; the store was only needed to start.
      (gr8s.store::release-store-request)
      (extend-api-connection-idle-timeout)
      (when (and follow fd)
        (setf watcher (bt:make-thread
                       (lambda ()
                         (loop until gone
                               do (sleep 1)
                                  (when (client-connection-closed-p fd) (setf gone t))))
                       :name "gr8s flows client")))
      (unwind-protect
           (gr8s.controllers::observe-cluster-flows
            runtime
            (lambda (flow)
              (when (and (not gone) (flow-in-namespace-p flow namespace))
                (handler-case
                    (progn (write-sequence (gr8s.resources:stringify-to-utf-8-bytes flow) out)
                           (write-byte 10 out)
                           (force-output out))
                  (error () (setf gone t)))))
            :follow follow :stop-p (lambda () gone))
        (setf gone t)
        (when watcher (ignore-errors (bt:join-thread watcher))))
      nil)))
