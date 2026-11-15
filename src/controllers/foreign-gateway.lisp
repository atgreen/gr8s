;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The Gateway API implementation on a foreign cluster (podster-982.5,
;;;; docs/design-foreign-cluster-networking.md).
;;;;
;;;; The existing gateway controller already reads everything it needs --
;;;; GatewayClasses, Gateways, routes, Secrets, Services, EndpointSlices --
;;;; through the desired-state seam, so on a foreign cluster it runs unchanged
;;;; over the agent's FOREIGN-RESOURCE-VIEW.  This file only composes it: a
;;;; factory handed to the foreign CNI agent, whose convergence loop then
;;;; drives the L7 and L4 listener plans whenever the watch caches move.

(in-package #:gr8s.controllers)

(defun start-foreign-gateway (view &key cert-dir resolver)
  "A Gateway controller over the foreign VIEW, for the CNI agent's loop.
Returns (values CONVERGER STOPPER): CONVERGER reconciles the HTTP and L4
listener plans against the watched Gateway resources; STOPPER tears every
listener down.  RESOLVER overrides backend resolution (tests)."
  (let ((controller (make-gateway-controller view :cert-dir cert-dir :resolver resolver)))
    (values
     (lambda ()
       (converge-gateway-listeners controller)
       (converge-gateway-l4-listeners controller))
     (lambda ()
       (stop-gateway-controller controller)))))
