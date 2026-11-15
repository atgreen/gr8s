;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The kube-proxy replacement on a foreign cluster (podster-982.4,
;;;; docs/design-foreign-cluster-networking.md).
;;;;
;;;; The socket load balancer's convergence already reads Services and
;;;; EndpointSlices through the desired-state seam, with kube-proxy's traffic
;;;; policies, terminating fallback and topology hints; over a foreign view it
;;;; runs unchanged.  This file composes it for the CNI agent's loop, around
;;;; the same Whistler cgroup/connect4 dataplane the native node uses.

(in-package #:gr8s.controllers)

(defun start-foreign-service-lb (view dataplane &key node-name)
  "The socket LB over the foreign VIEW's Services, as the CNI agent's extra
layer.  DATAPLANE is the attached service-lb dataplane (or a test double);
callers that could not attach one skip this layer and leave Service traffic to
whatever proxy the cluster still runs.  Returns (values CONVERGER STOPPER)."
  (let ((controller (make-service-lb-controller view dataplane node-name)))
    (values
     (lambda () (converge-service-lb-controller controller))
     (lambda ()
       (ignore-errors (gr8s.network::stop-service-lb-dataplane dataplane))))))
