;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Decide how the API server reaches a Pod or node: directly, or, for a control
;;;; plane with no route to them, through the agent on that node, over the session
;;;; the agent opened. Webhooks, aggregated APIs and the proxy subresources ask here.

(in-package #:gr8s.apiserver)

(defvar *pod-network-dialer* nil
  "NIL when this process routes to Pod IPs. Otherwise a function of a node name, address,
port and connect timeout that returns a stream that node's agent has connected there:
a control plane with no local agent calls webhooks and aggregated APIs this way.")

(defun pod-address-node (store address)
  "Return the name of the node whose Pod CIDRs or own address hold ADDRESS, or NIL."
  (with-store-lock (store)
    (loop for node being the hash-values of (pod-store-nodes store)
          when (or (equal address (node-record-underlay-address node))
                   (some (lambda (cidr) (gr8s.network::network-address-in-cidr-p cidr address))
                         (node-record-all-pod-cidrs node)))
            return (node-record-name node))))

(defun pod-network-dial (node-name &optional store address)
  "Return an HTTP-CLIENT dial function reaching an endpoint on NODE-NAME, or NIL to connect
directly. Without NODE-NAME, STORE finds the node that holds ADDRESS; an address on no
node, such as the control plane's own, is dialled directly."
  (let* ((dialer *pod-network-dialer*)
         (node-name (or node-name (and dialer store address (pod-address-node store address)))))
    (and dialer node-name
         (lambda (address port timeout) (funcall dialer node-name address port timeout)))))
