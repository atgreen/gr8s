;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise the consistency-plane split (src/raft-plane.lisp): durable API
;;;; resources route to the consensus (Raft) plane, high-churn/expiring state
;;;; (events, observed status, telemetry) stays on the local plane.

(in-package #:gr8s/tests)
(def-suite raft-plane :in gr8s)
(in-suite raft-plane)

(test raft-plane-classifies-consensus-vs-local
  (dolist (r '("configmaps" "secrets" "services" "gateways" "networkpolicies"
               "certificates" "httproutes"))
    (is (gr8s::raft-consensus-resource-p r) "~A is consensus state" r))
  (is (not (gr8s::raft-consensus-resource-p "events")))   ; deliberately local plane
  (is (not (gr8s::raft-consensus-resource-p "bogus")))    ; not a stored type -> not consensus
  (is (gr8s::raft-local-plane-category-p :observed-status))
  (is (gr8s::raft-local-plane-category-p :endpoint-telemetry))
  (is (gr8s::raft-local-plane-category-p :node-heartbeat))
  (is (not (gr8s::raft-local-plane-category-p :desired-state))))

(test raft-plane-routes-to-the-right-plane
  (let* ((routed '())
         (plane (gr8s::make-raft-plane
                 :consensus-fn (lambda (op) (push (cons :consensus op) routed) :c)
                 :local-fn (lambda (op) (push (cons :local op) routed) :l))))
    (is (eq :c (gr8s::raft-plane-submit plane "configmaps" :put)))
    (is (eq :l (gr8s::raft-plane-submit plane "events" :put)))
    (is (equal '((:consensus . :put) (:local . :put)) (nreverse routed)))))
