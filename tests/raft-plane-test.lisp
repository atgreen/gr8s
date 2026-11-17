;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the consistency-plane split (src/raft-plane.lisp): durable API
;;;; resources route to the consensus (Raft) plane, high-churn/expiring state
;;;; (events, observed status, telemetry) stays on the local plane.

(in-package #:gr8s/tests)
(def-suite raft-plane :in gr8s)
(in-suite raft-plane)

(test ha-adapters-have-an-explicit-package-boundary
  (let ((package (find-package "GR8S.HA")))
    (is (not (null package)))
    (dolist (name '("MAKE-RAFT-RESOURCE-STORE" "RAFT-PLANE-SUBMIT"
                    "START-HA-CONTROL-PLANE" "STOP-HA-CONTROL-PLANE"))
      (multiple-value-bind (symbol status) (and package (find-symbol name package))
        (is (not (null symbol)) "~A is present in GR8S.HA" name)
        (is (eq :external status) "~A is exported from GR8S.HA" name)))))

(test raft-plane-classifies-consensus-vs-local
  (dolist (r '("configmaps" "secrets" "services" "gateways" "networkpolicies"
               "certificates" "httproutes"))
    (is (gr8s.ha::raft-consensus-resource-p r) "~A is consensus state" r))
  (is (not (gr8s.ha::raft-consensus-resource-p "events")))   ; deliberately local plane
  (is (not (gr8s.ha::raft-consensus-resource-p "bogus")))    ; not a stored type -> not consensus
  (is (gr8s.ha::raft-local-plane-category-p :observed-status))
  (is (gr8s.ha::raft-local-plane-category-p :endpoint-telemetry))
  (is (gr8s.ha::raft-local-plane-category-p :node-heartbeat))
  (is (not (gr8s.ha::raft-local-plane-category-p :desired-state))))

(test raft-plane-routes-to-the-right-plane
  (let* ((routed '())
         (plane (gr8s.ha::make-raft-plane
                 :consensus-fn (lambda (op) (push (cons :consensus op) routed) :c)
                 :local-fn (lambda (op) (push (cons :local op) routed) :l))))
    (is (eq :c (gr8s.ha::raft-plane-submit plane "configmaps" :put)))
    (is (eq :l (gr8s.ha::raft-plane-submit plane "events" :put)))
    (is (equal '((:consensus . :put) (:local . :put)) (nreverse routed)))))

(test raft-leader-aware-http-redirect
  ;; Method classification.
  (is (not (gr8s.ha::raft-mutating-method-p :get)))
  (is (not (gr8s.ha::raft-mutating-method-p "HEAD")))
  (is (gr8s.ha::raft-mutating-method-p :post))
  (is (gr8s.ha::raft-mutating-method-p "DELETE"))
  (let ((leader "https://10.0.0.2:6443"))
    ;; A follower forwards a mutating request to the leader, preserving path+query.
    (is (equal "https://10.0.0.2:6443/api/v1/namespaces/default/configmaps?x=1"
               (gr8s.ha::raft-leader-redirect-url
                :post "/api/v1/namespaces/default/configmaps?x=1" nil leader)))
    ;; A trailing slash on the base URL does not double up.
    (is (equal "https://10.0.0.2:6443/api/v1/configmaps"
               (gr8s.ha::raft-leader-redirect-url :put "/api/v1/configmaps" nil "https://10.0.0.2:6443/")))
    ;; The leader serves writes locally; reads are always local.
    (is (null (gr8s.ha::raft-leader-redirect-url :post "/api/v1/configmaps" t leader)))
    (is (null (gr8s.ha::raft-leader-redirect-url :get "/api/v1/configmaps" nil leader)))
    ;; No known leader -> no redirect (caller answers 503).
    (is (null (gr8s.ha::raft-leader-redirect-url :post "/api/v1/configmaps" nil nil)))))

;;; podster-fq7: the dashboard login check POSTs a SelfSubjectRulesReview. As a
;;; write it was redirected to the leader's (stale, LAN) API URL, which the
;;; browser could not follow -> "Error Authenticating". Authorization and token
;;; reviews are read-only evaluations every member can answer, so they must not
;;; redirect.

(test auth-reviews-are-not-redirected-to-the-leader
  (flet ((redirects (path)
           (gr8s.apiserver::ha-non-redirecting-write-path-p path)))
    ;; Served locally on any member (no redirect):
    (is (redirects "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"))
    (is (redirects "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"))
    (is (redirects "/apis/authorization.k8s.io/v1/namespaces/default/localsubjectaccessreviews"))
    (is (redirects "/apis/authentication.k8s.io/v1/tokenreviews"))
    (is (redirects "/apis/gr8s.io/v1/patchrollouts"))
    ;; Real writes still redirect (function returns NIL -> caller redirects):
    (is (not (redirects "/api/v1/namespaces/default/pods")))
    (is (not (redirects "/apis/apps/v1/namespaces/default/deployments")))
    (is (not (redirects "/apis/authorization.k8s.io/v1/subjectaccessreviews"))
        "a cluster-admin SubjectAccessReview is not one of the self/local probes")))
