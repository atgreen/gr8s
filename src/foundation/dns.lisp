;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; gr8s's Kubernetes DNS policy over the standalone cl-dns-proxy library.
;;;;
;;;; The bounded UDP/TCP forwarding proxy -- its server threads, forward cache,
;;;; metrics, resolv.conf parsing and the authoritative-reply helpers -- now lives
;;;; in cl-dns-proxy (installed via ocicl).  That proxy answers a single decoded
;;;; question through a caller-supplied RESOLVER returning (ANSWERS HANDLED-P
;;;; RCODE), and forwards everything else upstream.  gr8s supplies the cluster
;;;; resolver (see MAKE-CLUSTER-DNS-RESOLVER in kubelet/service-dns.lisp), which
;;;; is what makes this a Kubernetes resolver rather than a plain forwarder; this
;;;; file keeps the cluster-specific constants and the reserved API-service answer
;;;; that resolver is built from, and re-homes the library's proxy API into the
;;;; gr8s composition package so existing callers reach it unchanged.

(in-package #:gr8s.foundation)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((symbols (mapcar (lambda (name)
                           (or (find-symbol name '#:cl-dns-proxy)
                               (error "cl-dns-proxy does not provide ~A, which gr8s requires." name)))
                         '("ANSWER-DNS-QUERY" "CACHED-DNS-FORWARD" "CALL-WITH-DNS-SERVER"
                           "DNS-FORWARD-CACHE" "DNS-METRICS" "DNS-METRICS-TEXT" "DNS-RESPONSE-CODE"
                           "DNS-SERVER" "DNS-SERVER-PORT" "DNS-UPSTREAMS-FOR-PACKET"
                           "FORWARD-DNS-TCP" "FORWARD-DNS-UDP" "HOST-DNS-UPSTREAMS"
                           "MAKE-DNS-FORWARD-CACHE" "MAKE-DNS-METRICS" "PARSE-RESOLV-CONF-UPSTREAMS"
                           "START-DNS-SERVER" "STOP-DNS-SERVER"
                           ;; DNS-name helpers gr8s builds its cluster policy from.
                           "CANONICAL-DNS-NAME" "DNS-NAME-IN-ZONE-P"))))
    (shadowing-import symbols '#:gr8s.foundation)
    (export symbols '#:gr8s.foundation)))

(defconstant +dns-name-error+ 3)

(defparameter +dns-cluster-zone+ "cluster.local")
(defparameter +dns-kubernetes-service+
  "kubernetes.default.svc.cluster.local")
(defparameter +dns-kubernetes-service-address+ #(10 96 0 1))
(defparameter +dns-pod-server-address+ "169.254.1.1")
(defparameter +dns-pod-searches+
  '("default.svc.cluster.local" "svc.cluster.local" "cluster.local"))
(defparameter +dns-pod-options+ '("ndots:5"))

(defun kubernetes-service-answer (question)
  "Return the reserved API Service A record for an A question."
  (when (= (0conf:question-qtype question) 0conf:+type-a+)
    (list (make-instance '0conf:a-record
                         :name (0conf:question-name question)
                         :address +dns-kubernetes-service-address+
                         :ttl 30))))
