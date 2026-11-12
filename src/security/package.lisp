;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for cluster identity, certificates, and TLS.

(defpackage #:gr8s.security
  (:use #:cl)
  (:shadow
   #:api-csr-profile-certificate-p
   #:ensure-cluster-pki
   #:ensure-raft-founder-credentials
   #:make-node-tls-channel
   #:parse-and-verify-certificate-request)
  (:export
   #:api-csr-profile-certificate-p
   #:ensure-cluster-pki
   #:ensure-raft-founder-credentials
   #:make-node-tls-channel
   #:parse-and-verify-certificate-request))
