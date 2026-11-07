;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for cluster identity, certificates, and TLS.

(defpackage #:gr8s.security
  (:use #:cl #:gr8s)
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

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((security (find-package '#:gr8s.security))
        (composition (find-package '#:gr8s)))
    (dolist (name '("API-CSR-PROFILE-CERTIFICATE-P"
                    "ENSURE-CLUSTER-PKI"
                    "ENSURE-RAFT-FOUNDER-CREDENTIALS"
                    "MAKE-NODE-TLS-CHANNEL"
                    "PARSE-AND-VERIFY-CERTIFICATE-REQUEST"))
      (multiple-value-bind (old old-status)
          (find-symbol name composition)
        (let ((new (find-symbol name security)))
        (dolist (user (package-used-by-list composition))
          (when (eq old (find-symbol name user))
            (shadowing-import new user)))
        (shadowing-import new composition)
        (export new security)
        (when (eq :external old-status)
          (export new composition)))))))
