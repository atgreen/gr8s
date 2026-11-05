;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Map verified Kubernetes API certificate subjects and live ServiceAccount
;;;; tokens into request identities. Share User/Group RBAC and server-owned CSR
;;;; actor fields. Identity headers count only through authorized impersonation.

(in-package #:gr8s)

(defstruct api-user-identity
  "Represent a verified certificate user independently of ServiceAccount storage."
  username uid groups extra)

(defvar *authenticated-api-identity* nil
  "Identity authenticated for the current public TLS API request only.")

(defun api-identity-username (identity)
  "Return the Kubernetes username of either supported authenticated identity."
  (etypecase identity
    (api-user-identity (api-user-identity-username identity))
    (api-service-account-identity
     (format nil "system:serviceaccount:~A:~A" (api-service-account-identity-namespace identity)
             (api-service-account-identity-name identity)))))

(defun api-identity-groups (identity)
  "Return certificate organization groups or the standard ServiceAccount groups."
  (etypecase identity
    (api-user-identity (api-user-identity-groups identity))
    (api-service-account-identity
     (vector "system:serviceaccounts"
             (format nil "system:serviceaccounts:~A" (api-service-account-identity-namespace identity))
             "system:authenticated"))))

(defun api-identity-actor (identity)
  "Produce immutable CSR actor fields from the verified request identity."
  (let ((actor (core-object "username" (api-identity-username identity) "groups" (api-identity-groups identity)))
        (uid (etypecase identity
               (api-user-identity (api-user-identity-uid identity))
               (api-service-account-identity (api-service-account-identity-uid identity)))))
    (when uid (setf (gethash "uid" actor) uid))
    (when (and (api-user-identity-p identity) (api-user-identity-extra identity))
      (setf (gethash "extra" actor) (api-user-identity-extra identity)))
    actor))

(defun certificate-api-identity (chain ca)
  "Verify the actual peer chain for client authentication, then decode CN, O, UID and credential ID."
  (when chain
    (handler-case
        (progn
          (pure-tls::verify-certificate-chain chain (list ca) :purpose :client-auth :trust-anchor-mode :replace)
          (let* ((leaf (first chain))
                 (raw (pure-tls::x509-certificate-raw-der leaf))
                 (tbs (pure-tls::asn1-children (first (pure-tls::asn1-children (pure-tls::parse-der raw)))))
                 (version (and tbs (= 2 (pure-tls::asn1-node-class (first tbs)))))
                 (subject (csr-subject-name (nth (if version 5 4) tbs)))
                 (rdns (pure-tls::x509-name-rdns subject))
                 (username (csr-subject-common-name subject))
                 (uid-name (pure-tls::oid-name '(1 3 6 1 4 1 57683 2)))
                 (uids (loop for (name . value) in rdns when (equal name uid-name) collect value)))
            (when (or (> (length uids) 1) (and uids (zerop (length (first uids)))))
              (core-resource-error 401 "Unauthorized" "Certificate user UID must be one nonempty string"))
            (when (and username (plusp (length username)))
              (make-api-user-identity :username username :uid (first uids)
                :groups (coerce (remove-duplicates
                                 (append (loop for (name . value) in rdns when (eq name :organization-name) collect value)
                                         (list "system:authenticated")) :test #'equal) 'vector)
                :extra (core-object "authentication.kubernetes.io/credential-id"
                         (vector (concatenate 'string "X509SHA256=" (string-downcase (octets-to-hex (ironclad:digest-sequence :sha256 raw))))))))))
      (kubernetes-error () (core-resource-error 401 "Unauthorized" "Certificate user identity is invalid"))
      (error () (core-resource-error 401 "Unauthorized" "A valid client-authentication certificate is required")))))
