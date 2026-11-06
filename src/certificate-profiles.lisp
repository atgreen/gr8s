;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Distinguish API-issued credentials from legacy internal enrollment/server
;;;; credentials without changing the existing root, its pathLen:0 constraint,
;;;; or pinned fingerprints. Every API leaf carries an issuer-controlled signed
;;;; noncritical certificate policy; internal protocols reject that profile.
;;;; UUID v5 URL namespace maps to the self-assigned 2.25 policy identifier.

(in-package #:gr8s)

(defparameter +oid-certificate-policies+ '(2 5 29 32))
(defparameter +api-csr-profile-policy-oid+ '(2 25 239647859381961005463536084722150751259)
  "UUID b44a7fb4-94d0-583f-a90a-6be9694b3c1b for the v1 API CSR issuance profile URL.")

(defun api-csr-profile-extension ()
  "Encode the UUID profile as RFC5280 certificatePolicies, avoiding Go's outer-OID integer limit."
  (pure-tls/acme::encode-extension +oid-certificate-policies+
    (pure-tls/acme::encode-sequence
      (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid +api-csr-profile-policy-oid+)))))

(defun api-csr-profile-certificate-p (certificate)
  "Inspect every signed policy entry; requested extensions never control the issuer profile."
  (loop for extension in (pure-tls::x509-certificate-extensions certificate)
        thereis (and (equal (pure-tls::x509-extension-oid extension) (pure-tls::oid-name +oid-certificate-policies+))
                     (let* ((root (pure-tls::parse-der (pure-tls::x509-extension-value extension)))
                            (policies (pure-tls::asn1-children root)))
                       (unless (pure-tls::asn1-sequence-p root)
                         (pki-fail "invalid-certificate-profile" "Certificate policy encoding is malformed"))
                       (loop for policy in policies
                             thereis (equal +api-csr-profile-policy-oid+
                                            (pure-tls::asn1-node-value (first (pure-tls::asn1-children policy)))))))))

(defun require-internal-certificate-profile (certificate ca)
  "Retain legacy direct-root credentials while rejecting API-profile leaves for internal protocols."
  (when (api-csr-profile-certificate-p certificate)
    (pki-fail "certificate-purpose-mismatch" "API-issued credentials cannot authenticate an internal node or control server"))
  (unless (handler-case (pure-tls::verify-certificate-signature certificate ca) (error () nil))
    (pki-fail "invalid-enrollment-issuer" "Internal credentials require a direct enrollment-root signature"))
  t)
