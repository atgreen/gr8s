;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Sign only explicitly approved, non-denied and non-failed requests for the
;;;; three built-in Kubernetes signer policies. Certificates use the actual
;;;; cluster CA, signed request subject/public key, permitted SANs/usages and
;;;; requested bounded lifetime; custom signers remain legitimately Pending.

(in-package #:gr8s)

(defparameter *csr-signer-clock* #'get-universal-time)
(defparameter *csr-certificate-duration* (* 365 24 60 60))
(defparameter *csr-built-in-signers*
  '("kubernetes.io/kube-apiserver-client" "kubernetes.io/kube-apiserver-client-kubelet" "kubernetes.io/kubelet-serving"))

(defun csr-true-condition-p (object type)
  "Require a real affirmative condition, never condition presence alone."
  (let ((condition (csr-condition (gethash "status" object) type)))
    (and condition (equal "True" (gethash "status" condition)))))

(defun csr-ready-for-signing-p (object)
  "Require explicit approval, a supported signer and no completed or failed issuance."
  (and (member (gethash "signerName" (gethash "spec" object)) *csr-built-in-signers* :test #'equal)
       (csr-true-condition-p object "Approved") (not (csr-true-condition-p object "Denied"))
       (not (csr-true-condition-p object "Failed"))
       (not (gethash "deletionTimestamp" (gethash "metadata" object)))
       (zerop (length (gethash "certificate" (gethash "status" object) "")))))

(defun csr-signer-policy-failure (parsed spec)
  "Return an upstream signer policy failure, or NIL for a genuine eligible request."
  (let* ((signer (gethash "signerName" spec)) (usages (coerce (gethash "usages" spec) 'list))
         (serving (equal signer "kubernetes.io/kubelet-serving"))
         (subject (pure-tls::x509-name-rdns (parsed-certificate-request-subject parsed)))
         (sans (parsed-certificate-request-sans parsed)))
    (cond
      ((equal signer "kubernetes.io/kube-apiserver-client")
       (unless (and (member "client auth" usages :test #'equal)
                    (every (lambda (usage) (member usage '("client auth" "digital signature" "key encipherment") :test #'equal)) usages))
         "Client signer requires client auth and permits only digital signature/key encipherment"))
      ((not (equal '("system:nodes") (loop for (oid . value) in subject when (eq oid :organization-name) collect value)))
       "Kubelet CSR organization must be exactly system:nodes")
      ((not (let ((name (cdr (assoc :common-name subject)))) (and name (uiop:string-prefix-p "system:node:" name))))
       "Kubelet CSR common name must begin system:node:")
      ((not (or (and (= (length usages) 2) (member "digital signature" usages :test #'equal)
                      (member (if serving "server auth" "client auth") usages :test #'equal))
                (and (= (length usages) 3) (member "digital signature" usages :test #'equal)
                     (member "key encipherment" usages :test #'equal) (member (if serving "server auth" "client auth") usages :test #'equal))))
       "Kubelet CSR usages do not match the signer policy")
      ((and (not serving) sans) "Kubelet client CSR may not contain DNS/IP/email/URI SANs")
      ((and serving (not (some (lambda (san) (member (first san) '(:dns :ip))) sans)))
       "Kubelet serving CSR requires a DNS or IP SAN")
      ((and serving (some (lambda (san) (member (first san) '(:email :uri))) sans))
       "Kubelet serving CSR may not contain email or URI SANs"))))

(defun csr-certificate-san-extension (parsed)
  "Re-encode only parsed supported SAN forms rather than copying arbitrary requested extensions."
  (let ((sans (parsed-certificate-request-sans parsed)))
    (when sans
      (funcall (if (null (pure-tls::x509-name-rdns (parsed-certificate-request-subject parsed)))
                   #'pure-tls/acme::encode-critical-extension #'pure-tls/acme::encode-extension)
               '(2 5 29 17)
               (apply #'pure-tls/acme::encode-sequence
                 (loop for (type value) in sans collect
                   (pure-tls/acme::encode-der (ecase type (:dns #x82) (:ip #x87) (:email #x81) (:uri #x86))
                                              (if (eq type :ip) value (pki-ascii-octets value)))))))))

(defun csr-ca-subject-der (pki)
  "Preserve the actual loaded CA subject instead of assuming a fixed issuer name."
  (let* ((root (pure-tls::parse-der (pure-tls::x509-certificate-raw-der (cluster-pki-ca-certificate pki))))
         (parts (pure-tls::asn1-children (first (pure-tls::asn1-children root))))
         (version (pure-tls::asn1-context-p (first parts) 0)))
    (pure-tls::asn1-node-raw-bytes (nth (if version 5 4) parts))))

(defun sign-approved-csr-certificate (pki parsed spec)
  "Issue an actual CA-signed non-CA certificate under the validated built-in policy."
  (let* ((now (funcall *csr-signer-clock*))
         (duration (min *csr-certificate-duration* (gethash "expirationSeconds" spec *csr-certificate-duration*)))
         (ca-expiry (pure-tls::x509-certificate-validity-not-after (cluster-pki-ca-certificate pki)))
         (not-after (min ca-expiry (+ now duration (if (< duration (* 8 3600)) 0 -300))))
         (usages (gethash "usages" spec))
         (flags (logior (if (find "digital signature" usages :test #'equal) #x80 0)
                        (if (find "key encipherment" usages :test #'equal) #x20 0)))
         (algorithm (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid pure-tls/acme::*oid-ecdsa-with-sha256*)))
         (extensions (list (api-csr-profile-extension)
                           (pure-tls/acme::encode-critical-extension +oid-basic-constraints+ (pure-tls/acme::encode-sequence))
                           (pure-tls/acme::encode-extension +oid-extended-key-usage+
                             (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid
                               (if (find "server auth" usages :test #'equal) '(1 3 6 1 5 5 7 3 1) +oid-client-auth+)))))))
    (unless (> not-after now) (error "Cluster CSR signer certificate has expired"))
    (when (plusp flags)
      (push (pure-tls/acme::encode-critical-extension +oid-key-usage+
              (pure-tls/acme::encode-bit-string (vector flags) (if (logtest flags #x20) 5 7))) extensions))
    (let ((san (csr-certificate-san-extension parsed))) (when san (push san extensions)))
    (let ((tbs (pure-tls/acme::encode-sequence
                 (pure-tls/acme::encode-context-tag 0 (pure-tls/acme::encode-integer 2))
                 (pure-tls/acme::encode-integer (random-positive-serial)) algorithm (csr-ca-subject-der pki)
                 (pure-tls/acme::encode-validity (- now 300) not-after)
                 (parsed-certificate-request-subject-der parsed) (parsed-certificate-request-spki-der parsed)
                 (pure-tls/acme::encode-x509-extensions (nreverse extensions)))))
      (pure-tls/acme::wrap-pem "CERTIFICATE"
        (pure-tls/acme::encode-sequence tbs algorithm
          (pure-tls/acme::encode-bit-string (ecdsa-sign-der (cluster-pki-ca-private-key pki) tbs)))))))

(defun reconcile-certificate-signing-requests (store pki)
  "Resume approved issuance after restart; conditionally persist only the same live UID/RV."
  (dolist (snapshot (list-core-resources store "certificatesigningrequests"))
    (when (csr-ready-for-signing-p snapshot)
      (handler-case
          (block completion
            (let* ((spec (gethash "spec" snapshot)) (metadata (gethash "metadata" snapshot))
                   (parsed (parse-and-verify-certificate-request (core-base64-bytes (gethash "request" spec) "request")))
                   (failure (csr-signer-policy-failure parsed spec))
                   (certificate (unless failure
                                  (bt:with-lock-held ((cluster-pki-lock pki)) (sign-approved-csr-certificate pki parsed spec))))
                   (*csr-write-path* :status))
              (update-core-resource store "certificatesigningrequests" nil (gethash "name" metadata)
                (lambda (current)
                  (unless (and (csr-ready-for-signing-p current)
                               (equal (gethash "uid" metadata) (gethash "uid" (gethash "metadata" current)))
                               (equal (gethash "resourceVersion" metadata) (gethash "resourceVersion" (gethash "metadata" current))))
                    (return-from completion nil))
                  (let ((status (gethash "status" current)))
                    (if failure
                        (setf (gethash "conditions" status)
                              (concatenate 'vector (gethash "conditions" status #())
                                (vector (core-object "type" "Failed" "status" "True" "reason" "SignerValidationFailure" "message" failure))))
                        (setf (gethash "certificate" status) (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes certificate)))))
                  current))))
        (error (condition) (format *error-output* "gr8s certificate request signing failed: ~A~%" condition)))))
  nil)
