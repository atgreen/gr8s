;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Parse actual PKCS#10 PEM/DER requests and verify their signatures with the
;;;; declared public key. Extract signed subjects and requested SANs for approved
;;;; signing, and validate real PEM certificate chains submitted to CSR status.
;;;; No certificate or successful verification is inferred from object fields.

(in-package #:gr8s)

(defstruct parsed-certificate-request
  "Retain only cryptographically verified request material for signer policy."
  subject subject-der spki spki-der sans san-extension)

(defun csr-invalid (control &rest arguments)
  "Report Kubernetes admission failure without exposing private PKI material."
  (apply #'core-resource-error 422 "Invalid" control arguments))

(defun csr-pem-blocks (bytes)
  "Decode actual complete PEM blocks, retaining labels and rejecting PEM headers."
  (let ((text (trivial-utf-8:utf-8-bytes-to-string bytes)) (offset 0) (blocks nil))
    (loop for begin = (search "-----BEGIN " text :start2 offset) while begin
          do (let* ((label-start (+ begin 11)) (label-end (search "-----" text :start2 label-start))
                    (label (and label-end (subseq text label-start label-end)))
                    (end-marker (and label (format nil "-----END ~A-----" label)))
                    (end (and end-marker (search end-marker text :start2 (+ label-end 5)))))
               (unless end (csr-invalid "Malformed PEM block"))
               (let* ((encoded (subseq text (+ label-end 5) end))
                      (clean (remove-if (lambda (character) (find character '(#\Space #\Tab #\Return #\Linefeed))) encoded)))
                 (when (find #\: clean) (csr-invalid "PEM headers are not permitted"))
                 (push (cons label (handler-case (core-base64-bytes clean "PEM block")
                                    (kubernetes-error () (csr-invalid "Invalid PEM block encoding")))) blocks))
               (setf offset (+ end (length end-marker)))))
    (nreverse blocks)))

(defun csr-requested-extensions (info)
  "Extract signed extensionRequest attributes and reject duplicate extension OIDs."
  (let ((extensions nil) (seen (make-hash-table :test #'equal)))
    (dolist (attribute (and (fourth (pure-tls::asn1-children info))
                           (pure-tls::asn1-children (fourth (pure-tls::asn1-children info)))))
      (let ((parts (pure-tls::asn1-children attribute)))
        (unless (= 2 (length parts)) (csr-invalid "Invalid CSR attribute"))
        (when (equal '(1 2 840 113549 1 9 14) (pure-tls::asn1-node-value (first parts)))
          (dolist (extension-list (pure-tls::asn1-children (second parts)))
            (dolist (extension (pure-tls::asn1-children extension-list))
              (let* ((fields (pure-tls::asn1-children extension))
                     (oid (pure-tls::asn1-node-value (first fields))))
                (unless (and (member (length fields) '(2 3)) (listp oid))
                  (csr-invalid "Invalid requested CSR extension"))
                (when (gethash oid seen) (csr-invalid "Duplicate requested CSR extension"))
                (setf (gethash oid seen) t)
                ;; Parsing also validates known SAN/usage/basic constraint DER.
                (pure-tls::parse-x509-extension extension)
                (push extension extensions)))))))
    (nreverse extensions)))

(defun validate-csr-pss-parameters (algorithm parameters)
  "Match Go x509 PSS rules instead of inferring salt or ignoring MGF parameters."
  (let* ((node (second (pure-tls::asn1-children algorithm)))
         (fields (and node (pure-tls::asn1-children node)))
         (seen (make-hash-table))
         (hash-size (cdr (assoc (getf parameters :hash) '((:sha256 . 32) (:sha384 . 48) (:sha512 . 64))))))
    (unless (and node (pure-tls::asn1-sequence-p node) hash-size) (csr-invalid "Unsupported RSA-PSS hash parameters"))
    (dolist (field fields)
      (let ((tag (pure-tls::asn1-node-tag field)))
        (unless (and (pure-tls::asn1-context-p field tag) (<= 0 tag 3) (not (gethash tag seen))
                     (= 1 (length (pure-tls::asn1-children field))))
          (csr-invalid "Invalid RSA-PSS parameter structure"))
        (setf (gethash tag seen) (first (pure-tls::asn1-children field)))))
    (let* ((hash (gethash 0 seen)) (mask (gethash 1 seen)) (salt (gethash 2 seen)) (trailer (gethash 3 seen))
           (mask-parts (and mask (pure-tls::asn1-children mask))))
      (unless (and hash mask salt (= 2 (length mask-parts))
                   (equal '(1 2 840 113549 1 1 8) (pure-tls::asn1-node-value (first mask-parts)))
                   (equal (pure-tls::asn1-node-value (first (pure-tls::asn1-children hash)))
                          (pure-tls::asn1-node-value (first (pure-tls::asn1-children (second mask-parts)))))
                   (eql hash-size (pure-tls::asn1-node-value salt))
                   (or (not trailer) (eql 1 (pure-tls::asn1-node-value trailer))))
        (csr-invalid "RSA-PSS requires matching MGF1/hash, digest-length salt and trailer 1")))))

(defun parse-and-verify-certificate-request (bytes)
  "Validate PKCS#10 structure and its actual RSA/ECDSA/EdDSA proof of possession."
  (handler-case
      (let* ((blocks (csr-pem-blocks bytes)) (block (first blocks)))
        (unless (and block (equal "CERTIFICATE REQUEST" (car block)))
          (csr-invalid "spec.request must contain a CERTIFICATE REQUEST PEM block"))
        (let* ((der (cdr block)) (root (pure-tls::parse-der der))
               (children (pure-tls::asn1-children root))
               (info (first children)) (parts (and info (pure-tls::asn1-children info)))
               (signature (third children)))
          (unless (and (pure-tls::asn1-sequence-p root) (= 3 (length children))
                       (equalp der (pure-tls::asn1-node-raw-bytes root))
                       (pure-tls::asn1-sequence-p info) (<= 3 (length parts) 4)
                       (eql 0 (pure-tls::asn1-node-value (first parts)))
                       (= pure-tls::+asn1-bit-string+ (pure-tls::asn1-node-tag signature))
                       (eql 0 (getf (pure-tls::asn1-node-value signature) :unused-bits)))
            (csr-invalid "Invalid PKCS#10 request structure"))
          (multiple-value-bind (algorithm parameters)
              (pure-tls::parse-algorithm-identifier-with-params (second children))
            (when (member algorithm '(:rsa-pss :rsassa-pss))
              (validate-csr-pss-parameters (second children) parameters))
            (let* ((spki (pure-tls::parse-subject-public-key-info (third parts)))
                   (verified (pure-tls::verify-certificate-signature
                              (pure-tls::make-x509-certificate
                               :tbs-raw (pure-tls::asn1-node-raw-bytes info) :signature-algorithm algorithm
                               :signature-algorithm-params parameters :signature (getf (pure-tls::asn1-node-value signature) :data))
                              (pure-tls::make-x509-certificate :subject-public-key-info spki)))
                   (extensions (and verified (csr-requested-extensions info)))
                   (san (find '(2 5 29 17) extensions :test #'equal
                              :key (lambda (extension) (pure-tls::asn1-node-value (first (pure-tls::asn1-children extension)))))))
              (unless verified (csr-invalid "CSR signature verification failed"))
              (make-parsed-certificate-request
               :subject (pure-tls::parse-name (second parts)) :subject-der (pure-tls::asn1-node-raw-bytes (second parts))
               :spki spki :spki-der (pure-tls::asn1-node-raw-bytes (third parts))
               :sans (and san (pure-tls::x509-extension-value (pure-tls::parse-x509-extension san)))
               :san-extension (and san (pure-tls::asn1-node-raw-bytes san)))))))
    (kubernetes-error (condition) (error condition))
    (error (condition) (csr-invalid "Could not parse or verify CSR: ~A" condition))))

(defun validate-csr-certificate-chain (bytes)
  "Require actual X.509 certificates in every PEM block without imposing signer policy."
  (unless (zerop (length bytes))
    (handler-case
        (let ((blocks (csr-pem-blocks bytes)))
          (unless blocks (csr-invalid "status.certificate requires at least one certificate PEM block"))
          (dolist (block blocks)
            (unless (equal "CERTIFICATE" (car block)) (csr-invalid "Only CERTIFICATE PEM blocks are allowed"))
            (pure-tls:parse-certificate (cdr block))))
      (kubernetes-error (condition) (error condition))
      (error (condition) (csr-invalid "Invalid certificate data: ~A" condition))))
  bytes)
