;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify genuine independently generated RSA/ECDSA/Ed25519 CSR signatures and
;;;; signed SAN extraction, reject tampered requests and malformed PEM, and parse
;;;; certificate-chain status data without confusing that with trust/issuance.
;;;; OpenSSL is a fixture generator only; production validation uses pure-tls.

(in-package #:gr8s/tests)
(def-suite csr-crypto :in gr8s)
(in-suite csr-crypto)

(defun csr-crypto-fixture (directory algorithm &key certificate (subject "/CN=fixture.example/O=fixture") (sans "DNS:fixture.example,IP:127.0.0.1") extra-extensions)
  "Generate an independent actual key/request or certificate in a disposable directory."
  (let* ((key (merge-pathnames (format nil "~A-key.pem" algorithm) directory))
         (output (merge-pathnames (format nil "~A-~A.pem" algorithm (if certificate "cert" "request")) directory))
         (key-arguments (cond ((equal algorithm "rsa") '("rsa:2048"))
                              ((equal algorithm "ec") '("ec" "-pkeyopt" "ec_paramgen_curve:P-256"))
                              (t '("ed25519")))))
    (uiop:run-program (append (list "openssl" "req" (if certificate "-x509" "-new") "-newkey") key-arguments
                             (list "-nodes" "-subj" subject)
                             (when sans (list "-addext" (concatenate 'string "subjectAltName=" sans)))
                             (loop for extension in extra-extensions append (list "-addext" extension))
                             (list "-keyout" (namestring key) "-out" (namestring output)))
                      :output :string :error-output :string)
    (pure-tls::read-file-bytes output)))

(test independent-csr-signature-algorithms-and-signed-sans
  (with-temporary-store (store directory)
    (declare (ignore store))
    (dolist (algorithm '("rsa" "ec" "ed25519"))
      (let* ((bytes (csr-crypto-fixture directory algorithm))
             (parsed (gr8s::parse-and-verify-certificate-request bytes))
             (der (copy-seq (cdar (gr8s::csr-pem-blocks bytes)))))
        (is (equal "fixture.example" (cdr (assoc :common-name (pure-tls::x509-name-rdns (gr8s::parsed-certificate-request-subject parsed))))))
        (is (= 2 (length (gr8s::parsed-certificate-request-sans parsed))))
        (is-true (gr8s::parsed-certificate-request-san-extension parsed))
        (setf (aref der (1- (length der))) (logxor 1 (aref der (1- (length der)))))
        (signals kubernetes-error
          (gr8s::parse-and-verify-certificate-request
           (trivial-utf-8:string-to-utf-8-bytes (pure-tls/acme::wrap-pem "CERTIFICATE REQUEST" der))))))))

(test csr-pem-label-structure-and-real-certificate-status-validation
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((certificate (csr-crypto-fixture directory "ec" :certificate t))
           (request (csr-crypto-fixture directory "rsa"))
           (text (trivial-utf-8:utf-8-bytes-to-string certificate)))
      (is (equalp certificate (gr8s::validate-csr-certificate-chain certificate)))
      (is (= 0 (length (gr8s::validate-csr-certificate-chain #()))))
      (is-true (gr8s::validate-csr-certificate-chain (concatenate '(vector (unsigned-byte 8)) certificate certificate)))
      (signals kubernetes-error (gr8s::parse-and-verify-certificate-request certificate))
      (signals kubernetes-error (gr8s::validate-csr-certificate-chain request))
      (signals kubernetes-error (gr8s::validate-csr-certificate-chain #(1 2 3)))
      (signals kubernetes-error
        (gr8s::validate-csr-certificate-chain
         (trivial-utf-8:string-to-utf-8-bytes
          (concatenate 'string text "-----BEGIN PRIVATE KEY-----" (string #\Newline) "AQ==" (string #\Newline) "-----END PRIVATE KEY-----"))))
      (signals kubernetes-error
        (gr8s::parse-and-verify-certificate-request
         (trivial-utf-8:string-to-utf-8-bytes
          (format nil "-----BEGIN CERTIFICATE REQUEST-----~%Headers: forbidden~%AQ==~%-----END CERTIFICATE REQUEST-----~%")))))))

(test rsa-pss-verifies-declared-parameters-instead-of-inferring-a-valid-salt
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((path (merge-pathnames "pss.pem" directory)) (key (merge-pathnames "pss-key.pem" directory)))
      (uiop:run-program (list "openssl" "req" "-new" "-newkey" "rsa:2048" "-nodes" "-subj" "/CN=pss.example"
                             "-sigopt" "rsa_padding_mode:pss" "-sigopt" "rsa_pss_saltlen:digest"
                             "-keyout" (namestring key) "-out" (namestring path)) :output :string :error-output :string)
      (let* ((bytes (pure-tls::read-file-bytes path))
             (root (pure-tls::parse-der (cdar (gr8s::csr-pem-blocks bytes))))
             (parts (pure-tls::asn1-children root))
             (algorithm (copy-seq (pure-tls::asn1-node-raw-bytes (second parts))))
             (salt-position (search #(#xa2 #x03 #x02 #x01 #x20) algorithm)))
        (is-true (gr8s::parse-and-verify-certificate-request bytes))
        (is-true salt-position)
        ;; The CSR signature still correctly signs its unchanged requestInfo;
        ;; only the declared outer algorithm's salt length is now false.
        (setf (aref algorithm (+ salt-position 4)) 31)
        (signals kubernetes-error
          (gr8s::parse-and-verify-certificate-request
           (trivial-utf-8:string-to-utf-8-bytes
            (pure-tls/acme::wrap-pem "CERTIFICATE REQUEST"
             (pure-tls/acme::encode-sequence (pure-tls::asn1-node-raw-bytes (first parts)) algorithm
                                             (pure-tls::asn1-node-raw-bytes (third parts)))))))))))

(defun rewrite-and-resign-rsa-csr (request directory transform)
  "Produce genuinely signed adversarial PKCS#10 structures using the original fixture key."
  (let* ((root (pure-tls::parse-der (cdar (gr8s::csr-pem-blocks request))))
         (parts (pure-tls::asn1-children root))
         (info (pure-tls::asn1-children (first parts)))
         (key (pure-tls:load-private-key (merge-pathnames "rsa-key.pem" directory)))
         (spki (pure-tls::parse-subject-public-key-info (third info)))
         (public (pure-tls::parse-rsa-public-key (getf spki :public-key)))
         (rewritten (funcall transform info))
         (signature (pure-tls/acme::sign-csr key public rewritten)))
    (is-true (pure-tls::verify-rsa-pkcs1v15-signature public rewritten signature :sha256))
    (trivial-utf-8:string-to-utf-8-bytes
     (pure-tls/acme::wrap-pem "CERTIFICATE REQUEST"
       (pure-tls/acme::encode-sequence rewritten (pure-tls::asn1-node-raw-bytes (second parts))
                                      (pure-tls/acme::encode-bit-string signature))))))

(test valid-signature-does-not-admit-an-unknown-public-key-identifier-or-malformed-name
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((request (csr-crypto-fixture directory "rsa")))
      (dolist (kind '(:unknown-key :invalid-name))
        (let ((rewritten (rewrite-and-resign-rsa-csr request directory
                           (lambda (info)
                             (pure-tls/acme::encode-sequence
                              (pure-tls::asn1-node-raw-bytes (first info))
                              (if (eq kind :invalid-name) (pure-tls/acme::encode-integer 123)
                                  (pure-tls::asn1-node-raw-bytes (second info)))
                              (if (eq kind :unknown-key)
                                  (pure-tls/acme::encode-sequence
                                   (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid '(1 2 840 113549 1 1 99)) (pure-tls/acme::encode-null))
                                   (pure-tls::asn1-node-raw-bytes (second (pure-tls::asn1-children (third info)))))
                                  (pure-tls::asn1-node-raw-bytes (third info)))
                              (pure-tls::asn1-node-raw-bytes (fourth info)))))))
          (signals kubernetes-error (gr8s::parse-and-verify-certificate-request rewritten)))))))
