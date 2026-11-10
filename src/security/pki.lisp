;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Persist cluster trust and node-bound enrollment credentials, validate real
;;;; signed requests and internal certificate profiles, and issue only identities
;;;; controlled by the appropriate enrollment or control-server issuer policy.

(in-package #:gr8s.security)

(define-condition pki-error (error)
  ((reason :initarg :reason :reader pki-error-reason)
   (message :initarg :message :reader pki-error-message))
  (:report (lambda (condition stream)
             (format stream "~A: ~A"
                     (pki-error-reason condition)
                     (pki-error-message condition)))))

(defstruct (cluster-pki (:constructor %make-cluster-pki))
  root
  ca-certificate-path
  ca-private-key-path
  ca-certificate
  ca-private-key
  ca-fingerprint
  token-directory
  (lock (bt:make-lock "gr8s cluster PKI")))

(defparameter +pki-ca-common-name+ "gr8s cluster CA")
(defparameter +oid-basic-constraints+ '(2 5 29 19))
(defparameter +oid-key-usage+ '(2 5 29 15))
(defparameter +oid-extended-key-usage+ '(2 5 29 37))
(defparameter +oid-client-auth+ '(1 3 6 1 5 5 7 3 2))

(defun cluster-pki-trust-certificates (pki)
  "Return every CA in the current transition bundle, active signer first."
  (pure-tls:load-certificate-chain (cluster-pki-ca-certificate-path pki)))

(defun pki-fail (reason control &rest arguments)
  "Signal a structured PKI failure with a stable reason and formatted message."
  (error 'pki-error
         :reason reason
         :message (apply #'format nil control arguments)))

(defun octets-to-hex (octets)
  "Encode octets as two hexadecimal digits each."
  (with-output-to-string (stream)
    (loop for octet across octets
          do (format stream "~2,'0x" octet))))

(defun hex-to-octets (string)
  "Decode hexadecimal token material or fail without using malformed identifiers."
  (unless (evenp (length string))
    (pki-fail "invalid-token" "Malformed hexadecimal token material"))
  (handler-case
      (let ((octets (make-array (/ (length string) 2)
                                :element-type '(unsigned-byte 8))))
        (loop for index below (length octets)
              do (setf (aref octets index)
                       (parse-integer string
                                      :start (* index 2)
                                      :end (+ (* index 2) 2)
                                      :radix 16)))
        octets)
    (error ()
      (pki-fail "invalid-token" "Malformed hexadecimal token material"))))

(defun pki-ascii-octets (string)
  "Encode ASCII characters as octets and reject non-ASCII input."
  (let ((octets (make-array (length string) :element-type '(unsigned-byte 8))))
    (loop for character across string
          for index from 0
          for code = (char-code character)
          do (when (> code 127)
               (pki-fail "invalid-node-name" "Node names must contain only ASCII characters"))
             (setf (aref octets index) code))
    octets))

(defun valid-node-name-p (name)
  "Recognize a bounded node name using the existing enrollment character rules."
  (and (stringp name)
       (<= 1 (length name) 253)
       (not (member (char name 0) '(#\- #\.) :test #'char=))
       (not (member (char name (1- (length name))) '(#\- #\.) :test #'char=))
       (loop for character across name
             always (or (alphanumericp character)
                        (char= character #\-)
                        (char= character #\.)))))

(defun ensure-valid-node-name (name)
  "Return a valid enrollment node name or signal a structured identity failure."
  (unless (valid-node-name-p name)
    (pki-fail "invalid-node-name" "Invalid node name ~S" name))
  name)

(defun write-private-text-exclusively (path text)
  "Create a new UTF-8 credential file with mode0600 and refuse existing paths.
TEXT is a string, or a function that writes the text to the stream it is given."
  (ensure-directories-exist path)
  (let ((descriptor
          (sb-posix:open (namestring path)
                         (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl)
                         #o600)))
    (let ((stream (sb-sys:make-fd-stream descriptor
                                         :output t
                                         :element-type 'character
                                         :external-format :utf-8
                                         :auto-close t)))
      (unwind-protect
           (if (functionp text) (funcall text stream) (write-string text stream))
        (close stream))))
  path)

(defun private-temporary-path (target)
  "Choose a random sibling pathname for an atomic credential update."
  (make-pathname
   :name (format nil ".~A-~A"
                 (pathname-name target)
                 (octets-to-hex (ironclad:random-data 12)))
   :type "tmp"
   :defaults target))

(defun write-private-text-atomically (path text)
  "Replace credential text through an exclusive private temporary file."
  (let ((temporary (private-temporary-path path)))
    (unwind-protect
         (progn
           (write-private-text-exclusively temporary text)
           (uiop:rename-file-overwriting-target temporary path))
      (when (probe-file temporary)
        (delete-file temporary))))
  path)

(defun write-public-text-exclusively (path text)
  "Create new public certificate text without overwriting an existing file."
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :if-exists :error
                          :if-does-not-exist :create)
    (write-string text stream))
  path)

(defun random-positive-serial ()
  "Generate a nonzero random certificate serial number."
  (let ((serial (ironclad:octets-to-integer (ironclad:random-data 16))))
    (if (zerop serial) 1 serial)))

(defun ecdsa-signature-der (raw-signature)
  "Encode fixed-width ECDSA scalars as minimal positive DER integers."
  ;; The ACME byte-array encoder retains redundant leading zeroes. The TLS
  ;; encoder converts scalars to integers first, as required by strict DER.
  (pure-tls::encode-ecdsa-signature-der raw-signature))

(defun ecdsa-sign-der (private-key bytes)
  "Sign certificate bytes using canonical DER without relaxing verification."
  (ecdsa-signature-der
   (ironclad:sign-message private-key
                          (ironclad:digest-sequence :sha256 bytes))))

(defun subject-public-key-identifier (subject-public-key)
  "RFC5280 method1 identifier: SHA-1 over the public-key BIT STRING value."
  (ironclad:digest-sequence :sha1
    (getf (pure-tls::parse-subject-public-key-info (pure-tls::parse-der subject-public-key)) :public-key)))

(defun certificate-issuer-key-identifier (certificate)
  "Use the issuer's actual SKI, including non-default identifiers; derive for legacy CAs."
  (let ((extension (find :subject-key-identifier (pure-tls::x509-certificate-extensions certificate)
                         :key #'pure-tls::x509-extension-oid)))
    (if extension
        (let ((node (pure-tls::parse-der (pure-tls::x509-extension-value extension))))
          (unless (and (= 0 (pure-tls::asn1-node-class node))
                       (not (pure-tls::asn1-node-constructed node))
                       (= 4 (pure-tls::asn1-node-tag node))
                       (plusp (length (pure-tls::asn1-node-value node))))
            (pki-fail "invalid-ca-key-identifier" "Issuer subject key identifier is malformed"))
          (pure-tls::asn1-node-value node))
        (ironclad:digest-sequence :sha1
          (getf (pure-tls::x509-certificate-subject-public-key-info certificate) :public-key)))))

(defun certificate-key-identifier-extensions (subject-id authority-id)
  (list (pure-tls/acme::encode-extension '(2 5 29 14) (pure-tls/acme::encode-octet-string subject-id))
        (pure-tls/acme::encode-extension '(2 5 29 35)
          (pure-tls/acme::encode-sequence (pure-tls/acme::encode-der #x80 authority-id)))))

(defun certificate-der (issuer subject subject-public-key extensions signer &key issuer-certificate)
  "Sign a direct leaf with the supplied issuer, subject, public key and policy extensions."
  (let* ((algorithm
           (pure-tls/acme::encode-sequence
            (pure-tls/acme::encode-oid pure-tls/acme::*oid-ecdsa-with-sha256*)))
         (now (get-universal-time))
         (tbs
           (pure-tls/acme::encode-sequence
            (pure-tls/acme::encode-context-tag
             0 (pure-tls/acme::encode-integer 2))
            (pure-tls/acme::encode-integer (random-positive-serial))
            algorithm
            issuer
            (pure-tls/acme::encode-validity
             (- now 300) (+ now (* 365 24 60 60)))
            subject
            subject-public-key
            (pure-tls/acme::encode-x509-extensions
             (append extensions
                     (certificate-key-identifier-extensions
                      (subject-public-key-identifier subject-public-key)
                      (if issuer-certificate
                          (certificate-issuer-key-identifier issuer-certificate)
                          (let ((point (getf (ironclad:destructure-private-key signer) :y)))
                            (unless point (pki-fail "invalid-ca-key" "Certificate issuer requires an EC key"))
                            (ironclad:digest-sequence :sha1 point)))))))))
    (pure-tls/acme::encode-sequence
     tbs algorithm
     (pure-tls/acme::encode-bit-string (ecdsa-sign-der signer tbs)))))

(defun ca-certificate-der (private-key public-key &key (common-name +pki-ca-common-name+))
  "Sign a self-issued CA with a zero subordinate-CA path length."
  (let* ((name (pure-tls/acme::encode-subject common-name))
         (basic-constraints
           (pure-tls/acme::encode-critical-extension
            +oid-basic-constraints+
            (pure-tls/acme::encode-sequence
             (pure-tls/acme::encode-der #x01 #(#xff))
             (pure-tls/acme::encode-integer 0))))
         (key-usage
           (pure-tls/acme::encode-critical-extension
            +oid-key-usage+
            (pure-tls/acme::encode-bit-string #(#x06) 1))))
    (let* ((algorithm
             (pure-tls/acme::encode-sequence
              (pure-tls/acme::encode-oid pure-tls/acme::*oid-ecdsa-with-sha256*)))
           (now (get-universal-time))
           (tbs
             (pure-tls/acme::encode-sequence
              (pure-tls/acme::encode-context-tag
               0 (pure-tls/acme::encode-integer 2))
              (pure-tls/acme::encode-integer (random-positive-serial))
              algorithm name
              (pure-tls/acme::encode-validity
               (- now 300) (+ now (* 10 365 24 60 60)))
              name
              (pure-tls/acme::encode-ec-public-key public-key)
              (pure-tls/acme::encode-x509-extensions
               (append (list basic-constraints key-usage)
                       (let ((identifier (subject-public-key-identifier (pure-tls/acme::encode-ec-public-key public-key))))
                         (certificate-key-identifier-extensions identifier identifier)))))))
      (pure-tls/acme::encode-sequence
       tbs algorithm
       (pure-tls/acme::encode-bit-string (ecdsa-sign-der private-key tbs))))))

(defun create-cluster-ca (certificate-path private-key-path)
  "Create a fresh CA certificate and private key without overwriting persisted credentials."
  (multiple-value-bind (private-key public-key)
      (ironclad:generate-key-pair :secp256r1)
    (let* ((certificate-der (ca-certificate-der private-key public-key))
           (certificate-pem
             (pure-tls/acme::wrap-pem "CERTIFICATE" certificate-der))
           (private-key-pem
             (pure-tls/acme::encode-ec-private-key-pem private-key)))
      (write-private-text-exclusively private-key-path private-key-pem)
      (handler-case
          (write-public-text-exclusively certificate-path certificate-pem)
        (error (condition)
          (ignore-errors (delete-file private-key-path))
          (error condition))))))

(defun ensure-cluster-pki (root)
  "Load persisted cluster trust or create a new pair, rejecting incomplete state."
  (let* ((root (uiop:ensure-directory-pathname root))
         (pki-directory (merge-pathnames "pki/" root))
         (certificate-path (merge-pathnames "cluster-ca.crt" pki-directory))
         (private-key-path (merge-pathnames "cluster-ca.key" pki-directory))
         (token-directory (merge-pathnames "tokens/" root)))
    (ensure-directories-exist pki-directory)
    (ensure-directories-exist token-directory)
    (cond
      ((and (probe-file certificate-path) (probe-file private-key-path)))
      ((or (probe-file certificate-path) (probe-file private-key-path))
       (pki-fail "incomplete-pki" "Cluster CA certificate and key must both exist"))
      (t
       (create-cluster-ca certificate-path private-key-path)))
    (handler-case
        (let* ((certificate
                 (or (first (pure-tls:load-certificate-chain certificate-path))
                     (pki-fail "invalid-ca" "Cluster CA certificate is empty")))
               (private-key (pure-tls:load-private-key private-key-path)))
          (unless (pure-tls::certificate-is-ca-p certificate)
            (pki-fail "invalid-ca" "Cluster certificate is not a CA"))
          (%make-cluster-pki
           :root root
           :ca-certificate-path certificate-path
           :ca-private-key-path private-key-path
           :ca-certificate certificate
           :ca-private-key private-key
           :ca-fingerprint
           (octets-to-hex (pure-tls:certificate-fingerprint certificate))
           :token-directory token-directory))
      (pki-error (condition) (error condition))
      (error (condition)
        (pki-fail "invalid-ca" "Could not load cluster CA: ~A" condition)))))

(defun token-path (pki identifier)
  "Locate the server-owned state record for a validated token identifier."
  (merge-pathnames (format nil "~A.json" identifier)
                   (cluster-pki-token-directory pki)))

(defun token-digest (salt secret)
  "Hash a join secret together with its server-generated salt."
  (ironclad:digest-sequence
   :sha256
   (concatenate '(vector (unsigned-byte 8)) salt (pki-ascii-octets secret))))

(defun join-token-role-name (role)
  "Return ROLE's persisted lower-case name, or reject an unknown trust role."
  (let ((name (string-downcase (string role))))
    (unless (member name '("node" "voter" "witness") :test #'string=)
      (pki-fail "invalid-token-role" "Unknown join-token role ~A" role))
    name))

(defun token-record-json (node-name salt digest state role)
  "Serialize node and role binding, salted digest and one-time enrollment state."
  (let ((record (make-hash-table :test #'equal)))
    (setf (gethash "nodeName" record) node-name
          (gethash "role" record) (join-token-role-name role)
          (gethash "salt" record) (octets-to-hex salt)
          (gethash "digest" record) (octets-to-hex digest)
          (gethash "state" record) state)
    (with-output-to-string (stream)
      (com.inuoe.jzon:stringify record :stream stream))))

(defun create-join-token (pki node-name &key (role :node))
  "Persist a new unused node-and-role-bound token digest and return its one-time secret."
  (ensure-valid-node-name node-name)
  (let ((role (join-token-role-name role)))
    (bt:with-lock-held ((cluster-pki-lock pki))
      (loop
        for identifier = (octets-to-hex (ironclad:random-data 12))
        for secret = (octets-to-hex (ironclad:random-data 32))
        for path = (token-path pki identifier)
        unless (probe-file path)
          do (let* ((salt (ironclad:random-data 16))
                    (digest (token-digest salt secret)))
               (write-private-text-exclusively
                path (token-record-json node-name salt digest "unused" role))
               (return (format nil "~A.~A" identifier secret)))))))

(defun split-join-token (token)
  "Validate token shape and hexadecimal identifier material before pathname use."
  (let ((separator (and (stringp token) (position #\. token))))
    (unless (and separator
                 (= separator 24)
                 (= (length token) (+ separator 1 64)))
      (pki-fail "invalid-token" "Malformed join token"))
    (let ((identifier (subseq token 0 separator))
          (secret (subseq token (1+ separator))))
      ;; Validate both halves before IDENTIFIER is used to form a pathname.
      (hex-to-octets identifier)
      (hex-to-octets secret)
      (values identifier secret))))

(defun load-token-record (pki identifier)
  "Read persisted issuance state or fail for an unknown or unreadable token."
  (let ((path (token-path pki identifier)))
    (unless (probe-file path)
      (pki-fail "invalid-token" "Unknown join token"))
    (handler-case
        (values (com.inuoe.jzon:parse path) path)
      (error ()
        (pki-fail "invalid-token" "Unreadable join-token record")))))

(defun validate-token (pki token node-name &key expected-role)
  "Check secret digest, exact node and optional role binding, and unused state."
  (multiple-value-bind (identifier secret) (split-join-token token)
    (multiple-value-bind (record path) (load-token-record pki identifier)
      (let* ((salt (hex-to-octets (gethash "salt" record)))
             (stored-digest (hex-to-octets (gethash "digest" record)))
             (presented-digest (token-digest salt secret)))
        (unless (ironclad:constant-time-equal stored-digest presented-digest)
          (pki-fail "invalid-token" "Join token secret does not match"))
        (unless (string= node-name (gethash "nodeName" record))
          (pki-fail "node-name-mismatch" "Join token belongs to a different node"))
        (let ((role (gethash "role" record)))
          (unless role
            (pki-fail "invalid-token-role" "Legacy unscoped join tokens are not accepted"))
          (join-token-role-name role)
          (when (and expected-role
                     (not (string= role (join-token-role-name expected-role))))
            (pki-fail "token-role-mismatch"
                      "Join token is bound to role ~A, not ~A" role expected-role)))
        (unless (string= "unused" (gethash "state" record))
          (pki-fail "token-already-used" "Join token has already been used"))
        (values record path salt stored-digest)))))

(defun generate-node-key-and-csr (node-name private-key-path)
  "Reuse or create the private RSA node key and return its signed enrollment request."
  (ensure-valid-node-name node-name)
  (when (probe-file private-key-path)
    ;; Failed enrollment must be retryable without replacing its private key.
    (let* ((private-key (pure-tls:load-private-key private-key-path))
           (parameters (ironclad:destructure-private-key private-key))
           (p (getf parameters :p)) (q (getf parameters :q))
           (d (getf parameters :d)) (n (getf parameters :n)))
      (unless (and p q d n)
        (pki-fail "invalid-node-key" "Existing node key must be an RSA private key"))
      (return-from generate-node-key-and-csr
        (pure-tls/acme:generate-csr
         private-key
         (ironclad:make-public-key :rsa :n n
                                  :e (ironclad::modular-inverse d (* (1- p) (1- q))))
         node-name))))
  (multiple-value-bind (private-key public-key)
      (pure-tls/acme::generate-rsa-key-with-e65537 2048)
    (let ((pem
            (pure-tls/acme::wrap-pem
             "RSA PRIVATE KEY"
             (pure-tls/acme::encode-rsa-private-key-der private-key public-key))))
      (write-private-text-exclusively private-key-path pem)
      (pure-tls/acme:generate-csr private-key public-key node-name))))

(defun parse-and-verify-node-csr (csr expected-node-name)
  "Verify the real RSA-SHA256 request and exact node CN before returning signed identity material."
  (handler-case
      (let* ((root (if (der-well-formed-p csr)
                       (pure-tls::parse-der csr)
                       (pki-fail "invalid-csr" "CSR must be a three-part DER sequence")))
             (children (pure-tls::asn1-children root)))
        (unless (and (pure-tls::asn1-sequence-p root) (= 3 (length children)))
          (pki-fail "invalid-csr" "CSR must be a three-part DER sequence"))
        (let* ((info (first children))
               (algorithm (second children))
               (signature-node (third children))
               (info-children (pure-tls::asn1-children info)))
          (unless (and (pure-tls::asn1-sequence-p info)
                       (>= (length info-children) 3)
                       (zerop (pure-tls::asn1-node-value (first info-children))))
            (pki-fail "invalid-csr" "Unsupported CSR info structure"))
          (unless (eql :sha256-with-rsa-encryption
                       (pure-tls::parse-algorithm-identifier algorithm))
            (pki-fail "invalid-csr" "CSR must use RSA with SHA-256"))
          (let* ((subject-node (second info-children))
                 (spki-node (third info-children))
                 (subject (pure-tls::parse-name subject-node))
                 (common-names
                   (loop for (oid . value) in (pure-tls::x509-name-rdns subject)
                         when (eql oid :common-name) collect value))
                 (spki (pure-tls::parse-subject-public-key-info spki-node))
                 (signature (getf (pure-tls::asn1-node-value signature-node) :data)))
            (unless (and (= 1 (length common-names))
                         (string= expected-node-name (first common-names)))
              (pki-fail "csr-name-mismatch"
                        "CSR common name does not match node ~A" expected-node-name))
            (unless (eql :rsa-encryption (getf spki :algorithm))
              (pki-fail "invalid-csr" "CSR public key must be RSA"))
            (let ((public-key
                    (pure-tls::parse-rsa-public-key (getf spki :public-key))))
              (unless (pure-tls::verify-rsa-pkcs1v15-signature
                       public-key
                       (pure-tls::asn1-node-raw-bytes info)
                       signature :sha256)
                (pki-fail "invalid-csr" "CSR signature verification failed")))
            (values (pure-tls::asn1-node-raw-bytes subject-node)
                    (pure-tls::asn1-node-raw-bytes spki-node)))))
    (pki-error (condition) (error condition))
    (error (condition)
      (pki-fail "invalid-csr" "Could not parse CSR: ~A" condition))))

(defun node-certificate-der (pki subject subject-public-key)
  "Sign the issuer-selected node subject and verified public key for client authentication."
  (let ((key-usage
          (pure-tls/acme::encode-critical-extension
           +oid-key-usage+
           (pure-tls/acme::encode-bit-string #(#xa0) 5)))
        (extended-key-usage
          (pure-tls/acme::encode-extension
           +oid-extended-key-usage+
           (pure-tls/acme::encode-sequence
            (pure-tls/acme::encode-oid +oid-client-auth+)))))
    (certificate-der
     (pure-tls/acme::encode-subject +pki-ca-common-name+)
     subject subject-public-key
     (list key-usage extended-key-usage)
     (cluster-pki-ca-private-key pki)
     :issuer-certificate (cluster-pki-ca-certificate pki))))

(defun enroll-node-csr (pki node-name token ca-fingerprint csr)
  "Issue only the validated internal node name and key; requested subject attributes cannot grant API user groups."
  (ensure-valid-node-name node-name)
  (unless (and (stringp ca-fingerprint)
               (string-equal ca-fingerprint (cluster-pki-ca-fingerprint pki)))
    (pki-fail "ca-pin-mismatch" "Presented cluster CA fingerprint does not match"))
  (bt:with-lock-held ((cluster-pki-lock pki))
    (multiple-value-bind (record path salt digest)
        (validate-token pki token node-name :expected-role :node)
      (multiple-value-bind (requested-subject subject-public-key)
          (parse-and-verify-node-csr csr node-name)
        (declare (ignore requested-subject))
        (setf (gethash "state" record) "used")
        (write-private-text-atomically
         path
         (token-record-json node-name salt digest "used" (gethash "role" record)))
        (pure-tls/acme::wrap-pem
         "CERTIFICATE"
         (node-certificate-der pki (pure-tls/acme::encode-subject node-name) subject-public-key))))))

(defun renew-authenticated-node-csr (pki node-name authenticated-certificate csr)
  "Renew the exact identity proven by an authenticated node session and CSR."
  (verify-node-certificate
   pki
   (pure-tls/acme::wrap-pem
    "CERTIFICATE" (pure-tls::x509-certificate-raw-der authenticated-certificate))
   node-name)
  (multiple-value-bind (requested-subject subject-public-key)
      (parse-and-verify-node-csr csr node-name)
    (declare (ignore requested-subject))
    (pure-tls/acme::wrap-pem
     "CERTIFICATE"
     (node-certificate-der
      pki (pure-tls/acme::encode-subject node-name) subject-public-key))))

(defun node-certificate-needs-active-ca-renewal-p (pki certificate)
  "Whether trusted CERTIFICATE is not directly issued by PKI's active CA."
  (not (handler-case
           (progn
             (require-internal-certificate-profile
              certificate (cluster-pki-ca-certificate pki))
             t)
         (error () nil))))

(defun node-certificate-issuer-fingerprint (pki certificate)
  "Return the trusted direct issuer fingerprint for internal node CERTIFICATE."
  (let ((issuer
          (find-if
           (lambda (candidate)
             (handler-case
                 (progn (require-internal-certificate-profile certificate candidate) t)
               (error () nil)))
           (cluster-pki-trust-certificates pki))))
    (unless issuer
      (pki-fail "invalid-enrollment-issuer"
                "Node certificate is not signed by a trusted enrollment root"))
    (octets-to-hex (pure-tls:certificate-fingerprint issuer))))

(defun certificate-from-pem (pem)
  "Parse a real node certificate PEM or return a structured certificate failure."
  (handler-case
      (pure-tls:parse-certificate
       (pure-tls::pem-decode
        (pure-tls::string-to-octets pem) "CERTIFICATE"))
    (error (condition)
      (pki-fail "invalid-certificate" "Could not parse node certificate: ~A" condition))))

(defun verify-node-certificate (pki certificate-pem expected-node-name)
  "Require a trusted internal-profile client certificate with exactly the expected node CN."
  (ensure-valid-node-name expected-node-name)
  (let ((certificate (certificate-from-pem certificate-pem)))
    (when (api-csr-profile-certificate-p certificate)
      (pki-fail "certificate-purpose-mismatch"
                "API-issued credentials cannot authenticate an internal node or control server"))
    (let* ((trust (cluster-pki-trust-certificates pki))
           (issuer (find-if (lambda (ca)
                              (handler-case
                                  (progn (require-internal-certificate-profile certificate ca) t)
                                (error () nil)))
                            trust)))
      (unless issuer
        (pki-fail "invalid-enrollment-issuer" "Internal credential is not signed by a trusted enrollment root"))
      (handler-case
          (pure-tls::verify-certificate-chain
           (list certificate) trust :purpose :client-auth :trust-anchor-mode :replace)
        (error (condition)
          (pki-fail "untrusted-certificate"
                    "Node certificate is not trusted by this cluster: ~A" condition)))
      (unless (equal (list expected-node-name)
                     (pure-tls:certificate-subject-common-names certificate))
        (pki-fail "certificate-name-mismatch"
                  "Node certificate does not belong to ~A" expected-node-name))
      t)))


(defparameter +node-server-common-name+ "gr8s-control")

(defun verify-node-server-certificate (certificate ca)
  "Require the trusted internal control-server profile, server purpose and hostname."
  (when (api-csr-profile-certificate-p certificate)
    (pki-fail "certificate-purpose-mismatch"
              "API-issued credentials cannot authenticate an internal node or control server"))
  (let* ((trust (if (listp ca) ca (list ca)))
         (issuer (find-if (lambda (candidate)
                            (handler-case
                                (progn (require-internal-certificate-profile certificate candidate) t)
                              (error () nil)))
                          trust)))
    (unless issuer
      (pki-fail "invalid-enrollment-issuer" "Control-server certificate is not signed by a trusted root")))
  (pure-tls::verify-certificate-chain
   (list certificate) (if (listp ca) ca (list ca))
   :purpose :server-auth :trust-anchor-mode :replace)
  (pure-tls::verify-hostname certificate +node-server-common-name+)
  t)

(defun ensure-node-server-credentials
    (pki &key (renew-within (* 90 86400)) rotate-key)
  "Reuse trusted internal server credentials or create a new persisted identity."
  (let ((certificate-path (merge-pathnames "pki/server.crt" (cluster-pki-root pki)))
        (key-path (merge-pathnames "pki/server.key" (cluster-pki-root pki))))
    (bt:with-lock-held ((cluster-pki-lock pki))
      (gr8s.apiserver::finish-pending-leaf-rotation certificate-path key-path)
      (cond
        ((and (probe-file certificate-path) (probe-file key-path))
         (let ((leaf (first (pure-tls:load-certificate-chain certificate-path))))
           (verify-node-server-certificate leaf (cluster-pki-trust-certificates pki))
           (when (or (gr8s.apiserver::certificate-renewal-due-p
                      certificate-path renew-within)
                     (node-certificate-needs-active-ca-renewal-p pki leaf))
             (gr8s.apiserver::issue-cluster-certificate
              pki certificate-path key-path +node-server-common-name+ nil
              :server t :dns-names (list +node-server-common-name+)
              :rotate-key rotate-key))))
        ((not (eql (not (null (probe-file certificate-path)))
                   (not (null (probe-file key-path)))))
         (if (probe-file certificate-path)
             (pki-fail "incomplete-server-identity" "Control-plane TLS certificate exists without its key")
             (gr8s.apiserver::issue-cluster-certificate
              pki certificate-path key-path +node-server-common-name+ nil
              :server t :dns-names (list +node-server-common-name+))))
        (t
         (gr8s.apiserver::issue-cluster-certificate
          pki certificate-path key-path +node-server-common-name+ nil
          :server t :dns-names (list +node-server-common-name+)
          :rotate-key rotate-key)))
    (values certificate-path key-path))))
