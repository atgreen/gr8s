(in-package #:gr8s)

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

(defun pki-fail (reason control &rest arguments)
  (error 'pki-error
         :reason reason
         :message (apply #'format nil control arguments)))

(defun octets-to-hex (octets)
  (with-output-to-string (stream)
    (loop for octet across octets
          do (format stream "~2,'0x" octet))))

(defun hex-to-octets (string)
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
  (let ((octets (make-array (length string) :element-type '(unsigned-byte 8))))
    (loop for character across string
          for index from 0
          for code = (char-code character)
          do (when (> code 127)
               (pki-fail "invalid-node-name" "Node names must contain only ASCII characters"))
             (setf (aref octets index) code))
    octets))

(defun valid-node-name-p (name)
  (and (stringp name)
       (<= 1 (length name) 253)
       (not (member (char name 0) '(#\- #\.) :test #'char=))
       (not (member (char name (1- (length name))) '(#\- #\.) :test #'char=))
       (loop for character across name
             always (or (alphanumericp character)
                        (char= character #\-)
                        (char= character #\.)))))

(defun ensure-valid-node-name (name)
  (unless (valid-node-name-p name)
    (pki-fail "invalid-node-name" "Invalid node name ~S" name))
  name)

(defun write-private-text-exclusively (path text)
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
           (write-string text stream)
        (close stream))))
  path)

(defun private-temporary-path (target)
  (make-pathname
   :name (format nil ".~A-~A"
                 (pathname-name target)
                 (octets-to-hex (ironclad:random-data 12)))
   :type "tmp"
   :defaults target))

(defun write-private-text-atomically (path text)
  (let ((temporary (private-temporary-path path)))
    (unwind-protect
         (progn
           (write-private-text-exclusively temporary text)
           (uiop:rename-file-overwriting-target temporary path))
      (when (probe-file temporary)
        (delete-file temporary))))
  path)

(defun write-public-text-exclusively (path text)
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :if-exists :error
                          :if-does-not-exist :create)
    (write-string text stream))
  path)

(defun random-positive-serial ()
  (let ((serial (ironclad:octets-to-integer (ironclad:random-data 16))))
    (if (zerop serial) 1 serial)))

(defun ecdsa-sign-der (private-key bytes)
  (pure-tls/acme::encode-ecdsa-signature
   (ironclad:sign-message private-key
                          (ironclad:digest-sequence :sha256 bytes))))

(defun certificate-der (issuer subject subject-public-key extensions signer)
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
            (pure-tls/acme::encode-x509-extensions extensions))))
    (pure-tls/acme::encode-sequence
     tbs algorithm
     (pure-tls/acme::encode-bit-string (ecdsa-sign-der signer tbs)))))

(defun ca-certificate-der (private-key public-key)
  (let* ((name (pure-tls/acme::encode-subject +pki-ca-common-name+))
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
               (list basic-constraints key-usage)))))
      (pure-tls/acme::encode-sequence
       tbs algorithm
       (pure-tls/acme::encode-bit-string (ecdsa-sign-der private-key tbs))))))

(defun create-cluster-ca (certificate-path private-key-path)
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
  (merge-pathnames (format nil "~A.json" identifier)
                   (cluster-pki-token-directory pki)))

(defun token-digest (salt secret)
  (ironclad:digest-sequence
   :sha256
   (concatenate '(vector (unsigned-byte 8)) salt (pki-ascii-octets secret))))

(defun token-record-json (node-name salt digest state)
  (let ((record (make-hash-table :test #'equal)))
    (setf (gethash "nodeName" record) node-name
          (gethash "salt" record) (octets-to-hex salt)
          (gethash "digest" record) (octets-to-hex digest)
          (gethash "state" record) state)
    (with-output-to-string (stream)
      (com.inuoe.jzon:stringify record :stream stream))))

(defun create-join-token (pki node-name)
  (ensure-valid-node-name node-name)
  (bt:with-lock-held ((cluster-pki-lock pki))
    (loop
      for identifier = (octets-to-hex (ironclad:random-data 12))
      for secret = (octets-to-hex (ironclad:random-data 32))
      for path = (token-path pki identifier)
      unless (probe-file path)
        do (let* ((salt (ironclad:random-data 16))
                  (digest (token-digest salt secret)))
             (write-private-text-exclusively
              path (token-record-json node-name salt digest "unused"))
             (return (format nil "~A.~A" identifier secret))))))

(defun split-join-token (token)
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
  (let ((path (token-path pki identifier)))
    (unless (probe-file path)
      (pki-fail "invalid-token" "Unknown join token"))
    (handler-case
        (values (com.inuoe.jzon:parse path) path)
      (error ()
        (pki-fail "invalid-token" "Unreadable join-token record")))))

(defun validate-token (pki token node-name)
  (multiple-value-bind (identifier secret) (split-join-token token)
    (multiple-value-bind (record path) (load-token-record pki identifier)
      (let* ((salt (hex-to-octets (gethash "salt" record)))
             (stored-digest (hex-to-octets (gethash "digest" record)))
             (presented-digest (token-digest salt secret)))
        (unless (ironclad:constant-time-equal stored-digest presented-digest)
          (pki-fail "invalid-token" "Join token secret does not match"))
        (unless (string= node-name (gethash "nodeName" record))
          (pki-fail "node-name-mismatch" "Join token belongs to a different node"))
        (unless (string= "unused" (gethash "state" record))
          (pki-fail "token-already-used" "Join token has already been used"))
        (values record path salt stored-digest)))))

(defun generate-node-key-and-csr (node-name private-key-path)
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
  (handler-case
      (let* ((root (pure-tls::parse-der csr))
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
     (cluster-pki-ca-private-key pki))))

(defun enroll-node-csr (pki node-name token ca-fingerprint csr)
  (ensure-valid-node-name node-name)
  (unless (and (stringp ca-fingerprint)
               (string-equal ca-fingerprint (cluster-pki-ca-fingerprint pki)))
    (pki-fail "ca-pin-mismatch" "Presented cluster CA fingerprint does not match"))
  (bt:with-lock-held ((cluster-pki-lock pki))
    (multiple-value-bind (record path salt digest)
        (validate-token pki token node-name)
      (multiple-value-bind (subject subject-public-key)
          (parse-and-verify-node-csr csr node-name)
        (setf (gethash "state" record) "used")
        (write-private-text-atomically
         path
         (token-record-json node-name salt digest "used"))
        (pure-tls/acme::wrap-pem
         "CERTIFICATE"
         (node-certificate-der pki subject subject-public-key))))))

(defun certificate-from-pem (pem)
  (handler-case
      (pure-tls:parse-certificate
       (pure-tls::pem-decode
        (pure-tls::string-to-octets pem) "CERTIFICATE"))
    (error (condition)
      (pki-fail "invalid-certificate" "Could not parse node certificate: ~A" condition))))

(defun verify-node-certificate (pki certificate-pem expected-node-name)
  (ensure-valid-node-name expected-node-name)
  (let ((certificate (certificate-from-pem certificate-pem)))
    (handler-case
        (pure-tls::verify-certificate-chain
         (list certificate)
         (list (cluster-pki-ca-certificate pki))
         :purpose :client-auth
         :trust-anchor-mode :replace)
      (error (condition)
        (pki-fail "untrusted-certificate"
                  "Node certificate is not trusted by this cluster: ~A" condition)))
    (unless (equal (list expected-node-name)
                   (pure-tls:certificate-subject-common-names certificate))
      (pki-fail "certificate-name-mismatch"
                "Node certificate does not belong to ~A" expected-node-name))
    t))


(defparameter +node-server-common-name+ "gr8s-control")

(defun verify-node-server-certificate (certificate ca)
  (pure-tls::verify-certificate-chain
   (list certificate) (list ca) :purpose :server-auth :trust-anchor-mode :replace)
  (pure-tls::verify-hostname certificate +node-server-common-name+)
  t)

(defun ensure-node-server-credentials (pki)
  (let ((certificate-path (merge-pathnames "pki/server.crt" (cluster-pki-root pki)))
        (key-path (merge-pathnames "pki/server.key" (cluster-pki-root pki))))
    (bt:with-lock-held ((cluster-pki-lock pki))
      (cond
        ((and (probe-file certificate-path) (probe-file key-path))
         (verify-node-server-certificate
          (first (pure-tls:load-certificate-chain certificate-path))
          (cluster-pki-ca-certificate pki)))
        ((or (probe-file certificate-path) (probe-file key-path))
         (pki-fail "incomplete-server-identity" "Control-plane TLS certificate/key pair is incomplete"))
        (t
         (multiple-value-bind (private-key public-key) (ironclad:generate-key-pair :secp256r1)
           (let* ((der
                    (certificate-der
                     (pure-tls/acme::encode-subject +pki-ca-common-name+)
                     (pure-tls/acme::encode-subject +node-server-common-name+)
                     (pure-tls/acme::encode-ec-public-key public-key)
                     (list
                      (pure-tls/acme::encode-critical-extension
                       +oid-key-usage+ (pure-tls/acme::encode-bit-string #(#x80) 7))
                      (pure-tls/acme::encode-extension
                       +oid-extended-key-usage+
                       (pure-tls/acme::encode-sequence
                        (pure-tls/acme::encode-oid '(1 3 6 1 5 5 7 3 1))))
                      (pure-tls/acme::encode-extension
                       pure-tls/acme::*oid-subject-alt-name*
                       (pure-tls/acme::encode-san-extension (list +node-server-common-name+))))
                     (cluster-pki-ca-private-key pki)))
                  (chain (concatenate 'string (pure-tls/acme::wrap-pem "CERTIFICATE" der)
                                      (uiop:read-file-string (cluster-pki-ca-certificate-path pki)))))
             (write-private-text-exclusively key-path
                                            (pure-tls/acme::encode-ec-private-key-pem private-key))
             (handler-case (write-private-text-exclusively certificate-path chain)
               (error (condition)
                 (ignore-errors (delete-file key-path))
                 (error condition))))))))
    (values certificate-path key-path)))
