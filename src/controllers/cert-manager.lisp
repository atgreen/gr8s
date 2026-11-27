;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; A subset of the cert-manager API (cert-manager.io/v1). Issuer/ClusterIssuer
;;;; describe how to mint certificates; a Certificate requests one and names the
;;;; kubernetes.io/tls Secret it should land in. This control-plane controller
;;;; reconciles Certificates: it issues an EC P-256 leaf through the referenced
;;;; issuer (selfSigned, or ca signing from the in-image cluster PKI), writes the
;;;; Secret, records status (Ready, notBefore/notAfter/renewalTime), and reissues
;;;; before expiry. The resulting Secret is exactly what a Gateway HTTPS listener
;;;; consumes, so a Certificate closes the TLS loop end to end.
;;;;
;;;; Scope: this is a compatible subset, not full cert-manager. selfSigned, ca and
;;;; acme issuers are implemented; vault/venafi are rejected at admission. The ca
;;;; issuer signs from the gr8s cluster CA rather than an arbitrary Secret-held CA
;;;; (reusing the in-image PKI); Secret-sourced CAs and standalone
;;;; CertificateRequest issuance are tracked follow-ups.
;;;;
;;;; The acme issuer (Let's Encrypt or any RFC 8555 server) supports HTTP-01
;;;; through http01.gatewayHTTPRoute solvers only. It drives the pure-tls ACME
;;;; client one step per reconcile pass, keeps the account key in the Secret
;;;; named by privateKeySecretRef, and writes an acme.cert-manager.io/v1
;;;; Challenge per pending authorization. Challenges travel to every node in the
;;;; Gateway projection, where the Gateway listeners answer
;;;; /.well-known/acme-challenge/<token> before route matching. Order progress
;;;; lives in memory: a restart or leader change abandons it and starts a new
;;;; order, which the ACME server satisfies from its still-valid authorizations.

(in-package #:gr8s.controllers)

(defparameter *cert-manager-clock* #'get-universal-time
  "Indirection over the wall clock so tests can drive issuance and renewal.")

(defparameter *cert-manager-default-duration* (* 90 24 60 60)
  "Default certificate validity when spec.duration is absent (cert-manager's 90d).")

;;; ---------------------------------------------------------------------------
;;; Time helpers (RFC 3339, UTC, over Common Lisp universal time).

(defun cm-rfc3339 (universal-time)
  "Format UNIVERSAL-TIME as an RFC 3339 UTC timestamp (\"YYYY-MM-DDThh:mm:ssZ\"),
   the form cert-manager status fields use."
  (multiple-value-bind (second minute hour day month year)
      (decode-universal-time universal-time 0)
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ"
            year month day hour minute second)))

(defun cm-parse-rfc3339 (string)
  "Parse a \"YYYY-MM-DDThh:mm:ssZ\" timestamp to universal time, or NIL."
  (when (and (stringp string) (>= (length string) 19))
    (ignore-errors
     (encode-universal-time (parse-integer string :start 17 :end 19)
                            (parse-integer string :start 14 :end 16)
                            (parse-integer string :start 11 :end 13)
                            (parse-integer string :start 8 :end 10)
                            (parse-integer string :start 5 :end 7)
                            (parse-integer string :start 0 :end 4) 0))))

(defun cm-parse-duration (value)
  "Parse a cert-manager/Go-ish duration (e.g. \"2160h\", \"30m\", \"10s\", \"90d\")
   or a plain integer number of seconds. Returns seconds, or NIL."
  (cond ((integerp value) value)
        ((and (stringp value) (plusp (length value)))
         (multiple-value-bind (n end) (ignore-errors (parse-integer value :junk-allowed t))
           (when (and n (plusp n))
             (case (char value (1- (length value)))
               (#\h (* n 3600)) (#\m (* n 60)) (#\s n) (#\d (* n 86400))
               (t (and (eql end (length value)) n))))))
        (t nil)))

;;; ---------------------------------------------------------------------------
;;; Leaf issuance (reuses the gr8s PKI signing primitives).

(defun cm-subject-alt-names (&key dns-names ip-addresses uris email-addresses)
  "The DER GeneralNames for a SAN: rfc822Name [1], dNSName [2], URI [6] and
   iPAddress [7] (4 or 16 octets), or NIL when there are none."
  (flet ((ia5 (tag names)
           (loop for name in names
                 collect (pure-tls/acme::encode-der tag (flexi-streams:string-to-octets
                                                         name :external-format :ascii)))))
    (let ((names (append (ia5 #x81 email-addresses)
                         (ia5 #x82 dns-names)
                         (ia5 #x86 uris)
                         (loop for address in ip-addresses
                               collect (pure-tls/acme::encode-der
                                        #x87 (or (gr8s.resources::certificate-ip-address-octets address)
                                                 (error "Certificate ipAddress ~S is not an IP address" address)))))))
      (when names
        (apply #'pure-tls/acme::encode-sequence names)))))

(defun cm-server-leaf-extensions (dns-names &key ip-addresses uris email-addresses)
  "basicConstraints CA:FALSE (critical), keyUsage digitalSignature+keyEncipherment,
   EKU serverAuth, and a SAN over DNS-NAMES, IP-ADDRESSES, URIS and EMAIL-ADDRESSES."
  (let ((extensions
          (list (pure-tls/acme::encode-critical-extension +oid-basic-constraints+
                  (pure-tls/acme::encode-sequence))
                (pure-tls/acme::encode-critical-extension +oid-key-usage+
                  (pure-tls/acme::encode-bit-string (vector #xA0) 5))  ; digitalSignature + keyEncipherment
                (pure-tls/acme::encode-extension +oid-extended-key-usage+
                  (pure-tls/acme::encode-sequence
                   (pure-tls/acme::encode-oid '(1 3 6 1 5 5 7 3 1))))))  ; serverAuth
        (alt-names (cm-subject-alt-names :dns-names dns-names :ip-addresses ip-addresses
                                         :uris uris :email-addresses email-addresses)))
    (when alt-names
      (setf extensions
            (append extensions
                    (list (pure-tls/acme::encode-extension pure-tls/acme::*oid-subject-alt-name*
                                                           alt-names)))))
    extensions))

(defun cm-issue-leaf (&key common-name dns-names ip-addresses uris email-addresses
                           duration-seconds issuer-subject-der signer-key issuer-certificate)
  "Mint an EC P-256 server leaf. For a CA issuer pass ISSUER-SUBJECT-DER and
   SIGNER-KEY (the CA); for selfSigned leave both NIL (issuer = subject, signed
   with the leaf's own key). Returns (values cert-pem key-pem not-before not-after)."
  (multiple-value-bind (private-key public-key) (ironclad:generate-key-pair :secp256r1)
    (let* ((now (funcall *cert-manager-clock*))
           (duration (or duration-seconds *cert-manager-default-duration*))
           (not-before (- now 300))
           (not-after (+ now duration))
           (common-name (or common-name (first dns-names) (first ip-addresses) ""))
           (subject (pure-tls/acme::encode-subject common-name))
           (issuer (or issuer-subject-der subject))
           (signer (or signer-key private-key))
           (algorithm (pure-tls/acme::encode-sequence
                       (pure-tls/acme::encode-oid pure-tls/acme::*oid-ecdsa-with-sha256*)))
           (tbs (pure-tls/acme::encode-sequence
                 (pure-tls/acme::encode-context-tag 0 (pure-tls/acme::encode-integer 2))
                 (pure-tls/acme::encode-integer (random-positive-serial))
                 algorithm issuer
                 (pure-tls/acme::encode-validity not-before not-after)
                 subject
                 (pure-tls/acme::encode-ec-public-key public-key)
                 (pure-tls/acme::encode-x509-extensions
                  (append (cm-server-leaf-extensions dns-names :ip-addresses ip-addresses
                                                     :uris uris :email-addresses email-addresses)
                          (gr8s.security::certificate-key-identifier-extensions
                           (gr8s.security::subject-public-key-identifier (pure-tls/acme::encode-ec-public-key public-key))
                           (if issuer-certificate
                               (gr8s.security::certificate-issuer-key-identifier issuer-certificate)
                               (ironclad:digest-sequence :sha1
                                 (getf (ironclad:destructure-private-key signer) :y))))))))
           (certificate-der (pure-tls/acme::encode-sequence
                             tbs algorithm
                             (pure-tls/acme::encode-bit-string (ecdsa-sign-der signer tbs)))))
      (values (pure-tls/acme::wrap-pem "CERTIFICATE" certificate-der)
              (pure-tls/acme::encode-ec-private-key-pem private-key)
              not-before not-after))))

;;; ---------------------------------------------------------------------------
;;; Issuer resolution.

(defun cm-resolve-issuer-spec (store namespace issuer-ref)
  "Return the issuer spec object for a Certificate's issuerRef, and the issuer
   itself, or NIL when the referenced Issuer/ClusterIssuer does not exist."
  (let ((name (and issuer-ref (gethash "name" issuer-ref)))
        (kind (or (and issuer-ref (gethash "kind" issuer-ref)) "Issuer")))
    (when name
      (let ((object (ignore-errors
                     (if (equal kind "ClusterIssuer")
                         (get-core-resource store "clusterissuers" nil name)
                         (get-core-resource store "issuers" namespace name)))))
        (and object (values (gethash "spec" object) object))))))

(defun cm-issuer-signer (pki issuer-spec)
  "Classify an issuer spec. Returns :self-signed, or (values ca-subject-der
   ca-key) for a ca issuer, or NIL for an unsupported/unknown type."
  (cond ((gethash "selfSigned" issuer-spec) :self-signed)
        ((gethash "ca" issuer-spec)
         (values (csr-ca-subject-der pki) (cluster-pki-ca-private-key pki) (cluster-pki-ca-certificate pki)))
        (t nil)))

;;; ---------------------------------------------------------------------------
;;; Secret + status writes.

(defparameter +cm-identity-annotation+ "gr8s.io/certificate-identity"
  "Secret annotation holding the digest of the Certificate identity it was issued
   for, so a changed spec (or a leaf issued before a field was honored) reissues.")

(defun cm-string-list (spec field)
  "Certificate SPEC's FIELD as a list of strings; absent or JSON null is empty."
  (let ((value (gethash field spec)))
    (if (vectorp value) (coerce value 'list) '())))

(defun cm-certificate-identity (spec)
  "A digest of what the issued leaf must say for SPEC: its subject, every SAN
   list, and the issuer that signs it."
  (let ((issuer-ref (gethash "issuerRef" spec)))
    (ironclad:byte-array-to-hex-string
     (ironclad:digest-sequence
      :sha256
      (trivial-utf-8:string-to-utf-8-bytes
       (with-standard-io-syntax
         (prin1-to-string
          (list (gethash "commonName" spec)
                (cm-string-list spec "dnsNames") (cm-string-list spec "ipAddresses")
                (cm-string-list spec "uris") (cm-string-list spec "emailAddresses")
                (and (hash-table-p issuer-ref) (gethash "kind" issuer-ref))
                (and (hash-table-p issuer-ref) (gethash "name" issuer-ref))))))))))

(defun cm-tls-secret-data (cert-pem key-pem)
  "Build the data map for a kubernetes.io/tls Secret: base64-encoded \"tls.crt\"
   and \"tls.key\" entries from CERT-PEM and KEY-PEM."
  (core-object "tls.crt" (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes cert-pem))
               "tls.key" (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes key-pem))))

(defun cm-write-tls-secret (store namespace secret-name cert-pem key-pem certificate)
  "Create or update the kubernetes.io/tls Secret, owned by CERTIFICATE and
   annotated with the identity it was issued for."
  (let ((data (cm-tls-secret-data cert-pem key-pem))
        (identity (cm-certificate-identity (gethash "spec" certificate))))
    (if (ignore-errors (get-core-resource store "secrets" namespace secret-name))
        (update-core-resource store "secrets" namespace secret-name
          (lambda (existing)
            (let ((metadata (gethash "metadata" existing)))
              (unless (hash-table-p (gethash "annotations" metadata))
                (setf (gethash "annotations" metadata) (core-object)))
              (setf (gethash +cm-identity-annotation+ (gethash "annotations" metadata)) identity))
            (setf (gethash "type" existing) "kubernetes.io/tls"
                  (gethash "data" existing) data)
            existing))
        (let* ((owner-md (gethash "metadata" certificate))
               (object (core-object
                        "apiVersion" "v1" "kind" "Secret"
                        "metadata" (core-object
                                    "name" secret-name "namespace" namespace
                                    "annotations" (core-object +cm-identity-annotation+ identity)
                                    "ownerReferences"
                                    (vector (core-object "apiVersion" "cert-manager.io/v1"
                                                         "kind" "Certificate"
                                                         "name" (gethash "name" owner-md)
                                                         "uid" (gethash "uid" owner-md))))
                        "type" "kubernetes.io/tls" "data" data)))
          (create-core-resource store "secrets" object namespace)))))

(defun cm-renewal-time (spec not-before not-after)
  "RENEWAL-TIME = not-after - renewBefore (default renewBefore = 1/3 of the validity)."
  (let* ((validity (- not-after not-before))
         (renew-before (or (cm-parse-duration (gethash "renewBefore" spec)) (floor validity 3))))
    (- not-after renew-before)))

(defun cm-set-ready-status (store namespace name not-before not-after renewal-time)
  "Write the Ready status onto the Certificate NAMESPACE/NAME in STORE: a
   Ready/True condition and the notBefore, notAfter and renewalTime timestamps.
   Best-effort -- a failed status write is swallowed."
  (ignore-errors
   (update-core-resource store "certificates" namespace name
     (lambda (certificate)
       (setf (gethash "status" certificate)
             (core-object "conditions"
                          (vector (core-object "type" "Ready" "status" "True" "reason" "Ready"
                                               "message" "Certificate has been issued"))
                          "notBefore" (cm-rfc3339 not-before)
                          "notAfter" (cm-rfc3339 not-after)
                          "renewalTime" (cm-rfc3339 renewal-time)))
       certificate))))

;;; ---------------------------------------------------------------------------
;;; Reconciliation.

(defun cm-certificate-needs-issue-p (store certificate)
  "True when CERTIFICATE has no usable Secret, its Secret was issued for a
   different identity (or before the identity was recorded), it has no status,
   or its renewalTime has arrived."
  (let* ((metadata (gethash "metadata" certificate))
         (namespace (gethash "namespace" metadata))
         (spec (gethash "spec" certificate))
         (secret-name (gethash "secretName" spec))
         (status (gethash "status" certificate))
         (secret (and secret-name (ignore-errors (get-core-resource store "secrets" namespace secret-name))))
         (annotations (and secret (gethash "annotations" (gethash "metadata" secret)))))
    (cond ((null secret) t)
          ((null (and (hash-table-p (gethash "data" secret))
                      (gethash "tls.crt" (gethash "data" secret)))) t)
          ((not (equal (cm-certificate-identity spec)
                       (and (hash-table-p annotations)
                            (gethash +cm-identity-annotation+ annotations))))
           t)
          ((null (hash-table-p status)) t)
          (t (let ((renewal (cm-parse-rfc3339 (gethash "renewalTime" status))))
               (or (null renewal) (>= (funcall *cert-manager-clock*) renewal)))))))

(defun cm-issue-certificate (store pki certificate)
  "Issue (or reissue) CERTIFICATE through its referenced issuer and persist the
   Secret and status. Returns T when it issued, NIL when it could not (missing or
   unsupported issuer, or an ACME order still in progress)."
  (let* ((metadata (gethash "metadata" certificate))
         (namespace (gethash "namespace" metadata))
         (name (gethash "name" metadata))
         (spec (gethash "spec" certificate))
         (secret-name (gethash "secretName" spec)))
    (multiple-value-bind (issuer-spec issuer) (cm-resolve-issuer-spec store namespace (gethash "issuerRef" spec))
      (when (and issuer-spec (gethash "acme" issuer-spec))
        (return-from cm-issue-certificate (cm-acme-reconcile store certificate issuer)))
      (when issuer-spec
        (multiple-value-bind (issuer-subject-der signer-key issuer-certificate) (cm-issuer-signer pki issuer-spec)
          (when issuer-subject-der                       ; NIL => unsupported issuer type
            (multiple-value-bind (cert-pem key-pem not-before not-after)
                (cm-issue-leaf :common-name (gethash "commonName" spec)
                               :dns-names (cm-string-list spec "dnsNames")
                               :ip-addresses (cm-string-list spec "ipAddresses")
                               :uris (cm-string-list spec "uris")
                               :email-addresses (cm-string-list spec "emailAddresses")
                               :duration-seconds (cm-parse-duration (gethash "duration" spec))
                               :issuer-subject-der (unless (eq issuer-subject-der :self-signed) issuer-subject-der)
                               :signer-key (unless (eq issuer-subject-der :self-signed) signer-key)
                               :issuer-certificate issuer-certificate)
              (cm-write-tls-secret store namespace secret-name cert-pem key-pem certificate)
              (cm-set-ready-status store namespace name not-before not-after
                                   (cm-renewal-time spec not-before not-after))
              t)))))))

(defun reconcile-certificates (store pki)
  "Control-plane reconcile: issue/renew every Certificate whose Secret is missing
   or due. Fail-soft per Certificate, like the other control-plane reconcilers."
  (let ((certificates (list-core-resources store "certificates")))
    (dolist (certificate certificates)
      (handler-case
          (when (cm-certificate-needs-issue-p store certificate)
            (cm-issue-certificate store pki certificate))
        (error (condition)
          (format *error-output* "gr8s: Certificate reconcile failed: ~A~%" condition))))
    (cm-acme-forget-orders-except certificates))
  store)
