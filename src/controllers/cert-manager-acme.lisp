;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The cert-manager acme issuer: RFC 8555 issuance with HTTP-01 validation,
;;;; driven through the pure-tls ACME client. Each reconcile pass moves a
;;;; Certificate's order at most one step, so no pass waits on the ACME server:
;;;;
;;;;   :new        create the order; write a Challenge per pending authorization
;;;;   :presented  after a short delay for nodes to receive the Challenges,
;;;;               tell the server to validate them
;;;;   :validating poll the authorizations until they are valid
;;;;   :finalize   send a CSR for a fresh RSA key
;;;;   :issuing    poll the order, download the chain, write the TLS Secret
;;;;
;;;; A failure deletes the Challenges, records failedIssuanceAttempts and
;;;; lastFailureTime on the Certificate, and waits a doubling backoff before a
;;;; new order, so a broken setup never hammers the server's rate limits. A
;;;; Retry-After from the server defers the next step instead of sleeping.
;;;; The network sits behind generic functions on *CM-ACME-BACKEND*, so tests
;;;; drive the whole state machine without one.

(in-package #:gr8s.controllers)

(defparameter *cm-acme-backend* :pure-tls
  "What the acme issuer talks to. :pure-tls is the real client; tests bind an
   object with their own methods on the CM-ACME-* generic functions.")

(defparameter *cm-cluster-resource-namespace* "kube-system"
  "Where a ClusterIssuer's account key Secret lives (cert-manager's
   --cluster-resource-namespace). kube-system always exists in gr8s.")

(defparameter *cm-acme-present-delay* 10
  "Seconds between writing Challenges and asking the server to validate them,
   so the Gateway projection reaches every node first.")

(defparameter *cm-acme-poll-interval* 5
  "Seconds between polls of a pending authorization or order.")

(defparameter *cm-acme-order-timeout* (* 15 60)
  "Seconds an order may take from creation to download before it counts as failed.")

(defparameter *cm-acme-initial-backoff* (* 5 60)
  "Seconds to wait after a first failed order; each further failure doubles it.")

(defparameter *cm-acme-max-backoff* (* 24 60 60)
  "The longest wait between failed orders.")

(defparameter *cm-acme-connection-timeout* 15
  "Seconds to wait for a connection to the ACME server.")

;;; ---------------------------------------------------------------------------
;;; The ACME seam.

(defgeneric cm-acme-account (backend server email account-key &key skip-tls-verify)
  (:documentation "Return a client for SERVER registered with ACCOUNT-KEY, and the account URL."))
(defgeneric cm-acme-new-order (backend client domains profile)
  (:documentation "Create an order for DOMAINS. Returns (values order order-url)."))
(defgeneric cm-acme-fetch (backend client url)
  (:documentation "POST-as-GET URL (an order or authorization) and return the decoded object."))
(defgeneric cm-acme-key-authorization (backend client token)
  (:documentation "The HTTP-01 key authorization for TOKEN under the client's account key."))
(defgeneric cm-acme-respond (backend client challenge-url)
  (:documentation "Tell the server the challenge at CHALLENGE-URL is ready to validate."))
(defgeneric cm-acme-finalize (backend client finalize-url csr-der)
  (:documentation "Submit CSR-DER to FINALIZE-URL and return the decoded order."))
(defgeneric cm-acme-download (backend client certificate-url)
  (:documentation "Return the issued PEM chain at CERTIFICATE-URL, or NIL."))

(define-condition cm-acme-deferred (error)
  ((seconds :initarg :seconds :reader cm-acme-deferred-seconds))
  (:report (lambda (condition stream)
             (format stream "the ACME server asked to retry in ~D seconds"
                     (cm-acme-deferred-seconds condition)))))

(defun cm-acme-defer (seconds)
  "Stand in for the client's sleep: give up the step and come back later."
  (error 'cm-acme-deferred :seconds (max 1 (ceiling (or seconds 1)))))

(defun cm-acme-http-request (url &rest arguments)
  "The client's HTTP transport, bounded so an unreachable server can't stall a pass."
  (apply #'drakma:http-request url :connection-timeout *cm-acme-connection-timeout* arguments))

(defmacro with-cm-acme-io (&body body)
  "Run BODY's ACME requests with bounded connections and no in-pass sleeping."
  `(let ((pure-tls/acme::*sleep-function* #'cm-acme-defer)
         (pure-tls/acme::*http-request-function* #'cm-acme-http-request))
     ,@body))

(defmethod cm-acme-account ((backend (eql :pure-tls)) server email account-key &key skip-tls-verify)
  (with-cm-acme-io
    (let ((client (pure-tls/acme:make-acme-client
                   :directory-url server :skip-tls-verify (and skip-tls-verify t)
                   ;; A store that already holds the key never touches the disk.
                   :store (pure-tls/acme::%make-cert-store :account-key account-key))))
      (pure-tls/acme:client-init client)
      (values client (pure-tls/acme:client-register-account client email)))))

(defmethod cm-acme-new-order ((backend (eql :pure-tls)) client domains profile)
  (with-cm-acme-io
    (if profile
        (pure-tls/acme:client-new-order client domains :profile profile)
        (pure-tls/acme:client-new-order client domains))))

(defmethod cm-acme-fetch ((backend (eql :pure-tls)) client url)
  (with-cm-acme-io
    (values (pure-tls/acme:client-get-authorization client url))))

(defmethod cm-acme-key-authorization ((backend (eql :pure-tls)) client token)
  (pure-tls/acme:client-compute-key-authorization client token))

(defmethod cm-acme-respond ((backend (eql :pure-tls)) client challenge-url)
  (with-cm-acme-io
    (multiple-value-bind (response status) (pure-tls/acme:client-respond-challenge client challenge-url)
      (unless (member status '(200 201 202))
        (error "ACME challenge response failed: HTTP ~A ~A" status (cm-acme-problem response)))
      response)))

(defmethod cm-acme-finalize ((backend (eql :pure-tls)) client finalize-url csr-der)
  (with-cm-acme-io
    (multiple-value-bind (response status) (pure-tls/acme:client-finalize-order client finalize-url csr-der)
      (unless (member status '(200 201 202))
        (error "ACME finalize failed: HTTP ~A ~A" status (cm-acme-problem response)))
      response)))

(defmethod cm-acme-download ((backend (eql :pure-tls)) client certificate-url)
  (with-cm-acme-io
    (pure-tls/acme:client-download-certificate client certificate-url)))

;;; ---------------------------------------------------------------------------
;;; Decoded ACME objects (cl-json alists with keyword keys).

(defun cm-acme-field (object &rest path)
  "Follow the keyword PATH through a decoded ACME object."
  (dolist (key path object)
    (setf object (and (listp object) (cdr (assoc key object))))))

(defun cm-acme-problem (object)
  "A short description of the problem document in OBJECT (or its error field)."
  (let ((problem (or (cm-acme-field object :error) object)))
    (format nil "~@[~A~]~@[: ~A~]" (cm-acme-field problem :type) (cm-acme-field problem :detail))))

(defun cm-acme-authorization-problem (authorization)
  "Why AUTHORIZATION went invalid: its failed challenge's error, if it has one."
  (let ((failed (find-if (lambda (challenge) (cm-acme-field challenge :error))
                         (cm-acme-field authorization :challenges))))
    (format nil "~A: ~A" (cm-acme-field authorization :identifier :value)
            (if failed (cm-acme-problem failed) "authorization is invalid"))))

;;; ---------------------------------------------------------------------------
;;; The account.

(defun cm-acme-account-secret-namespace (issuer)
  "An Issuer keeps its account key in its own namespace, a ClusterIssuer in
   *cm-cluster-resource-namespace*."
  (or (gethash "namespace" (gethash "metadata" issuer)) *cm-cluster-resource-namespace*))

(defun cm-acme-account-key (store issuer)
  "Load the issuer's EC P-256 account key from its privateKeySecretRef Secret,
   creating the key and the Secret the first time."
  (let* ((acme (gethash "acme" (gethash "spec" issuer)))
         (reference (gethash "privateKeySecretRef" acme))
         (name (gethash "name" reference))
         (field (or (gethash "key" reference) "tls.key"))
         (namespace (cm-acme-account-secret-namespace issuer))
         (secret (ignore-errors (get-core-resource store "secrets" namespace name)))
         (encoded (and secret (hash-table-p (gethash "data" secret)) (gethash field (gethash "data" secret)))))
    (if encoded
        (pure-tls/acme::parse-ec-private-key-der
         (pure-tls/acme::extract-pem-der
          (trivial-utf-8:utf-8-bytes-to-string (ag-grpc:base64-decode encoded)) "EC PRIVATE KEY"))
        (let* ((key (ironclad:generate-key-pair :secp256r1))
               (pem (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes
                                            (pure-tls/acme::encode-ec-private-key-pem key)))))
          (if secret
              (update-core-resource store "secrets" namespace name
                (lambda (existing)
                  (unless (hash-table-p (gethash "data" existing))
                    (setf (gethash "data" existing) (core-object)))
                  (setf (gethash field (gethash "data" existing)) pem)
                  existing))
              (create-core-resource store "secrets"
                                    (core-object "apiVersion" "v1" "kind" "Secret"
                                                 "metadata" (core-object "name" name "namespace" namespace)
                                                 "type" "Opaque" "data" (core-object field pem))
                                    namespace))
          key))))

(defvar *cm-acme-clients* (make-hash-table :test 'equal)
  "Registered clients by issuer identity, so passes reuse the directory, the
   account URL and the server's last nonce.")

(defun cm-acme-issuer-identity (issuer)
  "What a cached client depends on: the issuer, its server and its key Secret."
  (let ((metadata (gethash "metadata" issuer)) (acme (gethash "acme" (gethash "spec" issuer))))
    (list (gethash "uid" metadata) (gethash "server" acme) (gethash "email" acme)
          (gethash "name" (gethash "privateKeySecretRef" acme)) (and (gethash "skipTLSVerify" acme) t))))

(defun cm-acme-issuer-resource (issuer)
  (if (equal "ClusterIssuer" (gethash "kind" issuer)) "clusterissuers" "issuers"))

(defun cm-acme-record-account (store issuer account-url)
  "Report the registered account on the issuer, as cert-manager does, once."
  (let ((metadata (gethash "metadata" issuer)))
    (unless (equal account-url (cm-acme-field-of-status issuer))
      (ignore-errors
       (update-core-resource store (cm-acme-issuer-resource issuer)
                             (gethash "namespace" metadata) (gethash "name" metadata)
         (lambda (object)
           (setf (gethash "status" object)
                 (core-object "acme" (core-object "uri" account-url)
                              "conditions" (vector (core-object "type" "Ready" "status" "True"
                                                                "reason" "ACMEAccountRegistered"
                                                                "message" "The ACME account was registered with the ACME server"))))
           object))))))

(defun cm-acme-field-of-status (issuer)
  "The account URL ISSUER's status already reports, or NIL."
  (let* ((status (gethash "status" issuer)) (acme (and (hash-table-p status) (gethash "acme" status))))
    (and (hash-table-p acme) (gethash "uri" acme))))

(defun cm-acme-client (store issuer)
  "A registered client for ISSUER, cached across passes."
  (let ((identity (cm-acme-issuer-identity issuer)))
    (or (gethash identity *cm-acme-clients*)
        (let ((acme (gethash "acme" (gethash "spec" issuer))))
          (multiple-value-bind (client account-url)
              (cm-acme-account *cm-acme-backend* (gethash "server" acme) (gethash "email" acme)
                               (cm-acme-account-key store issuer)
                               :skip-tls-verify (gethash "skipTLSVerify" acme))
            (cm-acme-record-account store issuer account-url)
            (setf (gethash identity *cm-acme-clients*) client))))))

;;; ---------------------------------------------------------------------------
;;; Challenges.

(defun cm-acme-challenge-name (certificate-name token)
  "A stable, DNS-safe Challenge name: the Certificate's, plus a digest of TOKEN."
  (format nil "~A-~A" (string-right-trim "-." (subseq certificate-name 0 (min 52 (length certificate-name))))
          (subseq (ironclad:byte-array-to-hex-string
                   (ironclad:digest-sequence :sha256 (trivial-utf-8:string-to-utf-8-bytes token)))
                  0 10)))

(defun cm-acme-http01-solver (issuer)
  "The first http01 gatewayHTTPRoute solver; selectors are not implemented."
  (find-if (lambda (solver)
             (let ((http01 (gethash "http01" solver)))
               (and (hash-table-p http01) (hash-table-p (gethash "gatewayHTTPRoute" http01)))))
           (gethash "solvers" (gethash "acme" (gethash "spec" issuer)) #())))

(defun cm-acme-write-challenge (store certificate issuer authorization-url authorization challenge key)
  "Create the Challenge the Gateway answers for one pending authorization; return its name."
  (let* ((metadata (gethash "metadata" certificate))
         (namespace (gethash "namespace" metadata))
         (token (cm-acme-field challenge :token))
         (name (cm-acme-challenge-name (gethash "name" metadata) token))
         (object (core-object
                  "apiVersion" "acme.cert-manager.io/v1" "kind" "Challenge"
                  "metadata" (core-object
                              "name" name "namespace" namespace
                              "ownerReferences"
                              (vector (core-object "apiVersion" "cert-manager.io/v1" "kind" "Certificate"
                                                   "name" (gethash "name" metadata)
                                                   "uid" (gethash "uid" metadata)
                                                   "controller" t "blockOwnerDeletion" t)))
                  "spec" (core-object
                          "url" (cm-acme-field challenge :url)
                          "authorizationURL" authorization-url
                          "dnsName" (cm-acme-field authorization :identifier :value)
                          "wildcard" nil
                          "type" "HTTP-01"
                          "token" token
                          "key" key
                          "solver" (copy-core-object (cm-acme-http01-solver issuer))
                          "issuerRef" (copy-core-object (gethash "issuerRef" (gethash "spec" certificate))))
                  "status" (core-object "processing" t "presented" t "state" "pending"))))
    (unless (ignore-errors (get-core-resource store "challenges" namespace name))
      (create-core-resource store "challenges" object namespace))
    name))

(defun cm-acme-delete-challenges (store namespace names)
  (dolist (name names)
    (ignore-errors (delete-core-resource store "challenges" namespace name))))

;;; ---------------------------------------------------------------------------
;;; Certificate status.

(defun cm-acme-update-status (store certificate function)
  "Apply FUNCTION to CERTIFICATE's stored status object (created when absent)."
  (let ((metadata (gethash "metadata" certificate)))
    (ignore-errors
     (update-core-resource store "certificates" (gethash "namespace" metadata) (gethash "name" metadata)
       (lambda (object)
         (unless (hash-table-p (gethash "status" object))
           (setf (gethash "status" object) (core-object)))
         (funcall function (gethash "status" object))
         object)))))

(defun cm-acme-set-condition (status type value reason message)
  "Replace STATUS's condition TYPE."
  (let ((conditions (remove type (coerce (gethash "conditions" status #()) 'list)
                            :test #'equal :key (lambda (condition) (gethash "type" condition)))))
    (setf (gethash "conditions" status)
          (coerce (append conditions
                          (list (core-object "type" type "status" value "reason" reason "message" message
                                             "lastTransitionTime" (cm-rfc3339 (funcall *cert-manager-clock*)))))
                  'vector))))

(defun cm-acme-status-condition (certificate type)
  (let ((status (gethash "status" certificate)))
    (and (hash-table-p status)
         (find type (coerce (gethash "conditions" status #()) 'list)
               :test #'equal :key (lambda (condition) (gethash "type" condition))))))

(defun cm-acme-backoff (attempts)
  "Seconds to wait after ATTEMPTS consecutive failures."
  (min *cm-acme-max-backoff* (* *cm-acme-initial-backoff* (expt 2 (max 0 (1- attempts))))))

(defun cm-acme-backing-off-p (certificate now)
  "True while CERTIFICATE's last failure is within its backoff."
  (let* ((status (gethash "status" certificate))
         (attempts (and (hash-table-p status) (gethash "failedIssuanceAttempts" status)))
         (last (and (integerp attempts) (plusp attempts)
                    (cm-parse-rfc3339 (gethash "lastFailureTime" status)))))
    (and last (< now (+ last (cm-acme-backoff attempts))))))

;;; ---------------------------------------------------------------------------
;;; Orders.

(defstruct cm-acme-order
  identity phase (next 0) started order-url finalize-url authorizations challenges
  leaf-private-key leaf-public-key)

(defvar *cm-acme-orders* (make-hash-table :test 'equal)
  "In-progress orders by Certificate UID.")

(defun cm-acme-forget-orders-except (certificates)
  "Drop progress for Certificates that no longer exist."
  (let ((live (make-hash-table :test 'equal)))
    (dolist (certificate certificates)
      (setf (gethash (gethash "uid" (gethash "metadata" certificate)) live) t))
    (loop for uid in (loop for uid being the hash-keys of *cm-acme-orders* collect uid)
          unless (gethash uid live) do (remhash uid *cm-acme-orders*))))

(defun cm-acme-domains (spec)
  "The order's identifiers: dnsNames, with commonName first when it is one of them."
  (let ((names (cm-string-list spec "dnsNames"))
        (common-name (gethash "commonName" spec)))
    (cond ((or (cm-string-list spec "ipAddresses") (cm-string-list spec "uris")
               (cm-string-list spec "emailAddresses"))
           (error "the ACME issuer supports only dnsNames"))
          ((null names) (error "the ACME issuer needs at least one dnsName"))
          ((some (lambda (name) (find #\* name)) names)
           (error "wildcard dnsNames need DNS-01, which is not implemented"))
          ((and (stringp common-name) (plusp (length common-name)) (not (member common-name names :test #'equal)))
           (error "commonName ~A must also be one of the dnsNames" common-name))
          ((stringp common-name) (cons common-name (remove common-name names :test #'equal)))
          (t names))))

(defun cm-acme-start-order (store certificate issuer order now)
  "Create the ACME order and present a Challenge for each pending authorization."
  (let* ((spec (gethash "spec" certificate))
         (domains (cm-acme-domains spec))
         (client (cm-acme-client store issuer))
         (backend *cm-acme-backend*))
    (unless (cm-acme-http01-solver issuer)
      (error "the issuer has no http01 gatewayHTTPRoute solver"))
    (multiple-value-bind (response order-url)
        (cm-acme-new-order backend client domains (gethash "profile" (gethash "acme" (gethash "spec" issuer))))
      (setf (cm-acme-order-order-url order) order-url
            (cm-acme-order-finalize-url order) (cm-acme-field response :finalize)
            (cm-acme-order-authorizations order) (cm-acme-field response :authorizations)
            (cm-acme-order-started order) now)
      (dolist (url (cm-acme-order-authorizations order))
        (let ((authorization (cm-acme-fetch backend client url)))
          (unless (equal "valid" (cm-acme-field authorization :status))
            (let ((challenge (find "http-01" (cm-acme-field authorization :challenges)
                                   :test #'equal :key (lambda (challenge) (cm-acme-field challenge :type)))))
              (unless challenge
                (error "~A offers no http-01 challenge" (cm-acme-field authorization :identifier :value)))
              (push (list (cm-acme-write-challenge
                           store certificate issuer url authorization challenge
                           (cm-acme-key-authorization backend client (cm-acme-field challenge :token)))
                          (cm-acme-field challenge :url))
                    (cm-acme-order-challenges order))))))
      (cm-acme-update-status store certificate
        (lambda (status)
          (cm-acme-set-condition status "Issuing" "True" "Issuing"
                                 (format nil "ACME order created for ~{~A~^, ~}" domains))))
      (if (cm-acme-order-challenges order)
          (setf (cm-acme-order-phase order) :presented
                (cm-acme-order-next order) (+ now *cm-acme-present-delay*))
          ;; Every authorization is still valid from an earlier order.
          (setf (cm-acme-order-phase order) :finalize)))))

(defun cm-acme-issue (store certificate order pem)
  "Write the downloaded chain and the order's key as the TLS Secret, and report Ready."
  (let* ((metadata (gethash "metadata" certificate))
         (namespace (gethash "namespace" metadata))
         (spec (gethash "spec" certificate))
         (leaf (pure-tls:parse-certificate
                (pure-tls::pem-decode (trivial-utf-8:string-to-utf-8-bytes pem) "CERTIFICATE")))
         (not-before (pure-tls:certificate-not-before leaf))
         (not-after (pure-tls:certificate-not-after leaf))
         (key-pem (pure-tls/acme::wrap-pem "RSA PRIVATE KEY"
                                           (pure-tls/acme::encode-rsa-private-key-der
                                            (cm-acme-order-leaf-private-key order)
                                            (cm-acme-order-leaf-public-key order)))))
    (cm-write-tls-secret store namespace (gethash "secretName" spec) pem key-pem certificate)
    (cm-set-ready-status store namespace (gethash "name" metadata) not-before not-after
                         (cm-renewal-time spec not-before not-after))
    (cm-acme-delete-challenges store namespace (mapcar #'first (cm-acme-order-challenges order)))
    t))

(defun cm-acme-advance (store certificate issuer order now)
  "Take ORDER one step. Returns T once the Certificate is issued."
  (let ((backend *cm-acme-backend*))
    (when (and (cm-acme-order-started order)
               (> now (+ (cm-acme-order-started order) *cm-acme-order-timeout*)))
      (error "the ACME order did not complete within ~D seconds" *cm-acme-order-timeout*))
    (ecase (cm-acme-order-phase order)
      (:new
       (cm-acme-start-order store certificate issuer order now)
       nil)
      (:presented
       (let ((client (cm-acme-client store issuer)))
         (dolist (challenge (cm-acme-order-challenges order))
           (cm-acme-respond backend client (second challenge))))
       (setf (cm-acme-order-phase order) :validating
             (cm-acme-order-next order) (+ now *cm-acme-poll-interval*))
       nil)
      (:validating
       (let* ((client (cm-acme-client store issuer))
              (authorizations (mapcar (lambda (url) (cm-acme-fetch backend client url))
                                      (cm-acme-order-authorizations order)))
              (invalid (find-if (lambda (authorization)
                                  (member (cm-acme-field authorization :status)
                                          '("invalid" "deactivated" "expired" "revoked") :test #'equal))
                                authorizations)))
         (cond (invalid (error "validation failed for ~A" (cm-acme-authorization-problem invalid)))
               ((every (lambda (authorization) (equal "valid" (cm-acme-field authorization :status)))
                       authorizations)
                (setf (cm-acme-order-phase order) :finalize)
                (cm-acme-advance store certificate issuer order now))
               (t (setf (cm-acme-order-next order) (+ now *cm-acme-poll-interval*))
                  nil))))
      (:finalize
       (multiple-value-bind (private-key public-key) (pure-tls/acme:generate-domain-key)
         (setf (cm-acme-order-leaf-private-key order) private-key
               (cm-acme-order-leaf-public-key order) public-key)
         (let ((response (cm-acme-finalize backend (cm-acme-client store issuer)
                                           (cm-acme-order-finalize-url order)
                                           (pure-tls/acme:generate-csr
                                            private-key public-key (cm-acme-domains (gethash "spec" certificate))))))
           (setf (cm-acme-order-phase order) :issuing)
           (if (equal "valid" (cm-acme-field response :status))
               (cm-acme-advance store certificate issuer order now)
               (progn (setf (cm-acme-order-next order) (+ now *cm-acme-poll-interval*))
                      nil)))))
      (:issuing
       (let* ((client (cm-acme-client store issuer))
              (response (cm-acme-fetch backend client (cm-acme-order-order-url order)))
              (state (cm-acme-field response :status)))
         (cond ((equal state "valid")
                (let ((pem (cm-acme-download backend client (cm-acme-field response :certificate))))
                  (unless (and (stringp pem) (search "-----BEGIN CERTIFICATE-----" pem))
                    (error "the ACME server returned no certificate chain"))
                  (cm-acme-issue store certificate order pem)))
               ((equal state "invalid")
                (error "the ACME order became invalid: ~A" (cm-acme-problem response)))
               (t (setf (cm-acme-order-next order) (+ now *cm-acme-poll-interval*))
                  nil)))))))

(defun cm-acme-abandon (store certificate order)
  "Forget ORDER and delete the Challenges it presented."
  (let ((metadata (gethash "metadata" certificate)))
    (remhash (gethash "uid" metadata) *cm-acme-orders*)
    (cm-acme-delete-challenges store (gethash "namespace" metadata)
                               (mapcar #'first (cm-acme-order-challenges order)))))

(defun cm-acme-fail (store certificate order condition now)
  "Abandon ORDER and record the failure for backoff."
  (let ((metadata (gethash "metadata" certificate))
        (message (princ-to-string condition)))
    (cm-acme-abandon store certificate order)
    ;; A stale nonce or a changed account must not outlive the failure.
    (clrhash *cm-acme-clients*)
    (format *error-output* "gr8s: ACME issuance for Certificate ~A/~A failed: ~A~%"
            (gethash "namespace" metadata) (gethash "name" metadata) message)
    (cm-acme-update-status store certificate
      (lambda (status)
        (setf (gethash "failedIssuanceAttempts" status) (1+ (or (gethash "failedIssuanceAttempts" status) 0))
              (gethash "lastFailureTime" status) (cm-rfc3339 now))
        (cm-acme-set-condition status "Issuing" "False" "Failed" message)
        ;; A renewal failure leaves a still-valid certificate Ready.
        (let ((not-after (cm-parse-rfc3339 (gethash "notAfter" status))))
          (unless (and not-after (< now not-after))
            (cm-acme-set-condition status "Ready" "False" "Failed" message)))))
    nil))

(defun cm-acme-reconcile (store certificate issuer)
  "Move CERTIFICATE's ACME order one step, starting one unless backing off.
   Returns T when this pass issued the certificate."
  (let* ((now (funcall *cert-manager-clock*))
         (uid (gethash "uid" (gethash "metadata" certificate)))
         (identity (list (cm-certificate-identity (gethash "spec" certificate)) (cm-acme-issuer-identity issuer)))
         (order (gethash uid *cm-acme-orders*)))
    (unless (and order (equal identity (cm-acme-order-identity order)))
      ;; A changed spec or issuer is a new request, not a failure.
      (when order (cm-acme-abandon store certificate order))
      (when (cm-acme-backing-off-p certificate now)
        (return-from cm-acme-reconcile nil))
      (setf order (make-cm-acme-order :identity identity :phase :new)
            (gethash uid *cm-acme-orders*) order))
    (when (< now (cm-acme-order-next order))
      (return-from cm-acme-reconcile nil))
    (handler-case
        (when (cm-acme-advance store certificate issuer order now)
          (remhash uid *cm-acme-orders*)
          t)
      (cm-acme-deferred (condition)
        (setf (cm-acme-order-next order) (+ now (cm-acme-deferred-seconds condition)))
        nil)
      (error (condition)
        (cm-acme-fail store certificate order condition now)))))
