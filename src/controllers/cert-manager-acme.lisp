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
;;;; A step runs on its own thread, every request under a total deadline, so an
;;;; issuer's slow or hostile server can't hold up the reconcile pass. A failure
;;;; deletes the Challenges, records failedIssuanceAttempts and lastFailureTime
;;;; on the Certificate, and waits a doubling backoff before a new order, so a
;;;; broken setup never hammers the server's rate limits. A Retry-After from the
;;;; server, however long, defers the next step instead of sleeping or counting
;;;; as a failure. The server is trusted for nothing: TLS is verified unless the
;;;; issuer opts out, every authorization must be for one of the Certificate's
;;;; dnsNames, and the downloaded leaf must carry the order's key. The network
;;;; sits behind generic functions on *CM-ACME-BACKEND*, so tests drive the
;;;; whole state machine without one.

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

(defparameter *cm-acme-request-deadline* 30
  "Seconds one ACME request may take in all, however slowly the server sends.")

(defparameter *cm-acme-step-deadline* 120
  "Seconds one step may take in all; RSA key generation is part of finalize.")

(defparameter *cm-acme-rate-limit-floor* 60
  "The shortest wait after a rate-limited response that names no Retry-After.")

(defparameter *cm-acme-run-step* 'cm-acme-run-step-in-thread
  "Called with a thunk that takes one order one step. The default runs it on a
   new thread so the reconcile pass never waits on an ACME server; tests bind
   FUNCALL.")

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

(define-condition cm-acme-fenced (error) ()
  (:report "the control-plane leadership this ACME step began under has ended"))

(defun cm-acme-check-fence ()
  "Refuse a store write from a step whose leadership has ended: a demoted
   leader's writes are forwarded to the new one and would race its orders."
  (unless (funcall *cm-acme-fence*)
    (error 'cm-acme-fenced)))

(defvar *cm-acme-leadership-generation* nil
  "The leadership generation the in-memory orders and clients belong to.")

(defun cm-acme-note-leadership (generation)
  "Forget every order and client from an earlier leadership: steps still
   running under it are fenced, and whatever they left is cleaned up."
  (bt:with-lock-held (*cm-acme-lock*)
    (unless (eql generation *cm-acme-leadership-generation*)
      (clrhash *cm-acme-orders*)
      (clrhash *cm-acme-clients*)
      (setf *cm-acme-leadership-generation* generation))))

(defvar *cm-acme-tls-verify* :required
  "The drakma :verify for ACME requests: :required unless the issuer sets
   skipTLSVerify (for a test server such as Pebble).")

(defparameter *cm-acme-transport* 'drakma:http-request
  "The HTTP function under CM-ACME-HTTP-REQUEST; tests stand in for the server.")

(defun cm-acme-http-request (url &rest arguments)
  "The client's HTTP transport: verified TLS, a bounded connect and a bounded
   total time, so an unreachable or trickling server can't stall a step."
  (handler-case
      (sb-sys:with-deadline (:seconds *cm-acme-request-deadline*)
        (apply *cm-acme-transport* url :verify *cm-acme-tls-verify*
                                       :connection-timeout *cm-acme-connection-timeout* arguments))
    (sb-sys:deadline-timeout ()
      (error "the ACME server at ~A did not answer within ~D seconds" url *cm-acme-request-deadline*))))

(defmacro with-cm-acme-io ((client) &body body)
  "Run BODY's ACME requests for CLIENT with verified, bounded connections and
   no in-step sleeping: any wait the server asks for becomes a deferral."
  `(let ((pure-tls/acme::*sleep-function* #'cm-acme-defer)
         (pure-tls/acme::*default-retry-after* *cm-acme-rate-limit-floor*)
         (pure-tls/acme::*http-request-function* #'cm-acme-http-request)
         (*cm-acme-tls-verify* (if (pure-tls/acme::acme-client-skip-tls-verify ,client) nil :required)))
     ;; The client waits itself only up to its own budget; past that it gives
     ;; up on a rate limit, which still means "come back after Retry-After".
     (handler-bind ((pure-tls/acme:acme-rate-limited
                      (lambda (condition)
                        (cm-acme-defer (max *cm-acme-rate-limit-floor*
                                            (or (pure-tls/acme:acme-http-error-retry-after condition) 0))))))
       ;; One request at a time per client: they share its nonce and account URL.
       (bt:with-lock-held ((pure-tls/acme::acme-client-lock ,client))
         ,@body))))

(defun cm-acme-check-status (what response status &optional (ok '(200 201)))
  "Signal unless STATUS is one of OK, naming WHAT and the server's problem."
  (unless (member status ok)
    (error "ACME ~A failed: HTTP ~A ~A" what status (cm-acme-problem response)))
  response)

(defmethod cm-acme-account ((backend (eql :pure-tls)) server email account-key &key skip-tls-verify)
  (let ((client (pure-tls/acme:make-acme-client
                 :directory-url server :skip-tls-verify (and skip-tls-verify t)
                 ;; A store that already holds the key never touches the disk.
                 :store (pure-tls/acme::%make-cert-store :account-key account-key))))
    (with-cm-acme-io (client)
      (unless (consp (pure-tls/acme:client-init client))
        (error "~A is not an ACME directory" server))
      (values client (pure-tls/acme:client-register-account client email)))))

(defmethod cm-acme-new-order ((backend (eql :pure-tls)) client domains profile)
  ;; Not client-new-order: it always names a profile, and a server that offers
  ;; none rejects it. Only an issuer's own spec.acme.profile is sent.
  (with-cm-acme-io (client)
    (multiple-value-bind (response status location)
        (pure-tls/acme::client-post
         client (cdr (assoc :new-order (pure-tls/acme::acme-client-directory client)))
         `(("identifiers" . ,(map 'vector (lambda (domain) `(("type" . "dns") ("value" . ,domain))) domains))
           ,@(when profile `(("profile" . ,profile))))
         :use-kid t)
      (cm-acme-check-status "order creation" response status)
      (values response location))))

(defmethod cm-acme-fetch ((backend (eql :pure-tls)) client url)
  (with-cm-acme-io (client)
    (multiple-value-bind (response status) (pure-tls/acme:client-get-authorization client url)
      (cm-acme-check-status (format nil "fetch of ~A" url) response status '(200)))))

(defmethod cm-acme-key-authorization ((backend (eql :pure-tls)) client token)
  (pure-tls/acme:client-compute-key-authorization client token))

(defmethod cm-acme-respond ((backend (eql :pure-tls)) client challenge-url)
  (with-cm-acme-io (client)
    (multiple-value-bind (response status) (pure-tls/acme:client-respond-challenge client challenge-url)
      (cm-acme-check-status "challenge response" response status '(200 201 202)))))

(defmethod cm-acme-finalize ((backend (eql :pure-tls)) client finalize-url csr-der)
  (with-cm-acme-io (client)
    (multiple-value-bind (response status) (pure-tls/acme:client-finalize-order client finalize-url csr-der)
      (cm-acme-check-status "finalize" response status '(200 201 202)))))

(defmethod cm-acme-download ((backend (eql :pure-tls)) client certificate-url)
  (with-cm-acme-io (client)
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
          (cm-acme-check-fence)
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
      (cm-acme-check-fence)
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

(defvar *cm-acme-lock* (bt:make-lock "gr8s ACME orders")
  "Guards *cm-acme-orders* and *cm-acme-clients*, shared by the reconcile pass
   and the step threads.")

(defvar *cm-acme-registration-lock* (bt:make-lock "gr8s ACME registration")
  "Held while a client registers, so concurrent steps for one issuer register once.")

(defun cm-acme-client (store issuer)
  "A registered client for ISSUER, cached across passes."
  (let ((identity (cm-acme-issuer-identity issuer)))
    (bt:with-lock-held (*cm-acme-registration-lock*)
      (cm-acme-client-locked store issuer identity))))

(defun cm-acme-client-locked (store issuer identity)
  (or (bt:with-lock-held (*cm-acme-lock*) (gethash identity *cm-acme-clients*))
      (let ((acme (gethash "acme" (gethash "spec" issuer))))
        (multiple-value-bind (client account-url)
            (cm-acme-account *cm-acme-backend* (gethash "server" acme) (gethash "email" acme)
                             (cm-acme-account-key store issuer)
                             :skip-tls-verify (gethash "skipTLSVerify" acme))
          (cm-acme-record-account store issuer account-url)
          (bt:with-lock-held (*cm-acme-lock*)
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

(defun cm-acme-write-challenge (store certificate issuer authorization-url dns-name challenge key)
  "Create the Challenge the Gateway answers for DNS-NAME's pending authorization;
   return its name."
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
                          "dnsName" dns-name
                          "wildcard" nil
                          "type" "HTTP-01"
                          "token" token
                          "key" key
                          "solver" (copy-core-object (cm-acme-http01-solver issuer))
                          "issuerRef" (copy-core-object (gethash "issuerRef" (gethash "spec" certificate))))
                  "status" (core-object "processing" t "presented" t "state" "pending"))))
    (unless (ignore-errors (get-core-resource store "challenges" namespace name))
      (cm-acme-check-fence)
      (create-core-resource store "challenges" object namespace))
    name))

(defun cm-acme-delete-challenges (store namespace names)
  (dolist (name names)
    (cm-acme-check-fence)
    (ignore-errors (delete-core-resource store "challenges" namespace name))))

(defun cm-acme-challenge-owner-uid (challenge)
  "The UID of the Certificate controlling CHALLENGE, or NIL."
  (let ((owner (find "Certificate" (coerce (gethash "ownerReferences" (gethash "metadata" challenge) #()) 'list)
                     :test #'equal :key (lambda (reference) (gethash "kind" reference)))))
    (and owner (gethash "uid" owner))))

(defun cm-acme-delete-orphaned-challenges (store)
  "Delete every Certificate-owned Challenge whose Certificate has no order in
   progress: left by a restart, a leader change, an abandoned order, or an
   issuer that is no longer ACME. Nothing should answer for them."
  (let ((live (bt:with-lock-held (*cm-acme-lock*)
                (loop for uid being the hash-keys of *cm-acme-orders* collect uid))))
    (dolist (challenge (list-core-resources store "challenges"))
      (let ((owner (cm-acme-challenge-owner-uid challenge))
            (metadata (gethash "metadata" challenge)))
        (when (and owner (not (member owner live :test #'equal)))
          (cm-acme-delete-challenges store (gethash "namespace" metadata) (list (gethash "name" metadata))))))))

;;; ---------------------------------------------------------------------------
;;; Certificate status.

(defun cm-acme-update-status (store certificate function)
  "Apply FUNCTION to CERTIFICATE's stored status object (created when absent)."
  (let ((metadata (gethash "metadata" certificate)))
    (cm-acme-check-fence)
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
  identity phase (next 0) started running order-url finalize-url authorizations challenges
  leaf-private-key leaf-public-key)

(defvar *cm-acme-orders* (make-hash-table :test 'equal)
  "In-progress orders by Certificate UID.")

(defun cm-acme-retire-orders (active)
  "Drop orders for Certificates not in ACTIVE (deleted, issued elsewhere, or
   now on another issuer), unless a step is running for one."
  (bt:with-lock-held (*cm-acme-lock*)
    (loop for uid in (loop for uid being the hash-keys of *cm-acme-orders* collect uid)
          for order = (gethash uid *cm-acme-orders*)
          unless (or (member uid active :test #'equal) (cm-acme-order-running order))
            do (remhash uid *cm-acme-orders*))))

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

(defun cm-acme-authorization-domain (authorization domains)
  "AUTHORIZATION's DNS identifier, which must be one of the Certificate's DOMAINS:
   whatever the server says, a Challenge never names any other host."
  (let ((type (cm-acme-field authorization :identifier :type))
        (value (cm-acme-field authorization :identifier :value)))
    (unless (and (equal type "dns") (stringp value) (member value domains :test #'string-equal))
      (error "the ACME server sent an authorization for ~S, which the Certificate does not name" value))
    (find value domains :test #'string-equal)))

(defun cm-acme-start-order (store certificate issuer order now)
  "Create the ACME order and present a Challenge for each pending authorization.
   A deferral part way through resumes with the same order."
  (let* ((spec (gethash "spec" certificate))
         (domains (cm-acme-domains spec))
         (client (cm-acme-client store issuer))
         (backend *cm-acme-backend*))
    (unless (cm-acme-http01-solver issuer)
      (error "the issuer has no http01 gatewayHTTPRoute solver"))
    (unless (cm-acme-order-order-url order)
      ;; The pass may have read the Certificate before another step issued it.
      (let* ((metadata (gethash "metadata" certificate))
             (current (ignore-errors (get-core-resource store "certificates" (gethash "namespace" metadata)
                                                        (gethash "name" metadata)))))
        (unless (and current
                     (equal (gethash "uid" metadata) (gethash "uid" (gethash "metadata" current)))
                     (cm-certificate-needs-issue-p store current))
          (setf (cm-acme-order-next order) (+ now *cm-acme-poll-interval*))
          (return-from cm-acme-start-order nil)))
      ;; A new order answers only its own tokens: clear any an earlier one left.
      (let ((uid (gethash "uid" (gethash "metadata" certificate))))
        (dolist (challenge (list-core-resources store "challenges" (gethash "namespace" (gethash "metadata" certificate))))
          (when (equal uid (cm-acme-challenge-owner-uid challenge))
            (cm-acme-delete-challenges store (gethash "namespace" (gethash "metadata" challenge))
                                       (list (gethash "name" (gethash "metadata" challenge)))))))
      (multiple-value-bind (response order-url)
          (cm-acme-new-order backend client domains (gethash "profile" (gethash "acme" (gethash "spec" issuer))))
        (let ((authorizations (cm-acme-field response :authorizations)))
          (unless (and (stringp order-url) (consp authorizations)
                       (<= (length authorizations) (length domains)))
            (error "the ACME server's order does not match the ~D dnsNames requested" (length domains)))
          (setf (cm-acme-order-order-url order) order-url
                (cm-acme-order-finalize-url order) (cm-acme-field response :finalize)
                (cm-acme-order-authorizations order) authorizations
                (cm-acme-order-started order) now))))
    (dolist (url (cm-acme-order-authorizations order))
      (let* ((authorization (cm-acme-fetch backend client url))
             (domain (cm-acme-authorization-domain authorization domains)))
        (unless (equal "valid" (cm-acme-field authorization :status))
          (let ((challenge (find "http-01" (cm-acme-field authorization :challenges)
                                 :test #'equal :key (lambda (challenge) (cm-acme-field challenge :type)))))
            (unless challenge
              (error "~A offers no http-01 challenge" domain))
            (pushnew (list (cm-acme-write-challenge
                            store certificate issuer url domain challenge
                            (cm-acme-key-authorization backend client (cm-acme-field challenge :token)))
                           (cm-acme-field challenge :url))
                     (cm-acme-order-challenges order)
                     :test #'equal :key #'first)))))
    (cm-acme-update-status store certificate
      (lambda (status)
        (cm-acme-set-condition status "Issuing" "True" "Issuing"
                               (format nil "ACME order created for ~{~A~^, ~}" domains))))
    (if (cm-acme-order-challenges order)
        (setf (cm-acme-order-phase order) :presented
              (cm-acme-order-next order) (+ now *cm-acme-present-delay*))
        ;; Every authorization is still valid from an earlier order.
        (setf (cm-acme-order-phase order) :finalize))))

(defun cm-acme-issue (store certificate order pem)
  "Write the downloaded chain and the order's key as the TLS Secret, and report
   Ready. The leaf must carry the order's key, or the Secret is left alone."
  (let* ((metadata (gethash "metadata" certificate))
         (namespace (gethash "namespace" metadata))
         (spec (gethash "spec" certificate))
         (key-pem (pure-tls/acme::wrap-pem "RSA PRIVATE KEY"
                                           (pure-tls/acme::encode-rsa-private-key-der
                                            (cm-acme-order-leaf-private-key order)
                                            (cm-acme-order-leaf-public-key order))))
         (certificates
           (handler-case
               (nth-value 1 (gateway-check-tls-material (trivial-utf-8:string-to-utf-8-bytes pem)
                                                        (trivial-utf-8:string-to-utf-8-bytes key-pem)))
             (error (condition)
               (error "the downloaded certificate does not carry the order's key: ~A" condition))))
         (leaf (first certificates))
         (not-before (pure-tls:certificate-not-before leaf))
         (not-after (pure-tls:certificate-not-after leaf)))
    (cm-acme-check-fence)
    (cm-write-tls-secret store namespace (gethash "secretName" spec) pem key-pem certificate)
    (cm-acme-check-fence)
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
    (bt:with-lock-held (*cm-acme-lock*)
      (when (eq order (gethash (gethash "uid" metadata) *cm-acme-orders*))
        (remhash (gethash "uid" metadata) *cm-acme-orders*)))
    (cm-acme-delete-challenges store (gethash "namespace" metadata)
                               (mapcar #'first (cm-acme-order-challenges order)))))

(defun cm-acme-fail (store certificate order condition now)
  "Abandon ORDER and record the failure for backoff."
  (let ((metadata (gethash "metadata" certificate))
        (message (princ-to-string condition)))
    (cm-acme-abandon store certificate order)
    ;; A stale nonce or a changed account must not outlive the failure.
    (bt:with-lock-held (*cm-acme-lock*)
      (remhash (second (cm-acme-order-identity order)) *cm-acme-clients*))
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

(defun cm-acme-step (store certificate issuer order now)
  "Run one step of ORDER, turning a deferral into ORDER's next attempt time and
   any other failure into a recorded, backed-off failure. Returns T on issue."
  (handler-case
      (sb-sys:with-deadline (:seconds *cm-acme-step-deadline*)
        (when (cm-acme-advance store certificate issuer order now)
          (cm-acme-abandon store certificate order)
          t))
    (cm-acme-deferred (condition)
      (setf (cm-acme-order-next order) (+ now (cm-acme-deferred-seconds condition)))
      nil)
    (cm-acme-fenced ()
      (cm-acme-forget certificate order))
    (sb-sys:deadline-timeout ()
      (cm-acme-fail-unless-fenced store certificate order
                                  (format nil "an ACME step took longer than ~D seconds" *cm-acme-step-deadline*)
                                  now))
    (error (condition)
      (cm-acme-fail-unless-fenced store certificate order condition now))))

(defun cm-acme-forget (certificate order)
  "Drop ORDER from memory without touching the store."
  (let ((uid (gethash "uid" (gethash "metadata" certificate))))
    (bt:with-lock-held (*cm-acme-lock*)
      (when (eq order (gethash uid *cm-acme-orders*))
        (remhash uid *cm-acme-orders*))))
  nil)

(defun cm-acme-fail-unless-fenced (store certificate order condition now)
  "Record the failure, unless leadership ended first: then only forget ORDER."
  (handler-case (cm-acme-fail store certificate order condition now)
    (cm-acme-fenced () (cm-acme-forget certificate order))))

(defun cm-acme-run-step-in-thread (thunk)
  (bt:make-thread thunk :name "gr8s ACME step"))

(defun cm-acme-reconcile (store certificate issuer)
  "Move CERTIFICATE's ACME order one step, starting one unless backing off. The
   step runs through *cm-acme-run-step*; with the default it runs on its own
   thread and this returns at once. Returns T when the step ran here and issued."
  (let* ((now (funcall *cert-manager-clock*))
         (uid (gethash "uid" (gethash "metadata" certificate)))
         (identity (list (cm-certificate-identity (gethash "spec" certificate)) (cm-acme-issuer-identity issuer)))
         (stale nil)
         (order nil))
    (push uid *cm-acme-active*)
    (bt:with-lock-held (*cm-acme-lock*)
      (setf order (gethash uid *cm-acme-orders*))
      (when (and order (cm-acme-order-running order))
        (return-from cm-acme-reconcile nil))
      (unless (and order (equal identity (cm-acme-order-identity order)))
        ;; A changed spec or issuer is a new request, not a failure.
        (setf stale order
              order (make-cm-acme-order :identity identity :phase :new))))
    (when stale (cm-acme-abandon store certificate stale))
    (when (and (null (cm-acme-order-order-url order)) (cm-acme-backing-off-p certificate now))
      (return-from cm-acme-reconcile nil))
    (bt:with-lock-held (*cm-acme-lock*)
      (setf (gethash uid *cm-acme-orders*) order)
      (when (< now (cm-acme-order-next order))
        (return-from cm-acme-reconcile nil))
      (setf (cm-acme-order-running order) t))
    (let ((backend *cm-acme-backend*) (clock *cert-manager-clock*) (fence *cm-acme-fence*))
      (funcall *cm-acme-run-step*
               (lambda ()
                 (let ((*cm-acme-backend* backend) (*cert-manager-clock* clock) (*cm-acme-fence* fence))
                   (unwind-protect (cm-acme-step store certificate issuer order now)
                     (setf (cm-acme-order-running order) nil))))))))
