;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The control-plane half of podCertificate projected volumes (KEP-4317). A
;;;; node reports a PodCertificateClaim -- a signed PKCS#10 stub carrying the
;;;; public key it generated for a pod, with that pod's identity -- in its
;;;; NodeStatus; here we turn each claim into
;;;; a PodCertificateRequest, attributing the node from the authenticated
;;;; session rather than the claim. A built-in signer then issues a short-lived
;;;; SPIFFE leaf from the cluster CA for the signers gr8s hosts, filling
;;;; status.certificateChain so the request can be projected back and mounted.

(in-package #:gr8s.controllers)

(defparameter *pod-certificate-trust-domain* "cluster.local"
  "The SPIFFE trust domain the built-in pod-certificate signer issues under.")

(defparameter *pod-certificate-signers* '()
  "signerNames the built-in signer issues for. Empty by default: gr8s provides
   the KEP-4317 kubelet mechanics (the PodCertificateRequest API, projection and
   volumes) and leaves signing to whatever controller owns each signer -- as a
   real cluster does, and as Agent Substrate expects (it deploys its own
   podcertcontroller, which signs under its own CA). Set this (e.g. to
   '(\"podidentity.podcert.ate.dev/identity\")) only for a standalone gr8s that
   should self-sign those names from the cluster CA.")

(defparameter *pod-certificate-default-duration* (* 24 60 60)
  "The lifetime the built-in signer issues when a request sets no bound.")

;;; ---------------------------------------------------------------------------
;;; The PodCertificateRequest API: stored once, served at v1 and v1beta1
;;; ---------------------------------------------------------------------------

(defparameter +pod-certificate-request-beta-fields+ '("pkixPublicKey" "proofOfPossession")
  "Spec fields only v1beta1 has. v1 carries the key in stubPKCS10Request instead.")

(defun pod-certificate-request-path-version (path)
  "The API version a PodCertificateRequest URL is served in."
  (if (uiop:string-prefix-p "/apis/certificates.k8s.io/v1beta1/" path)
      +pod-certificate-request-beta-version+
      "certificates.k8s.io/v1"))

(defun pod-certificate-request-view (object version)
  "Show a stored PodCertificateRequest as VERSION does: v1 has no v1beta1-only spec fields."
  (let ((copy (copy-core-object object)))
    (setf (gethash "apiVersion" copy) version)
    (unless (equal version +pod-certificate-request-beta-version+)
      (let ((spec (gethash "spec" copy)))
        (when (hash-table-p spec)
          (dolist (field +pod-certificate-request-beta-fields+) (remhash field spec)))))
    copy))

(defun pod-certificate-request-api-view (input version)
  "Project PodCertificateRequests, their lists and watch envelopes into VERSION,
   leaving the group's other kinds untouched."
  (cond
    ((not (hash-table-p input)) input)
    ((equal "PodCertificateRequest" (gethash "kind" input)) (pod-certificate-request-view input version))
    ((equal "PodCertificateRequestList" (gethash "kind" input))
     (let ((object (copy-core-object input)))
       (setf (gethash "apiVersion" object) version
             (gethash "items" object) (map 'vector (lambda (item) (pod-certificate-request-view item version))
                                           (gethash "items" input)))
       object))
    ((hash-table-p (gethash "object" input))
     (let ((object (copy-core-object input)))
       (setf (gethash "object" object) (pod-certificate-request-api-view (gethash "object" input) version))
       object))
    (t input)))

(defun normalize-pod-certificate-request (input namespace name store)
  "Validate a PodCertificateRequest written in either served version and store it
   as v1. The spec is immutable and a write to the main resource keeps the stored
   status, as upstream's strategy does; only the status subresource sets status."
  (let* ((object (copy-core-object (require-object input "PodCertificateRequest")))
         (view (or *core-resource-view-version* "certificates.k8s.io/v1"))
         (version (gethash "apiVersion" object view))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (existing (and store name
                        (gethash (core-resource-key "podcertificaterequests" namespace name) (pod-store-resources store)))))
    ;; A request names its version in the URL; an in-process writer may use either.
    (unless (and (member version (if *core-resource-view-version*
                                     (list view "certificates.k8s.io/v1")
                                     (list "certificates.k8s.io/v1" +pod-certificate-request-beta-version+))
                         :test #'equal)
                 (equal "PodCertificateRequest" (gethash "kind" object "PodCertificateRequest")))
      (core-resource-error 400 "BadRequest" "Expected ~A PodCertificateRequest" view))
    (reject-unsupported-fields object '("apiVersion" "kind" "metadata" "spec" "status") "PodCertificateRequest")
    (validate-core-metadata metadata namespace name)
    (setf (gethash "apiVersion" object) "certificates.k8s.io/v1" (gethash "kind" object) "PodCertificateRequest"
          (gethash "namespace" metadata) namespace)
    (let ((spec (gethash "spec" object)))
      (unless (hash-table-p spec)
        (core-resource-error 422 "Invalid" "PodCertificateRequest spec must be an object"))
      (unless (and (stringp (gethash "signerName" spec)) (plusp (length (gethash "signerName" spec))))
        (core-resource-error 422 "Invalid" "PodCertificateRequest spec.signerName is required"))
      ;; Like upstream, accept only a stub request that parses and is signed by its key.
      (let ((stub (gethash "stubPKCS10Request" spec)))
        (when (and (stringp stub) (plusp (length stub)) (not existing))
          (handler-case
              (parse-and-verify-certificate-request
               (trivial-utf-8:string-to-utf-8-bytes
                (pure-tls/acme::wrap-pem "CERTIFICATE REQUEST" (core-base64-bytes stub "spec.stubPKCS10Request"))))
            (kubernetes-error (condition)
              (core-resource-error 422 "Invalid" "spec.stubPKCS10Request: Invalid value: ~A"
                                   (kubernetes-error-message condition))))))
      (when existing
        ;; A v1 writer never sees the v1beta1-only fields, so it cannot be clearing them.
        (let ((stored (gethash "spec" existing (core-object))))
          (dolist (field +pod-certificate-request-beta-fields+)
            (multiple-value-bind (value present) (gethash field stored)
              (when (and present (not (nth-value 1 (gethash field spec))))
                (setf (gethash field spec) value))))
          (unless (core-json-equal-p stored spec)
            (core-resource-error 422 "Invalid" "PodCertificateRequest spec: Invalid value: field is immutable")))))
    ;; Only an API request is held to that; in-process writers set status directly.
    (when (and *core-resource-view-version* (not *typed-api-status-write*))
      (let ((status (and existing (gethash "status" existing))))
        (if (hash-table-p status)
            (setf (gethash "status" object) (copy-core-object status))
            (remhash "status" object))))
    object))

;;; ---------------------------------------------------------------------------
;;; Node claim -> PodCertificateRequest resource
;;; ---------------------------------------------------------------------------

(defun node-metadata-uid (store node-name)
  "The API UID of NODE-NAME, or NIL, for attributing a request to its node."
  (ignore-errors (gethash "uid" (gethash "metadata" (node-api-object (get-node store node-name))))))

(defun pod-certificate-request-matches-claim-p (pcr pod-uid pkix &optional stub)
  "True when an existing PCR already belongs to this pod incarnation and key."
  (let ((spec (gethash "spec" pcr (core-object))))
    (and (equal pod-uid (gethash "podUID" spec))
         (if (and (stringp stub) (plusp (length stub)))
             (equal stub (gethash "stubPKCS10Request" spec))
             (equal pkix (gethash "pkixPublicKey" spec))))))

(defun signer-domain (signer-name)
  "The domain of a signerName, e.g. postgres.podcert.ate.dev for
   postgres.podcert.ate.dev/identity (the part before the final slash)."
  (let ((slash (position #\/ signer-name :from-end t)))
    (if slash (subseq signer-name 0 slash) signer-name)))

(defun pod-certificate-source-user-annotations (store namespace pod-name pod-uid request-name)
  "The userAnnotations of the podCertificate volume source that produced the
   request named REQUEST-NAME, copied verbatim into the request's
   unverifiedUserAnnotations for the signer (KEP-4317). Matched from the live pod
   by the source's derived request name -- a pod may carry several sources for
   one signer -- so a node cannot assert annotations the pod's spec does not set."
  (let ((pod (ignore-errors (get-pod store namespace pod-name))))
    (when (and pod (equal pod-uid (pod-uid pod)))
      (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
            for projected = (gethash "projected" volume)
            when projected
              do (loop for src across (gethash "sources" projected #())
                       for pc = (gethash "podCertificate" src)
                       when (and pc (equal request-name (pod-certificate-request-name pod pc)))
                         do (return-from pod-certificate-source-user-annotations
                              (gethash "userAnnotations" pc)))))))

(defun ensure-pod-certificate-request-from-claim (store node-name claim)
  "Idempotently ensure the PodCertificateRequest a node's CLAIM asks for exists
   and belongs to the current pod incarnation, creating or replacing it. The node
   name and UID come from the authenticated session, never from the claim."
  (let* ((namespace (slot-value claim 'gr8s.node.v1::namespace))
         (name (slot-value claim 'gr8s.node.v1::name))
         (pod-uid (slot-value claim 'gr8s.node.v1::pod-uid))
         (pkix (slot-value claim 'gr8s.node.v1::pkix-public-key))
         (stub (slot-value claim 'gr8s.node.v1::stub-pkcs10-request))
         (existing (ignore-errors (get-core-resource store "podcertificaterequests" namespace name))))
    (when (and existing (pod-certificate-request-matches-claim-p existing pod-uid pkix stub))
      (return-from ensure-pod-certificate-request-from-claim existing))
    (when existing
      ;; A request left from a prior incarnation or key: remove and reissue.
      (ignore-errors (delete-core-resource store "podcertificaterequests" namespace name)))
    (let ((max (slot-value claim 'gr8s.node.v1::max-expiration-seconds)))
      (create-core-resource
       store "podcertificaterequests"
       (build-pod-certificate-request
        :name name :namespace namespace
        :signer-name (slot-value claim 'gr8s.node.v1::signer-name)
        :pkix-public-key pkix :stub-pkcs10-request stub
        :pod-name (slot-value claim 'gr8s.node.v1::pod-name) :pod-uid pod-uid
        :service-account-name (slot-value claim 'gr8s.node.v1::service-account-name)
        ;; The node cannot resolve the SA UID (ServiceAccounts are not projected
        ;; to it), so the control plane fills it from its own store by SA name.
        :service-account-uid (let ((uid (slot-value claim 'gr8s.node.v1::service-account-uid))
                                   (sa-name (slot-value claim 'gr8s.node.v1::service-account-name)))
                               (if (plusp (length uid)) uid
                                   (let ((sa (ignore-errors
                                              (get-core-resource store "serviceaccounts" namespace sa-name))))
                                     (and sa (gethash "uid" (gethash "metadata" sa))))))
        :node-name node-name :node-uid (node-metadata-uid store node-name)
        :max-expiration-seconds (when (plusp max) max)
        :unverified-user-annotations
        (pod-certificate-source-user-annotations store namespace
                                                 (slot-value claim 'gr8s.node.v1::pod-name) pod-uid name))
       namespace))))

;;; ---------------------------------------------------------------------------
;;; Built-in signer
;;; ---------------------------------------------------------------------------

(defun pod-certificate-spiffe-id (namespace service-account)
  "The SPIFFE ID a pod SVID carries: spiffe://<trust-domain>/ns/<ns>/sa/<sa>."
  (format nil "spiffe://~A/ns/~A/sa/~A"
          *pod-certificate-trust-domain* namespace (or service-account "default")))

(defun pod-certificate-leaf-pem (pki spki-der spiffe-id duration)
  "Issue a short-lived SPIFFE leaf: an empty subject with a URI SAN, bound to the
   node-provided public key SPKI-DER and signed by the cluster CA for DURATION."
  (let* ((now (funcall *csr-signer-clock*))
         (ca-expiry (pure-tls::x509-certificate-validity-not-after (cluster-pki-ca-certificate pki)))
         (not-after (min ca-expiry (+ now duration)))
         (algorithm (pure-tls/acme::encode-sequence
                     (pure-tls/acme::encode-oid pure-tls/acme::*oid-ecdsa-with-sha256*)))
         (extensions
           (list (pure-tls/acme::encode-critical-extension +oid-basic-constraints+
                   (pure-tls/acme::encode-sequence))
                 (pure-tls/acme::encode-critical-extension +oid-key-usage+
                   (pure-tls/acme::encode-bit-string #(#x80) 7)) ; digitalSignature
                 (pure-tls/acme::encode-extension +oid-extended-key-usage+
                   (pure-tls/acme::encode-sequence
                    (pure-tls/acme::encode-oid +oid-client-auth+)
                    (pure-tls/acme::encode-oid '(1 3 6 1 5 5 7 3 1)))) ; serverAuth
                 (pure-tls/acme::encode-extension '(2 5 29 17)
                   (pure-tls/acme::encode-sequence
                    (pure-tls/acme::encode-der #x86 (pki-ascii-octets spiffe-id)))))))
    (unless (> not-after now) (error "Cluster CA has expired; cannot sign pod certificate"))
    (values
     (let ((tbs (pure-tls/acme::encode-sequence
                 (pure-tls/acme::encode-context-tag 0 (pure-tls/acme::encode-integer 2))
                 (pure-tls/acme::encode-integer (random-positive-serial)) algorithm
                 (csr-ca-subject-der pki)
                 (pure-tls/acme::encode-validity (- now 300) not-after)
                 (pure-tls/acme::encode-sequence) ; empty subject: identity is the SAN
                 spki-der
                 (pure-tls/acme::encode-x509-extensions extensions))))
       (pure-tls/acme::wrap-pem "CERTIFICATE"
         (pure-tls/acme::encode-sequence tbs algorithm
           (pure-tls/acme::encode-bit-string (ecdsa-sign-der (cluster-pki-ca-private-key pki) tbs)))))
     (- now 300) not-after)))

(defun pod-certificate-ca-pem (pki)
  "The cluster CA certificate as PEM, appended to a pod leaf to complete its chain."
  (pure-tls/acme::wrap-pem "CERTIFICATE"
    (pure-tls::x509-certificate-raw-der (cluster-pki-ca-certificate pki))))

(defun pod-certificate-request-ready-for-signing-p (object)
  "A request this built-in signer owns, not yet issued, denied or failed."
  (let ((status (gethash "status" object (core-object))))
    (and (member (gethash "signerName" (gethash "spec" object (core-object)))
                 *pod-certificate-signers* :test #'equal)
         (not (gethash "deletionTimestamp" (gethash "metadata" object)))
         (zerop (length (gethash "certificateChain" status "")))
         (not (pod-certificate-request-failure object)))))

(defun pod-certificate-request-spki (spec)
  "Return the DER SubjectPublicKeyInfo carried by SPEC's v1 stub or legacy key."
  (let ((stub (gethash "stubPKCS10Request" spec)))
    (if (and (stringp stub) (plusp (length stub)))
        (parsed-certificate-request-spki-der
         (parse-and-verify-certificate-request
          (trivial-utf-8:string-to-utf-8-bytes
           (pure-tls/acme::wrap-pem
            "CERTIFICATE REQUEST"
            (core-base64-bytes stub "stubPKCS10Request")))))
        (core-base64-bytes (gethash "pkixPublicKey" spec) "pkixPublicKey"))))

(defun sign-pod-certificate-request (store pki object)
  "Issue the SPIFFE leaf for one eligible PodCertificateRequest, writing
   status.certificateChain, notBefore and notAfter under a conditional update so
   a concurrently changed request is left alone."
  (let* ((spec (gethash "spec" object)) (metadata (gethash "metadata" object))
         (stub (gethash "stubPKCS10Request" spec))
         (pkix (gethash "pkixPublicKey" spec))
         (duration (let ((max (gethash "maxExpirationSeconds" spec)))
                     (if (and (integerp max) (plusp max))
                         (min max *pod-certificate-default-duration*)
                         *pod-certificate-default-duration*)))
         (spki (handler-case (pod-certificate-request-spki spec)
                 (error () (return-from sign-pod-certificate-request nil))))
         (spiffe (pod-certificate-spiffe-id (gethash "namespace" metadata)
                                            (gethash "serviceAccountName" spec))))
    (multiple-value-bind (chain not-before not-after)
        (bt:with-lock-held ((cluster-pki-lock pki))
          (multiple-value-bind (leaf nb na)
              (pod-certificate-leaf-pem pki spki spiffe duration)
            (values (concatenate 'string leaf (pod-certificate-ca-pem pki)) nb na)))
      (flet ((stamp (seconds) (rfc3339-from-unix (- seconds 2208988800))))
        (let ((*typed-api-status-write* t))
        (update-core-resource store "podcertificaterequests" (gethash "namespace" metadata)
                               (gethash "name" metadata)
          (lambda (current)
            (unless (and (pod-certificate-request-ready-for-signing-p current)
                         (equal (gethash "uid" metadata) (gethash "uid" (gethash "metadata" current)))
                         (let ((current-spec (gethash "spec" current)))
                           (if (and (stringp stub) (plusp (length stub)))
                               (equal stub (gethash "stubPKCS10Request" current-spec))
                               (equal pkix (gethash "pkixPublicKey" current-spec)))))
              (return-from sign-pod-certificate-request nil))
            (let ((status (gethash "status" current (core-object))))
              (setf (gethash "certificateChain" status) chain
                    (gethash "notBefore" status) (stamp not-before)
                    (gethash "notAfter" status) (stamp not-after)
                    (gethash "beginRefreshAt" status) (stamp (- not-after (floor (- not-after not-before) 3)))
                    ;; The v1beta1 terminal condition clients wait on.
                    (gethash "conditions" status)
                    (vector (core-object "type" "Issued" "status" "True" "reason" "Issued"
                                         "message" "gr8s built-in signer issued the certificate"
                                         "lastTransitionTime" (stamp not-before)))
                    (gethash "status" current) status))
            current)))))))

(defun reconcile-pod-certificate-requests (store pki)
  "Sign every eligible PodCertificateRequest for a gr8s-hosted signer, resuming
   after a restart. Requests for other signers are left Pending for their owner."
  (dolist (snapshot (list-core-resources store "podcertificaterequests"))
    (when (pod-certificate-request-ready-for-signing-p snapshot)
      (handler-case (sign-pod-certificate-request store pki snapshot)
        (error (condition)
          (format *error-output* "gr8s pod certificate signing failed: ~A~%" condition)))))
  nil)
