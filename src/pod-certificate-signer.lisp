;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; The control-plane half of podCertificate projected volumes (KEP-4317). A
;;;; node reports a PodCertificateClaim -- the public key it generated for a pod,
;;;; with that pod's identity -- in its NodeStatus; here we turn each claim into
;;;; a PodCertificateRequest, attributing the node from the authenticated
;;;; session rather than the claim. A built-in signer then issues a short-lived
;;;; SPIFFE leaf from the cluster CA for the signers gr8s hosts, filling
;;;; status.certificateChain so the request can be projected back and mounted.

(in-package #:gr8s)

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
;;; Node claim -> PodCertificateRequest resource
;;; ---------------------------------------------------------------------------

(defun node-metadata-uid (store node-name)
  "The API UID of NODE-NAME, or NIL, for attributing a request to its node."
  (ignore-errors (gethash "uid" (gethash "metadata" (node-api-object (get-node store node-name))))))

(defun pod-certificate-request-matches-claim-p (pcr pod-uid pkix)
  "True when an existing PCR already belongs to this pod incarnation and key."
  (let ((spec (gethash "spec" pcr (core-object))))
    (and (equal pod-uid (gethash "podUID" spec))
         (equal pkix (gethash "pkixPublicKey" spec)))))

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
         (existing (ignore-errors (get-core-resource store "podcertificaterequests" namespace name))))
    (when (and existing (pod-certificate-request-matches-claim-p existing pod-uid pkix))
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
        :pkix-public-key pkix
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

(defun sign-pod-certificate-request (store pki object)
  "Issue the SPIFFE leaf for one eligible PodCertificateRequest, writing
   status.certificateChain, notBefore and notAfter under a conditional update so
   a concurrently changed request is left alone."
  (let* ((spec (gethash "spec" object)) (metadata (gethash "metadata" object))
         (pkix (gethash "pkixPublicKey" spec))
         (duration (let ((max (gethash "maxExpirationSeconds" spec)))
                     (if (and (integerp max) (plusp max))
                         (min max *pod-certificate-default-duration*)
                         *pod-certificate-default-duration*)))
         (spki (handler-case (core-base64-bytes pkix "pkixPublicKey")
                 (error () (return-from sign-pod-certificate-request nil))))
         (spiffe (pod-certificate-spiffe-id (gethash "namespace" metadata)
                                            (gethash "serviceAccountName" spec))))
    (multiple-value-bind (chain not-before not-after)
        (bt:with-lock-held ((cluster-pki-lock pki))
          (multiple-value-bind (leaf nb na)
              (pod-certificate-leaf-pem pki spki spiffe duration)
            (values (concatenate 'string leaf (pod-certificate-ca-pem pki)) nb na)))
      (flet ((stamp (seconds) (rfc3339-from-unix (- seconds 2208988800))))
        (update-core-resource store "podcertificaterequests" (gethash "namespace" metadata)
                               (gethash "name" metadata)
          (lambda (current)
            (unless (and (pod-certificate-request-ready-for-signing-p current)
                         (equal (gethash "uid" metadata) (gethash "uid" (gethash "metadata" current)))
                         (equal pkix (gethash "pkixPublicKey" (gethash "spec" current))))
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
            current))))))

(defun reconcile-pod-certificate-requests (store pki)
  "Sign every eligible PodCertificateRequest for a gr8s-hosted signer, resuming
   after a restart. Requests for other signers are left Pending for their owner."
  (dolist (snapshot (list-core-resources store "podcertificaterequests"))
    (when (pod-certificate-request-ready-for-signing-p snapshot)
      (handler-case (sign-pod-certificate-request store pki snapshot)
        (error (condition)
          (format *error-output* "gr8s pod certificate signing failed: ~A~%" condition)))))
  nil)
