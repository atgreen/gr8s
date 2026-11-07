;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; podCertificate projected volumes (KEP-4317): the node generates a pod's
;;;; keypair locally and reports a signed PKCS#10 stub as a claim; the control
;;;; plane turns the claim into a PodCertificateRequest; a built-in signer issues
;;;; a short-lived SPIFFE leaf from the cluster CA; and the node mounts the
;;;; credential bundle only once the request is signed, gating the pod until then.

(in-package #:gr8s/tests)
(in-suite gr8s)

(defparameter *pod-certificate-volume*
  "[{\"name\":\"svid\",\"projected\":{\"defaultMode\":384,\"sources\":[{\"podCertificate\":{
      \"signerName\":\"podidentity.podcert.ate.dev/identity\",\"keyType\":\"ECDSAP256\",
      \"credentialBundlePath\":\"creds.pem\",\"keyPath\":\"key.pem\",\"certificateChainPath\":\"chain.pem\"}}]}}]")

(defun pod-certificate-source (&rest pairs)
  (apply #'gr8s::core-object pairs))

;;; --- admission ---------------------------------------------------------------

(test pod-certificate-source-admission
  (flet ((validate (part)
           (gr8s::validate-projected-source
            (gr8s::core-object "sources" (vector (gr8s::core-object "podCertificate" part))))))
    ;; A well-formed source with a signer, the one supported keyType and a path.
    (finishes (validate (pod-certificate-source "signerName" "s" "keyType" "ECDSAP256"
                                                "credentialBundlePath" "creds.pem")))
    ;; signerName is required.
    (signals gr8s:kubernetes-error (validate (pod-certificate-source "keyType" "ECDSAP256" "keyPath" "k")))
    ;; Only ECDSAP256 is issued.
    (signals gr8s:kubernetes-error (validate (pod-certificate-source "signerName" "s" "keyType" "RSA3072"
                                                                     "keyPath" "k")))
    ;; At least one output path is required.
    (signals gr8s:kubernetes-error (validate (pod-certificate-source "signerName" "s" "keyType" "ECDSAP256")))
    ;; maxExpirationSeconds is bounded below by one hour.
    (signals gr8s:kubernetes-error (validate (pod-certificate-source "signerName" "s" "keyType" "ECDSAP256"
                                                                     "keyPath" "k" "maxExpirationSeconds" 60)))
    ;; Two output paths cannot collide.
    (signals gr8s:kubernetes-error (validate (pod-certificate-source "signerName" "s" "keyType" "ECDSAP256"
                                                                     "keyPath" "same" "certificateChainPath" "same")))
    ;; userAnnotations (string map, copied into unverifiedUserAnnotations) and
    ;; user (file-owner UID) are accepted; a non-UID user is refused.
    (finishes (validate (pod-certificate-source "signerName" "s" "keyType" "ECDSAP256" "keyPath" "k"
                                                "userAnnotations" (gr8s::core-object "postgres.podcert.ate.dev/username" "owner")
                                                "user" 65532)))
    (signals gr8s:kubernetes-error (validate (pod-certificate-source "signerName" "s" "keyType" "ECDSAP256"
                                                                     "keyPath" "k" "user" -1)))))

(test pod-certificate-private-key-is-pkcs8-not-sec1
  ;; KEP-4317 credential bundles carry the key as PKCS#8 (PEM "PRIVATE KEY").
  ;; SEC1 ("EC PRIVATE KEY") is rejected by strict loaders such as Agent
  ;; Substrate's objectstore-plugin ("unknown PEM block type EC PRIVATE KEY").
  (multiple-value-bind (priv pub) (ironclad:generate-key-pair :secp256r1)
    (declare (ignore pub))
    (let ((pem (gr8s::ec-private-key-pkcs8-pem priv)))
      (is (uiop:string-prefix-p "-----BEGIN PRIVATE KEY-----" pem))
      (is (null (search "EC PRIVATE KEY" pem)))
      ;; It parses back as a valid PKCS#8 key.
      (finishes (pure-tls::parse-pkcs8-private-key
                 (pure-tls::pem-decode (trivial-utf-8:string-to-utf-8-bytes pem) "PRIVATE KEY"))))))

;;; --- node: claim, gating, projection -----------------------------------------

(defun count-pem-certificates (text)
  (loop with needle = "BEGIN CERTIFICATE" for start = 0 then (+ hit (length needle))
        for hit = (search needle text :start2 start) while hit count hit))

(test pod-certificate-node-gates-then-mounts
  (with-projection (runtime store directory)
    (let* ((pod (create-pod store (projection-pod *pod-certificate-volume*)))
           (volume (aref (gethash "volumes" (gethash "spec" (gr8s::pod-to-object pod))) 0)))
      ;; Before any request is signed, the node signals pending, so the volume is
      ;; not materialized and the pod stays Pending.
      (signals gr8s:runtime-error (gr8s::pod-volume-desired-files runtime pod volume))
      ;; Generating the keypair left exactly one claim to report, with the pod's
      ;; identity and the signed PKCS#10 stub -- and no private key or deprecated
      ;; v1beta1 public-key field.
      (let ((claims (gr8s::node-pending-pod-certificate-claims store)))
        (is (= 1 (length claims)))
        (let ((claim (first claims)))
          (is (string= "sonobuoy" (getf claim :namespace)))
          (is (string= "podidentity.podcert.ate.dev/identity" (getf claim :signer-name)))
          (is (string= "projected" (getf claim :pod-name)))
          (is (plusp (length (getf claim :stub-pkcs10-request))))
          (is (zerop (length (getf claim :pkix-public-key ""))))
          ;; The claim carries no private key material of any kind.
          (is (null (getf claim :private-key-pem)))
          ;; A source that names no lifetime still gets the kubelet default, so
          ;; signers that dereference maxExpirationSeconds don't see nil.
          (is (eql 86400 (getf claim :max-expiration-seconds))))
        ;; The claim name is stable across retries (same keypair, same request).
        (signals gr8s:runtime-error (gr8s::pod-volume-desired-files runtime pod volume))
        (is (string= (getf (first (gr8s::node-pending-pod-certificate-claims store)) :name)
                     (getf (first claims) :name))))
      ;; Simulate the signer having filled the request's status in this node's
      ;; store (what the projection delivers): the node now mounts the bundle.
      (let* ((claim (first (gr8s::node-pending-pod-certificate-claims store)))
             (name (getf claim :name)))
        (gr8s::create-core-resource
         store "podcertificaterequests"
         (gr8s::build-pod-certificate-request :name name :namespace "sonobuoy"
                                              :signer-name "podidentity.podcert.ate.dev/identity"
                                              :pkix-public-key (getf claim :pkix-public-key)
                                              :pod-name "projected" :pod-uid (gr8s::pod-uid pod))
         "sonobuoy")
        (gr8s::update-core-resource store "podcertificaterequests" "sonobuoy" name
          (lambda (current)
            (setf (gethash "status" current)
                  (gr8s::core-object "certificateChain" (format nil "-----BEGIN CERTIFICATE-----~%LEAF~%-----END CERTIFICATE-----~%")))
            current))
        (let ((files (gr8s::pod-volume-desired-files runtime pod volume)))
          (is (= 3 (length files)))
          (flet ((file-text (path)
                   (trivial-utf-8:utf-8-bytes-to-string
                    (second (find path files :key #'first :test #'equal)))))
            ;; The credential bundle is the private key PEM then the chain PEM.
            (let ((bundle (file-text "creds.pem")) (key (file-text "key.pem")) (chain (file-text "chain.pem")))
              (is (uiop:string-prefix-p "-----BEGIN PRIVATE KEY-----" key))
              (is (search "BEGIN CERTIFICATE" chain))
              (is (string= bundle (gr8s::pod-certificate-credential-bundle key chain))))))))))

;;; --- control plane: claim -> request, built-in signer -----------------------

(defun pod-certificate-claim-from (store)
  "Build the node-protocol claim message for the single pending claim in STORE."
  (gr8s::pod-certificate-claim-message (first (gr8s::node-pending-pod-certificate-claims store))))

(test pod-certificate-user-annotations-reach-the-request
  (with-projection (runtime store directory)
    (values directory)
    (let* ((object (gr8s::pod-to-object (projection-pod *pod-certificate-volume*)))
           (volume (aref (gethash "volumes" (gethash "spec" object)) 0))
           (source (gethash "podCertificate"
                            (aref (gethash "sources" (gethash "projected" volume)) 0))))
      (setf (gethash "userAnnotations" source)
            (gr8s::core-object "postgres.podcert.ate.dev/username" "owner"))
      (let* ((pod (create-pod store (parse-pod object)))
             (stored-volume (aref (gethash "volumes" (gethash "spec" (gr8s::pod-to-object pod))) 0)))
        (signals gr8s:runtime-error
          (gr8s::pod-volume-desired-files runtime pod stored-volume))
        (let* ((claim (pod-certificate-claim-from store))
               (name (gr8s.node.v1::name claim)))
          (gr8s::ensure-pod-certificate-request-from-claim store "n1" claim)
          (let* ((request (gr8s::get-core-resource store "podcertificaterequests" "sonobuoy" name))
                 (annotations (gethash "unverifiedUserAnnotations" (gethash "spec" request))))
            (is (string= "owner"
                         (gethash "postgres.podcert.ate.dev/username" annotations)))))))))

(test pod-certificate-control-plane-creates-and-signs
  ;; Exercise gr8s's optional built-in signer (off by default) by opting this
  ;; signer name in, as a standalone gr8s without Agent Substrate would.
  (let ((gr8s::*pod-certificate-signers* '("podidentity.podcert.ate.dev/identity")))
   (with-projection (runtime store directory)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (pod (create-pod store (projection-pod *pod-certificate-volume*)))
           (volume (aref (gethash "volumes" (gethash "spec" (gr8s::pod-to-object pod))) 0)))
      (signals gr8s:runtime-error (gr8s::pod-volume-desired-files runtime pod volume))
      ;; The control plane turns the node's claim into a PodCertificateRequest,
      ;; attributing the node from the (here simulated) session.
      (let* ((claim (pod-certificate-claim-from store))
             (name (gr8s.node.v1::name claim)))
        (gr8s::ensure-pod-certificate-request-from-claim store "n1" claim)
        (let ((pcr (gr8s::get-core-resource store "podcertificaterequests" "sonobuoy" name)))
          (is (string= "n1" (gethash "nodeName" (gethash "spec" pcr))))
          (let ((spec (gethash "spec" pcr)))
            (is (string= (gr8s.node.v1::stub-pkcs10-request claim)
                         (gethash "stubPKCS10Request" spec)))
            (multiple-value-bind (value present) (gethash "pkixPublicKey" spec)
              (declare (ignore value))
              (is (null present))))
          (is (zerop (length (gethash "certificateChain" (gethash "status" pcr (gr8s::core-object)) "")))))
        ;; A second claim for the same key is idempotent (no duplicate/replace).
        (gr8s::ensure-pod-certificate-request-from-claim store "n1" claim)
        (is (= 1 (length (gr8s::list-core-resources store "podcertificaterequests"))))
        ;; The built-in signer issues a two-cert SPIFFE chain from the cluster CA.
        (gr8s::reconcile-pod-certificate-requests store pki)
        (let* ((pcr (gr8s::get-core-resource store "podcertificaterequests" "sonobuoy" name))
               (status (gethash "status" pcr))
               (chain (gethash "certificateChain" status)))
          (is (= 2 (count-pem-certificates chain)))
          (is (plusp (length (gethash "notAfter" status))))
          (is (plusp (length (gethash "notBefore" status)))))
        ;; With the signed request in its store, the node now mounts the bundle.
        (let ((files (gr8s::pod-volume-desired-files runtime pod volume)))
          (is (= 3 (length files)))))))))

(test pod-certificate-signer-leaves-foreign-signers-pending
  ;; The built-in signer owns one name here; a request for any other signer is
  ;; left Pending for whatever controller owns it (e.g. Agent Substrate's).
  (let ((gr8s::*pod-certificate-signers* '("podidentity.podcert.ate.dev/identity")))
   (with-temporary-store (store directory)
    (let ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory))))
      (gr8s::create-core-resource
       store "podcertificaterequests"
       (gr8s::build-pod-certificate-request :name "foreign" :namespace "default"
                                            :signer-name "example.com/other"
                                            :pkix-public-key "QUJD" :pod-name "p" :pod-uid "u")
       "default")
      (gr8s::reconcile-pod-certificate-requests store pki)
      (let ((pcr (gr8s::get-core-resource store "podcertificaterequests" "default" "foreign")))
        (is (zerop (length (gethash "certificateChain" (gethash "status" pcr (gr8s::core-object)) "")))))))))

;;; --- projection back to the node --------------------------------------------

(test pod-certificate-request-projects-spec-and-status-to-node
  (with-temporary-store (store directory)
    (gr8s::create-core-resource
     store "podcertificaterequests"
     (gr8s::build-pod-certificate-request :name "req" :namespace "ate-system"
                                          :signer-name "podidentity.podcert.ate.dev/identity"
                                          :pkix-public-key "QUJD" :pod-name "demo" :pod-uid "uid-1")
     "ate-system")
    (gr8s::update-core-resource store "podcertificaterequests" "ate-system" "req"
      (lambda (current)
        (setf (gethash "status" current) (gr8s::core-object "certificateChain" "PEM"))
        current))
    (let ((resources (make-hash-table :test #'equal)))
      (gr8s::install-service-discovery-projection
       resources (slot-value (gr8s::node-desired-state-snapshot store "n1")
                             'gr8s.node.v1::service-discovery-objects-json))
      (let ((projected (gethash (gr8s::core-resource-key "podcertificaterequests" "ate-system" "req") resources)))
        (is (not (null projected)))
        (is (string= "podidentity.podcert.ate.dev/identity" (gethash "signerName" (gethash "spec" projected))))
        (is (string= "PEM" (gethash "certificateChain" (gethash "status" projected))))))))
