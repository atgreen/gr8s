;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; PodCertificateRequest (KEP-4317) is the namespaced certificates.k8s.io
;;;; /v1alpha1 object a node creates to get a short-lived pod X.509 from a
;;;; signer, which fills status.certificateChain. Exercise its CRUD, the
;;;; required signerName, that /status routes, and discovery.

(in-package #:gr8s/tests)

(in-suite gr8s)

(defun make-podcertificaterequest (name)
  (gr8s::core-object
   "apiVersion" "certificates.k8s.io/v1alpha1" "kind" "PodCertificateRequest"
   "metadata" (gr8s::core-object "name" name "namespace" "default")
   "spec" (gr8s::core-object
           "signerName" "podidentity.podcert.ate.dev/identity"
           "podName" "demo" "podUID" "11111111-1111-1111-1111-111111111111"
           "serviceAccountName" "sa" "nodeName" "gr8s-local"
           "pkixPublicKey" "AAAABBBB")))

(test podcertificaterequest-is-a-namespaced-v1alpha1-resource-with-status
  (with-temporary-store (store directory)
    (gr8s::create-core-resource store "podcertificaterequests"
                                (make-podcertificaterequest "pcr-1") "default")
    (let ((got (gr8s::get-core-resource store "podcertificaterequests" "default" "pcr-1")))
      (is (string= "PodCertificateRequest" (gethash "kind" got)))
      (is (string= "certificates.k8s.io/v1alpha1" (gethash "apiVersion" got)))
      (is (string= "podidentity.podcert.ate.dev/identity"
                   (gethash "signerName" (gethash "spec" got)))))
    (is (= 1 (length (gr8s::list-core-resources store "podcertificaterequests"))))
    ;; signerName is required.
    (signals gr8s:kubernetes-error
      (gr8s::create-core-resource
       store "podcertificaterequests"
       (gr8s::core-object "apiVersion" "certificates.k8s.io/v1alpha1" "kind" "PodCertificateRequest"
                          "metadata" (gr8s::core-object "name" "bad" "namespace" "default")
                          "spec" (gr8s::core-object))
       "default"))
    ;; The signer's status endpoint resolves (so it can write certificateChain).
    (is (equal '("podcertificaterequests" "default" "pcr-1")
               (gr8s::typed-status-route
                "/apis/certificates.k8s.io/v1alpha1/namespaces/default/podcertificaterequests/pcr-1/status"))))
  ;; Discovery advertises it, namespaced, under certificates.k8s.io/v1alpha1.
  (let ((entry (find "podcertificaterequests"
                     (gr8s::stored-resource-discovery "certificates.k8s.io/v1alpha1")
                     :key (lambda (r) (gethash "name" r)) :test #'equal)))
    (is (not (null entry)))
    (is (eq t (gethash "namespaced" entry)))
    (is (string= "PodCertificateRequest" (gethash "kind" entry)))))

(test podcertificaterequest-builders-produce-request-and-bundle
  ;; The request object carries the pod/SA/node identity and public key a signer
  ;; verifies.
  (let* ((pcr (gr8s::build-pod-certificate-request
               :name "demo-cert" :namespace "ate-system"
               :signer-name "podidentity.podcert.ate.dev/identity"
               :pkix-public-key "QkFTRTY0REVS"
               :pod-name "demo" :pod-uid "uid-1"
               :service-account-name "atenet" :service-account-uid "sa-uid"
               :node-name "gr8s-local" :node-uid "node-uid"
               :max-expiration-seconds 3600))
         (spec (gethash "spec" pcr)))
    (is (string= "PodCertificateRequest" (gethash "kind" pcr)))
    (is (string= "certificates.k8s.io/v1alpha1" (gethash "apiVersion" pcr)))
    (is (string= "ate-system" (gethash "namespace" (gethash "metadata" pcr))))
    (is (string= "podidentity.podcert.ate.dev/identity" (gethash "signerName" spec)))
    (is (string= "QkFTRTY0REVS" (gethash "pkixPublicKey" spec)))
    (is (string= "gr8s-local" (gethash "nodeName" spec)))
    (is (eql 3600 (gethash "maxExpirationSeconds" spec))))
  ;; The credential bundle is the key PEM then the chain PEM, with a newline
  ;; boundary even when the key lacks a trailing newline.
  (is (string= (format nil "KEY~%CHAIN~%")
               (gr8s::pod-certificate-credential-bundle "KEY" (format nil "CHAIN~%"))))
  (is (string= (format nil "KEY~%CHAIN~%")
               (gr8s::pod-certificate-credential-bundle (format nil "KEY~%") (format nil "CHAIN~%")))))
