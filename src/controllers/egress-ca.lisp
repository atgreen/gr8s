;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The egress CA (podster-wv1w.3). To add a credential to an HTTPS request the
;;;; node egress proxy must terminate the Pod's TLS, so it presents a certificate for
;;;; the destination host minted from this CA, and a Pod that wants credentials
;;;; injected trusts it through the gr8s-egress ClusterTrustBundle (a projected
;;;; clusterTrustBundle volume; gr8 mounts it for its sandbox).
;;;;
;;;; The control plane creates the CA once, as a kubernetes.io/tls Secret in
;;;; kube-system, and every node's snapshot carries it so any node can mint leaves for
;;;; the Pods it runs. It is a CA only for hosts that carry an injected credential, and
;;;; only Pods that mount the bundle trust it at all. A per-node CA, so one node's key
;;;; can't mint for another's Pods, is podster-wv1w follow-up work.

(in-package #:gr8s.controllers)

(defparameter +egress-ca-namespace+ "kube-system")
(defparameter +egress-ca-secret+ "gr8s-egress-ca")
(defparameter +egress-ca-bundle+ "gr8s-egress"
  "The ClusterTrustBundle Pods trust the egress proxy's certificates through.")

(defun ensure-egress-ca (store)
  "Create the egress CA Secret when it is missing, and keep the gr8s-egress
ClusterTrustBundle holding its certificate. Idempotent."
  (let ((secret (ignore-errors (get-core-resource store "secrets" +egress-ca-namespace+ +egress-ca-secret+))))
    (unless secret
      (multiple-value-bind (private-key public-key) (ironclad:generate-key-pair :secp256r1)
        (let ((certificate-pem (pure-tls/acme::wrap-pem
                                "CERTIFICATE"
                                (gr8s.security::ca-certificate-der private-key public-key :common-name "gr8s egress")))
              (key-pem (pure-tls/acme::encode-ec-private-key-pem private-key)))
          (create-core-resource
           store "secrets"
           (core-object "apiVersion" "v1" "kind" "Secret" "type" "kubernetes.io/tls"
                        "metadata" (core-object "name" +egress-ca-secret+ "namespace" +egress-ca-namespace+)
                        "data" (cm-tls-secret-data certificate-pem key-pem))
           +egress-ca-namespace+)
          (setf secret (get-core-resource store "secrets" +egress-ca-namespace+ +egress-ca-secret+)))))
    (let* ((certificate (trivial-utf-8:utf-8-bytes-to-string
                         (cl-base64:base64-string-to-usb8-array (gethash "tls.crt" (gethash "data" secret)))))
           (bundle (ignore-errors (get-core-resource store "clustertrustbundles" nil +egress-ca-bundle+))))
      (cond ((null bundle)
             (create-core-resource
              store "clustertrustbundles"
              (core-object "apiVersion" "certificates.k8s.io/v1" "kind" "ClusterTrustBundle"
                           "metadata" (core-object "name" +egress-ca-bundle+
                                                   "labels" (core-object "gr8s.io/egress" "true"))
                           "spec" (core-object "trustBundle" certificate))
              nil))
            ((not (equal certificate (gethash "trustBundle" (gethash "spec" bundle))))
             (update-core-resource store "clustertrustbundles" nil +egress-ca-bundle+
                                   (lambda (object)
                                     (setf (gethash "trustBundle" (gethash "spec" object)) certificate)
                                     object)))))))

(defun egress-ca-secrets (store)
  "The egress CA Secret, as a list for the node snapshot, or NIL before it exists."
  (let ((secret (ignore-errors (get-core-resource store "secrets" +egress-ca-namespace+ +egress-ca-secret+))))
    (when secret (list secret))))

(defun egress-ca-material (store)
  "The egress CA from STORE (a node's): (values private-key certificate), the key an
Ironclad key and the certificate parsed, or NIL before the CA reaches the node."
  (let ((secret (ignore-errors (get-core-resource store "secrets" +egress-ca-namespace+ +egress-ca-secret+))))
    (when secret
      (flet ((field (name) (cl-base64:base64-string-to-usb8-array (gethash name (gethash "data" secret)))))
        (values (pure-tls::parse-ec-private-key (pure-tls::pem-decode (field "tls.key") "EC PRIVATE KEY"))
                (pure-tls:parse-certificate (pure-tls::pem-decode (field "tls.crt") "CERTIFICATE")))))))

(defun make-egress-leaf-minter (ca-key ca-certificate &key (duration-seconds (* 7 24 60 60)))
  "A function from a host to (values certificate-chain key) for a leaf the egress CA
signs, cached per host until a day before it expires."
  (let ((cache (make-hash-table :test #'equal)) (lock (bt:make-lock "gr8s egress leaves")))
    (lambda (host)
      (bt:with-lock-held (lock)
        (let ((entry (gethash host cache)))
          (if (and entry (< (get-universal-time) (- (third entry) (* 24 60 60))))
              (values (first entry) (second entry))
              (multiple-value-bind (certificate-pem key-pem not-before not-after)
                  (cm-issue-leaf :dns-names (list host) :duration-seconds duration-seconds
                                 :issuer-subject-der (pure-tls/acme::encode-subject "gr8s egress")
                                 :signer-key ca-key :issuer-certificate ca-certificate)
                (declare (ignore not-before))
                (let ((chain (list (pure-tls:parse-certificate
                                    (pure-tls::pem-decode (babel:string-to-octets certificate-pem) "CERTIFICATE"))))
                      (key (pure-tls::parse-ec-private-key
                            (pure-tls::pem-decode (babel:string-to-octets key-pem) "EC PRIVATE KEY"))))
                  (setf (gethash host cache) (list chain key not-after))
                  (values chain key)))))))))
