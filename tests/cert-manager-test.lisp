;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the cert-manager.io/v1 subset: durable CRUD + discovery for
;;;; Issuer/ClusterIssuer/Certificate/CertificateRequest, fail-closed validation,
;;;; and the control-plane controller that issues leaves (selfSigned and ca) into
;;;; kubernetes.io/tls Secrets, records status, and renews on schedule.

(in-package #:gr8s/tests)
(def-suite cert-manager :in gr8s)
(in-suite cert-manager)

(defun cm-parse (json) (com.inuoe.jzon:parse json))

(defparameter *cm-selfsigned-issuer*
  "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"ClusterIssuer\",\"metadata\":{\"name\":\"selfsigned\"},\"spec\":{\"selfSigned\":{}}}")
(defparameter *cm-ca-issuer*
  "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Issuer\",\"metadata\":{\"name\":\"ca\",\"namespace\":\"certs\"},\"spec\":{\"ca\":{\"secretName\":\"ca-key-pair\"}}}")
(defparameter *cm-certificate*
  "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Certificate\",\"metadata\":{\"name\":\"web\",\"namespace\":\"certs\"},\"spec\":{\"secretName\":\"web-tls\",\"issuerRef\":{\"name\":\"selfsigned\",\"kind\":\"ClusterIssuer\"},\"dnsNames\":[\"web.example.com\",\"api.example.com\"],\"duration\":\"24h\"}}")
(defparameter *cm-certificaterequest*
  "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"CertificateRequest\",\"metadata\":{\"name\":\"req\",\"namespace\":\"certs\"},\"spec\":{\"issuerRef\":{\"name\":\"selfsigned\"},\"request\":\"Zm9v\"}}")

(test cert-manager-objects-persist-and-discover
  (with-core-api (store directory)
    (check-core-status 201 "/api/v1/namespaces" :method :post
                       :object (cm-parse "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"certs\"}}"))
    (let ((cases
            (list
             (list "/apis/cert-manager.io/v1/clusterissuers" "clusterissuers" nil "selfsigned" (cm-parse *cm-selfsigned-issuer*))
             (list "/apis/cert-manager.io/v1/namespaces/certs/issuers" "issuers" "certs" "ca" (cm-parse *cm-ca-issuer*))
             (list "/apis/cert-manager.io/v1/namespaces/certs/certificates" "certificates" "certs" "web" (cm-parse *cm-certificate*))
             (list "/apis/cert-manager.io/v1/namespaces/certs/certificaterequests" "certificaterequests" "certs" "req" (cm-parse *cm-certificaterequest*)))))
      (dolist (c cases)
        (destructuring-bind (collection resource namespace name object) c
          (let* ((created (check-core-status 201 collection :method :post :object object))
                 (url (concatenate 'string collection "/" name)))
            (is (equal "cert-manager.io/v1" (gethash "apiVersion" created)))
            (is (equal namespace (gethash "namespace" (gethash "metadata" created))))
            (check-core-status 409 collection :method :post :object object)
            (is (equalp created (check-core-status 200 url)))
            (is (equalp created (gr8s.resources::get-core-resource (open-store directory) resource namespace name)))
            (is (= 1 (length (gethash "items" (check-core-status 200 collection)))))))))
    ;; ClusterIssuer is cluster-scoped: not reachable under a namespace.
    (check-core-status 404 "/apis/cert-manager.io/v1/namespaces/certs/clusterissuers/selfsigned")
    (let ((names (map 'list (lambda (g) (gethash "name" g))
                      (gethash "groups" (check-core-status 200 "/apis")))))
      (is (member "cert-manager.io" names :test #'equal)))
    (let ((group (check-core-status 200 "/apis/cert-manager.io")))
      (is (equal "APIGroup" (gethash "kind" group)))
      (is (equal "cert-manager.io" (gethash "name" group))))
    (let* ((discovery (check-core-status 200 "/apis/cert-manager.io/v1"))
           (resources (map 'list (lambda (r) (gethash "name" r)) (gethash "resources" discovery))))
      (is (= 4 (length resources)))
      (dolist (n '("issuers" "clusterissuers" "certificates" "certificaterequests"))
        (is (member n resources :test #'equal))))))

(test cert-manager-validation-fails-closed
  (with-core-api (store directory)
    (values store directory)
    (check-core-status 201 "/api/v1/namespaces" :method :post
                       :object (cm-parse "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"certs\"}}"))
    (flet ((bad (collection json) (check-core-status 422 collection :method :post :object (cm-parse json))))
      ;; Issuer with no configured type, two types, or an incomplete acme issuer.
      (bad "/apis/cert-manager.io/v1/clusterissuers"
           "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"ClusterIssuer\",\"metadata\":{\"name\":\"empty\"},\"spec\":{}}")
      (bad "/apis/cert-manager.io/v1/clusterissuers"
           "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"ClusterIssuer\",\"metadata\":{\"name\":\"two\"},\"spec\":{\"selfSigned\":{},\"ca\":{\"secretName\":\"x\"}}}")
      (bad "/apis/cert-manager.io/v1/clusterissuers"
           "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"ClusterIssuer\",\"metadata\":{\"name\":\"acme\"},\"spec\":{\"acme\":{\"server\":\"https://x\"}}}")
      (bad "/apis/cert-manager.io/v1/namespaces/certs/issuers"
           "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Issuer\",\"metadata\":{\"name\":\"nosecret\",\"namespace\":\"certs\"},\"spec\":{\"ca\":{}}}")
      ;; Certificate missing secretName, issuerRef.name, or any subject.
      (bad "/apis/cert-manager.io/v1/namespaces/certs/certificates"
           "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Certificate\",\"metadata\":{\"name\":\"a\",\"namespace\":\"certs\"},\"spec\":{\"issuerRef\":{\"name\":\"selfsigned\"},\"dnsNames\":[\"x\"]}}")
      (bad "/apis/cert-manager.io/v1/namespaces/certs/certificates"
           "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Certificate\",\"metadata\":{\"name\":\"b\",\"namespace\":\"certs\"},\"spec\":{\"secretName\":\"s\",\"issuerRef\":{}}}")
      (bad "/apis/cert-manager.io/v1/namespaces/certs/certificates"
           "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Certificate\",\"metadata\":{\"name\":\"c\",\"namespace\":\"certs\"},\"spec\":{\"secretName\":\"s\",\"issuerRef\":{\"name\":\"selfsigned\"}}}"))))

;;; --- Issuance / controller --------------------------------------------------

(defun cm-secret-pem (store namespace name key)
  "Return the decoded PEM string stored under Secret data KEY, or NIL."
  (let* ((secret (ignore-errors (gr8s.resources::get-core-resource store "secrets" namespace name)))
         (data (and secret (gethash "data" secret)))
         (encoded (and data (gethash key data))))
    (when encoded
      (trivial-utf-8:utf-8-bytes-to-string (ag-grpc:base64-decode encoded)))))

(defun cm-write-temp (pem directory name)
  (let ((path (merge-pathnames name (uiop:ensure-directory-pathname directory))))
    (with-open-file (s path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-string pem s))
    path))

(test cert-manager-issues-selfsigned-into-tls-secret
  (with-temporary-store (store directory)
    (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *cm-selfsigned-issuer*) nil)
    (gr8s.resources::create-core-resource store "certificates" (cm-parse *cm-certificate*) "certs")
    (gr8s.controllers::reconcile-certificates store nil)       ; selfSigned needs no PKI
    (let ((secret (gr8s.resources::get-core-resource store "secrets" "certs" "web-tls")))
      (is (equal "kubernetes.io/tls" (gethash "type" secret)))
      (is (gethash "tls.crt" (gethash "data" secret)))
      (is (gethash "tls.key" (gethash "data" secret))))
    (let ((cert-pem (cm-secret-pem store "certs" "web-tls" "tls.crt"))
          (key-pem (cm-secret-pem store "certs" "web-tls" "tls.key")))
      ;; The Gateway consumes these via the same pure-tls path: it must load.
      (let ((chain (handler-bind ((warning #'muffle-warning))
                     (pure-tls:load-certificate-chain
                      (cm-write-temp cert-pem directory "web.crt")))))
        (is (= 1 (length chain))))
      (is (pure-tls:load-private-key (cm-write-temp key-pem directory "web.key")))
      ;; The SAN carries both dnsNames (IA5Strings in the DER, not the base64 PEM).
      (let ((der (pure-tls::pem-decode (babel:string-to-octets cert-pem) "CERTIFICATE")))
        (is (search (babel:string-to-octets "web.example.com") der))
        (is (search (babel:string-to-octets "api.example.com") der))))
    ;; Status records Ready + a renewalTime.
    (let* ((cert (gr8s.resources::get-core-resource store "certificates" "certs" "web"))
           (status (gethash "status" cert)))
      (is (equal "True" (gethash "status" (aref (gethash "conditions" status) 0))))
      (is (stringp (gethash "renewalTime" status)))
      (is (stringp (gethash "notAfter" status))))))

(test cert-manager-ca-issuer-signs-from-cluster-ca
  (with-temporary-store (store directory)
    (let ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki-root/" (uiop:ensure-directory-pathname directory)))))
      (gr8s.resources::create-core-resource store "issuers" (cm-parse *cm-ca-issuer*) "certs")
      (gr8s.resources::create-core-resource store "certificates"
        (cm-parse "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Certificate\",\"metadata\":{\"name\":\"svc\",\"namespace\":\"certs\"},\"spec\":{\"secretName\":\"svc-tls\",\"issuerRef\":{\"name\":\"ca\",\"kind\":\"Issuer\"},\"dnsNames\":[\"svc.example.com\"]}}")
        "certs")
      (gr8s.controllers::reconcile-certificates store pki)
      (let ((cert-pem (cm-secret-pem store "certs" "svc-tls" "tls.crt")))
        (is (stringp cert-pem))
        (let ((leaf (first (handler-bind ((warning #'muffle-warning))
                             (pure-tls:load-certificate-chain (cm-write-temp cert-pem directory "svc.crt"))))))
          (is (not (null leaf)))
          ;; A clean verify against the cluster CA means the leaf was CA-signed
          ;; (verify-certificate-chain signals on any failure).
          (is (progn (pure-tls::verify-certificate-chain
                      (list leaf) (list (gr8s.security::cluster-pki-ca-certificate pki))
                      :purpose :server-auth :trust-anchor-mode :replace)
                     t)))))))

(test cert-manager-reissues-after-renewal-time
  (with-temporary-store (store directory)
    (values directory)
    (let ((gr8s.controllers::*cert-manager-clock* (let ((now (get-universal-time))) (lambda () now))))
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *cm-selfsigned-issuer*) nil)
      (gr8s.resources::create-core-resource store "certificates" (cm-parse *cm-certificate*) "certs")
      (gr8s.controllers::reconcile-certificates store nil)
      (is (not (gr8s.controllers::cm-certificate-needs-issue-p
                store (gr8s.resources::get-core-resource store "certificates" "certs" "web"))))
      ;; Advance the clock past renewalTime (duration 24h, renewBefore default 8h).
      (let ((future (+ (funcall gr8s.controllers::*cert-manager-clock*) (* 20 3600))))
        (setf gr8s.controllers::*cert-manager-clock* (lambda () future)))
      (is (gr8s.controllers::cm-certificate-needs-issue-p
           store (gr8s.resources::get-core-resource store "certificates" "certs" "web")))
      ;; A reconcile at the later time refreshes the stored renewalTime.
      (let ((before (gethash "renewalTime" (gethash "status" (gr8s.resources::get-core-resource store "certificates" "certs" "web")))))
        (gr8s.controllers::reconcile-certificates store nil)
        (let ((after (gethash "renewalTime" (gethash "status" (gr8s.resources::get-core-resource store "certificates" "certs" "web")))))
          (is (not (equal before after))))))))

(defun cm-openssl-san (cert-pem directory)
  "The subjectAltName text openssl prints for CERT-PEM."
  (uiop:run-program (list "openssl" "x509" "-noout" "-ext" "subjectAltName" "-subject"
                          "-in" (namestring (cm-write-temp cert-pem directory "san.crt")))
                    :output :string))

(test certificate-ip-address-literals-are-strict
  (flet ((octets (address) (gr8s.resources::certificate-ip-address-octets address)))
    (is (equalp #(10 77 77 21) (octets "10.77.77.21")))
    (is (equalp #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1) (octets "::1")))
    (is (equalp #(#xfd 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1) (octets "fd00::1")))
    (is (equalp #(0 0 0 0 0 0 0 0 0 0 #xff #xff 1 2 3 4) (octets "::ffff:1.2.3.4")))
    (is (equalp #(0 1 0 2 0 3 0 4 0 5 0 6 0 7 0 8) (octets "1:2:3:4:5:6:7:8")))
    (dolist (bad '("01.2.3.4" "1.2.3" "1.2.3.4.5" "256.1.1.1" "" "host.example"
                   "fe80::1%eth0" "1::2::3" "1:2:3:4:5:6:7:8:9" "1:2:3:4:5:6:7:8::" "10000::1"
                   "1.2.3.4::" ":::" "1:2:3:4:5:6:7"))
      (is (null (octets bad)) "~S should not parse as an IP address" bad))))

(test cert-manager-validates-ip-addresses
  (with-core-api (store directory)
    (values store directory)
    (check-core-status 201 "/api/v1/namespaces" :method :post
                       :object (cm-parse "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"certs\"}}"))
    (flet ((certificate (name ips)
             (cm-parse (format nil "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Certificate\",\"metadata\":{\"name\":~S,\"namespace\":\"certs\"},\"spec\":{\"secretName\":\"s\",\"issuerRef\":{\"name\":\"selfsigned\"},\"ipAddresses\":[~{~S~^,~}]}}" name ips))))
      ;; ipAddresses alone are a subject, as in cert-manager.
      (check-core-status 201 "/apis/cert-manager.io/v1/namespaces/certs/certificates"
                         :method :post :object (certificate "ip-only" '("10.77.77.21" "fd00::1")))
      (check-core-status 422 "/apis/cert-manager.io/v1/namespaces/certs/certificates"
                         :method :post :object (certificate "bad-ip" '("10.77.77.21" "01.2.3.4"))))))

(test cert-manager-issues-every-subject-alt-name
  (with-temporary-store (store directory)
    (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *cm-selfsigned-issuer*) nil)
    (gr8s.resources::create-core-resource store "certificates"
      (cm-parse "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Certificate\",\"metadata\":{\"name\":\"reg\",\"namespace\":\"certs\"},\"spec\":{\"secretName\":\"reg-tls\",\"issuerRef\":{\"name\":\"selfsigned\",\"kind\":\"ClusterIssuer\"},\"dnsNames\":[\"registry.example.com\"],\"ipAddresses\":[\"10.77.77.21\",\"fd00::1\"],\"uris\":[\"spiffe://lab/registry\"],\"emailAddresses\":[\"ops@example.com\"]}}")
      "certs")
    (gr8s.controllers::reconcile-certificates store nil)
    (let ((san (cm-openssl-san (cm-secret-pem store "certs" "reg-tls" "tls.crt") directory)))
      (dolist (expected '("DNS:registry.example.com" "IP Address:10.77.77.21" "IP Address:FD00:0:0:0:0:0:0:1"
                          "URI:spiffe://lab/registry" "email:ops@example.com" "CN=registry.example.com"))
        (is (search expected san) "~A missing from ~A" expected san)))
    ;; With only IP addresses, the first one names the subject.
    (gr8s.resources::create-core-resource store "certificates"
      (cm-parse "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Certificate\",\"metadata\":{\"name\":\"bare\",\"namespace\":\"certs\"},\"spec\":{\"secretName\":\"bare-tls\",\"issuerRef\":{\"name\":\"selfsigned\",\"kind\":\"ClusterIssuer\"},\"ipAddresses\":[\"192.0.2.7\"]}}")
      "certs")
    (gr8s.controllers::reconcile-certificates store nil)
    (let ((san (cm-openssl-san (cm-secret-pem store "certs" "bare-tls" "tls.crt") directory)))
      (is (search "IP Address:192.0.2.7" san))
      (is (search "CN=192.0.2.7" san)))))

(test cert-manager-reissues-when-identity-changes
  (with-temporary-store (store directory)
    (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *cm-selfsigned-issuer*) nil)
    (gr8s.resources::create-core-resource store "certificates" (cm-parse *cm-certificate*) "certs")
    (gr8s.controllers::reconcile-certificates store nil)
    (flet ((certificate () (gr8s.resources::get-core-resource store "certificates" "certs" "web")))
      (is (not (gr8s.controllers::cm-certificate-needs-issue-p store (certificate))))
      ;; Adding an IP address to the spec reissues the leaf with it.
      (gr8s.resources::update-core-resource store "certificates" "certs" "web"
        (lambda (object)
          (setf (gethash "ipAddresses" (gethash "spec" object)) (vector "10.0.0.9"))
          object))
      (is (gr8s.controllers::cm-certificate-needs-issue-p store (certificate)))
      (gr8s.controllers::reconcile-certificates store nil)
      (is (not (gr8s.controllers::cm-certificate-needs-issue-p store (certificate))))
      (is (search "IP Address:10.0.0.9"
                  (cm-openssl-san (cm-secret-pem store "certs" "web-tls" "tls.crt") directory)))
      ;; A Secret issued before identities were recorded (no annotation) reissues once.
      (gr8s.resources::update-core-resource store "secrets" "certs" "web-tls"
        (lambda (secret)
          (remhash "gr8s.io/certificate-identity" (gethash "annotations" (gethash "metadata" secret)))
          secret))
      (is (gr8s.controllers::cm-certificate-needs-issue-p store (certificate)))
      (gr8s.controllers::reconcile-certificates store nil)
      (is (not (gr8s.controllers::cm-certificate-needs-issue-p store (certificate)))))))

(test managed-ca-leaf-passes-strict-openssl-chain-validation
  (with-temporary-pki (pki root)
    (multiple-value-bind (subject signer issuer)
        (gr8s.controllers::cm-issuer-signer pki (gr8s.resources::core-object "ca" (gr8s.resources::core-object)))
      (multiple-value-bind (certificate key before after)
          (gr8s.controllers::cm-issue-leaf :common-name "strict.test" :dns-names '("strict.test")
                                          :duration-seconds 3600 :issuer-subject-der subject
                                          :signer-key signer :issuer-certificate issuer)
        (declare (ignore key before after))
        (let ((path (merge-pathnames "managed-strict.crt" root)))
          (with-open-file (out path :direction :output :if-exists :error) (write-string certificate out))
          (multiple-value-bind (out err status)
              (uiop:run-program (list "openssl" "verify" "-x509_strict" "-purpose" "sslserver"
                                     "-CAfile" (namestring (gr8s.security::cluster-pki-ca-certificate-path pki))
                                     (namestring path)) :output :string :error-output :string :ignore-error-status t)
            (is (zerop status) "Managed leaf strict validation failed: ~A ~A" out err)))))))
