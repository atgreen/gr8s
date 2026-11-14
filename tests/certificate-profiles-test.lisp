;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Preserve legitimate legacy enrollment credentials and the existing CA/pin
;;;; while distinguishing actual API-issued credentials at TLS/session trust
;;;; boundaries. Public API leaves still verify for their intended purpose;
;;;; signed certificatePolicies markers are checked across every policy entry.

(in-package #:gr8s/tests)
(def-suite certificate-profiles :in gr8s)
(in-suite certificate-profiles)

(test wireguard-public-key-matches-rfc-7748
  (is (equalp
       (gr8s.security::hex-to-octets
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
       (gr8s.security::wireguard-public-key
        (gr8s.security::hex-to-octets
         "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")))))

(test wireguard-node-key-persists-and-rotates-explicitly
  (with-temporary-store (store directory)
    (declare (ignore store))
    (multiple-value-bind (private-1 public-1)
        (gr8s.security::ensure-wireguard-key-pair directory)
      (is (= 32 (length private-1)))
      (is (= 32 (length public-1)))
      (is (= #o600
             (logand #o777
                     (sb-posix:stat-mode
                      (sb-posix:stat
                       (namestring
                        (gr8s.security::wireguard-private-key-path directory)))))))
      (multiple-value-bind (private-2 public-2)
          (gr8s.security::ensure-wireguard-key-pair directory)
        (is (equalp private-1 private-2))
        (is (equalp public-1 public-2)))
      (multiple-value-bind (private-3 public-3)
          (gr8s.security::rotate-wireguard-key-pair directory)
        (is-false (equalp private-1 private-3))
        (is-false (equalp public-1 public-3))
        (multiple-value-bind (private-4 public-4)
            (gr8s.security::ensure-wireguard-key-pair directory)
          (is (equalp private-3 private-4))
          (is (equalp public-3 public-4)))))))

(test malformed-wireguard-node-key-is-never-silently-replaced
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let ((path (gr8s.security::wireguard-private-key-path directory)))
      (gr8s.security::write-private-text-atomically path "not-a-wireguard-key\n")
      (signals error (gr8s.security::ensure-wireguard-key-pair directory))
      (is (string= "not-a-wireguard-key\n" (uiop:read-file-string path))))))

(defun profile-test-issued-csr (store directory pki subject signer usages sans
                                &optional (algorithm "ec"))
  "Create and explicitly approve a real request before running the genuine signer."
  (let ((request (csr-crypto-fixture directory algorithm :subject subject :sans sans)))
    (gr8s.resources::create-core-resource store "certificatesigningrequests" (csr-fixture request :signer signer :usages usages) nil)
    (approve-csr-fixture store "example-csr")
    (gr8s.resources::reconcile-certificate-signing-requests store pki)
    (trivial-utf-8:utf-8-bytes-to-string
      (gr8s.resources::core-base64-bytes (gethash "certificate" (gethash "status" (gr8s.resources::get-core-resource store "certificatesigningrequests" nil "example-csr"))) "certificate"))))

(test api-client-profile-is-valid-public-tls-but-cannot-open-an-internal-node-session
  (with-temporary-store (store directory)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "ca/" directory)))
           (pin (gr8s.security::cluster-pki-ca-fingerprint pki))
           (server (gr8s.apiserver::start-node-grpc-server store :pki pki :port 0))
           (legacy-key (merge-pathnames "legacy/node.key" directory))
           (legacy-cert (merge-pathnames "legacy/node.crt" directory))
           (legacy-ca (merge-pathnames "legacy/ca.crt" directory))
           (api-cert (merge-pathnames "api-client.pem" directory)))
      (unwind-protect
           (progn
             (gr8s.agent::enroll-node-over-grpc "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server) "profile-worker"
               (gr8s.security::create-join-token pki "profile-worker") pin legacy-key legacy-cert legacy-ca)
             ;; An RSA key keeps the hello's certificate request constructible,
             ;; so the rejection under test is the server's profile check.
             (let* ((pem (profile-test-issued-csr store directory pki "/CN=profile-worker/O=api-users"
                           "kubernetes.io/kube-apiserver-client" #("digital signature" "client auth") nil "rsa"))
                    (certificate (gr8s.security::certificate-from-pem pem)))
               (is-true (gr8s.security::api-csr-profile-certificate-p certificate))
               (is-true (pure-tls::verify-certificate-chain (list certificate) (list (gr8s.security::cluster-pki-ca-certificate pki)) :purpose :client-auth :trust-anchor-mode :replace))
               (let ((direct-failure (handler-case (gr8s.security::verify-node-certificate pki pem "profile-worker")
                                       (gr8s.security::pki-error (condition) condition))))
                 (is-true direct-failure)
                 (is (equal "certificate-purpose-mismatch" (gr8s.security::pki-error-reason direct-failure))))
               (gr8s.security::write-private-text-atomically api-cert pem)
               (gr8s.apiserver::publish-node-desired-state server "profile-worker" (empty-desired-snapshot))
               (let ((failure (handler-case
                                (gr8s.agent::run-node-session "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server) "profile-worker"
                                  (merge-pathnames "api-identity.json" directory) (lambda (snapshot) (declare (ignore snapshot)))
                                  :ca-certificate-path legacy-ca :certificate-path api-cert
                                  :private-key-path (merge-pathnames "rsa-key.pem" directory) :max-sessions 1)
                                (error (condition) condition))))
                 (is-true failure)
                 (is (search "PROTOCOL-ERROR" (princ-to-string failure))))
               (is-false (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "profile-worker"))))
             ;; The actual already-enrolled leaf/key remain usable, with no CA
             ;; replacement, pin update or hidden credential regeneration.
             (is (equal pin (gr8s.security::cluster-pki-ca-fingerprint (gr8s.security::ensure-cluster-pki (gr8s.security::cluster-pki-root pki)))))
             (is-false (gr8s.security::api-csr-profile-certificate-p (gr8s.security::certificate-from-pem (uiop:read-file-string legacy-cert))))
             (gr8s.agent::run-node-session "127.0.0.1" (gr8s.apiserver::node-grpc-server-port server) "profile-worker"
               (merge-pathnames "legacy-identity.json" directory) (lambda (snapshot) (declare (ignore snapshot)))
               :ca-certificate-path legacy-ca :certificate-path legacy-cert :private-key-path legacy-key :max-sessions 1)
             (is-true (gr8s.model::node-record-ready-p (gr8s.controllers::get-node store "profile-worker"))))
        (gr8s.apiserver::stop-node-grpc-server server)))))

(test api-serving-profile-does-not-authenticate-the-internal-control-server
  (with-temporary-store (store directory)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "ca/" directory)))
           (pem (profile-test-issued-csr store directory pki "/CN=system:node:worker/O=system:nodes"
                   "kubernetes.io/kubelet-serving" #("digital signature" "server auth") "DNS:gr8s-control"))
           (certificate (gr8s.security::certificate-from-pem pem))
           (path (merge-pathnames "api-server.pem" directory)) (server nil) (thread nil))
      (is-true (pure-tls::verify-certificate-chain (list certificate) (list (gr8s.security::cluster-pki-ca-certificate pki)) :purpose :server-auth :trust-anchor-mode :replace))
      (finishes (pure-tls::verify-hostname certificate "gr8s-control"))
      (gr8s.security::write-private-text-atomically path pem)
      (setf server (ag-grpc:make-grpc-server 0 :host "127.0.0.1" :tls t :tls-certificate (namestring path)
                                            :tls-key (namestring (merge-pathnames "ec-key.pem" directory))))
      (unwind-protect
           (progn
             (setf thread (bt:make-thread (lambda () (ag-grpc:server-start server)) :name "CSR profile TLS proof server"))
             (is-true (wait-until (lambda () (and (eql :running (ag-grpc:server-state server)) (ag-grpc::server-socket server)))))
             (let ((failure (handler-case
                              (gr8s.security::make-node-tls-channel "127.0.0.1" (usocket:get-local-port (ag-grpc::server-socket server))
                                :ca-certificate-path (gr8s.security::cluster-pki-ca-certificate-path pki))
                              (gr8s.security::pki-error (condition) condition))))
               (is-true failure)
               (is (equal "certificate-purpose-mismatch" (gr8s.security::pki-error-reason failure)))))
        (ag-grpc:server-stop server)
        (when thread (bt:join-thread thread))))))

(test issuer-controls-the-single-profile-policy-regardless-of-requested-policies
  (with-temporary-store (store directory)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "ca/" directory)))
           (request (csr-crypto-fixture directory "ec" :extra-extensions '("certificatePolicies=1.2.3.4"))))
      (gr8s.resources::create-core-resource store "certificatesigningrequests"
        (csr-fixture request :signer "kubernetes.io/kube-apiserver-client" :usages #("client auth")) nil)
      (approve-csr-fixture store "example-csr")
      (gr8s.resources::reconcile-certificate-signing-requests store pki)
      (let* ((pem (gr8s.resources::core-base64-bytes (gethash "certificate" (gethash "status" (gr8s.resources::get-core-resource store "certificatesigningrequests" nil "example-csr"))) "certificate"))
             (certificate (pure-tls:parse-certificate (cdar (gr8s.security::csr-pem-blocks pem))))
             (extension (find (pure-tls::oid-name gr8s.security::+oid-certificate-policies+) (pure-tls::x509-certificate-extensions certificate)
                              :test #'equal :key #'pure-tls::x509-extension-oid))
             (policies (pure-tls::asn1-children (pure-tls::parse-der (pure-tls::x509-extension-value extension)))))
        (is (= 1 (length policies)))
        (is-false (pure-tls::x509-extension-critical extension))
        (is (equal gr8s.security::+api-csr-profile-policy-oid+ (pure-tls::asn1-node-value (first (pure-tls::asn1-children (first policies))))))))))

(test profile-policy-parser-inspects-every-policy-information-entry
  ;; This unsigned object checks only the parser; actual signature/purpose
  ;; authentication is exercised separately through TLS/session tests above.
  (let* ((value (pure-tls/acme::encode-sequence
                  (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid '(1 2 3 4)))
                  (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid gr8s.security::+api-csr-profile-policy-oid+))))
         (certificate (pure-tls::make-x509-certificate :extensions
                        (list (pure-tls::make-x509-extension :oid (pure-tls::oid-name gr8s.security::+oid-certificate-policies+) :value value)))))
    (is-true (gr8s.security::api-csr-profile-certificate-p certificate))))
