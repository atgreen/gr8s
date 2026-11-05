;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise real CSR HTTP strategies and durable state with independently
;;;; generated cryptographic requests. Verify JSON/protobuf inputs, immutable
;;;; actor/spec fields, status/approval isolation, watches, finalizers and
;;;; actual built-in issuance through the cluster CA without autoapproval.

(in-package #:gr8s/tests)
(def-suite csr-apis :in gr8s)
(in-suite csr-apis)

(test csr-kubelet-policy-uses-the-last-signed-common-name
  (with-temporary-store (store directory)
    (let ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory))))
      (loop for (subject expected-name eligible) in
            '(("/CN=ordinary-first/CN=system:node:last-node/O=system:nodes" "system:node:last-node" t)
              ("/CN=system:node:first-node/CN=ordinary-last/O=system:nodes" "ordinary-last" nil))
            for index from 0
            for name = (format nil "multi-cn-~D" index)
            for request = (csr-crypto-fixture directory "ec" :subject subject :sans nil)
            for parsed = (gr8s::parse-and-verify-certificate-request request)
            for fixture = (csr-fixture request :name name :signer "kubernetes.io/kube-apiserver-client-kubelet"
                                       :usages #("digital signature" "client auth"))
            do (is (equal expected-name (gr8s::csr-subject-common-name (gr8s::parsed-certificate-request-subject parsed))))
               (is (eq eligible (null (gr8s::csr-signer-policy-failure parsed (gethash "spec" fixture)))))
               (gr8s::create-core-resource store "certificatesigningrequests" fixture nil)
               (approve-csr-fixture store name)
               (gr8s::reconcile-certificate-signing-requests store pki)
               (let ((status (gethash "status" (gr8s::get-core-resource store "certificatesigningrequests" nil name))))
                 (if eligible
                     (let ((certificate (gr8s::certificate-from-pem
                                          (trivial-utf-8:utf-8-bytes-to-string
                                            (gr8s::core-base64-bytes (gethash "certificate" status) "certificate")))))
                       (is (equal expected-name (gr8s::csr-subject-common-name (pure-tls::x509-certificate-subject certificate)))))
                     (is-true (gr8s::csr-condition status "Failed"))))))))

(defun csr-fixture (request &key (name "example-csr") (signer "example.test/custom") (usages #("digital signature" "key encipherment" "server auth")))
  "Build a typed request around actual PKCS#10 PEM bytes."
  (gr8s::core-object "apiVersion" "certificates.k8s.io/v1" "kind" "CertificateSigningRequest"
    "metadata" (gr8s::core-object "name" name)
    "spec" (gr8s::core-object "request" (ag-grpc:base64-encode request) "signerName" signer "expirationSeconds" 3600 "usages" usages)))

(defmacro with-csr-api ((store directory) &body body)
  "Run focused CSR HTTP tests on their own port."
  `(with-temporary-store (,store ,directory)
     (let ((server (start-server :address "127.0.0.1" :port 18095 :store ,store :runtime (make-fake-runtime))))
       (unwind-protect (progn ,@body) (stop-server server)))))

(defun csr-api-request (code path &key (method :get) object text bytes (content-type "application/json") headers)
  "Make an actual request and check the precise HTTP code without hiding response details."
  (multiple-value-bind (body status response-headers)
      (drakma:http-request (concatenate 'string "http://127.0.0.1:18095" path) :method method :content-type content-type
                          :additional-headers headers :content (or bytes text (when object (com.inuoe.jzon:stringify object))))
    (is (= code status) "~A returned ~D: ~A" path status body)
    (values (com.inuoe.jzon:parse body) response-headers)))

(test csr-http-create-update-status-approval-and-durable-custom-signer
  (with-csr-api (store directory)
    (let* ((request (csr-crypto-fixture directory "ec"))
           (fixture (csr-fixture request))
           (collection "/apis/certificates.k8s.io/v1/certificatesigningrequests")
           (item (concatenate 'string collection "/example-csr")))
      (setf (gethash "username" (gethash "spec" fixture)) "forged-admin"
            (gethash "uid" (gethash "spec" fixture)) "forged-uid"
            (gethash "status" fixture) (gr8s::core-object "conditions" (vector (gr8s::core-object "type" "Approved" "status" "True"))))
      (let* ((created (csr-api-request 201 collection :method :post :object fixture))
             (uid (gethash "uid" (gethash "metadata" created)))
             (spec (gr8s::copy-core-object (gethash "spec" created))))
        (is (equal "system:anonymous" (gethash "username" spec)))
        (is-false (gethash "uid" spec))
        (is (= 0 (length (gethash "conditions" (gethash "status" created)))))
        (setf (gethash "spec" created) (gr8s::core-object "request" "forged")
              (gethash "status" created) (gr8s::core-object "certificate" "forged"))
        (let ((updated (csr-api-request 200 item :method :put :object created)))
          (is (gr8s::core-json-equal-p spec (gethash "spec" updated)))
          (is-false (gethash "certificate" (gethash "status" updated))))
        (csr-api-request 409 item :method :put :object created)
        (let ((unconditional (csr-api-request 200 item)))
          (remhash "resourceVersion" (gethash "metadata" unconditional))
          (csr-api-request 200 item :method :put :object unconditional))
        (csr-api-request 422 (concatenate 'string item "/status") :method :patch :content-type "application/merge-patch+json"
                         :object (gr8s::core-object "status" (gr8s::core-object "conditions" (vector (gr8s::core-object "type" "Approved" "status" "True")))))
        (let* ((approved (csr-api-request 200 (concatenate 'string item "/approval") :method :patch :content-type "application/merge-patch+json"
                             :object (gr8s::core-object "metadata" (gr8s::core-object "annotations" (gr8s::core-object "approval" "actual"))
                                      "status" (gr8s::core-object "conditions" (vector (gr8s::core-object "type" "Approved" "status" "True"))))))
               (condition (aref (gethash "conditions" (gethash "status" approved)) 0)))
          (is-true (gethash "lastUpdateTime" condition)) (is-true (gethash "lastTransitionTime" condition))
          (csr-api-request 422 (concatenate 'string item "/approval") :method :patch :content-type "application/merge-patch+json"
                           :object (gr8s::core-object "status" (gr8s::core-object "conditions" #())))
          (csr-api-request 422 (concatenate 'string item "/approval") :method :patch :content-type "application/merge-patch+json"
                           :object (gr8s::core-object "status" (gr8s::core-object "conditions" (vector condition (gr8s::core-object "type" "Denied" "status" "True"))))))
        (let* ((certificate (ag-grpc:base64-encode (csr-crypto-fixture directory "rsa" :certificate t)))
               (signed (csr-api-request 200 (concatenate 'string item "/status") :method :patch :content-type "application/merge-patch+json"
                                :object (gr8s::core-object "status" (gr8s::core-object "certificate" certificate)))))
          (is (equal certificate (gethash "certificate" (gethash "status" signed))))
          (csr-api-request 422 (concatenate 'string item "/status") :method :patch :content-type "application/merge-patch+json"
                           :object (gr8s::core-object "status" (gr8s::core-object "certificate" ""))))
        (let ((reopened (gr8s::get-core-resource (open-store directory) "certificatesigningrequests" nil "example-csr")))
          (is (equal uid (gethash "uid" (gethash "metadata" reopened))))
          (is-true (gethash "certificate" (gethash "status" reopened))))))))

(test csr-typed-protobuf-discovery-signer-selector-and-finalizer-deletion
  (with-csr-api (store directory)
    (let* ((request (csr-crypto-fixture directory "rsa"))
           (metadata (core-test-protobuf '((1 "Wire-CSR") (2 "") (3 "") (5 "") (6 "") (7 0))))
           (spec (core-test-protobuf (list (list 1 request) (list 2 "forged") (list 5 "digital signature")
                                           (list 5 "server auth") (list 7 "example.test/wire") (list 8 3600))))
           (wire (core-test-protobuf-envelope "CertificateSigningRequest" (list (list 1 metadata) (list 2 spec)) "certificates.k8s.io/v1"))
           (collection "/apis/certificates.k8s.io/v1/certificatesigningrequests")
           (created (csr-api-request 201 collection :method :post :bytes wire :content-type "application/vnd.kubernetes.protobuf")))
      (is (equal "Wire-CSR" (gethash "name" (gethash "metadata" created))))
      (csr-api-request 200 "/apis/certificates.k8s.io")
      (let ((resources (gethash "resources" (csr-api-request 200 "/apis/certificates.k8s.io/v1"))))
        ;; certificatesigningrequests (+/approval, +/status) and the GA
        ;; ClusterTrustBundle, all under certificates.k8s.io/v1 (k8s 1.37).
        (is (= 4 (length resources)))
        (is (find "clustertrustbundles" resources :test #'equal
                  :key (lambda (r) (gethash "name" r)))))
      (let ((listed (csr-api-request 200 (concatenate 'string collection "?fieldSelector=spec.signerName=example.test/wire"))))
        (is (= 1 (length (gethash "items" listed)))))
      (setf (gethash "finalizers" (gethash "metadata" created)) #("example.test/retain"))
      (csr-api-request 200 (concatenate 'string collection "/Wire-CSR") :method :put :object created)
      (csr-api-request 200 (concatenate 'string collection "?fieldSelector=spec.signerName=example.test/wire") :method :delete)
      (let ((deleting (csr-api-request 200 (concatenate 'string collection "/Wire-CSR"))))
        (is-true (gethash "deletionTimestamp" (gethash "metadata" deleting))))
      (let ((reopened (open-store directory)))
        (is-true (gethash "deletionTimestamp" (gethash "metadata" (gr8s::get-core-resource reopened "certificatesigningrequests" nil "Wire-CSR")))))
      (csr-api-request 200 (concatenate 'string collection "/Wire-CSR") :method :patch :content-type "application/merge-patch+json"
                       :object (gr8s::core-object "metadata" (gr8s::core-object "finalizers" #())))
      (csr-api-request 404 (concatenate 'string collection "/Wire-CSR")))))

(test csr-unknown-and-duplicate-fields-use-real-strict-and-warning-behavior
  (with-csr-api (store directory)
    (values store)
    (let* ((request (csr-crypto-fixture directory "ec"))
           (fixture (csr-fixture request))
           (collection "/apis/certificates.k8s.io/v1/certificatesigningrequests"))
      (setf (gethash "unknown" (gethash "spec" fixture)) t)
      (csr-api-request 400 (concatenate 'string collection "?fieldValidation=Strict") :method :post :object fixture)
      (multiple-value-bind (created headers)
          (csr-api-request 201 (concatenate 'string collection "?fieldValidation=Warn") :method :post :object fixture)
        (is-false (gethash "unknown" (gethash "spec" created)))
        (is-true (cdr (assoc :warning headers))))
      (let ((text (com.inuoe.jzon:stringify (csr-fixture request :name "duplicate-csr"))))
        (setf text (concatenate 'string "{\"kind\":\"Bogus\"," (subseq text 1)))
        (csr-api-request 400 (concatenate 'string collection "?fieldValidation=Strict") :method :post :text text)))))

(test approved-built-in-client-signing-is-real-and-custom-signers-remain-pending
  (with-temporary-store (store directory)
    (let* ((pki (gr8s::ensure-cluster-pki (merge-pathnames "ca/" directory)))
           (request (csr-crypto-fixture directory "ec"))
           (object (gr8s::create-core-resource store "certificatesigningrequests"
                     (csr-fixture request :signer "kubernetes.io/kube-apiserver-client" :usages #("digital signature" "client auth")) nil)))
      (gr8s::reconcile-certificate-signing-requests store pki)
      (is-false (gethash "certificate" (gethash "status" (gr8s::get-core-resource store "certificatesigningrequests" nil "example-csr"))))
      (let ((gr8s::*csr-write-path* :approval))
        (setf object (gr8s::update-core-resource store "certificatesigningrequests" nil "example-csr"
                         (lambda (old) (setf (gethash "status" old) (gr8s::core-object "conditions" (vector (gr8s::core-object "type" "Approved" "status" "True")))) old))))
      (gr8s::reconcile-certificate-signing-requests (open-store directory) pki)
      (let* ((issued (gr8s::get-core-resource (open-store directory) "certificatesigningrequests" nil "example-csr"))
             (certificate (gr8s::core-base64-bytes (gethash "certificate" (gethash "status" issued)) "certificate"))
             (parsed (pure-tls:parse-certificate (cdar (gr8s::csr-pem-blocks certificate))))
             (path (merge-pathnames "issued.pem" directory)))
        (is-true (pure-tls::verify-certificate-signature parsed (gr8s::cluster-pki-ca-certificate pki)))
        (is-false (pure-tls::certificate-is-ca-p parsed))
        (is (equal '("fixture.example") (pure-tls:certificate-subject-common-names parsed)))
        (is (= 2 (length (pure-tls::x509-extension-value (find :subject-alt-name (pure-tls::x509-certificate-extensions parsed) :key #'pure-tls::x509-extension-oid)))))
        (with-open-file (out path :direction :output :if-exists :supersede :element-type '(unsigned-byte 8)) (write-sequence certificate out))
        (is (search "OK" (uiop:run-program (list "openssl" "verify" "-CAfile" (namestring (gr8s::cluster-pki-ca-certificate-path pki)) (namestring path)) :output :string :error-output :string)))))))

(defun approve-csr-fixture (store name &optional (decision "Approved"))
  "Record an explicit real approval or denial through the API update strategy."
  (let ((gr8s::*csr-write-path* :approval))
    (gr8s::update-core-resource store "certificatesigningrequests" nil name
      (lambda (old)
        (setf (gethash "conditions" (gethash "status" old))
              (vector (gr8s::core-object "type" decision "status" "True" "reason" "ExplicitTestDecision"))) old))))

(test kubelet-signer-policies-denial-failure-and-custom-pending-are-truthful
  (with-temporary-store (store directory)
    (let ((pki (gr8s::ensure-cluster-pki (merge-pathnames "ca/" directory))))
      (dolist (case '(("node-client" "kubernetes.io/kube-apiserver-client-kubelet" nil #("digital signature" "client auth") t)
                      ("node-serving" "kubernetes.io/kubelet-serving" "DNS:worker.example,IP:127.0.0.1" #("digital signature" "server auth") t)
                      ("bad-node-client-san" "kubernetes.io/kube-apiserver-client-kubelet" "DNS:not-allowed.example" #("digital signature" "client auth") nil)
                      ("bad-node-serving-email" "kubernetes.io/kubelet-serving" "DNS:worker.example,email:worker@example.test" #("digital signature" "server auth") nil)))
        (destructuring-bind (name signer sans usages allowed) case
          (let* ((request (csr-crypto-fixture directory "ec" :subject "/CN=system:node:worker/O=system:nodes" :sans sans))
                 (object (gr8s::create-core-resource store "certificatesigningrequests" (csr-fixture request :name name :signer signer :usages usages) nil)))
            (approve-csr-fixture store name)
            (gr8s::reconcile-certificate-signing-requests store pki)
            (setf object (gr8s::get-core-resource store "certificatesigningrequests" nil name))
            (if allowed
                (let* ((data (gr8s::core-base64-bytes (gethash "certificate" (gethash "status" object)) "certificate"))
                       (certificate (pure-tls:parse-certificate (cdar (gr8s::csr-pem-blocks data))))
                       (request-info (gr8s::parse-and-verify-certificate-request request)))
                  (is-true (pure-tls::verify-certificate-signature certificate (gr8s::cluster-pki-ca-certificate pki)))
                  (is (equalp (gr8s::parsed-certificate-request-spki request-info) (pure-tls::x509-certificate-subject-public-key-info certificate)))
                  (is (equal '("system:node:worker") (pure-tls:certificate-subject-common-names certificate))))
                (progn (is-false (gethash "certificate" (gethash "status" object)))
                       (is-true (gr8s::csr-true-condition-p object "Failed"))
                       (is (equal "SignerValidationFailure" (gethash "reason" (gr8s::csr-condition (gethash "status" object) "Failed")))))))))
      (dolist (name '("denied-client" "custom-pending"))
        (gr8s::create-core-resource store "certificatesigningrequests"
          (csr-fixture (csr-crypto-fixture directory "ec") :name name
                       :signer (if (equal name "denied-client") "kubernetes.io/kube-apiserver-client" "example.test/custom")
                       :usages #("digital signature" "client auth")) nil)
        (approve-csr-fixture store name (if (equal name "denied-client") "Denied" "Approved")))
      (gr8s::reconcile-certificate-signing-requests store pki)
      (dolist (name '("denied-client" "custom-pending"))
        (let ((object (gr8s::get-core-resource store "certificatesigningrequests" nil name)))
          (is-false (gethash "certificate" (gethash "status" object)))
          (is-false (gr8s::csr-true-condition-p object "Failed")))))))

(test csr-actors-use-live-credential-uids-and-signer-approval-requires-extra-rbac
  (with-csr-api (store directory)
    (let* ((account (service-account-test-store store))
           (credential (gr8s::ensure-service-account-credential store "alpha" "reader"))
           (token (service-account-test-token credential))
           (identity (gr8s::authenticate-service-account-token store token))
           (fixture (csr-fixture (csr-crypto-fixture directory "ec")))
           (collection "/apis/certificates.k8s.io/v1/certificatesigningrequests"))
      (setf (gethash "username" (gethash "spec" fixture)) "forged-user"
            (gethash "groups" (gethash "spec" fixture)) #("system:masters"))
      (let ((created (csr-api-request 201 collection :method :post :object fixture
                      :headers (list (cons "Authorization" (concatenate 'string "Bearer " token)) (cons "Impersonate-User" "forged-user")))))
        (is (equal "system:serviceaccount:alpha:reader" (gethash "username" (gethash "spec" created))))
        (is (equal (gethash "uid" (gethash "metadata" account)) (gethash "uid" (gethash "spec" created))))
        (is (equalp #("system:serviceaccounts" "system:serviceaccounts:alpha" "system:authenticated") (gethash "groups" (gethash "spec" created)))))
      (signals kubernetes-error (gr8s::csr-authorize-signer store identity "example.test/custom" "approve"))
      (gr8s::create-core-resource store "clusterroles"
        (gr8s::core-object "metadata" (gr8s::core-object "name" "csr-approver") "rules"
          (vector (gr8s::core-object "apiGroups" #("certificates.k8s.io") "resources" #("signers") "verbs" #("approve") "resourceNames" #("example.test/*")))) nil)
      (gr8s::create-core-resource store "clusterrolebindings"
        (gr8s::core-object "metadata" (gr8s::core-object "name" "csr-approver")
          "subjects" (vector (gr8s::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha"))
          "roleRef" (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" "csr-approver")) nil)
      (finishes (gr8s::csr-authorize-signer store identity "example.test/custom" "approve"))
      (signals kubernetes-error (gr8s::csr-authorize-signer store identity "other.test/custom" "approve"))
      (signals kubernetes-error (gr8s::csr-authorize-signer store identity "example.test/custom" "sign")))))

(test csr-failed-persistence-rolls-back-approval-and-signing-state
  (with-temporary-store (store directory)
    (let* ((request (csr-crypto-fixture directory "ec"))
           (created (gr8s::create-core-resource store "certificatesigningrequests" (csr-fixture request) nil))
           (revision (gr8s::pod-store-resource-revision store))
           (original (symbol-function 'gr8s::write-private-text-atomically)))
      (unwind-protect
           (progn (setf (symbol-function 'gr8s::write-private-text-atomically)
                        (lambda (&rest arguments) (declare (ignore arguments)) (error "forced failed durable write")))
                  (signals error (approve-csr-fixture store "example-csr")))
        (setf (symbol-function 'gr8s::write-private-text-atomically) original))
      (is (= revision (gr8s::pod-store-resource-revision store)))
      (is (gr8s::core-json-equal-p created (gr8s::get-core-resource store "certificatesigningrequests" nil "example-csr")))
      (is (gr8s::core-json-equal-p created (gr8s::get-core-resource (open-store directory) "certificatesigningrequests" nil "example-csr"))))))

(test client-signer-subject-restriction-recognizes-bmp-encoded-masters-group
  (with-csr-api (store directory)
    (values store)
    (let* ((request (csr-crypto-fixture directory "rsa"))
           (rewritten
             (rewrite-and-resign-rsa-csr request directory
               (lambda (info)
                 (let* ((text "system:masters")
                        (bmp (make-array (+ 2 (* 2 (length text))) :element-type '(unsigned-byte 8) :initial-element 0)))
                   (loop for character across text for index from 1 by 2 do (setf (aref bmp index) (char-code character)))
                   (pure-tls/acme::encode-sequence
                    (pure-tls::asn1-node-raw-bytes (first info))
                    (pure-tls/acme::encode-sequence (pure-tls/acme::encode-der #x31
                     (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid '(2 5 4 10)) (pure-tls/acme::encode-der #x1e bmp))))
                    (pure-tls::asn1-node-raw-bytes (third info)) (pure-tls::asn1-node-raw-bytes (fourth info))))))))
      (is (equal "system:masters" (cdr (assoc :organization-name
                  (pure-tls::x509-name-rdns (gr8s::parsed-certificate-request-subject (gr8s::parse-and-verify-certificate-request rewritten)))))))
      (csr-api-request 403 "/apis/certificates.k8s.io/v1/certificatesigningrequests" :method :post
        :object (csr-fixture rewritten :signer "kubernetes.io/kube-apiserver-client" :usages #("client auth"))))))
