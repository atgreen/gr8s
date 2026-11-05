;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise actual public API mutual TLS with genuinely approved certificates,
;;;; User/Group RBAC, server-owned CSR actor identity and separate signer grants.
;;;; Preserve live ServiceAccount behavior and reject untrusted credential use.

(in-package #:gr8s/tests)
(def-suite api-client-certificates :in gr8s)
(in-suite api-client-certificates)

(defun certificate-api-test-request (pki certificate key path &key object (method "GET") headers)
  "Use an ordinary independent TLS client and return the actual HTTP status and JSON body."
  (let* ((text (uiop:run-program
                (append (list "curl" "--silent" "--show-error" "--max-time" "10"
                              "--cacert" (namestring (gr8s:cluster-pki-ca-certificate-path pki))
                              "--cert" (namestring certificate) "--key" (namestring key)
                              "--request" method "--write-out" (format nil "~%%{http_code}")
                              (concatenate 'string "https://127.0.0.1:18096" path))
                        (when object (list "--header" "Content-Type: application/json" "--data-binary" (com.inuoe.jzon:stringify object)))
                        (loop for header in headers append (list "--header" header)))
                :output :string :error-output :string))
         (boundary (position #\Newline text :from-end t)))
    (values (parse-integer text :start (1+ boundary)) (com.inuoe.jzon:parse (subseq text 0 boundary)))))

(defun certificate-api-test-invalid-proof-rejected-p (pki certificate wrong-key token)
  "Require actual TLS to reject a certificate presented with another private key, despite a valid token."
  (sb-sys:with-deadline (:seconds 10)
    (let ((socket (usocket:socket-connect "127.0.0.1" 18096 :element-type '(unsigned-byte 8))) (tls nil))
      (unwind-protect
           (handler-case
               (progn
                 (setf tls (pure-tls:make-tls-client-stream
                             (usocket:socket-stream socket) :hostname "kubernetes.default.svc"
                             :client-certificate certificate :client-key wrong-key
                             :context (pure-tls:make-tls-context :verify-mode pure-tls:+verify-required+
                                        :ca-file (namestring (gr8s:cluster-pki-ca-certificate-path pki))
                                        :auto-load-system-ca nil)))
                 (write-sequence
                   (trivial-utf-8:string-to-utf-8-bytes
                     (format nil "GET /version HTTP/1.1~C~CHost: kubernetes.default.svc~C~CAuthorization: Bearer ~A~C~CConnection: close~C~C~C~C"
                             #\Return #\Linefeed #\Return #\Linefeed token #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed)) tls)
                 (finish-output tls)
                 (null (read-byte tls nil nil)))
             (pure-tls:tls-error () t)
             (stream-error () t))
        (when tls (ignore-errors (close tls)))
        (ignore-errors (usocket:socket-close socket))))))

(defun certificate-api-test-grant (store name subject rules)
  "Create a real cluster role and binding for a certificate User or Group."
  (gr8s::create-core-resource store "clusterroles"
    (gr8s::core-object "metadata" (gr8s::core-object "name" name) "rules" rules) nil)
  (gr8s::create-core-resource store "clusterrolebindings"
    (gr8s::core-object "metadata" (gr8s::core-object "name" name) "subjects" (vector subject)
      "roleRef" (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" name)) nil))

(defun certificate-api-test-subject-leaf (pki attributes &key expired)
  "Sign a real client leaf with explicit subject OIDs for user mapping edge cases."
  (multiple-value-bind (private public) (ironclad:generate-key-pair :secp256r1)
    (let* ((subject (apply #'pure-tls/acme::encode-sequence
                     (loop for (oid . value) in attributes
                           collect (pure-tls/acme::encode-der #x31
                             (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid oid)
                               (pure-tls/acme::encode-utf8-string value))))))
           (der (gr8s::certificate-der
                  (pure-tls/acme::encode-subject gr8s::+pki-ca-common-name+) subject
                  (pure-tls/acme::encode-ec-public-key public)
                  (list (pure-tls/acme::encode-extension gr8s::+oid-extended-key-usage+
                          (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid '(1 3 6 1 5 5 7 3 2)))))
                  (gr8s::cluster-pki-ca-private-key pki))))
      (when expired
        (let* ((fields (pure-tls::asn1-children (first (pure-tls::asn1-children (pure-tls::parse-der der)))))
               (tbs (apply #'pure-tls/acme::encode-sequence
                      (loop for field in fields for index from 0
                            collect (if (= index 4)
                                        (pure-tls/acme::encode-validity (- (get-universal-time) 7200) (- (get-universal-time) 3600))
                                        (pure-tls::asn1-node-raw-bytes field))))))
          (setf der (pure-tls/acme::encode-sequence tbs (pure-tls::asn1-node-raw-bytes (third fields))
                      (pure-tls/acme::encode-bit-string (gr8s::ecdsa-sign-der (gr8s::cluster-pki-ca-private-key pki) tbs))))))
      (values (pure-tls::parse-certificate der) private))))

(test certificate-user-uid-mapping-and-purpose-verification
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (foreign (gr8s:ensure-cluster-pki (merge-pathnames "foreign/" directory)))
           (ca (gr8s::cluster-pki-ca-certificate pki))
           (attributes '(((2 5 4 3) . "subject-user") ((2 5 4 10) . "subject-group")
                         ((1 3 6 1 4 1 57683 2) . "subject-uid")))
           (leaf (certificate-api-test-subject-leaf pki attributes))
           (identity (gr8s::certificate-api-identity (list leaf) ca)))
      (is (equal "subject-user" (gr8s::api-identity-username identity)))
      (is (equal "subject-uid" (gr8s::api-user-identity-uid identity)))
      (is (find "subject-group" (gr8s::api-identity-groups identity) :test #'equal))
      (let ((multi (certificate-api-test-subject-leaf pki
                     '(((2 5 4 3) . "first-user") ((2 5 4 3) . "last-user") ((2 5 4 10) . "subject-group")))))
        (is (equal "last-user" (gr8s::api-identity-username (gr8s::certificate-api-identity (list multi) ca)))))
      (signals kubernetes-error (gr8s::certificate-api-identity (list leaf) (gr8s::cluster-pki-ca-certificate foreign)))
      (dolist (uids '(("first" "second") ("")))
        (signals kubernetes-error
          (gr8s::certificate-api-identity
            (list (certificate-api-test-subject-leaf pki
                    (append (subseq attributes 0 2) (loop for uid in uids collect (cons '(1 3 6 1 4 1 57683 2) uid))))) ca)))
      (is-false (gr8s::certificate-api-identity
                  (list (certificate-api-test-subject-leaf pki '(((2 5 4 10) . "no-common-name")))) ca))
      (multiple-value-bind (server-certificate server-key) (gr8s::ensure-kubernetes-api-credentials pki)
        (declare (ignore server-key))
        (signals kubernetes-error
          (gr8s::certificate-api-identity (pure-tls:load-certificate-chain server-certificate) ca))))))

(test certificate-authentication-errors-allow-live-token-alternatives-at-http
  (with-temporary-store (store directory)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (foreign (gr8s:ensure-cluster-pki (merge-pathnames "foreign/" directory)))
           (runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (collection "/apis/certificates.k8s.io/v1/certificatesigningrequests")
           (attributes '(((2 5 4 3) . "certificate-user")))
           (server nil))
      (service-account-test-store store)
      (let* ((secret (gr8s::ensure-service-account-credential store "alpha" "reader"))
             (token (service-account-test-token secret))
             (headers (list (concatenate 'string "Authorization: Bearer " token))))
        (certificate-api-test-grant store "token-csr-create"
          (gr8s::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha")
          (vector (gr8s::core-object "apiGroups" #("certificates.k8s.io") "resources" #("certificatesigningrequests") "verbs" #("create"))))
        (unwind-protect
             (progn
               (setf server (gr8s::start-in-cluster-api store runtime reconciler pki :address "127.0.0.1" :port 18096))
               (dolist (kind '(:expired :untrusted :valid))
                 (multiple-value-bind (leaf private)
                     (certificate-api-test-subject-leaf (if (eq kind :untrusted) foreign pki) attributes :expired (eq kind :expired))
                   (let ((certificate (merge-pathnames (format nil "~(~A~).pem" kind) directory))
                         (key (merge-pathnames (format nil "~(~A~).key" kind) directory)))
                     (gr8s::write-private-text-exclusively certificate
                       (pure-tls/acme::wrap-pem "CERTIFICATE" (pure-tls::x509-certificate-raw-der leaf)))
                     (gr8s::write-private-text-exclusively key (pure-tls/acme::encode-ec-private-key-pem private))
                     (is (= (if (eq kind :valid) 200 401) (certificate-api-test-request pki certificate key "/version")))
                     (is (= 200 (certificate-api-test-request pki certificate key "/version" :headers headers)))
                     (let* ((request (csr-crypto-fixture directory "ec"))
                            (fixture (csr-fixture request :name (string-downcase (symbol-name kind)))))
                       (multiple-value-bind (code created)
                           (certificate-api-test-request pki certificate key collection :method "POST" :object fixture :headers headers)
                         ;; A valid certificate wins authentication even when only
                         ;; the alternative token has the required resource grant.
                         (is (= (if (eq kind :valid) 403 201) code))
                         (unless (eq kind :valid)
                           (is (equal "system:serviceaccount:alpha:reader" (gethash "username" (gethash "spec" created))))
                           (is (equal (gr8s::api-service-account-identity-uid (gr8s::authenticate-service-account-token store token))
                                      (gethash "uid" (gethash "spec" created))))))))))
               (multiple-value-bind (certificate key) (gr8s::ensure-kubernetes-api-credentials pki)
                 (is (= 401 (certificate-api-test-request pki certificate key "/version")))
                 (is (= 200 (certificate-api-test-request pki certificate key "/version" :headers headers)))
                 (is-true (certificate-api-test-invalid-proof-rejected-p pki
                            (merge-pathnames "valid.pem" directory) key token))))
          (when server (stop-server server)))))))

(test trusted-system-masters-certificates-use-standard-privileged-authorization
  (with-temporary-store (store directory)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (collection "/apis/certificates.k8s.io/v1/certificatesigningrequests")
           (server nil))
      (unwind-protect
           (progn
             (setf server (gr8s::start-in-cluster-api store runtime reconciler pki :address "127.0.0.1" :port 18096))
             (is-false (gr8s::list-core-resources store "clusterrolebindings"))
             (dolist (privileged '(t nil))
               (multiple-value-bind (leaf private)
                   (certificate-api-test-subject-leaf pki
                     (list (cons '(2 5 4 3) (if privileged "admin-user" "normal-user"))
                           (cons '(2 5 4 10) (if privileged "system:masters" "engineering"))))
                 (let ((certificate (merge-pathnames (if privileged "admin.pem" "normal.pem") directory))
                       (key (merge-pathnames (if privileged "admin.key" "normal.key") directory)))
                   (gr8s::write-private-text-exclusively certificate
                     (pure-tls/acme::wrap-pem "CERTIFICATE" (pure-tls::x509-certificate-raw-der leaf)))
                   (gr8s::write-private-text-exclusively key (pure-tls/acme::encode-ec-private-key-pem private))
                   (is (= (if privileged 200 403) (certificate-api-test-request pki certificate key "/api/v1/pods")))
                   (is (= (if privileged 200 403) (certificate-api-test-request pki certificate key "/api/v1/namespaces/alpha/secrets"
                            :headers '("Impersonate-Group: system:masters"))))
                   (when privileged
                     (multiple-value-bind (code created)
                         (certificate-api-test-request pki certificate key collection :method "POST"
                           :object (csr-fixture (csr-crypto-fixture directory "ec")))
                       (is (= 201 code))
                       (setf (gethash "conditions" (gethash "status" created)) (vector (gr8s::core-object "type" "Approved" "status" "True")))
                       (multiple-value-bind (approval-code approved)
                           (certificate-api-test-request pki certificate key (concatenate 'string collection "/example-csr/approval") :method "PUT" :object created)
                         (is (= 200 approval-code))
                         (setf (gethash "certificate" (gethash "status" approved)) (ag-grpc:base64-encode (pure-tls::read-file-bytes certificate)))
                         (is (= 200 (certificate-api-test-request pki certificate key (concatenate 'string collection "/example-csr/status") :method "PUT" :object approved)))))))))
             (gr8s::create-core-resource store "roles"
               (gr8s::core-object "metadata" (gr8s::core-object "name" "pod-reader")
                 "rules" (vector (gr8s::core-object "apiGroups" #("") "resources" #("pods") "verbs" #("list")))) "alpha")
             (gr8s::create-core-resource store "rolebindings"
               (gr8s::core-object "metadata" (gr8s::core-object "name" "normal-reader")
                 "subjects" (vector (gr8s::core-object "kind" "User" "apiGroup" "rbac.authorization.k8s.io" "name" "normal-user"))
                 "roleRef" (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" "pod-reader")) "alpha")
             (let ((certificate (merge-pathnames "normal.pem" directory)) (key (merge-pathnames "normal.key" directory)))
               (is (= 200 (certificate-api-test-request pki certificate key "/api/v1/namespaces/alpha/pods")))
               (is (= 403 (certificate-api-test-request pki certificate key "/api/v1/namespaces/beta/pods")))
               (is (= 403 (certificate-api-test-request pki certificate key "/api/v1/namespaces/alpha/secrets")))))
        (when server (stop-server server))))))

(test internal-enrollment-issuer-projects-validated-node-name-without-requested-attributes
  (with-temporary-store (store directory)
    (declare (ignore store))
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (fingerprint (gr8s:cluster-pki-ca-fingerprint pki))
           (request (csr-crypto-fixture directory "rsa" :subject "/CN=worker-a/O=engineering/OU=caller-metadata/UID=caller-id" :sans "DNS:caller.example"))
           (csr-der (cdar (gr8s::csr-pem-blocks request)))
           (token (gr8s:create-join-token pki "worker-a"))
           (pem (gr8s:enroll-node-csr pki "worker-a" token fingerprint csr-der))
           (leaf (gr8s::certificate-from-pem pem))
           (identity (gr8s::certificate-api-identity (list leaf) (gr8s::cluster-pki-ca-certificate pki))))
      (is-true (gr8s:verify-node-certificate pki pem "worker-a"))
      (is (equal fingerprint (gr8s:cluster-pki-ca-fingerprint pki)))
      (is (equal '((:common-name . "worker-a")) (pure-tls::x509-name-rdns (pure-tls::x509-certificate-subject leaf))))
      (is (equal "worker-a" (gr8s::api-identity-username identity)))
      (is (equalp #("system:authenticated") (gr8s::api-identity-groups identity)))
      (is-false (gr8s::api-user-identity-uid identity)))))

(test approved-certificate-authenticates-actual-api-and-server-owned-csr-actor
  (with-temporary-store (store directory)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (certificate (merge-pathnames "client.pem" directory))
           (key (merge-pathnames "ec-key.pem" directory))
           (collection "/apis/certificates.k8s.io/v1/certificatesigningrequests")
           (runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)) (server nil))
      (gr8s::write-private-text-exclusively certificate
        (profile-test-issued-csr store directory pki "/CN=tester-csr/O=csr-team/O=second-team"
          "kubernetes.io/kube-apiserver-client" #("digital signature" "client auth") nil))
      (unwind-protect
           (progn
             (setf server (gr8s::start-in-cluster-api store runtime reconciler pki :address "127.0.0.1" :port 18096))
             (is (= 200 (certificate-api-test-request pki certificate key "/version")))
             (is (= 403 (certificate-api-test-request pki certificate key collection)))
             (certificate-api-test-grant store "csr-users"
               (gr8s::core-object "kind" "User" "apiGroup" "rbac.authorization.k8s.io" "name" "tester-csr")
               (vector (gr8s::core-object "apiGroups" #("certificates.k8s.io") "resources" #("certificatesigningrequests") "verbs" #("create"))))
             (let ((fixture (csr-fixture (pure-tls::read-file-bytes (merge-pathnames "ec-request.pem" directory)) :name "authenticated-client")))
               (setf (gethash "username" (gethash "spec" fixture)) "forged"
                     (gethash "uid" (gethash "spec" fixture)) "forged-uid"
                     (gethash "groups" (gethash "spec" fixture)) #("system:masters"))
               (multiple-value-bind (code created)
                   (certificate-api-test-request pki certificate key collection :method "POST" :object fixture
                     :headers '("Impersonate-User: forged" "X-Remote-User: forged"))
                 ;; Only an authorized impersonator can name another user.
                 (is (= 403 code)))
               (multiple-value-bind (code created)
                   (certificate-api-test-request pki certificate key collection :method "POST" :object fixture
                     :headers '("X-Remote-User: forged"))
                 (is (= 201 code))
                 (let ((spec (gethash "spec" created)))
                   (is (equal "tester-csr" (gethash "username" spec)))
                   (is-false (gethash "uid" spec))
                   (is (find "csr-team" (gethash "groups" spec) :test #'equal))
                   (is (find "second-team" (gethash "groups" spec) :test #'equal))
                   (is (find "system:authenticated" (gethash "groups" spec) :test #'equal))
                   (is-false (find "system:masters" (gethash "groups" spec) :test #'equal))
                   (is (equal (concatenate 'string "X509SHA256="
                                (string-downcase (gr8s::octets-to-hex
                                  (ironclad:digest-sequence :sha256 (pure-tls::x509-certificate-raw-der (first (pure-tls:load-certificate-chain certificate)))))))
                              (aref (gethash "authentication.kubernetes.io/credential-id" (gethash "extra" spec)) 0))))))
             (certificate-api-test-grant store "csr-subresources"
               (gr8s::core-object "kind" "User" "apiGroup" "rbac.authorization.k8s.io" "name" "tester-csr")
               (vector (gr8s::core-object "apiGroups" #("certificates.k8s.io")
                         "resources" #("certificatesigningrequests/approval" "certificatesigningrequests/status") "verbs" #("update"))))
             (let* ((pending (gr8s::get-core-resource store "certificatesigningrequests" nil "authenticated-client"))
                    (approval (concatenate 'string collection "/authenticated-client/approval"))
                    (status (concatenate 'string collection "/authenticated-client/status")))
               (setf (gethash "conditions" (gethash "status" pending))
                     (vector (gr8s::core-object "type" "Approved" "status" "True")))
               (is (= 403 (certificate-api-test-request pki certificate key approval :method "PUT" :object pending)))
               (certificate-api-test-grant store "csr-approve"
                 (gr8s::core-object "kind" "User" "apiGroup" "rbac.authorization.k8s.io" "name" "tester-csr")
                 (vector (gr8s::core-object "apiGroups" #("certificates.k8s.io") "resources" #("signers")
                           "resourceNames" #("example.test/custom") "verbs" #("approve"))))
               (multiple-value-bind (code approved)
                   (certificate-api-test-request pki certificate key approval :method "PUT" :object pending)
                 (is (= 200 code))
                 (setf (gethash "certificate" (gethash "status" approved))
                       (ag-grpc:base64-encode (pure-tls::read-file-bytes certificate)))
                 (is (= 403 (certificate-api-test-request pki certificate key status :method "PUT" :object approved)))
                 (certificate-api-test-grant store "csr-sign"
                   (gr8s::core-object "kind" "Group" "apiGroup" "rbac.authorization.k8s.io" "name" "csr-team")
                   (vector (gr8s::core-object "apiGroups" #("certificates.k8s.io") "resources" #("signers")
                             "resourceNames" #("example.test/*") "verbs" #("sign"))))
                 (is (= 200 (certificate-api-test-request pki certificate key status :method "PUT" :object approved)))))
             (certificate-api-test-grant store "csr-team"
               (gr8s::core-object "kind" "Group" "apiGroup" "rbac.authorization.k8s.io" "name" "csr-team")
               (vector (gr8s::core-object "apiGroups" #("certificates.k8s.io") "resources" #("certificatesigningrequests") "verbs" #("list"))))
             (is (= 200 (certificate-api-test-request pki certificate key collection)))
             (let ((connections (uiop:run-program
                      (list "curl" "--silent" "--show-error" "--max-time" "10"
                            "--cacert" (namestring (gr8s:cluster-pki-ca-certificate-path pki))
                            "--cert" (namestring certificate) "--key" (namestring key)
                            "--output" "/dev/null" "--write-out" (format nil "%{http_code}:%{num_connects}~%")
                            "https://127.0.0.1:18096/version"
                            "--output" "/dev/null" (concatenate 'string "https://127.0.0.1:18096" collection))
                      :output :string :error-output :string)))
               (is (equal (format nil "200:1~%200:0~%") connections)))
             (let ((connections (uiop:run-program
                       (list "curl" "--silent" "--show-error" "--max-time" "10"
                             "--cacert" (namestring (gr8s:cluster-pki-ca-certificate-path pki))
                             "--cert" (namestring certificate) "--key" (namestring key)
                             "--header" "Connection: close" "--output" "/dev/null"
                             "--write-out" (format nil "%{http_code}:%{num_connects}~%")
                             "https://127.0.0.1:18096/version" "--output" "/dev/null"
                             (concatenate 'string "https://127.0.0.1:18096" collection))
                       :output :string :error-output :string)))
               (is (equal (format nil "200:1~%200:1~%") connections)))
             (gr8s::delete-core-resource store "clusterrolebindings" nil "csr-team")
             (is (= 403 (certificate-api-test-request pki certificate key collection)))
             (gr8s::delete-core-resource store "clusterrolebindings" nil "csr-users")
             (is (= 403 (certificate-api-test-request pki certificate key collection :method "POST"
                         :object (csr-fixture (pure-tls::read-file-bytes (merge-pathnames "ec-request.pem" directory)) :name "forbidden-client")))))
        (when server (stop-server server))))))
