;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the cert-manager acme issuer without a network: admission of the
;;;; issuer and Challenge shapes, the Challenge's trip through the node
;;;; projection into the agent's Gateway view, the Gateway listener's HTTP-01
;;;; answer, and the controller's order state machine against a scripted ACME
;;;; server bound through *cm-acme-backend*.

(in-package #:gr8s/tests)
(in-suite cert-manager)

(defparameter *acme-issuer*
  "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"ClusterIssuer\",\"metadata\":{\"name\":\"letsencrypt\"},
    \"spec\":{\"acme\":{\"server\":\"https://acme.test/directory\",\"email\":\"ops@example.com\",
      \"privateKeySecretRef\":{\"name\":\"letsencrypt-account\"},
      \"solvers\":[{\"http01\":{\"gatewayHTTPRoute\":{\"parentRefs\":[{\"name\":\"web\",\"namespace\":\"certs\"}]}}}]}}}")

(defparameter *acme-certificate*
  "{\"apiVersion\":\"cert-manager.io/v1\",\"kind\":\"Certificate\",\"metadata\":{\"name\":\"demo\",\"namespace\":\"certs\"},
    \"spec\":{\"secretName\":\"demo-tls\",\"issuerRef\":{\"name\":\"letsencrypt\",\"kind\":\"ClusterIssuer\"},
      \"dnsNames\":[\"demo.example.com\"]}}")

(defun acme-challenge-object (&key (name "demo-1") (token "tok-1") (host "demo.example.com"))
  (cm-parse (format nil "{\"apiVersion\":\"acme.cert-manager.io/v1\",\"kind\":\"Challenge\",
    \"metadata\":{\"name\":\"~A\",\"namespace\":\"certs\"},
    \"spec\":{\"url\":\"https://acme.test/chall/1\",\"authorizationURL\":\"https://acme.test/authz/1\",
      \"dnsName\":\"~A\",\"type\":\"HTTP-01\",\"token\":\"~A\",\"key\":\"~A.thumb\",
      \"issuerRef\":{\"name\":\"letsencrypt\",\"kind\":\"ClusterIssuer\"}}}" name host token token)))

(test acme-issuer-and-challenge-admission
  (with-core-api (store directory)
    (values store directory)
    (check-core-status 201 "/api/v1/namespaces" :method :post
                       :object (cm-parse "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"certs\"}}"))
    (let ((created (check-core-status 201 "/apis/cert-manager.io/v1/clusterissuers" :method :post
                                      :object (cm-parse *acme-issuer*))))
      (is (equal "https://acme.test/directory" (gethash "server" (gethash "acme" (gethash "spec" created))))))
    (flet ((bad (mutate)
             (let ((issuer (cm-parse *acme-issuer*)))
               (setf (gethash "name" (gethash "metadata" issuer)) "bad")
               (funcall mutate (gethash "acme" (gethash "spec" issuer)))
               (check-core-status 422 "/apis/cert-manager.io/v1/clusterissuers" :method :post :object issuer))))
      (bad (lambda (acme) (setf (gethash "server" acme) "http://acme.test/directory")))
      (bad (lambda (acme) (remhash "email" acme)))
      (bad (lambda (acme) (remhash "privateKeySecretRef" acme)))
      (bad (lambda (acme) (setf (gethash "solvers" acme) #())))
      (bad (lambda (acme) (setf (gethash "solvers" acme)
                                (vector (cm-parse "{\"dns01\":{\"cloudflare\":{}}}")))))
      (bad (lambda (acme) (setf (gethash "solvers" acme)
                                (vector (cm-parse "{\"http01\":{\"ingress\":{\"class\":\"nginx\"}}}")))))
      (bad (lambda (acme) (setf (gethash "externalAccountBinding" acme) (cm-parse "{\"keyID\":\"k\"}")))))
    ;; Challenge is served, and discovered, in its own group.
    (check-core-status 201 "/apis/acme.cert-manager.io/v1/namespaces/certs/challenges" :method :post
                       :object (acme-challenge-object))
    (let ((challenge (acme-challenge-object :name "dns")))
      (setf (gethash "type" (gethash "spec" challenge)) "DNS-01")
      (check-core-status 422 "/apis/acme.cert-manager.io/v1/namespaces/certs/challenges" :method :post
                         :object challenge))
    (let ((challenge (acme-challenge-object :name "notoken")))
      (remhash "token" (gethash "spec" challenge))
      (check-core-status 422 "/apis/acme.cert-manager.io/v1/namespaces/certs/challenges" :method :post
                         :object challenge))
    (is (member "acme.cert-manager.io"
                (map 'list (lambda (group) (gethash "name" group)) (gethash "groups" (check-core-status 200 "/apis")))
                :test #'equal))
    (is (equal '("challenges")
               (map 'list (lambda (resource) (gethash "name" resource))
                    (remove-if (lambda (resource) (find #\/ (gethash "name" resource)))
                               (gethash "resources" (check-core-status 200 "/apis/acme.cert-manager.io/v1"))))))))

(test acme-challenges-reach-the-agent-gateway-view
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "challenges" (acme-challenge-object) "certs")
    (let* ((projection (gr8s.kubelet::service-discovery-projection store))
           (resources (gr8s.kubelet::decode-service-discovery-projection projection))
           (public (gethash '("challenges" "certs" "demo-1") resources)))
      (is (hash-table-p public))
      ;; Only what the listener needs crosses to the node.
      (is (equal '("dnsName" "key" "token" "type")
                 (sort (alexandria:hash-table-keys (gethash "spec" public)) #'string<)))
      (let* ((view (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index resources)))
             (table (gr8s.controllers::gateway-acme-challenge-table view)))
        (is (equal '("demo.example.com" . "tok-1.thumb") (gethash "tok-1" table)))))
    ;; A Challenge change rides the Gateway delta path, not a full node snapshot.
    (is (member "challenges" gr8s.protocol::+gateway-config-resources+ :test #'equal))))

(test gateway-listener-answers-acme-http01-before-routing
  (let* ((router (lambda (&rest arguments) (declare (ignore arguments)) nil))
         (gateway (gr8s.controllers::start-gateway-listener :port 0 :router router :resolver (constantly nil)
                                                           :name "acme"))
         (port (hunchentoot:acceptor-port gateway))
         (previous gr8s.controllers::*gateway-acme-challenges*))
    (unwind-protect
         (let ((table (make-hash-table :test 'equal)))
           (setf (gethash "tok-1" table) (cons "demo.example.com" "tok-1.thumb")
                 gr8s.controllers::*gateway-acme-challenges* table)
           (multiple-value-bind (code headers body)
               (gw-raw-request port "demo.example.com:80" "/.well-known/acme-challenge/tok-1")
             (declare (ignore headers))
             (is (= 200 code))
             (is (equal "tok-1.thumb" body)))
           ;; Another host, an unknown token, or a POST falls through to routing.
           (is (= 404 (gw-raw-request port "other.example.com" "/.well-known/acme-challenge/tok-1")))
           (is (= 404 (gw-raw-request port "demo.example.com" "/.well-known/acme-challenge/nope")))
           (is (= 404 (gw-raw-request port "demo.example.com" "/.well-known/acme-challenge/tok-1"
                                      :method "POST" :body "x"))))
      (setf gr8s.controllers::*gateway-acme-challenges* previous)
      (gr8s.controllers::stop-gateway-listener gateway))))

;;; --- The order state machine against a scripted ACME server -----------------

(defclass fake-acme ()
  ((orders :initform 0 :accessor fake-acme-orders)
   (responded :initform nil :accessor fake-acme-responded)
   (validations :initform 0 :accessor fake-acme-validations
                :documentation "Authorization polls after the response before it settles.")
   (outcome :initarg :outcome :initform "valid" :accessor fake-acme-outcome)
   (csr :initform nil :accessor fake-acme-csr)
   (defer :initform nil :accessor fake-acme-defer)))

(defmethod gr8s.controllers::cm-acme-account ((acme fake-acme) server email key &key skip-tls-verify)
  (declare (ignore server email key skip-tls-verify))
  (values :client "https://acme.test/acct/1"))

(defmethod gr8s.controllers::cm-acme-new-order ((acme fake-acme) client domains profile)
  (declare (ignore client profile))
  (when (fake-acme-defer acme)
    (error 'gr8s.controllers::cm-acme-deferred :seconds (shiftf (fake-acme-defer acme) nil)))
  (is (equal '("demo.example.com") domains))
  (incf (fake-acme-orders acme))
  (setf (fake-acme-responded acme) nil (fake-acme-csr acme) nil)
  (values '((:status . "pending") (:finalize . "https://acme.test/finalize/1")
            (:authorizations "https://acme.test/authz/1"))
          "https://acme.test/order/1"))

(defmethod gr8s.controllers::cm-acme-fetch ((acme fake-acme) client url)
  (declare (ignore client))
  (if (search "/authz/" url)
      `((:status . ,(cond ((not (fake-acme-responded acme)) "pending")
                          ((plusp (fake-acme-validations acme)) (decf (fake-acme-validations acme)) "pending")
                          (t (fake-acme-outcome acme))))
        (:identifier (:type . "dns") (:value . "demo.example.com"))
        (:challenges ((:type . "dns-01") (:url . "https://acme.test/chall/dns") (:token . "dns-token"))
                     ((:type . "http-01") (:url . "https://acme.test/chall/1") (:token . "tok-1")
                      ,@(when (equal "invalid" (fake-acme-outcome acme))
                          '((:error (:type . "urn:ietf:params:acme:error:connection")
                                    (:detail . "Timeout during connect")))))))
      `((:status . ,(if (fake-acme-csr acme) "valid" "ready"))
        (:certificate . "https://acme.test/cert/1"))))

(defmethod gr8s.controllers::cm-acme-key-authorization ((acme fake-acme) client token)
  (declare (ignore client))
  (format nil "~A.thumb" token))

(defmethod gr8s.controllers::cm-acme-respond ((acme fake-acme) client url)
  (declare (ignore client))
  (is (equal "https://acme.test/chall/1" url))
  (setf (fake-acme-responded acme) t))

(defmethod gr8s.controllers::cm-acme-finalize ((acme fake-acme) client url csr)
  (declare (ignore client))
  (is (equal "https://acme.test/finalize/1" url))
  (setf (fake-acme-csr acme) csr)
  '((:status . "processing")))

(defmethod gr8s.controllers::cm-acme-download ((acme fake-acme) client url)
  (declare (ignore client))
  (is (equal "https://acme.test/cert/1" url))
  (values (gr8s.controllers::cm-issue-leaf :dns-names '("demo.example.com"))))

(defmacro with-fake-acme ((acme clock &rest initargs) &body body)
  "Run BODY with a scripted ACME server ACME and a settable clock CLOCK (a cons)."
  `(let* ((,acme (make-instance 'fake-acme ,@initargs))
          (,clock (list 3900000000))
          (gr8s.controllers::*cm-acme-backend* ,acme)
          (gr8s.controllers::*cm-acme-orders* (make-hash-table :test 'equal))
          (gr8s.controllers::*cm-acme-clients* (make-hash-table :test 'equal))
          (gr8s.controllers::*cert-manager-clock* (lambda () (car ,clock))))
     ,@body))

(defun acme-certificate-condition (store type)
  (find type (coerce (gethash "conditions" (gethash "status" (gr8s.resources::get-core-resource
                                                             store "certificates" "certs" "demo"))
                                         #()) 'list)
        :test #'equal :key (lambda (condition) (gethash "type" condition))))

(test acme-issuer-orders-validates-and-writes-the-tls-secret
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (setf (fake-acme-validations acme) 1)
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
      (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
      (flet ((reconcile-after (&optional (seconds 0))
               (incf (car clock) seconds)
               (gr8s.controllers::reconcile-certificates store nil))
             (challenges () (gr8s.resources::list-core-resources store "challenges" "certs")))
        (reconcile-after)
        ;; The account key went to the ClusterIssuer's Secret, and the account to its status.
        (is (gethash "tls.key" (gethash "data" (gr8s.resources::get-core-resource
                                                store "secrets" "kube-system" "letsencrypt-account"))))
        (is (equal "https://acme.test/acct/1"
                   (gethash "uri" (gethash "acme" (gethash "status" (gr8s.resources::get-core-resource
                                                                     store "clusterissuers" nil "letsencrypt"))))))
        (is (= 1 (fake-acme-orders acme)))
        (is (= 1 (length (challenges))))
        (let ((spec (gethash "spec" (first (challenges)))))
          (is (equal "demo.example.com" (gethash "dnsName" spec)))
          (is (equal "tok-1" (gethash "token" spec)))
          (is (equal "tok-1.thumb" (gethash "key" spec)))
          (is (equal "https://acme.test/chall/1" (gethash "url" spec))))
        (is (equal "True" (gethash "status" (acme-certificate-condition store "Issuing"))))
        ;; The server is not asked to validate until nodes have had time to learn the Challenge.
        (reconcile-after 1)
        (is (null (fake-acme-responded acme)))
        (reconcile-after 10)
        (is (fake-acme-responded acme))
        (reconcile-after)
        (is (null (fake-acme-csr acme)) "a pass before the poll interval must not poll")
        (reconcile-after 5)                          ; still pending
        (is (null (fake-acme-csr acme)))
        (reconcile-after 5)                          ; valid: finalize with a CSR for the dnsNames
        (is (search (trivial-utf-8:string-to-utf-8-bytes "demo.example.com") (fake-acme-csr acme)))
        (is (null (ignore-errors (gr8s.resources::get-core-resource store "secrets" "certs" "demo-tls"))))
        (reconcile-after 5)                          ; order valid: download
        (let ((secret (gr8s.resources::get-core-resource store "secrets" "certs" "demo-tls")))
          (is (equal "kubernetes.io/tls" (gethash "type" secret)))
          (is (search "BEGIN CERTIFICATE" (cm-secret-pem store "certs" "demo-tls" "tls.crt")))
          (is (search "BEGIN RSA PRIVATE KEY" (cm-secret-pem store "certs" "demo-tls" "tls.key"))))
        (is (equal "True" (gethash "status" (acme-certificate-condition store "Ready"))))
        (is (gethash "renewalTime" (gethash "status" (gr8s.resources::get-core-resource
                                                      store "certificates" "certs" "demo"))))
        (is (null (challenges)))
        (is (= 1 (fake-acme-orders acme)))
        ;; Issued: later passes leave the server alone until renewal.
        (reconcile-after 3600)
        (is (= 1 (fake-acme-orders acme)))))))

(test acme-issuer-backs-off-after-a-failed-validation
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock :outcome "invalid")
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
      (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
      (flet ((reconcile-after (&optional (seconds 0))
               (incf (car clock) seconds)
               (gr8s.controllers::reconcile-certificates store nil))
             (status () (gethash "status" (gr8s.resources::get-core-resource store "certificates" "certs" "demo"))))
        (reconcile-after) (reconcile-after 10) (reconcile-after 5)
        (is (null (gr8s.resources::list-core-resources store "challenges" "certs")))
        (is (= 1 (gethash "failedIssuanceAttempts" (status))))
        (is (gethash "lastFailureTime" (status)))
        (is (search "Timeout during connect" (gethash "message" (acme-certificate-condition store "Ready"))))
        (is (equal "False" (gethash "status" (acme-certificate-condition store "Issuing"))))
        ;; Within the first backoff nothing reaches the server.
        (reconcile-after 60) (reconcile-after 120)
        (is (= 1 (fake-acme-orders acme)))
        (reconcile-after 300)
        (is (= 2 (fake-acme-orders acme)))
        ;; A second failure doubles the wait.
        (reconcile-after 10) (reconcile-after 5)
        (is (= 2 (gethash "failedIssuanceAttempts" (status))))
        (reconcile-after 400)
        (is (= 2 (fake-acme-orders acme)))
        (reconcile-after 300)
        (is (= 3 (fake-acme-orders acme)))))))

(test acme-issuer-defers-on-retry-after-without-counting-a-failure
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (setf (fake-acme-defer acme) 30)
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
      (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
      (flet ((reconcile-after (&optional (seconds 0))
               (incf (car clock) seconds)
               (gr8s.controllers::reconcile-certificates store nil)))
        (reconcile-after)
        (is (= 0 (fake-acme-orders acme)))
        (let ((status (gethash "status" (gr8s.resources::get-core-resource store "certificates" "certs" "demo"))))
          (is (null (and (hash-table-p status) (gethash "failedIssuanceAttempts" status)))))
        (reconcile-after 10)
        (is (= 0 (fake-acme-orders acme)))
        (reconcile-after 21)
        (is (= 1 (fake-acme-orders acme)))))))

(test acme-issuer-rejects-names-http01-cannot-validate
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
      (let ((certificate (cm-parse *acme-certificate*)))
        (setf (gethash "dnsNames" (gethash "spec" certificate)) (vector "*.example.com"))
        (gr8s.resources::create-core-resource store "certificates" certificate "certs"))
      (gr8s.controllers::reconcile-certificates store nil)
      (is (= 0 (fake-acme-orders acme)))
      (is (search "DNS-01" (gethash "message" (acme-certificate-condition store "Ready")))))))
