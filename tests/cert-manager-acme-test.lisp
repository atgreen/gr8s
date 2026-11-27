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

(defun acme-challenge-object (&key (name "demo-1") (token "tok-1") (host "demo.example.com") (namespace "certs"))
  "A Challenge whose solver attaches to Gateway certs/web."
  (cm-parse (format nil "{\"apiVersion\":\"acme.cert-manager.io/v1\",\"kind\":\"Challenge\",
    \"metadata\":{\"name\":\"~A\",\"namespace\":\"~A\"},
    \"spec\":{\"url\":\"https://acme.test/chall/1\",\"authorizationURL\":\"https://acme.test/authz/1\",
      \"dnsName\":\"~A\",\"type\":\"HTTP-01\",\"token\":\"~A\",\"key\":\"~A.thumb\",
      \"solver\":{\"http01\":{\"gatewayHTTPRoute\":{\"parentRefs\":[{\"name\":\"web\",\"namespace\":\"certs\"}]}}},
      \"issuerRef\":{\"name\":\"letsencrypt\",\"kind\":\"ClusterIssuer\"}}}" name namespace host token token)))

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
      (bad (lambda (acme) (setf (gethash "externalAccountBinding" acme) (cm-parse "{\"keyID\":\"k\"}"))))
      ;; A solver route without parents attaches nowhere, so nothing would answer.
      (bad (lambda (acme) (setf (gethash "solvers" acme)
                                (vector (cm-parse "{\"http01\":{\"gatewayHTTPRoute\":{}}}")))))
      (bad (lambda (acme) (setf (gethash "solvers" acme)
                                (vector (cm-parse "{\"http01\":{\"gatewayHTTPRoute\":{\"parentRefs\":[]}}}"))))))
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

(defun acme-gateway-view (&rest objects)
  "A node Gateway view holding the GatewayClass, Gateways and Challenges OBJECTS."
  (let ((resources (make-hash-table :test 'equal)))
    (dolist (object objects)
      (let ((metadata (gethash "metadata" object)))
        (setf (gethash (list (cond ((equal "GatewayClass" (gethash "kind" object)) "gatewayclasses")
                                   ((equal "Gateway" (gethash "kind" object)) "gateways")
                                   (t "challenges"))
                             (gethash "namespace" metadata) (gethash "name" metadata))
                       resources)
              object)))
    (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index resources))))

(defun acme-gateway (&key (name "web") (namespace "certs") (hostname "*.example.com") (from "Same"))
  (cm-parse (format nil "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",
    \"metadata\":{\"name\":\"~A\",\"namespace\":\"~A\"},
    \"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[
      {\"name\":\"http\",\"port\":80,\"protocol\":\"HTTP\",\"hostname\":\"~A\",
       \"allowedRoutes\":{\"namespaces\":{\"from\":\"~A\"}}},
      {\"name\":\"other\",\"port\":8080,\"protocol\":\"HTTP\",\"hostname\":\"elsewhere.test\"}]}}"
                    name namespace hostname from)))

(defun acme-gateway-class ()
  (let ((class (cm-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"GatewayClass\",
                           \"metadata\":{\"name\":\"gr8s\"},\"spec\":{}}")))
    (setf (gethash "controllerName" (gethash "spec" class)) gr8s.controllers::*gateway-controller-name*)
    class))

(defun acme-challenge-with-parents (challenge parent-refs-json)
  (setf (gethash "solver" (gethash "spec" challenge))
        (cm-parse (format nil "{\"http01\":{\"gatewayHTTPRoute\":{\"parentRefs\":~A}}}" parent-refs-json)))
  challenge)

(test acme-challenges-reach-the-agent-gateway-view
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource
     store "challenges" (acme-challenge-with-parents (acme-challenge-object) "[{\"name\":\"web\"}]") "certs")
    (let* ((projection (gr8s.kubelet::service-discovery-projection store))
           (resources (gr8s.kubelet::decode-service-discovery-projection projection))
           (public (gethash '("challenges" "certs" "demo-1") resources)))
      (is (hash-table-p public))
      ;; Only what the listener needs crosses to the node.
      (is (equal '("dnsName" "key" "solver" "token" "type")
                 (sort (alexandria:hash-table-keys (gethash "spec" public)) #'string<)))
      (let ((table (gr8s.controllers::gateway-acme-challenge-table
                    (apply #'acme-gateway-view (acme-gateway-class) (acme-gateway)
                           (alexandria:hash-table-values resources)))))
        ;; Port 80 covers the host and admits the namespace; port 8080 does neither.
        (is (equal '("demo.example.com" . "tok-1.thumb") (gethash "tok-1" (gethash 80 table))))
        (is (null (gethash 8080 table)))))
    ;; A Challenge change rides the Gateway delta path, not a full node snapshot.
    (is (member "challenges" gr8s.protocol::+gateway-config-resources+ :test #'equal))))

(test acme-challenges-answer-only-where-a-solver-route-could-attach
  (flet ((ports (gateway challenge)
           (let ((table (gr8s.controllers::gateway-acme-challenge-table
                         (acme-gateway-view (acme-gateway-class) gateway challenge))))
             (sort (loop for port being the hash-keys of table collect port) #'<))))
    (is (equal '(80) (ports (acme-gateway) (acme-challenge-object))))
    ;; Another tenant's namespace is not admitted by allowedRoutes: Same.
    (let ((foreign (acme-challenge-object)))
      (setf (gethash "namespace" (gethash "metadata" foreign)) "intruder")
      (is (null (ports (acme-gateway) foreign)))
      (is (equal '(80) (ports (acme-gateway :from "All") foreign))))
    ;; A host no listener covers is answered nowhere.
    (is (null (ports (acme-gateway) (acme-challenge-object :host "victim.org"))))
    (is (equal '(80) (ports (acme-gateway :hostname "demo.example.com") (acme-challenge-object))))
    ;; The solver's parentRefs pick the Gateway and the listener.
    (is (equal '(80) (ports (acme-gateway)
                            (acme-challenge-with-parents (acme-challenge-object)
                                                         "[{\"name\":\"web\",\"sectionName\":\"http\"}]"))))
    (is (null (ports (acme-gateway)
                     (acme-challenge-with-parents (acme-challenge-object) "[{\"name\":\"another\"}]"))))
    ;; No parentRefs: the solver route attaches nowhere, so nothing answers.
    (let ((orphan (acme-challenge-object)))
      (remhash "solver" (gethash "spec" orphan))
      (is (null (ports (acme-gateway :from "All") orphan))))
    ;; A Gateway of another controller is not ours to answer on.
    (let ((class (acme-gateway-class)))
      (setf (gethash "controllerName" (gethash "spec" class)) "example.com/other")
      (is (zerop (hash-table-count (gr8s.controllers::gateway-acme-challenge-table
                                    (acme-gateway-view class (acme-gateway) (acme-challenge-object)))))))))

(test acme-challenges-answer-on-the-listener-that-wins-the-host
  ;; One shared Gateway: L1 serves any host to any namespace; L2 serves only
  ;; victim.example.com, to its own namespace. Requests for victim.example.com
  ;; reach L2, so L1's broad admission must not answer for that host.
  (let ((gateway (cm-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",
          \"metadata\":{\"name\":\"web\",\"namespace\":\"certs\"},
          \"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[
            {\"name\":\"l1\",\"port\":80,\"protocol\":\"HTTP\",
             \"allowedRoutes\":{\"namespaces\":{\"from\":\"All\"}}},
            {\"name\":\"l2\",\"port\":80,\"protocol\":\"HTTP\",\"hostname\":\"victim.example.com\",
             \"allowedRoutes\":{\"namespaces\":{\"from\":\"Same\"}}}]}}")))
    (flet ((answered-p (challenge)
             (let ((table (gr8s.controllers::gateway-acme-challenge-table
                           (acme-gateway-view (acme-gateway-class) gateway challenge))))
               (and (gethash 80 table) (gethash "tok-1" (gethash 80 table)) t))))
      ;; A tenant elsewhere: not for the victim's host, which L2 wins...
      (is (not (answered-p (acme-challenge-object :namespace "intruder" :host "victim.example.com"))))
      ;; ...but yes for a host only L1 serves.
      (is (answered-p (acme-challenge-object :namespace "intruder" :host "tenant.example.net")))
      ;; The victim's own namespace is admitted by L2.
      (is (answered-p (acme-challenge-object :host "victim.example.com")))
      ;; Naming L1 by sectionName doesn't help: L2 still serves the host.
      (is (not (answered-p (acme-challenge-with-parents
                            (acme-challenge-object :namespace "intruder" :host "victim.example.com")
                            "[{\"name\":\"web\",\"namespace\":\"certs\",\"sectionName\":\"l1\"}]")))))))

(test gateway-listener-answers-acme-http01-before-routing
  (let* ((router (lambda (&rest arguments) (declare (ignore arguments)) nil))
         (gateway (gr8s.controllers::start-gateway-listener :port 0 :router router :resolver (constantly nil)
                                                           :name "acme"))
         (port (hunchentoot:acceptor-port gateway))
         (previous gr8s.controllers::*gateway-acme-challenges*))
    (unwind-protect
         (let ((table (make-hash-table)) (tokens (make-hash-table :test 'equal)))
           (setf (gethash "tok-1" tokens) (cons "demo.example.com" "tok-1.thumb")
                 (gethash port table) tokens
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
                                      :method "POST" :body "x")))
           ;; A token for another listener port is not this one's to answer.
           (remhash port table)
           (setf (gethash (1+ port) table) tokens)
           (is (= 404 (gw-raw-request port "demo.example.com" "/.well-known/acme-challenge/tok-1"))))
      (setf gr8s.controllers::*gateway-acme-challenges* previous)
      (gr8s.controllers::stop-gateway-listener gateway))))

;;; --- The real client's transport, against a stand-in server -----------------

(defun acme-test-client ()
  (let ((client (pure-tls/acme:make-acme-client
                 :directory-url "https://acme.test/directory"
                 :store (pure-tls/acme::%make-cert-store :account-key (ironclad:generate-key-pair :secp256r1)))))
    (setf (pure-tls/acme::acme-client-directory client)
          '((:new-order . "https://acme.test/new-order") (:new-nonce . "https://acme.test/nonce"))
          (pure-tls/acme::acme-client-account-url client) "https://acme.test/acct/1"
          (pure-tls/acme::acme-client-nonce client) "nonce-1")
    client))

(test acme-transport-verifies-tls-and-honours-long-retry-after
  (let* ((requests '())
         (gr8s.controllers::*cm-acme-transport*
           (lambda (url &rest arguments)
             (push (cons url arguments) requests)
             (cond ((search "new-order" url)
                    (values "{\"type\":\"urn:ietf:params:acme:error:rateLimited\",\"detail\":\"too many orders\"}"
                            429 '((:retry-after . "7200") (:replay-nonce . "nonce-2"))))
                   (t (values "{\"type\":\"urn:ietf:params:acme:error:malformed\",\"detail\":\"no such authorization\"}"
                              404 '((:replay-nonce . "nonce-3"))))))))
    ;; Two hours is past the client's own 120s budget; it is still a deferral.
    (let ((condition (handler-case (progn (gr8s.controllers::cm-acme-new-order
                                           :pure-tls (acme-test-client) '("demo.example.com") nil)
                                          nil)
                       (gr8s.controllers::cm-acme-deferred (condition) condition))))
      (is (typep condition 'gr8s.controllers::cm-acme-deferred))
      (is (= 7200 (gr8s.controllers::cm-acme-deferred-seconds condition))))
    (let ((request (find "https://acme.test/new-order" requests :key #'first :test #'equal)))
      (is (eq :required (getf (rest request) :verify)))
      ;; No profile is sent unless the issuer names one.
      (is (not (search "profile" (trivial-utf-8:utf-8-bytes-to-string (pure-tls/acme::base64url-decode
                                  (cdr (assoc :payload (cl-json:decode-json-from-string
                                                        (getf (rest request) :content))))))))))
    ;; An error reply to a fetch is an error, not an authorization still pending.
    (signals error (gr8s.controllers::cm-acme-fetch :pure-tls (acme-test-client) "https://acme.test/authz/9"))
    ;; skipTLSVerify alone turns verification off.
    (let ((client (acme-test-client)))
      (setf (pure-tls/acme::acme-client-skip-tls-verify client) t)
      (ignore-errors (gr8s.controllers::cm-acme-fetch :pure-tls client "https://acme.test/authz/9"))
      (is (null (getf (rest (first requests)) :verify :absent))))))

(test acme-transport-bounds-a-server-that-never-answers
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t))
         (port (usocket:get-local-port listener))
         (held nil)
         (acceptor (bt:make-thread (lambda () (setf held (ignore-errors (usocket:socket-accept listener))))
                                   :name "silent ACME server")))
    (unwind-protect
         (let ((gr8s.controllers::*cm-acme-request-deadline* 1)
               (started (get-internal-real-time)))
           (signals error (gr8s.controllers::cm-acme-http-request (format nil "http://127.0.0.1:~D/directory" port)))
           (is (< (/ (- (get-internal-real-time) started) internal-time-units-per-second) 10)))
      (ignore-errors (bt:join-thread acceptor))
      (when held (ignore-errors (usocket:socket-close held)))
      (usocket:socket-close listener))))

;;; --- The order state machine against a scripted ACME server -----------------

;;; Its methods ASSERT rather than IS: a step may run on its own thread, where
;;; FiveAM has no current test.
(defclass fake-acme ()
  ((orders :initform 0 :accessor fake-acme-orders)
   (responded :initform nil :accessor fake-acme-responded)
   (validations :initform 0 :accessor fake-acme-validations
                :documentation "Authorization polls after the response before it settles.")
   (outcome :initarg :outcome :initform "valid" :accessor fake-acme-outcome)
   (identifier :initarg :identifier :initform "demo.example.com" :accessor fake-acme-identifier)
   (wrong-key :initarg :wrong-key :initform nil :accessor fake-acme-wrong-key)
   (csr :initform nil :accessor fake-acme-csr)
   (defer :initform nil :accessor fake-acme-defer)
   (defer-authorization :initform nil :accessor fake-acme-defer-authorization)
   (registrations :initform 0 :accessor fake-acme-registrations)
   (account-delay :initform nil :accessor fake-acme-account-delay)
   (slow-server :initform nil :accessor fake-acme-slow-server)
   (on-new-order :initform nil :accessor fake-acme-on-new-order)
   (lock :initform (bt:make-lock "fake ACME") :reader fake-acme-lock)))

(defmethod gr8s.controllers::cm-acme-account ((acme fake-acme) server email key &key skip-tls-verify)
  (declare (ignore email key skip-tls-verify))
  (when (fake-acme-account-delay acme) (sleep (fake-acme-account-delay acme)))
  (when (equal server (fake-acme-slow-server acme)) (sleep 1.5))
  (bt:with-lock-held ((fake-acme-lock acme)) (incf (fake-acme-registrations acme)))
  (values :client "https://acme.test/acct/1"))

(defmethod gr8s.controllers::cm-acme-new-order ((acme fake-acme) client domains profile)
  (declare (ignore client profile))
  (when (fake-acme-defer acme)
    (error 'gr8s.controllers::cm-acme-deferred :seconds (shiftf (fake-acme-defer acme) nil)))
  (assert (equal '("demo.example.com") domains))
  (bt:with-lock-held ((fake-acme-lock acme)) (incf (fake-acme-orders acme)))
  (when (fake-acme-on-new-order acme) (funcall (fake-acme-on-new-order acme)))
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
        (:identifier (:type . "dns") (:value . ,(fake-acme-identifier acme)))
        (:challenges ((:type . "dns-01") (:url . "https://acme.test/chall/dns") (:token . "dns-token"))
                     ((:type . "http-01") (:url . "https://acme.test/chall/1") (:token . "tok-1")
                      ,@(when (equal "invalid" (fake-acme-outcome acme))
                          '((:error (:type . "urn:ietf:params:acme:error:connection")
                                    (:detail . "Timeout during connect")))))))
      `((:status . ,(if (fake-acme-csr acme) "valid" "ready"))
        (:certificate . "https://acme.test/cert/1"))))

(defmethod gr8s.controllers::cm-acme-key-authorization ((acme fake-acme) client token)
  (declare (ignore client))
  (when (fake-acme-defer-authorization acme)
    (error 'gr8s.controllers::cm-acme-deferred :seconds (shiftf (fake-acme-defer-authorization acme) nil)))
  (format nil "~A.thumb" token))

(defmethod gr8s.controllers::cm-acme-respond ((acme fake-acme) client url)
  (declare (ignore client))
  (assert (equal "https://acme.test/chall/1" url))
  (setf (fake-acme-responded acme) t))

(defmethod gr8s.controllers::cm-acme-finalize ((acme fake-acme) client url csr)
  (declare (ignore client))
  (assert (equal "https://acme.test/finalize/1" url))
  (setf (fake-acme-csr acme) csr)
  '((:status . "processing")))

(defun acme-test-leaf-pem (subject-public-key-info)
  "A leaf for demo.example.com carrying SUBJECT-PUBLIC-KEY-INFO, as a CA would
   issue for the CSR; who signs it is beside the point here."
  (let* ((signer (ironclad:generate-key-pair :secp256r1))
         (now (get-universal-time))
         (subject (pure-tls/acme::encode-subject "demo.example.com"))
         (algorithm (pure-tls/acme::encode-sequence
                     (pure-tls/acme::encode-oid pure-tls/acme::*oid-ecdsa-with-sha256*)))
         (tbs (pure-tls/acme::encode-sequence
               (pure-tls/acme::encode-context-tag 0 (pure-tls/acme::encode-integer 2))
               (pure-tls/acme::encode-integer 7) algorithm subject
               (pure-tls/acme::encode-validity (- now 60) (+ now (* 90 24 60 60)))
               subject subject-public-key-info)))
    (pure-tls/acme::wrap-pem "CERTIFICATE"
                             (pure-tls/acme::encode-sequence
                              tbs algorithm
                              (pure-tls/acme::encode-bit-string (gr8s.controllers::ecdsa-sign-der signer tbs))))))

(defmethod gr8s.controllers::cm-acme-download ((acme fake-acme) client url)
  (declare (ignore client))
  (assert (equal "https://acme.test/cert/1" url))
  (if (fake-acme-wrong-key acme)
      (values (gr8s.controllers::cm-issue-leaf :dns-names '("demo.example.com")))
      (let ((order (first (alexandria:hash-table-values gr8s.controllers::*cm-acme-orders*))))
        (acme-test-leaf-pem (pure-tls/acme::encode-rsa-public-key
                             (gr8s.controllers::cm-acme-order-leaf-private-key order)
                             (gr8s.controllers::cm-acme-order-leaf-public-key order))))))

(defmacro with-fake-acme ((acme clock &rest initargs) &body body)
  "Run BODY with a scripted ACME server ACME and a settable clock CLOCK (a cons).
   Steps run in the caller's thread, so each pass completes before the next."
  `(let* ((,acme (make-instance 'fake-acme ,@initargs))
          (,clock (list 3900000000))
          (gr8s.controllers::*cm-acme-backend* ,acme)
          (gr8s.controllers::*cm-acme-run-step* 'funcall)
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
          (is (null (if (hash-table-p status) (gethash "failedIssuanceAttempts" status) nil))))
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

(test acme-issuer-refuses-an-authorization-for-a-name-it-did-not-ask-for
  ;; A server (a tenant's own, say) that answers with another host's
  ;; authorization must not get a Challenge for that host presented.
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock :identifier "victim.example.org")
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
      (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
      (gr8s.controllers::reconcile-certificates store nil)
      (is (null (gr8s.resources::list-core-resources store "challenges")))
      (is (search "victim.example.org" (gethash "message" (acme-certificate-condition store "Ready")))))))

(test acme-issuer-refuses-a-certificate-without-the-order-key
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock :wrong-key t)
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
      (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
      (flet ((reconcile-after (&optional (seconds 0))
               (incf (car clock) seconds)
               (gr8s.controllers::reconcile-certificates store nil)))
        (reconcile-after) (reconcile-after 10) (reconcile-after 5) (reconcile-after 5)
        (is (null (ignore-errors (gr8s.resources::get-core-resource store "secrets" "certs" "demo-tls"))))
        (is (search "order's key" (gethash "message" (acme-certificate-condition store "Ready"))))))))

(test acme-issuer-deletes-challenges-no-order-owns
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
      (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
      (gr8s.controllers::reconcile-certificates store nil)
      (is (= 1 (length (gr8s.resources::list-core-resources store "challenges" "certs"))))
      ;; A restart or leader change loses the order; its Challenge must not outlive it.
      (clrhash gr8s.controllers::*cm-acme-orders*)
      (setf (fake-acme-defer acme) 600)            ; and the next order waits
      (gr8s.controllers::reconcile-certificates store nil)
      (is (null (gr8s.resources::list-core-resources store "challenges" "certs")))
      ;; A Challenge nobody owns is left to whoever wrote it.
      (gr8s.resources::create-core-resource store "challenges" (acme-challenge-object :name "manual") "certs")
      (gr8s.controllers::reconcile-certificates store nil)
      (is (= 1 (length (gr8s.resources::list-core-resources store "challenges" "certs"))))
      ;; Moving the Certificate to a non-ACME issuer retires its order and Challenges.
      (gr8s.resources::delete-core-resource store "challenges" "certs" "manual")
      (setf (fake-acme-defer acme) nil)
      (incf (car clock) 700)
      (gr8s.controllers::reconcile-certificates store nil)
      (is (= 1 (length (gr8s.resources::list-core-resources store "challenges" "certs"))))
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *cm-selfsigned-issuer*) nil)
      (gr8s.resources::update-core-resource store "certificates" "certs" "demo"
        (lambda (certificate)
          (setf (gethash "name" (gethash "issuerRef" (gethash "spec" certificate))) "selfsigned")
          certificate))
      (gr8s.controllers::reconcile-certificates store nil)
      (is (null (gr8s.resources::list-core-resources store "challenges" "certs")))
      (is (zerop (hash-table-count gr8s.controllers::*cm-acme-orders*))))))

(test acme-steps-run-off-the-reconcile-thread
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (let* ((release (bt:make-semaphore))
             (threads '())
             (gr8s.controllers::*cm-acme-run-step*
               (lambda (thunk)
                 (push (bt:make-thread (lambda () (bt:wait-on-semaphore release :timeout 10) (funcall thunk))
                                       :name "test ACME step")
                       threads))))
        (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
        (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
        ;; The pass returns while the step waits on its "server", and the next
        ;; pass does not start a second step for the same order.
        (gr8s.controllers::reconcile-certificates store nil)
        (gr8s.controllers::reconcile-certificates store nil)
        (is (= 1 (length threads)))
        (is (= 0 (fake-acme-orders acme)))
        (bt:signal-semaphore release)
        (bt:join-thread (first threads))
        (is (= 1 (fake-acme-orders acme)))
        (is (= 1 (length (gr8s.resources::list-core-resources store "challenges" "certs"))))))))

(test certificate-renewal-clamps-renew-before-to-the-real-validity
  (let ((day (* 24 60 60)))
    ;; The CA chose 7 days whatever spec.duration said; renewBefore 30d would
    ;; put renewal before issuance and reissue on every pass.
    (is (= (+ 1000 (* 14/3 day))
           (gr8s.controllers::cm-renewal-time (cm-parse "{\"renewBefore\":\"720h\"}") 1000 (+ 1000 (* 7 day)))))
    (is (= (+ 1000 (* 6 day))
           (gr8s.controllers::cm-renewal-time (cm-parse "{\"renewBefore\":\"24h\"}") 1000 (+ 1000 (* 7 day)))))))

(test certificate-renew-before-must-be-shorter-than-duration
  (with-core-api (store directory)
    (values store directory)
    (check-core-status 201 "/api/v1/namespaces" :method :post
                       :object (cm-parse "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"certs\"}}"))
    (flet ((post (name spec-extra)
             (let ((certificate (cm-parse *acme-certificate*)))
               (setf (gethash "name" (gethash "metadata" certificate)) name)
               (maphash (lambda (key value) (setf (gethash key (gethash "spec" certificate)) value))
                        (cm-parse spec-extra))
               certificate)))
      (check-core-status 422 "/apis/cert-manager.io/v1/namespaces/certs/certificates" :method :post
                         :object (post "a" "{\"duration\":\"24h\",\"renewBefore\":\"24h\"}"))
      (check-core-status 422 "/apis/cert-manager.io/v1/namespaces/certs/certificates" :method :post
                         :object (post "b" "{\"renewBefore\":\"2400h\"}"))
      (check-core-status 201 "/apis/cert-manager.io/v1/namespaces/certs/certificates" :method :post
                         :object (post "c" "{\"duration\":\"24h\",\"renewBefore\":\"8h\"}")))))

(test acme-issuer-resumes-an-order-deferred-part-way
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (setf (fake-acme-defer-authorization acme) 20)
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
      (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
      (gr8s.controllers::reconcile-certificates store nil)
      (is (= 1 (fake-acme-orders acme)))
      (incf (car clock) 21)
      (gr8s.controllers::reconcile-certificates store nil)
      ;; The same order carries on: no second order, one Challenge.
      (is (= 1 (fake-acme-orders acme)))
      (is (= 1 (length (gr8s.resources::list-core-resources store "challenges" "certs"))))
      (is (= 1 (length (gr8s.controllers::cm-acme-order-challenges
                        (first (alexandria:hash-table-values gr8s.controllers::*cm-acme-orders*)))))))))

(test acme-steps-stop-writing-once-leadership-ends
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (let ((leader t))
        (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
        (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
        ;; Demoted while the step talks to the server: it writes nothing after.
        (setf (fake-acme-on-new-order acme) (lambda () (setf leader nil)))
        (gr8s.controllers::reconcile-certificates store nil :leadership (cons 1 (lambda () leader)))
        (is (= 1 (fake-acme-orders acme)))
        (is (null (gr8s.resources::list-core-resources store "challenges")))
        (let ((status (gethash "status" (gr8s.resources::get-core-resource store "certificates" "certs" "demo"))))
          (is (null (if (hash-table-p status) (gethash "failedIssuanceAttempts" status) nil))))
        (is (zerop (hash-table-count gr8s.controllers::*cm-acme-orders*)))
        ;; Leadership regained (a new generation): orders start over cleanly.
        (setf (fake-acme-on-new-order acme) nil leader t)
        (gr8s.controllers::reconcile-certificates store nil :leadership (cons 2 (lambda () leader)))
        (is (= 1 (length (gr8s.resources::list-core-resources store "challenges" "certs"))))
        (is (= 1 (hash-table-count gr8s.controllers::*cm-acme-orders*)))
        ;; Another generation drops that order: the next one starts afresh and
        ;; replaces its Challenge rather than adding to it.
        (gr8s.controllers::reconcile-certificates store nil :leadership (cons 3 (lambda () leader)))
        (is (= 3 (fake-acme-orders acme)))
        (is (= 1 (length (gr8s.resources::list-core-resources store "challenges" "certs"))))))))

(test acme-steps-for-one-issuer-register-once
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (setf (fake-acme-account-delay acme) 0.3)
      (let* ((threads '())
             (gr8s.controllers::*cm-acme-run-step*
               (lambda (thunk) (push (bt:make-thread thunk :name "test ACME step") threads))))
        (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
        (dolist (name '("demo" "demo-two"))
          (let ((certificate (cm-parse *acme-certificate*)))
            (setf (gethash "name" (gethash "metadata" certificate)) name
                  (gethash "secretName" (gethash "spec" certificate)) (format nil "~A-tls" name))
            (gr8s.resources::create-core-resource store "certificates" certificate "certs")))
        (gr8s.controllers::reconcile-certificates store nil)
        (mapc #'bt:join-thread threads)
        (is (= 2 (length threads)))
        (is (= 1 (fake-acme-registrations acme)))
        (is (= 2 (fake-acme-orders acme)))))))

(test certificate-durations-parse-as-go-writes-them
  (loop for (text seconds) in '(("2160h0m0s" 7776000) ("1h30m" 5400) ("1.5h" 5400) ("90d" 7776000)
                                ("45m" 2700) ("10s" 10) ("1h0m30.5s" 3630) ("3600" 3600) (3600 3600)
                                ("500ms" nil) ("0s" nil) ("-1h" nil) ("1h30" nil) ("h" nil) ("1x" nil)
                                ("1..5h" nil) ("" nil))
        do (is (eql seconds (gr8s.resources::certificate-duration-seconds text)) "~S" text)))

(test certificate-status-writes-survive-a-rule-added-after-admission
  ;; A Certificate admitted before renewBefore < duration was enforced keeps
  ;; taking status writes; changing its spec has to satisfy the rule.
  (let* ((certificate (cm-parse *acme-certificate*))
         (spec (gethash "spec" certificate)))
    (setf (gethash "duration" spec) "24h" (gethash "renewBefore" spec) "48h")
    (finishes (gr8s.resources::validate-cert-manager-resource
               "certificates" certificate (gr8s.resources::copy-core-object spec)))
    (signals gr8s.resources::kubernetes-error
      (gr8s.resources::validate-cert-manager-resource "certificates" certificate))
    (let ((older (gr8s.resources::copy-core-object spec)))
      (setf (gethash "renewBefore" older) "8h")
      (signals gr8s.resources::kubernetes-error
        (gr8s.resources::validate-cert-manager-resource "certificates" certificate older)))))

(test acme-https-listeners-never-answer-http01
  (let ((gateway (cm-parse "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"Gateway\",
          \"metadata\":{\"name\":\"web\",\"namespace\":\"certs\"},
          \"spec\":{\"gatewayClassName\":\"gr8s\",\"listeners\":[
            {\"name\":\"https\",\"port\":443,\"protocol\":\"HTTPS\",\"hostname\":\"demo.example.com\",
             \"tls\":{\"certificateRefs\":[{\"name\":\"demo-tls\"}]}}]}}")))
    (is (zerop (hash-table-count (gr8s.controllers::gateway-acme-challenge-table
                                  (acme-gateway-view (acme-gateway-class) gateway (acme-challenge-object))))))))

(test acme-slow-registration-for-one-issuer-does-not-hold-up-another
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (setf (fake-acme-slow-server acme) "https://slow.test/directory")
      (let* ((threads '())
             (gr8s.controllers::*cm-acme-run-step*
               (lambda (thunk) (push (bt:make-thread thunk :name "test ACME step") threads))))
        (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
        (let ((slow (cm-parse *acme-issuer*)))
          (setf (gethash "name" (gethash "metadata" slow)) "slow"
                (gethash "server" (gethash "acme" (gethash "spec" slow))) "https://slow.test/directory")
          (gr8s.resources::create-core-resource store "clusterissuers" slow nil))
        (let ((certificate (cm-parse *acme-certificate*)))
          (setf (gethash "name" (gethash "metadata" certificate)) "a-slow"
                (gethash "secretName" (gethash "spec" certificate)) "slow-tls"
                (gethash "name" (gethash "issuerRef" (gethash "spec" certificate))) "slow")
          (gr8s.resources::create-core-resource store "certificates" certificate "certs"))
        (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
        (let ((started (get-internal-real-time)))
          (gr8s.controllers::reconcile-certificates store nil)
          ;; The fast issuer's order is placed while the slow one still registers.
          (loop until (or (find-if (lambda (challenge)
                                     (uiop:string-prefix-p "demo-" (gethash "name" (gethash "metadata" challenge))))
                                   (gr8s.resources::list-core-resources store "challenges" "certs"))
                          (> (- (get-internal-real-time) started) (* 3 internal-time-units-per-second)))
                do (sleep 0.02))
          (is (< (/ (- (get-internal-real-time) started) internal-time-units-per-second) 1.0))
          (is (= 1 (fake-acme-registrations acme)) "the slow registration has not finished yet"))
        (mapc #'bt:join-thread threads)
        (is (= 2 (fake-acme-registrations acme)))))))

(test acme-issuer-without-solver-parents-reports-instead-of-ordering
  (with-temporary-store (store path)
    (values path)
    (with-fake-acme (acme clock)
      (gr8s.resources::create-core-resource store "clusterissuers" (cm-parse *acme-issuer*) nil)
      (gr8s.resources::create-core-resource store "certificates" (cm-parse *acme-certificate*) "certs")
      ;; An issuer admitted before parentRefs were required, as the controller reads it.
      (let* ((issuer (gr8s.resources::get-core-resource store "clusterissuers" nil "letsencrypt"))
             (solver (aref (gethash "solvers" (gethash "acme" (gethash "spec" issuer))) 0)))
        (remhash "parentRefs" (gethash "gatewayHTTPRoute" (gethash "http01" solver)))
        ;; Its status writes are not refused for the newer rule...
        (finishes (gr8s.resources::validate-cert-manager-resource
                   "clusterissuers" issuer (gr8s.resources::copy-core-object (gethash "spec" issuer))))
        (signals gr8s.resources::kubernetes-error
          (gr8s.resources::validate-cert-manager-resource "clusterissuers" issuer))
        ;; ...and it places no order, saying why on the issuer and the Certificate.
        (gr8s.controllers::cm-acme-reconcile
         store (gr8s.resources::get-core-resource store "certificates" "certs" "demo") issuer))
      (is (= 0 (fake-acme-orders acme)))
      (is (= 0 (fake-acme-registrations acme)))
      (is (search "parentRefs" (gethash "message" (acme-certificate-condition store "Ready"))))
      (let* ((status (gethash "status" (gr8s.resources::get-core-resource store "clusterissuers" nil "letsencrypt")))
             (ready (find "Ready" (coerce (gethash "conditions" status) 'list)
                          :test #'equal :key (lambda (condition) (gethash "type" condition)))))
        (is (equal "NoUsableSolver" (gethash "reason" ready)))))))
