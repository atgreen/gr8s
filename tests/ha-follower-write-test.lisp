;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; A member that does not lead carries a write to the leader itself and passes
;;;; the answer back (podster-l8i). It used to answer 307 and leave the client to
;;;; reach the leader, where a client waited out its own timeout if the leader had
;;;; just stopped. The follower holds the write while no leader can take it, serves
;;;; it itself if it comes to lead, and never sends it twice. Reads are served
;;;; locally, and a request that upgrades its connection is still redirected.

(in-package #:gr8s/tests)
(def-suite ha-follower-write :in gr8s)
(in-suite ha-follower-write)

(defun follower-write-request (port method path &key content (content-type "application/json"))
  "Send one API request to the server on PORT; return its status, parsed JSON body and headers."
  (multiple-value-bind (body status headers)
      (drakma:http-request (format nil "http://127.0.0.1:~D~A" port path)
                           :method method :redirect nil :content content :content-type content-type
                           :force-binary t)
    (values status
            (ignore-errors (com.inuoe.jzon:parse body))
            headers)))

(defun follower-write-configmap-json (name value)
  (format nil "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"~A\",\"namespace\":\"default\"},\"data\":{\"k\":\"~A\"}}"
          name value))

(defun call-with-leader-and-follower (function &key (patience 5))
  "Call FUNCTION with a leader's port and store, a follower's port and store, and a
function that sets what the follower believes: (values self-leader-p leader-url)."
  (with-temporary-store (leader-store leader-path)
    (with-temporary-store (follower-store follower-path)
      (declare (ignore leader-path follower-path))
      (let* ((belief (list nil nil))
             (leader (gr8s.apiserver::start-server :address "127.0.0.1" :port 0 :store leader-store))
             (follower (gr8s.apiserver::start-server
                        :address "127.0.0.1" :port 0 :store follower-store
                        :leader-status-fn (lambda () (values (first belief) (second belief)))))
             (saved gr8s.apiserver::*leader-relay-patience-seconds*))
        (unwind-protect
             (progn
               ;; Request threads read the global value.
               (setf gr8s.apiserver::*leader-relay-patience-seconds* patience)
               (funcall function
                        (hunchentoot:acceptor-port leader) leader-store
                        (hunchentoot:acceptor-port follower) follower-store
                        (lambda (self-leader-p leader-url) (setf belief (list self-leader-p leader-url)))))
          (setf gr8s.apiserver::*leader-relay-patience-seconds* saved)
          (gr8s.apiserver::stop-server follower)
          (gr8s.apiserver::stop-server leader))))))

(test a-follower-carries-a-write-to-the-leader
  (call-with-leader-and-follower
   (lambda (leader-port leader-store follower-port follower-store believe)
     (funcall believe nil (format nil "http://127.0.0.1:~D" leader-port))
     (multiple-value-bind (status body)
         (follower-write-request follower-port :post "/api/v1/namespaces/default/configmaps?fieldManager=test"
                                 :content (follower-write-configmap-json "carried" "one"))
       (is (= 201 status))
       (is (equal "carried" (gethash "name" (gethash "metadata" body))) "the leader's answer comes back"))
     (is (equal "one" (configmap-value leader-store "carried" "k")) "the leader holds the write")
     (is (null (configmap-value follower-store "carried" "k")) "the follower wrote nothing itself")
     ;; What the leader refuses, the client is told as the leader put it.
     (multiple-value-bind (status body)
         (follower-write-request follower-port :post "/api/v1/namespaces/default/configmaps"
                                 :content (follower-write-configmap-json "carried" "two"))
       (is (= 409 status))
       (is (equal "AlreadyExists" (gethash "reason" body))))
     ;; The method, the body and its type all travel.
     (is (= 200 (follower-write-request follower-port :patch "/api/v1/namespaces/default/configmaps/carried"
                                        :content "{\"data\":{\"k\":\"patched\"}}"
                                        :content-type "application/merge-patch+json")))
     (is (equal "patched" (configmap-value leader-store "carried" "k")))
     (is (= 200 (follower-write-request follower-port :delete "/api/v1/namespaces/default/configmaps/carried")))
     (is (null (configmap-value leader-store "carried" "k")))
     ;; A read is answered here.
     (is (= 200 (follower-write-request follower-port :get "/api/v1/namespaces/default/configmaps"))))))

(test a-write-waits-for-a-leader-that-can-take-it
  ;; The leader has just stopped. Nothing answers at its address, so the write
  ;; was not sent and may go to whoever leads next.
  (call-with-leader-and-follower
   (lambda (leader-port leader-store follower-port follower-store believe)
     (declare (ignore follower-store))
     (funcall believe nil "http://127.0.0.1:1")
     (let* ((started (get-internal-real-time))
            (elected (bt:make-thread (lambda ()
                                       (sleep 1.5)
                                       (funcall believe nil (format nil "http://127.0.0.1:~D" leader-port))))))
       (is (= 201 (follower-write-request follower-port :post "/api/v1/namespaces/default/configmaps"
                                          :content (follower-write-configmap-json "held" "v"))))
       (bt:join-thread elected)
       (is (>= (/ (- (get-internal-real-time) started) internal-time-units-per-second) 1.4)
           "the client waited for the election, and no longer")
       (is (equal "v" (configmap-value leader-store "held" "k")))))))

(test a-follower-that-comes-to-lead-serves-the-write-itself
  (call-with-leader-and-follower
   (lambda (leader-port leader-store follower-port follower-store believe)
     (declare (ignore leader-port))
     (funcall believe nil "http://127.0.0.1:1")
     (let ((elected (bt:make-thread (lambda () (sleep 1) (funcall believe t nil)))))
       (is (= 201 (follower-write-request follower-port :post "/api/v1/namespaces/default/configmaps"
                                          :content (follower-write-configmap-json "mine" "v"))))
       (bt:join-thread elected))
     (is (equal "v" (configmap-value follower-store "mine" "k")))
     (is (null (configmap-value leader-store "mine" "k"))))))

(test a-write-no-leader-takes-is-refused-so-that-the-client-tries-again
  (call-with-leader-and-follower
   (lambda (leader-port leader-store follower-port follower-store believe)
     (declare (ignore leader-port leader-store follower-store))
     (dolist (leader-url '(nil "http://127.0.0.1:1"))
       (funcall believe nil leader-url)
       (multiple-value-bind (status body headers)
           (follower-write-request follower-port :post "/api/v1/namespaces/default/configmaps"
                                   :content (follower-write-configmap-json "nobody" "v"))
         (is (= 503 status))
         (is (equal "ServiceUnavailable" (gethash "reason" body)))
         (is (equal "1" (cdr (assoc :retry-after headers)))))))
   :patience 1))

(test a-request-that-upgrades-its-connection-is-still-sent-to-the-leader
  ;; An exec or a port-forward is a conversation, not a request: the client has
  ;; to hold it with the member that will carry it.
  (call-with-leader-and-follower
   (lambda (leader-port leader-store follower-port follower-store believe)
     (declare (ignore leader-port leader-store follower-store))
     (funcall believe nil "http://10.0.0.9:6443")
     (dolist (path '("/api/v1/namespaces/default/pods/p/exec?command=ls"
                     "/api/v1/namespaces/default/pods/p/attach"
                     "/api/v1/namespaces/default/pods/p/portforward"
                     "/api/v1/namespaces/default/services/s/proxy/x"))
       (multiple-value-bind (status body headers) (follower-write-request follower-port :post path :content "")
         (declare (ignore body))
         (is (= 307 status) "~A" path)
         (is (equal (concatenate 'string "http://10.0.0.9:6443" path) (cdr (assoc :location headers)))))))))

;;; Over TLS the follower asks with its own administrative certificate. What the
;;; leader then does it must do as the client, with the client's rights and no more.

(defun follower-write-grant (store name rules)
  (certificate-api-test-grant
   store name
   (gr8s.resources::core-object "kind" "User" "name" "engineer" "apiGroup" "rbac.authorization.k8s.io")
   rules))

(test the-leader-acts-as-the-client-whose-write-a-follower-carried
  (with-temporary-store (leader-store leader-directory)
    (with-temporary-store (follower-store follower-directory)
      (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" leader-directory)))
             (collection "/apis/certificates.k8s.io/v1/certificatesigningrequests")
             (certificate (merge-pathnames "engineer.pem" follower-directory))
             (key (merge-pathnames "engineer.key" follower-directory))
             (requests (gr8s.resources::core-object "apiGroups" #("certificates.k8s.io")
                                                    "resources" #("certificatesigningrequests") "verbs" #("create")))
             (secrets (gr8s.resources::core-object "apiGroups" #("") "resources" #("secrets") "verbs" #("create")))
             (leader nil) (follower nil) (*tls-api-port* nil))
        (unwind-protect
             (flet ((listener (store &rest arguments)
                      (let ((runtime (make-fake-runtime)))
                        (apply #'gr8s.apiserver::start-in-cluster-api store runtime (make-reconciler store runtime) pki
                               :address "127.0.0.1" :port 0 arguments)))
                    (actor (name)
                      (let ((spec (gethash "spec" (gr8s.resources::get-core-resource
                                                   leader-store "certificatesigningrequests" nil name))))
                        (list (gethash "username" spec) (gethash "uid" spec)
                              (sort (coerce (gethash "groups" spec) 'list) #'string<)
                              (let ((extra (gethash "extra" spec)))
                                (and (hash-table-p extra)
                                     (sort (loop for k being the hash-keys of extra using (hash-value v)
                                                 collect (cons k (coerce v 'list)))
                                           #'string< :key #'car)))))))
               (setf leader (listener leader-store))
               (let ((leader-url (format nil "https://127.0.0.1:~D" (hunchentoot:acceptor-port leader))))
                 (setf follower (listener follower-store :leader-status-fn (lambda () (values nil leader-url)))))
               (multiple-value-bind (leaf private)
                   (certificate-api-test-subject-leaf
                    pki '(((2 5 4 3) . "engineer") ((2 5 4 10) . "engineering")
                          ((1 3 6 1 4 1 57683 2) . "engineer-uid")))
                 (gr8s.security::write-private-text-exclusively
                  certificate (pure-tls/acme::wrap-pem "CERTIFICATE" (pure-tls::x509-certificate-raw-der leaf)))
                 (gr8s.security::write-private-text-exclusively
                  key (pure-tls/acme::encode-ec-private-key-pem private)))
               ;; The follower believes the engineer may also create Secrets; the leader knows better.
               (follower-write-grant leader-store "engineer" (vector requests))
               (follower-write-grant follower-store "engineer" (vector requests secrets))
               (let ((request (csr-crypto-fixture follower-directory "ec")))
                 (setf *tls-api-port* (hunchentoot:acceptor-port leader))
                 (is (= 201 (certificate-api-test-request pki certificate key collection :method "POST"
                                                          :object (csr-fixture request :name "direct"))))
                 (setf *tls-api-port* (hunchentoot:acceptor-port follower))
                 (is (= 201 (certificate-api-test-request pki certificate key collection :method "POST"
                                                          :object (csr-fixture request :name "carried")))))
               (is (null (gr8s.resources::list-core-resources follower-store "certificatesigningrequests")))
               (is (equal "engineer" (first (actor "carried"))))
               (is (equal "engineer-uid" (second (actor "carried"))))
               (is (find "engineering" (third (actor "carried")) :test #'equal))
               (is (not (find "system:masters" (third (actor "carried")) :test #'equal)))
               (is (equal (actor "direct") (actor "carried"))
                   "the leader records the same requester whichever member the client asked")
               (multiple-value-bind (status body)
                   (certificate-api-test-request
                    pki certificate key "/api/v1/namespaces/default/secrets" :method "POST"
                    :object (gr8s.resources::core-object "apiVersion" "v1" "kind" "Secret"
                                                         "metadata" (gr8s.resources::core-object "name" "s")))
                 (is (= 403 status) "the leader refuses what the client may not do")
                 (is (search "engineer" (gethash "message" body))))
               (is (null (gr8s.resources::list-core-resources leader-store "secrets" "default")))
               ;; A group named "a,b" would reach the leader as the groups a and b. A client
               ;; that holds such a name is not spoken for; it is sent to the leader.
               (let ((odd-certificate (merge-pathnames "odd.pem" follower-directory))
                     (odd-key (merge-pathnames "odd.key" follower-directory)))
                 (multiple-value-bind (leaf private)
                     (certificate-api-test-subject-leaf
                      pki '(((2 5 4 3) . "engineer") ((2 5 4 10) . "engineering,system:masters")))
                   (gr8s.security::write-private-text-exclusively
                    odd-certificate (pure-tls/acme::wrap-pem "CERTIFICATE" (pure-tls::x509-certificate-raw-der leaf)))
                   (gr8s.security::write-private-text-exclusively
                    odd-key (pure-tls/acme::encode-ec-private-key-pem private)))
                 (setf *tls-api-port* (hunchentoot:acceptor-port follower))
                 (let ((text (uiop:run-program
                              (list "curl" "--silent" "--max-time" "10" "--output" "/dev/null"
                                    "--cacert" (namestring (gr8s.security::cluster-pki-ca-certificate-path pki))
                                    "--cert" (namestring odd-certificate) "--key" (namestring odd-key)
                                    "--request" "POST" "--header" "Content-Type: application/json"
                                    "--data-binary" "{}" "--write-out" "%{http_code}"
                                    (format nil "https://127.0.0.1:~D/api/v1/namespaces/default/secrets" *tls-api-port*))
                              :output :string)))
                   (is (equal "307" text)))
                 (is (null (gr8s.resources::list-core-resources leader-store "secrets" "default"))))
               ;; What a bound token proves about its Pod travels as extra attributes.
               (multiple-value-bind (admin-certificate admin-key)
                   (gr8s.apiserver::ensure-admin-client-credentials pki)
                 (setf *tls-api-port* (hunchentoot:acceptor-port leader))
                 (is (= 201 (certificate-api-test-request
                             pki admin-certificate admin-key collection :method "POST"
                             :object (csr-fixture (csr-crypto-fixture follower-directory "ec") :name "with-extra")
                             :headers '("Impersonate-User: engineer"
                                        "Impersonate-Extra-authentication.kubernetes.io%2Fpod-name: builder-0"))))
                 (is (equal '(("authentication.kubernetes.io/pod-name" "builder-0"))
                            (fourth (actor "with-extra"))))))
          (when follower (stop-server follower))
          (when leader (stop-server leader)))))))

(test an-identity-is-carried-only-if-headers-can-hold-it-exactly
  (flet ((expressible-p (&rest arguments)
           (gr8s.apiserver::leader-relay-identity-expressible-p
            (apply #'gr8s.resources::make-api-user-identity arguments)))
         (extra (key &rest values)
           (let ((table (make-hash-table :test #'equal)))
             (setf (gethash key table) (coerce values 'vector))
             table)))
    (is (expressible-p :username "system:serviceaccount:monitoring:prometheus" :uid "0f3c"
                       :groups #("system:serviceaccounts" "system:authenticated")
                       :extra (extra "authentication.kubernetes.io/pod-name" "prometheus-0")))
    (is (expressible-p :username "CN=Jane Doe, OU=eng" :groups #("system:authenticated"))
        "a name is one header and is not divided")
    (is (not (expressible-p :username "jane" :groups #("devs,system:masters"))))
    (is (not (expressible-p :username "jane" :groups #(" system:masters"))))
    (is (not (expressible-p :username (format nil "jane~C~CImpersonate-Group: system:masters" #\Return #\Linefeed)
                            :groups #("devs"))))
    (is (not (expressible-p :username "jane" :uid (format nil "1~Cx" #\Tab) :groups #("devs"))))
    (is (not (expressible-p :username (format nil "j~Cne" (code-char 228)) :groups #("devs"))))
    (is (not (expressible-p :username "jane" :groups #("devs") :extra (extra "scopes" "a,b"))))
    (is (not (expressible-p :username "jane" :groups #("devs") :extra (extra "Scopes" "a"))))
    (is (not (expressible-p :username "" :groups #("devs"))))))
