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
                                        "Impersonate-Extra-authentication.kubernetes.io%2Fpod-name: builder-0"
                                        ;; One attribute's values in one header, or in several.
                                        "Impersonate-Extra-scopes: view, edit"
                                        "Impersonate-Extra-teams: a" "Impersonate-Extra-teams: b"))))
                 (is (equal '(("authentication.kubernetes.io/pod-name" "builder-0")
                              ("scopes" "edit" "view") ("teams" "a" "b"))
                            (mapcar (lambda (entry) (cons (car entry) (sort (copy-list (cdr entry)) #'string<)))
                                    (fourth (actor "with-extra")))))))
          (when follower (stop-server follower))
          (when leader (stop-server leader)))))))

(test an-identity-is-carried-only-if-headers-can-hold-it-exactly
  (flet ((expressible-p (username &rest arguments &key (groups '("devs")) &allow-other-keys)
           (gr8s.apiserver::leader-relay-identity-expressible-p
            (apply #'gr8s.resources::make-api-user-identity
                   :username username
                   :groups (coerce (append groups '("system:authenticated")) 'vector)
                   (alexandria:remove-from-plist arguments :groups))))
         (extra (key &rest values)
           (let ((table (make-hash-table :test #'equal)))
             (setf (gethash key table) (coerce values 'vector))
             table)))
    (is (expressible-p "jane" :uid "0f3c" :extra (extra "authentication.kubernetes.io/pod-name" "builder-0")))
    (is (expressible-p "CN=Jane Doe, OU=eng") "a name is one header and is not divided")
    (is (not (expressible-p "jane" :groups '("devs,system:masters"))))
    (is (not (expressible-p "jane" :groups '(" system:masters"))))
    (is (not (expressible-p (format nil "jane~C~CImpersonate-Group: system:masters" #\Return #\Linefeed))))
    (is (not (expressible-p "jane" :uid (format nil "1~Cx" #\Tab))))
    (is (not (expressible-p (format nil "j~Cne" (code-char 228)))))
    (is (not (expressible-p "jane" :extra (extra "scopes" "a,b"))))
    (is (not (expressible-p "jane" :extra (extra "Scopes" "a"))))
    (is (not (expressible-p "jane" :extra (extra "scopes"))) "a key with no value has no header")
    (is (not (expressible-p "")))
    ;; The leader gives these groups to whoever is named so. A client must hold them already.
    (is (not (expressible-p "system:serviceaccount:monitoring:prometheus"))
        "a certificate named like a ServiceAccount is not one")
    (is (gr8s.apiserver::leader-relay-identity-expressible-p
         (gr8s.resources::make-api-service-account-identity :namespace "monitoring" :name "prometheus" :uid "0f3c")))
    (is (not (gr8s.apiserver::leader-relay-identity-expressible-p
              (gr8s.resources::make-api-user-identity :username "jane" :groups #("devs"))))
        "the leader would count this client among the authenticated")
    (is (gr8s.apiserver::leader-relay-identity-expressible-p
         (gr8s.resources::make-api-user-identity :username "system:anonymous" :groups #("system:unauthenticated"))))
    ;; Several values of one attribute travel in one header: the receiver keeps
    ;; only the first of several headers whose name it has not met before.
    (is (equal '(("Impersonate-User" . "jane") ("Impersonate-Group" . "system:authenticated")
                 ("Impersonate-Extra-scopes" . "view, edit"))
               (gr8s.apiserver::leader-relay-identity-headers
                (gr8s.resources::make-api-user-identity :username "jane" :groups #("system:authenticated")
                                                        :extra (extra "scopes" "view" "edit")))))))

(defun follower-write-curl (port &rest arguments)
  "POST a ConfigMap to PORT with curl and extra ARGUMENTS; return the status and the response headers."
  (let* ((text (uiop:run-program
                (append (list "curl" "--silent" "--max-time" "20" "--output" "/dev/null" "--dump-header" "-"
                              "--request" "POST" "--header" "Content-Type: application/json"
                              "--data-binary" (follower-write-configmap-json (format nil "c~D" (random 1000000)) "v")
                              "--write-out" "%{http_code}")
                        arguments
                        (list (format nil "http://127.0.0.1:~D/api/v1/namespaces/default/configmaps" port)))
                :output :string :ignore-error-status t))
         (code (parse-integer text :start (max 0 (- (length text) 3)) :junk-allowed t)))
    (values code (string-downcase text))))

(test a-write-that-asks-leave-to-send-its-body-is-answered-once
  ;; curl sends Expect: 100-continue when told to. The follower gives that leave
  ;; itself; the leader must not be asked for it again, or its interim answer
  ;; would be taken for the answer.
  (call-with-leader-and-follower
   (lambda (leader-port leader-store follower-port follower-store believe)
     (declare (ignore follower-store))
     (funcall believe nil (format nil "http://127.0.0.1:~D" leader-port))
     (is (= 201 (follower-write-curl follower-port "--header" "Expect: 100-continue")))
     (is (= 1 (length (gr8s.resources::list-core-resources leader-store "configmaps" "default")))))))

(test members-that-take-each-other-for-the-leader-do-not-pass-a-write-around
  (with-temporary-store (store-a path-a)
    (with-temporary-store (store-b path-b)
      (declare (ignore path-a path-b))
      (let* ((url-b nil) (url-a nil)
             (a (gr8s.apiserver::start-server :address "127.0.0.1" :port 0 :store store-a
                                              :leader-status-fn (lambda () (values nil url-b))))
             (b (gr8s.apiserver::start-server :address "127.0.0.1" :port 0 :store store-b
                                              :leader-status-fn (lambda () (values nil url-a))))
             (saved gr8s.apiserver::*leader-relay-patience-seconds*))
        (unwind-protect
             (progn
               (setf url-a (format nil "http://127.0.0.1:~D" (hunchentoot:acceptor-port a))
                     url-b (format nil "http://127.0.0.1:~D" (hunchentoot:acceptor-port b))
                     gr8s.apiserver::*leader-relay-patience-seconds* 1)
               ;; A member told that a write was carried to it says that it does not lead.
               (multiple-value-bind (code headers)
                   (follower-write-curl (hunchentoot:acceptor-port b) "--header" "X-Gr8s-Relayed: 1")
                 (is (= 503 code))
                 (is (search "x-gr8s-not-leader" headers)))
               ;; So a asks b, b refuses, and a gives up when its patience ends.
               (let ((started (get-internal-real-time)))
                 (is (= 503 (follower-write-curl (hunchentoot:acceptor-port a))))
                 (is (< (/ (- (get-internal-real-time) started) internal-time-units-per-second) 6)))
               (is (null (gr8s.resources::list-core-resources store-a "configmaps" "default")))
               (is (null (gr8s.resources::list-core-resources store-b "configmaps" "default"))))
          (setf gr8s.apiserver::*leader-relay-patience-seconds* saved)
          (gr8s.apiserver::stop-server a)
          (gr8s.apiserver::stop-server b))))))

(test a-member-holds-only-so-many-writes-while-there-is-no-leader
  (call-with-leader-and-follower
   (lambda (leader-port leader-store follower-port follower-store believe)
     (declare (ignore leader-port leader-store follower-store))
     (funcall believe nil "http://127.0.0.1:1")
     (let ((saved gr8s.apiserver::*leader-relay-waiting-places*)
           (started (get-internal-real-time)))
       (unwind-protect
            (progn
              (setf gr8s.apiserver::*leader-relay-waiting-places* 0)
              (is (= 503 (follower-write-curl follower-port)))
              (is (< (/ (- (get-internal-real-time) started) internal-time-units-per-second) 3)
                  "a write that finds no place is refused at once"))
         (setf gr8s.apiserver::*leader-relay-waiting-places* saved))
       (is (zerop gr8s.apiserver::*leader-relay-waiting*))))
   :patience 20))

(test an-answer-the-leader-does-not-finish-ends-the-request
  ;; The leader sends the head of its answer and then nothing. The follower's
  ;; thread must end, with its two connections, and not wait in the debugger.
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (peer nil)
         (stalling-leader
           (bt:make-thread
            (lambda ()
              (ignore-errors
                (setf peer (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
                (let ((stream (usocket:socket-stream peer)))
                  ;; Read the request's head, then answer with half a body.
                  (loop with seen = 0
                        for octet = (read-byte stream nil nil)
                        while octet
                        do (setf seen (if (member octet '(13 10)) (1+ seen) 0))
                        until (= seen 4))
                  (write-sequence (trivial-utf-8:string-to-utf-8-bytes
                                   (format nil "HTTP/1.1 200 OK~C~CContent-Length: 100~C~C~C~Chalf"
                                           #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))
                                  stream)
                  (force-output stream)
                  (sleep 8))))))
         (saved gr8s.apiserver::*leader-relay-answer-seconds*))
    (unwind-protect
         (call-with-leader-and-follower
          (lambda (leader-port leader-store follower-port follower-store believe)
            (declare (ignore leader-port leader-store follower-store))
            (funcall believe nil (format nil "http://127.0.0.1:~D" port))
            (setf gr8s.apiserver::*leader-relay-answer-seconds* 1)
            (let ((started (get-internal-real-time)))
              (follower-write-curl follower-port "--data-binary" "{}")
              (is (< (/ (- (get-internal-real-time) started) internal-time-units-per-second) 6)
                  "the client's connection is ended when the leader's time is up"))))
      (setf gr8s.apiserver::*leader-relay-answer-seconds* saved)
      (when peer (ignore-errors (usocket:socket-close peer)))
      (ignore-errors (usocket:socket-close listener))
      (ignore-errors (bt:join-thread stalling-leader)))))

;;; podster-f9u: handing the leadership over is asked of the leader, like any write.

(test a-follower-carries-a-request-to-hand-the-leadership-over
  (with-temporary-store (leader-store leader-directory)
    (with-temporary-store (follower-store follower-directory)
      (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" leader-directory)))
             (certificate (merge-pathnames "engineer.pem" follower-directory))
             (key (merge-pathnames "engineer.key" follower-directory))
             (members '((:id "cp1" :role :voter :leader t :contact :self)
                        (:id "cp2" :role :voter :contact :in-contact)
                        (:id "cp3" :role :voter :contact :in-contact)
                        (:id "w" :role :witness :contact :in-contact)))
             (asked-of-leader nil) (asked-of-follower nil)
             (leader nil) (follower nil) (*tls-api-port* nil))
        (flet ((listener (store membership-fn &rest arguments)
                 (let ((runtime (make-fake-runtime)))
                   (apply #'gr8s.apiserver::start-in-cluster-api store runtime (make-reconciler store runtime) pki
                          :address "127.0.0.1" :port 0 :control-plane-membership-fn membership-fn arguments)))
               (ask (name &optional (method "POST") (subresource "/leadership"))
                 (multiple-value-bind (status body)
                     (certificate-api-test-request
                      pki certificate key
                      (format nil "/apis/gr8s.io/v1/controlplanemembers/~A~A" name subresource) :method method)
                   (list status (gethash "message" body)))))
          (unwind-protect
               (progn
                 (setf leader (listener leader-store
                                        (lambda (action &optional id)
                                          (ecase action
                                            (:list (list :self "cp1" :leader "cp1" :members members))
                                            (:transfer-leadership
                                             (push id asked-of-leader)
                                             (cond ((equal id "cp1") (values nil :self))
                                                   ((equal id "w") (values nil :not-voter))
                                                   ((equal id "cp3") (values nil :out-of-contact))
                                                   (t (values t nil))))))))
                 (let ((leader-url (format nil "https://127.0.0.1:~D" (hunchentoot:acceptor-port leader))))
                   (setf follower (listener follower-store
                                            (lambda (action &optional id)
                                              (ecase action
                                                (:list (list :self "cp2" :leader "cp1" :members members))
                                                (:transfer-leadership (push id asked-of-follower)
                                                                      (values nil :not-leader))))
                                            :leader-status-fn (lambda () (values nil leader-url)))))
                 (multiple-value-bind (leaf private)
                     (certificate-api-test-subject-leaf pki '(((2 5 4 3) . "engineer")))
                   (gr8s.security::write-private-text-exclusively
                    certificate (pure-tls/acme::wrap-pem "CERTIFICATE" (pure-tls::x509-certificate-raw-der leaf)))
                   (gr8s.security::write-private-text-exclusively
                    key (pure-tls/acme::encode-ec-private-key-pem private)))
                 (setf *tls-api-port* (hunchentoot:acceptor-port follower))
                 (is (= 403 (first (ask "cp2"))) "the right must be granted")
                 (is (null asked-of-leader))
                 (dolist (store (list leader-store follower-store))
                   (follower-write-grant
                    store "engineer"
                    (vector (gr8s.resources::core-object "apiGroups" #("gr8s.io")
                                                         "resources" #("controlplanemembers/leadership")
                                                         "verbs" #("create")))))
                 (let ((answer (ask "cp2")))
                   (is (= 202 (first answer)) "the handover has started; it is not yet done")
                   (is (search "cp2" (second answer))))
                 (is (equal '("cp2") asked-of-leader))
                 (is (null asked-of-follower) "a follower has no leadership to hand over")
                 (let ((answer (ask "cp1")))
                   (is (= 200 (first answer)))
                   (is (search "already leads" (second answer))))
                 (let ((answer (ask "w")))
                   (is (= 409 (first answer)))
                   (is (search "is a witness; only a voter can lead" (second answer))))
                 (let ((answer (ask "cp3")))
                   (is (= 409 (first answer)))
                   (is (search "has not heard from" (second answer))))
                 (setf asked-of-leader nil)
                 (is (= 404 (first (ask "nobody"))))
                 (is (null asked-of-leader))
                 (is (= 403 (first (ask "cp3" "DELETE" "")))
                     "the right to move the leadership is not the right to remove a member"))
            (when follower (stop-server follower))
            (when leader (stop-server leader))))))))
