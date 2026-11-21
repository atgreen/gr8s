;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the in-agent Gateway L7 proxy end to end: a real HTTP request to a
;;;; Gateway listener is terminated, dispatched through the compiled router to a
;;;; backend, resolved to an address, and proxied to a live backend HTTP server;
;;;; unmatched hosts yield 404, unresolvable backends 503; and HTTPRoute filters
;;;; (request/response header modifier, URL rewrite, request redirect) are
;;;; applied to the exchange.

(in-package #:gr8s/tests)
(def-suite gateway-proxy :in gr8s)
(in-suite gateway-proxy)

(test gateway-certificate-index-reconciles-additions-removals-and-precedence
  (let* ((old (gr8s.controllers::make-gateway-certificate-index
               '(("a.test" :a) ("*.test" :wild) (nil :default))))
         (same (gr8s.controllers::gateway-update-certificate-index
                old '(("a.test" :a) ("*.test" :wild) (nil :default))))
         (changed (gr8s.controllers::gateway-update-certificate-index
                   old '(("b.test" :b) ("B.TEST" :loser) ("*.test" :wild) (nil :default))))
         (empty (gr8s.controllers::gateway-update-certificate-index changed nil)))
    (is (eq old same))
    (is (eq :a (gr8s.controllers::gateway-certificate-for-host old "a.test")))
    (is (eq :wild (gr8s.controllers::gateway-certificate-for-host changed "a.test")))
    (is (eq :b (gr8s.controllers::gateway-certificate-for-host changed "b.test")))
    (is (eq (gr8s.controllers::gateway-certificate-index-wildcard old)
            (gr8s.controllers::gateway-certificate-index-wildcard changed)))
    (is (null (gr8s.controllers::gateway-certificate-for-host empty "a.test")))
    (is (null (gr8s.controllers::gateway-certificate-for-host empty nil)))
    (is (fset:empty? (gr8s.controllers::gateway-certificate-index-exact empty)))
    (is (fset:empty? (gr8s.controllers::gateway-certificate-index-wildcard empty)))))

(test gateway-certificate-index-updates-preserve-the-published-snapshot
  (let* ((old (gr8s.controllers::make-gateway-certificate-index
               '(("a.test" :old-a) ("b.test" :b) ("*.wild.test" :old-wild) (nil :default))))
         (next (gr8s.controllers::gateway-replace-certificate-binding old "A.TEST" :new-a))
         (wild (gr8s.controllers::gateway-replace-certificate-binding next "*.wild.test" :new-wild))
         (default (gr8s.controllers::gateway-replace-certificate-binding wild nil :new-default)))
    (is (eq :old-a (gr8s.controllers::gateway-certificate-for-host old "a.test")))
    (is (eq :new-a (gr8s.controllers::gateway-certificate-for-host next "a.test")))
    (is (eq :b (gr8s.controllers::gateway-certificate-for-host next "b.test")))
    (is (eq :old-wild (gr8s.controllers::gateway-certificate-for-host next "one.wild.test")))
    (is (eq :new-wild (gr8s.controllers::gateway-certificate-for-host wild "one.wild.test")))
    (is (eq :default (gr8s.controllers::gateway-certificate-for-host wild nil)))
    (is (eq :new-default (gr8s.controllers::gateway-certificate-for-host default nil)))
    (is (eq (gr8s.controllers::gateway-certificate-index-wildcard old)
            (gr8s.controllers::gateway-certificate-index-wildcard next)))))

(test gateway-tls-provider-pins-listener-and-rejects-sibling-hosts
  (let* ((router-a (lambda (&rest args) (declare (ignore args)) :a))
         (router-b (lambda (&rest args) (declare (ignore args)) :b))
         (a (gr8s.controllers::make-gateway-tls-binding
             :certificate '(:cert-a) :key :key-a :router router-a))
         (b (gr8s.controllers::make-gateway-tls-binding
             :certificate '(:cert-b) :key :key-b :router router-b))
         (snapshot (gr8s.controllers::make-gateway-tls-snapshot
                    :index (gr8s.controllers::make-gateway-certificate-index
                            (list (list "*.a.test" a) (list "b.test" b)))
                    :bootstrap a))
         (acceptor (make-instance 'gr8s.controllers::gateway-tls-acceptor
                                 :tls-snapshot snapshot :router router-b)))
    (progv '(gr8s.controllers::*gateway-connection-tls-snapshot*
             gr8s.controllers::*gateway-connection-tls-binding*)
        (list snapshot nil)
      (is (equal '((:cert-a) :key-a)
                 (multiple-value-list
                  (gr8s.controllers::gateway-tls-certificate-provider "one.a.test" nil))))
      (is (eq router-a (gr8s.controllers::gateway-connection-router acceptor "two.a.test")))
      (is (null (gr8s.controllers::gateway-connection-router acceptor "b.test")))
      (is (null (gr8s.controllers::gateway-connection-router acceptor "unknown.test")))
      (signals pure-tls:tls-error
        (gr8s.controllers::gateway-tls-certificate-provider "unknown.test" nil))
      (signals pure-tls:tls-error
        (gr8s.controllers::gateway-tls-certificate-provider nil nil)))))

(test gateway-certificate-index-selects-the-most-specific-listener
  (let ((index (gr8s.controllers::make-gateway-certificate-index
                '(("*.example.test" :broad)
                  ("*.apps.example.test" :narrow)
                  ("api.apps.example.test" :exact)
                  ("api.apps.example.test" :loser)))))
    (is (eq :exact (gr8s.controllers::gateway-certificate-for-host index "API.apps.example.test")))
    (is (eq :narrow (gr8s.controllers::gateway-certificate-for-host index "web.apps.example.test")))
    (is (eq :broad (gr8s.controllers::gateway-certificate-for-host index "apps.example.test")))
    (is (eq :broad (gr8s.controllers::gateway-certificate-for-host index "a.b.example.test")))
    (is (null (gr8s.controllers::gateway-certificate-for-host index "example.test")))
    (is (null (gr8s.controllers::gateway-certificate-for-host index "badexample.test")))
    (is (null (gr8s.controllers::gateway-certificate-for-host index "unrelated.test")))
    (is (null (gr8s.controllers::gateway-certificate-for-host index nil)))))

(test gateway-certificate-index-allows-only-an-explicit-default
  (let ((index (gr8s.controllers::make-gateway-certificate-index
                '((nil :default) ("example.test" :exact)))))
    (is (eq :default (gr8s.controllers::gateway-certificate-for-host index nil)))
    (is (eq :default (gr8s.controllers::gateway-certificate-for-host index "other.test")))
    (is (eq :exact (gr8s.controllers::gateway-certificate-for-host index "example.test")))))

(test gateway-tls-snapshot-enforces-sni-on-real-connections
  (let* ((root (asdf:system-relative-pathname "gr8s" "tests/fixtures/gateway-tls/"))
         (certificate (pure-tls:load-certificate-chain (merge-pathnames "server.crt" root)))
         (key (pure-tls:load-private-key (merge-pathnames "server.key" root)))
         (router (lambda (&rest args)
                   (declare (ignore args))
                   (gr8s.controllers::make-gw-dispatch
                    :backend (gr8s.controllers::make-gw-backend :name "missing" :port 80))))
         (a (gr8s.controllers::make-gateway-tls-binding :certificate certificate :key key :router router))
         (b (gr8s.controllers::make-gateway-tls-binding :certificate certificate :key key :router router))
         (snapshot (gr8s.controllers::make-gateway-tls-snapshot
                    :bootstrap a :index (gr8s.controllers::make-gateway-certificate-index
                                         (list (list "a.test" a) (list "b.test" b)))))
         (gateway (gr8s.controllers::start-gateway-listener
                   :port 0 :router router :resolver (constantly nil) :tls (list :snapshot snapshot)))
         (port (hunchentoot:acceptor-port gateway)))
    (unwind-protect
         (flet ((request (sni host)
                  (multiple-value-bind (output error-output exit)
                      (uiop:run-program
                       (list "curl" "--silent" "--show-error" "--insecure" "--noproxy" "*"
                             "--max-time" "5" "--output" "/dev/null" "--write-out" "%{http_code}"
                             "--resolve" (format nil "~A:~D:127.0.0.1" sni port)
                             "--header" (format nil "Host: ~A" host)
                             (format nil "https://~A:~D/" sni port))
                       :output :string :error-output :string :ignore-error-status t)
                    (declare (ignore error-output))
                    (values output exit))))
           ;; An admitted TLS connection reaches routing, which reports the missing backend.
           (is (equal "503" (request "a.test" "a.test")))
           (is (equal "503" (request "b.test" "b.test")))
           (is (equal "404" (request "a.test" "b.test")))
           (is (not (zerop (nth-value 1 (request "unknown.test" "a.test")))))
           ;; curl omits SNI for an IP literal; the bootstrap certificate must not escape.
           (is (not (zerop (nth-value 1 (request "127.0.0.1" "a.test")))))
           (setf (gr8s.controllers::gateway-acceptor-tls-snapshot gateway)
                 (gr8s.controllers::make-gateway-tls-snapshot
                  :bootstrap b :index (gr8s.controllers::make-gateway-certificate-index
                                       (list (list "b.test" b)))))
           (is (not (zerop (nth-value 1 (request "a.test" "a.test")))))
           (is (equal "503" (request "b.test" "b.test"))))
      (gr8s.controllers::stop-gateway-listener gateway))))

(test gateway-backend-resolver-maps-the-route-port-to-a-service-port
  (with-temporary-store (store directory)
    (values directory)
    (gr8s.resources::create-core-resource
     store "services"
     (gr8s.resources::core-object
      "metadata" (gr8s.resources::core-object "name" "web")
      "spec" (gr8s.resources::core-object
              "clusterIP" "10.96.0.40"
              "ports" (vector (gr8s.resources::core-object "name" "http" "port" 80
                                                  "targetPort" 8080))))
     "default")
    (gr8s.resources::create-core-resource
     store "endpointslices"
     (gr8s.resources::core-object
      "metadata" (gr8s.resources::core-object
                  "name" "web-a"
                  "labels" (gr8s.resources::core-object "kubernetes.io/service-name" "web"))
      "addressType" "IPv4"
      "ports" (vector (gr8s.resources::core-object "name" "http" "port" 8080 "protocol" "TCP"))
      "endpoints" (vector (gr8s.resources::core-object
                           "addresses" (vector "10.80.0.8")
                           "conditions" (gr8s.resources::core-object "ready" t))))
     "default")
    (multiple-value-bind (address port)
        (funcall (gr8s.controllers::make-service-backend-resolver store)
                 (gr8s.controllers::make-gw-backend :name "web" :namespace "default" :port 80))
      (is (equal "10.80.0.8" address))
      (is (= 8080 port)))
    (multiple-value-bind (address port)
        (funcall (gr8s.controllers::make-service-backend-resolver store)
                 (gr8s.controllers::make-gw-backend :name "web" :namespace "default" :port "http"))
      (is (equal "10.80.0.8" address))
      (is (= 8080 port)))))

;;; A minimal backend "Service" HTTP server that records the exchange.
(defvar *gw-backend-last* nil "(method path headers-alist body-string) of the last backend request.")

(defclass gw-echo-acceptor (hunchentoot:acceptor) ())

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor gw-echo-acceptor) request)
  (let ((body (hunchentoot:raw-post-data :force-binary t)))
    (setf *gw-backend-last*
          (list (hunchentoot:request-method request)
                (hunchentoot:script-name request)
                (mapcar (lambda (h) (cons (string-downcase (string (car h))) (cdr h)))
                        (hunchentoot:headers-in* request))
                (and body (babel:octets-to-string body :encoding :utf-8))))
    (setf (hunchentoot:content-type*) "text/plain; charset=utf-8"
          (hunchentoot:header-out :x-backend) "origin")
    "backend-ok"))


(defun gw-raw-request (port host path &key (method "GET") body extra-headers)
  "Send one HTTP/1.1 request with an explicit Host header over a raw socket and
   return (values status-code headers-alist body-string). EXTRA-HEADERS is an alist
   of (name . value) sent verbatim. Connection: close frames the read."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
           (let ((stream (sb-bsd-sockets:socket-make-stream
                          socket :input t :output t :element-type 'character
                          :external-format :latin-1)))
             (format stream "~A ~A HTTP/1.1~C~CHost: ~A~C~CConnection: close~C~C"
                     method path #\Return #\Newline host #\Return #\Newline #\Return #\Newline)
             (loop for (name . value) in extra-headers
                   do (format stream "~A: ~A~C~C" name value #\Return #\Newline))
             (when body
               (format stream "Content-Length: ~D~C~CContent-Type: text/plain~C~C"
                       (length body) #\Return #\Newline #\Return #\Newline))
             (format stream "~C~C" #\Return #\Newline)
             (when body (write-string body stream))
             (finish-output stream)
             (let ((raw (with-output-to-string (out)
                          (loop for c = (read-char stream nil nil) while c do (write-char c out)))))
               (let* ((crlf (format nil "~C~C" #\Return #\Newline))
                      (sep (search (concatenate 'string crlf crlf) raw))
                      (head (subseq raw 0 sep))
                      (payload (and sep (subseq raw (+ sep 4))))
                      (lines (loop with start = 0
                                   for pos = (search crlf head :start2 start)
                                   collect (subseq head start (or pos (length head)))
                                   while pos do (setf start (+ pos 2))))
                      (status-line (first lines))
                      (code (parse-integer status-line :start (1+ (position #\Space status-line))
                                                        :junk-allowed t))
                      (headers (loop for line in (rest lines)
                                     for colon = (position #\: line)
                                     when colon
                                       collect (cons (string-downcase (string-trim " " (subseq line 0 colon)))
                                                     (string-trim " " (subseq line (1+ colon)))))))
                 (values code headers payload)))))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun gw-header (headers name) (cdr (assoc name headers :test #'string-equal)))

(defun gw-request-header-seen (name)
  (cdr (assoc name (third *gw-backend-last*) :test #'string-equal)))

(test gateway-proxy-routes-dispatches-and-proxies
  (let* ((backend (hunchentoot:start (make-instance 'gw-echo-acceptor
                                                    :address "127.0.0.1" :port 0)))
         (backend-port (hunchentoot:acceptor-port backend))
         (routes (list
                  (gr8s.controllers::make-gw-route
                   :namespace "default" :hostnames '("app.example.com")
                   :rules (list (gr8s.controllers::make-gw-rule
                                 :matches (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                 :backends (list (gr8s.controllers::make-gw-backend :name "echo" :port backend-port)))))
                  (gr8s.controllers::make-gw-route
                   :namespace "default" :hostnames '("fail.example.com")
                   :rules (list (gr8s.controllers::make-gw-rule
                                 :matches (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                 :backends (list (gr8s.controllers::make-gw-backend :name "missing" :port 1)))))))
         (router (gr8s.controllers::build-gateway-router routes))
         (resolver (lambda (backend)
                     (when (equal (gr8s.controllers::gw-backend-name backend) "echo")
                       (values "127.0.0.1" backend-port))))
         (gateway (gr8s.controllers::start-gateway-listener :port 0
                                                :router router :resolver resolver :name "test"))
         (listener-port (hunchentoot:acceptor-port gateway)))
    (unwind-protect
         (progn
           (setf *gw-backend-last* nil)
           (multiple-value-bind (code headers body)
               (gw-raw-request listener-port "app.example.com" "/cart" :method "POST" :body "hello")
             (is (= 200 code))
             (is (equal "backend-ok" body))
             (is (equal "origin" (gw-header headers "x-backend")))
             (is (equal :post (first *gw-backend-last*)))
             (is (equal "/cart" (second *gw-backend-last*)))
             (is (equal "hello" (fourth *gw-backend-last*))))
           (setf *gw-backend-last* nil)
           (is (= 404 (gw-raw-request listener-port "nope.org" "/x")))
           (is (null *gw-backend-last*))
           (is (= 503 (gw-raw-request listener-port "fail.example.com" "/y"))))
      (gr8s.controllers::stop-gateway-listener gateway)
      (hunchentoot:stop backend))))

(test gateway-forwards-the-client-authorization-to-the-backend
  ;; podster-8lq: the Gateway is a pass-through proxy, so the end user's
  ;; Authorization must reach the backend app (e.g. an S3 server validating a
  ;; SigV4 signature). The pod proxy strips it (the apiserver credential); the
  ;; Gateway must not.
  (let* ((backend (hunchentoot:start (make-instance 'gw-echo-acceptor
                                                    :address "127.0.0.1" :port 0)))
         (backend-port (hunchentoot:acceptor-port backend))
         (routes (list (gr8s.controllers::make-gw-route
                        :namespace "default" :hostnames '("app.example.com")
                        :rules (list (gr8s.controllers::make-gw-rule
                                      :matches (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                      :backends (list (gr8s.controllers::make-gw-backend :name "echo" :port backend-port)))))))
         (router (gr8s.controllers::build-gateway-router routes))
         (resolver (lambda (b) (when (equal (gr8s.controllers::gw-backend-name b) "echo")
                                 (values "127.0.0.1" backend-port))))
         (gateway (gr8s.controllers::start-gateway-listener :port 0
                                                :router router :resolver resolver :name "test"))
         (listener-port (hunchentoot:acceptor-port gateway)))
    (unwind-protect
         (progn
           (setf *gw-backend-last* nil)
           (let ((auth "AWS4-HMAC-SHA256 Credential=key/20260101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef"))
             (is (= 200 (gw-raw-request listener-port "app.example.com" "/"
                                        :extra-headers (list (cons "Authorization" auth)))))
             (is (equal auth (gw-request-header-seen "authorization")))))
      (gr8s.controllers::stop-gateway-listener gateway)
      (hunchentoot:stop backend))))

(test gateway-rate-limiter-admits-then-throttles
  ;; Unit-level token bucket: capacity = rps, starts full; rapid calls drain it.
  (let ((gr8s.controllers::*gateway-rate-buckets* (make-hash-table :test 'equal)))
    (is (gr8s.controllers::gateway-rate-allow-p "ns/r" 1))        ; first token
    (is (not (gr8s.controllers::gateway-rate-allow-p "ns/r" 1)))  ; drained, throttled
    ;; A different route has its own bucket.
    (is (gr8s.controllers::gateway-rate-allow-p "ns/other" 1))))

(test gateway-proxy-rate-limits-and-counts-metrics
  (let* ((backend (hunchentoot:start (make-instance 'gw-echo-acceptor
                                                    :address "127.0.0.1" :port 0)))
         (backend-port (hunchentoot:acceptor-port backend))
         (routes (list (gr8s.controllers::make-gw-route
                        :namespace "default" :name "rl" :rate-limit 1 :hostnames '("rl.test")
                        :rules (list (gr8s.controllers::make-gw-rule
                                      :matches (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                      :backends (list (gr8s.controllers::make-gw-backend :name "echo" :port backend-port)))))))
         (router (gr8s.controllers::build-gateway-router routes))
         (resolver (lambda (b) (declare (ignore b)) (values "127.0.0.1" backend-port)))
         (gateway (gr8s.controllers::start-gateway-listener :port 0
                                                :router router :resolver resolver :name "rl-gw"))
         (listener-port (hunchentoot:acceptor-port gateway)))
    ;; The acceptor handles requests on its own thread, so dynamic rebinding would
    ;; not reach it; clear the process-global tables instead.
    (clrhash gr8s.controllers::*gateway-rate-buckets*)
    (clrhash gr8s.controllers::*gateway-request-counts*)
    (unwind-protect
         (progn
           ;; First request passes to the backend; the immediate second is throttled.
           (is (= 200 (gw-raw-request listener-port "rl.test" "/a")))
           (is (= 429 (gw-raw-request listener-port "rl.test" "/a")))
           ;; Metrics recorded both outcomes for this route.
           (let ((text (gr8s.controllers::gateway-metrics-text)))
             (is (search "gr8s_gateway_requests_total" text))
             (is (search "route=\"default/rl\"" text))
             (is (search "code=\"200\"" text))
             (is (search "code=\"429\"" text))))
      (gr8s.controllers::stop-gateway-listener gateway)
      (hunchentoot:stop backend))))

(test gateway-proxy-applies-http-filters
  (let* ((backend (hunchentoot:start (make-instance 'gw-echo-acceptor
                                                    :address "127.0.0.1" :port 0)))
         (backend-port (hunchentoot:acceptor-port backend))
         (echo (gr8s.controllers::make-gw-backend :name "echo" :port backend-port))
         (routes (list
                  ;; Header modifiers: set a request header the backend should see,
                  ;; and a response header the client should see.
                  (gr8s.controllers::make-gw-route
                   :namespace "default" :hostnames '("hdr.test")
                   :rules (list (gr8s.controllers::make-gw-rule
                                 :matches (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                 :filters (list (gr8s.controllers::make-gw-filter
                                                 :type :request-headers
                                                 :data (list :set '(("x-test" . "injected")) :add nil :remove nil))
                                                (gr8s.controllers::make-gw-filter
                                                 :type :response-headers
                                                 :data (list :set '(("x-resp" . "added")) :add nil :remove nil)))
                                 :backends (list echo))))
                  ;; URL rewrite: ReplacePrefixMatch /api -> /.
                  (gr8s.controllers::make-gw-route
                   :namespace "default" :hostnames '("rw.test")
                   :rules (list (gr8s.controllers::make-gw-rule
                                 :matches (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/api"))
                                 :filters (list (gr8s.controllers::make-gw-filter
                                                 :type :rewrite
                                                 :data (list :hostname nil :path (list :type :prefix :value "/"))))
                                 :backends (list echo))))
                  ;; Request redirect: short-circuit to https, 301, no backend.
                  (gr8s.controllers::make-gw-route
                   :namespace "default" :hostnames '("redir.test")
                   :rules (list (gr8s.controllers::make-gw-rule
                                 :matches (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                 :filters (list (gr8s.controllers::make-gw-filter
                                                 :type :redirect
                                                 :data (list :scheme "https" :status-code 301
                                                             :hostname nil :port nil :path nil))))))))
         (router (gr8s.controllers::build-gateway-router routes))
         (resolver (lambda (b) (declare (ignore b)) (values "127.0.0.1" backend-port)))
         (gateway (gr8s.controllers::start-gateway-listener :port 0
                                                :router router :resolver resolver :name "filters"))
         (listener-port (hunchentoot:acceptor-port gateway)))
    (unwind-protect
         (progn
           ;; Header modifiers.
           (setf *gw-backend-last* nil)
           (multiple-value-bind (code headers body)
               (gw-raw-request listener-port "hdr.test" "/go")
             (is (= 200 code))
             (is (equal "backend-ok" body))
             (is (equal "injected" (gw-request-header-seen "x-test")))  ; backend saw the set header
             (is (equal "added" (gw-header headers "x-resp"))))         ; client saw the response header
           ;; URL rewrite: /api/users -> backend sees /users.
           (setf *gw-backend-last* nil)
           (is (= 200 (gw-raw-request listener-port "rw.test" "/api/users")))
           (is (equal "/users" (second *gw-backend-last*)))
           ;; Request redirect: 301 with https Location, backend untouched.
           (setf *gw-backend-last* nil)
           (multiple-value-bind (code headers body)
               (gw-raw-request listener-port "redir.test" "/page")
             (declare (ignore body))
             (is (= 301 code))
             (is (equal "https://redir.test/page" (gw-header headers "location")))
             (is (null *gw-backend-last*))))
      (gr8s.controllers::stop-gateway-listener gateway)
      (hunchentoot:stop backend))))

(test gateway-proxy-invalid-backend-kind-does-not-resolve-a-service
  (let ((calls 0))
    (dolist (reference '("{\"name\":\"echo\",\"port\":80,\"kind\":\"UnknownKind\"}"
                         "{\"name\":\"echo\",\"port\":80,\"kind\":\"Service\",\"group\":\"example.com\"}"))
      (let* ((backend (gr8s.controllers::gw-parse-backend (com.inuoe.jzon:parse reference) "infra"))
             (route (gr8s.controllers::make-gw-route
                     :namespace "infra" :name "invalid"
                     :rules (list (gr8s.controllers::make-gw-rule
                                   :matches (list (gr8s.controllers::make-gw-match))
                                   :backends (list backend)))))
             (gateway (gr8s.controllers::start-gateway-listener
                       :port 0 :router (gr8s.controllers::build-gateway-router (list route))
                       :resolver (lambda (candidate) (declare (ignore candidate)) (incf calls) nil))))
        (unwind-protect
             (is (= 500 (gw-raw-request (hunchentoot:acceptor-port gateway) "any" "/")))
          (gr8s.controllers::stop-gateway-listener gateway))))
    (is (= 0 calls))))

(test gateway-proxy-missing-service-or-port-is-an-invalid-reference
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gr8s.resources::create-core-resource
     store "services" (com.inuoe.jzon:parse
                       "{\"metadata\":{\"name\":\"web\",\"namespace\":\"default\"},\"spec\":{\"ports\":[{\"port\":80}]}}") "default")
    (dolist (reference '("{\"name\":\"missing\",\"port\":80}" "{\"name\":\"web\",\"port\":81}"))
      (let* ((backend (gr8s.controllers::gw-parse-backend (com.inuoe.jzon:parse reference) "default"))
             (route (gr8s.controllers::make-gw-route
                     :namespace "default" :name "invalid"
                     :rules (list (gr8s.controllers::make-gw-rule
                                   :matches (list (gr8s.controllers::make-gw-match))
                                   :backends (list backend)))))
             (gateway (gr8s.controllers::start-gateway-listener
                       :port 0 :router (gr8s.controllers::build-gateway-router (list route))
                       :resolver (gr8s.controllers::make-service-backend-resolver store))))
        (unwind-protect
             (is (= 500 (gw-raw-request (hunchentoot:acceptor-port gateway) "any" "/")))
          (gr8s.controllers::stop-gateway-listener gateway))))))

(test gateway-cross-namespace-backend-requires-a-matching-reference-grant
  (let* ((objects (make-hash-table :test #'equal))
         (backend (gr8s.controllers::gw-parse-backend
                   (com.inuoe.jzon:parse "{\"name\":\"web\",\"namespace\":\"target\",\"port\":80}") "source"))
         (grant (com.inuoe.jzon:parse
                 "{\"apiVersion\":\"gateway.networking.k8s.io/v1\",\"kind\":\"ReferenceGrant\",\"metadata\":{\"name\":\"allow\",\"namespace\":\"target\"},\"spec\":{\"from\":[{\"group\":\"gateway.networking.k8s.io\",\"kind\":\"HTTPRoute\",\"namespace\":\"source\"}],\"to\":[{\"group\":\"\",\"kind\":\"Service\",\"name\":\"web\"}]}}")))
    (setf (gethash '("services" "target" "web") objects)
          (com.inuoe.jzon:parse
           "{\"metadata\":{\"name\":\"web\",\"namespace\":\"target\"},\"spec\":{\"clusterIP\":\"10.96.0.40\",\"ports\":[{\"port\":80}]}}"))
    (flet ((check (allowed)
             (let ((view (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index objects))))
               (multiple-value-bind (host port reason)
                   (gr8s.controllers::resolve-gateway-backend backend (gr8s.controllers::make-service-backend-resolver view))
                 (declare (ignore port))
                 (is (eq allowed (not (null host))))
                 (is (equal (unless allowed "RefNotPermitted") reason))))))
      (check nil)
      (setf (gethash '("referencegrants" "target" "allow") objects) grant)
      (check t)
      (dolist (case '(("from" "namespace" "other") ("from" "kind" "Gateway")
                      ("from" "group" "example.com") ("to" "kind" "Secret")
                      ("to" "group" "example.com") ("to" "name" "different")))
        (destructuring-bind (side key value) case
          (let* ((copy (gr8s.resources::copy-core-object grant))
                 (entry (aref (gethash side (gethash "spec" copy)) 0)))
            (setf (gethash key entry) value
                  (gethash '("referencegrants" "target" "allow") objects) copy)
            (check nil))))
      (let ((copy (gr8s.resources::copy-core-object grant)))
        (remhash "name" (aref (gethash "to" (gethash "spec" copy)) 0))
        (setf (gethash '("referencegrants" "target" "allow") objects) copy)
        (check t))
      (remhash '("referencegrants" "target" "allow") objects)
      (check nil))))

(test gateway-reference-grant-does-not-confuse-http-and-tcp-routes
  (let* ((objects (make-hash-table :test #'equal))
         (route (com.inuoe.jzon:parse
                 "{\"kind\":\"TCPRoute\",\"metadata\":{\"namespace\":\"source\"},\"spec\":{\"rules\":[{\"backendRefs\":[{\"name\":\"web\",\"namespace\":\"target\",\"port\":80}]}]}}"))
         (backend (first (gr8s.controllers::l4-tcp-route-backends (gr8s.controllers::parse-tcproute route)))))
    (setf (gethash '("services" "target" "web") objects)
          (com.inuoe.jzon:parse "{\"spec\":{\"clusterIP\":\"10.96.0.40\",\"ports\":[{\"port\":80}]}}")
          (gethash '("referencegrants" "target" "allow") objects)
          (com.inuoe.jzon:parse "{\"spec\":{\"from\":[{\"group\":\"gateway.networking.k8s.io\",\"kind\":\"HTTPRoute\",\"namespace\":\"source\"}],\"to\":[{\"group\":\"\",\"kind\":\"Service\"}]}}"))
    (let ((view (gr8s.agent::make-gateway-projection-store (gr8s.agent::gateway-resource-index objects))))
      (is (equal "RefNotPermitted" (gr8s.controllers::gateway-backend-reference-error view backend))))))

;;; WebSocket upgrades (podster-1fk): the handshake reaches the backend with its
;;; Upgrade intact, the 101 comes back, and the spliced connection carries bytes
;;; both ways -- past the listener's ordinary read timeout.

(defvar *gw-ws-backend-request* nil "The request head the WebSocket backend last received.")

(defun gw-read-head (stream)
  "Read octets from STREAM through the blank line ending an HTTP head; return it as a string."
  (let ((head (make-array 0 :element-type 'character :adjustable t :fill-pointer 0)))
    (loop for octet = (read-byte stream nil nil)
          while octet
          do (vector-push-extend (code-char octet) head)
          until (and (>= (length head) 4) (string= (subseq head (- (length head) 4))
                                                   (format nil "~C~C~C~C" #\Return #\Linefeed #\Return #\Linefeed))))
    (coerce head 'simple-string)))

(defun gw-head-header (head name)
  (loop for line in (rest (uiop:split-string (string-right-trim '(#\Return #\Linefeed) head) :separator '(#\Linefeed)))
        for colon = (position #\: line)
        when (and colon (string-equal name (string-trim " " (subseq line 0 colon))))
          return (string-trim '(#\Space #\Return) (subseq line (1+ colon)))))

(defun gw-websocket-backend ()
  "A backend that accepts a WebSocket handshake on /ws (then echoes raw bytes) and
   refuses one anywhere else with 400. Returns (values port stop-fn)."
  (let ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
        (stopping nil))
    (flet ((serve (raw)
             (let ((stream (usocket:socket-stream raw)))
               (ignore-errors
                (let* ((head (gw-read-head stream))
                       (path (second (uiop:split-string head :separator " ")))
                       (key (gw-head-header head "Sec-WebSocket-Key")))
                  (setf *gw-ws-backend-request* head)
                  (if (and (string= (subseq path 0 (position #\? path)) "/ws") key
                           (string-equal "websocket" (gw-head-header head "Upgrade")))
                      (progn
                        (write-sequence (trivial-utf-8:string-to-utf-8-bytes
                                         (format nil "HTTP/1.1 101 Switching Protocols~C~CUpgrade: websocket~C~CConnection: Upgrade~C~CSec-WebSocket-Accept: ~A~C~C~C~C"
                                                 #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed
                                                 (gr8s.apiserver::websocket-accept-value key)
                                                 #\Return #\Linefeed #\Return #\Linefeed))
                                        stream)
                        (finish-output stream)
                        (loop for octet = (read-byte stream nil nil)
                              while octet
                              do (write-byte octet stream) (finish-output stream)))
                      (progn
                        (write-sequence (trivial-utf-8:string-to-utf-8-bytes
                                         (format nil "HTTP/1.1 400 Bad Request~C~CContent-Length: 6~C~CConnection: close~C~C~C~Cno-ws!"
                                                 #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))
                                        stream)
                        (finish-output stream)))))
               (ignore-errors (usocket:socket-close raw)))))
      (let ((thread (bt:make-thread
                     (lambda ()
                       (loop until stopping
                             do (when (usocket:wait-for-input listener :timeout 0.2 :ready-only t)
                                  (handler-case
                                      (let ((raw (usocket:socket-accept listener)))
                                        (bt:make-thread (lambda () (serve raw)) :name "gw ws backend conn"))
                                    (error () nil)))))
                     :name "gw ws backend accept")))
        (values (usocket:get-local-port listener)
                (lambda ()
                  (setf stopping t)
                  (ignore-errors (bt:join-thread thread))
                  (ignore-errors (usocket:socket-close listener))))))))

(defun gw-websocket-handshake (port path)
  "Open a connection to the Gateway on PORT and send a WebSocket handshake for
   PATH on ws.example.com. Returns (values socket stream response-head)."
  (let* ((socket (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)))
         (stream (usocket:socket-stream socket)))
    (write-sequence (trivial-utf-8:string-to-utf-8-bytes
                     (format nil "GET ~A HTTP/1.1~C~CHost: ws.example.com~C~CConnection: Upgrade~C~CUpgrade: websocket~C~CSec-WebSocket-Version: 13~C~CSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==~C~C~C~C"
                             path #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed
                             #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))
                    stream)
    (finish-output stream)
    (values socket stream (gw-read-head stream))))

(test gateway-proxies-websocket-upgrades
  (multiple-value-bind (backend-port stop-backend) (gw-websocket-backend)
    (let* ((routes (list (gr8s.controllers::make-gw-route
                          :namespace "default" :hostnames '("ws.example.com")
                          :rules (list (gr8s.controllers::make-gw-rule
                                        :matches (list (gr8s.controllers::make-gw-match :path-type :prefix :path "/"))
                                        :backends (list (gr8s.controllers::make-gw-backend :name "ws" :port backend-port)))))))
           (router (gr8s.controllers::build-gateway-router routes))
           (resolver (lambda (b) (declare (ignore b)) (values "127.0.0.1" backend-port)))
           ;; A one-second ordinary read timeout, so the idle check below is quick.
           (gateway (let ((hunchentoot:*default-connection-timeout* 1))
                      (gr8s.controllers::start-gateway-listener :port 0 :router router
                                                                :resolver resolver :name "test")))
           (listener-port (hunchentoot:acceptor-port gateway)))
      (unwind-protect
           (progn
             (multiple-value-bind (socket stream head) (gw-websocket-handshake listener-port "/ws?src=cam")
               (unwind-protect
                    (progn
                      (is (search "101" (subseq head 0 (position #\Return head))) "handshake answered ~S" head)
                      (is (equal "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" (gw-head-header head "Sec-WebSocket-Accept")))
                      (is (string-equal "websocket" (gw-head-header head "Upgrade")))
                      ;; The backend saw the upgrade, the query, and the forwarded host.
                      (is (search "GET /ws?src=cam HTTP/1.1" *gw-ws-backend-request*))
                      (is (string-equal "Upgrade" (gw-head-header *gw-ws-backend-request* "Connection")))
                      (is (equal "ws.example.com" (gw-head-header *gw-ws-backend-request* "X-Forwarded-Host")))
                      ;; Quiet past the listener's read timeout, then bytes still flow both ways.
                      (sleep 2.5)
                      (let ((payload (trivial-utf-8:string-to-utf-8-bytes "frame-bytes")))
                        (write-sequence payload stream)
                        (finish-output stream)
                        (let ((echo (make-array (length payload) :element-type '(unsigned-byte 8))))
                          (is (= (length payload) (read-sequence echo stream)))
                          (is (equalp payload echo)))))
                 (ignore-errors (usocket:socket-close socket))))
             ;; A backend that refuses the upgrade answers as an ordinary response.
             (multiple-value-bind (socket stream head) (gw-websocket-handshake listener-port "/elsewhere")
               (unwind-protect
                    (progn
                      (is (search "400" (subseq head 0 (position #\Return head))) "refusal answered ~S" head)
                      (let ((body (make-array 6 :element-type '(unsigned-byte 8))))
                        (read-sequence body stream)
                        (is (equal "no-ws!" (trivial-utf-8:utf-8-bytes-to-string body)))))
                 (ignore-errors (usocket:socket-close socket)))))
        (gr8s.controllers::stop-gateway-listener gateway)
        (funcall stop-backend)))))
