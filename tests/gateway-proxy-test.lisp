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


(defun gw-raw-request (port host path &key (method "GET") body)
  "Send one HTTP/1.1 request with an explicit Host header over a raw socket and
   return (values status-code headers-alist body-string). Connection: close
   frames the read."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
           (let ((stream (sb-bsd-sockets:socket-make-stream
                          socket :input t :output t :element-type 'character
                          :external-format :latin-1)))
             (format stream "~A ~A HTTP/1.1~C~CHost: ~A~C~CConnection: close~C~C"
                     method path #\Return #\Newline host #\Return #\Newline #\Return #\Newline)
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
