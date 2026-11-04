;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
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

(defconstant +gw-backend-port+ 18090)
(defconstant +gw-listener-port+ 18091)

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
                                                    :address "127.0.0.1" :port +gw-backend-port+)))
         (routes (list
                  (gr8s::make-gw-route
                   :namespace "default" :hostnames '("app.example.com")
                   :rules (list (gr8s::make-gw-rule
                                 :matches (list (gr8s::make-gw-match :path-type :prefix :path "/"))
                                 :backends (list (gr8s::make-gw-backend :name "echo" :port +gw-backend-port+)))))
                  (gr8s::make-gw-route
                   :namespace "default" :hostnames '("fail.example.com")
                   :rules (list (gr8s::make-gw-rule
                                 :matches (list (gr8s::make-gw-match :path-type :prefix :path "/"))
                                 :backends (list (gr8s::make-gw-backend :name "missing" :port 1)))))))
         (router (gr8s::compile-gateway-router routes))
         (resolver (lambda (backend)
                     (when (equal (gr8s::gw-backend-name backend) "echo")
                       (values "127.0.0.1" +gw-backend-port+))))
         (gateway (gr8s::start-gateway-listener :port +gw-listener-port+
                                                :router router :resolver resolver :name "test")))
    (unwind-protect
         (progn
           (setf *gw-backend-last* nil)
           (multiple-value-bind (code headers body)
               (gw-raw-request +gw-listener-port+ "app.example.com" "/cart" :method "POST" :body "hello")
             (is (= 200 code))
             (is (equal "backend-ok" body))
             (is (equal "origin" (gw-header headers "x-backend")))
             (is (equal :post (first *gw-backend-last*)))
             (is (equal "/cart" (second *gw-backend-last*)))
             (is (equal "hello" (fourth *gw-backend-last*))))
           (setf *gw-backend-last* nil)
           (is (= 404 (gw-raw-request +gw-listener-port+ "nope.org" "/x")))
           (is (null *gw-backend-last*))
           (is (= 503 (gw-raw-request +gw-listener-port+ "fail.example.com" "/y"))))
      (gr8s::stop-gateway-listener gateway)
      (hunchentoot:stop backend))))

(test gateway-proxy-applies-http-filters
  (let* ((backend (hunchentoot:start (make-instance 'gw-echo-acceptor
                                                    :address "127.0.0.1" :port +gw-backend-port+)))
         (echo (gr8s::make-gw-backend :name "echo" :port +gw-backend-port+))
         (routes (list
                  ;; Header modifiers: set a request header the backend should see,
                  ;; and a response header the client should see.
                  (gr8s::make-gw-route
                   :namespace "default" :hostnames '("hdr.test")
                   :rules (list (gr8s::make-gw-rule
                                 :matches (list (gr8s::make-gw-match :path-type :prefix :path "/"))
                                 :filters (list (gr8s::make-gw-filter
                                                 :type :request-headers
                                                 :data (list :set '(("x-test" . "injected")) :add nil :remove nil))
                                                (gr8s::make-gw-filter
                                                 :type :response-headers
                                                 :data (list :set '(("x-resp" . "added")) :add nil :remove nil)))
                                 :backends (list echo))))
                  ;; URL rewrite: ReplacePrefixMatch /api -> /.
                  (gr8s::make-gw-route
                   :namespace "default" :hostnames '("rw.test")
                   :rules (list (gr8s::make-gw-rule
                                 :matches (list (gr8s::make-gw-match :path-type :prefix :path "/api"))
                                 :filters (list (gr8s::make-gw-filter
                                                 :type :rewrite
                                                 :data (list :hostname nil :path (list :type :prefix :value "/"))))
                                 :backends (list echo))))
                  ;; Request redirect: short-circuit to https, 301, no backend.
                  (gr8s::make-gw-route
                   :namespace "default" :hostnames '("redir.test")
                   :rules (list (gr8s::make-gw-rule
                                 :matches (list (gr8s::make-gw-match :path-type :prefix :path "/"))
                                 :filters (list (gr8s::make-gw-filter
                                                 :type :redirect
                                                 :data (list :scheme "https" :status-code 301
                                                             :hostname nil :port nil :path nil))))))))
         (router (gr8s::compile-gateway-router routes))
         (resolver (lambda (b) (declare (ignore b)) (values "127.0.0.1" +gw-backend-port+)))
         (gateway (gr8s::start-gateway-listener :port +gw-listener-port+
                                                :router router :resolver resolver :name "filters")))
    (unwind-protect
         (progn
           ;; Header modifiers.
           (setf *gw-backend-last* nil)
           (multiple-value-bind (code headers body)
               (gw-raw-request +gw-listener-port+ "hdr.test" "/go")
             (is (= 200 code))
             (is (equal "backend-ok" body))
             (is (equal "injected" (gw-request-header-seen "x-test")))  ; backend saw the set header
             (is (equal "added" (gw-header headers "x-resp"))))         ; client saw the response header
           ;; URL rewrite: /api/users -> backend sees /users.
           (setf *gw-backend-last* nil)
           (is (= 200 (gw-raw-request +gw-listener-port+ "rw.test" "/api/users")))
           (is (equal "/users" (second *gw-backend-last*)))
           ;; Request redirect: 301 with https Location, backend untouched.
           (setf *gw-backend-last* nil)
           (multiple-value-bind (code headers body)
               (gw-raw-request +gw-listener-port+ "redir.test" "/page")
             (declare (ignore body))
             (is (= 301 code))
             (is (equal "https://redir.test/page" (gw-header headers "location")))
             (is (null *gw-backend-last*))))
      (gr8s::stop-gateway-listener gateway)
      (hunchentoot:stop backend))))
