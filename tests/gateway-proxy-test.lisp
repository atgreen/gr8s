;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise the in-agent Gateway L7 proxy end to end: a real HTTP request to a
;;;; Gateway listener is terminated, dispatched through the compiled router to a
;;;; backend, resolved to an address, and proxied to a live backend HTTP server;
;;;; unmatched hosts yield 404 and unresolvable backends 503.

(in-package #:gr8s/tests)
(def-suite gateway-proxy :in gr8s)
(in-suite gateway-proxy)

;;; A minimal backend "Service" HTTP server that records the exchange.
(defvar *gw-backend-last* nil "(method path body-string) of the last backend request.")

(defclass gw-echo-acceptor (hunchentoot:acceptor) ())

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor gw-echo-acceptor) request)
  (let ((body (hunchentoot:raw-post-data :force-binary t)))
    (setf *gw-backend-last*
          (list (hunchentoot:request-method request)
                (hunchentoot:script-name request)
                (and body (babel:octets-to-string body :encoding :utf-8))))
    (setf (hunchentoot:content-type*) "text/plain; charset=utf-8")
    "backend-ok"))

(defconstant +gw-backend-port+ 18090)
(defconstant +gw-listener-port+ 18091)

(defun gw-raw-request (port host path &key (method "GET") body)
  "Send one HTTP/1.1 request with an explicit Host header over a raw socket and
   return (values status-code body-string). Connection: close frames the read."
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
               (let* ((line-end (search (format nil "~C~C" #\Return #\Newline) raw))
                      (status-line (subseq raw 0 line-end))
                      (code (parse-integer status-line :start (1+ (position #\Space status-line))
                                                        :junk-allowed t))
                      (sep (search (format nil "~C~C~C~C" #\Return #\Newline #\Return #\Newline) raw))
                      (payload (and sep (subseq raw (+ sep 4)))))
                 (values code payload)))))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

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
         ;; Resolve only "echo" to the live backend; "missing" is unresolvable.
         (resolver (lambda (backend)
                     (when (equal (gr8s::gw-backend-name backend) "echo")
                       (values "127.0.0.1" +gw-backend-port+))))
         (gateway (gr8s::start-gateway-listener :port +gw-listener-port+
                                                :router router :resolver resolver :name "test")))
    (unwind-protect
         (progn
           ;; Matched route: terminated, dispatched, proxied to the live backend.
           (setf *gw-backend-last* nil)
           (multiple-value-bind (code body)
               (gw-raw-request +gw-listener-port+ "app.example.com" "/cart" :method "POST" :body "hello")
             (is (= 200 code))
             (is (equal "backend-ok" body))
             (is (equal :post (first *gw-backend-last*)))
             (is (equal "/cart" (second *gw-backend-last*)))
             (is (equal "hello" (third *gw-backend-last*))))
           ;; Unmatched host -> 404, backend untouched.
           (setf *gw-backend-last* nil)
           (is (= 404 (gw-raw-request +gw-listener-port+ "nope.org" "/x")))
           (is (null *gw-backend-last*))
           ;; Matched route but unresolvable backend -> 503.
           (is (= 503 (gw-raw-request +gw-listener-port+ "fail.example.com" "/y"))))
      (gr8s::stop-gateway-listener gateway)
      (hunchentoot:stop backend))))
