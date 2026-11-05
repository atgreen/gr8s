;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise the L4 data plane: parsing TCPRoute/TLSRoute/GRPCRoute into the
;;;; normalized model, SNI host dispatch, a TCP splice end to end, and TLS SNI
;;;; passthrough steering an inbound ClientHello to the backend whose hostname
;;;; matches (reusing the ClientHello builder from the SNI suite).

(in-package #:gr8s/tests)
(def-suite gateway-l4 :in gr8s)
(in-suite gateway-l4)

(defconstant +l4-listener-port+ 18092)
(defconstant +l4-backend-a-port+ 18093)
(defconstant +l4-backend-b-port+ 18094)
(defconstant +l4-tls-listener-port+ 18095)
(defconstant +l4-tls-backend-a-port+ 18096)
(defconstant +l4-tls-backend-b-port+ 18097)

(defun l4-start-tag-backend (port tag)
  "Accept connections and send TAG on connect, then close. Raw sockets (no
   fd-streams) to match the proxy's I/O. Returns a stop fn."
  (let* ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
         (stop (list nil))
         (tag-bytes (babel:string-to-octets tag))
         (thread nil))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket #(127 0 0 1) port)
    (sb-bsd-sockets:socket-listen socket 8)
    (setf thread
          (bt:make-thread
           (lambda ()
             (loop until (car stop) do
               (handler-case
                   (let ((client (sb-bsd-sockets:socket-accept socket)))
                     (sb-bsd-sockets:socket-send client tag-bytes (length tag-bytes))
                     (ignore-errors (sb-bsd-sockets:socket-close client)))
                 (error () nil))))
           :name (format nil "l4 test backend ~A" tag)))
    (lambda ()
      (setf (car stop) t)
      ;; Wake the accept and wait for this thread before closing. Closing first leaves it
      ;; looping on a descriptor number that the next listener takes, where it accepted
      ;; and closed that server's connections: podster-uqb.106.
      (ignore-errors
       (let ((waker (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
         (unwind-protect (sb-bsd-sockets:socket-connect waker #(127 0 0 1) port)
           (ignore-errors (sb-bsd-sockets:socket-close waker)))))
      (ignore-errors (bt:join-thread thread))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(test the-tag-backend-is-gone-before-its-listener-closes
  ;; podster-uqb.106: a backend thread that outlived its listener went on accepting on that
  ;; descriptor number, which by then was the next test server's, and closed its connections.
  (let* ((tag "stops-cleanly")
         (stop (l4-start-tag-backend +l4-backend-a-port+ tag))
         (name (format nil "l4 test backend ~A" tag)))
    (flet ((running-p ()
             (find name (bt:all-threads) :key #'bt:thread-name :test #'equal)))
      (is-true (running-p))
      (funcall stop)
      (is-false (running-p)))))

(defun l4-client-read-tag (port &key send)
  "Connect to PORT, optionally SEND bytes, and read the reply tag as a string.
   Raw sockets, to match the proxy's I/O and avoid fd-stream reuse quirks."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
           (when send (sb-bsd-sockets:socket-send socket send (length send)))
           (let ((buffer (make-array 64 :element-type '(unsigned-byte 8))))
             (multiple-value-bind (buf n)
                 (handler-case (sb-ext:with-timeout 4 (sb-bsd-sockets:socket-receive socket buffer 64))
                   (sb-ext:timeout () (values nil 0))
                   (error () (values nil 0)))
               (declare (ignore buf))
               (if (and n (plusp n)) (babel:octets-to-string (subseq buffer 0 n)) ""))))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun l4-backend (name port) (gr8s::make-gw-backend :name name :port port))

(test gateway-l4-parses-routes
  (let ((tcp (gr8s::parse-tcproute
              (com.inuoe.jzon:parse
               "{\"metadata\":{\"name\":\"db\",\"namespace\":\"data\"},\"spec\":{\"rules\":[{\"backendRefs\":[{\"name\":\"mysql\",\"port\":3306}]}]}}")))
        (tls (gr8s::parse-sni-route
              (com.inuoe.jzon:parse
               "{\"metadata\":{\"name\":\"sni\",\"namespace\":\"edge\"},\"spec\":{\"hostnames\":[\"a.example.com\",\"*.wild.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"tls-svc\",\"port\":8443}]}]}}"))))
    (is (equal "data" (gr8s::l4-tcp-route-namespace tcp)))
    (is (equal "mysql" (gr8s::gw-backend-name (first (gr8s::l4-tcp-route-backends tcp)))))
    (is (= 3306 (gr8s::gw-backend-port (first (gr8s::l4-tcp-route-backends tcp)))))
    (is (equal '("a.example.com" "*.wild.com") (gr8s::l4-sni-route-hostnames tls)))
    (is (equal "tls-svc" (gr8s::gw-backend-name (first (gr8s::l4-sni-route-backends tls)))))))

(test gateway-l4-sni-dispatch-prefers-exact
  (let ((routes (list (gr8s::make-l4-sni-route :hostnames '("*.example.com")
                                               :backends (list (l4-backend "wild" 1)))
                      (gr8s::make-l4-sni-route :hostnames '("api.example.com")
                                               :backends (list (l4-backend "exact" 2))))))
    (is (equal "exact" (gr8s::gw-backend-name (gr8s::l4-sni-dispatch routes "api.example.com"))))
    (is (equal "wild" (gr8s::gw-backend-name (gr8s::l4-sni-dispatch routes "other.example.com"))))
    (is (null (gr8s::l4-sni-dispatch routes "nope.org")))
    (is (null (gr8s::l4-sni-dispatch routes nil)))))

(test gateway-l4-tcp-splices-to-backend
  (let* ((stop-backend (l4-start-tag-backend +l4-backend-a-port+ "tcp-ok"))
         (resolver (lambda (b) (declare (ignore b)) (values "127.0.0.1" +l4-backend-a-port+)))
         (dispatcher (lambda (sni) (declare (ignore sni)) (l4-backend "db" +l4-backend-a-port+)))
         (listener (gr8s::start-l4-listener :port +l4-listener-port+ :mode :tcp
                                            :dispatcher dispatcher :resolver resolver :name "tcp")))
    (unwind-protect
         (is (equal "tcp-ok" (l4-client-read-tag +l4-listener-port+ :send (babel:string-to-octets "ping"))))
      (gr8s::stop-l4-listener listener)
      (funcall stop-backend))))

(test gateway-l4-tls-sni-steers-to-matching-backend
  (let* ((stop-a (l4-start-tag-backend +l4-tls-backend-a-port+ "A"))
         (stop-b (l4-start-tag-backend +l4-tls-backend-b-port+ "B"))
         (sni-routes (list (gr8s::make-l4-sni-route :hostnames '("one.test")
                                                    :backends (list (l4-backend "a" +l4-tls-backend-a-port+)))
                           (gr8s::make-l4-sni-route :hostnames '("two.test")
                                                    :backends (list (l4-backend "b" +l4-tls-backend-b-port+)))))
         (resolver (lambda (backend)
                     (values "127.0.0.1"
                             (if (equal (gr8s::gw-backend-name backend) "a")
                                 +l4-tls-backend-a-port+ +l4-tls-backend-b-port+))))
         (dispatcher (lambda (sni) (gr8s::l4-sni-dispatch sni-routes sni)))
         (listener (gr8s::start-l4-listener :port +l4-tls-listener-port+ :mode :tls
                                            :dispatcher dispatcher :resolver resolver :name "tls")))
    (unwind-protect
         (progn
           (is (equal "A" (l4-client-read-tag +l4-tls-listener-port+
                                              :send (gwsni-client-hello :server-name "one.test"))))
           (is (equal "B" (l4-client-read-tag +l4-tls-listener-port+
                                              :send (gwsni-client-hello :server-name "two.test")))))
      (gr8s::stop-l4-listener listener)
      (funcall stop-a)
      (funcall stop-b))))
