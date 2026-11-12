;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise the L4 data plane: parsing TCPRoute/TLSRoute/GRPCRoute into the
;;;; normalized model, SNI host dispatch, a TCP splice end to end, and TLS SNI
;;;; passthrough steering an inbound ClientHello to the backend whose hostname
;;;; matches (reusing the ClientHello builder from the SNI suite).

(in-package #:gr8s/tests)
(def-suite gateway-l4 :in gr8s)
(in-suite gateway-l4)

;;; Every listener and backend takes a kernel-assigned port: fixed ones collided with
;;; other suites' servers in the same run (podster-uqb.127).

(defun l4-start-tag-backend (tag)
  "Accept connections on a kernel-assigned port and send TAG on connect, then close.
   Raw sockets (no fd-streams) to match the proxy's I/O. Returns a stop fn and the port."
  (let* ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
         (stop (list nil))
         (tag-bytes (babel:string-to-octets tag))
         (thread nil)
         (port nil))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket #(127 0 0 1) 0)
    (setf port (nth-value 1 (sb-bsd-sockets:socket-name socket)))
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
    (values
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
       (ignore-errors (sb-bsd-sockets:socket-close socket)))
     port)))

(defun l4-listener-bound-port (listener)
  "Return the port LISTENER actually listens on."
  (nth-value 1 (sb-bsd-sockets:socket-name (gr8s.controllers::l4-listener-socket listener))))

(test the-tag-backend-is-gone-before-its-listener-closes
  ;; podster-uqb.106: a backend thread that outlived its listener went on accepting on that
  ;; descriptor number, which by then was the next test server's, and closed its connections.
  (let* ((tag "stops-cleanly")
         (stop (l4-start-tag-backend tag))
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

(defun l4-backend (name port) (gr8s.controllers::make-gw-backend :name name :port port))

(test gateway-l4-parses-routes
  (let ((tcp (gr8s.controllers::parse-tcproute
              (com.inuoe.jzon:parse
               "{\"metadata\":{\"name\":\"db\",\"namespace\":\"data\"},\"spec\":{\"rules\":[{\"backendRefs\":[{\"name\":\"mysql\",\"port\":3306}]}]}}")))
        (tls (gr8s.controllers::parse-sni-route
              (com.inuoe.jzon:parse
               "{\"metadata\":{\"name\":\"sni\",\"namespace\":\"edge\"},\"spec\":{\"hostnames\":[\"a.example.com\",\"*.wild.com\"],\"rules\":[{\"backendRefs\":[{\"name\":\"tls-svc\",\"port\":8443}]}]}}"))))
    (is (equal "data" (gr8s.controllers::l4-tcp-route-namespace tcp)))
    (is (equal "mysql" (gr8s.controllers::gw-backend-name (first (gr8s.controllers::l4-tcp-route-backends tcp)))))
    (is (= 3306 (gr8s.controllers::gw-backend-port (first (gr8s.controllers::l4-tcp-route-backends tcp)))))
    (is (equal '("a.example.com" "*.wild.com") (gr8s.controllers::l4-sni-route-hostnames tls)))
    (is (equal "tls-svc" (gr8s.controllers::gw-backend-name (first (gr8s.controllers::l4-sni-route-backends tls)))))))

(test gateway-l4-sni-dispatch-prefers-exact
  (let ((routes (list (gr8s.controllers::make-l4-sni-route :hostnames '("*.example.com")
                                               :backends (list (l4-backend "wild" 1)))
                      (gr8s.controllers::make-l4-sni-route :hostnames '("api.example.com")
                                               :backends (list (l4-backend "exact" 2))))))
    (is (equal "exact" (gr8s.controllers::gw-backend-name (gr8s.controllers::l4-sni-dispatch routes "api.example.com"))))
    (is (equal "wild" (gr8s.controllers::gw-backend-name (gr8s.controllers::l4-sni-dispatch routes "other.example.com"))))
    (is (null (gr8s.controllers::l4-sni-dispatch routes "nope.org")))
    (is (null (gr8s.controllers::l4-sni-dispatch routes nil)))))

(test gateway-l4-tcp-splices-to-backend
  (multiple-value-bind (stop-backend backend-port) (l4-start-tag-backend "tcp-ok")
    (let* ((resolver (lambda (b) (declare (ignore b)) (values "127.0.0.1" backend-port)))
           (dispatcher (lambda (sni) (declare (ignore sni)) (l4-backend "db" backend-port)))
           (listener (gr8s.controllers::start-l4-listener :port 0 :mode :tcp
                                              :dispatcher dispatcher :resolver resolver :name "tcp")))
      (unwind-protect
           (progn
             (is (= (l4-listener-bound-port listener) (gr8s.controllers::l4-listener-port listener)))
             (is (equal "tcp-ok" (l4-client-read-tag (gr8s.controllers::l4-listener-port listener)
                                                     :send (babel:string-to-octets "ping")))))
        (gr8s.controllers::stop-l4-listener listener)
        (funcall stop-backend)))))

(test gateway-l4-tls-sni-steers-to-matching-backend
  (multiple-value-bind (stop-a port-a) (l4-start-tag-backend "A")
    (multiple-value-bind (stop-b port-b) (l4-start-tag-backend "B")
      (let* ((sni-routes (list (gr8s.controllers::make-l4-sni-route :hostnames '("one.test")
                                                        :backends (list (l4-backend "a" port-a)))
                               (gr8s.controllers::make-l4-sni-route :hostnames '("two.test")
                                                        :backends (list (l4-backend "b" port-b)))))
             (resolver (lambda (backend)
                         (values "127.0.0.1"
                                 (if (equal (gr8s.controllers::gw-backend-name backend) "a") port-a port-b))))
             (dispatcher (lambda (sni) (gr8s.controllers::l4-sni-dispatch sni-routes sni)))
             (listener (gr8s.controllers::start-l4-listener :port 0 :mode :tls
                                                :dispatcher dispatcher :resolver resolver :name "tls"))
             (port (gr8s.controllers::l4-listener-port listener)))
        (unwind-protect
             (progn
               (is (equal "A" (l4-client-read-tag port :send (gwsni-client-hello :server-name "one.test"))))
               (is (equal "B" (l4-client-read-tag port :send (gwsni-client-hello :server-name "two.test")))))
          (gr8s.controllers::stop-l4-listener listener)
          (funcall stop-a)
          (funcall stop-b))))))
