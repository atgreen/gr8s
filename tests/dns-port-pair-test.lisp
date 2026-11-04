;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Force actual TCP conflicts after a UDP ephemeral reservation and verify bounded
;;;; retry, configured-port honesty and complete owned-socket cleanup.

(in-package #:gr8s/tests)
(def-suite dns-port-pair :in gr8s)
(in-suite dns-port-pair)

(defmacro with-conflicting-dns-port ((port tcp) &body body)
  "Own an actual TCP listener and expose its allocated number as a UDP candidate."
  `(let* ((,tcp (gr8s::make-bound-dns-socket :stream :tcp "127.0.0.1" 0))
          (,port (nth-value 1 (sb-bsd-sockets:socket-name ,tcp))))
     (sb-bsd-sockets:socket-listen ,tcp 4)
     (unwind-protect (progn ,@body) (sb-bsd-sockets:socket-close ,tcp))))

(defun dns-test-port-still-owned-p (port listener)
  "Connect to the original listener to prove failed DNS allocation did not close it."
  (let ((client (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
        (accepted nil))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect client #(127 0 0 1) port)
           (setf accepted (sb-bsd-sockets:socket-accept listener))
           t)
      (when accepted (sb-bsd-sockets:socket-close accepted))
      (sb-bsd-sockets:socket-close client))))

(test dns-port-zero-retries-an-actual-cross-protocol-conflict
  (with-conflicting-dns-port (occupied listener)
    (let ((original (symbol-function 'gr8s::make-bound-dns-socket))
          (attempts 0) (server nil) (selected nil))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::make-bound-dns-socket)
                   (lambda (type protocol address port)
                     (when (and (eq type :datagram) (zerop port))
                       (incf attempts)
                       (when (= attempts 1) (setf port occupied)))
                     (funcall original type protocol address port)))
             (setf server (gr8s::start-dns-server :address "127.0.0.1" :port 0)
                   selected (gr8s::dns-server-port server))
             (is (>= attempts 2))
             (is (/= occupied selected))
             (is (= selected (nth-value 1 (sb-bsd-sockets:socket-name (gr8s::dns-server-udp-socket server)))))
             (is (= selected (nth-value 1 (sb-bsd-sockets:socket-name (gr8s::dns-server-tcp-socket server)))))
             (is (equalp #(10 96 0 1) (dns-first-a-address (test-udp-dns-query selected +kubernetes-service-name+))))
             (is (equalp #(10 96 0 1) (dns-first-a-address (test-tcp-dns-query selected +kubernetes-service-name+))))
             (is (dns-test-port-still-owned-p occupied listener))
             (let ((released (funcall original :datagram :udp "127.0.0.1" occupied)))
               (is (not (null released))) (sb-bsd-sockets:socket-close released)))
        (setf (symbol-function 'gr8s::make-bound-dns-socket) original)
        (when server (gr8s::stop-dns-server server)))
      (let ((udp (funcall original :datagram :udp "127.0.0.1" selected))
            (tcp (funcall original :stream :tcp "127.0.0.1" selected)))
        (is (and udp tcp))
        (sb-bsd-sockets:socket-close udp)
        (sb-bsd-sockets:socket-close tcp)))))

(test dns-port-zero-conflict-exhaustion-is-bounded-and-releases-every-candidate
  (with-conflicting-dns-port (occupied listener)
    (let ((original (symbol-function 'gr8s::make-bound-dns-socket)) (attempts 0))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::make-bound-dns-socket)
                   (lambda (type protocol address port)
                     (when (and (eq type :datagram) (zerop port))
                       (incf attempts) (setf port occupied))
                     (funcall original type protocol address port)))
             (signals sb-bsd-sockets:address-in-use-error (gr8s::start-dns-server :address "127.0.0.1" :port 0))
             (is (= gr8s::+dns-ephemeral-bind-attempts+ attempts))
             (let ((released (funcall original :datagram :udp "127.0.0.1" occupied)))
               (is (not (null released))) (sb-bsd-sockets:socket-close released))
             (is (dns-test-port-still-owned-p occupied listener)))
        (setf (symbol-function 'gr8s::make-bound-dns-socket) original)))))

(test dns-configured-port-conflicts-are-not-retried
  (with-conflicting-dns-port (occupied listener)
    (let ((original (symbol-function 'gr8s::make-bound-dns-socket)) (tcp-attempts 0))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::make-bound-dns-socket)
                   (lambda (type protocol address port)
                     (when (eq type :stream) (incf tcp-attempts))
                     (funcall original type protocol address port)))
             (signals sb-bsd-sockets:address-in-use-error (gr8s::start-dns-server :address "127.0.0.1" :port occupied))
             (is (= 1 tcp-attempts))
             (let ((released (funcall original :datagram :udp "127.0.0.1" occupied)))
               (is (not (null released))) (sb-bsd-sockets:socket-close released))
             (is (dns-test-port-still-owned-p occupied listener)))
        (setf (symbol-function 'gr8s::make-bound-dns-socket) original)))))
