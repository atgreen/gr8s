;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify authoritative replies and actual UDP/TCP forwarding, including silent
;;;; upstream timeout recovery and continued server liveness.

(in-package #:gr8s/tests)

(in-suite gr8s)

(defparameter +kubernetes-service-name+
  "kubernetes.default.svc.cluster.local")

(defun dns-a-query (name &optional (id #x4752))
  (0conf:encode-message
   (0conf:make-dns-message
    :id id
    :flags #x0100
    :questions
    (list (0conf:make-question :name name
                               :qtype 0conf:+type-a+
                               :qclass 0conf:+class-in+)))))

(test dns-answers-the-kubernetes-service-authoritatively
  (let* ((forwarded nil)
         (response
           (gr8s::answer-dns-query
            (dns-a-query +kubernetes-service-name+)
            (lambda (packet)
              (setf forwarded packet)
              packet)))
         (message (0conf:decode-message response))
         (answer (first (0conf:dns-message-answers message))))
    (is (null forwarded))
    (is (= #x4752 (0conf:dns-message-id message)))
    (is (logtest #x8000 (0conf:dns-message-flags message)))
    (is (logtest #x0400 (0conf:dns-message-flags message)))
    (is (logtest #x0100 (0conf:dns-message-flags message)))
    (is (typep answer '0conf:a-record))
    (is (equalp #(10 96 0 1) (0conf:a-address answer)))))

(test dns-forwards-names-outside-the-cluster-zone
  (let* ((query (dns-a-query "example.test"))
         (upstream-response #(1 2 3 4))
         (forwarded nil)
         (response
           (gr8s::answer-dns-query
            query
            (lambda (packet)
              (setf forwarded packet)
              upstream-response))))
    (is (equalp query forwarded))
    (is (eq upstream-response response))))

(test dns-does-not-leak-unknown-cluster-names-upstream
  (let* ((forwarded nil)
         (response
           (gr8s::answer-dns-query
            (dns-a-query "missing.default.svc.cluster.local")
            (lambda (packet)
              (setf forwarded packet)
              packet)))
         (message (0conf:decode-message response)))
    (is (null forwarded))
    (is (= 3 (logand #x000f (0conf:dns-message-flags message))))
    (is (null (0conf:dns-message-answers message)))))

(test resolv-conf-nameservers-become-dns-upstreams
  (with-input-from-string
      (stream (format nil "# generated~%search example.test~%nameserver 127.0.0.53~%nameserver 192.0.2.53 # fallback~%nameserver 2001:db8::53~%"))
    (is (equal '(("127.0.0.53" . 53) ("192.0.2.53" . 53))
               (gr8s::parse-resolv-conf-upstreams stream)))))

(test managed-dns-lifecycle-stops-the-server-after-the-body
  (let ((events nil)
        (instance (list :dns-server)))
    (is (eq :body-result
            (gr8s::call-with-dns-server
             (lambda ()
               (push :body events)
               :body-result)
             :starter (lambda (&rest arguments)
                        (push (list :start arguments) events)
                        instance)
             :stopper (lambda (server)
                        (is (eq instance server))
                        (push :stop events))
             :address "10.88.0.1"
             :port 53
             :upstreams '(("127.0.0.53" . 53)))))
    (is (equal '(:stop :body (:start (:address "10.88.0.1" :port 53
                                      :upstreams (("127.0.0.53" . 53)))))
               events))))

(defun test-dns-answer (query address)
  (let* ((message (0conf:decode-message query))
         (question (first (0conf:dns-message-questions message))))
    (0conf:encode-message
     (0conf:make-dns-message
      :id (0conf:dns-message-id message)
      :flags #x8180
      :questions (0conf:dns-message-questions message)
      :answers (list (make-instance '0conf:a-record
                                    :name (0conf:question-name question)
                                    :address address
                                    :ttl 30))))))

(defun test-udp-dns-query (port name)
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type :datagram :protocol :udp))
        (query (dns-a-query name))
        (buffer (make-array 4096 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
           (sb-bsd-sockets:socket-send socket query (length query))
           (multiple-value-bind (ignored size)
               (sb-bsd-sockets:socket-receive socket buffer (length buffer))
             (declare (ignore ignored))
             (subseq buffer 0 size)))
      (sb-bsd-sockets:socket-close socket))))

(defun write-test-dns-frame (stream packet)
  (write-byte (ldb (byte 8 8) (length packet)) stream)
  (write-byte (ldb (byte 8 0) (length packet)) stream)
  (write-sequence packet stream)
  (finish-output stream))

(defun read-test-dns-frame (stream)
  (let* ((length (+ (ash (read-byte stream) 8) (read-byte stream)))
         (packet (make-array length :element-type '(unsigned-byte 8))))
    (is (= length (read-sequence packet stream)))
    packet))

(defun test-tcp-dns-query (port name)
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type :stream :protocol :tcp))
        (stream nil))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
           (setf stream
                 (sb-bsd-sockets:socket-make-stream
                  socket :input t :output t
                  :element-type '(unsigned-byte 8) :buffering :none))
           (write-test-dns-frame stream (dns-a-query name))
           (read-test-dns-frame stream))
      (if stream
          (ignore-errors (close stream)))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun dns-first-a-address (packet)
  (0conf:a-address
   (first (0conf:dns-message-answers (0conf:decode-message packet)))))

(test dns-server-serves-and-forwards-over-udp-and-tcp
  (let ((udp-forwarded nil)
        (tcp-forwarded nil)
        (server nil))
    (unwind-protect
         (progn
           (setf server
                 (gr8s::start-dns-server
                  :address "127.0.0.1" :port 0
                  :upstreams '(("192.0.2.53" . 53))
                  :udp-forwarder
                  (lambda (packet upstreams timeout)
                    (declare (ignore upstreams timeout))
                    (setf udp-forwarded t)
                    (test-dns-answer packet #(203 0 113 9)))
                  :tcp-forwarder
                  (lambda (packet upstreams timeout)
                    (declare (ignore upstreams timeout))
                    (setf tcp-forwarded t)
                    (test-dns-answer packet #(203 0 113 10)))))
           (is (equalp #(10 96 0 1)
                       (dns-first-a-address
                        (test-udp-dns-query
                         (gr8s::dns-server-port server)
                         +kubernetes-service-name+))))
           (is (equalp #(203 0 113 9)
                       (dns-first-a-address
                        (test-udp-dns-query
                         (gr8s::dns-server-port server) "udp.example"))))
           (is (equalp #(10 96 0 1)
                       (dns-first-a-address
                        (test-tcp-dns-query
                         (gr8s::dns-server-port server)
                         +kubernetes-service-name+))))
           (is (equalp #(203 0 113 10)
                       (dns-first-a-address
                        (test-tcp-dns-query
                         (gr8s::dns-server-port server) "tcp.example"))))
           (is (eq t udp-forwarded))
           (is (eq t tcp-forwarded)))
      (when server (gr8s::stop-dns-server server)))))

(test dns-survives-an-actual-silent-udp-upstream-and-continues-serving
  (let* ((silent (gr8s::make-bound-dns-socket :datagram :udp "127.0.0.1" 0))
         (silent-port (nth-value 1 (sb-bsd-sockets:socket-name silent)))
         (server nil))
    (unwind-protect
         (progn
           (setf server (gr8s::start-dns-server :address "127.0.0.1" :port 0
                          :upstreams (list (cons "127.0.0.1" silent-port)) :timeout .05))
           ;; A bound, deliberately unread UDP socket supplies neither a reply
           ;; nor an ICMP refusal: the actual recvfrom must hit its timeout.
           (dotimes (index 2)
             (declare (ignore index))
             (sb-sys:with-deadline (:seconds 2)
               (is (= 2 (gr8s::dns-response-code
                         (test-udp-dns-query (gr8s::dns-server-port server) "silent.example"))))))
           (is (bt:thread-alive-p (gr8s::dns-server-udp-thread server)))
           (is (equalp #(10 96 0 1)
                       (dns-first-a-address (test-udp-dns-query (gr8s::dns-server-port server) +kubernetes-service-name+)))))
      (when server (gr8s::stop-dns-server server))
      (sb-bsd-sockets:socket-close silent))))

(test dns-upstream-retries-contain-deadline-timeouts
  (let ((attempts 0))
    (is (eq :answered
            (gr8s::try-dns-upstreams '(first second)
              (lambda (upstream)
                (incf attempts)
                (if (eq upstream 'first) (error 'sb-sys:deadline-timeout) :answered)))))
    (is (= 2 attempts))))
