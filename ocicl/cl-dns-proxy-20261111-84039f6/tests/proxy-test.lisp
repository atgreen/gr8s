;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-dns-proxy/tests)
(in-suite cl-dns-proxy)

(defun dns-a-query (name &optional (id #x4752))
  (0conf:encode-message
   (0conf:make-dns-message
    :id id :flags #x0100
    :questions (list (0conf:make-question
                      :name name :qtype 0conf:+type-a+
                      :qclass 0conf:+class-in+)))))

(defun dns-response (query address &key (ttl 30))
  (let* ((message (0conf:decode-message query))
         (question (first (0conf:dns-message-questions message))))
    (0conf:encode-message
     (0conf:make-dns-message
      :id (0conf:dns-message-id message) :flags #x8180
      :questions (0conf:dns-message-questions message)
      :answers (list (make-instance '0conf:a-record
                                    :name (0conf:question-name question)
                                    :address address :ttl ttl))))))

(test resolver-may-answer-or-decline
  (let ((forwarded 0))
    (flet ((forward (packet) (incf forwarded) (dns-response packet #(192 0 2 1)))
           (resolve (question)
             (if (string= "local.example" (0conf:question-name question))
                 (values (list (make-instance '0conf:a-record
                                              :name "local.example"
                                              :address #(198 51 100 7) :ttl 20))
                         t 0)
                 (values nil nil nil))))
      (let ((local (0conf:decode-message
                    (answer-dns-query (dns-a-query "local.example")
                                      #'forward #'resolve))))
        (is (= 0 forwarded))
        (is (logtest #x0400 (0conf:dns-message-flags local)))
        (is (equalp #(198 51 100 7)
                    (0conf:a-address (first (0conf:dns-message-answers local))))))
      (answer-dns-query (dns-a-query "elsewhere.example") #'forward #'resolve)
      (is (= 1 forwarded)))))

(test cache-preserves-query-identities-ages-ttls-and-expires
  (let* ((now 100) (calls 0)
         (cache (make-dns-forward-cache :maximum-entries 8 :clock (lambda () now))))
    (flet ((forward (query upstreams timeout)
             (declare (ignore upstreams timeout))
             (incf calls)
             (dns-response query #(192 0 2 44) :ttl 10)))
      (let ((first (0conf:decode-message
                    (cached-dns-forward cache (dns-a-query "cache.example" 1)
                                        nil 2 #'forward))))
        (is (= 1 calls))
        (is (= 1 (0conf:dns-message-id first)))
        (is (= 10 (0conf:rr-ttl (first (0conf:dns-message-answers first))))))
      (setf now 104)
      (let ((second (0conf:decode-message
                     (cached-dns-forward cache (dns-a-query "cache.example" 2)
                                         nil 2 #'forward))))
        (is (= 1 calls))
        (is (= 2 (0conf:dns-message-id second)))
        (is (= 6 (0conf:rr-ttl (first (0conf:dns-message-answers second))))))
      (setf now 111)
      (cached-dns-forward cache (dns-a-query "cache.example" 3) nil 2 #'forward)
      (is (= 2 calls)))))

(test conditional-forwarding-uses-longest-zone
  (let ((rules '(("corp.example" ("192.0.2.1" . 53))
                 ("dev.corp.example" ("192.0.2.2" . 5353))))
        (defaults '(("192.0.2.53" . 53))))
    (is (equal '(("192.0.2.2" . 5353))
               (dns-upstreams-for-packet
                (dns-a-query "api.dev.corp.example") defaults rules)))
    (is (equal '(("192.0.2.1" . 53))
               (dns-upstreams-for-packet
                (dns-a-query "www.corp.example") defaults rules)))
    (is (equal defaults
               (dns-upstreams-for-packet
                (dns-a-query "example.net") defaults rules)))))

(test resolver-configuration-yields-ipv4-upstreams
  (with-input-from-string
      (stream (format nil "# generated~%nameserver 127.0.0.53~%nameserver 192.0.2.53 # fallback~%nameserver 2001:db8::53~%"))
    (is (equal '(("127.0.0.53" . 53) ("192.0.2.53" . 53))
               (parse-resolv-conf-upstreams stream)))))

(defun udp-query (port name &optional (id #x4752))
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type :datagram :protocol :udp))
        (packet (dns-a-query name id))
        (buffer (make-array 4096 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
           (sb-bsd-sockets:socket-send socket packet (length packet))
           (multiple-value-bind (ignored size)
               (sb-bsd-sockets:socket-receive socket buffer (length buffer))
             (declare (ignore ignored))
             (subseq buffer 0 size)))
      (sb-bsd-sockets:socket-close socket))))

(defun write-frame (stream packet)
  (write-byte (ldb (byte 8 8) (length packet)) stream)
  (write-byte (ldb (byte 8 0) (length packet)) stream)
  (write-sequence packet stream)
  (finish-output stream))

(defun read-frame (stream)
  (let* ((length (+ (ash (read-byte stream) 8) (read-byte stream)))
         (packet (make-array length :element-type '(unsigned-byte 8))))
    (is (= length (read-sequence packet stream)))
    packet))

(defun tcp-query (port name &optional (id #x4752))
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type :stream :protocol :tcp))
        (stream nil))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
           (setf stream
                 (sb-bsd-sockets:socket-make-stream
                  socket :input t :output t :element-type '(unsigned-byte 8)
                  :buffering :none))
           (write-frame stream (dns-a-query name id))
           (read-frame stream))
      (if stream (ignore-errors (close stream)))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun first-a-address (packet)
  (0conf:a-address
   (first (0conf:dns-message-answers (0conf:decode-message packet)))))

(test server-serves-resolved-and-forwarded-queries-over-udp-and-tcp
  (let ((server nil) (udp-calls 0) (tcp-calls 0))
    (unwind-protect
         (progn
           (setf server
                 (start-dns-server
                  :address "127.0.0.1" :port 0 :upstreams nil
                  :resolver
                  (lambda (question)
                    (if (string= "local.example" (0conf:question-name question))
                        (values (list (make-instance '0conf:a-record
                                                     :name "local.example"
                                                     :address #(198 51 100 8)
                                                     :ttl 30))
                                t 0)
                        (values nil nil nil)))
                  :udp-forwarder
                  (lambda (packet upstreams timeout)
                    (declare (ignore upstreams timeout))
                    (incf udp-calls)
                    (dns-response packet #(203 0 113 9)))
                  :tcp-forwarder
                  (lambda (packet upstreams timeout)
                    (declare (ignore upstreams timeout))
                    (incf tcp-calls)
                    (dns-response packet #(203 0 113 10)))))
           (is (plusp (dns-server-port server)))
           (is (equalp #(198 51 100 8)
                       (first-a-address
                        (udp-query (dns-server-port server) "local.example"))))
           (is (equalp #(203 0 113 9)
                       (first-a-address
                        (udp-query (dns-server-port server) "udp.example"))))
           (is (equalp #(198 51 100 8)
                       (first-a-address
                        (tcp-query (dns-server-port server) "local.example"))))
           (is (equalp #(203 0 113 10)
                       (first-a-address
                        (tcp-query (dns-server-port server) "tcp.example"))))
           (is (= 1 udp-calls))
           (is (= 1 tcp-calls)))
      (when server (stop-dns-server server)))))

(test forwarding-errors-become-servfail-without-stopping-the-server
  (let ((server nil))
    (unwind-protect
         (progn
           (setf server
                 (start-dns-server
                  :address "127.0.0.1" :port 0 :upstreams nil
                  :udp-forwarder
                  (lambda (&rest arguments)
                    (declare (ignore arguments))
                    (error "upstream unavailable"))))
           (is (= 2 (dns-response-code
                     (udp-query (dns-server-port server) "first.example" 1))))
           (is (= 2 (dns-response-code
                     (udp-query (dns-server-port server) "second.example" 2)))))
      (when server (stop-dns-server server)))))

(test stopping-releases-the-paired-listener-port
  (let* ((server (start-dns-server :address "127.0.0.1" :port 0
                                    :upstreams nil))
         (port (dns-server-port server)))
    (stop-dns-server server)
    (let ((udp (cl-dns-proxy::make-bound-dns-socket
                :datagram :udp "127.0.0.1" port))
          (tcp (cl-dns-proxy::make-bound-dns-socket
                :stream :tcp "127.0.0.1" port)))
      (unwind-protect
           (is (and udp tcp))
        (sb-bsd-sockets:socket-close udp)
        (sb-bsd-sockets:socket-close tcp)))))

(test configured-port-conflict-releases-the-partially-bound-socket
  (let ((listener (cl-dns-proxy::make-bound-dns-socket
                   :stream :tcp "127.0.0.1" 0)))
    (unwind-protect
         (let ((port (nth-value 1 (sb-bsd-sockets:socket-name listener))))
           (sb-bsd-sockets:socket-listen listener 4)
           (signals sb-bsd-sockets:address-in-use-error
             (cl-dns-proxy::bind-dns-socket-pair "127.0.0.1" port))
           (let ((udp (cl-dns-proxy::make-bound-dns-socket
                       :datagram :udp "127.0.0.1" port)))
             (is-true udp)
             (sb-bsd-sockets:socket-close udp)))
      (sb-bsd-sockets:socket-close listener))))

(test metrics-cover-forwarding-cache-and-response-codes
  (let ((server nil)
        (metrics (make-dns-metrics)))
    (unwind-protect
         (progn
           (setf server
                 (start-dns-server
                  :address "127.0.0.1" :port 0 :upstreams nil
                  :metrics metrics
                  :udp-forwarder
                  (lambda (packet upstreams timeout)
                    (declare (ignore upstreams timeout))
                    (dns-response packet #(203 0 113 11) :ttl 30))))
           (udp-query (dns-server-port server) "metrics.example" 1)
           (udp-query (dns-server-port server) "metrics.example" 2)
           (let ((text (dns-metrics-text metrics)))
             (is (search "cl_dns_proxy_queries_total{protocol=\"udp\"} 2" text))
             (is (search "cl_dns_proxy_cache_requests_total{result=\"miss\"} 1" text))
             (is (search "cl_dns_proxy_cache_requests_total{result=\"hit\"} 1" text))
             (is (search "cl_dns_proxy_responses_total{rcode=\"NOERROR\"} 2" text))))
      (when server (stop-dns-server server)))))
