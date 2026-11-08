;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve authoritative Kubernetes DNS replies and bounded UDP/TCP forwarding;
;;;; upstream timeout conditions are contained so a resolver outage cannot stop the node.

(in-package #:gr8s)

(defconstant +dns-response+ #x8000)
(defconstant +dns-authoritative+ #x0400)
(defconstant +dns-recursion-desired+ #x0100)
(defconstant +dns-name-error+ 3)

(defparameter +dns-cluster-zone+ "cluster.local")
(defparameter +dns-kubernetes-service+
  "kubernetes.default.svc.cluster.local")
(defparameter +dns-kubernetes-service-address+ #(10 96 0 1))
(defparameter +dns-pod-server-address+ "169.254.1.1")
(defparameter +dns-pod-searches+
  '("default.svc.cluster.local" "svc.cluster.local" "cluster.local"))
(defparameter +dns-pod-options+ '("ndots:5"))

(defstruct dns-metrics
  (queries (make-hash-table :test #'equal))
  (responses (make-hash-table :test #'equal))
  (cache (make-hash-table :test #'equal))
  (forward (make-hash-table :test #'equal))
  (forward-duration 0d0)
  (forward-duration-count 0)
  (lock (bt:make-lock "gr8s DNS metrics")))

(defparameter *dns-metrics* (make-dns-metrics)
  "Process-local telemetry for the node's embedded DNS service.")

(defun dns-metric-incf (metrics table key)
  "Increment KEY in one bounded-label counter TABLE."
  (when metrics
    (bt:with-lock-held ((dns-metrics-lock metrics))
      (incf (gethash key table 0)))))

(defun dns-rcode-name (code)
  "Return the stable Prometheus label for a DNS response code."
  (case code (0 "NOERROR") (1 "FORMERR") (2 "SERVFAIL") (3 "NXDOMAIN")
        (4 "NOTIMP") (5 "REFUSED") (otherwise "OTHER")))

(defun dns-metrics-text (&optional (metrics *dns-metrics*))
  "Render embedded DNS counters and forwarding duration in Prometheus text format."
  (bt:with-lock-held ((dns-metrics-lock metrics))
    (with-output-to-string (out)
      (flet ((family (name help table label)
               (format out "# HELP ~A ~A~%# TYPE ~A counter~%" name help name)
               (dolist (key (sort (loop for key being the hash-keys of table collect key) #'string<))
                 (format out "~A{~A=~S} ~D~%" name label key (gethash key table)))))
        (family "gr8s_dns_queries_total" "DNS queries received." (dns-metrics-queries metrics) "protocol")
        (family "gr8s_dns_responses_total" "DNS responses returned." (dns-metrics-responses metrics) "rcode")
        (family "gr8s_dns_cache_requests_total" "External DNS cache lookups." (dns-metrics-cache metrics) "result")
        (family "gr8s_dns_forward_requests_total" "External DNS forwarding attempts." (dns-metrics-forward metrics) "result")
        (format out "# HELP gr8s_dns_forward_duration_seconds Time spent forwarding external DNS queries.~%")
        (format out "# TYPE gr8s_dns_forward_duration_seconds summary~%")
        (format out "gr8s_dns_forward_duration_seconds_sum ~,6F~%" (dns-metrics-forward-duration metrics))
        (format out "gr8s_dns_forward_duration_seconds_count ~D~%" (dns-metrics-forward-duration-count metrics))))))

#+linux
(sb-alien:define-alien-routine ("setsockopt" %linux-setsockopt) sb-alien:int
  (socket sb-alien:int)
  (level sb-alien:int)
  (option sb-alien:int)
  (value (* t))
  (length sb-alien:unsigned-int))

(defconstant +linux-ip-freebind+ 15)

(defun canonical-dns-name (name)
  "Normalize a DNS name for case-insensitive comparisons."
  (string-downcase (string-right-trim "." name)))

(defun dns-name-in-zone-p (name zone)
  "Recognize a zone apex or one of its descendant names."
  (let ((name (canonical-dns-name name))
        (zone (canonical-dns-name zone)))
    (or (string= name zone)
        (and (> (length name) (length zone))
             (char= #\. (char name (- (length name) (length zone) 1)))
             (string= zone name :start2 (- (length name) (length zone)))))))

(defun authoritative-dns-flags (query-flags &optional (rcode 0))
  "Build authoritative response flags while preserving requested recursion."
  (logior +dns-response+
          +dns-authoritative+
          (logand query-flags +dns-recursion-desired+)
          rcode))

(defun dns-authoritative-response (query &key answers (rcode 0))
  "Encode an authoritative response with the original question and identifier."
  (0conf:encode-message
   (0conf:make-dns-message
    :id (0conf:dns-message-id query)
    :flags (authoritative-dns-flags
            (0conf:dns-message-flags query) rcode)
    :questions (0conf:dns-message-questions query)
    :answers answers)))

(defun kubernetes-service-answer (question)
  "Return the reserved API Service A record for an A question."
  (when (= (0conf:question-qtype question) 0conf:+type-a+)
    (list (make-instance '0conf:a-record
                         :name (0conf:question-name question)
                         :address +dns-kubernetes-service-address+
                         :ttl 30))))

(defun answer-dns-query (packet forward &optional service-resolver)
  "Answer cluster-authoritative names and forward queries outside the cluster zone."
  (let* ((query (0conf:decode-message packet))
         (questions (0conf:dns-message-questions query))
         (question (first questions)))
    (cond
      ((and (= 1 (length questions))
            (string= (canonical-dns-name (0conf:question-name question))
                     +dns-kubernetes-service+))
       (dns-authoritative-response
        query :answers (kubernetes-service-answer question)))
      ((and service-resolver (= 1 (length questions)))
       (multiple-value-bind (answers exists reverse-authority) (funcall service-resolver question)
         (if (or reverse-authority
                 (dns-name-in-zone-p (0conf:question-name question) +dns-cluster-zone+))
             (dns-authoritative-response query :answers answers :rcode (if exists 0 +dns-name-error+))
             (funcall forward packet))))
      ((and question
            (dns-name-in-zone-p (0conf:question-name question)
                                +dns-cluster-zone+))
       (dns-authoritative-response query :rcode +dns-name-error+))
      (t
       (funcall forward packet)))))

(defstruct (dns-server (:constructor %make-dns-server))
  address
  port
  upstreams
  forward-rules
  timeout
  service-resolver
  udp-forwarder
  tcp-forwarder
  forward-cache
  (metrics *dns-metrics*)
  udp-socket
  tcp-socket
  udp-thread
  tcp-thread
  (stop-requested nil))

(defun dns-socket-address (address)
  "Parse or retain a four-octet IPv4 socket address."
  (etypecase address
    (string (0conf:parse-ipv4 address))
    ((vector (unsigned-byte 8) 4) address)))

(defun enable-ip-freebind (socket)
  "Allow binding the node DNS address before its interface exists."
  #+linux
  (sb-alien:with-alien ((enabled sb-alien:int 1))
    (unless (zerop (%linux-setsockopt
                    (sb-bsd-sockets:socket-file-descriptor socket)
                    0 +linux-ip-freebind+ (sb-alien:addr enabled)
                    (sb-alien:alien-size sb-alien:int :bytes)))
      (error "could not enable IP_FREEBIND: ~A"
             (sb-int:strerror (sb-alien:get-errno)))))
  #-linux
  (declare (ignore socket))
  socket)

(defun make-bound-dns-socket (type protocol address port)
  "Create and bind an owned DNS socket, closing it if initialization fails."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type type :protocol protocol)))
    (handler-case
        (progn
          (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
          (enable-ip-freebind socket)
          (sb-bsd-sockets:socket-bind socket
                                      (dns-socket-address address) port)
          socket)
      (error (condition)
        (sb-bsd-sockets:socket-close socket)
        (error condition)))))

(defun receive-dns-datagram (socket)
  "Read one complete UDP DNS packet and its sender address."
  (let ((buffer (make-array #xffff :element-type '(unsigned-byte 8))))
    (multiple-value-bind (ignored size host port)
        (sb-bsd-sockets:socket-receive socket buffer (length buffer))
      (declare (ignore ignored))
      (values (subseq buffer 0 size) host port))))

(defun send-dns-datagram (socket packet host port)
  "Send one DNS response packet to its requesting peer."
  (sb-bsd-sockets:socket-send socket packet (length packet)
                              :address (list host port)))

(defun dns-response-code (packet)
  "Extract a DNS packet response code."
  (logand #x000f
          (0conf:dns-message-flags (0conf:decode-message packet))))

(defun dns-servfail-response (packet)
  "Encode SERVFAIL for a valid query whose upstream failed."
  (let ((query (0conf:decode-message packet)))
    (0conf:encode-message
     (0conf:make-dns-message
      :id (0conf:dns-message-id query)
      :flags (logior +dns-response+
                     (logand (0conf:dns-message-flags query)
                             +dns-recursion-desired+)
                     2)
      :questions (0conf:dns-message-questions query)))))

(defstruct dns-forward-cache-entry
  packet
  stored-at
  expires-at)

(defstruct (dns-forward-cache (:constructor %make-dns-forward-cache))
  (entries (make-hash-table :test #'equalp))
  (maximum-entries 1024)
  (clock #'get-universal-time)
  (lock (bt:make-lock "gr8s DNS forward cache")))

(defun make-dns-forward-cache (&key (maximum-entries 1024) (clock #'get-universal-time))
  "Create a bounded external-response cache using CLOCK seconds for deterministic expiry."
  (unless (and (integerp maximum-entries) (plusp maximum-entries))
    (error "DNS cache maximum entries must be positive"))
  (%make-dns-forward-cache :maximum-entries maximum-entries :clock clock))

(defun dns-forward-cache-key (packet)
  "Return the wire query without its per-request transaction identifier."
  (when (< (length packet) 2) (error "truncated DNS query"))
  (let ((key (copy-seq packet)))
    (setf (aref key 0) 0 (aref key 1) 0)
    key))

(defun dns-response-records (message)
  "Return every record whose TTL must remain valid while a whole response is cached."
  (append (0conf:dns-message-answers message)
          (0conf:dns-message-authorities message)
          (0conf:dns-message-additionals message)))

(defun dns-response-cache-ttl (message)
  "Return the safe whole-response lifetime, or NIL for a response we must not cache."
  (let* ((rcode (logand #x000f (0conf:dns-message-flags message)))
         (records (cond ((and (zerop rcode) (0conf:dns-message-answers message))
                         (dns-response-records message))
                        ((member rcode '(0 3))
                         (0conf:dns-message-authorities message)))))
    (when records
      (let ((ttl (reduce #'min records :key #'0conf:rr-ttl)))
        (and (plusp ttl) ttl)))))

(defun age-dns-response (packet query-id age)
  "Copy a cached response, install QUERY-ID and subtract AGE seconds from every TTL."
  (let ((message (0conf:decode-message packet)))
    (setf (0conf:dns-message-id message) query-id)
    (dolist (record (dns-response-records message))
      (setf (0conf:rr-ttl record) (max 0 (- (0conf:rr-ttl record) age))))
    (0conf:encode-message message)))

(defun evict-one-dns-cache-entry (cache)
  "Remove the entry that expires first from a full CACHE. Caller holds its lock."
  (let ((victim nil) (expiry nil))
    (maphash (lambda (key entry)
               (when (or (null expiry) (< (dns-forward-cache-entry-expires-at entry) expiry))
                 (setf victim key expiry (dns-forward-cache-entry-expires-at entry))))
             (dns-forward-cache-entries cache))
    (when victim (remhash victim (dns-forward-cache-entries cache)))))

(defun cached-dns-forward (cache packet upstreams timeout forwarder &optional metrics)
  "Forward PACKET through FORWARDER, caching positive and authoritative negative responses."
  (let* ((key (dns-forward-cache-key packet))
         (now (funcall (dns-forward-cache-clock cache)))
         (query-id (0conf:dns-message-id (0conf:decode-message packet)))
         (hit nil))
    (bt:with-lock-held ((dns-forward-cache-lock cache))
      (let ((entry (gethash key (dns-forward-cache-entries cache))))
        (when entry
          (if (< now (dns-forward-cache-entry-expires-at entry))
              (setf hit (age-dns-response
                         (dns-forward-cache-entry-packet entry) query-id
                         (floor (- now (dns-forward-cache-entry-stored-at entry)))))
              (remhash key (dns-forward-cache-entries cache))))))
    (if hit
        (progn (when metrics (dns-metric-incf metrics (dns-metrics-cache metrics) "hit")) hit)
        (progn
          (when metrics (dns-metric-incf metrics (dns-metrics-cache metrics) "miss"))
          (let* ((started (get-internal-real-time))
                 (response
                   (handler-case
                       (prog1 (funcall forwarder packet upstreams timeout)
                         (when metrics (dns-metric-incf metrics (dns-metrics-forward metrics) "success")))
                     (error (condition)
                       (when metrics (dns-metric-incf metrics (dns-metrics-forward metrics) "error"))
                       (error condition))))
               (message (0conf:decode-message response))
               (ttl (dns-response-cache-ttl message)))
          (when metrics
            (bt:with-lock-held ((dns-metrics-lock metrics))
              (incf (dns-metrics-forward-duration metrics)
                    (/ (- (get-internal-real-time) started)
                       (coerce internal-time-units-per-second 'double-float)))
              (incf (dns-metrics-forward-duration-count metrics))))
          (when ttl
            (bt:with-lock-held ((dns-forward-cache-lock cache))
              (when (and (null (gethash key (dns-forward-cache-entries cache)))
                         (>= (hash-table-count (dns-forward-cache-entries cache))
                             (dns-forward-cache-maximum-entries cache)))
                (evict-one-dns-cache-entry cache))
              (setf (gethash key (dns-forward-cache-entries cache))
                    (make-dns-forward-cache-entry
                     :packet (copy-seq response) :stored-at now :expires-at (+ now ttl)))))
          response)))))

(defun dns-upstreams-for-packet (packet defaults rules)
  "Choose the longest matching conditional forwarding zone, or DEFAULTS."
  (let* ((message (0conf:decode-message packet))
         (question (first (0conf:dns-message-questions message)))
         (name (and question (canonical-dns-name (0conf:question-name question))))
         (best nil))
    (dolist (rule rules)
      (when (and name (dns-name-in-zone-p name (car rule))
                 (or (null best) (> (length (car rule)) (length (car best)))))
        (setf best rule)))
    (if best (cdr best) defaults)))

(defun call-dns-handler (server packet protocol)
  "Resolve one query and convert ordinary forwarding failures into SERVFAIL."
  (dns-metric-incf (dns-server-metrics server) (dns-metrics-queries (dns-server-metrics server))
                   (string-downcase (symbol-name protocol)))
  (let ((response
          (handler-case
              (answer-dns-query
       packet
       (lambda (query)
         (cached-dns-forward
          (dns-server-forward-cache server) query
          (dns-upstreams-for-packet query (dns-server-upstreams server)
                                    (dns-server-forward-rules server))
          (dns-server-timeout server)
          (ecase protocol
            (:udp (dns-server-udp-forwarder server))
            (:tcp (dns-server-tcp-forwarder server)))
          (dns-server-metrics server)))
       (dns-server-service-resolver server))
            (error (condition)
              (format *error-output* "gr8s DNS query failed: ~A~%" condition)
              (handler-case (dns-servfail-response packet)
                (error () nil))))))
    (when response
      (dns-metric-incf (dns-server-metrics server) (dns-metrics-responses (dns-server-metrics server))
                       (dns-rcode-name (dns-response-code response))))
    response))

(defun dns-udp-loop (server)
  "Receive and answer UDP queries until the DNS server stops."
  (loop until (dns-server-stop-requested server)
        do (when (sb-sys:wait-until-fd-usable
                  (sb-bsd-sockets:socket-file-descriptor
                   (dns-server-udp-socket server))
                  :input 0.1)
             (handler-case
               (multiple-value-bind (packet host port)
                   (receive-dns-datagram (dns-server-udp-socket server))
                 (unless (dns-server-stop-requested server)
                   (let ((response (call-dns-handler server packet :udp)))
                     (when response
                       (send-dns-datagram
                        (dns-server-udp-socket server) response host port)))))
             (error (condition)
               (unless (dns-server-stop-requested server)
                 (format *error-output* "gr8s DNS UDP error: ~A~%" condition)))))))

(defun read-dns-frame (stream)
  "Read a complete length-prefixed DNS message from a TCP stream."
  (let ((high (read-byte stream nil nil)))
    (when high
      (let* ((low (read-byte stream))
             (length (+ (ash high 8) low))
             (packet (make-array length :element-type '(unsigned-byte 8))))
        (unless (= length (read-sequence packet stream))
          (error "truncated DNS-over-TCP frame"))
        packet))))

(defun write-dns-frame (stream packet)
  "Write a length-prefixed DNS message to a TCP stream."
  (let ((length (length packet)))
    (when (> length #xffff)
      (error "DNS-over-TCP frame exceeds 65535 octets"))
    (write-byte (ldb (byte 8 8) length) stream)
    (write-byte (ldb (byte 8 0) length) stream)
    (write-sequence packet stream)
    (finish-output stream)))

(defun serve-dns-tcp-client (server socket)
  "Serve framed DNS queries on one accepted TCP client and close its socket."
  (let ((stream
          (sb-bsd-sockets:socket-make-stream
           socket :input t :output t
           :element-type '(unsigned-byte 8) :buffering :none)))
    (unwind-protect
         (let ((packet (read-dns-frame stream)))
           (when packet
             (let ((response (call-dns-handler server packet :tcp)))
               (when response (write-dns-frame stream response)))))
      (ignore-errors (close stream))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun dns-tcp-loop (server)
  "Accept DNS TCP clients and dispatch their connection handlers."
  (loop until (dns-server-stop-requested server)
        do (when (sb-sys:wait-until-fd-usable
                  (sb-bsd-sockets:socket-file-descriptor
                   (dns-server-tcp-socket server))
                  :input 0.1)
             (handler-case
               (let ((client
                       (sb-bsd-sockets:socket-accept
                        (dns-server-tcp-socket server))))
                 (if (dns-server-stop-requested server)
                     (sb-bsd-sockets:socket-close client)
                     (serve-dns-tcp-client server client)))
             (error (condition)
               (unless (dns-server-stop-requested server)
                 (format *error-output* "gr8s DNS TCP error: ~A~%" condition)))))))

(defun parse-resolv-conf-upstreams (stream)
  "Read usable IPv4 nameserver entries from a resolv.conf stream."
  (let ((upstreams nil))
    (loop for raw-line = (read-line stream nil nil)
          while raw-line
          for comment = (position #\# raw-line)
          for line = (if comment (subseq raw-line 0 comment) raw-line)
          for fields = (remove "" (uiop:split-string
                                    line :separator '(#\Space #\Tab))
                               :test #'string=)
          when (and (string-equal "nameserver" (first fields))
                    (second fields)
                    (find #\. (second fields)))
            do (handler-case
                   (progn
                     (0conf:parse-ipv4 (second fields))
                     (push (cons (second fields) 53) upstreams))
                 (error () nil)))
    (nreverse upstreams)))

(defun host-dns-upstreams (&optional (path "/etc/resolv.conf"))
  "Load the host resolver configuration for external DNS forwarding."
  (with-open-file (stream path :direction :input)
    (parse-resolv-conf-upstreams stream)))

(defun try-dns-upstreams (upstreams operation)
  "Try each upstream while containing network errors and both SBCL timeout conditions."
  (let ((last-error nil))
    (dolist (upstream upstreams)
      (handler-case
          (return-from try-dns-upstreams (funcall operation upstream))
        (sb-ext:timeout (condition)
          (setf last-error condition))
        (sb-sys:deadline-timeout (condition)
          (setf last-error condition))
        (error (condition)
          (setf last-error condition))))
    (error "all DNS upstreams failed~@[; last error: ~A~]" last-error)))

(defun forward-dns-udp (packet upstreams timeout)
  "Forward a DNS packet over UDP with a bounded receive timeout."
  (try-dns-upstreams
   upstreams
   (lambda (upstream)
     (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                                  :type :datagram :protocol :udp))
           (buffer (make-array #xffff :element-type '(unsigned-byte 8))))
       (unwind-protect
            (sb-ext:with-timeout timeout
              (sb-bsd-sockets:socket-connect
               socket (dns-socket-address (car upstream)) (cdr upstream))
              (sb-bsd-sockets:socket-send socket packet (length packet))
              (multiple-value-bind (ignored size)
                  (sb-bsd-sockets:socket-receive
                   socket buffer (length buffer))
                (declare (ignore ignored))
                (subseq buffer 0 size)))
         (sb-bsd-sockets:socket-close socket))))))

(defun forward-dns-tcp (packet upstreams timeout)
  "Forward a framed DNS packet over TCP with a bounded operation timeout."
  (try-dns-upstreams
   upstreams
   (lambda (upstream)
     (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                                  :type :stream :protocol :tcp))
           (stream nil))
       (unwind-protect
            (sb-ext:with-timeout timeout
              (sb-bsd-sockets:socket-connect
               socket (dns-socket-address (car upstream)) (cdr upstream))
              (setf stream
                    (sb-bsd-sockets:socket-make-stream
                     socket :input t :output t
                     :element-type '(unsigned-byte 8) :buffering :none))
              (write-dns-frame stream packet)
              (or (read-dns-frame stream)
                  (error "DNS upstream closed without a response")))
         (if stream
             (ignore-errors (close stream)))
         (ignore-errors (sb-bsd-sockets:socket-close socket)))))))

(defconstant +dns-ephemeral-bind-attempts+ 16)

(defun bind-dns-socket-pair (address port)
  "Return owned UDP/TCP listeners on one port; retry port 0 conflicts with complete cleanup."
  (let ((limit (if (zerop port) +dns-ephemeral-bind-attempts+ 1)))
    (loop for attempt from 1 to limit
          do (let ((udp nil) (tcp nil) (transferred nil))
               (unwind-protect
                    (handler-case
                        (let ((selected nil))
                          (setf udp (make-bound-dns-socket :datagram :udp address port)
                                selected (nth-value 1 (sb-bsd-sockets:socket-name udp))
                                tcp (make-bound-dns-socket :stream :tcp address selected))
                          (sb-bsd-sockets:socket-listen tcp 16)
                          (setf transferred t)
                          (return-from bind-dns-socket-pair (values udp tcp selected)))
                      (sb-bsd-sockets:address-in-use-error (condition)
                        (unless (and (zerop port) (< attempt limit)) (error condition))))
                 (unless transferred
                   (when tcp (ignore-errors (sb-bsd-sockets:socket-close tcp)))
                   (when udp (ignore-errors (sb-bsd-sockets:socket-close udp)))))))))

(defun start-dns-server
    (&key (address +dns-pod-server-address+) (port 53) upstreams
          (timeout 2.0) service-resolver forward-rules
          (forward-cache (make-dns-forward-cache))
          (metrics *dns-metrics*)
          (udp-forwarder #'forward-dns-udp)
          (tcp-forwarder #'forward-dns-tcp))
  "Bind owned UDP and TCP listeners and start the DNS worker threads."
  (multiple-value-bind (udp-socket tcp-socket selected-port) (bind-dns-socket-pair address port)
    (let ((server nil))
      (handler-case
          (progn
            (setf server
                  (%make-dns-server
                   :address address :port selected-port :upstreams upstreams :forward-rules forward-rules
                   :timeout timeout :service-resolver service-resolver :udp-forwarder udp-forwarder
                   :tcp-forwarder tcp-forwarder :forward-cache forward-cache :metrics metrics :udp-socket udp-socket
                   :tcp-socket tcp-socket))
            (setf (dns-server-udp-thread server)
                  (bt:make-thread (lambda () (dns-udp-loop server)) :name "gr8s DNS UDP")
                  (dns-server-tcp-thread server)
                  (bt:make-thread (lambda () (dns-tcp-loop server)) :name "gr8s DNS TCP"))
            server)
        (error (condition)
          (sb-bsd-sockets:socket-close tcp-socket)
          (sb-bsd-sockets:socket-close udp-socket)
          (error condition))))))

(defun join-dns-thread (thread)
  "Join a DNS worker thread when one was started."
  (when thread
    (bt:join-thread thread)))

(defun stop-dns-server (server)
  "Stop and join DNS workers before releasing their listening sockets."
  (setf (dns-server-stop-requested server) t)
  (join-dns-thread (dns-server-udp-thread server))
  (join-dns-thread (dns-server-tcp-thread server))
  (ignore-errors (sb-bsd-sockets:socket-close
                  (dns-server-udp-socket server)))
  (ignore-errors (sb-bsd-sockets:socket-close
                  (dns-server-tcp-socket server)))
  nil)

(defun call-with-dns-server
    (function &key
                (starter #'start-dns-server)
                (stopper #'stop-dns-server)
                (address +dns-pod-server-address+)
                (port 53)
                (upstreams (host-dns-upstreams)) service-resolver forward-rules)
  "Run a body with an owned DNS service and always stop it afterward."
  (let ((server (apply starter :address address :port port
                       :upstreams upstreams
                       (append (when service-resolver (list :service-resolver service-resolver))
                               (when forward-rules (list :forward-rules forward-rules))))))
    (unwind-protect
         (funcall function)
      (funcall stopper server))))
