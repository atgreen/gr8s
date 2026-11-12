;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; One outbound HTTP/1.1-over-TLS client for the trust-sensitive request/response
;;;; paths (admission webhooks, the PKI and in-cluster API clients, aggregated-API
;;;; fetches).  It replaces several hand-rolled copies that each re-implemented the
;;;; same socket connect, pure-tls handshake, request framing and response parsing.
;;;;
;;;; The non-obvious properties it centralises:
;;;;
;;;;   * A fresh per-call pure-tls session-ticket cache.  pure-tls trusts a resumed
;;;;     session without re-checking the certificate chain, so a shared cache would
;;;;     let one caller's trust bundle vouch for another connection to the same host.
;;;;
;;;;   * A connect address that differs from the verified name.  Webhooks and the
;;;;     API aggregator dial a resolved endpoint but must verify against, and send
;;;;     SNI/Host for, the service name -- so HOST (dial) and SERVER-NAME (verify)
;;;;     are independent arguments.
;;;;
;;;;   * Cancellation and deadlines via cl-cancel: the request runs under a timeout
;;;;     context derived from the caller's context, and a monitor force-closes the
;;;;     socket when that context is done, unblocking a read stuck on a hung peer.
;;;;     Closing the raw socket (not the TLS stream) avoids a close-notify write
;;;;     that could itself block after the deadline has passed.
;;;;
;;;;   * Bounded retry on transport-transient failures (connection refused/reset,
;;;;     premature EOF).  Off by default (MAX-ATTEMPTS 1); honest HTTP status codes
;;;;     are never retried -- that is the caller's failure policy.

(defpackage #:gr8s.http-client
  (:use #:cl)
  (:export #:https-request
           #:http-client-error
           #:http-client-error-message
           #:http-response-too-large
           #:+default-response-limit+))

(in-package #:gr8s.http-client)

(define-condition http-client-error (error)
  ((message :initarg :message :reader http-client-error-message))
  (:report (lambda (condition stream)
             (write-string (http-client-error-message condition) stream))))

(define-condition http-response-too-large (http-client-error) ())

(define-condition http-connection-closed (http-client-error) ()
  (:documentation "The peer closed the connection before (or during) its response.
A fresh connection may succeed, so a pooled connection failing this way is replaced
rather than treated as a request error."))

(defparameter +default-response-limit+ (* 16 1024 1024)
  "Default ceiling on a response body, in octets.")

;;; ---------------------------------------------------------------------------
;;; Wire reading primitives

(defun read-crlf-line (stream)
  "Read one CRLF-terminated line from STREAM, returning it without the terminator.
A lone LF is tolerated; end of stream before any octet signals an error."
  (let ((line (make-array 64 :element-type 'character :adjustable t :fill-pointer 0))
        (saw-octet nil))
    (loop for byte = (read-byte stream nil nil)
          do (cond
               ((null byte)
                (if saw-octet (return) (error 'http-connection-closed :message "connection closed mid-response")))
               ((= byte 13))                      ; CR -- swallow, the LF ends the line
               ((= byte 10) (return))             ; LF -- end of line
               (t (setf saw-octet t)
                  (vector-push-extend (code-char byte) line))))
    (coerce line 'simple-string)))

(defun read-exactly (stream count)
  "Read exactly COUNT octets from STREAM or signal an error."
  (let ((buffer (make-array count :element-type '(unsigned-byte 8))))
    (let ((got (read-sequence buffer stream)))
      (unless (= got count)
        (error 'http-connection-closed :message "connection closed before the full response body")))
    buffer))

;;; ---------------------------------------------------------------------------
;;; Request / response framing

(defun write-request (stream method target host headers body &optional keep-alive)
  "Send one HTTP/1.1 request over STREAM.  HEADERS is an alist of (name . value);
Content-Length is added here, and Connection is keep-alive or close per KEEP-ALIVE.
BODY is an octet vector."
  (write-sequence
   (trivial-utf-8:string-to-utf-8-bytes
    (with-output-to-string (out)
      (flet ((line (control &rest arguments)
               (format out "~?~C~C" control arguments #\Return #\Linefeed)))
        (line "~A ~A HTTP/1.1" (string-upcase (string method)) target)
        (line "Host: ~A" host)
        (loop for (name . value) in headers do (line "~A: ~A" name value))
        (when (plusp (length body)) (line "Content-Length: ~D" (length body)))
        (line "Connection: ~A" (if keep-alive "keep-alive" "close"))
        (line ""))))
   stream)
  (when (plusp (length body)) (write-sequence body stream))
  (force-output stream))

(defun read-response-head (stream)
  "Read a response status line and headers, returning the status code and a
lowercase-keyed alist of headers."
  (let* ((status-line (read-crlf-line stream))
         (space (position #\Space status-line))
         (code (or (and space (parse-integer status-line :start (1+ space) :junk-allowed t))
                   (error 'http-client-error :message "malformed HTTP status line"))))
    (values code
            (loop for line = (read-crlf-line stream)
                  until (zerop (length line))
                  for colon = (position #\: line)
                  when colon
                    collect (cons (string-downcase (subseq line 0 colon))
                                  (string-trim '(#\Space #\Tab) (subseq line (1+ colon))))))))

(defun read-response-body (stream headers &key (limit +default-response-limit+))
  "Read the body following HEADERS from STREAM, honouring Content-Length, chunked
transfer-encoding, or read-until-close, never exceeding LIMIT octets.  Returns
(values body framed-p), where FRAMED-P is true when the body's end was known from
a Content-Length or chunked framing -- the precondition for reusing the
connection; a read-until-close body leaves the connection spent."
  (let ((length-text (cdr (assoc "content-length" headers :test #'string=)))
        (chunked (search "chunked"
                         (string-downcase (or (cdr (assoc "transfer-encoding" headers :test #'string=)) "")))))
    (flet ((too-large ()
             (error 'http-response-too-large :message "HTTP response is too large")))
      (cond
        (chunked
         (let ((body (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
           (loop
             (let* ((line (read-crlf-line stream))
                    (size (parse-integer line :end (or (position #\; line) (length line)) :radix 16)))
               (when (zerop size)
                 (loop until (zerop (length (read-crlf-line stream))))
                 (return))
               (when (> (+ size (length body)) limit) (too-large))
               (loop for octet across (read-exactly stream size) do (vector-push-extend octet body))
               (read-crlf-line stream)))
           (values (coerce body '(simple-array (unsigned-byte 8) (*))) t)))
        (length-text
         (let ((length (parse-integer length-text)))
           (when (> length limit) (too-large))
           (values (read-exactly stream length) t)))
        (t
         (let ((body (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
           (loop for octet = (read-byte stream nil nil)
                 while octet
                 do (when (>= (length body) limit) (too-large))
                    (vector-push-extend octet body))
           (values (coerce body '(simple-array (unsigned-byte 8) (*))) nil)))))))

;;; ---------------------------------------------------------------------------
;;; TLS context

(defun make-client-context (trust-certificates auto-load-system-ca insecure)
  "A pure-tls client context.  INSECURE skips verification entirely (for an
endpoint that opts out of TLS verification, e.g. an APIService with
insecureSkipTLSVerify).  Otherwise the chain is verified against exactly
TRUST-CERTIFICATES, or the system roots when AUTO-LOAD-SYSTEM-CA and no
certificates are given."
  (if insecure
      (pure-tls:make-tls-context :verify-mode pure-tls:+verify-none+ :auto-load-system-ca nil)
      (let ((context (pure-tls:make-tls-context
                      :verify-mode pure-tls:+verify-required+
                      :auto-load-system-ca (and auto-load-system-ca (null trust-certificates)))))
        (when trust-certificates
          (setf (pure-tls::tls-context-trust-store context)
                (pure-tls::make-trust-store :certificates trust-certificates)))
        context)))

;;; ---------------------------------------------------------------------------
;;; The client

(defparameter *retryable-conditions*
  '(usocket:connection-refused-error usocket:connection-reset-error
    usocket:timeout-error end-of-file)
  "Transport-transient failures worth retrying within the deadline.  Honest HTTP
status codes are never here -- a 5xx is the caller's failure policy, not ours.")

(defun retryable-p (condition)
  (some (lambda (type) (typep condition type)) *retryable-conditions*))

;;; ---------------------------------------------------------------------------
;;; Connection pool (opt-in keep-alive reuse)
;;;
;;; A pooled connection is only ever handed back to a request with the identical
;;; dial target, verified name, TLS trust and client identity: the pool key
;;; captures each of those, so reuse can never cross a trust boundary.

(defstruct (pooled-connection (:constructor %make-pooled-connection))
  socket stream key (idle-since (get-internal-real-time)))

(defvar *connection-pool* (make-hash-table :test 'equal)
  "Pool key -> list of idle POOLED-CONNECTIONs.")
(defvar *connection-pool-lock* (bt:make-lock "gr8s http-client pool"))
(defparameter *max-idle-per-key* 8
  "Idle connections kept per distinct endpoint/trust key.")
(defparameter *idle-timeout-seconds* 90
  "An idle pooled connection older than this is discarded rather than reused.")

(defun trust-fingerprint (trust-certificates auto-load-system-ca insecure)
  "A stable key component for the TLS trust: :INSECURE, :SYSTEM, :NONE, or a digest
of the trusted certificates.  Distinct trust must never share a pooled connection."
  (cond (insecure :insecure)
        ((null trust-certificates) (if auto-load-system-ca :system :none))
        (t (ironclad:byte-array-to-hex-string
            (ironclad:digest-sequence
             :sha256
             (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
                    (mapcar #'pure-tls::x509-certificate-raw-der trust-certificates)))))))

(defun connection-key (host port server-name insecure trust-certificates auto-load-system-ca
                       client-certificate client-key)
  (list host port server-name (and insecure t)
        (and client-certificate (namestring client-certificate))
        (and client-key (namestring client-key))
        (trust-fingerprint trust-certificates auto-load-system-ca insecure)))

(defun close-pooled (conn)
  (ignore-errors (usocket:socket-close (pooled-connection-socket conn))))

(defun pool-checkout (key)
  "Take an idle, not-timed-out connection for KEY, or NIL; close any timed-out ones
passed over."
  (bt:with-lock-held (*connection-pool-lock*)
    (loop for conn = (pop (gethash key *connection-pool*))
          while conn
          do (if (< (- (get-internal-real-time) (pooled-connection-idle-since conn))
                    (* *idle-timeout-seconds* internal-time-units-per-second))
                 (return conn)
                 (close-pooled conn)))))

(defun pool-checkin (conn)
  "Return CONN to the pool, or close it if its key's pool is full."
  (setf (pooled-connection-idle-since conn) (get-internal-real-time))
  (let ((closep nil))
    (bt:with-lock-held (*connection-pool-lock*)
      (if (< (length (gethash (pooled-connection-key conn) *connection-pool*)) *max-idle-per-key*)
          (push conn (gethash (pooled-connection-key conn) *connection-pool*))
          (setf closep t)))
    (when closep (close-pooled conn))))

(defun open-connection (host port server-name insecure trust-certificates auto-load-system-ca
                        client-certificate client-key connect-timeout)
  "Dial HOST:PORT and complete the TLS handshake; return (values socket stream).
A fresh session-ticket cache per connection keeps one request's trust from
vouching for another's resumed session to the same host."
  (let ((pure-tls:*session-ticket-cache* (make-hash-table :test 'equal))
        (socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                   :timeout connect-timeout :nodelay t)))
    (handler-case
        (values socket
                (pure-tls:make-tls-client-stream
                 (usocket:socket-stream socket)
                 :hostname server-name
                 :context (make-client-context trust-certificates auto-load-system-ca insecure)
                 :verify (if insecure pure-tls:+verify-none+ pure-tls:+verify-required+)
                 :client-certificate (and client-certificate (namestring client-certificate))
                 :client-key (and client-key (namestring client-key))))
      (error (condition)
        (ignore-errors (usocket:socket-close socket))
        (error condition)))))

(defun exchange (socket stream method target host-header headers body body-limit keep-alive
                 context timeout)
  "Write one request and read its response over the existing STREAM, bounded by a
cl-cancel timeout derived from CONTEXT, whose monitor force-closes the socket on a
deadline or cancellation.  Returns (values code response-headers body-octets
reusable-p); REUSABLE-P is true only when the connection may be pooled afterwards
-- a kept-alive, framed response the server did not mark Connection: close."
  (cl-cancel:with-timeout-context (ctx timeout (cl-cancel:ensure-cancellable context))
    (let ((monitor (cl-cancel:close-stream-on-cancel (usocket:socket-stream socket) ctx)))
      (unwind-protect
           (handler-bind ((error (lambda (condition)
                                   (declare (ignore condition))
                                   (when (cl-cancel:done-p ctx)
                                     (cl-cancel:check-cancellation ctx)))))
             (write-request stream method target host-header headers (or body #()) keep-alive)
             (multiple-value-bind (code response-headers) (read-response-head stream)
               (multiple-value-bind (body framed)
                   (if (or (eq method :head) (member code '(204 304)))
                       (values (make-array 0 :element-type '(unsigned-byte 8)) t)
                       (read-response-body stream response-headers :limit body-limit))
                 (values code response-headers body
                         (and keep-alive framed
                              (not (search "close"
                                           (string-downcase
                                            (or (cdr (assoc "connection" response-headers :test #'string=))
                                                "")))))))))
        (funcall monitor)))))

(defun stale-connection-p (condition)
  "A pooled connection failing this way is dead -- the request should be retried on
a fresh one.  A deadline or cancellation is not here, so it propagates instead."
  (or (retryable-p condition)
      (typep condition 'stream-error)
      (typep condition 'http-connection-closed)))

(defun attempt-request (host port server-name host-header method target headers body
                        trust-certificates auto-load-system-ca insecure client-certificate client-key
                        timeout body-limit context reuse)
  "One request/response, returning (values code headers body-octets).  With REUSE, a
keep-alive connection is taken from the pool when one waits and returned to it when
the response leaves it reusable; otherwise the connection is closed afterwards."
  (let ((host-header (or host-header (format nil "~A:~D" server-name port)))
        (key (and reuse (connection-key host port server-name insecure trust-certificates
                                        auto-load-system-ca client-certificate client-key))))
    ;; 1. Reuse a waiting connection, discarding any that proves dead.
    (when reuse
      (loop for pooled = (pool-checkout key) while pooled do
        (handler-case
            (multiple-value-bind (code headers body reusable)
                (exchange (pooled-connection-socket pooled) (pooled-connection-stream pooled)
                          method target host-header headers body body-limit t context timeout)
              (if reusable (pool-checkin pooled) (close-pooled pooled))
              (return-from attempt-request (values code headers body)))
          (error (condition)
            (close-pooled pooled)
            (unless (stale-connection-p condition) (error condition))))))
    ;; 2. A fresh connection; pooled on success when REUSE and the response allows.
    (multiple-value-bind (socket stream)
        (open-connection host port server-name insecure trust-certificates auto-load-system-ca
                         client-certificate client-key timeout)
      (let ((keep nil))
        (unwind-protect
             (multiple-value-bind (code headers body reusable)
                 (exchange socket stream method target host-header headers body body-limit reuse
                           context timeout)
               (when (and reuse reusable)
                 (pool-checkin (%make-pooled-connection :socket socket :stream stream :key key))
                 (setf keep t))
               (return-from attempt-request (values code headers body)))
          (unless keep (ignore-errors (usocket:socket-close socket))))))))

(defun https-request (&key host port server-name host-header (method :get) target headers body
                           trust-certificates (auto-load-system-ca nil) (insecure nil) (reuse nil)
                           client-certificate client-key
                           (timeout 10) (max-attempts 1) (retry-interval 1)
                           (body-limit +default-response-limit+)
                           (context cl-cancel:*current-cancel-context*))
  "Send one HTTP/1.1 request to HOST:PORT over TLS, verifying the chain against
TRUST-CERTIFICATES (or the system roots when AUTO-LOAD-SYSTEM-CA) for SERVER-NAME,
and return (values status-code response-headers body-octets).

HOST is dialed; SERVER-NAME is what the certificate must match and what SNI/Host
carry (HOST-HEADER overrides the Host line).  METHOD is a keyword; HEADERS an alist;
BODY an octet vector.  INSECURE skips certificate verification entirely (for an
endpoint that opts out, e.g. insecureSkipTLSVerify).  REUSE keeps the connection
alive and pools it for the next request with the identical endpoint, trust and
client identity (a stale pooled connection is transparently replaced).  The
exchange is bounded by TIMEOUT seconds, tightened by any deadline on CONTEXT, and
an already-cancelled CONTEXT aborts it.  On a transport-transient failure up to
MAX-ATTEMPTS are made, RETRY-INTERVAL seconds apart; HTTP status codes are
returned, never retried."
  (loop with attempt = 0
        do (incf attempt)
           (handler-case
               (return (attempt-request host port server-name host-header method target headers body
                                        trust-certificates auto-load-system-ca insecure
                                        client-certificate client-key timeout body-limit context reuse))
             (error (condition)
               (if (and (< attempt max-attempts) (retryable-p condition))
                   (when (plusp retry-interval) (cl-cancel:sleep-fractional retry-interval))
                   (error condition))))))
