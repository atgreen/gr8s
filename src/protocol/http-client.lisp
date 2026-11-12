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
                (if saw-octet (return) (error 'http-client-error :message "connection closed mid-response")))
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
        (error 'http-client-error :message "connection closed before the full response body")))
    buffer))

;;; ---------------------------------------------------------------------------
;;; Request / response framing

(defun write-request (stream method target host headers body)
  "Send one HTTP/1.1 request over STREAM, closing the connection after its response.
HEADERS is an alist of (name . value); Content-Length and Connection: close are
added here.  BODY is an octet vector."
  (write-sequence
   (trivial-utf-8:string-to-utf-8-bytes
    (with-output-to-string (out)
      (flet ((line (control &rest arguments)
               (format out "~?~C~C" control arguments #\Return #\Linefeed)))
        (line "~A ~A HTTP/1.1" (string-upcase (string method)) target)
        (line "Host: ~A" host)
        (loop for (name . value) in headers do (line "~A: ~A" name value))
        (when (plusp (length body)) (line "Content-Length: ~D" (length body)))
        (line "Connection: close")
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
transfer-encoding, or read-until-close, never exceeding LIMIT octets."
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
           (coerce body '(simple-array (unsigned-byte 8) (*)))))
        (length-text
         (let ((length (parse-integer length-text)))
           (when (> length limit) (too-large))
           (read-exactly stream length)))
        (t
         (let ((body (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
           (loop for octet = (read-byte stream nil nil)
                 while octet
                 do (when (>= (length body) limit) (too-large))
                    (vector-push-extend octet body))
           (coerce body '(simple-array (unsigned-byte 8) (*)))))))))

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

(defun attempt-request (host port server-name host-header method target headers body
                        trust-certificates auto-load-system-ca insecure client-certificate client-key
                        timeout body-limit context)
  "One connect/handshake/exchange.  Returns (values code headers body-octets).

The exchange runs under a cl-cancel timeout context derived from CONTEXT, so it is
bounded by TIMEOUT and also ends the moment an outer CONTEXT is cancelled.  A
monitor force-closes the socket when that context is done, interrupting a read
stuck on a hung peer; the resulting stream error is reported as the deadline /
cancellation it is.  Closing the raw socket rather than the TLS stream avoids a
close-notify write that could itself block past the deadline."
  (let ((socket nil)
        (pure-tls:*session-ticket-cache* (make-hash-table :test 'equal)))
    (unwind-protect
         (cl-cancel:with-timeout-context
             (context timeout (cl-cancel:ensure-cancellable context))
           (setf socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                           :timeout timeout :nodelay t))
           (let ((monitor (cl-cancel:close-stream-on-cancel (usocket:socket-stream socket) context)))
             (unwind-protect
                  (handler-bind ((error (lambda (condition)
                                          (declare (ignore condition))
                                          (when (cl-cancel:done-p context)
                                            (cl-cancel:check-cancellation context)))))
                    (let ((stream (pure-tls:make-tls-client-stream
                                   (usocket:socket-stream socket)
                                   :hostname server-name
                                   :context (make-client-context trust-certificates auto-load-system-ca insecure)
                                   :verify (if insecure pure-tls:+verify-none+ pure-tls:+verify-required+)
                                   :client-certificate (and client-certificate (namestring client-certificate))
                                   :client-key (and client-key (namestring client-key)))))
                      (write-request stream method target
                                     (or host-header (format nil "~A:~D" server-name port))
                                     headers (or body #()))
                      (multiple-value-bind (code response-headers) (read-response-head stream)
                        (values code response-headers
                                (if (or (eq method :head) (member code '(204 304)))
                                    (make-array 0 :element-type '(unsigned-byte 8))
                                    (read-response-body stream response-headers :limit body-limit))))))
               (funcall monitor))))
      (when socket (ignore-errors (usocket:socket-close socket))))))

(defun https-request (&key host port server-name host-header (method :get) target headers body
                           trust-certificates (auto-load-system-ca nil) (insecure nil)
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
endpoint that opts out, e.g. insecureSkipTLSVerify).  The exchange is bounded by
TIMEOUT seconds, tightened by any deadline on CONTEXT, and an already-cancelled
CONTEXT aborts it.  On a transport-transient failure up to MAX-ATTEMPTS are made,
RETRY-INTERVAL seconds apart; HTTP status codes are returned, never retried."
  (loop with attempt = 0
        do (incf attempt)
           (handler-case
               (return (attempt-request host port server-name host-header method target headers body
                                        trust-certificates auto-load-system-ca insecure
                                        client-certificate client-key timeout body-limit context))
             (error (condition)
               (if (and (< attempt max-attempts) (retryable-p condition))
                   (when (plusp retry-interval) (cl-cancel:sleep-fractional retry-interval))
                   (error condition))))))
