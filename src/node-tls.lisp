;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Mutually authenticated TLS for node-to-control-plane sessions.
;;;;
;;;; Node agents reach the control plane over HTTP/2 gRPC, and both ends must
;;;; prove who they are before any application data -- including a bootstrap join
;;;; token -- crosses the wire. The client verifies the server's leaf against the
;;;; pinned cluster CA (by fingerprint during bootstrap, or by a CA file once
;;;; enrolled) and requires an "h2" ALPN; the server requests a client
;;;; certificate only optionally, so credential-less enrollment shares the
;;;; listener while authenticated calls can still demand a verified, name-bound
;;;; node cert. A handshake deadline keeps a stalled peer from tying up or killing
;;;; the listener, and a per-connection session-ticket cache stops a bootstrap
;;;; ticket from resuming a later authenticated session.

(in-package #:gr8s)

(defun node-server-tls-options (pki)
  "Return the TLS listener options for the node server when PKI is present, NIL
   otherwise: the server certificate and key, optional client-certificate
   verification -- so credential-less enrollment and authenticated calls share
   one listener -- and a trust store holding the cluster CA."
  (when pki
    (multiple-value-bind (certificate key) (ensure-node-server-credentials pki)
      (list :tls t :tls-certificate (namestring certificate) :tls-key (namestring key)
            ;; Enrollment shares this listener and has no certificate yet.
            ;; Connect additionally requires a verified, name-bound peer cert.
            :tls-verify-client :optional
            :tls-ca-certificate
            (pure-tls::make-trust-store :certificates (list (cluster-pki-ca-certificate pki)))))))

(defun authenticate-node-server-stream (stream ca-pin ca-certificate-path)
  "Verify, from the client side, that STREAM's peer presented the pinned cluster
   CA and a valid server leaf. The CA comes from CA-CERTIFICATE-PATH, or is the
   peer chain's CA whose fingerprint matches CA-PIN. Signals a PKI failure when
   no trusted CA is found, the pin mismatches, the leaf fails verification, or the
   peer did not negotiate HTTP/2."
  (let* ((chain (pure-tls:tls-peer-certificate-chain stream))
         (leaf (first chain))
         (ca (if ca-certificate-path
                 (first (pure-tls:load-certificate-chain ca-certificate-path))
                 (find-if
                  (lambda (certificate)
                    (and (pure-tls::certificate-is-ca-p certificate)
                         (string-equal ca-pin
                                       (octets-to-hex (pure-tls:certificate-fingerprint certificate)))))
                  chain))))
    (unless (and leaf ca (or ca-pin ca-certificate-path))
      (pki-fail "untrusted-server" "Server did not present the pinned cluster CA"))
    (when (and ca-pin
               (not (string-equal ca-pin (octets-to-hex (pure-tls:certificate-fingerprint ca)))))
      (pki-fail "ca-pin-mismatch" "Server CA fingerprint does not match"))
    (verify-node-server-certificate leaf ca)
    (unless (equal "h2" (pure-tls:tls-selected-alpn stream))
      (pki-fail "invalid-server-protocol" "Node server did not negotiate HTTP/2"))))

(defun %make-node-tls-channel
    (host port &key (timeout 10) ca-pin ca-certificate-path certificate-path private-key-path)
  "Authenticate the server before sending HTTP/2 data, including join tokens."
  (unless (or ca-pin ca-certificate-path)
    (pki-fail "missing-server-trust" "A cluster CA pin or certificate is required"))
  (let ((socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                       :timeout timeout))
        (tls nil))
    (handler-case
        (progn
          ;; During bootstrap only the root fingerprint is known. TLS verifies
          ;; CertificateVerify; we then verify chain, purpose, role and pin
          ;; before starting HTTP/2. No application credentials precede this.
          (setf tls (pure-tls:make-tls-client-stream
                     (usocket:socket-stream socket)
                     :sni-hostname +node-server-common-name+
                     :verify pure-tls:+verify-none+ :alpn-protocols '("h2")
                     :client-certificate (when certificate-path (namestring certificate-path))
                     :client-key (when private-key-path (namestring private-key-path))))
          (authenticate-node-server-stream tls ca-pin ca-certificate-path)
          (let* ((connection (make-instance 'ag-http2:http2-connection
                                           :socket socket :stream tls :tls-p t :client-p t))
                 (channel (ag-grpc:make-channel host port :connect nil :tls t :timeout timeout)))
            (setf (ag-http2:connection-multiplexer connection)
                  (ag-http2::make-stream-multiplexer :client-p t))
            (ag-http2::connection-handshake connection)
            (setf (ag-grpc:channel-connection channel) connection)
            channel))
      (error (condition)
        (when tls (ignore-errors (close tls)))
        (ignore-errors (usocket:socket-close socket))
        (error condition)))))

(defparameter *tls-handshake-seconds* 10
  "How long a listener lets a client negotiate TLS before dropping its connection.")

(define-condition tls-handshake-timeout (error)
  ((seconds :initarg :seconds :reader tls-handshake-timeout-seconds))
  (:report (lambda (condition stream)
             (format stream "TLS negotiation did not finish within ~A seconds"
                     (tls-handshake-timeout-seconds condition))))
  (:documentation "A peer took too long to negotiate TLS. Unlike SB-SYS:DEADLINE-TIMEOUT, which
is a SERIOUS-CONDITION, it is an ERROR, so connection handlers that catch errors drop the
connection instead of letting the condition kill the process."))

(defmacro with-tls-handshake-deadline ((seconds) &body body)
  "Run BODY, a TLS negotiation, signalling TLS-HANDSHAKE-TIMEOUT after SECONDS.
Hunchentoot logs and drops a connection whose setup signals an ERROR, but nothing
catches a bare deadline: one client that stalled its handshake for ten seconds
ended the whole server (podster-uqb.138 focused run, 117b50c)."
  (let ((limit (gensym "SECONDS")))
    `(let ((,limit ,seconds))
       (handler-case (sb-sys:with-deadline (:seconds ,limit) ,@body)
         (sb-sys:deadline-timeout ()
           (error 'tls-handshake-timeout :seconds ,limit))))))

(defun make-node-tls-channel (host port &rest options &key timeout &allow-other-keys)
  "Open an authenticated gRPC channel to HOST:PORT, bounding the whole TLS and
   HTTP/2 negotiation by TIMEOUT seconds (default 10) -- a socket-connect timeout
   alone does not. Uses a fresh per-call session-ticket cache so a bootstrap
   ticket can never resume a later authenticated node session. OPTIONS pass
   through to the underlying connector."
  ;; Socket connect timeouts alone do not bound TLS and HTTP/2 negotiation.
  ;; Every connection must present both identities. In particular a bootstrap
  ;; ticket must never resume a subsequent authenticated node session.
  (let ((pure-tls:*session-ticket-cache* (make-hash-table :test #'equal)))
    (with-tls-handshake-deadline ((or timeout 10))
      (apply #'%make-node-tls-channel host port options))))

(defun authenticate-node-peer (pki context node-name)
  "Server-side check that a persistent node session presented a client
   certificate valid for NODE-NAME, verified against PKI. A no-op when PKI is NIL.
   Signals a PKI failure when the peer offered no certificate."
  (when pki
    (let* ((connection (ag-grpc::context-connection context))
           (stream (ag-http2:connection-stream connection))
           (certificate (and (typep stream 'pure-tls::tls-stream)
                             (pure-tls:tls-peer-certificate stream))))
      (unless certificate
        (pki-fail "unauthenticated-node" "Persistent node sessions require a client certificate"))
      (verify-node-certificate
       pki (pure-tls/acme::wrap-pem "CERTIFICATE" (pure-tls::x509-certificate-raw-der certificate))
       node-name))))
