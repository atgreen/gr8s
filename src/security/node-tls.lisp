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

(in-package #:gr8s.security)

(defun wireguard-private-key-path (state-directory)
  "Return the node-local WireGuard private-key path below STATE-DIRECTORY."
  (merge-pathnames "wireguard.key"
                   (uiop:ensure-directory-pathname state-directory)))

(defun wireguard-public-key (private-key)
  "Derive the 32-byte Curve25519 public key WireGuard uses for PRIVATE-KEY."
  (unless (= 32 (length private-key))
    (error "WireGuard private keys must contain exactly 32 bytes"))
  (getf (ironclad:destructure-private-key
         (ironclad:make-private-key :curve25519 :x private-key))
        :y))

(defun decode-wireguard-private-key (text path)
  "Decode one canonical base64 WireGuard private key from TEXT, naming PATH on error."
  (handler-case
      (let* ((encoded (string-trim '(#\Space #\Tab #\Newline #\Return) text))
             (private-key (ag-grpc:base64-decode encoded)))
        (unless (and (= 32 (length private-key))
                     (string= encoded (ag-grpc:base64-encode private-key)))
          (error "not one canonical 32-byte key"))
        private-key)
    (error (condition)
      (error "Invalid WireGuard private key in ~A: ~A" path condition))))

(defun write-wireguard-key-pair (state-directory)
  "Generate and atomically persist a new node-local WireGuard key pair."
  (multiple-value-bind (private-object public-object)
      (ironclad:generate-key-pair :curve25519)
    (let* ((private-key (getf (ironclad:destructure-private-key private-object) :x))
           (public-key (getf (ironclad:destructure-public-key public-object) :y))
           (path (wireguard-private-key-path state-directory)))
      (write-private-text-atomically
       path (format nil "~A~%" (ag-grpc:base64-encode private-key)))
      (values private-key public-key))))

(defun ensure-wireguard-key-pair (state-directory)
  "Return this node's durable WireGuard private and public keys.

Create the key on first use. Existing malformed key material is rejected rather
than silently replacing the node's authenticated network identity."
  (let ((path (wireguard-private-key-path state-directory)))
    (if (probe-file path)
        (let ((private-key
                (decode-wireguard-private-key (uiop:read-file-string path) path)))
          (sb-posix:chmod (namestring path) #o600)
          (values private-key (wireguard-public-key private-key)))
        (write-wireguard-key-pair state-directory))))

(defun rotate-wireguard-key-pair (state-directory)
  "Explicitly replace this node's durable WireGuard key pair and return it."
  (write-wireguard-key-pair state-directory))

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
            (pure-tls::make-trust-store :certificates (cluster-pki-trust-certificates pki))))))

(defun authenticate-node-server-stream (stream ca-pin ca-certificate-path)
  "Verify, from the client side, that STREAM's peer presented the pinned cluster
   CA and a valid server leaf. The CA comes from CA-CERTIFICATE-PATH, or is the
   peer chain's CA whose fingerprint matches CA-PIN. Signals a PKI failure when
   no trusted CA is found, the pin mismatches, the leaf fails verification, or the
   peer did not negotiate HTTP/2."
  (let* ((chain (pure-tls:tls-peer-certificate-chain stream))
         (leaf (first chain))
         (ca (if ca-certificate-path
                 (pure-tls:load-certificate-chain ca-certificate-path)
                 (find-if
                  (lambda (certificate)
                    (and (pure-tls::certificate-is-ca-p certificate)
                         (string-equal ca-pin
                                       (octets-to-hex (pure-tls:certificate-fingerprint certificate)))))
                  chain))))
    (unless (and leaf ca (or ca-pin ca-certificate-path))
      (pki-fail "untrusted-server" "Server did not present the pinned cluster CA"))
    (when (and ca-pin (not ca-certificate-path)
               (not (string-equal ca-pin (octets-to-hex (pure-tls:certificate-fingerprint ca)))))
      (pki-fail "ca-pin-mismatch" "Server CA fingerprint does not match"))
    (verify-node-server-certificate leaf ca)
    (unless (equal "h2" (pure-tls:tls-selected-alpn stream))
      (pki-fail "invalid-server-protocol" "Node server did not negotiate HTTP/2"))))

(defparameter +node-channel-dead-peer-timeout-seconds+ 15
  "How long a node/member channel may carry unacknowledged data before the
kernel declares the peer dead. A suspended or parted peer otherwise leaves
heartbeats buffering locally for minutes before EOF surfaces: after a laptop
resume the agent kept writing into a dead session for 2m22s and the node sat
NotReady the whole time (podster-ao6).")

(defun harden-node-channel-socket (socket)
  "Bound dead-peer detection on SOCKET with TCP_USER_TIMEOUT (unacknowledged
sends) and keep-alive probes (a fully idle direction). Best-effort: an
unsupported option never blocks the connection."
  (ignore-errors
    (let ((fd (sb-bsd-sockets:socket-file-descriptor (usocket:socket socket))))
      (cffi:with-foreign-object (value :int)
        (flet ((set-option (level option option-value)
                 (setf (cffi:mem-ref value :int) option-value)
                 (cffi:foreign-funcall "setsockopt" :int fd :int level :int option
                                       :pointer value :unsigned-int 4 :int)))
          (set-option 1 9 1)   ; SOL_SOCKET SO_KEEPALIVE
          (set-option 6 18 (* 1000 +node-channel-dead-peer-timeout-seconds+)) ; SOL_TCP TCP_USER_TIMEOUT (ms)
          (set-option 6 4 5)   ; TCP_KEEPIDLE: probe an idle connection after 5s
          (set-option 6 5 5)   ; TCP_KEEPINTVL: every 5s
          (set-option 6 6 3))))) ; TCP_KEEPCNT: dead after 3 missed probes
  socket)

(defun %make-node-tls-channel
    (host port &key (timeout 10) (read-timeout nil read-timeout-p)
                    ca-pin ca-certificate-path certificate-path private-key-path)
  "Authenticate the server before sending HTTP/2 data, including join tokens.
READ-TIMEOUT, when given, replaces TIMEOUT as the limit on each read from the
socket once the channel is up, for a caller whose calls carry deadlines of
their own: the socket's limit would otherwise end a call that was allowed
longer."
  (unless (or ca-pin ca-certificate-path)
    (pki-fail "missing-server-trust" "A cluster CA pin or certificate is required"))
  ;; TIMEOUT is NIL for a long-lived session, whose reads must not time out. The
  ;; connect still must: an address that drops SYNs -- a firewalled member, or a
  ;; witness that has no node listener -- otherwise holds the caller for the
  ;; kernel's two-minute connect timeout before it can try another member.
  (let ((socket (harden-node-channel-socket
                 (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                         :timeout (or timeout 10))))
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
            ;; usocket gave TIMEOUT to the stream as well as to the connect.
            (when read-timeout-p
              (setf (sb-impl::fd-stream-timeout (usocket:socket-stream socket))
                    (and read-timeout (coerce read-timeout 'single-float))))
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
ended the whole server (podster-uqb.138 focused run, 117b50c).

An error in BODY is signalled again only after the deadline is out of force. A
handler further out runs before the stack unwinds, so it ran under the deadline;
if that had already passed, the handler's first wait -- Hunchentoot takes a lock
to log the error -- signalled the bare deadline from where nothing here could
catch it. A server stopped for longer than SECONDS (a paused virtual machine, a
suspended laptop, SIGSTOP) with a handshake in flight exited when it resumed."
  (let ((limit (gensym "SECONDS")) (results (gensym "RESULTS")) (failure (gensym "FAILURE")))
    `(let ((,limit ,seconds))
       (multiple-value-bind (,results ,failure)
           (handler-case (multiple-value-list (sb-sys:with-deadline (:seconds ,limit) ,@body))
             (sb-sys:deadline-timeout ()
               (values nil (make-condition 'tls-handshake-timeout :seconds ,limit)))
             (error (condition) (values nil condition)))
         (when ,failure (error ,failure))
         (values-list ,results)))))

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
       node-name)
      certificate)))
