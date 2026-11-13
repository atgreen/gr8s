(in-package #:gr8s/tests)

(in-suite gr8s)

(test kubernetes-api-addresses-cover-all-local-ipv4-plus-stable-addresses
  ;; podster-1v6: the API serving certificate must cover every local IPv4 address
  ;; (as k0s does), so a kubeconfig pointed at any local interface still verifies
  ;; even when the server advertised a different one. local-addresses is injected
  ;; here instead of enumerating the host.
  (let ((names (gr8s.apiserver::kubernetes-api-addresses
                '("192.168.1.198")
                '("10.77.77.10" "192.168.1.198" "127.0.0.1"))))
    ;; the explicitly advertised address, every local address, and the stable
    ;; Service + loopback addresses are all present...
    (dolist (expected '("192.168.1.198" "10.77.77.10" "10.96.0.1" "127.0.0.1"))
      (is (member expected names :test #'equal) "~A missing from ~A" expected names))
    ;; ...with no duplicates (192.168.1.198 and 127.0.0.1 appeared twice in input).
    (is (= (length names) (length (remove-duplicates names :test #'equal))))
    (is (= 4 (length names))))
  ;; Degrades gracefully: no enumerable local addresses still yields the stable set.
  (is (equal '("10.96.0.1" "127.0.0.1")
             (gr8s.apiserver::kubernetes-api-addresses '() '()))))

(test certificate-signatures-use-minimal-positive-der-integers
  (let ((signature (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref signature 31) 1 (aref signature 63) 128)
    (is (equalp #(48 7 2 1 1 2 2 0 128) (gr8s.security::ecdsa-signature-der signature)))
    (let ((parsed (pure-tls::parse-ecdsa-cert-signature (gr8s.security::ecdsa-signature-der signature))))
      (is (= 1 (getf parsed :r)))
      (is (= 128 (getf parsed :s))))
    (setf (aref signature 31) 0 (aref signature 63) 127)
    (is (equalp #(48 6 2 1 0 2 1 127) (gr8s.security::ecdsa-signature-der signature)))))

(defmacro with-temporary-pki ((pki path) &body body)
  `(let* ((,path (merge-pathnames
                  (format nil "gr8s-pki-test-~36R/" (random (expt 36 10)))
                  (uiop:temporary-directory)))
          (,pki (gr8s.security::ensure-cluster-pki ,path)))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,path :validate t :if-does-not-exist :ignore))))

(defun file-mode (path)
  (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring path)))))

(defun pki-error-reason-from (thunk)
  (handler-case
      (progn (funcall thunk) nil)
    (gr8s.security::pki-error (condition)
      (gr8s.security::pki-error-reason condition))))

(test cluster-ca-is-persistent-pinned-and-kept-private
  (with-temporary-pki (pki path)
    (let ((fingerprint (gr8s.security::cluster-pki-ca-fingerprint pki))
          (certificate (gr8s.security::cluster-pki-ca-certificate-path pki))
          (private-key (gr8s.security::cluster-pki-ca-private-key-path pki)))
      (is (= 64 (length fingerprint)))
      (is (probe-file certificate))
      (is (probe-file private-key))
      (is (= #o600 (file-mode private-key)))
      (let ((reopened (gr8s.security::ensure-cluster-pki path)))
        (is (string= fingerprint (gr8s.security::cluster-pki-ca-fingerprint reopened)))
        (is (string= (uiop:read-file-string certificate)
                     (uiop:read-file-string
                      (gr8s.security::cluster-pki-ca-certificate-path reopened))))))))

(test join-tokens-are-bound-to-a-node-and-never-persisted-in-plaintext
  (with-temporary-pki (pki path)
    (let* ((token (gr8s.security::create-join-token pki "worker-a"))
           (secret (subseq token (1+ (position #\. token))))
           (records (directory (merge-pathnames "tokens/*.json" path))))
      (is (= 1 (length records)))
      (let ((contents (uiop:read-file-string (first records))))
        (is (null (search token contents)))
        (is (null (search secret contents)))
        (is (search "worker-a" contents))))))

(test enrollment-verifies-pin-token-csr-name-and-one-time-use
  (with-temporary-pki (pki path)
    (let* ((worker-a-key (merge-pathnames "worker-a.key" path))
           (worker-b-key (merge-pathnames "worker-b.key" path))
           (worker-a-csr (gr8s.security::generate-node-key-and-csr "worker-a" worker-a-key))
           (worker-b-csr (gr8s.security::generate-node-key-and-csr "worker-b" worker-b-key))
           (fingerprint (gr8s.security::cluster-pki-ca-fingerprint pki)))
      (is (= #o600 (file-mode worker-a-key)))
      (let ((token (gr8s.security::create-join-token pki "worker-a")))
        (is (string= "ca-pin-mismatch"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s.security::enroll-node-csr
                         pki "worker-a" token (make-string 64 :initial-element #\0)
                         worker-a-csr)))))
        (is (string= "invalid-token"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s.security::enroll-node-csr
                         pki "worker-a" (concatenate 'string token "x") fingerprint
                         worker-a-csr)))))
        (is (string= "invalid-token"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s.security::enroll-node-csr
                         pki "worker-a"
                         (concatenate
                          'string "/tmp/" (make-string 19 :initial-element #\a)
                          "." (make-string 64 :initial-element #\0))
                         fingerprint worker-a-csr)))))
        (is (string= "node-name-mismatch"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s.security::enroll-node-csr
                         pki "worker-b" token fingerprint worker-b-csr)))))
        (is (string= "csr-name-mismatch"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s.security::enroll-node-csr
                         pki "worker-a" token fingerprint worker-b-csr)))))
        (let ((tampered-csr (copy-seq worker-a-csr)))
          (setf (aref tampered-csr (1- (length tampered-csr)))
                (logxor #xff (aref tampered-csr (1- (length tampered-csr)))))
          (is (string= "invalid-csr"
                       (pki-error-reason-from
                        (lambda ()
                          (gr8s.security::enroll-node-csr
                           pki "worker-a" token fingerprint tampered-csr))))))
        (let ((certificate
                (gr8s.security::enroll-node-csr
                 pki "worker-a" token fingerprint worker-a-csr)))
          (is (gr8s.security::verify-node-certificate pki certificate "worker-a"))
          (is (string= "certificate-name-mismatch"
                       (pki-error-reason-from
                        (lambda ()
                          (gr8s.security::verify-node-certificate pki certificate "worker-b"))))))
        (is (string= "token-already-used"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s.security::enroll-node-csr
                         pki "worker-a" token fingerprint worker-a-csr)))))))))

(test node-sessions-require-mutual-tls-bound-to-the-cluster-ca
  "podster-0oc.12 (P0): the persistent node listener runs mutual TLS. It presents a
   server cert/key and trusts the cluster CA to verify client certificates, while
   leaving them optional so credential-less enrollment shares the one listener. A
   Connect stream that presents no client certificate is rejected, and a presented
   cert is verified and name-bound (name-binding is covered by the
   verify-node-certificate assertions above). N4 additionally refuses to start the
   node listener without PKI, so the no-TLS branch here is never reached in production."
  (with-temporary-pki (pki path)
    path
    ;; The live node listener is configured for mutual TLS against the cluster CA.
    (let ((options (gr8s.security::node-server-tls-options pki)))
      (is (eq t (getf options :tls)))
      (is (eq :optional (getf options :tls-verify-client)))
      (is (stringp (getf options :tls-certificate)))
      (is (stringp (getf options :tls-key)))
      (is (not (null (getf options :tls-ca-certificate)))))
    ;; Without PKI there is no listener TLS at all (and N4 refuses that listener).
    (is (null (gr8s.security::node-server-tls-options nil)))
    ;; A persistent session whose stream carries no client certificate is rejected.
    (let* ((connection (make-instance 'ag-http2:http2-connection :stream :no-client-tls))
           (context (make-instance 'ag-grpc::grpc-call-context :connection connection)))
      (is (string= "unauthenticated-node"
                   (pki-error-reason-from
                    (lambda ()
                      (gr8s.security::authenticate-node-peer pki context "worker-a"))))))
    ;; With no PKI, peer authentication is a deliberate no-op (bootstrap/enrollment).
    (is (null (gr8s.security::authenticate-node-peer nil nil "worker-a")))))

(test control-plane-tls-identity-is-persistent-and-bound-to-the-cluster-ca
  (with-temporary-store (store path)
    (values store)
    (let ((pki (gr8s.security::ensure-cluster-pki path)))
      (multiple-value-bind (certificate key) (gr8s.security::ensure-node-server-credentials pki)
        (let ((original (uiop:read-file-string certificate)))
          (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat key)))))
          (is (= 2 (length (pure-tls:load-certificate-chain certificate))))
          (is (gr8s.security::verify-node-server-certificate
               (first (pure-tls:load-certificate-chain certificate))
               (gr8s.security::cluster-pki-ca-certificate pki)))
          (gr8s.security::ensure-node-server-credentials (gr8s.security::ensure-cluster-pki path))
          (is (string= original (uiop:read-file-string certificate))))))))

(test control-plane-tls-identity-renews-under-the-promoted-ca
  (with-temporary-store (store path)
    (declare (ignore store))
    (let* ((pki (gr8s.security::ensure-cluster-pki path))
           (certificate (gr8s.security::ensure-node-server-credentials pki))
           (old-leaf (first (pure-tls:load-certificate-chain certificate))))
      (gr8s.server::prepare-cluster-ca-rotation path)
      (gr8s.server::promote-cluster-ca-rotation path)
      (let ((promoted (gr8s.security::ensure-cluster-pki path)))
        (is-true
         (gr8s.security::node-certificate-needs-active-ca-renewal-p promoted old-leaf))
        (gr8s.security::ensure-node-server-credentials promoted)
        (let* ((chain (pure-tls:load-certificate-chain certificate))
               (renewed (first chain)))
          (is (= 2 (length chain)))
          (is-false
           (gr8s.security::node-certificate-needs-active-ca-renewal-p promoted renewed))
          (is-true
           (gr8s.security::verify-node-server-certificate
            renewed (gr8s.security::cluster-pki-trust-certificates promoted))))))))
