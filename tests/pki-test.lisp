(in-package #:gr8s/tests)

(in-suite gr8s)

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
