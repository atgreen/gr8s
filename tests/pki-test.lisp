(in-package #:gr8s/tests)

(in-suite gr8s)

(defmacro with-temporary-pki ((pki path) &body body)
  `(let* ((,path (merge-pathnames
                  (format nil "gr8s-pki-test-~36R/" (random (expt 36 10)))
                  (uiop:temporary-directory)))
          (,pki (gr8s:ensure-cluster-pki ,path)))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,path :validate t :if-does-not-exist :ignore))))

(defun file-mode (path)
  (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring path)))))

(defun pki-error-reason-from (thunk)
  (handler-case
      (progn (funcall thunk) nil)
    (gr8s:pki-error (condition)
      (gr8s:pki-error-reason condition))))

(test cluster-ca-is-persistent-pinned-and-kept-private
  (with-temporary-pki (pki path)
    (let ((fingerprint (gr8s:cluster-pki-ca-fingerprint pki))
          (certificate (gr8s:cluster-pki-ca-certificate-path pki))
          (private-key (gr8s:cluster-pki-ca-private-key-path pki)))
      (is (= 64 (length fingerprint)))
      (is (probe-file certificate))
      (is (probe-file private-key))
      (is (= #o600 (file-mode private-key)))
      (let ((reopened (gr8s:ensure-cluster-pki path)))
        (is (string= fingerprint (gr8s:cluster-pki-ca-fingerprint reopened)))
        (is (string= (uiop:read-file-string certificate)
                     (uiop:read-file-string
                      (gr8s:cluster-pki-ca-certificate-path reopened))))))))

(test join-tokens-are-bound-to-a-node-and-never-persisted-in-plaintext
  (with-temporary-pki (pki path)
    (let* ((token (gr8s:create-join-token pki "worker-a"))
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
           (worker-a-csr (gr8s:generate-node-key-and-csr "worker-a" worker-a-key))
           (worker-b-csr (gr8s:generate-node-key-and-csr "worker-b" worker-b-key))
           (fingerprint (gr8s:cluster-pki-ca-fingerprint pki)))
      (is (= #o600 (file-mode worker-a-key)))
      (let ((token (gr8s:create-join-token pki "worker-a")))
        (is (string= "ca-pin-mismatch"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s:enroll-node-csr
                         pki "worker-a" token (make-string 64 :initial-element #\0)
                         worker-a-csr)))))
        (is (string= "invalid-token"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s:enroll-node-csr
                         pki "worker-a" (concatenate 'string token "x") fingerprint
                         worker-a-csr)))))
        (is (string= "invalid-token"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s:enroll-node-csr
                         pki "worker-a"
                         (concatenate
                          'string "/tmp/" (make-string 19 :initial-element #\a)
                          "." (make-string 64 :initial-element #\0))
                         fingerprint worker-a-csr)))))
        (is (string= "node-name-mismatch"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s:enroll-node-csr
                         pki "worker-b" token fingerprint worker-b-csr)))))
        (is (string= "csr-name-mismatch"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s:enroll-node-csr
                         pki "worker-a" token fingerprint worker-b-csr)))))
        (let ((tampered-csr (copy-seq worker-a-csr)))
          (setf (aref tampered-csr (1- (length tampered-csr)))
                (logxor #xff (aref tampered-csr (1- (length tampered-csr)))))
          (is (string= "invalid-csr"
                       (pki-error-reason-from
                        (lambda ()
                          (gr8s:enroll-node-csr
                           pki "worker-a" token fingerprint tampered-csr))))))
        (let ((certificate
                (gr8s:enroll-node-csr
                 pki "worker-a" token fingerprint worker-a-csr)))
          (is (gr8s:verify-node-certificate pki certificate "worker-a"))
          (is (string= "certificate-name-mismatch"
                       (pki-error-reason-from
                        (lambda ()
                          (gr8s:verify-node-certificate pki certificate "worker-b"))))))
        (is (string= "token-already-used"
                     (pki-error-reason-from
                      (lambda ()
                        (gr8s:enroll-node-csr
                         pki "worker-a" token fingerprint worker-a-csr)))))))))

(test control-plane-tls-identity-is-persistent-and-bound-to-the-cluster-ca
  (with-temporary-store (store path)
    (values store)
    (let ((pki (gr8s:ensure-cluster-pki path)))
      (multiple-value-bind (certificate key) (gr8s::ensure-node-server-credentials pki)
        (let ((original (uiop:read-file-string certificate)))
          (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat key)))))
          (is (= 2 (length (pure-tls:load-certificate-chain certificate))))
          (is (gr8s::verify-node-server-certificate
               (first (pure-tls:load-certificate-chain certificate))
               (gr8s::cluster-pki-ca-certificate pki)))
          (gr8s::ensure-node-server-credentials (gr8s:ensure-cluster-pki path))
          (is (string= original (uiop:read-file-string certificate))))))))
