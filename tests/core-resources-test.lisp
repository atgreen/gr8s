(in-package #:gr8s/tests)
(def-suite core-resources :in gr8s)
(in-suite core-resources)

(test resource-semantics-have-an-explicit-package-boundary
  (let ((resources (find-package '#:gr8s.resources))
        (composition (find-package '#:gr8s)))
    (is-true resources)
    (dolist (name '("CORE-OBJECT"
                    "NORMALIZE-CORE-RESOURCE"
                    "GET-CORE-RESOURCE"
                    "LIST-CORE-RESOURCES"
                    "CREATE-CORE-RESOURCE"
                    "UPDATE-CORE-RESOURCE"
                    "DELETE-CORE-RESOURCE"
                    "WITH-CRD-DEFERRED-CONVERSIONS"))
      (multiple-value-bind (implementation status)
          (find-symbol name resources)
        (is (eq :external status))
        (is (eq implementation (find-symbol name composition)))))
    (is (not (eq :external
                 (nth-value 1 (find-symbol "FOR" resources)))))))

(defun core-fixture (kind name &rest fields)
  (apply #'gr8s::core-object "apiVersion" "v1" "kind" kind
         "metadata" (gr8s::core-object "name" name) fields))

(defun core-resource-status (function)
  (handler-case (progn (funcall function) nil)
    (kubernetes-error (condition) (gr8s::kubernetes-error-status-code condition))))

(test core-resources-survive-restart-and-isolate-namespaces-and-returned-values
  (with-temporary-store (store path)
    (let* ((created (gr8s::create-core-resource store "configmaps"
                     (core-fixture "ConfigMap" "settings" "data" (gr8s::core-object "key" "one")) "alpha"))
           (uid (gethash "uid" (gethash "metadata" created))))
      (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "settings") "beta")
      (setf (gethash "key" (gethash "data" created)) "not stored")
      (let* ((reopened (open-store path))
             (read (gr8s::get-core-resource reopened "configmaps" "alpha" "settings")))
        (is (string= uid (gethash "uid" (gethash "metadata" read))))
        (is (string= "one" (gethash "key" (gethash "data" read)))))
      (is (= 1 (length (gr8s::list-core-resources store "configmaps" "alpha"))))
      (is (= 2 (length (gr8s::list-core-resources store "configmaps"))))
      (is (= 404 (core-resource-status (lambda () (gr8s::get-core-resource store "secrets" "alpha" "settings")))))
      (is (= 409 (core-resource-status (lambda () (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "settings") "alpha"))))))))

(test core-resource-updates-and-deletes-enforce-concurrency-and-preconditions
  (with-temporary-store (store path)
    (values path)
    (let* ((created (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "settings") "default"))
           (first-version (gethash "resourceVersion" (gethash "metadata" created)))
           (updated (gr8s::update-core-resource store "configmaps" "default" "settings"
                      (lambda (old) (setf (gethash "data" old) (gr8s::core-object "x" "y")) old))))
      (is (not (string= first-version (gethash "resourceVersion" (gethash "metadata" updated)))))
      (is (= 409 (core-resource-status
                  (lambda () (gr8s::update-core-resource store "configmaps" "default" "settings"
                               (lambda (old) (declare (ignore old)) created))))))
      (is (= 409 (core-resource-status
                  (lambda () (gr8s::delete-core-resource store "configmaps" "default" "settings" :uid "wrong")))))
      (gr8s::delete-core-resource store "configmaps" "default" "settings"
                                 :uid (gethash "uid" (gethash "metadata" updated))
                                 :resource-version (gethash "resourceVersion" (gethash "metadata" updated)))
      (is (null (gr8s::list-core-resources (open-store path) "configmaps"))))))

(test secrets-merge-string-data-on-write-and-store-only-base64
  (with-temporary-store (store path)
    (let ((secret (gr8s::create-core-resource store "secrets"
                    (core-fixture "Secret" "credentials"
                                  "data" (gr8s::core-object "password" "b2xk" "bytes" "AP8=")
                                  "stringData" (gr8s::core-object "password" "new")) "default")))
      (is (string= "Opaque" (gethash "type" secret)))
      (is (null (gethash "stringData" secret)))
      (is (string= "bmV3" (gethash "password" (gethash "data" secret))))
      (is (string= "AP8=" (gethash "bytes" (gethash "data" secret))))
      ;; Neither the checkpoint nor the journal of later commits keeps stringData, and both are private.
      (gr8s::update-core-resource store "secrets" "default" "credentials"
        (lambda (object) (setf (gethash "stringData" object) (gr8s::core-object "other" "plain")) object))
      (is (probe-file (gr8s::core-journal-path store)))
      (dolist (path (list (gr8s::core-resource-state-path store) (gr8s::core-journal-path store)))
        (is (null (search "stringData" (uiop:read-file-string path))))
        (is (null (search "plain" (uiop:read-file-string path))))
        (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat path)))))))))

(test secret-encryption-enable-rewrites-durable-data-and-round-trips
  (with-temporary-store (store path)
    (let* ((encoded "c3VwZXItc2VjcmV0LXZhbHVl")
           (secret (gr8s::create-core-resource
                    store "secrets"
                    (core-fixture "Secret" "credentials"
                                  "data" (gr8s::core-object "password" encoded))
                    "default")))
      (is (string= encoded (gethash "password" (gethash "data" secret))))
      (gr8s::enable-secret-encryption store)
      (let ((checkpoint (uiop:read-file-string (gr8s::core-resource-state-path store))))
        (is (null (search encoded checkpoint)))
        (is (search "encryptedData" checkpoint)))
      (let* ((reopened (open-store path))
             (restored (gr8s::get-core-resource reopened "secrets" "default" "credentials")))
        (is (string= encoded
                     (gethash "password" (gethash "data" restored))))))))

(test encrypted-secret-journal-round-trips-and-authentication-fails-closed
  (with-temporary-store (store path)
    (gr8s::enable-secret-encryption store)
    (gr8s::create-core-resource
     store "secrets"
     (core-fixture "Secret" "credentials"
                   "data" (gr8s::core-object "password" "am91cm5hbC1zZW50aW5lbA=="))
     "default")
    (let* ((journal-path (gr8s::core-journal-path store))
           (journal (uiop:read-file-string journal-path)))
      (is (null (search "am91cm5hbC1zZW50aW5lbA==" journal)))
      (is (search "encryptedData" journal))
      (is (gr8s::get-core-resource (open-store path) "secrets" "default" "credentials"))
      (let* ((record (com.inuoe.jzon:parse (string-right-trim '(#\Newline) journal)))
             (object (gethash "object" (aref (gethash "changes" record) 0)))
             (envelope (gethash "gr8s.io/encryptedData" object))
             (ciphertext (gethash "ciphertext" envelope)))
        (setf (char ciphertext 0) (if (char= (char ciphertext 0) #\A) #\B #\A))
        (gr8s.security::write-private-text-atomically
         journal-path (concatenate 'string (com.inuoe.jzon:stringify record) (string #\Newline)))
        (signals error (open-store path))))))

(test encrypted-secret-recovery-requires-the-cluster-identity
  (with-temporary-store (store path)
    (gr8s::enable-secret-encryption store)
    (gr8s::create-core-resource
     store "secrets"
     (core-fixture "Secret" "identity-bound"
                   "data" (gr8s::core-object "password" "aWRlbnRpdHktc2VudGluZWw="))
     "default")
    (let ((key (merge-pathnames "pki/cluster-ca.key" path))
          (backup (merge-pathnames "pki/cluster-ca.key.backup" path)))
      (rename-file key backup)
      (unwind-protect
           (signals error (open-store path))
        (when (probe-file backup)
          (rename-file backup key))))
    (is (gr8s::get-core-resource (open-store path)
                                 "secrets" "default" "identity-bound"))))

(test secret-encryption-rotation-stages-retain-old-keys-until-reencrypted
  (with-temporary-store (store path)
    (gr8s::enable-secret-encryption store)
    (gr8s::create-core-resource
     store "secrets"
     (core-fixture "Secret" "credentials"
                   "data" (gr8s::core-object "password" "cm90YXRpb24tc2VudGluZWw="))
     "default")
    (let* ((initial-status (gr8s::secret-encryption-status store))
           (old-id (gethash "activeKeyId" initial-status))
           (prepared-id (gr8s::prepare-secret-encryption-key store)))
      (is (not (equal old-id prepared-id)))
      (is (equal prepared-id
                 (gethash "preparedKeyId" (gr8s::secret-encryption-status store))))
      (gr8s::promote-secret-encryption-key store)
      (is (equal prepared-id
                 (gethash "activeKeyId" (gr8s::secret-encryption-status store))))
      (signals error (gr8s::finalize-secret-encryption-key store))
      (gr8s::reencrypt-secrets store)
      (gr8s::finalize-secret-encryption-key store)
      (let* ((status (gr8s::secret-encryption-status store))
             (keys (gethash "keys" status))
             (checkpoint (uiop:read-file-string (gr8s::core-resource-state-path store))))
        (is (= 1 (length keys)))
        (is (equal prepared-id (gethash "id" (aref keys 0))))
        (is (null (search old-id checkpoint)))
        (let ((reopened (open-store path)))
          (is (gr8s::get-core-resource reopened
                                       "secrets" "default" "credentials"))
          (gr8s::disable-secret-encryption reopened)
          (is-false (gethash "enabled" (gr8s::secret-encryption-status reopened)))
          (let ((plaintext (uiop:read-file-string
                            (gr8s::core-resource-state-path reopened))))
            (is (search "cm90YXRpb24tc2VudGluZWw=" plaintext))
            (is (null (search "gr8s.io/encryptedData" plaintext)))))))))

(test invalid-core-resource-input-is-rejected-without-changing-state
  (with-temporary-store (store path)
    (values path)
    (dolist (fixture
              (list (list "configmaps" (core-fixture "ConfigMap" "bad" "data" (gr8s::core-object "same" "plain")
                                                      "binaryData" (gr8s::core-object "same" "Yg==")) 422)
                    (list "secrets" (core-fixture "Secret" "bad" "data" (gr8s::core-object "password" "!!!")) 400)
                    (list "secrets" (core-fixture "Secret" "bad" "data" (gr8s::core-object "../key" "Yg==")) 422)
                    (list "secrets" (core-fixture "Secret" "bad" "type" "kubernetes.io/tls") 422)
                    (list "configmaps" (core-fixture "ConfigMap" "bad" "immutable" "true") 422)
                    (list "configmaps" (core-fixture "ConfigMap" "bad" "data" (gr8s::core-object "huge" (make-string (1+ (* 1024 1024)) :initial-element #\x))) 422)))
      (is (= (third fixture) (core-resource-status
                             (lambda () (gr8s::create-core-resource store (first fixture) (second fixture) "default"))))))
    (is (zerop (gr8s::pod-store-resource-revision store)))
    (is (zerop (hash-table-count (gr8s::pod-store-resources store))))))

(test immutable-core-resources-permit-only-metadata-updates
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "configmaps"
                               (core-fixture "ConfigMap" "fixed" "immutable" t "data" (gr8s::core-object "key" "fixed")) "default")
    (gr8s::update-core-resource store "configmaps" "default" "fixed"
      (lambda (old) (setf (gethash "labels" (gethash "metadata" old)) (gr8s::core-object "app" "test")) old))
    (is (= 422 (core-resource-status
                (lambda () (gr8s::update-core-resource store "configmaps" "default" "fixed"
                             (lambda (old) (setf (gethash "key" (gethash "data" old)) "changed") old))))))
    (is (= 422 (core-resource-status
                (lambda () (gr8s::update-core-resource store "configmaps" "default" "fixed"
                             (lambda (old) (remhash "immutable" old) old))))))))

(test dry-run-core-resource-writes-do-not-persist-or-consume-revisions
  (with-temporary-store (store path)
    (values path)
    (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "dry") "default" :dry-run t)
    (is (null (gr8s::list-core-resources store "configmaps")))
    (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "dry") "default")
    (gr8s::delete-core-resource store "configmaps" "default" "dry" :dry-run t)
    (is (= 1 (length (gr8s::list-core-resources store "configmaps"))))
    (is (= 1 (gr8s::pod-store-resource-revision store)))))

(test maximum-size-secret-survives-the-json-storage-roundtrip
  (with-temporary-store (store path)
    (let* ((bytes (make-array (* 1024 1024) :element-type '(unsigned-byte 8) :initial-element 255))
           (encoded (ag-grpc:base64-encode bytes)))
      (gr8s::create-core-resource store "secrets"
                                 (core-fixture "Secret" "large" "data" (gr8s::core-object "payload" encoded)) "default")
      (let ((loaded (gr8s::get-core-resource (open-store path) "secrets" "default" "large")))
        (is (string= encoded (gethash "payload" (gethash "data" loaded))))))))

(defun core-test-protobuf (fields)
  (let ((buffer (make-array 64 :element-type '(unsigned-byte 8) :fill-pointer 0 :adjustable t)))
    (dolist (field fields buffer)
      (destructuring-bind (number value) field
        (ag-proto::write-field-tag number (if (integerp value) 0 2) buffer)
        (if (integerp value) (ag-proto::write-varint value buffer)
            (ag-proto::write-length-delimited
             (if (stringp value) (trivial-utf-8:string-to-utf-8-bytes value) value) buffer))))))

(defun core-test-protobuf-envelope (kind fields &optional (version "v1"))
  (concatenate '(vector (unsigned-byte 8)) #(107 56 115 0)
               (core-test-protobuf
                (list (list 1 (core-test-protobuf (list (list 1 version) (list 2 kind))))
                      (list 2 (core-test-protobuf fields))))))

(test kubernetes-protobuf-secret-preserves-binary-data-and-false-immutable
  (let* ((metadata (core-test-protobuf '((1 "credentials") (3 "default"))))
         (map (core-test-protobuf (list (list 1 "bytes") (list 2 (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(0 255))))))
         (input (core-test-protobuf-envelope "Secret" (list (list 1 metadata) (list 2 map) (list 3 "Opaque") (list 5 0))))
         (object (gr8s::decode-core-resource-protobuf input "Secret")))
    (is (string= "AP8=" (gethash "bytes" (gethash "data" object))))
    (is (null (gethash "immutable" object)))
    (is-true (nth-value 1 (gethash "immutable" object)))
    (is (string= "credentials" (gethash "name" (gethash "metadata" object))))
    (loop for length from 0 below (length input)
          do (is (= 400 (core-resource-status
                         (lambda () (gr8s::decode-core-resource-protobuf (subseq input 0 length) "Secret"))))))))

(test protobuf-delete-options-preserve-dryrun-and-preconditions
  (let* ((preconditions (core-test-protobuf '((1 "object-uid") (2 "9"))))
         (input (core-test-protobuf-envelope "DeleteOptions" (list (list 2 preconditions) (list 5 "All"))))
         (options (gr8s::decode-core-resource-protobuf input "DeleteOptions")))
    (is (equalp #( "All") (gethash "dryRun" options)))
    (is (string= "object-uid" (gethash "uid" (gethash "preconditions" options))))
    (is (string= "9" (gethash "resourceVersion" (gethash "preconditions" options))))))

(test malformed-protobuf-and-unsupported-ownership-fail-closed
  (let ((wrong-kind (core-test-protobuf-envelope "Secret" nil))
        (owner (core-test-protobuf-envelope "ConfigMap"
                 (list (list 1 (core-test-protobuf (list (list 1 "owned") (list 13 (core-test-protobuf nil)))))))))
    (is (= 400 (core-resource-status (lambda () (gr8s::decode-core-resource-protobuf wrong-kind "ConfigMap")))))
    (is (= 422 (core-resource-status (lambda () (gr8s::decode-core-resource-protobuf owner "ConfigMap")))))
    (dolist (bad (list #(107 56 115 0 0) #(107 56 115 0 10 255 255 255 255 127)
                      #(107 56 115 0 255 255 255 255 255 255 255 255 255 255 1)))
      (is (= 400 (core-resource-status
                  (lambda () (gr8s::decode-core-resource-protobuf
                               (map '(vector (unsigned-byte 8)) #'identity bad) "ConfigMap"))))))))

(test create-copies-large-payload-only-for-normalization-and-private-response
  (with-temporary-store (store root)
    (declare (ignore root))
    (let* ((payload (make-string 65536 :initial-element #\x))
           (input (gr8s::core-object "apiVersion" "v1" "kind" "ConfigMap"
                    "metadata" (gr8s::core-object "generateName" "copy-" "resourceVersion" "")
                    "data" (gr8s::core-object "value" payload)))
           (copy (symbol-function 'gr8s::copy-core-object))
           (bulk-copies 0) (result nil))
      (unwind-protect
           (progn
             (setf (symbol-function 'gr8s::copy-core-object)
                   (lambda (object)
                     (when (and (stringp object) (= 65536 (length object))) (incf bulk-copies))
                     (funcall copy object)))
             (setf result (gr8s::create-core-resource store "configmaps" input "default")))
        (setf (symbol-function 'gr8s::copy-core-object) copy))
      (is (= 2 bulk-copies))
      (is (not (gethash "name" (gethash "metadata" input))))
      (is (equal "" (gethash "resourceVersion" (gethash "metadata" input))))
      (is (equal payload (gethash "value" (gethash "data" result))))
      (setf (char (gethash "value" (gethash "data" result)) 0) #\y)
      (is (char= #\x (char payload 0)))
      (is (char= #\x (char (gethash "value" (gethash "data"
                               (gr8s::get-core-resource store "configmaps" "default"
                                 (gethash "name" (gethash "metadata" result))))) 0))))))

(in-suite gr8s)
