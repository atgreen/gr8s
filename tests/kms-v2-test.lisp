;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)

(def-suite kms-v2 :in gr8s)
(in-suite kms-v2)

(defstruct fake-kms
  "A KMS v2 plugin in this process: it wraps with AES-GCM under KEYS' entry for KEY-ID,
counting each call by method."
  (key-id "key-1") (keys (list (cons "key-1" (ironclad:random-data 32))))
  (calls (make-hash-table :test #'equal)) (healthz "ok"))

(defun fake-kms-rotate (kms id)
  (push (cons id (ironclad:random-data 32)) (fake-kms-keys kms))
  (setf (fake-kms-key-id kms) id))

(defun fake-kms-transport (kms)
  (lambda (method request)
    (incf (gethash method (fake-kms-calls kms) 0))
    (flet ((mode (key-id nonce)
             (ironclad:make-authenticated-encryption-mode
              :gcm :cipher-name :aes :key (cdr (assoc key-id (fake-kms-keys kms) :test #'equal))
              :initialization-vector nonce)))
      (cond
        ((equal method "Status")
         (make-instance 'gr8s.kms.v2::status-response :version "v2" :healthz (fake-kms-healthz kms)
                                                      :key-id (fake-kms-key-id kms)))
        ((equal method "Encrypt")
         (let* ((nonce (ironclad:random-data 12))
                (mode (mode (fake-kms-key-id kms) nonce))
                (sealed (ironclad:encrypt-message mode (gr8s.kms.v2::plaintext request))))
           (make-instance 'gr8s.kms.v2::encrypt-response
                          :ciphertext (concatenate '(vector (unsigned-byte 8)) sealed (ironclad:produce-tag mode))
                          :key-id (fake-kms-key-id kms)
                          :annotations (list (cons "nonce.fake.kms.example" nonce)))))
        ((equal method "Decrypt")
         (let* ((ciphertext (gr8s.kms.v2::ciphertext request))
                (nonce (cdr (assoc "nonce.fake.kms.example" (gr8s.kms.v2::annotations request) :test #'equal)))
                (key (cdr (assoc (gr8s.kms.v2::key-id request) (fake-kms-keys kms) :test #'equal)))
                (mode (mode (gr8s.kms.v2::key-id request) nonce)))
           (reinitialize-instance mode :cipher-name :aes :key key :initialization-vector nonce
                                       :tag (subseq ciphertext (- (length ciphertext) 16)))
           (make-instance 'gr8s.kms.v2::decrypt-response
                          :plaintext (ironclad:decrypt-message mode (subseq ciphertext 0 (- (length ciphertext) 16))))))))))

(defmacro with-fake-kms ((kms &optional (name "test-kms")) &body body)
  `(let* ((,kms (make-fake-kms))
          (gr8s.resources::*kms-plugins* (make-hash-table :test #'equal :synchronized t))
          (gr8s.resources::*kms-data-keys* (make-hash-table :test #'equal :synchronized t)))
     (gr8s.resources::register-kms-plugin
      (gr8s.protocol::make-kms-plugin ,name nil :transport (fake-kms-transport ,kms)))
     ,@body))

(test kms-v2-messages-round-trip-on-the-wire
  ;; The annotations map is what a real plugin leans on to unwrap; it must survive.
  (let* ((response (make-instance 'gr8s.kms.v2::encrypt-response
                                  :ciphertext (coerce #(1 2 3) '(vector (unsigned-byte 8))) :key-id "k"
                                  :annotations (list (cons "a.example.com" (coerce #(9 8) '(vector (unsigned-byte 8)))))))
         (back (ag-proto:deserialize-from-bytes 'gr8s.kms.v2::encrypt-response (ag-proto:serialize-to-bytes response))))
    (is (equalp #(1 2 3) (gr8s.kms.v2::ciphertext back)))
    (is (equal "k" (gr8s.kms.v2::key-id back)))
    (is (equalp '(("a.example.com" . #(9 8))) (gr8s.kms.v2::annotations back)))))

(test secrets-encrypted-with-a-kms-key-never-store-the-key-and-survive-a-restart
  (with-fake-kms (kms)
    (with-temporary-store (store path)
      (let ((encoded "a21zLXByb3RlY3RlZC12YWx1ZQ=="))
        (gr8s.resources::create-core-resource
         store "secrets" (core-fixture "Secret" "login" "data" (gr8s.resources::core-object "token" encoded)) "default")
        (gr8s.resources::enable-secret-encryption store :kms "test-kms")
        (let* ((config (gr8s.resources::secret-encryption-status store))
               (record (aref (gethash "keys" config) 0))
               (checkpoint (uiop:read-file-string (gr8s.resources::core-resource-state-path store))))
          (is (equal "kms-v2" (gethash "provider" record)))
          (is (equal "key-1" (gethash "kmsKeyId" record)))
          (is (null (gethash "salt" record)))
          (is (null (search encoded checkpoint)))
          ;; What is stored is the wrapped key, never the key.
          (is (null (search (ag-grpc:base64-encode (gethash (gethash "id" record) gr8s.resources::*kms-data-keys*))
                            checkpoint))))
        (is (= 1 (gethash "Encrypt" (fake-kms-calls kms))))
        ;; A restarted server unwraps the key with its plugin, once.
        (clrhash gr8s.resources::*kms-data-keys*)
        (let ((reopened (open-store path)))
          (is (string= encoded (gethash "token" (gethash "data" (gr8s.resources::get-core-resource reopened "secrets" "default" "login")))))
          (gr8s.resources::get-core-resource reopened "secrets" "default" "login")
          (is (= 1 (gethash "Decrypt" (fake-kms-calls kms)))))
        ;; Without its plugin, a server can't read them, and says which plugin it needs.
        (clrhash gr8s.resources::*kms-data-keys*)
        (clrhash gr8s.resources::*kms-plugins*)
        (let ((message (handler-case (progn (open-store path) "") (error (condition) (princ-to-string condition)))))
          (is (search "test-kms" message)))))))

(test a-kms-key-rotation-wraps-a-new-key-and-keeps-reading-the-old
  (with-fake-kms (kms)
    (with-temporary-store (store path)
      (values path)
      (gr8s.resources::enable-secret-encryption store :kms "test-kms")
      (gr8s.resources::create-core-resource
       store "secrets" (core-fixture "Secret" "before" "data" (gr8s.resources::core-object "v" "YmVmb3Jl")) "default")
      (is (null (gr8s.resources::rotate-kms-secret-key store)) "rotated with the key unchanged")
      (fake-kms-rotate kms "key-2")
      (let ((new (gr8s.resources::rotate-kms-secret-key store)))
        (is (stringp new))
        (let* ((config (gr8s.resources::secret-encryption-status store))
               (active (gr8s.resources::secret-encryption-key-record config (gethash "activeKeyId" config))))
          (is (equal new (gethash "activeKeyId" config)))
          (is (equal "key-2" (gethash "kmsKeyId" active)))
          (is (= 2 (length (gethash "keys" config))))))
      (gr8s.resources::create-core-resource
       store "secrets" (core-fixture "Secret" "after" "data" (gr8s.resources::core-object "v" "YWZ0ZXI=")) "default")
      (clrhash gr8s.resources::*kms-data-keys*)
      (let ((reopened (open-store path)))
        (is (equal "YmVmb3Jl" (gethash "v" (gethash "data" (gr8s.resources::get-core-resource reopened "secrets" "default" "before")))))
        (is (equal "YWZ0ZXI=" (gethash "v" (gethash "data" (gr8s.resources::get-core-resource reopened "secrets" "default" "after"))))))
      ;; Re-encrypting and finalizing leaves only the new key.
      (gr8s.resources::reencrypt-secrets store)
      (gr8s.resources::finalize-secret-encryption-key store)
      (is (= 1 (length (gethash "keys" (gr8s.resources::secret-encryption-status store))))))))

(test a-cluster-identity-key-migrates-to-a-kms-key
  (with-fake-kms (kms)
    (with-temporary-store (store path)
      (gr8s.resources::enable-secret-encryption store)
      (gr8s.resources::create-core-resource
       store "secrets" (core-fixture "Secret" "old" "data" (gr8s.resources::core-object "v" "b2xk")) "default")
      (gr8s.resources::prepare-secret-encryption-key store :kms "test-kms")
      (gr8s.resources::promote-secret-encryption-key store)
      (gr8s.resources::reencrypt-secrets store)
      (gr8s.resources::finalize-secret-encryption-key store)
      (let ((keys (gethash "keys" (gr8s.resources::secret-encryption-status store))))
        (is (= 1 (length keys)))
        (is (equal "kms-v2" (gethash "provider" (aref keys 0)))))
      (clrhash gr8s.resources::*kms-data-keys*)
      (is (equal "b2xk" (gethash "v" (gethash "data" (gr8s.resources::get-core-resource (open-store path) "secrets" "default" "old"))))))))

(test kms-plugin-health-reports-a-plugin-that-says-it-is-not-ok
  (with-fake-kms (kms)
    (is (equal '(("test-kms" t nil)) (gr8s.resources::kms-plugins-health)))
    (setf (fake-kms-healthz kms) "degraded")
    (destructuring-bind ((name healthy why)) (gr8s.resources::kms-plugins-health)
      (is (equal "test-kms" name))
      (is-false healthy)
      (is (search "degraded" why)))))

(test the-kms-providers-check-fails-with-its-plugin-as-upstreams-does
  (let ((kms (make-fake-kms))
        (plugins gr8s.resources::*kms-plugins*)
        (health gr8s.resources::*kms-plugin-health*))
    (unwind-protect
         (progn
           ;; The API answers on its own threads, which see the global tables.
           (setf gr8s.resources::*kms-plugins* (make-hash-table :test #'equal :synchronized t)
                 gr8s.resources::*kms-plugin-health* (make-hash-table :test #'equal :synchronized t))
           (gr8s.resources::register-kms-plugin
            (gr8s.protocol::make-kms-plugin "test-kms" nil :transport (fake-kms-transport kms)))
           (gr8s.resources::refresh-kms-plugin-health)
           (with-core-api (store path)
             (values store path)
             (flet ((fetch (path)
                      (multiple-value-bind (body status) (drakma:http-request (core-api-url path))
                        (values (if (stringp body) body (flexi-streams:octets-to-string body :external-format :utf-8))
                                status))))
               (is (search "[+]kms-providers ok" (fetch "/healthz?verbose=1")))
               (is (equal "ok" (fetch "/livez/kms-providers")))
               (setf (fake-kms-healthz kms) "degraded")
               (gr8s.resources::refresh-kms-plugin-health)
               (multiple-value-bind (body status) (fetch "/healthz")
                 (is (= 500 status))
                 (is (search "[-]kms-providers failed" body)))
               (is (= 500 (nth-value 1 (fetch "/livez/kms-providers"))))
               (is (= 200 (nth-value 1 (fetch "/healthz?exclude=kms-providers")))))))
      (setf gr8s.resources::*kms-plugins* plugins gr8s.resources::*kms-plugin-health* health))))

(test kms-plugins-are-named-on-the-command-line
  (let ((plugin (gr8s.server::parse-kms-plugin-option "vault=unix:///run/kms/vault.sock")))
    (is (equal "vault" (gr8s.protocol::kms-plugin-name plugin)))
    (is (equal "/run/kms/vault.sock" (gr8s.protocol::kms-plugin-socket-path plugin))))
  (signals error (gr8s.server::parse-kms-plugin-option "no-endpoint"))
  (signals error (gr8s.server::parse-kms-plugin-option "=unix:///x"))
  (let ((options (gr8s.server::parse-secrets-encrypt-options
                  '("enable" "--kms-plugin" "a=/run/a.sock" "--kms" "a"))))
    (is (equal "a" (getf options :kms)))
    (is (= 1 (length (getf options :kms-plugins)))))
  ;; A key wrapped by a plugin the command wasn't given would be wrapped by no one.
  (signals error (gr8s.server::parse-secrets-encrypt-options '("enable" "--kms" "missing")))
  (signals error (gr8s.server::parse-secrets-encrypt-options
                  '("promote" "--kms-plugin" "a=/run/a.sock" "--kms" "a")))
  (is (= 1 (length (getf (gr8s.server::parse-serve-options '("--kms-plugin" "a=/run/a.sock")) :kms-plugins)))))

(test a-new-standalone-cluster-encrypts-its-secrets-from-the-start
  (with-fake-kms (kms)
    (let ((options '(:encrypt-secrets-with "test-kms")))
      ;; New: encrypted before anything is written.
      (with-temporary-store (store path)
        (values path)
        (gr8s.server::encrypt-new-cluster-secrets store options)
        (is-true (gr8s.resources::secret-encryption-enabled-p store))
        (is (equal "kms-v2" (gethash "provider" (aref (gethash "keys" (gr8s.resources::secret-encryption-status store)) 0)))))
      ;; Existing: left as it is.
      (with-temporary-store (store path)
        (values path)
        (gr8s.resources::create-core-resource
         store "secrets" (core-fixture "Secret" "x" "data" (gr8s.resources::core-object "v" "eA==")) "default")
        (gr8s.server::encrypt-new-cluster-secrets store options)
        (is-false (gr8s.resources::secret-encryption-enabled-p store)))
      ;; Starting or joining HA: opt-in until every member reaches the same KMS.
      (with-temporary-store (store path)
        (values path)
        (gr8s.server::encrypt-new-cluster-secrets store (list* :raft-init t options))
        (is-false (gr8s.resources::secret-encryption-enabled-p store)))
      ;; A plugin that doesn't answer stops the start rather than leave Secrets plaintext.
      (setf (fake-kms-healthz kms) "starting")
      (with-temporary-store (store path)
        (values path)
        (let ((gr8s.server::+kms-plugin-wait-seconds+ 1))
          (signals error (gr8s.server::encrypt-new-cluster-secrets store options)))
        (is-false (gr8s.resources::secret-encryption-enabled-p store))))))
