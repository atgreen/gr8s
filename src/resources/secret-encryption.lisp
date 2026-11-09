;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Authenticated encryption for Kubernetes Secret data at every durable and
;;;; replicated store boundary.  Live resource objects remain ordinary
;;;; Kubernetes objects; only their serialized representation is enveloped.

(in-package #:gr8s.resources)

(defparameter +secret-encrypted-data-field+ "gr8s.io/encryptedData")
(defparameter +secret-encryption-context+ "gr8s secret encryption v1")

(defun secret-json-object (&rest pairs)
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr
          do (setf (gethash key object) value))
    object))

(defun secret-encryption-enabled-p (store)
  (let ((config (pod-store-secret-encryption-config store)))
    (and (hash-table-p config) (eq t (gethash "enabled" config)))))

(defun secret-encryption-key-record (config key-id)
  (find key-id (gethash "keys" config #()) :test #'equal
        :key (lambda (record) (gethash "id" record))))

(defun secret-encryption-ca-key-bytes (store)
  (let ((path (merge-pathnames "pki/cluster-ca.key" (pod-store-path store))))
    (unless (probe-file path)
      (error "Secret encryption requires the cluster CA private key at ~A" path))
    (pure-tls::read-file-bytes path)))

(defun derive-secret-encryption-key (store record)
  "Derive a data-encryption key from cluster identity plus RECORD's public salt."
  (let ((hmac (ironclad:make-hmac (secret-encryption-ca-key-bytes store) :sha256)))
    (ironclad:update-hmac
     hmac
     (concatenate '(vector (unsigned-byte 8))
                  (trivial-utf-8:string-to-utf-8-bytes +secret-encryption-context+)
                  (ag-grpc:base64-decode (gethash "salt" record))))
    (ironclad:hmac-digest hmac)))

(defun secret-encryption-aad (resource namespace name key-id)
  (trivial-utf-8:string-to-utf-8-bytes
   (format nil "~A~C~A~C~A~C~A~C~A"
           +secret-encryption-context+ #\Null resource #\Null
           (or namespace "") #\Null name #\Null key-id)))

(defun encrypt-secret-object (store resource object)
  "Return OBJECT's durable representation, encrypting a Secret's data map."
  (if (or (not (equal resource "secrets"))
          (not (secret-encryption-enabled-p store))
          (not (hash-table-p object)))
      object
      (let* ((config (pod-store-secret-encryption-config store))
             (key-id (gethash "activeKeyId" config))
             (record (or (secret-encryption-key-record config key-id)
                         (error "Missing active Secret encryption key ~A" key-id)))
             (metadata (gethash "metadata" object))
             (namespace (and metadata (gethash "namespace" metadata)))
             (name (and metadata (gethash "name" metadata)))
             (nonce (ironclad:random-data 12))
             (mode (ironclad:make-authenticated-encryption-mode
                    :gcm :cipher-name :aes
                    :key (derive-secret-encryption-key store record)
                    :initialization-vector nonce))
             (plaintext (trivial-utf-8:string-to-utf-8-bytes
                         (com.inuoe.jzon:stringify
                          (gethash "data" object (make-hash-table :test #'equal)))))
             (ciphertext (ironclad:encrypt-message
                          mode plaintext
                          :associated-data
                          (secret-encryption-aad resource namespace name key-id)))
             (copy (copy-core-object object)))
        (remhash "data" copy)
        (setf (gethash +secret-encrypted-data-field+ copy)
              (secret-json-object
               "version" 1 "provider" "aes-gcm" "keyId" key-id
               "nonce" (ag-grpc:base64-encode nonce)
               "ciphertext" (ag-grpc:base64-encode ciphertext)
               "tag" (ag-grpc:base64-encode (ironclad:produce-tag mode))))
        copy)))

(defun decrypt-secret-object (store resource object)
  "Return a live Secret object from an authenticated durable envelope."
  (let ((envelope (and (hash-table-p object)
                       (gethash +secret-encrypted-data-field+ object))))
    (if (null envelope)
        object
        (let* ((config (pod-store-secret-encryption-config store))
               (key-id (gethash "keyId" envelope))
               (record (or (secret-encryption-key-record config key-id)
                           (error "Unknown Secret encryption key ~A" key-id)))
               (metadata (gethash "metadata" object))
               (namespace (and metadata (gethash "namespace" metadata)))
               (name (and metadata (gethash "name" metadata)))
               (mode (ironclad:make-authenticated-encryption-mode
                      :gcm :cipher-name :aes
                      :key (derive-secret-encryption-key store record)
                      :initialization-vector
                      (ag-grpc:base64-decode (gethash "nonce" envelope))))
               (ciphertext (ag-grpc:base64-decode (gethash "ciphertext" envelope)))
               (tag (ag-grpc:base64-decode (gethash "tag" envelope)))
               (copy (copy-core-object object)))
          (unless (and (equal resource "secrets")
                       (eql 1 (gethash "version" envelope))
                       (equal "aes-gcm" (gethash "provider" envelope)))
            (error "Invalid Secret encryption envelope"))
          (reinitialize-instance mode
                                 :cipher-name :aes
                                 :key (derive-secret-encryption-key store record)
                                 :initialization-vector
                                 (ag-grpc:base64-decode (gethash "nonce" envelope))
                                 :tag tag)
          (setf (gethash "data" copy)
                (com.inuoe.jzon:parse
                 (trivial-utf-8:utf-8-bytes-to-string
                  (ironclad:decrypt-message
                   mode ciphertext
                   :associated-data
                   (secret-encryption-aad resource namespace name key-id)))))
          (remhash +secret-encrypted-data-field+ copy)
          copy))))

(defun encrypt-secret-history-entry (store entry)
  (if (not (hash-table-p entry))
      entry
      (let* ((copy (copy-core-object entry))
             (resource (gethash "resource" copy)))
        (dolist (field '("old" "new"))
          (let ((object (gethash field copy)))
            (when (hash-table-p object)
              (setf (gethash field copy)
                    (encrypt-secret-object store resource object)))))
        copy)))

(defun decrypt-secret-history-entry (store entry)
  (if (not (hash-table-p entry))
      entry
      (let* ((copy (copy-core-object entry))
             (resource (gethash "resource" copy)))
        (dolist (field '("old" "new"))
          (let ((object (gethash field copy)))
            (when (hash-table-p object)
              (setf (gethash field copy)
                    (decrypt-secret-object store resource object)))))
        copy)))

(defun decrypt-core-state-secrets (store state)
  "Decrypt every Secret-bearing checkpoint field in STATE in place."
  (setf (gethash "items" state)
        (map 'vector
             (lambda (object)
               (decrypt-secret-object
                store
                (or (first (find (gethash "kind" object)
                                 (append *stored-resource-types*
                                         *internal-stored-resource-types*)
                                 :key #'second :test #'equal))
                    "")
                object))
             (gethash "items" state #()))
        (gethash "templateHistory" state)
        (map 'vector (lambda (entry)
                       (decrypt-secret-history-entry store entry))
             (gethash "templateHistory" state #())))
  state)

(defun new-secret-encryption-config ()
  (let* ((salt (ironclad:random-data 32))
         (id (subseq (ironclad:byte-array-to-hex-string
                      (ironclad:digest-sequence :sha256 salt)) 0 16)))
    (secret-json-object
     "version" 1 "enabled" t "activeKeyId" id
     "keys" (vector (secret-json-object "id" id
                                         "salt" (ag-grpc:base64-encode salt))))))

(defun enable-secret-encryption (store)
  "Enable encryption and atomically rewrite all currently durable Secret data."
  (bt:with-lock-held ((pod-store-lock store))
    (unless (secret-encryption-enabled-p store)
      (gr8s.security::ensure-cluster-pki (pod-store-path store))
      (setf (pod-store-secret-encryption-config store)
            (new-secret-encryption-config))
      (let ((token-key (or (pod-store-template-token-key store)
                           (secure-random-octets 32))))
        (write-core-checkpoint
         store
         (core-checkpoint-object
          store (pod-store-resources store) (pod-store-resource-revision store)
          (pod-store-workload-deletions store)
          (pod-store-job-controller-states store)
          (pod-store-template-history store)
          (pod-store-template-history-floor store)
          token-key (pod-store-event-expirations store)))
        (setf (pod-store-template-token-key store) token-key)))
    (pod-store-secret-encryption-config store)))
