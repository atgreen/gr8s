;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The HA datastore's encrypted bootstrap record for cluster-wide PKI state.

(in-package #:gr8s.resources)

(defparameter +pki-authority-resource+ "pkiauthorities")
(defparameter +pki-authority-name+ "cluster")
(defparameter +pki-authority-context+ "gr8s HA PKI authority v1")
(defparameter +pki-authority-files+
  '("pki/pki/cluster-ca.crt" "pki/pki/cluster-ca.key"
    "pki/pki/cluster-ca-next.crt" "pki/pki/cluster-ca-next.key"
    "pki/pki/cluster-ca-retiring.crt" "pki/pki/cluster-ca-retiring.key"
    "pki/pki/cluster-ca-rotation.json" "pki/service-account-signing-key.json"))

(defvar *pki-authority-observers* (make-hash-table :test #'eq)
  "STORE -> callbacks notified after replicated PKI material is extracted.")
(defvar *installed-pki-authority-identities* (make-hash-table :test #'eq)
  "STORE -> serialized replicated authority last extracted in this process.")
(defvar *pki-authority-observers-lock* (bt:make-lock "HA PKI authority observers"))

(defun add-pki-authority-observer (store function)
  "Notify FUNCTION after STORE installs replicated authority material."
  (bt:with-lock-held (*pki-authority-observers-lock*)
    (pushnew function (gethash store *pki-authority-observers*) :test #'eq))
  function)

(defun remove-pki-authority-observer (store function)
  "Stop notifying FUNCTION for STORE."
  (bt:with-lock-held (*pki-authority-observers-lock*)
    (setf (gethash store *pki-authority-observers*)
          (delete function (gethash store *pki-authority-observers*) :test #'eq))
    (unless (gethash store *pki-authority-observers*)
      (remhash store *pki-authority-observers*)))
  nil)

(defun notify-pki-authority-observers (store)
  (let ((observers
          (bt:with-lock-held (*pki-authority-observers-lock*)
            (copy-list (gethash store *pki-authority-observers*)))))
    (dolist (observer observers) (funcall observer))))

(defun pki-authority-bootstrap-key-path (store)
  "Return the stable voter-shared Raft CA key used to protect bootstrap state."
  (merge-pathnames "pki/raft/pki/cluster-ca.key" (pod-store-path store)))

(defun pki-authority-key (store)
  (let ((path (pki-authority-bootstrap-key-path store)))
    (unless (probe-file path)
      (error "HA PKI authority requires the Raft CA private key at ~A" path))
    (ironclad:digest-sequence
     :sha256
     (concatenate '(vector (unsigned-byte 8))
                  (trivial-utf-8:string-to-utf-8-bytes +pki-authority-context+)
                  (pure-tls::read-file-bytes path)))))

(defun pki-authority-key-id (store)
  (subseq (ironclad:byte-array-to-hex-string
           (ironclad:digest-sequence :sha256 (pki-authority-key store))) 0 16))

(defun pki-authority-aad (key-id)
  (trivial-utf-8:string-to-utf-8-bytes
   (format nil "~A~C~A" +pki-authority-context+ #\Null key-id)))

(defun capture-pki-authority-material (store)
  "Capture the complete allowlisted local PKI transition state as a JSON object."
  (let ((files (core-object)))
    (dolist (relative +pki-authority-files+)
      (let ((path (merge-pathnames relative (pod-store-path store))))
        (when (probe-file path)
          (setf (gethash relative files) (uiop:read-file-string path)))))
    (unless (and (gethash "pki/pki/cluster-ca.crt" files)
                 (gethash "pki/pki/cluster-ca.key" files))
      (error "Cluster CA material is incomplete under ~A" (pod-store-path store)))
    (core-object "format" "gr8s-pki-authority" "version" 1 "files" files)))

(defun encrypt-pki-authority-material (store material)
  "Return an authenticated envelope whose ciphertext is safe for the Raft log."
  (let* ((key-id (pki-authority-key-id store))
         (nonce (ironclad:random-data 12))
         (mode (ironclad:make-authenticated-encryption-mode
                :gcm :cipher-name :aes :key (pki-authority-key store)
                :initialization-vector nonce))
         (ciphertext
           (ironclad:encrypt-message
            mode
            (stringify-to-utf-8-bytes material)
            :associated-data (pki-authority-aad key-id))))
    (core-object "format" "gr8s-pki-authority-envelope" "version" 1
                 "provider" "aes-gcm" "keyId" key-id
                 "nonce" (ag-grpc:base64-encode nonce)
                 "ciphertext" (ag-grpc:base64-encode ciphertext)
                 "tag" (ag-grpc:base64-encode (ironclad:produce-tag mode)))))

(defun decrypt-pki-authority-material (store envelope)
  "Authenticate and decrypt ENVELOPE with this voter's stable bootstrap key."
  (unless (and (hash-table-p envelope)
               (equal "gr8s-pki-authority-envelope" (gethash "format" envelope))
               (eql 1 (gethash "version" envelope))
               (equal "aes-gcm" (gethash "provider" envelope))
               (equal (pki-authority-key-id store) (gethash "keyId" envelope)))
    (error "Invalid or foreign HA PKI authority envelope"))
  (let* ((key-id (gethash "keyId" envelope))
         (nonce (ag-grpc:base64-decode (gethash "nonce" envelope)))
         (tag (ag-grpc:base64-decode (gethash "tag" envelope)))
         (mode (ironclad:make-authenticated-encryption-mode
                :gcm :cipher-name :aes :key (pki-authority-key store)
                :initialization-vector nonce)))
    (reinitialize-instance mode :cipher-name :aes :key (pki-authority-key store)
                           :initialization-vector nonce :tag tag)
    (com.inuoe.jzon:parse
     (ironclad:decrypt-message
      mode (ag-grpc:base64-decode (gethash "ciphertext" envelope))
      :associated-data (pki-authority-aad key-id)))))

(defun pki-authority-state (envelope)
  (core-object
   "apiVersion" "gr8s.io/v1" "kind" "PKIAuthorityState"
   "metadata" (core-object "name" +pki-authority-name+)
   "spec" (core-object "envelope" envelope)))

(defun current-pki-authority-envelope (store)
  (let* ((key (core-resource-key +pki-authority-resource+ nil +pki-authority-name+))
         (state (gethash key (pod-store-resources store))))
    (and state (gethash "envelope" (gethash "spec" state)))))

(defun install-pki-authority-material (store material)
  "Extract one authenticated authority record, removing allowlisted files it omits."
  (unless (and (hash-table-p material)
               (equal "gr8s-pki-authority" (gethash "format" material))
               (eql 1 (gethash "version" material))
               (hash-table-p (gethash "files" material)))
    (error "Invalid HA PKI authority material"))
  (let ((files (gethash "files" material)))
    (loop for relative being the hash-keys of files
          unless (member relative +pki-authority-files+ :test #'equal)
            do (error "HA PKI authority contains unsupported path ~A" relative))
    (dolist (relative +pki-authority-files+)
      (let ((path (merge-pathnames relative (pod-store-path store)))
            (text (gethash relative files)))
        (if text
            (gr8s.security::write-private-text-atomically path text)
            (when (probe-file path) (delete-file path))))))
  material)

(defun reconcile-pki-authority (store)
  "Extract the current replicated authority record, if this cluster has one."
  (let ((envelope (current-pki-authority-envelope store)))
    (when envelope
      (let* ((identity (com.inuoe.jzon:stringify envelope))
             (changed
               (bt:with-lock-held (*pki-authority-observers-lock*)
                 (not (equal identity
                             (gethash store *installed-pki-authority-identities*))))))
        (when changed
          (prog1
              (install-pki-authority-material
               store (decrypt-pki-authority-material store envelope))
            (bt:with-lock-held (*pki-authority-observers-lock*)
              (setf (gethash store *installed-pki-authority-identities*) identity))
            (notify-pki-authority-observers store)))))))

(defun publish-pki-authority (store &optional (material (capture-pki-authority-material store)))
  "Commit encrypted MATERIAL through the ordinary replicated core transaction path."
  (let* ((envelope (encrypt-pki-authority-material store material))
         (key (core-resource-key +pki-authority-resource+ nil +pki-authority-name+)))
    (with-core-write (store)
      (let* ((resources (copy-core-resource-index store))
             (old (gethash key resources))
             (revision (1+ (pod-store-resource-revision store)))
             (state (pki-authority-state envelope)))
        (prepare-core-resource-metadata state old revision)
        (setf (gethash key resources) state)
        (commit-core-resources store resources revision)))
    (reconcile-pki-authority store)
    envelope))

(pushnew '("pkiauthorities" "PKIAuthorityState" "gr8s.io/v1" nil)
         *internal-stored-resource-types* :test #'equal)
