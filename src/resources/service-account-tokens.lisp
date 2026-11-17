;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Mint and verify audience-bound ServiceAccount JSON Web Tokens signed with a
;;;; persisted cluster key, publish that key through OIDC discovery, and keep the
;;;; tokens of projected volumes fresh. Verification always rechecks the live
;;;; account and any bound Pod, so deleting either invalidates the token.

(in-package #:gr8s.resources)

(defparameter +service-account-issuer+ "https://kubernetes.default.svc.cluster.local"
  "The issuer of every minted token, and its default audience, as a kubeadm cluster uses.")

(defparameter +service-account-token-default-seconds+ 3600)
(defparameter +service-account-token-minimum-seconds+ 600)
(defparameter +service-account-token-maximum-seconds+ (expt 2 32))

(defun base64url-encode (bytes)
  "Encode BYTES in unpadded URL-safe base64, as JOSE requires."
  (substitute #\_ #\/ (substitute #\- #\+ (string-right-trim "=" (ag-grpc:base64-encode bytes)))))

(defun base64url-decode (text)
  "Decode unpadded URL-safe base64 TEXT, returning NIL when it is malformed."
  (ignore-errors
   (let* ((standard (substitute #\/ #\_ (substitute #\+ #\- text)))
          (padding (mod (- 4 (mod (length standard) 4)) 4)))
     (when (and (every (lambda (character) (or (alphanumericp character) (find character "+/"))) standard)
                (/= padding 3))
       (ag-grpc:base64-decode
        (concatenate 'string standard (make-string padding :initial-element #\=)))))))

(defun service-account-signing-key-path (store)
  "Return the cluster-wide private signing key record's path under the shared PKI root."
  (merge-pathnames "pki/service-account-signing-key.json" (pod-store-path store)))

(defun legacy-service-account-signing-key-path (store)
  "Return the pre-HA location of STORE's ServiceAccount signing key."
  (merge-pathnames "credentials/service-account-signing-key.json" (pod-store-path store)))

(defun service-account-signing-key-path-under-pki-root (root)
  "Return the ServiceAccount signing key path beneath a control plane's PKI ROOT."
  (merge-pathnames "service-account-signing-key.json" (uiop:ensure-directory-pathname root)))

(defmacro with-service-account-signing-key-lock ((store) &body body)
  "Serialize signing-set mutation across threads and operator CLI processes."
  (let ((store-var (gensym "STORE")) (path-var (gensym "PATH"))
        (stream-var (gensym "STREAM")) (fd-var (gensym "FD")))
    `(let* ((,store-var ,store)
            (,path-var (merge-pathnames "pki/service-account-signing-key.lock"
                                        (pod-store-path ,store-var))))
       (bt:with-lock-held ((pod-store-credential-lock ,store-var))
         (ensure-directories-exist ,path-var)
         (with-open-file (,stream-var ,path-var :direction :io
                                      :if-does-not-exist :create :if-exists :overwrite)
           (let ((,fd-var (sb-sys:fd-stream-fd ,stream-var)))
             (sb-posix:fchmod ,fd-var #o600)
             (unless (zerop (cffi:foreign-funcall "flock" :int ,fd-var :int 2 :int))
               (error "cannot lock ServiceAccount signing-key state"))
             (unwind-protect (progn ,@body)
               (cffi:foreign-funcall "flock" :int ,fd-var :int 8 :int))))))))

(defun service-account-signing-key-from-record (record)
  "Decode the active private key in legacy or version-two JSON RECORD."
  (let* ((entry (if (gethash "keys" record)
                    (find (gethash "activeKid" record) (gethash "keys" record)
                          :key (lambda (candidate) (gethash "kid" candidate)) :test #'equal)
                    record)))
    (unless entry (error "ServiceAccount signing set has no active key"))
    (if (gethash "keys" record)
        (service-account-key-from-entry entry)
        (ironclad:make-private-key :secp256r1
                                   :x (hex-to-octets (gethash "d" entry))
                                   :y (hex-to-octets (gethash "q" entry))))))

(defun service-account-key-entry (key &key (latest-expiry 0))
  "Encode private KEY and its latest issued token expiry as a durable set entry."
  (let ((parts (ironclad:destructure-private-key key)))
    (core-object "kid" (service-account-key-id key)
                 "d" (octets-to-hex (getf parts :x))
                 "q" (octets-to-hex (getf parts :y))
                 "latestExpiry" latest-expiry)))

(defun service-account-key-from-entry (entry)
  "Decode and validate one private-key ENTRY."
  (let ((key (ironclad:make-private-key :secp256r1
                                         :x (hex-to-octets (gethash "d" entry))
                                         :y (hex-to-octets (gethash "q" entry)))))
    (unless (equal (gethash "kid" entry) (service-account-key-id key))
      (error "ServiceAccount signing-key identifier does not match its public key"))
    key))

(defun make-service-account-signing-key-set (key &key (latest-expiry 0))
  "Return the version-two one-key signing set for KEY."
  (let ((entry (service-account-key-entry key :latest-expiry latest-expiry)))
    (core-object "formatVersion" 2 "activeKid" (gethash "kid" entry)
                 "keys" (vector entry))))

(defun validate-service-account-signing-key-set (record)
  "Validate and return version-two signing-set RECORD."
  (unless (= 2 (gethash "formatVersion" record 0))
    (error "unsupported ServiceAccount signing-key format"))
  (let* ((entries (gethash "keys" record))
         (active (gethash "activeKid" record))
         (prepared (gethash "preparedKid" record))
         (ids (and (vectorp entries)
                   (loop for entry across entries
                         collect (progn (service-account-key-from-entry entry)
                                        (gethash "kid" entry))))))
    (unless (and ids (= (length ids) (length (remove-duplicates ids :test #'equal)))
                 (member active ids :test #'equal)
                 (or (null prepared) (and (not (equal active prepared))
                                          (member prepared ids :test #'equal))))
      (error "invalid ServiceAccount signing-key set")))
  record)

(defun migrate-service-account-signing-key-record (record now)
  "Convert a legacy single-key RECORD without shortening any possible token lifetime."
  (make-service-account-signing-key-set
   (service-account-signing-key-from-record record)
   :latest-expiry (+ now +service-account-token-maximum-seconds+)))

(defun write-service-account-signing-key-set (path record)
  "Atomically persist validated signing-set RECORD at PATH."
  (validate-service-account-signing-key-set record)
  (ensure-directories-exist path)
  (write-private-text-atomically path (com.inuoe.jzon:stringify record))
  record)

(defun read-service-account-signing-key-set (store &key (now (unix-time-now)))
  "Read, create, or safely migrate STORE's durable signing set.
The caller must hold STORE's credential lock."
  (let* ((path (service-account-signing-key-path store))
         (legacy (legacy-service-account-signing-key-path store)))
    (unless (probe-file path)
      (if (probe-file legacy)
          (install-shared-service-account-signing-key
           (merge-pathnames "pki/" (pod-store-path store)) (uiop:read-file-string legacy))
          (write-service-account-signing-key-set
           path (make-service-account-signing-key-set
                 (ironclad:generate-key-pair :secp256r1)))))
    (let ((record (com.inuoe.jzon:parse path)))
      (if (gethash "keys" record)
          (validate-service-account-signing-key-set record)
          (write-service-account-signing-key-set
           path (migrate-service-account-signing-key-record record now))))))

(defun install-shared-service-account-signing-key (pki-root json)
  "Install the cluster ServiceAccount signing key beneath PKI-ROOT without replacing a different one."
  (let* ((path (service-account-signing-key-path-under-pki-root pki-root))
         (incoming-record (com.inuoe.jzon:parse json))
         (incoming (service-account-signing-key-from-record incoming-record)))
    (when (gethash "keys" incoming-record)
      (validate-service-account-signing-key-set incoming-record))
    (when (probe-file path)
      (let* ((existing-record (com.inuoe.jzon:parse path))
             (existing (service-account-signing-key-from-record existing-record)))
        (when (gethash "keys" existing-record)
          (validate-service-account-signing-key-set existing-record))
        (unless (equal (service-account-key-id existing) (service-account-key-id incoming))
          (pki-fail "service-account-signing-key-conflict"
                    "~A already has a different ServiceAccount signing key" pki-root))
        (return-from install-shared-service-account-signing-key path)))
    (ensure-directories-exist path)
    (write-private-text-atomically path json)
    path))

(defun load-service-account-signing-key (store)
  "Return the cluster's active signing key, creating or migrating its set once."
  (with-service-account-signing-key-lock (store)
    (let ((key (service-account-signing-key-from-record
                (read-service-account-signing-key-set store))))
      (setf (pod-store-service-account-signing-key store) key)
      key)))

(defun prepare-service-account-signing-key-rotation (store &key (now (unix-time-now)))
  "Add and publish a prepared key without changing the active signer."
  (with-service-account-signing-key-lock (store)
    (let* ((path (service-account-signing-key-path store))
           (record (read-service-account-signing-key-set store :now now))
           (entries (gethash "keys" record)))
      (when (gethash "preparedKid" record)
        (error "ServiceAccount signing-key rotation is already prepared"))
      (unless (= 1 (length entries))
        (error "finalize the previous ServiceAccount signing-key rotation first"))
      (let* ((entry (service-account-key-entry (ironclad:generate-key-pair :secp256r1)))
             (kid (gethash "kid" entry)))
        (setf (gethash "keys" record) (vector (aref entries 0) entry)
              (gethash "preparedKid" record) kid)
        (write-service-account-signing-key-set path record)
        kid))))

(defun promote-service-account-signing-key-rotation (store &key (now (unix-time-now)))
  "Make the prepared key the sole signer while retaining every verification key."
  (with-service-account-signing-key-lock (store)
    (let* ((path (service-account-signing-key-path store))
           (record (read-service-account-signing-key-set store :now now))
           (prepared (gethash "preparedKid" record)))
      (unless prepared (error "ServiceAccount signing-key rotation is not prepared"))
      (setf (gethash "activeKid" record) prepared)
      (remhash "preparedKid" record)
      (write-service-account-signing-key-set path record)
      (setf (pod-store-service-account-signing-key store)
            (service-account-signing-key-from-record record))
      prepared)))

(defun finalize-service-account-signing-key-rotation (store &key (now (unix-time-now)))
  "Remove inactive verification keys only after all of their issued tokens expire."
  (with-service-account-signing-key-lock (store)
    (let* ((path (service-account-signing-key-path store))
           (record (read-service-account-signing-key-set store :now now))
           (active (gethash "activeKid" record))
           (inactive (remove active (coerce (gethash "keys" record) 'list)
                             :key (lambda (entry) (gethash "kid" entry)) :test #'equal)))
      (when (gethash "preparedKid" record)
        (error "promote the prepared ServiceAccount signing key before finalizing"))
      (unless inactive (error "ServiceAccount signing-key rotation has nothing to finalize"))
      (let ((unsafe (find-if (lambda (entry) (> (gethash "latestExpiry" entry 0) now)) inactive)))
        (when unsafe
          (error "ServiceAccount signing key ~A must remain until Unix time ~D"
                 (gethash "kid" unsafe) (gethash "latestExpiry" unsafe))))
      (setf (gethash "keys" record)
            (vector (find active (gethash "keys" record)
                          :key (lambda (entry) (gethash "kid" entry)) :test #'equal)))
      (write-service-account-signing-key-set path record)
      active)))

(defun service-account-public-point (key)
  "Return the uncompressed public point of signing KEY."
  (getf (ironclad:destructure-private-key key) :y))

(defun service-account-key-id (key)
  "Identify signing KEY by the digest of its public point."
  (base64url-encode (ironclad:digest-sequence :sha256 (coerce (service-account-public-point key)
                                                              '(simple-array (unsigned-byte 8) (*))))))

(defun jwt-json-segment (object)
  "Encode OBJECT as one JOSE base64url JSON segment."
  (base64url-encode (stringify-to-utf-8-bytes object)))

(defun unix-time-now ()
  "Return the current Unix time in seconds."
  (- (get-universal-time) 2208988800))

(defun sign-service-account-claims (store claims)
  "Return the compact ES256 token carrying CLAIMS."
  (with-service-account-signing-key-lock (store)
    (let* ((path (service-account-signing-key-path store))
           (record (read-service-account-signing-key-set store))
           (active (gethash "activeKid" record))
           (entry (find active (gethash "keys" record)
                        :key (lambda (candidate) (gethash "kid" candidate)) :test #'equal))
           (expiry (gethash "exp" claims))
           (key (service-account-key-from-entry entry)))
      ;; Persist the retirement gate before a token can escape this process.
      (when (and (integerp expiry) (> expiry (gethash "latestExpiry" entry 0)))
        (setf (gethash "latestExpiry" entry) expiry)
        (write-service-account-signing-key-set path record))
      (let ((signed (concatenate 'string
                                 (jwt-json-segment (core-object "alg" "ES256" "kid" active))
                                 "."
                                 (jwt-json-segment claims))))
        (concatenate 'string signed "."
                     (base64url-encode
                      (ironclad:sign-message
                       key (ironclad:digest-sequence
                            :sha256 (trivial-utf-8:string-to-utf-8-bytes signed)))))))))

(defun mint-service-account-token (store account &key audiences (seconds +service-account-token-default-seconds+) binding node)
  "Mint a token for the stored ACCOUNT. BINDING is (kind name uid), NODE is (name uid) of its Pod's node.
Returns the token and its Unix expiry."
  (let* ((metadata (gethash "metadata" account))
         (namespace (gethash "namespace" metadata)) (name (gethash "name" metadata))
         (now (unix-time-now)) (expiry (+ now seconds))
         (kubernetes (core-object "namespace" namespace
                                  "serviceaccount" (core-object "name" name "uid" (gethash "uid" metadata)))))
    (when binding
      (setf (gethash (string-downcase (first binding)) kubernetes)
            (core-object "name" (second binding) "uid" (third binding))))
    (when node
      (setf (gethash "node" kubernetes) (core-object "name" (first node) "uid" (or (second node) ""))))
    (values
     (sign-service-account-claims
      store (core-object "iss" +service-account-issuer+
                         "sub" (format nil "system:serviceaccount:~A:~A" namespace name)
                         "aud" (coerce (or audiences (list +service-account-issuer+)) 'vector)
                         "exp" expiry "iat" now "nbf" now
                         "jti" (string-downcase (generate-uid))
                         "kubernetes.io" kubernetes))
     expiry)))

(defparameter +verified-token-cache-size+ 4096
  "How many verified token signatures to remember. Signature checks are too slow to repeat per request.")

(defun service-account-jwt-claims (store token)
  "Return TOKEN's claims when this cluster's key signed it, remembering the answer for later requests."
  (let* ((cache (pod-store-verified-tokens store))
         (digest (octets-to-hex (service-account-token-digest token)))
         (known (bt:with-lock-held ((pod-store-credential-lock store)) (gethash digest cache))))
    (or known
        (let ((claims (verify-service-account-jwt-signature store token)))
          (when claims
            (bt:with-lock-held ((pod-store-credential-lock store))
              (when (>= (hash-table-count cache) +verified-token-cache-size+) (clrhash cache))
              (setf (gethash digest cache) claims)))
          claims))))

(defun verify-service-account-jwt-signature (store token)
  "Return TOKEN's claims when a published cluster key signed it, otherwise NIL."
  (let ((parts (uiop:split-string token :separator '(#\.))))
    (when (= 3 (length parts))
      (let* ((header (base64url-decode (first parts)))
             (payload (base64url-decode (second parts)))
             (signature (base64url-decode (third parts)))
             (signed (concatenate 'string (first parts) "." (second parts))))
        (when (and header payload signature (= 64 (length signature)))
          (let ((header-object (ignore-errors (com.inuoe.jzon:parse header))))
            (when (and (hash-table-p header-object) (equal "ES256" (gethash "alg" header-object)))
              (let* ((kid (gethash "kid" header-object))
                     (entry
                       (bt:with-lock-held ((pod-store-credential-lock store))
                         (find kid (gethash "keys" (read-service-account-signing-key-set store))
                               :key (lambda (candidate) (gethash "kid" candidate)) :test #'equal))))
                (when (and entry
                           (ironclad:verify-signature
                            (ironclad:make-public-key
                             :secp256r1 :y (service-account-public-point
                                            (service-account-key-from-entry entry)))
                            (ironclad:digest-sequence
                             :sha256 (trivial-utf-8:string-to-utf-8-bytes signed))
                            (coerce signature '(simple-array (unsigned-byte 8) (*)))))
                  (ignore-errors
                   (com.inuoe.jzon:parse payload)))))))))))

(defun service-account-claims-bound-live-p (store namespace kubernetes)
  "Check any Pod or Secret the claims name is still the same live object."
  (flet ((live-p (reader field)
           (let ((reference (gethash field kubernetes)))
             (or (null reference)
                 (let ((object (ignore-errors (funcall reader (gethash "name" reference)))))
                   (and object (equal (gethash "uid" reference) (gethash "uid" (gethash "metadata" object)))))))))
    (and (live-p (lambda (name) (pod-to-object (get-pod store namespace name))) "pod")
         (live-p (lambda (name) (get-core-resource store "secrets" namespace name)) "secret"))))

(defun service-account-claims-extra (claims)
  "Render what a token's CLAIMS prove as the user extra fields upstream reports."
  (let* ((kubernetes (gethash "kubernetes.io" claims)) (extra (core-object)))
    (flet ((note (key value)
             (when (and (stringp value) (plusp (length value)))
               (setf (gethash (concatenate 'string "authentication.kubernetes.io/" key) extra) (vector value)))))
      (when (gethash "jti" claims) (note "credential-id" (concatenate 'string "JTI=" (gethash "jti" claims))))
      (dolist (field '("pod" "node"))
        (let ((reference (gethash field kubernetes)))
          (when (hash-table-p reference)
            (note (concatenate 'string field "-name") (gethash "name" reference))
            (note (concatenate 'string field "-uid") (gethash "uid" reference))))))
    extra))

(defun verify-service-account-jwt (store token &optional required-audiences)
  "Authenticate TOKEN against its signature, time window, audience and live bindings.
Returns the identity and the audiences it is valid for, intersected with REQUIRED-AUDIENCES."
  (let ((claims (ignore-errors (service-account-jwt-claims store token))))
    (when (and (hash-table-p claims) (equal +service-account-issuer+ (gethash "iss" claims)))
      (let* ((now (unix-time-now))
             (kubernetes (gethash "kubernetes.io" claims))
             (audiences (coerce (let ((value (gethash "aud" claims))) (if (stringp value) (vector value) (or value #()))) 'list))
             (accepted (if required-audiences
                           (intersection audiences required-audiences :test #'equal)
                           audiences)))
        (when (and accepted (hash-table-p kubernetes)
                   (integerp (gethash "exp" claims)) (< now (gethash "exp" claims))
                   (integerp (gethash "nbf" claims)) (<= (gethash "nbf" claims) now))
          (let* ((namespace (gethash "namespace" kubernetes))
                 (reference (gethash "serviceaccount" kubernetes))
                 (account (and (hash-table-p reference)
                               (handler-case (get-core-resource store "serviceaccounts" namespace (gethash "name" reference))
                                 (kubernetes-error () nil)))))
            (when (and account (equal (gethash "uid" reference) (gethash "uid" (gethash "metadata" account)))
                       (service-account-claims-bound-live-p store namespace kubernetes))
              (values (make-api-service-account-identity :namespace namespace :name (gethash "name" reference)
                                                         :uid (gethash "uid" reference)
                                                         :extra (service-account-claims-extra claims))
                      accepted))))))))

;;; OIDC discovery

(defun openid-configuration-response ()
  "Serve the OIDC discovery document for this cluster's issuer."
  (json-response (core-object "issuer" +service-account-issuer+
                              "jwks_uri" (concatenate 'string +service-account-issuer+ "/openid/v1/jwks")
                              "response_types_supported" #("id_token")
                              "subject_types_supported" #("public")
                              "id_token_signing_alg_values_supported" #("ES256"))))

(defun service-account-jwks-object (store)
  "Return every verification JWK in stable key-id order."
  (let ((entries
          (bt:with-lock-held ((pod-store-credential-lock store))
            (sort (copy-list (coerce (gethash "keys" (read-service-account-signing-key-set store)) 'list))
                  #'string< :key (lambda (entry) (gethash "kid" entry))))))
    (core-object
     "keys"
     (coerce
      (loop for entry in entries
            for key = (service-account-key-from-entry entry)
            for point = (service-account-public-point key)
            collect (core-object "use" "sig" "kty" "EC" "crv" "P-256" "alg" "ES256"
                                 "kid" (gethash "kid" entry)
                                 "x" (base64url-encode (subseq point 1 33))
                                 "y" (base64url-encode (subseq point 33 65))))
      'vector))))

(defun openid-jwks-response (store)
  "Serve all retained public signing keys as a JSON Web Key Set."
  (let ((response (json-response (service-account-jwks-object store))))
    (setf (hunchentoot:content-type*) "application/jwk-set+json")
    response))

;;; Projected volumes

(defun pod-projected-token-sources (pod)
  "List POD's serviceAccountToken projections in a stable order."
  (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
        for projected = (gethash "projected" volume)
        when projected
          append (loop for source across (gethash "sources" projected #())
                       for token = (gethash "serviceAccountToken" source)
                       when token collect token)))

(defun projected-token-secret-name (pod)
  "Name the agent-side Secret that carries POD's minted projected tokens. It is never stored on the server."
  ;; UIDs are uppercase, and an object name must be a lowercase DNS subdomain.
  (format nil "gr8s-projected-token-~A" (string-downcase (pod-uid pod))))

(defun projected-token-data-key (source)
  "Name the entry holding the token a projection SOURCE asks for."
  (string-downcase
   (octets-to-hex
    (ironclad:digest-sequence
     :sha256 (trivial-utf-8:string-to-utf-8-bytes
              (format nil "~A|~A" (gethash "audience" source "")
                      (gethash "expirationSeconds" source +service-account-token-default-seconds+)))))))

(defun pod-token-node-claim (store pod)
  "Return the (name uid) of the node POD runs on, for a token to prove, or NIL before it is assigned."
  (let ((name (pod-node-name pod)))
    (when name
      (list name (ignore-errors (gethash "uid" (gethash "metadata" (node-api-object (get-node store name)))))))))

(defun cached-projected-token (store pod source)
  "Return a current token for projection SOURCE, renewing it after 80% of its lifetime, as a kubelet does."
  (let* ((key (list (pod-uid pod) (projected-token-data-key source)))
         (cache (pod-store-projected-tokens store))
         (now (unix-time-now))
         (entry (bt:with-lock-held ((pod-store-credential-lock store)) (gethash key cache))))
    (if (and entry (< now (getf entry :refresh)))
        (getf entry :token)
        (let* ((seconds (gethash "expirationSeconds" source +service-account-token-default-seconds+))
               (audience (gethash "audience" source ""))
               (account (get-core-resource store "serviceaccounts" (pod-namespace pod)
                                           (or (gethash "serviceAccountName" (gethash "spec" (pod-to-object pod))) "default"))))
          (multiple-value-bind (token expiry)
              (mint-service-account-token store account
                                          :audiences (when (plusp (length audience)) (list audience))
                                          :seconds seconds
                                          :binding (list "pod" (pod-name pod) (pod-uid pod))
                                          :node (pod-token-node-claim store pod))
            (bt:with-lock-held ((pod-store-credential-lock store))
              (setf (gethash key cache)
                    (list :token token :pod (pod-uid pod) :refresh (- expiry (ceiling seconds 5)))))
            token)))))

(defun pod-projected-token-object (store pod)
  "Return the transient Secret delivering POD's minted tokens to its agent, or NIL if it projects none."
  (let ((sources (pod-projected-token-sources pod)))
    (when sources
      (let ((data (core-object)))
        (dolist (source sources)
          (setf (gethash (projected-token-data-key source) data)
                (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes (cached-projected-token store pod source)))))
        (core-object "apiVersion" "v1" "kind" "Secret" "type" "Opaque"
                     "metadata" (core-object "name" (projected-token-secret-name pod) "namespace" (pod-namespace pod))
                     "data" data)))))

(defun pod-fs-user (pod)
  "Return the one user every init and application container of POD runs as, or NIL, as the
kubelet's FsUserFrom does: each container's own runAsUser, else the Pod's."
  (let* ((spec (gethash "spec" (pod-to-object pod)))
         (pod-user (gethash "runAsUser" (gethash "securityContext" spec (core-object))))
         (users (loop for container across (concatenate 'vector (gethash "initContainers" spec #())
                                                        (gethash "containers" spec #()))
                      collect (or (gethash "runAsUser" (gethash "securityContext" container (core-object)))
                                  pod-user))))
    (when (and users (every #'integerp users) (every (lambda (user) (eql user (first users))) users))
      (first users))))

(defun projected-token-volume-files (runtime pod source default-mode)
  "Return the (path bytes mode owner) entry writing the token a projection SOURCE asks for.
As the kubelet's projected volume plugin does, a Pod with one runAsUser or with an fsGroup gets
a token readable only by its owner, that user, instead of DEFAULT-MODE; fsGroup adds group read."
  (let* ((secret (get-core-resource (containerd-runtime-resource-store runtime) "secrets" (pod-namespace pod)
                                    (projected-token-secret-name pod)))
         (encoded (gethash (projected-token-data-key source) (gethash "data" secret))))
    (unless encoded
      (error 'runtime-error :message "The control plane has not delivered this projected token"))
    (let ((user (pod-fs-user pod)))
      (list (list (gethash "path" source) (ag-grpc:base64-decode encoded)
                  (if (or user (pod-fs-group pod)) #o600 default-mode)
                  user)))))

(defun prune-projected-tokens (store)
  "Forget the cached tokens and podCertificate keys of Pods that no longer exist."
  (let ((live (make-hash-table :test #'equal)))
    (dolist (pod (list-pods store)) (setf (gethash (pod-uid pod) live) t))
    (bt:with-lock-held ((pod-store-credential-lock store))
      (dolist (cache (list (pod-store-projected-tokens store) (pod-store-pod-certificates store)))
        (loop for key being the hash-keys of cache using (hash-value entry)
              unless (gethash (getf entry :pod) live) do (remhash key cache))))))
