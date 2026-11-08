;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Choose the registry credentials for an image from a Pod's imagePullSecrets,
;;;; matching them as the kubelet's keyring does. A credential is a (username .
;;;; password) pair, so nothing here may put one in a message, log or thread name.

(in-package #:gr8s.kubelet)

(defparameter +default-registry-key+ "index.docker.io"
  "The key Docker configs use for the default registry, once their /v1/ path is removed.")

(defparameter *credential-provider-clock* #'get-universal-time
  "Wall clock used to expire executable credential-provider responses.")

(defparameter *credential-provider-timeout-seconds* 60
  "Maximum execution time of one kubelet credential-provider plugin.")

(defstruct image-credential-provider
  "One validated kubelet exec credential provider and its private response cache."
  name executable match-images default-cache-seconds api-version args environment token-attributes
  (cache (make-hash-table :test #'equal))
  (lock (bt:make-lock "image credential provider cache")))

(defun credential-provider-token-attributes (value name)
  "Validate VALUE as kubelet v1 service-account token attributes for provider NAME."
  (when value
    (let* ((attributes (require-object value "tokenAttributes"))
           (audience (gethash "serviceAccountTokenAudience" attributes))
           (cache-type (gethash "cacheType" attributes))
           (required-pair (multiple-value-list (gethash "requireServiceAccount" attributes)))
           (require-service-account (first required-pair))
           (required (credential-provider-string-vector
                      (gethash "requiredServiceAccountAnnotationKeys" attributes #())
                      "requiredServiceAccountAnnotationKeys"))
           (optional (credential-provider-string-vector
                      (gethash "optionalServiceAccountAnnotationKeys" attributes #())
                      "optionalServiceAccountAnnotationKeys")))
      (unless (and (stringp audience) (plusp (length audience)))
        (error "Credential provider ~A token audience is required" name))
      (unless (member cache-type '("ServiceAccount" "Token") :test #'equal)
        (error "Credential provider ~A token cacheType must be ServiceAccount or Token" name))
      (unless (and (second required-pair) (typep require-service-account 'boolean))
        (error "Credential provider ~A requireServiceAccount must be boolean" name))
      (dolist (key (append required optional))
        (unless (core-qualified-key-p key)
          (error "Credential provider ~A annotation key ~S is not qualified" name key)))
      (unless (= (length required) (length (remove-duplicates required :test #'equal)))
        (error "Credential provider ~A has duplicate required annotation keys" name))
      (unless (= (length optional) (length (remove-duplicates optional :test #'equal)))
        (error "Credential provider ~A has duplicate optional annotation keys" name))
      (when (intersection required optional :test #'equal)
        (error "Credential provider ~A annotation keys must be either required or optional" name))
      (when (and required (not require-service-account))
        (error "Credential provider ~A requires annotations but not a ServiceAccount" name))
      (list :audience audience :cache-type cache-type
            :require-service-account require-service-account
            :required-annotations required :optional-annotations optional))))

(defun credential-provider-duration-seconds (value context)
  "Parse VALUE as a nonnegative Go duration, signaling a configuration error otherwise."
  (let ((nanoseconds (and (stringp value) (gr8s.resources::cel-parse-duration value))))
    (unless (and nanoseconds (not (minusp nanoseconds)))
      (error "~A must be a nonnegative duration" context))
    (/ nanoseconds 1000000000)))

(defun credential-provider-string-vector (value context)
  "Return VALUE as a list of strings, requiring its kubelet configuration shape."
  (unless (vectorp value) (error "~A must be an array" context))
  (loop for item across value
        do (unless (stringp item) (error "~A entries must be strings" context))
        collect item))

(defun load-image-credential-providers (config-path bin-directory)
  "Load and validate a kubelet v1 CredentialProviderConfig from CONFIG-PATH.
Provider names resolve only within BIN-DIRECTORY and are returned in configuration order."
  (multiple-value-bind (document duplicates)
      (gr8s.resources::yaml-parse (uiop:read-file-string config-path))
    (when duplicates (error "Credential provider config has duplicate fields: ~{~A~^; ~}" duplicates))
    (let* ((config (require-object document "credential provider config"))
           (providers (gethash "providers" config))
           (seen (make-hash-table :test #'equal)))
      (unless (and (equal "kubelet.config.k8s.io/v1" (gethash "apiVersion" config))
                   (equal "CredentialProviderConfig" (gethash "kind" config)))
        (error "Credential provider config must be kubelet.config.k8s.io/v1 CredentialProviderConfig"))
      (unless (and (vectorp providers) (plusp (length providers)))
        (error "Credential provider config must contain providers"))
      (loop for raw across providers
            for index from 0
            for provider = (require-object raw "credential provider")
            for name = (gethash "name" provider)
            for api-version = (gethash "apiVersion" provider)
            for executable = (and (stringp name) (merge-pathnames name bin-directory))
            do (unless (and (stringp name) (plusp (length name))
                            (null (find #\/ name)) (not (member name '("." "..") :test #'equal)))
                 (error "Credential provider ~D has an invalid name" index))
               (when (gethash name seen) (error "Credential provider name ~A is duplicated" name))
               (setf (gethash name seen) t)
               (unless (equal api-version "credentialprovider.kubelet.k8s.io/v1")
                 (error "Credential provider ~A uses unsupported apiVersion ~A" name api-version))
               (unless (probe-file executable)
                 (error "Credential provider executable ~A does not exist" executable))
            collect
            (make-image-credential-provider
             :name name :executable (namestring executable) :api-version api-version
             :match-images
             (credential-provider-string-vector (gethash "matchImages" provider) "matchImages")
             :default-cache-seconds
             (credential-provider-duration-seconds
              (gethash "defaultCacheDuration" provider) "defaultCacheDuration")
             :args (credential-provider-string-vector (gethash "args" provider #()) "args")
             :token-attributes
             (credential-provider-token-attributes (gethash "tokenAttributes" provider) name)
             :environment
             (let ((environment (gethash "env" provider #())))
               (unless (vectorp environment) (error "env must be an array"))
               (loop for binding across environment
                     for object = (require-object binding "credential provider environment")
                     for variable = (gethash "name" object)
                     for value = (gethash "value" object)
                     do (unless (and (stringp variable) (plusp (length variable))
                                     (stringp value) (null (find #\= variable)))
                          (error "Credential provider ~A has an invalid environment entry" name))
                     collect (format nil "~A=~A" variable value))))))))

(defun credential-provider-response-entries (provider image &optional token annotations)
  "Invoke PROVIDER for IMAGE and return its validated registry entries and cache metadata."
  (let* ((request (core-object "kind" "CredentialProviderRequest"
                               "apiVersion" (image-credential-provider-api-version provider)
                               "image" image))
         (request-ready
           (progn
             (when token (setf (gethash "serviceAccountToken" request) token))
             (when annotations (setf (gethash "serviceAccountAnnotations" request) annotations))
             request))
         (command (append (list "/usr/bin/env")
                          (image-credential-provider-environment provider)
                          (list (image-credential-provider-executable provider))
                          (image-credential-provider-args provider)))
         (output
           (sb-ext:with-timeout *credential-provider-timeout-seconds*
             (uiop:run-program
              command :input (make-string-input-stream (com.inuoe.jzon:stringify request-ready))
              :output '(:string :stripped t) :error-output :string)))
         (response (handler-case (com.inuoe.jzon:parse output)
                     (error () (error "Credential provider ~A returned malformed JSON"
                                      (image-credential-provider-name provider)))))
         (object (require-object response "credential provider response"))
         (cache-key-type (gethash "cacheKeyType" object))
         (duration (if (eq 'missing (gethash "cacheDuration" object 'missing))
                       (image-credential-provider-default-cache-seconds provider)
                       (credential-provider-duration-seconds
                        (gethash "cacheDuration" object) "cacheDuration")))
         (auth (gethash "auth" object (core-object))))
    (unless (and (equal "CredentialProviderResponse" (gethash "kind" object))
                 (equal (image-credential-provider-api-version provider)
                        (gethash "apiVersion" object))
                 (member cache-key-type '("Image" "Registry" "Global") :test #'equal))
      (error "Credential provider ~A returned an invalid response identity or cacheKeyType"
             (image-credential-provider-name provider)))
    (values
     (loop for key being the hash-keys of (require-object auth "credential provider auth")
             using (hash-value credential)
           for entry = (require-object credential "credential provider credential")
           for username = (gethash "username" entry)
           for password = (gethash "password" entry)
           do (unless (and (stringp username) (stringp password))
                (error "Credential provider ~A returned a non-string credential"
                       (image-credential-provider-name provider)))
           collect (list* key username password))
     cache-key-type duration)))

(defun credential-provider-cache-key (type repository)
  "Return the kubelet cache key for TYPE and normalized REPOSITORY."
  (cond ((equal type "Image") repository)
        ((equal type "Registry") (subseq repository 0 (position #\/ repository)))
        ((equal type "Global") "")))

(defun credential-provider-pod-context (provider runtime pod)
  "Return PROVIDER's token, annotations, cache identity and eligibility for POD."
  (let ((attributes (image-credential-provider-token-attributes provider)))
    (unless attributes (return-from credential-provider-pod-context (values nil nil nil t)))
    (let* ((spec (and pod (gethash "spec" (pod-to-object pod))))
           (service-account (and spec (gethash "serviceAccountName" spec ""))))
      (when (zerop (length service-account))
        (return-from credential-provider-pod-context
          (values nil nil nil (not (getf attributes :require-service-account)))))
      (let ((function (and runtime (containerd-runtime-credential-provider-token-function runtime))))
        (unless function (error "No control-plane token provider is connected"))
        (multiple-value-bind (token annotations identity)
            (funcall function pod (getf attributes :audience)
                     (getf attributes :required-annotations)
                     (getf attributes :optional-annotations))
          (let ((cache-identity
                  (list identity
                        (loop for key being the hash-keys of (or annotations (core-object))
                                using (hash-value value)
                              collect (cons key value)))))
            (when (equal "Token" (getf attributes :cache-type))
              (setf cache-identity
                    (list cache-identity
                          (octets-to-hex
                           (ironclad:digest-sequence
                            :sha256 (trivial-utf-8:string-to-utf-8-bytes token))))))
            (values token annotations cache-identity t)))))))

(defun image-credential-provider-entries (providers image &optional runtime pod)
  "Return matching executable-provider registry entries for IMAGE in provider order."
  (let ((repository (image-repository image)) (now (funcall *credential-provider-clock*)))
    (loop for provider in providers
          when (some (lambda (pattern) (registry-key-matches-p pattern repository))
                     (image-credential-provider-match-images provider))
            append
            (handler-case
                (multiple-value-bind (token annotations identity eligible)
                    (credential-provider-pod-context provider runtime pod)
                  (when eligible
                    (bt:with-lock-held ((image-credential-provider-lock provider))
                      (let ((cache (image-credential-provider-cache provider)))
                        (multiple-value-bind (cached hit)
                            (loop for type in '("Image" "Registry" "Global")
                                  for key = (list identity type (credential-provider-cache-key type repository))
                                  for value = (gethash key cache)
                                  when (and value (> (car value) now))
                                    do (return (values (cdr value) t))
                                  finally (return (values nil nil)))
                          (if hit
                              cached
                              (multiple-value-bind (entries type duration)
                                  (if (image-credential-provider-token-attributes provider)
                                      (credential-provider-response-entries provider image token annotations)
                                      (credential-provider-response-entries provider image))
                                (when (and token
                                           (equal "ServiceAccount"
                                                  (getf (image-credential-provider-token-attributes provider)
                                                        :cache-type))
                                           (some (lambda (entry) (equal token (cddr entry))) entries))
                                  (error "Credential provider returned its bound token as a cached password"))
                                (when (plusp duration)
                                  (setf (gethash
                                         (list identity type (credential-provider-cache-key type repository)) cache)
                                        (cons (+ now duration) entries)))
                                entries)))))))
              ;; Plugin errors do not prevent credentials from earlier keyrings
              ;; from being attempted, and their output may contain credentials.
              (error () nil)))))

(defun image-repository (image)
  "Return IMAGE's normalized repository without its tag or digest: docker.io/library/a for a."
  (let* ((name (subseq image 0 (position #\@ image)))
         (last-slash (position #\/ name :from-end t))
         (name (subseq name 0 (position #\: name :start (if last-slash (1+ last-slash) 0))))
         (first-slash (position #\/ name))
         (domain (and first-slash (subseq name 0 first-slash)))
         (default-domain (member domain '("docker.io" "index.docker.io") :test #'equal)))
    (if (and domain (not default-domain)
             (or (find #\. domain) (find #\: domain) (equal domain "localhost")))
        name
        (let ((path (if default-domain (subseq name (1+ first-slash)) name)))
          (format nil "docker.io/~:[library/~;~]~A" (find #\/ path) path)))))

(defun docker-config-key (location)
  "Reduce a Docker config LOCATION to the host and path it applies to, treating /v1/ and /v2/ as the host."
  (let* ((scheme (search "://" location))
         (bare (if scheme (subseq location (+ scheme 3)) location))
         (slash (position #\/ bare))
         (host (subseq bare 0 slash))
         (path (if slash (subseq bare slash) "")))
    (when (or (uiop:string-prefix-p "/v1/" path) (uiop:string-prefix-p "/v2/" path))
      (setf path (subseq path 3)))
    (if (member path '("" "/") :test #'equal) host (concatenate 'string host path))))

(defun host-part-matches-p (glob text)
  "Return whether TEXT matches GLOB, in which * is any run of characters and ? is any one."
  (labels ((match (g s)
             (cond ((= g (length glob)) (= s (length text)))
                   ((char= #\* (char glob g))
                    (or (match (1+ g) s) (and (< s (length text)) (match g (1+ s)))))
                   ((= s (length text)) nil)
                   ((or (char= #\? (char glob g)) (char= (char glob g) (char text s)))
                    (match (1+ g) (1+ s))))))
    (match 0 0)))

(defun split-registry-location (location)
  "Return LOCATION's host name parts, port and path."
  (let* ((slash (position #\/ location))
         (authority (subseq location 0 slash))
         (colon (position #\: authority)))
    (values (uiop:split-string (subseq authority 0 colon) :separator ".")
            (if colon (subseq authority (1+ colon)) "")
            (if slash (subseq location slash) ""))))

(defun registry-key-matches-p (key repository)
  "Return whether Docker config KEY applies to REPOSITORY: same port and host shape, and a path prefix."
  (multiple-value-bind (key-parts key-port key-path) (split-registry-location key)
    (multiple-value-bind (parts port path) (split-registry-location repository)
      (and (equal key-port port)
           (= (length key-parts) (length parts))
           (uiop:string-prefix-p key-path path)
           (every #'host-part-matches-p key-parts parts)))))

(defun docker-config-credential (entry)
  "Return a Docker config ENTRY's credential, its auth field overriding its username and password."
  (flet ((text (field)
           (let ((value (gethash field (require-object entry "registry entry"))))
             (if (stringp value) value ""))))
    (if (zerop (length (text "auth")))
        (cons (text "username") (text "password"))
        ;; Upstream accepts this field with or without base64 padding.
        (let* ((auth (string-right-trim "=" (text "auth")))
               (padding (make-string (mod (- (length auth)) 4) :initial-element #\=))
               (decoded (trivial-utf-8:utf-8-bytes-to-string
                         (ag-grpc:base64-decode (concatenate 'string auth padding))))
               (colon (or (position #\: decoded) (error "auth is not username:password"))))
          (cons (subseq decoded 0 colon) (subseq decoded (1+ colon)))))))

(defun pull-secret-entries (secret)
  "Return (KEY . CREDENTIAL) for each registry in SECRET; a Secret of another type has none."
  (let* ((type (gethash "type" secret))
         (encoded (and (gethash "data" secret)
                       (gethash (cond ((equal type "kubernetes.io/dockerconfigjson") ".dockerconfigjson")
                                      ((equal type "kubernetes.io/dockercfg") ".dockercfg")
                                      (t ""))
                                (gethash "data" secret)))))
    (when encoded
      (let* ((config (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string
                                            (core-base64-bytes encoded "pull secret"))))
             (registries (if (equal type "kubernetes.io/dockerconfigjson")
                             (gethash "auths" (require-object config "pull secret") (core-object))
                             (require-object config "pull secret"))))
        (loop for location being the hash-keys of (require-object registries "pull secret")
                using (hash-value entry)
              collect (cons (docker-config-key location) (docker-config-credential entry)))))))

(defun docker-config-entries (config context)
  "Return registry key/credential pairs from Docker CONFIG, requiring its auths object."
  (let ((registries (gethash "auths" (require-object config context))))
    (loop for location being the hash-keys of (require-object registries context)
            using (hash-value entry)
          collect (cons (docker-config-key location) (docker-config-credential entry)))))

(defun load-node-registry-credentials (path)
  "Read Docker config JSON at PATH and return its validated registry credentials."
  (handler-case
      (docker-config-entries
       (com.inuoe.jzon:parse (uiop:read-file-string path)) "node registry credential file")
    (error ()
      (error "Node registry credential file ~A is malformed" path))))

(defun matching-registry-credentials (entries repository)
  "Return the credentials in ENTRIES for REPOSITORY, the most specific keys first.
Every matching credential is returned, because the kubelet tries them all to allow for rotation."
  (let* ((keys (sort (remove-duplicates (mapcar #'car entries) :test #'equal) #'string>))
         (matched (or (remove-if-not (lambda (key) (registry-key-matches-p key repository)) keys)
                      (when (and (uiop:string-prefix-p "docker.io/" repository)
                                 (member +default-registry-key+ keys :test #'equal))
                        (list +default-registry-key+)))))
    (remove-duplicates
     (loop for key in matched
           append (loop for (entry-key . credential) in entries
                        when (equal key entry-key) collect credential))
     :test #'equal :from-end t)))

(defun pod-pull-secret (runtime pod container-name name)
  "Return POD's pull Secret NAME; a missing one is reported and skipped, as the kubelet does."
  (handler-case (get-core-resource (containerd-runtime-resource-store runtime) "secrets" (pod-namespace pod) name)
    (kubernetes-error (condition)
      (unless (= 404 (kubernetes-error-status-code condition)) (error condition))
      (record-container-lifecycle-event
       runtime (pod-uid pod) container-name name "FailedToRetrieveImagePullSecret"
       (format nil "Unable to retrieve image pull secret ~A; pulling without it" name) "Warning")
      nil)))

(defun pod-image-pull-credentials (runtime pod container-name image)
  "Return POD's credentials for IMAGE, or signal a pull error naming a malformed Secret."
  (let ((entries
          (when (containerd-runtime-resource-store runtime)
            (loop for reference across (gethash "imagePullSecrets" (gethash "spec" (pod-to-object pod)) #())
                  for name = (gethash "name" reference "")
                  for secret = (and (plusp (length name)) (pod-pull-secret runtime pod container-name name))
                  when secret
                    append (handler-case (pull-secret-entries secret)
                             ;; The parse error could quote the Secret, so it isn't repeated.
                             (error ()
                               (error 'container-image-pull-error
                                      :message (format nil "Image pull secret ~A is malformed" name))))))))
    (setf entries
          (append entries
                  (containerd-runtime-registry-credentials runtime)
                  (image-credential-provider-entries
                   (containerd-runtime-credential-providers runtime) image runtime pod)))
    (matching-registry-credentials entries (image-repository image))))

(defun image-pull-job-key (image credentials)
  "Return the pull record's key: pulls with different credentials must not satisfy one another."
  (if credentials
      (format nil "~A|~A" image
              (octets-to-hex (ironclad:digest-sequence
                              :sha256 (trivial-utf-8:string-to-utf-8-bytes (prin1-to-string credentials)))))
      image))

(defun pull-image-with-credentials (socket image credentials)
  "Pull IMAGE, trying each credential in turn as the kubelet does, or anonymously when it has none."
  (if credentials
      (let ((failures nil))
        (dolist (credential credentials (error "~{~A~^; ~}" (nreverse failures)))
          (handler-case (return (cri-pull-image socket image :auth credential))
            (error (condition) (push (princ-to-string condition) failures)))))
      (cri-pull-image socket image)))
