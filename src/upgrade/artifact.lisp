;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; A gr8s release's packages as one signed OCI artifact (podster-igs.1). Its
;;;; manifest holds every package -- RPM and DEB, for each architecture -- as a layer
;;;; of its own, so a host fetches only its one; release.json, which names each
;;;; package's file, architecture, format and SHA-256; and release.json.sig, an
;;;; Ed25519 signature of release.json by a release key gr8s carries. A host trusts
;;;; a package only through that signature: the registry, its TLS and the digests
;;;; it serves prove where bytes came from, not who released them.
;;;;
;;;; The registry client speaks the OCI Distribution API through the image
;;;; distribution's verified requests (each host its own CA, redirects checked hop
;;;; by hop), with the bearer-token challenge registries such as ghcr.io use.

(in-package #:gr8s.upgrade)

(defparameter +release-artifact-type+ "application/vnd.gr8s.release.v1")
(defparameter +release-manifest-media-type+ "application/vnd.gr8s.release.manifest.v1+json")
(defparameter +release-signature-media-type+ "application/vnd.gr8s.release.signature.v1")
(defparameter +oci-manifest-media-type+ "application/vnd.oci.image.manifest.v1+json")
(defparameter +oci-empty-media-type+ "application/vnd.oci.empty.v1+json")

(defun package-media-type (format)
  (format nil "application/vnd.gr8s.package.~(~A~)" format))

;;; Keys.

(defstruct (release-key (:constructor %make-release-key (id public private)))
  "An Ed25519 release key: its public half, and the private half when it can sign."
  id public private)

(defun octets-hex (octets) (ironclad:byte-array-to-hex-string octets))

(defun hex-octets (text)
  (handler-case (ironclad:hex-string-to-byte-array (string-trim '(#\Space #\Newline #\Return #\Tab) text))
    (error () (upgrade-fail "~S is not a hexadecimal key" text))))

(defun release-key-id-of (public)
  "A key's name: the first 16 hexadecimal digits of its public half's SHA-256."
  (subseq (octets-hex (ironclad:digest-sequence :sha256 public)) 0 16))

(defun make-release-public-key (public-hex)
  (let ((public (hex-octets public-hex)))
    (unless (= 32 (length public)) (upgrade-fail "an Ed25519 public key is 32 bytes, not ~D" (length public)))
    (%make-release-key (release-key-id-of public) public nil)))

(defun read-release-signing-key (text)
  "The signing key TEXT holds: the 32-byte Ed25519 private key in hexadecimal."
  (let ((private (hex-octets text)))
    (unless (= 32 (length private)) (upgrade-fail "an Ed25519 private key is 32 bytes, not ~D" (length private)))
    (let ((public (ironclad::ed25519-public-key private)))
      (%make-release-key (release-key-id-of public) public private))))

(defparameter *trusted-release-keys*
  (mapcar #'make-release-public-key
          '(;; gr8s release key 1, held by the release workflow as GR8S_RELEASE_SIGNING_KEY.
            "ff5919d63b809e4888681224f471a615dd93c4356207ba785d8f50d1cd2fb403"))
  "The release keys a host trusts a package from. A key is retired by a release that
drops it; hosts trust whatever the release they run carries.")

(defun sign-release-manifest (key octets)
  (unless (release-key-private key) (upgrade-fail "release key ~A can't sign: it has no private half" (release-key-id key)))
  (ironclad:sign-message (ironclad:make-private-key :ed25519 :x (release-key-private key) :y (release-key-public key))
                         octets))

(defun verify-release-manifest (octets signature key-id &key (keys *trusted-release-keys*))
  "Signal unless SIGNATURE is a trusted release key's signature of OCTETS, release.json."
  (let ((key (find key-id keys :key #'release-key-id :test #'equal)))
    (unless key
      (upgrade-fail "the release is signed by key ~A, which this gr8s doesn't trust" key-id))
    (unless (ignore-errors
             (ironclad:verify-signature (ironclad:make-public-key :ed25519 :y (release-key-public key))
                                        octets signature))
      (upgrade-fail "the release's signature by key ~A is not valid" key-id))
    key))

;;; References.

(defun parse-artifact-reference (reference)
  "REFERENCE, REGISTRY/REPOSITORY:TAG or REGISTRY/REPOSITORY@sha256:..., as (values
registry repository tag-or-digest)."
  (let* ((slash (position #\/ reference))
         (at (position #\@ reference))
         (colon (and (null at) slash (position #\: reference :start slash :from-end t))))
    (unless (and slash (or at colon))
      (upgrade-fail "~S names no registry, repository and tag or digest, as ghcr.io/atgreen/gr8s-packages:v1.37.2-gr8s.8" reference))
    (let ((registry (subseq reference 0 slash))
          (repository (subseq reference (1+ slash) (or at colon)))
          (target (subseq reference (1+ (or at colon)))))
      (unless (and (gr8s.image-distribution::valid-registry-host-p registry)
                   (cl-ppcre:scan "^[a-z0-9]+(?:[._/-][a-z0-9]+)*$" repository)
                   (if at
                       (cl-ppcre:scan "^sha256:[0-9a-f]{64}$" target)
                       (cl-ppcre:scan "^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$" target)))
        (upgrade-fail "~S is not a valid artifact reference" reference))
      (values registry repository target))))

;;; The registry client.

(defvar *registry-http* 'gr8s.image-distribution::registry-http-request
  "The function a registry request goes through, as REGISTRY-HTTP-REQUEST takes its
arguments: a URL, headers, then drakma's keywords. Tests stand a registry in for it.")

(defstruct (registry-session (:constructor %make-registry-session (registry repository username password)))
  "Requests to one repository of one registry, with the bearer token it last handed out."
  registry repository username password token)

(defun registry-auth-files ()
  "Where podman and Docker keep registry logins, the ones podman reads first."
  (remove nil (list (uiop:getenv "REGISTRY_AUTH_FILE")
                    (let ((runtime (uiop:getenv "XDG_RUNTIME_DIR")))
                      (and runtime (format nil "~A/containers/auth.json" runtime)))
                    (namestring (merge-pathnames ".config/containers/auth.json" (user-homedir-pathname)))
                    (namestring (merge-pathnames ".docker/config.json" (user-homedir-pathname))))))

(defun stored-registry-credentials (registry)
  "The login `podman login' or `docker login' stored for REGISTRY: (values username password)."
  (dolist (file (registry-auth-files))
    (let* ((object (ignore-errors (com.inuoe.jzon:parse (uiop:read-file-string file))))
           (entry (and (hash-table-p object) (hash-table-p (gethash "auths" object))
                       (gethash registry (gethash "auths" object))))
           (auth (and (hash-table-p entry) (gethash "auth" entry)))
           (pair (and (stringp auth)
                      (ignore-errors (trivial-utf-8:utf-8-bytes-to-string (ag-grpc:base64-decode auth)))))
           (colon (and pair (position #\: pair))))
      (when colon (return (values (subseq pair 0 colon) (subseq pair (1+ colon))))))))

(defun make-registry-session (registry repository &key username password)
  "A session with REGISTRY's REPOSITORY, logged in as USERNAME, or as the login stored
for REGISTRY, if any."
  (if username
      (%make-registry-session registry repository username password)
      (multiple-value-bind (stored-username stored-password) (stored-registry-credentials registry)
        (%make-registry-session registry repository stored-username stored-password))))

(defun challenge-parameters (header)
  "The parameters of a WWW-Authenticate Bearer challenge, as an alist."
  (let ((parameters nil))
    (cl-ppcre:do-register-groups (name value) ("([a-zA-Z]+)=\"([^\"]*)\"" header)
      (push (cons (string-downcase name) value) parameters))
    parameters))

(defun registry-url (session path)
  (format nil "https://~A/v2/~A/~A" (registry-session-registry session) (registry-session-repository session) path))

(defun fetch-registry-token (session challenge)
  "Answer CHALLENGE, a Bearer WWW-Authenticate header, with a token from its realm."
  (let* ((parameters (challenge-parameters challenge))
         (realm (cdr (assoc "realm" parameters :test #'string=))))
    (unless (and realm (uiop:string-prefix-p "https://" realm))
      (upgrade-fail "registry ~A asks for credentials in a way gr8s doesn't speak: ~A"
                    (registry-session-registry session) challenge))
    (multiple-value-bind (body status)
        (apply *registry-http*
               (format nil "~A?~{~A=~A~^&~}" realm
                       (loop for key in '("service" "scope")
                             for value = (cdr (assoc key parameters :test #'string=))
                             when value collect key and collect (drakma:url-encode value :utf-8)))
               nil :method :get :force-binary t
               (when (registry-session-username session)
                 (list :basic-authorization (list (registry-session-username session)
                                                  (registry-session-password session)))))
      (unless (= status 200)
        (upgrade-fail "registry ~A refused a token (HTTP ~D)" (registry-session-registry session) status))
      (let ((object (com.inuoe.jzon:parse body)))
        (or (gethash "token" object) (gethash "access_token" object)
            (upgrade-fail "registry ~A's token answer has no token" (registry-session-registry session)))))))

(defun registry-request (session url &rest arguments &key (headers nil) &allow-other-keys)
  "Request URL of SESSION's registry, answering one bearer challenge; return (values
body status headers)."
  (remf arguments :headers)
  (flet ((attempt ()
           (apply *registry-http*
                  url
                  (append headers
                          (when (registry-session-token session)
                            (list (cons "Authorization" (format nil "Bearer ~A" (registry-session-token session))))))
                  :force-binary t arguments)))
    (multiple-value-bind (body status response-headers) (attempt)
      (let ((challenge (and (= status 401) (drakma:header-value :www-authenticate response-headers))))
        (cond ((and challenge (uiop:string-prefix-p "bearer" (string-downcase challenge)))
               (setf (registry-session-token session) (fetch-registry-token session challenge))
               (attempt))
              ;; A registry such as zot or distribution's htpasswd asks for the
              ;; credentials themselves, on every request.
              ((and challenge (uiop:string-prefix-p "basic" (string-downcase challenge))
                    (registry-session-username session))
               (apply *registry-http* url headers :force-binary t
                      :basic-authorization (list (registry-session-username session)
                                                 (registry-session-password session))
                      arguments))
              (t (values body status response-headers)))))))

(defun sha256-digest (octets)
  (concatenate 'string "sha256:" (octets-hex (ironclad:digest-sequence :sha256 octets))))

(defun fetch-manifest (session target)
  "The manifest TARGET, a tag or digest, names: (values object octets digest)."
  (multiple-value-bind (body status) (registry-request session (registry-url session (format nil "manifests/~A" target))
                                                       :method :get
                                                       :headers (list (cons "Accept" +oci-manifest-media-type+)))
    (unless (= status 200)
      (upgrade-fail "~A/~A has no manifest ~A (HTTP ~D)" (registry-session-registry session)
                    (registry-session-repository session) target status))
    (let ((digest (sha256-digest body)))
      (when (and (uiop:string-prefix-p "sha256:" target) (not (equal digest target)))
        (upgrade-fail "manifest ~A arrived with digest ~A" target digest))
      (values (com.inuoe.jzon:parse body) body digest))))

(defun fetch-blob-octets (session digest)
  "The blob DIGEST names, checked against it."
  (multiple-value-bind (body status) (registry-request session (registry-url session (format nil "blobs/~A" digest)) :method :get)
    (unless (= status 200)
      (upgrade-fail "blob ~A: HTTP ~D" digest status))
    (unless (equal (sha256-digest body) digest)
      (upgrade-fail "blob ~A arrived with another digest" digest))
    body))

(defun fetch-blob-to-file (session digest path)
  "Stream the blob DIGEST names into PATH, checking it against DIGEST."
  (multiple-value-bind (stream status)
      (registry-request session (registry-url session (format nil "blobs/~A" digest)) :method :get :want-stream t)
    (unwind-protect
         (progn
           (unless (= status 200) (upgrade-fail "blob ~A: HTTP ~D" digest status))
           (let ((hash (ironclad:make-digest :sha256))
                 (buffer (make-array 65536 :element-type '(unsigned-byte 8))))
             (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                                       :if-exists :supersede :if-does-not-exist :create)
               (loop for count = (read-sequence buffer stream)
                     while (plusp count)
                     do (ironclad:update-digest hash buffer :end count)
                        (write-sequence buffer out :end count)))
             (let ((received (concatenate 'string "sha256:" (octets-hex (ironclad:produce-digest hash)))))
               (unless (equal received digest)
                 (delete-file path)
                 (upgrade-fail "blob ~A arrived with digest ~A" digest received)))))
      (when (streamp stream) (close stream :abort t))))
  path)

(defun blob-present-p (session digest)
  (multiple-value-bind (body status) (registry-request session (registry-url session (format nil "blobs/~A" digest)) :method :head)
    (declare (ignore body))
    (= status 200)))

(defun push-blob (session octets-or-path)
  "Upload a blob, an octet vector or a file, unless the registry has it; return its digest and size."
  (let* ((octets (if (pathnamep octets-or-path)
                     (with-open-file (in octets-or-path :element-type '(unsigned-byte 8))
                       (let ((buffer (make-array (file-length in) :element-type '(unsigned-byte 8))))
                         (read-sequence buffer in)
                         buffer))
                     octets-or-path))
         (digest (sha256-digest octets)))
    (unless (blob-present-p session digest)
      (multiple-value-bind (body status headers)
          (registry-request session (registry-url session "blobs/uploads/") :method :post :content-length 0 :content "")
        (declare (ignore body))
        (unless (= status 202) (upgrade-fail "registry refused a blob upload (HTTP ~D)" status))
        (let* ((location (or (drakma:header-value :location headers) (upgrade-fail "a blob upload had no Location")))
               (url (puri:render-uri (puri:merge-uris location (registry-url session "blobs/uploads/")) nil))
               (url (format nil "~A~:[?~;&~]digest=~A" url (find #\? url) (drakma:url-encode digest :utf-8))))
          (multiple-value-bind (body status)
              (registry-request session url :method :put :content octets :content-type "application/octet-stream")
            (declare (ignore body))
            (unless (= status 201) (upgrade-fail "registry refused blob ~A (HTTP ~D)" digest status))))))
    (values digest (length octets))))

(defun push-manifest (session tag octets)
  (multiple-value-bind (body status)
      (registry-request session (registry-url session (format nil "manifests/~A" tag))
                        :method :put :content octets :content-type +oci-manifest-media-type+)
    (declare (ignore body))
    (unless (= status 201) (upgrade-fail "registry refused manifest ~A (HTTP ~D)" tag status))
    (sha256-digest octets)))

;;; The release artifact.

(defstruct (release-artifact (:constructor make-release-artifact (reference digest version packages manifest session)))
  "A fetched, verified release: its manifest digest, version, and packages as plists of
:file :architecture :format :sha256 :size :digest."
  reference digest version packages manifest session)

(defun package-file-facts (path)
  "What release.json says of the package at PATH: from nfpm's file names
gr8s-1.37.2+gr8s.7-1.x86_64.rpm and gr8s_1.37.2+gr8s.7-1_amd64.deb."
  (let ((name (file-namestring path)))
    (multiple-value-bind (format architecture)
        (cond ((cl-ppcre:scan "\\.x86_64\\.rpm$" name) (values "rpm" "amd64"))
              ((cl-ppcre:scan "\\.aarch64\\.rpm$" name) (values "rpm" "arm64"))
              ((cl-ppcre:scan "_amd64\\.deb$" name) (values "deb" "amd64"))
              ((cl-ppcre:scan "_arm64\\.deb$" name) (values "deb" "arm64"))
              ;; The bare executables, for hosts install.sh set up.
              ((cl-ppcre:scan "^gr8s-linux-amd64$" name) (values "binary" "amd64"))
              ((cl-ppcre:scan "^gr8s-linux-arm64$" name) (values "binary" "arm64"))
              (t (upgrade-fail "~A is not a gr8s RPM, DEB or executable for amd64 or arm64" name)))
      (with-open-file (in path :element-type '(unsigned-byte 8))
        (let ((octets (make-array (file-length in) :element-type '(unsigned-byte 8))))
          (read-sequence octets in)
          (list :file name :architecture architecture :format format
                :sha256 (octets-hex (ironclad:digest-sequence :sha256 octets)) :size (length octets)))))))

(defun release-manifest-octets (version packages)
  (trivial-utf-8:string-to-utf-8-bytes
   (com.inuoe.jzon:stringify
    (gr8s-resources-object
     "version" version
     "packages" (coerce (loop for package in packages
                              collect (gr8s-resources-object
                                       "file" (getf package :file) "architecture" (getf package :architecture)
                                       "format" (getf package :format) "sha256" (getf package :sha256)
                                       "size" (getf package :size)))
                        'vector))
    :pretty t)))

(defun gr8s-resources-object (&rest pairs)
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key object) value))
    object))

(defun descriptor (media-type digest size &rest annotations)
  (let ((object (gr8s-resources-object "mediaType" media-type "digest" digest "size" size)))
    (when annotations (setf (gethash "annotations" object) (apply #'gr8s-resources-object annotations)))
    object))

(defun publish-release-artifact (reference version package-paths key &key username password)
  "Push PACKAGE-PATHS as release VERSION to REFERENCE (REGISTRY/REPOSITORY:TAG), with
release.json signed by KEY. Return the manifest's digest."
  (multiple-value-bind (registry repository tag) (parse-artifact-reference reference)
    (let* ((session (make-registry-session registry repository :username username :password password))
           (packages (mapcar #'package-file-facts package-paths))
           (release (release-manifest-octets version packages))
           (signature (sign-release-manifest key release))
           (layers nil))
      (flet ((layer (media-type content &rest annotations)
               (multiple-value-bind (digest size) (push-blob session content)
                 (push (apply #'descriptor media-type digest size annotations) layers)
                 digest)))
        (layer +release-manifest-media-type+ release "org.opencontainers.image.title" "release.json")
        (layer +release-signature-media-type+ signature "org.opencontainers.image.title" "release.json.sig"
               "io.gr8s.release.key" (release-key-id key))
        (loop for package in packages for path in package-paths
              do (layer (package-media-type (getf package :format)) (pathname path)
                        "org.opencontainers.image.title" (getf package :file)
                        "io.gr8s.package.architecture" (getf package :architecture)
                        "io.gr8s.package.format" (getf package :format))))
      (let ((empty (trivial-utf-8:string-to-utf-8-bytes "{}")))
        (push-blob session empty)
        (push-manifest session tag
                       (trivial-utf-8:string-to-utf-8-bytes
                        (com.inuoe.jzon:stringify
                         (gr8s-resources-object
                          "schemaVersion" 2 "mediaType" +oci-manifest-media-type+
                          "artifactType" +release-artifact-type+
                          "config" (descriptor +oci-empty-media-type+ (sha256-digest empty) 2)
                          "layers" (coerce (reverse layers) 'vector)
                          "annotations" (gr8s-resources-object "org.opencontainers.image.version" version)))))))))

(defun manifest-layer (manifest media-type)
  (find media-type (gethash "layers" manifest #()) :key (lambda (layer) (gethash "mediaType" layer)) :test #'equal))

(defun fetch-release-artifact (reference &key (keys *trusted-release-keys*) username password)
  "Fetch the release REFERENCE names and verify its signature: a RELEASE-ARTIFACT whose
packages can be fetched with FETCH-RELEASE-PACKAGE."
  (multiple-value-bind (registry repository target) (parse-artifact-reference reference)
    (let ((session (make-registry-session registry repository :username username :password password)))
      (multiple-value-bind (manifest octets digest) (fetch-manifest session target)
        (declare (ignore octets))
        (unless (equal +release-artifact-type+ (gethash "artifactType" manifest))
          (upgrade-fail "~A is not a gr8s release (its artifact type is ~S)" reference (gethash "artifactType" manifest)))
        (let* ((release-layer (or (manifest-layer manifest +release-manifest-media-type+)
                                  (upgrade-fail "~A has no release.json" reference)))
               (signature-layer (or (manifest-layer manifest +release-signature-media-type+)
                                    (upgrade-fail "~A is not signed" reference)))
               (release (fetch-blob-octets session (gethash "digest" release-layer)))
               (signature (fetch-blob-octets session (gethash "digest" signature-layer))))
          (verify-release-manifest release signature
                                   (gethash "io.gr8s.release.key" (gethash "annotations" signature-layer (gr8s-resources-object)))
                                   :keys keys)
          (let ((object (com.inuoe.jzon:parse release)))
            (make-release-artifact
             reference digest (gethash "version" object)
             (loop for package across (gethash "packages" object #())
                   for file = (gethash "file" package)
                   for layer = (find file (gethash "layers" manifest #())
                                     :key (lambda (layer) (gethash "org.opencontainers.image.title"
                                                                   (gethash "annotations" layer (gr8s-resources-object))))
                                     :test #'equal)
                   when layer
                     collect (list :file file :architecture (gethash "architecture" package)
                                   :format (gethash "format" package) :sha256 (gethash "sha256" package)
                                   :size (gethash "size" package) :digest (gethash "digest" layer)))
             manifest session)))))))

(defun fetch-release-package (artifact package directory)
  "Fetch PACKAGE of ARTIFACT into DIRECTORY, checked against the signed release.json."
  (let ((path (merge-pathnames (getf package :file) (uiop:ensure-directory-pathname directory))))
    (ensure-directories-exist path)
    (fetch-blob-to-file (release-artifact-session artifact) (getf package :digest) path)
    ;; The layer's digest is the registry's word; release.json's SHA-256 is the release's.
    (unless (equal (concatenate 'string "sha256:" (getf package :sha256)) (getf package :digest))
      (delete-file path)
      (upgrade-fail "~A differs from the signed release.json" (getf package :file)))
    path))

(defun mirror-release-artifact (source destination &key username password)
  "Copy the verified release SOURCE names to DESTINATION, REGISTRY/REPOSITORY:TAG, by
digest: the same manifest, so the same signature. Return the manifest's digest."
  (let ((artifact (fetch-release-artifact source)))
    (multiple-value-bind (registry repository tag) (parse-artifact-reference destination)
      (let ((target (make-registry-session registry repository :username username :password password))
            (origin (release-artifact-session artifact))
            (manifest (release-artifact-manifest artifact)))
        (dolist (descriptor (cons (gethash "config" manifest) (coerce (gethash "layers" manifest) 'list)))
          (let ((digest (gethash "digest" descriptor)))
            (unless (blob-present-p target digest)
              (uiop:with-temporary-file (:pathname path :keep nil)
                (fetch-blob-to-file origin digest path)
                (push-blob target (pathname path))))))
        (multiple-value-bind (object octets digest) (fetch-manifest origin (release-artifact-digest artifact))
          (declare (ignore object digest))
          (push-manifest target tag octets))))))
