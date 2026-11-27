;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Images for browser nodes (podster-57fv.4, docs/design-browser-nodes.md).
;;;;
;;;; A browser can't pull from most registries itself (they send no CORS headers), and
;;;; it shouldn't hold registry credentials. So the server resolves a container's image
;;;; to its linux/arm64 manifest and configuration, and serves the layers from a cache;
;;;; the browser unpacks them, in order and with their whiteouts, into the container's
;;;; root, and the guest runs the container chrooted there. Only layers of images the
;;;; server resolved are served, so the join listener is no open proxy. Each layer is
;;;; checked against its digest before it is cached; a zstd layer is then decompressed
;;;; here, since a browser can't. A Pod's imagePullSecrets authenticate the server's
;;;; requests and never reach the browser.

(in-package #:gr8s.server)

(defparameter +browser-image-manifest-types+
  '("application/vnd.oci.image.index.v1+json"
    "application/vnd.docker.distribution.manifest.list.v2+json"
    "application/vnd.oci.image.manifest.v1+json"
    "application/vnd.docker.distribution.manifest.v2+json")
  "The manifest media types a browser image may resolve through.")

(defun parse-image-reference (reference)
  "REFERENCE (busybox, ghcr.io/o/r:tag, r@sha256:...) as (values registry repository
tag-or-digest), with Docker Hub's defaults."
  (let* ((at (position #\@ reference))
         (name (subseq reference 0 (or at (length reference))))
         (slash (position #\/ name))
         (first (and slash (subseq name 0 slash)))
         (registry (if (and first (or (find #\. first) (find #\: first) (equal first "localhost")))
                       first "docker.io"))
         (path (if (equal registry "docker.io")
                   (if (and first (not (find #\. first)) (not (find #\: first)) (not (equal first "localhost")))
                       name
                       (subseq name (if first (1+ slash) 0)))
                   (subseq name (1+ slash))))
         (colon (position #\: path :from-end t))
         (tag (cond (at (subseq reference (1+ at)))
                    ((and colon (not (find #\/ path :start colon))) (subseq path (1+ colon)))
                    (t "latest")))
         (repository (if (and colon (not at) (not (find #\/ path :start colon))) (subseq path 0 colon) path)))
    (when (and (equal registry "docker.io") (not (find #\/ repository)))
      (setf repository (concatenate 'string "library/" repository)))
    (values registry repository tag)))

(defun basic-authorization (credential)
  "The Basic Authorization value for CREDENTIAL, (username . password)."
  (format nil "Basic ~A" (cl-base64:string-to-base64-string
                          (format nil "~A:~A" (car credential) (cdr credential)))))

(defun registry-bearer-token (challenge repository &optional credential)
  "A token for pulling REPOSITORY, from the realm a WWW-Authenticate Bearer CHALLENGE names,
asked for with CREDENTIAL, (username . password), or anonymously. NIL when the challenge
is not Bearer."
  (when (and challenge (uiop:string-prefix-p "Bearer " challenge))
    (let ((fields (make-hash-table :test #'equal)))
      (cl-ppcre:do-register-groups (key value) ("([a-zA-Z]+)=\"([^\"]*)\"" challenge)
        (setf (gethash key fields) value))
      (let ((realm (gethash "realm" fields)))
        (when realm
          (let* ((url (format nil "~A?~@[service=~A&~]scope=repository:~A:pull" realm
                              (and (gethash "service" fields) (hunchentoot:url-encode (gethash "service" fields)))
                              repository))
                 (body (gr8s.image-distribution::registry-http-request
                        url (and credential (list (cons "Authorization" (basic-authorization credential))))
                        :method :get :force-binary t))
                 (object (com.inuoe.jzon:parse body)))
            (or (gethash "token" object) (gethash "access_token" object))))))))

(defun registry-fetch (registry repository path accept token-cell &key want-stream)
  "GET PATH from REPOSITORY's REGISTRY, authenticating with the Authorization in TOKEN-CELL,
a list (authorization credential): a challenge fills its first element, from its credential
when it has one. Returns (values body headers). Signals on failure."
  (flet ((request ()
           (gr8s.image-distribution::registry-http-request
            (gr8s.image-distribution::upstream-registry-url (gr8s.image-distribution::registry-origin-host registry) path)
            (append (and accept (list (cons "Accept" accept)))
                    (and (car token-cell) (list (cons "Authorization" (car token-cell)))))
            :method :get :force-binary t :want-stream want-stream)))
    (multiple-value-bind (body status headers) (request)
      (when (and (= status 401) (null (car token-cell)))
        (when (streamp body) (close body))
        (let ((challenge (drakma:header-value :www-authenticate headers))
              (credential (second token-cell)))
          (setf (car token-cell)
                (if (and credential challenge (uiop:string-prefix-p "Basic" challenge))
                    (basic-authorization credential)
                    (let ((token (registry-bearer-token challenge repository credential)))
                      (and token (format nil "Bearer ~A" token))))))
        (multiple-value-setq (body status headers) (request)))
      (unless (= status 200)
        (when (streamp body) (close body))
        (error 'runtime-error :message (format nil "~A/~A: the registry answered ~D for ~A" registry repository status path)))
      (values body headers))))

(defstruct (browser-images (:constructor %make-browser-images (directory)))
  "What the server knows of images for browser nodes: resolved images by reference, and
which registry and repository each layer it may serve comes from."
  directory
  (lock (bt:make-lock "gr8s browser images"))
  (resolved (make-hash-table :test #'equal))
  (layers (make-hash-table :test #'equal))
  ;; Each resolved image's regular files, path -> digest (browser-content.lisp).
  (files (make-hash-table :test #'equal)))

(defun make-browser-images (directory)
  "An image cache for browser nodes under DIRECTORY."
  (%make-browser-images (uiop:ensure-directory-pathname directory)))

(defun resolve-browser-image (images reference &optional credential)
  "REFERENCE's linux/arm64 image: an object with its layers (digest and media type, base
first) and the configuration it runs with (Entrypoint, Cmd, Env, WorkingDir), fetched
with CREDENTIAL, (username . password), when given. Resolved once and remembered. A zstd
layer is listed as the plain tar the server serves for it. Signals a RUNTIME-ERROR when
there is no arm64 image."
  (or (bt:with-lock-held ((browser-images-lock images))
        (gethash reference (browser-images-resolved images)))
      (multiple-value-bind (registry repository tag) (parse-image-reference reference)
        (let* ((token (list nil credential))
               (accept (format nil "~{~A~^, ~}" +browser-image-manifest-types+))
               (bytes (registry-fetch registry repository (format nil "/v2/~A/manifests/~A" repository tag)
                                      accept token))
               (manifest (com.inuoe.jzon:parse bytes)))
          (when (gethash "manifests" manifest)
            (let ((entry (find-if (lambda (entry)
                                    (let ((platform (gethash "platform" entry)))
                                      (and (hash-table-p platform)
                                           (equal "linux" (gethash "os" platform))
                                           (equal "arm64" (gethash "architecture" platform)))))
                                  (gethash "manifests" manifest))))
              (unless entry
                (error 'runtime-error :message (format nil "~A has no linux/arm64 image" reference)))
              (setf bytes (registry-fetch registry repository
                                          (format nil "/v2/~A/manifests/~A" repository (gethash "digest" entry))
                                          accept token)
                    manifest (com.inuoe.jzon:parse bytes))))
          (let* ((config (com.inuoe.jzon:parse
                          (registry-fetch registry repository
                                          (format nil "/v2/~A/blobs/~A" repository
                                                  (gethash "digest" (gethash "config" manifest)))
                                          nil token)))
                 (run (gethash "config" config (core-object)))
                 (image (core-object
                         "layers" (map 'vector (lambda (layer)
                                                 (let ((type (gethash "mediaType" layer "")))
                                                   (if (search "zstd" type)
                                                       ;; Served decompressed: its bytes aren't the digest's.
                                                       (core-object "digest" (gethash "digest" layer)
                                                                    "mediaType" "application/vnd.oci.image.layer.v1.tar"
                                                                    "decompressed" t)
                                                       (core-object "digest" (gethash "digest" layer)
                                                                    "mediaType" type))))
                                       (gethash "layers" manifest #()))
                         ;; The arm64 manifest's digest, from the bytes the server read, and the
                         ;; image's labels: what a page from it may say about it.
                         "digest" (format nil "sha256:~(~A~)" (ironclad:byte-array-to-hex-string
                                                               (ironclad:digest-sequence :sha256 (coerce bytes (quote (simple-array (unsigned-byte 8) (*)))))))
                         "labels" (let ((labels (gethash "Labels" run)))
                                    (if (hash-table-p labels) labels (core-object)))
                         "config" (core-object "Entrypoint" (gethash "Entrypoint" run 'null)
                                               "Cmd" (gethash "Cmd" run 'null)
                                               "Env" (gethash "Env" run #())
                                               "WorkingDir" (gethash "WorkingDir" run "")))))
            (unless (equal "arm64" (gethash "architecture" config "arm64"))
              (error 'runtime-error :message (format nil "~A is ~A, not arm64" reference (gethash "architecture" config))))
            (bt:with-lock-held ((browser-images-lock images))
              (loop for layer across (gethash "layers" manifest #())
                    do (setf (gethash (gethash "digest" layer) (browser-images-layers images))
                             (list registry repository token (gethash "mediaType" layer ""))))
              (setf (gethash reference (browser-images-resolved images)) image)))))))

(defun browser-image-layer-file (images digest)
  "The cached file of layer DIGEST, fetched and checked first when it isn't cached yet;
NIL when DIGEST belongs to no image this server resolved."
  (let ((source (bt:with-lock-held ((browser-images-lock images))
                  (gethash digest (browser-images-layers images)))))
    (when (and source (cl-ppcre:scan "^sha256:[0-9a-f]{64}$" digest))
      (let ((path (merge-pathnames (make-pathname :name (subseq digest 7) :type "layer")
                                   (browser-images-directory images))))
        (unless (probe-file path)
          (destructuring-bind (registry repository token &optional (media-type "")) source
            (let ((temporary (make-pathname :type "part" :defaults path))
                  (digester (ironclad:make-digest :sha256))
                  (buffer (make-array 65536 :element-type '(unsigned-byte 8))))
              (ensure-directories-exist path)
              (let ((stream (registry-fetch registry repository (format nil "/v2/~A/blobs/~A" repository digest)
                                            nil token :want-stream t)))
                (unwind-protect
                     (with-open-file (out temporary :direction :output :element-type '(unsigned-byte 8)
                                                    :if-exists :supersede)
                       (loop for count = (read-sequence buffer stream)
                             while (plusp count)
                             do (write-sequence buffer out :end count)
                                (ironclad:update-digest digester buffer :end count)))
                  (close stream)))
              (unless (equal digest (format nil "sha256:~(~A~)"
                                            (ironclad:byte-array-to-hex-string (ironclad:produce-digest digester))))
                (delete-file temporary)
                (error 'runtime-error :message (format nil "layer ~A did not match its digest" digest)))
              (if (search "zstd" media-type)
                  ;; A browser can't decompress zstd: serve the tar.
                  (progn (gr8s.runtime::zstd-decompress-file temporary path)
                         (delete-file temporary))
                  (rename-file temporary path)))))
        path))))
