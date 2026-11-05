;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Choose the registry credentials for an image from a Pod's imagePullSecrets,
;;;; matching them as the kubelet's keyring does. A credential is a (username .
;;;; password) pair, so nothing here may put one in a message, log or thread name.

(in-package #:gr8s)

(defparameter +default-registry-key+ "index.docker.io"
  "The key Docker configs use for the default registry, once their /v1/ path is removed.")

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
