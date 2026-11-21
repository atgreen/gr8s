;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.image-distribution)

(defconstant +default-image-piece-length+ (* 1024 1024))

(defun valid-registry-host-p (host)
  (and (stringp host) (plusp (length host))
       (every (lambda (character)
                (or (alphanumericp character)
                    (find character ".-_:")))
              host)))

(defun registry-origin-host (registry-host)
  (if (member registry-host '("docker.io" "index.docker.io") :test #'string-equal)
      "registry-1.docker.io"
      registry-host))

(defun containerd-registry-hosts-text (registry-host mirror-port)
  "Render strict containerd hosts.toml with no direct-registry escape hatch.
The original host is carried in a fixed header; only the lease-holding mirror
may fetch a missing blob from it."
  (unless (valid-registry-host-p registry-host)
    (error "Invalid OCI registry host ~S" registry-host))
  (unless (typep mirror-port '(integer 1 65535))
    (error "Invalid OCI mirror port ~S" mirror-port))
  (let ((origin (registry-origin-host registry-host)))
   (format nil
          "server = \"http://127.0.0.1:~D\"~%~%[host.\"http://127.0.0.1:~D\"]~%  capabilities = [\"pull\", \"resolve\"]~%  [host.\"http://127.0.0.1:~D\".header]~%    X-Gr8s-Upstream = [\"~A\"]~%"
          mirror-port mirror-port mirror-port origin)))

(defun registry-host-config-path (directory registry-host)
  (merge-pathnames (format nil "~A/hosts.toml" registry-host)
                   (uiop:ensure-directory-pathname directory)))

(defun ensure-containerd-registry-host-config
    (directory registry-host mirror-port)
  (let ((path (registry-host-config-path directory registry-host)))
    (ensure-directories-exist path)
    (with-open-file (stream path :direction :output :if-exists :supersede
                                 :if-does-not-exist :create)
      (write-string (containerd-registry-hosts-text registry-host mirror-port)
                    stream))
    path))

(defun upstream-request-headers (headers)
  "Forward only registry negotiation and authorization headers. Hop-by-hop and
mirror-routing headers never cross the loopback trust boundary."
  (loop for (name . value) in headers
        when (member (string-downcase (string name))
                     '("authorization" "accept" "user-agent" "range"
                       "if-none-match") :test #'string=)
          collect (cons name value)))

(defun upstream-registry-url (host path)
  (unless (valid-registry-host-p host) (error "Invalid registry host ~S" host))
  (unless (and (stringp path) (uiop:string-prefix-p "/v2/" path))
    (error "Invalid registry path ~S" path))
  (format nil "https://~A~A" host path))

(defvar *registry-ca-files* '()
  "Alist of registry host (HOST or HOST:PORT, as image references name it) to a
PEM file of the CAs trusted for that registry in place of the system roots:
the node's --registry-ca, joined by cluster registry trust (registry-trust.lisp).
Every other registry is verified against the system roots.")

(defparameter +registry-redirect-limit+ 5)

(defun registry-uri-host (uri)
  "URI's authority as image references name a registry: HOST, or HOST:PORT
when the port is not the https default."
  (let ((port (puri:uri-port uri)))
    (if (and port (/= port 443))
        (format nil "~A:~D" (puri:uri-host uri) port)
        (puri:uri-host uri))))

(defun registry-host-key (host)
  "HOST without an explicit default https port, so HOST:443 and HOST match."
  (if (uiop:string-suffix-p host ":443")
      (subseq host 0 (- (length host) 4))
      host))

(defun registry-tls-arguments (host)
  "Drakma arguments that verify HOST's certificate: always required, against
HOST's configured CA file when it has one, else the system roots."
  (let ((ca-file (cdr (assoc (registry-host-key host) *registry-ca-files*
                             :key #'registry-host-key :test #'string-equal))))
    (list* :verify :required (and ca-file (list :ca-file (namestring ca-file))))))

(defun registry-http-request (url headers &rest arguments)
  "Drakma request to registry URL with its certificate verified, following up
to +REGISTRY-REDIRECT-LIMIT+ redirects by hand so each hop is verified against
its own host's trust (a blob redirect to a CDN must not be held to a private
registry CA, nor a private CA honored for the CDN). Redirects must stay on
https, and drop Authorization as drakma's own redirects do."
  (loop with uri = (puri:parse-uri url)
        for hop from 0
        do (multiple-value-bind (body status response-headers)
               (apply #'drakma:http-request uri
                      :additional-headers headers :redirect nil :proxy nil
                      (append arguments (registry-tls-arguments (registry-uri-host uri))))
             (let ((location (and (member status '(301 302 303 307 308))
                                  (drakma:header-value :location response-headers))))
               (unless location
                 (return (values body status response-headers)))
               (when (streamp body) (close body :abort t))
               (when (>= hop +registry-redirect-limit+)
                 (error "Registry ~A redirected more than ~D times" url +registry-redirect-limit+))
               (setf uri (puri:merge-uris location uri)
                     headers (remove "authorization" headers
                                     :key (lambda (header) (string-downcase (string (car header))))
                                     :test #'string=))
               (unless (eq :https (puri:uri-scheme uri))
                 (error "Registry ~A redirected to non-https ~A" url (puri:render-uri uri nil)))))))

(defun proxy-oci-registry-request (method host path headers)
  "Proxy a non-blob Distribution request, preserving auth challenges and media
types. Drakma returns the byte body so manifests/configs remain exact. Redirects
are returned to the client, not followed."
  (multiple-value-bind (body status response-headers)
      (apply #'drakma:http-request
             (upstream-registry-url host path) :method method
             :additional-headers (upstream-request-headers headers)
             :force-binary t :redirect nil :proxy nil
             (registry-tls-arguments host))
    (values body status response-headers)))

(defun fetch-oci-registry-blob (temporary host repository digest headers)
  "Stream one registry blob into TEMPORARY. Digest verification is deliberately
owned by ENSURE-OCI-BLOB after this function returns."
  (multiple-value-bind (stream status response-headers)
      (registry-http-request
       (upstream-registry-url host (format nil "/v2/~A/blobs/~A" repository digest))
       (upstream-request-headers headers)
       :method :get :want-stream t :force-binary t)
    (declare (ignore response-headers))
    (unwind-protect
         (progn
           (unless (<= 200 status 299)
             (error "Registry ~A returned HTTP ~D for ~A" host status digest))
           (with-open-file (output temporary :direction :output
                                      :if-does-not-exist :create
                                      :if-exists :supersede
                                      :element-type '(unsigned-byte 8))
             (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8))))
               (loop for count = (read-sequence buffer stream)
                     while (plusp count)
                     do (write-sequence buffer output :end count))))
           t)
      (when (streamp stream) (close stream :abort t)))))

(defun tracker-status (response)
  (let ((status (getf response :status)))
    (etypecase status
      (keyword status)
      (string (intern (string-upcase status) :keyword)))))

(defun call-tracker (tracker-call action digest &rest arguments)
  (apply tracker-call action digest arguments))

(defun call-with-origin-renewal
    (tracker-call digest token function &key (renewal-interval 30))
  "Run FUNCTION while renewing TOKEN until it returns. Renewal failures abort
the fetch owner before it can publish under a stale lease."
  (let ((stopping nil)
        (failure nil)
        (lock (bt:make-lock "gr8s image origin renewal"))
        (changed (bt:make-condition-variable :name "gr8s image origin renewal")))
    (let ((thread
            (bt:make-thread
             (lambda ()
               (handler-case
                   (loop
                     (bt:with-lock-held (lock)
                       (when stopping (return))
                       (bt:condition-wait changed lock :timeout renewal-interval)
                       (when stopping (return)))
                     (call-tracker tracker-call :renew digest :token token))
                 (error (condition)
                   (setf failure condition))))
             :name "gr8s image origin lease renewal")))
      (unwind-protect
           (multiple-value-prog1 (funcall function)
             (when failure (error failure)))
        (bt:with-lock-held (lock)
          (setf stopping t)
          (bt:condition-notify changed))
        (bt:join-thread thread)))))

(defun ensure-strict-p2p-blob
    (cache digest tracker-call peer-fetch origin-fetch publish-seed
     &key (piece-length +default-image-piece-length+) (wait-interval 0.1)
          (renewal-interval 30) (max-peer-attempts 3))
  "Materialize DIGEST without a registry stampede. TRACKER-CALL serializes the
cold fetch. PEER-FETCH receives TEMPORARY, METAINFO and PEERS. ORIGIN-FETCH is
invoked while this node holds the exclusive lease, or as a last resort after
MAX-PEER-ATTEMPTS failed peer fetches. PUBLISH-SEED receives the verified path,
torrent and token and must publish the initial seed before waiters can observe
final metadata.

Peer fetching is an optimization, not a requirement: a peer that is unreachable
(for example a cross-node peer whose port a host firewall drops), slow, or
serving bad data must never fail a pull that the origin registry can serve. So
PEER failures are swallowed and, once the tracker keeps advertising a peer this
node cannot use, ORIGIN-FETCH runs without a lease -- serving the blob and
announcing this node as a peer without claiming the authoritative origin seed."
  (let ((held-token nil)
        (cached (oci-cache-blob-path cache digest)))
   (when (verified-oci-blob-p cached digest)
     (funcall publish-seed cached
              (make-oci-blob-torrent cached digest piece-length) nil)
     (return-from ensure-strict-p2p-blob cached))
   (labels ((peer (temporary)
             (let ((view (call-tracker tracker-call :lookup digest)))
               (when (eq :available (tracker-status view))
                 (handler-case
                     (funcall peer-fetch temporary digest (getf view :metainfo)
                              (getf view :peers))
                   (error (condition)
                     ;; An unreachable, slow, or dishonest peer is not a pull
                     ;; failure: report no peer so the caller falls back to
                     ;; origin. ENSURE-OCI-BLOB re-verifies the digest, so a
                     ;; partial or wrong peer write cannot be mistaken for the
                     ;; blob.
                     (format *error-output*
                             "~&[image-mirror] peer fetch for ~A failed (~A); ~
                              falling back to origin~%"
                             digest condition)
                     nil)))))
           (origin (temporary)
             (let ((peer-attempts 0))
               (loop
                 for lease = (call-tracker tracker-call :acquire digest)
                 for status = (tracker-status lease)
                 do (case status
                      (:granted
                       (let ((token (getf lease :token)))
                         (setf held-token token)
                         (call-with-origin-renewal
                          tracker-call digest token
                          (lambda () (funcall origin-fetch temporary))
                          :renewal-interval renewal-interval)
                         (return t)))
                      (:available
                       (when (peer temporary) (return t))
                       ;; The tracker advertises a peer we could not fetch from.
                       ;; Retry a few times for a transient hiccup, then fetch
                       ;; from the origin registry rather than spin forever on a
                       ;; peer that will never serve us.
                       (when (>= (incf peer-attempts) max-peer-attempts)
                         (funcall origin-fetch temporary)
                         (return t))
                       (sleep wait-interval))
                      ((:waiting :missing) (sleep wait-interval))
                      (otherwise
                       (error "Unexpected image tracker acquire status ~S" status))))))
           (publish (path source)
             ;; With a lease, publish as the authoritative origin seed; without
             ;; one (the peer-exhaustion fallback above), announce as an ordinary
             ;; peer instead -- PUBLISH-SEED treats a NIL token as an announce.
             (funcall publish-seed path
                      (make-oci-blob-torrent path digest piece-length)
                      (and (eq source :origin) held-token))))
    (ensure-oci-blob cache digest :peer-fetch #'peer :origin-fetch #'origin
                     :publish #'publish))))

(defstruct (oci-mirror (:constructor %make-oci-mirror))
  cache tracker-call peer-fetch origin-fetch publish-seed proxy-request
  acceptor)

(defclass oci-mirror-acceptor (hunchentoot:easy-acceptor)
  ((mirror :initarg :mirror :reader acceptor-oci-mirror)))

(defun make-oci-mirror
    (directory tracker-call peer-fetch origin-fetch publish-seed proxy-request)
  "Construct a loopback OCI Distribution mirror. Network behavior is injected
so registry credentials remain request-scoped and peer transport remains mTLS."
  (%make-oci-mirror
   :cache (make-oci-blob-cache directory) :tracker-call tracker-call
   :peer-fetch peer-fetch :origin-fetch origin-fetch
   :publish-seed publish-seed :proxy-request proxy-request))

(defun oci-blob-request (path)
  (multiple-value-bind (match captures)
      (cl-ppcre:scan-to-strings
       "^/v2/(.+)/blobs/(sha256:[0-9A-Fa-f]{64})$" path)
    (when match (values (aref captures 0) (aref captures 1)))))

(defun copy-proxy-response-headers (headers)
  (dolist (header headers)
    (let ((name (string-downcase (string (car header)))))
      (when (member name
                    '("content-type" "content-length" "docker-content-digest"
                      "etag" "www-authenticate" "location")
                    :test #'string=)
        (setf (hunchentoot:header-out (car header))
              (if (string= name "content-length")
                  (parse-integer (princ-to-string (cdr header)))
                  (cdr header)))))))

(defun handle-oci-mirror-request (mirror method path upstream headers)
  "Serve one Distribution request. Blob bodies are always local verified files;
all other endpoints are credential-preserving upstream proxy requests."
  (unless (valid-registry-host-p upstream)
    (setf (hunchentoot:return-code*) 400)
    (return-from handle-oci-mirror-request "invalid upstream registry"))
  (multiple-value-bind (repository digest) (oci-blob-request path)
    (if digest
        (handler-case
            (let ((pathname
                    (ensure-strict-p2p-blob
                     (oci-mirror-cache mirror) digest
                     (oci-mirror-tracker-call mirror)
                     (oci-mirror-peer-fetch mirror)
                     (lambda (temporary)
                       (funcall (oci-mirror-origin-fetch mirror)
                                temporary upstream repository digest headers))
                     (oci-mirror-publish-seed mirror))))
              (setf (hunchentoot:header-out :docker-content-digest) digest
                    (hunchentoot:content-type*) "application/octet-stream")
              (if (eq method :head)
                  (progn
                    (setf (hunchentoot:content-length*)
                          (with-open-file (stream pathname :element-type '(unsigned-byte 8))
                            (file-length stream)))
                    "")
                  (hunchentoot:handle-static-file pathname "application/octet-stream")))
          (error (condition)
            ;; A failed local optimization must preserve containerd's configured
            ;; upstream fallback rather than returning corrupt or partial bytes.
            (setf (hunchentoot:return-code*) 503)
            (format nil "image mirror unavailable: ~A" condition)))
        (multiple-value-bind (body status response-headers)
            (funcall (oci-mirror-proxy-request mirror)
                     method upstream path headers)
          (setf (hunchentoot:return-code*) status)
          (copy-proxy-response-headers response-headers)
          body))))

(defmethod hunchentoot:acceptor-dispatch-request
    ((acceptor oci-mirror-acceptor) request)
  (handle-oci-mirror-request
   (acceptor-oci-mirror acceptor)
   (hunchentoot:request-method* request)
   (hunchentoot:script-name* request)
   (or (hunchentoot:header-in* :x-gr8s-upstream request) "")
   (hunchentoot:headers-in* request)))

(defun start-oci-mirror (mirror &key (port 0))
  "Start MIRROR on IPv4 loopback only and return its assigned port."
  (when (oci-mirror-acceptor mirror)
    (error "OCI mirror is already running"))
  (let ((acceptor (make-instance 'oci-mirror-acceptor
                                 :mirror mirror :address "127.0.0.1" :port port)))
    (hunchentoot:start acceptor)
    (setf (oci-mirror-acceptor mirror) acceptor)
    (hunchentoot:acceptor-port acceptor)))

(defun stop-oci-mirror (mirror)
  (let ((acceptor (shiftf (oci-mirror-acceptor mirror) nil)))
    (when acceptor (hunchentoot:stop acceptor)))
  mirror)
