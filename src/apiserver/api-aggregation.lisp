;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Aggregate external API servers registered as APIServices, as kube-aggregator
;;;; does: publish the request-header trust they read from kube-system, track each
;;;; one's availability, serve its group in discovery, and proxy its version's
;;;; requests over TLS with the caller's identity in front-proxy headers.
;;;; OpenAPI is not merged, so kubectl explain doesn't cover aggregated types.

(in-package #:gr8s.apiserver)

(defparameter +front-proxy-client-name+ "front-proxy-client"
  "The one common name aggregated servers accept request-header identity from.")

(defparameter +aggregator-probe-timeout+ 5
  "Seconds one availability check may take, as upstream allows.")

(defparameter +aggregator-available-interval+ 5
  "Seconds between checks of an APIService that last passed. A failing one is checked each second.")

(defstruct aggregator
  "Own the availability thread, proxy credentials, discovery cache and open proxy connections."
  store certificate-path key-path thread stopping
  (discovery (make-hash-table :test #'equal))
  (next-check (make-hash-table :test #'equal))
  (connections nil)
  (lock (bt:make-lock "gr8s aggregator")))

(defvar *aggregators* (make-hash-table :test #'eq :weakness :key :synchronized t)
  "The running aggregator of each store.")

;;; Request-header trust

(defun write-front-proxy-ca (certificate-path key-path)
  "Create the private CA whose only job is to vouch for the aggregator's client certificate."
  (multiple-value-bind (private public) (ironclad:generate-key-pair :secp256r1)
    (write-private-text-exclusively key-path (pure-tls/acme::encode-ec-private-key-pem private))
    (write-public-text-exclusively
     certificate-path
     (pure-tls/acme::wrap-pem "CERTIFICATE" (ca-certificate-der private public :common-name "gr8s-front-proxy-ca")))))

(defun write-front-proxy-client (ca-private-key certificate-path key-path &key issuer-certificate)
  "Sign the aggregator's client certificate under the front-proxy CA."
  (multiple-value-bind (private public) (ironclad:generate-key-pair :secp256r1)
    (let ((der (certificate-der
                (pure-tls/acme::encode-subject "gr8s-front-proxy-ca")
                (pure-tls/acme::encode-subject +front-proxy-client-name+)
                (pure-tls/acme::encode-ec-public-key public)
                (list (pure-tls/acme::encode-critical-extension
                       +oid-key-usage+ (pure-tls/acme::encode-bit-string #(#x80) 7))
                      (pure-tls/acme::encode-extension
                       +oid-extended-key-usage+
                       (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid '(1 3 6 1 5 5 7 3 2)))))
                ca-private-key :issuer-certificate issuer-certificate)))
      (write-private-text-exclusively key-path (pure-tls/acme::encode-ec-private-key-pem private))
      (write-public-text-exclusively certificate-path (pure-tls/acme::wrap-pem "CERTIFICATE" der)))))

(defun ensure-front-proxy-credentials (pki)
  "Return the front-proxy CA path, client certificate path and client key path, creating them once."
  (let* ((root (cluster-pki-root pki))
         (ca (merge-pathnames "front-proxy-ca.crt" root))
         (ca-key (merge-pathnames "front-proxy-ca.key" root))
         (certificate (merge-pathnames "front-proxy-client.crt" root))
         (key (merge-pathnames "front-proxy-client.key" root)))
    (bt:with-lock-held ((cluster-pki-lock pki))
      (unless (and (probe-file ca) (probe-file ca-key))
        (when (or (probe-file ca) (probe-file ca-key))
          (pki-fail "incomplete-front-proxy" "Front-proxy CA certificate and key must both exist"))
        (write-front-proxy-ca ca ca-key))
      (unless (and (probe-file certificate) (probe-file key))
        (when (or (probe-file certificate) (probe-file key))
          (pki-fail "incomplete-front-proxy" "Front-proxy client certificate and key must both exist"))
        (write-front-proxy-client (pure-tls:load-private-key ca-key) certificate key
                                  :issuer-certificate (first (pure-tls:load-certificate-chain ca)))))
    (values ca certificate key)))

(defun extension-apiserver-authentication-data (client-ca request-header-ca)
  "Return what kube-apiserver publishes for servers that delegate authentication to it."
  (flet ((json-list (value) (com.inuoe.jzon:stringify (vector value))))
    (core-object "client-ca-file" client-ca
                 "requestheader-client-ca-file" request-header-ca
                 "requestheader-allowed-names" (json-list +front-proxy-client-name+)
                 "requestheader-username-headers" (json-list "X-Remote-User")
                 "requestheader-group-headers" (json-list "X-Remote-Group")
                 "requestheader-extra-headers-prefix" (json-list "X-Remote-Extra-"))))

(defun ensure-extension-apiserver-authentication (store pki)
  "Publish kube-system's extension-apiserver-authentication ConfigMap, correcting a stale one."
  (let* ((data (extension-apiserver-authentication-data
                (uiop:read-file-string (cluster-pki-ca-certificate-path pki))
                (uiop:read-file-string (ensure-front-proxy-credentials pki))))
         (name "extension-apiserver-authentication")
         (existing (handler-case (get-core-resource store "configmaps" "kube-system" name)
                     (kubernetes-error (condition)
                       (unless (= 404 (kubernetes-error-status-code condition)) (error condition))))))
    (cond ((null existing)
           (let ((*resource-quota-admission-exempt* t))
             (create-core-resource store "configmaps"
                                   (core-object "metadata" (core-object "name" name) "data" data)
                                   "kube-system")))
          ((not (core-json-equal-p data (gethash "data" existing)))
           (update-core-resource store "configmaps" "kube-system" name
                                 (lambda (object) (setf (gethash "data" object) data) object))))))

(defun ensure-extension-apiserver-rbac (store)
  "Create upstream's Role for reading that ConfigMap, and its binding to the core controllers."
  (let ((name "extension-apiserver-authentication-reader"))
    (ensure-default-rbac-object
     store "roles"
     (core-object "metadata" (default-rbac-metadata name)
                  "rules" (vector (core-object "apiGroups" #("") "resources" #("configmaps")
                                               "resourceNames" #("extension-apiserver-authentication")
                                               "verbs" #("get" "list" "watch"))))
     "kube-system")
    (ensure-default-rbac-object
     store "rolebindings"
     (core-object "metadata" (default-rbac-metadata (format nil "system::~A" name))
                  "roleRef" (core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" name)
                  "subjects" (vector (core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "User"
                                                  "name" "system:kube-controller-manager")
                                     (core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "User"
                                                  "name" "system:kube-scheduler")))
     "kube-system")))

;;; The registered object

(defun apiservice-object-name (object)
  "Return OBJECT's metadata name."
  (gethash "name" (gethash "metadata" object)))

(defun validate-apiservice (object)
  "Apply upstream's rules for one APIService, and default its Service port."
  (let* ((name (apiservice-object-name object))
         (spec (require-object (gethash "spec" object) "spec"))
         (group (gethash "group" spec ""))
         (version (gethash "version" spec ""))
         (service (gethash "service" spec))
         (bundle (gethash "caBundle" spec))
         (insecure (gethash "insecureSkipTLSVerify" spec)))
    (flet ((invalid (control &rest arguments)
             (core-resource-error 422 "Invalid" "APIService ~S is invalid: ~?" name control arguments)))
      (unless (equal name (if (equal group "") version (format nil "~A.~A" version group)))
        (invalid "metadata.name must be <version>.<group>"))
      (when (and (equal group "") (not (equal version "v1")))
        (invalid "spec.group: only v1 may have an empty group"))
      (unless (or (equal group "") (dns-subdomain-p group)) (invalid "spec.group must be a DNS subdomain"))
      (unless (dns-label-p version) (invalid "spec.version must be a DNS label"))
      (unless (typep (gethash "groupPriorityMinimum" spec) '(integer 1 20000))
        (invalid "spec.groupPriorityMinimum must be between 1 and 20000"))
      (unless (typep (gethash "versionPriority" spec) '(integer 1 1000))
        (invalid "spec.versionPriority must be between 1 and 1000"))
      (cond
        ((hash-table-p service)
         (typed-api-require service "namespace" "spec.service")
         (typed-api-require service "name" "spec.service")
         (typed-api-default service "port" 443)
         (unless (typep (gethash "port" service) '(integer 1 65535))
           (invalid "spec.service.port must be between 1 and 65535"))
         (when (and insecure bundle (plusp (length bundle)))
           (invalid "spec.insecureSkipTLSVerify may not be set with spec.caBundle"))
         (unless (or insecure (and bundle (plusp (length bundle))))
           (invalid "spec.caBundle is required unless spec.insecureSkipTLSVerify is set")))
        ((or insecure bundle) (invalid "a local APIService may not set TLS options"))))))

(defun default-local-apiservice-status (object)
  "Report an APIService with no backing Service as served by this server, as upstream does on create."
  (unless (hash-table-p (gethash "service" (gethash "spec" object)))
    (setf (gethash "status" object)
          (core-object "conditions"
                       (vector (core-object "type" "Available" "status" "True"
                                            "lastTransitionTime" (current-timestamp) "reason" "Local"
                                            "message" "Local APIServices are always available"))))))

(defun refuse-builtin-apiservice (name)
  "Report that a built-in version is already registered. The caller holds the store lock, so custom resources aren't read."
  (when (find name (local-apiservices nil) :key #'apiservice-object-name :test #'equal)
    (core-resource-error 409 "AlreadyExists" "apiservices.apiregistration.k8s.io ~S already exists" name)))

(defun stored-apiservice (store name)
  "Return the stored APIService called NAME, or NIL."
  (with-store-lock (store)
    (gethash (core-resource-key "apiservices" nil name) (pod-store-resources store))))

(defun stored-apiservices (store)
  "Return every stored APIService."
  (list-core-resources store "apiservices"))

(defun apiservice-service (apiservice)
  "Return the Service reference that makes APIService external, or NIL."
  (let ((service (gethash "service" (gethash "spec" apiservice))))
    (and (hash-table-p service) service)))

(defun aggregated-apiservice (store group version)
  "Return the external APIService serving GROUP/VERSION, or NIL."
  (let ((apiservice (stored-apiservice store (format nil "~A.~A" version group))))
    (and apiservice (apiservice-service apiservice) apiservice)))

(defun apiservice-available-p (apiservice)
  "Report whether APIService's Available condition is True."
  (let* ((status (gethash "status" apiservice))
         (conditions (and (hash-table-p status) (gethash "conditions" status)))
         (available (and conditions
                         (find "Available" conditions :test #'equal
                                                      :key (lambda (condition) (gethash "type" condition))))))
    (and available (equal "True" (gethash "status" available)))))

;;; Discovery

(defun aggregated-api-groups (store)
  "Describe each group with an external APIService, its versions highest priority first."
  (let ((groups (make-hash-table :test #'equal)))
    (dolist (apiservice (stored-apiservices store))
      (when (apiservice-service apiservice)
        (push apiservice (gethash (gethash "group" (gethash "spec" apiservice)) groups))))
    (loop for group being the hash-keys of groups using (hash-value members)
          for versions = (map 'vector
                              (lambda (apiservice)
                                (let ((version (gethash "version" (gethash "spec" apiservice))))
                                  (core-object "groupVersion" (format nil "~A/~A" group version) "version" version)))
                              (sort (copy-list members) #'>
                                    :key (lambda (apiservice) (gethash "versionPriority" (gethash "spec" apiservice)))))
          collect (core-object "apiVersion" "v1" "kind" "APIGroup" "name" group "versions" versions
                               "preferredVersion" (aref versions 0)))))

(defun aggregated-group-p (store group)
  "Report whether GROUP has an external version, which makes this file answer its group document."
  (and (some (lambda (apiservice)
               (and (apiservice-service apiservice)
                    (equal group (gethash "group" (gethash "spec" apiservice)))))
             (stored-apiservices store))
       t))

(defun aggregated-version-document (store group version)
  "Return the last discovery document GROUP/VERSION's server gave a passing check, or NIL."
  (let ((aggregator (gethash store *aggregators*)))
    (when aggregator
      (bt:with-lock-held ((aggregator-lock aggregator))
        (gethash (format nil "~A/~A" group version) (aggregator-discovery aggregator))))))

;;; Reaching the registered server

(defun aggregator-connect (store apiservice aggregator)
  "Open a verified TLS connection to APIService's Service, returning its socket and stream."
  (let* ((service (apiservice-service apiservice))
         (spec (gethash "spec" apiservice))
         (bundle (gethash "caBundle" spec))
         (server-name (format nil "~A.~A.svc" (gethash "name" service) (gethash "namespace" service)))
         (socket nil)
         (pure-tls:*session-ticket-cache* (make-hash-table :test 'equal)))
    (multiple-value-bind (address port) (admission-service-endpoint store service)
      (handler-case
          (let ((connected nil))
            (unwind-protect
                 (sb-sys:with-deadline (:seconds +aggregator-probe-timeout+)
                   (setf socket (usocket:socket-connect address port :element-type '(unsigned-byte 8)
                                                                     :timeout +aggregator-probe-timeout+ :nodelay t))
                   (let* ((insecure (gethash "insecureSkipTLSVerify" spec))
                          (stream (pure-tls:make-tls-client-stream
                                   (usocket:socket-stream socket)
                                   :hostname server-name
                                   :context (if insecure
                                                (pure-tls:make-tls-context :verify-mode pure-tls:+verify-none+
                                                                           :auto-load-system-ca nil)
                                                (admission-tls-context bundle))
                                   :verify (if insecure pure-tls:+verify-none+ pure-tls:+verify-required+)
                                   :client-certificate (namestring (aggregator-certificate-path aggregator))
                                   :client-key (namestring (aggregator-key-path aggregator)))))
                     (setf connected t)
                     (values socket stream)))
              (when (and socket (not connected)) (ignore-errors (usocket:socket-close socket)))))
        (sb-sys:deadline-timeout ()
          (error "timed out connecting to ~A" server-name))))))

(defun aggregator-write-request (stream method target host headers body)
  "Send one HTTP/1.1 request, closing the connection after its response."
  (write-sequence
   (trivial-utf-8:string-to-utf-8-bytes
    (with-output-to-string (out)
      (flet ((line (control &rest arguments)
               (format out "~?~C~C" control arguments #\Return #\Linefeed)))
        (line "~A ~A HTTP/1.1" (string-upcase method) target)
        (line "Host: ~A" host)
        (loop for (name . value) in headers do (line "~A: ~A" name value))
        (when (plusp (length body)) (line "Content-Length: ~D" (length body)))
        (line "Connection: close")
        (line ""))))
   stream)
  (when (plusp (length body)) (write-sequence body stream))
  (force-output stream))

(defun aggregator-read-response-head (stream)
  "Read a response's status line and headers, returning the code and a lowercase header list."
  (let* ((status-line (admission-read-line stream))
         (space (position #\Space status-line))
         (code (or (and space (parse-integer status-line :start (1+ space) :junk-allowed t))
                   (error "malformed HTTP status line"))))
    (values code
            (loop for line = (admission-read-line stream)
                  until (zerop (length line))
                  for colon = (position #\: line)
                  when colon
                    collect (cons (string-downcase (subseq line 0 colon))
                                  (string-trim '(#\Space #\Tab) (subseq line (1+ colon))))))))

(defun aggregator-https-request (store apiservice aggregator method target headers
                                 &key (timeout +aggregator-probe-timeout+))
  "Issue one non-streaming request to APIService's backend over the aggregator's
front-proxy mutual TLS, returning (values code response-headers body-octets).

The connect endpoint comes from the Service; the certificate is verified for, and
SNI/Host carry, the Service's cluster name; trust is the APIService's caBundle,
or no verification when it sets insecureSkipTLSVerify.  (The streaming proxy keeps
its own aggregator-connect; this is only for request/response callers.)"
  (let* ((service (apiservice-service apiservice))
         (spec (gethash "spec" apiservice))
         (bundle (gethash "caBundle" spec))
         (insecure (and (gethash "insecureSkipTLSVerify" spec) t))
         (server-name (format nil "~A.~A.svc" (gethash "name" service) (gethash "namespace" service))))
    (multiple-value-bind (address port) (admission-service-endpoint store service)
      (gr8s.http-client:https-request
       :host address :port port :server-name server-name
       :host-header (format nil "~A:~D" server-name (gethash "port" service))
       :method method :target target :headers headers
       :trust-certificates (and bundle (not insecure)
                                (admission-ca-certificates (core-base64-bytes bundle "caBundle")))
       :insecure insecure
       :client-certificate (aggregator-certificate-path aggregator)
       :client-key (aggregator-key-path aggregator)
       ;; Availability probes and the HPA metrics poll hit the same aggregated
       ;; backend repeatedly; keep the front-proxy mTLS connection alive.
       :reuse t
       :timeout timeout))))

(defun aggregated-api-fetch-json (store apiservice target)
  "Fetch TARGET from an available APIService over the authenticated aggregator transport."
  (let ((aggregator (gethash store *aggregators*)))
    (unless aggregator (error "the API aggregator is not running"))
    (multiple-value-bind (code headers body)
        (aggregator-https-request store apiservice aggregator :get target
                                  (append (aggregator-identity-headers nil)
                                          '(("Accept" . "application/json")
                                            ("User-Agent" . "kube-aggregator/gr8s"))))
      (declare (ignore headers))
      (unless (<= 200 code 299)
        (error "aggregated server returned HTTP ~D for ~A" code target))
      (com.inuoe.jzon:parse body))))

(defun merge-aggregated-openapi-v2 (store document)
  "Merge available APIService Swagger paths and definitions into local DOCUMENT.
Local entries win name collisions, matching the aggregator's ownership of its built-in paths."
  (let ((paths (gethash "paths" document))
        (definitions (gethash "definitions" document)))
    (dolist (apiservice (stored-apiservices store))
      (when (and (apiservice-service apiservice) (apiservice-available-p apiservice))
        (handler-case
            (let ((remote (aggregated-api-fetch-json store apiservice "/openapi/v2")))
              (when (equal "2.0" (gethash "swagger" remote))
                (dolist (pair (list (cons paths (gethash "paths" remote))
                                    (cons definitions (gethash "definitions" remote))))
                  (when (hash-table-p (cdr pair))
                    (maphash (lambda (name value)
                               (unless (gethash name (car pair))
                                 (setf (gethash name (car pair)) value)))
                             (cdr pair))))))
          (error () nil))))
    document))

(defun aggregator-copy-body (upstream client headers)
  "Forward each chunk as it arrives: a watch's events must not wait for a buffer to fill."
  (let ((length-text (cdr (assoc "content-length" headers :test #'string=)))
        (chunked (search "chunked" (string-downcase (or (cdr (assoc "transfer-encoding" headers :test #'string=)) ""))))
        (buffer (make-array 16384 :element-type '(unsigned-byte 8))))
    (flet ((copy (count)
             (loop while (plusp count)
                   for got = (read-sequence buffer upstream :end (min count (length buffer)))
                   do (when (zerop got) (error "Truncated aggregated API response"))
                      (write-sequence buffer client :end got)
                      (decf count got))
             (finish-output client)))
      (cond
        (chunked
         (loop
           (let* ((line (admission-read-line upstream))
                  (size (parse-integer line :end (or (position #\; line) (length line)) :radix 16)))
             (when (zerop size) (return))
             (copy size)
             (admission-read-line upstream))))
        (length-text (copy (parse-integer length-text)))
        (t (loop for octet = (read-byte upstream nil nil)
                 while octet do (write-byte octet client))
           (finish-output client))))))

(defun aggregator-identity-headers (identity)
  "Express IDENTITY in the front-proxy headers. The local listener's requests are administrative."
  (if identity
      (let ((actor (api-identity-actor identity)))
        (append (list (cons "X-Remote-User" (gethash "username" actor)))
                (map 'list (lambda (group) (cons "X-Remote-Group" group)) (gethash "groups" actor))
                (let ((extra (gethash "extra" actor)))
                  (when (hash-table-p extra)
                    (loop for key being the hash-keys of extra using (hash-value values)
                          append (map 'list
                                      (lambda (value)
                                        (cons (concatenate 'string "X-Remote-Extra-"
                                                           (hunchentoot:url-encode key :utf-8))
                                              value))
                                      values))))))
      '(("X-Remote-User" . "system:admin") ("X-Remote-Group" . "system:masters")
        ("X-Remote-Group" . "system:authenticated"))))

(defun aggregator-forwarded-headers ()
  "Keep end-to-end request headers, dropping what only this server may interpret."
  (remove-if (lambda (header)
               (or (uiop:string-prefix-p "impersonate-" (car header))
                   (uiop:string-prefix-p "x-remote-" (car header))))
             (pod-proxy-end-to-end-headers
              (mapcar (lambda (header) (cons (string-downcase (string (car header))) (cdr header)))
                      (hunchentoot:headers-in*))
              :request t)))

(defun aggregator-send-response-head (code headers)
  "Start the client's response with the aggregated server's status and end-to-end headers."
  (setf (hunchentoot:return-code*) code (hunchentoot:content-type*) nil)
  (dolist (header (pod-proxy-end-to-end-headers headers))
    (let ((name (intern (string-upcase (car header)) :keyword)))
      (case name
        (:content-length (setf (hunchentoot:header-out name) (parse-integer (cdr header))))
        (:content-type (setf (hunchentoot:header-out name) (cdr header)))
        (t (push (cons name (cdr header)) (slot-value hunchentoot:*reply* 'hunchentoot::headers-out))))))
  (hunchentoot:send-headers))

(defun aggregator-track-connection (aggregator socket)
  "Remember SOCKET so that stopping can end a watch blocked reading it."
  (bt:with-lock-held ((aggregator-lock aggregator))
    (push socket (aggregator-connections aggregator))))

(defun aggregator-forget-connection (aggregator socket)
  "Forget a finished proxy connection."
  (bt:with-lock-held ((aggregator-lock aggregator))
    (setf (aggregator-connections aggregator) (delete socket (aggregator-connections aggregator)))))

(defun aggregated-api-unavailable (apiservice &optional reason)
  "Answer as upstream does while the registered server can't take a request."
  (core-resource-error 503 "ServiceUnavailable" "the server is currently unable to handle the request (~A~@[: ~A~])"
                       (apiservice-object-name apiservice) reason))

(defun request-client-fd ()
  "Return the file descriptor of the current request's client connection, or NIL."
  (let ((stream hunchentoot::*hunchentoot-stream*))
    (loop repeat 8
          do (typecase stream
               (sb-sys:fd-stream (return (sb-sys:fd-stream-fd stream)))
               (chunga:chunked-stream (setf stream (chunga:chunked-stream-stream stream)))
               (flexi-streams:flexi-stream (setf stream (flexi-streams:flexi-stream-stream stream)))
               (pure-tls::tls-stream (setf stream (pure-tls::tls-stream-underlying-stream stream)))
               (t (return nil))))))

(defun watch-client-departure (fd socket)
  "Shut the proxied SOCKET down once the client on FD goes away, so a watch that has nothing to
send does not keep its thread until the aggregated server next writes. Return a function that
stops watching and reports whether the client left. The proxy still closes SOCKET itself:
shutting it down only wakes the read, and leaves the descriptor its own until then."
  (let* ((done nil) (gone nil)
         (thread (bt:make-thread
                  (lambda ()
                    (loop until done
                          do (sleep 1)
                             (when (and (not done) (client-connection-closed-p fd))
                               (setf gone t)
                               (ignore-errors (usocket:socket-shutdown socket :io))
                               (return))))
                  :name "gr8s aggregated watch client")))
    (lambda ()
      (setf done t)
      (ignore-errors (bt:join-thread thread))
      gone)))

(defun aggregated-watch-request-p (method)
  "Recognize a long-running watch, which may wait a long time for its next event."
  (and (eq method :get)
       (or (true-parameter-p (hunchentoot:get-parameter "watch"))
           (search "/watch/" (hunchentoot:script-name*)))))

(defun aggregated-api-proxy-response (store apiservice method &key (target (hunchentoot:request-uri*)))
  "Forward the current request to APIService's server and relay its answer as it arrives.
TARGET is the request line's path, the current request's own unless given."
  (let ((aggregator (gethash store *aggregators*)))
    (unless (and aggregator (apiservice-available-p apiservice))
      (aggregated-api-unavailable apiservice))
    (let ((socket nil) (stream nil) (started nil) (stop-watching nil))
      (unwind-protect
           (handler-case
               (progn
                 (multiple-value-setq (socket stream) (aggregator-connect store apiservice aggregator))
                 (aggregator-track-connection aggregator socket)
                 (let ((fd (and (aggregated-watch-request-p method) (request-client-fd))))
                   (when fd (setf stop-watching (watch-client-departure fd socket))))
                 (let* ((service (apiservice-service apiservice))
                        (body (or (hunchentoot:raw-post-data :force-binary t) #()))
                        (content-type (hunchentoot:header-in* :content-type)))
                   (aggregator-write-request
                    stream method target
                    (format nil "~A.~A.svc:~D" (gethash "name" service) (gethash "namespace" service)
                            (gethash "port" service))
                    (append (aggregator-identity-headers *authenticated-api-identity*)
                            (when content-type (list (cons "content-type" content-type)))
                            (aggregator-forwarded-headers))
                    body))
                 (multiple-value-bind (code headers) (aggregator-read-response-head stream)
                   (let ((client (aggregator-send-response-head code headers)))
                     (setf started t)
                     (unless (or (eq method :head) (member code '(204 304)))
                       (aggregator-copy-body stream client headers)))))
             (error (condition)
               (cond ((and stop-watching (funcall stop-watching))
                      ;; The client left, and closing its upstream ended the copy.
                      nil)
                     ((or started hunchentoot::*headers-sent*) (error condition))
                     (t (aggregated-api-unavailable apiservice (remove #\Newline (princ-to-string condition)))))))
        (when stop-watching (funcall stop-watching))
        (when socket
          (aggregator-forget-connection aggregator socket)
          (ignore-errors (usocket:socket-close socket)))))))

(defun aggregated-api-route (store path)
  "Return the external APIService owning PATH's version and T, or NIL and whether PATH is only its group."
  (when (and store (uiop:string-prefix-p "/apis/" path))
    (let* ((rest (subseq path 6))
           (slash (position #\/ rest)))
      (if slash
          (let* ((group (subseq rest 0 slash))
                 (after (subseq rest (1+ slash)))
                 (version (subseq after 0 (or (position #\/ after) (length after)))))
            (when (plusp (length version))
              (let ((apiservice (aggregated-apiservice store group version)))
                (when apiservice (values apiservice t)))))
          (when (aggregated-group-p store rest)
            (values nil rest))))))

(defun aggregated-api-response (store path method)
  "Answer a request under an aggregated group: its group document, or the proxied server."
  (multiple-value-bind (apiservice route) (aggregated-api-route store path)
    (if apiservice
        (aggregated-api-proxy-response store apiservice method)
        (json-response (find route (aggregated-api-groups store) :test #'equal
                             :key (lambda (group) (gethash "name" group)))))))

;;; Availability

(defun apiservice-availability-probe (store apiservice aggregator)
  "Fetch APIService's discovery document, returning NIL and it, or the failure's reason and message."
  (let* ((service (apiservice-service apiservice))
         (spec (gethash "spec" apiservice))
         (namespace (gethash "namespace" service)) (name (gethash "name" service))
         (port (gethash "port" service))
         (object (handler-case (get-core-resource store "services" namespace name)
                   (kubernetes-error () nil))))
    (unless object
      (return-from apiservice-availability-probe
        (values "ServiceNotFound" (format nil "service/~A in ~S is not present" name namespace))))
    (unless (or (equal "ExternalName" (gethash "type" (gethash "spec" object)))
                (find port (gethash "ports" (gethash "spec" object) #())
                      :key (lambda (entry) (gethash "port" entry))))
      (return-from apiservice-availability-probe
        (values "ServicePortError" (format nil "service/~A in ~S is not listening on port ~D" name namespace port))))
    (let ((target (format nil "/apis/~A/~A" (gethash "group" spec) (gethash "version" spec))))
      (handler-case
          (multiple-value-bind (code headers response)
              (aggregator-https-request
               store apiservice aggregator :get target
               '(("Accept" . "application/json") ("User-Agent" . "kube-aggregator/gr8s")
                 ("X-Remote-User" . "system:kube-aggregator") ("X-Remote-Group" . "system:masters")))
            (declare (ignore headers))
            (if (<= 200 code 299)
                (values nil (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string response)))
                (values "FailedDiscoveryCheck"
                        (format nil "failing or missing response from https://~A.~A.svc:~D~A: bad status: ~D"
                                name namespace port target code))))
        (admission-call-failure (condition)
          (values "MissingEndpoints" (admission-call-failure-message condition)))
        ((or error sb-sys:deadline-timeout) (condition)
          (values "FailedDiscoveryCheck"
                  (format nil "failing or missing response from https://~A.~A.svc:~D~A: ~A"
                          name namespace port target (remove #\Newline (princ-to-string condition)))))))))

(defun set-apiservice-available (store name status reason message)
  "Record the Available condition, keeping every other condition and the transition time if unchanged."
  (let ((*typed-api-status-write* t)
        (*core-resource-view-version* "apiregistration.k8s.io/v1"))
    (update-core-resource
     store "apiservices" nil name
     (lambda (object)
       (let* ((current (let ((value (gethash "status" object))) (if (hash-table-p value) value (core-object))))
              (conditions (coerce (typed-api-array current "conditions") 'list))
              (existing (find "Available" conditions :test #'equal
                                                     :key (lambda (condition) (gethash "type" condition))))
              (condition (core-object "type" "Available" "status" status
                                      "lastTransitionTime"
                                      (if (and existing (equal status (gethash "status" existing)))
                                          (gethash "lastTransitionTime" existing)
                                          (current-timestamp))
                                      "reason" reason "message" message)))
         (setf (gethash "conditions" current)
               (coerce (if existing
                           (substitute condition existing conditions)
                           (cons condition conditions))
                       'vector)
               (gethash "status" object) current)
         object)))))

(defun apiservice-condition-current-p (apiservice status reason message)
  "Report whether APIService already says this, so an unchanged result writes nothing."
  (let* ((value (gethash "status" apiservice))
         (condition (and (hash-table-p value)
                         (find "Available" (typed-api-array value "conditions") :test #'equal
                                                                                :key (lambda (entry) (gethash "type" entry))))))
    (and condition (equal status (gethash "status" condition))
         (equal reason (gethash "reason" condition)) (equal message (gethash "message" condition)))))

(defun check-apiservice-availability (aggregator apiservice)
  "Probe one APIService, remember its discovery document, and update its status if that changed."
  (let* ((store (aggregator-store aggregator))
         (spec (gethash "spec" apiservice))
         (group-version (format nil "~A/~A" (gethash "group" spec) (gethash "version" spec))))
    (multiple-value-bind (reason detail) (apiservice-availability-probe store apiservice aggregator)
      (bt:with-lock-held ((aggregator-lock aggregator))
        (if reason
            (remhash group-version (aggregator-discovery aggregator))
            (setf (gethash group-version (aggregator-discovery aggregator)) detail)))
      (let ((status (if reason "False" "True"))
            (reason (or reason "Passed"))
            (message (if reason detail "all checks passed")))
        (unless (apiservice-condition-current-p apiservice status reason message)
          (set-apiservice-available store (apiservice-object-name apiservice) status reason message)))
      (not reason))))

(defun aggregator-check-pass (aggregator)
  "Check each external APIService that is due, on the schedule its last result set."
  (let ((now (get-internal-real-time)) (seen nil))
    (dolist (apiservice (stored-apiservices (aggregator-store aggregator)))
      (when (apiservice-service apiservice)
        (let ((name (apiservice-object-name apiservice)))
          (push name seen)
          (when (>= now (gethash name (aggregator-next-check aggregator) 0))
            (let ((passed (handler-case (check-apiservice-availability aggregator apiservice)
                            (error (condition)
                              ;; A conflicting or deleted object is rechecked on the next pass.
                              (format *error-output* "gr8s APIService ~A check failed: ~A~%" name condition)
                              nil))))
              (setf (gethash name (aggregator-next-check aggregator))
                    (+ (get-internal-real-time)
                       (* (if passed +aggregator-available-interval+ 1) internal-time-units-per-second))))))))
    (let ((gone (loop for name being the hash-keys of (aggregator-next-check aggregator)
                      unless (member name seen :test #'equal) collect name)))
      (dolist (name gone) (remhash name (aggregator-next-check aggregator))))))

(defun start-api-aggregator (store pki)
  "Start tracking APIServices in STORE and allow requests to be proxied to them."
  (multiple-value-bind (ca certificate key) (ensure-front-proxy-credentials pki)
    (declare (ignore ca))
    (let ((aggregator (make-aggregator :store store :certificate-path certificate :key-path key)))
      (setf (gethash store *aggregators*) aggregator
            (aggregator-thread aggregator)
            (bt:make-thread
             (lambda ()
               (loop until (aggregator-stopping aggregator)
                     do (handler-case (aggregator-check-pass aggregator)
                          (error (condition)
                            (format *error-output* "gr8s aggregator pass failed: ~A~%" condition)))
                        (sleep 0.25)))
             :name "gr8s aggregator availability"))
      aggregator)))

(defun stop-api-aggregator (aggregator)
  "Stop checking, end any proxied watch, and join the availability thread."
  (when aggregator
    (setf (aggregator-stopping aggregator) t)
    (remhash (aggregator-store aggregator) *aggregators*)
    ;; Under the lock, because a closed socket's descriptor can already belong to
    ;; another connection, and a connection is forgotten before it is closed.
    (bt:with-lock-held ((aggregator-lock aggregator))
      (dolist (socket (aggregator-connections aggregator))
        (ignore-errors (usocket:socket-shutdown socket :io))))
    (ignore-errors (bt:join-thread (aggregator-thread aggregator)))))
