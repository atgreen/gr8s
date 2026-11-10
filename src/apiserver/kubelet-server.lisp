;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve a node's kubelet endpoints over HTTPS, as the kubelet does on port 10250:
;;;; /metrics/resource, /metrics/cadvisor, /stats/summary, /metrics, /metrics/probes and /healthz, for
;;;; metrics-server, Prometheus and the API
;;;; server's Node proxy. The serving certificate is signed by the cluster CA for the
;;;; node's address, so clients that trust the in-cluster CA verify it. Requests are
;;;; authenticated by a client certificate from that CA or by a bearer token checked
;;;; with a TokenReview, and authorized with a SubjectAccessReview on the nodes
;;;; subresource the path maps to, both delegated to the API server and cached for
;;;; the kubelet's default lifetimes. The API server's Node proxy reaches this
;;;; listener with its own client certificate.

(in-package #:gr8s.apiserver)

(defparameter +kubelet-default-port+ 10250
  "The kubelet's authenticated HTTPS port, which clients assume when a Node reports none.")

(defparameter +kubelet-apiserver-client-name+ "kube-apiserver-kubelet-client"
  "The API server's identity toward kubelets.")

;;; Credentials, issued by the cluster CA

(defun encode-kubelet-subject (common-name &optional organization)
  "Encode an X.501 Name holding ORGANIZATION, when given, and COMMON-NAME."
  (apply #'pure-tls/acme::encode-sequence
         (append
          (when organization
            (list (pure-tls/acme::encode-set
                   (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid '(2 5 4 10))
                                                   (pure-tls/acme::encode-utf8-string organization)))))
          (list (pure-tls/acme::encode-set
                 (pure-tls/acme::encode-sequence (pure-tls/acme::encode-oid pure-tls/acme::*oid-common-name*)
                                                 (pure-tls/acme::encode-utf8-string common-name)))))))

(defun ipv4-address-octets (address)
  "Return dotted-quad ADDRESS as four octets, or NIL when it is not one."
  (let ((parts (uiop:split-string address :separator ".")))
    (when (and (= 4 (length parts))
               (every (lambda (part) (and (plusp (length part)) (every #'digit-char-p part) (<= (parse-integer part) 255)))
                      parts))
      (coerce (mapcar #'parse-integer parts) '(vector (unsigned-byte 8))))))

(defun kubelet-san-extension (addresses dns-names)
  "Encode subjectAltName with DNS-NAMES and the IPv4 ADDRESSES."
  (apply #'pure-tls/acme::encode-sequence
         (append (loop for name in dns-names collect (pure-tls/acme::encode-der #x82 (pki-ascii-octets name)))
                 (loop for address in addresses
                       for octets = (ipv4-address-octets address)
                       when octets collect (pure-tls/acme::encode-der #x87 octets)))))

(defun leaf-rotation-manifest-path (certificate-path)
  (make-pathname :name (format nil ".~A-rotation" (pathname-name certificate-path))
                 :type "json" :defaults certificate-path))

(defun finish-pending-leaf-rotation (certificate-path key-path)
  "Complete a durable key/certificate replacement interrupted after its intent was recorded."
  (let ((manifest-path (leaf-rotation-manifest-path certificate-path)))
    (when (probe-file manifest-path)
      (let ((record (com.inuoe.jzon:parse manifest-path)))
        (unless (and (hash-table-p record)
                     (equal "gr8s-leaf-rotation" (gethash "format" record))
                     (eql 1 (gethash "version" record))
                     (stringp (gethash "key" record))
                     (stringp (gethash "certificate" record)))
          (pki-fail "invalid-leaf-rotation" "Invalid leaf rotation manifest ~A" manifest-path))
        (write-private-text-atomically key-path (gethash "key" record))
        (write-private-text-atomically certificate-path (gethash "certificate" record))
        (delete-file manifest-path)))))

(defun replace-leaf-key-pair (certificate-path key-path certificate-pem key-pem)
  "Durably replace a complete leaf identity, recoverable by FINISH-PENDING-LEAF-ROTATION."
  (let ((manifest-path (leaf-rotation-manifest-path certificate-path)))
    (write-private-text-atomically
     manifest-path
     (com.inuoe.jzon:stringify
      (gr8s.resources::core-object "format" "gr8s-leaf-rotation" "version" 1
                                   "key" key-pem "certificate" certificate-pem)))
    (write-private-text-atomically key-path key-pem)
    (write-private-text-atomically certificate-path certificate-pem)
    (delete-file manifest-path)))

(defun issue-cluster-certificate (pki certificate-path key-path common-name organization
                                  &key server (addresses nil) (dns-names nil) rotate-key)
  "Issue COMMON-NAME while preserving an existing key, so renewal replaces one file.
An initial interrupted key-first creation is retryable; a certificate without its key is refused."
  (finish-pending-leaf-rotation certificate-path key-path)
  (when (and (probe-file certificate-path) (not (probe-file key-path)))
    (pki-fail "incomplete-leaf-identity" "Certificate ~A exists without its private key" certificate-path))
  (let ((new-key-p (or rotate-key (not (probe-file key-path))))
        (old-key-pem (when (probe-file key-path) (uiop:read-file-string key-path))))
    (multiple-value-bind (private public)
        (if new-key-p
            (ironclad:generate-key-pair :secp256r1)
            (let* ((private (pure-tls:load-private-key key-path))
                   (parameters (ironclad:destructure-private-key private))
                   (encoded-public (getf parameters :y)))
              (unless (and (getf parameters :x) encoded-public)
                (pki-fail "invalid-leaf-key" "Private key ~A must be a P-256 EC key" key-path))
              (values private (ironclad:make-public-key :secp256r1 :y encoded-public))))
    (let* ((der (certificate-der
                (pure-tls/acme::encode-subject +pki-ca-common-name+)
                (encode-kubelet-subject common-name organization)
                (pure-tls/acme::encode-ec-public-key public)
                (append
                 (list (pure-tls/acme::encode-critical-extension
                        +oid-key-usage+ (pure-tls/acme::encode-bit-string #(#x80) 7))
                       (pure-tls/acme::encode-extension
                        +oid-extended-key-usage+
                        (pure-tls/acme::encode-sequence
                         (pure-tls/acme::encode-oid (if server '(1 3 6 1 5 5 7 3 1) +oid-client-auth+)))))
                 (when server
                   (list (pure-tls/acme::encode-extension pure-tls/acme::*oid-subject-alt-name*
                                                          (kubelet-san-extension addresses dns-names)))))
                (cluster-pki-ca-private-key pki)))
           (key-pem (and new-key-p (pure-tls/acme::encode-ec-private-key-pem private)))
           (certificate-pem
             (concatenate 'string (pure-tls/acme::wrap-pem "CERTIFICATE" der)
                          (pure-tls/acme::wrap-pem
                           "CERTIFICATE"
                           (pure-tls::x509-certificate-raw-der
                            (cluster-pki-ca-certificate pki))))))
      (ensure-directories-exist certificate-path)
      (handler-case
          (if (and rotate-key old-key-pem (probe-file certificate-path))
              (replace-leaf-key-pair certificate-path key-path certificate-pem key-pem)
              (progn
                (when new-key-p (write-private-text-atomically key-path key-pem))
                (write-private-text-atomically certificate-path certificate-pem)))
        (error (condition)
          (when (and rotate-key old-key-pem)
            (write-private-text-atomically key-path old-key-pem)
            (ignore-errors (delete-file (leaf-rotation-manifest-path certificate-path))))
          (error condition)))
      (values certificate-path key-path)))))

(defun kubelet-credential-paths (directory)
  "Return the serving certificate, its key, the client certificate and its key under DIRECTORY."
  (let ((directory (uiop:ensure-directory-pathname directory)))
    (values (merge-pathnames "kubelet.crt" directory) (merge-pathnames "kubelet.key" directory)
            (merge-pathnames "kubelet-client.crt" directory) (merge-pathnames "kubelet-client.key" directory))))

(defun issue-kubelet-credentials (pki directory node-name addresses)
  "Give NODE-NAME's kubelet a serving certificate for ADDRESSES and its node name, and a client
certificate as system:node:NODE-NAME for the reviews it delegates, as kubelet TLS bootstrap would.
Both are issued afresh, so an address that changed is covered."
  (multiple-value-bind (certificate key client-certificate client-key) (kubelet-credential-paths directory)
    (let ((subject (format nil "system:node:~A" node-name)))
      (issue-cluster-certificate pki certificate key subject "system:nodes"
                                 :server t :addresses addresses
                                 :dns-names (remove-duplicates (list node-name (machine-instance)) :test #'equal))
      (issue-cluster-certificate pki client-certificate client-key subject "system:nodes"))))

(defun ensure-apiserver-kubelet-client-credentials
    (pki &key (renew-within +certificate-leaf-renewal-seconds+) rotate-key)
  "Return the API server's client certificate and key toward kubelets, issuing them when missing."
  (let ((certificate (merge-pathnames "apiserver-kubelet-client.crt" (cluster-pki-root pki)))
        (key (merge-pathnames "apiserver-kubelet-client.key" (cluster-pki-root pki))))
    (bt:with-lock-held ((cluster-pki-lock pki))
      (finish-pending-leaf-rotation certificate key)
      (unless (and (probe-file certificate) (probe-file key)
                   (not (certificate-renewal-due-p certificate renew-within))
                   (handler-case
                       (progn
                         (pure-tls::verify-certificate-chain
                          (list (first (pure-tls:load-certificate-chain certificate)))
                          (list (cluster-pki-ca-certificate pki))
                          :purpose :client-auth :trust-anchor-mode :replace)
                         t)
                     (error () nil)))
        (issue-cluster-certificate pki certificate key +kubelet-apiserver-client-name+ "system:masters"
                                   :rotate-key rotate-key)))
    (values certificate key)))

;;; HTTPS requests with client credentials

(defun read-http-response-body (stream headers &key (limit (* 16 1024 1024)))
  "Read the body HEADERS frame on STREAM, of at most LIMIT octets."
  (let ((length-text (cdr (assoc "content-length" headers :test #'string=)))
        (chunked (search "chunked" (string-downcase (or (cdr (assoc "transfer-encoding" headers :test #'string=)) "")))))
    (cond
      (chunked
       (let ((body (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
         (loop
           (let* ((line (admission-read-line stream))
                  (size (parse-integer line :end (or (position #\; line) (length line)) :radix 16)))
             (when (zerop size)
               (loop until (zerop (length (admission-read-line stream))))
               (return))
             (when (> (+ size (length body)) limit) (error "HTTP response is too large"))
             (loop for octet across (admission-read-exactly stream size) do (vector-push-extend octet body))
             (admission-read-line stream)))
         (coerce body '(simple-array (unsigned-byte 8) (*)))))
      (length-text
       (let ((length (parse-integer length-text)))
         (when (> length limit) (error "HTTP response is too large"))
         (admission-read-exactly stream length)))
      (t (let ((body (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
           (loop for octet = (read-byte stream nil nil)
                 while octet
                 do (when (>= (length body) limit) (error "HTTP response is too large"))
                    (vector-push-extend octet body))
           (coerce body '(simple-array (unsigned-byte 8) (*))))))))

(defun tls-http-request (&key address port server-name (method :get) target headers body
                              trust-certificates client-certificate client-key (timeout 10))
  "Send one HTTP/1.1 request over TLS verified against TRUST-CERTIFICATES for SERVER-NAME,
presenting CLIENT-CERTIFICATE when given. Return the status, lowercase headers and body octets."
  (let ((socket nil) (pure-tls:*session-ticket-cache* (make-hash-table :test 'equal)))
    (unwind-protect
         ;; A deadline is no ERROR, and one escaping a request thread ends the process.
         (handler-case
          (sb-sys:with-deadline (:seconds timeout)
           (setf socket (usocket:socket-connect address port :element-type '(unsigned-byte 8)
                                                             :timeout timeout :nodelay t))
           (let* ((context (pure-tls:make-tls-context :verify-mode pure-tls:+verify-required+ :auto-load-system-ca nil))
                  (stream (progn
                            (setf (pure-tls::tls-context-trust-store context)
                                  (pure-tls::make-trust-store :certificates trust-certificates))
                            (pure-tls:make-tls-client-stream
                             (usocket:socket-stream socket) :hostname server-name :context context
                             :verify pure-tls:+verify-required+
                             :client-certificate (and client-certificate (namestring client-certificate))
                             :client-key (and client-key (namestring client-key))))))
             (aggregator-write-request stream method target (format nil "~A:~D" server-name port)
                                       headers (or body #()))
             (multiple-value-bind (code response-headers) (aggregator-read-response-head stream)
               (values code response-headers
                       (if (or (eq method :head) (member code '(204 304)))
                           (make-array 0 :element-type '(unsigned-byte 8))
                           (read-http-response-body stream response-headers))))))
           (sb-sys:deadline-timeout ()
             (error "no answer from ~A:~D within ~D seconds" address port timeout)))
      (when socket (ignore-errors (usocket:socket-close socket))))))

;;; Delegated authentication and authorization

(defstruct (kubelet-auth (:constructor %make-kubelet-auth))
  "How a kubelet checks its callers: certificates against CLIENT-CA, and tokens and access with
the API server at API-ADDRESS:API-PORT, which it trusts by TRUST-CERTIFICATES and reaches as
CLIENT-CERTIFICATE. REVIEW, when set, replaces the API call: it takes a review object and
returns the API server's answer."
  client-ca
  api-address
  (api-port 443)
  (api-server-name "kubernetes.default.svc")
  trust-certificates
  client-certificate
  client-key
  review
  (cache (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s kubelet auth cache")))

(defparameter +kubelet-authentication-cache-seconds+ 120
  "How long a token's review is reused, the kubelet's default.")

(defparameter +kubelet-authorized-cache-seconds+ 300
  "How long an allowed access review is reused, the kubelet's default.")

(defparameter +kubelet-unauthorized-cache-seconds+ 30
  "How long a denied access review is reused, the kubelet's default.")

(defparameter +kubelet-auth-cache-limit+ 1024
  "Entries kept before the cache starts over, so reviews of many tokens cost bounded memory.")

(defun make-kubelet-auth (&key client-ca api-address (api-port 443) trust-certificates
                               client-certificate client-key review)
  "Return how a kubelet authenticates and authorizes its callers."
  (%make-kubelet-auth :client-ca client-ca :api-address api-address :api-port api-port
                      :trust-certificates trust-certificates :client-certificate client-certificate
                      :client-key client-key :review review))

(defun kubelet-auth-cached (auth key ttl-function compute)
  "Return KEY's cached answer, or COMPUTE it and keep it for as long as TTL-FUNCTION says it may be."
  (let ((now (get-universal-time)))
    (bt:with-lock-held ((kubelet-auth-lock auth))
      (let ((entry (gethash key (kubelet-auth-cache auth))))
        (when (and entry (< now (car entry)))
          (return-from kubelet-auth-cached (cdr entry)))))
    (let ((value (funcall compute)))
      (bt:with-lock-held ((kubelet-auth-lock auth))
        (when (>= (hash-table-count (kubelet-auth-cache auth)) +kubelet-auth-cache-limit+)
          (clrhash (kubelet-auth-cache auth)))
        (setf (gethash key (kubelet-auth-cache auth)) (cons (+ now (funcall ttl-function value)) value)))
      value)))

(defun kubelet-delegated-review (auth review)
  "Create REVIEW, a TokenReview or SubjectAccessReview object, with the API server and return its answer."
  (if (kubelet-auth-review auth)
      (funcall (kubelet-auth-review auth) review)
      (let ((group (if (equal "TokenReview" (gethash "kind" review)) "authentication.k8s.io" "authorization.k8s.io"))
            (resource (if (equal "TokenReview" (gethash "kind" review)) "tokenreviews" "subjectaccessreviews")))
        (multiple-value-bind (code headers body)
            (tls-http-request :address (kubelet-auth-api-address auth) :port (kubelet-auth-api-port auth)
                              :server-name (kubelet-auth-api-server-name auth) :method :post
                              :target (format nil "/apis/~A/v1/~A" group resource)
                              :headers '(("Content-Type" . "application/json") ("Accept" . "application/json"))
                              :body (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify review))
                              :trust-certificates (kubelet-auth-trust-certificates auth)
                              :client-certificate (kubelet-auth-client-certificate auth)
                              :client-key (kubelet-auth-client-key auth))
          (declare (ignore headers))
          (unless (<= 200 code 299)
            (error "~A review failed with HTTP ~D: ~A" (gethash "kind" review) code
                   (trivial-utf-8:utf-8-bytes-to-string body)))
          (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string body))))))

(defun kubelet-token-identity (auth token)
  "Return the identity a TokenReview finds for TOKEN, or NIL when the token is not valid."
  (kubelet-auth-cached
   auth (list :token (octets-to-hex (ironclad:digest-sequence :sha256 (trivial-utf-8:string-to-utf-8-bytes token))))
   (constantly +kubelet-authentication-cache-seconds+)
   (lambda ()
     (let* ((answer (kubelet-delegated-review
                     auth (core-object "apiVersion" "authentication.k8s.io/v1" "kind" "TokenReview"
                                       "spec" (core-object "token" token))))
            (status (gethash "status" answer)))
       (when (and (hash-table-p status) (eq t (gethash "authenticated" status)))
         (let ((user (gethash "user" status)))
           (make-api-user-identity :username (gethash "username" user)
                                   :uid (let ((uid (gethash "uid" user))) (and (plusp (length uid)) uid))
                                   :groups (coerce (gethash "groups" user #()) 'vector)
                                   :extra (let ((extra (gethash "extra" user))) (and (hash-table-p extra) extra)))))))))

(defun kubelet-authenticate (auth chain authorization)
  "Return the caller's identity from a verified client certificate CHAIN or the bearer token in
the AUTHORIZATION header, or NIL."
  (or (and chain (handler-case (certificate-api-identity chain (kubelet-auth-client-ca auth))
                   (kubernetes-error () nil)))
      (let ((token (and authorization (uiop:string-prefix-p "Bearer " authorization)
                        (string-trim " " (subseq authorization 7)))))
        (and token (plusp (length token)) (kubelet-token-identity auth token)))))

(defun kubelet-authorized-p (auth identity verb subresource node-name)
  "Ask whether IDENTITY may VERB nodes/SUBRESOURCE on NODE-NAME."
  (let ((actor (api-identity-actor identity)))
    (kubelet-auth-cached
     auth (list :access (gethash "username" actor) (coerce (gethash "groups" actor #()) 'list)
                (gethash "uid" actor) verb subresource node-name)
     (lambda (allowed) (if allowed +kubelet-authorized-cache-seconds+ +kubelet-unauthorized-cache-seconds+))
     (lambda ()
       (let* ((spec (core-object "user" (gethash "username" actor) "groups" (gethash "groups" actor #())
                                 "resourceAttributes" (core-object "verb" verb "version" "v1" "resource" "nodes"
                                                                   "subresource" subresource "name" node-name)))
              (answer (progn
                        (when (gethash "uid" actor) (setf (gethash "uid" spec) (gethash "uid" actor)))
                        (when (hash-table-p (gethash "extra" actor)) (setf (gethash "extra" spec) (gethash "extra" actor)))
                        (kubelet-delegated-review
                         auth (core-object "apiVersion" "authorization.k8s.io/v1" "kind" "SubjectAccessReview"
                                           "spec" spec))))
              (status (gethash "status" answer)))
         (and (hash-table-p status) (eq t (gethash "allowed" status))))))))

(defun kubelet-request-verb (method)
  "Map an HTTP METHOD to the verb the kubelet authorizes, as its auth filter does."
  (case method (:post "create") (:get "get") (:put "update") (:patch "patch") (:delete "delete") (t "")))

(defun kubelet-request-subresources (path)
  "Return the nodes subresources that may allow PATH, in the order the kubelet tries them.
With fine-grained authorization, always on since 1.36, /pods, /healthz and /configz have their
own subresource and fall back to proxy; /stats and /metrics have only theirs."
  (flet ((under (prefix) (or (equal path prefix) (uiop:string-prefix-p (concatenate 'string prefix "/") path))))
    (append
     (cond ((or (under "/allocatedPods") (under "/pods") (under "/runningpods")) '("pods"))
           ((under "/healthz") '("healthz"))
           ((under "/configz") '("configz")))
     (list (cond ((under "/stats") "stats")
                 ((under "/metrics") "metrics")
                 ((under "/logs") "log")
                 ((under "/checkpoint") "checkpoint")
                 ((under "/statusz") "statusz")
                 ((under "/flagz") "configz")
                 (t "proxy"))))))

;;; The listener

(defclass kubelet-acceptor (gr8s-acceptor)
  ((certificate :initarg :certificate :reader kubelet-acceptor-certificate)
   (private-key :initarg :private-key :reader kubelet-acceptor-private-key)
   (node-name :initarg :node-name :reader kubelet-acceptor-node-name)
   (auth :initarg :auth :reader kubelet-acceptor-auth)
   (stats-function :initarg :stats-function :reader kubelet-acceptor-stats-function)
   (cadvisor-function :initarg :cadvisor-function :initform (constantly nil) :reader kubelet-acceptor-cadvisor-function)
   (probes-function :initarg :probes-function :initform (constantly nil) :reader kubelet-acceptor-probes-function)
   (states-function :initarg :states-function :initform (lambda () (values 0 nil)) :reader kubelet-acceptor-states-function)
   (network-metrics-function :initarg :network-metrics-function :initform (constantly "")
                             :reader kubelet-acceptor-network-metrics-function)
   (volumes-function :initarg :volumes-function :initform (constantly nil) :reader kubelet-acceptor-volumes-function))
  (:documentation "Serve a node's kubelet endpoints to authenticated, authorized callers over TLS.")
  (:default-initargs
   :taskmaster (make-instance 'hunchentoot:one-thread-per-connection-taskmaster :max-thread-count 64
                                                                                  :max-accept-count 128)))

(defmethod hunchentoot:acceptor-ssl-p ((acceptor kubelet-acceptor))
  "Identify this acceptor as HTTPS."
  t)

(defmethod hunchentoot:process-connection :around ((acceptor kubelet-acceptor) socket)
  "Keep each connection's verified client chain to that connection."
  (let ((*api-connection-certificate-chain* nil)) (call-next-method)))

(defmethod hunchentoot:initialize-connection-stream ((acceptor kubelet-acceptor) stream)
  "Accept an optional client certificate, whose chain the request's authentication then verifies."
  (with-tls-handshake-deadline (*tls-handshake-seconds*)
    (let* ((pure-tls:*server-ticket-key* (ironclad:random-data 32))
           (tls (pure-tls:make-tls-server-stream stream :certificate (kubelet-acceptor-certificate acceptor)
                                                        :key (kubelet-acceptor-private-key acceptor)
                                                        :verify pure-tls:+verify-peer+ :trust-store nil)))
      (setf *api-connection-certificate-chain* (pure-tls:tls-peer-certificate-chain tls))
      tls)))

(defun kubelet-text-response (code text &optional (content-type "text/plain; charset=utf-8"))
  "Answer with status CODE and TEXT."
  (setf (hunchentoot:return-code*) code (hunchentoot:content-type*) content-type)
  text)

(defun kubelet-own-metrics-text (states node-name &optional volumes network-metrics)
  "Render the kubelet's own /metrics: STATES, the running Pod count and container states, the
instrumented runtime operations and Pod latencies, its identity, the statistics of VOLUMES,
the (namespace claim host-path) of each mounted claim, and the process collector."
  (with-output-to-string (out)
    (write-string (kubelet-instrumentation-text) out)
    (write-string (dns-metrics-text) out)
    (write-prometheus-family out "kubelet_node_name" "[ALPHA] The node's name. The count is always 1." "gauge"
                             (list (list (list (cons "node" node-name)) 1)))
    (when states
      (write-prometheus-family out "kubelet_running_containers" "[ALPHA] Number of containers currently running" "gauge"
                               (loop for (state . count) in (second states)
                                     collect (list (list (cons "container_state" state)) count)))
      (write-prometheus-family out "kubelet_running_pods" "[ALPHA] Number of pods that have a running pod sandbox" "gauge"
                               (list (list nil (first states)))))
    (write-string (kubelet-volume-stats-text volumes) out)
    (when network-metrics (write-string network-metrics out))
    (write-string (process-metrics-text) out)))

(defvar *kubelet-process-start-time* (get-universal-time)
  "When this process started serving, in universal time.")

(defun kubelet-probe-metrics-text (manager)
  "Render the kubelet's /metrics/probes from the probe workers of MANAGER, which may be NIL.
As upstream's workers do, each result series appears once that result has happened, and
goes with its worker."
  (let ((totals nil) (durations nil))
    (when manager
      (bt:with-lock-held ((container-probe-manager-lock manager))
        (loop for target being the hash-values of (container-probe-manager-targets manager)
              do (dolist (worker (container-probe-target-workers target))
                   (let ((labels (list (cons "container" (container-probe-target-name target))
                                       (cons "namespace" (or (container-probe-target-namespace target) ""))
                                       (cons "pod" (or (container-probe-target-pod-name target) ""))))
                         (type (container-probe-worker-type worker)))
                     (loop for (result count) in (list (list "successful" (container-probe-worker-successes worker))
                                                       (list "failed" (container-probe-worker-failures worker)))
                           when (plusp count)
                             do (push (list (append labels (list (cons "pod_uid" (container-probe-target-uid target))
                                                                 (cons "probe_type" type) (cons "result" result)))
                                            count)
                                      totals))
                     (let ((histogram (container-probe-worker-latencies worker)))
                       (when histogram
                         (push (cons (append labels (list (cons "probe_type" type))) (copy-histogram histogram))
                               durations))))))))
    (with-output-to-string (out)
      (write-prometheus-histograms out "prober_probe_duration_seconds" "[ALPHA] Duration in seconds for a probe response."
                                   durations)
      (write-prometheus-family out "prober_probe_total"
                               "[BETA] Cumulative number of a liveness, readiness or startup probe for a container by result."
                               "counter" totals)
      (write-prometheus-family out "process_start_time_seconds" "[ALPHA] Start time of the process since unix epoch in seconds." "gauge"
                               (list (list nil (- *kubelet-process-start-time* 2208988800)))))))

(defparameter *kubelet-log-directory* #p"/var/log/"
  "The directory the kubelet's /logs/ endpoint serves, as upstream's http.FileServer over /var/log.")

(defun kubelet-log-pathname (path)
  "Map a /logs/... request PATH to a pathname under *kubelet-log-directory*, or NIL when a
segment is empty-named, . or .., which could leave the directory."
  (let ((segments (uiop:split-string (subseq path (min (length path) (length "/logs/"))) :separator "/")))
    (unless (some (lambda (segment) (member segment '("." "..") :test #'equal)) segments)
      (let ((names (remove "" segments :test #'equal)))
        (if (or (null names) (uiop:string-suffix-p path "/"))
            (merge-pathnames (format nil "~{~A/~}" names) *kubelet-log-directory*)
            (merge-pathnames (format nil "~{~A/~}~A" (butlast names) (car (last names))) *kubelet-log-directory*))))))

(defun kubelet-html-escape (text)
  "Escape TEXT for an HTML listing, as Go's htmlReplacer does."
  (with-output-to-string (out)
    (loop for character across text
          do (case character
               (#\& (write-string "&amp;" out)) (#\< (write-string "&lt;" out)) (#\> (write-string "&gt;" out))
               (#\" (write-string "&#34;" out)) (#\' (write-string "&#39;" out))
               (t (write-char character out))))))

(defun kubelet-logs-response (path)
  "Serve the node's log directory as the kubelet's /logs/ file server does: a directory as a
sorted HTML listing, a file as itself, and a directory named without its trailing slash, or
/logs itself, as a redirect to it."
  (let ((pathname (kubelet-log-pathname path)))
    (cond
      ((or (null pathname) (equal path "/logs") (not (or (uiop:directory-exists-p pathname) (probe-file pathname))))
       (if (equal path "/logs")
           (progn (setf (hunchentoot:header-out :location) "/logs/")
                  (kubelet-text-response 301 ""))
           (kubelet-text-response 404 (format nil "404 page not found~%"))))
      ((and (uiop:directory-exists-p (uiop:ensure-directory-pathname pathname)) (not (uiop:string-suffix-p path "/")))
       (setf (hunchentoot:header-out :location) (concatenate 'string path "/"))
       (kubelet-text-response 301 ""))
      ((uiop:directory-exists-p pathname)
       (let ((names (sort (append (mapcar (lambda (directory) (concatenate 'string (car (last (pathname-directory directory))) "/"))
                                          (uiop:subdirectories pathname))
                                  (mapcar #'file-namestring (uiop:directory-files pathname)))
                          #'string<)))
         (kubelet-text-response
          200 (format nil "<!doctype html>~%<meta name=\"viewport\" content=\"width=device-width\">~%<pre>~%~{~A~}</pre>~%"
                      (mapcar (lambda (name)
                                ;; A directory's trailing slash stays a path separator in its link.
                                (let ((directory (uiop:string-suffix-p name "/")))
                                  (format nil "<a href=\"~A~:[~;/~]\">~A</a>~%"
                                          (kubelet-html-escape (hunchentoot:url-encode (if directory (subseq name 0 (1- (length name))) name)))
                                          directory (kubelet-html-escape name))))
                              names))
          "text/html; charset=utf-8")))
      (t (hunchentoot:handle-static-file pathname "text/plain; charset=utf-8")))))

(defun kubelet-endpoint-response (acceptor path method)
  "Serve PATH for a caller already allowed to read it."
  (cond
    ((and (or (equal path "/logs") (uiop:string-prefix-p "/logs/" path)) (member method '(:get :head)))
     (kubelet-logs-response path))
    ((and (equal path "/metrics/probes") (member method '(:get :head)))
     (kubelet-text-response 200 (kubelet-probe-metrics-text (funcall (kubelet-acceptor-probes-function acceptor)))
                            "text/plain; version=0.0.4; charset=utf-8"))
    ((and (equal path "/metrics/cadvisor") (member method '(:get :head)))
     (kubelet-text-response
      200 (handler-case (kubelet-cadvisor-metrics-text (funcall (kubelet-acceptor-cadvisor-function acceptor)))
            (error (condition)
              (format *error-output* "gr8s kubelet cadvisor metrics: ~A~%" condition)
              (kubelet-cadvisor-metrics-text nil)))
      "text/plain; version=0.0.4; charset=utf-8"))
    ((and (equal path "/metrics") (member method '(:get :head)))
     (kubelet-text-response
      200 (kubelet-own-metrics-text (ignore-errors (multiple-value-list (funcall (kubelet-acceptor-states-function acceptor))))
                                    (kubelet-acceptor-node-name acceptor)
                                    (ignore-errors (funcall (kubelet-acceptor-volumes-function acceptor)))
                                    (ignore-errors (funcall (kubelet-acceptor-network-metrics-function acceptor))))
      "text/plain; version=0.0.4; charset=utf-8"))
    ((and (equal path "/metrics/resource") (member method '(:get :head)))
     (let ((text (handler-case (kubelet-resource-metrics-text (funcall (kubelet-acceptor-stats-function acceptor)))
                   (error (condition)
                     (format *error-output* "gr8s kubelet resource metrics: ~A~%" condition)
                     (kubelet-resource-metrics-text nil :error t)))))
       (kubelet-text-response 200 text "text/plain; version=0.0.4; charset=utf-8")))
    ((and (equal path "/stats/summary") (member method '(:get :post)))
     (let ((only (loop for (name . value) in (hunchentoot:get-parameters*)
                       when (equal name "only_cpu_and_memory") collect value)))
       (handler-case
           (kubelet-text-response
            200 (com.inuoe.jzon:stringify
                 (kubelet-stats-summary-object (funcall (kubelet-acceptor-stats-function acceptor))
                                               :cpu-and-memory-only (equal only '("true"))))
            "application/json")
         (error (condition)
           (kubelet-text-response 500 (format nil "Internal Error: failed to get node info: ~A~%" condition))))))
    ((and (member path '("/healthz" "/healthz/ping") :test #'equal) (member method '(:get :head)))
     (kubelet-text-response 200 "ok"))
    (t (kubelet-text-response 404 (format nil "404 page not found~%")))))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor kubelet-acceptor) request)
  "Authenticate, authorize as the kubelet's filter does, then serve the endpoint."
  (let* ((path (hunchentoot:script-name request)) (method (hunchentoot:request-method request))
         (auth (kubelet-acceptor-auth acceptor)) (node (kubelet-acceptor-node-name acceptor)))
    (handler-case
        (let ((identity (kubelet-authenticate auth *api-connection-certificate-chain*
                                              (hunchentoot:header-in :authorization request))))
          (cond
            ((null identity) (kubelet-text-response 401 "Unauthorized"))
            ((let ((verb (kubelet-request-verb method)) (subresources (kubelet-request-subresources path)))
               (unless (some (lambda (subresource) (kubelet-authorized-p auth identity verb subresource node))
                             subresources)
                 (kubelet-text-response 403 (format nil "Forbidden (user=~A, verb=~A, resource=nodes, subresource(s)=[~{~A~^ ~}])~%"
                                                    (api-identity-username identity) verb subresources)))))
            (t (kubelet-endpoint-response acceptor path method))))
      ((or error sb-sys:deadline-timeout sb-ext:timeout) (condition)
        (format *error-output* "gr8s kubelet request ~A: ~A~%" path condition)
        (kubelet-text-response 500 (format nil "Internal Error: ~A~%" condition))))))

(defun start-kubelet-server (&key (address "0.0.0.0") (port +kubelet-default-port+) certificate key
                                  node-name auth stats-function (cadvisor-function (constantly nil))
                                  (states-function (lambda () (values 0 nil))) (probes-function (constantly nil))
                                  (network-metrics-function (constantly ""))
                                  (volumes-function (constantly nil)))
  "Start serving NODE-NAME's kubelet endpoints. STATS-FUNCTION returns a fresh KUBELET-NODE-STATS."
  (hunchentoot:start
   (make-instance 'kubelet-acceptor :address address :port port
                                    ;; Loaded once, so connections need not read the files.
                                    :certificate (pure-tls:load-certificate-chain certificate)
                                    :private-key (pure-tls:load-private-key key)
                                    :node-name node-name :auth auth :stats-function stats-function
                                    :cadvisor-function cadvisor-function :states-function states-function
                                    :network-metrics-function network-metrics-function
                                    :probes-function probes-function :volumes-function volumes-function
                                    :access-log-destination nil :message-log-destination *error-output*)))

(defun stop-kubelet-server (server)
  "Stop a kubelet listener and the requests it is serving."
  (ignore-errors (hunchentoot:stop server)))

;;; The API server side: the Node proxy

(defun node-kubelet-endpoint (store name)
  "Return NAME's address and advertised kubelet port, or NIL when its kubelet serves nothing."
  (with-store-lock (store)
    (let ((node (gethash name (pod-store-nodes store))))
      (when (and node (not (node-record-api-only node)) (plusp (or (node-record-kubelet-port node) 0)))
        (values (node-reported-address node) (node-record-kubelet-port node))))))

(defvar *kubelet-proxy-credentials* nil
  "The cluster CA trust set, and the API server's kubelet client certificate and key paths, once known.")

(defun kubelet-proxy-response (store name port suffix method)
  "Forward a Node proxy read to NAME's kubelet and relay its status, type and body."
  (multiple-value-bind (address advertised) (node-kubelet-endpoint store name)
    (destructuring-bind (&optional ca certificate key) *kubelet-proxy-credentials*
      (unless (and address ca)
        (core-resource-error 503 "ServiceUnavailable" "Node ~A has no kubelet endpoint to proxy to" name))
      (let* ((raw (hunchentoot:request-uri*))
             (query (let ((question (position #\? raw))) (and question (subseq raw question))))
             (target-port (if (and port (plusp (length port)) (every #'digit-char-p port)) (parse-integer port) advertised)))
        (multiple-value-bind (code headers body)
            (handler-case
                (tls-http-request :address address :port target-port :server-name address :method method
                                  :target (concatenate 'string suffix (or query ""))
                                  :headers '(("Accept" . "*/*"))
                                  :trust-certificates (if (listp ca) ca (list ca))
                                  :client-certificate certificate :client-key key)
              (error (condition)
                (core-resource-error 503 "ServiceUnavailable" "error trying to reach the kubelet of node ~A: ~A"
                                     name (remove #\Newline (princ-to-string condition)))))
          (setf (hunchentoot:return-code*) code
                (hunchentoot:content-type*) (or (cdr (assoc "content-type" headers :test #'string=)) "text/plain"))
          body)))))

;;; The agent side

(defun start-agent-kubelet-server (options node-name runtime &key (network-metrics-function (constantly "")))
  "Start the agent's kubelet listener when OPTIONS give it a port and its credentials exist,
returning it, or NIL. A port another process holds leaves the node without one, as reported."
  (let ((port (or (getf options :kubelet-port) 0))
        (directory (uiop:ensure-directory-pathname (getf options :state-directory))))
    (multiple-value-bind (certificate key client-certificate client-key) (kubelet-credential-paths directory)
      (when (and (plusp port) (probe-file certificate) (probe-file client-certificate))
        (handler-case
            (let ((ca (first (pure-tls:load-certificate-chain (merge-pathnames "ca.crt" directory)))))
              (multiple-value-bind (api-host api-port) (parse-agent-server (or (getf options :kubelet-api-server) "10.96.0.1:443"))
                (start-kubelet-server
                 :port port :certificate certificate :key key :node-name node-name
                 :auth (make-kubelet-auth :client-ca ca :api-address api-host :api-port api-port
                                          :trust-certificates (list ca)
                                          :client-certificate client-certificate :client-key client-key)
                 :stats-function (lambda () (collect-kubelet-node-stats runtime node-name))
                 :cadvisor-function (lambda () (runtime-cadvisor-entries runtime))
                 :states-function (lambda () (runtime-container-state-counts runtime))
                 :network-metrics-function network-metrics-function
                 :volumes-function (lambda () (runtime-claim-volume-paths runtime))
                 :probes-function (lambda () (and (typep runtime 'containerd-runtime)
                                                  (containerd-runtime-probes runtime))))))
          (error (condition)
            (format *error-output* "gr8s kubelet endpoints on port ~D are unavailable: ~A~%" port condition)
            nil))))))
