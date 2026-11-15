;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; A Kubernetes API client for running gr8s components against a foreign
;;;; cluster (docs/design-foreign-cluster-networking.md).
;;;;
;;;; The client speaks the same JSON the rest of gr8s does -- objects are the
;;;; EQUAL-keyed hash tables com.inuoe.jzon produces, exactly the shapes the
;;;; controllers consume from the gr8s store -- so a watch cache can stand in
;;;; for the store behind the desired-state read seam.  It provides one-shot
;;;; requests, the list+watch loop with resourceVersion resume and bookmark
;;;; support, an informer that materializes a resource collection into a local
;;;; cache, and coordination.k8s.io Lease leader election for the small amount
;;;; of cluster-scoped work a DaemonSet of equal agents must do exactly once.

(defpackage #:gr8s.kube-client
  (:use #:cl)
  (:export #:kube-cluster
           #:make-kube-cluster
           #:kube-cluster-p
           #:kube-cluster-host
           #:kube-cluster-port
           #:kube-cluster-namespace
           #:cluster-from-service-account
           #:cluster-from-kubeconfig
           #:resource-path
           #:kube-error
           #:kube-error-status
           #:kube-error-body
           #:kube-request
           #:kube-get
           #:kube-list
           #:kube-create
           #:kube-replace
           #:kube-delete
           #:kube-watch
           #:informer
           #:start-informer
           #:stop-informer
           #:informer-synced-p
           #:informer-object
           #:informer-objects
           #:object-key
           #:run-lease-leader))

(in-package #:gr8s.kube-client)

;;; ---------------------------------------------------------------------------
;;; Cluster descriptions

(defstruct kube-cluster
  "How to reach and authenticate to one Kubernetes API server.
TOKEN-FUNCTION returns a current bearer token or NIL; it is called per request
because ServiceAccount tokens rotate.  PLAIN speaks http:// (a test server or a
local proxy); otherwise the chain verifies against TRUST-CERTIFICATES."
  (host "127.0.0.1") (port 6443) server-name
  plain insecure trust-certificates
  token-function client-certificate-path client-key-path
  (namespace "default"))

(defun parse-pem-certificates (text)
  "Parse every PEM certificate block in TEXT into pure-tls certificates."
  (let ((begin "-----BEGIN CERTIFICATE-----") (end "-----END CERTIFICATE-----"))
    (loop with cursor = 0
          for start = (search begin text :start2 cursor)
          while start
          collect (let ((stop (or (search end text :start2 start)
                                  (error "Unterminated PEM certificate block"))))
                    (setf cursor (+ stop (length end)))
                    (pure-tls:parse-certificate
                     (ag-grpc:base64-decode
                      (remove-if (lambda (character)
                                   (member character '(#\Space #\Tab #\Newline #\Return)))
                                 (subseq text (+ start (length begin)) stop))))))))

(defparameter +service-account-root+ #P"/var/run/secrets/kubernetes.io/serviceaccount/"
  "Where a Pod's ServiceAccount credentials are projected.")

(defun cluster-from-service-account (&key (root +service-account-root+)
                                          (host (uiop:getenv "KUBERNETES_SERVICE_HOST"))
                                          (port (uiop:getenv "KUBERNETES_SERVICE_PORT")))
  "The in-cluster configuration every Kubernetes Pod is born with."
  (let ((token-path (merge-pathnames "token" root)))
    (make-kube-cluster
     :host (or host "kubernetes.default.svc")
     :port (if port (parse-integer port) 443)
     :server-name "kubernetes.default.svc"
     :trust-certificates (parse-pem-certificates
                          (uiop:read-file-string (merge-pathnames "ca.crt" root)))
     :token-function (lambda () (string-trim '(#\Newline #\Space)
                                             (uiop:read-file-string token-path)))
     :namespace (string-trim '(#\Newline #\Space)
                             (uiop:read-file-string (merge-pathnames "namespace" root))))))

(defun yaml-find (sequence name)
  "Find the entry of a kubeconfig NAME-keyed YAML sequence."
  (find name (coerce sequence 'list) :test #'equal
        :key (lambda (entry) (gethash "name" entry))))

(defun kubeconfig-bytes-or-file (table data-key path-key)
  "Return decoded TEXT for a kubeconfig field stored inline or as a path, or NIL."
  (let ((data (gethash data-key table)))
    (if data
        (trivial-utf-8:utf-8-bytes-to-string (ag-grpc:base64-decode data))
        (let ((path (gethash path-key table)))
          (and path (uiop:read-file-string path))))))

(defun kubeconfig-credential-path (table data-key path-key what)
  "A file path for a kubeconfig credential: the named path, or inline data
materialized to a private file (TLS clients take key material by path)."
  (or (gethash path-key table)
      (let ((data (gethash data-key table)))
        (when data
          (let ((path (merge-pathnames
                       (format nil "gr8s-kubeconfig-~A-~36R.pem" what
                               (random most-positive-fixnum (make-random-state t)))
                       (uiop:temporary-directory))))
            (uiop:with-output-file (out path :if-exists :supersede)
              (write-string (trivial-utf-8:utf-8-bytes-to-string
                             (ag-grpc:base64-decode data))
                            out))
            #+sbcl (sb-posix:chmod (namestring path) #o600)
            (namestring path))))))

(defun cluster-from-kubeconfig (path &key context)
  "Read a kubeconfig file: CONTEXT by name, or its current-context."
  (let* ((config (cl-safe-yaml:parse-yaml (uiop:read-file-string path)))
         (context-name (or context (gethash "current-context" config)
                           (error "kubeconfig ~A names no current-context" path)))
         (entry (or (yaml-find (gethash "contexts" config) context-name)
                    (error "kubeconfig ~A has no context ~A" path context-name)))
         (selected (gethash "context" entry))
         (cluster-entry (or (yaml-find (gethash "clusters" config) (gethash "cluster" selected))
                            (error "kubeconfig ~A has no cluster ~A" path (gethash "cluster" selected))))
         (cluster (gethash "cluster" cluster-entry))
         (user-entry (yaml-find (gethash "users" config) (gethash "user" selected)))
         (user (and user-entry (gethash "user" user-entry)))
         (uri (puri:parse-uri (gethash "server" cluster)))
         (plain (eq (puri:uri-scheme uri) :http))
         (ca-text (kubeconfig-bytes-or-file cluster "certificate-authority-data" "certificate-authority"))
         (token (and user (gethash "token" user))))
    (make-kube-cluster
     :host (puri:uri-host uri)
     :port (or (puri:uri-port uri) (if plain 80 443))
     :server-name (puri:uri-host uri)
     :plain plain
     :insecure (eq t (gethash "insecure-skip-tls-verify" cluster))
     :trust-certificates (and ca-text (parse-pem-certificates ca-text))
     :token-function (and token (constantly token))
     :client-certificate-path
     (and user (kubeconfig-credential-path user "client-certificate-data"
                                           "client-certificate" "certificate"))
     :client-key-path
     (and user (kubeconfig-credential-path user "client-key-data" "client-key" "key"))
     :namespace (or (and selected (gethash "namespace" selected)) "default"))))

;;; ---------------------------------------------------------------------------
;;; Requests

(define-condition kube-error (error)
  ((status :initarg :status :reader kube-error-status)
   (body :initarg :body :reader kube-error-body))
  (:report (lambda (condition stream)
             (format stream "Kubernetes API error ~D: ~A"
                     (kube-error-status condition)
                     (let ((body (kube-error-body condition)))
                       (or (and (hash-table-p body) (gethash "message" body))
                           body))))))

(defun percent-encode (text)
  "Encode TEXT for one query-string value."
  (with-output-to-string (out)
    (loop for octet across (trivial-utf-8:string-to-utf-8-bytes text)
          for character = (code-char octet)
          do (if (or (alphanumericp character) (find character "-._~"))
                 (write-char character out)
                 (format out "%~2,'0X" octet)))))

(defun query-target (path query)
  "PATH with the non-NIL-valued QUERY alist appended as a query string."
  (let ((live (remove nil query :key #'cdr)))
    (if (null live)
        path
        (format nil "~A?~{~A~^&~}" path
                (mapcar (lambda (pair)
                          (format nil "~A=~A" (car pair)
                                  (percent-encode (princ-to-string (cdr pair)))))
                        live)))))

(defun resource-path (group version resource &key namespace name subresource)
  "The URL path of a resource collection, object, or subresource."
  (format nil "~A~@[/namespaces/~A~]/~A~@[/~A~]~@[/~A~]"
          (if (or (null group) (equal group ""))
              (format nil "/api/~A" version)
              (format nil "/apis/~A/~A" group version))
          namespace resource name subresource))

(defun cluster-headers (cluster)
  (let* ((token-function (kube-cluster-token-function cluster))
         (token (and token-function (funcall token-function))))
    (append '(("Accept" . "application/json")
              ("Content-Type" . "application/json"))
            (when token (list (cons "Authorization"
                                    (concatenate 'string "Bearer " token)))))))

(defun normalize-json-nulls (value)
  "Replace jzon's JSON-null (the symbol CL:NULL) with NIL throughout VALUE, in
place for hash tables and vectors.  A foreign cluster leaves fields explicitly
null where gr8s's own serialization omits them; CL:NULL is a truthy, non-sequence
symbol that breaks array reads and OR-defaults, while NIL is a valid empty
sequence and the natural absent value.  Returns the normalized VALUE."
  (cond
    ((eq value 'null) nil)
    ((hash-table-p value)
     (maphash (lambda (key inner)
                (setf (gethash key value) (normalize-json-nulls inner)))
              value)
     value)
    ((and (vectorp value) (not (stringp value)))
     (dotimes (index (length value) value)
       (setf (aref value index) (normalize-json-nulls (aref value index)))))
    (t value)))

(defun parse-kube-json (text)
  "Parse a Kubernetes API JSON response, with JSON null normalized to NIL."
  (normalize-json-nulls
   (com.inuoe.jzon:parse text :max-string-length +response-limit+)))

(defun read-stream-octets (stream limit)
  "Read STREAM to its end into an octet vector of at most LIMIT octets."
  (let ((body (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for byte = (read-byte stream nil nil)
          while byte
          do (when (>= (length body) limit)
               (error 'gr8s.http-client:http-response-too-large
                      :message "Kubernetes API response is too large"))
             (vector-push-extend byte body))
    (coerce body '(simple-array (unsigned-byte 8) (*)))))

(defparameter +response-limit+ (* 64 1024 1024)
  "Largest accepted API response; a big cluster's Pod list is tens of megabytes.")

(defun call-with-cluster-response (cluster function &key (method :get) target body timeout on-connect)
  (gr8s.http-client:call-with-http-response
   function
   :host (kube-cluster-host cluster) :port (kube-cluster-port cluster)
   :server-name (kube-cluster-server-name cluster)
   :method method :target target
   :headers (cluster-headers cluster)
   :body (and body (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify body)))
   :plain (kube-cluster-plain cluster)
   :insecure (kube-cluster-insecure cluster)
   :trust-certificates (kube-cluster-trust-certificates cluster)
   :client-certificate (kube-cluster-client-certificate-path cluster)
   :client-key (kube-cluster-client-key-path cluster)
   :timeout timeout :on-connect on-connect))

(defun kube-request (cluster method path &key body query (timeout 30) (errorp t))
  "One API request; the parsed JSON body and status code.  With ERRORP (the
default) a non-2xx answer signals a KUBE-ERROR carrying the parsed Status."
  (call-with-cluster-response
   cluster
   (lambda (code headers stream)
     (declare (ignore headers))
     (let* ((octets (read-stream-octets stream +response-limit+))
            (parsed (when (plusp (length octets))
                      (ignore-errors
                        (parse-kube-json (trivial-utf-8:utf-8-bytes-to-string octets))))))
       (when (and errorp (not (<= 200 code 299)))
         (error 'kube-error :status code :body parsed))
       (values parsed code)))
   :method method :target (query-target path query) :body body :timeout timeout))

(defun kube-get (cluster path &key query (timeout 30))
  (kube-request cluster :get path :query query :timeout timeout))

(defun kube-list (cluster path &key label-selector field-selector resource-version (timeout 60))
  (kube-request cluster :get path :timeout timeout
                        :query `(("labelSelector" . ,label-selector)
                                 ("fieldSelector" . ,field-selector)
                                 ("resourceVersion" . ,resource-version))))

(defun kube-create (cluster path object &key (timeout 30))
  (kube-request cluster :post path :body object :timeout timeout))

(defun kube-replace (cluster path object &key (timeout 30))
  (kube-request cluster :put path :body object :timeout timeout))

(defun kube-delete (cluster path &key (timeout 30) (errorp t))
  (kube-request cluster :delete path :timeout timeout :errorp errorp))

;;; ---------------------------------------------------------------------------
;;; Watching

(defun read-json-line (stream)
  "Read one LF-terminated line of UTF-8 from STREAM, or NIL at end of stream."
  (let ((octets (make-array 256 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for byte = (read-byte stream nil nil)
          do (cond ((null byte)
                    (return (when (plusp (length octets))
                              (trivial-utf-8:utf-8-bytes-to-string octets))))
                   ((= byte 10)
                    (return (trivial-utf-8:utf-8-bytes-to-string octets)))
                   (t (vector-push-extend byte octets))))))

(defun event-resource-version (object)
  (let ((metadata (and (hash-table-p object) (gethash "metadata" object))))
    (and metadata (gethash "resourceVersion" metadata))))

(defun kube-watch (cluster path on-event &key resource-version label-selector field-selector
                                              timeout-seconds on-connect)
  "Run one watch request against PATH, calling ON-EVENT with (type object) for
each ADDED/MODIFIED/DELETED event.  Returns (values last-resource-version exit):
exit :CLOSED when the server ended the stream (resume from the returned
revision), :EXPIRED when the start revision was too old (relist before watching
again).  Bookmarks advance the returned revision without reaching ON-EVENT."
  (let ((revision resource-version) (exit :closed))
    (call-with-cluster-response
     cluster
     (lambda (code headers stream)
       (declare (ignore headers))
       (unless (= code 200)
         (let ((body (ignore-errors
                       (parse-kube-json
                        (trivial-utf-8:utf-8-bytes-to-string
                         (read-stream-octets stream +response-limit+))))))
           (when (eql code 410) (return-from kube-watch (values nil :expired)))
           (error 'kube-error :status code :body body)))
       (loop for line = (handler-case (read-json-line stream)
                          ;; A watch normally ends with the server (or our
                          ;; closer) dropping the connection, cleanly or not.
                          ((or end-of-file stream-error
                               gr8s.http-client::http-connection-closed) ()
                            nil))
             while line
             do (when (plusp (length line))
                  (let* ((event (parse-kube-json line))
                         (type (gethash "type" event))
                         (object (gethash "object" event)))
                    (cond
                      ((equal type "ERROR")
                       (when (eql 410 (and (hash-table-p object) (gethash "code" object)))
                         (setf exit :expired revision nil))
                       (return))
                      ((equal type "BOOKMARK")
                       (let ((new (event-resource-version object)))
                         (when new (setf revision new))))
                      (t
                       (let ((new (event-resource-version object)))
                         (when new (setf revision new)))
                       (funcall on-event type object)))))))
     :target (query-target path `(("watch" . "true")
                                  ("allowWatchBookmarks" . "true")
                                  ("resourceVersion" . ,resource-version)
                                  ("labelSelector" . ,label-selector)
                                  ("fieldSelector" . ,field-selector)
                                  ("timeoutSeconds" . ,timeout-seconds)))
     :on-connect on-connect)
    (values revision exit)))

;;; ---------------------------------------------------------------------------
;;; Informer: a resource collection, materialized

(defun object-key (object)
  "The cache key of an API object: namespace/name, or name when cluster-scoped."
  (let* ((metadata (gethash "metadata" object))
         (namespace (and metadata (gethash "namespace" metadata)))
         (name (and metadata (gethash "name" metadata))))
    (if (and namespace (plusp (length namespace)))
        (concatenate 'string namespace "/" name)
        name)))

(defstruct (informer (:constructor %make-informer))
  cluster path label-selector field-selector on-change
  (lock (bt:make-lock "gr8s kube informer"))
  (cache (make-hash-table :test 'equal))
  (synced nil) (running t)
  resource-version thread closer)

(defun informer-synced-p (informer)
  (bt:with-lock-held ((informer-lock informer)) (informer-synced informer)))

(defun informer-object (informer key)
  (bt:with-lock-held ((informer-lock informer))
    (gethash key (informer-cache informer))))

(defun informer-objects (informer)
  (bt:with-lock-held ((informer-lock informer))
    (loop for object being the hash-values of (informer-cache informer) collect object)))

(defun informer-note (informer change key object)
  (let ((on-change (informer-on-change informer)))
    (when on-change
      (handler-case (funcall on-change change key object)
        (error (condition)
          (format *error-output* "~&gr8s informer ~A handler failed: ~A~%"
                  (informer-path informer) condition))))))

(defun informer-apply (informer type object)
  (let ((key (object-key object)))
    (when key
      (bt:with-lock-held ((informer-lock informer))
        (if (equal type "DELETED")
            (remhash key (informer-cache informer))
            (setf (gethash key (informer-cache informer)) object)))
      (informer-note informer
                     (cond ((equal type "DELETED") :deleted)
                           ((equal type "ADDED") :added)
                           (t :modified))
                     key object))))

(defun informer-relist (informer)
  "List the collection, replace the cache, emit the differences, return the revision."
  (let* ((page (kube-list (informer-cluster informer) (informer-path informer)
                          :label-selector (informer-label-selector informer)
                          :field-selector (informer-field-selector informer)))
         (revision (gethash "resourceVersion" (gethash "metadata" page)))
         (fresh (make-hash-table :test 'equal))
         (changes nil))
    (loop for object across (gethash "items" page)
          for key = (object-key object)
          when key do (setf (gethash key fresh) object))
    (bt:with-lock-held ((informer-lock informer))
      (loop for key being the hash-keys of (informer-cache informer)
            unless (gethash key fresh)
              do (push (list :deleted key (gethash key (informer-cache informer))) changes))
      (loop for key being the hash-keys of fresh using (hash-value object)
            for old = (gethash key (informer-cache informer))
            do (cond ((null old) (push (list :added key object) changes))
                     ((not (equal (event-resource-version old) (event-resource-version object)))
                      (push (list :modified key object) changes))))
      (setf (informer-cache informer) fresh
            (informer-resource-version informer) revision
            (informer-synced informer) t))
    (dolist (change (nreverse changes))
      (apply #'informer-note informer change))
    revision))

(defun informer-loop (informer)
  (loop while (informer-running informer)
        do (handler-case
               (let ((revision (informer-relist informer)))
                 (loop while (informer-running informer)
                       do (multiple-value-bind (last exit)
                              (kube-watch (informer-cluster informer) (informer-path informer)
                                          (lambda (type object) (informer-apply informer type object))
                                          :resource-version revision
                                          :label-selector (informer-label-selector informer)
                                          :field-selector (informer-field-selector informer)
                                          :on-connect (lambda (closer)
                                                        (setf (informer-closer informer) closer)
                                                        (unless (informer-running informer)
                                                          (funcall closer))))
                            (when last (setf revision last
                                             (informer-resource-version informer) last))
                            (when (eq exit :expired) (return)))))
             (kube-error (condition)
               ;; A 404 collection is not an error to wait out: the resource's
               ;; CRD simply is not installed, and the correct cache is empty.
               ;; Report synced so consumers proceed, and look again rarely in
               ;; case the CRD arrives later.
               (cond
                 ((eql 404 (kube-error-status condition))
                  (bt:with-lock-held ((informer-lock informer))
                    (setf (informer-synced informer) t))
                  (loop repeat 30 while (informer-running informer) do (sleep 1)))
                 (t
                  (when (informer-running informer)
                    (format *error-output* "~&gr8s informer ~A: ~A; re-establishing~%"
                            (informer-path informer) condition)
                    (sleep 1)))))
             (error (condition)
               (when (informer-running informer)
                 (format *error-output* "~&gr8s informer ~A: ~A; re-establishing~%"
                         (informer-path informer) condition)
                 (sleep 1))))))

(defun start-informer (cluster path &key label-selector field-selector on-change)
  "Materialize the collection at PATH into a cache kept current by list+watch.
ON-CHANGE, when given, is called with (:added|:modified|:deleted key object)
after each cache update, including the differences a relist discovers."
  (let ((informer (%make-informer :cluster cluster :path path
                                  :label-selector label-selector
                                  :field-selector field-selector
                                  :on-change on-change)))
    (setf (informer-thread informer)
          (bt:make-thread (lambda () (informer-loop informer))
                          :name (format nil "gr8s informer ~A" path)))
    informer))

(defun stop-informer (informer)
  "Stop INFORMER's thread, interrupting any in-flight watch."
  (setf (informer-running informer) nil)
  (let ((closer (informer-closer informer)))
    (when closer (ignore-errors (funcall closer))))
  (let ((thread (informer-thread informer)))
    (when (and thread (bt:thread-alive-p thread))
      (bt:join-thread thread)))
  nil)

;;; ---------------------------------------------------------------------------
;;; Lease leader election

(defun rfc3339-micro (universal-time)
  "UNIVERSAL-TIME as the MicroTime text coordination.k8s.io carries."
  (multiple-value-bind (second minute hour day month year)
      (decode-universal-time universal-time 0)
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0D.000000Z"
            year month day hour minute second)))

(defun parse-rfc3339 (text)
  "The universal time of an RFC 3339 UTC timestamp, ignoring fractions; NIL unless parseable."
  (ignore-errors
    (encode-universal-time
     (parse-integer text :start 17 :end 19) (parse-integer text :start 14 :end 16)
     (parse-integer text :start 11 :end 13) (parse-integer text :start 8 :end 10)
     (parse-integer text :start 5 :end 7) (parse-integer text :start 0 :end 4)
     0)))

(defun lease-expired-p (spec duration now)
  (let* ((renew-text (gethash "renewTime" spec))
         (renewed (and renew-text (parse-rfc3339 renew-text))))
    (or (null renewed) (> now (+ renewed duration)))))

(defun run-lease-leader (cluster name identity
                         &key (namespace "kube-system") (lease-seconds 15) (renew-seconds 5)
                              on-gained on-lost (stop-predicate (constantly nil)))
  "Contend for the coordination.k8s.io Lease NAME in NAMESPACE as IDENTITY, until
STOP-PREDICATE returns true.  ON-GAINED runs after each acquisition, ON-LOST after
leadership is observed lost.  Write conflicts and transport failures are retried;
holding is re-proven every RENEW-SECONDS."
  (let ((path (resource-path "coordination.k8s.io" "v1" "leases"
                             :namespace namespace :name name))
        (collection (resource-path "coordination.k8s.io" "v1" "leases" :namespace namespace))
        (holding nil))
    (flet ((note (held)
             (cond ((and held (not holding)) (setf holding t) (when on-gained (funcall on-gained)))
                   ((and (not held) holding) (setf holding nil) (when on-lost (funcall on-lost))))))
      (unwind-protect
           (loop until (funcall stop-predicate)
                 do (handler-case
                        (let ((lease (handler-case (kube-get cluster path)
                                       (kube-error (condition)
                                         (unless (eql 404 (kube-error-status condition))
                                           (error condition))
                                         nil)))
                              (now (get-universal-time)))
                          (cond
                            ((null lease)
                             (kube-create
                              cluster collection
                              (let ((spec (make-hash-table :test 'equal))
                                    (metadata (make-hash-table :test 'equal))
                                    (object (make-hash-table :test 'equal)))
                                (setf (gethash "holderIdentity" spec) identity
                                      (gethash "leaseDurationSeconds" spec) lease-seconds
                                      (gethash "acquireTime" spec) (rfc3339-micro now)
                                      (gethash "renewTime" spec) (rfc3339-micro now)
                                      (gethash "leaseTransitions" spec) 0
                                      (gethash "name" metadata) name
                                      (gethash "namespace" metadata) namespace
                                      (gethash "apiVersion" object) "coordination.k8s.io/v1"
                                      (gethash "kind" object) "Lease"
                                      (gethash "metadata" object) metadata
                                      (gethash "spec" object) spec)
                                object))
                             (note t))
                            (t
                             (let* ((spec (gethash "spec" lease))
                                    (holder (gethash "holderIdentity" spec)))
                               (cond
                                 ((equal holder identity)
                                  (setf (gethash "renewTime" spec) (rfc3339-micro now))
                                  (kube-replace cluster path lease)
                                  (note t))
                                 ((lease-expired-p spec lease-seconds now)
                                  (setf (gethash "holderIdentity" spec) identity
                                        (gethash "acquireTime" spec) (rfc3339-micro now)
                                        (gethash "renewTime" spec) (rfc3339-micro now)
                                        (gethash "leaseTransitions" spec)
                                        (1+ (or (ignore-errors
                                                  (floor (gethash "leaseTransitions" spec 0)))
                                                0)))
                                  (kube-replace cluster path lease)
                                  (note t))
                                 (t (note nil)))))))
                      (kube-error (condition)
                        ;; A write conflict or a momentary API failure: someone
                        ;; else moved first, or the server blinked.  Re-read.
                        (declare (ignore condition))
                        (note nil))
                      (error (condition)
                        (declare (ignore condition))
                        (note nil)))
                    (cl-cancel:sleep-fractional
                     (if holding renew-seconds (max 1 (floor lease-seconds 3)))))
        (note nil)))))
