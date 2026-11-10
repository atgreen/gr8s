;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Read-only operational inventory for every locally persisted cluster
;;;; certificate and signing key. Stable names and machine fields are the
;;;; foundation for rotation gates; absence is reported without creating PKI.

(in-package #:gr8s.server)

(defparameter +certificate-warning-seconds+ (* 120 86400))

(defparameter +local-certificate-paths+
  '(("admin" "pki/admin.crt")
    ("agent-kubelet-client" "agent/kubelet-client.crt")
    ("agent-kubelet-serving" "agent/kubelet.crt")
    ("agent-node-client" "agent/node.crt")
    ("agent-standalone-trust-anchor" "ca.crt")
    ("agent-trust-anchor" "agent/ca.crt")
    ("apiserver-kubelet-client" "pki/apiserver-kubelet-client.crt")
    ("cluster-ca" "pki/pki/cluster-ca.crt")
    ("front-proxy-ca" "pki/front-proxy-ca.crt")
    ("front-proxy-client" "pki/front-proxy-client.crt")
    ("kubernetes-api" "pki/kubernetes-api.crt")
    ("node-client" "node.crt")
    ("node-server" "pki/pki/server.crt")
    ("raft-member" "pki/raft/member.crt")))

(defun certificate-status-duration (text)
  "Parse an operator duration such as 45d, 12h, 30m or 90s into seconds."
  (unless (and (stringp text) (> (length text) 1))
    (error "invalid certificate duration: ~S" text))
  (let* ((suffix (char-downcase (char text (1- (length text)))))
         (multiplier (case suffix (#\d 86400) (#\h 3600) (#\m 60) (#\s 1)
                       (otherwise (error "invalid certificate duration: ~A" text))))
         (number (parse-integer text :end (1- (length text)) :junk-allowed t)))
    (unless (and number (plusp number)
                 (string= (write-to-string number) (subseq text 0 (1- (length text)))))
      (error "invalid certificate duration: ~A" text))
    (* number multiplier)))

(defun parse-certificate-options (arguments)
  "Parse certificate inventory and staged ServiceAccount signing-key operations."
  (let* ((subcommand (first arguments))
         (key-rotation-p (string= subcommand "service-account-key"))
         (leaf-rotation-p (string= subcommand "rotate"))
         (ca-rotation-p (string= subcommand "rotate-ca"))
         (stage (and (or key-rotation-p ca-rotation-p) (second arguments)))
         (command (cond
                    ((member subcommand '("status" "check") :test #'string=) :certificate-status)
                    (leaf-rotation-p :certificate-rotate)
                    ((and ca-rotation-p (string= stage "prepare")) :certificate-ca-prepare)
                    ((and ca-rotation-p (string= stage "promote")) :certificate-ca-promote)
                    ((and ca-rotation-p (string= stage "finalize")) :certificate-ca-finalize)
                    ((and key-rotation-p (string= stage "prepare")) :certificate-service-account-key-prepare)
                    ((and key-rotation-p (string= stage "promote")) :certificate-service-account-key-promote)
                    ((and key-rotation-p (string= stage "finalize")) :certificate-service-account-key-finalize)
                    (t (error "unknown certificate subcommand: ~{~A~^ ~}" arguments)))))
    (let ((options (list :command command
                         :state-directory (namestring (default-state-directory))
                         :kubeconfig nil
                         :output-format :table
                         :warn-within +certificate-warning-seconds+
                         :services nil :api-addresses nil))
          (arguments (nthcdr (if (or key-rotation-p ca-rotation-p) 2 1) arguments)))
      (loop while arguments
          for option = (first arguments)
          do (cond
               ((string= option "--state-directory")
                (setf (getf options :state-directory) (option-value arguments option)
                      arguments (cddr arguments)))
               ((and (or key-rotation-p ca-rotation-p) (string= option "--kubeconfig"))
                (setf (getf options :kubeconfig) (option-value arguments option)
                      arguments (cddr arguments)))
               ((and (eq command :certificate-status) (string= option "--warn-within"))
                (setf (getf options :warn-within)
                      (certificate-status-duration (option-value arguments option))
                      arguments (cddr arguments)))
               ((and (eq command :certificate-status) (string= option "--output"))
                (let ((value (option-value arguments option)))
                  (setf (getf options :output-format)
                        (cond ((string= value "table") :table)
                              ((string= value "json") :json)
                              (t (error "certificate status output must be table or json")))
                        arguments (cddr arguments))))
               ((and leaf-rotation-p (string= option "--service"))
                (let ((services (uiop:split-string (option-value arguments option) :separator ",")))
                  (unless (and services
                               (every (lambda (service)
                                        (member service '("api-server" "admin" "node-server"
                                                          "apiserver-kubelet-client" "raft-member")
                                                :test #'string=))
                                      services))
                    (error "certificate rotate service must be api-server, admin, node-server, apiserver-kubelet-client, or raft-member"))
                  (setf (getf options :services) (remove-duplicates services :test #'string=)
                        arguments (cddr arguments))))
               ((and leaf-rotation-p (string= option "--api-address"))
                (push (option-value arguments option) (getf options :api-addresses))
                (setf arguments (cddr arguments)))
               (t (error "unknown certificate option: ~A" option))))
      options)))

(defun certificate-kubeconfig-value (text field)
  (let ((value nil)
        (pattern (format nil "(?m)^[ \\t]+~A:[ \\t]+([^ \\t\\r\\n]+)[ \\t]*$"
                         (cl-ppcre:quote-meta-chars field))))
    (cl-ppcre:register-groups-bind (match) (pattern text) (setf value match))
    (or value (error "kubeconfig does not contain ~A" field))))

(defun read-pki-api-response-body (stream headers)
  "Read one non-streaming PKI API response body from STREAM."
  (let* ((length-text (cdr (assoc :content-length headers)))
         (length (and length-text (parse-integer length-text)))
         (body (make-array (or length 256) :element-type '(unsigned-byte 8)
                           :adjustable (null length) :fill-pointer (if length length 0))))
    (if length
        (loop with offset = 0
              while (< offset length)
              for next = (read-sequence body stream :start offset)
              do (when (= next offset) (error "PKI authority response body was truncated"))
                 (setf offset next))
        (loop for octet = (read-byte stream nil nil)
              while octet do (vector-push-extend octet body)))
    (trivial-utf-8:utf-8-bytes-to-string body)))

(defun pki-api-request (url ca certificate key &optional (redirects-left 3))
  "POST URL over verified mutual TLS, following only HTTPS redirects."
  (let* ((uri (puri:parse-uri url))
         (scheme (puri:uri-scheme uri))
         (host (puri:uri-host uri))
         (port (or (puri:uri-port uri) 443))
         (path (or (puri:uri-path uri) "/"))
         (target (format nil "~A~@[?~A~]" path (puri:uri-query uri)))
         (socket nil)
         (stream nil))
    (unless (and (eq scheme :https) host)
      (error "PKI authority endpoint must be an HTTPS URL: ~A" url))
    (unwind-protect
         (progn
           (setf socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                :timeout 15)
                 stream (pure-tls:make-tls-client-stream
                         (usocket:socket-stream socket)
                         :hostname host
                         :context (pure-tls:make-tls-context
                                   :verify-mode pure-tls:+verify-required+
                                   :ca-file (namestring ca) :auto-load-system-ca nil)
                         :verify pure-tls:+verify-required+
                         :client-certificate (namestring certificate)
                         :client-key (namestring key)))
           (write-sequence
            (gr8s.protocol::ascii-octets
             (format nil "POST ~A HTTP/1.1~C~CHost: ~A:~D~C~CAccept: application/json~C~CContent-Length: 0~C~CConnection: close~C~C~C~C"
                     target #\Return #\Linefeed host port #\Return #\Linefeed
                     #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed
                     #\Return #\Linefeed))
            stream)
           (force-output stream)
           (multiple-value-bind (status headers)
               (gr8s.protocol::parse-http-response-head
                (gr8s.protocol::read-http-response-head stream))
             (let ((body (read-pki-api-response-body stream headers))
                   (location (cdr (assoc :location headers))))
               (if (member status '(301 302 303 307 308))
                   (progn
                     (unless (and location (plusp redirects-left))
                       (error "PKI authority redirect could not be followed (HTTP ~D)" status))
                     (pki-api-request
                      (puri:render-uri (puri:merge-uris location uri) nil)
                      ca certificate key (1- redirects-left)))
                   (values body status)))))
      (when stream (ignore-errors (close stream)))
      (when socket (ignore-errors (usocket:socket-close socket))))))

(defun call-pki-authority-api (options kind stage)
  "Invoke one authenticated online PKI transition through the Kubernetes API."
  (let* ((text (uiop:read-file-string (getf options :kubeconfig)))
         (server (certificate-kubeconfig-value text "server"))
         (directory (uiop:ensure-directory-pathname
                     (sb-posix:mkdtemp
                      (namestring (merge-pathnames "gr8s-pki-client-XXXXXX"
                                                   (uiop:temporary-directory))))))
         (ca (merge-pathnames "ca.crt" directory))
         (certificate (merge-pathnames "client.crt" directory))
         (key (merge-pathnames "client.key" directory)))
    (unwind-protect
         (progn
           (write-private-text-atomically
            ca (trivial-utf-8:utf-8-bytes-to-string
                (ag-grpc:base64-decode
                 (certificate-kubeconfig-value text "certificate-authority-data"))))
           (write-private-text-atomically
            certificate (trivial-utf-8:utf-8-bytes-to-string
                         (ag-grpc:base64-decode
                          (certificate-kubeconfig-value text "client-certificate-data"))))
           (write-private-text-atomically
            key (trivial-utf-8:utf-8-bytes-to-string
                 (ag-grpc:base64-decode
                  (certificate-kubeconfig-value text "client-key-data"))))
           (multiple-value-bind (reply status)
               (pki-api-request
                (format nil "~A/apis/gr8s.io/v1/pkiauthorities/cluster/~A/~A"
                        (string-right-trim "/" server) kind stage)
                ca certificate key)
             (unless (= status 200)
               (error "PKI authority request failed (HTTP ~D): ~A" status reply))
             (write-line reply)
             0))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(defun run-certificate-rotation (options)
  "Rotate selected locally owned leaf credentials; the next process start loads them."
  (call-with-offline-state-ownership
   (getf options :state-directory)
   (lambda ()
     (let* ((root (uiop:ensure-directory-pathname (getf options :state-directory)))
            (pki-root (merge-pathnames "pki/" root))
            (pki (ensure-cluster-pki pki-root))
            (explicit-services (getf options :services))
            (services (or explicit-services
                          '("api-server" "admin" "node-server"
                            "apiserver-kubelet-client" "raft-member"))))
       (dolist (service services)
         (cond
           ((string= service "api-server")
            (ensure-kubernetes-api-credentials
             pki :addresses (nreverse (copy-list (getf options :api-addresses)))
             :renew-within most-positive-fixnum :rotate-key t))
           ((string= service "admin")
            (ensure-admin-client-credentials pki :renew-within most-positive-fixnum :rotate-key t))
           ((string= service "node-server")
            (ensure-node-server-credentials pki :renew-within most-positive-fixnum :rotate-key t))
           ((string= service "apiserver-kubelet-client")
            (gr8s.apiserver::ensure-apiserver-kubelet-client-credentials
             pki :renew-within most-positive-fixnum :rotate-key t))
           ((string= service "raft-member")
            (let* ((certificate-path
                     (gr8s.security::raft-member-certificate-path pki-root))
                   (key-path (gr8s.security::raft-member-key-path pki-root)))
              (unless (and (probe-file certificate-path) (probe-file key-path))
                (if explicit-services
                    (error "raft-member credentials do not exist in ~A" root)
                    (progn
                      (format t "skipped raft-member; no local Raft credential exists~%")
                      (return))))
              (let* ((leaf (first (pure-tls:load-certificate-chain certificate-path)))
                     (member-id (first (pure-tls:certificate-subject-common-names leaf)))
                     (temporary-key
                       (make-pathname :name ".member-rotation-new" :type "key"
                                      :defaults key-path)))
                (unwind-protect
                     (progn
                       (when (probe-file temporary-key) (delete-file temporary-key))
                       (let* ((csr (gr8s.security::generate-node-key-and-csr member-id temporary-key))
                              (new-key (uiop:read-file-string temporary-key))
                              (new-certificate
                                (gr8s.security::issue-raft-member-certificate pki member-id csr)))
                         (gr8s.apiserver::replace-leaf-key-pair
                          certificate-path key-path new-certificate new-key)))
                  (when (probe-file temporary-key) (delete-file temporary-key)))))))
         (format t "rotated ~A; restart gr8s processes using this credential~%" service))
       0))))

(defun certificate-pem (certificate)
  "Encode CERTIFICATE as one PEM block."
  (pure-tls/acme::wrap-pem
   "CERTIFICATE" (pure-tls::x509-certificate-raw-der certificate)))

(defun cluster-ca-transition-paths (state-directory)
  "Return the active, prepared and retiring CA paths for STATE-DIRECTORY."
  (let ((directory (merge-pathnames "pki/"
                                    (uiop:ensure-directory-pathname state-directory))))
    (values (merge-pathnames "cluster-ca.crt" directory)
            (merge-pathnames "cluster-ca.key" directory)
            (merge-pathnames "cluster-ca-next.crt" directory)
            (merge-pathnames "cluster-ca-next.key" directory)
            (merge-pathnames "cluster-ca-retiring.crt" directory)
            (merge-pathnames "cluster-ca-retiring.key" directory))))

(defun cluster-ca-transition-manifest-path (state-directory)
  (merge-pathnames "pki/cluster-ca-rotation.json"
                   (uiop:ensure-directory-pathname state-directory)))

(defun certificate-fingerprint-string (certificate)
  (octets-to-hex (pure-tls:certificate-fingerprint certificate)))

(defun read-cluster-ca-transition-manifest (state-directory)
  "Read and validate the durable CA transition state, or return NIL for legacy state."
  (let ((path (cluster-ca-transition-manifest-path state-directory)))
    (when (probe-file path)
      (let ((record (com.inuoe.jzon:parse path)))
        (unless (and (hash-table-p record)
                     (equal "gr8s-cluster-ca-rotation" (gethash "format" record))
                     (eql 1 (gethash "version" record))
                     (member (gethash "stage" record)
                             '("preparing" "prepared" "promoting" "promoted"
                               "finalizing" "idle") :test #'equal)
                     (stringp (gethash "activeFingerprint" record)))
          (error "Invalid cluster CA rotation manifest ~A" path))
        record))))

(defun write-cluster-ca-transition-manifest (state-directory stage active
                                               &key prepared retiring)
  "Atomically persist the CA transition intent before its corresponding file changes."
  (let ((record (gr8s.resources::core-object
                 "format" "gr8s-cluster-ca-rotation" "version" 1
                 "stage" stage "activeFingerprint" active)))
    (when prepared (setf (gethash "preparedFingerprint" record) prepared))
    (when retiring (setf (gethash "retiringFingerprint" record) retiring))
    (write-private-text-atomically
     (cluster-ca-transition-manifest-path state-directory)
     (com.inuoe.jzon:stringify record))
    record))

(defun cluster-ca-manifest-stage (manifest)
  (and manifest (gethash "stage" manifest)))

(defun prepare-cluster-ca-rotation (state-directory)
  "Generate a prepared CA and publish dual trust without changing the active signer."
  (let ((pki (ensure-cluster-pki state-directory))
        (manifest (read-cluster-ca-transition-manifest state-directory)))
    (multiple-value-bind (active-certificate active-key next-certificate next-key)
        (cluster-ca-transition-paths state-directory)
      (declare (ignore active-key))
      (when (member (cluster-ca-manifest-stage manifest)
                    '("prepared" "promoting" "promoted" "finalizing") :test #'equal)
        (error "cluster CA rotation is already at stage ~A"
               (cluster-ca-manifest-stage manifest)))
      (unless (and (probe-file next-certificate) (probe-file next-key))
        (when (or (probe-file next-certificate) (probe-file next-key))
          (error "incomplete prepared cluster CA credential pair"))
        (create-cluster-ca next-certificate next-key))
      (let* ((active (cluster-pki-ca-certificate pki))
             (active-fingerprint (certificate-fingerprint-string active))
             (next (first (pure-tls:load-certificate-chain next-certificate)))
             (next-fingerprint (certificate-fingerprint-string next)))
        (write-cluster-ca-transition-manifest
         state-directory "preparing" active-fingerprint :prepared next-fingerprint)
        (write-private-text-atomically
         active-certificate
         (concatenate 'string (certificate-pem active) (certificate-pem next)))
        (write-cluster-ca-transition-manifest
         state-directory "prepared" active-fingerprint :prepared next-fingerprint)
        active-fingerprint))))

(defun promote-cluster-ca-rotation (state-directory)
  "Make the prepared CA the active signer while retaining both trust anchors."
  (let ((pki (ensure-cluster-pki state-directory))
        (manifest (read-cluster-ca-transition-manifest state-directory)))
    (multiple-value-bind (active-certificate active-key next-certificate next-key
                          retiring-certificate retiring-key)
        (cluster-ca-transition-paths state-directory)
      (when (equal "promoted" (cluster-ca-manifest-stage manifest))
        (when (probe-file next-certificate) (delete-file next-certificate))
        (when (probe-file next-key) (delete-file next-key))
        (return-from promote-cluster-ca-rotation
          (certificate-fingerprint-string
           (first (pure-tls:load-certificate-chain active-certificate)))))
      (unless (member (cluster-ca-manifest-stage manifest) '("prepared" "promoting")
                      :test #'equal)
        (error "cluster CA rotation must be prepared before promotion"))
      (unless (and (probe-file next-certificate) (probe-file next-key))
        (error "prepared cluster CA credential pair is incomplete"))
      (let* ((old-certificate (if (probe-file retiring-certificate)
                                  (first (pure-tls:load-certificate-chain retiring-certificate))
                                  (cluster-pki-ca-certificate pki)))
             (old-certificate-pem (certificate-pem old-certificate))
             (old-key-pem (uiop:read-file-string
                           (if (probe-file retiring-key) retiring-key active-key)))
             (new-certificate (first (pure-tls:load-certificate-chain next-certificate)))
             (new-key-pem (uiop:read-file-string next-key))
             (old-fingerprint (certificate-fingerprint-string old-certificate))
             (new-fingerprint (certificate-fingerprint-string new-certificate)))
        (write-cluster-ca-transition-manifest
         state-directory "promoting" old-fingerprint
         :prepared new-fingerprint :retiring old-fingerprint)
        (write-private-text-atomically retiring-key old-key-pem)
        (write-private-text-atomically retiring-certificate old-certificate-pem)
        (write-private-text-atomically active-key new-key-pem)
        (write-private-text-atomically
         active-certificate
         (concatenate 'string (certificate-pem new-certificate) old-certificate-pem))
        (write-cluster-ca-transition-manifest
         state-directory "promoted" new-fingerprint :retiring old-fingerprint)
        (delete-file next-certificate)
        (delete-file next-key)
        new-fingerprint))))

(defun certificate-signed-by-p (path ca &key (purpose :client-auth))
  "True when PATH's leaf was signed directly by CA.
PURPOSE is retained for callers that distinguish client and server leaves; the
rotation guard only needs the cryptographic issuer relationship."
  (declare (ignore purpose))
  (handler-case
      (pure-tls::verify-certificate-signature
       (first (pure-tls:load-certificate-chain path)) ca)
    (error () nil)))

(defun retiring-ca-local-leaves (state-directory retiring-ca)
  "Return locally persisted leaves that still chain to RETIRING-CA."
  (let ((root (uiop:ensure-directory-pathname state-directory)))
    (loop for (name relative) in +local-certificate-paths+
          for path = (merge-pathnames relative root)
          when (and (not (member name '("cluster-ca" "agent-standalone-trust-anchor"
                                        "agent-trust-anchor" "front-proxy-ca") :test #'string=))
                    (probe-file path)
                    (or (certificate-signed-by-p path retiring-ca :purpose :client-auth)
                        (certificate-signed-by-p path retiring-ca :purpose :server-auth)))
            collect name)))

(defun finalize-cluster-ca-rotation (state-directory &key store-directory)
  "Discard retiring CA material only after local leaves and registered nodes renewed."
  (multiple-value-bind (active-certificate active-key next-certificate next-key
                        retiring-certificate retiring-key)
      (cluster-ca-transition-paths state-directory)
    (declare (ignore active-key next-certificate next-key))
    (let ((manifest (read-cluster-ca-transition-manifest state-directory)))
      (unless (member (cluster-ca-manifest-stage manifest) '("promoted" "finalizing")
                      :test #'equal)
        (error "cluster CA rotation must be promoted before finalization")))
    (unless (and (probe-file retiring-certificate) (probe-file retiring-key))
      (error "no promoted cluster CA transition exists"))
    (let* ((retiring (first (pure-tls:load-certificate-chain retiring-certificate)))
           (old-leaves (retiring-ca-local-leaves
                        (or store-directory state-directory) retiring)))
      (when old-leaves
        (error "refusing to finalize: credentials still use the retiring CA: ~{~A~^, ~}"
               old-leaves))
      (let* ((active (first (pure-tls:load-certificate-chain active-certificate)))
             (active-fingerprint (certificate-fingerprint-string active))
             (retiring-fingerprint (certificate-fingerprint-string retiring)))
        (let* ((store (open-store (or store-directory state-directory)))
               (stale-nodes
                 (loop for node in (list-nodes store)
                       unless (or (node-record-api-only node)
                                  (equal active-fingerprint
                                         (node-record-certificate-issuer-fingerprint node)))
                         collect (node-record-name node))))
          (when stale-nodes
            (error "refusing to finalize: nodes have not reconnected with active-CA credentials: ~{~A~^, ~}"
                   stale-nodes)))
        (write-cluster-ca-transition-manifest
         state-directory "finalizing" active-fingerprint :retiring retiring-fingerprint)
        (write-private-text-atomically active-certificate (certificate-pem active)))
      (delete-file retiring-certificate)
      (delete-file retiring-key)
      (let ((active (first (pure-tls:load-certificate-chain active-certificate))))
        (write-cluster-ca-transition-manifest
         state-directory "idle" (certificate-fingerprint-string active)))
      t)))

(defun run-cluster-ca-rotation (options)
  "Run one explicit cluster CA transition stage."
  (when (getf options :kubeconfig)
    (return-from run-cluster-ca-rotation
      (call-pki-authority-api
       options "ca"
       (ecase (getf options :command)
         (:certificate-ca-prepare "prepare")
         (:certificate-ca-promote "promote")
         (:certificate-ca-finalize "finalize")))))
  (call-with-offline-state-ownership
   (getf options :state-directory)
   (lambda ()
     (let* ((state-directory (uiop:ensure-directory-pathname
                              (getf options :state-directory)))
            (pki-directory (merge-pathnames "pki/" state-directory))
            (fingerprint
             (ecase (getf options :command)
               (:certificate-ca-prepare
                (prepare-cluster-ca-rotation pki-directory))
               (:certificate-ca-promote
                (promote-cluster-ca-rotation pki-directory))
               (:certificate-ca-finalize
                (finalize-cluster-ca-rotation
                 pki-directory :store-directory state-directory)))))
       (format t "~A~%" fingerprint)
       0))))

(defun certificate-status-stamp (universal-time)
  "Format UNIVERSAL-TIME as a deterministic UTC RFC3339 timestamp."
  (multiple-value-bind (second minute hour day month year)
      (decode-universal-time universal-time 0)
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ"
            year month day hour minute second)))

(defun load-bounded-certificate-chain (path)
  "Load a small, structurally valid certificate-only PEM chain from PATH."
  (let ((bytes (read-bounded-credential-file path)))
    (let ((blocks (gr8s.security::csr-pem-blocks bytes)))
      (unless (and blocks
                   (every (lambda (block)
                            (and (string= "CERTIFICATE" (car block))
                                 (gr8s.security::der-well-formed-p (cdr block))))
                          blocks))
        (error "expected a well-formed CERTIFICATE PEM chain")))
    (pure-tls:load-certificate-chain path)))

(defun read-bounded-credential-file (path &optional (limit (* 1024 1024)))
  "Read at most LIMIT octets from PATH, rejecting oversized or short reads."
  (with-open-file (stream path :direction :input :element-type '(unsigned-byte 8))
    (let ((length (file-length stream)))
      (when (> length limit)
        (error "credential file exceeds ~D bytes" limit))
      (let ((bytes (make-array length :element-type '(unsigned-byte 8))))
        (unless (= length (read-sequence bytes stream))
          (error "short credential read"))
        bytes))))

(defun certificate-record (name path now warn-within)
  "Return the inventory plist for certificate PATH without modifying it."
  (if (not (probe-file path))
      (list :name name :kind :certificate :path (namestring path) :severity :missing)
      (handler-case
          (let* ((chain (load-bounded-certificate-chain path))
                 (leaf (or (first chain) (error "empty certificate chain")))
                 (not-before (pure-tls:certificate-not-before leaf))
                 (not-after (pure-tls:certificate-not-after leaf))
                 (remaining (- not-after now))
                 (severity (cond ((< now not-before) :not-yet-valid)
                                 ((minusp remaining) :expired)
                                 ((<= remaining warn-within) :warning)
                                 (t :healthy))))
            (list :name name :kind :certificate :path (namestring path)
                  :severity severity :not-before not-before :not-after not-after
                  :remaining-seconds remaining
                  :fingerprint (octets-to-hex (pure-tls:certificate-fingerprint leaf))
                  :issuer-fingerprint
                  (octets-to-hex (pure-tls:certificate-fingerprint (or (second chain) leaf)))))
        (error (condition)
          (list :name name :kind :certificate :path (namestring path)
                :severity :invalid :error (princ-to-string condition))))))

(defun service-account-key-record (root)
  "Return the local ServiceAccount signing-key inventory record without generating a key."
  (let ((path (merge-pathnames "pki/service-account-signing-key.json" root)))
    (if (not (probe-file path))
        (list :name "service-account-signing-key" :kind :key
              :path (namestring path) :severity :missing)
        (handler-case
            (let* ((json (trivial-utf-8:utf-8-bytes-to-string
                          (read-bounded-credential-file path)))
                   (key (service-account-signing-key-from-record
                         (com.inuoe.jzon:parse json))))
              (list :name "service-account-signing-key" :kind :key
                    :path (namestring path) :severity :healthy
                    :fingerprint (service-account-key-id key)))
          (error (condition)
            (list :name "service-account-signing-key" :kind :key
                  :path (namestring path) :severity :invalid
                  :error (princ-to-string condition)))))))

(defun certificate-inventory (state-directory &key (now (get-universal-time))
                                                   (warn-within +certificate-warning-seconds+))
  "Return a deterministic read-only inventory of local cluster credentials."
  (let ((root (uiop:ensure-directory-pathname state-directory)))
    (append
     (loop for (name relative) in +local-certificate-paths+
           collect (certificate-record name (merge-pathnames relative root) now warn-within))
     (list (service-account-key-record root)))))

(defun certificate-record-json (record)
  "Convert one inventory plist into its stable public JSON object."
  (let ((object (core-object "name" (getf record :name)
                             "kind" (string-downcase (string (getf record :kind)))
                             "path" (getf record :path)
                             "severity" (string-downcase (string (getf record :severity))))))
    (dolist (field '((:not-before "notBefore") (:not-after "notAfter")))
      (when (getf record (first field))
        (setf (gethash (second field) object)
              (certificate-status-stamp (getf record (first field))))))
    (dolist (field '((:remaining-seconds "remainingSeconds")
                     (:fingerprint "fingerprint")
                     (:issuer-fingerprint "issuerFingerprint")
                     (:error "error")))
      (when (getf record (first field))
        (setf (gethash (second field) object) (getf record (first field)))))
    object))

(defun certificate-inventory-json (records)
  "Serialize RECORDS as deterministic machine-readable inventory JSON."
  (com.inuoe.jzon:stringify (coerce (mapcar #'certificate-record-json records) 'vector)))

(defun write-certificate-inventory-table (records &optional (stream *standard-output*))
  "Write a compact stable certificate inventory table to STREAM."
  (format stream "~28A  ~11A  ~20A  ~A~%" "NAME" "STATUS" "EXPIRES" "PATH")
  (dolist (record records)
    (format stream "~28A  ~11A  ~20A  ~A~%"
            (getf record :name)
            (string-downcase (string (getf record :severity)))
            (if (getf record :not-after)
                (certificate-status-stamp (getf record :not-after)) "-")
            (getf record :path))))

(defun run-certificate-status (options)
  "Print certificate status in the selected format and return warning-sensitive status."
  (let ((records (certificate-inventory (getf options :state-directory)
                                        :warn-within (getf options :warn-within))))
    (ecase (getf options :output-format)
      (:table (write-certificate-inventory-table records))
      (:json (write-line (certificate-inventory-json records))))
    (if (find-if (lambda (record)
                   (member (getf record :severity)
                           '(:warning :expired :not-yet-valid :invalid)))
                 records)
        1 0)))

(defun run-service-account-signing-key-rotation (options)
  "Run one staged signing-key transition and print the resulting active or prepared key id."
  (when (getf options :kubeconfig)
    (return-from run-service-account-signing-key-rotation
      (call-pki-authority-api
       options "service-account-key"
       (ecase (getf options :command)
         (:certificate-service-account-key-prepare "prepare")
         (:certificate-service-account-key-promote "promote")
         (:certificate-service-account-key-finalize "finalize")))))
  (let* ((store (open-store (getf options :state-directory)))
         (kid (ecase (getf options :command)
                (:certificate-service-account-key-prepare
                 (prepare-service-account-signing-key-rotation store))
                (:certificate-service-account-key-promote
                 (promote-service-account-signing-key-rotation store))
                (:certificate-service-account-key-finalize
                 (finalize-service-account-signing-key-rotation store)))))
    (format t "~A~%" kid)
    0))

(defun pki-authority-status-json (store)
  "Return the non-secret operator view of the replicated PKI authority record."
  (let ((envelope (gr8s.resources::current-pki-authority-envelope store))
        (manifest (read-cluster-ca-transition-manifest
                   (merge-pathnames "pki/" (pod-store-path store)))))
    (core-object
     "replicated" (if envelope t nil)
     "keyId" (and envelope (gethash "keyId" envelope))
     "caStage" (or (cluster-ca-manifest-stage manifest) "legacy"))))

(defun update-replicated-pki-authority (store kind stage)
  "Apply one leader-routed PKI transition and commit its encrypted authority record."
  (let ((envelope (gr8s.resources::current-pki-authority-envelope store)))
    (unless envelope (error "HA PKI authority has not been initialized"))
    (let ((previous (gr8s.resources::decrypt-pki-authority-material store envelope)))
      (gr8s.resources::install-pki-authority-material store previous)
      (handler-case
          (progn
            (let ((pki-directory (merge-pathnames "pki/" (pod-store-path store))))
              (cond
              ((equal kind "ca")
               (ecase stage
                 (:prepare (prepare-cluster-ca-rotation pki-directory))
                 (:promote (promote-cluster-ca-rotation pki-directory))
                 (:finalize (finalize-cluster-ca-rotation
                             pki-directory :store-directory (pod-store-path store)))))
              ((equal kind "service-account-key")
               (ecase stage
                 (:prepare (prepare-service-account-signing-key-rotation store))
                 (:promote (promote-service-account-signing-key-rotation store))
                 (:finalize (finalize-service-account-signing-key-rotation store))))
              (t (error "Unknown replicated PKI authority kind ~A" kind))))
            (gr8s.resources::publish-pki-authority store)
            (pki-authority-status-json store))
        (error (condition)
          (gr8s.resources::install-pki-authority-material store previous)
          (when (equal kind "service-account-key")
            (load-service-account-signing-key store))
          (error condition))))))

(defun serve-pki-authority-request (store path method)
  "Serve the authenticated leader-routed PKI management endpoint."
  (setf (hunchentoot:content-type*) "application/json")
  (cond
    ((and (equal path "/apis/gr8s.io/v1/pkiauthorities/cluster") (eq method :get))
     (com.inuoe.jzon:stringify (pki-authority-status-json store)))
    ((eq method :post)
     (let ((pattern "^/apis/gr8s[.]io/v1/pkiauthorities/cluster/(ca|service-account-key)/(prepare|promote|finalize)$"))
       (if (cl-ppcre:scan pattern path)
           (cl-ppcre:register-groups-bind (kind action) (pattern path)
             (com.inuoe.jzon:stringify
              (update-replicated-pki-authority
               store kind (intern (string-upcase action) :keyword))))
           (core-resource-error 404 "NotFound" "Unknown PKI authority operation"))))
    (t (core-resource-error 405 "MethodNotAllowed" "Unsupported PKI authority operation"))))
