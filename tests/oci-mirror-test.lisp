;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)

(test strict-containerd-registry-hosts-have-no-direct-origin-fallback
  (let ((text (gr8s.image-distribution::containerd-registry-hosts-text
               "registry.example:5443" 18443)))
    (is (search "server = \"http://127.0.0.1:18443\"" text))
    (is-false (search "server = \"https://registry.example:5443\"" text))
    (is (search "[host.\"http://127.0.0.1:18443\"]" text))
    (is (search "capabilities = [\"pull\", \"resolve\"]" text))
    (is (search "X-Gr8s-Upstream = [\"registry.example:5443\"]" text))))

(test image-pull-prepares-the-exact-containerd-registry-namespace
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-hosts-~36R/" (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (runtime (gr8s.runtime.containerd::make-containerd-runtime
                   :registry-host-config-directory directory
                   :image-mirror-port 18443)))
    (unwind-protect
         (progn
           (gr8s.kubelet::prepare-image-mirror-host runtime "alpine:3.22")
           (let* ((path (merge-pathnames "docker.io/hosts.toml" directory))
                  (text (uiop:read-file-string path)))
             (is (probe-file path))
             (is (search "X-Gr8s-Upstream = [\"registry-1.docker.io\"]" text))
             (is-false (search "https://registry-1.docker.io" text))))
      (uiop:delete-directory-tree directory :validate t
                                            :if-does-not-exist :ignore))))

(test strict-cold-start-takes-one-origin-lease-before-publishing-a-seed
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-strict-origin-~36R/"
                             (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (cache (gr8s.image-distribution::make-oci-blob-cache directory))
         (bytes (bt-octets "strict origin"))
         (digest (format nil "sha256:~A"
                         (ironclad:byte-array-to-hex-string
                          (ironclad:digest-sequence :sha256 bytes))))
         (actions nil) (published nil))
    (unwind-protect
         (let ((path
                 (gr8s.image-distribution::ensure-strict-p2p-blob
                  cache digest
                  (lambda (action requested-digest &rest arguments)
                    (declare (ignore arguments))
                    (push (list action requested-digest) actions)
                    (ecase action
                      (:lookup '(:status :missing))
                      (:acquire '(:status :granted :token #(1 2 3)))
                      (:renew '(:status :ok))))
                  (lambda (temporary requested-digest metainfo peers)
                    (declare (ignore temporary requested-digest metainfo peers)) nil)
                  (lambda (temporary)
                    (with-open-file (stream temporary :direction :output
                                                      :if-does-not-exist :create
                                                      :element-type '(unsigned-byte 8))
                      (write-sequence bytes stream))
                    t)
                  (lambda (verified-path torrent token)
                    (setf published (list verified-path torrent token)))
                  :piece-length 16384 :renewal-interval 60)))
           (is (equal path (first published)))
           (is (typep (second published)
                      'gr8s.image-distribution::blob-torrent))
           (is (equalp #(1 2 3) (third published)))
           (is (equal '(:lookup :acquire) (mapcar #'first (reverse actions)))))
      (uiop:delete-directory-tree directory :validate t
                                            :if-does-not-exist :ignore))))

(test strict-unreachable-peer-falls-back-to-origin
  ;; The tracker advertises a peer this node cannot reach (e.g. a cross-node
  ;; peer whose port a host firewall drops). Peer fetching must not fail the
  ;; pull: after a bounded number of attempts the origin registry serves it, and
  ;; the lease-less fallback announces (NIL token) rather than claiming the seed.
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-strict-fallback-~36R/"
                             (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (cache (gr8s.image-distribution::make-oci-blob-cache directory))
         (bytes (bt-octets "fallback body"))
         (digest (format nil "sha256:~A"
                         (ironclad:byte-array-to-hex-string
                          (ironclad:digest-sequence :sha256 bytes))))
         (peer-attempts 0) (origin-calls 0) (published nil))
    (unwind-protect
         (let ((path
                 (gr8s.image-distribution::ensure-strict-p2p-blob
                  cache digest
                  ;; Always advertises a peer and never grants a lease: the only
                  ;; routes to the blob are peer-fetch (which fails) or fallback.
                  (lambda (action requested-digest &rest arguments)
                    (declare (ignore requested-digest arguments))
                    (ecase action
                      (:lookup '(:status :available))
                      (:acquire '(:status :available))
                      ((:announce :publish :renew) '(:status :ok))))
                  ;; An unreachable peer: every fetch signals.
                  (lambda (temporary requested-digest metainfo peers)
                    (declare (ignore temporary requested-digest metainfo peers))
                    (incf peer-attempts)
                    (error "simulated unreachable peer"))
                  ;; The origin registry can serve it.
                  (lambda (temporary)
                    (incf origin-calls)
                    (with-open-file (stream temporary :direction :output
                                                      :if-does-not-exist :create
                                                      :element-type '(unsigned-byte 8))
                      (write-sequence bytes stream))
                    t)
                  (lambda (verified-path torrent token)
                    (setf published (list verified-path torrent token)))
                  :piece-length 16384 :wait-interval 0.0 :max-peer-attempts 2)))
           (is (equal path (first published)))
           (is (gr8s.image-distribution::verified-oci-blob-p path digest))
           (is (<= 1 peer-attempts))
           (is (= 1 origin-calls))
           (is (null (third published))))
      (uiop:delete-directory-tree directory :validate t
                                            :if-does-not-exist :ignore))))

(test loopback-oci-mirror-serves-only-a-verified-leased-blob
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-http-mirror-~36R/"
                             (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (bytes (bt-octets "from registry once"))
         (digest (format nil "sha256:~A"
                         (ironclad:byte-array-to-hex-string
                          (ironclad:digest-sequence :sha256 bytes))))
         (origin-calls 0) (origin-request nil) (published nil)
         (mirror
           (gr8s.image-distribution::make-oci-mirror
            directory
            (lambda (action requested-digest &rest arguments)
              (declare (ignore requested-digest arguments))
              (ecase action
                (:lookup '(:status :missing))
                (:acquire '(:status :granted :token #(9 8 7)))
                (:renew '(:status :ok))))
            (lambda (&rest ignored) (declare (ignore ignored)) nil)
            (lambda (temporary host repository requested-digest headers)
              (declare (ignore headers))
              (setf origin-request (list host repository requested-digest))
              (incf origin-calls)
              (with-open-file (stream temporary :direction :output
                                                :if-does-not-exist :create
                                                :element-type '(unsigned-byte 8))
                (write-sequence bytes stream))
              t)
            (lambda (path torrent token)
              (setf published (list path torrent token)))
            (lambda (&rest ignored)
              (declare (ignore ignored))
              (values #() 500 nil)))))
    (unwind-protect
         (let* ((port (gr8s.image-distribution::start-oci-mirror mirror))
                (body (drakma:http-request
                       (format nil "http://127.0.0.1:~D/v2/team/image/blobs/~A"
                               port digest)
                       :additional-headers
                       '(("X-Gr8s-Upstream" . "registry.example"))
                       :force-binary t :proxy nil)))
           (is (equalp bytes body))
           (is (= 1 origin-calls))
           (is (equal (list "registry.example" "team/image" digest)
                      origin-request))
           (is (equalp #(9 8 7) (third published))))
      (gr8s.image-distribution::stop-oci-mirror mirror)
      (uiop:delete-directory-tree directory :validate t
                                            :if-does-not-exist :ignore))))

(test loopback-oci-mirror-accepts-a-textual-upstream-content-length
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-http-proxy-~36R/"
                             (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (body (bt-octets "manifest"))
         (mirror
           (gr8s.image-distribution::make-oci-mirror
            directory
            (lambda (&rest ignored) (declare (ignore ignored)))
            (lambda (&rest ignored) (declare (ignore ignored)))
            (lambda (&rest ignored) (declare (ignore ignored)))
            (lambda (&rest ignored) (declare (ignore ignored)))
            (lambda (&rest ignored)
              (declare (ignore ignored))
              (values body 401
                      `((:content-type . "application/json")
                        (:content-length . ,(princ-to-string (length body)))
                        (:www-authenticate . "Bearer realm=\"https://auth.example/token\"")))))))
    (unwind-protect
         (let ((port (gr8s.image-distribution::start-oci-mirror mirror)))
           (multiple-value-bind (response status response-headers)
               (drakma:http-request
                (format nil "http://127.0.0.1:~D/v2/team/image/manifests/latest" port)
                :additional-headers '(("X-Gr8s-Upstream" . "registry.example"))
                :force-binary t :proxy nil)
             (is (= 401 status))
             (is (equalp body response))
             (is (string= (princ-to-string (length body))
                          (cdr (assoc :content-length response-headers))))))
      (gr8s.image-distribution::stop-oci-mirror mirror)
      (uiop:delete-directory-tree directory :validate t
                                            :if-does-not-exist :ignore))))

;;; Upstream registry TLS: the mirror verifies every registry it fetches from,
;;; against the system roots or a --registry-ca for that host (podster-sqb).

(defun registry-tls-test-leaf (pki directory name &key dns-names ip-addresses)
  "Write a server leaf for DNS-NAMES/IP-ADDRESSES signed by PKI's CA into
DIRECTORY; return the certificate and key paths."
  (multiple-value-bind (subject signer issuer)
      (gr8s.controllers::cm-issuer-signer pki (gr8s.resources::core-object "ca" (gr8s.resources::core-object)))
    (multiple-value-bind (certificate key)
        (gr8s.controllers::cm-issue-leaf :dns-names dns-names :ip-addresses ip-addresses
                                         :duration-seconds 3600 :issuer-subject-der subject
                                         :signer-key signer :issuer-certificate issuer)
      (let ((certificate-path (merge-pathnames (format nil "~A.crt" name) directory))
            (key-path (merge-pathnames (format nil "~A.key" name) directory)))
        (alexandria:write-string-into-file certificate certificate-path :if-exists :supersede)
        (alexandria:write-string-into-file key key-path :if-exists :supersede)
        (values (namestring certificate-path) (namestring key-path))))))

(defun registry-tls-test-backend (certificate key respond &key (address "127.0.0.1"))
  "A TLS server on ADDRESS presenting CERTIFICATE. RESPOND maps a request path
to (values status headers body-string). Returns (values port stop-fn)."
  (let* ((listener (usocket:socket-listen address 0 :reuse-address t
                                                         :element-type '(unsigned-byte 8)))
         (stopping nil))
    (flet ((serve (raw)
             (ignore-errors
              (let* ((tls (pure-tls:make-tls-server-stream (usocket:socket-stream raw)
                                                           :certificate certificate :key key))
                     (request-line (gr8s.apiserver::admission-read-line tls))
                     (path (second (uiop:split-string request-line :separator " "))))
                (loop until (zerop (length (gr8s.apiserver::admission-read-line tls))))
                (multiple-value-bind (status headers body) (funcall respond path)
                  (let ((octets (trivial-utf-8:string-to-utf-8-bytes (or body ""))))
                    (write-sequence
                     (trivial-utf-8:string-to-utf-8-bytes
                      (format nil "HTTP/1.1 ~D X~C~C~:{~A: ~A~C~C~}Content-Length: ~D~C~CConnection: close~C~C~C~C"
                              status #\Return #\Linefeed
                              (loop for (name . value) in headers collect (list name value #\Return #\Linefeed))
                              (length octets) #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))
                     tls)
                    (write-sequence octets tls)
                    (force-output tls)))))
             (ignore-errors (usocket:socket-close raw))))
      (let ((thread (bt:make-thread
                     (lambda ()
                       (loop until stopping
                             do (when (usocket:wait-for-input listener :timeout 0.2 :ready-only t)
                                  (handler-case
                                      (let ((raw (usocket:socket-accept listener)))
                                        (bt:make-thread (lambda () (serve raw)) :name "registry tls test conn"))
                                    (error () nil)))))
                     :name "registry tls test accept")))
        (values (usocket:get-local-port listener)
                (lambda ()
                  (setf stopping t)
                  (ignore-errors (bt:join-thread thread))
                  (ignore-errors (usocket:socket-close listener))))))))

(defmacro with-registry-tls-test-pkis ((directory &rest pkis) &body body)
  `(let ((,directory (merge-pathnames (format nil "gr8s-registry-tls-~36R/" (random (expt 36 10)))
                                      (uiop:temporary-directory))))
     (ensure-directories-exist ,directory)
     (unwind-protect
          (let* (,@(loop for pki in pkis
                         collect `(,pki (gr8s.security::ensure-cluster-pki
                                         (merge-pathnames ,(format nil "~(~A~)/" pki) ,directory))))
                 (gr8s.image-distribution::*registry-ca-files* '()))
            ,@body)
       (uiop:delete-directory-tree ,directory :validate t :if-does-not-exist :ignore))))

(defun registry-tls-test-ca (pki)
  (namestring (gr8s.security::cluster-pki-ca-certificate-path pki)))

(defmacro with-full-tls-handshakes (&body body)
  "Run BODY with an empty TLS session-ticket cache. pure-tls keys client tickets
by hostname alone and these in-process test servers share one ticket key, so a
ticket from an earlier verified 127.0.0.1 server would otherwise resume -- and
skip certificate verification -- against the next one."
  `(let ((pure-tls::*session-ticket-cache* (make-hash-table :test 'equal)))
     ,@body))

(test oci-mirror-verifies-the-registry-certificate
  (with-registry-tls-test-pkis (directory pki)
    (multiple-value-bind (certificate key)
        (registry-tls-test-leaf pki directory "ip" :ip-addresses '("127.0.0.1"))
      (multiple-value-bind (port stop)
          (registry-tls-test-backend certificate key (lambda (path) (declare (ignore path)) (values 200 nil "{}")))
        (unwind-protect
             (let ((host (format nil "127.0.0.1:~D" port)))
               (flet ((proxy () (with-full-tls-handshakes
                                 (gr8s.image-distribution::proxy-oci-registry-request :get host "/v2/" nil))))
                 ;; A CA the system roots don't know: refused, not silently trusted.
                 (signals error (proxy))
                 ;; The same registry with its CA configured verifies and answers.
                 (let ((gr8s.image-distribution::*registry-ca-files*
                         (list (cons host (registry-tls-test-ca pki)))))
                   (is (= 200 (nth-value 1 (proxy)))))))
          (funcall stop))))
    ;; A trusted CA does not excuse a certificate that doesn't name the address.
    (multiple-value-bind (certificate key)
        (registry-tls-test-leaf pki directory "dns" :dns-names '("registry.example"))
      (multiple-value-bind (port stop)
          (registry-tls-test-backend certificate key (lambda (path) (declare (ignore path)) (values 200 nil "{}")))
        (unwind-protect
             (let* ((host (format nil "127.0.0.1:~D" port))
                    (gr8s.image-distribution::*registry-ca-files*
                      (list (cons host (registry-tls-test-ca pki)))))
               (signals error (with-full-tls-handshakes
                               (gr8s.image-distribution::proxy-oci-registry-request :get host "/v2/" nil))))
          (funcall stop))))))

(test oci-mirror-verifies-each-blob-redirect-hop-against-its-own-host
  ;; The CDN is another host (127.0.0.2), as a real blob redirect target is.
  (with-registry-tls-test-pkis (directory registry-pki cdn-pki)
    (multiple-value-bind (cdn-certificate cdn-key)
        (registry-tls-test-leaf cdn-pki directory "cdn" :ip-addresses '("127.0.0.2"))
      (multiple-value-bind (cdn-port stop-cdn)
          (registry-tls-test-backend cdn-certificate cdn-key
                                     (lambda (path) (declare (ignore path)) (values 200 nil "blob bytes"))
                                     :address "127.0.0.2")
        (multiple-value-bind (registry-certificate registry-key)
            (registry-tls-test-leaf registry-pki directory "registry" :ip-addresses '("127.0.0.1"))
          (let ((redirect-to (format nil "https://127.0.0.2:~D/blob" cdn-port)))
            (multiple-value-bind (registry-port stop-registry)
                (registry-tls-test-backend registry-certificate registry-key
                                           (lambda (path)
                                             (values 307 (list (cons "Location" (if (search "plain" path)
                                                                                    "http://127.0.0.1:1/blob"
                                                                                    redirect-to)))
                                                     "")))
              (unwind-protect
                   (let ((registry (format nil "127.0.0.1:~D" registry-port))
                         (cdn (format nil "127.0.0.2:~D" cdn-port))
                         (target (merge-pathnames "blob" directory)))
                     (flet ((fetch (repository)
                              (with-full-tls-handshakes
                                (gr8s.image-distribution::fetch-oci-registry-blob
                                 target registry repository "sha256:00" nil))))
                       ;; Only the registry's CA configured: the CDN hop is held to
                       ;; the system roots, not to the registry's private CA.
                       (let ((gr8s.image-distribution::*registry-ca-files*
                               (list (cons registry (registry-tls-test-ca registry-pki)))))
                         (signals error (fetch "library/app")))
                       ;; Each host verified against its own CA: the blob arrives.
                       (let ((gr8s.image-distribution::*registry-ca-files*
                               (list (cons registry (registry-tls-test-ca registry-pki))
                                     (cons cdn (registry-tls-test-ca cdn-pki)))))
                         (is (fetch "library/app"))
                         (is (equal "blob bytes" (alexandria:read-file-into-string target)))
                         ;; A redirect off https is refused outright.
                         (signals error (fetch "plain/app")))))
                (funcall stop-registry)
                (funcall stop-cdn)))))))))

(test registry-ca-option-scopes-a-ca-to-one-registry
  (let ((ca (namestring (merge-pathnames "registry-ca-option.pem" (uiop:temporary-directory)))))
    (alexandria:write-string-into-file "x" ca :if-exists :supersede)
    (unwind-protect
         (let ((cas (gr8s.server::add-registry-ca
                     (gr8s.server::add-registry-ca '() "10.77.77.21:30500")
                     (format nil "registry.example=~A" ca))))
           (is (equal (list (cons "10.77.77.21:30500" :cluster) (cons "registry.example" ca)) cas))
           (signals error (gr8s.server::add-registry-ca cas "registry.example"))
           (signals error (gr8s.server::add-registry-ca '() "bad host"))
           (signals error (gr8s.server::add-registry-ca '() "r.example=relative.pem"))
           (signals error (gr8s.server::add-registry-ca '() "r.example=/nonexistent/ca.pem"))
           (let ((gr8s.image-distribution::*registry-ca-files* (list (cons "registry.example:443" ca))))
             (is (equal (list :verify :required :ca-file ca)
                        (gr8s.image-distribution::registry-tls-arguments "registry.example")))
             (is (equal (list :verify :required)
                        (gr8s.image-distribution::registry-tls-arguments "other.example")))))
      (ignore-errors (delete-file ca)))))
