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
         (runtime (gr8s.runtime.containerd:make-containerd-runtime
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
