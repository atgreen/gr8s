;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; In-process installation of optional runtime addons (gVisor, Kata) for the
;;;; `gr8s runtime install` CLI. Everything is native to the image: drakma
;;;; downloads over HTTPS, ironclad verifies checksums, the libzstd binding
;;;; (zstd.lisp) decompresses, and the tar extractor (tar.lisp) unpacks -- no
;;;; curl/zstd/tar subprocesses. The result is a checksum-pinned addon under
;;;; <state>/runtime-addons/<name>/ with the addon.json that
;;;; load-installed-runtime-addons verifies at startup. Core runtimes
;;;; (containerd, runc, CNI) stay embedded; this is only for optional add-ons.

(in-package #:gr8s)

(define-condition runtime-install-error (error)
  ((message :initarg :message :reader runtime-install-error-message))
  (:report (lambda (condition stream)
             (format stream "~A" (runtime-install-error-message condition)))))

(defun runtime-install-error (format-control &rest arguments)
  (error 'runtime-install-error :message (apply #'format nil format-control arguments)))

(defun runtime-machine-arch ()
  "The current machine as a keyword, :amd64 or :arm64; error on anything else."
  (let ((machine (string-upcase (machine-type))))
    (cond ((or (search "X86-64" machine) (search "X86_64" machine) (search "AMD64" machine)) :amd64)
          ((or (search "ARM64" machine) (search "AARCH64" machine)) :arm64)
          (t (runtime-install-error "unsupported architecture: ~A" (machine-type))))))

(defun runtime-file-sha256 (path)
  "Lowercase hex SHA-256 of PATH's contents."
  (ironclad:byte-array-to-hex-string (ironclad:digest-file :sha256 path)))

;;; A minimal HTTPS GET built on gr8s's own pure-tls (not cl+ssl/OpenSSL),
;;; mirroring the outbound-webhook client in admission-webhooks.lisp: usocket +
;;; make-tls-client-stream with the system CA roots. Enough to fetch a release
;;; asset -- status line, headers, redirects, and a Content-Length or chunked
;;; body streamed to disk in bounded memory.

(defun parse-https-url (url)
  "Return (values HOST PORT PATH) for an https:// URL; signal otherwise."
  (unless (uiop:string-prefix-p "https://" url)
    (runtime-install-error "only https downloads are supported: ~A" url))
  (let* ((rest (subseq url (length "https://")))
         (slash (or (position #\/ rest) (length rest)))
         (authority (subseq rest 0 slash))
         (path (if (< slash (length rest)) (subseq rest slash) "/"))
         (colon (position #\: authority)))
    (values (if colon (subseq authority 0 colon) authority)
            (if colon (parse-integer (subseq authority (1+ colon))) 443)
            path)))

(defun http-read-crlf-line (stream)
  "Read one CRLF-terminated line from STREAM as an ASCII string (CR/LF stripped)."
  (let ((bytes (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for byte = (read-byte stream nil :eof)
          until (or (eq byte :eof) (= byte 10))
          unless (= byte 13) do (vector-push-extend byte bytes))
    (map 'string #'code-char bytes)))

(defun http-read-headers (stream)
  "Read response headers up to the blank line; alist of (lowercased-name . value)."
  (loop for line = (http-read-crlf-line stream)
        until (zerop (length line))
        for colon = (position #\: line)
        when colon
          collect (cons (string-downcase (string-trim " " (subseq line 0 colon)))
                        (string-trim '(#\Space #\Tab) (subseq line (1+ colon))))))

(defun http-copy-n (stream out n)
  "Copy exactly N body octets from STREAM to OUT."
  (let ((buffer (make-array (min (max n 1) 1048576) :element-type '(unsigned-byte 8)))
        (remaining n))
    (loop while (plusp remaining) do
      (let* ((want (min (length buffer) remaining))
             (got (read-sequence buffer stream :end want)))
        (when (zerop got) (runtime-install-error "unexpected EOF reading HTTP body"))
        (write-sequence buffer out :end got)
        (decf remaining got)))))

(defun http-stream-body-to-file (stream headers destination)
  "Stream the response body (chunked, Content-Length, or read-to-close) to DESTINATION."
  (ensure-directories-exist destination)
  (with-open-file (out destination :direction :output :element-type '(unsigned-byte 8)
                                   :if-exists :supersede :if-does-not-exist :create)
    (let ((encoding (cdr (assoc "transfer-encoding" headers :test #'string=)))
          (length (cdr (assoc "content-length" headers :test #'string=))))
      (cond
        ((and encoding (search "chunked" (string-downcase encoding)))
         (loop for size = (parse-integer (http-read-crlf-line stream) :radix 16 :junk-allowed t)
               while (and size (plusp size))
               do (http-copy-n stream out size)
                  (http-read-crlf-line stream))) ; CRLF trailing each chunk
        (length
         (http-copy-n stream out (parse-integer length)))
        (t ; no framing: read until the server closes (Connection: close)
         (let ((buffer (make-array 1048576 :element-type '(unsigned-byte 8))))
           (loop for n = (read-sequence buffer stream)
                 while (plusp n) do (write-sequence buffer out :end n))))))))

(defun runtime-download-file (url destination &key (what "file") (max-redirects 10))
  "GET URL over pure-tls, following redirects, streaming the body to DESTINATION."
  (format t "  downloading ~A~%" what)
  (finish-output)
  (let ((current url)
        (crlf (coerce (list #\Return #\Linefeed) 'string)))
    (dotimes (attempt (1+ max-redirects)
                      (runtime-install-error "too many redirects for ~A" url))
      (multiple-value-bind (host port path) (parse-https-url current)
        (let ((socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                         :nodelay t)))
          (unwind-protect
               (let* ((context (pure-tls:make-tls-context :verify-mode pure-tls:+verify-required+
                                                          :auto-load-system-ca t))
                      (stream (pure-tls:make-tls-client-stream (usocket:socket-stream socket)
                                                               :hostname host :context context
                                                               :verify pure-tls:+verify-required+)))
                 (write-sequence
                  (trivial-utf-8:string-to-utf-8-bytes
                   (concatenate 'string
                                "GET " path " HTTP/1.1" crlf
                                "Host: " host crlf
                                "User-Agent: gr8s/" +gr8s-version+ crlf
                                "Accept: */*" crlf
                                "Connection: close" crlf
                                crlf))
                  stream)
                 (force-output stream)
                 (let* ((status-line (http-read-crlf-line stream))
                        (space (position #\Space status-line))
                        (status (and space (parse-integer status-line :start (1+ space)
                                                                       :junk-allowed t)))
                        (headers (http-read-headers stream)))
                   (cond
                     ((and (member status '(301 302 303 307 308))
                           (cdr (assoc "location" headers :test #'string=)))
                      (let ((location (cdr (assoc "location" headers :test #'string=))))
                        (setf current (if (uiop:string-prefix-p "http" location)
                                          location
                                          (format nil "https://~A~A" host location)))))
                     ((eql status 200)
                      (http-stream-body-to-file stream headers destination)
                      (return-from runtime-download-file destination))
                     (t (runtime-install-error "download of ~A failed: HTTP ~A"
                                               current (or status status-line))))))
            (ignore-errors (usocket:socket-close socket))))))))

(defun runtime-unpack-zstd-tarball (zst-path destination)
  "Decompress ZST-PATH (a .tar.zst) and extract the tar into DESTINATION. The
   intermediate tar is written beside ZST-PATH (on disk, not a RAM-backed tmp)
   and removed afterwards. Returns the number of entries extracted."
  (let ((tar (make-pathname :type "tar" :defaults zst-path)))
    (unwind-protect
         (progn
           (format t "  decompressing + extracting~%")
           (finish-output)
           (zstd-decompress-file zst-path tar)
           (extract-tar-file tar destination))
      (ignore-errors (delete-file tar)))))

(defun runtime-descriptor-file-entry (addon-directory relative-path)
  "A {\"path\",\"sha512\"} descriptor entry for RELATIVE-PATH under ADDON-DIRECTORY."
  (let ((entry (make-hash-table :test 'equal)))
    (setf (gethash "path" entry) relative-path
          (gethash "sha512" entry)
          (runtime-addon-file-sha512 (merge-pathnames relative-path addon-directory)))
    entry))

(defun write-addon-descriptor (addon-directory &key name runtime-type runtime-class
                                                     binaries assets options)
  "Write <ADDON-DIRECTORY>/addon.json. BINARIES and ASSETS are lists of
   addon-relative paths (each checksummed here); OPTIONS is an alist of
   (containerd-option-key . value). The JSON is produced through jzon, so it is
   always well-formed and round-trips through parse-runtime-addon-descriptor."
  (let ((root (make-hash-table :test 'equal)))
    (setf (gethash "name" root) name
          (gethash "runtimeType" root) runtime-type
          (gethash "runtimeClass" root) (or runtime-class name)
          (gethash "binaries" root)
          (map 'vector (lambda (p) (runtime-descriptor-file-entry addon-directory p)) binaries))
    (when assets
      (setf (gethash "assets" root)
            (map 'vector (lambda (p) (runtime-descriptor-file-entry addon-directory p)) assets)))
    (when options
      (let ((table (make-hash-table :test 'equal)))
        (loop for (key . value) in options do (setf (gethash key table) value))
        (setf (gethash "options" root) table)))
    (with-open-file (out (merge-pathnames "addon.json" addon-directory)
                         :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-string (com.inuoe.jzon:stringify root :pretty t) out)
      (terpri out))))

(defun runtime-install-temp-directory (state-directory)
  "A scratch directory for downloads/extraction, kept OUTSIDE runtime-addons/ so
   a transient or interrupted install never looks like an installed addon."
  (merge-pathnames ".runtime-install-tmp/"
                   (uiop:ensure-directory-pathname state-directory)))

(defun runtime-fresh-addon-directory (state-directory name)
  "Return a freshly emptied <state>/runtime-addons/<name>/ directory."
  (let ((addon (merge-pathnames (format nil "~A/" name)
                                (runtime-addons-directory state-directory))))
    (uiop:delete-directory-tree (uiop:ensure-directory-pathname addon)
                                :validate (constantly t) :if-does-not-exist :ignore)
    (ensure-directories-exist addon)
    addon))

;;; ---------------------------------------------------------------------------
;;; gVisor (runsc) -- a shim-only sandbox; the bundle unpacks flat.
;;; ---------------------------------------------------------------------------

(defun install-gvisor-runtime (state-directory &key (release "latest"))
  (let* ((arch (ecase (runtime-machine-arch) (:amd64 "x86_64") (:arm64 "aarch64")))
         (base (format nil "https://storage.googleapis.com/gvisor/releases/release/~A/~A"
                       release arch))
         (temporary (runtime-install-temp-directory state-directory))
         (bundle (merge-pathnames "gvisor.tar.zstd" temporary))
         (checksum (merge-pathnames "gvisor.tar.zstd.sha512" temporary)))
    (ensure-directories-exist temporary)
    (unwind-protect
         (progn
           (runtime-download-file (format nil "~A/gvisor.tar.zstd" base) bundle
                                  :what (format nil "gVisor (~A, ~A)" release arch))
           (runtime-download-file (format nil "~A/gvisor.tar.zstd.sha512" base) checksum
                                  :what "gVisor checksum")
           ;; gVisor publishes "<sha512>  gvisor.tar.zstd"; compare the hex.
           (let ((expected (first (uiop:split-string (uiop:read-file-string checksum)
                                                     :separator '(#\Space #\Tab #\Newline))))
                 (actual (runtime-addon-file-sha512 bundle)))
             (unless (string-equal expected actual)
               (runtime-install-error "gVisor SHA-512 mismatch~%  expected ~A~%  actual   ~A"
                                      expected actual)))
           (format t "  SHA-512 verified~%")
           (let ((addon (runtime-fresh-addon-directory state-directory "gvisor")))
             (runtime-unpack-zstd-tarball bundle addon)
             (dolist (binary '("runsc" "containerd-shim-runsc-v1"))
               (let ((path (merge-pathnames binary addon)))
                 (unless (probe-file path)
                   (runtime-install-error "gVisor bundle missing ~A" binary))
                 (sb-posix:chmod (namestring path) #o755)))
             (write-addon-descriptor addon
                                     :name "runsc"
                                     :runtime-type "io.containerd.runsc.v1"
                                     :runtime-class "gvisor"
                                     :binaries '("containerd-shim-runsc-v1" "runsc"))
             (values addon "gvisor")))
      (ignore-errors (uiop:delete-directory-tree (uiop:ensure-directory-pathname temporary)
                                                 :validate (constantly t)
                                                 :if-does-not-exist :ignore)))))

;;; ---------------------------------------------------------------------------
;;; Kata Containers -- a microVM runtime; the bundle unpacks under opt/kata and
;;; carries absolute /opt/kata paths that must be relocated.
;;; ---------------------------------------------------------------------------

(defparameter +kata-configuration-names+
  '(("qemu"       . "runtime-rs/configuration-qemu-runtime-rs.toml")
    ("clh"        . "runtime-rs/configuration-clh-runtime-rs.toml")
    ("fc"         . "runtime-rs/configuration-rs-fc.toml")
    ("dragonball" . "runtime-rs/configuration-dragonball.toml"))
  "Kata 4.x runtime-rs config, relative to share/defaults/kata-containers, per
   hypervisor choice.")

(defun string-replace-all (old new string)
  "Every non-overlapping OLD in STRING replaced by NEW (plain text, no regex)."
  (with-output-to-string (out)
    (loop with start = 0
          for position = (search old string :start2 start)
          while position do
            (write-string string out :start start :end position)
            (write-string new out)
            (setf start (+ position (length old)))
          finally (write-string string out :start start))))

(defun symlink-target (path)
  "The target of PATH if it is a symbolic link, else NIL (also NIL if absent)."
  (handler-case (sb-posix:readlink (namestring path)) (error () nil)))

(defun path-exists-p (path)
  "True if PATH exists, whether or not it is a dangling symlink."
  (handler-case (progn (sb-posix:lstat (namestring path)) t) (error () nil)))

(defun kata-rewrite-config-paths (defaults-directory prefix)
  "Rewrite the compiled-in /opt/kata paths in every real configuration .toml
   under DEFAULTS-DIRECTORY to PREFIX. Symlinked configs are skipped so the
   rewrite follows them to their (already-rewritten) target rather than
   replacing the link with a regular file."
  (dolist (config (directory (merge-pathnames "**/configuration*.toml" defaults-directory)))
    (when (and (probe-file config)
               (not (uiop:directory-pathname-p config))
               (not (symlink-target config)))
      (let ((text (uiop:read-file-string config)))
        (with-open-file (out config :direction :output :if-exists :supersede
                                    :if-does-not-exist :create)
          (write-string (string-replace-all "/opt/kata" prefix text) out))))))

(defun kata-config-value (config-path key)
  "The first `KEY = \"VALUE\"` string value in CONFIG-PATH, or NIL."
  (let ((scanner (cl-ppcre:create-scanner
                  (format nil "(?m)^[ \\t]*~A[ \\t]*=[ \\t]*\"([^\"]*)\"" key))))
    (multiple-value-bind (start end starts ends)
        (cl-ppcre:scan scanner (uiop:read-file-string config-path))
      (declare (ignore end))
      (when start (subseq (uiop:read-file-string config-path) (aref starts 0) (aref ends 0))))))

(defun install-kata-runtime (state-directory &key (version "4.3.1") (hypervisor "qemu") sha256
                                                  bundle-path)
  (let ((config-relative (cdr (assoc hypervisor +kata-configuration-names+ :test #'string=))))
    (unless config-relative
      (runtime-install-error "unsupported kata hypervisor: ~A" hypervisor))
    (let* ((arch (ecase (runtime-machine-arch) (:amd64 "amd64") (:arm64 "arm64")))
           (bundle-name (format nil "kata-static-~A-~A.tar.zst" version arch))
           (url (format nil "https://github.com/kata-containers/kata-containers/releases/download/~A/~A"
                        version bundle-name))
           (temporary (runtime-install-temp-directory state-directory))
           (bundle (if bundle-path (pathname bundle-path) (merge-pathnames bundle-name temporary))))
      (unless bundle-path (ensure-directories-exist temporary))
      (unwind-protect
           (progn
             (unless bundle-path
               (runtime-download-file url bundle :what (format nil "Kata ~A (~A, ~~1GB)" version arch)))
             (let ((actual (runtime-file-sha256 bundle)))
               (unless sha256
                 (runtime-install-error
                  "no --sha256 pinned (trust-on-first-use).~%  downloaded ~A sha256 = ~A~%  verify it, then re-run with --sha256 ~A"
                  bundle-name actual actual))
               (unless (string-equal actual sha256)
                 (runtime-install-error "Kata SHA-256 mismatch~%  expected ~A~%  actual   ~A"
                                        sha256 actual)))
             (format t "  SHA-256 verified~%")
             (let* ((addon (runtime-fresh-addon-directory state-directory "kata"))
                    (prefix (merge-pathnames "opt/kata/" addon))
                    (prefix-string (string-right-trim "/" (namestring prefix)))
                    (defaults (merge-pathnames "share/defaults/kata-containers/" prefix)))
               (runtime-unpack-zstd-tarball bundle addon)
               (unless (uiop:directory-exists-p prefix)
                 (runtime-install-error "Kata bundle did not contain opt/kata"))
               (kata-rewrite-config-paths defaults prefix-string)
               (let* ((config-path (merge-pathnames config-relative defaults))
                      (shim (merge-pathnames "runtime-rs/bin/containerd-shim-kata-v2" prefix)))
                 (unless (probe-file config-path)
                   (runtime-install-error "Kata bundle missing ~A" config-relative))
                 (unless (probe-file shim)
                   (runtime-install-error "Kata bundle missing runtime-rs/bin/containerd-shim-kata-v2"))
                 (sb-posix:chmod (namestring shim) #o755)
                 ;; containerd execs the shim by name off the addon-root PATH.
                 (let ((shim-link (merge-pathnames "containerd-shim-kata-v2" addon)))
                   (ignore-errors (sb-posix:unlink (namestring shim-link)))
                   (sb-posix:symlink "opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
                                     (namestring shim-link)))
                 ;; Re-verify the kernel and rootfs the chosen config actually boots.
                 (let* ((kernel (kata-config-value config-path "kernel"))
                        (image (kata-config-value config-path "image"))
                        (initrd (kata-config-value config-path "initrd"))
                        (assets (list (format nil "opt/kata/share/defaults/kata-containers/~A"
                                              config-relative))))
                   (dolist (absolute (list kernel image initrd))
                     (when (and absolute (probe-file absolute))
                       (push (enough-namestring (truename absolute) (truename addon)) assets)))
                   (write-addon-descriptor
                    addon
                    :name "kata"
                    :runtime-type "io.containerd.kata.v2"
                    :runtime-class "kata"
                    :binaries '("containerd-shim-kata-v2")
                    :assets (nreverse assets)
                    :options (list (cons "ConfigPath" (namestring config-path)))))
                 (kata-link-opt-kata prefix)
                 (values addon "kata"))))
        (unless bundle-path
          (ignore-errors (uiop:delete-directory-tree (uiop:ensure-directory-pathname temporary)
                                                     :validate (constantly t)
                                                     :if-does-not-exist :ignore)))))))

(defun kata-link-opt-kata (prefix)
  "Point /opt/kata at PREFIX unless something else owns it. kata-static's qemu
   has a compiled-in firmware search path under /opt/kata that is not expressible
   in config, so the bundle must be reachable there -- hence one kata addon per
   host."
  (let* ((prefix-string (string-right-trim "/" (namestring prefix)))
         (target (symlink-target "/opt/kata")))
    (cond
      ((and (path-exists-p "/opt/kata") (null target))
       (format t "  WARNING /opt/kata exists and is not a symlink; left as is~%"))
      ((and target (not (string= (string-right-trim "/" target) prefix-string)))
       (format t "  WARNING /opt/kata points elsewhere (~A); left as is~%" target))
      (t
       (ignore-errors (sb-posix:unlink "/opt/kata"))
       (sb-posix:symlink prefix-string "/opt/kata")
       (format t "  linked /opt/kata -> ~A~%" prefix-string)))))

;;; ---------------------------------------------------------------------------
;;; Dispatch + listing
;;; ---------------------------------------------------------------------------

(defun install-runtime (name state-directory &key version hypervisor sha256 bundle-path release)
  "Install the optional runtime NAME (\"gvisor\" or \"kata\") under STATE-DIRECTORY."
  (format t "Installing ~A runtime into ~A~%" name (namestring (uiop:ensure-directory-pathname state-directory)))
  (multiple-value-bind (addon runtime-class)
      (cond
        ((string= name "gvisor")
         (install-gvisor-runtime state-directory :release (or release version "latest")))
        ((string= name "kata")
         (install-kata-runtime state-directory
                               :version (or version "4.3.1")
                               :hypervisor (or hypervisor "qemu")
                               :sha256 sha256
                               :bundle-path bundle-path))
        (t (runtime-install-error "unknown runtime: ~A (choose gvisor or kata)" name)))
    (format t "~&Staged ~A addon at ~A~%" name (namestring addon))
    (format t "Restart gr8s, then create a RuntimeClass with handler '~A'.~%" runtime-class)
    addon))

(defun print-runtime-list (state-directory)
  "List embedded runtime assets and installed optional runtime addons."
  (format t "Embedded runtime assets:~%")
  (if *embedded-runtime-assets*
      (dolist (asset *embedded-runtime-assets*)
        (format t "  ~20A ~:D bytes~%" (runtime-asset-name asset)
                (length (runtime-asset-octets asset))))
      (format t "  (external -- not embedded in this build)~%"))
  (format t "~%Installed runtime addons (~A):~%"
          (namestring (runtime-addons-directory state-directory)))
  (let ((root (runtime-addons-directory state-directory))
        (found nil))
    (when (uiop:directory-exists-p root)
      (dolist (directory (sort (uiop:subdirectories root) #'string< :key #'namestring))
        ;; Only directories that carry an addon.json are addons; ignore anything
        ;; else that happens to sit under runtime-addons/.
        (when (probe-file (merge-pathnames "addon.json" directory))
          (let ((name (car (last (pathname-directory directory))))
                (handler (handler-case (load-runtime-addon directory) (error () nil))))
            (setf found t)
            (if handler
                (format t "  ~20A verified   ~A~%" name (getf handler :runtime-type))
                (format t "  ~20A UNVERIFIED (checksum/descriptor problem)~%" name))))))
    (unless found
      (format t "  (none)~%"))))
