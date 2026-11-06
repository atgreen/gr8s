;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Unit coverage for the native runtime installer's pure helpers: URL parsing,
;;;; the /opt/kata path rewrite, tar path-safety, and the addon.json descriptor
;;;; round-tripping back through the engine's loader. The heavy paths (libzstd
;;;; decompression, tar extraction, HTTPS download) are exercised against real
;;;; release bundles out of band.

(in-package #:gr8s/tests)

(in-suite gr8s)

(test runtime-install-parse-https-url
  (multiple-value-bind (host port path) (gr8s::parse-https-url "https://example.com/a/b.tar")
    (is (string= "example.com" host))
    (is (= 443 port))
    (is (string= "/a/b.tar" path)))
  (multiple-value-bind (host port path) (gr8s::parse-https-url "https://h.test:8443/p?x=1&y=2")
    (is (string= "h.test" host))
    (is (= 8443 port))
    (is (string= "/p?x=1&y=2" path)))
  (multiple-value-bind (host port path) (gr8s::parse-https-url "https://h.test")
    (declare (ignore port path))
    (is (string= "h.test" host)))
  ;; http:// (or anything non-https) is refused.
  (signals error (gr8s::parse-https-url "http://example.com/x")))

(test runtime-install-string-replace-all
  (is (string= "/P/x and /P/y"
               (gr8s::string-replace-all "/opt/kata" "/P" "/opt/kata/x and /opt/kata/y")))
  (is (string= "unchanged" (gr8s::string-replace-all "/opt/kata" "/P" "unchanged")))
  (is (string= "" (gr8s::string-replace-all "x" "y" ""))))

(test runtime-install-tar-path-safety
  (let ((dest (merge-pathnames "gr8s-tar-safe/" (uiop:temporary-directory))))
    ;; A normal nested path resolves under the destination.
    (is (uiop:subpathp (gr8s::tar-safe-path "opt/kata/bin/runsc" dest)
                       (uiop:ensure-directory-pathname dest)))
    ;; The archive's own "./" root maps to the destination itself.
    (is (equal (uiop:ensure-directory-pathname dest)
               (uiop:ensure-directory-pathname (gr8s::tar-safe-path "./" dest))))
    ;; Traversal and absolute entries are refused.
    (signals gr8s::tar-error (gr8s::tar-safe-path "../escape" dest))
    (signals gr8s::tar-error (gr8s::tar-safe-path "a/../../escape" dest))
    (signals gr8s::tar-error (gr8s::tar-safe-path "/etc/passwd" dest))))

(test runtime-install-descriptor-round-trips-through-loader
  "write-addon-descriptor must emit an addon.json the engine's load-runtime-addon
   accepts, with options surfacing as containerd TOML scalars."
  (let ((addon (merge-pathnames (format nil "gr8s-desc-~36R/" (random (expt 36 8)))
                                (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (ensure-directories-exist addon)
           (with-open-file (stream (merge-pathnames "shim" addon)
                                   :direction :output :element-type '(unsigned-byte 8)
                                   :if-exists :supersede :if-does-not-exist :create)
             (write-sequence #(7 8 9) stream))
           (gr8s::write-addon-descriptor
            addon
            :name "demo" :runtime-type "io.containerd.demo.v2" :runtime-class "demo"
            :binaries '("shim")
            :options (list (cons "ConfigPath" "/etc/demo/config.toml")))
           (let ((handler (gr8s::load-runtime-addon addon)))
             (is (not (null handler)))
             (is (string= "io.containerd.demo.v2" (getf handler :runtime-type)))
             ;; A JSON string option renders to a single-quoted TOML literal.
             (is (equal '(("ConfigPath" . "'/etc/demo/config.toml'"))
                        (getf handler :options)))))
      (uiop:delete-directory-tree (uiop:ensure-directory-pathname addon)
                                  :validate t :if-does-not-exist :ignore))))
