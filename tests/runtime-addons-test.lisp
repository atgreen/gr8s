;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise runtime-addon discovery: a valid, checksum-matching addon becomes
;;;; an extra CRI runtime handler, while a checksum mismatch, a missing
;;;; descriptor, and a path-traversal binary are each skipped without aborting.

(in-package #:gr8s/tests)

(in-suite gr8s)

(defun write-runtime-addon (root name json &key (binary-name "shim") (binary-bytes #(1 2 3 4)))
  "Create ROOT/runtime-addons/NAME/ with BINARY-NAME and an addon.json whose
   body is JSON (a function of the binary's actual sha512 hex). Returns the
   addon directory."
  (let* ((addon (merge-pathnames (format nil "runtime-addons/~A/" name)
                                 (uiop:ensure-directory-pathname root)))
         (binary (merge-pathnames binary-name addon)))
    (ensure-directories-exist addon)
    (with-open-file (stream binary :direction :output :element-type '(unsigned-byte 8)
                                   :if-exists :supersede :if-does-not-exist :create)
      (write-sequence binary-bytes stream))
    (with-open-file (stream (merge-pathnames "addon.json" addon)
                            :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-string (funcall json (gr8s::runtime-addon-file-sha512 binary)) stream))
    addon))

(test runtime-addons-load-verifies-checksums-and-rejects-bad-addons
  (let ((root (merge-pathnames (format nil "gr8s-addons-~36R/" (random (expt 36 8)))
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           ;; Absent directory: no addons, no error.
           (is (null (gr8s::load-installed-runtime-addons root)))

           ;; A valid, checksum-matching addon becomes a runtime handler.
           (write-runtime-addon
            root "runsc"
            (lambda (sha)
              (format nil "{\"name\":\"runsc\",\"runtimeType\":\"io.containerd.runsc.v1\",~
                           \"binaries\":[{\"path\":\"shim\",\"sha512\":\"~A\"}]}" sha)))
           (let ((handlers (gr8s::load-installed-runtime-addons root)))
             (is (= 1 (length handlers)))
             (is (string= "runsc" (getf (first handlers) :name)))
             (is (string= "io.containerd.runsc.v1" (getf (first handlers) :runtime-type)))
             (is (null (getf (first handlers) :options))))

           ;; A checksum mismatch is skipped; the good addon still loads.
           (let ((addon (merge-pathnames "runtime-addons/bad/" root)))
             (ensure-directories-exist addon)
             (with-open-file (s (merge-pathnames "shim" addon) :direction :output
                                :element-type '(unsigned-byte 8) :if-exists :supersede)
               (write-sequence #(9 9 9) s))
             (with-open-file (s (merge-pathnames "addon.json" addon) :direction :output
                                :if-exists :supersede)
               (write-string "{\"name\":\"bad\",\"runtimeType\":\"io.containerd.bad.v1\",\"binaries\":[{\"path\":\"shim\",\"sha512\":\"00deadbeef\"}]}" s)))
           ;; A path-traversal binary reference never reads outside the addon dir.
           (let ((addon (merge-pathnames "runtime-addons/evil/" root)))
             (ensure-directories-exist addon)
             (with-open-file (s (merge-pathnames "addon.json" addon) :direction :output
                                :if-exists :supersede)
               (write-string "{\"name\":\"evil\",\"runtimeType\":\"io.containerd.evil.v1\",\"binaries\":[{\"path\":\"../../../../etc/hostname\",\"sha512\":\"00\"}]}" s)))

           (handler-bind ((warning #'muffle-warning))
             (let ((names (mapcar (lambda (h) (getf h :name))
                                  (gr8s::load-installed-runtime-addons root))))
               (is (member "runsc" names :test #'string=))
               (is (not (member "bad" names :test #'string=)))
               (is (not (member "evil" names :test #'string=))))))
      (uiop:delete-directory-tree (uiop:ensure-directory-pathname root)
                                  :validate t :if-does-not-exist :ignore))))

(defun write-addon-file (addon relative bytes)
  "Write BYTES into ADDON/RELATIVE; return its sha512 hex."
  (let ((file (merge-pathnames relative addon)))
    (ensure-directories-exist file)
    (with-open-file (stream file :direction :output :element-type '(unsigned-byte 8)
                                 :if-exists :supersede :if-does-not-exist :create)
      (write-sequence bytes stream))
    (gr8s::runtime-addon-file-sha512 file)))

(test runtime-addons-verify-non-binary-assets
  "A microVM runtime ships data files (guest kernel, rootfs/initrd,
   configuration.toml) that are not executables but must still be tamper-checked
   on every startup. The descriptor's optional \"assets\" list is verified just
   like \"binaries\": a mismatched or missing asset skips the whole addon even
   when every binary checksum is good."
  (let ((root (merge-pathnames (format nil "gr8s-addon-assets-~36R/" (random (expt 36 8)))
                               (uiop:temporary-directory))))
    (unwind-protect
         (flet ((addon (name) (merge-pathnames (format nil "runtime-addons/~A/" name) root))
                (descriptor (dir name shim-sha kernel-sha)
                  (with-open-file (s (merge-pathnames "addon.json" dir) :direction :output
                                     :if-exists :supersede :if-does-not-exist :create)
                    (write-string
                     (format nil "{\"name\":\"~A\",\"runtimeType\":\"io.containerd.kata.v2\",~
                                  \"binaries\":[{\"path\":\"shim\",\"sha512\":\"~A\"}],~
                                  \"assets\":[{\"path\":\"share/kernel\",\"sha512\":\"~A\"}]}"
                             name shim-sha kernel-sha)
                     s))))
           ;; Good binary + good asset: addon loads.
           (let* ((dir (addon "kata"))
                  (shim-sha (write-addon-file dir "shim" #(1 2 3 4)))
                  (kernel-sha (write-addon-file dir "share/kernel" #(9 8 7 6 5))))
             (descriptor dir "kata" shim-sha kernel-sha)
             (let ((handlers (gr8s::load-installed-runtime-addons root)))
               (is (member "kata" (mapcar (lambda (h) (getf h :name)) handlers) :test #'string=))))

           ;; Good binary but TAMPERED asset: whole addon skipped.
           (let* ((dir (addon "kata-bad-asset"))
                  (shim-sha (write-addon-file dir "shim" #(1 2 3 4))))
             (write-addon-file dir "share/kernel" #(9 8 7 6 5))
             ;; Declare a kernel sha that does not match the bytes on disk.
             (descriptor dir "kata-bad-asset" shim-sha "00deadbeef"))

           ;; Good binary but MISSING asset file: whole addon skipped.
           (let* ((dir (addon "kata-missing-asset"))
                  (shim-sha (write-addon-file dir "shim" #(1 2 3 4))))
             (descriptor dir "kata-missing-asset" shim-sha
                         "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"))

           (handler-bind ((warning #'muffle-warning))
             (let ((names (mapcar (lambda (h) (getf h :name))
                                  (gr8s::load-installed-runtime-addons root))))
               (is (member "kata" names :test #'string=))
               (is (not (member "kata-bad-asset" names :test #'string=)))
               (is (not (member "kata-missing-asset" names :test #'string=))))))
      (uiop:delete-directory-tree (uiop:ensure-directory-pathname root)
                                  :validate t :if-does-not-exist :ignore))))

(test runtime-addons-carry-containerd-runtime-options
  "A microVM runtime (e.g. Kata) needs per-handler containerd options such as
   ConfigPath. The descriptor's optional \"options\" map is rendered into a
   deterministic alist of (KEY . TOML-SCALAR) by JSON type; a non-scalar value
   or an unquotable string skips the addon rather than emitting broken TOML."
  (let ((root (merge-pathnames (format nil "gr8s-addon-opts-~36R/" (random (expt 36 8)))
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           ;; String, boolean, and integer options render as TOML scalars,
           ;; sorted by key for stable config output.
           (write-runtime-addon
            root "kata"
            (lambda (sha)
              (format nil "{\"name\":\"kata\",\"runtimeType\":\"io.containerd.kata.v2\",~
                           \"binaries\":[{\"path\":\"shim\",\"sha512\":\"~A\"}],~
                           \"options\":{\"ConfigPath\":\"/opt/kata/configuration.toml\",~
                                        \"Debug\":true,\"Retries\":3,\"SystemdCgroup\":false}}"
                      sha)))
           (let* ((handlers (gr8s::load-installed-runtime-addons root))
                  (kata (find "kata" handlers :key (lambda (h) (getf h :name)) :test #'string=)))
             (is (not (null kata)))
             (is (string= "io.containerd.kata.v2" (getf kata :runtime-type)))
             (is (equal '(("ConfigPath" . "'/opt/kata/configuration.toml'")
                          ("Debug" . "true")
                          ("Retries" . "3")
                          ("SystemdCgroup" . "false"))
                        (getf kata :options))))

           ;; A nested-object option value is not a TOML scalar: skip the addon.
           (let ((addon (merge-pathnames "runtime-addons/nested/" root)))
             (ensure-directories-exist addon)
             (with-open-file (s (merge-pathnames "addon.json" addon) :direction :output
                                :if-exists :supersede)
               (write-string "{\"name\":\"nested\",\"runtimeType\":\"io.containerd.nested.v2\",\"binaries\":[],\"options\":{\"K\":{\"a\":1}}}" s)))
           ;; A single quote in a string option cannot be a TOML literal: skip.
           (let ((addon (merge-pathnames "runtime-addons/quote/" root)))
             (ensure-directories-exist addon)
             (with-open-file (s (merge-pathnames "addon.json" addon) :direction :output
                                :if-exists :supersede)
               (write-string "{\"name\":\"quote\",\"runtimeType\":\"io.containerd.quote.v2\",\"binaries\":[],\"options\":{\"ConfigPath\":\"/it's/bad.toml\"}}" s)))

           (handler-bind ((warning #'muffle-warning))
             (let ((names (mapcar (lambda (h) (getf h :name))
                                  (gr8s::load-installed-runtime-addons root))))
               (is (member "kata" names :test #'string=))
               (is (not (member "nested" names :test #'string=)))
               (is (not (member "quote" names :test #'string=))))))
      (uiop:delete-directory-tree (uiop:ensure-directory-pathname root)
                                  :validate t :if-does-not-exist :ignore))))
