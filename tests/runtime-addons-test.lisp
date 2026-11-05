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
