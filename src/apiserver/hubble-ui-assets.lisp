;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Bake Hubble UI's built frontend into the gr8s image (podster-e9a.6), as
;;;; dashboard-assets.lisp bakes Headlamp's: the files under assets/hubble-ui/
;;;; (`make hubble-ui-assets') are read at compile and load time, so a dumped
;;;; binary serves the dashboard's Hubble tab with no files on disk. Without the directory
;;;; the table is empty and the command says so.

(in-package #:gr8s.apiserver)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defvar *hubble-ui-assets* (make-hash-table :test 'equal)
    "Map of a Hubble UI asset's relative path to its bytes, gzip-compressed for the
paths in *HUBBLE-UI-ASSET-ENCODINGS*.")
  (defvar *hubble-ui-asset-encodings* (make-hash-table :test 'equal)
    "Map of a Hubble UI asset's logical path to \"gzip\" when its bytes are stored compressed."))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (labels ((read-file-bytes (path)
             (with-open-file (in path :element-type '(unsigned-byte 8))
               (let ((bytes (make-array (file-length in) :element-type '(unsigned-byte 8))))
                 (read-sequence bytes in)
                 bytes)))
           (collect (root directory)
             (dolist (file (uiop:directory-files directory))
               (let ((name (enough-namestring file root)))
                 (if (uiop:string-suffix-p name ".gz")
                     (let ((logical (subseq name 0 (- (length name) 3))))
                       (setf (gethash logical *hubble-ui-assets*) (read-file-bytes file)
                             (gethash logical *hubble-ui-asset-encodings*) "gzip"))
                     (setf (gethash name *hubble-ui-assets*) (read-file-bytes file)))))
             (dolist (sub (uiop:subdirectories directory))
               (collect root sub))))
    (let ((root (merge-pathnames "assets/hubble-ui/" (asdf:system-source-directory :gr8s))))
      (when (uiop:directory-exists-p root)
        (collect root root)))))

(defun hubble-ui-assets-present-p ()
  "True when a Hubble UI frontend build is embedded in this image."
  (plusp (hash-table-count *hubble-ui-assets*)))

(defun hubble-ui-asset-response (relative base)
  "Serve the embedded asset RELATIVE, or the app's index.html for a path it isn't, as
its own router expects. index.html's <base> becomes BASE, the path the UI is served
under, so its relative asset and API URLs resolve there."
  (let* ((known (gethash relative *hubble-ui-assets*))
         (name (if known relative "index.html"))
         (bytes (gethash name *hubble-ui-assets*)))
    (setf (hunchentoot:content-type*) (dashboard-content-type name))
    (if (equal name "index.html")
        (progn
          (setf (hunchentoot:header-out :cache-control) "no-store")
          (trivial-utf-8:string-to-utf-8-bytes
           (cl-ppcre:regex-replace "<base href=[^>]*>" (trivial-utf-8:utf-8-bytes-to-string bytes)
                                   (format nil "<base href=\"~A\">" base))))
        (let ((encoding (gethash name *hubble-ui-asset-encodings*)))
          (cond ((null encoding) bytes)
                ((search encoding (string-downcase (or (hunchentoot:header-in* :accept-encoding) "")))
                 (setf (hunchentoot:header-out :content-encoding) encoding)
                 bytes)
                (t (chipz:decompress nil 'chipz:gzip bytes)))))))
