;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Bake the built Headlamp frontend into the gr8s image.
;;;;
;;;; The static assets under assets/dashboard/ (a Headlamp frontend build) are
;;;; read at compile and load time into *dashboard-assets*, so a dumped gr8s
;;;; binary serves the dashboard with no files on disk and no configuration --
;;;; the single-binary story. When the directory is absent (a build without the
;;;; vendored assets) the table is simply empty and the dashboard stays off.

(in-package #:gr8s.apiserver)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defvar *dashboard-assets* (make-hash-table :test 'equal)
    "Map of a dashboard asset's relative path (e.g. \"index.html\",
\"static/js/main.js\") to its contents as a byte vector."))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (labels ((read-file-bytes (path)
             (with-open-file (in path :element-type '(unsigned-byte 8))
               (let ((bytes (make-array (file-length in) :element-type '(unsigned-byte 8))))
                 (read-sequence bytes in)
                 bytes)))
           (collect (root directory)
             (dolist (file (uiop:directory-files directory))
               (setf (gethash (enough-namestring file root) *dashboard-assets*)
                     (read-file-bytes file)))
             (dolist (sub (uiop:subdirectories directory))
               (collect root sub))))
    (let ((root (merge-pathnames "assets/dashboard/"
                                 (asdf:system-source-directory :gr8s))))
      ;; Populate (idempotently) only when the vendored build is present; never
      ;; clear, so a dumped image keeps the assets baked in at build time.
      (when (uiop:directory-exists-p root)
        (collect root root)))))

(defparameter +dashboard-content-types+
  '(("html" . "text/html; charset=utf-8")
    ("js" . "text/javascript; charset=utf-8")
    ("mjs" . "text/javascript; charset=utf-8")
    ("css" . "text/css; charset=utf-8")
    ("json" . "application/json")
    ("map" . "application/json")
    ("svg" . "image/svg+xml")
    ("png" . "image/png")
    ("jpg" . "image/jpeg")
    ("jpeg" . "image/jpeg")
    ("gif" . "image/gif")
    ("ico" . "image/x-icon")
    ("webp" . "image/webp")
    ("woff" . "font/woff")
    ("woff2" . "font/woff2")
    ("ttf" . "font/ttf")
    ("txt" . "text/plain; charset=utf-8")
    ("wasm" . "application/wasm"))
  "Content types for dashboard assets, keyed by lowercased filename extension.")

(defun dashboard-content-type (relative)
  "Return the HTTP content type for the dashboard asset named RELATIVE."
  (let* ((dot (position #\. relative :from-end t))
         (extension (and dot (string-downcase (subseq relative (1+ dot))))))
    (or (cdr (assoc extension +dashboard-content-types+ :test #'equal))
        "application/octet-stream")))

(defun dashboard-assets-present-p ()
  "True when a Headlamp frontend build is embedded in this image."
  (plusp (hash-table-count *dashboard-assets*)))
