;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Third-party notices for `gr8s notices`. The native build (build-native.lisp)
;;;; gzip-compresses the NOTICES document -- produced by `make notices`
;;;; (scripts/collect-notices.sh: gr8s's own NOTICE, the embedded/linked native
;;;; components, and ocicl's collection of every vendored Common Lisp
;;;; dependency's license) -- and bakes it into the image here, so the full
;;;; attribution travels inside the single binary. A dev image reads the plain
;;;; NOTICES file from the tree root instead.

(in-package #:gr8s)

(defvar *embedded-notices-gz* nil
  "The gzip-compressed NOTICES document, set by build-native.lisp for the native
   image; NIL in a dev image.")

(defun notices-text ()
  "The third-party NOTICES document: the embedded gzip when present, otherwise
   the plain NOTICES file at the gr8s tree root, otherwise NIL."
  (cond
    (*embedded-notices-gz*
     (trivial-utf-8:utf-8-bytes-to-string
      (chipz:decompress nil 'chipz:gzip *embedded-notices-gz*)))
    (t
     (let ((file (merge-pathnames "NOTICES" (gr8s-root-directory))))
       (when (probe-file file)
         (uiop:read-file-string file))))))

(defun print-notices ()
  "Print the collected third-party copyright and license notices."
  (let ((text (notices-text)))
    (if (and text (plusp (length text)))
        (write-string text)
        (format t "No notices are bundled in this build.~%~
                   Run `make notices` to generate the NOTICES document.~%"))))
