;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The RE2-syntax regular expression engine now lives in the standalone cl-re2
;;;; library (installed via ocicl); gr8s.resources imports its public API in
;;;; package.lisp.  All that remains here is the gr8s-specific memoization layer
;;;; that remembers the handful of patterns CRD and CEL validation read over and
;;;; over, so a program is compiled once per distinct pattern.

(in-package #:gr8s.resources)

(defvar *re2-compiled* (make-hash-table :test #'equal :synchronized t)
  "Patterns already compiled, as validation reads the same few over and over.")

(defun re2-compiled (pattern)
  "Return PATTERN's program, remembering it."
  (or (gethash pattern *re2-compiled*)
      (progn
        (when (> (hash-table-count *re2-compiled*) 4096) (clrhash *re2-compiled*))
        (setf (gethash pattern *re2-compiled*) (re2-compile pattern)))))
