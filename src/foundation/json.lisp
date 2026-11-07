;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Small JSON construction primitives shared by every architectural layer.

(in-package #:gr8s)

(defun json-object (&rest pairs)
  "Build an EQUAL hash table from alternating key and value PAIRS.

When a key occurs more than once, its final value wins."
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr
          do (setf (gethash key object) value))
    object))
