;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Compatibility facade for callers that still use the historical GR8S API.

(in-package #:gr8s.agent)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((agent (find-package '#:gr8s.agent))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol agent)
      ;; The reader interns LOOP keywords and lexical variable names in this
      ;; package too.  Only definitions are part of the compatibility API.
      (when (and (eq agent (symbol-package symbol))
                 (or (fboundp symbol)
                     (boundp symbol)
                     (find-class symbol nil)))
        (export symbol agent)
        (shadowing-import symbol composition)))))
