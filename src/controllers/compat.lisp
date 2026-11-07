;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Compatibility facade for callers that still use the historical GR8S API.

(in-package #:gr8s.controllers)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((controllers (find-package '#:gr8s.controllers))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol controllers)
      (when (and (eq controllers (symbol-package symbol))
                 (or (fboundp symbol)
                     (boundp symbol)
                     (find-class symbol nil)))
        (export symbol controllers)
        (shadowing-import symbol composition)))))
