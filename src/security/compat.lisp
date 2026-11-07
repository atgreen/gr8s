;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Compatibility facade for callers using the historical GR8S API.

(in-package #:gr8s.security)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((security (find-package '#:gr8s.security))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol security)
      (when (and (eq security (symbol-package symbol))
                 (or (fboundp symbol)
                     (boundp symbol)
                     (find-class symbol nil)))
        (export symbol security)
        (shadowing-import symbol composition)))))
