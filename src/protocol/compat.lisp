;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Compatibility facade for callers using the historical GR8S API.

(in-package #:gr8s.protocol)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((protocol (find-package '#:gr8s.protocol))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol protocol)
      (when (and (eq protocol (symbol-package symbol))
                 (or (fboundp symbol)
                     (boundp symbol)
                     (find-class symbol nil)))
        (export symbol protocol)
        (shadowing-import symbol composition)))))
