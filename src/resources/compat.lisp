;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Compatibility facade for callers that still use the historical GR8S API.

(in-package #:gr8s.resources)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((resources (find-package '#:gr8s.resources))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol resources)
      (when (and (eq resources (symbol-package symbol))
                 (or (fboundp symbol)
                     (boundp symbol)
                     (find-class symbol nil)))
        (export symbol resources)
        (shadowing-import symbol composition)))))
