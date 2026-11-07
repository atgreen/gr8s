;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Compatibility facade for callers using the historical GR8S API.

(in-package #:gr8s.kubelet)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((kubelet (find-package '#:gr8s.kubelet))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol kubelet)
      (when (and (eq kubelet (symbol-package symbol))
                 (or (fboundp symbol)
                     (boundp symbol)
                     (find-class symbol nil)))
        (export symbol kubelet)
        (shadowing-import symbol composition)))))
