;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Imports made available by controller modules loaded after the core HTTP surface.

(in-package #:gr8s.apiserver)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((apiserver (find-package '#:gr8s.apiserver))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol composition)
      (when (and (not (member (symbol-package symbol)
                              (list (find-package '#:cl)
                                    (find-package '#:keyword)
                                    apiserver))))
        (multiple-value-bind (present status)
            (find-symbol (symbol-name symbol) apiserver)
          (declare (ignore status))
          (when (or (null present) (eq present symbol))
            (import symbol apiserver)))))))
