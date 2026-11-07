;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.server)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((server (find-package '#:gr8s.server))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol composition)
      (when (and (not (member (symbol-package symbol)
                              (list (find-package '#:cl)
                                    (find-package '#:keyword)
                                    server))))
        (multiple-value-bind (present status)
            (find-symbol (symbol-name symbol) server)
          (declare (ignore status))
          (when (or (null present) (eq present symbol))
            (import symbol server)))))))
