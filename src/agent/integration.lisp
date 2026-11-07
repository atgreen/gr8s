;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Temporary imports from layers not yet extracted from the composition package.

(in-package #:gr8s.agent)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((agent (find-package '#:gr8s.agent))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol composition)
      (when (and (not (member (symbol-package symbol)
                              (list (find-package '#:cl)
                                    (find-package '#:keyword)
                                    agent))))
        (multiple-value-bind (present status)
            (find-symbol (symbol-name symbol) agent)
          (declare (ignore status))
          (when (or (null present) (eq present symbol))
            (import symbol agent)))))))
