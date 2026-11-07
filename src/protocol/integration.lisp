;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Imports from layers that still expose their implementation through GR8S.

(in-package #:gr8s.protocol)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((protocol (find-package '#:gr8s.protocol))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol composition)
      (when (and (not (member (symbol-package symbol)
                              (list (find-package '#:cl)
                                    (find-package '#:keyword)
                                    protocol))))
        (multiple-value-bind (present status)
            (find-symbol (symbol-name symbol) protocol)
          (declare (ignore status))
          (when (or (null present) (eq present symbol))
            (import symbol protocol)))))))
