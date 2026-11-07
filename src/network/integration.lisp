;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Temporary imports from layers not yet extracted from the composition package.

(in-package #:gr8s.network)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((network (find-package '#:gr8s.network))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol composition)
      (when (and (not (member (symbol-package symbol)
                              (list (find-package '#:cl)
                                    (find-package '#:keyword)
                                    network)))
                 (not (string= "VALIDATE-NETWORK-POLICY-SPEC"
                               (symbol-name symbol))))
        (multiple-value-bind (present status)
            (find-symbol (symbol-name symbol) network)
          (declare (ignore status))
          (when (or (null present) (eq present symbol))
            (import symbol network)))))))
