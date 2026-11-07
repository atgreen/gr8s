;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Imports the lower-layer interfaces consumed by node orchestration.

(in-package #:gr8s.kubelet)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((kubelet (find-package '#:gr8s.kubelet))
        (composition (find-package '#:gr8s)))
    (do-symbols (symbol composition)
      (when (and (not (member (symbol-package symbol)
                              (list (find-package '#:cl)
                                    (find-package '#:keyword)
                                    kubelet))))
        (multiple-value-bind (present status)
            (find-symbol (symbol-name symbol) kubelet)
          (declare (ignore status))
          (when (or (null present) (eq present symbol))
            (import symbol kubelet)))))))
