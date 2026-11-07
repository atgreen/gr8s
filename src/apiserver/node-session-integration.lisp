;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Imports required by the control-plane half of the node session.

(in-package #:gr8s.apiserver)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((apiserver (find-package '#:gr8s.apiserver))
        (composition (find-package '#:gr8s)))
    ;; These control-plane functions are implemented later in the load graph.
    ;; Intern them in GR8S now so this package compiles calls to their eventual
    ;; definitions instead of creating lookalike APISERVER symbols.
    (dolist (name '("ENSURE-POD-CERTIFICATE-REQUEST-FROM-CLAIM"
                    "NODE-DESIRED-STATE-SNAPSHOT"))
      (import (intern name composition) apiserver))
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
