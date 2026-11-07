;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Imports from lower layers still exposed through the GR8S facade.

(in-package #:gr8s.security)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((security (find-package '#:gr8s.security))
        (composition (find-package '#:gr8s)))
    ;; These collaborators load later in the serial system. Interning their
    ;; names in the facade now preserves one symbol across that forward edge.
    (dolist (name '("CORE-BASE64-BYTES"
                    "INSTALL-SHARED-SERVICE-ACCOUNT-SIGNING-KEY"
                    "SERVICE-ACCOUNT-SIGNING-KEY-PATH-UNDER-PKI-ROOT"
                    "VERIFY-ENROLLMENT-CA-PIN"))
      (import (intern name composition) security))
    (do-symbols (symbol composition)
      (when (and (not (member (symbol-package symbol)
                              (list (find-package '#:cl)
                                    (find-package '#:keyword)
                                    security))))
        (multiple-value-bind (present status)
            (find-symbol (symbol-name symbol) security)
          (declare (ignore status))
          (when (or (null present) (eq present symbol))
            (import symbol security)))))))
