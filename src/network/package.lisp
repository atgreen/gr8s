;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for CNI and the node networking dataplane.

(defpackage #:gr8s.network
  (:use #:cl #:gr8s)
  (:export #:validate-network-policy-spec))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((network (find-package '#:gr8s.network))
        (composition (find-package '#:gr8s)))
    ;; Bootstrap code validates the default NetworkPolicy before this module is
    ;; loaded.  Establish that forward reference with the symbol this package
    ;; will define.
    (let ((symbol (find-symbol "VALIDATE-NETWORK-POLICY-SPEC" network)))
      (shadowing-import symbol composition))))
