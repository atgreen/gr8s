;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for CLI and process assembly.

(defpackage #:gr8s.server
  (:use #:cl)
  (:shadow #:main #:parse-cli-options #:run-doctor)
  (:export #:main #:parse-cli-options #:run-doctor))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((server (find-package '#:gr8s.server))
        (composition (find-package '#:gr8s)))
    (dolist (name '("MAIN" "PARSE-CLI-OPTIONS" "RUN-DOCTOR"))
      (multiple-value-bind (old old-status)
          (find-symbol name composition)
        (declare (ignore old))
        (let ((new (find-symbol name server)))
          (shadowing-import new composition)
          (export new server)
          (when (eq :external old-status)
            (export new composition)))))))
