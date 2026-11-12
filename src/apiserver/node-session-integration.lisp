;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Imports required by the control-plane half of the node session.

(in-package #:gr8s.apiserver)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((apiserver (find-package '#:gr8s.apiserver))
        (controllers (find-package '#:gr8s.controllers)))
    ;; These control-plane functions are implemented later in the load graph,
    ;; in gr8s.controllers.  Intern them in their owner now and import them so
    ;; this package compiles calls to their eventual definitions instead of
    ;; creating lookalike APISERVER symbols.
    (dolist (name '("ENSURE-POD-CERTIFICATE-REQUEST-FROM-CLAIM"
                    "NODE-DESIRED-STATE-SNAPSHOT"))
      (shadowing-import (intern name controllers) apiserver))))
