;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Imports required by the control-plane half of the node session.

(in-package #:gr8s.apiserver)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((apiserver (find-package '#:gr8s.apiserver))
        (controllers (find-package '#:gr8s.controllers))
        (model (find-package '#:gr8s.model))
        (runtime (find-package '#:gr8s.runtime)))
    ;; These control-plane functions are implemented later in the load graph,
    ;; in gr8s.controllers.  Intern them in their owner now and import them so
    ;; this package compiles calls to their eventual definitions instead of
    ;; creating lookalike APISERVER symbols.
    (dolist (name '("ENSURE-POD-CERTIFICATE-REQUEST-FROM-CLAIM"
                    "NODE-DESIRED-STATE-SNAPSHOT"))
      (shadowing-import (intern name controllers) apiserver))
    ;; node-session.lisp signals and catches these conditions by their bare
    ;; names, but it loads BEFORE the gr8s.apiserver integration shadowing-import
    ;; (apiserver/integration.lisp) runs.  Import the condition symbols from their
    ;; owning packages here, before node-session.lisp compiles, so its handler-case
    ;; types and (error 'c ...) forms reference the real condition classes.
    ;; Otherwise node-session interns lookalike APISERVER symbols that the later
    ;; integration shadowing-import uninterns, stranding the compiled references as
    ;; homeless #:KUBERNETES-ERROR / #:RUNTIME-ERROR symbols -- which then crash
    ;; TYPEP / MAKE-CONDITION (and the process) when such a condition is raised.
    (dolist (name '("KUBERNETES-ERROR" "KUBERNETES-ERROR-STATUS-CODE"))
      (shadowing-import (intern name model) apiserver))
    (dolist (name '("RUNTIME-ERROR" "RUNTIME-ERROR-MESSAGE"))
      (shadowing-import (intern name runtime) apiserver))))
