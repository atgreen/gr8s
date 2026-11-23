;;;; SPDX-License-Identifier: MIT
;;;; The doctor on its own, without the rest of gr8s: what scripts/gr8s-doctor
;;;; and the tests in tests/doctor/ load. gr8s.asd lists the same files.
(asdf:defsystem "gr8s-doctor"
  :description "gr8s doctor diagnostics: Prolog rules run by ag-prolog"
  :license "MIT"
  :depends-on ("ag-prolog/syntax" "cl-commonmark" "com.inuoe.jzon" "tuition")
  :serial t
  ;; rules.lisp reads the Prolog files when it is compiled, so they come first.
  :components ((:file "package")
               (:static-file "rules/catalog.pl")
               (:static-file "rules/references.pl")
               (:static-file "rules/pods.pl")
               (:static-file "rules/scheduling.pl")
               (:static-file "rules/applications.pl")
               (:static-file "rules/logs.pl")
               (:static-file "rules/access.pl")
               (:static-file "rules/relations.pl")
               (:static-file "rules/explanation.pl")
               (:static-file "rules/impact.pl")
               (:file "rules")
               (:file "progress")
               (:file "live")
               (:file "markdown")
               (:file "catalog")
               (:file "extended-catalog")
               (:file "readiness")
               (:file "applications")
               (:file "doctor")
               (:file "causal")
               (:file "logs")
               (:file "pod-events")
               (:file "flows")
               (:file "scheduling")
               (:file "survey")
               (:file "impact")))
