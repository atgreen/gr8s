;;;; SPDX-License-Identifier: MIT
;;;; Run the doctor from source: see scripts/gr8s-diagnose.
(load (merge-pathnames "../tests/doctor/load.lisp" *load-truename*))
(uiop:quit (uiop:symbol-call :gr8s-diagnose :main (uiop:command-line-arguments)))
