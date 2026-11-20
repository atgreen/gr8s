;;;; SPDX-License-Identifier: MIT
;;;; Run the doctor from source: see scripts/gr8s-doctor.
(load (merge-pathnames "../tests/doctor/load.lisp" *load-truename*))
(uiop:quit (uiop:symbol-call :gr8s-diagnose :doctor-main (uiop:command-line-arguments)))
