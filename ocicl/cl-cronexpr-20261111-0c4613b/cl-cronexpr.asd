;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(asdf:defsystem "cl-cronexpr"
  :description "Cron expression scheduling with named TZif time zones"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :version "0.1.0"
  :depends-on ("bordeaux-threads")
  :serial t
  :components ((:module "src" :components ((:file "package") (:file "cron"))))
  :in-order-to ((test-op (test-op "cl-cronexpr/tests"))))

(asdf:defsystem "cl-cronexpr/tests"
  :depends-on ("cl-cronexpr" "fiveam")
  :serial t
  :components ((:module "tests" :components ((:file "package") (:file "cron-test"))))
  :perform (test-op (operation component)
             (declare (ignore operation component))
             (unless (uiop:symbol-call :fiveam :run!
                                       (find-symbol "CL-CRONEXPR" "CL-CRONEXPR/TESTS"))
               (error "cl-cronexpr tests failed"))))

