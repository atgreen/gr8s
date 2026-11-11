;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(asdf:defsystem "cl-work-queue"
  :description "Keyed lane-limited background work queues"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :version "0.1.0"
  :depends-on ("bordeaux-threads")
  :serial t
  :components ((:module "src" :components ((:file "package") (:file "queue"))))
  :in-order-to ((test-op (test-op "cl-work-queue/tests"))))

(asdf:defsystem "cl-work-queue/tests"
  :depends-on ("cl-work-queue" "fiveam")
  :serial t
  :components ((:module "tests" :components ((:file "package") (:file "queue-test"))))
  :perform (test-op (operation component)
             (declare (ignore operation component))
             (unless (uiop:symbol-call :fiveam :run!
                                       (find-symbol "CL-WORK-QUEUE" "CL-WORK-QUEUE/TESTS"))
               (error "cl-work-queue tests failed"))))

