;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)

(defun start-suite-watchdog ()
  "Report every thread's stack and exit if the suite outlives GR8S_TEST_TIMEOUT_SECONDS."
  ;; A hung suite otherwise sits idle holding a shared build slot, and leaves no
  ;; evidence of what it was waiting for.
  (let ((seconds (parse-integer (or (uiop:getenv "GR8S_TEST_TIMEOUT_SECONDS") "3600")))
        (output *error-output*))
    (bt:make-thread
     (lambda ()
       (sleep seconds)
       (format output "~&gr8s test suite still running after ~D seconds~%" seconds)
       (let ((*standard-output* output))
         (gr8s::debug-backtraces "" 3))
       (finish-output output)
       (sb-ext:exit :code 124 :abort t))
     :name "gr8s test suite watchdog")))
