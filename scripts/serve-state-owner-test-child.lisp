;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(destructuring-bind (root ready)
    (let ((args (uiop:command-line-arguments))) (if (equal "--" (first args)) (rest args) args))
  (gr8s.server::call-with-serve-state-ownership
   (list :state-directory root)
   (lambda () (gr8s.security::write-private-text-atomically ready "owned") (loop (sleep 1)))))
