;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(destructuring-bind (root ready phase)
    (let ((args (uiop:command-line-arguments))) (if (equal "--" (first args)) (rest args) args))
  (let* ((store (gr8s.store::open-store root))
         (wanted (intern (string-upcase phase) :keyword)))
    (setf (symbol-function 'gr8s.resources::store-member-bootstrap-progress)
          (lambda (incoming current descriptor)
            (declare (ignore descriptor))
            (when (and (eq store incoming) (eq current wanted))
              (gr8s.security::write-private-text-atomically ready phase)
              (loop (sleep 1)))))
    (gr8s.store::quiesce-store-access store)
    (gr8s.store::call-with-store-application-barriers
     store (lambda () (gr8s.resources::bootstrap-store-member-wal store "fresh")))
    (error "Bootstrap failed to pause at requested phase")))
