;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Compatibility facade for callers that still use the historical GR8S API.

(in-package #:gr8s.apiserver)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((apiserver (find-package '#:gr8s.apiserver))
        (composition (find-package '#:gr8s)))
    (let* ((public-names '("START-SERVER" "STOP-SERVER"))
           (old-public-symbols
             (mapcar (lambda (name) (find-symbol name composition)) public-names)))
      (do-symbols (symbol apiserver)
        (when (and (eq apiserver (symbol-package symbol))
                   (or (fboundp symbol)
                       (boundp symbol)
                       (find-class symbol nil)))
          (export symbol apiserver)
          (shadowing-import symbol composition)))
      ;; Packages using GR8S may have inherited the facade's old symbols before
      ;; this implementation package was loaded.  Replace only those inherited
      ;; identities, then restore the two names as public GR8S API.
      (loop for name in public-names
            for old in old-public-symbols
            for new = (find-symbol name apiserver)
            do (dolist (user (package-used-by-list composition))
                 (when (eq old (find-symbol name user))
                   (shadowing-import new user))))
      (export (mapcar (lambda (name) (find-symbol name apiserver)) public-names)
              composition))))
