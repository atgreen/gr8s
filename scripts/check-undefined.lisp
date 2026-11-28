;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Recompile gr8s and its tests from source and fail on any undefined function or
;;;; variable the compiler reports in gr8s's own files (podster-8o0k). An undefined
;;;; function is a call that fails at run time, and one inside IGNORE-ERRORS fails
;;;; silently: credential injection never worked on any node that way (podster-sxfe).
;;;; A variable used before its DEFVAR is compiled is free, not special, so a LET of it
;;;; binds nothing callers can see. Run by `make check-undefined`, after bootstrap.lisp.

(let* ((root (truename (merge-pathnames "../" (make-pathname :name nil :type nil :defaults *load-truename*))))
       (found '()))
  (flet ((ours-p ()
           (and *compile-file-truename*
                (uiop:subpathp *compile-file-truename* root)
                (not (uiop:subpathp *compile-file-truename* (merge-pathnames "ocicl/" root))))))
    (handler-bind ((warning
                     (lambda (condition)
                       (let ((text (string-downcase (princ-to-string condition))))
                         (when (and (or (search "undefined function" text) (search "undefined variable" text))
                                    (or (ours-p)
                                        ;; Undefined functions are reported once, at the end of the
                                        ;; compilation unit, outside any one file: count gr8s's own.
                                        (and (null *compile-file-truename*) (search "gr8s" text))))
                           (pushnew (format nil "~A~@[ (~A)~]" (princ-to-string condition)
                                            (and *compile-file-truename* (enough-namestring *compile-file-truename* root)))
                                    found :test #'string=))))))
      (asdf:load-system "gr8s/tests" :force '("gr8s" "gr8s/tests"))))
  (cond (found
         (format *error-output* "~&~%gr8s: ~D undefined name~:P in gr8s's own code:~%~{  ~A~%~}"
                 (length found) (reverse found))
         (uiop:quit 1))
        (t (format t "~&gr8s: no undefined functions or variables~%")
           (uiop:quit 0))))
