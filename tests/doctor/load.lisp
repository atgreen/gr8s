;;;; SPDX-License-Identifier: MIT
;;;; Load the doctor on its own, from the repository's pinned dependencies.
(require :asdf)
(let ((root (merge-pathnames "../../" (uiop:pathname-directory-pathname *load-truename*))))
  (asdf:initialize-source-registry
   `(:source-registry (:tree ,(merge-pathnames "ocicl/" root)) :inherit-configuration))
  (asdf:load-asd (merge-pathnames "src/diagnostics/gr8s-doctor.asd" root)))
(let ((*standard-output* *error-output*)
      (*compile-verbose* nil) (*load-verbose* nil))
  (asdf:load-system "gr8s-doctor"))
