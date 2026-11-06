;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The gr8s version string. +GR8S-VERSION+ is the ASDF :version from gr8s.asd,
;;;; augmented with git state (tag, else base-gHASH, with a +dirty suffix) when
;;;; the native binary is built -- scripts/build-native.lisp sets it just before
;;;; save-lisp-and-die, since that build does not go through asdf:program-op.
;;;; In a REPL/dev image it is the plain base version.

(in-package #:gr8s)

(version-string:define-version-parameter +gr8s-version+ :gr8s)

(defun kubernetes-api-version-components ()
  "Return (values major minor) of the Kubernetes API version gr8s implements,
   parsed from the single source of truth -- the ASDF :version in gr8s.asd."
  (let ((parts (uiop:split-string (version-string:get-base-version :gr8s) :separator '(#\.))))
    (values (or (first parts) "1") (or (second parts) "0"))))

(defun kubernetes-git-version ()
  "The Kubernetes-style gitVersion string clients see (e.g. in /version and a
   Node's kubeletVersion): the gr8s build version with a leading \"v\". A release
   tag like v1.37.2-gr8s.0 is reported verbatim; an untagged build reports the
   k8s base version with the commit hash (v1.37.2-g1a2b3c4)."
  (if (and (plusp (length +gr8s-version+)) (char-equal #\v (char +gr8s-version+ 0)))
      +gr8s-version+
      (format nil "v~A" +gr8s-version+)))
