;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The gr8s version string. +GR8S-VERSION+ is the ASDF :version from gr8s.asd,
;;;; augmented with git state (tag, else base-gHASH, with a +dirty suffix) when
;;;; the native binary is built -- scripts/build-native.lisp sets it just before
;;;; save-lisp-and-die, since that build does not go through asdf:program-op.
;;;; In a REPL/dev image it is the plain base version.

(in-package #:gr8s)

(version-string:define-version-parameter +gr8s-version+ :gr8s)
