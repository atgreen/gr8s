;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Compile historical dd36841 packet stages in an isolated process for upgrade tests.
;;;; Usage: sbcl --script THIS_FILE OUTPUT service-packet-guard
(require :asdf)
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,project) (:tree ,(merge-pathnames "ocicl/" project)) :inherit-configuration))
  (unless (equal "service-packet-guard" (second (uiop:command-line-arguments)))
    (error "usage: compile-legacy-service-packet-guard-fixture.lisp OUTPUT service-packet-guard"))
  (asdf:load-system "gr8s")
  (load (merge-pathnames "tests/fixtures/service-packet-pre-reservation.lisp" project))
  (load (merge-pathnames "scripts/compile-endpoint-policy-fixture.lisp" project)))
