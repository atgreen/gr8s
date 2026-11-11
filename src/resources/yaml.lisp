;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The safe, bounded YAML reader used for kubectl apply, static manifests and
;;;; pull-secret config now lives in the standalone cl-safe-yaml library
;;;; (installed via ocicl).  Its PARSE-YAML returns the decoded value and the list
;;;; of repeated-key descriptions, exactly as gr8s needs, but signals its own
;;;; CL-SAFE-YAML:YAML-PARSE-ERROR for a malformed document.  gr8s serves YAML to
;;;; API clients, where a malformed document is a 400 BadRequest, so this thin
;;;; wrapper runs the library's reader and translates that one condition into the
;;;; Kubernetes client error gr8s's callers already expect -- keeping the library
;;;; general while preserving gr8s's API contract.

(in-package #:gr8s.resources)

(defun parse-yaml (text)
  "Decode TEXT's first YAML document with cl-safe-yaml, returning the value and
the list of repeated-key descriptions.  A malformed document is reported as a
400 BadRequest, as gr8s's API handlers require."
  (handler-case (cl-safe-yaml:parse-yaml text)
    (cl-safe-yaml:yaml-parse-error (condition)
      (core-resource-error 400 "BadRequest" "error decoding YAML: yaml: line ~D: ~A"
                           (cl-safe-yaml:yaml-parse-error-line condition)
                           (cl-safe-yaml:yaml-parse-error-message condition)))))
