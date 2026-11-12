;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for CLI and process assembly.

(defpackage #:gr8s.server
  (:use #:cl)
  (:shadow #:main #:parse-cli-options #:run-doctor)
  (:export #:main #:parse-cli-options #:run-doctor))
