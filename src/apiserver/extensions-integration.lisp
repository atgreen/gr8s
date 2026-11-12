;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Imports made available by controller modules loaded after the core HTTP surface.

(in-package #:gr8s.apiserver)

;;;; The cross-module symbols the extension surface references are imported
;;;; explicitly in apiserver/integration.lisp and apiserver/moved-imports; this
;;;; file no longer pulls the GR8S composition in bulk.
