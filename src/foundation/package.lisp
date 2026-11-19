;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package boundary for the lowest architectural layer: version reporting, the
;;;; JSON construction primitive, cluster DNS policy constants, and deterministic
;;;; network steering.  These depend only on Common Lisp and a few standalone
;;;; libraries (version-string, 0conf, cl-dns-proxy), so GR8S.FOUNDATION uses
;;;; nothing but CL and is loaded before every other gr8s module.

(defpackage #:gr8s.foundation
  (:use #:cl)
  (:export #:json-object
           #:+gr8s-version+
           #:+dns-pod-server-address+
           #:node-steering-capacity-score
           #:rank-network-steering-candidates
           #:steering-bounded-integer))
