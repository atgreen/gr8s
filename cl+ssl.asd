;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Route the "cl+ssl" system name to pure-tls's drop-in cl+ssl compatibility
;;;; layer, so everything that depends on cl+ssl (drakma -- gr8s's HTTP proxies
;;;; and container probes) links gr8s's own pure-Lisp TLS instead of OpenSSL.
;;;; gr8s links no cl-plus-ssl / OpenSSL at all.
;;;;
;;;; This file lives at the repo root, which ocicl's ~/.sbclrc puts on the ASDF
;;;; source-registry as a :directory, so ASDF resolves "cl+ssl" to this shim
;;;; before ocicl would fetch the real cl-plus-ssl artifact.

(asdf:defsystem "cl+ssl"
  :description "Shim: the cl+ssl API backed by pure-tls (no OpenSSL)."
  :license "MIT"
  :depends-on ("pure-tls/cl+ssl-compat"))
