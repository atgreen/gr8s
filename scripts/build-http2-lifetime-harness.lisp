;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; sbcl --noinform --non-interactive --load scripts/build-http2-lifetime-harness.lisp
;;;; build/gr8s-http2-lifetime --dynamic-space-size 384
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(load "scripts/http2-lifetime-harness.lisp")
(ensure-directories-exist #P"build/")
(sb-ext:save-lisp-and-die #P"build/gr8s-http2-lifetime" :toplevel #'http2-lifetime-main
                        :executable t :compression t :save-runtime-options :accept-runtime-options)
