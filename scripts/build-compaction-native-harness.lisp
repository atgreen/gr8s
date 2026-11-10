;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(load "scripts/compaction-native-harness.lisp")
(ensure-directories-exist #P"build/")
(sb-ext:save-lisp-and-die #P"build/gr8s-compaction-acceptance" :toplevel #'compaction-native-main
                        :executable t :compression t :save-runtime-options :accept-runtime-options)
