;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; sbcl --noinform --non-interactive --load scripts/build-learner-native-harness.lisp
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(load "scripts/learner-native-harness.lisp")
(ensure-directories-exist #P"build/")
(sb-ext:save-lisp-and-die #P"build/gr8s-learner-acceptance" :toplevel #'learner-native-main
                        :executable t :compression t :save-runtime-options :accept-runtime-options)
