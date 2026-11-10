;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(ensure-directories-exist #P"build/")
(multiple-value-bind (output warnings failure)
    (compile-file "scripts/compaction-native-harness.lisp" :output-file "build/compaction-native-harness.fasl")
  (declare (ignore warnings))
  (when failure (error "Compaction harness compilation failed"))
  (load output))
(sb-ext:save-lisp-and-die #P"build/gr8s-compaction-acceptance" :toplevel #'compaction-native-main
                        :executable t :compression t :save-runtime-options :accept-runtime-options)
