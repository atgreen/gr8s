;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(load "scripts/learner-native-harness.lisp")
(multiple-value-bind (output warnings failure)
    (compile-file "scripts/compaction-cluster-native-harness.lisp"
                  :output-file "build/compaction-cluster-native-harness.fasl")
  (declare (ignore warnings))
  (when failure (error "Compaction cluster harness compilation failed"))
  (load output))
(sb-ext:save-lisp-and-die #P"build/gr8s-compaction-cluster-acceptance"
                        :toplevel #'compaction-cluster-native-main
                        :executable t :compression t :save-runtime-options :accept-runtime-options)
