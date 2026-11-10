;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(ensure-directories-exist #P"build/")
(multiple-value-bind (output warnings failure)
    (compile-file "scripts/snapshot-freeze-native-harness.lisp"
                  :output-file "build/snapshot-freeze-native-harness.fasl")
  (declare (ignore warnings))
  (when failure (error "Snapshot freeze harness compilation failed"))
  (load output))
(sb-ext:save-lisp-and-die #P"build/gr8s-snapshot-freeze-acceptance"
                        :toplevel #'snapshot-freeze-native-main
                        :executable t :compression t :save-runtime-options :accept-runtime-options)
