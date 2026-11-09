;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system :gr8s)
(destructuring-bind (recipe-file key-file output) (uiop:command-line-arguments)
  (let* ((recipe (gr8s.patch::read-json recipe-file))
         (secret (ironclad:hex-string-to-byte-array
                  (string-trim '(#\Space #\Newline #\Return) (uiop:read-file-string key-file))))
         (key (ironclad:make-private-key :ed25519 :x secret)))
    (format t "~A~%" (gr8s.patch::build-artifact recipe key output))))
