;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(destructuring-bind (wal ready)
    (let ((args (uiop:command-line-arguments)))
      (if (equal "--" (first args)) (rest args) args))
  (let ((storage (gr8s.raft:open-file-raft-storage wal)))
    (unwind-protect
         (progn
           (gr8s.raft:raft-storage-save-hard-state storage 17 "child")
           (with-open-file (out ready :direction :output :if-exists :supersede)
             (write-line "owned" out))
           (loop (sleep 1)))
      (gr8s.raft:close-file-raft-storage storage))))
