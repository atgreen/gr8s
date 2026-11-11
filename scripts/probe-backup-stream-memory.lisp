;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Run from the checkout: sbcl --dynamic-space-size 96 --noinform --non-interactive
;;;; --load scripts/probe-backup-stream-memory.lisp -- /path/to/public-test-fixture.bin
;;;; Public fixture key and payload; this is not an operator backup command.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system :ironclad)
(asdf:load-system :bordeaux-threads)
(asdf:load-system :trivial-utf-8)
(unless (find-package :gr8s.server) (make-package :gr8s.server :use '(:cl)))
(load "src/server/backup-stream.lisp")
(let* ((arguments (uiop:command-line-arguments))
       (arguments (if (equal "--" (first arguments)) (rest arguments) arguments))
       (file (if (= 1 (length arguments)) (first arguments)
                 (error "Provide one fixture output path after --")))
       (key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42))
       (payload (make-array 65536 :element-type '(unsigned-byte 8) :initial-element 99))
       (records 2048) (seen 0))
 (with-open-file (out file :direction :output :element-type '(unsigned-byte 8) :if-exists :supersede)
  (let ((writer (gr8s.server::open-backup-writer out key)))
   (dotimes (i records) (gr8s.server::write-backup-record writer payload))
   (gr8s.server::finish-backup-writer writer)))
 (with-open-file (in file :element-type '(unsigned-byte 8))
  (let ((reader (gr8s.server::open-backup-reader in key)))
   (loop for block = (gr8s.server::read-backup-record reader) while block do
    (unless (and (= 65536 (length block)) (every (lambda (n) (= n 99)) block)) (error "Payload mismatch"))
    (incf seen))))
 (unless (= records seen) (error "Missing records"))
 (sb-ext:gc :full t)
 (format t "~&BACKUP_STREAM_MEMORY passed records=~D plaintext-bytes=~D heap-limit=~D after-gc=~D~%"
         seen (* seen 65536) (sb-ext:dynamic-space-size) (sb-kernel:dynamic-usage)))
