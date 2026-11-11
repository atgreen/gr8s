;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Pause a real persistence call after a durable partial UTF-8 frame write.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(destructuring-bind (wal ready)
    (let ((args (uiop:command-line-arguments))) (if (equal "--" (first args)) (rest args) args))
  (let ((storage (gr8s.raft:open-file-raft-storage wal))
        (original (symbol-function 'cl-raft::raft-wal-write-frame)))
    (unwind-protect
         (progn
           (setf (symbol-function 'cl-raft::raft-wal-write-frame)
                 (lambda (form stream)
                   (finish-output stream)
                   (let* ((bytes (trivial-utf-8:string-to-utf-8-bytes
                                  (with-output-to-string (out) (funcall original form out))))
                          (cut (+ 2 (or (position #xf0 bytes) (error "Missing UTF-8 test boundary")))))
                     (with-open-file (out wal :direction :output :element-type '(unsigned-byte 8) :if-exists :append)
                       (write-sequence bytes out :end cut)
                       (finish-output out)
                       (sb-posix:fsync (sb-sys:fd-stream-fd out))))
                   (gr8s::write-private-text-atomically ready "partial-unacknowledged-write")
                   (loop (sleep 1))))
           ;; This call never returns or acknowledges success before SIGKILL.
           (gr8s.raft:raft-storage-save-hard-state storage 99 "pending-éλ😀"))
      (setf (symbol-function 'cl-raft::raft-wal-write-frame) original)
      (gr8s.raft:close-file-raft-storage storage))))
