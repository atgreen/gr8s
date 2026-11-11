;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Internal source-memory probe, not the operator backup CLI.
;;;; sbcl --dynamic-space-size 192 --noinform --non-interactive
;;;; --load scripts/probe-backup-bundle-memory.lisp -- /stopped/state/directory
;;;; Writes an encrypted fixture and random private key under TMPDIR.
(require :asdf)
(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system "gr8s")
(let* ((arguments (uiop:command-line-arguments))
       (arguments (if (equal "--" (first arguments)) (rest arguments) arguments))
       (source (if (= 1 (length arguments))
                   (truename (uiop:ensure-directory-pathname (first arguments)))
                   (error "Provide one stopped state directory after --")))
       (base (uiop:ensure-directory-pathname
              (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-backup-bundle-XXXXXX" (uiop:temporary-directory))))))
       (target (merge-pathnames "state.bin" base))
       (key (ironclad:random-data 32)) (seen 0))
 (with-open-stream (out (gr8s.resources::open-snapshot-generation-output (merge-pathnames "key.bin" base) :binary t))
  (write-sequence key out) (finish-output out) (sb-posix:fsync (sb-sys:fd-stream-fd out)))
 (multiple-value-bind (path count bytes) (gr8s.server::capture-state-backup source target key)
  (with-open-file (in path :element-type '(unsigned-byte 8))
   (multiple-value-bind (manifest verified-count verified-bytes)
       (gr8s.server::verify-state-backup-stream
        in key :on-data (lambda (record start end) (declare (ignore record)) (incf seen (- end start))))
    (unless (and (= count verified-count) (= bytes verified-bytes seen)) (error "Bundle count mismatch"))
    (sb-ext:gc :full t)
    (let ((result (gr8s::json-object
                   "passed" t "source" (namestring source) "evidence" (namestring base)
                   "files" count "plaintextBytes" bytes "ciphertextBytes" (sb-posix:stat-size (sb-posix:stat path))
                   "heapLimitBytes" (sb-ext:dynamic-space-size) "afterFullGcBytes" (sb-kernel:dynamic-usage)
                   "manifest" manifest)))
     (with-open-stream (out (gr8s.resources::open-snapshot-generation-output (merge-pathnames "result.json" base)))
      (com.inuoe.jzon:stringify result :stream out))
     (format t "~&BACKUP_BUNDLE_PRODUCTION ~A~%" (com.inuoe.jzon:stringify result)))))))
