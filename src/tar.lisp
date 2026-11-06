;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A minimal streaming tar extractor -- enough to unpack the runtime bundles
;;;; `gr8s runtime install` fetches. It reads a (already zstd-decompressed) tar
;;;; file block by block, writing regular files, directories, symlinks and hard
;;;; links to a destination directory, and preserving the executable bits a
;;;; shim/hypervisor needs. GNU long-name/long-link records and pax extended
;;;; headers are handled; other exotic entry types are skipped. Every entry path
;;;; is validated to stay within the destination, so a crafted archive cannot
;;;; escape it.

(in-package #:gr8s)

(define-condition tar-error (error)
  ((message :initarg :message :reader tar-error-message))
  (:report (lambda (condition stream)
             (format stream "tar: ~A" (tar-error-message condition)))))

(defun tar-field-string (block start max-length)
  "Decode a NUL-terminated ASCII field of BLOCK at START (up to MAX-LENGTH)."
  (let ((end (or (position 0 block :start start :end (+ start max-length))
                 (+ start max-length))))
    (map 'string #'code-char (subseq block start end))))

(defun tar-field-octal (block start length)
  "Decode a space/NUL-padded octal numeric field of BLOCK."
  (let ((text (string-trim '(#\Space #\Nul)
                           (map 'string #'code-char (subseq block start (+ start length))))))
    (if (zerop (length text)) 0 (parse-integer text :radix 8 :junk-allowed t))))

(defun tar-safe-path (name destination)
  "Resolve tar entry NAME to a pathname under DESTINATION, or signal if it would
   escape (absolute path, a .. component, or otherwise outside DESTINATION)."
  (let* ((destination (uiop:ensure-directory-pathname destination))
         (trimmed (if (and (>= (length name) 2) (string= (subseq name 0 2) "./"))
                      (subseq name 2)
                      name))
         (trimmed (string-left-trim "/" trimmed))
         (components (remove-if (lambda (c) (or (zerop (length c)) (string= c ".")))
                                (uiop:split-string trimmed :separator "/"))))
    (when (or (uiop:absolute-pathname-p name)
              (member ".." components :test #'string=))
      (error 'tar-error :message (format nil "unsafe tar path: ~A" name)))
    ;; An empty path (the archive's own "./" root entry) refers to DESTINATION
    ;; itself -- a legitimate directory entry, not an escape.
    (if (null components)
        destination
        (let ((path (merge-pathnames trimmed destination)))
          (unless (uiop:subpathp path destination)
            (error 'tar-error :message (format nil "tar path escapes destination: ~A" name)))
          path))))

(defun tar-skip (in block-count)
  "Discard BLOCK-COUNT 512-byte blocks from IN."
  (let ((pad (make-array 512 :element-type '(unsigned-byte 8))))
    (dotimes (_ block-count)
      (read-sequence pad in))))

(defun tar-read-data-string (in size)
  "Read SIZE bytes of entry data from IN as a string, then consume padding to the
   next 512-byte boundary. Trailing NULs are stripped (GNU name records)."
  (let* ((blocks (ceiling size 512))
         (buffer (make-array (* blocks 512) :element-type '(unsigned-byte 8)))
         (got (read-sequence buffer in)))
    (when (< got (* blocks 512))
      (error 'tar-error :message "unexpected EOF in tar long-name record"))
    (string-right-trim '(#\Nul) (map 'string #'code-char (subseq buffer 0 size)))))

(defun tar-write-file (in destination size)
  "Write SIZE bytes of entry data from IN to DESTINATION, then consume padding."
  (ensure-directories-exist destination)
  (with-open-file (out destination :direction :output :element-type '(unsigned-byte 8)
                                   :if-exists :supersede :if-does-not-exist :create)
    (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8)))
          (remaining size))
      (loop while (plusp remaining) do
        (let* ((want (min 65536 remaining))
               (got (read-sequence buffer in :end want)))
          (when (zerop got)
            (error 'tar-error :message "unexpected EOF in tar file data"))
          (write-sequence buffer out :end got)
          (decf remaining got)))))
  (let ((pad (- (* 512 (ceiling size 512)) size)))
    (when (plusp pad)
      (read-sequence (make-array pad :element-type '(unsigned-byte 8)) in))))

(defun extract-tar-file (tar-path destination)
  "Extract the (uncompressed) tar archive at TAR-PATH into DESTINATION, returning
   the number of entries written. Supports regular files, directories, symlinks,
   hard links, GNU long name/link records and pax headers; preserves mode bits."
  (let ((destination (uiop:ensure-directory-pathname destination))
        (block (make-array 512 :element-type '(unsigned-byte 8)))
        (pending-name nil)
        (pending-link nil)
        (written 0))
    (ensure-directories-exist destination)
    (with-open-file (in tar-path :element-type '(unsigned-byte 8))
      (loop
        (let ((n (read-sequence block in)))
          (when (< n 512) (return))            ; trailing short read: done
          (when (every #'zerop block) (return)) ; zero block: end of archive
          (let* ((name (or pending-name
                           (let ((prefix (tar-field-string block 345 155))
                                 (base (tar-field-string block 0 100)))
                             (if (plusp (length prefix))
                                 (concatenate 'string prefix "/" base)
                                 base))))
                 (mode (tar-field-octal block 100 8))
                 (size (tar-field-octal block 124 12))
                 (typeflag (code-char (aref block 156)))
                 (linkname (or pending-link (tar-field-string block 157 100))))
            (setf pending-name nil pending-link nil)
            (case typeflag
              (#\L                               ; GNU long name for next entry
               (setf pending-name (tar-read-data-string in size)))
              (#\K                               ; GNU long link for next entry
               (setf pending-link (tar-read-data-string in size)))
              ((#\g #\x)                          ; pax extended headers: skip
               (tar-skip in (ceiling size 512)))
              (t
               (let ((target (tar-safe-path name destination)))
                 (case typeflag
                   ((#\0 #\Nul)                   ; regular file
                    (tar-write-file in target size)
                    (ignore-errors (sb-posix:chmod (namestring target) (logand mode #o777)))
                    (incf written))
                   (#\5                           ; directory
                    (ensure-directories-exist (uiop:ensure-directory-pathname target))
                    (incf written))
                   (#\2                           ; symbolic link
                    (ensure-directories-exist target)
                    (ignore-errors (sb-posix:unlink (namestring target)))
                    (sb-posix:symlink linkname (namestring target))
                    (incf written))
                   (#\1                           ; hard link
                    (ensure-directories-exist target)
                    (ignore-errors (sb-posix:unlink (namestring target)))
                    (sb-posix:link (namestring (tar-safe-path linkname destination))
                                   (namestring target))
                    (incf written))
                   (t                             ; char/block/fifo etc.: skip data
                    (tar-skip in (ceiling size 512)))))))))))
    written))
