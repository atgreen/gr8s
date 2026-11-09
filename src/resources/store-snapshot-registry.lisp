;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.resources)

(defun store-snapshot-artifact-reference (index term digest)
  "Portable WAL identity; never contains a member-local pathname."
  (unless (and (typep index '(integer 1 #.most-positive-fixnum))
               (typep term '(integer 0 #.most-positive-fixnum))
               (stringp digest) (= 64 (length digest))
               (every (lambda (char) (find char "0123456789abcdef")) digest))
    (error "Invalid store snapshot artifact identity"))
  (list :gr8s-store-artifact 1 :index index :term term :sha256 (copy-seq digest)))

(defun store-snapshot-registry-directory (root)
  (let* ((root (uiop:ensure-directory-pathname root))
         (path (merge-pathnames "snapshot-artifacts/" root)))
    (gr8s.store::check-store-generation-directory root :metadata t)
    (gr8s.store::ensure-store-generation-directory path root)))

(defun checked-store-snapshot-artifact-path (root reference)
  "Resolve a canonical reference, checking permissions and hashing bytes on every use.
Published artifacts are immutable by contract. The private member root must not be
modified concurrently by another process. Semantic validation occurs at publication."
  (unless (and (listp reference) (= 8 (length reference))
               (equal reference
                      (store-snapshot-artifact-reference
                       (fourth reference) (sixth reference) (eighth reference))))
    (error "Invalid store snapshot artifact reference"))
  (let* ((digest (eighth reference))
         (path (merge-pathnames (format nil "~A.jsonl" digest)
                               (store-snapshot-registry-directory root)))
         (fd (sb-posix:open (namestring path)
                           (logior sb-posix:o-rdonly sb-posix:o-nofollow sb-posix:o-nonblock) 0))
         (input nil))
    (unwind-protect
         (let ((stat (sb-posix:fstat fd))
               (hash (ironclad:make-digest :sha256))
               (buffer (make-array 65536 :element-type '(unsigned-byte 8))))
           (unless (and (sb-posix:s-isreg (sb-posix:stat-mode stat))
                        (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                        (= #o600 (logand #o777 (sb-posix:stat-mode stat))))
             (error "Unsafe store snapshot artifact"))
           (setf input (sb-sys:make-fd-stream fd :input t :element-type '(unsigned-byte 8) :auto-close t))
           (loop for count = (read-sequence buffer input) while (plusp count)
                 do (ironclad:update-digest hash buffer :end count))
           (unless (equal digest (ironclad:byte-array-to-hex-string (ironclad:produce-digest hash)))
             (error "Store snapshot artifact checksum mismatch")))
      (if input (close input) (sb-posix:close fd)))
    ;; Bind index and term as well as digest, including after process restart.
    (validate-store-snapshot path :expected-index (fourth reference) :expected-term (sixth reference))
    path))

(defun retain-store-snapshot-artifact (root source index term digest)
  "Durably retain verified bytes before a caller writes their reference to the WAL.
Copies in 64 KiB buffers, validates the private copy, then publishes without replacing
an existing artifact. Returns its pathname and portable reference. No garbage collection
is performed: WAL snapshots, retained suffixes and transfers may still depend on it."
  (let* ((reference (store-snapshot-artifact-reference index term digest))
         (directory (store-snapshot-registry-directory root))
         (target (merge-pathnames (format nil "~A.jsonl" digest) directory))
         (temporary (merge-pathnames (format nil "~A.part" (generate-uid)) directory)))
    (unwind-protect
         (progn
           (copy-snapshot-generation-source (pathname source) temporary digest)
           (validate-store-snapshot temporary :expected-index index :expected-term term)
           ;; LINK is atomic and refuses overwrite. Concurrent identical retainers
           ;; can share the winner, but an invalid existing file is never replaced.
           (handler-case (sb-posix:link (namestring temporary) (namestring target))
             (sb-posix:syscall-error (condition)
               (unless (= sb-posix:eexist (sb-posix:syscall-errno condition)) (error condition))))
           (checked-store-snapshot-artifact-path root reference)
           (gr8s.store::sync-store-generation-directory directory)
           (values target reference))
      (when (probe-file temporary) (delete-file temporary)))))
