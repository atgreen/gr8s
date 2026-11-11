;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite backup-stream :in gr8s)
(in-suite backup-stream)

(defun backup-test-key () (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42))
(defun make-test-backup-stream (&rest records)
  (flexi-streams:with-output-to-sequence (out)
    (let ((writer (gr8s.server::open-backup-writer out (backup-test-key))))
      (dolist (record records) (gr8s.server::write-backup-record writer record))
      (gr8s.server::finish-backup-writer writer))))
(defun read-test-backup-stream (bytes &optional (key (backup-test-key)))
  (flexi-streams:with-input-from-sequence (in bytes)
    (let ((reader (gr8s.server::open-backup-reader in key)))
      (loop for record = (gr8s.server::read-backup-record reader) while record collect record))))

(test backup-encryption-roundtrips-bounded-records-and-empty-streams
  (let* ((message (trivial-utf-8:string-to-utf-8-bytes "private cluster identity and credentials"))
         (large (make-array 65536 :element-type '(unsigned-byte 8) :initial-element 99))
         (bundle (make-test-backup-stream message large)))
    (is (equalp (list message large) (read-test-backup-stream bundle)))
    (is (null (search message bundle)))
    (is (not (equalp bundle (make-test-backup-stream message large))))
    (is (null (read-test-backup-stream (make-test-backup-stream))))))

(test backup-encryption-rejects-every-truncated-prefix-and-single-byte-tampering
  (let ((bundle (make-test-backup-stream (make-array 3 :element-type '(unsigned-byte 8) :initial-element 7))))
    (dotimes (end (length bundle))
      (signals error (read-test-backup-stream (subseq bundle 0 end))))
    (dotimes (i (length bundle))
      (let ((changed (copy-seq bundle)))
        (setf (aref changed i) (logxor 1 (aref changed i)))
        (signals error (read-test-backup-stream changed))))))

(test backup-encryption-rejects-wrong-key-trailing-bytes-and-frame-reordering
  (let* ((bundle (make-test-backup-stream
                  (make-array 3 :element-type '(unsigned-byte 8) :initial-element 1)
                  (make-array 3 :element-type '(unsigned-byte 8) :initial-element 2)))
         (first (subseq bundle 40 64)) (second (subseq bundle 64 88))
         (footer (subseq bundle 88)))
    (signals error (read-test-backup-stream bundle (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (signals error (read-test-backup-stream (concatenate '(vector (unsigned-byte 8)) bundle #(0))))
    (dolist (records (list (list second first) (list first first second) (list second)))
      (signals error (read-test-backup-stream
                      (apply #'concatenate '(vector (unsigned-byte 8)) (subseq bundle 0 40)
                             (append records (list footer))))))))

(test backup-encryption-bounds-lengths-and-poisons-failed-readers
  (let ((bundle (make-test-backup-stream (make-array 1 :element-type '(unsigned-byte 8) :initial-element 4))))
    (setf (aref bundle 40) 255)
    (flexi-streams:with-input-from-sequence (in bundle)
      (let ((reader (gr8s.server::open-backup-reader in (backup-test-key))))
        (signals error (gr8s.server::read-backup-record reader))
        (is (= 45 (file-position in)))
        (signals error (gr8s.server::read-backup-record reader))
        (is (= 45 (file-position in)))))))

(test backup-encryption-rejects-invalid-writes-and-counter-exhaustion
  (dolist (size '(0 65537))
    (flexi-streams:with-output-to-sequence (out)
      (let ((writer (gr8s.server::open-backup-writer out (backup-test-key))))
        (signals error (gr8s.server::write-backup-record writer (make-array size :element-type '(unsigned-byte 8))))
        (is (gr8s.server::backup-stream-failed-p writer)))))
  (flexi-streams:with-output-to-sequence (out)
    (let ((writer (gr8s.server::open-backup-writer out (backup-test-key))))
      (setf (gr8s.server::backup-stream-sequence writer) #x100000000)
      (signals error (gr8s.server::finish-backup-writer writer))))
  (flexi-streams:with-output-to-sequence (out)
    (let ((writer (gr8s.server::open-backup-writer out (backup-test-key))))
      (gr8s.server::finish-backup-writer writer)
      (signals error (gr8s.server::write-backup-record writer (make-array 1 :element-type '(unsigned-byte 8)))))))

(test backup-stream-is-thread-confined-before-any-frame-is-written
  (flexi-streams:with-output-to-sequence (out)
    (let ((writer (gr8s.server::open-backup-writer out (backup-test-key))) (rejected nil))
      (bt:join-thread
       (bt:make-thread
        (lambda ()
          (handler-case (gr8s.server::write-backup-record writer (make-array 1 :element-type '(unsigned-byte 8)))
            (error () (setf rejected t))))))
      (is (not (null rejected)))
      (is (zerop (gr8s.server::backup-stream-sequence writer)))
      (is (gr8s.server::backup-stream-failed-p writer)))))
