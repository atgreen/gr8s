;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.server)

(defparameter +backup-stream-magic+ (trivial-utf-8:string-to-utf-8-bytes "GR8SBK01"))
(defconstant +backup-frame-limit+ 65536)
(defstruct (backup-stream (:constructor %make-backup-stream))
  stream key header writer-p (owner (bt:current-thread)) (sequence 0) finished-p failed-p)

(defun backup-octets-p (value length)
  (and (typep value '(simple-array (unsigned-byte 8) (*))) (= length (length value))))

(defun backup-big-endian (value bytes)
  (unless (typep value `(unsigned-byte ,(* 8 bytes))) (error "Backup integer out of range"))
  (let ((result (make-array bytes :element-type '(unsigned-byte 8))))
    (dotimes (i bytes result) (setf (aref result i) (ldb (byte 8 (* 8 (- bytes i 1))) value)))))

(defun backup-read-exactly (stream size)
  (let ((buffer (make-array size :element-type '(unsigned-byte 8))))
    (unless (= size (read-sequence buffer stream)) (error "Truncated backup stream"))
    buffer))

(defun derive-backup-stream-key (master salt)
  (unless (backup-octets-p master 32) (error "Backup encryption key must contain exactly 32 bytes"))
  (ironclad:derive-key
   (ironclad:make-kdf :hmac-kdf :digest :sha256
                      :additional-data (trivial-utf-8:string-to-utf-8-bytes "gr8s backup chunk key v1"))
   master salt 1 32))

(defun open-backup-writer (stream master)
  (let* ((salt (ironclad:random-data 32))
         (header (concatenate '(vector (unsigned-byte 8)) +backup-stream-magic+ salt))
         (key (derive-backup-stream-key master salt)))
    (write-sequence header stream)
    (%make-backup-stream :stream stream :key key :header header :writer-p t)))

(defun open-backup-reader (stream master)
  (let ((header (backup-read-exactly stream 40)))
    (unless (equalp +backup-stream-magic+ (subseq header 0 8)) (error "Unsupported backup stream format"))
    (%make-backup-stream :stream stream :header header :key (derive-backup-stream-key master (subseq header 8)))))

(defun backup-frame-mode (state prefix &optional tag)
  (let* ((sequence (backup-stream-sequence state))
         (counter (backup-big-endian sequence 8))
         (nonce (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; At most 2^32 invocations per derived key; reserve the last for finalization.
    (unless (< sequence (if (= 1 (aref prefix 4)) #x100000000 #xffffffff))
      (error "Backup stream frame limit exhausted"))
    (replace nonce counter :start1 4)
    (values (ironclad:make-authenticated-encryption-mode
             :gcm :cipher-name :aes :key (backup-stream-key state)
             :initialization-vector nonce :tag tag)
            (concatenate '(vector (unsigned-byte 8)) (backup-stream-header state) counter prefix))))

(defun require-backup-stream (state writer-p)
  (unless (and (eq (bt:current-thread) (backup-stream-owner state))
               (eq writer-p (backup-stream-writer-p state))
               (not (backup-stream-failed-p state)) (not (backup-stream-finished-p state)))
    (error "Backup stream is not available for this operation")))

(defun write-backup-frame (state payload kind)
  (handler-case
      (progn
        (require-backup-stream state t)
        (unless (and (typep payload '(simple-array (unsigned-byte 8) (*)))
                     (<= 1 (length payload) +backup-frame-limit+))
          (error "Backup frame must contain 1 to 65536 bytes"))
        (let ((prefix (concatenate '(vector (unsigned-byte 8)) (backup-big-endian (length payload) 4) (vector kind))))
          (multiple-value-bind (mode aad) (backup-frame-mode state prefix)
            (let ((ciphertext (ironclad:encrypt-message mode payload :associated-data aad))
                  (stream (backup-stream-stream state)))
              (write-sequence prefix stream)
              (write-sequence ciphertext stream)
              (write-sequence (ironclad:produce-tag mode) stream)
              (incf (backup-stream-sequence state))))))
    (error (condition) (setf (backup-stream-failed-p state) t) (error condition))))

(defun write-backup-record (state payload)
  (write-backup-frame state payload 0))

(defun finish-backup-writer (state)
  ;; A one-byte sentinel avoids ambiguous empty data/final records.
  (handler-case
      (progn
        (write-backup-frame state (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0) 1)
        (finish-output (backup-stream-stream state))
        (setf (backup-stream-finished-p state) t))
    (error (condition) (setf (backup-stream-failed-p state) t) (error condition))))

(defun read-backup-record (state)
  "Return one authenticated plaintext record, or NIL only after verified final EOF.
Earlier records are not proof of a complete bundle: callers stage all writes until
this function verifies the end marker. Any error permanently poisons the reader."
  (when (and (eq (bt:current-thread) (backup-stream-owner state))
             (backup-stream-finished-p state) (not (backup-stream-writer-p state))
             (not (backup-stream-failed-p state)))
    (return-from read-backup-record nil))
  (handler-case
      (progn
        (require-backup-stream state nil)
        (let* ((stream (backup-stream-stream state))
               (prefix (backup-read-exactly stream 5))
               (length (loop for i below 4 for result = (aref prefix i) then (+ (ash result 8) (aref prefix i)) finally (return result)))
               (kind (aref prefix 4)))
          (unless (and (member kind '(0 1)) (<= 1 length +backup-frame-limit+)
                       (or (zerop kind) (= 1 length)))
            (error "Invalid backup frame header"))
          (let ((ciphertext (backup-read-exactly stream length))
                (tag (backup-read-exactly stream 16)))
            (multiple-value-bind (mode aad) (backup-frame-mode state prefix tag)
              (let ((plaintext (ironclad:decrypt-message mode ciphertext :associated-data aad)))
                (incf (backup-stream-sequence state))
                (if (zerop kind) plaintext
                    (progn
                      (unless (and (zerop (aref plaintext 0)) (null (read-byte stream nil nil)))
                        (error "Invalid backup final marker or trailing data"))
                      (setf (backup-stream-finished-p state) t)
                      nil)))))))
    (error (condition) (setf (backup-stream-failed-p state) t) (error condition))))
