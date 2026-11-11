;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.image-distribution)

(defconstant +tracker-metainfo-chunk-bytes+ 49152)
(defconstant +tracker-metainfo-inline-bytes+ (* 3 512 1024))

(defun tracker-chunked-swarm-record-p (record)
  (and (equal "imageTrackerSwarm" (gethash "kind" record))
       (equal "chunks-v1" (gethash "metainfoFormat" record))))

(defstruct tracker-metainfo-input header stream hash (received 0))

(defun close-tracker-metainfo-input (input)
  (when (and input (tracker-metainfo-input-stream input))
    (let ((stream (tracker-metainfo-input-stream input)))
      (setf (tracker-metainfo-input-stream input) nil)
      ;; Discard pending scratch writes before normal close. ABORT on a stream
      ;; associated with /proc/self/fd would attempt to unlink that pseudo-path.
      (unwind-protect (clear-output stream) (close stream)))))

(defun start-tracker-metainfo-input (header directory)
  "Own one anonymous, close-on-exec spool; retain no metainfo payload in RAM."
  (let ((fd nil) (stream nil) (transferred nil))
    (unwind-protect
         (progn
           ;; Linux O_TMPFILE | O_DIRECTORY and O_CLOEXEC, as in the Raft cache.
           ;; No scratch pathname survives a failed validation or process crash.
           (setf fd (sb-posix:open (namestring (uiop:ensure-directory-pathname directory))
                                   (logior sb-posix:o-rdwr #o20200000 #o2000000) #o600)
                 stream (sb-sys:make-fd-stream fd :input t :output t
                                              :file (format nil "/proc/self/fd/~D" fd)
                                              :element-type '(unsigned-byte 8) :auto-close t)
                 fd nil)
           (prog1
               (make-tracker-metainfo-input
                :header (image-tracker-object "digest" (gethash "digest" header)
                                              "infohash" (gethash "infohash" header)
                                              "metainfoBytes" (gethash "metainfoBytes" header)
                                              "metainfoSha256" (gethash "metainfoSha256" header))
                :stream stream :hash (ironclad:make-digest :sha256))
             (setf transferred t)))
      (unless transferred
        (cond (stream (close stream))
              (fd (sb-posix:close fd)))))))

(defun feed-tracker-metainfo-input (input record consumer)
  "Validate one ordered chunk. Call CONSUMER only after full semantic validation.
Returns true when the complete blob has been validated and its spool closed."
  (let* ((header (tracker-metainfo-input-header input))
         (stream (tracker-metainfo-input-stream input))
         (bytes (tracker-record-octets record "data"))
         (received (tracker-metainfo-input-received input))
         (total (gethash "metainfoBytes" header)))
    (unless (and (equal (gethash "digest" header) (gethash "digest" record))
                 (= received (gethash "offset" record))
                 (<= (+ received (length bytes)) total))
      (error "Out-of-order or oversized tracker metainfo chunk"))
    (write-sequence bytes stream)
    (ironclad:update-digest (tracker-metainfo-input-hash input) bytes)
    (incf (tracker-metainfo-input-received input) (length bytes))
    (when (= total (tracker-metainfo-input-received input))
      (unwind-protect
           (progn
             (unless (equal (gethash "metainfoSha256" header)
                            (ironclad:byte-array-to-hex-string
                             (ironclad:produce-digest (tracker-metainfo-input-hash input))))
               (error "Tracker metainfo content checksum mismatch"))
             (finish-output stream)
             (validate-tracker-metainfo-stream stream total (gethash "digest" header)
                                               (tracker-record-octets header "infohash" 32))
             (when consumer
               (file-position stream 0)
               (funcall consumer header stream total))
             t)
        (close-tracker-metainfo-input input)))))
