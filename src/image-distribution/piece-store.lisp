;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.image-distribution)

(defstruct (piece-store (:constructor %make-piece-store))
  torrent pathname completed received-blocks
  (lock (bt:make-lock "gr8s BitTorrent piece store")))

(defun torrent-piece-count (torrent)
  (length (blob-torrent-piece-hashes torrent)))

(defun torrent-piece-size (torrent piece)
  (let ((offset (* piece (blob-torrent-piece-length torrent))))
    (min (blob-torrent-piece-length torrent)
         (- (blob-torrent-length torrent) offset))))

(defun piece-block-count (torrent piece)
  (ceiling (torrent-piece-size torrent piece) +peer-block-length+))

(defun ensure-piece-file (pathname length resume-p)
  (let ((existing-length
          (and resume-p (probe-file pathname)
               (with-open-file (stream pathname :direction :input
                                                :element-type '(unsigned-byte 8))
                 (file-length stream)))))
    (unless (eql existing-length length)
      (with-open-file (stream pathname :direction :output
                                       :if-exists :supersede
                                       :if-does-not-exist :create
                                       :element-type '(unsigned-byte 8))
        (when (plusp length)
          (file-position stream (1- length))
          (write-byte 0 stream))))))

(defun hash-file-region-as-bep52-piece (pathname start length piece-length)
  (with-open-file (stream pathname :direction :input
                                   :element-type '(unsigned-byte 8))
    (file-position stream start)
    (let ((remaining length)
          (leaves nil))
      (loop while (plusp remaining)
            for count = (min remaining +torrent-v2-block-length+)
            for bytes = (make-array count :element-type '(unsigned-byte 8))
            do (unless (= count (read-sequence bytes stream))
                 (error "Torrent piece file ended unexpectedly"))
               (push (ironclad:digest-sequence :sha256 bytes) leaves)
               (decf remaining count))
      (let ((level (pad-merkle-level
                    (coerce (nreverse leaves) 'vector)
                    (/ piece-length +torrent-v2-block-length+))))
        (loop while (> (length level) 1)
              do (setf level (merkle-parent-level level)))
        (aref level 0)))))

(defun piece-hash-valid-p (store piece)
  (let* ((torrent (piece-store-torrent store))
         (actual (hash-file-region-as-bep52-piece
                  (piece-store-pathname store)
                  (* piece (blob-torrent-piece-length torrent))
                  (torrent-piece-size torrent piece)
                  (blob-torrent-piece-length torrent)))
         (expected (aref (blob-torrent-piece-hashes torrent) piece)))
    (ironclad:constant-time-equal actual expected)))

(defun make-piece-store (torrent pathname &key resume-p)
  "Create or resume a sparse destination, trusting only verified whole pieces."
  (let* ((count (torrent-piece-count torrent))
         (completed (make-array count :element-type 'bit :initial-element 0))
         (received
           (loop for piece below count
                 collect (make-array (piece-block-count torrent piece)
                                     :element-type 'bit :initial-element 0))))
    (ensure-piece-file pathname (blob-torrent-length torrent) resume-p)
    (let ((store (%make-piece-store :torrent torrent :pathname pathname
                                    :completed completed
                                    :received-blocks (coerce received 'vector))))
      (when resume-p
        (loop for piece below count
              when (piece-hash-valid-p store piece)
                do (setf (aref completed piece) 1)
                   (fill (aref (piece-store-received-blocks store) piece) 1)))
      store)))

(defun piece-store-complete-p (store)
  (every (lambda (value) (= value 1)) (piece-store-completed store)))

(defun piece-store-accept-block (store piece begin payload)
  "Write one requested block and publish its piece only after BEP 52 verification."
  (bt:with-lock-held ((piece-store-lock store))
    (let* ((torrent (piece-store-torrent store))
           (piece-count (torrent-piece-count torrent)))
      (unless (typep piece `(integer 0 (,piece-count)))
        (error "BitTorrent piece index is out of range"))
      (let* ((piece-size (torrent-piece-size torrent piece))
             (block (floor begin +peer-block-length+))
             (expected-length (min +peer-block-length+ (- piece-size begin))))
        (unless (and (zerop (mod begin +peer-block-length+))
                     (<= 0 begin) (< begin piece-size)
                     (= expected-length (length payload)))
          (error "BitTorrent block does not match the requested piece geometry"))
        (with-open-file (stream (piece-store-pathname store)
                                :direction :io :if-exists :overwrite
                                :element-type '(unsigned-byte 8))
          (file-position stream (+ (* piece (blob-torrent-piece-length torrent)) begin))
          (write-sequence payload stream)
          (finish-output stream))
        (setf (aref (aref (piece-store-received-blocks store) piece) block) 1)
        (if (not (every (lambda (value) (= value 1))
                        (aref (piece-store-received-blocks store) piece)))
            :accepted
            (if (piece-hash-valid-p store piece)
                (progn (setf (aref (piece-store-completed store) piece) 1)
                       :complete)
                (progn
                  (setf (aref (piece-store-completed store) piece) 0)
                  (fill (aref (piece-store-received-blocks store) piece) 0)
                  :corrupt)))))))
