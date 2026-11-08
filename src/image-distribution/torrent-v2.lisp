;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.image-distribution)

(defconstant +torrent-v2-block-length+ 16384)

(defstruct blob-torrent
  "Canonical BEP 52 metadata and verified hashes for one OCI blob."
  metainfo info infohash pieces-root piece-hashes length piece-length oci-digest)

(defun power-of-two-p (number)
  (and (plusp number) (zerop (logand number (1- number)))))

(defun torrent-sha256 (&rest octet-vectors)
  (ironclad:digest-sequence
   :sha256 (apply #'concatenate '(vector (unsigned-byte 8)) octet-vectors)))

(defun read-bep52-leaves (pathname)
  "Hash PATHNAME as BEP 52's sequence of 16KiB leaf blocks."
  (with-open-file (stream pathname :direction :input
                                   :element-type '(unsigned-byte 8))
    (let ((buffer (make-array +torrent-v2-block-length+
                              :element-type '(unsigned-byte 8)))
          (leaves nil))
      (loop for count = (read-sequence buffer stream)
            while (plusp count)
            do (push (ironclad:digest-sequence :sha256 buffer :end count) leaves))
      (coerce (nreverse leaves) 'vector))))

(defun pad-merkle-level (hashes &optional (minimum-length 1))
  "Pad HASHES with zero leaf hashes to its next power-of-two length."
  (if (zerop (length hashes)) hashes
      (let* ((length (length hashes))
             (target (max minimum-length
                          (ash 1 (ceiling (log length 2)))))
             (result (make-array target)))
        (replace result hashes)
        (loop for index from length below target
              do (setf (aref result index)
                       (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 0)))
        result)))

(defun merkle-parent-level (hashes)
  (let ((parents (make-array (/ (length hashes) 2))))
    (loop for index below (length parents)
          do (setf (aref parents index)
                   (torrent-sha256 (aref hashes (* index 2))
                                   (aref hashes (1+ (* index 2))))))
    parents))

(defun bep52-tree (leaves piece-length file-length)
  "Return the pieces root and the non-padding hashes at the piece layer."
  (when (plusp file-length)
    (let* ((leaves-per-piece (/ piece-length +torrent-v2-block-length+))
           (piece-count (ceiling file-length piece-length))
           ;; BEP 52 pads a short final piece to the piece boundary before
           ;; deriving its root, even when the entire file is one 16KiB leaf.
           (level (pad-merkle-level leaves leaves-per-piece)))
      (loop repeat (integer-length (1- leaves-per-piece))
            do (setf level (merkle-parent-level level)))
      (let ((piece-hashes (subseq level 0 piece-count)))
        (loop while (> (length level) 1)
              do (setf level (merkle-parent-level level)))
        (values (aref level 0) piece-hashes)))))

(defun concatenate-hashes (hashes)
  (let ((result (make-array (* 32 (length hashes))
                            :element-type '(unsigned-byte 8))))
    (loop for hash across hashes for offset from 0 by 32
          do (replace result hash :start1 offset))
    result))

(defun parse-oci-sha256 (digest)
  (unless (and (= (length digest) 71)
               (string-equal "sha256:" digest :end2 7)
               (every (lambda (character) (digit-char-p character 16))
                      (subseq digest 7)))
    (error "OCI blob digest must be sha256 followed by 64 hexadecimal digits"))
  (ironclad:hex-string-to-byte-array digest :start 7))

(defun make-oci-blob-torrent (pathname digest piece-length)
  "Verify PATHNAME as OCI DIGEST and construct deterministic single-file BEP 52 metadata."
  (unless (and (>= piece-length +torrent-v2-block-length+)
               (power-of-two-p piece-length))
    (error "BitTorrent piece length must be a power of two of at least 16384 bytes"))
  (let ((expected (parse-oci-sha256 digest))
        (actual (ironclad:digest-file :sha256 pathname)))
    (unless (ironclad:constant-time-equal expected actual)
      (error "OCI blob digest does not match ~A" pathname))
    (let* ((length (with-open-file (stream pathname :direction :input
                                                    :element-type '(unsigned-byte 8))
                     (file-length stream)))
           (leaves (read-bep52-leaves pathname)))
      (multiple-value-bind (pieces-root piece-hashes)
          (bep52-tree leaves piece-length length)
        (let* ((hex (string-downcase (subseq digest 7)))
               (properties
                 (bencode-dictionary
                  (append (list (cons "length" length))
                          (when pieces-root
                            (list (cons "pieces root" pieces-root))))))
               (file-tree
                 (bencode-dictionary
                  (list (cons hex
                              (bencode-dictionary
                               (list (cons #() properties)))))))
               (info
                 (bencode-dictionary
                  (list (cons "file tree" file-tree)
                        (cons "meta version" 2)
                        (cons "name" hex)
                        (cons "piece length" piece-length))))
               (infohash (torrent-sha256 (encode-bencode info)))
               (piece-layers
                 (bencode-dictionary
                  (if (> length piece-length)
                      (list (cons pieces-root (concatenate-hashes piece-hashes)))
                      nil)))
               (metainfo
                 (bencode-dictionary
                  (list (cons "announce" "gr8s://tracker")
                        (cons "info" info)
                        (cons "piece layers" piece-layers)))))
          (make-blob-torrent
           :metainfo (encode-bencode metainfo)
           :info info
           :infohash infohash
           :pieces-root pieces-root
           :piece-hashes (or piece-hashes #())
           :length length
           :piece-length piece-length
           :oci-digest (format nil "sha256:~A" hex)))))))

(defun split-piece-layer (octets piece-count)
  (unless (= (length octets) (* 32 piece-count))
    (error "BEP 52 piece layer has the wrong length"))
  (let ((hashes (make-array piece-count)))
    (dotimes (index piece-count hashes)
      (setf (aref hashes index)
            (subseq octets (* index 32) (* (1+ index) 32))))))

(defun parse-oci-blob-torrent (metainfo digest)
  "Validate final canonical METINFO for DIGEST and reconstruct its verified
piece geometry for the peer engine."
  (let* ((digest (canonical-oci-digest digest))
         (root (decode-bencode metainfo))
         (info (bencode-value root "info"))
         (canonical (encode-bencode root))
         (hex (subseq digest 7))
         (file (bencode-value (bencode-value info "file tree") hex))
         (properties (and file (bencode-value file #())))
         (length (and properties (bencode-value properties "length")))
         (pieces-root (and properties (bencode-value properties "pieces root")))
         (piece-length (bencode-value info "piece length"))
         (piece-count (and length (ceiling length piece-length)))
         (layers (bencode-value root "piece layers"))
         (layer (and pieces-root (bencode-value layers pieces-root)))
         (piece-hashes
           (cond ((zerop (or length 0)) #())
                 ((= piece-count 1) (vector pieces-root))
                 (layer (split-piece-layer layer piece-count))
                 (t (error "BEP 52 metadata omits its required piece layer")))))
    (unless (equalp canonical metainfo)
      (error "Torrent metadata must use canonical bencoding"))
    (unless (and (= 2 (bencode-value info "meta version" 0))
                 (equalp (bencode-value info "name")
                         (trivial-utf-8:string-to-utf-8-bytes hex))
                 (integerp length) (not (minusp length))
                 (integerp piece-length) (power-of-two-p piece-length)
                 (>= piece-length +torrent-v2-block-length+)
                 (or (zerop length) (= 32 (length pieces-root))))
      (error "Invalid BEP 52 OCI blob metadata for ~A" digest))
    (make-blob-torrent
     :metainfo (copy-seq metainfo) :info info
     :infohash (torrent-sha256 (encode-bencode info))
     :pieces-root pieces-root :piece-hashes piece-hashes
     :length length :piece-length piece-length :oci-digest digest)))
