;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; gr8s OCI-blob torrents over the cl-torrent single-blob API.  cl-torrent
;;;; provides the canonical BEP 52 metadata, the Merkle-tree verification and the
;;;; piece store; gr8s owns only the OCI contract -- binding each torrent to its
;;;; sha256 digest and checking that the local blob actually hashes to that
;;;; digest before it is published to the swarm.

(in-package #:gr8s.image-distribution)

(defun parse-oci-sha256 (digest)
  "Return DIGEST's 32 raw bytes, requiring the canonical \"sha256:<64 hex>\" form."
  (unless (and (= (length digest) 71)
               (string-equal "sha256:" digest :end2 7)
               (every (lambda (character) (digit-char-p character 16))
                      (subseq digest 7)))
    (error "OCI blob digest must be sha256 followed by 64 hexadecimal digits"))
  (ironclad:hex-string-to-byte-array digest :start 7))

(defun make-oci-blob-torrent (pathname digest piece-length)
  "Verify PATHNAME hashes to the OCI DIGEST, then build its single-blob BEP 52
torrent bound to that digest.  The metadata and Merkle tree come from cl-torrent;
only the sha256/digest contract is gr8s's."
  (let ((expected (parse-oci-sha256 digest))
        (actual (ironclad:digest-file :sha256 pathname)))
    (unless (ironclad:constant-time-equal expected actual)
      (error "OCI blob digest does not match ~A" pathname)))
  (let ((canonical (canonical-oci-digest digest)))
    ;; The in-torrent filename is the bare sha256 hex; the tracker's metainfo
    ;; validator binds both the info name and the file-tree entry to it.
    (cl-torrent:make-blob-torrent pathname :piece-length piece-length
                                           :content-id canonical
                                           :name (subseq canonical 7))))

(defun parse-oci-blob-torrent (metainfo digest)
  "Parse canonical METAINFO into a single-blob torrent, requiring that the digest
it carries is DIGEST."
  (let ((digest (canonical-oci-digest digest))
        (torrent (cl-torrent:parse-blob-metainfo metainfo)))
    (unless (equal digest (cl-torrent:blob-torrent-content-id torrent))
      (error "OCI blob torrent is bound to ~A, not ~A"
             (cl-torrent:blob-torrent-content-id torrent) digest))
    torrent))
