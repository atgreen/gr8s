;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Pin canonical bencoding and BEP 52 single-blob metadata before the image
;;;; distribution implementation is allowed to join a swarm.

(in-package #:gr8s/tests)

(defun bt-octets (text)
  (trivial-utf-8:string-to-utf-8-bytes text))

(defun bt-text (octets)
  (trivial-utf-8:utf-8-bytes-to-string octets))

(defun bt-temp-file (octets)
  (let ((path (merge-pathnames
               (format nil "gr8s-torrent-v2-~36R.blob" (random most-positive-fixnum))
               (uiop:temporary-directory))))
    (with-open-file (stream path :direction :output :if-exists :error
                                 :element-type '(unsigned-byte 8))
      (write-sequence octets stream))
    path))

(defun bt-concatenate (&rest vectors)
  (apply #'concatenate '(vector (unsigned-byte 8)) vectors))

(test bencode-is-canonical-and-binary-safe
  (let* ((dictionary
           (gr8s.image-distribution::bencode-dictionary
            (list (cons "spam" "eggs")
                  (cons "cow" "moo")
                  (cons #(0 255) #(1 2 3)))))
         (encoded (gr8s.image-distribution::encode-bencode dictionary))
         (decoded (gr8s.image-distribution::decode-bencode encoded)))
    (is (equalp (bt-octets "d2:") (subseq encoded 0 3)))
    (is (equalp #(1 2 3)
                (gr8s.image-distribution::bencode-value decoded #(0 255))))
    (is (string= "moo"
                 (bt-text (gr8s.image-distribution::bencode-value decoded "cow"))))
    (is (string= "eggs"
                 (bt-text (gr8s.image-distribution::bencode-value decoded "spam"))))))

(test bencode-rejects-noncanonical-input
  (signals error
    (gr8s.image-distribution::decode-bencode (bt-octets "i03e")))
  (signals error
    (gr8s.image-distribution::decode-bencode (bt-octets "d4:spam1:a3:cow1:be")))
  (signals error
    (gr8s.image-distribution::decode-bencode (bt-octets "1:aJUNK"))))

(test torrent-v2-builds-the-bep-52-merkle-tree
  (let* ((bytes (make-array 16385 :element-type '(unsigned-byte 8) :initial-element 0))
         (path (bt-temp-file bytes)))
    (unwind-protect
         (let* ((oci-hash (ironclad:digest-sequence :sha256 bytes))
                (digest (format nil "sha256:~A" (ironclad:byte-array-to-hex-string oci-hash)))
                (torrent (gr8s.image-distribution::make-oci-blob-torrent
                          path digest 16384))
                (leaf-0 (ironclad:digest-sequence :sha256 (subseq bytes 0 16384)))
                (leaf-1 (ironclad:digest-sequence :sha256 (subseq bytes 16384)))
                (root (ironclad:digest-sequence :sha256
                                                (bt-concatenate leaf-0 leaf-1))))
           (is (= 16385 (gr8s.image-distribution::blob-torrent-length torrent)))
           (is (= 16384 (gr8s.image-distribution::torrent-piece-length torrent)))
           (is (= 32 (length (gr8s.image-distribution::torrent-infohash torrent))))
           ;; cl-torrent builds the BEP 52 metadata; gr8s only pins that the
           ;; canonical piece layer matches the OCI blob's bytes.
           (let* ((metainfo (gr8s.image-distribution::decode-bencode
                             (gr8s.image-distribution::torrent-metainfo torrent)))
                  (layers (gr8s.image-distribution::bencode-value metainfo "piece layers")))
             (is (equalp (bt-concatenate leaf-0 leaf-1)
                         (gr8s.image-distribution::bencode-value layers root)))))
      (ignore-errors (delete-file path)))))

(test torrent-v2-validates-oci-digest-and-piece-length
  (let ((path (bt-temp-file #(1 2 3))))
    (unwind-protect
         (progn
           (signals error
             (gr8s.image-distribution::make-oci-blob-torrent
              path (format nil "sha256:~64,'0X" 0) 16384))
           (signals error
             (gr8s.image-distribution::make-oci-blob-torrent
              path "sha256:039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"
              20000)))
      (ignore-errors (delete-file path)))))

(test torrent-v2-final-metainfo-reconstructs-download-piece-hashes
  (let* ((bytes (make-array 33000 :element-type '(unsigned-byte 8)
                                  :initial-element 7))
         (path (bt-temp-file bytes))
         (digest (format nil "sha256:~A"
                         (ironclad:byte-array-to-hex-string
                          (ironclad:digest-sequence :sha256 bytes)))))
    (unwind-protect
         (let* ((built (gr8s.image-distribution::make-oci-blob-torrent
                        path digest 16384))
                (parsed (gr8s.image-distribution::parse-oci-blob-torrent
                         (gr8s.image-distribution::torrent-metainfo built)
                         digest)))
           (is (equalp (gr8s.image-distribution::torrent-infohash built)
                       (gr8s.image-distribution::torrent-infohash parsed)))
           ;; Parsing re-derives and verifies the download piece hashes; an
           ;; exact metainfo round-trip is the observable proof.
           (is (equalp (gr8s.image-distribution::torrent-metainfo built)
                       (gr8s.image-distribution::torrent-metainfo parsed))))
      (ignore-errors (delete-file path)))))
