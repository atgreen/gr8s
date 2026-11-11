;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Define the private OCI image-distribution package.
;;;;
;;;; The generic torrent primitives gr8s shares with the standalone cl-torrent
;;;; library (installed via ocicl) -- the bencoding codec and the peer-wire
;;;; handshake/message codec, which are byte-for-byte the extracted originals --
;;;; now come from cl-torrent, re-homed here before the files that use them.  The
;;;; OCI/BEP52-specific layer (blob torrents, the image tracker, the BEP52 piece
;;;; store and the OCI cache/mirror) stays in gr8s: it is a specialization of,
;;;; not covered by, the general library.

(defpackage #:gr8s.image-distribution
  (:use #:cl))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((symbols (mapcar (lambda (name)
                           (or (find-symbol name '#:cl-torrent)
                               (error "cl-torrent does not provide ~A, which gr8s requires." name)))
                         '(;; Bencoding codec.
                           "DECODE-BENCODE" "ENCODE-BENCODE" "BENCODE-DICTIONARY"
                           "BENCODE-VALUE" "BENCODE-MAP" "BENCODE-ERROR" "AS-OCTETS"
                           ;; Peer-wire handshake/message codec and its wire structs.
                           "PEER-HANDSHAKE" "MAKE-PEER-HANDSHAKE"
                           "PEER-HANDSHAKE-INFOHASH" "PEER-HANDSHAKE-PEER-ID"
                           "ENCODE-PEER-HANDSHAKE" "DECODE-PEER-HANDSHAKE"
                           "PEER-MESSAGE" "MAKE-PEER-MESSAGE"
                           "PEER-MESSAGE-KIND" "PEER-MESSAGE-PIECE" "PEER-MESSAGE-BEGIN"
                           "PEER-MESSAGE-LENGTH" "PEER-MESSAGE-PAYLOAD"
                           "ENCODE-PEER-MESSAGE" "DECODE-PEER-MESSAGE"
                           ;; Canonical BEP 52 metadata and its single-blob API.
                           "TORRENT" "MAKE-BLOB-TORRENT" "PARSE-BLOB-METAINFO"
                           "BLOB-TORRENT-P" "BLOB-TORRENT-FILE" "BLOB-TORRENT-LENGTH"
                           "BLOB-TORRENT-CONTENT-ID"
                           "TORRENT-CONTENT-ID" "TORRENT-INFOHASH" "TORRENT-METAINFO"
                           "TORRENT-PIECE-LENGTH" "TORRENT-PIECE-COUNT" "TORRENT-PIECE-SIZE"
                           ;; Verifying piece store.
                           "OPEN-PIECE-STORE" "OPEN-BLOB-STORE" "ACCEPT-BLOCK"
                           "COMPLETED-PIECES" "PIECE-STORE-COMPLETE-P"))))
    (shadowing-import symbols '#:gr8s.image-distribution)))
