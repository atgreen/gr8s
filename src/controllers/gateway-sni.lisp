;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Peek the Server Name Indication (SNI) out of a TLS ClientHello without
;;;; terminating the connection. This is what lets the Gateway data plane route
;;;; TLS and TLSRoute/GRPCRoute traffic by hostname at L4 (SNI passthrough) and
;;;; pick the right listener certificate, parsing only the first flight of bytes.
;;;;
;;;; Pure byte parsing over the TLS record + handshake structure (RFC 8446 /
;;;; RFC 6066); it never allocates per byte and fails closed (returns NIL) on any
;;;; truncation or malformed length rather than erroring.

(in-package #:gr8s.controllers)

(defun gw-u16 (bytes offset)
  "Return the big-endian unsigned 16-bit integer at OFFSET in BYTES."
  (logior (ash (aref bytes offset) 8) (aref bytes (1+ offset))))

(defun gw-u24 (bytes offset)
  "Return the big-endian unsigned 24-bit integer at OFFSET in BYTES."
  (logior (ash (aref bytes offset) 16)
          (ash (aref bytes (+ offset 1)) 8)
          (aref bytes (+ offset 2))))

(defmacro gw-sni-need (bytes end)
  "Return NIL from the enclosing function unless END bytes are available."
  `(when (> ,end (length ,bytes)) (return-from parse-tls-client-hello-sni nil)))

(defun parse-tls-client-hello-sni (bytes)
  "Return the SNI host_name from a TLS ClientHello in BYTES (an (unsigned-byte 8)
   vector of at least the ClientHello record), or NIL when absent or malformed.
   BYTES begins at the TLS record header (0x16 handshake)."
  (block parse-tls-client-hello-sni
    (when (< (length bytes) 43) (return-from parse-tls-client-hello-sni nil))
    ;; TLS record header: type(1)=22, version(2), length(2).
    (unless (= 22 (aref bytes 0)) (return-from parse-tls-client-hello-sni nil))
    ;; Handshake header at offset 5: msg_type(1)=1 (ClientHello), length(3).
    (unless (= 1 (aref bytes 5)) (return-from parse-tls-client-hello-sni nil))
    (let ((pos 9))                      ; after record(5) + handshake header(4)
      ;; client_version(2) + random(32).
      (incf pos (+ 2 32))
      ;; session_id: len(1) + len.
      (gw-sni-need bytes (1+ pos))
      (incf pos (1+ (aref bytes pos)))
      ;; cipher_suites: len(2) + len.
      (gw-sni-need bytes (+ pos 2))
      (incf pos (+ 2 (gw-u16 bytes pos)))
      ;; compression_methods: len(1) + len.
      (gw-sni-need bytes (1+ pos))
      (incf pos (1+ (aref bytes pos)))
      ;; extensions: len(2) + body.
      (gw-sni-need bytes (+ pos 2))
      (let ((ext-end (+ pos 2 (gw-u16 bytes pos))))
        (incf pos 2)
        (gw-sni-need bytes ext-end)
        (loop while (< pos ext-end) do
          (gw-sni-need bytes (+ pos 4))
          (let ((ext-type (gw-u16 bytes pos))
                (ext-len (gw-u16 bytes (+ pos 2))))
            (incf pos 4)
            (gw-sni-need bytes (+ pos ext-len))
            (when (= ext-type 0)        ; server_name
              ;; server_name_list: len(2), then entries of type(1)+len(2)+name.
              (let ((list-pos (+ pos 2)))
                (loop while (< list-pos (+ pos ext-len)) do
                  (gw-sni-need bytes (+ list-pos 3))
                  (let ((name-type (aref bytes list-pos))
                        (name-len (gw-u16 bytes (1+ list-pos))))
                    (incf list-pos 3)
                    (gw-sni-need bytes (+ list-pos name-len))
                    (when (= name-type 0)  ; host_name
                      (return-from parse-tls-client-hello-sni
                        (map 'string #'code-char (subseq bytes list-pos (+ list-pos name-len)))))
                    (incf list-pos name-len))))
              (return-from parse-tls-client-hello-sni nil))
            (incf pos ext-len)))
        nil))))
