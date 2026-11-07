;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Minimal RFC 6455 WebSocket framing: read and write single frames.
;;;;
;;;; gr8s speaks the WebSocket wire format directly rather than pulling in a
;;;; client library, because its only use is tunnelling the Kubernetes streaming
;;;; endpoints (exec, attach, port-forward) over the same HTTP server. Just the
;;;; frame layer lives here -- opcode, FIN, the 7/16/64-bit payload length, and
;;;; the client-side masking the spec mandates -- not the opening handshake or
;;;; the control-frame protocol. Every incoming frame is bounded by
;;;; *MAX-WEBSOCKET-FRAME-SIZE* so a hostile length field cannot force a huge
;;;; allocation, and an EOF inside a frame is treated as a protocol error, not a
;;;; clean close.

(in-package #:gr8s)

(defparameter *max-websocket-frame-size* (* 16 1024 1024))

(defun read-required-byte (stream)
  "Read one byte from STREAM, or signal a RUNTIME-ERROR when the stream has
   already ended -- an EOF mid-frame is a protocol error, not a clean close."
  (or (read-byte stream nil nil)
      (error 'runtime-error :message "WebSocket stream ended inside a frame")))

(defun websocket-payload-length (stream encoded-length)
  "Resolve an RFC 6455 payload length from its 7-bit ENCODED-LENGTH: read two
   further big-endian bytes from STREAM when it is 126, eight when 127, and
   otherwise take ENCODED-LENGTH as the length itself."
  (case encoded-length
    (126 (+ (ash (read-required-byte stream) 8)
            (read-required-byte stream)))
    (127 (loop with value = 0
               repeat 8
               do (setf value (+ (ash value 8)
                                 (read-required-byte stream)))
               finally (return value)))
    (otherwise encoded-length)))

(defun read-websocket-frame (stream)
  "Read one RFC 6455 frame, returning OPCODE, PAYLOAD, and FIN-P."
  (let* ((first (read-required-byte stream))
         (second (read-required-byte stream))
         (fin-p (logbitp 7 first))
         (opcode (logand first #x0f))
         (masked-p (logbitp 7 second))
         (length (websocket-payload-length stream (logand second #x7f))))
    (unless (zerop (logand first #x70))
      (error 'runtime-error :message "WebSocket RSV bits are unsupported"))
    (when (> length *max-websocket-frame-size*)
      (error 'runtime-error :message "WebSocket frame exceeds the receive limit"))
    (let ((mask (and masked-p
                     (make-array 4 :element-type '(unsigned-byte 8))))
          (payload (make-array length :element-type '(unsigned-byte 8))))
      (when mask
        (dotimes (index 4)
          (setf (aref mask index) (read-required-byte stream))))
      (dotimes (index length)
        (let ((octet (read-required-byte stream)))
          (setf (aref payload index)
                (if mask
                    (logxor octet (aref mask (mod index 4)))
                    octet))))
      (values opcode payload fin-p masked-p))))

(defun write-websocket-length (stream length masked-p)
  "Write the RFC 6455 payload-length prefix for LENGTH to STREAM, OR-ing the mask
   bit into its first byte when MASKED-P: one byte for <=125, a 126 marker plus a
   16-bit length for <=65535, else a 127 marker plus a 64-bit length. Big-endian."
  (let ((mask-bit (if masked-p #x80 0)))
    (cond
      ((<= length 125)
       (write-byte (logior mask-bit length) stream))
      ((<= length #xffff)
       (write-byte (logior mask-bit 126) stream)
       (write-byte (ldb (byte 8 8) length) stream)
       (write-byte (ldb (byte 8 0) length) stream))
      (t
       (write-byte (logior mask-bit 127) stream)
       (loop for shift from 56 downto 0 by 8
             do (write-byte (ldb (byte 8 shift) length) stream))))))

(defun write-websocket-frame (stream opcode payload &key masked-p)
  "Write one final RFC 6455 frame. Client callers set MASKED-P true."
  (when (> (length payload) *max-websocket-frame-size*)
    (error 'runtime-error :message "WebSocket frame exceeds the send limit"))
  (let ((mask (and masked-p
                   (make-array 4 :element-type '(unsigned-byte 8)
                                 :initial-contents
                                 (loop repeat 4 collect (random 256))))))
    (write-byte (logior #x80 opcode) stream)
    (write-websocket-length stream (length payload) masked-p)
    (when mask
      (write-sequence mask stream))
    (loop for octet across payload
          for index from 0
          do (write-byte
              (if mask
                  (logxor octet (aref mask (mod index 4)))
                  octet)
              stream))
    (finish-output stream)))
