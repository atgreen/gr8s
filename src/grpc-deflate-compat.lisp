;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Make the pinned ag-gRPC compress a message in time proportional to its size,
;;;; and compress an empty one correctly. Its salza2 callback pushed every output
;;;; octet through VECTOR-PUSH-EXTEND, which the node session paid for each
;;;; desired-state message it sent (podster-uqb.139). salza2 also compresses an
;;;; empty input as 32768 zero octets, so an empty gzipped message decompressed to
;;;; 32 KB (podster-uqb.141). Drop this file once the pinned version has both fixes.

(in-package #:gr8s)

(defparameter +empty-gzip-member+
  (coerce #(#x1f #x8b 8 0 0 0 0 0 0 #xff 3 0 0 0 0 0 0 0 0 0) '(simple-array (unsigned-byte 8) (*)))
  "A gzip member of no data: header, an empty final fixed-Huffman block, CRC-32 0, size 0.")

(defparameter +empty-deflate-stream+
  (coerce #(3 0) '(simple-array (unsigned-byte 8) (*)))
  "A raw deflate stream of no data: one empty final fixed-Huffman block.")

(defun salza2-compress-octets (compressor-class data)
  "Compress DATA with salza2's COMPRESSOR-CLASS, copying each output block whole."
  (let ((input (if (typep data '(simple-array (unsigned-byte 8) (*)))
                   data
                   (coerce data '(simple-array (unsigned-byte 8) (*)))))
        (blocks nil)
        (total 0))
    (salza2:with-compressor (compressor compressor-class
                                        :callback (lambda (buffer end)
                                                    (push (subseq buffer 0 end) blocks)
                                                    (incf total end)))
      (salza2:compress-octet-vector input compressor))
    (let ((output (make-array total :element-type '(unsigned-byte 8)))
          (position 0))
      (dolist (block (nreverse blocks) output)
        (replace output block :start1 position)
        (incf position (length block))))))

(defun ag-grpc::gzip-compress (data)
  "Compress DATA using gzip. Returns a compressed simple octet vector."
  (if (zerop (length data))
      (copy-seq +empty-gzip-member+)
      (salza2-compress-octets 'salza2:gzip-compressor data)))

(defun ag-grpc::compress-grpc-message (data encoding)
  "Compress a gRPC message body.
ENCODING is the compression algorithm name.
Returns (values compressed-data compressed-p)."
  (cond
    ((or (null encoding) (string= encoding "identity"))
     (values data nil))
    ((string= encoding "gzip")
     (values (ag-grpc::gzip-compress data) t))
    ((string= encoding "deflate")
     (values (if (zerop (length data))
                 (copy-seq +empty-deflate-stream+)
                 (salza2-compress-octets 'salza2:deflate-compressor data))
             t))
    (t
     (error 'ag-grpc:grpc-error
            :message (format nil "Unknown compression: ~A" encoding)))))
