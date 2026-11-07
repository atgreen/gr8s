;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Make the pinned ag-gRPC decompress a message into memory proportional to its
;;;; size. Its bomb defense allocates a buffer of the whole 16 MB limit for every
;;;; compressed message, and a node agent receives several a second, each a few
;;;; kilobytes. That made gigabytes of garbage a minute, so the collector ran every
;;;; few messages and aged short-lived objects into generations it rarely collects.

(in-package #:gr8s.protocol)

(defparameter +grpc-inflate-initial-ratio+ 8
  "Start a decompression buffer at this multiple of the compressed size.")

(defparameter +grpc-inflate-minimum-buffer+ 4096
  "Smallest decompression buffer, for a tiny compressed message.")

(defun grpc-inflate-error (control &rest arguments)
  "Reject a compressed message the way the dependency does."
  (error 'ag-grpc:grpc-error :message (apply #'format nil control arguments)))

(defun ag-grpc::bounded-inflate (data format)
  "Decompress DATA (FORMAT is 'chipz:gzip or 'chipz:deflate), never holding more than
AG-GRPC:*MAX-DECOMPRESSED-SIZE* + 1 bytes of output, or without a bound when that is NIL.
The output buffer starts near the expected size and doubles as needed, so a bomb is still
rejected once its output passes the limit, having allocated at most twice the limit."
  (let* ((input (if (typep data '(simple-array (unsigned-byte 8) (*)))
                    data
                    (coerce data '(simple-array (unsigned-byte 8) (*)))))
         (cap ag-grpc:*max-decompressed-size*)
         (state (chipz:make-dstate format))
         (size (max +grpc-inflate-minimum-buffer+ (* +grpc-inflate-initial-ratio+ (length input))))
         (output (make-array (if cap (min size (1+ cap)) size) :element-type '(unsigned-byte 8)))
         (input-start 0)
         (produced 0))
    (loop
      (multiple-value-bind (consumed written)
          (chipz:decompress output state input :input-start input-start :output-start produced)
        (incf input-start consumed)
        (incf produced written)
        (when (and cap (> produced cap))
          (grpc-inflate-error "Decompressed size exceeds limit ~D bytes (gzip bomb defense)" cap))
        (when (handler-case (chipz:finish-dstate state) (chipz:premature-end-of-stream () nil))
          (return (subseq output 0 produced)))
        (when (< produced (length output))
          ;; Stopped with room left, so the input ended before the stream did.
          (grpc-inflate-error "Decompressed stream is truncated or corrupt"))
        (let ((grown (make-array (if cap (min (* 2 (length output)) (1+ cap)) (* 2 (length output)))
                                 :element-type '(unsigned-byte 8))))
          (replace grown output)
          (setf output grown))))))
