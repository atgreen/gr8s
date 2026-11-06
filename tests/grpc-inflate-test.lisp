;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify compressed gRPC messages decompress exactly into memory proportional to
;;;; their size, while a bomb, a truncated stream and the size limit still fail.

(in-package #:gr8s/tests)
(def-suite grpc-inflate :in gr8s)
(in-suite grpc-inflate)

(defun inflate-test-octets (count)
  "Return COUNT octets that compress well but not trivially, like a node snapshot."
  (let ((octets (make-array count :element-type '(unsigned-byte 8))))
    (dotimes (index count octets)
      (setf (aref octets index) (if (zerop (mod index 7)) (mod (* index 31) 251) (char-code #\a))))))

(test compressed-messages-round-trip-at-every-size
  ;; Including 0: the dependency's gzip-compress turned an empty message into 32768 zero octets.
  (dolist (count '(0 1 4095 4096 70000 1000000))
    (let ((octets (inflate-test-octets count)))
      (is (equalp octets (ag-grpc::gzip-decompress (ag-grpc::gzip-compress octets))))
      (is (equalp octets (ag-grpc::decompress-grpc-message
                          (ag-grpc::compress-grpc-message octets "gzip") "gzip"))))))

(test compression-costs-a-small-multiple-of-the-message
  ;; podster-uqb.139: the dependency pushed every compressed octet separately.
  (let ((octets (inflate-test-octets 1000000)))
    (ag-grpc::gzip-compress octets)
    (let ((before (sb-ext:get-bytes-consed)))
      (ag-grpc::gzip-compress octets)
      (is (< (- (sb-ext:get-bytes-consed) before) (* 4 1024 1024)))))
  (dolist (encoding '("gzip" "deflate"))
    (dolist (count '(0 5 70000))
      (let ((octets (inflate-test-octets count)))
        (multiple-value-bind (compressed compressed-p) (ag-grpc::compress-grpc-message octets encoding)
          (is (eq t compressed-p))
          (is (typep compressed '(simple-array (unsigned-byte 8) (*))))
          (is (equalp octets (ag-grpc::decompress-grpc-message compressed encoding))))))))

(test a-small-message-does-not-allocate-the-whole-limit
  (let* ((compressed (ag-grpc::gzip-compress (inflate-test-octets 150000)))
         (before (sb-ext:get-bytes-consed)))
    (ag-grpc::gzip-decompress compressed)
    ;; The dependency's own version allocated the 16 MB limit for every message.
    (is (< (- (sb-ext:get-bytes-consed) before) (* 2 1024 1024)))))

(test the-limit-still-rejects-a-bomb-and-a-truncated-stream
  (let ((compressed (ag-grpc::gzip-compress (make-array 100000 :element-type '(unsigned-byte 8)
                                                                  :initial-element 0))))
    (let ((ag-grpc:*max-decompressed-size* 99999))
      (signals ag-grpc:grpc-error (ag-grpc::gzip-decompress compressed)))
    (let ((ag-grpc:*max-decompressed-size* 100000))
      (is (= 100000 (length (ag-grpc::gzip-decompress compressed)))))
    (let ((ag-grpc:*max-decompressed-size* nil))
      (is (= 100000 (length (ag-grpc::gzip-decompress compressed)))))
    (signals ag-grpc:grpc-error
      (ag-grpc::gzip-decompress (subseq compressed 0 (floor (length compressed) 2))))))
