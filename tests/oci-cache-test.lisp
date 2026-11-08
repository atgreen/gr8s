;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)

(test oci-cache-prefers-peers-verifies-and-publishes-atomically
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-oci-cache-~36R/"
                             (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (cache (gr8s.image-distribution::make-oci-blob-cache directory))
         (bytes (bt-octets "shared layer"))
         (digest (format nil "sha256:~A"
                         (ironclad:byte-array-to-hex-string
                          (ironclad:digest-sequence :sha256 bytes))))
         (peer-calls 0) (origin-calls 0) (published nil))
    (unwind-protect
         (let ((path
                 (gr8s.image-distribution::ensure-oci-blob
                  cache digest
                  :peer-fetch
                  (lambda (temporary)
                    (incf peer-calls)
                    (with-open-file (stream temporary :direction :output
                                                      :if-does-not-exist :create
                                                      :element-type '(unsigned-byte 8))
                      (write-sequence bytes stream))
                    t)
                  :origin-fetch (lambda (temporary)
                                  (declare (ignore temporary))
                                  (incf origin-calls) t)
                  :publish (lambda (path source)
                             (setf published (list path source))))))
           (is (= 1 peer-calls))
           (is (zerop origin-calls))
           (is (eq :peer (second published)))
           (is (equal path (first published)))
           (is-true (gr8s.image-distribution::verified-oci-blob-p path digest))
           (is (equal path
                      (gr8s.image-distribution::ensure-oci-blob
                       cache digest
                       :peer-fetch (lambda (temporary)
                                     (declare (ignore temporary))
                                     (incf peer-calls) nil))))
           (is (= 1 peer-calls))
           (is (null (directory (merge-pathnames "blobs/sha256/*.partial"
                                                  directory)))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test oci-cache-rejects-corrupt-peer-and-origin-content
  (let* ((directory (merge-pathnames
                     (format nil "gr8s-oci-corrupt-~36R/"
                             (random most-positive-fixnum))
                     (uiop:temporary-directory)))
         (cache (gr8s.image-distribution::make-oci-blob-cache directory))
         (digest "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    (unwind-protect
         (signals error
           (gr8s.image-distribution::ensure-oci-blob
            cache digest
            :peer-fetch
            (lambda (temporary)
              (with-open-file (stream temporary :direction :output
                                                :if-does-not-exist :create
                                                :element-type '(unsigned-byte 8))
                (write-sequence #(1 2 3) stream))
              t)))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))
