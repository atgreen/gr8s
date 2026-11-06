;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Check the image archive import against containerd's wire format: the
;;;; ImageStore that names and unpacks an archive, and the credit-based Data
;;;; stream that carries it.

(in-package #:gr8s/tests)

(in-suite gr8s)

(defun window-update-any (bytes)
  (gr8s::containerd-any "containerd.types.transfer.WindowUpdate"
                        (make-instance 'gr8s.containerd.transfer.v1::window-update :update bytes)))

(defun octets (&rest parts)
  "Concatenate PARTS, each a string (as UTF-8) or a sequence of bytes, into one byte vector."
  (coerce (loop for part in parts
                append (coerce (if (stringp part) (trivial-utf-8:string-to-utf-8-bytes part) part) 'list))
          '(vector (unsigned-byte 8))))

(test image-archives-are-the-tar-files-in-name-order
  (let ((directory (uiop:ensure-directory-pathname
                    (format nil "/tmp/gr8s-images-~36R/" (random (expt 36 8) (make-random-state t))))))
    (ensure-directories-exist directory)
    (unwind-protect
         (progn
           (dolist (name '("b.tar" "a.tar" "notes.txt" "c.tar.partial"))
             (with-open-file (stream (merge-pathnames name directory) :direction :output)
               (write-string "x" stream)))
           (is (equal '("a.tar" "b.tar")
                      (mapcar #'file-namestring (gr8s::image-archive-paths directory)))))
      (uiop:delete-directory-tree directory :validate t)))
  (is (null (gr8s::image-archive-paths "/nonexistent/gr8s-images/"))))

(test the-import-destination-matches-containerds-image-store
  ;; containerd.types.transfer.ImageStore{platforms: 3, extra_references: 6, unpacks: 10},
  ;; as `ctr images import` sends it: named from the archive, unpacked for this platform.
  (let* ((platform (octets '(10 5) "linux" '(18 5) "amd64"))
         (reference (octets '(10 11) "import-gr8s" '(16 1 24 1)))
         (unpack (octets (list 10 (length platform)) platform '(18 9) "overlayfs")))
    (is (equalp (octets (list 26 (length platform)) platform
                        (list 50 (length reference)) reference
                        (list 82 (length unpack)) unpack)
                (ag-proto:serialize-to-bytes (gr8s::image-archive-import-store "linux/amd64" "overlayfs")))))
  (let ((arm (gr8s::containerd-transfer-platform "linux/arm64/v8")))
    (is (equal "arm64" (gr8s.containerd.transfer.v1::architecture arm)))
    (is (equal "v8" (gr8s.containerd.transfer.v1::variant arm)))))

(test archive-data-is-sent-only-within-containerds-window
  (let* ((size (+ (* 3 32 1024) 100))
         (archive (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
                    (dotimes (i size bytes) (setf (aref bytes i) (mod (* i 7) 256)))))
         (sent '()) (granted 0) (credit-seen '()))
    (flexi-streams:with-input-from-sequence (input archive)
      (gr8s::send-image-archive
       input
       (lambda (message)
         (is (equal "containerd.types.transfer.Data" (gr8s.containerd.transfer.v1::type-url message)))
         (push (gr8s.containerd.transfer.v1::data
                (ag-proto:deserialize-from-bytes 'gr8s.containerd.transfer.v1::data
                                                 (gr8s.containerd.transfer.v1::value message)))
               sent))
       (lambda ()
         (push (reduce #'+ sent :key #'length) credit-seen)
         (incf granted 65536)
         (window-update-any 65536))))
    (let ((chunks (reverse sent)))
      (is (equalp archive (apply #'concatenate '(vector (unsigned-byte 8)) chunks)))
      (is (every (lambda (chunk) (<= 1 (length chunk) (* 32 1024))) chunks)))
    ;; Each grant was asked for only once the previous one was spent.
    (is (equal '(0 65536) (reverse credit-seen)))
    (is (<= size granted))))

(test archive-sending-stops-when-containerd-does
  (flexi-streams:with-input-from-sequence (input (make-array 10 :element-type '(unsigned-byte 8) :initial-element 1))
    (signals gr8s::runtime-error
      (gr8s::send-image-archive input (lambda (message) message) (lambda () nil))))
  (flexi-streams:with-input-from-sequence (input (make-array 10 :element-type '(unsigned-byte 8) :initial-element 1))
    (signals gr8s::runtime-error
      (gr8s::send-image-archive input (lambda (message) message)
                                (lambda () (gr8s::containerd-any "containerd.types.transfer.Data"
                                                                 (make-instance 'gr8s.containerd.transfer.v1::data)))))))
