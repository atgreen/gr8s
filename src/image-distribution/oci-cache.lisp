;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s.image-distribution)

(defstruct (oci-blob-cache (:constructor %make-oci-blob-cache))
  directory
  (locks (make-hash-table :test #'equal))
  (locks-lock (bt:make-lock "gr8s OCI cache lock table")))

(defun make-oci-blob-cache (directory)
  (let ((directory (uiop:ensure-directory-pathname directory)))
    (ensure-directories-exist (merge-pathnames "blobs/sha256/.keep" directory))
    (%make-oci-blob-cache :directory directory)))

(defun oci-cache-blob-path (cache digest)
  (canonical-oci-digest digest)
  (merge-pathnames (format nil "blobs/sha256/~A" (subseq digest 7))
                   (oci-blob-cache-directory cache)))

(defun oci-cache-digest-lock (cache digest)
  (bt:with-lock-held ((oci-blob-cache-locks-lock cache))
    (or (gethash digest (oci-blob-cache-locks cache))
        (setf (gethash digest (oci-blob-cache-locks cache))
              (bt:make-lock (format nil "gr8s OCI blob ~A" digest))))))

(defun verified-oci-blob-p (pathname digest)
  (and (probe-file pathname)
       (ironclad:constant-time-equal
        (parse-oci-sha256 digest)
        (ironclad:digest-file :sha256 pathname))))

(defun cache-temporary-path (cache digest)
  (merge-pathnames
   ;; Keep the temporary suffix in the pathname name, not its type.  Common
   ;; Lisp's RENAME-FILE defaults an omitted destination type from the source;
   ;; a ".partial" type would therefore leak onto the content-addressed name.
   (format nil "blobs/sha256/.partial-~A-~A"
           (subseq digest 7)
           (ironclad:byte-array-to-hex-string (ironclad:random-data 8)))
   (oci-blob-cache-directory cache)))

(defun publish-cache-file (temporary final)
  (ensure-directories-exist final)
  ;; The per-digest lock guarantees that FINAL does not race another writer;
  ;; both pathnames share a directory, so the filesystem rename is atomic.
  (uiop:rename-file-overwriting-target temporary final)
  final)

(defun ensure-oci-blob
    (cache digest &key peer-fetch origin-fetch publish)
  "Return a verified cached blob. PEER-FETCH and ORIGIN-FETCH receive a temporary
   pathname and return true after writing it; PUBLISH announces the final file."
  (let* ((digest (canonical-oci-digest digest))
         (final (oci-cache-blob-path cache digest))
         (lock (oci-cache-digest-lock cache digest)))
    (bt:with-lock-held (lock)
      (when (verified-oci-blob-p final digest)
        (return-from ensure-oci-blob final))
      (when (probe-file final) (delete-file final))
      (let ((temporary (cache-temporary-path cache digest))
            (source nil))
        (unwind-protect
             (progn
               (when (and peer-fetch (funcall peer-fetch temporary))
                 (setf source :peer))
               (unless source
                 (unless (and origin-fetch (funcall origin-fetch temporary))
                   (error "Neither a peer nor the origin supplied OCI blob ~A" digest))
                 (setf source :origin))
               (unless (verified-oci-blob-p temporary digest)
                 (error "~A supplied OCI blob ~A with the wrong digest" source digest))
               (publish-cache-file temporary final)
               (when publish (funcall publish final source))
               final)
          (when (probe-file temporary) (ignore-errors (delete-file temporary))))))))
