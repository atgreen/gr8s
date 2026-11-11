;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite backup-bundle :in gr8s)
(in-suite backup-bundle)

(defun verify-test-state-backup (path &rest options)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (apply #'gr8s.server::verify-state-backup-stream in (backup-test-key) options)))

(defun make-test-bundle-records (records)
  (flexi-streams:with-output-to-sequence (out)
    (let ((writer (gr8s.server::open-backup-writer out (backup-test-key))))
      (gr8s.server::write-backup-bundle-json
       writer 0 (gr8s::json-object "format" "gr8s-state-bundle" "version" 1
                                  "buildID" gr8s.patch:*build-id* "release" "test"
                                  "createdAt" 0 "exclusionPolicy" "gr8s-control-plane-v1"))
      (dolist (record records) (gr8s.server::write-backup-record writer record))
      (gr8s.server::finish-backup-writer writer))))
(defun test-bundle-json-record (kind object)
  (concatenate '(vector (unsigned-byte 8)) (vector kind)
               (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify object))))
(defun test-bundle-file-records (path &optional (payload (make-array 0 :element-type '(unsigned-byte 8))))
  (list (test-bundle-json-record 1 (gr8s::json-object "path" path "bytes" (length payload) "mode" #o600))
        (concatenate '(vector (unsigned-byte 8)) #(3) (ironclad:digest-sequence :sha256 payload))))
(defun test-bundle-footer (files bytes)
  (test-bundle-json-record 4 (gr8s::json-object "files" files "bytes" bytes "excluded" #())))
(defun verify-test-bundle-bytes (bytes)
  (flexi-streams:with-input-from-sequence (in bytes)
    (gr8s.server::verify-state-backup-stream in (backup-test-key))))

(test encrypted-state-bundle-streams-empty-large-and-identity-files
  (with-temporary-store (store root)
    (declare (ignore store))
    (with-temporary-store (output-store output-root)
      (declare (ignore output-store))
      (let ((target (merge-pathnames "backup.bin" output-root))
            (seen nil) (copied 0))
        (write-backup-fixture root "a/identity.key" "private cluster identity")
        (write-backup-fixture root "a-b.key" "sibling after directory")
        (write-backup-fixture root "empty" "")
        (write-backup-fixture root "large" (make-string 200000 :initial-element #\x))
        (multiple-value-bind (path files bytes)
            (gr8s.server::capture-state-backup root target (backup-test-key))
          (is (equal target path))
          (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat path)))))
          (multiple-value-bind (manifest verified-files verified-bytes)
              (verify-test-state-backup path :on-file (lambda (name size) (declare (ignore size)) (push name seen))
                                            :on-data (lambda (record start end) (declare (ignore record)) (incf copied (- end start))))
            (is (equal "gr8s-state-bundle" (gethash "format" manifest)))
            (is (= files verified-files)) (is (= bytes verified-bytes copied))))
        (dolist (name '("a/identity.key" "a-b.key" "empty" "large")) (is (member name seen :test #'equal)))
        (is (null (directory (merge-pathnames ".gr8s-backup-*.*" output-root))))))))

(test encrypted-state-bundle-does-not-overwrite-or-capture-its-own-output
  (with-temporary-store (store root)
    (declare (ignore store))
    (signals error (gr8s.server::capture-state-backup root (merge-pathnames "backup.bin" root) (backup-test-key)))
    (is (not (probe-file (merge-pathnames "backup.bin" root))))
    (with-temporary-store (output-store output-root)
      (declare (ignore output-store))
      (let ((path (write-backup-fixture output-root "existing.bin" "keep original")))
        (signals error (gr8s.server::capture-state-backup root path (backup-test-key)))
        (is (equal "keep original" (uiop:read-file-string path)))
        (is (null (directory (merge-pathnames ".gr8s-backup-*.*" output-root))))))))

(test bundle-verification-rejects-authenticated-unsafe-paths-and-order
  (dolist (name '("../escape" "/absolute" "x/../escape" "x//y" "x\\y" "patches/process.lock" "agent/containerd/x"))
    (signals error
      (verify-test-bundle-bytes (make-test-bundle-records
                                (append (test-bundle-file-records name) (list (test-bundle-footer 1 0)))))))
  (dolist (paths '(("same" "same") ("z" "a") ("a" "a/b") ("a/b" "a")))
    (signals error
      (verify-test-bundle-bytes
       (make-test-bundle-records
        (append (mapcan #'test-bundle-file-records paths) (list (test-bundle-footer 2 0))))))))

(test bundle-verification-rejects-incomplete-files-digests-and-totals
  (let* ((file (test-bundle-file-records "file"))
         (bad-digest (copy-seq (second file))))
    (setf (aref bad-digest 1) (logxor 1 (aref bad-digest 1)))
    (dolist (records (list (list (first file) (test-bundle-footer 1 0))
                           (list (first file) bad-digest (test-bundle-footer 1 0))
                           (append file (list (test-bundle-footer 2 0)))
                           (append file (list (test-bundle-footer 1 1)))
                           file
                           (append file (list (test-bundle-footer 1 0) (test-bundle-footer 1 0)))))
      (signals error (verify-test-bundle-bytes (make-test-bundle-records records))))))

(test interrupted-bundle-capture-discards-private-temporary-output
  (with-temporary-store (store root)
    (declare (ignore store))
    (with-temporary-store (out-store out-root)
      (declare (ignore out-store))
      (write-backup-fixture root "victim" "original")
      (let ((original (symbol-function 'gr8s.server::write-backup-bundle-file))
            (target (merge-pathnames "backup.bin" out-root)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.server::write-backup-bundle-file)
                     (lambda (writer name path expected)
                       (funcall original writer name path expected)
                       (error "Injected capture failure")))
               (signals error (gr8s.server::capture-state-backup root target (backup-test-key)))
               (is (not (probe-file target)))
               (is (null (directory (merge-pathnames ".gr8s-backup-*.*" out-root)))))
          (setf (symbol-function 'gr8s.server::write-backup-bundle-file) original))))))

(test bundle-capture-refuses-source-replacement-between-inventory-and-open
  (with-temporary-store (store root)
    (declare (ignore store))
    (with-temporary-store (out-store out-root)
      (declare (ignore out-store))
      (write-backup-fixture root "victim" "original")
      (let ((original (symbol-function 'gr8s.server::write-backup-bundle-file))
            (target (merge-pathnames "backup.bin" out-root)) (replaced nil))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.server::write-backup-bundle-file)
                     (lambda (writer name path expected)
                       (when (equal name "victim")
                         (setf replaced t)
                         (sb-posix:rename path (merge-pathnames "retained-original" root))
                         (write-backup-fixture root "victim" "replaced"))
                       (funcall original writer name path expected)))
               (signals error (gr8s.server::capture-state-backup root target (backup-test-key)))
               (is (not (null replaced)))
               (is (not (probe-file target)))
               (is (null (directory (merge-pathnames ".gr8s-backup-*.*" out-root)))))
          (setf (symbol-function 'gr8s.server::write-backup-bundle-file) original))))))

(test bundle-verification-rejects-missing-and-excess-payload-and-unknown-records
  (let ((file (test-bundle-file-records "file")))
    (dolist (records (list (list (test-bundle-json-record 1 (gr8s::json-object "path" "file" "bytes" 1 "mode" #o600))
                                (second file) (test-bundle-footer 1 1))
                           (list (first file) (make-array 2 :element-type '(unsigned-byte 8) :initial-element 2)
                                 (second file) (test-bundle-footer 1 0))
                           (list (make-array 1 :element-type '(unsigned-byte 8) :initial-element 99))))
      (signals error (verify-test-bundle-bytes (make-test-bundle-records records))))))
