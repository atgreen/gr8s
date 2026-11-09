;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite store-snapshot-registry :in gr8s)
(in-suite store-snapshot-registry)

(test retained-artifacts-survive-source-cleanup-and-reopen
  (with-temporary-store (store root)
    (let ((source (merge-pathnames "transfer.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let ((digest (snapshot-test-digest source)))
        (multiple-value-bind (path reference)
            (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)
          (is (equal reference (list :gr8s-store-artifact 1 :index 42 :term 7 :sha256 digest)))
          (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat path)))))
          (is (= #o700 (logand #o777 (sb-posix:stat-mode
                                     (sb-posix:stat (uiop:pathname-directory-pathname path))))))
          (is (equal path (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)))
          (delete-file source)
          (is (equal path (gr8s.resources::checked-store-snapshot-artifact-path root reference)))
          (multiple-value-bind (generation descriptor)
              (gr8s.resources::materialize-store-snapshot root path digest :expected-index 42 :expected-term 7)
            (declare (ignore generation))
            (is (= 42 (gethash "index" descriptor))))
          (signals error (gr8s.resources::checked-store-snapshot-artifact-path
                          root (gr8s.resources::store-snapshot-artifact-reference 43 7 digest)))
          (with-open-file (out path :direction :output :if-exists :append) (write-line "corrupt" out))
          (signals error (gr8s.resources::checked-store-snapshot-artifact-path root reference)))))))

(test rejected-artifacts-never-get-published
  (with-temporary-store (store root)
    (let ((source (merge-pathnames "transfer.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let* ((digest (snapshot-test-digest source))
             (directory (gr8s.resources::store-snapshot-registry-directory root)))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 43 7 digest))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 8 digest))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 7 (make-string 64 :initial-element #\0)))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 7 "../bad"))
        (is (null (directory (merge-pathnames "*.*" directory))))
        (signals error (gr8s.resources::checked-store-snapshot-artifact-path
                        root (gr8s.resources::store-snapshot-artifact-reference 42 7 digest)))
        (signals error (gr8s.resources::checked-store-snapshot-artifact-path
                        root (list :gr8s-store-artifact 2 :index 42 :term 7 :sha256 digest)))))))

(test retained-artifact-symlinks-and-unsafe-permissions-are-rejected
  (with-temporary-store (store root)
    (let ((source (merge-pathnames "transfer.jsonl" root)))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let* ((digest (snapshot-test-digest source))
             (reference (gr8s.resources::store-snapshot-artifact-reference 42 7 digest))
             (directory (gr8s.resources::store-snapshot-registry-directory root))
             (target (merge-pathnames (format nil "~A.jsonl" digest) directory)))
        (sb-posix:symlink (namestring source) (namestring target))
        (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest))
        (signals error (gr8s.resources::checked-store-snapshot-artifact-path root reference))
        (sb-posix:unlink (namestring target))
        (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)
        (sb-posix:chmod (namestring target) #o644)
        (signals error (gr8s.resources::checked-store-snapshot-artifact-path root reference))))))

(test artifact-directory-sync-failure-requires-a-successful-retry
  (with-temporary-store (store root)
    (let* ((source (merge-pathnames "transfer.jsonl" root))
           (directory (gr8s.resources::store-snapshot-registry-directory root))
           (original (symbol-function 'gr8s.store::sync-store-generation-directory))
           (injected nil))
      (gr8s.resources::capture-store-snapshot store source 42 7)
      (let ((digest (snapshot-test-digest source)))
        (unwind-protect
             (progn
               (setf (symbol-function 'gr8s.store::sync-store-generation-directory)
                     (lambda (path)
                       (when (equal path directory)
                         (setf injected t)
                         (error "Injected registry directory sync failure"))
                       (funcall original path)))
               (signals error (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)))
          (setf (symbol-function 'gr8s.store::sync-store-generation-directory) original))
        (is-true injected)
        (multiple-value-bind (path reference)
            (gr8s.resources::retain-store-snapshot-artifact root source 42 7 digest)
          (delete-file source)
          (is (equal path (gr8s.resources::checked-store-snapshot-artifact-path root reference))))))))
