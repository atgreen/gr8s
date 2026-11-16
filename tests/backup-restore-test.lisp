;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite backup-restore :in gr8s)
(in-suite backup-restore)

(test backup-roundtrip-restores-contents-modes-and-layout
  (with-temporary-store (store root)
    (declare (ignore store))
    (with-temporary-store (work-store work)
      (declare (ignore work-store))
      (write-backup-fixture root "identity/cluster-ca.key" "cluster identity")
      (write-backup-fixture root "raft/log" "committed entries")
      (write-backup-fixture root "empty" "")
      (let ((bundle (merge-pathnames "state.gr8s-backup" work))
            (target (merge-pathnames "restored/" work)))
        (gr8s.server::capture-state-backup root bundle (backup-test-key))
        (multiple-value-bind (published manifest files bytes)
            (gr8s.server::restore-state-backup bundle target (backup-test-key))
          (is (equal (namestring target) (namestring published)))
          (is (equal "gr8s-state-bundle" (gethash "format" manifest)))
          (is (= 3 files))
          (is (= bytes (+ (length "cluster identity") (length "committed entries"))))
          (dolist (name '("identity/cluster-ca.key" "raft/log" "empty"))
            (is (equal (uiop:read-file-string (merge-pathnames name root))
                       (uiop:read-file-string (merge-pathnames name target))))
            (is (= #o600 (logand #o777 (sb-posix:stat-mode
                                        (sb-posix:stat (merge-pathnames name target)))))))
          (is (= #o700 (logand #o777 (sb-posix:stat-mode
                                      (sb-posix:stat (merge-pathnames "identity" target))))))
          (is (null (directory (merge-pathnames ".gr8s-restore-*.*" work)))))))))

(test restore-refuses-an-existing-target-and-leaves-it-alone
  (with-temporary-store (store root)
    (declare (ignore store))
    (with-temporary-store (work-store work)
      (declare (ignore work-store))
      (write-backup-fixture root "file" "captured")
      (let ((bundle (merge-pathnames "state.gr8s-backup" work))
            (kept (write-backup-fixture work "occupied/resident" "keep me")))
        (gr8s.server::capture-state-backup root bundle (backup-test-key))
        (signals error
          (gr8s.server::restore-state-backup bundle (merge-pathnames "occupied/" work)
                                             (backup-test-key)))
        (is (equal "keep me" (uiop:read-file-string kept)))
        (is (null (directory (merge-pathnames ".gr8s-restore-*.*" work))))))))

(test restore-of-a-tampered-or-truncated-bundle-publishes-nothing
  (with-temporary-store (store root)
    (declare (ignore store))
    (with-temporary-store (work-store work)
      (declare (ignore work-store))
      (write-backup-fixture root "file" "payload worth protecting")
      (let ((bundle (merge-pathnames "state.gr8s-backup" work)))
        (gr8s.server::capture-state-backup root bundle (backup-test-key))
        (let ((bytes (alexandria:read-file-into-byte-vector bundle)))
          (flet ((attempt (damaged)
                   (let ((path (merge-pathnames "damaged.bin" work)))
                     (when (probe-file path) (delete-file path))
                     (alexandria:write-byte-vector-into-file damaged path)
                     (signals error
                       (gr8s.server::restore-state-backup path (merge-pathnames "fresh/" work)
                                                          (backup-test-key)))
                     (is (not (probe-file (merge-pathnames "fresh/" work))))
                     (is (null (directory (merge-pathnames ".gr8s-restore-*.*" work)))))))
            (let ((tampered (copy-seq bytes)))
              (setf (aref tampered (- (length tampered) 30))
                    (logxor 1 (aref tampered (- (length tampered) 30))))
              (attempt tampered))
            (attempt (subseq bytes 0 (- (length bytes) 20)))))))))

(test backup-key-files-generate-privately-and-reject-unsafe-input
  (with-temporary-store (store root)
    (declare (ignore store))
    (let ((path (merge-pathnames "backup.key" root)))
      (gr8s.server::generate-backup-key-file path)
      (is (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat path)))))
      (is (= 32 (length (gr8s.server::read-backup-key-file path))))
      (signals error (gr8s.server::generate-backup-key-file path))
      (sb-posix:chmod path #o644)
      (signals error (gr8s.server::read-backup-key-file path))
      (sb-posix:chmod path #o600)
      (let ((short (write-backup-fixture root "short.key" "abcd"))
            (junk (write-backup-fixture root "junk.key" "not hexadecimal at all!")))
        (signals error (gr8s.server::read-backup-key-file short))
        (signals error (gr8s.server::read-backup-key-file junk))))))

(test backup-cli-roundtrip-produces-json-summaries
  (with-temporary-store (store root)
    (declare (ignore store))
    (with-temporary-store (work-store work)
      (declare (ignore work-store))
      (write-backup-fixture root "raft/log" "entries")
      (let* ((key-file (namestring (merge-pathnames "backup.key" work)))
             (bundle (namestring (merge-pathnames "state.gr8s-backup" work)))
             (target (namestring (merge-pathnames "restored" work))))
        (flet ((invoke (runner options)
                 (com.inuoe.jzon:parse
                  (with-output-to-string (out)
                    (is (= 0 (funcall runner options out)))))))
          (invoke #'gr8s.server::run-backup-command
               (list :command :backup-keygen :key-file key-file))
          (let ((saved (invoke #'gr8s.server::run-backup-command
                            (list :command :backup-save :state-directory (namestring root)
                                  :output bundle :key-file key-file))))
            (is (equal bundle (gethash "path" saved)))
            (is (= 1 (gethash "files" saved))))
          (let ((verified (invoke #'gr8s.server::run-backup-command
                               (list :command :backup-verify :input bundle :key-file key-file))))
            (is (equal gr8s.server::+gr8s-version+ (gethash "release" verified))))
          (let ((restored (invoke #'gr8s.server::run-restore-command
                               (list :command :restore :input bundle
                                     :state-directory target :key-file key-file))))
            (is (= 1 (gethash "files" restored)))
            (is (equal "entries"
                       (uiop:read-file-string (merge-pathnames "raft/log"
                                                               (uiop:ensure-directory-pathname target)))))))))))

(test backup-and-restore-key-mismatch-is-rejected
  (with-temporary-store (store root)
    (declare (ignore store))
    (with-temporary-store (work-store work)
      (declare (ignore work-store))
      (write-backup-fixture root "file" "secret state")
      (let ((bundle (merge-pathnames "state.gr8s-backup" work))
            (other (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
        (gr8s.server::capture-state-backup root bundle (backup-test-key))
        (signals error
          (gr8s.server::restore-state-backup bundle (merge-pathnames "fresh/" work) other))
        (is (not (probe-file (merge-pathnames "fresh/" work))))))))
