;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite serve-state-ownership :in gr8s)
(in-suite serve-state-ownership)

(test serve-owns-state-before-open-store-and-releases-on-initializer-failure
  (let* ((root (uiop:ensure-directory-pathname (sb-posix:mkdtemp "/tmp/gr8s-owner-XXXXXX")))
         (options (list :state-directory root))
         (original (symbol-function 'gr8s:open-store)) (opened 0))
    (unwind-protect
         (progn
           (signals error (gr8s.server::serve-owned options))
           (setf (symbol-function 'gr8s:open-store)
                 (lambda (path)
                   (incf opened)
                   (is (equal root (truename path)))
                   (is (not (null (gr8s.server::require-serve-state-ownership options))))
                   (signals error (gr8s.server::call-with-serve-state-ownership options (lambda () (fail "second owner entered"))))
                   (error "Injected open-store initialization failure")))
           (signals error (gr8s::serve options))
           (is (= 1 opened))
           (is (eq :released (gr8s.server::call-with-serve-state-ownership options (lambda () :released)))))
      (setf (symbol-function 'gr8s:open-store) original)
      (uiop:delete-directory-tree root :validate t))))

(test serve-lease-covers-unwind-cleanup-and-canonical-aliases
  (with-temporary-store (store root)
    (declare (ignore store))
    (let ((alias (merge-pathnames "alias/" root)) (options (list :state-directory root)) (cleaned nil))
      (sb-posix:symlink (namestring root) (string-right-trim "/" (namestring alias)))
      (unwind-protect
           (progn
             (gr8s.server::call-with-serve-state-ownership
              options
              (lambda ()
                (unwind-protect :body
                  (setf cleaned t)
                  (signals error (gr8s.server::call-with-serve-state-ownership
                                  (list :state-directory alias) (lambda () (fail "alias bypassed ownership")))))))
             (is-true cleaned)
             (is (eq :released (gr8s.server::call-with-serve-state-ownership options (lambda () :released)))))
        (sb-posix:unlink (string-right-trim "/" (namestring alias)))))))

(test ha-mode-survives-failure-and-refuses-standalone-fallback
  (with-temporary-store (store root)
    (declare (ignore store))
    (let ((ha (list :state-directory root :raft-init t)) (plain (list :state-directory root)))
      (gr8s.server::call-with-serve-state-ownership plain (lambda () nil))
      (signals error (gr8s.server::call-with-serve-state-ownership ha (lambda () (error "startup interrupted"))))
      (let* ((path (merge-pathnames "metadata/server-mode.json" root)) (before (uiop:read-file-string path)))
        (signals error (gr8s.server::call-with-serve-state-ownership plain (lambda () (fail "HA opened as standalone"))))
        (is (equal before (uiop:read-file-string path)))
        (is (eq :ha (gr8s.server::call-with-serve-state-ownership ha (lambda () :ha)))))))
  (dolist (evidence '("raft/control-plane.log" "raft/bootstrap.json" "pki/raft/pki/cluster-ca.crt" "raft/witness.log"))
    (with-temporary-store (store root)
      (declare (ignore store))
      (let ((path (merge-pathnames evidence root)))
        (ensure-directories-exist path)
        (with-open-file (out path :direction :output :if-does-not-exist :create) (write-line "existing" out))
        (signals error (gr8s.server::call-with-serve-state-ownership
                        (list :state-directory root) (lambda () (fail "legacy Raft state opened as standalone"))))
        (is (equal (format nil "existing~%") (uiop:read-file-string path)))))))

(test serve-ownership-refuses-links-and-unsafe-mode-descriptors
  (dolist (failure '(:symlink :hardlink :permissions :mode))
    (with-temporary-store (store root)
      (declare (ignore store))
      (let ((path (merge-pathnames ".gr8s-serve.lock" root)))
        (gr8s.server::call-with-serve-state-ownership (list :state-directory root) (lambda () nil))
        (ecase failure
          (:symlink (delete-file path) (sb-posix:symlink "missing" (namestring path)))
          (:hardlink (sb-posix:link (namestring path) (namestring (merge-pathnames "other.lock" root))))
          (:permissions (sb-posix:chmod (namestring path) #o644))
          (:mode (with-open-file (out (merge-pathnames "metadata/server-mode.json" root) :direction :output :if-exists :supersede)
                   (write-string "{}" out))))
        (signals error (gr8s.server::call-with-serve-state-ownership
                        (list :state-directory root) (lambda () (fail "unsafe owner state accepted"))))))))

(test serve-process-death-releases-state-ownership
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((script (namestring (merge-pathnames "scripts/serve-state-owner-test-child.lisp" (asdf:system-source-directory :gr8s))))
           (ready (merge-pathnames "owner-ready.txt" root))
           (log (merge-pathnames "owner-child.log" root))
           (process (sb-ext:run-program "sbcl"
                     (list "--dynamic-space-size" "384" "--noinform" "--non-interactive" "--load" script "--" (namestring root) (namestring ready))
                     :search t :wait nil :input nil :output log :error :output)))
      (unwind-protect
           (progn
             (poll-until (lambda () (or (probe-file ready) (not (sb-ext:process-alive-p process)))) :timeout 60)
             (unless (probe-file ready) (error "Ownership child failed: ~A" (uiop:read-file-string log)))
             (signals error (gr8s.server::call-with-serve-state-ownership
                             (list :state-directory root) (lambda () (fail "competing process entered"))))
             (sb-ext:process-kill process sb-posix:sigkill)
             (sb-ext:process-wait process)
             (is (eq :signaled (sb-ext:process-status process)))
             (is (eq :released (gr8s.server::call-with-serve-state-ownership
                                (list :state-directory root) (lambda () :released)))))
        (when (sb-ext:process-alive-p process)
          (sb-ext:process-kill process sb-posix:sigkill) (sb-ext:process-wait process))
        (sb-ext:process-close process)))))

(test invalid-ha-options-do-not-change-the-persisted-mode
  (with-temporary-store (store root)
    (declare (ignore store))
    (gr8s.server::call-with-serve-state-ownership (list :state-directory root) (lambda () nil))
    (let* ((path (merge-pathnames "metadata/server-mode.json" root)) (before (uiop:read-file-string path)))
      (dolist (flags '((:raft-init t :raft-join "host:7449") (:raft-join "host:not-a-port")))
        (signals error (gr8s.server::call-with-serve-state-ownership
                        (append (list :state-directory root) flags) (lambda () (fail "invalid request entered")))))
      (is (equal before (uiop:read-file-string path))))))

(test metadata-directory-link-cannot-redirect-mode-publication
  (let* ((root (uiop:ensure-directory-pathname (sb-posix:mkdtemp "/tmp/gr8s-owner-XXXXXX")))
         (outside (uiop:ensure-directory-pathname (sb-posix:mkdtemp "/tmp/gr8s-owner-XXXXXX")))
         (alias (merge-pathnames "metadata" root))
         (mode (merge-pathnames "server-mode.json" outside)))
    (unwind-protect
         (progn
           (gr8s.server::write-serve-state-mode mode "standalone")
           (sb-posix:symlink (namestring outside) (namestring alias))
           (let ((before (uiop:read-file-string mode)))
             (signals error (gr8s.server::call-with-serve-state-ownership
                             (list :state-directory root :raft-init t) (lambda () (fail "linked metadata accepted"))))
             (is (equal before (uiop:read-file-string mode)))))
      (when (gr8s.store::store-generation-stat alias) (sb-posix:unlink (namestring alias)))
      (uiop:delete-directory-tree root :validate t)
      (uiop:delete-directory-tree outside :validate t))))

(test serve-command-owns-state-during-patch-startup-and-shutdown
  (with-temporary-store (store root)
    (declare (ignore store))
    (let* ((options (list :state-directory root))
           (symbols '(gr8s.server::bootstrap-patches gr8s.server::serve-owned gr8s.server::shutdown-patches))
           (originals (mapcar #'symbol-function symbols))
           (events nil))
      (flet ((owned (event)
               (push event events)
               (is (not (null (gr8s.server::require-serve-state-ownership options))))
               (signals error (gr8s.server::call-with-serve-state-ownership
                               options (lambda () (fail "patch lifecycle lost ownership"))))))
        (unwind-protect
             (progn
               (setf (symbol-function (first symbols)) (lambda (ignored) (declare (ignore ignored)) (owned :patches))
                     (symbol-function (second symbols)) (lambda (ignored) (declare (ignore ignored)) (owned :serve) (error "initializer failure"))
                     (symbol-function (third symbols)) (lambda () (owned :shutdown)))
               (signals error (gr8s.server::run-serve-command options))
               (is (equal '(:shutdown :serve :patches) events))
               (is (eq :released (gr8s.server::call-with-serve-state-ownership options (lambda () :released)))))
          (loop for symbol in symbols for original in originals do (setf (symbol-function symbol) original)))))))
