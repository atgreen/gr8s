;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.server)

(defstruct serve-state-lease root fd device inode thread)
(defvar *serve-state-lease* nil)

(defun require-serve-state-ownership (options)
  "Require this thread's live serve lease before opening application state."
  (let* ((lease *serve-state-lease*)
         (root (truename (uiop:ensure-directory-pathname (getf options :state-directory))))
         (stat (and lease (serve-state-lease-fd lease)
                    (sb-posix:fstat (serve-state-lease-fd lease)))))
    (unless (and lease (eq (bt:current-thread) (serve-state-lease-thread lease))
                 (equal root (serve-state-lease-root lease)) stat
                 (= (sb-posix:stat-dev stat) (serve-state-lease-device lease))
                 (= (sb-posix:stat-ino stat) (serve-state-lease-inode lease)))
      (error "Serve must own its state directory before opening application files"))
    lease))

(defun write-serve-state-mode (path mode)
  (let ((temporary (gr8s.security::private-temporary-path path)))
    (unwind-protect
         (progn
           (gr8s.security::write-private-text-exclusively
            temporary
            (lambda (stream)
              (com.inuoe.jzon:stringify
               (gr8s.resources::core-object "format" "gr8s-serve-mode" "version" 1 "mode" mode) :stream stream)
              (finish-output stream)
              (sb-posix:fsync (sb-sys:fd-stream-fd stream))))
           (sb-posix:rename (namestring temporary) (namestring path))
           (gr8s.store::sync-store-generation-directory (uiop:pathname-directory-pathname path)))
      (when (gr8s.store::store-generation-stat temporary) (sb-posix:unlink (namestring temporary))))))

(defun check-serve-state-mode (root options)
  "Never silently open a Raft application's files as standalone state."
  (when (and (getf options :raft-init) (getf options :raft-join))
    (error "Serve cannot both found and join a Raft cluster"))
  (when (getf options :raft-join) (parse-agent-server (getf options :raft-join)))
  (when (gr8s.store::store-generation-stat (merge-pathnames "raft/witness.log" root))
    (error "Witness state cannot be opened by serve"))
  (let* ((directory (merge-pathnames "metadata/" root))
         (path (merge-pathnames "server-mode.json" directory))
         (requested (if (or (getf options :raft-init) (getf options :raft-join)) "ha" "standalone"))
         (existing (progn
                     (when (gr8s.store::store-generation-stat directory)
                       (gr8s.store::check-store-generation-directory directory :metadata t))
                     (when (gr8s.store::store-generation-stat path)
                       (gr8s.store::read-private-generation-json path))))
         (legacy-ha (some (lambda (name) (gr8s.store::store-generation-stat (merge-pathnames name root)))
                          '("raft/control-plane.log" "raft/bootstrap.json" "pki/raft/"))))
    (when existing
      (unless (and (hash-table-p existing) (= 3 (hash-table-count existing))
                   (equal "gr8s-serve-mode" (gethash "format" existing))
                   (eql 1 (gethash "version" existing))
                   (member (gethash "mode" existing) '("ha" "standalone") :test #'equal))
        (error "Invalid persisted serve mode")))
    (when (and (equal requested "standalone")
               (or legacy-ha (and existing (equal "ha" (gethash "mode" existing)))))
      (error "HA state requires its Raft startup options; standalone fallback is refused"))
    ;; An explicit HA request can found a cluster from existing standalone data.
    ;; Persist intent before opening files, so interrupted HA startup cannot later
    ;; fall through to standalone merely because its flags were omitted.
    (unless (and existing (equal requested (gethash "mode" existing)))
      (gr8s.store::ensure-store-generation-directory directory root :metadata t)
      (write-serve-state-mode path requested))))

(defun call-with-serve-state-ownership (options function)
  "Own the canonical state directory across all initialization and teardown.
Do not remove the stable lock file on close: another opener may already hold it."
  (unless (and (functionp function) (or (stringp (getf options :state-directory))
                                      (pathnamep (getf options :state-directory))))
    (error "Invalid serve state ownership arguments"))
  (let* ((requested (uiop:ensure-directory-pathname (getf options :state-directory)))
         (root (progn (ensure-directories-exist (merge-pathnames ".gr8s-serve.lock" requested))
                      (truename requested)))
         (path (merge-pathnames ".gr8s-serve.lock" root))
         (fd nil) (lease nil))
    (gr8s.store::check-store-generation-directory root :metadata t)
    (unwind-protect
         (progn
           (setf fd (sb-posix:open (namestring path)
                                   (logior sb-posix:o-rdwr sb-posix:o-creat sb-posix:o-nofollow sb-posix:o-nonblock) #o600))
           (unless (zerop (cffi:foreign-funcall "fcntl" :int fd :int 2 :int 1 :int))
             (error "Cannot protect serve ownership across exec"))
           (let ((stat (sb-posix:fstat fd)))
             (unless (and (sb-posix:s-isreg (sb-posix:stat-mode stat))
                          (= 1 (sb-posix:stat-nlink stat))
                          (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                          (= #o600 (logand #o777 (sb-posix:stat-mode stat))))
               (error "Unsafe serve ownership file"))
             (unless (zerop (cffi:foreign-funcall "flock" :int fd :int 6 :int))
               (error "Another serve process owns state directory ~A" root))
             (setf lease (make-serve-state-lease :root root :fd fd
                          :device (sb-posix:stat-dev stat) :inode (sb-posix:stat-ino stat)
                          :thread (bt:current-thread))))
           (let ((*serve-state-lease* lease))
             (check-serve-state-mode root options)
             (funcall function)))
      (when lease (setf (serve-state-lease-fd lease) nil))
      (when fd (sb-posix:close fd)))))
