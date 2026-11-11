;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.server)

(defparameter +backup-runtime-prefixes+
  '("agent/containerd/" "agent/runtime/" "agent/pods/" "containerd/" "raft/transfers/"))
(defparameter +backup-lock-paths+
  '(".gr8s-serve.lock" "raft/control-plane.log.lock" "raft/witness.log.lock"))

(defun backup-excluded-path-p (relative)
  (or (member relative +backup-lock-paths+ :test #'equal)
      (some (lambda (prefix)
              (or (equal relative (string-right-trim "/" prefix))
                  (uiop:string-prefix-p prefix relative)))
            +backup-runtime-prefixes+)))

(defun map-offline-backup-files (directory function)
  "Visit stable state files under offline ownership without opening application state.
FUNCTION receives relative name, source pathname and lstat metadata. Payload bytes
are never loaded here. A bundle writer must open with no-follow and recheck the
metadata before copying. Runtime trees and ownership inodes are explicitly omitted;
all other files, including identity, generations and patch state, are retained."
  (unless (functionp function) (error "Backup visitor must be a function"))
  (call-with-offline-state-ownership
   directory
   (lambda ()
     (let* ((root (truename (uiop:ensure-directory-pathname directory)))
            (count 0) (bytes 0) (excluded nil))
       (labels ((visit (path relative)
                  (when (backup-excluded-path-p relative)
                    (push relative excluded)
                    (return-from visit nil))
                  (let ((stat (gr8s.store::store-generation-stat path)))
                    (unless (and stat (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                                 (zerop (logand #o022 (sb-posix:stat-mode stat))))
                      (error "Unsafe backup source ~A" relative))
                    (cond
                      ((sb-posix:s-isdir (sb-posix:stat-mode stat))
                       (dolist (child (sort (directory (merge-pathnames #P"*.*" (uiop:ensure-directory-pathname path))
                                                      :resolve-symlinks nil)
                                           #'string< :key (lambda (child) (string-right-trim "/" (namestring child)))))
                         (visit child (enough-namestring child root))))
                      ((and (sb-posix:s-isreg (sb-posix:stat-mode stat))
                            (= 1 (sb-posix:stat-nlink stat)))
                       (funcall function relative path stat)
                       (incf count) (incf bytes (sb-posix:stat-size stat)))
                      (t (error "Backup refuses links or special files: ~A" relative))))))
         (visit root "")
         (values count bytes (nreverse excluded)))))))
