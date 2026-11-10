;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Read-only development probe. Never opens a writable WAL or acquires its lease.
(require :asdf)
(require :sb-posix)
(let ((*standard-output* *error-output*))
  (asdf:initialize-source-registry
   `(:source-registry (:tree ,(namestring (truename "ocicl/"))) :inherit-configuration))
  (dolist (system '("bordeaux-threads" "ironclad" "cffi" "flexi-streams" "trivial-utf-8" "com.inuoe.jzon"))
    (asdf:load-system system))
  (load "src/raft/package.lisp")
  (load "src/raft/core.lisp")
  (load "src/raft/log.lisp"))

(defun ha-inspect-object (&rest pairs)
  (let ((object (make-hash-table :test 'equal)))
    (loop for (key value) on pairs by #'cddr do (setf (gethash key object) value))
    object))

(defun ha-inspect-wal (path)
  (let* ((saved (gr8s.raft:load-raft-log path))
         (state (gr8s.raft:raft-recovered-snapshot-state saved))
         (config (when (gr8s.raft::raft-snapshot-envelope-p state) (getf (cddr state) :members)))
         (commit (gr8s.raft:raft-recovered-commit-index saved)))
    (dolist (entry (gr8s.raft:raft-recovered-entries saved))
      (let ((command (gr8s.raft:raft-entry-command entry)))
        (when (and (<= (gr8s.raft:raft-entry-index entry) commit)
                   (consp command) (eq :raft-config (first command)))
          (setf config (getf (cdr command) :members)))))
    (ha-inspect-object
     "path" path "term" (gr8s.raft:raft-recovered-term saved)
     "commit" commit "snapshotIndex" (gr8s.raft:raft-recovered-snapshot-index saved)
     "members" (coerce (mapcar (lambda (entry)
                                 (ha-inspect-object "id" (car entry)
                                                    "role" (string-downcase (symbol-name (cdr entry))))) config) 'vector))))

(let* ((args (uiop:command-line-arguments))
       (paths (if (equal "--" (first args)) (rest args) args)))
  (write-line (com.inuoe.jzon:stringify (map 'vector #'ha-inspect-wal paths))))
