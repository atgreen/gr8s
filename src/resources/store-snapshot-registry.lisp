;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.resources)

(defun store-snapshot-artifact-reference (index term digest)
  "Portable WAL identity; index zero is reserved for a local learner baseline."
  (unless (and (typep index '(integer 0 #.most-positive-fixnum))
               (typep term '(integer 0 #.most-positive-fixnum))
               (or (plusp index) (zerop term))
               (stringp digest) (= 64 (length digest))
               (every (lambda (char) (find char "0123456789abcdef")) digest))
    (error "Invalid store snapshot artifact identity"))
  (list :gr8s-store-artifact 1 :index index :term term :sha256 (copy-seq digest)))

(defun store-snapshot-registry-directory (root)
  (let* ((root (uiop:ensure-directory-pathname root))
         (path (merge-pathnames "snapshot-artifacts/" root)))
    (gr8s.store::check-store-generation-directory root :metadata t)
    (gr8s.store::ensure-store-generation-directory path root)))

(defun checked-store-snapshot-artifact-path (root reference)
  "Resolve a canonical reference, checking permissions and hashing bytes on every use.
Published artifacts are immutable by contract. The private member root must not be
modified concurrently by another process. Semantic validation occurs at publication."
  (unless (and (listp reference) (= 8 (length reference))
               (equal reference
                      (store-snapshot-artifact-reference
                       (fourth reference) (sixth reference) (eighth reference))))
    (error "Invalid store snapshot artifact reference"))
  (let* ((digest (eighth reference))
         (path (merge-pathnames (format nil "~A.jsonl" digest)
                               (store-snapshot-registry-directory root)))
         (fd (sb-posix:open (namestring path)
                           (logior sb-posix:o-rdonly sb-posix:o-nofollow sb-posix:o-nonblock) 0))
         (input nil))
    (unwind-protect
         (let ((stat (sb-posix:fstat fd))
               (hash (ironclad:make-digest :sha256))
               (buffer (make-array 65536 :element-type '(unsigned-byte 8))))
           (unless (and (sb-posix:s-isreg (sb-posix:stat-mode stat))
                        (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                        (= #o600 (logand #o777 (sb-posix:stat-mode stat))))
             (error "Unsafe store snapshot artifact"))
           (setf input (sb-sys:make-fd-stream fd :input t :element-type '(unsigned-byte 8) :auto-close t))
           (loop for count = (read-sequence buffer input) while (plusp count)
                 do (ironclad:update-digest hash buffer :end count))
           (unless (equal digest (ironclad:byte-array-to-hex-string (ironclad:produce-digest hash)))
             (error "Store snapshot artifact checksum mismatch")))
      (if input (close input) (sb-posix:close fd)))
    ;; Bind index and term as well as digest, including after process restart.
    (validate-store-snapshot path :expected-index (fourth reference) :expected-term (sixth reference))
    path))

(defun retain-store-snapshot-artifact (root source index term digest)
  "Durably retain verified bytes before a caller writes their reference to the WAL.
Copies in 64 KiB buffers, validates the private copy, then publishes without replacing
an existing artifact. Returns its pathname and portable reference. No garbage collection
is performed: WAL snapshots, retained suffixes and transfers may still depend on it."
  (let* ((reference (store-snapshot-artifact-reference index term digest))
         (directory (store-snapshot-registry-directory root))
         (target (merge-pathnames (format nil "~A.jsonl" digest) directory))
         (temporary (merge-pathnames (format nil "~A.part" (generate-uid)) directory)))
    (unwind-protect
         (progn
           (copy-snapshot-generation-source (pathname source) temporary digest)
           (validate-store-snapshot temporary :expected-index index :expected-term term)
           ;; LINK is atomic and refuses overwrite. Concurrent identical retainers
           ;; can share the winner, but an invalid existing file is never replaced.
           (handler-case (sb-posix:link (namestring temporary) (namestring target))
             (sb-posix:syscall-error (condition)
               (unless (= sb-posix:eexist (sb-posix:syscall-errno condition)) (error condition))))
           (checked-store-snapshot-artifact-path root reference)
           (gr8s.store::sync-store-generation-directory directory)
           (values target reference))
      (when (probe-file temporary) (delete-file temporary)))))

(defun install-store-artifact-transport-unlocked (member root)
  "Install filesystem callbacks inside a caller's atomic member configuration."
  (unless (sb-thread:holding-mutex-p (gr8s.raft.transport:raft-member-lock member))
    (error "Artifact transport configuration requires the member lock"))
  (let ((root (uiop:ensure-directory-pathname root)))
    (setf (gr8s.raft.transport::raft-member-artifact-source-fn member)
          (lambda (member message)
            (declare (ignore member))
            (checked-store-snapshot-artifact-path root
             (getf (cddr (getf message :state)) :application)))
          (gr8s.raft.transport::raft-member-artifact-retain-fn member)
          (lambda (member path message)
            (declare (ignore member))
            (let ((reference (getf (cddr (getf message :state)) :application)))
              (retain-store-snapshot-artifact root path (getf message :last-index)
                                             (getf message :last-term) (eighth reference)))
            t)))
  member)

(defun configure-store-artifact-transport (member root)
  "Bind filesystem-only source/retention callbacks to MEMBER's stable ROOT.
This does not install application restore callbacks or enable compaction."
  (bt:with-lock-held ((gr8s.raft.transport:raft-member-lock member))
    (install-store-artifact-transport-unlocked member root)))

(defun reap-store-snapshot-artifacts-unlocked (member root)
  "Reclaim superseded immutable artifacts under exclusive WAL/member ownership.
Keep the durable snapshot, unfinished installation, original bootstrap baseline
and every queued/sender-owned snapshot. Unknown or unsafe files are untouched."
  (unless (and (sb-thread:holding-mutex-p (gr8s.raft.transport:raft-member-lock member))
               (let ((storage (gr8s.raft.transport::raft-member-owned-storage member)))
                 (and (typep storage 'gr8s.raft::file-raft-storage)
                      (eq storage (gr8s.raft:raft-node-storage (gr8s.raft.transport:raft-member-node member)))
                      (equal (merge-pathnames "raft/control-plane.log" root)
                             (merge-pathnames (gr8s.raft::file-raft-storage-path storage)))
                      (open-stream-p (gr8s.raft::file-raft-storage-stream storage)))))
    (error "Artifact reclamation requires the member's open application WAL and lock"))
  (let* ((node (gr8s.raft.transport:raft-member-node member))
         (directory (store-snapshot-registry-directory root))
         (keep (make-hash-table :test 'equal)) (removed 0))
    (labels ((keep-state (state)
               (when (gr8s.raft::raft-snapshot-envelope-p state)
                 (let ((reference (getf (cddr state) :application)))
                   (when reference
                     (unless (and (listp reference) (= 8 (length reference))
                                  (equal reference (store-snapshot-artifact-reference
                                                    (fourth reference) (sixth reference) (eighth reference))))
                       (error "Cannot reclaim artifacts with an unknown snapshot reference"))
                     (setf (gethash (eighth reference) keep) t))))))
      (unless (keep-state (gr8s.raft:raft-node-snapshot-state node))
        (error "Artifact reclamation requires a durable application snapshot baseline"))
      (when (gr8s.raft:raft-node-snapshot-pending node)
        (keep-state (third (gr8s.raft:raft-node-snapshot-pending node))))
      (dolist (message (gr8s.raft.transport::raft-member-snapshot-messages-unlocked member))
        (keep-state (getf message :state)))
      (let ((journal (merge-pathnames "raft/bootstrap.json" root)))
        (when (gr8s.store::store-generation-stat journal)
          (let ((record (gr8s.store::read-private-generation-json journal)))
            (unless (and (hash-table-p record)
                         (member (gethash "role" record) '("founder" "learner") :test #'equal)
                         (stringp (gethash "apiURL" record)))
              (error "Invalid bootstrap identity during artifact reclamation"))
            (validate-store-member-bootstrap record (gr8s.raft:raft-node-id node)
                                             (gethash "role" record) (gethash "apiURL" record))
            (unless (equal "creating" (gethash "phase" record))
              (setf (gethash (gethash "sha256" (gethash "application" record)) keep) t)))))
      (unwind-protect
           (gr8s.raft.transport::raft-snapshot-map-directory
            directory
            (lambda (name)
              (when (and (= (length name) 70) (string= ".jsonl" name :start2 64)
                         (every (lambda (char) (find char "0123456789abcdef")) (subseq name 0 64))
                         (not (gethash (subseq name 0 64) keep)))
                (let* ((path (merge-pathnames name directory))
                       (stat (sb-posix:lstat (namestring path))))
                  (when (gr8s.raft.transport::raft-snapshot-private-stat-p stat nil)
                    (sb-posix:unlink (namestring path))
                    (incf removed))))))
        (when (plusp removed) (gr8s.store::sync-store-generation-directory directory)))
      removed)))
