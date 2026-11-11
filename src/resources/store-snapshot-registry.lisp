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

(defun copy-store-snapshot-artifact-reference (reference)
  "Validate a portable identity and return a privately owned canonical copy."
  (unless (and (alexandria:proper-list-p reference) (= 8 (length reference)))
    (error "Invalid store snapshot artifact reference"))
  (let ((copy (store-snapshot-artifact-reference
               (fourth reference) (sixth reference) (eighth reference))))
    (unless (equal reference copy) (error "Invalid store snapshot artifact reference"))
    copy))

(defun call-with-store-artifact-pin (member reference function)
  "Protect REFERENCE before publishing its file, through adoption or abandonment.
FUNCTION runs outside the member mutex. Its owner must publish the durable Raft
reference before returning; failed/abandoned files become reclaimable on unwind.
Nested or concurrent owners of the same digest retain independent pins."
  (when (sb-thread:holding-mutex-p (gr8s.raft.transport:raft-member-lock member))
    (error "Artifact pin scope must start outside the member mutex"))
  (let ((pin (list (copy-store-snapshot-artifact-reference reference))))
    (bt:with-lock-held ((gr8s.raft.transport:raft-member-lock member))
      (push pin (gr8s.raft.transport::raft-member-artifact-pins member)))
    (unwind-protect (funcall function)
      (bt:with-lock-held ((gr8s.raft.transport:raft-member-lock member))
        (setf (gr8s.raft.transport::raft-member-artifact-pins member)
              (delete pin (gr8s.raft.transport::raft-member-artifact-pins member)
                      :test #'eq :count 1))))))

(defun store-snapshot-registry-directory (root)
  (let* ((root (uiop:ensure-directory-pathname root))
         (path (merge-pathnames "snapshot-artifacts/" root)))
    (gr8s.store::check-store-generation-directory root :metadata t)
    (gr8s.store::ensure-store-generation-directory path root)))

(defun checked-store-snapshot-artifact-path (root reference)
  "Resolve a canonical reference, checking permissions and hashing bytes on every use.
Published artifacts are immutable by contract. The private member root must not be
modified concurrently by another process. Semantic validation occurs at publication."
  (copy-store-snapshot-artifact-reference reference)
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
           (unless (gr8s.raft.transport::raft-snapshot-private-stat-p
                    (sb-posix:lstat (namestring temporary)) nil)
             (error "Unsafe private store snapshot artifact"))
           (validate-store-snapshot temporary :expected-index index :expected-term term)
           ;; LINK is atomic and refuses overwrite. Concurrent identical retainers
           ;; can share the winner, but an invalid existing file is never replaced.
           (handler-case (sb-posix:link (namestring temporary) (namestring target))
             (sb-posix:syscall-error (condition)
               (unless (= sb-posix:eexist (sb-posix:syscall-errno condition)) (error condition))
               ;; A pre-existing winner is not our verified inode. Authenticate
               ;; and validate it fully, including a retry after failed fsync.
               (checked-store-snapshot-artifact-path root reference)))
           ;; Successful LINK published the already hashed, validated private
           ;; inode. Re-reading it here doubles a potentially large semantic
           ;; scan while the caller holds its consensus/application barriers.
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

(defun store-snapshot-artifact-owner-p (member root)
  "True only under the member mutex with its matching application WAL open."
  (and (sb-thread:holding-mutex-p (gr8s.raft.transport:raft-member-lock member))
       (let* ((storage (gr8s.raft.transport::raft-member-owned-storage member))
              (stream (and (typep storage 'gr8s.raft::file-raft-storage)
                           (gr8s.raft::file-raft-storage-stream storage))))
         (and stream (open-stream-p stream)
              (eq storage (gr8s.raft:raft-node-storage (gr8s.raft.transport:raft-member-node member)))
              (let ((expected (probe-file (merge-pathnames "raft/control-plane.log" root))))
                (and expected
                     (equal expected (probe-file (gr8s.raft::file-raft-storage-path storage)))))))))

(defun store-snapshot-artifact-keep-digests-unlocked (member root)
  "Validate all protected roots before claiming any registry file."
  (unless (store-snapshot-artifact-owner-p member root)
    (error "Artifact reclamation requires the member's open application WAL and lock"))
  (let* ((node (gr8s.raft.transport:raft-member-node member))
         (keep (make-hash-table :test 'equal)))
    (labels ((keep-reference (reference)
               (let ((copy (copy-store-snapshot-artifact-reference reference)))
                 (setf (gethash (eighth copy) keep) t)))
             (keep-state (state)
               (when (gr8s.raft::raft-snapshot-envelope-p state)
                 (let ((reference (getf (cddr state) :application)))
                   (when reference
                     (keep-reference reference))))))
      (unless (keep-state (gr8s.raft:raft-node-snapshot-state node))
        (error "Artifact reclamation requires a durable application snapshot baseline"))
      (when (gr8s.raft:raft-node-snapshot-pending node)
        (keep-state (third (gr8s.raft:raft-node-snapshot-pending node))))
      (dolist (pin (gr8s.raft.transport::raft-member-artifact-pins member))
        (keep-reference (first pin)))
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
      keep)))

(defun store-snapshot-artifact-filename-p (name)
  (and (= (length name) 70) (string= ".jsonl" name :start2 64)
       (every (lambda (char) (find char "0123456789abcdef")) (subseq name 0 64))))

(defun store-snapshot-artifact-trash-name-p (name)
  (let* ((prefix ".retired-") (digest-start (length prefix))
         (digest-end (+ digest-start 64)) (uuid-start (1+ digest-end))
         (uuid-end (+ uuid-start 36)))
    (and (= (length name) (+ uuid-end (length ".jsonl")))
         (uiop:string-prefix-p prefix name)
         (every (lambda (char) (find char "0123456789abcdef")) (subseq name digest-start digest-end))
         (char= #\- (char name digest-end))
         (gr8s.store::store-generation-id-p (subseq name uuid-start uuid-end))
         (string= ".jsonl" name :start2 uuid-end))))

(defun claim-store-snapshot-artifacts-unlocked (member root &key (maximum-artifacts 1))
  "Detach a bounded batch of unreferenced artifacts under WAL/member ownership.
All roots are validated before renaming. Claimed files use unique private trash
names; later retention of the same digest publishes a separate canonical file.
No payload is read or unlinked in this critical section. Returns trash paths."
  (unless (typep maximum-artifacts '(integer 1 *)) (error "Invalid artifact claim budget"))
  (let* ((keep (store-snapshot-artifact-keep-digests-unlocked member root))
         (directory (store-snapshot-registry-directory root)) (claimed nil))
    (unwind-protect
         (block scan
           (gr8s.raft.transport::raft-snapshot-map-directory
            directory
            (lambda (name)
              (when (and (store-snapshot-artifact-filename-p name)
                         (not (gethash (subseq name 0 64) keep)))
                (let* ((path (merge-pathnames name directory))
                       (stat (gr8s.store::store-generation-stat path)))
                  (when (and stat (gr8s.raft.transport::raft-snapshot-private-stat-p stat nil))
                    (let ((trash (merge-pathnames
                                  (format nil ".retired-~A-~A.jsonl" (subseq name 0 64) (generate-uid)) directory)))
                      (sb-sys:without-interrupts
                        (unless (zerop (cffi:foreign-funcall "renameat2" :int -100 :string (namestring path)
                                                           :int -100 :string (namestring trash) :uint 1 :int))
                          (error "Cannot claim superseded snapshot artifact"))
                        (push trash claimed)))
                    (when (>= (length claimed) maximum-artifacts) (return-from scan nil))))))))
      (when claimed (gr8s.store::sync-store-generation-directory directory)))
    (nreverse claimed)))

(defun reap-store-snapshot-artifact-trash (root &key (maximum-artifacts 8))
  "Unlink recognized private detached artifacts outside the member mutex.
A trash pathname can never be a portable artifact reference. Its UUID separates
an old claimed inode from concurrent new retention of the same digest. Recheck
ownership, mode and single-link regular-file status; unsafe/unknown files stay.
The caller retains member-root ownership through maintenance shutdown/join."
  (unless (typep maximum-artifacts '(integer 1 *)) (error "Invalid artifact cleanup budget"))
  (let ((directory (store-snapshot-registry-directory root)) (removed 0))
    (unwind-protect
         (block scan
           (gr8s.raft.transport::raft-snapshot-map-directory
            directory
            (lambda (name)
              (when (store-snapshot-artifact-trash-name-p name)
                (let* ((path (merge-pathnames name directory))
                       (stat (gr8s.store::store-generation-stat path)))
                  (when (and stat (gr8s.raft.transport::raft-snapshot-private-stat-p stat nil))
                    (handler-case (progn (sb-posix:unlink (namestring path)) (incf removed))
                      (sb-posix:syscall-error (condition)
                        (unless (= sb-posix:enoent (sb-posix:syscall-errno condition)) (error condition)))))))
              (when (>= removed maximum-artifacts) (return-from scan nil)))))
      (when (plusp removed) (gr8s.store::sync-store-generation-directory directory)))
    removed))


(defun store-snapshot-startup-temporary-name-p (name registry-p)
  "Recognize only our UUID publication/capture names, including pre-rename scratch."
  (labels ((uuid (start end) (gr8s.store::store-generation-id-p (subseq name start end))))
    (if registry-p
        (and (= 41 (length name)) (string= ".part" name :start2 36) (uuid 0 36))
        (or (and (= 50 (length name)) (string= "capture-" name :end2 8)
                 (uuid 8 44) (string= ".jsonl" name :start2 44))
            (and (= 74 (length name)) (string= ".capture-" name :end2 9)
                 (uuid 9 45) (char= #\- (char name 45))
                 (every (lambda (char) (digit-char-p char 16)) (subseq name 46 70))
                 (string= ".tmp" name :start2 70))))))

(defun reap-store-snapshot-startup-temporaries-unlocked (member store)
  "Remove recognized abandoned private scratch only before application listening.
Production caller also holds/verifies its state-directory lease. Application
barriers and the recovered WAL lease exclude legitimate live publishers."
  (let* ((root (pod-store-path store))
         (storage (gr8s.raft.transport::raft-member-owned-storage member)))
    (unless (and (sb-thread:holding-mutex-p (gr8s.raft.transport:raft-member-lock member))
                 (gr8s.store::store-application-barriers-owned-p store)
                 (gr8s.store::store-access-blocked-p store)
                 (not (gr8s.raft.transport::raft-member-running member))
                 (null (gr8s.raft.transport::raft-member-grpc-server member))
                 (typep storage 'gr8s.raft::file-raft-storage)
                 (eq storage (gr8s.raft:raft-node-storage (gr8s.raft.transport:raft-member-node member)))
                 (gr8s.raft::file-raft-storage-ownership-fd storage)
                 (gr8s.raft::file-raft-storage-stream storage)
                 (open-stream-p (gr8s.raft::file-raft-storage-stream storage))
                 (equal (merge-pathnames "raft/control-plane.log" root)
                        (merge-pathnames (gr8s.raft::file-raft-storage-path storage))))
      (error "Startup scratch reclamation requires pre-listener recovered WAL and application ownership"))
    (gr8s.store::check-store-generation-directory root :metadata t)
    (let ((removed 0))
      (dolist (spec '(("snapshot-artifacts/" . t) ("raft/" . nil)))
        (let ((directory (merge-pathnames (car spec) root)) (changed nil))
          (when (gr8s.store::store-generation-stat directory)
            ;; Never follow a substituted directory or traverse children.
            (gr8s.store::check-store-generation-directory directory :metadata (not (cdr spec)))
            (unwind-protect
                 (gr8s.raft.transport::raft-snapshot-map-directory
                  directory
                  (lambda (name)
                    (when (store-snapshot-startup-temporary-name-p name (cdr spec))
                      (let* ((path (merge-pathnames name directory))
                             (stat (sb-posix:lstat (namestring path))))
                        (when (gr8s.raft.transport::raft-snapshot-private-stat-p stat nil)
                          (sb-posix:unlink (namestring path))
                          (setf changed t)
                          (incf removed))))))
              (when changed (gr8s.store::sync-store-generation-directory directory))))))
      removed)))
