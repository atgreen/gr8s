;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.resources)

(defun store-member-bootstrap-progress (store phase descriptor)
  "Durable bootstrap phase boundary, before RPC traffic is allowed."
  (declare (ignore store phase descriptor)))

(defun validate-store-member-bootstrap (record id role api-url)
  (unless (and (hash-table-p record) (= 7 (hash-table-count record))
               (equal "gr8s-store-bootstrap" (gethash "format" record))
               (eql 1 (gethash "version" record))
               (equal id (gethash "memberID" record))
               (equal role (gethash "role" record))
               (equal api-url (gethash "apiURL" record))
               (member (gethash "phase" record) '("creating" "prepared" "published") :test #'equal))
    (error "Application WAL bootstrap identity or phase mismatch"))
  (let* ((application (gethash "application" record))
         (index (if (equal role "founder") 1 0))
         (phase (gethash "phase" record)))
    (unless (and (hash-table-p application) (= 3 (hash-table-count application))
                 (eql index (gethash "index" application)) (eql 0 (gethash "term" application)))
      (error "Invalid bootstrap application boundary"))
    (if (equal phase "creating")
        (unless (equal "" (gethash "sha256" application)) (error "Creating bootstrap already names an artifact"))
        (store-snapshot-artifact-reference index 0 (gethash "sha256" application))))
  record)

(defun write-store-member-bootstrap (path descriptor &key replace)
  "Fsync the journal before publishing it, then fsync its containing directory."
  (let ((temporary (gr8s.security::private-temporary-path path)))
    (unwind-protect
         (progn
           (gr8s.security::write-private-text-exclusively
            temporary
            (lambda (stream)
              (com.inuoe.jzon:stringify descriptor :stream stream)
              (finish-output stream)
              (sb-posix:fsync (sb-sys:fd-stream-fd stream))))
           (if replace
               (sb-posix:rename (namestring temporary) (namestring path))
               (unless (zerop (cffi:foreign-funcall "renameat2" :int -100 :string (namestring temporary)
                                                   :int -100 :string (namestring path) :uint 1 :int))
                 (error "Cannot create application bootstrap journal")))
           (gr8s.store::sync-store-generation-directory (uiop:pathname-directory-pathname path)))
      (when (gr8s.store::store-generation-stat temporary) (sb-posix:unlink (namestring temporary)))))
  descriptor)

(defun store-member-bootstrap-envelope (descriptor)
  (let* ((application (gethash "application" descriptor))
         (reference (store-snapshot-artifact-reference (gethash "index" application) 0 (gethash "sha256" application)))
         (id (gethash "memberID" descriptor))
         (role (if (equal "founder" (gethash "role" descriptor)) :voter :learner))
         (api-url (gethash "apiURL" descriptor)))
    ;; The first committed config change carries the complete bound address book.
    ;; A learner's zero boundary cannot mask the leader's index-one baseline.
    (list :cl-raft-snapshot 1 :application reference :application-present t
          :members (list (cons id role)) :addresses nil
          :api-urls (when (plusp (length api-url)) (list (cons id api-url))))))

(defun bootstrap-store-member-wal (store id &key (role :founder) api-url)
  "Publish or resume a pristine application WAL before starting its member.
Caller owns the outer application barriers and a drained access gate. This does
not select application files, serve RPCs, start elections or replace an active WAL.
Returns WAL pathname and retained artifact reference. Production callers must
also own their state directory before opening/writing application files."
  (unless (and (stringp id) (<= 1 (length id) 253) (member role '(:founder :learner))
               (or (null api-url) (and (stringp api-url) (<= (length api-url) 256))))
    (error "Invalid application member bootstrap identity"))
  (unless (gr8s.store::store-application-barriers-owned-p store)
    (error "Application bootstrap requires outer writer barriers"))
  (bt:with-lock-held ((pod-store-lock store)) (gr8s.store::require-store-reload-quiescence store))
  (let* ((root (pod-store-path store))
         (directory (merge-pathnames "raft/" root))
         (wal (merge-pathnames "control-plane.log" directory))
         (journal (merge-pathnames "bootstrap.json" directory))
         (role-name (if (eq role :founder) "founder" "learner"))
         (api-url (or api-url ""))
         (index (if (eq role :founder) 1 0))
         (descriptor nil) (storage nil))
    (gr8s.store::check-store-generation-directory root :metadata t)
    (gr8s.store::ensure-store-generation-directory directory root :metadata t)
    (unwind-protect
         (progn
           (setf storage
                 (gr8s.raft:open-file-raft-storage
                  wal :prepare-fn
                  (lambda (canonical)
                    (let ((stat (gr8s.store::store-generation-stat canonical)))
                      (when (and stat (or (not (sb-posix:s-isreg (sb-posix:stat-mode stat)))
                                          (/= 1 (sb-posix:stat-nlink stat))))
                        (error "Unsafe existing application WAL"))
                      (if (gr8s.store::store-generation-stat journal)
                          (setf descriptor
                                (validate-store-member-bootstrap
                                 (gr8s.store::read-private-generation-json journal) id role-name api-url))
                          (progn
                            (when stat (error "Existing application WAL has no bootstrap journal"))
                            (setf descriptor
                                  (core-object "format" "gr8s-store-bootstrap" "version" 1
                                               "memberID" id "role" role-name "apiURL" api-url
                                               "phase" "creating" "application"
                                               (core-object "index" index "term" 0 "sha256" "")))
                            (write-store-member-bootstrap journal descriptor)))
                      (when (and (equal "published" (gethash "phase" descriptor)) (null stat))
                        (error "Published application WAL is missing"))
                      (when (and stat (plusp (sb-posix:stat-size stat))
                                 (equal "creating" (gethash "phase" descriptor)))
                        (error "Unprepared bootstrap already contains WAL records"))
                      (store-member-bootstrap-progress store :before-open descriptor)))))
           (let ((size (sb-posix:stat-size (sb-posix:stat wal))))
             (when (and (zerop size) (equal "published" (gethash "phase" descriptor)))
               (error "Published application WAL is empty"))
             (when (equal "creating" (gethash "phase" descriptor))
               (let ((source (merge-pathnames (format nil "bootstrap-~A.jsonl" (generate-uid)) directory)))
                 (unwind-protect
                      (progn
                        (capture-store-snapshot store source index 0)
                        (let ((digest (ironclad:byte-array-to-hex-string (ironclad:digest-file :sha256 source))))
                          (retain-store-snapshot-artifact root source index 0 digest)
                          (setf (gethash "sha256" (gethash "application" descriptor)) digest
                                (gethash "phase" descriptor) "prepared")
                          (write-store-member-bootstrap journal descriptor :replace t)))
                   (when (gr8s.store::store-generation-stat source) (sb-posix:unlink (namestring source))))))
             (let* ((state (store-member-bootstrap-envelope descriptor))
                    (reference (getf (cddr state) :application)))
               (checked-store-snapshot-artifact-path root reference)
               (store-member-bootstrap-progress store :prepared descriptor)
               (when (zerop size)
                 (gr8s.raft::raft-storage-replace-snapshot storage index 0 state 0 nil #()))
               ;; An interrupted atomic rename is either empty or a complete
               ;; pristine baseline. Never compact or overwrite later hard state.
               (let ((recovered (gr8s.raft:load-raft-log wal)))
                 (unless (and (= 0 (gr8s.raft::raft-recovered-term recovered))
                              (null (gr8s.raft::raft-recovered-vote recovered))
                              (null (gr8s.raft::raft-recovered-entries recovered))
                              (= index (gr8s.raft::raft-recovered-snapshot-index recovered))
                              (= 0 (gr8s.raft::raft-recovered-snapshot-term recovered))
                              (equal state (gr8s.raft::raft-recovered-snapshot-state recovered)))
                   (error "Bootstrap cannot replace an initialized or mismatched application WAL")))
               (store-member-bootstrap-progress store :wal-published descriptor)
               (unless (equal "published" (gethash "phase" descriptor))
                 (setf (gethash "phase" descriptor) "published")
                 (write-store-member-bootstrap journal descriptor :replace t))
               (store-member-bootstrap-progress store :published descriptor)
               (values wal reference))))
      (when storage (gr8s.raft:close-file-raft-storage storage)))))
