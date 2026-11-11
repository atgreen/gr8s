;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.store)

(defun call-with-store-data-reader (store function)
  "Pin the current filesystem generation while FUNCTION receives its pathname.
Use for readers that outlive the raw store mutex. Normal synchronous application
loading and writes already hold that mutex. Pins survive application reload."
  (let ((path nil) (entered nil))
    (unwind-protect
         (progn
           (bt:with-lock-held ((pod-store-lock store))
             (unless (and (pod-store-application-loaded-p store) (not (pod-store-access-blocked store)))
               (error "Application data is unavailable"))
             (setf path (store-data-path store))
             (sb-sys:without-interrupts
               (incf (gethash path (pod-store-generation-readers store) 0))
               (setf entered t)))
           (funcall function path))
      (when entered
        (bt:with-lock-held ((pod-store-lock store))
          (sb-sys:without-interrupts
            (when (zerop (decf (gethash path (pod-store-generation-readers store))))
              (remhash path (pod-store-generation-readers store)))))))))

(defun store-generation-trash-path (root id)
  (unless (store-generation-id-p id) (error "Invalid retired generation identity"))
  (merge-pathnames (format nil ".retired-~A/" id) (store-generation-base root)))

(defun store-generation-protected-p (store id)
  "Caller holds the raw store mutex. Fail closed throughout incomplete reloads."
  (let* ((root (pod-store-path store)) (path (store-generation-root root id))
         (selected (selected-store-generation-root root))
         (intent (read-store-restore-intent root)))
    (or (not (pod-store-application-loaded-p store))
        (pod-store-access-blocked store)
        (not (equal (store-data-path store) (or selected root)))
        intent
        (equal selected path) (equal (store-data-path store) path)
        (plusp (gethash path (pod-store-generation-readers store) 0)))))

(defun claim-retired-store-generation (store descriptor)
  "Atomically detach a verified retired generation under the raw mutex.
No tree traversal or data unlink occurs while holding the store mutex."
  (bt:with-lock-held ((pod-store-lock store))
    (let* ((root (pod-store-path store)) (id (gethash "generation" descriptor))
           (source (store-generation-root root id)) (trash (store-generation-trash-path root id)))
      (when (store-generation-protected-p store id)
        (return-from claim-retired-store-generation nil))
      (check-store-generation-directory (store-generation-base root))
      (unless (store-generation-descriptor-equal-p
               descriptor (read-store-generation-descriptor (store-generation-retirement-path root id)))
        (error "Retirement descriptor changed"))
      (when (store-generation-stat source)
        (unless (store-generation-descriptor-equal-p descriptor (checked-store-generation-descriptor root id))
          (error "Retired generation has a different completion marker"))
        (when (store-generation-stat trash) (error "Retired generation exists in both locations"))
        (unless (zerop (cffi:foreign-funcall "renameat2" :int -100 :string (namestring source)
                                            :int -100 :string (namestring trash) :uint 1 :int))
          (error "Cannot detach retired generation"))
        (sync-store-generation-directory (store-generation-base root)))
      (when (store-generation-stat trash)
        (check-store-generation-directory trash)
        (let ((marker (merge-pathnames "generation.meta" trash)))
          (when (store-generation-stat marker)
            (unless (store-generation-descriptor-equal-p descriptor (read-store-generation-descriptor marker))
              (error "Retired trash has a different completion marker"))))
        trash))))

(defun map-generation-directory-entries (path function)
  "Enumerate without resolving symlinks or building a list of application files.
Stop when FUNCTION returns NIL. The callback may unlink the current entry."
  (check-store-generation-directory path)
  (let ((directory (sb-posix:opendir (namestring path))))
    (unwind-protect
         (loop for entry = (sb-posix:readdir directory)
               until (sb-alien:null-alien entry)
               for name = (sb-posix:dirent-name entry)
               unless (member name '("." "..") :test #'equal)
                 do (unless (funcall function name) (return)))
      (sb-posix:closedir directory))))

(defun known-generation-file-p (directory name)
  (cond ((equal directory "")
         (or (equal name "pod-revision.ceiling")
             (and (equal (pathname-type name) "json") (store-generation-id-p (pathname-name name)))))
        ((equal directory "objects/") (member name '("state.json" "journal.jsonl") :test #'equal))
        ((equal directory "metadata/")
         (member name '("snapshot-boundary.json" "consensus-pod-revision.txt") :test #'equal))
        ((equal directory "image-tracker/") (equal name "state.jsonl"))
        ((member directory '("nodes/" "observations/" "publications/") :test #'equal)
         (and (equal (pathname-type name) "json") (stringp (pathname-name name)) (plusp (length (pathname-name name)))
              (every (lambda (char) (or (alphanumericp char) (find char "-_."))) (pathname-name name))))))

(defun remove-empty-generation-directory (path)
  (handler-case (progn (sb-posix:rmdir (namestring path)) t)
    (sb-posix:syscall-error (condition)
      (unless (member (sb-posix:syscall-errno condition) (list sb-posix:enotempty sb-posix:eexist))
        (error condition)))))

(defun prune-store-generation-trash (path maximum-entries)
  "Unlink only known, private, owned single-link regular application files.
Bound application entry visits by MAXIMUM-ENTRIES; fixed metadata and empty
directory cleanup add operations. Unknown contents and links are retained.
The fixed application layout has no recursive subdirectories."
  (let ((remaining maximum-entries) (removed 0))
    (labels ((prune (directory)
               (let ((base (merge-pathnames directory path)))
                 (when (and (plusp remaining) (store-generation-stat base))
                   (map-generation-directory-entries
                    base (lambda (name)
                           (unless (plusp remaining) (return-from prune nil))
                           (decf remaining)
                           (when (known-generation-file-p directory name)
                             (let* ((file (merge-pathnames name base)) (stat (store-generation-stat file)))
                               (when (and stat (sb-posix:s-isreg (sb-posix:stat-mode stat))
                                          (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                                          (= 1 (sb-posix:stat-nlink stat))
                                          ;; Older Pod/Node writers use 0644. The enclosing
                                          ;; generation and child directories are private 0700.
                                          (zerop (logand #o7133 (sb-posix:stat-mode stat))))
                                 (sb-posix:unlink (namestring file)) (incf removed))))
                           (plusp remaining)))
                   (sync-store-generation-directory base)
                   (unless (equal directory "") (remove-empty-generation-directory base))))))
      ;; Traverse known directories explicitly; never descend into unknown paths.
      (dolist (directory '("objects/" "nodes/" "observations/" "publications/" "metadata/" "image-tracker/" ""))
        (prune directory))
      (let ((only-marker t))
        (map-generation-directory-entries
         path (lambda (name)
                (unless (equal name "generation.meta") (setf only-marker nil)) only-marker))
        (when only-marker
          (let ((marker (merge-pathnames "generation.meta" path)))
            (when (store-generation-stat marker)
              ;; The descriptor was validated before pruning. Recheck file safety.
              (read-store-generation-descriptor marker)
              (sb-posix:unlink (namestring marker))))
          (remove-empty-generation-directory path)))
      removed)))

(defun reap-retired-store-generations (store &key (maximum-entries 64))
  "Claim at most one retired tree and prune a bounded batch outside live locks.
Run from maintenance, never from a member critical section. Directory metadata
is small; application payloads are neither parsed nor loaded into memory."
  (unless (typep maximum-entries '(integer 1 *)) (error "Invalid reclamation budget"))
  (bt:with-lock-held ((pod-store-generation-reap-lock store))
    (let* ((root (pod-store-path store))
           (directory (merge-pathnames "metadata/retired-generations/" root)))
      (unless (store-generation-stat directory) (return-from reap-retired-store-generations 0))
      (check-store-generation-directory (merge-pathnames "metadata/" root) :metadata t)
      (check-store-generation-directory directory)
      (let* ((records (sort (directory (merge-pathnames "*.json" directory) :resolve-symlinks nil)
                            #'string< :key #'namestring))
             (cursor (pod-store-generation-reap-cursor store))
             (ordered (if cursor
                          (append (remove-if (lambda (path) (string<= (namestring path) cursor)) records)
                                  (remove-if (lambda (path) (string> (namestring path) cursor)) records))
                          records)))
       (dolist (record ordered 0)
        (setf (pod-store-generation-reap-cursor store) (namestring record))
        (let* ((descriptor (read-store-generation-descriptor record)) (id (gethash "generation" descriptor)))
          (unless (equal record (store-generation-retirement-path root id))
            (error "Retirement filename disagrees with descriptor"))
          (let* ((trash (claim-retired-store-generation store descriptor))
                 (removed (if trash (prune-store-generation-trash trash maximum-entries) 0)))
            (bt:with-lock-held ((pod-store-lock store))
              (unless (or (store-generation-protected-p store id)
                          (store-generation-stat (store-generation-root root id))
                          (store-generation-stat (store-generation-trash-path root id)))
                ;; Resume this durable cleanup if a previous unlink/fsync failed.
                (sync-store-generation-directory (store-generation-base root))
                (sb-posix:unlink (namestring record))
                (sync-store-generation-directory directory)))
            (when trash (return removed)))))))))
