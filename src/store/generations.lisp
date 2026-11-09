;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Application generations are separate from stable member identity and Raft state.
(in-package #:gr8s.store)

(defun store-data-path (store)
  "Application files live in the selected generation; PATH remains the member root."
  (or (pod-store-data-root store) (pod-store-path store)))

(defun store-generation-id-p (value)
  (and (stringp value) (= 36 (length value))
       (loop for char across value for i from 0
             always (if (member i '(8 13 18 23)) (char= char #\-)
                        (find char "0123456789abcdef")))))

(defun store-generation-stat (path)
  (handler-case (sb-posix:lstat (string-right-trim "/" (namestring path)))
    (sb-posix:syscall-error (condition)
      (unless (= sb-posix:enoent (sb-posix:syscall-errno condition)) (error condition)))))

(defun check-store-generation-directory (path &key metadata)
  (let ((stat (store-generation-stat path)))
    (unless (and stat (sb-posix:s-isdir (sb-posix:stat-mode stat))
                 (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                 (if metadata (zerop (logand #o022 (sb-posix:stat-mode stat)))
                     (= #o700 (logand #o777 (sb-posix:stat-mode stat)))))
      (error "Unsafe store generation directory ~A" path)))
  path)

(defun sync-store-generation-directory (path)
  (let ((fd (sb-posix:open (string-right-trim "/" (namestring path))
                           (logior sb-posix:o-rdonly sb-posix:o-directory sb-posix:o-nofollow) 0)))
    (unwind-protect (sb-posix:fsync fd) (sb-posix:close fd))))

(defun ensure-store-generation-directory (path parent &key metadata)
  (handler-case
      (progn (sb-posix:mkdir (namestring path) #o700) (sync-store-generation-directory parent))
    (sb-posix:syscall-error (condition)
      (unless (= sb-posix:eexist (sb-posix:syscall-errno condition)) (error condition))))
  (check-store-generation-directory path :metadata metadata))

(defun store-generation-base (root)
  (merge-pathnames "application-generations/" (uiop:ensure-directory-pathname root)))

(defun store-generation-root (root id)
  (unless (store-generation-id-p id) (error "Invalid store generation identity"))
  (merge-pathnames (format nil "~A/" id) (store-generation-base root)))

(defun store-generation-selector-path (root)
  (merge-pathnames "metadata/application-generation.json" (uiop:ensure-directory-pathname root)))

(defun store-generation-complete-path (root id)
  ;; Do not use .json: the generation root's *.json files are desired Pods.
  (merge-pathnames "generation.meta" (store-generation-root root id)))

(defun validate-store-generation-descriptor (record)
  (unless (and (hash-table-p record) (= 6 (hash-table-count record))
               (equal "gr8s-store-generation" (gethash "format" record))
               (eql 1 (gethash "version" record))
               (store-generation-id-p (gethash "generation" record))
               (typep (gethash "index" record) '(unsigned-byte 64))
               (typep (gethash "term" record) '(unsigned-byte 64))
               (let ((digest (gethash "artifactSha256" record)))
                 (and (stringp digest) (= 64 (length digest))
                      (every (lambda (char) (find char "0123456789abcdef")) digest))))
    (error "Invalid store generation descriptor"))
  record)

(defun read-private-generation-json (path)
  "Refuse links, nonprivate files and unbounded metadata before parsing."
  (let ((fd (sb-posix:open (namestring path) (logior sb-posix:o-rdonly sb-posix:o-nofollow sb-posix:o-nonblock) 0))
        (stream nil))
    (unwind-protect
         (progn
           (let ((stat (sb-posix:fstat fd)))
             (unless (and (sb-posix:s-isreg (sb-posix:stat-mode stat))
                          (= 1 (sb-posix:stat-nlink stat))
                          (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                          (= #o600 (logand #o777 (sb-posix:stat-mode stat)))
                          (<= 1 (sb-posix:stat-size stat) 4096))
               (error "Unsafe store generation descriptor ~A" path)))
           (setf stream (sb-sys:make-fd-stream fd :input t :element-type 'character
                                               :external-format :utf-8 :auto-close t))
           (com.inuoe.jzon:parse stream :max-depth 8 :max-string-length 256))
      (if stream (close stream) (sb-posix:close fd)))))

(defun read-store-generation-descriptor (path)
  (validate-store-generation-descriptor (read-private-generation-json path)))

(defun checked-store-generation-descriptor (root id)
  (check-store-generation-directory (store-generation-base root))
  (check-store-generation-directory (store-generation-root root id))
  (let ((descriptor (read-store-generation-descriptor (store-generation-complete-path root id))))
    (unless (equal id (gethash "generation" descriptor)) (error "Generation marker identity mismatch"))
    descriptor))

(defun selected-store-generation-root (root)
  "Resolve a complete generation before any application data is loaded. NIL means legacy layout."
  (let ((selector (store-generation-selector-path root)))
    (when (store-generation-stat selector)
      (check-store-generation-directory (uiop:pathname-directory-pathname selector) :metadata t)
      (let* ((descriptor (read-store-generation-descriptor selector))
             (id (gethash "generation" descriptor))
             (complete (checked-store-generation-descriptor root id)))
        (unless (loop for key being the hash-keys of descriptor
                      always (equal (gethash key descriptor) (gethash key complete)))
          (error "Selected generation does not match its complete marker"))
        (store-generation-root root id)))))

(defun write-store-generation-descriptor (path descriptor &key replace)
  "Synchronize private metadata, publish it atomically, then synchronize its directory."
  (validate-store-generation-descriptor descriptor)
  (let* ((temporary (make-pathname :name (format nil ".generation-~A" (generate-uid))
                                   :type "tmp" :defaults path))
         (fd nil) (stream nil))
    (unwind-protect
         (progn
           (setf fd (sb-posix:open (namestring temporary)
                                   (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl) #o600)
                 stream (sb-sys:make-fd-stream fd :output t :element-type 'character
                                                 :external-format :utf-8 :auto-close t))
           (com.inuoe.jzon:stringify descriptor :stream stream)
           (finish-output stream)
           (sb-posix:fsync fd)
           (close stream)
           (setf stream nil fd nil)
           (if replace (sb-posix:rename (namestring temporary) (namestring path))
               (unless (zerop (cffi:foreign-funcall "renameat2" :int -100 :string (namestring temporary)
                                                   :int -100 :string (namestring path) :uint 1 :int))
                 (error "Cannot replace immutable generation marker ~A" path)))
           (sync-store-generation-directory (uiop:pathname-directory-pathname path)))
      (cond (stream (close stream)) (fd (sb-posix:close fd)))
      (when (store-generation-stat temporary) (sb-posix:unlink (namestring temporary)))))
  descriptor)

(defun create-store-generation (root id)
  "Create a private staging directory; it is not selectable until completed."
  (let* ((root (uiop:ensure-directory-pathname root)) (base (store-generation-base root))
         (path (store-generation-root root id)))
    (ensure-store-generation-directory base root)
    (sb-posix:mkdir (namestring path) #o700)
    (sync-store-generation-directory base)
    path))

(defun complete-store-generation (root id index term digest)
  "Caller has validated and synchronized ALL staged application files and subdirectories."
  (let ((descriptor (store-json-object "format" "gr8s-store-generation" "version" 1
                                       "generation" id "index" index "term" term "artifactSha256" digest)))
    (check-store-generation-directory (store-generation-base root))
    (check-store-generation-directory (store-generation-root root id))
    (write-store-generation-descriptor (store-generation-complete-path root id) descriptor)))

(defun publish-store-generation (root id)
  "Select a completed generation. Caller must quiesce the live store and manage restore intent/reload.
This helper does not change an existing store object's indexes or data-root."
  (let* ((root (uiop:ensure-directory-pathname root))
         (descriptor (checked-store-generation-descriptor root id))
         (selector (store-generation-selector-path root)))
    (let ((intent (read-store-restore-intent root)))
      (when (and intent (not (store-generation-descriptor-equal-p intent descriptor)))
        (error "Generation selection conflicts with pending application restore")))
    (selected-store-generation-root root) ; never silently overwrite malformed selection
    (ensure-store-generation-directory (uiop:pathname-directory-pathname selector) root :metadata t)
    (write-store-generation-descriptor selector descriptor :replace t)))


(defun store-generation-descriptor-equal-p (left right)
  (and (= (hash-table-count left) (hash-table-count right))
       (loop for key being the hash-keys of left
             always (equal (gethash key left) (gethash key right)))))

(defun store-restore-intent-path (root)
  (merge-pathnames "metadata/application-restore.json" (uiop:ensure-directory-pathname root)))

(defun read-store-restore-intent (root)
  "An intent is the exact immutable target descriptor, never executable data."
  (let ((path (store-restore-intent-path root)))
    (when (store-generation-stat path)
      (check-store-generation-directory (uiop:pathname-directory-pathname path) :metadata t)
      (let* ((intent (read-store-generation-descriptor path))
             (complete (checked-store-generation-descriptor root (gethash "generation" intent))))
        (unless (store-generation-descriptor-equal-p intent complete)
          (error "Application restore intent does not match its complete generation"))
        intent))))

(defun begin-store-restore (root id)
  "Durably commit to selecting a complete application generation.
Caller must quiesce live access and coordinate the member's applied/WAL boundary.
This function neither selects nor changes any existing store object's indexes."
  (let* ((root (uiop:ensure-directory-pathname root))
         (descriptor (checked-store-generation-descriptor root id))
         (path (store-restore-intent-path root))
         (pending (read-store-restore-intent root)))
    (selected-store-generation-root root) ; reject malformed existing selection
    (when (and pending (not (store-generation-descriptor-equal-p pending descriptor)))
      (error "Another application restore is pending"))
    (ensure-store-generation-directory (uiop:pathname-directory-pathname path) root :metadata t)
    (if pending
        (sync-store-generation-directory (uiop:pathname-directory-pathname path))
        (write-store-generation-descriptor path descriptor))
    descriptor))

(defun resume-store-restore-selection (root)
  "Resume pending selection BEFORE loading or exposing application data.
Keep the intent until application loading succeeds. Never roll back an intent."
  (let ((intent (read-store-restore-intent root)))
    (when intent
      (publish-store-generation root (gethash "generation" intent))
      intent)))

(defun finish-store-restore (store descriptor)
  "Clear the intent only after the selected application's indexes loaded successfully.
This acknowledges application loading, not production Raft/WAL recovery."
  (let* ((root (pod-store-path store))
         (target (store-generation-root root (gethash "generation" descriptor)))
         (selected (selected-store-generation-root root))
         (pending (read-store-restore-intent root))
         (selector (read-store-generation-descriptor (store-generation-selector-path root)))
         (path (store-restore-intent-path root)))
    (unless (and (equal selected target) (equal (store-data-path store) target)
                 (store-generation-descriptor-equal-p descriptor selector)
                 (or (null pending) (store-generation-descriptor-equal-p pending descriptor)))
      (error "Cannot finish application restore from another generation"))
    (when pending (sb-posix:unlink (namestring path)))
    ;; Also synchronize on idempotent retry after an uncertain unlink sync.
    (sync-store-generation-directory (uiop:pathname-directory-pathname path))
    store))
