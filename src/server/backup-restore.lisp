;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s.server)

(defun read-backup-key-file (path)
  "Load a 32-byte backup master key from a private hexadecimal key file."
  (let ((stat (gr8s.store::store-generation-stat path)))
    (unless (and stat (sb-posix:s-isreg (sb-posix:stat-mode stat))
                 (= (sb-posix:geteuid) (sb-posix:stat-uid stat))
                 (zerop (logand #o077 (sb-posix:stat-mode stat))))
      (error "Backup key file must be a private regular file owned by the caller")))
  (let ((key (ironclad:hex-string-to-byte-array
              (string-trim '(#\Space #\Tab #\Newline #\Return)
                           (uiop:read-file-string path)))))
    (unless (= 32 (length key))
      (error "Backup key file must contain 64 hexadecimal characters"))
    key))

(defun generate-backup-key-file (path)
  "Create a fresh private key file; an existing file is never overwritten."
  (let ((fd (sb-posix:open (namestring path)
                           (logior sb-posix:o-wronly sb-posix:o-creat
                                   sb-posix:o-excl sb-posix:o-nofollow)
                           #o600))
        (stream nil))
    (unwind-protect
         (progn
           (setf stream (sb-sys:make-fd-stream fd :output t :auto-close t))
           (write-line (ironclad:byte-array-to-hex-string (ironclad:random-data 32)) stream)
           (finish-output stream)
           (sb-posix:fsync (sb-sys:fd-stream-fd stream))
           path)
      (if stream (close stream) (sb-posix:close fd)))))

(defun restore-staging-file-path (staging name)
  "Resolve a verified bundle member inside STAGING, creating private directories."
  (let ((components (backup-relative-components name))
        (directory staging))
    (dolist (component (butlast components))
      (setf directory (merge-pathnames (concatenate 'string component "/") directory))
      (unless (gr8s.store::store-generation-stat directory)
        (sb-posix:mkdir (string-right-trim "/" (namestring directory)) #o700)))
    (merge-pathnames (first (last components)) directory)))

(defun fsync-directory-tree (root)
  "Make a staged tree durable before it is published."
  (dolist (entry (directory (merge-pathnames #P"*.*" root) :resolve-symlinks nil))
    (let ((stat (gr8s.store::store-generation-stat entry)))
      (when (and stat (sb-posix:s-isdir (sb-posix:stat-mode stat)))
        (fsync-directory-tree (uiop:ensure-directory-pathname entry)))))
  (gr8s.store::sync-store-generation-directory root))

(defun restore-state-backup (input target key)
  "Verify INPUT completely while staging privately, then publish TARGET.
Nothing is published, and nothing of the staging remains, unless the whole
bundle authenticates through its final marker. TARGET must not exist."
  (let* ((directory (uiop:ensure-directory-pathname target))
         (parent (truename (uiop:pathname-directory-pathname
                            (string-right-trim "/" (namestring directory)))))
         (published (merge-pathnames
                     (concatenate 'string (first (last (pathname-directory directory))) "/")
                     parent))
         (staging (merge-pathnames (format nil ".gr8s-restore-~A.tmp/" (generate-uid)) parent))
         (member-stream nil) (complete nil))
    (unless (stringp (first (last (pathname-directory directory))))
      (error "Restore target must name a directory"))
    (gr8s.store::check-store-generation-directory parent :metadata t)
    (when (gr8s.store::store-generation-stat published)
      (error "Restore target already exists: ~A" published))
    (sb-posix:mkdir (string-right-trim "/" (namestring staging)) #o700)
    (unwind-protect
         (with-open-stream
             (stream (sb-sys:make-fd-stream
                      (sb-posix:open (namestring input)
                                     (logior sb-posix:o-rdonly sb-posix:o-nofollow) 0)
                      :input t :element-type '(unsigned-byte 8) :auto-close t))
           (multiple-value-bind (manifest count bytes)
               (verify-state-backup-stream
                stream key
                :on-file (lambda (name size)
                           (declare (ignore size))
                           (let ((fd (sb-posix:open
                                      (namestring (restore-staging-file-path staging name))
                                      (logior sb-posix:o-wronly sb-posix:o-creat
                                              sb-posix:o-excl sb-posix:o-nofollow)
                                      #o600)))
                             (setf member-stream
                                   (sb-sys:make-fd-stream fd :output t
                                                          :element-type '(unsigned-byte 8)
                                                          :auto-close t))))
                :on-data (lambda (record start end)
                           (write-sequence record member-stream :start start :end end))
                :on-file-end (lambda ()
                               (finish-output member-stream)
                               (sb-posix:fsync (sb-sys:fd-stream-fd member-stream))
                               (close member-stream)
                               (setf member-stream nil)))
             (fsync-directory-tree staging)
             (unless (zerop (cffi:foreign-funcall "renameat2"
                                                  :int -100 :string (string-right-trim "/" (namestring staging))
                                                  :int -100 :string (string-right-trim "/" (namestring published))
                                                  :uint 1 :int))
               (error "Cannot publish restored state; destination must not exist"))
             (gr8s.store::sync-store-generation-directory parent)
             (setf complete t)
             (values published manifest count bytes)))
      (when member-stream (close member-stream))
      (unless complete
        (uiop:delete-directory-tree staging :validate t :if-does-not-exist :ignore)))))

(defun parse-backup-options (arguments)
  "Parse the offline encrypted backup workflow."
  (let* ((subcommand (first arguments))
         (command (cdr (assoc subcommand
                              '(("keygen" . :backup-keygen)
                                ("save" . :backup-save)
                                ("verify" . :backup-verify))
                              :test #'equal))))
    (unless command
      (error "unknown backup subcommand: ~A" (or subcommand "")))
    (let ((options (list :command command
                         :state-directory (namestring (default-state-directory))))
          (arguments (rest arguments)))
      (loop while arguments
            for option = (first arguments)
            do (cond
                 ((and (eq command :backup-save) (string= option "--state-directory"))
                  (setf (getf options :state-directory) (option-value arguments option)
                        arguments (cddr arguments)))
                 ((and (eq command :backup-save) (string= option "--output"))
                  (setf (getf options :output) (option-value arguments option)
                        arguments (cddr arguments)))
                 ((and (eq command :backup-verify) (string= option "--input"))
                  (setf (getf options :input) (option-value arguments option)
                        arguments (cddr arguments)))
                 ((string= option "--key-file")
                  (setf (getf options :key-file) (option-value arguments option)
                        arguments (cddr arguments)))
                 (t (error "unknown backup ~A option: ~A" subcommand option))))
      (when (and (eq command :backup-save) (not (getf options :output)))
        (error "backup save requires --output FILE"))
      (when (and (eq command :backup-verify) (not (getf options :input)))
        (error "backup verify requires --input FILE"))
      (unless (getf options :key-file)
        (error "backup ~A requires --key-file FILE" subcommand))
      options)))

(defun parse-restore-options (arguments)
  "Parse the verify-then-publish state restore."
  (let ((options (list :command :restore
                       :state-directory (namestring (default-state-directory)))))
    (loop while arguments
          for option = (first arguments)
          do (cond
               ((string= option "--input")
                (setf (getf options :input) (option-value arguments option)
                      arguments (cddr arguments)))
               ((string= option "--state-directory")
                (setf (getf options :state-directory) (option-value arguments option)
                      arguments (cddr arguments)))
               ((string= option "--key-file")
                (setf (getf options :key-file) (option-value arguments option)
                      arguments (cddr arguments)))
               (t (error "unknown restore option: ~A" option))))
    (unless (getf options :input) (error "restore requires --input FILE"))
    (unless (getf options :key-file) (error "restore requires --key-file FILE"))
    options))

(defun run-backup-command (options &optional (output *standard-output*))
  "Run one offline backup operation and print a JSON summary."
  (flet ((summary (object)
           (com.inuoe.jzon:stringify object :stream output)
           (terpri output)
           (finish-output output)
           0))
    (ecase (getf options :command)
      (:backup-keygen
       (summary (json-object "keyFile" (namestring (generate-backup-key-file (getf options :key-file))))))
      (:backup-save
       (multiple-value-bind (path files bytes)
           (capture-state-backup (getf options :state-directory) (getf options :output)
                                 (read-backup-key-file (getf options :key-file)))
         (summary (json-object "path" (namestring path) "files" files "bytes" bytes))))
      (:backup-verify
       (with-open-file (in (getf options :input) :element-type '(unsigned-byte 8))
         (multiple-value-bind (manifest files bytes)
             (verify-state-backup-stream in (read-backup-key-file (getf options :key-file)))
           (summary (json-object "release" (gethash "release" manifest)
                                 "createdAt" (gethash "createdAt" manifest)
                                 "files" files "bytes" bytes))))))))

(defun run-restore-command (options &optional (output *standard-output*))
  "Restore a verified bundle into a fresh state directory and print a JSON summary."
  (multiple-value-bind (published manifest files bytes)
      (restore-state-backup (getf options :input) (getf options :state-directory)
                            (read-backup-key-file (getf options :key-file)))
    (com.inuoe.jzon:stringify
     (json-object "stateDirectory" (namestring published)
                  "release" (gethash "release" manifest)
                  "files" files "bytes" bytes)
     :stream output)
    (terpri output)
    (finish-output output)
    0))
