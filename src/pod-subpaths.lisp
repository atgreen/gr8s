;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Resolve container volume subpaths beneath a pinned Linux directory descriptor,
;;;; then keep their exact inode mounted in a private Pod-owned staging directory.

(in-package #:gr8s)

#+linux
(sb-alien:define-alien-type subpath-open-how
  (sb-alien:struct subpath-open-how
    (flags sb-alien:unsigned-long-long)
    (mode sb-alien:unsigned-long-long)
    (resolve sb-alien:unsigned-long-long)))

#+linux
(sb-alien:define-alien-routine ("syscall" %subpath-openat2) sb-alien:long
  (number sb-alien:long) (directory sb-alien:long) (path sb-alien:c-string)
  (how (* subpath-open-how)) (size sb-alien:unsigned-long))

#+linux
(sb-alien:define-alien-routine ("mkdirat" %subpath-mkdirat) sb-alien:int
  (directory sb-alien:int) (name sb-alien:c-string) (mode sb-alien:unsigned-int))

(defun valid-container-subpath-p (path)
  "Accept a relative Linux mount subpath without NUL or any parent traversal."
  (and (stringp path) (not (find #\Null path))
       (or (zerop (length path)) (not (char= #\/ (char path 0))))
       (not (member ".." (uiop:split-string path :separator '(#\/)) :test #'equal))))

(define-condition subpath-error (runtime-error)
  ((errno :initarg :errno :reader subpath-error-errno)))

(defun subpath-system-error (operation &optional (code (sb-alien:get-errno)))
  "Report an actual kernel failure without publishing a private host pathname."
  (error 'subpath-error :errno code
         :message (format nil "Volume subpath ~A failed: ~A (~D)"
                          operation (sb-int:strerror code) code)))

(defun open-beneath-subpath (directory path &key directory-only)
  "Pin PATH beneath DIRECTORY; the kernel rejects escaping links and procfs magic links."
  #+linux
  (sb-alien:with-alien ((how subpath-open-how))
    ;; Linux openat2 UAPI: O_PATH|O_CLOEXEC, optionally O_DIRECTORY;
    ;; RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS. syscall437 is shared by the
    ;; supported Linux x86-64 and arm64 native targets. No unsafe fallback.
    (setf (sb-alien:slot how 'flags) (logior #x200000 #x80000 (if directory-only #x10000 0))
          (sb-alien:slot how 'mode) 0
          (sb-alien:slot how 'resolve) #x0a)
    (loop repeat 8
          for descriptor = (%subpath-openat2 437 directory path (sb-alien:addr how) 24)
          when (not (minusp descriptor)) return descriptor
          unless (= (sb-alien:get-errno) sb-posix:eagain)
            do (subpath-system-error "open")
          finally (subpath-system-error "open" sb-posix:eagain)))
  #-linux (declare (ignore directory path directory-only))
  #-linux (error 'runtime-error :message "Safe volume subpaths require Linux openat2"))

(defun container-mount-subpath (mount environment)
  "Expand subPathExpr once using actual environment values, rejecting absent or empty references."
  (let ((expression (gethash "subPathExpr" mount "")))
    (if (zerop (length expression)) (gethash "subPath" mount "")
        (let ((missing nil))
          ;; Scan only references the expansion consumes: escaped $$(VAR)
          ;; remains literal and is never expanded twice.
          (let ((names (loop with index = 0 while (< index (length expression))
                              when (and (char= #\$ (char expression index))
                                        (< (1+ index) (length expression))
                                        (char= #\$ (char expression (1+ index))))
                                do (incf index 2)
                              else when (and (char= #\$ (char expression index))
                                             (< (1+ index) (length expression))
                                             (char= #\( (char expression (1+ index)))
                                             (position #\) expression :start (+ index 2)))
                                collect (let ((end (position #\) expression :start (+ index 2))))
                                          (prog1 (subseq expression (+ index 2) end) (setf index (1+ end))))
                              else do (incf index))))
            (dolist (name names)
              (let ((entry (find name environment :key #'car :test #'equal :from-end t)))
                (unless (and entry (cdr entry) (plusp (length (cdr entry))))
                  (push name missing))))
            (when missing (error 'runtime-error :message "Volume subPathExpr has an empty or missing environment value"))
            (expand-container-command-argument expression environment))))))

(defun canonical-subpath-relative (root relative)
  "Resolve existing internal links once, then return a name to reopen beneath the pinned root."
  (let* ((base (namestring root))
         (path (concatenate 'string base relative))
         (existing (probe-file path)))
    (if (null existing) relative
        (let ((canonical (namestring (truename existing))))
          (unless (or (equal (string-right-trim "/" base) canonical)
                      (uiop:string-prefix-p base canonical))
            (error 'runtime-error :message "Volume subpath link escapes its volume"))
          (if (< (length canonical) (length base)) "" (subseq canonical (length base)))))))

(defun pin-volume-subpath (base relative &key create-directory)
  "Return a caller-owned descriptor to the exact inode below BASE, safely making missing directories."
  (unless (valid-container-subpath-p relative)
    (error 'runtime-error :message "Volume subpath must be relative without parent traversal"))
  (let* ((root (uiop:ensure-directory-pathname (truename base)))
         (descriptor (sb-posix:open (namestring root) (logior #x200000 #x80000 #x10000 #x20000)))
         (result nil))
    (unwind-protect
         (progn
           (handler-case
               (setf result (open-beneath-subpath descriptor
                             (let ((path (canonical-subpath-relative root relative)))
                               (if (zerop (length path)) "." path))))
             (subpath-error (condition)
               (unless (and create-directory (= (subpath-error-errno condition) sb-posix:enoent))
                 (error condition))))
           (when (and create-directory (null result))
             (let ((parent (sb-posix:dup descriptor)) (prefix ""))
               (unwind-protect
                    (dolist (component (remove-if (lambda (part) (member part '("" ".") :test #'equal))
                                                 (uiop:split-string relative :separator '(#\/))))
                      (setf prefix (concatenate 'string prefix component))
                      (let* ((created nil)
                             (child (handler-case (open-beneath-subpath descriptor
                                                    (canonical-subpath-relative root prefix) :directory-only t)
                                     (subpath-error (condition)
                                       (unless (= (subpath-error-errno condition) sb-posix:enoent) (error condition))
                                       (let ((code (%subpath-mkdirat parent component
                                                     (logand #o7777 (sb-posix:stat-mode (sb-posix:fstat descriptor))))))
                                         (setf created (zerop code))
                                         (unless (or (zerop code) (= (sb-alien:get-errno) sb-posix:eexist))
                                           (subpath-system-error "mkdir")))
                                       (open-beneath-subpath descriptor
                                         (canonical-subpath-relative root prefix) :directory-only t)))))
                        (let ((previous parent))
                          (setf parent child prefix (concatenate 'string prefix "/"))
                          (sb-posix:close previous))
                        (when created
                          ;; The proc descriptor path names the pinned inode;
                          ;; chmod therefore cannot follow a replaced user path.
                          (sb-posix:chmod (format nil "/proc/self/fd/~D" child)
                                         (logand #o7777 (sb-posix:stat-mode (sb-posix:fstat descriptor)))))))
                 (sb-posix:close parent)))
             (setf result (open-beneath-subpath descriptor
                                           (canonical-subpath-relative root relative)))))
      (sb-posix:close descriptor))
    result))

(defun pod-subpath-directory (runtime uid)
  "Locate only this UID's private host-side staging mounts."
  (merge-pathnames "volume-subpaths/" (containerd-pod-log-directory runtime uid)))

(defun decode-subpath-mountinfo-path (encoded)
  "Decode Linux mountinfo's octal pathname escapes without interpreting arbitrary input."
  (with-output-to-string (out)
    (loop with index = 0 while (< index (length encoded))
          do (if (and (char= #\\ (char encoded index)) (<= (+ index 4) (length encoded))
                      (every (lambda (char) (digit-char-p char 8)) (subseq encoded (1+ index) (+ index 4))))
                 (progn (write-char (code-char (parse-integer encoded :start (1+ index) :end (+ index 4) :radix 8)) out)
                        (incf index 4))
                 (progn (write-char (char encoded index) out) (incf index))))))

(defun pod-subpath-mounted-targets (runtime uid)
  "Read actual mounts beneath the exact private UID staging directory, never a prefix sibling."
  (let ((prefix (namestring (pod-subpath-directory runtime uid))))
    (loop for line in (uiop:split-string (uiop:read-file-string #P"/proc/self/mountinfo") :separator '(#\Newline))
          for fields = (uiop:split-string line :separator '(#\Space))
          for target = (and (>= (length fields) 5) (decode-subpath-mountinfo-path (nth 4 fields)))
          when (and target (uiop:string-prefix-p prefix target)) collect target)))

(defun remove-subpath-placeholder (target)
  "Remove only a private unmounted empty directory or regular-file placeholder."
  (let ((stat (handler-case (sb-posix:lstat target)
                (sb-posix:syscall-error (condition)
                  (unless (= sb-posix:enoent (sb-posix:syscall-errno condition)) (error condition))))))
    (when stat
      (cond ((sb-posix:s-isdir (sb-posix:stat-mode stat)) (sb-posix:rmdir target))
            ((sb-posix:s-isreg (sb-posix:stat-mode stat)) (sb-posix:unlink target))
            (t (error 'runtime-error :message "Unexpected private volume subpath placeholder type"))))))

(defun stage-container-volume-subpath (runtime pod container mount index source relative)
  "Bind the pinned source inode to a private, recoverable UID/container/mount-index target."
  (let* ((descriptor (pin-volume-subpath source relative :create-directory t))
         (target (namestring (merge-pathnames
                    (format nil "~A/~A/~D" (gethash "name" mount) (container-spec-name container) index)
                    (pod-subpath-directory runtime (pod-uid pod)))))
         (mounted nil) (prepared nil))
    (unwind-protect
         (progn
           (when (member target (pod-subpath-mounted-targets runtime (pod-uid pod)) :test #'equal)
             (let ((actual (sb-posix:stat target)) (desired (sb-posix:fstat descriptor)))
               (when (and (= (sb-posix:stat-dev actual) (sb-posix:stat-dev desired))
                          (= (sb-posix:stat-ino actual) (sb-posix:stat-ino desired)))
                 (return-from stage-container-volume-subpath (pathname target))))
             (unless (zerop (%linux-umount target 0)) (subpath-system-error "replace unmount")))
           (remove-subpath-placeholder target)
           (ensure-directories-exist target)
           (sb-posix:chmod (namestring (pod-subpath-directory runtime (pod-uid pod))) #o700)
           (if (sb-posix:s-isdir (sb-posix:stat-mode (sb-posix:fstat descriptor)))
               (sb-posix:mkdir target #o700)
               (sb-posix:close (sb-posix:open target (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl) #o600)))
           (setf prepared t)
           ;; The descriptor pins the inode throughout the kernel mount call;
           ;; the user-supplied pathname is never handed to the mount syscall.
           (unless (zerop (%linux-mount (format nil "/proc/~D/fd/~D" (sb-posix:getpid) descriptor)
                                       target nil #x1000 nil))
             (subpath-system-error "bind mount"))
           (setf mounted t)
           (pathname target))
      (sb-posix:close descriptor)
      (when (and prepared (not mounted)) (remove-subpath-placeholder target)))))

(defun cleanup-pod-subpaths (runtime uid)
  "Unmount only this UID's staged paths after CRI teardown, preserving foreign mounts."
  (dolist (target (sort (pod-subpath-mounted-targets runtime uid) #'> :key #'length))
    (unless (zerop (%linux-umount target 0)) (subpath-system-error "cleanup unmount")))
  (let ((directory (pod-subpath-directory runtime uid)))
    (when (probe-file directory)
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))
