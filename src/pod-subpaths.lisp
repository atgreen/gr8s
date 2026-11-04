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

(defun pin-volume-subpath (base relative &key create-directory)
  "Return a caller-owned descriptor to the exact inode below BASE, safely making missing directories."
  (unless (valid-container-subpath-p relative)
    (error 'runtime-error :message "Volume subpath must be relative without parent traversal"))
  (let* ((root (uiop:ensure-directory-pathname (truename base)))
         (descriptor (sb-posix:open (namestring root) (logior #x200000 #x80000 #x10000 #x20000)))
         (result nil))
    (unwind-protect
         (progn
           (when create-directory
             (let ((parent (sb-posix:dup descriptor)) (prefix ""))
               (unwind-protect
                    (dolist (component (remove-if (lambda (part) (member part '("" ".") :test #'equal))
                                                 (uiop:split-string relative :separator '(#\/))))
                      (setf prefix (concatenate 'string prefix component))
                      (let ((child (handler-case (open-beneath-subpath descriptor prefix :directory-only t)
                                     (subpath-error (condition)
                                       (unless (= (subpath-error-errno condition) sb-posix:enoent) (error condition))
                                       (let ((code (%subpath-mkdirat parent component #o777)))
                                         (unless (or (zerop code) (= (sb-alien:get-errno) sb-posix:eexist))
                                           (subpath-system-error "mkdir")))
                                       (open-beneath-subpath descriptor prefix :directory-only t)))))
                        (sb-posix:close parent)
                        (setf parent child prefix (concatenate 'string prefix "/"))))
                 (sb-posix:close parent))))
           (setf result (open-beneath-subpath descriptor (if (zerop (length relative)) "." relative))))
      (sb-posix:close descriptor))
    result))
