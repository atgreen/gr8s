;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise genuine Linux descriptor resolution under link/rename attacks and
;;;; strict once-only subPathExpr environment expansion without privileged mounts.

(in-package #:gr8s/tests)
(def-suite pod-subpaths :in gr8s)
(in-suite pod-subpaths)

(defun subpath-test-write (path text)
  "Create a real fixture file whose contents distinguish safe and escaped inodes."
  (ensure-directories-exist path)
  (with-open-file (out path :direction :output :if-exists :supersede) (write-string text out)))

(defun subpath-test-fd-count ()
  "Count actual open descriptors while including this enumeration's own descriptor."
  (let ((directory (sb-posix:opendir "/proc/self/fd")))
    (unwind-protect
         (loop for entry = (sb-posix:readdir directory) until (sb-alien:null-alien entry)
               count (not (member (sb-posix:dirent-name entry) '("." "..") :test #'equal)))
      (sb-posix:closedir directory))))

(test subpath-expression-uses-actual-environment-and-consumes-dollars-once
  (let ((env '(("NAME" . "first") ("NAME" . "last") ("NESTED" . "$(NAME)") ("EMPTY" . ""))))
    (is (equal "dir/last" (gr8s::container-mount-subpath (gr8s::core-object "subPathExpr" "dir/$(NAME)") env)))
    (is (equal "$(NAME)/$(NAME)" (gr8s::container-mount-subpath (gr8s::core-object "subPathExpr" "$$(NAME)/$(NESTED)") env)))
    (signals gr8s::runtime-error (gr8s::container-mount-subpath (gr8s::core-object "subPathExpr" "$(ABSENT)") env))
    (signals gr8s::runtime-error (gr8s::container-mount-subpath (gr8s::core-object "subPathExpr" "$(EMPTY)") env))))

(test subpath-descriptor-stays-pinned-after-file-rename-and-link-replacement
  (with-temporary-store (store directory)
    (values store)
    (let* ((root (merge-pathnames "volume/" directory)) (file (merge-pathnames "value" root))
           (outside (merge-pathnames "outside" directory)) (descriptor nil))
      (subpath-test-write file "safe") (subpath-test-write outside "outside")
      (unwind-protect
           (progn
             (setf descriptor (gr8s::pin-volume-subpath root "value"))
             (sb-posix:rename (namestring file) (namestring (merge-pathnames "renamed" root)))
             (sb-posix:symlink (namestring outside) (namestring file))
             (is (equal "safe" (uiop:read-file-string (format nil "/proc/self/fd/~D" descriptor))))
             (signals gr8s::runtime-error (gr8s::pin-volume-subpath root "value")))
        (when descriptor (sb-posix:close descriptor))))))

(test subpath-relative-links-work-but-escaping-links-and-traversal-do-not
  (with-temporary-store (store directory)
    (values store)
    (let* ((root (merge-pathnames "volume/" directory)) (target (merge-pathnames "nested/value" root))
           (outside (merge-pathnames "outside/value" directory)))
      (subpath-test-write target "inside") (subpath-test-write outside "outside")
      (sb-posix:symlink "nested/value" (namestring (merge-pathnames "link" root)))
      (sb-posix:symlink "../outside" (namestring (merge-pathnames "escape" root)))
      (let ((descriptor (gr8s::pin-volume-subpath root "link")))
        (unwind-protect (is (equal "inside" (uiop:read-file-string (format nil "/proc/self/fd/~D" descriptor))))
          (sb-posix:close descriptor)))
      (dolist (path '("../outside/value" "escape/value" "/etc/passwd"))
        (signals gr8s::runtime-error (gr8s::pin-volume-subpath root path)))
      (signals gr8s::runtime-error (gr8s::pin-volume-subpath root "escape/must-not-create" :create-directory t))
      (is (not (probe-file (merge-pathnames "outside/must-not-create" directory)))))))

(test subpath-makes-real-directories-and-releases-descriptors-on-failure
  (with-temporary-store (store directory)
    (values store)
    (let* ((root (merge-pathnames "volume/" directory)) (before (subpath-test-fd-count)))
      (ensure-directories-exist root)
      (let ((descriptor (gr8s::pin-volume-subpath root "a/b" :create-directory t)))
        (unwind-protect (is (sb-posix:s-isdir (sb-posix:stat-mode (sb-posix:fstat descriptor))))
          (sb-posix:close descriptor)))
      (is (probe-file (merge-pathnames "a/b/" root)))
      (dotimes (index 32)
        (declare (ignore index))
        (handler-case (gr8s::pin-volume-subpath root "absent") (gr8s::runtime-error () nil)))
      (is (= before (subpath-test-fd-count))))))
