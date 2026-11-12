;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
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
    (is (equal "dir/last" (gr8s.kubelet::container-mount-subpath (gr8s.resources::core-object "subPathExpr" "dir/$(NAME)") env)))
    (is (equal "$(NAME)/$(NAME)" (gr8s.kubelet::container-mount-subpath (gr8s.resources::core-object "subPathExpr" "$$(NAME)/$(NESTED)") env)))
    (signals gr8s.runtime::runtime-error (gr8s.kubelet::container-mount-subpath (gr8s.resources::core-object "subPathExpr" "$(ABSENT)") env))
    (signals gr8s.runtime::runtime-error (gr8s.kubelet::container-mount-subpath (gr8s.resources::core-object "subPathExpr" "$(EMPTY)") env))))

(test subpath-descriptor-stays-pinned-after-file-rename-and-link-replacement
  (with-temporary-store (store directory)
    (values store)
    (let* ((root (merge-pathnames "volume/" directory)) (file (merge-pathnames "value" root))
           (outside (merge-pathnames "outside" directory)) (descriptor nil))
      (subpath-test-write file "safe") (subpath-test-write outside "outside")
      (unwind-protect
           (progn
             (setf descriptor (gr8s.kubelet::pin-volume-subpath root "value"))
             (sb-posix:rename (namestring file) (namestring (merge-pathnames "renamed" root)))
             (sb-posix:symlink (namestring outside) (namestring file))
             (is (equal "safe" (uiop:read-file-string (format nil "/proc/self/fd/~D" descriptor))))
             (signals gr8s.runtime::runtime-error (gr8s.kubelet::pin-volume-subpath root "value")))
        (when descriptor (sb-posix:close descriptor))))))

(test subpath-relative-links-work-but-escaping-links-and-traversal-do-not
  (with-temporary-store (store directory)
    (values store)
    (let* ((root (merge-pathnames "volume/" directory)) (target (merge-pathnames "nested/value" root))
           (outside (merge-pathnames "outside/value" directory)))
      (subpath-test-write target "inside") (subpath-test-write outside "outside")
      (sb-posix:symlink "nested/value" (namestring (merge-pathnames "link" root)))
      (sb-posix:symlink "../outside" (namestring (merge-pathnames "escape" root)))
      (let ((descriptor (gr8s.kubelet::pin-volume-subpath root "link")))
        (unwind-protect (is (equal "inside" (uiop:read-file-string (format nil "/proc/self/fd/~D" descriptor))))
          (sb-posix:close descriptor)))
      (dolist (path '("../outside/value" "escape/value" "/etc/passwd"))
        (signals gr8s.runtime::runtime-error (gr8s.kubelet::pin-volume-subpath root path)))
      (signals gr8s.runtime::runtime-error (gr8s.kubelet::pin-volume-subpath root "escape/must-not-create" :create-directory t))
      (is (not (probe-file (merge-pathnames "outside/must-not-create" directory)))))))

(test subpath-makes-real-directories-and-releases-descriptors-on-failure
  (with-temporary-store (store directory)
    (values store)
    (let* ((root (merge-pathnames "volume/" directory)) (before (subpath-test-fd-count)))
      (ensure-directories-exist root)
      (let ((descriptor (gr8s.kubelet::pin-volume-subpath root "a/b" :create-directory t)))
        (unwind-protect (is (sb-posix:s-isdir (sb-posix:stat-mode (sb-posix:fstat descriptor))))
          (sb-posix:close descriptor)))
      (is (probe-file (merge-pathnames "a/b/" root)))
      (dotimes (index 32)
        (declare (ignore index))
        (handler-case (gr8s.kubelet::pin-volume-subpath root "absent") (gr8s.runtime::runtime-error () nil)))
      (is (= before (subpath-test-fd-count))))))

(test subpath-allows-absolute-links-inside-the-root-and-preserves-real-directory-mode
  (with-temporary-store (store directory)
    (values store)
    (let* ((root (merge-pathnames "volume/" directory)) (file (merge-pathnames "real/value" root)))
      (subpath-test-write file "bounded")
      (sb-posix:chmod (namestring root) #o2770)
      (sb-posix:symlink (namestring file) (namestring (merge-pathnames "absolute-link" root)))
      (let ((descriptor (gr8s.kubelet::pin-volume-subpath root "absolute-link" :create-directory t)))
        (unwind-protect (is (equal "bounded" (uiop:read-file-string (format nil "/proc/self/fd/~D" descriptor))))
          (sb-posix:close descriptor)))
      (let ((descriptor (gr8s.kubelet::pin-volume-subpath root "new/child" :create-directory t)))
        (unwind-protect (is (= #o2770 (logand #o7777 (sb-posix:stat-mode (sb-posix:fstat descriptor)))))
          (sb-posix:close descriptor))))))

(test subpath-uses-literal-linux-filenames-with-wildcard-characters
  (with-temporary-store (store directory)
    (values store)
    (let ((root (merge-pathnames "volume/" directory)))
      (ensure-directories-exist root)
      (let ((file (concatenate 'string (namestring root) "literal*[value]")))
        (sb-posix:close (sb-posix:open file (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl) #o600))
        (let ((descriptor (gr8s.kubelet::pin-volume-subpath root "literal*[value]" :create-directory t)))
          (unwind-protect (is (= (sb-posix:stat-ino (sb-posix:stat file))
                                (sb-posix:stat-ino (sb-posix:fstat descriptor))))
            (sb-posix:close descriptor)))))))

(defun subpath-test-object (mount)
  "Build a real admitted Pod with a shared emptyDir and the supplied mount declaration."
  (let* ((object (com.inuoe.jzon:parse *valid-pod-json*)) (spec (gethash "spec" object)))
    (setf (gethash "volumes" spec) (vector (gr8s.resources::core-object "name" "data" "emptyDir" (gr8s.resources::core-object)))
          (gethash "volumeMounts" (aref (gethash "containers" spec) 0)) (vector mount))
    object))

(test subpath-admission-rejects-traversal-and-mutually-exclusive-fields
  (dolist (path '("../escape" "safe/../escape" "/absolute"))
    (dolist (field '("subPath" "subPathExpr"))
      (signals gr8s.model::kubernetes-error
        (parse-pod (subpath-test-object (gr8s.resources::core-object "name" "data" "mountPath" "/data" field path))))))
  (signals gr8s.model::kubernetes-error
    (parse-pod (subpath-test-object (gr8s.resources::core-object "name" "data" "mountPath" "/data"
                                                     "subPath" "one" "subPathExpr" "$(NAME)"))))
  (is (typep (parse-pod (subpath-test-object (gr8s.resources::core-object "name" "data" "mountPath" "/data"
                                                             "subPathExpr" "$(ANNOTATION)/$(POD_NAME)"))) 'gr8s.model::pod)))

(test subpath-annotation-environment-retries-use-the-actual-updated-pod
  (with-temporary-store (store directory)
    (let* ((object (subpath-test-object (gr8s.resources::core-object "name" "data" "mountPath" "/data" "subPathExpr" "$(ANNOTATION)/$(POD_NAME)")))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root directory)))
      (setf (gethash "env" (aref (gethash "containers" (gethash "spec" object)) 0))
            (vector (gr8s.resources::core-object "name" "ANNOTATION" "valueFrom"
                     (gr8s.resources::core-object "fieldRef" (gr8s.resources::core-object "fieldPath" "metadata.annotations['mysubpath']")))
                    (gr8s.resources::core-object "name" "POD_NAME" "valueFrom"
                     (gr8s.resources::core-object "fieldRef" (gr8s.resources::core-object "fieldPath" "metadata.name")))))
      (let* ((pod (create-pod store (parse-pod object))) (container (aref (pod-containers pod) 0))
             (mount (aref (gethash "volumeMounts" (aref (gethash "containers" (gethash "spec" (pod-to-object pod))) 0)) 0)))
        (signals gr8s.runtime::runtime-error
          (gr8s.kubelet::container-mount-subpath mount (gr8s.kubelet::containerd-pod-environment runtime pod container "unused")))
        (let* ((replacement (gr8s.resources::copy-core-object (pod-to-object pod)))
               (before (gr8s.runtime::pod-runtime-spec-fingerprint pod)))
          (setf (gethash "annotations" (gethash "metadata" replacement)) (gr8s.resources::core-object "mysubpath" "actual-directory"))
          (let* ((updated (gr8s.store::update-pod store (parse-pod replacement) (pod-resource-version pod)))
                 (environment (gr8s.kubelet::containerd-pod-environment runtime updated (aref (pod-containers updated) 0) "unused")))
            (is (equal before (gr8s.runtime::pod-runtime-spec-fingerprint updated)))
            (is (equal (format nil "actual-directory/~A" (pod-name pod))
                       (gr8s.kubelet::container-mount-subpath mount environment)))))))))

(test escaping-subpaths-wait-with-the-kubelets-config-error
  ;; Upstream's subPath suites wait for CreateContainerConfigError naming the subPath.
  (with-temporary-store (store directory)
    (let* ((pod (create-pod store (parse-pod (subpath-test-object (gr8s.resources::core-object "name" "data" "mountPath" "/data" "subPath" "escape")))))
           (runtime (gr8s.runtime.containerd::make-containerd-runtime :log-root (merge-pathnames "logs/" directory)))
           (container (aref (pod-containers pod) 0))
           (volume (gr8s.kubelet::materialize-pod-volume runtime pod (aref (gethash "volumes" (gethash "spec" (pod-to-object pod))) 0))))
      (sb-posix:symlink "../../../" (namestring (merge-pathnames "escape" volume)))
      (let ((condition (handler-case (progn (gr8s.kubelet::containerd-pod-mounts runtime pod container) nil)
                         (gr8s.runtime::container-config-error (condition) condition))))
        (is-true condition)
        (when condition
          (is (equal "CreateContainerConfigError" (gr8s.kubelet::container-config-error-reason condition)))
          (is (search (format nil "failed to prepare subPath for volumeMount \"data\" of container ~S"
                              (gr8s.model::container-spec-name container))
                      (gr8s.runtime::runtime-error-message condition))))))))
