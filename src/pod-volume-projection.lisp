;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Compute the files a ConfigMap, Secret, downwardAPI or projected volume should
;;;; contain, then reconcile them into its directory: changed files are replaced
;;;; atomically and vanished ones removed, so running containers see live updates.
;;;; Mounts are read-only, so only the agent ever writes these directories.

(in-package #:gr8s)

(defun go-quoted-string (text)
  "Quote TEXT as Go's %q does for the characters Kubernetes metadata can contain."
  (with-output-to-string (out)
    (write-char #\" out)
    (loop for character across text
          do (case character
               (#\" (write-string "\\\"" out))
               (#\\ (write-string "\\\\" out))
               (#\Newline (write-string "\\n" out))
               (#\Tab (write-string "\\t" out))
               (#\Return (write-string "\\r" out))
               (t (write-char character out))))
    (write-char #\" out)))

(defun format-downward-map (map)
  "Render labels or annotations as sorted key=\"value\" lines, as Kubernetes does."
  (let ((keys (sort (and map (loop for key being the hash-keys of map collect key)) #'string<)))
    (format nil "~{~A~^~%~}"
            (mapcar (lambda (key) (format nil "~A=~A" key (go-quoted-string (gethash key map)))) keys))))

(defun downward-field-value (pod path)
  "Return the text of a validated metadata field reference."
  (let ((metadata (gethash "metadata" (pod-to-object pod)))
        (subscript (pod-metadata-subscript-reference path)))
    (cond (subscript (gethash (cdr subscript) (gethash (car subscript) metadata (core-object)) ""))
          ((equal path "metadata.name") (pod-name pod))
          ((equal path "metadata.namespace") (pod-namespace pod))
          ((equal path "metadata.uid") (pod-uid pod))
          ((equal path "metadata.labels") (format-downward-map (gethash "labels" metadata)))
          ((equal path "metadata.annotations") (format-downward-map (gethash "annotations" metadata)))
          (t (error 'runtime-error :message (format nil "Unsupported downward field ~A" path))))))

(defun container-quantity-nanos (quantity)
  "Return QUANTITY in exact billionths, large enough for any node's memory."
  (container-quantity-integer quantity :scale -9 :maximum (expt 10 40)))

(defun downward-resource-value (pod reference)
  "Return a resource value divided by its divisor and rounded up, as text.
An unset limit reports node allocatable, as a Pod with no limit can use all of it."
  (let* ((resource (gethash "resource" reference))
         (dot (position #\. resource))
         (kind (subseq resource 0 dot)) (name (subseq resource (1+ dot)))
         (spec (gethash "spec" (pod-to-object pod)))
         (container (find (gethash "containerName" reference)
                          (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec))
                          :test #'equal :key (lambda (object) (gethash "name" object))))
         (declared (and container (container-resource-quantity container kind name)))
         (nanos (cond (declared (container-quantity-nanos declared))
                      ((equal kind "requests") 0)
                      ((equal name "cpu") (* (node-allocatable-cpu) (expt 10 9)))
                      (t (* (node-allocatable-memory) (expt 10 9)))))
         (text (gethash "divisor" reference))
         (divisor (and text (container-quantity-nanos (parse-container-quantity text)))))
    (write-to-string (ceiling nanos (if (member divisor '(nil 0)) (expt 10 9) divisor)))))

(defun downward-volume-files (pod items default-mode)
  "Return (path bytes mode) entries for downward API ITEMS."
  (loop for item across items
        for field = (gethash "fieldRef" item)
        for text = (if field
                       (downward-field-value pod (gethash "fieldPath" field))
                       (downward-resource-value pod (gethash "resourceFieldRef" item)))
        collect (list (gethash "path" item) (trivial-utf-8:string-to-utf-8-bytes text)
                      (gethash "mode" item default-mode))))

(defun object-volume-files (runtime pod resource source name default-mode)
  "Return (path bytes mode) entries for a ConfigMap or Secret source named NAME."
  (let* ((optional (eq t (gethash "optional" source)))
         (object (handler-case (get-core-resource (containerd-runtime-resource-store runtime)
                                                  resource (pod-namespace pod) name)
                   (kubernetes-error (condition)
                     (unless (and optional (= 404 (kubernetes-error-status-code condition)))
                       (error condition)))))
         (data (pod-volume-data resource object))
         (items (gethash "items" source))
         (selected (if (and items (plusp (length items)))
                       (coerce items 'list)
                       (loop for key being the hash-keys of data
                             collect (core-object "key" key "path" key)))))
    (loop for item in selected
          for key = (gethash "key" item)
          for bytes = (gethash key data)
          do (unless (or bytes optional)
               (error 'runtime-error :message (format nil "Volume ~A lacks key ~A" name key)))
          when bytes
            collect (list (gethash "path" item) bytes (gethash "mode" item default-mode)))))

(defun pod-volume-desired-files (runtime pod volume)
  "Return VOLUME's (path bytes mode) entries and whether it is a projection at all."
  (let ((mode (lambda (source) (gethash "defaultMode" source #o644))))
    (cond
      ((gethash "configMap" volume)
       (let ((source (gethash "configMap" volume)))
         (values (object-volume-files runtime pod "configmaps" source (gethash "name" source)
                                      (funcall mode source)) t)))
      ((gethash "secret" volume)
       (let ((source (gethash "secret" volume)))
         (values (object-volume-files runtime pod "secrets" source (gethash "secretName" source)
                                      (funcall mode source)) t)))
      ((gethash "downwardAPI" volume)
       (let ((source (gethash "downwardAPI" volume)))
         (values (downward-volume-files pod (gethash "items" source #()) (funcall mode source)) t)))
      ((gethash "projected" volume)
       (let* ((projected (gethash "projected" volume)) (default-mode (funcall mode projected)))
         (values
          (loop for source across (gethash "sources" projected #())
                append (cond
                         ((gethash "configMap" source)
                          (let ((part (gethash "configMap" source)))
                            (object-volume-files runtime pod "configmaps" part (gethash "name" part) default-mode)))
                         ((gethash "secret" source)
                          (let ((part (gethash "secret" source)))
                            (object-volume-files runtime pod "secrets" part (gethash "name" part) default-mode)))
                         ((gethash "downwardAPI" source)
                          (downward-volume-files pod (gethash "items" (gethash "downwardAPI" source) #())
                                                 default-mode))))
          t)))
      (t (values nil nil)))))

(defun volume-file-pathname (directory relative)
  "Resolve a validated relative path beneath DIRECTORY without treating it as a wildcard."
  (unless (safe-volume-relative-path-p relative) (invalid-pod "unsafe volume projection path"))
  (merge-pathnames (uiop:parse-native-namestring relative) directory))

(defun volume-file-current-p (target bytes mode)
  "Report whether TARGET already has exactly BYTES and permission MODE."
  (and (probe-file target)
       (= mode (logand #o777 (sb-posix:stat-mode (sb-posix:stat (uiop:native-namestring target)))))
       (equalp bytes (read-file-octets target))))

(defun volume-directory-files (directory)
  "List every file beneath DIRECTORY without following links."
  (append (uiop:directory-files directory)
          (loop for child in (uiop:subdirectories directory)
                append (volume-directory-files child))))

(defun publish-pod-volume-files (directory files group)
  "Make DIRECTORY hold exactly FILES, with GROUP readable when an fsGroup applies."
  (let ((wanted nil))
    (loop for (relative bytes mode) in files
          do (let ((target (volume-file-pathname directory relative))
                   (actual (if group (logior mode #o440) mode)))
               (push (uiop:native-namestring target) wanted)
               (unless (volume-file-current-p target bytes actual)
                 (write-projected-volume-file target bytes actual group))))
    (dolist (path (volume-directory-files directory))
      (unless (member (uiop:native-namestring path) wanted :test #'equal)
        (delete-file path)))))

(defun refresh-pod-projected-volumes (runtime pod)
  "Bring POD's existing projected volumes up to date, keeping old content on any failure."
  (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
        for directory = (pod-volume-directory runtime pod (gethash "name" volume))
        when (uiop:directory-exists-p directory)
          do (handler-case
                 (multiple-value-bind (files projection) (pod-volume-desired-files runtime pod volume)
                   (when projection
                     (publish-pod-volume-files directory files (pod-fs-group pod))))
               ((or runtime-error kubernetes-error file-error sb-posix:syscall-error) (condition)
                 (format *error-output* "gr8s Pod ~A/~A volume ~A refresh: ~A~%" (pod-namespace pod)
                         (pod-name pod) (gethash "name" volume) condition)))))
