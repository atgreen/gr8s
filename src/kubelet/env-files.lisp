;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Environment variables read from a file in one of the Pod's emptyDir volumes
;;;; (env valueFrom.fileKeyRef, EnvFiles, beta and on by default since v1.35). An
;;;; earlier container writes KEY='value' lines; the kubelet reads the named key
;;;; when it creates each container that refers to it.

(in-package #:gr8s.kubelet)

(defun relaxed-environment-name-p (name)
  "Accept what IsRelaxedEnvVarName does: printable ASCII other than '='."
  (and (stringp name) (plusp (length name))
       (every (lambda (character) (and (char<= #\Space character #\~) (char/= character #\=))) name)))

(defun validate-file-key-selector (selector)
  "Validate a fileKeyRef as validateFileKeySelector does."
  (drop-null-fields selector)
  (reject-unsupported-fields selector '("volumeName" "path" "key" "optional") "fileKeyRef")
  (let ((key (gethash "key" selector)) (volume (gethash "volumeName" selector)) (path (gethash "path" selector)))
    (unless (and (stringp key) (plusp (length key)))
      (invalid-pod "fileKeyRef.key: Required value"))
    (unless (relaxed-environment-name-p key)
      (invalid-pod "fileKeyRef.key: Invalid value: ~S: a valid environment variable name must consist only of printable ASCII characters other than '='" key))
    (unless (and (stringp volume) (plusp (length volume)))
      (invalid-pod "fileKeyRef.volumeName: Required value"))
    (unless (dns-label-p volume)
      (invalid-pod "fileKeyRef.volumeName: Invalid value: ~S: must be a DNS label" volume))
    (unless (and (stringp path) (plusp (length path)))
      (invalid-pod "fileKeyRef.path: Required value"))
    (when (member ".." (uiop:split-string path :separator '(#\/)) :test #'equal)
      (invalid-pod "fileKeyRef.path: Invalid value: ~S: must not contain '..'" path))
    (multiple-value-bind (optional present) (gethash "optional" selector)
      (when (and present (not (member optional '(t nil))))
        (invalid-pod "fileKeyRef.optional must be boolean")))))

(defun validate-file-key-ref-volumes (spec)
  "Require every fileKeyRef to name one of SPEC's emptyDir volumes, as validateFileKeyRefVolumes does."
  (let ((volumes (gethash "volumes" spec #())))
    (loop for container across (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec #())
                                            (gethash "ephemeralContainers" spec #()))
          when (hash-table-p container)
            do (loop for variable across (gethash "env" container #())
                     for from = (and (hash-table-p variable) (gethash "valueFrom" variable))
                     for selector = (and (hash-table-p from) (gethash "fileKeyRef" from))
                     for name = (and (hash-table-p selector) (gethash "volumeName" selector))
                     for volume = (and name (find name volumes :test #'equal
                                                  :key (lambda (item) (and (hash-table-p item) (gethash "name" item)))))
                     when (hash-table-p selector)
                       do (cond ((null volume)
                                 (invalid-pod "env.valueFrom.fileKeyRef.volumeName: Not found: ~S" name))
                                ((not (gethash "emptyDir" volume))
                                 (invalid-pod "env.valueFrom.fileKeyRef.volumeName: Invalid value: ~S: referenced volume must be of type emptyDir"
                                              name)))))))

(defun parse-environment-file-value (text key)
  "Return KEY's value in the environment file TEXT, or NIL when it is absent, as ParseEnv reads one.
Each line is KEY='value', a single-quoted value may span lines, and blank lines and # comments are
skipped. Whitespace after '=' gives an empty value, as bash would. Malformed text signals an error."
  (let ((lines (uiop:split-string text :separator '(#\Newline))) (number 0))
    (flet ((malformed (control &rest arguments)
             (error "invalid environment variable format at line ~D: ~?" number control arguments)))
      (loop while lines
            do (let ((line (string-left-trim '(#\Space #\Tab) (pop lines))))
                 (incf number)
                 (unless (or (zerop (length line)) (char= #\# (char line 0)))
                   (let* ((equals (or (position #\= line) (malformed "missing '='")))
                          (name-part (subseq line 0 equals))
                          (name (string-right-trim '(#\Space #\Tab) name-part))
                          (value-part (subseq line (1+ equals)))
                          (trimmed (string-left-trim '(#\Space #\Tab) value-part)))
                     (when (zerop (length name)) (malformed "empty variable name"))
                     (unless (equal name name-part) (malformed "whitespace before '=' is not allowed"))
                     (cond
                       ((not (equal value-part trimmed))
                        (when (equal name key) (return-from parse-environment-file-value "")))
                       ((not (and (plusp (length trimmed)) (char= #\' (char trimmed 0))))
                        (malformed "value must be enclosed in single quotes"))
                       (t
                        (let ((rest (subseq trimmed 1)) (start number))
                          (with-output-to-string (value)
                            (loop
                              (let ((closing (position #\' rest)))
                                (when closing
                                  (write-string rest value :end closing)
                                  (let ((after (string-left-trim '(#\Space #\Tab) (subseq rest (1+ closing)))))
                                    (unless (or (zerop (length after)) (char= #\# (char after 0)))
                                      (malformed "unexpected content after closing quote")))
                                  (when (equal name key)
                                    (return-from parse-environment-file-value (get-output-stream-string value)))
                                  (return))
                                (write-string rest value)
                                (write-char #\Newline value)
                                (unless lines
                                  (setf number start)
                                  (malformed "unclosed single quote"))
                                (setf rest (pop lines))
                                (incf number)))))))))))
      nil)))

(defun containerd-file-key-environment-value (runtime pod selector)
  "Return SELECTOR's value from its emptyDir file, with T, or NIL when an optional key is absent.
A missing or malformed file, or a missing required key, leaves the container waiting in
CreateContainerConfigError until a later attempt finds it."
  (let* ((directory (pod-volume-directory runtime pod (gethash "volumeName" selector)))
         (path (merge-pathnames (string-left-trim "/" (gethash "path" selector)) directory))
         (key (gethash "key" selector))
         (value (handler-case (parse-environment-file-value
                               (uiop:read-file-string path :external-format :utf-8) key)
                  (error ()
                    (container-config-error "couldn't parse env file")))))
    (cond ((plusp (length value)) (values value t))
          ((eq t (gethash "optional" selector)) (values nil nil))
          (t (container-config-error "environment variable key ~S not found in file ~S" key (namestring path))))))
