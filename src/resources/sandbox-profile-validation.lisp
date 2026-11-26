;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate gr8.gr8s.io/v1alpha1 SandboxProfile (podster-wv1w.5): what a
;;;; command gr8 runs gets beyond its working directory -- paths in the caller's
;;;; home, read-write or read-only, and environment placeholders (a stand-in API key
;;;; the node egress proxy overwrites). Paths are relative to $HOME and may not climb
;;;; out of it, so a profile can't grant /etc or another user's files.

(in-package #:gr8s.resources)

(defun %sbp-invalid (control &rest arguments)
  (apply #'core-resource-error 422 "Invalid" (concatenate 'string "SandboxProfile " control) arguments))

(defun %sbp-home-path-p (path)
  (and (stringp path) (plusp (length path)) (char/= #\/ (char path 0))
       (notany (lambda (part) (member part '(".." "") :test #'equal))
               (uiop:split-string (string-right-trim "/" path) :separator "/"))))

(defun validate-sandbox-profile (object)
  "Validate SandboxProfile OBJECT's spec; signal a 422 naming the first problem."
  (let ((spec (gethash "spec" object)))
    (unless (hash-table-p spec) (%sbp-invalid "spec must be an object"))
    (dolist (key (loop for key being the hash-keys of spec collect key))
      (unless (member key '("commands" "home" "env") :test #'equal)
        (%sbp-invalid "spec.~A is not supported" key)))
    (let ((commands (gethash "commands" spec)))
      (unless (and (vectorp commands) (not (stringp commands)) (plusp (length commands))
                   (every (lambda (c) (and (stringp c) (plusp (length c)) (not (find #\/ c)))) commands))
        (%sbp-invalid "spec.commands must name at least one command by its base name")))
    (multiple-value-bind (home present) (gethash "home" spec)
      (when present
        (unless (hash-table-p home) (%sbp-invalid "spec.home must be an object"))
        (dolist (key (loop for key being the hash-keys of home collect key))
          ;; placeholders: credential files the sandbox sees with stand-in tokens,
          ;; never the real ones, and never saves back (podster-wv1w.7).
          (unless (member key '("readWrite" "readOnly" "placeholders") :test #'equal)
            (%sbp-invalid "spec.home.~A is not supported" key))
          (let ((paths (gethash key home)))
            (unless (and (vectorp paths) (not (stringp paths)) (every #'%sbp-home-path-p paths))
              (%sbp-invalid "spec.home.~A must list paths relative to $HOME, without .." key))))))
    (multiple-value-bind (env present) (gethash "env" spec)
      (when present
        (unless (hash-table-p env) (%sbp-invalid "spec.env must map names to values"))
        (maphash (lambda (name value)
                   (unless (and (cl-ppcre:scan "^[A-Za-z_][A-Za-z0-9_]*$" name) (stringp value))
                     (%sbp-invalid "spec.env.~A must be a variable name with a string value" name)))
                 env)))))
