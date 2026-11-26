;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate gr8.gr8s.io/v1alpha1 SandboxProfile (podster-wv1w.5): what a
;;;; command gr8 runs gets beyond its working directory -- paths in the caller's
;;;; home, read-write or read-only, and environment placeholders (a stand-in API key
;;;; the node egress proxy overwrites). Paths are relative to $HOME and may not climb
;;;; out of it, so a profile can't grant /etc or another user's files.
;;;;
;;;; spec.egress is read by the node, not by gr8 (podster-wv1w.11): whether the node
;;;; egress proxy terminates the command's TLS to see each request (Terminate, the
;;;; default) or relays it undecrypted (Passthrough, or for passthroughHosts), and
;;;; whether a request breaking a rule is refused (Enforce, the default) or only
;;;; reported (Audit). spec.namespaceSelector limits a profile to the gr8 Pods of the
;;;; namespaces it selects; one that names a namespace wins over one that doesn't.

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
      (unless (member key '("commands" "namespaceSelector" "run" "home" "env" "egress") :test #'equal)
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
    ;; One run's alone, by its Pod's gr8s.io/gr8-run label: a gr8 policy's (podster-wv1w.14).
    (multiple-value-bind (run present) (gethash "run" spec)
      (when (and present (not (and (stringp run) (dns-subdomain-p run))))
        (%sbp-invalid "spec.run must name a gr8 run's Pod")))
    ;; Which namespaces' gr8 Pods it is for: all, without one.
    (multiple-value-bind (selector present) (gethash "namespaceSelector" spec)
      (when present
        (unless (hash-table-p selector) (%sbp-invalid "spec.namespaceSelector must be a label selector"))
        (validate-workload-selector selector :allow-empty t)))
    (multiple-value-bind (egress present) (gethash "egress" spec)
      (when present
        (unless (hash-table-p egress) (%sbp-invalid "spec.egress must be an object"))
        (maphash (lambda (key value)
                   (cond ((equal key "tls")
                          (unless (member value '("Terminate" "Passthrough") :test #'equal)
                            (%sbp-invalid "spec.egress.tls must be Terminate or Passthrough")))
                         ((equal key "enforcement")
                          (unless (member value '("Enforce" "Audit") :test #'equal)
                            (%sbp-invalid "spec.egress.enforcement must be Enforce or Audit")))
                         ((equal key "passthroughHosts")
                          (unless (and (vectorp value) (not (stringp value))
                                       (every (lambda (host)
                                                (and (stringp host)
                                                     (cl-ppcre:scan "^(\\*\\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$" host)))
                                              value))
                            (%sbp-invalid "spec.egress.passthroughHosts must list hostnames, *.example.com for subdomains")))
                         ((equal key "binaries")
                          ;; Which programs may reach which hosts (podster-wv1w.13).
                          (unless (and (vectorp value) (not (stringp value)))
                            (%sbp-invalid "spec.egress.binaries must be a list"))
                          (loop for entry across value
                                for index from 0
                                do (unless (hash-table-p entry)
                                     (%sbp-invalid "spec.egress.binaries[~D] must be an object" index))
                                   (maphash (lambda (field items)
                                              (unless (member field '("hosts" "paths") :test #'equal)
                                                (%sbp-invalid "spec.egress.binaries[~D].~A is not supported" index field))
                                              (unless (and (vectorp items) (not (stringp items)) (plusp (length items))
                                                           (every #'stringp items))
                                                (%sbp-invalid "spec.egress.binaries[~D].~A must list strings" index field)))
                                            entry)
                                   (unless (and (gethash "hosts" entry) (gethash "paths" entry))
                                     (%sbp-invalid "spec.egress.binaries[~D] needs hosts and paths" index))
                                   (loop for host across (gethash "hosts" entry)
                                         unless (cl-ppcre:scan "^(\\*\\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$" host)
                                           do (%sbp-invalid "spec.egress.binaries[~D].hosts: ~S is not a hostname" index host))
                                   (loop for path across (gethash "paths" entry)
                                         unless (and (plusp (length path)) (char= #\/ (char path 0)))
                                           do (%sbp-invalid "spec.egress.binaries[~D].paths: ~S is not an absolute path" index path))))
                         (t (%sbp-invalid "spec.egress.~A is not supported" key))))
                 egress)))
    (multiple-value-bind (env present) (gethash "env" spec)
      (when present
        (unless (hash-table-p env) (%sbp-invalid "spec.env must map names to values"))
        (maphash (lambda (name value)
                   (unless (and (cl-ppcre:scan "^[A-Za-z_][A-Za-z0-9_]*$" name) (stringp value))
                     (%sbp-invalid "spec.env.~A must be a variable name with a string value" name)))
                 env)))))
