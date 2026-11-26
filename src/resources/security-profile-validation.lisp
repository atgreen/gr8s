;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate the subset of OpenKruise Agents' SecurityProfile (agents.kruise.io/
;;;; v1alpha1) that gr8s serves natively for credential injection (podster-wv1w.3,
;;;; docs/design-agent-egress.md). A profile selects Pods by label and, for requests
;;;; to the domains, schemes, paths and methods a rule matches, has the node egress
;;;; proxy overwrite named headers with a value rendered from a Secret. Whatever gr8s
;;;; doesn't implement is refused here, so a manifest gr8s accepts means what it says:
;;;; one ApiKey token transformation per rule, failing closed.
;;;;
;;;; One extension of gr8s's own, type OAuthRefresh (podster-kn03): for an OAuth token
;;;; endpoint, the proxy puts the Secret's real refresh token into a refresh request in
;;;; place of the stand-in, keeps the new real tokens the response carries (the node
;;;; writes them back to the Secret) and hands the client stand-ins.

(in-package #:gr8s.resources)

(defun %sp-invalid (control &rest arguments)
  (apply #'core-resource-error 422 "Invalid" (concatenate 'string "SecurityProfile " control) arguments))

(defun %sp-object (value path)
  (unless (hash-table-p value) (%sp-invalid "~A must be an object" path))
  value)

(defun %sp-fields (object allowed path)
  (dolist (key (loop for key being the hash-keys of object collect key))
    (unless (member key allowed :test #'equal)
      (%sp-invalid "~A.~A is not supported by gr8s" path key))))

(defun %sp-strings (value path &key (min 1))
  (unless (and (vectorp value) (not (stringp value)) (>= (length value) min)
               (every (lambda (item) (and (stringp item) (plusp (length item)))) value))
    (%sp-invalid "~A must be a list of at least ~D non-empty strings" path min))
  (coerce value 'list))

(defparameter +sp-domain-scanner+
  (cl-ppcre:create-scanner "^(\\*\\.)?([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\\.)+[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$")
  "An exact host, or one led by a single *. wildcard.")

(defparameter +sp-token-template+ "{{ .Token }}"
  "The only template action gr8s renders: the Secret's value.")

(defun %sp-match (match path)
  (%sp-object match path)
  (%sp-fields match '("domains" "schemes" "paths" "methods") path)
  (loop for domain in (%sp-strings (gethash "domains" match) (format nil "~A.domains" path))
        unless (cl-ppcre:scan +sp-domain-scanner+ domain)
          do (%sp-invalid "~A.domains: ~S is not a host or *.host" path domain))
  (multiple-value-bind (schemes present) (gethash "schemes" match)
    (when present
      (dolist (scheme (%sp-strings schemes (format nil "~A.schemes" path)))
        (unless (member scheme '("https" "http") :test #'equal)
          (%sp-invalid "~A.schemes must be https or http" path)))))
  (multiple-value-bind (methods present) (gethash "methods" match)
    (when present (%sp-strings methods (format nil "~A.methods" path))))
  (multiple-value-bind (paths present) (gethash "paths" match)
    (when present
      (unless (and (vectorp paths) (not (stringp paths)) (plusp (length paths)))
        (%sp-invalid "~A.paths must be a non-empty list" path))
      (loop for item across paths
            for index from 0
            for item-path = (format nil "~A.paths[~D]" path index)
            do (%sp-object item item-path)
               (%sp-fields item '("type" "value") item-path)
               (unless (member (gethash "type" item "Prefix") '("Prefix" "Exact") :test #'equal)
                 (%sp-invalid "~A.type must be Prefix or Exact" item-path))
               (let ((value (gethash "value" item)))
                 (unless (and (stringp value) (plusp (length value)) (char= #\/ (char value 0)))
                   (%sp-invalid "~A.value must be a path beginning with /" item-path)))))))

(defun %sp-token-transformation (transformation path)
  (%sp-object transformation path)
  (%sp-fields transformation '("type" "failStrategy" "credentialRef" "apiKey" "oauthRefresh") path)
  (unless (member (gethash "type" transformation) '("ApiKey" "OAuthRefresh") :test #'equal)
    (%sp-invalid "~A.type must be ApiKey or OAuthRefresh" path))
  (unless (member (gethash "failStrategy" transformation "Block") '("Block") :test #'equal)
    (%sp-invalid "~A.failStrategy must be Block: gr8s never sends a request whose credential it couldn't add" path))
  (let* ((reference-path (format nil "~A.credentialRef" path))
         (reference (%sp-object (gethash "credentialRef" transformation) reference-path))
         (secret-path (format nil "~A.secret" reference-path)))
    (%sp-fields reference '("secret") reference-path)
    (let ((secret (%sp-object (gethash "secret" reference) secret-path)))
      (%sp-fields secret '("name" "key") secret-path)
      (unless (and (stringp (gethash "name" secret)) (dns-subdomain-p (gethash "name" secret)))
        (%sp-invalid "~A.name must name a Secret in the profile's namespace" secret-path))
      (multiple-value-bind (key present) (gethash "key" secret)
        (when (and present (not (and (stringp key) (plusp (length key)))))
          (%sp-invalid "~A.key must be a data key" secret-path)))))
  (when (equal (gethash "type" transformation) "OAuthRefresh")
    (when (nth-value 1 (gethash "apiKey" transformation))
      (%sp-invalid "~A.apiKey is for type ApiKey" path))
    (multiple-value-bind (refresh present) (gethash "oauthRefresh" transformation)
      (when present
        (let ((refresh-path (format nil "~A.oauthRefresh" path)))
          (%sp-object refresh refresh-path)
          (%sp-fields refresh '("accessTokenKey" "refreshTokenKey") refresh-path)
          (maphash (lambda (key value)
                     (unless (and (stringp value) (cl-ppcre:scan "^[-._a-zA-Z0-9]+$" value))
                       (%sp-invalid "~A.~A must be a Secret data key" refresh-path key)))
                   refresh))))
    (return-from %sp-token-transformation))
  (when (nth-value 1 (gethash "oauthRefresh" transformation))
    (%sp-invalid "~A.oauthRefresh is for type OAuthRefresh" path))
  (let* ((api-path (format nil "~A.apiKey" path))
         (api-key (%sp-object (gethash "apiKey" transformation) api-path))
         (headers-path (format nil "~A.targetHeaders" api-path))
         (headers (%sp-object (gethash "targetHeaders" api-key) headers-path))
         (value-path (format nil "~A.value" api-path))
         (value (%sp-object (gethash "value" api-key) value-path)))
    (%sp-fields api-key '("targetHeaders" "value") api-path)
    (%sp-fields headers '("names") headers-path)
    (dolist (name (%sp-strings (gethash "names" headers) (format nil "~A.names" headers-path)))
      (unless (cl-ppcre:scan "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$" name)
        (%sp-invalid "~A.names: ~S is not a header name" headers-path name)))
    (%sp-fields value '("template") value-path)
    (let ((template (gethash "template" value)))
      (unless (stringp template) (%sp-invalid "~A.template must be a string" value-path))
      ;; Only {{ .Token }} renders; any other action would silently mean nothing.
      (let ((rest (cl-ppcre:regex-replace-all "\\{\\{\\s*\\.Token\\s*\\}\\}" template "")))
        (when (or (search "{{" rest) (search "}}" rest))
          (%sp-invalid "~A.template may use only ~A" value-path +sp-token-template+))
        (when (string= rest template)
          (%sp-invalid "~A.template must use ~A" value-path +sp-token-template+))))))

(defun validate-security-profile (object)
  "Validate SecurityProfile OBJECT's spec against the subset gr8s implements; signal a
422 naming the first problem."
  (let ((spec (%sp-object (gethash "spec" object) "spec")))
    (%sp-fields spec '("selector" "priority" "rules") "spec")
    (validate-workload-selector (%sp-object (gethash "selector" spec) "spec.selector") :allow-empty t)
    (multiple-value-bind (priority present) (gethash "priority" spec)
      (when (and present (not (integerp priority)))
        (%sp-invalid "spec.priority must be an integer")))
    (let ((rules (gethash "rules" spec)))
      (unless (and (vectorp rules) (not (stringp rules)) (plusp (length rules)))
        (%sp-invalid "spec.rules must be a non-empty list"))
      (loop for rule across rules
            for index from 0
            for path = (format nil "spec.rules[~D]" index)
            do (%sp-object rule path)
               (%sp-fields rule '("name" "match" "actions") path)
               (unless (and (stringp (gethash "name" rule)) (plusp (length (gethash "name" rule))))
                 (%sp-invalid "~A.name is required" path))
               (let ((matches (gethash "match" rule)))
                 (unless (and (vectorp matches) (not (stringp matches)) (plusp (length matches)))
                   (%sp-invalid "~A.match must be a non-empty list" path))
                 (loop for match across matches
                       for m from 0
                       do (%sp-match match (format nil "~A.match[~D]" path m))))
               (let ((actions (%sp-object (gethash "actions" rule) (format nil "~A.actions" path))))
                 (%sp-fields actions '("tokenTransformation") (format nil "~A.actions" path))
                 (%sp-token-transformation (gethash "tokenTransformation" actions)
                                           (format nil "~A.actions.tokenTransformation" path)))))))
