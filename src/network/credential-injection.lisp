;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Credential injection (podster-wv1w.3, docs/design-agent-egress.md): the node
;;;; egress proxy adds a credential from a Secret to the requests a SecurityProfile
;;;; matches, so the Pod never holds it. The Pod may send any placeholder; the proxy
;;;; overwrites the named headers on every matching request, and only those, which is
;;;; what keeps a stolen placeholder -- or a credential sent to the wrong host --
;;;; worthless.
;;;;
;;;; This file is the node's model: which profiles select a Pod, which rule matches a
;;;; request, and the header value a rule renders. The proxy (src/controllers/
;;;; egress-proxy.lisp) does the TLS and HTTP. The node agent already reads the Secrets
;;;; of the Pods it runs, so injecting for them gives it no new authority.

(in-package #:gr8s.network)

(defstruct (injection-rule (:constructor make-injection-rule
                               (&key name profile namespace priority domains schemes paths methods
                                     headers template secret-name secret-key
                                     (kind :api-key) access-token-key refresh-token-key)))
  "One SecurityProfile rule as the proxy applies it. PATHS is a list of (:prefix or
:exact . path); SCHEMES, METHODS and PATHS are NIL for any. KIND :api-key overwrites
HEADERS with TEMPLATE rendered from SECRET-KEY; :oauth-refresh exchanges the Secret's
REFRESH-TOKEN-KEY in a refresh request and keeps the tokens it returns (podster-kn03)."
  name profile namespace priority domains schemes paths methods headers template secret-name secret-key
  kind access-token-key refresh-token-key)

(defstruct (security-profile-spec (:constructor make-security-profile-spec (&key name namespace selector rules)))
  name namespace selector rules)

(defun %sp-strings (value) (and (vectorp value) (coerce value 'list)))

(defun security-profile-specs-from-objects (objects)
  "Parse stored or projected SecurityProfiles into security-profile-specs, one
injection-rule per (rule, match) pair."
  (loop for object in objects
        for metadata = (gethash "metadata" object)
        for spec = (gethash "spec" object)
        when (hash-table-p spec)
          collect (let ((name (gethash "name" metadata)) (namespace (gethash "namespace" metadata))
                        (priority (gethash "priority" spec 1000)))
                    (make-security-profile-spec
                     :name name :namespace namespace :selector (gethash "selector" spec (core-object))
                     :rules
                     (loop for rule across (gethash "rules" spec #())
                           for transformation = (gethash "tokenTransformation" (gethash "actions" rule (core-object)))
                           for secret = (and transformation
                                             (gethash "secret" (gethash "credentialRef" transformation (core-object))))
                           for api-key = (and transformation (gethash "apiKey" transformation))
                           for refresh = (and transformation (equal "OAuthRefresh" (gethash "type" transformation))
                                              (gethash "oauthRefresh" transformation (core-object)))
                           when (and secret (or api-key refresh))
                             append (loop for match across (gethash "match" rule #())
                                          collect (make-injection-rule
                                                   :name (gethash "name" rule) :profile name :namespace namespace
                                                   :priority priority
                                                   :domains (%sp-strings (gethash "domains" match))
                                                   :schemes (%sp-strings (gethash "schemes" match))
                                                   :methods (mapcar #'string-upcase (%sp-strings (gethash "methods" match)))
                                                   :paths (loop for path across (gethash "paths" match #())
                                                                collect (cons (if (equal (gethash "type" path "Prefix") "Exact")
                                                                                  :exact :prefix)
                                                                              (gethash "value" path)))
                                                   :kind (if refresh :oauth-refresh :api-key)
                                                   :headers (and api-key (%sp-strings (gethash "names" (gethash "targetHeaders" api-key))))
                                                   :template (and api-key (gethash "template" (gethash "value" api-key)))
                                                   :secret-name (gethash "name" secret)
                                                   :secret-key (gethash "key" secret)
                                                   :access-token-key (and refresh (gethash "accessTokenKey" refresh "accessToken"))
                                                   :refresh-token-key (and refresh (gethash "refreshTokenKey" refresh "refreshToken")))))))))

(defun security-profile-selects-pod-p (profile pod)
  (and (equal (security-profile-spec-namespace profile) (np-pod-namespace pod))
       (np-selector-matches-p (security-profile-spec-selector profile) (np-pod-labels pod))))

(defun pod-injection-rules (pod profiles)
  "The injection rules of the PROFILES selecting POD, lower priority first (then by
profile name), each profile's in written order."
  (loop for profile in (stable-sort (remove-if-not (lambda (profile) (security-profile-selects-pod-p profile pod))
                                                   profiles)
                                    (lambda (a b)
                                      (let ((pa (injection-rule-priority (first (security-profile-spec-rules a))))
                                            (pb (injection-rule-priority (first (security-profile-spec-rules b)))))
                                        (if (eql pa pb)
                                            (string< (security-profile-spec-name a) (security-profile-spec-name b))
                                            (< (or pa 1000) (or pb 1000))))))
        append (security-profile-spec-rules profile)))

(defun pod-credential-hosts (pod profiles)
  "The domain patterns POD's injected credentials are bound to, in rule order, once each."
  (remove-duplicates (loop for rule in (pod-injection-rules pod profiles)
                           append (copy-list (injection-rule-domains rule)))
                     :test #'equal :from-end t))

(defun injection-host-p (rules host)
  "True when one of RULES names HOST: the proxy must terminate TLS for it."
  (some (lambda (rule) (some (lambda (domain) (egress-domain-matches-p domain host)) (injection-rule-domains rule)))
        rules))

(defun matching-injection-rule (rules host scheme method path)
  "The first of RULES matching a request for PATH (without its query) by METHOD to HOST
over SCHEME, or NIL."
  (let ((path (subseq path 0 (or (position #\? path) (length path)))))
    (find-if (lambda (rule)
               (and (some (lambda (domain) (egress-domain-matches-p domain host)) (injection-rule-domains rule))
                    (or (null (injection-rule-schemes rule)) (member scheme (injection-rule-schemes rule) :test #'equal))
                    (or (null (injection-rule-methods rule))
                        (member (string-upcase method) (injection-rule-methods rule) :test #'equal))
                    (or (null (injection-rule-paths rule))
                        (some (lambda (entry)
                                (destructuring-bind (type . value) entry
                                  (if (eq type :exact)
                                      (string= value path)
                                      (and (>= (length path) (length value)) (string= value path :end2 (length value))))))
                              (injection-rule-paths rule)))))
             rules)))

(defun secret-credential (secret key)
  "The credential SECRET (a Secret object) holds: under KEY, or its only data key. Returns
a string, or NIL when there is no single answer."
  (let* ((data (gethash "data" secret (core-object)))
         (string-data (gethash "stringData" secret (core-object)))
         (keys (remove-duplicates (append (loop for k being the hash-keys of data collect k)
                                          (loop for k being the hash-keys of string-data collect k))
                                  :test #'equal))
         (chosen (or key (and (= 1 (length keys)) (first keys)))))
    (when chosen
      (multiple-value-bind (text present) (gethash chosen string-data)
        (if present
            text
            (let ((encoded (gethash chosen data)))
              (and (stringp encoded)
                   (ignore-errors
                    (trivial-utf-8:utf-8-bytes-to-string (cl-base64:base64-string-to-usb8-array encoded))))))))))

(defun render-injection-value (template credential)
  "TEMPLATE with each {{ .Token }} replaced by CREDENTIAL."
  (cl-ppcre:regex-replace-all "\\{\\{\\s*\\.Token\\s*\\}\\}" template
                              (lambda (match &rest registers) (declare (ignore match registers)) credential)
                              :simple-calls t))

(defun security-profile-secret-names (profiles namespace labels)
  "The names of the Secrets PROFILES that select a Pod in NAMESPACE with LABELS take
credentials from: what that Pod's assignment may carry beyond its own references."
  (let ((pod (make-np-pod :namespace namespace :labels labels)))
    (remove-duplicates
     (loop for profile in profiles
           when (security-profile-selects-pod-p profile pod)
             append (mapcar #'injection-rule-secret-name (security-profile-spec-rules profile)))
     :test #'equal)))
