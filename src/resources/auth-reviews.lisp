;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve the create-only review APIs, TokenRequest and request impersonation.
;;;; Reviews never store anything: they evaluate the live RBAC objects and token
;;;; verifier that real requests pass through, so their answers match enforcement.

(in-package #:gr8s.resources)

(defparameter +auth-review-kinds+
  '(("SubjectAccessReview" "authorization.k8s.io/v1") ("LocalSubjectAccessReview" "authorization.k8s.io/v1")
    ("SelfSubjectAccessReview" "authorization.k8s.io/v1") ("SelfSubjectRulesReview" "authorization.k8s.io/v1")
    ("TokenRequest" "authentication.k8s.io/v1") ("TokenReview" "authentication.k8s.io/v1")
    ("SelfSubjectReview" "authentication.k8s.io/v1")))

(defparameter +auth-review-resources+
  '(("subjectaccessreviews" "SubjectAccessReview" "authorization.k8s.io" nil)
    ("localsubjectaccessreviews" "LocalSubjectAccessReview" "authorization.k8s.io" t)
    ("selfsubjectaccessreviews" "SelfSubjectAccessReview" "authorization.k8s.io" nil)
    ("selfsubjectrulesreviews" "SelfSubjectRulesReview" "authorization.k8s.io" nil)
    ("tokenreviews" "TokenReview" "authentication.k8s.io" nil)
    ("selfsubjectreviews" "SelfSubjectReview" "authentication.k8s.io" nil))
  "Each entry: resource, kind, group and whether its collection is namespaced.")

(defun auth-review-kind-version (kind)
  "Return the API version of a review KIND, or NIL for any other kind."
  (second (assoc kind +auth-review-kinds+ :test #'equal)))

(defun decode-auth-review-protobuf (raw kind version)
  "Decode a review or TokenRequest from its pinned wire schema."
  (let* ((package (if (equal version "authorization.k8s.io/v1") "authorization" "authentication"))
         (object (template-protobuf-message (format nil "k8s.io.api.~A.v1.~A" package kind) raw))
         (metadata (core-protobuf-value (core-protobuf-fields raw) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) version (gethash "kind" object) kind)
    object))

;;; Discovery

(defun auth-review-groups ()
  "Describe the authorization and authentication API groups."
  (vector (typed-api-group "authorization.k8s.io") (typed-api-group "authentication.k8s.io")))

(defun auth-review-discovery-response (group)
  "Describe the create-only review collections of GROUP."
  (json-response
   (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" (format nil "~A/v1" group)
                "resources"
                (coerce (loop for (resource kind entry-group namespaced) in +auth-review-resources+
                              when (equal group entry-group)
                                collect (core-object "name" resource "singularName" (string-downcase kind)
                                                     "namespaced" namespaced "kind" kind "verbs" #("create")))
                        'vector))))

(defun auth-review-group-route (path)
  "Return the group and whether PATH names a review group's version document."
  (dolist (group '("authorization.k8s.io" "authentication.k8s.io"))
    (let ((root (concatenate 'string "/apis/" group)))
      (cond ((equal path root) (return (values group nil)))
            ((equal path (concatenate 'string root "/v1")) (return (values group t)))))))

(defun auth-review-route (path)
  "Resolve a review collection URL to its table entry and namespace."
  (let ((parts (rest (uiop:split-string path :separator '(#\/)))))
    (when (and (equal "apis" (first parts)) (equal "v1" (third parts)))
      (let* ((tail (nthcdr 3 parts))
             (namespace (and (= 3 (length tail)) (equal "namespaces" (first tail)) (second tail)))
             (resource (if namespace (third tail) (and (= 1 (length tail)) (first tail))))
             (entry (assoc resource +auth-review-resources+ :test #'equal)))
        (when (and entry (equal (second parts) (third entry))
                   (if (fourth entry) namespace (null namespace)))
          (values entry namespace))))))

;;; Identities and authorization

(defun request-api-identity ()
  "Return the current request's identity. The local administrative listener acts as a cluster administrator."
  (or *authenticated-api-identity*
      (make-api-user-identity :username "system:admin" :groups (vector "system:masters" "system:authenticated"))))

(defun review-subject-identity (spec)
  "Build the identity a SubjectAccessReview SPEC asks about."
  (make-api-user-identity :username (gethash "user" spec "") :uid (gethash "uid" spec)
                          :groups (let ((groups (gethash "groups" spec)))
                                    (if (member groups '(nil null)) #() groups))
                          :extra (gethash "extra" spec)))

(defun access-review-status (store identity spec)
  "Evaluate review SPEC's attributes for IDENTITY, the same way a real request is authorized."
  (let* ((attributes (gethash "resourceAttributes" spec))
         (non-resource (gethash "nonResourceAttributes" spec))
         (allowed
           (if (hash-table-p attributes)
               (let ((resource (gethash "resource" attributes "")) (subresource (gethash "subresource" attributes "")))
                 (service-account-authorized-p
                  store identity (gethash "verb" attributes "") (gethash "group" attributes "")
                  (if (plusp (length subresource)) (format nil "~A/~A" resource subresource) resource)
                  (let ((name (gethash "name" attributes ""))) (and (plusp (length name)) name))
                  (let ((namespace (gethash "namespace" attributes ""))) (and (plusp (length namespace)) namespace))))
               (service-account-authorized-p
                store identity (gethash "verb" non-resource "") "" nil nil nil (gethash "path" non-resource "")))))
    (if allowed
        (core-object "allowed" t "reason" "RBAC: allowed")
        (core-object "allowed" nil "reason" "RBAC: no matching rule"))))

(defun validate-access-review-attributes (spec)
  "Require exactly one attribute kind in review SPEC."
  (let ((attributes (gethash "resourceAttributes" spec)) (non-resource (gethash "nonResourceAttributes" spec)))
    (unless (not (eq (hash-table-p attributes) (hash-table-p non-resource)))
      (core-resource-error 422 "Invalid" "spec needs exactly one of resourceAttributes or nonResourceAttributes"))))

(defun review-object-response (review status)
  "Echo REVIEW with its evaluated STATUS, as a created review is never stored."
  (setf (gethash "status" review) status)
  (when (hash-table-p (gethash "metadata" review))
    (setf (gethash "creationTimestamp" (gethash "metadata" review)) 'null))
  (json-response review 201))

(defun self-subject-rules-status (store identity namespace)
  "List the rules IDENTITY's live bindings grant in NAMESPACE."
  ;; As SERVICE-ACCOUNT-AUTHORIZED-P, which honors this group without any binding.
  (when (find "system:masters" (api-identity-groups identity) :test #'equal)
    (return-from self-subject-rules-status
      (core-object "resourceRules" (vector (core-object "verbs" #("*") "apiGroups" #("*") "resources" #("*")))
                   "nonResourceRules" (vector (core-object "verbs" #("*") "nonResourceURLs" #("*")))
                   "incomplete" nil)))
  (let ((resource-rules nil) (non-resource-rules nil))
    (dolist (binding (append (list-core-resources store "clusterrolebindings")
                             (when namespace (list-core-resources store "rolebindings" namespace))))
      (let ((binding-namespace (gethash "namespace" (gethash "metadata" binding)))
            (reference (gethash "roleRef" binding)))
        (when (some (lambda (subject) (rbac-subject-matches-account-p subject binding-namespace identity))
                    (gethash "subjects" binding #()))
          (let ((role (handler-case
                          (if (equal "ClusterRole" (gethash "kind" reference))
                              (get-core-resource store "clusterroles" nil (gethash "name" reference))
                              (get-core-resource store "roles" binding-namespace (gethash "name" reference)))
                        (kubernetes-error () nil))))
            (when role
              (loop for rule across (gethash "rules" role #())
                    do (if (plusp (length (gethash "nonResourceURLs" rule #())))
                           (push (core-object "verbs" (gethash "verbs" rule) "nonResourceURLs" (gethash "nonResourceURLs" rule))
                                 non-resource-rules)
                           (push (core-object "verbs" (gethash "verbs" rule)
                                              "apiGroups" (gethash "apiGroups" rule #())
                                              "resources" (gethash "resources" rule #())
                                              "resourceNames" (gethash "resourceNames" rule #()))
                                 resource-rules))))))))
    (core-object "resourceRules" (coerce (nreverse resource-rules) 'vector)
                 "nonResourceRules" (coerce (nreverse non-resource-rules) 'vector)
                 "incomplete" nil)))

(defun user-info-object (identity)
  "Render IDENTITY as an authentication.k8s.io UserInfo."
  (let ((user (core-object "username" (api-identity-username identity) "groups" (api-identity-groups identity))))
    (let ((uid (etypecase identity
                 (api-user-identity (api-user-identity-uid identity))
                 (api-service-account-identity (api-service-account-identity-uid identity)))))
      (when uid (setf (gethash "uid" user) uid)))
    (when (and (api-service-account-identity-p identity) (api-service-account-identity-extra identity))
      (setf (gethash "extra" user) (api-service-account-identity-extra identity)))
    user))

(defun token-review-status (store spec)
  "Authenticate the token in SPEC for its audiences, reporting the identity it proves."
  (let* ((token (gethash "token" spec ""))
         (audiences (coerce (let ((value (gethash "audiences" spec))) (if (member value '(nil null)) #() value)) 'list)))
    (multiple-value-bind (identity accepted) (authenticate-service-account-token store token audiences)
      (if identity
          (core-object "authenticated" t "user" (user-info-object identity)
                       "audiences" (coerce (or accepted audiences (list +service-account-issuer+)) 'vector))
          (core-object "authenticated" nil "error" "token is invalid, expired or revoked" "audiences" #())))))

(defun dispatch-auth-review-request (store path method)
  "Evaluate and answer one review without storing it."
  (multiple-value-bind (entry namespace) (auth-review-route path)
    (unless (eq method :post)
      (core-resource-error 405 "MethodNotAllowed" "Review collections only support create"))
    (let* ((kind (second entry)) (resource (first entry))
           (*core-resource-view-version* (auth-review-kind-version kind))
           (review (core-resource-request-object kind))
           (schema (template-schema (format nil "io.k8s.api.~A.v1.~A"
                                            (if (equal "authorization.k8s.io" (third entry)) "authorization" "authentication")
                                            kind))))
      (unless (and (equal (auth-review-kind-version kind) (gethash "apiVersion" review (auth-review-kind-version kind)))
                   (equal kind (gethash "kind" review kind)))
        (core-resource-error 400 "BadRequest" "Expected ~A" kind))
      (setf (gethash "apiVersion" review) (auth-review-kind-version kind) (gethash "kind" review) kind)
      ;; Clients send an empty status, whose required lists Go renders as null. The server fills it in.
      (remhash "status" review)
      (validate-template-shape review schema kind)
      (let ((spec (let ((value (gethash "spec" review))) (if (hash-table-p value) value (core-object)))))
        (setf (gethash "spec" review) spec)
        (unless (hash-table-p (gethash "metadata" review)) (setf (gethash "metadata" review) (core-object)))
        (cond
          ((equal resource "subjectaccessreviews")
           (validate-access-review-attributes spec)
           (unless (or (plusp (length (gethash "user" spec ""))) (plusp (length (gethash "groups" spec #()))))
             (core-resource-error 422 "Invalid" "spec needs a user or groups"))
           (review-object-response review (access-review-status store (review-subject-identity spec) spec)))
          ((equal resource "localsubjectaccessreviews")
           (validate-access-review-attributes spec)
           (unless (or (plusp (length (gethash "user" spec ""))) (plusp (length (gethash "groups" spec #()))))
             (core-resource-error 422 "Invalid" "spec needs a user or groups"))
           (unless (equal namespace (gethash "namespace" (gethash "metadata" review) namespace))
             (core-resource-error 400 "BadRequest" "metadata.namespace does not match the request namespace"))
           (setf (gethash "namespace" (gethash "metadata" review)) namespace)
           (let ((attributes (gethash "resourceAttributes" spec)))
             (unless (and (hash-table-p attributes) (equal namespace (gethash "namespace" attributes)))
               (core-resource-error 422 "Invalid" "spec.resourceAttributes.namespace must match metadata.namespace")))
           (review-object-response review (access-review-status store (review-subject-identity spec) spec)))
          ((equal resource "selfsubjectaccessreviews")
           (validate-access-review-attributes spec)
           (review-object-response review (access-review-status store (request-api-identity) spec)))
          ((equal resource "selfsubjectrulesreviews")
           (review-object-response review (self-subject-rules-status store (request-api-identity) (gethash "namespace" spec))))
          ((equal resource "tokenreviews")
           (unless (plusp (length (gethash "token" spec "")))
             (core-resource-error 422 "Invalid" "spec.token is required"))
           (review-object-response review (token-review-status store spec)))
          (t (review-object-response
              review (core-object "userInfo" (user-info-object (request-api-identity))))))))))

;;; TokenRequest

(defun service-account-token-route (path)
  "Resolve a /api/v1/namespaces/NS/serviceaccounts/NAME/token URL to its namespace and account name."
  (let ((parts (uiop:split-string path :separator '(#\/))))
    (when (and (= 8 (length parts)) (equal (subseq parts 0 4) '("" "api" "v1" "namespaces"))
               (equal "serviceaccounts" (sixth parts)) (equal "token" (eighth parts))
               (dns-label-p (fifth parts)) (dns-subdomain-p (seventh parts)))
      (values (fifth parts) (seventh parts)))))

(defun token-request-binding (store namespace reference)
  "Resolve a TokenRequest's boundObjectRef to the (kind name uid) binding and any node it runs on."
  (let* ((kind (gethash "kind" reference)) (name (gethash "name" reference)) (uid (gethash "uid" reference))
         (object (handler-case
                     (cond ((equal kind "Pod") (pod-to-object (get-pod store namespace name)))
                           ((equal kind "Secret") (get-core-resource store "secrets" namespace name))
                           (t (core-resource-error 400 "BadRequest" "Cannot bind a token to a ~A" kind)))
                   (kubernetes-error (condition)
                     (if (= 404 (kubernetes-error-status-code condition))
                         (core-resource-error 404 "NotFound" "The bound ~A ~A was not found" kind name)
                         (error condition))))))
    (when (and uid (plusp (length uid)) (not (equal uid (gethash "uid" (gethash "metadata" object)))))
      (core-resource-error 409 "Conflict" "The bound object's UID has changed"))
    (list (string-downcase kind) name (gethash "uid" (gethash "metadata" object)))))

(defun rfc3339-from-unix (seconds)
  "Render Unix SECONDS as a Kubernetes timestamp."
  (current-timestamp (+ seconds 2208988800)))

(defun service-account-token-response (store path method)
  "Mint a token for the named ServiceAccount, as its token subresource does."
  (unless (eq method :post)
    (core-resource-error 405 "MethodNotAllowed" "The token subresource only supports create"))
  (multiple-value-bind (namespace name) (service-account-token-route path)
    (let* ((*core-resource-view-version* (auth-review-kind-version "TokenRequest"))
           (request (core-resource-request-object "TokenRequest"))
           (account (get-core-resource store "serviceaccounts" namespace name))
           (spec (let ((value (gethash "spec" request))) (if (hash-table-p value) value (core-object))))
           (seconds (let ((value (gethash "expirationSeconds" spec)))
                      (if (member value '(nil null 0)) +service-account-token-default-seconds+ value)))
           (audiences (let ((value (gethash "audiences" spec))) (if (member value '(nil null)) #() value)))
           (reference (gethash "boundObjectRef" spec))
           (binding (when (hash-table-p reference) (token-request-binding store namespace reference))))
      (validate-template-shape request (template-schema "io.k8s.api.authentication.v1.TokenRequest") "TokenRequest")
      (unless (and (integerp seconds) (<= +service-account-token-minimum-seconds+ seconds +service-account-token-maximum-seconds+))
        (core-resource-error 422 "Invalid" "spec.expirationSeconds may not specify a duration less than 10 minutes or more than 2^32 seconds"))
      (when (core-resource-dry-run-p)
        (core-resource-error 400 "BadRequest" "Dry-run is not supported for token requests"))
      (multiple-value-bind (token expiry)
          (mint-service-account-token store account :audiences (coerce audiences 'list) :seconds seconds :binding binding)
        (json-response
         (core-object "apiVersion" "authentication.k8s.io/v1" "kind" "TokenRequest"
                      "metadata" (core-object "name" name "namespace" namespace "creationTimestamp" (current-timestamp)
                                              "uid" (gethash "uid" (gethash "metadata" account)))
                      "spec" (core-object "audiences" (if (plusp (length audiences)) audiences (vector +service-account-issuer+))
                                          "expirationSeconds" seconds
                                          "boundObjectRef" (if (hash-table-p reference) reference 'null))
                      "status" (core-object "token" token "expirationTimestamp" (rfc3339-from-unix expiry)))
         201)))))

;;; Impersonation

(defun impersonation-header-values (request name)
  "Return the values of repeated header NAME, which the HTTP layer joins with commas."
  (let ((value (hunchentoot:header-in name request)))
    (when value
      (mapcar (lambda (item) (string-trim " " item))
              (uiop:split-string value :separator '(#\,))))))

(defun impersonation-allowed-p (store identity resource group name &optional namespace)
  "Return whether IDENTITY may impersonate NAME as RESOURCE."
  (service-account-authorized-p store identity "impersonate" group resource name namespace))

(defun service-account-username-parts (username)
  "Split system:serviceaccount:NS:NAME, returning its namespace and name."
  (let ((parts (uiop:split-string username :separator '(#\:))))
    (when (and (= 4 (length parts)) (equal "system" (first parts)) (equal "serviceaccount" (second parts)))
      (values (third parts) (fourth parts)))))

(defun impersonation-extra (request)
  "The extra attributes REQUEST impersonates, as an alist of key to values: one
Impersonate-Extra-<key> header for each key, the key percent-encoded."
  (loop for (name . nil) in (hunchentoot:headers-in request)
        for text = (string-downcase (string name))
        when (and (uiop:string-prefix-p "impersonate-extra-" text) (> (length text) 18))
          collect (cons (hunchentoot:url-decode (subseq text 18) hunchentoot::+utf-8+)
                        (impersonation-header-values request name))))

(defun impersonated-api-identity (store identity request)
  "Return the identity REQUEST impersonates, checking each attribute, or IDENTITY if it impersonates none."
  (let ((user (hunchentoot:header-in :impersonate-user request))
        (groups (impersonation-header-values request :impersonate-group))
        (uid (hunchentoot:header-in :impersonate-uid request))
        (extra nil))
    ;; Groups or a UID alone impersonate nobody, so the request keeps its own identity.
    (when (or (null user) (equal user ""))
      (return-from impersonated-api-identity identity))
    (setf extra (impersonation-extra request))
    (flet ((refuse (what)
             (core-resource-error 403 "Forbidden" "User ~A cannot impersonate ~A"
                                  (api-identity-username identity) what)))
      (multiple-value-bind (account-namespace account-name) (service-account-username-parts user)
        (unless (if account-namespace
                    (impersonation-allowed-p store identity "serviceaccounts" "" account-name account-namespace)
                    (impersonation-allowed-p store identity "users" "" user))
          (refuse user))
        (dolist (group groups)
          (unless (impersonation-allowed-p store identity "groups" "" group) (refuse group)))
        (when (and uid (not (impersonation-allowed-p store identity "uids" "authentication.k8s.io" uid)))
          (refuse uid))
        (loop for (key . values) in extra
              do (dolist (value values)
                   (unless (impersonation-allowed-p store identity (format nil "userextras/~A" key)
                                                    "authentication.k8s.io" value)
                     (refuse (format nil "~A=~A" key value)))))
        (let ((all (append groups
                           (when account-namespace
                             (list "system:serviceaccounts" (format nil "system:serviceaccounts:~A" account-namespace)))
                           (unless (equal user "system:anonymous") (list "system:authenticated")))))
          (make-api-user-identity :username user :uid uid
                                  :groups (coerce (remove-duplicates all :test #'equal :from-end t) 'vector)
                                  :extra (when extra
                                           (let ((table (make-hash-table :test #'equal)))
                                             (loop for (key . values) in extra
                                                   do (setf (gethash key table) (coerce values 'vector)))
                                             table))))))))
