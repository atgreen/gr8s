;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Supply namespace-bound ServiceAccount credentials to Pods and authenticate
;;;; them against live account identities. Evaluate stored RBAC policies for the
;;;; authenticated identity before granting in-cluster API resource access.
;;;; Credentials are opaque random bearer tokens; deleting/recreating an account
;;;; invalidates its previous credentials through the account UID binding.

(in-package #:gr8s)

(defstruct api-service-account-identity
  "Represent a ServiceAccount authenticated by a live, UID-bound credential."
  namespace name uid)

(defun service-account-token-secret-name (name uid)
  "Return a stable Secret name bound to the account NAME and UID."
  (format nil "~A-token-~A" (subseq name 0 (min 220 (length name)))
          (string-downcase (subseq uid 0 8))))

(defun service-account-token-digest (token)
  "Hash a bearer token for private issuer records and constant-time comparisons."
  (ironclad:digest-sequence :sha256 (trivial-utf-8:string-to-utf-8-bytes token)))

(defun service-account-issuer-record-path (store digest)
  "Return the private issuance record path derived from a token DIGEST."
  (merge-pathnames (format nil "credentials/service-accounts/~A.json" (octets-to-hex digest))
                   (pod-store-path store)))

(defun read-service-account-issuer-record (store digest)
  "Read a server-owned issuance record, never a client-writable Secret claim."
  (let ((path (service-account-issuer-record-path store digest)))
    (when (probe-file path) (com.inuoe.jzon:parse path))))

(defun ensure-service-account-credential (store namespace account-name)
  "Return a server-issued credential Secret bound to the live account and Secret UIDs."
  (bt:with-lock-held ((pod-store-credential-lock store))
    (let* ((account (get-core-resource store "serviceaccounts" namespace account-name))
           (uid (gethash "uid" (gethash "metadata" account)))
           (secret-name (service-account-token-secret-name account-name uid))
           (existing (handler-case (get-core-resource store "secrets" namespace secret-name)
                       (kubernetes-error (condition)
                         (unless (= 404 (kubernetes-error-status-code condition)) (error condition))))))
      (when existing
        (let* ((data (gethash "data" existing))
               (token (and data (gethash "token" data)))
               (digest (and token (ironclad:digest-sequence :sha256 (core-base64-bytes token "token"))))
               (record (and digest (read-service-account-issuer-record store digest))))
          (unless (and record (equal namespace (gethash "namespace" record))
                       (equal account-name (gethash "name" record)) (equal uid (gethash "uid" record))
                       (equal (gethash "uid" (gethash "metadata" existing)) (gethash "secretUID" record)))
            (core-resource-error 409 "Conflict" "Existing ServiceAccount credential was not issued for this identity")))
        (return-from ensure-service-account-credential existing))
      (let* ((config (pod-store-in-cluster-config store))
             (token (octets-to-hex (secure-random-octets 32))) (data (core-object)))
        (unless config (error "in-cluster API configuration is unavailable"))
        (loop for (key . value) in (list (cons "token" token) (cons "namespace" namespace)
                                         (cons "ca.crt" (getf config :ca-pem)))
              do (setf (gethash key data) (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes value))))
        (let ((secret
                (create-core-resource store "secrets"
                 (core-object "metadata" (core-object "name" secret-name
                                                      "annotations" (core-object "kubernetes.io/service-account.name" account-name
                                                                                 "kubernetes.io/service-account.uid" uid))
                              "type" "kubernetes.io/service-account-token" "immutable" t "data" data)
                 namespace)))
          (handler-case
              (write-private-text-atomically
               (service-account-issuer-record-path store (service-account-token-digest token))
               (com.inuoe.jzon:stringify
                (core-object "namespace" namespace "name" account-name "uid" uid
                             "secretName" secret-name "secretUID" (gethash "uid" (gethash "metadata" secret)))))
            (error (condition)
              (ignore-errors
                (delete-core-resource store "secrets" namespace secret-name
                                      :uid (gethash "uid" (gethash "metadata" secret))))
              (error condition)))
          secret)))))

(defun pod-automount-service-account-p (spec account)
  "Resolve Pod and account automount settings, preserving explicit false values."
  (multiple-value-bind (value present) (gethash "automountServiceAccountToken" spec)
    (if present value
        (multiple-value-bind (value present) (gethash "automountServiceAccountToken" account)
          (if present value t)))))

(defun admit-in-cluster-pod (store pod)
  "Inject service environment and authorized credential mounts when the API is enabled."
  (let ((config (pod-store-in-cluster-config store)))
    (unless config (return-from admit-in-cluster-pod pod))
    (let* ((object (copy-core-object (pod-to-object pod)))
           (spec (gethash "spec" object))
           (namespace (pod-namespace pod))
           (account-name (gethash "serviceAccountName" spec "default"))
           (account (get-core-resource store "serviceaccounts" namespace account-name))
           (mount-p (pod-automount-service-account-p spec account))
           (secret (when mount-p (ensure-service-account-credential store namespace account-name)))
           (secret-name (when secret (gethash "name" (gethash "metadata" secret))))
           (volume-name "gr8s-api-access")
           (mount-path "/var/run/secrets/kubernetes.io/serviceaccount"))
      (setf (gethash "serviceAccountName" spec) account-name)
      (when mount-p
        (let ((existing (find volume-name (gethash "volumes" spec #()) :test #'equal
                              :key (lambda (volume) (gethash "name" volume)))))
          (if existing
              (unless (equal secret-name (gethash "secretName" (gethash "secret" existing (core-object))))
                (invalid-pod "gr8s-api-access volume name is reserved for account credentials"))
              (setf (gethash "volumes" spec)
                    (concatenate 'vector (gethash "volumes" spec #())
                                 (vector (core-object "name" volume-name
                                                      "secret" (core-object "secretName" secret-name "defaultMode" #o644))))))))
      (loop for container across (gethash "containers" spec)
            do (dolist (pair (list (cons "KUBERNETES_SERVICE_HOST" (getf config :host))
                                  (cons "KUBERNETES_SERVICE_PORT" (write-to-string (getf config :port)))
                                  (cons "KUBERNETES_SERVICE_PORT_HTTPS" (write-to-string (getf config :port)))))
                 (unless (find (car pair) (gethash "env" container #()) :test #'equal
                               :key (lambda (entry) (gethash "name" entry)))
                   (setf (gethash "env" container)
                         (concatenate 'vector (gethash "env" container #())
                                      (vector (core-object "name" (car pair) "value" (cdr pair)))))))
               (when (and mount-p
                          (not (find mount-path (gethash "volumeMounts" container #()) :test #'equal
                                     :key (lambda (mount) (gethash "mountPath" mount)))))
                 (setf (gethash "volumeMounts" container)
                       (concatenate 'vector (gethash "volumeMounts" container #())
                                    (vector (core-object "name" volume-name "mountPath" mount-path "readOnly" t))))))
      (parse-pod object :allow-generate-name (null (pod-name pod))))))

(defun authenticate-service-account-token (store token)
  "Authenticate only server-issued tokens against live account and credential UIDs."
  (unless (and (stringp token) (<= 1 (length token) 4096))
    (return-from authenticate-service-account-token nil))
  (let* ((digest (service-account-token-digest token))
         (record (read-service-account-issuer-record store digest)))
    (when record
      (let* ((namespace (gethash "namespace" record)) (name (gethash "name" record))
             (account (handler-case (get-core-resource store "serviceaccounts" namespace name)
                        (kubernetes-error () nil)))
             (secret (handler-case (get-core-resource store "secrets" namespace (gethash "secretName" record))
                       (kubernetes-error () nil))))
        (when (and account secret
                   (equal (gethash "uid" record) (gethash "uid" (gethash "metadata" account)))
                   (equal (gethash "secretUID" record) (gethash "uid" (gethash "metadata" secret)))
                   (gethash "data" secret) (gethash "token" (gethash "data" secret))
                   (ironclad:constant-time-equal digest
                    (ironclad:digest-sequence :sha256 (core-base64-bytes (gethash "token" (gethash "data" secret)) "token"))))
          (make-api-service-account-identity :namespace namespace :name name :uid (gethash "uid" record)))))))

(defun rbac-subject-matches-account-p (subject binding-namespace identity)
  "Match live ServiceAccount or verified certificate identities using standard User and Group subjects."
  (let ((username (api-identity-username identity)))
    (cond
      ((equal "ServiceAccount" (gethash "kind" subject))
       (equal username (format nil "system:serviceaccount:~A:~A"
                               (gethash "namespace" subject binding-namespace) (gethash "name" subject))))
      ((equal "User" (gethash "kind" subject)) (equal (gethash "name" subject) username))
      ((equal "Group" (gethash "kind" subject))
       (find (gethash "name" subject) (api-identity-groups identity) :test #'equal)))))

(defun rbac-rule-allows-p (rule verb group resource name url)
  "Evaluate one RBAC policy rule for a resource or nonresource request."
  (and (or (find "*" (gethash "verbs" rule) :test #'equal)
           (find verb (gethash "verbs" rule) :test #'equal))
       (if resource
           (and (or (find "*" (gethash "apiGroups" rule) :test #'equal)
                    (find group (gethash "apiGroups" rule) :test #'equal))
                (some (lambda (pattern)
                        (or (equal pattern "*") (equal pattern resource)
                            (and (uiop:string-prefix-p "*/" pattern)
                                 (uiop:string-suffix-p resource (subseq pattern 1)))))
                      (gethash "resources" rule))
                (or (null (gethash "resourceNames" rule))
                    (zerop (length (gethash "resourceNames" rule)))
                    (and name (find name (gethash "resourceNames" rule) :test #'equal))))
           (some (lambda (pattern)
                   (or (equal pattern url)
                       (and (uiop:string-suffix-p pattern "*")
                            (uiop:string-prefix-p (subseq pattern 0 (1- (length pattern))) url))))
                 (gethash "nonResourceURLs" rule)))))

(defun service-account-authorized-p (store identity verb group resource name namespace &optional url)
  "Evaluate applicable live RoleBindings and ClusterRoleBindings for IDENTITY."
  (let ((bindings (append (list-core-resources store "clusterrolebindings")
                          (when namespace (list-core-resources store "rolebindings" namespace)))))
    (some
     (lambda (binding)
       (let* ((binding-namespace (gethash "namespace" (gethash "metadata" binding)))
              (reference (gethash "roleRef" binding)))
         (and (some (lambda (subject) (rbac-subject-matches-account-p subject binding-namespace identity))
                    (gethash "subjects" binding))
              (let ((role (handler-case
                              (get-core-resource store
                               (if (equal "ClusterRole" (gethash "kind" reference)) "clusterroles" "roles")
                               (unless (equal "ClusterRole" (gethash "kind" reference)) binding-namespace)
                               (gethash "name" reference))
                            (kubernetes-error () nil))))
                (and role (some (lambda (rule) (rbac-rule-allows-p rule verb group resource name url))
                                (gethash "rules" role)))))))
     bindings)))

(defun ensure-default-service-account (store namespace)
  "Create the namespace's default ServiceAccount without replacing an existing identity."
  (handler-case
      (create-core-resource store "serviceaccounts"
       (core-object "metadata" (core-object "name" "default")) namespace)
    (kubernetes-error (condition)
      (if (= 409 (kubernetes-error-status-code condition))
          (get-core-resource store "serviceaccounts" namespace "default")
          (error condition)))))

(defun ensure-native-bootstrap-namespaces (store)
  "Create the standard namespaces and their default accounts for a native cluster."
  (dolist (name '("default" "kube-system" "kube-public" "kube-node-lease"))
    (handler-case
        (create-core-resource store "namespaces"
         (core-object "metadata" (core-object "name" name
                                              "labels" (core-object "kubernetes.io/metadata.name" name))) nil)
      (kubernetes-error (condition)
        (unless (= 409 (kubernetes-error-status-code condition)) (error condition))))
    (ensure-default-service-account store name)))

(defun ensure-namespace-root-ca (store namespace)
  "Publish the actual native API trust anchor without rotating the ConfigMap identity."
  (let* ((ca (getf (pod-store-in-cluster-config store) :ca-pem))
         (existing (handler-case (get-core-resource store "configmaps" namespace "kube-root-ca.crt")
                     (kubernetes-error (condition)
                       (unless (= 404 (kubernetes-error-status-code condition)) (error condition))))))
    (when ca
      (cond
        ((null existing)
         (let ((owner (get-core-resource store "namespaces" nil namespace)))
           (create-core-resource store "configmaps"
            (core-object "metadata" (core-object "name" "kube-root-ca.crt"
                                      "ownerReferences" (vector (core-object "apiVersion" "v1" "kind" "Namespace"
                                                                "name" namespace "uid" (gethash "uid" (gethash "metadata" owner)))))
                         "data" (core-object "ca.crt" ca)) namespace)))
        ((not (equal ca (gethash "ca.crt" (or (gethash "data" existing) (core-object)))))
         (update-core-resource store "configmaps" namespace "kube-root-ca.crt"
          (lambda (object)
            (unless (gethash "data" object) (setf (gethash "data" object) (core-object)))
            (setf (gethash "ca.crt" (gethash "data" object)) ca)
            object)))))))

(defun ensure-native-namespace-root-cas (store)
  "Initialize CA ConfigMaps for persisted namespaces once the native CA is available."
  (dolist (namespace (list-core-resources store "namespaces"))
    (ensure-namespace-root-ca store (gethash "name" (gethash "metadata" namespace)))))

(defun complete-created-bootstrap-resource (store resource object dry-run)
  "Create the default account and API trust anchor after a real Namespace is admitted."
  (when (and (equal resource "namespaces") (not dry-run) (pod-store-in-cluster-config store))
    (let ((namespace (gethash "name" (gethash "metadata" object))))
      (ensure-default-service-account store namespace)
      (ensure-namespace-root-ca store namespace)))
  object)
