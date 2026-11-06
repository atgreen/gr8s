;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Supply namespace-bound ServiceAccount credentials to Pods and authenticate
;;;; them against live account identities. Evaluate stored RBAC policies for the
;;;; authenticated identity before granting in-cluster API resource access.
;;;; Pods mount signed tokens bound to them (see service-account-tokens.lisp).
;;;; Opaque tokens in legacy credential Secrets still authenticate. Either way,
;;;; deleting and recreating an account invalidates its previous credentials.

(in-package #:gr8s)

(defstruct api-service-account-identity
  "Represent a ServiceAccount authenticated by a live, UID-bound credential, with what its token proves as EXTRA."
  namespace name uid extra)

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
                ;; The credential is the Pod's identity, not a user's write. It
                ;; counts as usage, but quota cannot refuse the Pod's own account.
                (let ((*resource-quota-admission-exempt* t))
                  (create-core-resource store "secrets"
                   (core-object "metadata" (core-object "name" secret-name
                                                        "annotations" (core-object "kubernetes.io/service-account.name" account-name
                                                                                   "kubernetes.io/service-account.uid" uid))
                                "type" "kubernetes.io/service-account-token" "immutable" t "data" data)
                   namespace))))
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

(defparameter +service-account-mount-path+ "/var/run/secrets/kubernetes.io/serviceaccount"
  "Where a Pod's containers find their automounted API credentials.")

(defparameter +automount-token-seconds+ 3607
  "The lifetime upstream gives automounted tokens, which the node renews before expiry.")

(defun automount-api-access-volume ()
  "Build the projected volume holding a Pod's token, the cluster CA and its namespace, as upstream admission does."
  (core-object
   "name" (format nil "kube-api-access-~A" (string-downcase (subseq (generate-uid) 0 5)))
   "projected"
   (core-object
    "defaultMode" #o644
    "sources"
    (vector (core-object "serviceAccountToken" (core-object "path" "token" "expirationSeconds" +automount-token-seconds+))
            (core-object "configMap" (core-object "name" "kube-root-ca.crt"
                                                  "items" (vector (core-object "key" "ca.crt" "path" "ca.crt"))))
            (core-object "downwardAPI"
                         (core-object "items"
                                      (vector (core-object "path" "namespace"
                                                           "fieldRef" (core-object "apiVersion" "v1"
                                                                                   "fieldPath" "metadata.namespace")))))))))

(defun admit-in-cluster-pod (store pod)
  "Run Pod policy admission, then inject service environment and credential mounts when the API is enabled."
  (require-namespace-accepts-content store (pod-namespace pod))
  (let ((pod (admit-pod-policies store pod))
        (config (pod-store-in-cluster-config store)))
    (unless config (return-from admit-in-cluster-pod pod))
    (let* ((object (copy-core-object (pod-to-object pod)))
           (spec (gethash "spec" object))
           (namespace (pod-namespace pod))
           (account-name (gethash "serviceAccountName" spec "default"))
           (account (get-core-resource store "serviceaccounts" namespace account-name))
           (mount-p (pod-automount-service-account-p spec account))
           (containers (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec)))
           ;; A container already mounting this path brought its own credentials.
           (unmounted (remove-if (lambda (container)
                                   (find +service-account-mount-path+ (gethash "volumeMounts" container #()) :test #'equal
                                         :key (lambda (mount) (gethash "mountPath" mount))))
                                 containers))
           (volume (when (and mount-p (plusp (length unmounted))) (automount-api-access-volume))))
      ;; The API server reports the deprecated serviceAccount alias alongside the name.
      (setf (gethash "serviceAccountName" spec) account-name
            (gethash "serviceAccount" spec) account-name)
      ;; A Pod naming no pull secrets uses its account's, and later edits to the account don't change it.
      (when (and (zerop (length (gethash "imagePullSecrets" spec #())))
                 (plusp (length (gethash "imagePullSecrets" account #()))))
        (setf (gethash "imagePullSecrets" spec)
              (map 'vector (lambda (reference) (core-object "name" (gethash "name" reference)))
                   (gethash "imagePullSecrets" account))))
      (when volume
        (setf (gethash "volumes" spec) (concatenate 'vector (gethash "volumes" spec #()) (vector volume))))
      (loop for container across containers
            do (dolist (pair (list (cons "KUBERNETES_SERVICE_HOST" (getf config :host))
                                  (cons "KUBERNETES_SERVICE_PORT" (write-to-string (getf config :port)))
                                  (cons "KUBERNETES_SERVICE_PORT_HTTPS" (write-to-string (getf config :port)))))
                 (unless (find (car pair) (gethash "env" container #()) :test #'equal
                               :key (lambda (entry) (gethash "name" entry)))
                   (setf (gethash "env" container)
                         (concatenate 'vector (gethash "env" container #())
                                      (vector (core-object "name" (car pair) "value" (cdr pair)))))))
               (when (and volume (find container unmounted :test #'eq))
                 (setf (gethash "volumeMounts" container)
                       (concatenate 'vector (gethash "volumeMounts" container #())
                                    (vector (core-object "name" (gethash "name" volume)
                                                         "mountPath" +service-account-mount-path+ "readOnly" t))))))
      (parse-pod object :allow-generate-name (null (pod-name pod))))))

(defun authenticate-service-account-token (store token &optional audiences)
  "Authenticate a signed token for AUDIENCES, defaulting to the API's own, or a server-issued opaque credential."
  (unless (and (stringp token) (<= 1 (length token) 4096))
    (return-from authenticate-service-account-token nil))
  (when (find #\. token)
    (return-from authenticate-service-account-token
      (verify-service-account-jwt store token (or audiences (list +service-account-issuer+)))))
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

(defparameter +discovery-url-patterns+
  '("/api" "/api/*" "/apis" "/apis/*" "/openapi" "/openapi/*" "/version" "/version/"
    "/healthz" "/livez" "/readyz")
  "The URLs upstream's system:discovery and system:public-info-viewer roles grant to every
authenticated user, which gr8s answers without stored RBAC objects.")

(defun authenticated-default-grant-p (identity verb group resource url)
  "Report what upstream's default bindings grant every authenticated user: reading the
discovery and health URLs, and creating self reviews (system:basic-user)."
  (and (find "system:authenticated" (api-identity-groups identity) :test #'equal)
       (if url
           (and (member verb '("get" "head") :test #'equal)
                (some (lambda (pattern)
                        (if (uiop:string-suffix-p pattern "*")
                            (uiop:string-prefix-p (subseq pattern 0 (1- (length pattern))) url)
                            (equal pattern url)))
                      +discovery-url-patterns+))
           (and (equal verb "create")
                (or (and (equal group "authorization.k8s.io")
                         (member resource '("selfsubjectaccessreviews" "selfsubjectrulesreviews") :test #'equal))
                    (and (equal group "authentication.k8s.io") (equal resource "selfsubjectreviews")))))
       t))

(defun service-account-authorized-p (store identity verb group resource name namespace &optional url)
  "Honor the verified system:masters group and the grants every authenticated user has, then
evaluate applicable live RoleBindings and ClusterRoleBindings."
  (when (find "system:masters" (api-identity-groups identity) :test #'equal)
    (return-from service-account-authorized-p t))
  (when (authenticated-default-grant-p identity verb group resource url)
    (return-from service-account-authorized-p t))
  (when (node-authorizer-allows-p store identity verb group resource name namespace)
    (return-from service-account-authorized-p t))

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
  "Create the namespace's default ServiceAccount without replacing an existing identity.
It passes admission as upstream's service account controller's create does."
  (handler-case
      (let ((*resource-quota-admission-exempt* t))
        (controller-create-core-resource store "serviceaccounts"
                                         (core-object "metadata" (core-object "name" "default")) namespace
                                         "service-account-controller"))
    (kubernetes-error (condition)
      (if (= 409 (kubernetes-error-status-code condition))
          (get-core-resource store "serviceaccounts" namespace "default")
          (error condition)))))

(defun ensure-system-cluster-roles (store)
  "Create the upstream bootstrap ClusterRoles clients bind to by name, keeping any existing one."
  (ensure-default-cluster-roles store)
  (ensure-default-rbac-object
   store "clusterroles"
   (core-object "metadata" (default-rbac-metadata "system:service-account-issuer-discovery")
                "rules" (vector (core-object "nonResourceURLs" #("/.well-known/openid-configuration" "/openid/v1/jwks")
                                             "verbs" #("get")))))
  (ensure-default-rbac-object
   store "clusterroles"
   (core-object "metadata" (default-rbac-metadata "system:auth-delegator")
                "rules" (vector (core-object "apiGroups" #("authentication.k8s.io") "resources" #("tokenreviews")
                                             "verbs" #("create"))
                                (core-object "apiGroups" #("authorization.k8s.io") "resources" #("subjectaccessreviews")
                                             "verbs" #("create"))))))

(defun ensure-native-bootstrap-namespaces (store)
  "Create the standard namespaces and their default accounts for a native cluster."
  (dolist (name '("default" "kube-system" "kube-public" "kube-node-lease"))
    (handler-case
        (create-core-resource store "namespaces"
         (core-object "metadata" (core-object "name" name
                                              "labels" (core-object "kubernetes.io/metadata.name" name))) nil)
      (kubernetes-error (condition)
        (unless (= 409 (kubernetes-error-status-code condition)) (error condition))))
    (ensure-default-service-account store name))
  (ensure-system-priority-classes store)
  (ensure-system-cluster-roles store)
  (ensure-extension-apiserver-rbac store))

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
           (let ((*resource-quota-admission-exempt* t))
             (controller-create-core-resource
              store "configmaps"
              (core-object "metadata" (core-object "name" "kube-root-ca.crt"
                                        "ownerReferences" (vector (core-object "apiVersion" "v1" "kind" "Namespace"
                                                                  "name" namespace "uid" (gethash "uid" (gethash "metadata" owner)))))
                           "data" (core-object "ca.crt" ca))
              namespace "root-ca-cert-publisher"))))
        ((not (equal ca (gethash "ca.crt" (or (gethash "data" existing) (core-object)))))
         (controller-update-core-resource
          store "configmaps" namespace "kube-root-ca.crt"
          (lambda (object)
            (unless (gethash "data" object) (setf (gethash "data" object) (core-object)))
            (setf (gethash "ca.crt" (gethash "data" object)) ca)
            object)
          "root-ca-cert-publisher"))))))

(defun ensure-native-namespace-root-cas (store)
  "Initialize CA ConfigMaps for persisted namespaces once the native CA is available."
  (dolist (namespace (list-core-resources store "namespaces"))
    (ensure-namespace-root-ca store (gethash "name" (gethash "metadata" namespace)))))

(defun complete-created-bootstrap-resource (store resource object dry-run)
  "Create the default account and API trust anchor after a real Namespace is admitted."
  (when (and (equal resource "namespaces") (not dry-run) (pod-store-in-cluster-config store))
    (let ((namespace (gethash "name" (gethash "metadata" object))))
      ;; Admission may refuse either for now; the Namespace stands, and the
      ;; controller pass tries again, as upstream's controllers retry.
      (dolist (ensure (list #'ensure-default-service-account #'ensure-namespace-root-ca))
        (handler-case (funcall ensure store namespace)
          (kubernetes-error (condition)
            (format *error-output* "~&Namespace ~A defaults: ~A~%" namespace (kubernetes-error-message condition)))))))
  object)

;;; Node authorization: a kubelet reads what the Pods bound to its node use, as
;;; upstream's node authorizer allows from its graph, and nothing more of those kinds.

(defun node-identity-name (identity)
  "Return the node name a system:node:<name> identity in system:nodes speaks for, or NIL."
  (let ((username (api-identity-username identity)))
    (and (uiop:string-prefix-p "system:node:" username)
         (find "system:nodes" (api-identity-groups identity) :test #'equal)
         (subseq username (length "system:node:")))))

(defun pod-references (pod-object kind)
  "List the names of the KIND objects (:secret, :configmap or :claim) POD-OBJECT's spec uses."
  (let ((spec (gethash "spec" pod-object)) (names nil))
    (labels ((add (name) (when (stringp name) (pushnew name names :test #'equal)))
             (each (value visit) (when (vectorp value) (map nil visit value)))
             (env (container)
               (each (gethash "env" container)
                     (lambda (variable)
                       (let ((from (gethash "valueFrom" variable)))
                         (when (hash-table-p from)
                           (add (table-get from (if (eq kind :secret) "secretKeyRef" "configMapKeyRef") "name"))))))
               (each (gethash "envFrom" container)
                     (lambda (source) (add (table-get source (if (eq kind :secret) "secretRef" "configMapRef") "name"))))))
      (dolist (field '("containers" "initContainers" "ephemeralContainers"))
        (unless (eq kind :claim) (each (gethash field spec) #'env)))
      (when (eq kind :secret)
        (each (gethash "imagePullSecrets" spec) (lambda (reference) (add (gethash "name" reference)))))
      (each (gethash "volumes" spec)
            (lambda (volume)
              (ecase kind
                (:secret (add (table-get volume "secret" "secretName")))
                (:configmap (add (table-get volume "configMap" "name")))
                (:claim (add (table-get volume "persistentVolumeClaim" "claimName"))
                 (when (hash-table-p (gethash "ephemeral" volume))
                   (add (format nil "~A-~A" (table-get pod-object "metadata" "name") (gethash "name" volume))))))
              (unless (eq kind :claim)
                (each (table-get volume "projected" "sources")
                      (lambda (source)
                        (add (table-get source (if (eq kind :secret) "secret" "configMap") "name"))))))))
    names))

(defun node-authorizer-allows-p (store identity verb group resource name namespace)
  "Allow a node to get a Secret, ConfigMap or PersistentVolumeClaim a Pod bound to it uses."
  (let ((node (node-identity-name identity))
        (kind (and (equal group "") (cdr (assoc resource '(("secrets" . :secret) ("configmaps" . :configmap)
                                                            ("persistentvolumeclaims" . :claim))
                                                :test #'equal)))))
    (and node kind name namespace (equal verb "get")
         (some (lambda (pod)
                 (let ((object (pod-to-object pod)))
                   (and (equal node (table-get object "spec" "nodeName"))
                        (member name (pod-references object kind) :test #'equal))))
               (list-pods store namespace))
         t)))
