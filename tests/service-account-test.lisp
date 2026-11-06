;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise issuance provenance, account and Secret UID revocation, durable
;;;; authentication, namespace-scoped RBAC and opt-out credential projection.

(in-package #:gr8s/tests)
(def-suite service-accounts :in gr8s)
(in-suite service-accounts)

(defun service-account-test-store (store &optional (name "reader") (namespace "alpha"))
  "Enable a test API configuration and create an account."
  (setf (gr8s::pod-store-in-cluster-config store) (list :host "10.96.0.1" :port 443 :ca-pem "test-ca"))
  (gr8s::create-core-resource store "serviceaccounts"
    (gr8s::core-object "metadata" (gr8s::core-object "name" name)) namespace))

(defun service-account-test-token (secret)
  "Decode the actual credential token from its Secret data."
  (trivial-utf-8:utf-8-bytes-to-string
   (gr8s::core-base64-bytes (gethash "token" (gethash "data" secret)) "token")))

(test native-namespace-creation-publishes-and-restores-the-real-root-ca
  (with-temporary-store (store directory)
    (setf (gr8s::pod-store-in-cluster-config store) (list :ca-pem "the-cluster-ca"))
    (let ((namespace (gr8s::create-core-resource store "namespaces"
                       (gr8s::core-object "metadata" (gr8s::core-object "name" "e2e-test")) nil)))
      (gr8s::complete-created-bootstrap-resource store "namespaces" namespace nil)
      (let* ((original (gr8s::get-core-resource store "configmaps" "e2e-test" "kube-root-ca.crt"))
             (uid (gethash "uid" (gethash "metadata" original))))
        (is (equal "the-cluster-ca" (gethash "ca.crt" (gethash "data" original))))
        (is (equal (gethash "uid" (gethash "metadata" namespace))
                   (gethash "uid" (aref (gethash "ownerReferences" (gethash "metadata" original)) 0))))
        (gr8s::update-core-resource store "configmaps" "e2e-test" "kube-root-ca.crt"
         (lambda (object) (setf (gethash "data" object) (gr8s::core-object "other" "preserved")) object))
        (gr8s::ensure-native-namespace-root-cas store)
        (let ((restored (gr8s::get-core-resource store "configmaps" "e2e-test" "kube-root-ca.crt")))
          (is (equal uid (gethash "uid" (gethash "metadata" restored))))
          (is (equal "the-cluster-ca" (gethash "ca.crt" (gethash "data" restored))))
          (is (equal "preserved" (gethash "other" (gethash "data" restored))))
          (gr8s::ensure-native-namespace-root-cas store)
          (is (equalp restored (gr8s::get-core-resource store "configmaps" "e2e-test" "kube-root-ca.crt")))
          (is (equalp restored (gr8s::get-core-resource (open-store directory) "configmaps" "e2e-test" "kube-root-ca.crt")))))
      (let ((preview (gr8s::create-core-resource store "namespaces"
                       (gr8s::core-object "metadata" (gr8s::core-object "name" "preview")) nil :dry-run t)))
        (gr8s::complete-created-bootstrap-resource store "namespaces" preview t)
        (is (null (gr8s::list-core-resources store "configmaps" "preview")))))))

(test credentials-require-private-issuance-and-live-account-identities
  (with-temporary-store (store directory)
    (service-account-test-store store)
    (let* ((secret (gr8s::ensure-service-account-credential store "alpha" "reader"))
           (token (service-account-test-token secret))
           (identity (gr8s::authenticate-service-account-token store token)))
      (is (equal "alpha" (gr8s::api-service-account-identity-namespace identity)))
      (is (equal "reader" (gr8s::api-service-account-identity-name identity)))
      (is (null (gr8s::authenticate-service-account-token store "forged")))
      (is (equalp secret (gr8s::ensure-service-account-credential store "alpha" "reader")))
      (is (not (null (gr8s::authenticate-service-account-token (open-store directory) token))))
      (let* ((path (gr8s::service-account-issuer-record-path store (gr8s::service-account-token-digest token)))
             (mode (sb-posix:stat-mode (sb-posix:stat (namestring path)))))
        (is (= #o600 (logand mode #o777))))
      (gr8s::delete-core-resource store "serviceaccounts" "alpha" "reader")
      (service-account-test-store store)
      (is (null (gr8s::authenticate-service-account-token store token)))
      (let ((new-secret (gr8s::ensure-service-account-credential store "alpha" "reader")))
        (is (not (equal token (service-account-test-token new-secret)))))
      (let ((forged (gr8s::copy-core-object secret)))
        (setf (gethash "name" (gethash "metadata" forged)) "forged-token")
        (remhash "resourceVersion" (gethash "metadata" forged))
        (setf (gethash "token" (gethash "data" forged)) (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes "chosen-token")))
        (gr8s::create-core-resource store "secrets" forged "alpha")
        (is (null (gr8s::authenticate-service-account-token store "chosen-token")))))))

(test deleting-and-recreating-the-secret-revokes-its-token
  (with-temporary-store (store directory)
    (values directory)
    (service-account-test-store store)
    (let* ((secret (gr8s::ensure-service-account-credential store "alpha" "reader"))
           (token (service-account-test-token secret))
           (name (gethash "name" (gethash "metadata" secret))))
      (gr8s::delete-core-resource store "secrets" "alpha" name)
      (is (null (gr8s::authenticate-service-account-token store token)))
      (remhash "resourceVersion" (gethash "metadata" secret))
      (gr8s::create-core-resource store "secrets" secret "alpha")
      (is (null (gr8s::authenticate-service-account-token store token)))
      (signals kubernetes-error (gr8s::ensure-service-account-credential store "alpha" "reader")))))

(test field-selector-name-authorizes-list-watch-against-resourcenames
  ;; A rule with resourceNames grants list/watch when the request pins the object
  ;; by metadata.name (KEP-4601) -- Agent Substrate's controller watches a single
  ;; Secret this way. Without the name the resourceNames rule must not match.
  (is (string= "egress-mitm-ca-pool"
               (gr8s::field-selector-exact-name "metadata.name=egress-mitm-ca-pool")))
  (is (string= "x" (gr8s::field-selector-exact-name "status.phase=Running,metadata.name==x")))
  (is (null (gr8s::field-selector-exact-name "metadata.name!=x")))
  (is (null (gr8s::field-selector-exact-name "status.phase=Running")))
  (let ((rule (gr8s::core-object "apiGroups" #("") "resources" #("secrets")
                                 "verbs" #("get" "list" "watch") "resourceNames" #("egress-mitm-ca-pool"))))
    (is (not (null (gr8s::rbac-rule-allows-p rule "watch" "" "secrets" "egress-mitm-ca-pool" nil))))
    (is (not (gr8s::rbac-rule-allows-p rule "watch" "" "secrets" nil nil)))          ; no name -> denied
    (is (not (gr8s::rbac-rule-allows-p rule "watch" "" "secrets" "other" nil)))))    ; wrong name -> denied

(test service-account-rbac-grants-only-bound-resources-and-namespaces
  (with-temporary-store (store directory)
    (values directory)
    (service-account-test-store store)
    (let* ((secret (gr8s::ensure-service-account-credential store "alpha" "reader"))
           (identity (gr8s::authenticate-service-account-token store (service-account-test-token secret))))
      (is (not (gr8s::service-account-authorized-p store identity "get" "" "pods" "hello" "alpha")))
      (gr8s::create-core-resource store "roles"
        (gr8s::core-object "metadata" (gr8s::core-object "name" "read-pods")
                           "rules" (vector (gr8s::core-object "apiGroups" #("") "resources" #("pods") "verbs" #("get" "list")))) "alpha")
      (gr8s::create-core-resource store "rolebindings"
        (gr8s::core-object "metadata" (gr8s::core-object "name" "read-pods")
                           "roleRef" (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" "read-pods")
                           "subjects" (vector (gr8s::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha"))) "alpha")
      (is (not (null (gr8s::service-account-authorized-p store identity "get" "" "pods" "hello" "alpha"))))
      (is (not (gr8s::service-account-authorized-p store identity "delete" "" "pods" "hello" "alpha")))
      (is (not (gr8s::service-account-authorized-p store identity "get" "" "pods" "hello" "beta")))
      (is (not (gr8s::service-account-authorized-p store identity "get" "" "secrets" "hello" "alpha")))
      (gr8s::delete-core-resource store "rolebindings" "alpha" "read-pods")
      (is (not (gr8s::service-account-authorized-p store identity "get" "" "pods" "hello" "alpha"))))))

(test admission-projects-real-credentials-and-preserves-automount-opt-out
  (with-temporary-store (store directory)
    (values directory)
    (service-account-test-store store "default" "default")
    (let* ((pod (gr8s::admit-in-cluster-pod store (parse-pod *valid-pod-json*)))
           (spec (gethash "spec" (pod-to-object pod)))
           (container (aref (gethash "containers" spec) 0)))
      (is (equal "default" (gethash "serviceAccountName" spec)))
      (is (= 1 (length (gethash "volumes" spec))))
      (is (= 1 (length (gethash "volumeMounts" container))))
      (is (uiop:string-prefix-p "kube-api-access-" (gethash "name" (aref (gethash "volumes" spec) 0))))
      (is (equal gr8s::+service-account-mount-path+ (gethash "mountPath" (aref (gethash "volumeMounts" container) 0))))
      ;; The node receives the root CA and the minted token, and nothing else.
      (gr8s::create-core-resource store "namespaces" (gr8s::core-object "metadata" (gr8s::core-object "name" "default")) nil)
      (gr8s::ensure-namespace-root-ca store "default")
      (is (= 2 (length (gr8s::pod-referenced-resource-objects store pod))))
      (let ((host (find "KUBERNETES_SERVICE_HOST" (gethash "env" container) :test #'equal
                        :key (lambda (entry) (gethash "name" entry)))))
        (is (equal "10.96.0.1" (gethash "value" host))))
      (is (equalp (pod-to-object pod) (pod-to-object (gr8s::admit-in-cluster-pod store pod)))))
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*)) (spec (gethash "spec" object)))
      (setf (gethash "automountServiceAccountToken" spec) nil)
      (let ((admitted (gr8s::admit-in-cluster-pod store (parse-pod object))))
        (is (null (gethash "volumes" (gethash "spec" (pod-to-object admitted)))))))))

(defun service-account-tls-status (pki path &optional token)
  "Read an HTTP response status over verified TLS using the test cluster CA."
  (sb-sys:with-deadline (:seconds 10)
    (let* ((socket (usocket:socket-connect "127.0.0.1" 18091 :element-type '(unsigned-byte 8)))
           (tls nil))
      (unwind-protect
           (progn
             (setf tls (pure-tls:make-tls-client-stream
                        (usocket:socket-stream socket) :hostname "kubernetes.default.svc"
                        :context (pure-tls:make-tls-context :verify-mode pure-tls:+verify-required+
                                   :ca-file (namestring (gr8s:cluster-pki-ca-certificate-path pki))
                                   :auto-load-system-ca nil)))
             (write-sequence
              (trivial-utf-8:string-to-utf-8-bytes
               (with-output-to-string (out)
                 (format out "GET ~A HTTP/1.1~C~CHost: kubernetes.default.svc~C~CConnection: close~C~C"
                         path #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed)
                 (when token (format out "Authorization: Bearer ~A~C~C" token #\Return #\Linefeed))
                 (format out "~C~C" #\Return #\Linefeed))) tls)
             (finish-output tls)
             (let ((line (with-output-to-string (out)
                           (loop for octet = (read-byte tls nil nil)
                                 while (and octet (/= octet 10))
                                 unless (= octet 13) do (write-char (code-char octet) out)))))
               (parse-integer line :start 9 :end 12)))
        (when tls (ignore-errors (close tls)))
        (ignore-errors (usocket:socket-close socket))))))

(test tls-api-requires-credentials-and-live-rbac-grants
  (with-temporary-store (store directory)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (server nil))
      (service-account-test-store store)
      (unwind-protect
           (progn
             (setf server (gr8s::start-in-cluster-api store runtime reconciler pki :address "127.0.0.1" :port 18091))
             (let* ((secret (gr8s::ensure-service-account-credential store "alpha" "reader"))
                    (token (service-account-test-token secret)))
               (is (= 401 (service-account-tls-status pki "/version")))
               (is (= 401 (service-account-tls-status pki "/version" "forged")))
               (is (= 200 (service-account-tls-status pki "/version" token)))
               (is (= 403 (service-account-tls-status pki "/api/v1/pods" token)))
               (gr8s::create-core-resource store "clusterroles"
                (gr8s::core-object "apiVersion" "rbac.authorization.k8s.io/v1"
                                   "metadata" (gr8s::core-object "name" "all-pods")
                                   "rules" (vector (gr8s::core-object "apiGroups" #("") "resources" #("pods") "verbs" #("get" "list")))) nil)
               (gr8s::create-core-resource store "clusterrolebindings"
                (gr8s::core-object "apiVersion" "rbac.authorization.k8s.io/v1"
                                   "metadata" (gr8s::core-object "name" "all-pods")
                                   "roleRef" (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" "all-pods")
                                   "subjects" (vector (gr8s::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha"))) nil)
               (is (= 200 (service-account-tls-status pki "/api/v1/pods" token)))
               (gr8s::delete-core-resource store "serviceaccounts" "alpha" "reader")
               (is (= 401 (service-account-tls-status pki "/api/v1/pods" token)))))
        (when server (stop-server server))))))

(test default-cluster-roles-exist-and-grant-nothing-until-bound
  (with-temporary-store (store directory)
    (values directory)
    (service-account-test-store store)
    (let* ((secret (gr8s::ensure-service-account-credential store "alpha" "reader"))
           (account (gr8s::authenticate-service-account-token store (service-account-test-token secret)))
           (user (gr8s::make-api-user-identity :username "someone" :groups #("system:authenticated")))
           (master (gr8s::make-api-user-identity :username "root" :groups #("system:masters" "system:authenticated"))))
      (flet ((allowed (identity verb group resource &optional namespace)
               (not (null (gr8s::service-account-authorized-p store identity verb group resource nil namespace))))
             (ensure () (gr8s::ensure-system-cluster-roles store)))
        (ensure)
        ;; Run twice: a restart must not fail or duplicate them.
        (ensure)
        (dolist (name '("cluster-admin" "admin" "edit" "view"))
          (is (gr8s::get-core-resource store "clusterroles" nil name))
          (is (equal "rbac-defaults" (gethash "kubernetes.io/bootstrapping"
                                              (gethash "labels" (gethash "metadata" (gr8s::get-core-resource store "clusterroles" nil name)))))))
        (let ((binding (gr8s::get-core-resource store "clusterrolebindings" nil "cluster-admin")))
          (is (equalp "system:masters" (gethash "name" (aref (gethash "subjects" binding) 0)))))
        ;; No existing identity gained anything.
        (dolist (identity (list account user))
          (dolist (request '(("get" "" "pods" "alpha") ("list" "" "secrets" "alpha") ("list" "" "nodes" nil)
                             ("get" "rbac.authorization.k8s.io" "clusterroles" nil) ("create" "apps" "deployments" "alpha")))
            (is (not (allowed identity (first request) (second request) (third request) (fourth request)))
                "~A was allowed ~A" (gr8s::api-identity-username identity) request)))
        (is (allowed master "delete" "" "nodes"))
        ;; An upstream-shaped RoleBinding gives each role upstream's reach, in that namespace only.
        (flet ((bind (role)
                 (gr8s::create-core-resource store "rolebindings"
                   (gr8s::core-object "metadata" (gr8s::core-object "name" (format nil "bind-~A" role))
                                      "roleRef" (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" role)
                                      "subjects" (vector (gr8s::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha")))
                   "alpha"))
               (unbind (role) (gr8s::delete-core-resource store "rolebindings" "alpha" (format nil "bind-~A" role))))
          (bind "view")
          (is (allowed account "list" "" "pods" "alpha"))
          (is (allowed account "get" "" "pods/log" "alpha"))
          (is (allowed account "get" "apps" "deployments" "alpha"))
          (is (not (allowed account "list" "" "pods" "beta")))
          (is (not (allowed account "get" "" "secrets" "alpha")))
          (is (not (allowed account "delete" "" "pods" "alpha")))
          (unbind "view")
          (bind "edit")
          (is (allowed account "get" "" "secrets" "alpha"))
          (is (allowed account "delete" "" "pods" "alpha"))
          (is (allowed account "create" "" "pods/exec" "alpha"))
          (is (not (allowed account "create" "rbac.authorization.k8s.io" "rolebindings" "alpha")))
          (unbind "edit")
          (bind "admin")
          (is (allowed account "create" "rbac.authorization.k8s.io" "rolebindings" "alpha"))
          (is (allowed account "get" "" "secrets" "alpha"))
          (is (not (allowed account "list" "" "nodes" nil)))
          (unbind "admin")
          (is (not (allowed account "list" "" "pods" "alpha"))))))))

(test default-cluster-roles-keep-an-existing-role
  (with-temporary-store (store directory)
    (values directory)
    (gr8s::create-core-resource store "clusterroles"
      (gr8s::core-object "metadata" (gr8s::core-object "name" "view")
                         "rules" (vector (gr8s::core-object "apiGroups" #("") "resources" #("pods") "verbs" #("get")))) nil)
    (gr8s::ensure-system-cluster-roles store)
    (is (= 1 (length (gethash "rules" (gr8s::get-core-resource store "clusterroles" nil "view")))))
    (is (< 1 (length (gethash "rules" (gr8s::get-core-resource store "clusterroles" nil "edit")))))))

(test cluster-roles-aggregate-labelled-roles
  (with-temporary-store (store directory)
    (values directory)
    (gr8s::ensure-system-cluster-roles store)
    (flet ((rules (name) (gethash "rules" (gr8s::get-core-resource store "clusterroles" nil name)))
           (grants-p (name resource)
             (some (lambda (rule) (find resource (gethash "resources" rule) :test #'equal))
                   (gethash "rules" (gr8s::get-core-resource store "clusterroles" nil name)))))
      ;; admin, edit and view aggregate upstream's system:aggregate-to-* roles.
      (is (gethash "aggregationRule" (gr8s::get-core-resource store "clusterroles" nil "edit")))
      (is (grants-p "view" "pods"))
      (is (grants-p "edit" "secrets"))
      (is (grants-p "admin" "rolebindings"))
      (is (not (grants-p "edit" "rolebindings")))
      (is (not (grants-p "view" "secrets")))
      ;; A chart's role labelled for edit adds its rules to edit and admin, not view.
      (gr8s::create-core-resource store "clusterroles"
        (gr8s::core-object "metadata" (gr8s::core-object "name" "widgets-edit"
                                                         "labels" (gr8s::core-object "rbac.authorization.k8s.io/aggregate-to-edit" "true"
                                                                                     "rbac.authorization.k8s.io/aggregate-to-admin" "true"))
                           "rules" (vector (gr8s::core-object "apiGroups" #("example.test") "resources" #("widgets") "verbs" #("get"))))
        nil)
      (gr8s::reconcile-cluster-role-aggregation store)
      (is (grants-p "edit" "widgets"))
      (is (grants-p "admin" "widgets"))
      (is (not (grants-p "view" "widgets")))
      ;; A rule the sources share appears once, and the pass is idempotent.
      (let ((before (length (rules "admin"))))
        (gr8s::reconcile-cluster-role-aggregation store)
        (is (= before (length (rules "admin")))))
      ;; Removing the source takes its rules away again.
      (gr8s::delete-core-resource store "clusterroles" nil "widgets-edit")
      (gr8s::reconcile-cluster-role-aggregation store)
      (is (not (grants-p "edit" "widgets")))
      ;; Rules written by hand are replaced by what the selectors gather.
      (gr8s::create-core-resource store "clusterroles"
        (gr8s::core-object "metadata" (gr8s::core-object "name" "mine")
                           "aggregationRule" (gr8s::core-object "clusterRoleSelectors"
                                                                (vector (gr8s::core-object "matchLabels" (gr8s::core-object "team" "a"))))
                           "rules" (vector (gr8s::core-object "apiGroups" #("") "resources" #("nodes") "verbs" #("get"))))
        nil)
      (gr8s::reconcile-cluster-role-aggregation store)
      (is (zerop (length (rules "mine"))))
      ;; An aggregationRule needs at least one valid selector.
      (signals gr8s::kubernetes-error
        (gr8s::create-core-resource store "clusterroles"
          (gr8s::core-object "metadata" (gr8s::core-object "name" "empty")
                             "aggregationRule" (gr8s::core-object "clusterRoleSelectors" #()))
          nil))
      (signals gr8s::kubernetes-error
        (gr8s::create-core-resource store "clusterroles"
          (gr8s::core-object "metadata" (gr8s::core-object "name" "bad")
                             "aggregationRule" (gr8s::core-object "clusterRoleSelectors"
                                                                  (vector (gr8s::core-object "matchExpressions"
                                                                                             (vector (gr8s::core-object "key" "a" "operator" "Bogus"))))))
          nil)))))

(test nodes-read-only-what-their-pods-use
  (with-temporary-store (store directory)
    (values directory)
    (let ((node (gr8s::make-api-user-identity :username "system:node:n1" :groups #("system:nodes" "system:authenticated")))
          (other (gr8s::make-api-user-identity :username "system:node:n2" :groups #("system:nodes" "system:authenticated")))
          (impostor (gr8s::make-api-user-identity :username "system:node:n1" :groups #("system:authenticated"))))
      (create-pod store (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"user\",\"namespace\":\"alpha\"},
        \"spec\":{\"nodeName\":\"n1\",\"imagePullSecrets\":[{\"name\":\"pull\"}],
          \"containers\":[{\"name\":\"web\",\"image\":\"busybox:1.36.1\",
            \"env\":[{\"name\":\"A\",\"valueFrom\":{\"configMapKeyRef\":{\"name\":\"settings\",\"key\":\"a\"}}}],
            \"envFrom\":[{\"secretRef\":{\"name\":\"env-secret\"}}]}],
          \"volumes\":[{\"name\":\"s\",\"secret\":{\"secretName\":\"mounted\"}},
                       {\"name\":\"d\",\"persistentVolumeClaim\":{\"claimName\":\"data\"}},
                       {\"name\":\"p\",\"projected\":{\"sources\":[{\"configMap\":{\"name\":\"projected\"}}]}}]}}"))
      (flet ((allowed (identity resource name &optional (verb "get") (namespace "alpha"))
               (gr8s::node-authorizer-allows-p store identity verb "" resource name namespace)))
        (dolist (name '("pull" "env-secret" "mounted"))
          (is-true (allowed node "secrets" name) "~A" name))
        (dolist (name '("settings" "projected"))
          (is-true (allowed node "configmaps" name) "~A" name))
        (is-true (allowed node "persistentvolumeclaims" "data"))
        ;; Nothing the Pod doesn't use, nothing for another node or a pretender, and only get.
        (is-false (allowed node "secrets" "unrelated"))
        (is-false (allowed node "secrets" "mounted" "get" "beta"))
        (is-false (allowed other "secrets" "mounted"))
        (is-false (allowed impostor "secrets" "mounted"))
        (is-false (allowed node "secrets" "mounted" "update"))
        (is-false (allowed node "secrets" nil "list"))))))
