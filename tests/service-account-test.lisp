;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Exercise issuance provenance, account and Secret UID revocation, durable
;;;; authentication, namespace-scoped RBAC and opt-out credential projection.

(in-package #:gr8s/tests)
(def-suite service-accounts :in gr8s)
(in-suite service-accounts)

(defun service-account-test-store (store &optional (name "reader") (namespace "alpha"))
  "Enable a test API configuration and create an account."
  (setf (gr8s.store::pod-store-in-cluster-config store) (list :host "10.96.0.1" :port 443 :ca-pem "test-ca"))
  (gr8s.resources::create-core-resource store "serviceaccounts"
    (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" name)) namespace))

(defun service-account-test-token (secret)
  "Decode the actual credential token from its Secret data."
  (trivial-utf-8:utf-8-bytes-to-string
   (gr8s.resources::core-base64-bytes (gethash "token" (gethash "data" secret)) "token")))

(defun service-account-token-key-id (token)
  "Return TOKEN's JOSE key identifier."
  (let* ((header (first (uiop:split-string token :separator '(#\.))))
         (json (trivial-utf-8:utf-8-bytes-to-string
                (gr8s.resources::base64url-decode header))))
    (gethash "kid" (com.inuoe.jzon:parse json))))

(test service-account-signing-key-rotation-is-staged-and-preserves-verification
  (with-temporary-store (store directory)
    (let* ((account (service-account-test-store store))
           (path (gr8s.resources::service-account-signing-key-path store))
           (old-token (gr8s.resources::mint-service-account-token store account :seconds 1200))
           (old-kid (service-account-token-key-id old-token))
           (now (gr8s.resources::unix-time-now)))
      (let* ((new-kid (gr8s.resources::prepare-service-account-signing-key-rotation store :now now))
             (prepared (com.inuoe.jzon:parse path))
             (jwks-before (com.inuoe.jzon:stringify (gr8s.resources::service-account-jwks-object store)))
             (still-old (gr8s.resources::mint-service-account-token store account :seconds 1200)))
        (is (= 2 (gethash "formatVersion" prepared)))
        (is (= 2 (length (gethash "keys" prepared))))
        (is (equal old-kid (gethash "activeKid" prepared)))
        (is (equal new-kid (gethash "preparedKid" prepared)))
        (is (equal old-kid (service-account-token-key-id still-old)))
        (is (string= jwks-before
                     (com.inuoe.jzon:stringify (gr8s.resources::service-account-jwks-object store))))
        (is (= 2 (length (gethash "keys" (gr8s.resources::service-account-jwks-object store)))))
        (is (equal new-kid
                   (gr8s.resources::promote-service-account-signing-key-rotation store :now now)))
        (let ((new-token (gr8s.resources::mint-service-account-token store account :seconds 1200)))
          (is (equal new-kid (service-account-token-key-id new-token)))
          (is (gr8s.resources::verify-service-account-jwt-signature store old-token))
          (is (gr8s.resources::verify-service-account-jwt-signature store new-token))
          (signals error
            (gr8s.resources::finalize-service-account-signing-key-rotation store :now (+ now 1199)))
          (is (equal new-kid
                     (gr8s.resources::finalize-service-account-signing-key-rotation store
                                                                         :now (+ now 1201))))
          (is (= 1 (length (gethash "keys" (com.inuoe.jzon:parse path)))))
          (is (null (gr8s.resources::verify-service-account-jwt-signature store old-token)))
          (is (gr8s.resources::verify-service-account-jwt-signature store new-token)))))))

(test legacy-service-account-signing-key-migration-keeps-the-full-safety-window
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((key (gr8s.resources::load-service-account-signing-key store))
           (parts (ironclad:destructure-private-key key))
           (path (gr8s.resources::service-account-signing-key-path store))
           (now (gr8s.resources::unix-time-now)))
      (gr8s.security::write-private-text-atomically
       path (com.inuoe.jzon:stringify
             (gr8s.resources::core-object "d" (gr8s.security::octets-to-hex (getf parts :x))
                                "q" (gr8s.security::octets-to-hex (getf parts :y)))))
      (gr8s.resources::prepare-service-account-signing-key-rotation store :now now)
      (let* ((migrated (com.inuoe.jzon:parse path))
             (old (find (gethash "activeKid" migrated) (gethash "keys" migrated)
                        :key (lambda (entry) (gethash "kid" entry)) :test #'equal)))
        (is (>= (gethash "latestExpiry" old)
                (+ now gr8s.resources::+service-account-token-maximum-seconds+))))
      (gr8s.resources::promote-service-account-signing-key-rotation store :now now)
      (signals error
        (gr8s.resources::finalize-service-account-signing-key-rotation
         store :now (+ now gr8s.resources::+service-account-token-maximum-seconds+ -1))))))

(test native-namespace-creation-publishes-and-restores-the-real-root-ca
  (with-temporary-store (store directory)
    (setf (gr8s.store::pod-store-in-cluster-config store) (list :ca-pem "the-cluster-ca"))
    (let ((namespace (gr8s.resources::create-core-resource store "namespaces"
                       (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "e2e-test")) nil)))
      (gr8s.resources::complete-created-bootstrap-resource store "namespaces" namespace nil)
      (let* ((original (gr8s.resources::get-core-resource store "configmaps" "e2e-test" "kube-root-ca.crt"))
             (uid (gethash "uid" (gethash "metadata" original))))
        (is (equal "the-cluster-ca" (gethash "ca.crt" (gethash "data" original))))
        (is (equal (gethash "uid" (gethash "metadata" namespace))
                   (gethash "uid" (aref (gethash "ownerReferences" (gethash "metadata" original)) 0))))
        (gr8s.resources::update-core-resource store "configmaps" "e2e-test" "kube-root-ca.crt"
         (lambda (object) (setf (gethash "data" object) (gr8s.resources::core-object "other" "preserved")) object))
        (gr8s.resources::ensure-native-namespace-root-cas store)
        (let ((restored (gr8s.resources::get-core-resource store "configmaps" "e2e-test" "kube-root-ca.crt")))
          (is (equal uid (gethash "uid" (gethash "metadata" restored))))
          (is (equal "the-cluster-ca" (gethash "ca.crt" (gethash "data" restored))))
          (is (equal "preserved" (gethash "other" (gethash "data" restored))))
          (gr8s.resources::ensure-native-namespace-root-cas store)
          (is (equalp restored (gr8s.resources::get-core-resource store "configmaps" "e2e-test" "kube-root-ca.crt")))
          (is (equalp restored (gr8s.resources::get-core-resource (open-store directory) "configmaps" "e2e-test" "kube-root-ca.crt")))))
      (let ((preview (gr8s.resources::create-core-resource store "namespaces"
                       (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "preview")) nil :dry-run t)))
        (gr8s.resources::complete-created-bootstrap-resource store "namespaces" preview t)
        (is (null (gr8s.resources::list-core-resources store "configmaps" "preview")))))))

(test a-single-control-plane-bootstraps-the-cluster-without-a-local-agent
  ;; A control plane serving only remote agents is a real cluster too.
  (let ((managed '(:runtime "containerd" :containerd-mode "managed")))
    (is-true (gr8s.server::serve-bootstraps-cluster-p managed nil nil))
    (is-true (gr8s.server::serve-bootstraps-cluster-p '(:runtime "fake") :agent nil))
    (is-true (gr8s.server::serve-bootstraps-cluster-p managed :agent nil))
    ;; A Raft member keeps its earlier behaviour: only with a local managed agent.
    (is-true (gr8s.server::serve-bootstraps-cluster-p managed :agent :ha))
    (is-false (gr8s.server::serve-bootstraps-cluster-p managed nil :ha))
    (is-false (gr8s.server::serve-bootstraps-cluster-p '(:runtime "containerd" :containerd-mode "external") :agent :ha)))
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (gr8s.resources::ensure-native-bootstrap-namespaces store)
    (dolist (name '("default" "kube-system" "kube-public" "kube-node-lease"))
      (is-true (gr8s.resources::get-core-resource store "namespaces" nil name))
      (is-true (gr8s.resources::get-core-resource store "serviceaccounts" name "default")))
    (dolist (role '("cluster-admin" "admin" "edit" "view" "system:auth-delegator"))
      (is-true (gr8s.resources::get-core-resource store "clusterroles" nil role) "missing ClusterRole ~A" role))
    ;; Running it again, as every start does, keeps what exists.
    (let ((uid (gethash "uid" (gethash "metadata" (gr8s.resources::get-core-resource store "namespaces" nil "default")))))
      (gr8s.resources::ensure-native-bootstrap-namespaces store)
      (is (equal uid (gethash "uid" (gethash "metadata" (gr8s.resources::get-core-resource store "namespaces" nil "default"))))))))

(test credentials-require-private-issuance-and-live-account-identities
  (with-temporary-store (store directory)
    (service-account-test-store store)
    (let* ((secret (gr8s.resources::ensure-service-account-credential store "alpha" "reader"))
           (token (service-account-test-token secret))
           (identity (gr8s.resources::authenticate-service-account-token store token)))
      (is (equal "alpha" (gr8s.resources::api-service-account-identity-namespace identity)))
      (is (equal "reader" (gr8s.resources::api-service-account-identity-name identity)))
      (is (null (gr8s.resources::authenticate-service-account-token store "forged")))
      (is (equalp secret (gr8s.resources::ensure-service-account-credential store "alpha" "reader")))
      (is (not (null (gr8s.resources::authenticate-service-account-token (open-store directory) token))))
      (let* ((path (gr8s.resources::service-account-issuer-record-path store (gr8s.resources::service-account-token-digest token)))
             (mode (sb-posix:stat-mode (sb-posix:stat (namestring path)))))
        (is (= #o600 (logand mode #o777))))
      (gr8s.resources::delete-core-resource store "serviceaccounts" "alpha" "reader")
      (service-account-test-store store)
      (is (null (gr8s.resources::authenticate-service-account-token store token)))
      (let ((new-secret (gr8s.resources::ensure-service-account-credential store "alpha" "reader")))
        (is (not (equal token (service-account-test-token new-secret)))))
      (let ((forged (gr8s.resources::copy-core-object secret)))
        (setf (gethash "name" (gethash "metadata" forged)) "forged-token")
        (remhash "resourceVersion" (gethash "metadata" forged))
        (setf (gethash "token" (gethash "data" forged)) (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes "chosen-token")))
        (gr8s.resources::create-core-resource store "secrets" forged "alpha")
        (is (null (gr8s.resources::authenticate-service-account-token store "chosen-token")))))))

(test deleting-and-recreating-the-secret-revokes-its-token
  (with-temporary-store (store directory)
    (values directory)
    (service-account-test-store store)
    (let* ((secret (gr8s.resources::ensure-service-account-credential store "alpha" "reader"))
           (token (service-account-test-token secret))
           (name (gethash "name" (gethash "metadata" secret))))
      (gr8s.resources::delete-core-resource store "secrets" "alpha" name)
      (is (null (gr8s.resources::authenticate-service-account-token store token)))
      (remhash "resourceVersion" (gethash "metadata" secret))
      (gr8s.resources::create-core-resource store "secrets" secret "alpha")
      (is (null (gr8s.resources::authenticate-service-account-token store token)))
      (signals kubernetes-error (gr8s.resources::ensure-service-account-credential store "alpha" "reader")))))

(test field-selector-name-authorizes-list-watch-against-resourcenames
  ;; A rule with resourceNames grants list/watch when the request pins the object
  ;; by metadata.name (KEP-4601) -- Agent Substrate's controller watches a single
  ;; Secret this way. Without the name the resourceNames rule must not match.
  (is (string= "egress-mitm-ca-pool"
               (gr8s.apiserver::field-selector-exact-name "metadata.name=egress-mitm-ca-pool")))
  (is (string= "x" (gr8s.apiserver::field-selector-exact-name "status.phase=Running,metadata.name==x")))
  (is (null (gr8s.apiserver::field-selector-exact-name "metadata.name!=x")))
  (is (null (gr8s.apiserver::field-selector-exact-name "status.phase=Running")))
  (let ((rule (gr8s.resources::core-object "apiGroups" #("") "resources" #("secrets")
                                 "verbs" #("get" "list" "watch") "resourceNames" #("egress-mitm-ca-pool"))))
    (is (not (null (gr8s.resources::rbac-rule-allows-p rule "watch" "" "secrets" "egress-mitm-ca-pool" nil))))
    (is (not (gr8s.resources::rbac-rule-allows-p rule "watch" "" "secrets" nil nil)))          ; no name -> denied
    (is (not (gr8s.resources::rbac-rule-allows-p rule "watch" "" "secrets" "other" nil)))))    ; wrong name -> denied

(test service-account-rbac-grants-only-bound-resources-and-namespaces
  (with-temporary-store (store directory)
    (values directory)
    (service-account-test-store store)
    (let* ((secret (gr8s.resources::ensure-service-account-credential store "alpha" "reader"))
           (identity (gr8s.resources::authenticate-service-account-token store (service-account-test-token secret))))
      (is (not (gr8s.resources::service-account-authorized-p store identity "get" "" "pods" "hello" "alpha")))
      (gr8s.resources::create-core-resource store "roles"
        (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "read-pods")
                           "rules" (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("pods") "verbs" #("get" "list")))) "alpha")
      (gr8s.resources::create-core-resource store "rolebindings"
        (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "read-pods")
                           "roleRef" (gr8s.resources::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" "read-pods")
                           "subjects" (vector (gr8s.resources::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha"))) "alpha")
      (is (not (null (gr8s.resources::service-account-authorized-p store identity "get" "" "pods" "hello" "alpha"))))
      (is (not (gr8s.resources::service-account-authorized-p store identity "delete" "" "pods" "hello" "alpha")))
      (is (not (gr8s.resources::service-account-authorized-p store identity "get" "" "pods" "hello" "beta")))
      (is (not (gr8s.resources::service-account-authorized-p store identity "get" "" "secrets" "hello" "alpha")))
      (gr8s.resources::delete-core-resource store "rolebindings" "alpha" "read-pods")
      (is (not (gr8s.resources::service-account-authorized-p store identity "get" "" "pods" "hello" "alpha"))))))

(test rbac-escalation-and-bind-require-held-permissions-or-the-verb
  (with-temporary-store (store directory)
    (values directory)
    (service-account-test-store store)
    (let ((editor (gr8s.resources::make-api-user-identity :username "editor" :groups #("system:authenticated")))
          (master (gr8s.resources::make-api-user-identity :username "root" :groups #("system:masters"))))
      ;; "editor" is granted only get/list pods in alpha.
      (gr8s.resources::create-core-resource store "roles"
        (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "pod-reader")
          "rules" (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("pods") "verbs" #("get" "list")))) "alpha")
      (gr8s.resources::create-core-resource store "rolebindings"
        (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "pod-reader")
          "roleRef" (gr8s.resources::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" "pod-reader")
          "subjects" (vector (gr8s.resources::core-object "kind" "User" "name" "editor" "apiGroup" "rbac.authorization.k8s.io"))) "alpha")
      ;; Granting only permissions it already holds is allowed.
      (finishes (gr8s.resources::confirm-rbac-role-grant-authorized
                 store editor
                 (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("pods") "verbs" #("get")))
                 nil "r1" "alpha"))
      ;; Granting a permission it does not hold is an escalation -> 403.
      (signals gr8s.model:kubernetes-error
        (gr8s.resources::confirm-rbac-role-grant-authorized
         store editor
         (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("secrets") "verbs" #("get")))
         nil "r2" "alpha"))
      ;; A nil identity (internal/bootstrap write) and system:masters are exempt.
      (finishes (gr8s.resources::confirm-rbac-role-grant-authorized
                 store nil
                 (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("secrets") "verbs" #("*")))
                 nil "r3" "alpha"))
      (finishes (gr8s.resources::confirm-rbac-role-grant-authorized
                 store master
                 (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("secrets") "verbs" #("*")))
                 nil "r4" "alpha"))
      ;; bind: editor cannot bind a role whose permissions it lacks; masters/nil can.
      (gr8s.resources::create-core-resource store "roles"
        (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "secret-admin")
          "rules" (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("secrets") "verbs" #("*")))) "alpha")
      (let ((binding (gr8s.resources::core-object
                      "roleRef" (gr8s.resources::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" "secret-admin")
                      "subjects" (vector (gr8s.resources::core-object "kind" "User" "name" "editor" "apiGroup" "rbac.authorization.k8s.io")))))
        (signals gr8s.model:kubernetes-error
          (gr8s.resources::confirm-rbac-binding-authorized store editor binding nil "alpha"))
        (finishes (gr8s.resources::confirm-rbac-binding-authorized store nil binding nil "alpha"))
        (finishes (gr8s.resources::confirm-rbac-binding-authorized store master binding nil "alpha"))))))

(test admission-projects-real-credentials-and-preserves-automount-opt-out
  (with-temporary-store (store directory)
    (values directory)
    (service-account-test-store store "default" "default")
    (let* ((pod (gr8s.resources::admit-in-cluster-pod store (parse-pod *valid-pod-json*)))
           (spec (gethash "spec" (pod-to-object pod)))
           (container (aref (gethash "containers" spec) 0)))
      (is (equal "default" (gethash "serviceAccountName" spec)))
      (is (= 1 (length (gethash "volumes" spec))))
      (is (= 1 (length (gethash "volumeMounts" container))))
      (is (uiop:string-prefix-p "kube-api-access-" (gethash "name" (aref (gethash "volumes" spec) 0))))
      (is (equal gr8s.resources::+service-account-mount-path+ (gethash "mountPath" (aref (gethash "volumeMounts" container) 0))))
      ;; The node receives the root CA and the minted token, and nothing else.
      (gr8s.resources::create-core-resource store "namespaces" (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "default")) nil)
      (gr8s.resources::ensure-namespace-root-ca store "default")
      (is (= 2 (length (gr8s.kubelet::pod-referenced-resource-objects store pod))))
      ;; The API Service's variables are not stored in the spec: upstream's kubelet adds them as it
      ;; starts the container (pkg/kubelet/kubelet_pods.go makeEnvironmentVariables, from
      ;; getServiceEnvVarMap), and so does the runtime here (pod-service-environment).
      (is (null (find "KUBERNETES_SERVICE_HOST" (gethash "env" container #()) :test #'equal
                      :key (lambda (entry) (gethash "name" entry)))))
      (is (equalp (pod-to-object pod) (pod-to-object (gr8s.resources::admit-in-cluster-pod store pod)))))
    (let* ((object (com.inuoe.jzon:parse *valid-pod-json*)) (spec (gethash "spec" object)))
      (setf (gethash "automountServiceAccountToken" spec) nil)
      (let ((admitted (gr8s.resources::admit-in-cluster-pod store (parse-pod object))))
        (is (null (gethash "volumes" (gethash "spec" (pod-to-object admitted)))))))))

(defvar *tls-api-port* nil "The kernel-assigned port of the current in-cluster TLS API test server.")

(defun start-test-tls-api (store runtime reconciler pki)
  "Start an in-cluster TLS API on a kernel-assigned port, recording it in *TLS-API-PORT*."
  (let ((server (gr8s.apiserver::start-in-cluster-api store runtime reconciler pki :address "127.0.0.1" :port 0)))
    (setf *tls-api-port* (hunchentoot:acceptor-port server))
    server))

(test tls-api-preserves-optional-control-plane-metrics-provider
  (with-temporary-store (store directory)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (runtime (make-fake-runtime))
           (provider (lambda () (format nil "gr8s_raft_term 42~%")))
           (server nil))
      (unwind-protect
           (progn
             (setf server (gr8s.apiserver::start-in-cluster-api
                           store runtime (make-reconciler store runtime) pki
                           :address "127.0.0.1" :port 0 :control-plane-metrics-fn provider))
             (is (eq provider (gr8s.apiserver::acceptor-control-plane-metrics-fn server)))
             (is (typep server 'gr8s.apiserver::gr8s-acceptor)))
        (when server (stop-server server))))))

(defun service-account-tls-status (pki path &optional token)
  "Read an HTTP response status over verified TLS using the test cluster CA."
  (sb-sys:with-deadline (:seconds 10)
    (let* ((socket (usocket:socket-connect "127.0.0.1" *tls-api-port* :element-type '(unsigned-byte 8)))
           (tls nil))
      (unwind-protect
           (progn
             (setf tls (pure-tls:make-tls-client-stream
                        (usocket:socket-stream socket) :hostname "kubernetes.default.svc"
                        :context (pure-tls:make-tls-context :verify-mode pure-tls:+verify-required+
                                   :ca-file (namestring (gr8s.security::cluster-pki-ca-certificate-path pki))
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

(test tls-api-stop-returns-after-waking-its-listener
  (with-temporary-store (store directory)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime))
           (server (start-test-tls-api store runtime reconciler pki))
           (stopper nil))
      (unwind-protect
           (progn
             (setf stopper
                   (bt:make-thread (lambda () (stop-server server))
                                   :name "test TLS API stopper"))
             (is-true (wait-until (lambda () (not (bt:thread-alive-p stopper)))
                                  :timeout 3)))
        (when (and stopper (bt:thread-alive-p stopper))
          (ignore-errors
            (usocket:socket-close (hunchentoot::acceptor-listen-socket server)))
          (ignore-errors (bt:destroy-thread stopper)))
        (when stopper (ignore-errors (bt:join-thread stopper)))))))

(defclass unresponsive-test-acceptor (gr8s.apiserver::gr8s-acceptor) ())

(defmethod hunchentoot:accept-connections ((acceptor unresponsive-test-acceptor))
  "Model the intermittent listener that remains blocked after its wake connection."
  (declare (ignore acceptor))
  (loop (sleep 60)))

(test api-stop-is-bounded-when-the-listener-does-not-wake
  (with-temporary-store (store directory)
    (declare (ignore directory))
    (let* ((runtime (make-fake-runtime))
           (reconciler (make-reconciler store runtime))
           (server (hunchentoot:start
                    (make-instance 'unresponsive-test-acceptor
                                   :address "127.0.0.1" :port 0
                                   :store store :runtime runtime :reconciler reconciler)))
           (taskmaster (hunchentoot::acceptor-taskmaster server))
           (listener (hunchentoot::acceptor-process taskmaster))
           (stopper nil))
      (unwind-protect
           (progn
             (setf stopper
                   (bt:make-thread (lambda () (stop-server server))
                                   :name "test unresponsive API stopper"))
             (is-true (wait-until (lambda () (not (bt:thread-alive-p stopper)))
                                  :timeout 3)))
        (when (bt:thread-alive-p listener)
          (ignore-errors (bt:destroy-thread listener)))
        (when (and stopper (bt:thread-alive-p stopper))
          (ignore-errors (bt:destroy-thread stopper)))
        (when stopper (ignore-errors (bt:join-thread stopper)))
        (ignore-errors
          (usocket:socket-close (hunchentoot::acceptor-listen-socket server)))))))

(test tls-api-requires-credentials-and-live-rbac-grants
  (with-temporary-store (store directory)
    (let* ((pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime))
           (server nil) (*tls-api-port* nil))
      (service-account-test-store store)
      (unwind-protect
           (progn
             (setf server (start-test-tls-api store runtime reconciler pki))
             (let* ((secret (gr8s.resources::ensure-service-account-credential store "alpha" "reader"))
                    (token (service-account-test-token secret)))
               (is (= 401 (service-account-tls-status pki "/version")))
               (is (= 401 (service-account-tls-status pki "/version" "forged")))
               (is (= 200 (service-account-tls-status pki "/version" token)))
               (is (= 403 (service-account-tls-status pki "/api/v1/pods" token)))
               (gr8s.resources::create-core-resource store "clusterroles"
                (gr8s.resources::core-object "apiVersion" "rbac.authorization.k8s.io/v1"
                                   "metadata" (gr8s.resources::core-object "name" "all-pods")
                                   "rules" (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("pods") "verbs" #("get" "list")))) nil)
               (gr8s.resources::create-core-resource store "clusterrolebindings"
                (gr8s.resources::core-object "apiVersion" "rbac.authorization.k8s.io/v1"
                                   "metadata" (gr8s.resources::core-object "name" "all-pods")
                                   "roleRef" (gr8s.resources::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" "all-pods")
                                   "subjects" (vector (gr8s.resources::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha"))) nil)
               (is (= 200 (service-account-tls-status pki "/api/v1/pods" token)))
               (gr8s.resources::delete-core-resource store "serviceaccounts" "alpha" "reader")
               (is (= 401 (service-account-tls-status pki "/api/v1/pods" token)))))
        (when server (stop-server server))))))

(test default-cluster-roles-exist-and-grant-nothing-until-bound
  (with-temporary-store (store directory)
    (values directory)
    (service-account-test-store store)
    (let* ((secret (gr8s.resources::ensure-service-account-credential store "alpha" "reader"))
           (account (gr8s.resources::authenticate-service-account-token store (service-account-test-token secret)))
           (user (gr8s.resources::make-api-user-identity :username "someone" :groups #("system:authenticated")))
           (master (gr8s.resources::make-api-user-identity :username "root" :groups #("system:masters" "system:authenticated"))))
      (flet ((allowed (identity verb group resource &optional namespace)
               (not (null (gr8s.resources::service-account-authorized-p store identity verb group resource nil namespace))))
             (ensure () (gr8s.resources::ensure-system-cluster-roles store)))
        (ensure)
        ;; Run twice: a restart must not fail or duplicate them.
        (ensure)
        (dolist (name '("cluster-admin" "admin" "edit" "view"))
          (is (gr8s.resources::get-core-resource store "clusterroles" nil name))
          (is (equal "rbac-defaults" (gethash "kubernetes.io/bootstrapping"
                                              (gethash "labels" (gethash "metadata" (gr8s.resources::get-core-resource store "clusterroles" nil name)))))))
        (let ((binding (gr8s.resources::get-core-resource store "clusterrolebindings" nil "cluster-admin")))
          (is (equalp "system:masters" (gethash "name" (aref (gethash "subjects" binding) 0)))))
        ;; No existing identity gained anything.
        (dolist (identity (list account user))
          (dolist (request '(("get" "" "pods" "alpha") ("list" "" "secrets" "alpha") ("list" "" "nodes" nil)
                             ("get" "rbac.authorization.k8s.io" "clusterroles" nil) ("create" "apps" "deployments" "alpha")))
            (is (not (allowed identity (first request) (second request) (third request) (fourth request)))
                "~A was allowed ~A" (gr8s.resources::api-identity-username identity) request)))
        (is (allowed master "delete" "" "nodes"))
        ;; An upstream-shaped RoleBinding gives each role upstream's reach, in that namespace only.
        (flet ((bind (role)
                 (gr8s.resources::create-core-resource store "rolebindings"
                   (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" (format nil "bind-~A" role))
                                      "roleRef" (gr8s.resources::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" role)
                                      "subjects" (vector (gr8s.resources::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha")))
                   "alpha"))
               (unbind (role) (gr8s.resources::delete-core-resource store "rolebindings" "alpha" (format nil "bind-~A" role))))
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
    (gr8s.resources::create-core-resource store "clusterroles"
      (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "view")
                         "rules" (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("pods") "verbs" #("get")))) nil)
    (gr8s.resources::ensure-system-cluster-roles store)
    (is (= 1 (length (gethash "rules" (gr8s.resources::get-core-resource store "clusterroles" nil "view")))))
    (is (< 1 (length (gethash "rules" (gr8s.resources::get-core-resource store "clusterroles" nil "edit")))))))

(test cluster-roles-aggregate-labelled-roles
  (with-temporary-store (store directory)
    (values directory)
    (gr8s.resources::ensure-system-cluster-roles store)
    (flet ((rules (name) (gethash "rules" (gr8s.resources::get-core-resource store "clusterroles" nil name)))
           (grants-p (name resource)
             (some (lambda (rule) (find resource (gethash "resources" rule) :test #'equal))
                   (gethash "rules" (gr8s.resources::get-core-resource store "clusterroles" nil name)))))
      ;; admin, edit and view aggregate upstream's system:aggregate-to-* roles.
      (is (gethash "aggregationRule" (gr8s.resources::get-core-resource store "clusterroles" nil "edit")))
      (is (grants-p "view" "pods"))
      (is (grants-p "edit" "secrets"))
      (is (grants-p "admin" "rolebindings"))
      (is (not (grants-p "edit" "rolebindings")))
      (is (not (grants-p "view" "secrets")))
      ;; A chart's role labelled for edit adds its rules to edit and admin, not view.
      (gr8s.resources::create-core-resource store "clusterroles"
        (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "widgets-edit"
                                                         "labels" (gr8s.resources::core-object "rbac.authorization.k8s.io/aggregate-to-edit" "true"
                                                                                     "rbac.authorization.k8s.io/aggregate-to-admin" "true"))
                           "rules" (vector (gr8s.resources::core-object "apiGroups" #("example.test") "resources" #("widgets") "verbs" #("get"))))
        nil)
      (gr8s.resources::reconcile-cluster-role-aggregation store)
      (is (grants-p "edit" "widgets"))
      (is (grants-p "admin" "widgets"))
      (is (not (grants-p "view" "widgets")))
      ;; A rule the sources share appears once, and the pass is idempotent.
      (let ((before (length (rules "admin"))))
        (gr8s.resources::reconcile-cluster-role-aggregation store)
        (is (= before (length (rules "admin")))))
      ;; Removing the source takes its rules away again.
      (gr8s.resources::delete-core-resource store "clusterroles" nil "widgets-edit")
      (gr8s.resources::reconcile-cluster-role-aggregation store)
      (is (not (grants-p "edit" "widgets")))
      ;; Rules written by hand are replaced by what the selectors gather.
      (gr8s.resources::create-core-resource store "clusterroles"
        (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "mine")
                           "aggregationRule" (gr8s.resources::core-object "clusterRoleSelectors"
                                                                (vector (gr8s.resources::core-object "matchLabels" (gr8s.resources::core-object "team" "a"))))
                           "rules" (vector (gr8s.resources::core-object "apiGroups" #("") "resources" #("nodes") "verbs" #("get"))))
        nil)
      (gr8s.resources::reconcile-cluster-role-aggregation store)
      (is (zerop (length (rules "mine"))))
      ;; An aggregationRule needs at least one valid selector.
      (signals gr8s.model::kubernetes-error
        (gr8s.resources::create-core-resource store "clusterroles"
          (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "empty")
                             "aggregationRule" (gr8s.resources::core-object "clusterRoleSelectors" #()))
          nil))
      (signals gr8s.model::kubernetes-error
        (gr8s.resources::create-core-resource store "clusterroles"
          (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "bad")
                             "aggregationRule" (gr8s.resources::core-object "clusterRoleSelectors"
                                                                  (vector (gr8s.resources::core-object "matchExpressions"
                                                                                             (vector (gr8s.resources::core-object "key" "a" "operator" "Bogus"))))))
          nil)))))

(test nodes-read-only-what-their-pods-use
  (with-temporary-store (store directory)
    (values directory)
    (let ((node (gr8s.resources::make-api-user-identity :username "system:node:n1" :groups #("system:nodes" "system:authenticated")))
          (other (gr8s.resources::make-api-user-identity :username "system:node:n2" :groups #("system:nodes" "system:authenticated")))
          (impostor (gr8s.resources::make-api-user-identity :username "system:node:n1" :groups #("system:authenticated"))))
      (create-pod store (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"user\",\"namespace\":\"alpha\"},
        \"spec\":{\"nodeName\":\"n1\",\"imagePullSecrets\":[{\"name\":\"pull\"}],
          \"containers\":[{\"name\":\"web\",\"image\":\"busybox:1.36.1\",
            \"env\":[{\"name\":\"A\",\"valueFrom\":{\"configMapKeyRef\":{\"name\":\"settings\",\"key\":\"a\"}}}],
            \"envFrom\":[{\"secretRef\":{\"name\":\"env-secret\"}}]}],
          \"volumes\":[{\"name\":\"s\",\"secret\":{\"secretName\":\"mounted\"}},
                       {\"name\":\"d\",\"persistentVolumeClaim\":{\"claimName\":\"data\"}},
                       {\"name\":\"p\",\"projected\":{\"sources\":[{\"configMap\":{\"name\":\"projected\"}}]}}]}}"))
      (flet ((allowed (identity resource name &optional (verb "get") (namespace "alpha"))
               (gr8s.resources::node-authorizer-allows-p store identity verb "" resource name namespace)))
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

(test namespace-defaults-pass-admission-as-their-controllers
  ;; The default ServiceAccount and root CA ConfigMap are written as upstream's controllers
  ;; write them, so admission sees them, under the controllers' own identities.
  (with-temporary-store (store directory)
    (values directory)
    (setf (gr8s.store::pod-store-in-cluster-config store) (list :ca-pem "the-cluster-ca"))
    (gr8s.resources::create-core-resource store "validatingadmissionpolicies"
      (gr8s.resources::core-object
       "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicy"
       "metadata" (gr8s.resources::core-object "name" "no-defaults")
       "spec" (gr8s.resources::core-object
               "matchConstraints" (gr8s.resources::core-object
                                   "resourceRules" (vector (gr8s.resources::core-object "apiGroups" #("") "apiVersions" #("v1")
                                                                              "operations" #("CREATE" "UPDATE")
                                                                              "resources" #("serviceaccounts" "configmaps"))))
               "validations" (vector (gr8s.resources::core-object
                                      "expression" "!request.userInfo.username.startsWith('system:serviceaccount:kube-system:')"
                                      "message" "controllers may not write here"))))
      nil)
    (gr8s.resources::create-core-resource store "validatingadmissionpolicybindings"
      (gr8s.resources::core-object
       "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicyBinding"
       "metadata" (gr8s.resources::core-object "name" "no-defaults")
       "spec" (gr8s.resources::core-object "policyName" "no-defaults" "validationActions" #("Deny")))
      nil)
    (let ((namespace (gr8s.resources::create-core-resource store "namespaces"
                       (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "guarded")) nil)))
      ;; Refused, the Namespace still stands and simply lacks them for now.
      (finishes (gr8s.resources::complete-created-bootstrap-resource store "namespaces" namespace nil))
      (is (null (gr8s.resources::list-core-resources store "serviceaccounts" "guarded")))
      (is (null (gr8s.resources::list-core-resources store "configmaps" "guarded")))
      ;; Once the policy goes, the controller pass restores both.
      (gr8s.resources::delete-core-resource store "validatingadmissionpolicybindings" nil "no-defaults")
      (gr8s.resources::reconcile-namespace-defaults store)
      (is (gr8s.resources::get-core-resource store "serviceaccounts" "guarded" "default"))
      (is (equal "the-cluster-ca"
                 (gethash "ca.crt" (gethash "data" (gr8s.resources::get-core-resource store "configmaps" "guarded" "kube-root-ca.crt"))))))))

(test authenticated-users-hold-upstreams-default-grants
  ;; Without any binding: system:discovery, system:public-info-viewer and system:basic-user,
  ;; so a SubjectAccessReview an aggregated server sends agrees with what the API itself allows.
  (with-temporary-store (store directory)
    (values directory)
    (let ((user (gr8s.resources::make-api-user-identity :username "someone" :groups #("system:authenticated")))
          (anonymous (gr8s.resources::make-api-user-identity :username "system:anonymous" :groups #("system:unauthenticated"))))
      (flet ((url (identity verb path) (gr8s.resources::service-account-authorized-p store identity verb "" nil nil nil path))
             (resource (identity verb group resource)
               (gr8s.resources::service-account-authorized-p store identity verb group resource nil nil)))
        (dolist (path '("/api" "/api/v1" "/apis/wardle.example.com/v1beta1" "/openapi/v3"
                        "/openapi/v3/apis/wardle.example.com/v1beta1" "/version" "/healthz" "/readyz"))
          (is-true (url user "get" path) "~A" path))
        (is-false (url user "post" "/openapi/v3"))
        (is-false (url user "get" "/metrics"))
        (is-false (url user "get" "/logs"))
        (is-false (url anonymous "get" "/openapi/v3"))
        (is-true (resource user "create" "authorization.k8s.io" "selfsubjectaccessreviews"))
        (is-true (resource user "create" "authentication.k8s.io" "selfsubjectreviews"))
        (is-false (resource user "create" "authorization.k8s.io" "subjectaccessreviews"))
        (is-false (resource user "get" "" "pods"))))))
