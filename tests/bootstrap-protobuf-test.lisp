;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify typed ServiceAccount and RBAC requests, correct API group envelopes,
;;;; durable HTTP admission, and actual TLS authorization grants and revocations.

(in-package #:gr8s/tests)
(def-suite bootstrap-protobuf :in gr8s)
(in-suite bootstrap-protobuf)

(defun bootstrap-wire-fixture (kind name &key version resource-version (role-kind "Role") (role-name "read-pods")
                                           (role-api-group "rbac.authorization.k8s.io"))
  "Construct wire requests using the pinned Kubernetes core/RBAC field numbers."
  (let* ((account (equal kind "ServiceAccount"))
         (binding (member kind '("RoleBinding" "ClusterRoleBinding") :test #'equal))
         (metadata (core-test-protobuf (append (list (list 1 name))
                                               (when resource-version (list (list 6 resource-version))))))
         (fields (list (list 1 metadata))))
    (cond
      (account
       (setf fields (append fields (list (list 2 (core-test-protobuf '((1 "") (2 "") (3 "account-secret") (4 "") (5 "") (6 "") (7 ""))))
                                        (list 3 (core-test-protobuf '((1 "registry-secret")))) (list 4 0)))))
      (binding
       (setf fields (append fields (list (list 2 (core-test-protobuf '((1 "ServiceAccount") (2 "") (3 "reader") (4 "alpha"))))
                                        (list 3 (core-test-protobuf (append (when role-api-group (list (list 1 role-api-group)))
                                                                           (list (list 2 role-kind) (list 3 role-name)))))))))
      (t
       (setf fields (append fields (list (list 2 (core-test-protobuf '((1 "get") (1 "list") (2 "") (3 "pods")))))))))
    (core-test-protobuf-envelope kind fields (or version (if account "v1" "rbac.authorization.k8s.io/v1")))))

(test typed-serviceaccount-preserves-optional-false-and-reference-shapes
  (with-core-api (store path)
    (values path)
    (let* ((input (bootstrap-wire-fixture "ServiceAccount" "reader"))
           (created (check-core-status 201 "/api/v1/namespaces/alpha/serviceaccounts" :method :post
                                     :content-type "application/vnd.kubernetes.protobuf" :octets input)))
      (is (equal "v1" (gethash "apiVersion" created)))
      (is (equal "account-secret" (gethash "name" (aref (gethash "secrets" created) 0))))
      (is (equal "registry-secret" (gethash "name" (aref (gethash "imagePullSecrets" created) 0))))
      (is-true (nth-value 1 (gethash "automountServiceAccountToken" created)))
      (is (null (gethash "automountServiceAccountToken" created)))
      (is (equal (gethash "uid" (gethash "metadata" created))
                 (gethash "uid" (gethash "metadata" (gr8s::get-core-resource (open-store path) "serviceaccounts" "alpha" "reader")))))
      (check-core-status 400 "/api/v1/namespaces/alpha/serviceaccounts" :method :post
                         :content-type "application/vnd.kubernetes.protobuf"
                         :octets (bootstrap-wire-fixture "ServiceAccount" "wrong" :version "rbac.authorization.k8s.io/v1")))))

(test typed-rbac-kinds-enforce-group-version-and-optimistic-update
  (with-core-api (store path)
    (values store path)
    (dolist (descriptor '(("Role" "roles" "alpha") ("RoleBinding" "rolebindings" "alpha")
                          ("ClusterRole" "clusterroles" nil) ("ClusterRoleBinding" "clusterrolebindings" nil)))
      (destructuring-bind (kind resource namespace) descriptor
        (let* ((collection (format nil "/apis/rbac.authorization.k8s.io/v1~A/~A"
                                   (if namespace (concatenate 'string "/namespaces/" namespace) "") resource))
               (role-kind (if namespace "Role" "ClusterRole"))
               (input (bootstrap-wire-fixture kind "wire" :role-kind role-kind))
               (created (check-core-status 201 collection :method :post :content-type "application/vnd.kubernetes.protobuf" :octets input))
               (metadata (gethash "metadata" created))
               (item (concatenate 'string collection "/wire"))
               (update (bootstrap-wire-fixture kind "wire" :role-kind role-kind :resource-version (gethash "resourceVersion" metadata))))
          (is (equal "rbac.authorization.k8s.io/v1" (gethash "apiVersion" created)))
          (is (equal kind (gethash "kind" created)))
          (let ((updated (check-core-status 200 item :method :put :content-type "application/vnd.kubernetes.protobuf" :octets update)))
            (is (equal (gethash "uid" metadata) (gethash "uid" (gethash "metadata" updated)))))
          (check-core-status 409 item :method :put :content-type "application/vnd.kubernetes.protobuf" :octets update)
          (check-core-status 400 collection :method :post :content-type "application/vnd.kubernetes.protobuf"
                             :octets (bootstrap-wire-fixture kind "wrong" :version "v1" :role-kind role-kind))
          (check-core-status 400 collection :method :post :content-type "application/vnd.kubernetes.protobuf" :octets (subseq input 0 5))
          (check-core-status 200 item :method :delete :content-type "application/vnd.kubernetes.protobuf"
                             :octets (core-test-protobuf-envelope "DeleteOptions" nil "rbac.authorization.k8s.io/v1")))))))

(test typed-rbac-grants-are-enforced-by-the-authenticated-tls-api
  (with-core-api (store directory)
    (let* ((pki (gr8s:ensure-cluster-pki (merge-pathnames "pki/" directory)))
           (runtime (make-fake-runtime)) (reconciler (make-reconciler store runtime)) (tls-server nil))
      (setf (gr8s::pod-store-in-cluster-config store)
            (list :host "10.96.0.1" :port 443 :ca-pem (uiop:read-file-string (gr8s:cluster-pki-ca-certificate-path pki))))
      (check-core-status 201 "/api/v1/namespaces/alpha/serviceaccounts" :method :post :content-type "application/vnd.kubernetes.protobuf"
                         :octets (bootstrap-wire-fixture "ServiceAccount" "reader"))
      (let* ((secret (gr8s::ensure-service-account-credential store "alpha" "reader"))
             (token (service-account-test-token secret)))
        (unwind-protect
             (progn
               (setf tls-server (gr8s::start-in-cluster-api store runtime reconciler pki :address "127.0.0.1" :port 18091))
               (is (= 403 (service-account-tls-status pki "/api/v1/namespaces/alpha/pods" token)))
               (check-core-status 201 "/apis/rbac.authorization.k8s.io/v1/namespaces/alpha/roles"
                                  :method :post :content-type "application/vnd.kubernetes.protobuf"
                                  :octets (bootstrap-wire-fixture "Role" "read-pods"))
               (check-core-status 201 "/apis/rbac.authorization.k8s.io/v1/namespaces/alpha/rolebindings"
                                  :method :post :content-type "application/vnd.kubernetes.protobuf"
                                  :octets (bootstrap-wire-fixture "RoleBinding" "read-pods" :role-api-group nil))
               (is (= 200 (service-account-tls-status pki "/api/v1/namespaces/alpha/pods" token)))
               (is (= 403 (service-account-tls-status pki "/api/v1/namespaces/beta/pods" token)))
               (check-core-status 200 "/apis/rbac.authorization.k8s.io/v1/namespaces/alpha/rolebindings/read-pods" :method :delete)
               (is (= 403 (service-account-tls-status pki "/api/v1/namespaces/alpha/pods" token)))
               (check-core-status 201 "/apis/rbac.authorization.k8s.io/v1/clusterroles" :method :post
                                  :content-type "application/vnd.kubernetes.protobuf" :octets (bootstrap-wire-fixture "ClusterRole" "read-pods"))
               (check-core-status 201 "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" :method :post
                                  :content-type "application/vnd.kubernetes.protobuf"
                                  :octets (bootstrap-wire-fixture "ClusterRoleBinding" "read-pods" :role-kind "ClusterRole" :role-api-group nil))
               (is (= 200 (service-account-tls-status pki "/api/v1/pods" token)))
               (check-core-status 200 "/api/v1/namespaces/alpha/serviceaccounts/reader" :method :delete)
               (is (= 401 (service-account-tls-status pki "/api/v1/pods" token))))
          (when tls-server (stop-server tls-server)))))))

(test rbac-binding-json-defaults-role-and-subject-api-groups
  (with-core-api (store path)
    (values store path)
    (dolist (kind '("RoleBinding" "ClusterRoleBinding"))
      (let* ((cluster (equal kind "ClusterRoleBinding"))
             (collection (if cluster "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
                             "/apis/rbac.authorization.k8s.io/v1/namespaces/alpha/rolebindings"))
             (object (gr8s::core-object
                      "apiVersion" "rbac.authorization.k8s.io/v1" "kind" kind
                      "metadata" (gr8s::core-object "name" "defaults")
                      "roleRef" (gr8s::core-object "kind" (if cluster "ClusterRole" "Role") "name" "read-pods")
                      "subjects" (vector (gr8s::core-object "kind" "User" "name" "alice")
                                          (gr8s::core-object "kind" "Group" "name" "builders" "apiGroup" "")
                                          (gr8s::core-object "kind" "ServiceAccount" "name" "reader" "namespace" "alpha"))))
             (item (concatenate 'string collection "/defaults"))
             (created (check-core-status 201 collection :method :post :object object)))
        (is (equal "rbac.authorization.k8s.io" (gethash "apiGroup" (gethash "roleRef" created))))
        (is (not (nth-value 1 (gethash "apiGroup" (gethash "roleRef" object)))))
        (loop for subject across (gethash "subjects" created)
              do (is (equal (if (equal "ServiceAccount" (gethash "kind" subject)) "" "rbac.authorization.k8s.io")
                            (gethash "apiGroup" subject))))
        ;; Defaulting occurs before immutable roleRef comparison on updates.
        (remhash "apiGroup" (gethash "roleRef" created))
        (let* ((updated (check-core-status 200 item :method :put :object created))
               (revision (gethash "resourceVersion" (gethash "metadata" updated))))
          (setf (gethash "apiGroup" (gethash "roleRef" updated)) "other.example")
          (check-core-status 422 item :method :put :object updated)
          (is (equal revision (gethash "resourceVersion" (gethash "metadata" (check-core-status 200 item))))))))))

(test typed-rbac-role-reference-groups-default-for-omitted-and-empty-wire-fields
  (with-core-api (store path)
    (values store path)
    (dolist (kind '("RoleBinding" "ClusterRoleBinding"))
      (let* ((cluster (equal kind "ClusterRoleBinding"))
             (collection (if cluster "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
                             "/apis/rbac.authorization.k8s.io/v1/namespaces/alpha/rolebindings")))
        (loop for group in '(nil "") for index from 0
              for name = (format nil "default-~D" index)
              for wire = (bootstrap-wire-fixture kind name :role-kind (if cluster "ClusterRole" "Role") :role-api-group group)
              for created = (check-core-status 201 collection :method :post :content-type "application/vnd.kubernetes.protobuf" :octets wire)
              do (is (equal "rbac.authorization.k8s.io" (gethash "apiGroup" (gethash "roleRef" created)))))))))

(test rbac-defaulting-keeps-wrong-groups-invalid-and-dry-run-is-atomic
  (with-core-api (store path)
    (values store path)
    (let* ((collection "/apis/rbac.authorization.k8s.io/v1/namespaces/alpha/rolebindings")
           (object (gr8s::core-object "kind" "RoleBinding" "metadata" (gr8s::core-object "name" "preview")
                                      "roleRef" (gr8s::core-object "kind" "Role" "name" "read-pods")
                                      "subjects" (vector (gr8s::core-object "kind" "User" "name" "alice")))))
      (let ((preview (check-core-status 201 (concatenate 'string collection "?dryRun=All") :method :post :object object)))
        (is (equal "rbac.authorization.k8s.io" (gethash "apiGroup" (gethash "roleRef" preview)))))
      (check-core-status 404 (concatenate 'string collection "/preview"))
      (dolist (bad '(nil 0 "other.example"))
        (setf (gethash "apiGroup" (gethash "roleRef" object)) bad)
        (check-core-status 422 collection :method :post :object object))
      (remhash "apiGroup" (gethash "roleRef" object))
      (setf (gethash "apiGroup" (aref (gethash "subjects" object) 0)) "other.example")
      (check-core-status 422 collection :method :post :object object))))

(in-suite gr8s)

(test a-binding-can-arrive-in-protobuf-as-client-go-sends-it
  (with-core-api (store path)
    (values path)
    (gr8s:register-node store (gr8s:make-node-record :id "bind-pb-id" :name "bind-pb" :pod-cidr "10.88.41.0/24"))
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (input (core-test-protobuf-envelope
                   "Binding"
                   (list (list 1 (core-test-protobuf (list (list 1 (pod-name pod)))))
                         (list 2 (core-test-protobuf '((1 "Node") (3 "bind-pb"))))))))
      (check-core-status 201 (format nil "/api/v1/namespaces/default/pods/~A/binding" (pod-name pod))
                         :method :post :content-type "application/vnd.kubernetes.protobuf" :octets input)
      (is (equal "bind-pb" (gr8s::pod-node-name (gr8s:get-pod store "default" (pod-name pod))))))))
