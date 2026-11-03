;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise bootstrap resource discovery, durable scoped CRUD, optimistic
;;;; revisions and malformed RBAC policy rejection over the HTTP boundary.

(in-package #:gr8s/tests)
(def-suite bootstrap-resources :in gr8s)
(in-suite bootstrap-resources)

(defun bootstrap-fixtures ()
  "Return representative upstream Sonobuoy bootstrap objects and their URLs."
  (mapcar (lambda (fixture)
            (append (subseq fixture 0 3) (list (com.inuoe.jzon:parse (fourth fixture)))))
          '(
            ("/api/v1/namespaces" "namespaces" nil "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"sonobuoy\"}}")
            ("/api/v1/namespaces/sonobuoy/serviceaccounts" "serviceaccounts" "sonobuoy" "{\"apiVersion\":\"v1\",\"kind\":\"ServiceAccount\",\"metadata\":{\"name\":\"sonobuoy\"}}")
            ("/apis/rbac.authorization.k8s.io/v1/clusterroles" "clusterroles" nil "{\"apiVersion\":\"rbac.authorization.k8s.io/v1\",\"kind\":\"ClusterRole\",\"metadata\":{\"name\":\"sonobuoy\"},\"rules\":[{\"apiGroups\":[\"*\"],\"resources\":[\"*\"],\"verbs\":[\"*\"]}]}")
            ("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" "clusterrolebindings" nil "{\"apiVersion\":\"rbac.authorization.k8s.io/v1\",\"kind\":\"ClusterRoleBinding\",\"metadata\":{\"name\":\"sonobuoy\"},\"roleRef\":{\"apiGroup\":\"rbac.authorization.k8s.io\",\"kind\":\"ClusterRole\",\"name\":\"sonobuoy\"},\"subjects\":[{\"kind\":\"ServiceAccount\",\"name\":\"sonobuoy\",\"namespace\":\"sonobuoy\"}]}")
            )))

(test bootstrap-objects-persist-and-use-their-proper-api-groups
  (with-core-api (store directory)
    (dolist (fixture (bootstrap-fixtures))
      (destructuring-bind (collection resource namespace object) fixture
        (let* ((created (check-core-status 201 collection :method :post :object object))
               (metadata (gethash "metadata" created))
               (url (concatenate 'string collection "/sonobuoy")))
          (is (stringp (gethash "uid" metadata)))
          (is (equal namespace (gethash "namespace" metadata)))
          (is (equal (gethash "apiVersion" object) (gethash "apiVersion" created)))
          (check-core-status 409 collection :method :post :object object)
          (is (equalp created (check-core-status 200 url)))
          (is (equalp created (gr8s::get-core-resource (open-store directory) resource namespace "sonobuoy")))
          (let ((list (check-core-status 200 collection)))
            (is (= 1 (length (gethash "items" list))))
            (is (equal (gethash "apiVersion" object) (gethash "apiVersion" list))))
          (check-core-status 200 url :method :patch :content-type "application/merge-patch+json"
                             :object (gr8s::core-object "metadata" (gr8s::core-object "labels" (gr8s::core-object "updated" "yes"))))
          (check-core-status 409 url :method :put :object created))))
    (check-core-status 404 "/api/v1/clusterroles")
    (check-core-status 404 "/api/v1/namespaces/other/serviceaccounts/sonobuoy")
    (let* ((groups (check-core-status 200 "/apis"))
           (group (aref (gethash "groups" groups) 0)))
      (is (equal "rbac.authorization.k8s.io" (gethash "name" group))))
    (let ((discovery (check-core-status 200 "/apis/rbac.authorization.k8s.io/v1")))
      (is (= 4 (length (gethash "resources" discovery)))))))

(test bootstrap-validation-rejects-wrong-scope-invalid-policy-and-role-ref-changes
  (with-core-api (store directory)
    (values store directory)
    (dolist (fixture (bootstrap-fixtures))
      (check-core-status 201 (first fixture) :method :post :object (fourth fixture)))
    (let ((namespace (fourth (first (bootstrap-fixtures)))))
      (setf (gethash "namespace" (gethash "metadata" namespace)) "wrong")
      (check-core-status 400 "/api/v1/namespaces" :method :post :object namespace))
    (check-core-status 422 "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/sonobuoy"
                       :method :patch :content-type "application/merge-patch+json"
                       :object (gr8s::core-object "roleRef" (gr8s::core-object "name" "another-role")))
    (let ((role (fourth (third (bootstrap-fixtures)))))
      (setf (gethash "rules" role)
            (vector (gr8s::core-object "verbs" #("get") "resources" #("pods"))))
      (check-core-status 422 "/apis/rbac.authorization.k8s.io/v1/clusterroles" :method :post :object role))))

(test node-api-reflects-registration-and-live-readiness
  (with-core-api (store directory)
    (values directory)
    (let ((node (gr8s:make-node-record :id "node-identity" :name "worker-a"
                                      :pod-cidr "10.88.0.0/24" :underlay-address "192.0.2.5")))
      (gr8s:register-node store node)
      (let ((object (check-core-status 200 "/api/v1/nodes/worker-a")))
        (is (equal "False" (gethash "status" (aref (gethash "conditions" (gethash "status" object)) 0)))))
      (gr8s:mark-node-ready store "worker-a" (get-universal-time))
      (let* ((list (check-core-status 200 "/api/v1/nodes"))
             (object (aref (gethash "items" list) 0)))
        (is (= 1 (length (gethash "items" list))))
        (is (equal "node-identity" (gethash "uid" (gethash "metadata" object))))
        (is (equal "True" (gethash "status" (aref (gethash "conditions" (gethash "status" object)) 0)))))
      (let ((list (check-core-status 200 "/api/v1/nodes" :parameters '(("fieldSelector" . "spec.unschedulable=false")))))
        (is (= 1 (length (gethash "items" list)))))
      (let ((list (check-core-status 200 "/api/v1/nodes" :parameters '(("fieldSelector" . "spec.unschedulable=true")))))
        (is (= 0 (length (gethash "items" list)))))
      (check-core-status 404 "/api/v1/nodes/absent"))))
