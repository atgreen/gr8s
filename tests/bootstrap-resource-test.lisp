;;;; SPDX-FileCopyrightText: 2026 Anthony Green
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

(defun discovery-entry (document name)
  "Return the entry for NAME in a legacy discovery DOCUMENT."
  (find name (gethash "resources" document) :test #'equal :key (lambda (entry) (gethash "name" entry))))

(test discovery-publishes-upstream-short-names-and-categories
  ;; Values read from kubernetes/kubernetes release-1.36 api/discovery.
  (with-core-api (store directory)
    (values store directory)
    (loop for (path name short-names categories)
            in '(("/api/v1" "namespaces" ("ns") nil)
                 ("/api/v1" "serviceaccounts" ("sa") nil)
                 ("/api/v1" "nodes" ("no") nil)
                 ("/api/v1" "pods" ("po") ("all"))
                 ("/api/v1" "services" ("svc") ("all"))
                 ("/api/v1" "replicationcontrollers" ("rc") ("all"))
                 ("/api/v1" "secrets" nil nil)
                 ("/api/v1" "events" ("ev") nil)
                 ("/apis/events.k8s.io/v1" "events" ("ev") nil)
                 ("/apis/apps/v1" "deployments" ("deploy") ("all"))
                 ("/apis/apps/v1" "statefulsets" ("sts") ("all"))
                 ("/apis/apps/v1" "controllerrevisions" nil nil)
                 ("/apis/batch/v1" "jobs" nil ("all"))
                 ("/apis/batch/v1" "cronjobs" ("cj") ("all"))
                 ("/apis/autoscaling/v1" "horizontalpodautoscalers" ("hpa") ("all"))
                 ("/apis/autoscaling/v2" "horizontalpodautoscalers" ("hpa") ("all"))
                 ("/apis/policy/v1" "poddisruptionbudgets" ("pdb") nil)
                 ("/apis/networking.k8s.io/v1" "ipaddresses" ("ip") nil)
                 ("/apis/networking.k8s.io/v1" "ingressclasses" nil nil)
                 ("/apis/storage.k8s.io/v1" "storageclasses" ("sc") nil)
                 ("/apis/scheduling.k8s.io/v1" "priorityclasses" ("pc") nil)
                 ("/apis/apiextensions.k8s.io/v1" "customresourcedefinitions" ("crd" "crds") ("api-extensions"))
                 ("/apis/apiregistration.k8s.io/v1" "apiservices" nil ("api-extensions"))
                 ("/apis/admissionregistration.k8s.io/v1" "validatingwebhookconfigurations" nil ("api-extensions")))
          do (let ((entry (discovery-entry (check-core-status 200 path) name)))
               (is (hash-table-p entry) "~A ~A is not served" path name)
               (is (equal short-names (coerce (gethash "shortNames" entry #()) 'list)) "~A ~A short names" path name)
               (is (equal categories (coerce (gethash "categories" entry #()) 'list)) "~A ~A categories" path name)
               (is (not (equal "" (gethash "singularName" entry))) "~A ~A singular name" path name)))))

(test every-named-discovery-resource-exists
  ;; A misspelled table entry would silently publish nothing.
  (loop for (resource) in gr8s::*resource-discovery-names*
        do (is (or (member resource '("pods" "nodes" "apiservices" "volumeattributesclasses" "componentstatuses") :test #'equal)
                   (assoc resource gr8s::*stored-resource-types* :test #'equal))
               "~A is not a served resource" resource)))

(test collection-delete-discovery-matches-what-is-served
  (with-core-api (store directory)
    (values store directory)
    (flet ((verbs (path name) (coerce (gethash "verbs" (discovery-entry (check-core-status 200 path) name)) 'list)))
      ;; Served all along but undiscoverable, so clients fell back to deleting one by one.
      (is (member "deletecollection" (verbs "/apis/batch/v1" "jobs") :test #'equal))
      (is (member "deletecollection" (verbs "/apis/batch/v1" "cronjobs") :test #'equal))
      (is (member "deletecollection" (verbs "/apis/policy/v1" "poddisruptionbudgets") :test #'equal))
      (check-core-status 200 "/apis/batch/v1/namespaces/default/jobs" :method :delete)
      ;; As upstream: a Namespace cannot be deleted through its collection.
      (is (not (member "deletecollection" (verbs "/api/v1" "namespaces") :test #'equal))))))

(test core-discovery-has-no-resource-from-another-group
  (with-core-api (store directory)
    (values store directory)
    (let ((document (check-core-status 200 "/api/v1")))
      ;; A parentless subresource surfaced as a verbless top-level kind in aggregated discovery.
      (is (null (discovery-entry document "volumeattachments/status")))
      (loop for entry across (gethash "resources" document)
            for name = (gethash "name" entry)
            for slash = (position #\/ name)
            when slash
              do (is (discovery-entry document (subseq name 0 slash)) "~A has no parent" name))
      (dolist (name '("nodes/status" "namespaces/status" "namespaces/finalize" "pods/attach" "pods/exec" "pods/portforward" "serviceaccounts/token"))
        (is (discovery-entry document name) "~A is served but not discoverable" name)))))

(defun node-watch-names (events)
  "Return (type name) for Node watch EVENTS."
  (mapcar (lambda (event) (list (gethash "type" event) (gethash "name" (gethash "metadata" (gethash "object" event))))) events))

(test node-changes-clients-can-see-get-revisions-and-events
  (with-temporary-store (store directory)
    (values directory)
    (let ((start (gr8s::pod-store-pod-revision store)))
      (gr8s:register-node store (gr8s:make-node-record :id "a" :name "worker-a" :pod-cidr "10.88.0.0/24"))
      (let ((registered (gr8s::node-record-resource-version (gr8s::get-node store "worker-a"))))
        (gr8s:mark-node-ready store "worker-a" 100)
        (let ((ready (gr8s::node-record-resource-version (gr8s::get-node store "worker-a"))))
          (is (> (parse-integer ready) (parse-integer registered)))
          ;; A later heartbeat renews the lease, which clients cannot see.
          (gr8s:mark-node-ready store "worker-a" 110)
          (is (equal ready (gr8s::node-record-resource-version (gr8s::get-node store "worker-a"))))))
      (gr8s::update-node-extended-resources store "worker-a" (gr8s::core-object "example.com/gpu" "2"))
      (gr8s::mark-node-not-ready store "worker-a")
      (gr8s::mark-node-not-ready store "worker-a")
      (let ((events (gr8s::node-watch-events store "" "" start)))
        (is (equal '(("ADDED" "worker-a") ("MODIFIED" "worker-a") ("MODIFIED" "worker-a") ("MODIFIED" "worker-a"))
                   (node-watch-names events)))
        (is (apply #'< (mapcar (lambda (event) (parse-integer (gethash "resourceVersion" (gethash "metadata" (gethash "object" event)))))
                               events)))
        (is (equal "False" (gethash "status" (aref (gethash "conditions" (gethash "status" (gethash "object" (fourth events)))) 0)))))
      ;; Resuming returns exactly what came later.
      (let ((revision (gr8s::pod-store-pod-revision store)))
        (is (null (gr8s::node-watch-events store "" "" revision)))
        (gr8s:mark-node-ready store "worker-a" 120)
        (is (equal '(("MODIFIED" "worker-a")) (node-watch-names (gr8s::node-watch-events store "" "" revision))))))))

(test node-revisions-survive-restart-and-old-revisions-expire
  (with-temporary-store (store directory)
    (gr8s:register-node store (gr8s:make-node-record :id "a" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (gr8s:mark-node-ready store "worker-a" 100)
    (let* ((before (parse-integer (gr8s::node-record-resource-version (gr8s::get-node store "worker-a"))))
           (reopened (open-store directory)))
      (is (= before (parse-integer (gr8s::node-record-resource-version (gr8s::get-node reopened "worker-a")))))
      (is (>= (gr8s::pod-store-pod-revision reopened) before))
      ;; The journal is memory-only, so a client from before the restart must relist.
      (is (= 410 (handler-case (progn (gr8s::node-list-page reopened "" "" (write-to-string (1- before))) 0)
                   (kubernetes-error (condition) (gr8s::kubernetes-error-status-code condition))))))))

(test node-selectors-turn-leaving-the-selection-into-a-deletion
  (with-core-api (store directory)
    (values directory)
    (check-core-status 201 "/api/v1/nodes" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Node"
                                 "metadata" (gr8s::core-object "name" "api-a" "labels" (gr8s::core-object "set" "one"))))
    (let ((revision (gr8s::pod-store-pod-revision store)))
      (is (= 1 (length (gethash "items" (check-core-status 200 "/api/v1/nodes" :parameters '(("labelSelector" . "set=one")))))))
      (check-core-status 200 "/api/v1/nodes/api-a" :method :patch :content-type "application/merge-patch+json"
        :object (gr8s::core-object "metadata" (gr8s::core-object "labels" (gr8s::core-object "set" "two"))))
      (is (= 0 (length (gethash "items" (check-core-status 200 "/api/v1/nodes" :parameters '(("labelSelector" . "set=one")))))))
      (is (equal '(("DELETED" "api-a")) (node-watch-names (gr8s::node-watch-events store "set=one" "" revision))))
      (is (equal '(("ADDED" "api-a")) (node-watch-names (gr8s::node-watch-events store "set=two" "" revision))))
      (is (equal '(("MODIFIED" "api-a")) (node-watch-names (gr8s::node-watch-events store "" "metadata.name=api-a" revision)))))))

(test node-list-and-watch-share-a-revision-over-http
  (with-core-api (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "a" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    (let* ((list (check-core-status 200 "/api/v1/nodes"))
           (revision (gethash "resourceVersion" (gethash "metadata" list))))
      (is (equal "NodeList" (gethash "kind" list)))
      (is (= (gr8s::pod-store-pod-revision store) (parse-integer revision)))
      (let ((verbs (coerce (gethash "verbs" (discovery-entry (check-core-status 200 "/api/v1") "nodes")) 'list)))
        (is (equal '("create" "delete" "deletecollection" "get" "list" "patch" "update" "watch") verbs)))
      (sb-sys:with-deadline (:seconds 10)
        (multiple-value-bind (stream code)
            (drakma:http-request "http://127.0.0.1:18089/api/v1/nodes" :want-stream t
                                 :parameters `(("watch" . "true") ("resourceVersion" . ,revision) ("timeoutSeconds" . "3")))
          (unwind-protect
               (progn
                 (is (= 200 code))
                 (gr8s:mark-node-ready store "worker-a" 100)
                 (let ((event (read-template-watch-event stream)))
                   (is (equal "MODIFIED" (gethash "type" event)))
                   (is (equal "True" (gethash "status" (aref (gethash "conditions" (gethash "status" (gethash "object" event))) 0))))))
            (close stream))))
      (check-core-status 400 "/api/v1/nodes" :parameters '(("watch" . "true") ("resourceVersion" . "not-a-number")))
      (check-core-status 504 "/api/v1/nodes" :parameters '(("watch" . "true") ("resourceVersion" . "999999"))))))

(test node-delete-collection-removes-api-nodes-and-refuses-agent-nodes
  (with-core-api (store directory)
    (values directory)
    (flet ((node (name label)
             (check-core-status 201 "/api/v1/nodes" :method :post
               :object (gr8s::core-object "apiVersion" "v1" "kind" "Node"
                                          "metadata" (gr8s::core-object "name" name "labels" (gr8s::core-object "set" label))))))
      (node "api-a" "one")
      (node "api-b" "one")
      (node "api-c" "two"))
    (let ((revision (gr8s::pod-store-pod-revision store)))
      (check-core-status 200 "/api/v1/nodes" :method :delete :parameters '(("labelSelector" . "set=one")))
      (is (null (ignore-errors (gr8s::get-node store "api-a"))))
      (is (gr8s::get-node store "api-c"))
      (is (equal '(("DELETED" "api-a") ("DELETED" "api-b")) (node-watch-names (gr8s::node-watch-events store "" "" revision)))))
    (gr8s:register-node store (gr8s:make-node-record :id "a" :name "worker-a" :pod-cidr "10.88.0.0/24"))
    ;; An agent's Node stays, and so does the rest of the selection: nothing happens by halves.
    (check-core-status 409 "/api/v1/nodes" :method :delete)
    (is (gr8s::get-node store "api-c"))
    (is (gr8s::get-node store "worker-a"))))

(test apiservices-watch-follows-custom-resource-versions
  (with-crd-api (store directory)
    (values directory)
    ;; Revision 0 would mean "any", so give the list a real one to resume from.
    (gr8s::create-core-resource store "configmaps" (gr8s::core-object "metadata" (gr8s::core-object "name" "one")) "alpha")
    (let ((collection (crd-api-url "/apis/apiregistration.k8s.io/v1/apiservices"))
          (revision (gethash "resourceVersion" (gethash "metadata" (crd-api-request 200 "/apis/apiregistration.k8s.io/v1/apiservices")))))
      (sb-sys:with-deadline (:seconds 15)
        (multiple-value-bind (stream code)
            (drakma:http-request collection :want-stream t
                                 :parameters `(("watch" . "true") ("resourceVersion" . ,revision) ("timeoutSeconds" . "5")
                                               ("allowWatchBookmarks" . "true")))
          (unwind-protect
               (progn
                 (is (= 200 code))
                 (crd-api-request 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post :object (crd-fixture))
                 (let ((event (read-template-watch-event stream)))
                   (is (equal "ADDED" (gethash "type" event)))
                   (is (equal (gethash "group" (gethash "spec" (crd-fixture)))
                              (gethash "group" (gethash "spec" (gethash "object" event)))))))
            (close stream)))
        ;; That revision is now behind a change nothing recorded, so it must relist.
        (multiple-value-bind (stream code)
            (drakma:http-request collection :want-stream t :parameters `(("watch" . "true") ("resourceVersion" . ,revision) ("timeoutSeconds" . "1")))
          (unwind-protect
               (let ((event (read-template-watch-event stream)))
                 (is (= 200 code))
                 (is (equal "ERROR" (gethash "type" event)))
                 (is (= 410 (gethash "code" (gethash "object" event)))))
            (close stream))))
      (dolist (event (let ((*watch-test-server* (crd-api-url "")))
                       (apply #'collect-watch-stream "/apis/apiregistration.k8s.io/v1/apiservices" (watch-list-parameters))))
        (is (member (gethash "type" event) '("ADDED" "BOOKMARK") :test #'equal))))))

(test rbac-objects-accept-the-colons-upstream-names-use
  (with-core-api (store directory)
    (values store directory)
    (loop with prefix = "/apis/rbac.authorization.k8s.io/v1/"
          for (collection kind) in '(("clusterroles" "ClusterRole") ("clusterrolebindings" "ClusterRoleBinding")
                                     ("namespaces/alpha/roles" "Role") ("namespaces/alpha/rolebindings" "RoleBinding"))
          for name = "wardler:aggregator-1:auth-delegator"
          for object = (gr8s::core-object "apiVersion" "rbac.authorization.k8s.io/v1" "kind" kind
                                          "metadata" (gr8s::core-object "name" name))
          do (if (search "binding" collection)
                 (setf (gethash "roleRef" object)
                       (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole" "name" "system:auth-delegator")
                       (gethash "subjects" object) #())
                 (setf (gethash "rules" object) #()))
             (check-core-status 201 (concatenate 'string prefix collection) :method :post :object object)
             (is (equal name (gethash "name" (gethash "metadata" (check-core-status 200 (format nil "~A~A/~A" prefix collection name))))))
             (check-core-status 200 (format nil "~A~A/~A" prefix collection name) :method :delete))
    ;; Other kinds keep DNS names.
    (check-core-status 422 "/api/v1/namespaces/alpha/configmaps" :method :post
      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "not:dns")))))

(test pods-can-be-bound-once-to-a-node-that-exists
  (with-core-api (store directory)
    (values directory)
    (gr8s:register-node store (gr8s:make-node-record :id "bind-id" :name "bind-node" :pod-cidr "10.88.40.0/24"))
    (let* ((pod (create-pod store (parse-pod *valid-pod-json*)))
           (name (pod-name pod))
           (binding (concatenate 'string "/api/v1/namespaces/default/pods/" name "/binding")))
      (flet ((bind (code node &optional (bound-name name))
               (check-core-status
                code binding :method :post
                :object (gr8s::core-object "apiVersion" "v1" "kind" "Binding"
                                           "metadata" (gr8s::core-object "name" bound-name)
                                           "target" (gr8s::core-object "kind" "Node" "name" node)))))
        (bind 404 "no-such-node")
        (bind 400 "bind-node" "another-pod")
        (is (null (gr8s::pod-node-name (gr8s:get-pod store "default" name))))
        (is (= 201 (gethash "code" (bind 201 "bind-node"))))
        (is (equal "bind-node" (gr8s::pod-node-name (gr8s:get-pod store "default" name))))
        ;; A Pod is bound once.
        (bind 409 "bind-node")))))

(test componentstatuses-are-listed-and-read-only
  (with-core-api (store directory)
    (values store directory)
    (let ((items (gethash "items" (check-core-status 200 "/api/v1/componentstatuses"))))
      (is (equal '("controller-manager" "etcd-0" "scheduler")
                 (map 'list (lambda (item) (gethash "name" (gethash "metadata" item))) items)))
      (is (equal "True" (gethash "status" (aref (gethash "conditions" (aref items 0)) 0)))))
    (is (equal "ComponentStatus" (gethash "kind" (check-core-status 200 "/api/v1/componentstatuses/scheduler"))))
    (check-core-status 404 "/api/v1/componentstatuses/nothing")
    (check-core-status 405 "/api/v1/componentstatuses/scheduler" :method :delete)
    (let ((names (map 'list (lambda (entry) (gethash "name" entry))
                      (gethash "resources" (check-core-status 200 "/api/v1")))))
      (is (member "componentstatuses" names :test #'equal))
      (is (member "pods/binding" names :test #'equal)))))

(test a-chunked-request-body-ends-at-its-last-chunk
  ;; kubectl create --raw -f - chunks what it reads from stdin. The body's read used to
  ;; wait out the connection's 20 second timeout and fail with a 500.
  (with-core-api (store directory)
    (values store directory)
    (let* ((body "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"chunked\"}}")
           (socket (usocket:socket-connect "127.0.0.1" 18089 :element-type '(unsigned-byte 8)))
           (stream (usocket:socket-stream socket)))
      (unwind-protect
           (progn
             (write-sequence
              (trivial-utf-8:string-to-utf-8-bytes
               (format nil "POST /api/v1/namespaces HTTP/1.1~C~CHost: x~C~CContent-Type: application/json~C~CTransfer-Encoding: chunked~C~C~C~C~X~C~C~A~C~C0~C~C~C~C"
                       #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed
                       (length body) #\Return #\Linefeed body #\Return #\Linefeed
                       #\Return #\Linefeed #\Return #\Linefeed))
              stream)
             (finish-output stream)
             (is-true (usocket:wait-for-input socket :timeout 5 :ready-only t) "no answer within 5 seconds")
             (let ((status (gr8s::admission-read-line stream)))
               (is (search " 201 " status) "got ~A" status))
             (is (equal "chunked" (gethash "name" (gethash "metadata" (gr8s::get-core-resource store "namespaces" nil "chunked"))))))
        (usocket:socket-close socket)))))

(test componentstatuses-print-their-health-as-a-table
  (with-core-api (store directory)
    (values store directory)
    (multiple-value-bind (body status)
        (drakma:http-request "http://127.0.0.1:18089/api/v1/componentstatuses"
                             :accept "application/json;as=Table;v=v1;g=meta.k8s.io")
      (is (= 200 status))
      (let* ((table (com.inuoe.jzon:parse (if (stringp body) body (trivial-utf-8:utf-8-bytes-to-string body))))
             (columns (map 'list (lambda (column) (gethash "name" column)) (gethash "columnDefinitions" table)))
             (row (gethash "cells" (aref (gethash "rows" table) 0))))
        (is (equal "Table" (gethash "kind" table)))
        (is (equal '("Name" "Status" "Message" "Error") columns))
        (is (equalp #("controller-manager" "Healthy" "ok" "") row))))))
