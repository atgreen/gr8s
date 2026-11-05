(in-package #:gr8s/tests)
(def-suite core-resource-http :in gr8s)
(in-suite core-resource-http)

(defun core-api-request (path &key (method :get) object octets (content-type "application/json") parameters)
  (multiple-value-bind (body status)
      (drakma:http-request (concatenate 'string "http://127.0.0.1:18089" path)
                           :method method :content-type content-type :parameters parameters
                           :content (or octets (when object (com.inuoe.jzon:stringify object))))
    (values (com.inuoe.jzon:parse body :max-string-length (* 2 1024 1024)) status)))

(defmacro with-core-api ((store path) &body body)
  `(with-temporary-store (,store ,path)
     (let ((server (start-server :address "127.0.0.1" :port 18089 :store ,store :runtime (make-fake-runtime))))
       (unwind-protect (progn ,@body) (stop-server server)))))

(defun check-core-status (expected path &rest options)
  (multiple-value-bind (body status) (apply #'core-api-request path options)
    (is (= expected status) "~A returned ~A: ~A" path status body)
    body))

(test core-resource-http-discovery-and-openapi-advertise-supported-operations
  (with-core-api (store path)
    (values store path)
    (let ((discovery (check-core-status 200 "/api/v1")))
      (dolist (name '("configmaps" "secrets"))
        (let ((resource (find name (gethash "resources" discovery) :test #'equal
                              :key (lambda (object) (gethash "name" object)))))
          (is (hash-table-p resource))
          (is (eq t (gethash "namespaced" resource)))
          (is (equal '("create" "delete" "get" "list" "patch" "update" "watch")
                     (coerce (gethash "verbs" resource) 'list))))))
    (let* ((openapi (check-core-status 200 "/openapi/v3/api/v1"))
           (schemas (gethash "schemas" (gethash "components" openapi))))
      (is (gethash "io.k8s.api.core.v1.ConfigMap" schemas))
      (is (gethash "io.k8s.api.core.v1.Secret" schemas))
      (is (gethash "/api/v1/namespaces/{namespace}/configmaps" (gethash "paths" openapi))))))

(test configmap-http-workflow-preserves-versions-and-namespace-isolation
  (with-core-api (store path)
    (values store path)
    (let* ((collection "/api/v1/namespaces/alpha/configmaps")
           (item "/api/v1/namespaces/alpha/configmaps/settings")
           (original (check-core-status 201 collection :method :post
                       :object (core-fixture "ConfigMap" "settings" "data"
                                             (gr8s::core-object "mode" "first" "remove" "old")))))
      (is (string= "alpha" (gethash "namespace" (gethash "metadata" original))))
      (check-core-status 404 "/api/v1/namespaces/beta/configmaps/settings")
      (let ((patched (check-core-status 200 item :method :patch :content-type "application/merge-patch+json"
                       :object (gr8s::core-object "data" (gr8s::core-object "mode" "second" "remove" 'null)))))
        (is (string= "second" (gethash "mode" (gethash "data" patched))))
        (is (not (nth-value 1 (gethash "remove" (gethash "data" patched))))))
      (check-core-status 409 item :method :put :object original)
      (let ((replacement (check-core-status 200 item)))
        (setf (gethash "mode" (gethash "data" replacement)) "third")
        (check-core-status 200 item :method :put :object replacement))
      (let ((listing (check-core-status 200 "/api/v1/configmaps")))
        (is (string= "ConfigMapList" (gethash "kind" listing)))
        (is (= 1 (length (gethash "items" listing)))))
      (check-core-status 200 item :method :delete
                         :object (gr8s::core-object "preconditions"
                                  (gr8s::core-object "uid" (gethash "uid" (gethash "metadata" original)))))
      (check-core-status 404 item))))

(test secret-http-normalizes-stringdata-and-enforces-delete-preconditions
  (with-core-api (store path)
    (values store path)
    (let* ((collection "/api/v1/namespaces/default/secrets")
           (item "/api/v1/namespaces/default/secrets/passwords")
           (object (check-core-status 201 collection :method :post
                     :object (core-fixture "Secret" "passwords" "stringData" (gr8s::core-object "password" "first"))))
           (uid (gethash "uid" (gethash "metadata" object))))
      (is (string= "Zmlyc3Q=" (gethash "password" (gethash "data" object))))
      (is (not (nth-value 1 (gethash "stringData" object))))
      (let ((patched (check-core-status 200 item :method :patch :content-type "application/strategic-merge-patch+json"
                       :object (gr8s::core-object "stringData" (gr8s::core-object "password" "second")))))
        (is (string= "c2Vjb25k" (gethash "password" (gethash "data" patched)))))
      (check-core-status 409 item :method :delete :object
                         (gr8s::core-object "preconditions" (gr8s::core-object "uid" "not-the-secret")))
      (check-core-status 200 item :method :delete)
      (check-core-status 201 collection :method :post :object (core-fixture "Secret" "passwords"))
      (check-core-status 409 item :method :delete :object
                         (gr8s::core-object "preconditions" (gr8s::core-object "uid" uid))))))

(test core-resource-http-selectors-pagination-and-expiration
  (with-core-api (store path)
    (values path)
    (loop for name in '("alpha" "beta" "gamma")
          do (let ((object (core-fixture "ConfigMap" name)))
               (setf (gethash "labels" (gethash "metadata" object)) (gr8s::core-object "app" "test"))
               (gr8s::create-core-resource store "configmaps" object "default")))
    (let* ((collection "/api/v1/namespaces/default/configmaps")
           (page (check-core-status 200 collection :parameters '(("limit" . "1") ("labelSelector" . "app in (test,other)"))))
           (continuation (gethash "continue" (gethash "metadata" page)))
           (parameters `(("limit" . "1") ("labelSelector" . "app in (test,other)") ("continue" . ,continuation))))
      (is (= 1 (length (gethash "items" page))))
      (is (plusp (length continuation)))
      (let* ((next (check-core-status 200 collection :parameters parameters))
             (item (aref (gethash "items" next) 0)))
        (is (string= "beta" (gethash "name" (gethash "metadata" item)))))
      (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "delta") "default")
      (let ((page (check-core-status 200 collection :parameters parameters)))
        (is (equal "beta" (gethash "name" (gethash "metadata" (aref (gethash "items" page) 0))))))
      (let ((filtered (check-core-status 200 collection :parameters '(("fieldSelector" . "metadata.name=gamma")))))
        (is (= 1 (length (gethash "items" filtered)))))
      (check-core-status 400 collection :parameters '(("watch" . "true") ("resourceVersion" . "invalid")))
      (check-core-status 400 collection :parameters '(("fieldSelector" . "data.key=x"))))))

(test core-resource-json-patch-tests-values-case-sensitively-and-atomically
  (with-core-api (store path)
    (values path)
    (gr8s::create-core-resource store "configmaps"
                               (core-fixture "ConfigMap" "settings" "data" (gr8s::core-object "value" "lower")) "default")
    (let ((item "/api/v1/namespaces/default/configmaps/settings"))
      (check-core-status 409 item :method :patch :content-type "application/json-patch+json"
                         :object (vector (gr8s::core-object "op" "replace" "path" "/data/value" "value" "changed")
                                         (gr8s::core-object "op" "test" "path" "/data/value" "value" "CHANGED")))
      (is (string= "lower" (gethash "value" (gethash "data" (check-core-status 200 item)))))
      (check-core-status 200 item :method :patch :content-type "application/json-patch+json"
                         :object (vector (gr8s::core-object "op" "test" "path" "/data/value" "value" "lower")
                                         (gr8s::core-object "op" "add" "path" "/metadata/annotations" "value" (gr8s::core-object))
                                         (gr8s::core-object "op" "add" "path" "/metadata/annotations/test.io~1key" "value" "yes")))
      (let ((annotations (gethash "annotations" (gethash "metadata" (check-core-status 200 item)))))
        (is (string= "yes" (gethash "test.io/key" annotations)))))))

(test core-resource-http-dryrun-and-error-shapes
  (with-core-api (store path)
    (values store path)
    (let ((collection "/api/v1/namespaces/default/configmaps")
          (item "/api/v1/namespaces/default/configmaps/dry"))
      (check-core-status 201 (concatenate 'string collection "?dryRun=All")
                         :method :post :object (core-fixture "ConfigMap" "dry"))
      (check-core-status 404 item)
      (check-core-status 201 collection :method :post :object (core-fixture "ConfigMap" "dry"))
      (check-core-status 200 (concatenate 'string item "?dryRun=All") :method :delete)
      (check-core-status 200 item :method :delete :object (gr8s::core-object "dryRun" #( "All")))
      (check-core-status 200 item)
      (let ((body (check-core-status 400 item :method :patch :content-type "application/apply-patch+yaml"
                                    :object (core-fixture "ConfigMap" "dry"))))
        (is (string= "Status" (gethash "kind" body)))
        (is (string= "Failure" (gethash "status" body)))
        (is (search "fieldManager is required" (gethash "message" body))))
      (let ((wrong (core-fixture "ConfigMap" "wrong")))
        (setf (gethash "namespace" (gethash "metadata" wrong)) "other")
        (check-core-status 400 collection :method :post :object wrong)))))

(test core-resource-http-accepts-kubernetes-protobuf-and-honors-binary-delete-dryrun
  (with-core-api (store path)
    (values store path)
    (let* ((metadata (core-test-protobuf '((1 "binary") (3 "default"))))
           (entry (core-test-protobuf '((1 "mode") (2 "protobuf"))))
           (input (core-test-protobuf-envelope "ConfigMap" (list (list 1 metadata) (list 2 entry))))
           (item "/api/v1/namespaces/default/configmaps/binary"))
      (let ((created (check-core-status 201 "/api/v1/namespaces/default/configmaps"
                                       :method :post :content-type "application/vnd.kubernetes.protobuf" :octets input)))
        (is (string= "protobuf" (gethash "mode" (gethash "data" created)))))
      (check-core-status 200 item :method :delete :content-type "application/vnd.kubernetes.protobuf"
                         :octets (core-test-protobuf-envelope "DeleteOptions" '((5 "All"))))
      (check-core-status 200 item)
      (check-core-status 400 item :method :delete :content-type "application/vnd.kubernetes.protobuf"
                         :octets (subseq input 0 5))
      (check-core-status 200 item))))

(test namespace-http-accepts-upstream-protobuf-with-generate-name
  (with-core-api (store path)
    (values store path)
    (let* ((label (core-test-protobuf '((1 "pod-security.kubernetes.io/enforce") (2 "privileged"))))
           (metadata (core-test-protobuf (list (list 2 "e2e-framework-") (list 11 label))))
           (input (core-test-protobuf-envelope "Namespace"
                    (list (list 1 metadata) (list 2 (core-test-protobuf nil))
                          (list 3 (core-test-protobuf nil)))))
           (created (check-core-status 201 "/api/v1/namespaces" :method :post
                      :content-type "application/vnd.kubernetes.protobuf" :octets input))
           (name (gethash "name" (gethash "metadata" created))))
      (is (uiop:string-prefix-p "e2e-framework-" name))
      (is (equal "Active" (gethash "phase" (gethash "status" created))))
      (check-core-status 200 (concatenate 'string "/api/v1/namespaces/" name)))))

(in-suite core-resource-http)

(test pod-http-accepts-typed-protobuf-with-go-zero-values
  (with-core-api (store path)
    (values path)
    (let* ((field-ref (core-test-protobuf '((1 "v1") (2 "metadata.name"))))
           (from (core-test-protobuf (list (list 1 field-ref))))
           (env (core-test-protobuf (list (list 1 "POD_NAME") (list 2 "") (list 3 from))))
           (container (core-test-protobuf (list (list 1 "main") (list 2 "web:v1")
                                               (list 3 "echo") (list 4 "") (list 5 "")
                                               (list 7 env) (list 8 #()) (list 13 "")
                                               (list 14 "") (list 16 0) (list 17 0) (list 18 0) (list 20 ""))))
           (spec (core-test-protobuf (list (list 2 container) (list 3 "") (list 6 "")
                                          (list 8 "") (list 9 "") (list 10 "")
                                          (list 11 0) (list 12 0) (list 13 0)
                                          (list 16 "") (list 17 "") (list 19 ""))))
           (input (core-test-protobuf-envelope "Pod" (list (list 1 (core-test-protobuf '((1 "wire-pod"))))
                                                           (list 2 spec) (list 3 #()))))
           (created (check-core-status 201 "/api/v1/namespaces/alpha/pods" :method :post
                        :content-type "application/vnd.kubernetes.protobuf" :octets input))
           (actual (gethash "spec" created))
           (main (aref (gethash "containers" actual) 0)))
      (is (equal "alpha" (gethash "namespace" (gethash "metadata" created))))
      (is (equal "wire-pod" (gethash "name" (gethash "metadata" created))))
      (is (equalp #("echo") (gethash "command" main)))
      (is (equalp #("" ) (gethash "args" main)))
      (is (equal "metadata.name" (gethash "fieldPath" (gethash "fieldRef" (gethash "valueFrom" (aref (gethash "env" main) 0))))))
      (is (= 1 (length (list-pods store "alpha"))))
      (check-core-status 400 "/api/v1/namespaces/alpha/pods" :method :post
                         :content-type "application/vnd.kubernetes.protobuf" :octets (subseq input 0 (1- (length input))))
      (check-core-status 400 "/api/v1/namespaces/alpha/pods" :method :post
                         :content-type "application/vnd.kubernetes.protobuf"
                         :octets (core-test-protobuf-envelope "ConfigMap" (list (list 1 #()))))
      (check-core-status 415 "/api/v1/namespaces/alpha/pods" :method :post
                         :content-type "text/plain" :octets input))))

(test pod-protobuf-retains-explicit-pointer-zero-and-unsupported-features
  (let* ((container (core-test-protobuf '((1 "main") (2 "web:v1"))))
         (spec (core-test-protobuf (list (list 2 container) (list 21 0) (list 11 1) (list 27 1))))
         (input (core-test-protobuf-envelope "Pod" (list (list 1 (core-test-protobuf '((1 "unsupported")))) (list 2 spec))))
         (decoded (gr8s::decode-core-resource-protobuf input "Pod")))
    (is (not (null (nth-value 1 (gethash "automountServiceAccountToken" (gethash "spec" decoded))))))
    (is (null (gethash "automountServiceAccountToken" (gethash "spec" decoded))))
    (is (eq t (gethash "hostNetwork" (gethash "spec" decoded))))
    (with-core-api (store path)
      (values path)
      (check-core-status 422 "/api/v1/namespaces/alpha/pods" :method :post
                         :content-type "application/vnd.kubernetes.protobuf" :octets input)
      (is (null (list-pods store "alpha"))))))

(defun service-wire-fixture (name &key (target 0) (type ""))
  "Return a Kubernetes typed Service with Go's serialized zero fields."
  (let* ((target-message (core-test-protobuf (if (stringp target)
                                              (list (list 1 1) (list 2 0) (list 3 target))
                                              (list (list 1 0) (list 2 target) (list 3 "")))))
         (port (core-test-protobuf (list (list 1 "") (list 2 "") (list 3 8080) (list 4 target-message) (list 5 0))))
         (selector (core-test-protobuf '((1 "app") (2 ""))))
         (spec (core-test-protobuf (list (list 1 port) (list 2 selector) (list 3 "")
                                        (list 4 type) (list 7 "") (list 8 "") (list 10 "")
                                        (list 11 "") (list 12 0) (list 13 0))))
         (metadata (core-test-protobuf (list (list 1 name)))))
    (core-test-protobuf-envelope "Service" (list (list 1 metadata) (list 2 spec) (list 3 #())))))

(test service-http-accepts-typed-protobuf-with-allocation-and-port-defaults
  (with-core-api (store path)
    (values path)
    (let* ((input (service-wire-fixture "wire-service"))
           (created (check-core-status 201 "/api/v1/namespaces/alpha/services" :method :post
                                      :content-type "application/vnd.kubernetes.protobuf" :octets input))
           (actual (gethash "spec" created))
           (port (aref (gethash "ports" actual) 0)))
      (is (equal "ClusterIP" (gethash "type" actual)))
      (is (equal "None" (gethash "sessionAffinity" actual)))
      (is (equal "" (gethash "app" (gethash "selector" actual))))
      (is (not (null (gr8s::service-ip-index (gethash "clusterIP" actual)))))
      (is (= 8080 (gethash "targetPort" port)))
      (is (equal "TCP" (gethash "protocol" port)))
      (is (= 1 (length (gr8s::list-core-resources store "services" "alpha"))))
      (check-core-status 400 "/api/v1/namespaces/alpha/services" :method :post
                         :content-type "application/vnd.kubernetes.protobuf" :octets (subseq input 0 5)))))

(test service-protobuf-retains-named-targets-and-unsupported-types
  (with-core-api (store path)
    (values path)
    (let* ((input (service-wire-fixture "named-service" :target "http"))
           (created (check-core-status 201 "/api/v1/namespaces/alpha/services" :method :post
                                      :content-type "application/vnd.kubernetes.protobuf" :octets input))
           (port (aref (gethash "ports" (gethash "spec" created)) 0)))
      (is (equal "http" (gethash "targetPort" port)))
      (check-core-status 422 "/api/v1/namespaces/alpha/services" :method :post
                         :content-type "application/vnd.kubernetes.protobuf"
                         :octets (service-wire-fixture "nodeport" :type "NodePort"))
      (is (= 1 (length (gr8s::list-core-resources store "services" "alpha")))))))

(in-suite gr8s)
