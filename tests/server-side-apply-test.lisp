;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify server-side apply, field validation diagnostics, aggregated discovery,
;;;; Table negotiation and the published OpenAPI of custom resources over HTTP.

(in-package #:gr8s/tests)
(def-suite server-side-apply :in gr8s)
(in-suite server-side-apply)

(defun apply-crd-fixture (schema &key (plural "foos") (kind "Foo"))
  "Build a cluster-scoped definition with SCHEMA, as upstream's field validation tests do."
  (gr8s::core-object "apiVersion" "apiextensions.k8s.io/v1" "kind" "CustomResourceDefinition"
    "metadata" (gr8s::core-object "name" (format nil "~A.mygroup.example.com" plural))
    "spec" (gr8s::core-object "group" "mygroup.example.com" "scope" "Cluster"
             "names" (gr8s::core-object "plural" plural "kind" kind)
             "versions" (vector (gr8s::core-object "name" "v1" "served" t "storage" t
                                  "schema" (gr8s::core-object "openAPIV3Schema" schema))))))

(defun apply-schema-from-json (text)
  "Parse a schema literal."
  (com.inuoe.jzon:parse text))

(defparameter *apply-test-schema*
  "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"properties\":{
     \"foo\":{\"type\":\"string\"},\"bar\":{\"type\":\"string\"},
     \"bars\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"required\":[\"name\"],\"properties\":{
        \"name\":{\"type\":\"string\"},\"feeling\":{\"type\":\"string\",\"enum\":[\"Great\",\"Down\"]}}}}}}}}")

(defun apply-request (expected path text &key (manager "mgr") (validation "Strict") force)
  "Send an apply patch and assert its status, returning the decoded body."
  (multiple-value-bind (body status headers)
      (drakma:http-request (concatenate 'string "http://127.0.0.1:18094" path) :method :patch
                           :content-type "application/apply-patch+yaml" :content text
                           :parameters (append (when manager (list (cons "fieldManager" manager)))
                                               (when validation (list (cons "fieldValidation" validation)))
                                               (when force (list (cons "force" "true")))))
    (declare (ignorable headers))
    (let ((text (if (stringp body) body (babel:octets-to-string body))))
      (is (= expected status) "~A returned ~A: ~A" path status text)
      (com.inuoe.jzon:parse text))))

(defun apply-document (name &rest spec-lines)
  "Render an applied configuration whose spec has SPEC-LINES."
  (format nil "apiVersion: mygroup.example.com/v1~%kind: Foo~%metadata:~%  name: ~A~%spec:~%~{  ~A~%~}" name spec-lines))

(defun install-apply-crd (schema)
  "Create the test definition from a schema literal."
  (crd-api-request 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post
                   :object (apply-crd-fixture (apply-schema-from-json schema))))

(defun applied-spec (object)
  "Read the spec of a decoded object."
  (gethash "spec" object))

(test apply-creates-updates-and-prunes-what-a-manager-stops-declaring
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd *apply-test-schema*)
    (let* ((item "/apis/mygroup.example.com/v1/foos/one")
           (created (apply-request 201 item (apply-document "one" "foo: a" "bar: b")))
           (entry (aref (gethash "managedFields" (gethash "metadata" created)) 0)))
      (is (equal "a" (gethash "foo" (applied-spec created))))
      (is (equal "mgr" (gethash "manager" entry)))
      (is (equal "Apply" (gethash "operation" entry)))
      (is (equal "FieldsV1" (gethash "fieldsType" entry)))
      (is (hash-table-p (gethash "f:foo" (gethash "f:spec" (gethash "fieldsV1" entry)))))
      (let ((updated (apply-request 200 item (apply-document "one" "foo: c"))))
        (is (equal "c" (gethash "foo" (applied-spec updated))))
        (is (not (nth-value 1 (gethash "bar" (applied-spec updated))))))
      (is (equal "c" (gethash "foo" (applied-spec (crd-api-request 200 item))))))))

(test apply-reports-conflicts-between-managers-until-forced
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd *apply-test-schema*)
    (let ((item "/apis/mygroup.example.com/v1/foos/one"))
      (apply-request 201 item (apply-document "one" "foo: a"))
      (let ((conflict (apply-request 409 item (apply-document "one" "foo: b") :manager "other")))
        (is (equal "Conflict" (gethash "reason" conflict)))
        (is (search "conflict with \"mgr\": .spec.foo" (gethash "message" conflict)))
        (is (equal ".spec.foo" (gethash "field" (aref (gethash "causes" (gethash "details" conflict)) 0)))))
      ;; Agreeing on a value shares ownership, and a field another manager holds survives.
      (let ((shared (apply-request 200 item (apply-document "one" "foo: a" "bar: z") :manager "other")))
        (is (= 2 (length (gethash "managedFields" (gethash "metadata" shared))))))
      (is (equal "a" (gethash "foo" (applied-spec (apply-request 200 item (apply-document "one" "bar: z"))))))
      (let ((forced (apply-request 200 item (apply-document "one" "foo: d" "bar: z") :manager "other" :force t)))
        (is (equal "d" (gethash "foo" (applied-spec forced))))))))

(test apply-requires-a-manager-and-a-matching-name
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd *apply-test-schema*)
    (let ((item "/apis/mygroup.example.com/v1/foos/one"))
      (is (search "fieldManager is required" (gethash "message" (apply-request 400 item (apply-document "one") :manager nil))))
      (is (search "does not match the name" (gethash "message" (apply-request 400 item (apply-document "two"))))))))

(test apply-rejects-undeclared-custom-fields-with-upstream-paths
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd *apply-test-schema*)
    (let ((item "/apis/mygroup.example.com/v1/foos/one"))
      (is (search ".unknownField: field not declared in schema"
                  (gethash "message" (apply-request 400 item (format nil "apiVersion: mygroup.example.com/v1~%kind: Foo~%metadata:~%  name: one~%unknownField: x~%")))))
      (is (search ".metadata.unknownMeta: field not declared in schema"
                  (gethash "message" (apply-request 400 item (format nil "apiVersion: mygroup.example.com/v1~%kind: Foo~%metadata:~%  name: one~%  unknownMeta: x~%")))))
      (is (search ".spec.nope: field not declared in schema"
                  (gethash "message" (apply-request 400 item (apply-document "one" "nope: x"))))))))

(test apply-checks-embedded-metadata-inside-preserved-objects
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-preserve-unknown-fields\":true,\"properties\":{\"template\":{\"type\":\"object\",\"x-kubernetes-embedded-resource\":true,\"properties\":{\"spec\":{\"type\":\"object\"}}}}}}}")
    (let ((item "/apis/mygroup.example.com/v1/foos/one"))
      (is (search ".spec.template.metadata.unknownSubMeta: field not declared in schema"
                  (gethash "message" (apply-request 400 item (apply-document "one" "template:" "  apiVersion: foo/v1" "  kind: Sub" "  metadata:" "    unknownSubMeta: x" "    name: sub")))))
      ;; Fields the schema preserves are stored as given.
      (is (equal "kept" (gethash "free" (applied-spec (apply-request 201 item (apply-document "one" "free: kept")))))))))

(test apply-honors-strict-duplicate-keys-only-when-strict
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd *apply-test-schema*)
    (let ((item "/apis/mygroup.example.com/v1/foos/one")
          (text (format nil "~%apiVersion: mygroup.example.com/v1~%kind: Foo~%metadata:~%  name: one~%spec:~%  bar: b~%  foo: foo1~%  foo: foo2~%")))
      (is (search "line 9: key \"foo\" already set in map" (gethash "message" (apply-request 400 item text))))
      (is (equal "foo2" (gethash "foo" (applied-spec (apply-request 201 item text :validation "Warn"))))))))

(test apply-works-on-typed-resources
  (with-crd-api (store path)
    (values store path)
    (let* ((item "/api/v1/namespaces/default/configmaps/one")
           (document (lambda (data) (format nil "apiVersion: v1~%kind: ConfigMap~%metadata:~%  name: one~%  labels:~%    app: x~%data:~%  ~A~%" data)))
           (created (apply-request 201 item (funcall document "a: \"1\""))))
      (is (equal "1" (gethash "a" (gethash "data" created))))
      (is (= 1 (length (gethash "managedFields" (gethash "metadata" created)))))
      (let ((updated (apply-request 200 item (funcall document "b: \"2\""))))
        (is (equal "2" (gethash "b" (gethash "data" updated))))
        (is (not (nth-value 1 (gethash "a" (gethash "data" updated))))))
      (is (equal "x" (gethash "app" (gethash "labels" (gethash "metadata" (crd-api-request 200 item)))))))))

(test apply-rejects-undeclared-typed-fields
  (with-crd-api (store path)
    (values store path)
    (let ((item "/apis/apps/v1/namespaces/default/deployments/one"))
      (is (search ".spec.nope: field not declared in schema"
                  (gethash "message" (apply-request 400 item (format nil "apiVersion: apps/v1~%kind: Deployment~%metadata:~%  name: one~%spec:~%  nope: 1~%"))))))))

(defun deployment-json (&key (metadata-extra "") (spec-extra ""))
  "Render a Deployment literal, leaving room for repeated and unknown keys."
  (format nil "{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"metadata\":{\"name\":\"my-dep\",~A\"labels\":{\"app\":\"nginx\"}},\"spec\":{~A\"replicas\":2,\"selector\":{\"matchLabels\":{\"app\":\"nginx\"}},\"template\":{\"metadata\":{\"labels\":{\"app\":\"nginx\"}},\"spec\":{\"containers\":[{\"name\":\"nginx\",\"image\":\"nginx:latest\"}]}}}}"
          metadata-extra spec-extra))

(test typed-strict-validation-reports-unknown-and-duplicate-fields
  (with-crd-api (store path)
    (values store path)
    (let ((collection "/apis/apps/v1/namespaces/default/deployments"))
      (is (search "strict decoding error: unknown field \"spec.unknownField\", duplicate field \"spec.replicas\""
                  (gethash "message" (crd-api-request 400 collection :method :post :parameters '(("fieldValidation" . "Strict"))
                    :text (deployment-json :spec-extra "\"unknownField\":\"foo\",\"replicas\":3,")))))
      (is (search "strict decoding error: unknown field \"metadata.unknownMeta\""
                  (gethash "message" (crd-api-request 400 collection :method :post :parameters '(("fieldValidation" . "Strict"))
                    :text (deployment-json :metadata-extra "\"unknownMeta\":\"foo\",")))))
      ;; Without Strict the field is dropped and the object still admitted.
      (let ((created (crd-api-request 201 collection :method :post :parameters '(("fieldValidation" . "Ignore"))
                       :text (deployment-json :spec-extra "\"unknownField\":\"foo\","))))
        (is (not (nth-value 1 (gethash "unknownField" (gethash "spec" created)))))))))

(test custom-resource-diagnostics-name-fields-as-upstream-does
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd *apply-test-schema*)
    (let ((collection "/apis/mygroup.example.com/v1/foos"))
      (flet ((message (expected spec)
               (gethash "message"
                        (crd-api-request expected collection :method :post :parameters '(("fieldValidation" . "Strict"))
                          :text (format nil "{\"apiVersion\":\"mygroup.example.com/v1\",\"kind\":\"Foo\",\"metadata\":{\"name\":\"bad\"},\"spec\":~A}" spec)))))
        (is (search "unknown field \"spec.foo2\"" (message 400 "{\"foo2\":true}")))
        (is (search "spec.bars[0].name: Required value" (message 422 "{\"bars\":[{\"feeling\":\"Great\"}]}")))
        (is (search "Unsupported value: \"Nope\"" (message 422 "{\"bars\":[{\"name\":\"a\",\"feeling\":\"Nope\"}]}")))))))

(test discovery-routes-accept-a-trailing-slash
  (with-crd-api (store path)
    (values store path)
    (is (equal "APIVersions" (gethash "kind" (crd-api-request 200 "/api/"))))
    (is (equal "APIGroupList" (gethash "kind" (crd-api-request 200 "/apis/"))))
    (is (equal "apps" (gethash "name" (crd-api-request 200 "/apis/apps/"))))))

(defun aggregated-request (path)
  "Request PATH's aggregated discovery form, returning the document and Content-Type."
  (multiple-value-bind (body status headers)
      (drakma:http-request (concatenate 'string "http://127.0.0.1:18094" path)
                           :accept "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,application/json")
    (is (= 200 status))
    (values (com.inuoe.jzon:parse (if (stringp body) body (babel:octets-to-string body)))
            (cdr (assoc :content-type headers)))))

(defun aggregated-item (document name)
  "Find a group entry of an aggregated document."
  (find name (gethash "items" document) :test #'equal
        :key (lambda (item) (gethash "name" (gethash "metadata" item) ""))))

(test aggregated-discovery-describes-builtin-and-custom-resources
  (with-crd-api (store path)
    (values store path)
    (multiple-value-bind (legacy content-type) (aggregated-request "/api")
      (is (equal "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList" content-type))
      (is (equal "APIGroupDiscoveryList" (gethash "kind" legacy)))
      (let* ((version (aref (gethash "versions" (aggregated-item legacy "")) 0))
             (namespaces (find "namespaces" (gethash "resources" version) :test #'equal :key (lambda (r) (gethash "resource" r))))
             (pods (find "pods" (gethash "resources" version) :test #'equal :key (lambda (r) (gethash "resource" r)))))
        (is (equal "v1" (gethash "version" version)))
        (is (equal "Cluster" (gethash "scope" namespaces)))
        (is (equal "Namespaced" (gethash "scope" pods)))
        (is (find "status" (gethash "subresources" pods) :test #'equal :key (lambda (r) (gethash "subresource" r))))))
    (install-apply-crd *apply-test-schema*)
    (let* ((document (aggregated-request "/apis"))
           (custom (aggregated-item document "mygroup.example.com"))
           (resource (aref (gethash "resources" (aref (gethash "versions" custom) 0)) 0)))
      (is (equal "foos" (gethash "resource" resource)))
      (is (equal "Foo" (gethash "kind" (gethash "responseKind" resource))))
      (is (aggregated-item document "apps")))
    ;; A client that did not ask keeps the legacy document.
    (is (equal "APIGroupList" (gethash "kind" (crd-api-request 200 "/apis"))))))

(test table-only-clients-are-told-what-is-acceptable
  (with-crd-api (store path)
    (values store path)
    (multiple-value-bind (body status)
        (drakma:http-request "http://127.0.0.1:18094/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
                             :method :post :content-type "application/json"
                             :content "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectAccessReview\",\"spec\":{\"nonResourceAttributes\":{\"path\":\"/\",\"verb\":\"get\"}}}"
                             :accept "application/json;as=Table;v=v1;g=meta.k8s.io")
      (is (= 406 status))
      (is (equal "NotAcceptable" (gethash "reason" (com.inuoe.jzon:parse (if (stringp body) body (babel:octets-to-string body)))))))
    ;; kubectl offers a fallback alongside Table and must not be refused.
    (multiple-value-bind (body status)
        (drakma:http-request "http://127.0.0.1:18094/api/v1/namespaces"
                             :accept "application/json;as=Table;v=v1;g=meta.k8s.io,application/json")
      (declare (ignore body))
      (is (= 200 status)))))

(test custom-kinds-publish-under-rest-friendly-names-with-upstream-shapes
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd "{\"type\":\"object\",\"description\":\"Foo\",\"properties\":{\"spec\":{\"type\":\"object\",\"description\":\"Spec\",\"properties\":{\"free\":{\"type\":\"object\",\"x-kubernetes-preserve-unknown-fields\":true,\"properties\":{\"a\":{\"type\":\"string\"}}}}}}}")
    (crd-api-request 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post
      :object (apply-crd-fixture (apply-schema-from-json "{\"type\":\"object\",\"x-kubernetes-preserve-unknown-fields\":true}") :plural "opens" :kind "Open"))
    (let* ((v2 (crd-api-request 200 "/openapi/v2"))
           (definitions (gethash "definitions" v2))
           (foo (gethash "com.example.mygroup.v1.Foo" definitions))
           (open (gethash "com.example.mygroup.v1.Open" definitions)))
      (is (hash-table-p foo))
      (is (equal "Foo" (gethash "description" foo)))
      (let ((properties (gethash "properties" foo)))
        (is (search "APIVersion defines" (gethash "description" (gethash "apiVersion" properties))))
        (is (search "Standard object's metadata" (gethash "description" (gethash "metadata" properties))))
        (is (gethash "$ref" (gethash "metadata" properties)))
        (let ((free (gethash "free" (gethash "properties" (gethash "spec" properties)))))
          (is (not (nth-value 1 (gethash "type" free))))
          (is (not (nth-value 1 (gethash "properties" free))))))
      ;; An object preserving unknown fields at its root publishes no properties in v2.
      (is (equal "object" (gethash "type" open)))
      (is (not (nth-value 1 (gethash "properties" open))))
      (is (gethash "x-kubernetes-group-version-kind" open)))
    (let* ((v3 (crd-api-request 200 "/openapi/v3/apis/mygroup.example.com/v1"))
           (schemas (gethash "schemas" (gethash "components" v3)))
           (open (gethash "com.example.mygroup.v1.Open" schemas))
           (meta (gethash "properties" (gethash "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta" schemas))))
      (is (gethash "x-kubernetes-preserve-unknown-fields" open))
      (is (gethash "allOf" (gethash "metadata" (gethash "properties" open))))
      (is (search "CreationTimestamp is a timestamp" (gethash "description" (gethash "creationTimestamp" meta)))))))

(test watch-events-read-the-journal-after-a-revision
  (with-temporary-store (store path)
    (values path)
    (let ((created (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "one") "default")))
      (declare (ignorable created))
      (let ((revision (gr8s::pod-store-resource-revision store)))
        ;; An idle watch sees nothing at the current revision.
        (multiple-value-bind (events watermark) (gr8s::template-watch-events store "default" "" "" revision :resource "configmaps")
          (is (null events))
          (is (= revision watermark)))
        (gr8s::create-core-resource store "configmaps" (core-fixture "ConfigMap" "two") "default")
        (gr8s::delete-core-resource store "configmaps" "default" "one")
        (multiple-value-bind (events watermark) (gr8s::template-watch-events store "default" "" "" revision :resource "configmaps")
          (is (equal '("ADDED" "DELETED") (mapcar (lambda (event) (gethash "type" event)) events)))
          (is (= watermark (gr8s::pod-store-resource-revision store))))
        ;; A journal read without recent entries, as after a restart, finds the same events.
        (setf (gr8s::pod-store-template-history-recent store) nil)
        (is (= 2 (length (gr8s::template-watch-events store "default" "" "" revision :resource "configmaps"))))
        ;; Revisions beyond the store and compacted ones still fail.
        (signals gr8s::kubernetes-error
          (gr8s::template-watch-events store "default" "" "" (+ 5 (gr8s::pod-store-resource-revision store)) :resource "configmaps"))
        (setf (gr8s::pod-store-template-history-floor store) revision)
        (signals gr8s::kubernetes-error
          (gr8s::template-watch-events store "default" "" "" (1- revision) :resource "configmaps"))))))

(test api-server-outlasts-more-open-watches-than-hunchentoots-default
  (with-crd-api (store path)
    (values store path)
    (let ((acceptors (list (make-instance 'gr8s::gr8s-acceptor :address "127.0.0.1" :port 0))))
      (dolist (acceptor acceptors)
        (is (<= 1000 (hunchentoot::taskmaster-max-thread-count (hunchentoot::acceptor-taskmaster acceptor))))))))

(defun openapi-v3-patch-for-kind (document kind)
  "Find a patch operation for KIND in a document's paths, as kubectl's verifier does."
  (loop for item being the hash-values of (gethash "paths" document)
        for patch = (gethash "patch" item)
        when (and patch (equal kind (gethash "kind" (gethash "x-kubernetes-group-version-kind" patch))))
          return patch))

(test every-patchable-resource-tells-kubectl-it-validates-fields
  (with-crd-api (store path)
    (values store path)
    (let ((urls (gethash "paths" (crd-api-request 200 "/openapi/v3"))))
      (dolist (entry '(("api/v1" "Service") ("api/v1" "Namespace") ("api/v1" "ServiceAccount")
                       ("apis/apps/v1" "Deployment") ("apis/batch/v1" "Job")))
        (is (gethash (first entry) urls) "~A is not advertised" (first entry))
        (let* ((document (crd-api-request 200 (format nil "/openapi/v3/~A" (first entry))))
               (patch (openapi-v3-patch-for-kind document (second entry))))
          (is (hash-table-p patch) "~A has no patch operation" (second entry))
          (when patch
            (is (find "fieldValidation" (gethash "parameters" patch) :test #'equal
                      :key (lambda (parameter) (gethash "name" parameter))))))))
    ;; Paths that discovery does not back are still absent.
    (crd-api-request 404 "/openapi/v3/apis/none.example.com/v1")))

(defparameter *field-validation-spec-schema*
  "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-preserve-unknown-fields\":true,\"properties\":{
     \"foo\":{\"type\":\"string\"},
     \"cronSpec\":{\"type\":\"string\",\"pattern\":\"^(\\\\d+|\\\\*)(/\\\\d+)?(\\\\s+(\\\\d+|\\\\*)(/\\\\d+)?){4}$\"},
     \"ports\":{\"type\":\"array\",\"x-kubernetes-list-map-keys\":[\"containerPort\",\"protocol\"],\"x-kubernetes-list-type\":\"map\",
       \"items\":{\"type\":\"object\",\"required\":[\"containerPort\",\"protocol\"],\"properties\":{
         \"containerPort\":{\"format\":\"int32\",\"type\":\"integer\"},\"hostIP\":{\"type\":\"string\"},
         \"hostPort\":{\"format\":\"int32\",\"type\":\"integer\"},\"name\":{\"type\":\"string\"},\"protocol\":{\"type\":\"string\"}}}}}}}}"
  "The schema of upstream's field validation specs.")

(test upstream-field-validation-flow-against-its-own-schema
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd *field-validation-spec-schema*)
    ;; The instance upstream creates and deletes to prime its watch cache.
    (let ((collection "/apis/mygroup.example.com/v1/foos"))
      (crd-api-request 201 collection :method :post
        :text "{\"apiVersion\":\"mygroup.example.com/v1\",\"kind\":\"Foo\",\"metadata\":{\"namespace\":\"\",\"name\":\"setup-instance\"},\"alpha\":\"foo_123\",\"beta\":10,\"gamma\":\"bar\",\"delta\":\"hello\",\"epsilon\":\"foobar\",\"spec\":{}}")
      (crd-api-request 200 (concatenate 'string collection "/setup-instance") :method :delete))
    (let* ((item "/apis/mygroup.example.com/v1/foos/mytest")
           (created (apply-request 201 item (format nil "~%apiVersion: mygroup.example.com/v1~%kind: Foo~%metadata:~%  name: mytest~%spec:~%  foo: foo1~%  cronSpec: \"* * * * */5\"~%  ports:~%  - name: x~%    containerPort: 80~%    protocol: TCP"))))
      (is (= 80 (gethash "containerPort" (aref (gethash "ports" (applied-spec created)) 0)))))))

(test a-body-without-a-content-type-is-read-as-json
  ;; client-go sends raw byte bodies with no Content-Type header at all.
  (with-crd-api (store path)
    (values store path)
    (install-apply-crd *apply-test-schema*)
    (let ((text "{\"apiVersion\":\"mygroup.example.com/v1\",\"kind\":\"Foo\",\"metadata\":{\"name\":\"bare\"}}"))
      (multiple-value-bind (body status)
          (drakma:http-request "http://127.0.0.1:18094/apis/mygroup.example.com/v1/foos" :method :post
                               :content text :content-type nil)
        (declare (ignore body))
        (is (= 201 status))))
    (multiple-value-bind (body status)
        (drakma:http-request "http://127.0.0.1:18094/apis/apps/v1/namespaces/default/deployments?fieldValidation=Strict"
                             :method :post :content-type nil
                             :content (deployment-json :metadata-extra "\"unknownMeta\":\"foo\","))
      (is (= 400 status))
      (is (search "metadata.unknownMeta" (if (stringp body) body (babel:octets-to-string body)))))))

(defun hpa-fixture (version &rest spec-fields)
  "Build an autoscaler in VERSION with SPEC-FIELDS after its required target."
  (gr8s::core-object "apiVersion" version "kind" "HorizontalPodAutoscaler"
    "metadata" (gr8s::core-object "name" "web")
    "spec" (apply #'gr8s::core-object
                  "scaleTargetRef" (gr8s::core-object "apiVersion" "apps/v1" "kind" "Deployment" "name" "web")
                  "maxReplicas" 5 spec-fields)))

(test autoscalers-round-trip-between-their-versions
  (with-crd-api (store path)
    (values store path)
    (let* ((v1 "/apis/autoscaling/v1/namespaces/default/horizontalpodautoscalers")
           (v2 "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers")
           (created (crd-api-request 201 v1 :method :post :object (hpa-fixture "autoscaling/v1" "targetCPUUtilizationPercentage" 50))))
      (is (equal "autoscaling/v1" (gethash "apiVersion" created)))
      (is (= 50 (gethash "targetCPUUtilizationPercentage" (gethash "spec" created))))
      (is (= 1 (gethash "minReplicas" (gethash "spec" created))))
      (is (not (nth-value 1 (gethash "metrics" (gethash "spec" created)))))
      (let* ((stored (crd-api-request 200 (concatenate 'string v2 "/web")))
             (metric (aref (gethash "metrics" (gethash "spec" stored)) 0)))
        (is (equal "autoscaling/v2" (gethash "apiVersion" stored)))
        (is (= 50 (gethash "averageUtilization" (gethash "target" (gethash "resource" metric))))))
      (is (equal "autoscaling/v1" (gethash "apiVersion" (crd-api-request 200 (concatenate 'string v1 "/web")))))
      (is (= 1 (length (gethash "items" (crd-api-request 200 v1)))))
      (is (equal "autoscaling/v1" (gethash "apiVersion" (crd-api-request 200 v1))))
      (crd-api-request 200 (concatenate 'string v1 "/web") :method :delete)
      (crd-api-request 404 (concatenate 'string v2 "/web")))))

(test autoscalers-validate-their-target-and-range
  (with-crd-api (store path)
    (values store path)
    (let ((v2 "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers"))
      (is (search "spec.maxReplicas" (gethash "message" (crd-api-request 422 v2 :method :post :object (hpa-fixture "autoscaling/v2" "minReplicas" 9)))))
      (let ((missing (hpa-fixture "autoscaling/v2")))
        (remhash "scaleTargetRef" (gethash "spec" missing))
        (is (search "spec.scaleTargetRef" (gethash "message" (crd-api-request 422 v2 :method :post :object missing)))))
      ;; A client cannot claim status for itself.
      (let ((claimed (hpa-fixture "autoscaling/v2")))
        (setf (gethash "status" claimed) (gr8s::core-object "currentReplicas" 3 "desiredReplicas" 3))
        (is (= 0 (gethash "currentReplicas" (gethash "status" (crd-api-request 201 v2 :method :post :object claimed)))))))))

(test apiservices-describe-local-versions-and-refuse-invalid-registration
  (with-crd-api (store path)
    (values store path)
    (let* ((collection "/apis/apiregistration.k8s.io/v1/apiservices")
           (items (gethash "items" (crd-api-request 200 collection)))
           (names (map 'list (lambda (item) (gethash "name" (gethash "metadata" item))) items)))
      (dolist (name '("v1" "v1.apps" "v2.autoscaling"))
        (is (member name names :test #'equal) "~A is absent" name))
      (is (equal "apps" (gethash "group" (gethash "spec" (crd-api-request 200 (concatenate 'string collection "/v1.apps"))))))
      (crd-api-request 404 (concatenate 'string collection "/v9.none"))
      ;; Registration works, but only for what upstream's rules accept.
      (crd-api-request 422 collection :method :post :text "{}")
      ;; A version this server describes itself is not a stored object to change.
      (crd-api-request 405 (concatenate 'string collection "/v1.apps") :method :delete))))

(defun apply-merge-patch (path text &optional manager)
  "Merge-patch PATH as a named manager."
  (check-core-status 200 path :method :patch :octets text :content-type "application/merge-patch+json"
                     :parameters (when manager (list (cons "fieldManager" manager)))))

(test update-managers-own-what-they-change-and-conflict-with-appliers
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/api/v1/namespaces" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "alpha")))
    (let ((config-path "/api/v1/namespaces/alpha/configmaps/one"))
      (check-core-status 201 config-path :method :patch
        :octets "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"one\"},\"data\":{\"a\":\"1\"}}"
        :content-type "application/apply-patch+yaml" :parameters '(("fieldManager" . "applier")))
      (let* ((patched (apply-merge-patch config-path "{\"data\":{\"a\":\"2\",\"b\":\"3\"}}" "patcher"))
             (entries (gethash "managedFields" (gethash "metadata" patched)))
             (updater (find "patcher" entries :test #'equal :key (lambda (entry) (gethash "manager" entry))))
             (applier (find "applier" entries :test #'equal :key (lambda (entry) (gethash "manager" entry)))))
        (is (equal "Update" (gethash "operation" updater)))
        (is (hash-table-p (gethash "f:a" (gethash "f:data" (gethash "fieldsV1" updater)))))
        (is (hash-table-p (gethash "f:b" (gethash "f:data" (gethash "fieldsV1" updater)))))
        ;; The updater took the changed field from the applier.
        (is (null applier)))
      ;; The applier now conflicts with the Update manager, until it forces.
      (let ((conflict (check-core-status 409 config-path :method :patch
                        :octets "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"one\"},\"data\":{\"a\":\"9\"}}"
                        :content-type "application/apply-patch+yaml" :parameters '(("fieldManager" . "applier")))))
        (is (search "patcher" (gethash "message" conflict)) "~A" (gethash "message" conflict)))
      (let ((forced (check-core-status 200 config-path :method :patch
                      :octets "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"one\"},\"data\":{\"a\":\"9\"}}"
                      :content-type "application/apply-patch+yaml"
                      :parameters '(("fieldManager" . "applier") ("force" . "true")))))
        (is (equal "9" (gethash "a" (gethash "data" forced))))
        (is (equal "3" (gethash "b" (gethash "data" forced))))
        (let ((updater (find "patcher" (gethash "managedFields" (gethash "metadata" forced)) :test #'equal
                             :key (lambda (entry) (gethash "manager" entry)))))
          (is (not (nth-value 1 (gethash "f:a" (gethash "f:data" (gethash "fieldsV1" updater))))))
          (is (hash-table-p (gethash "f:b" (gethash "f:data" (gethash "fieldsV1" updater)))))))
      ;; An unchanged write takes nothing and an explicit empty list resets tracking.
      (let* ((current (check-core-status 200 config-path)))
        (setf (gethash "managedFields" (gethash "metadata" current)) #())
        (let ((reset (check-core-status 200 config-path :method :put :object current)))
          (is (not (gethash "managedFields" (gethash "metadata" reset)))))))))

(test map-lists-merge-by-key-and-prune-only-what-a-manager-owned
  (with-core-api (store path)
    (values store path)
    (let* ((definition (crd-fixture))
           (version (aref (gethash "versions" (gethash "spec" definition)) 0))
           (spec-properties (gethash "properties" (gethash "spec" (gethash "properties" (gethash "openAPIV3Schema" (gethash "schema" version)))))))
      (setf (gethash "ports" spec-properties)
            (gr8s::core-object "type" "array" "x-kubernetes-list-type" "map" "x-kubernetes-list-map-keys" #("name")
                               "items" (gr8s::core-object "type" "object" "required" #("name")
                                                          "properties" (gr8s::core-object "name" (gr8s::core-object "type" "string")
                                                                                          "port" (gr8s::core-object "type" "integer"))))
            (gethash "tags" spec-properties)
            (gr8s::core-object "type" "array" "x-kubernetes-list-type" "set" "items" (gr8s::core-object "type" "string")))
      (check-core-status 201 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post :object definition))
    (check-core-status 201 "/api/v1/namespaces" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "alpha")))
    (let ((widget "/apis/widgets.example.test/v1/namespaces/alpha/widgets/one"))
      (flet ((apply-widget (manager spec &optional (expected 200) force)
               (check-core-status expected widget :method :patch
                 :octets (format nil "{\"apiVersion\":\"widgets.example.test/v1\",\"kind\":\"Widget\",\"metadata\":{\"name\":\"one\"},\"spec\":~A}" spec)
                 :content-type "application/apply-patch+yaml"
                 :parameters (append (list (cons "fieldManager" manager))
                                     (when force '(("force" . "true")))))))
        (apply-widget "first" "{\"ports\":[{\"name\":\"a\",\"port\":1}],\"tags\":[\"x\"]}" 201)
        (let ((both (apply-widget "second" "{\"ports\":[{\"name\":\"b\",\"port\":2}],\"tags\":[\"y\"]}")))
          (is (= 2 (length (gethash "ports" (gethash "spec" both)))))
          (is (= 2 (length (gethash "tags" (gethash "spec" both)))))
          (let* ((first-entry (find "second" (gethash "managedFields" (gethash "metadata" both)) :test #'equal
                                    :key (lambda (entry) (gethash "manager" entry))))
                 (ports (gethash "f:ports" (gethash "f:spec" (gethash "fieldsV1" first-entry)))))
            (is (hash-table-p (gethash "k:{\"name\":\"b\"}" ports)) "~A" (com.inuoe.jzon:stringify ports))
            (is (hash-table-p (gethash "v:\"y\"" (gethash "f:tags" (gethash "f:spec" (gethash "fieldsV1" first-entry))))))))
        ;; Changing another manager's entry conflicts; touching only one's own does not.
        (apply-widget "second" "{\"ports\":[{\"name\":\"a\",\"port\":9}]}" 409)
        (let ((dropped (apply-widget "first" "{\"tags\":[\"x\"]}")))
          (is (equal '("b") (map 'list (lambda (port) (gethash "name" port)) (gethash "ports" (gethash "spec" dropped)))))
          (is (equal '("x" "y") (sort (coerce (gethash "tags" (gethash "spec" dropped)) 'list) #'string<))))))))

(test apply-reaches-pods-and-their-status
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/api/v1/namespaces" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "alpha")))
    (let ((pod "/api/v1/namespaces/alpha/pods/one"))
      (flet ((apply-pod (where manager body expected)
               (check-core-status expected where :method :patch :octets body
                                  :content-type "application/apply-patch+yaml"
                                  :parameters (list (cons "fieldManager" manager)))))
        (let ((created (apply-pod pod "first"
                                  "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"one\"},\"spec\":{\"containers\":[{\"name\":\"a\",\"image\":\"i\"}]}}"
                                  201)))
          (is (equal "first" (gethash "manager" (aref (gethash "managedFields" (gethash "metadata" created)) 0)))))
        (let ((status "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"one\"},\"status\":{\"conditions\":[{\"type\":\"MyStatus\",\"status\":\"True\"}]}}"))
          ;; The Pod endpoint ignores status; the status endpoint applies it.
          (apply-pod pod "second" status 200)
          (flet ((has-status ()
                   (find "MyStatus" (gethash "conditions" (gethash "status" (check-core-status 200 pod)) #())
                         :test #'equal :key (lambda (condition) (gethash "type" condition)))))
            (is (null (has-status)))
            (apply-pod (concatenate 'string pod "/status") "second" status 200)
            (is-true (has-status))))))))

(test map-list-keys-default-and-shared-items-do-not-conflict
  (let* ((gr8s::*apply-schema*
           (com.inuoe.jzon:parse "{\"properties\":{\"ports\":{\"type\":\"array\",\"x-kubernetes-list-type\":\"map\",\"x-kubernetes-list-map-keys\":[\"containerPort\",\"protocol\"],\"items\":{\"type\":\"object\"}}}}"))
         (live (com.inuoe.jzon:parse "{\"metadata\":{},\"ports\":[{\"containerPort\":80,\"protocol\":\"TCP\",\"name\":\"a\"}]}"))
         (first-config (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"X\",\"metadata\":{},\"ports\":[{\"containerPort\":80,\"name\":\"a\"}]}"))
         (second-config (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"X\",\"metadata\":{},\"ports\":[{\"containerPort\":80,\"hostPort\":9}]}"))
         (dropped (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"X\",\"metadata\":{}}")))
    (let* ((one (gr8s::apply-merge live first-config "configmaps" "first" nil))
           (two (gr8s::apply-merge one second-config "configmaps" "second" nil)))
      ;; A port without a protocol is the TCP entry, which both managers may hold.
      (is (= 1 (length (gethash "ports" two))))
      (is (= 9 (gethash "hostPort" (aref (gethash "ports" two) 0))))
      (let ((alone (gr8s::apply-merge one dropped "configmaps" "first" nil)))
        (is (not (nth-value 1 (gethash "ports" alone))))))))

(test nested-items-go-when-dropped-while-their-parent-stays
  (let* ((gr8s::*apply-schema*
           (com.inuoe.jzon:parse "{\"properties\":{\"containers\":{\"type\":\"array\",\"x-kubernetes-list-type\":\"map\",\"x-kubernetes-list-map-keys\":[\"name\"],\"items\":{\"type\":\"object\",\"properties\":{\"ports\":{\"type\":\"array\",\"x-kubernetes-list-type\":\"map\",\"x-kubernetes-list-map-keys\":[\"containerPort\",\"protocol\"],\"items\":{\"type\":\"object\"}}}}}}}"))
         (live (com.inuoe.jzon:parse "{\"metadata\":{}}"))
         (with-port (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"X\",\"metadata\":{},\"containers\":[{\"name\":\"c\",\"image\":\"i\",\"ports\":[{\"containerPort\":80}]}]}"))
         (without (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"X\",\"metadata\":{},\"containers\":[{\"name\":\"c\",\"image\":\"i\"}]}"))
         (one (gr8s::apply-merge live with-port "configmaps" "m" nil))
         (two (gr8s::apply-merge one without "configmaps" "m" nil))
         (container (aref (gethash "containers" two) 0)))
    (is (equal "i" (gethash "image" container)))
    (is (not (nth-value 1 (gethash "ports" container))))
    ;; Upstream serializes FieldsV1 sorted, with an item's "." first.
    (let ((fields (com.inuoe.jzon:stringify (gethash "fieldsV1" (aref (gethash "managedFields" (gethash "metadata" two)) 0)))))
      (is (search "{\".\":{},\"f:image\":{},\"f:name\":{}}" fields) "~A" fields))))

(test appliers-of-the-same-service-share-its-defaulted-ports
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/api/v1/namespaces" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "alpha")))
    (let ((service "/api/v1/namespaces/alpha/services/one")
          (body "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"one\"},\"spec\":{\"ports\":[{\"port\":8080,\"protocol\":\"TCP\"}]}}"))
      (check-core-status 201 service :method :patch :octets body :content-type "application/apply-patch+yaml"
                         :parameters '(("fieldManager" . "first")))
      (let* ((second (check-core-status 200 service :method :patch :octets body :content-type "application/apply-patch+yaml"
                                        :parameters '(("fieldManager" . "second"))))
             (entries (gethash "managedFields" (gethash "metadata" second))))
        (is (= 2 (length entries)))
        (is (gr8s::crd-json-equal-p (gethash "fieldsV1" (aref entries 0)) (gethash "fieldsV1" (aref entries 1))))))))

;;; External API servers (podster-uqb.84)

(defun aggregator-test-backend (pki server-name directory)
  "Serve a small aggregated API over TLS, as sample-apiserver would, recording each request's head.
Return its port, a function to read the records, and a function to stop it."
  (multiple-value-bind (private public) (ironclad:generate-key-pair :secp256r1)
    (let* ((certificate (merge-pathnames "backend.crt" directory))
           (key (merge-pathnames "backend.key" directory))
           (listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
           (lock (bt:make-lock "aggregator test backend"))
           (seen nil)
           (stopping nil))
      (gr8s::write-private-text-exclusively key (pure-tls/acme::encode-ec-private-key-pem private))
      (gr8s::write-public-text-exclusively
       certificate
       (pure-tls/acme::wrap-pem
        "CERTIFICATE"
        (gr8s::certificate-der
         (pure-tls/acme::encode-subject gr8s::+pki-ca-common-name+)
         (pure-tls/acme::encode-subject server-name)
         (pure-tls/acme::encode-ec-public-key public)
         (list (pure-tls/acme::encode-extension
                pure-tls/acme::*oid-subject-alt-name*
                (pure-tls/acme::encode-sequence
                 (pure-tls/acme::encode-der #x82 (gr8s::pki-ascii-octets server-name)))))
         (gr8s::cluster-pki-ca-private-key pki))))
      (flet ((serve (raw)
               (let ((tls (pure-tls:make-tls-server-stream
                           (usocket:socket-stream raw) :certificate (namestring certificate)
                           :key (namestring key) :verify pure-tls:+verify-peer+ :trust-store nil)))
                 (multiple-value-bind (method target headers body) (aggregator-test-read-request tls)
                   (bt:with-lock-held (lock)
                     (push (list method target headers body (pure-tls:tls-peer-certificate tls)) seen))
                   (if (search "flunders" target)
                       ;; Two chunks: a watch's events have to arrive one at a time.
                       (flet ((write-text (text)
                                (write-sequence (trivial-utf-8:string-to-utf-8-bytes text) tls)
                                (force-output tls)))
                         (write-text (format nil "HTTP/1.1 200 OK~C~CContent-Type: application/json~C~CTransfer-Encoding: chunked~C~C~C~C"
                                             #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))
                         (write-text (format nil "7~C~C{\"a\":1}~C~C" #\Return #\Linefeed #\Return #\Linefeed))
                         (write-text (format nil "0~C~C~C~C" #\Return #\Linefeed #\Return #\Linefeed)))
                       (let ((document (com.inuoe.jzon:stringify
                                        (gr8s::core-object
                                         "apiVersion" "v1" "kind" "APIResourceList"
                                         "groupVersion" "wardle.example.com/v1alpha1"
                                         "resources" (vector (gr8s::core-object
                                                              "name" "flunders" "singularName" "flunder" "namespaced" t
                                                              "kind" "Flunder" "verbs" #("get" "list")))))))
                         (write-sequence
                          (trivial-utf-8:string-to-utf-8-bytes
                           (format nil "HTTP/1.1 200 OK~C~CContent-Type: application/json~C~CContent-Length: ~D~C~C~C~C~A"
                                   #\Return #\Linefeed #\Return #\Linefeed (length document)
                                   #\Return #\Linefeed #\Return #\Linefeed document))
                          tls)
                         (force-output tls)))))))
        (let ((thread (bt:make-thread
                       (lambda ()
                         (handler-case
                             (loop (let ((raw (usocket:socket-accept listener)))
                                     (when stopping
                                       (usocket:socket-close raw)
                                       (return))
                                     (bt:make-thread
                                      (lambda ()
                                        (unwind-protect (ignore-errors (serve raw))
                                          (ignore-errors (usocket:socket-close raw))))
                                      :name "aggregator test backend request")))
                           (error () nil)))
                       :name "aggregator test backend")))
          (values (usocket:get-local-port listener)
                  (lambda () (bt:with-lock-held (lock) (copy-list seen)))
                  (lambda ()
                    ;; Closing a listener doesn't wake its accept, so connect to it.
                    (setf stopping t)
                    (ignore-errors
                     (usocket:socket-close
                      (usocket:socket-connect "127.0.0.1" (usocket:get-local-port listener))))
                    (ignore-errors (bt:join-thread thread))
                    (ignore-errors (usocket:socket-close listener)))))))))

(defun aggregator-test-read-request (stream)
  "Read one request from STREAM, returning its method, target, lowercase headers and body."
  (let* ((request-line (gr8s::admission-read-line stream))
         (parts (uiop:split-string request-line :separator " "))
         (headers (loop for line = (gr8s::admission-read-line stream)
                        until (zerop (length line))
                        for colon = (position #\: line)
                        collect (cons (string-downcase (subseq line 0 colon))
                                      (string-trim " " (subseq line (1+ colon))))))
         (length (cdr (assoc "content-length" headers :test #'string=))))
    (values (first parts) (second parts) headers
            (when length (gr8s::admission-read-exactly stream (parse-integer length))))))

(defun aggregator-test-service (store namespace port)
  "Create a Service and one ready endpoint at PORT, which a registered APIService can name."
  (gr8s::create-core-resource
   store "services"
   (gr8s::core-object "metadata" (gr8s::core-object "name" "sample-api")
                      "spec" (gr8s::core-object "clusterIP" "None"
                                                "ports" (vector (gr8s::core-object "port" 7443 "targetPort" port))))
   namespace)
  ;; The API refuses a loopback endpoint, which is the only address this backend has.
  (gr8s::with-store-lock (store)
    (setf (gethash (gr8s::core-resource-key "endpointslices" namespace "sample-api-1") (gr8s::pod-store-resources store))
          (gr8s::core-object "apiVersion" "discovery.k8s.io/v1" "kind" "EndpointSlice" "addressType" "IPv4"
                             "metadata" (gr8s::core-object "name" "sample-api-1" "namespace" namespace
                                                           "labels" (gr8s::core-object "kubernetes.io/service-name" "sample-api"))
                             "endpoints" (vector (gr8s::core-object "addresses" #("127.0.0.1")))
                             "ports" (vector (gr8s::core-object "port" port "protocol" "TCP"))))))

(defun aggregator-test-apiservice (pki)
  "Return a registration of wardle.example.com/v1alpha1 trusting PKI's CA."
  (gr8s::core-object
   "apiVersion" "apiregistration.k8s.io/v1" "kind" "APIService"
   "metadata" (gr8s::core-object "name" "v1alpha1.wardle.example.com")
   "spec" (gr8s::core-object
           "group" "wardle.example.com" "version" "v1alpha1" "groupPriorityMinimum" 2000 "versionPriority" 200
           "caBundle" (ag-grpc:base64-encode
                       (trivial-utf-8:string-to-utf-8-bytes
                        (uiop:read-file-string (gr8s::cluster-pki-ca-certificate-path pki))))
           "service" (gr8s::core-object "namespace" "alpha" "name" "sample-api" "port" 7443))))

(defun apiservice-condition (object type)
  "Return OBJECT's condition of TYPE."
  (let ((status (gethash "status" object)))
    (and status
         (find type (gethash "conditions" status #()) :test #'equal
               :key (lambda (condition) (gethash "type" condition))))))

(test extension-apiserver-trust-matches-what-a-real-server-publishes
  (with-temporary-store (store path)
    (let ((pki (gr8s::ensure-cluster-pki (merge-pathnames "pki/" path))))
      (gr8s::create-core-resource store "namespaces" (gr8s::core-object "metadata" (gr8s::core-object "name" "kube-system")) nil)
      (gr8s::ensure-extension-apiserver-rbac store)
      (dotimes (repeat 2) (gr8s::ensure-extension-apiserver-authentication store pki))
      (let ((data (gethash "data" (gr8s::get-core-resource store "configmaps" "kube-system" "extension-apiserver-authentication")))
            (role (gr8s::get-core-resource store "roles" "kube-system" "extension-apiserver-authentication-reader"))
            (binding (gr8s::get-core-resource store "rolebindings" "kube-system"
                                              "system::extension-apiserver-authentication-reader")))
        (is (equal "[\"front-proxy-client\"]" (gethash "requestheader-allowed-names" data)))
        (is (equal "[\"X-Remote-User\"]" (gethash "requestheader-username-headers" data)))
        (is (equal "[\"X-Remote-Group\"]" (gethash "requestheader-group-headers" data)))
        (is (equal "[\"X-Remote-Extra-\"]" (gethash "requestheader-extra-headers-prefix" data)))
        (is (equal (uiop:read-file-string (gr8s::cluster-pki-ca-certificate-path pki)) (gethash "client-ca-file" data)))
        ;; A separate CA: nothing the cluster CA signs may assert a request's identity.
        (is-false (equal (gethash "client-ca-file" data) (gethash "requestheader-client-ca-file" data)))
        (is (equalp #("extension-apiserver-authentication")
                    (gethash "resourceNames" (aref (gethash "rules" role) 0))))
        (is (equal "extension-apiserver-authentication-reader" (gethash "name" (gethash "roleRef" binding))))
        (is (equalp '("system:kube-controller-manager" "system:kube-scheduler")
                    (map 'list (lambda (subject) (gethash "name" subject)) (gethash "subjects" binding)))))
      ;; The client certificate chains to the published CA and is for client authentication.
      (multiple-value-bind (ca certificate) (gr8s::ensure-front-proxy-credentials pki)
        (let ((leaf (first (pure-tls:load-certificate-chain certificate))))
          (is (equal "front-proxy-client" (first (pure-tls::certificate-subject-common-names leaf))))
          (finishes (pure-tls::verify-certificate-chain
                     (list leaf) (list (first (pure-tls:load-certificate-chain ca)))
                     :purpose :client-auth :trust-anchor-mode :replace)))))))

(test apiservice-registration-reports-availability-and-proxies-requests
  (with-crd-api (store path)
    (let* ((pki (gr8s::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (aggregator (gr8s::start-api-aggregator store pki))
           (collection "/apis/apiregistration.k8s.io/v1/apiservices")
           (item (concatenate 'string collection "/v1alpha1.wardle.example.com"))
           (flunders "/apis/wardle.example.com/v1alpha1/namespaces/default/flunders"))
      (multiple-value-bind (port records stop)
          (aggregator-test-backend pki "sample-api.alpha.svc" path)
        (unwind-protect
             (progn
               (gr8s::create-core-resource store "namespaces" (gr8s::core-object "metadata" (gr8s::core-object "name" "alpha")) nil)
               ;; No Service yet: registered, not available, and requests get 503.
               (is (null (gethash "status" (crd-api-request 201 collection :method :post :object (aggregator-test-apiservice pki)))))
               (is-true (wait-until
                         (lambda ()
                           (let ((condition (apiservice-condition (crd-api-request 200 item) "Available")))
                             (and condition (equal "ServiceNotFound" (gethash "reason" condition)))))
                         :timeout 10))
               (crd-api-request 503 flunders)
               ;; Once it has an endpoint, its discovery check passes.
               (aggregator-test-service store "alpha" port)
               (is-true (wait-until
                         (lambda ()
                           (let ((condition (apiservice-condition (crd-api-request 200 item) "Available")))
                             (and condition (equal "True" (gethash "status" condition)))))
                         :timeout 15))
               (let ((available (aref (gethash "conditions" (gethash "status" (crd-api-request 200 (concatenate 'string item "/status")))) 0)))
                 (is (equal "all checks passed" (gethash "message" available)))
                 (is (equal "Passed" (gethash "reason" available))))
               ;; Proxying: the chunked answer arrives, and the caller's identity went with it.
               (is (= 1 (gethash "a" (crd-api-request 200 flunders :parameters '(("labelSelector" . "x=y"))))))
               (destructuring-bind (method target headers body peer) (first (funcall records))
                 (declare (ignore body))
                 (is (equal "GET" method))
                 (is (equal (concatenate 'string flunders "?labelSelector=x%3Dy") target))
                 (is (equal "system:admin" (cdr (assoc "x-remote-user" headers :test #'string=))))
                 (is (member "system:masters" headers :test #'equal :key #'cdr))
                 (is-true peer "the backend saw no client certificate"))
               ;; A request's own identity headers don't reach the server, nor does its credential.
               (multiple-value-bind (body status)
                   (drakma:http-request (concatenate 'string "http://127.0.0.1:18094" flunders)
                                        :additional-headers '(("X-Remote-User" . "mallory") ("Authorization" . "Bearer secret")))
                 (declare (ignore body))
                 (is (= 200 status)))
               (let ((headers (third (first (funcall records)))))
                 (is (equal '("system:admin")
                            (loop for (name . value) in headers when (string= name "x-remote-user") collect value)))
                 (is-false (assoc "authorization" headers :test #'string=)))
               ;; A body is forwarded unchanged.
               (crd-api-request 200 flunders :method :post :text "{\"b\":2}")
               (is (equal "{\"b\":2}" (trivial-utf-8:utf-8-bytes-to-string (fourth (first (funcall records))))))
               ;; Discovery names the group and its resources in both forms.
               (let* ((groups (crd-api-request 200 "/apis"))
                      (group (find "wardle.example.com" (gethash "groups" groups) :test #'equal
                                   :key (lambda (entry) (gethash "name" entry)))))
                 (is-true group)
                 (is (equal "wardle.example.com/v1alpha1"
                            (gethash "groupVersion" (gethash "preferredVersion" group)))))
               (is (equal "wardle.example.com" (gethash "name" (crd-api-request 200 "/apis/wardle.example.com"))))
               (let* ((document
                        (com.inuoe.jzon:parse
                         (drakma:http-request
                          "http://127.0.0.1:18094/apis"
                          :accept "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList")))
                      (entry (find "wardle.example.com" (gethash "items" document) :test #'equal
                                   :key (lambda (entry) (gethash "name" (gethash "metadata" entry))))))
                 (is (equal "flunders"
                            (gethash "resource" (aref (gethash "resources" (aref (gethash "versions" entry) 0)) 0)))))
               ;; Its OpenAPI v3 document is listed and comes from the server itself.
               (is (gethash "apis/wardle.example.com/v1alpha1" (gethash "paths" (crd-api-request 200 "/openapi/v3"))))
               (crd-api-request 200 "/openapi/v3/apis/wardle.example.com/v1alpha1?hash=x")
               (is (equal "/openapi/v3/apis/wardle.example.com/v1alpha1" (second (first (funcall records)))))
               ;; The object takes spec and status writes, keeping conditions it doesn't own.
               (is (= 400 (gethash "versionPriority"
                                   (gethash "spec" (crd-api-request 200 item :method :patch
                                                     :text "{\"spec\":{\"versionPriority\":400}}"
                                                     :content-type "application/merge-patch+json")))))
               (let ((status (crd-api-request 200 (concatenate 'string item "/status"))))
                 (setf (gethash "conditions" (gethash "status" status))
                       (concatenate 'vector (gethash "conditions" (gethash "status" status))
                                    (vector (gr8s::core-object "type" "StatusUpdated" "status" "True" "reason" "E2E"
                                                               "message" "Set from e2e test"))))
                 (crd-api-request 200 (concatenate 'string item "/status") :method :put :object status))
               (is-true (apiservice-condition (crd-api-request 200 item) "StatusUpdated"))
               ;; The list holds both kinds, and deleting by label leaves the local ones.
               (crd-api-request 200 item :method :patch :text "{\"metadata\":{\"labels\":{\"e2e\":\"yes\"}}}"
                                         :content-type "application/merge-patch+json")
               (flet ((names (&rest parameters)
                        (map 'list (lambda (entry) (gethash "name" (gethash "metadata" entry)))
                             (gethash "items" (crd-api-request 200 collection :parameters parameters)))))
                 (is (member "v1.apps" (names) :test #'equal))
                 (is (equal '("v1alpha1.wardle.example.com") (names '("labelSelector" . "e2e=yes"))))
                 (crd-api-request 200 collection :method :delete :parameters '(("labelSelector" . "e2e=yes")))
                 (is (null (names '("labelSelector" . "e2e=yes"))))
                 (is (member "v1.apps" (names) :test #'equal)))
               ;; Gone from routing and discovery too.
               (crd-api-request 404 flunders)
               (is-false (gethash "apis/wardle.example.com/v1alpha1" (gethash "paths" (crd-api-request 200 "/openapi/v3"))))
               (is-false (find "wardle.example.com" (gethash "groups" (crd-api-request 200 "/apis")) :test #'equal
                               :key (lambda (entry) (gethash "name" entry)))))
          (gr8s::stop-api-aggregator aggregator)
          (funcall stop))))))

(test apiservice-validation-follows-upstreams-rules
  (with-crd-api (store path)
    (values store)
    (let* ((pki (gr8s::ensure-cluster-pki (merge-pathnames "pki/" path)))
           (collection "/apis/apiregistration.k8s.io/v1/apiservices"))
      (flet ((refused (code change)
               (let ((object (aggregator-test-apiservice pki)))
                 (funcall change object)
                 (crd-api-request code collection :method :post :object object))))
        (refused 422 (lambda (object) (setf (gethash "name" (gethash "metadata" object)) "wrong.name")))
        (refused 422 (lambda (object) (setf (gethash "groupPriorityMinimum" (gethash "spec" object)) 0)))
        (refused 422 (lambda (object) (setf (gethash "versionPriority" (gethash "spec" object)) 1001)))
        (refused 422 (lambda (object) (remhash "caBundle" (gethash "spec" object))))
        (refused 422 (lambda (object) (setf (gethash "insecureSkipTLSVerify" (gethash "spec" object)) t)))
        (refused 409 (lambda (object)
                       (setf (gethash "name" (gethash "metadata" object)) "v1.apps"
                             (gethash "group" (gethash "spec" object)) "apps"
                             (gethash "version" (gethash "spec" object)) "v1")))))))

(test a-field-selected-name-is-the-name-authorization-sees
  ;; A server delegating authentication reads one ConfigMap by list and watch with a field
  ;; selector, under a rule limited to that ConfigMap by resourceNames.
  (flet ((target-name (&rest arguments)
           (fourth (multiple-value-list
                    (apply #'gr8s::kubernetes-authorization-target
                           "/api/v1/namespaces/kube-system/configmaps" :get arguments)))))
    (is (equal "wanted" (target-name :field-selector "metadata.name=wanted")))
    (is (equal "wanted" (target-name :field-selector "metadata.name==wanted")))
    (is (equal "wanted" (target-name :watch t :field-selector "a=b,metadata.name=wanted")))
    (is (null (target-name)))
    (is (null (target-name :field-selector "metadata.name!=wanted")))
    (is (null (target-name :field-selector "metadata.namespace=wanted")))
    (is (null (target-name :field-selector "metadata.name=not/a/name"))))
  ;; A request naming an object keeps that name, and a create names nothing it selects.
  (is (equal "one" (fourth (multiple-value-list
                            (gr8s::kubernetes-authorization-target
                             "/api/v1/namespaces/kube-system/configmaps/one" :get
                             :field-selector "metadata.name=other")))))
  (is (null (fourth (multiple-value-list
                     (gr8s::kubernetes-authorization-target
                      "/api/v1/namespaces/kube-system/configmaps" :post
                      :field-selector "metadata.name=other"))))))

(test proxied-watches-notice-a-departed-client
  ;; A watch relayed from an aggregated server ends when its client goes, not at the next event.
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
         (client (usocket:socket-connect "127.0.0.1" (usocket:get-local-port listener) :element-type '(unsigned-byte 8)))
         (server (usocket:socket-accept listener))
         (fd (sb-sys:fd-stream-fd (usocket:socket-stream server))))
    (unwind-protect
         (progn
           (is-false (gr8s::client-connection-closed-p fd))
           ;; Data waiting to be read is not a departure, and peeking leaves it there.
           (write-byte 7 (usocket:socket-stream client))
           (force-output (usocket:socket-stream client))
           (is-true (wait-until (lambda () (listen (usocket:socket-stream server))) :timeout 5))
           (is-false (gr8s::client-connection-closed-p fd))
           (is (= 7 (read-byte (usocket:socket-stream server))))
           (usocket:socket-close client)
           (setf client nil)
           (is-true (wait-until (lambda () (gr8s::client-connection-closed-p fd)) :timeout 5)))
      (when client (usocket:socket-close client))
      (usocket:socket-close server)
      (usocket:socket-close listener))))
