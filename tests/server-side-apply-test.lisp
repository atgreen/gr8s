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
                             :method :post :content-type "application/json" :content "{}"
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
