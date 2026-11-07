;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Publish each genuinely served custom version's structural OpenAPI schema
;;;; and CRUD/status paths. Schema identities include group/version/kind rather
;;;; than relying on plural names that can collide across independent groups.

(in-package #:gr8s.apiserver)

(defparameter *crd-definition-schema*
  (gethash "schema" (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/crd-v1.json"))))

(defun crd-openapi-builtin-definition ()
  "Describe the actual JSON CRD API using its supported request schema."
  (core-object "spec" (core-object "group" "apiextensions.k8s.io" "scope" "Cluster"
                   "names" (core-object "plural" "customresourcedefinitions" "kind" "CustomResourceDefinition" "listKind" "CustomResourceDefinitionList"))))

(defun crd-openapi-definition-name (definition version &optional list)
  "Name a custom kind's definition as Kubernetes does: group reversed, then version and kind."
  (let* ((spec (gethash "spec" definition)) (names (gethash "names" spec)))
    (format nil "~{~A.~}~A.~A" (reverse (uiop:split-string (gethash "group" spec) :separator '(#\.)))
            version (gethash (if list "listKind" "kind") names))))

(defparameter +openapi-type-meta-descriptions+
  '(("apiVersion" . "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources")
    ("kind" . "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"))
  "Descriptions of the type fields Kubernetes adds to every published kind.")

(defparameter +openapi-metadata-description+
  "Standard object's metadata. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata")

(defun crd-openapi-v2-schema (schema)
  "Copy SCHEMA without what OpenAPI v2 cannot express, as Kubernetes does when publishing it.
Nullable, preserved and int-or-string nodes lose their type, since v2 clients would
otherwise reject the values these allow."
  (let ((copy (copy-core-object schema)))
    (dolist (field '("allOf" "anyOf" "oneOf" "not")) (remhash field copy))
    (when (or (gethash "nullable" copy) (gethash "x-kubernetes-preserve-unknown-fields" copy)
              (gethash "x-kubernetes-int-or-string" copy))
      (dolist (field '("type" "items" "properties" "additionalProperties" "nullable")) (remhash field copy)))
    (when (hash-table-p (gethash "properties" copy))
      (let ((properties (core-object)))
        (maphash (lambda (key child) (setf (gethash key properties) (crd-openapi-v2-schema child)))
                 (gethash "properties" copy))
        (setf (gethash "properties" copy) properties)))
    (dolist (field '("items" "additionalProperties"))
      (when (hash-table-p (gethash field copy))
        (setf (gethash field copy) (crd-openapi-v2-schema (gethash field copy)))))
    copy))

(defun crd-openapi-add-object-fields (schema v3)
  "Declare the type and metadata fields of a Kubernetes object on SCHEMA."
  (let ((properties (gethash "properties" schema (core-object))))
    (loop for (field . description) in +openapi-type-meta-descriptions+
          do (setf (gethash field properties) (core-object "type" "string" "description" description)))
    (let ((metadata (reference-schema "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta")))
      (setf (gethash "metadata" properties)
            (if v3
                (core-object "allOf" (vector metadata) "description" +openapi-metadata-description+)
                (progn (setf (gethash "description" metadata) +openapi-metadata-description+) metadata))))
    (setf (gethash "properties" schema) properties)
    schema))

(defun crd-openapi-add-embedded-fields (schema v3)
  "Declare object fields wherever SCHEMA embeds a Kubernetes resource."
  (when (hash-table-p schema)
    (when (hash-table-p (gethash "properties" schema))
      (maphash (lambda (key child) (declare (ignore key)) (crd-openapi-add-embedded-fields child v3))
               (gethash "properties" schema)))
    (dolist (field '("items" "additionalProperties"))
      (crd-openapi-add-embedded-fields (gethash field schema) v3))
    (when (gethash "x-kubernetes-embedded-resource" schema)
      (crd-openapi-add-object-fields schema v3)))
  schema)

(defun crd-openapi-kind-schema (version v3)
  "Build the published schema of an admitted version.
An OpenAPI v2 client assumes unlisted fields are invalid, so a schema that preserves
them at its root is published as a bare object."
  (let ((schema (crd-schema version)))
    (if (and (not v3) (gethash "x-kubernetes-preserve-unknown-fields" schema))
        (core-object "type" "object")
        (crd-openapi-add-object-fields
         (crd-openapi-add-embedded-fields (if v3 (copy-core-object schema) (crd-openapi-v2-schema schema)) v3)
         v3))))

(defun crd-add-openapi-version (document definition version v3 &key schema-names)
  "Publish an admitted version's schemas and real collection/item/status paths.
SCHEMA-NAMES, the kind's and its list's, name schemas the document already has, which are
then used as they stand."
  (let* ((spec (gethash "spec" definition)) (names (gethash "names" spec))
         (group (gethash "group" spec)) (version-name (gethash "name" version))
         (schema-name (or (first schema-names) (crd-openapi-definition-name definition version-name)))
         (list-name (or (second schema-names) (crd-openapi-definition-name definition version-name t)))
         (schema (unless schema-names (crd-openapi-kind-schema version v3)))
         (definitions (if v3 (gethash "schemas" (gethash "components" document)) (gethash "definitions" document)))
         (paths (gethash "paths" document)) (namespaced (equal "Namespaced" (gethash "scope" spec)))
         (collection (format nil "/apis/~A/~A/~A~A" group version-name
                             (if namespaced "namespaces/{namespace}/" "") (gethash "plural" names)))
         (item (concatenate 'string collection "/{name}")))
    (unless schema-names
      (setf (gethash "x-kubernetes-group-version-kind" schema)
            (vector (core-object "group" group "version" version-name "kind" (gethash "kind" names))))
      (setf (gethash schema-name definitions) schema
          (gethash list-name definitions)
          (core-object "type" "object" "properties"
                       (core-object "apiVersion" (core-object "type" "string") "kind" (core-object "type" "string")
                                    "metadata" (core-object "type" "object" "properties" (core-object "resourceVersion" (core-object "type" "string") "continue" (core-object "type" "string")))
                                    "items" (core-object "type" "array" "items" (reference-schema schema-name)))
                       "x-kubernetes-group-version-kind" (vector (core-object "group" group "version" version-name "kind" (gethash "listKind" names))))))
    (labels ((operation (action response &optional body)
               (let ((value (core-object "operationId" (format nil "~A_~A_~A_~A" action group version-name (gethash "kind" names))
                                         "x-kubernetes-action" action
                                         "x-kubernetes-group-version-kind" (core-object "group" group "version" version-name "kind" (gethash "kind" names))
                                         "responses" (core-object "200" (if v3
                                                                             (core-object "description" "Success" "content" (core-object "application/json" (core-object "schema" (reference-schema response))))
                                                                             (core-object "description" "Success" "schema" (reference-schema response)))))))
                 (when body
                   (setf (gethash "parameters" value)
                         (vector (if v3
                                     (core-object "name" "fieldValidation" "in" "query" "schema" (core-object "type" "string" "enum" #("Strict" "Warn" "Ignore")))
                                     (core-object "name" "fieldValidation" "in" "query" "type" "string" "enum" #("Strict" "Warn" "Ignore")))))
                   (if v3
                       (setf (gethash "requestBody" value) (core-object "content" (core-object "application/json" (core-object "schema" (reference-schema schema-name)))))
                       (setf (gethash "parameters" value) (concatenate 'vector (gethash "parameters" value)
                                                               (vector (core-object "name" "body" "in" "body" "schema" (reference-schema schema-name)))))))
                 value))
             (parameters (name-p scope-p)
               (coerce (loop for name in (append (when scope-p '("namespace")) (when name-p '("name")))
                             collect (if v3 (core-object "name" name "in" "path" "required" t "schema" (core-object "type" "string"))
                                         (core-object "name" name "in" "path" "required" t "type" "string"))) 'vector)))
      (setf (gethash collection paths)
            (core-object "parameters" (parameters nil namespaced) "get" (operation "list" list-name)
                         "post" (operation "create" schema-name t) "delete" (operation "deletecollection" "io.k8s.apimachinery.pkg.apis.meta.v1.Status"))
            (gethash item paths)
            (core-object "parameters" (parameters t namespaced) "get" (operation "get" schema-name)
                         "put" (operation "update" schema-name t) "patch" (operation "patch" schema-name t)
                         "delete" (operation "delete" "io.k8s.apimachinery.pkg.apis.meta.v1.Status")))
      (when namespaced
        (setf (gethash (format nil "/apis/~A/~A/~A" group version-name (gethash "plural" names)) paths)
              (core-object "get" (operation "listAllNamespaces" list-name))))
      (when (nth-value 1 (gethash "status" (gethash "subresources" version (core-object))))
        (setf (gethash (concatenate 'string item "/status") paths)
              (core-object "parameters" (parameters t namespaced) "get" (operation "getStatus" schema-name)
                           "put" (operation "updateStatus" schema-name t) "patch" (operation "patchStatus" schema-name t)))))
    document))

(defparameter +crd-openapi-builtin-schema-names+
  '("io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition"
    "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinitionList")
  "Upstream's schemas for the CRD API itself, which the vendored schemas include.")

(defun crd-openapi-document (store group version v3)
  "Build a current OpenAPI document from genuinely served durable definitions."
  (let* ((*schema-reference-prefix* (if v3 "#/components/schemas/" "#/definitions/"))
         (document (if v3 (core-object "openapi" "3.0.0" "info" (core-object "title" "gr8s custom APIs" "version" "v1")
                                      "paths" (core-object) "components" (core-object "schemas" (openapi-definitions group version)))
                       (openapi-document))))
    (when (or (null group) (equal group "apiextensions.k8s.io"))
      (crd-add-openapi-version document (crd-openapi-builtin-definition)
                               (core-object "name" "v1" "schema" (core-object "openAPIV3Schema" *crd-definition-schema*) "subresources" (core-object "status" (core-object))) v3
                               :schema-names +crd-openapi-builtin-schema-names+))
    (dolist (definition (list-core-resources store "customresourcedefinitions"))
      (when (or (null group) (equal group (gethash "group" (gethash "spec" definition))))
        (loop for entry across (gethash "versions" (gethash "spec" definition))
              when (and (gethash "served" entry) (or (null version) (equal version (gethash "name" entry))))
                do (crd-add-openapi-version document definition entry v3))))
    document))

(defun crd-openapi-discovery-response (store)
  "Expose current schema URLs for every actually served group/version."
  (let ((paths (core-object)))
    (dolist (key '("apis/admissionregistration.k8s.io/v1" "apis/discovery.k8s.io/v1" "apis/networking.k8s.io/v1"
                   "apis/certificates.k8s.io/v1" "apis/apps/v1" "apis/node.k8s.io/v1" "apis/scheduling.k8s.io/v1"
                   "apis/storage.k8s.io/v1" "api/v1" "apis/events.k8s.io/v1"))
      (setf (gethash key paths) (core-object "serverRelativeURL" (openapi-builtin-document-url key))))
    ;; Every group discovery advertises has a document, even one with only generic paths.
    (loop for group across (gethash "groups" (com.inuoe.jzon:parse (api-groups-response store)))
          do (loop for version across (gethash "versions" group)
                   for key = (concatenate 'string "apis/" (gethash "groupVersion" version))
                   unless (or (gethash key paths)
                              (aggregated-apiservice store (gethash "name" group) (gethash "version" version)))
                     do (setf (gethash key paths) (core-object "serverRelativeURL" (openapi-builtin-document-url key)))))
    (dolist (group (crd-api-groups store))
      (loop for version across (gethash "versions" group)
            for key = (concatenate 'string "apis/" (gethash "groupVersion" version))
            do (setf (gethash key paths) (core-object "serverRelativeURL"
                                                     (format nil "/openapi/v3/~A?hash=~A-~D" key +openapi-schema-hash+ (pod-store-resource-revision store))))))
    ;; An aggregated version is listed while its server is available, as upstream's aggregator lists it.
    (dolist (apiservice (stored-apiservices store))
      (when (and (apiservice-service apiservice) (apiservice-available-p apiservice))
        (let* ((spec (gethash "spec" apiservice))
               (key (format nil "apis/~A/~A" (gethash "group" spec) (gethash "version" spec))))
          (setf (gethash key paths)
                (core-object "serverRelativeURL"
                             (format nil "/openapi/v3/~A?hash=~A" key
                                     (gethash "resourceVersion" (gethash "metadata" apiservice))))))))
    (json-response (core-object "paths" paths))))

(defvar *openapi-v3-completing* nil
  "True while a hand-written OpenAPI document is being read for completion.")

(defun openapi-v3-document-group-version (path)
  "Return the group and version a /openapi/v3/ document PATH describes, or NIL."
  (let ((parts (rest (rest (rest (uiop:split-string path :separator '(#\/)))))))
    (cond ((and (= 2 (length parts)) (equal "api" (first parts))) (values "" (second parts) t))
          ((and (= 3 (length parts)) (equal "apis" (first parts))) (values (second parts) (third parts) t)))))

(defun openapi-v3-kind-patched-p (paths kind group version)
  "Report whether PATHS already offers a patch operation for this kind."
  (loop for item being the hash-values of paths
        for patch = (and (hash-table-p item) (gethash "patch" item))
        for gvk = (and patch (gethash "x-kubernetes-group-version-kind" patch))
        thereis (and (hash-table-p gvk) (equal kind (gethash "kind" gvk))
                     (equal group (gethash "group" gvk)) (equal version (gethash "version" gvk)))))

(defun openapi-v3-add-resource-paths (paths resource group version)
  "Describe a discovered RESOURCE's operations, so that clients can see which options each takes.
kubectl falls back to the v2 document when a kind has no patch operation here."
  (let* ((name (gethash "name" resource)) (kind (gethash "kind" resource))
         (namespaced (gethash "namespaced" resource))
         (verbs (coerce (gethash "verbs" resource #()) 'list))
         (prefix (if (equal group "") (format nil "/api/~A" version) (format nil "/apis/~A/~A" group version)))
         (collection (format nil "~A/~:[~;namespaces/{namespace}/~]~A" prefix namespaced name))
         (item (concatenate 'string collection "/{name}")))
    (flet ((operation (action &optional writes)
             (let ((operation (core-object "x-kubernetes-action" action
                                           "operationId" (format nil "~A~A~A" action (remove #\. group) kind)
                                           "x-kubernetes-group-version-kind" (core-object "group" group "version" version "kind" kind)
                                           "responses" (core-object "200" (core-object "description" "OK")))))
               (when writes
                 (setf (gethash "parameters" operation)
                       (vector (core-object "name" "fieldValidation" "in" "query"
                                            "schema" (core-object "type" "string" "enum" #("Strict" "Warn" "Ignore"))))))
               operation))
           (parameters (&rest names)
             (coerce (loop for parameter in names
                           collect (core-object "name" parameter "in" "path" "required" t "schema" (core-object "type" "string")))
                     'vector))
           (add (path verb operation parameters)
             (let ((entry (or (gethash path paths)
                              (setf (gethash path paths) (core-object "parameters" parameters)))))
               (unless (gethash verb entry) (setf (gethash verb entry) operation)))))
      (let ((collection-parameters (if namespaced (parameters "namespace") (parameters)))
            (item-parameters (if namespaced (parameters "namespace" "name") (parameters "name"))))
        (when (member "list" verbs :test #'equal) (add collection "get" (operation "list") collection-parameters))
        (when (member "create" verbs :test #'equal) (add collection "post" (operation "post" t) collection-parameters))
        (when (member "get" verbs :test #'equal) (add item "get" (operation "get") item-parameters))
        (when (member "update" verbs :test #'equal) (add item "put" (operation "put" t) item-parameters))
        (when (member "patch" verbs :test #'equal) (add item "patch" (operation "patch" t) item-parameters))
        (when (member "delete" verbs :test #'equal) (add item "delete" (operation "delete") item-parameters))))))

(defun openapi-v3-declare-field-validation (paths)
  "Declare fieldValidation on every write, since every request handler honors it."
  (loop for item being the hash-values of paths
        do (dolist (verb '("post" "put" "patch"))
             (let ((operation (and (hash-table-p item) (gethash verb item))))
               (when (and operation
                          (not (find "fieldValidation" (gethash "parameters" operation #()) :test #'equal
                                     :key (lambda (parameter) (gethash "name" parameter)))))
                 (setf (gethash "parameters" operation)
                       (concatenate 'vector (gethash "parameters" operation #())
                                    (vector (core-object "name" "fieldValidation" "in" "query"
                                                         "schema" (core-object "type" "string" "enum" #("Strict" "Warn" "Ignore")))))))))))

(defun openapi-v3-drop-empty-fields (value)
  "Remove the empty parameters lists and properties maps that kube-openapi's spec3 types omit,
so that a client's decode and re-encode of the document gives back an equal document."
  (cond ((hash-table-p value)
         (loop for key in (loop for key being the hash-keys of value collect key)
               for child = (gethash key value)
               do (if (or (and (equal key "parameters") (vectorp child) (zerop (length child)))
                          (and (equal key "properties") (hash-table-p child) (zerop (hash-table-count child))))
                      (remhash key value)
                      (openapi-v3-drop-empty-fields child))))
        ((and (vectorp value) (not (stringp value)))
         (map nil #'openapi-v3-drop-empty-fields value)))
  value)

(defun openapi-v3-complete-response (store runtime reconciler path)
  "Serve an OpenAPI v3 group document covering every resource its version discovers."
  (multiple-value-bind (group version found) (openapi-v3-document-group-version path)
    ;; An aggregated version's document is its own server's, which upstream's aggregator
    ;; publishes as it stands; it is fetched when asked for rather than kept.
    (when (and found (plusp (length group)))
      (let ((apiservice (aggregated-apiservice store group version)))
        (when apiservice
          (unless (apiservice-available-p apiservice)
            (core-resource-error 404 "NotFound" "No OpenAPI document for unavailable ~A/~A" group version))
          (return-from openapi-v3-complete-response
            (aggregated-api-proxy-response store apiservice :get
                                           :target (format nil "/openapi/v3/apis/~A/~A" group version))))))
    (let* ((body (let ((*openapi-v3-completing* t)) (route-http-request store runtime reconciler path :get)))
           (status (hunchentoot:return-code*)))
      (unless found (return-from openapi-v3-complete-response body))
      (let* ((discovery (com.inuoe.jzon:parse
                         (let ((*openapi-v3-completing* t))
                           (route-http-request store runtime reconciler
                                               (if (equal group "") (format nil "/api/~A" version) (format nil "/apis/~A/~A" group version))
                                               :get))))
             (resources (gethash "resources" discovery #()))
             (document (if (= status 200)
                           (com.inuoe.jzon:parse body)
                           ;; A document with no hand-written route still publishes its kinds' schemas.
                           (core-object "openapi" "3.0.0" "info" (core-object "title" "gr8s" "version" "v1")
                                        "paths" (core-object)
                                        "components" (core-object
                                                      "schemas"
                                                      (let ((*schema-reference-prefix* "#/components/schemas/"))
                                                        (openapi-definitions group version))))))
             (paths (gethash "paths" document)))
        (when (zerop (length resources))
          (setf (hunchentoot:return-code*) status)
          (return-from openapi-v3-complete-response body))
        (loop for resource across resources
              for own-group = (gethash "group" resource group)
              unless (or (find #\/ (gethash "name" resource)) (not (equal own-group group))
                         (openapi-v3-kind-patched-p paths (gethash "kind" resource) group version))
                do (openapi-v3-add-resource-paths paths resource group version))
        (openapi-v3-declare-field-validation paths)
        (openapi-v3-drop-empty-fields document)
        (setf (hunchentoot:return-code*) 200
              (hunchentoot:content-type*) "application/json")
        (com.inuoe.jzon:stringify document)))))
