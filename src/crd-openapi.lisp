;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Publish each genuinely served custom version's structural OpenAPI schema
;;;; and CRUD/status paths. Schema identities include group/version/kind rather
;;;; than relying on plural names that can collide across independent groups.

(in-package #:gr8s)

(defparameter *crd-definition-schema*
  (gethash "schema" (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/crd-v1.json"))))

(defun crd-openapi-builtin-definition ()
  "Describe the actual JSON CRD API using its supported request schema."
  (core-object "spec" (core-object "group" "apiextensions.k8s.io" "scope" "Cluster"
                   "names" (core-object "plural" "customresourcedefinitions" "kind" "CustomResourceDefinition" "listKind" "CustomResourceDefinitionList"))))

(defun crd-openapi-definition-name (definition version &optional list)
  "Return a group-qualified schema identity for one actual custom kind."
  (let* ((spec (gethash "spec" definition)) (names (gethash "names" spec)))
    (format nil "io.gr8s.custom.~A.~A.~A" (gethash "group" spec) version (gethash (if list "listKind" "kind") names))))

(defun crd-add-openapi-version (document definition version v3)
  "Publish an admitted version's schemas and real collection/item/status paths."
  (let* ((spec (gethash "spec" definition)) (names (gethash "names" spec))
         (group (gethash "group" spec)) (version-name (gethash "name" version))
         (schema-name (crd-openapi-definition-name definition version-name))
         (list-name (crd-openapi-definition-name definition version-name t))
         (schema (copy-core-object (crd-schema version)))
         (definitions (if v3 (gethash "schemas" (gethash "components" document)) (gethash "definitions" document)))
         (paths (gethash "paths" document)) (namespaced (equal "Namespaced" (gethash "scope" spec)))
         (collection (format nil "/apis/~A/~A/~A~A" group version-name
                             (if namespaced "namespaces/{namespace}/" "") (gethash "plural" names)))
         (item (concatenate 'string collection "/{name}")))
    (setf (gethash "x-kubernetes-group-version-kind" schema)
          (vector (core-object "group" group "version" version-name "kind" (gethash "kind" names))))
    (let ((properties (gethash "properties" schema (core-object))))
      (dolist (field '("kind" "apiVersion")) (setf (gethash field properties) (core-object "type" "string")))
      (setf (gethash "metadata" properties) (reference-schema "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta")
            (gethash "properties" schema) properties))
    (setf (gethash schema-name definitions) schema
          (gethash list-name definitions)
          (core-object "type" "object" "properties"
                       (core-object "apiVersion" (core-object "type" "string") "kind" (core-object "type" "string")
                                    "metadata" (core-object "type" "object" "properties" (core-object "resourceVersion" (core-object "type" "string") "continue" (core-object "type" "string")))
                                    "items" (core-object "type" "array" "items" (reference-schema schema-name)))
                       "x-kubernetes-group-version-kind" (vector (core-object "group" group "version" version-name "kind" (gethash "listKind" names)))))
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

(defun crd-openapi-document (store group version v3)
  "Build a current OpenAPI document from genuinely served durable definitions."
  (let* ((*schema-reference-prefix* (if v3 "#/components/schemas/" "#/definitions/"))
         (document (if v3 (core-object "openapi" "3.0.0" "info" (core-object "title" "gr8s custom APIs" "version" "v1")
                                      "paths" (core-object) "components" (core-object "schemas" (openapi-definitions)))
                       (openapi-document))))
    (let* ((definitions (if v3 (gethash "schemas" (gethash "components" document)) (gethash "definitions" document)))
           (metadata (gethash "properties" (gethash "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta" definitions))))
      (setf (gethash "finalizers" metadata) (core-object "type" "array" "items" (core-object "type" "string"))
            (gethash "ownerReferences" metadata) (core-object "type" "array" "items" (core-object "type" "object" "properties"
                 (core-object "apiVersion" (core-object "type" "string") "kind" (core-object "type" "string")
                              "name" (core-object "type" "string") "uid" (core-object "type" "string")
                              "controller" (core-object "type" "boolean") "blockOwnerDeletion" (core-object "type" "boolean"))))
            (gethash "io.k8s.apimachinery.pkg.apis.meta.v1.Status" definitions)
            (core-object "type" "object" "properties" (core-object "apiVersion" (core-object "type" "string") "kind" (core-object "type" "string")
                          "status" (core-object "type" "string") "message" (core-object "type" "string") "reason" (core-object "type" "string")
                          "code" (core-object "type" "integer")))))
    (when (or (null group) (equal group "apiextensions.k8s.io"))
      (crd-add-openapi-version document (crd-openapi-builtin-definition)
                               (core-object "name" "v1" "schema" (core-object "openAPIV3Schema" *crd-definition-schema*)) v3))
    (dolist (definition (list-core-resources store "customresourcedefinitions"))
      (when (or (null group) (equal group (gethash "group" (gethash "spec" definition))))
        (loop for entry across (gethash "versions" (gethash "spec" definition))
              when (and (gethash "served" entry) (or (null version) (equal version (gethash "name" entry))))
                do (crd-add-openapi-version document definition entry v3))))
    (when (or (null group) (equal group "apiextensions.k8s.io"))
      (remhash "delete" (gethash "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" (gethash "paths" document))))
    document))

(defun crd-openapi-discovery-response (store)
  "Expose current schema URLs for every actually served group/version."
  (let ((paths (core-object "api/v1" (core-object "serverRelativeURL" "/openapi/v3/api/v1?hash=gr8s-v1")
                            "apis/events.k8s.io/v1" (core-object "serverRelativeURL" "/openapi/v3/apis/events.k8s.io/v1?hash=gr8s-events-v1"))))
    (dolist (group (crd-api-groups store))
      (loop for version across (gethash "versions" group)
            for key = (concatenate 'string "apis/" (gethash "groupVersion" version))
            do (setf (gethash key paths) (core-object "serverRelativeURL"
                                                     (format nil "/openapi/v3/~A?hash=~D" key (pod-store-resource-revision store))))))
    (json-response (core-object "paths" paths))))
