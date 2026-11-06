;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Publish discovery and structural OpenAPI for stable EndpointSlices. Ordinary
;;;; JSON/protobuf CRUD, selector lists, durable watches and patches use the shared
;;;; transactional registry; EndpointSlices do not expose synthetic status routes.

(in-package #:gr8s)

(defun endpointslice-api-group ()
  "Describe the implemented stable network discovery API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "discovery.k8s.io"
               "versions" (vector (core-object "groupVersion" "discovery.k8s.io/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "discovery.k8s.io/v1" "version" "v1")))

(defun endpointslice-discovery-response ()
  "Advertise actual EndpointSlice operations from the durable registry."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "discovery.k8s.io/v1"
                              "resources" (stored-resource-discovery "discovery.k8s.io/v1"))))

(defun add-endpointslice-openapi-paths (paths)
  "Describe namespaced and cluster-wide lists with typed item and mutation schemas."
  (labels ((parameter (name)
             (core-object "name" name "in" "path" "required" t "schema" (core-object "type" "string")))
           (operation (method)
             (let ((operation (core-object "x-kubernetes-action" method
                                           "x-kubernetes-group-version-kind" (core-object "group" "discovery.k8s.io" "version" "v1" "kind" "EndpointSlice")
                                           "responses" (core-object "200" (core-object "description" "Success")))))
               (when (member method '("post" "put" "patch") :test #'equal)
                 (setf (gethash "requestBody" operation)
                       (core-object "required" t "content"
                                    (core-object "application/json" (core-object "schema" (reference-schema "io.k8s.api.discovery.v1.EndpointSlice"))
                                                 "application/strategic-merge-patch+json" (core-object "schema" (reference-schema "io.k8s.api.discovery.v1.EndpointSlice"))))))
               operation)))
    (let* ((collection "/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices")
           (item (concatenate 'string collection "/{name}")))
      (setf (gethash "/apis/discovery.k8s.io/v1/endpointslices" paths) (core-object "get" (operation "list"))
            (gethash collection paths) (core-object "parameters" (vector (parameter "namespace"))
                                                    "get" (operation "list") "post" (operation "post") "delete" (operation "deletecollection"))
            (gethash item paths) (core-object "parameters" (vector (parameter "namespace") (parameter "name"))
                                              "get" (operation "get") "put" (operation "put") "patch" (operation "patch") "delete" (operation "delete")))))
  paths)
