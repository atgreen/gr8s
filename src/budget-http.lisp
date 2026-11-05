;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Expose policy/v1 discovery and OpenAPI paths for PodDisruptionBudgets. Their
;;;; status subresource is served with the workloads', and evictions in pod-eviction.lisp.

(in-package #:gr8s)

(defun budget-api-group ()
  "Describe the implemented policy/v1 API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "policy"
               "versions" (vector (core-object "groupVersion" "policy/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "policy/v1" "version" "v1")))

(defun budget-resources-response ()
  "Advertise PodDisruptionBudgets and their separately authorized status subresource."
  (let ((resources (stored-resource-discovery "policy/v1")))
    (json-response
     (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "policy/v1"
                  "resources" (concatenate 'vector resources
                                           (vector (core-object "name" "poddisruptionbudgets/status" "namespaced" t
                                                                "kind" "PodDisruptionBudget" "verbs" #("get" "patch" "update"))))))))

(defun add-budget-openapi-paths (paths)
  "Describe PodDisruptionBudget CRUD and status schemas for clients that discover them."
  (let* ((schema "io.k8s.api.policy.v1.PodDisruptionBudget")
         (collection "/apis/policy/v1/namespaces/{namespace}/poddisruptionbudgets")
         (item (concatenate 'string collection "/{name}")))
    (labels ((parameters (names)
               (coerce (loop for name in names
                             collect (core-object "name" name "in" "path" "required" t "schema" (core-object "type" "string"))) 'vector))
             (operation (action &optional body)
               (let ((result (core-object "operationId" (format nil "~APolicyV1NamespacedPodDisruptionBudget" action)
                                          "x-kubernetes-group-version-kind"
                                          (core-object "group" "policy" "version" "v1" "kind" "PodDisruptionBudget")
                                          "responses" (core-object "200" (core-object "description" "Success")))))
                 (when body
                   (setf (gethash "requestBody" result)
                         (core-object "required" t "content"
                                      (core-object "application/json" (core-object "schema" (reference-schema schema))))))
                 result)))
      (setf (gethash collection paths)
            (core-object "parameters" (parameters '("namespace")) "get" (operation "list")
                         "post" (operation "create" t) "delete" (operation "deleteCollection"))
            (gethash item paths)
            (core-object "parameters" (parameters '("namespace" "name")) "get" (operation "read")
                         "put" (operation "replace" t) "patch" (operation "patch" t) "delete" (operation "delete"))
            (gethash (concatenate 'string item "/status") paths)
            (core-object "parameters" (parameters '("namespace" "name")) "get" (operation "readStatus")
                         "put" (operation "replaceStatus" t) "patch" (operation "patchStatus" t)))))
  paths)
