;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Expose node.k8s.io and scheduling.k8s.io discovery, OpenAPI paths for the
;;;; policy collections, and the ResourceQuota status subresource. Ordinary
;;;; operations and watches run through the shared durable resource store.

(in-package #:gr8s)

(defun policy-api-group (group)
  "Describe the served v1 API GROUP."
  (let ((version (format nil "~A/v1" group)))
    (core-object "apiVersion" "v1" "kind" "APIGroup" "name" group
                 "versions" (vector (core-object "groupVersion" version "version" "v1"))
                 "preferredVersion" (core-object "groupVersion" version "version" "v1"))))

(defun policy-discovery-response (group)
  "Describe the collections actually served in GROUP's v1 version."
  (let ((version (format nil "~A/v1" group)))
    (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" version
                                "resources" (stored-resource-discovery version)))))

(defun policy-status-discovery ()
  "Advertise the ResourceQuota status subresource."
  (vector (core-object "name" "resourcequotas/status" "singularName" "" "namespaced" t
                       "kind" "ResourceQuota" "verbs" #("get" "patch" "update"))))

(defun policy-status-route (path)
  "Resolve a named ResourceQuota status URL to its collection, namespace and name."
  (when (uiop:string-suffix-p path "/status")
    (let ((route (core-resource-route (subseq path 0 (- (length path) 7)))))
      (when (and route (third route) (equal "resourcequotas" (first route))) route))))

(defun dispatch-policy-status-request (store path method)
  "Read or replace only a ResourceQuota's status, never its spec."
  (destructuring-bind (resource namespace name) (policy-status-route path)
    (when (eq method :get)
      (return-from dispatch-policy-status-request (json-response (get-core-resource store resource namespace name))))
    (unless (member method '(:put :patch))
      (core-resource-error 405 "MethodNotAllowed" "Unsupported ResourceQuota status method"))
    (let* ((*policy-status-write* t)
           (dry-run (core-resource-dry-run-p))
           (content-type (request-media-type))
           (input (if (eq method :put)
                      (core-resource-request-object (core-resource-kind resource))
                      (progn
                        (unless (member content-type '("application/merge-patch+json" "application/strategic-merge-patch+json"
                                                       "application/json-patch+json")
                                        :test #'equal)
                          (core-resource-error 415 "UnsupportedMediaType" "Unsupported ResourceQuota status patch type"))
                        (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t))))))
      (json-response
       (update-core-resource
        store resource namespace name
        (lambda (old)
          (let* ((requested (cond ((eq method :put) input)
                                  ((equal content-type "application/json-patch+json")
                                   (apply-core-json-patch (copy-core-object old) input))
                                  (t (merge-json-object (copy-core-object old) (require-object input "patch")))))
                 (metadata (require-object (gethash "metadata" requested) "metadata")))
            (unless (and (equal name (gethash "name" metadata))
                         (member (gethash "namespace" metadata namespace) (list namespace "") :test #'equal))
              (core-resource-error 400 "BadRequest" "ResourceQuota status metadata does not match its URL"))
            (setf (gethash "status" old) (copy-core-object (require-object (gethash "status" requested (core-object)) "status")))
            (unless (member (gethash "resourceVersion" metadata) '(nil "") :test #'equal)
              (setf (gethash "resourceVersion" (gethash "metadata" old)) (gethash "resourceVersion" metadata)))
            old))
        :dry-run dry-run)))))

(defun node-status-route (path)
  "Return the node name of a /api/v1/nodes/NAME/status URL."
  (let ((parts (uiop:split-string path :separator '(#\/))))
    (when (and (= 6 (length parts)) (equal (subseq parts 0 4) '("" "api" "v1" "nodes"))
               (equal "status" (sixth parts)) (dns-subdomain-p (fifth parts)))
      (fifth parts))))

(defun node-status-extended-resources (status)
  "Select the valid extended resources a written Node STATUS advertises.
As with a kubelet, measured CPU, memory, storage and conditions are never taken from clients."
  (let ((source (or (gethash "allocatable" status) (gethash "capacity" status)))
        (resources (core-object)))
    (when source
      (maphash (lambda (name value)
                 (when (extended-resource-name-p name)
                   (let ((quantity (policy-quantity value (format nil "status.allocatable[~A]" name))))
                     (when (or (minusp (container-quantity-coefficient quantity))
                               (minusp (container-quantity-scale quantity)))
                       (core-resource-error 422 "Invalid" "Extended resource ~A must be a whole nonnegative number" name))
                     (setf (gethash name resources) (container-quantity-string quantity)))))
               source))
    resources))

(defun dispatch-node-status-request (store path method)
  "Serve Node status, whose writes advertise the extended resources the scheduler charges."
  (let* ((name (node-status-route path))
         (current (node-api-object (get-node store name))))
    (when (eq method :get)
      (return-from dispatch-node-status-request (json-response current)))
    (unless (member method '(:put :patch))
      (core-resource-error 405 "MethodNotAllowed" "Unsupported Node status method"))
    (let* ((content-type (request-media-type))
           (requested
             (if (eq method :put)
                 (core-resource-request-object "Node")
                 (let ((patch (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t))))
                   (cond ((equal content-type "application/json-patch+json")
                          (apply-core-json-patch (copy-core-object current) patch))
                         ((member content-type '("application/merge-patch+json" "application/strategic-merge-patch+json")
                                  :test #'equal)
                          (merge-json-object (copy-core-object current) (require-object patch "patch")))
                         (t (core-resource-error 415 "UnsupportedMediaType" "Unsupported Node status patch type"))))))
           (metadata (require-object (gethash "metadata" requested (core-object)) "metadata")))
      (when (and (gethash "name" metadata) (not (equal name (gethash "name" metadata))))
        (core-resource-error 400 "BadRequest" "Node status metadata does not match its URL"))
      (let ((resources (node-status-extended-resources (require-object (gethash "status" requested (core-object)) "status"))))
        (unless (core-resource-dry-run-p)
          (update-node-extended-resources store name (and (plusp (hash-table-count resources)) resources))))
      (json-response (node-api-object (get-node store name))))))

(defun add-policy-openapi-paths (paths version)
  "Describe the policy collections served in API VERSION from the pinned schemas."
  (dolist (resource '("resourcequotas" "limitranges" "runtimeclasses" "priorityclasses"))
    (when (equal version (core-resource-api-version resource))
      (let* ((namespaced (core-resource-namespaced-p resource))
             (kind (core-resource-kind resource))
             (slash (position #\/ version))
             (group (if slash (subseq version 0 slash) ""))
             (prefix (if slash (concatenate 'string "/apis/" version) "/api/v1"))
             (collection (concatenate 'string prefix (if namespaced "/namespaces/{namespace}/" "/") resource))
             (item (concatenate 'string collection "/{name}")))
        (labels ((parameter (name)
                   (core-object "name" name "in" "path" "required" t "schema" (core-object "type" "string")))
                 (operation (method)
                   (let ((operation (core-object "x-kubernetes-action" method
                                                 "x-kubernetes-group-version-kind"
                                                 (core-object "group" group "version" "v1" "kind" kind)
                                                 "responses" (core-object "200" (core-object "description" "Success")))))
                     (when (member method '("post" "put" "patch") :test #'equal)
                       (setf (gethash "requestBody" operation)
                             (core-object "required" t "content"
                                          (core-object (if (equal method "patch") "application/strategic-merge-patch+json" "application/json")
                                                       (core-object "schema" (reference-schema (policy-resource-schema-name resource)))))))
                     operation)))
          (setf (gethash collection paths)
                (core-object "parameters" (if namespaced (vector (parameter "namespace")) #())
                             "get" (operation "list") "post" (operation "post") "delete" (operation "deletecollection"))
                (gethash item paths)
                (core-object "parameters" (if namespaced (vector (parameter "namespace") (parameter "name")) (vector (parameter "name")))
                             "get" (operation "get") "put" (operation "put") "patch" (operation "patch") "delete" (operation "delete")))
          (when (equal resource "resourcequotas")
            (setf (gethash (concatenate 'string item "/status") paths)
                  (core-object "parameters" (gethash "parameters" (gethash item paths))
                               "get" (operation "get") "put" (operation "put") "patch" (operation "patch"))))))))
  paths)
