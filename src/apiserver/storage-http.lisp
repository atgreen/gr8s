;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Expose typed storage discovery, status writes and OpenAPI paths. Ordinary
;;;; resource operations and durable watches use the existing shared API store.

(in-package #:gr8s.apiserver)

(defun storage-api-group ()
  "Describe the stable storage.k8s.io API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "storage.k8s.io"
               "versions" (vector (core-object "groupVersion" "storage.k8s.io/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "storage.k8s.io/v1" "version" "v1")))

(defun storage-discovery-response ()
  "Describe actual StorageClass operations using the shared resource registry."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "storage.k8s.io/v1"
                              "resources" (concatenate 'vector (stored-resource-discovery "storage.k8s.io/v1")
                                                       (map 'vector (lambda (resource)
                                                                      (core-object "name" (concatenate 'string resource "/status") "singularName" ""
                                                                                   "namespaced" nil "kind" (core-resource-kind resource)
                                                                                   "verbs" #("get" "patch" "update")))
                                                            '("csinodes" "volumeattachments"))))))

(defun storage-status-discovery ()
  "Advertise implemented PV/PVC status subresources; VolumeAttachment's belongs to storage.k8s.io."
  (map 'vector (lambda (resource)
                 (core-object "name" (concatenate 'string resource "/status") "singularName" ""
                              "namespaced" (core-resource-namespaced-p resource) "kind" (core-resource-kind resource)
                              "verbs" #("get" "patch" "update")))
       '("persistentvolumes" "persistentvolumeclaims")))

(defun storage-status-route (path)
  "Resolve only named PV, PVC, CSINode and VolumeAttachment status subresources."
  (when (uiop:string-suffix-p path "/status")
    (let ((route (core-resource-route (subseq path 0 (- (length path) 7)))))
      (when (and route (third route) (member (first route) '("persistentvolumes" "persistentvolumeclaims" "csinodes" "volumeattachments") :test #'equal)) route))))

(defun dispatch-storage-status-request (store path method)
  "Read or atomically update storage status without allowing status writes to replace spec."
  (destructuring-bind (resource namespace name) (storage-status-route path)
    (when (eq method :get) (return-from dispatch-storage-status-request (json-response (get-core-resource store resource namespace name))))
    (unless (member method '(:put :patch)) (core-resource-error 405 "MethodNotAllowed" "Unsupported storage status method"))
    (let* ((*storage-status-write* t)
           (dry-run (core-resource-dry-run-p))
           (content-type (request-media-type))
           (input (if (eq method :put) (core-resource-request-object (core-resource-kind resource))
                      (progn
                        (unless (member content-type '("application/merge-patch+json" "application/strategic-merge-patch+json" "application/json-patch+json") :test #'equal)
                          (core-resource-error 415 "UnsupportedMediaType" "Unsupported storage status patch type"))
                        (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-binary t)))))
           (admit (lambda (requested old)
                    (admit-subresource-write store resource "status" namespace name requested old :dry-run dry-run)))
           (admission-probe (admission-attributes-for store "UPDATE" resource namespace name :subresource "status")))
      ;; Webhooks cannot run inside the update's transaction, so settle a selected write first.
      (when (admission-active-p store admission-probe)
        (let* ((old (get-core-resource store resource namespace name)))
          (setf input (funcall admit (if (eq method :put) input
                                         (if (equal content-type "application/json-patch+json")
                                             (apply-core-json-patch (copy-core-object old) input)
                                             (merge-json-object (copy-core-object old) (require-object input "patch"))))
                               old)
                method :put)))
      (json-response
       (update-core-resource
        store resource namespace name
        (lambda (old)
          (let* ((requested (if (eq method :put) input
                                (if (equal content-type "application/json-patch+json")
                                    (apply-core-json-patch (copy-core-object old) input)
                                    (merge-json-object (copy-core-object old) (require-object input "patch")))))
                 (metadata (require-object (gethash "metadata" requested) "metadata")))
            (unless (and (equal name (gethash "name" metadata))
                         (or (null namespace) (equal namespace (gethash "namespace" metadata namespace))))
              (core-resource-error 400 "BadRequest" "Storage status metadata does not match its URL"))
            (setf (gethash "status" old) (copy-core-object (require-object (gethash "status" requested) "status"))
                  (gethash "resourceVersion" (gethash "metadata" old)) (gethash "resourceVersion" metadata))
            old))
        :dry-run dry-run)))))

(defun delete-storage-collection (store resource namespace labels fields &key dry-run)
  "Honor per-object storage protection when deleting a selector-matched collection."
  (let ((label-test (core-selector-predicate labels))
        (field-test (core-selector-predicate fields :fields t :field-paths (core-resource-field-paths resource))))
    (dolist (object (list-core-resources store resource namespace))
      (when (and (funcall label-test object) (funcall field-test object))
        (let ((metadata (gethash "metadata" object)))
          (delete-core-resource store resource namespace (gethash "name" metadata)
                                :uid (gethash "uid" metadata) :dry-run dry-run))))))

(defun add-storage-openapi-paths (paths &optional (version "v1"))
  "Describe stable storage paths from the pinned schemas."
  (dolist (resource '("persistentvolumes" "persistentvolumeclaims" "storageclasses" "volumeattributesclasses"
                      "csidrivers" "csinodes" "volumeattachments" "csistoragecapacities"))
    (when (equal version (core-resource-api-version resource))
      (let* ((namespaced (core-resource-namespaced-p resource))
             (kind (core-resource-kind resource))
             (prefix (if (equal version "v1") "/api/v1" "/apis/storage.k8s.io/v1"))
             (collection (concatenate 'string prefix (if namespaced "/namespaces/{namespace}/" "/") resource))
             (item (concatenate 'string collection "/{name}")))
        (labels ((parameter (name)
                   (core-object "name" name "in" "path" "required" t "schema" (core-object "type" "string")))
                 (operation (method)
                   (let ((operation (core-object "x-kubernetes-action" method
                                                  "x-kubernetes-group-version-kind" (core-object "group" (if (equal version "v1") "" "storage.k8s.io") "version" "v1" "kind" kind)
                                                  "responses" (core-object "200" (core-object "description" "Success")))))
                     (when (member method '("post" "put" "patch") :test #'equal)
                       (setf (gethash "parameters" operation) (vector (core-object "name" "fieldValidation" "in" "query" "schema" (core-object "type" "string")))
                             (gethash "requestBody" operation)
                             (core-object "required" t "content"
                                          (core-object (if (equal method "patch") "application/strategic-merge-patch+json" "application/json")
                                                       (core-object "schema" (reference-schema (storage-resource-schema-name resource)))))))
                     operation)))
          (setf (gethash collection paths)
                (core-object "parameters" (if namespaced (vector (parameter "namespace")) #())
                             "get" (operation "list") "post" (operation "post") "delete" (operation "deletecollection"))
                (gethash item paths)
                (core-object "parameters" (if namespaced (vector (parameter "namespace") (parameter "name")) (vector (parameter "name")))
                             "get" (operation "get") "put" (operation "put") "patch" (operation "patch") "delete" (operation "delete")))
          (when (member resource '("persistentvolumes" "persistentvolumeclaims" "csinodes" "volumeattachments") :test #'equal)
            (setf (gethash (concatenate 'string item "/status") paths)
                  (core-object "parameters" (gethash "parameters" (gethash item paths))
                               "get" (operation "get") "put" (operation "put") "patch" (operation "patch"))))))))
  paths)
