;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Expose apps/v1 discovery, structural OpenAPI paths and real scale/status
;;;; subresources, including those of core/v1 ReplicationControllers. Subresource transactions preserve ordinary desired state,
;;;; optimistic revisions and the workload's server-owned generation.

(in-package #:gr8s)

(defun workload-api-group ()
  "Describe the implemented apps/v1 API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "apps" "versions" (vector (core-object "groupVersion" "apps/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "apps/v1" "version" "v1")))

(defun workload-resources-response ()
  "Advertise workload collections and their separately authorized subresources."
  (let ((resources (stored-resource-discovery "apps/v1")))
    (json-response
     (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "apps/v1" "resources"
                  (concatenate 'vector resources
                    (coerce (loop for name in '("deployments" "replicasets" "daemonsets" "statefulsets")
                                  for kind in '("Deployment" "ReplicaSet" "DaemonSet" "StatefulSet")
                                  append (append
                                          (unless (equal name "daemonsets")
                                            (list (core-object "name" (concatenate 'string name "/scale") "namespaced" t
                                                               "kind" "Scale" "group" "autoscaling" "version" "v1"
                                                               "verbs" #("get" "patch" "update"))))
                                          (list (core-object "name" (concatenate 'string name "/status") "namespaced" t
                                                             "kind" kind "verbs" #("get" "patch" "update"))))) 'vector))))))

(defun workload-subresource-route (path)
  "Resolve valid namespaced workload scale and status endpoints and Job and budget status endpoints."
  (let ((parts (uiop:split-string path :separator '(#\/))))
    (cond
      ((and (= 8 (length parts)) (equal (subseq parts 0 4) '("" "api" "v1" "namespaces"))
            (dns-label-p (fifth parts)) (equal (sixth parts) "replicationcontrollers")
            (dns-subdomain-p (seventh parts)) (member (eighth parts) '("scale" "status") :test #'equal))
       (list (sixth parts) (fifth parts) (seventh parts) (eighth parts)))
      ((and (= 9 (length parts)) (dns-label-p (sixth parts)) (dns-subdomain-p (eighth parts))
            (or (and (equal (subseq parts 0 5) '("" "apis" "apps" "v1" "namespaces"))
                     (member (seventh parts) '("deployments" "replicasets" "statefulsets") :test #'equal)
                     (member (ninth parts) '("scale" "status") :test #'equal))
                (and (equal (subseq parts 0 5) '("" "apis" "apps" "v1" "namespaces"))
                     (equal (seventh parts) "daemonsets") (equal (ninth parts) "status"))
                (and (equal (subseq parts 0 5) '("" "apis" "batch" "v1" "namespaces"))
                     (batch-resource-p (seventh parts)) (equal (ninth parts) "status"))
                (and (equal (subseq parts 0 5) '("" "apis" "policy" "v1" "namespaces"))
                     (budget-resource-p (seventh parts)) (equal (ninth parts) "status"))))
       (list (seventh parts) (sixth parts) (eighth parts) (ninth parts))))))

(defun workload-scale-object (object)
  "Return desired replicas and observed replicas/selector using the real workload identity."
  (core-object "apiVersion" "autoscaling/v1" "kind" "Scale" "metadata" (copy-core-object (workload-metadata object))
               "spec" (core-object "replicas" (gethash "replicas" (gethash "spec" object)))
               "status" (core-object "replicas" (gethash "replicas" (gethash "status" object) 0)
                                     "selector" (workload-selector-string (workload-spec-selector object)))))

(defun workload-read-subresource-input (old kind schema method)
  "Read JSON/protobuf PUT or schema-aware supported patch formats."
  (if (eq method :put) (core-resource-request-object kind)
      (let* ((content-type (request-media-type))
             (patch (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t))))
        (cond ((equal content-type "application/json-patch+json") (apply-core-json-patch old patch))
              ((equal content-type "application/merge-patch+json") (merge-json-object old (require-object patch "patch")))
              ((equal content-type "application/strategic-merge-patch+json")
               (template-strategic-merge old (require-object patch "patch") schema))
              (t (core-resource-error 415 "UnsupportedMediaType" "Unsupported workload subresource patch format"))))))

(defun workload-update-status-request (store resource namespace name input dry-run)
  "Write only status, preserving spec, generation and protected resource identity."
  (let* ((metadata (require-object (gethash "metadata" input) "metadata"))
         (status (require-object (gethash "status" input) "status")))
    (unless (and (equal (core-resource-kind resource) (gethash "kind" input (core-resource-kind resource)))
                 (equal (core-resource-api-version resource) (gethash "apiVersion" input (core-resource-api-version resource))))
      (core-resource-error 400 "BadRequest" "Incorrect workload status kind or API version"))
    (validate-template-shape status (template-schema (workload-schema-name resource "Status")) "status")
    (when (budget-resource-p resource) (validate-disruption-status status))
    (with-store-lock (store)
      (let* ((existing (get-core-resource-unlocked store resource namespace name)) (emeta (workload-metadata existing))
             (copy (copy-core-object existing)) (resources (copy-core-resource-index store))
             (revision (1+ (pod-store-resource-revision store))))
        (unless (or (member (gethash "resourceVersion" metadata) '(nil "") :test #'equal)
                    (equal (gethash "resourceVersion" metadata) (gethash "resourceVersion" emeta)))
          (core-resource-error 409 "Conflict" "Resource version has changed"))
        (when (and (gethash "uid" metadata) (not (equal (gethash "uid" metadata) (gethash "uid" emeta))))
          (core-resource-error 409 "Conflict" "UID precondition does not match"))
        (when (and (gethash "name" metadata) (not (equal name (gethash "name" metadata))))
          (core-resource-error 400 "BadRequest" "metadata.name does not match request name"))
        (setf (gethash "status" copy) (copy-core-object status))
        ;; Kubernetes status writes may also change these, but never the spec.
        (dolist (field '("labels" "annotations"))
          (multiple-value-bind (value present) (gethash field metadata)
            (when (and present (not (eq value 'null)))
              (setf (gethash field (workload-metadata copy)) (copy-core-object value)))))
        (prepare-core-resource-metadata copy existing revision)
        (setf (gethash (core-resource-key resource namespace name) resources) copy)
        (unless dry-run (commit-core-resources store resources revision))
        copy))))

(defun dispatch-workload-subresource (store path method)
  "Serve independently authorized scale and status without accepting spec writes through status."
  (destructuring-bind (resource namespace name subresource) (workload-subresource-route path)
    (let* ((old (get-core-resource store resource namespace name))
           (scale (equal subresource "scale")) (kind (if scale "Scale" (core-resource-kind resource)))
           (representation (if scale (workload-scale-object old) old))
           (schema (template-schema (if scale "io.k8s.api.autoscaling.v1.Scale"
                                       (workload-schema-name resource "")))))
      (cond ((eq method :get) (json-response representation))
            ((member method '(:put :patch))
             (let* ((dry-run (core-resource-dry-run-p))
                    (input (admit-subresource-write store resource subresource namespace name
                                                    (workload-read-subresource-input representation kind schema method)
                                                    representation
                                                    :kind (when scale "Scale") :kind-api-version (when scale "autoscaling/v1")
                                                    :dry-run dry-run))
                    (metadata (require-object (gethash "metadata" input) "metadata")))
               (when (and (gethash "name" metadata) (not (equal name (gethash "name" metadata))))
                 (core-resource-error 400 "BadRequest" "metadata.name does not match request name"))
               (when (and (gethash "namespace" metadata) (not (member (gethash "namespace" metadata) (list "" namespace) :test #'equal)))
                 (core-resource-error 400 "BadRequest" "metadata.namespace does not match request namespace"))
               (if scale
                   (progn
                     (validate-template-shape input schema "Scale")
                     (unless (and (equal "Scale" (gethash "kind" input "Scale"))
                                  (equal "autoscaling/v1" (gethash "apiVersion" input "autoscaling/v1")))
                       (core-resource-error 400 "BadRequest" "Expected autoscaling/v1 Scale"))
                     (let* ((count (workload-int (gethash "replicas" (require-object (gethash "spec" input) "spec")) "spec.replicas"))
                            (updated (update-core-resource store resource namespace name
                                       (lambda (current)
                                         (unless (member (gethash "resourceVersion" metadata) '(nil "") :test #'equal)
                                           (setf (gethash "resourceVersion" (workload-metadata current)) (gethash "resourceVersion" metadata)))
                                         (when (gethash "uid" metadata) (setf (gethash "uid" (workload-metadata current)) (gethash "uid" metadata)))
                                         (setf (gethash "replicas" (gethash "spec" current)) count) current) :dry-run dry-run)))
                       (json-response (workload-scale-object updated))))
                   (json-response (workload-update-status-request store resource namespace name input dry-run)))))
            (t (core-resource-error 405 "MethodNotAllowed" "Unsupported workload subresource method"))))))

(defun add-workload-openapi-paths (paths)
  "Describe workload CRUD, collection deletion, and status/scale request schemas."
  (dolist (resource '("deployments" "replicasets" "daemonsets" "statefulsets" "controllerrevisions"))
    (let* ((kind (core-resource-kind resource)) (schema (concatenate 'string "io.k8s.api.apps.v1." kind))
           (collection (format nil "/apis/apps/v1/namespaces/{namespace}/~A" resource))
           (item (concatenate 'string collection "/{name}")))
      (labels ((parameters (&optional item)
                 (coerce (loop for name in (if item '("namespace" "name") '("namespace"))
                               collect (core-object "name" name "in" "path" "required" t "schema" (core-object "type" "string"))) 'vector))
               (operation (action &optional body-schema)
                 (let ((operation (core-object "operationId" (format nil "~AAppsV1Namespaced~A" action kind)
                                               "x-kubernetes-group-version-kind" (core-object "group" "apps" "version" "v1" "kind" kind)
                                               "responses" (core-object "200" (core-object "description" "Success")))))
                   (when body-schema
                     (setf (gethash "requestBody" operation)
                           (core-object "required" t "content" (core-object "application/json" (core-object "schema" (reference-schema body-schema))
                                                                            "application/strategic-merge-patch+json" (core-object "schema" (reference-schema body-schema))))))
                   operation)))
        (setf (gethash collection paths) (core-object "parameters" (parameters) "get" (operation "list") "post" (operation "create" schema) "delete" (operation "deleteCollection"))
              (gethash item paths) (core-object "parameters" (parameters t) "get" (operation "read") "put" (operation "replace" schema)
                                               "patch" (operation "patch" schema) "delete" (operation "delete")))
        (dolist (subresource (cond ((equal resource "controllerrevisions") nil)
                                   ((equal resource "daemonsets") '("status"))
                                   (t '("status" "scale"))))
          (let ((subschema (if (equal subresource "scale") "io.k8s.api.autoscaling.v1.Scale" schema)))
            (setf (gethash (concatenate 'string item "/" subresource) paths)
                  (core-object "parameters" (parameters t) "get" (operation (concatenate 'string "read" subresource))
                               "put" (operation (concatenate 'string "replace" subresource) subschema)
                               "patch" (operation (concatenate 'string "patch" subresource) subschema))))))))
  paths)

(defun batch-api-group ()
  "Describe the implemented batch/v1 API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "batch"
               "versions" (vector (core-object "groupVersion" "batch/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "batch/v1" "version" "v1")))

(defun batch-resources-response ()
  "Advertise Jobs, CronJobs and their separately authorized status subresources."
  (json-response
   (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "batch/v1" "resources"
                (concatenate 'vector (stored-resource-discovery "batch/v1")
                             (vector (core-object "name" "jobs/status" "namespaced" t "kind" "Job"
                                                  "verbs" #("get" "patch" "update"))
                                     (core-object "name" "cronjobs/status" "namespaced" t "kind" "CronJob"
                                                  "verbs" #("get" "patch" "update")))))))
