;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The Kubernetes REST surface: HTTP requests in, Kubernetes JSON out.
;;;;
;;;; This file turns API requests into store and reconciler calls and encodes the
;;;; replies the way kubectl and client-go expect them. It holds three things a
;;;; real kube-apiserver keeps apart: the JSON object/response helpers every
;;;; handler shares; the Pod lifecycle handlers (create, get, list/watch, apply,
;;;; replace, delete, logs) and the discovery documents that advertise them (API
;;;; groups and resources, OpenAPI v2 and v3); and the exec/attach bridge, which
;;;; upgrades the client connection to the Kubernetes remotecommand channel
;;;; protocol and either drives a node exec session or proxies containerd's local
;;;; streaming server. The guiding constraint throughout is byte-level fidelity to
;;;; upstream's wire behaviour -- media types, status reasons, resourceVersion
;;;; ordering -- because conformance clients compare it literally.
;;;;
;;;; See https://kubernetes.io/docs/reference/using-api/api-concepts/ for the
;;;; list/watch and resourceVersion semantics the Pod handlers implement.

(in-package #:gr8s.apiserver)

(defun shallow-copy-object (object)
  "Copy OBJECT's top level only, sharing its values."
  (let ((copy (make-hash-table :test (hash-table-test object) :size (hash-table-count object))))
    (maphash (lambda (key value) (setf (gethash key copy) value)) object)
    copy))

(defun list-items-without-type-meta (object)
  "Return a typed list OBJECT whose items carry no apiVersion or kind, as upstream encodes a
built-in or PartialObjectMetadata list; the list's own kind names theirs. Custom resource
lists keep them, as upstream's unstructured encoding does. OBJECT itself is left alone."
  (let ((items (and (hash-table-p object) (gethash "items" object)))
        (kind (and (hash-table-p object) (gethash "kind" object))))
    (if (and (vectorp items) (not (stringp items)) (stringp kind) (uiop:string-suffix-p kind "List")
             (or (equal kind "PartialObjectMetadataList") (null *crd-view-definition*))
             (some (lambda (item) (and (hash-table-p item) (or (gethash "kind" item) (gethash "apiVersion" item)))) items))
        (let ((copy (shallow-copy-object object)))
          (setf (gethash "items" copy)
                (map 'vector (lambda (item)
                               (if (hash-table-p item)
                                   (let ((bare (shallow-copy-object item)))
                                     (remhash "kind" bare) (remhash "apiVersion" bare)
                                     bare)
                                   item))
                     items))
          copy)
        object)))

(defun json-response (object &optional (status 200))
  "Set the response code to STATUS and the content type to application/json, then
   return OBJECT serialized as the body. OBJECT passes through the event, CRD, and
   table-representation views, and built-in list items have their type metadata
   stripped, before encoding. The content type carries no charset parameter on
   purpose (see the comment)."
  (setf (hunchentoot:return-code*) status
        ;; client-go v0.27 discovery compares this media type literally. JSON
        ;; is UTF-8 already; a charset parameter breaks its legacy fallback.
        (hunchentoot:content-type*) "application/json")
  (com.inuoe.jzon:stringify
   (list-items-without-type-meta (table-representation (crd-api-view (event-api-view object))))))

(defun status-response (status reason message code &optional details)
  "Answer a Kubernetes Status, with DETAILS such as the causes clients inspect when given."
  (let ((object (json-object "apiVersion" "v1"
                             "kind" "Status"
                             "status" status
                             "reason" reason
                             "message" message
                             "code" code)))
    (when details (setf (gethash "details" object) details))
    (json-response object code)))

(defun kubernetes-error-response (error)
  "Render ERROR, a kubernetes-error, as a Kubernetes Status of kind Failure,
   carrying its reason, message, status code, and details."
  (status-response "Failure"
                   (kubernetes-error-reason error)
                   (kubernetes-error-message error)
                   (kubernetes-error-status-code error)
                   (kubernetes-error-details error)))

(defun copy-json-object (object)
  "Return an independent deep copy of OBJECT, by serializing it to JSON and
   parsing it back."
  (com.inuoe.jzon:parse (com.inuoe.jzon:stringify object)))

(defun pod-response-object (pod status)
  "Return POD encoded as a Kubernetes object with STATUS as its status subobject.
   When POD carries a status revision, metadata.resourceVersion is set to it (as a
   string). The source object is copied, so POD is left unchanged."
  (let ((object (copy-json-object (pod-to-object pod))))
    (setf (gethash "status" object) status)
    (when (pod-status-revision pod)
      (setf (gethash "resourceVersion" (gethash "metadata" object))
            (write-to-string (pod-status-revision pod))))
    object))

(defun request-pod-in-namespace (object namespace &key allow-generate-name)
  "Validate the request namespace and default omitted Pod metadata.namespace."
  (let* ((metadata (require-object (gethash "metadata" object) "metadata"))
         (specified (gethash "namespace" metadata)))
    (when (and specified (not (equal specified "")) (not (equal namespace specified)))
      (core-resource-error 400 "BadRequest" "metadata.namespace does not match request namespace"))
    (setf (gethash "namespace" metadata) namespace)
    ;; Ordinary Pod writes cannot supply runtime status, including GET-to-PUT metadata edits.
    (remhash "status" object)
    (parse-pod object :allow-generate-name allow-generate-name)))

(defun request-object (&optional (namespace "default"))
  "Decode the current request body as a Pod bound to NAMESPACE, validating and
   defaulting its metadata.namespace."
  (request-pod-in-namespace
   (core-resource-request-object "Pod")
   namespace))

(defun request-json-object ()
  "Parse the current request body as a JSON object, signaling a Kubernetes error
   if it is not one. Used for patch bodies."
  (require-object
   (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t))
   "patch"))

(defun merge-json-object (target patch)
  "Apply PATCH to TARGET in place with JSON Merge Patch semantics (RFC 7386): a
   null value deletes its key, two objects merge recursively, and any other value
   replaces. Mutates and returns TARGET."
  (maphash
   (lambda (key patch-value)
     (cond
       ((eq patch-value 'null)
        (remhash key target))
       ((and (hash-table-p patch-value)
             (hash-table-p (gethash key target)))
        (merge-json-object (gethash key target) patch-value))
       (t
        (setf (gethash key target) patch-value))))
   patch)
  target)

(defun version-response ()
  "Answer /version with the Kubernetes version gr8s reports. The build metadata
   (commit, tree state, date, compiler, platform) is fixed placeholder detail."
  (multiple-value-bind (major minor) (kubernetes-api-version-components)
    (json-response
     (json-object "major" major
                  "minor" minor
                  "gitVersion" (kubernetes-git-version)
                  "gitCommit" "unknown"
                  "gitTreeState" "clean"
                  "buildDate" "1970-01-01T00:00:00Z"
                  "goVersion" "common-lisp"
                  "compiler" "sbcl"
                  "platform" "linux/amd64"))))

(defun api-versions-response ()
  "Answer /api with the single core API version (v1) this server serves."
  (json-response
   (json-object "apiVersion" "v1"
                "kind" "APIVersions"
                "versions" #( "v1")
                "serverAddressByClientCIDRs" #())))

(defun builtin-api-groups ()
  "Describe the groups this server always serves, whatever its store holds."
  (let ((groups (vector (rbac-api-group)
                       (event-api-group) (workload-api-group) (batch-api-group) (budget-api-group) (storage-api-group) (csr-api-group) (endpointslice-api-group) (networking-api-group)
                       (policy-api-group "node.k8s.io") (policy-api-group "scheduling.k8s.io") (admission-api-group-object) (gateway-api-group) (cert-manager-api-group)
                       (resource-metrics-api-group))))
    (setf groups (concatenate 'vector groups (typed-api-groups) (auth-review-groups)))
    (setf groups (concatenate 'vector groups (vector (autoscaling-api-group) (apiservice-api-group))))
    groups))

(defun api-groups-response (&optional store)
  "Describe builtin groups and actual store-scoped custom API groups."
  (let ((groups (builtin-api-groups)))
    (when store
      (setf groups (concatenate 'vector groups (coerce (crd-api-groups store) 'vector)
                                (coerce (aggregated-api-groups store) 'vector))))
    (json-response (json-object "apiVersion" "v1" "kind" "APIGroupList" "groups" groups))))

(defun api-resources-response ()
  "Answer /api/v1 discovery: the core v1 resources and subresources this server
   serves, each with its allowed verbs."
  (json-response
   (json-object
    "apiVersion" "v1" "groupVersion" "v1" "kind" "APIResourceList"
    "resources"
    (concatenate
     'vector
     (vector
      (resource-discovery-entry "pods" "pod" t "Pod"
                                #("create" "delete" "deletecollection" "get" "list" "patch" "update" "watch"))
      (json-object "name" "pods/status" "singularName" "" "namespaced" t "kind" "Pod"
                   "verbs" #("get" "patch" "update"))
      (json-object "name" "pods/ephemeralcontainers" "singularName" "" "namespaced" t "kind" "Pod"
                   "verbs" #("get" "patch" "update"))
      (json-object "name" "pods/resize" "singularName" "" "namespaced" t "kind" "Pod"
                   "verbs" #("get" "patch" "update"))
      (json-object "name" "pods/log" "singularName" "" "namespaced" t "kind" "Pod" "verbs" #("get"))
      (json-object "name" "pods/exec" "singularName" "" "namespaced" t "kind" "PodExecOptions" "verbs" #("create" "get"))
      (json-object "name" "pods/attach" "singularName" "" "namespaced" t "kind" "PodAttachOptions" "verbs" #("create" "get"))
      (json-object "name" "pods/binding" "singularName" "" "namespaced" t "kind" "Binding" "verbs" #("create"))
      (resource-discovery-entry "componentstatuses" "componentstatus" nil "ComponentStatus" #("get" "list"))
      (json-object "name" "pods/portforward" "singularName" "" "namespaced" t "kind" "PodPortForwardOptions" "verbs" #("create" "get"))
      (json-object "name" "pods/eviction" "singularName" "" "namespaced" t "kind" "Eviction"
                   "group" "policy" "version" "v1" "verbs" #("create"))
      (json-object "name" "pods/proxy" "singularName" "" "namespaced" t "kind" "PodProxyOptions"
                   "verbs" #("get" "create" "update" "patch" "delete"))
      (resource-discovery-entry "nodes" "node" nil "Node"
                                #("create" "delete" "deletecollection" "get" "list" "patch" "update" "watch"))
      (json-object "name" "nodes/status" "singularName" "" "namespaced" nil "kind" "Node" "verbs" #("get" "patch" "update"))
      (json-object "name" "namespaces/status" "singularName" "" "namespaced" nil "kind" "Namespace"
                   "verbs" #("get" "patch" "update"))
      (json-object "name" "namespaces/finalize" "singularName" "" "namespaced" nil "kind" "Namespace" "verbs" #("update"))
      (json-object "name" "serviceaccounts/token" "singularName" "" "namespaced" t "kind" "TokenRequest"
                   "group" "authentication.k8s.io" "version" "v1" "verbs" #("create"))
      (json-object "name" "replicationcontrollers/status" "singularName" "" "namespaced" t
                   "kind" "ReplicationController" "verbs" #("get" "patch" "update"))
      (json-object "name" "replicationcontrollers/scale" "singularName" "" "namespaced" t
                   "kind" "Scale" "group" "autoscaling" "version" "v1" "verbs" #("get" "patch" "update")))
     (stored-resource-discovery "v1") (storage-status-discovery) (policy-status-discovery) (service-subresource-discovery)))))

(defvar *schema-reference-prefix* "#/definitions/")

(defun reference-schema (name)
  "Return a JSON Schema reference to NAME under the current
   *schema-reference-prefix* (definitions for v2, components for v3)."
  (json-object "$ref" (format nil "~A~A" *schema-reference-prefix* name)))

(defparameter *upstream-openapi*
  (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/openapi-v1.json"))
  "The component schemas Kubernetes publishes for the group versions gr8s serves, and the
schema names each of its documents lists, from scripts/generate-openapi-schema.py.")

(defparameter +openapi-registered-everywhere+
  '("io.k8s.apimachinery.pkg.apis.meta.v1.DeleteOptions" "io.k8s.apimachinery.pkg.apis.meta.v1.WatchEvent")
  "Schemas that every group version registers, so each document lists its own GVKs on them.")

(defparameter +openapi-common-schemas+
  '("io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta" "io.k8s.apimachinery.pkg.apis.meta.v1.ListMeta"
    "io.k8s.apimachinery.pkg.apis.meta.v1.Status" "io.k8s.apimachinery.pkg.apis.meta.v1.Patch"
    "io.k8s.apimachinery.pkg.apis.meta.v1.DeleteOptions" "io.k8s.apimachinery.pkg.apis.meta.v1.WatchEvent")
  "What a document for a group version Kubernetes does not publish starts from, as upstream's
custom resource documents do.")

(defparameter +openapi-schema-hash+
  (subseq (ironclad:byte-array-to-hex-string
           (ironclad:digest-file :sha256 (asdf:system-relative-pathname :gr8s "schema/openapi-v1.json")))
          0 16)
  "Changes whenever the vendored schemas do, so that clients caching a document by its
discovery URL fetch the new one.")

(defun openapi-document-key (group version)
  "Name the /openapi/v3 document of GROUP and VERSION: api/v1 or apis/GROUP/VERSION."
  (if (equal group "") (format nil "api/~A" version) (format nil "apis/~A/~A" group version)))

(defun openapi-builtin-document-url (key)
  "The discovery URL of a document served from the vendored schemas."
  (format nil "/openapi/v3/~A?hash=~A" key +openapi-schema-hash+))

(defun openapi-key-group-version (key)
  "Split a document key back into (group . version)."
  (let ((parts (uiop:split-string key :separator '(#\/))))
    (if (equal (first parts) "api") (cons "" (second parts)) (cons (second parts) (third parts)))))

(defun openapi-registered-everywhere-schema (name group-versions)
  "Copy NAME's vendored schema with a GVK for the core group and each of GROUP-VERSIONS."
  (let ((schema (shallow-copy-object (gethash name (gethash "schemas" *upstream-openapi*))))
        (kind (car (last (uiop:split-string name :separator '(#\.))))))
    (setf (gethash "x-kubernetes-group-version-kind" schema)
          (coerce (loop for (group . version) in (remove-duplicates (cons (cons "" "v1") group-versions)
                                                                    :test #'equal :from-end t)
                        collect (json-object "group" group "kind" kind "version" version))
                  'vector))
    schema))

(defun openapi-schema-references (schema)
  "Collect the schema names SCHEMA refers to, at any depth."
  (let ((names '()))
    (labels ((walk (value)
               (cond ((hash-table-p value)
                      (maphash (lambda (key child)
                                 (if (and (equal key "$ref") (stringp child))
                                     (push (car (last (uiop:split-string child :separator '(#\/)))) names)
                                     (walk child)))
                               value))
                     ((and (vectorp value) (not (stringp value))) (map nil #'walk value)))))
      (walk schema))
    names))

(defun openapi-schema-closure (roots)
  "Return ROOTS and every vendored schema they refer to, directly or not."
  (let ((schemas (gethash "schemas" *upstream-openapi*)) (seen (make-hash-table :test #'equal)))
    (labels ((visit (name)
               (unless (gethash name seen)
                 (let ((schema (gethash name schemas)))
                   (when schema
                     (setf (gethash name seen) t)
                     (mapc #'visit (openapi-schema-references schema)))))))
      (mapc #'visit roots))
    (loop for name being the hash-keys of seen collect name)))

(defun openapi-v2-schema (schema)
  "Write a v3 component SCHEMA as kube-openapi writes it in a v2 document: references lose
their allOf wrapper and defaults, int-or-string and quantities become strings, and nullable
goes. scripts/generate-openapi-schema.py checks this gives upstream's swagger.json."
  (if (not (hash-table-p schema))
      schema
      (let ((result (shallow-copy-object schema)))
        (remhash "default" result)
        (remhash "nullable" result)
        (let ((all-of (gethash "allOf" result)))
          (when (and (vectorp all-of) (= 1 (length all-of)) (hash-table-p (aref all-of 0))
                     (gethash "$ref" (aref all-of 0)))
            (remhash "allOf" result)
            (setf (gethash "$ref" result) (gethash "$ref" (aref all-of 0)))))
        (let ((reference (gethash "$ref" result)))
          (when (and (stringp reference) (uiop:string-prefix-p "#/components/schemas/" reference))
            (setf (gethash "$ref" result)
                  (concatenate 'string "#/definitions/" (subseq reference (length "#/components/schemas/"))))))
        (let ((one-of (gethash "oneOf" result)))
          (when (and (vectorp one-of)
                     (member (map 'list (lambda (entry) (and (hash-table-p entry) (gethash "type" entry))) one-of)
                             '(("integer" "string") ("string" "number")) :test #'equal))
            (remhash "oneOf" result)
            (setf (gethash "type" result) "string")))
        (let ((properties (gethash "properties" result)))
          (when (hash-table-p properties)
            (let ((converted (make-hash-table :test #'equal)))
              (maphash (lambda (key value) (setf (gethash key converted) (openapi-v2-schema value))) properties)
              (setf (gethash "properties" result) converted))))
        (dolist (key '("items" "additionalProperties"))
          (multiple-value-bind (value found) (gethash key result)
            (when found (setf (gethash key result) (openapi-v2-schema value)))))
        result)))

(defvar *openapi-v2-definitions* nil
  "Every vendored schema written for OpenAPI v2, built on first use.")

(defun openapi-v2-definitions ()
  "Return the vendored schemas as v2 definitions. Callers must not change the schemas."
  (or *openapi-v2-definitions*
      (setf *openapi-v2-definitions*
            (let ((definitions (make-hash-table :test #'equal))
                  (group-versions (loop for key being the hash-keys of (gethash "documents" *upstream-openapi*)
                                        collect (openapi-key-group-version key))))
              (maphash (lambda (name schema)
                         (setf (gethash name definitions)
                               (openapi-v2-schema
                                (if (member name +openapi-registered-everywhere+ :test #'equal)
                                    (openapi-registered-everywhere-schema name (sort group-versions #'string< :key #'car))
                                    schema))))
                       (gethash "schemas" *upstream-openapi*))
              definitions))))

(defun openapi-definitions (&optional group version)
  "Return a fresh table of the schemas a document publishes, as Kubernetes v1.37.2 publishes
them. Under the v2 reference prefix this is every vendored definition. Otherwise it is the v3
components of GROUP and VERSION's upstream document, or, for a version Kubernetes does not
publish, the object metadata and status schemas. The schemas themselves are shared and must
not be changed; add or replace entries instead."
  (let ((definitions (make-hash-table :test #'equal)))
    (if (equal *schema-reference-prefix* "#/definitions/")
        (maphash (lambda (name schema) (setf (gethash name definitions) schema)) (openapi-v2-definitions))
        (let* ((listed (and group (gethash (openapi-document-key group version) (gethash "documents" *upstream-openapi*))))
               (schemas (gethash "schemas" *upstream-openapi*)))
          (dolist (name (if listed (coerce listed 'list) (openapi-schema-closure +openapi-common-schemas+)))
            (setf (gethash name definitions)
                  (if (member name +openapi-registered-everywhere+ :test #'equal)
                      (openapi-registered-everywhere-schema name (and group (list (cons group version))))
                      (gethash name schemas))))))
    definitions))

(defun openapi-document ()
  "Build gr8s's OpenAPI v2 (Swagger 2.0) document: every vendored v2 definition,
   with the CSR endpoints as its paths."
  (json-object "swagger" "2.0"
               "info" (json-object "title" "gr8s" "version" "v1")
               "paths" (add-csr-openapi-v2-paths (make-hash-table :test #'equal))
               "definitions" (openapi-definitions)))

(defun pod-group-version-kind ()
  "The group/version/kind object for a core v1 Pod."
  (json-object "group" "" "version" "v1" "kind" "Pod"))

(defun openapi-v3-pod-paths ()
  "Build the OpenAPI v3 path items for the namespaced Pod collection (POST create)
   and a named Pod (PATCH), referencing the core v1 Pod schema."
  (json-object
   "/api/v1/namespaces/{namespace}/pods"
   (json-object
    "parameters"
    (vector (json-object "name" "namespace"
                         "in" "path"
                         "required" t
                         "schema" (json-object "type" "string")))
    "post"
    (json-object
     "operationId" "createCoreV1NamespacedPod"
     "x-kubernetes-action" "post"
     "x-kubernetes-group-version-kind" (pod-group-version-kind)
     "requestBody"
     (json-object
      "required" t
      "content"
      (json-object
       "application/json"
       (json-object "schema"
                    (reference-schema "io.k8s.api.core.v1.Pod"))))
     "responses"
     (json-object
      "201"
      (json-object
       "description" "Created"
       "content"
       (json-object
        "application/json"
        (json-object "schema"
                     (reference-schema "io.k8s.api.core.v1.Pod")))))))
   "/api/v1/namespaces/{namespace}/pods/{name}"
   (json-object
    "parameters"
    (vector (json-object "name" "namespace"
                         "in" "path"
                         "required" t
                         "schema" (json-object "type" "string"))
            (json-object "name" "name"
                         "in" "path"
                         "required" t
                         "schema" (json-object "type" "string")))
    "patch"
    (json-object
     "operationId" "patchCoreV1NamespacedPod"
     "x-kubernetes-action" "patch"
     "x-kubernetes-group-version-kind" (pod-group-version-kind)
     "parameters"
     (vector (json-object "name" "fieldValidation"
                          "in" "query"
                          "schema" (json-object "type" "string")))
     "requestBody"
     (json-object
      "required" t
      "content"
      (json-object
       "application/strategic-merge-patch+json"
       (json-object "schema"
                    (reference-schema "io.k8s.api.core.v1.Pod"))
       "application/apply-patch+yaml"
       (json-object "schema"
                    (reference-schema "io.k8s.api.core.v1.Pod"))))
     "responses"
     (json-object
      "200"
      (json-object
       "description" "OK"
       "content"
       (json-object
        "application/json"
        (json-object "schema"
                     (reference-schema "io.k8s.api.core.v1.Pod")))))))))

(defun openapi-v3-response (&optional (version "v1"))
  "Answer /openapi/v3 for VERSION (a group version such as \"v1\" or \"apps/v1\"):
   a 3.0.0 document whose paths and component schemas are those of that group
   version. Schema references use the v3 components prefix."
  (let ((*schema-reference-prefix* "#/components/schemas/"))
    (json-response
     (json-object
      "openapi" "3.0.0"
      "info" (json-object "title" "gr8s" "version" "v1")
      "paths" (cond ((equal version "certificates.k8s.io/v1") (add-csr-openapi-paths (core-object)))
                    ((equal version +admission-api-version+) (add-admission-openapi-paths (core-object)))
                    ((equal version "discovery.k8s.io/v1") (add-endpointslice-openapi-paths (core-object)))
                    ((equal version "networking.k8s.io/v1") (add-networking-openapi-paths (core-object)))
                    ((equal version "events.k8s.io/v1") (add-event-openapi-paths (core-object) t))
                    ((equal version "apps/v1") (add-workload-openapi-paths (core-object)))
                    ((equal version "policy/v1") (add-budget-openapi-paths (core-object)))
                    ((equal version "storage.k8s.io/v1") (add-storage-openapi-paths (core-object) version))
                    ((member version '("node.k8s.io/v1" "scheduling.k8s.io/v1") :test #'equal)
                     (add-policy-openapi-paths (core-object) version))
                    (t (add-policy-openapi-paths
                        (add-storage-openapi-paths (add-core-resource-openapi-paths (openapi-v3-pod-paths))) "v1")))
      "components" (json-object "schemas"
                                (let ((slash (position #\/ version)))
                                  (if slash
                                      (openapi-definitions (subseq version 0 slash) (subseq version (1+ slash)))
                                      (openapi-definitions "" version))))))))

(defun create-pod-response (store reconciler &optional (namespace "default"))
  "Admit a new Pod; a dry run runs every admission and quota check but stores nothing."
  (let ((raw (core-resource-request-object "Pod"))
        ;; The client comes to own the fields it created, as an Update.
        (*apply-update-manager* (list (apply-default-manager) nil)))
    ;; The API server defaults a request as it decodes it, so admission sees the defaults.
    (when (hash-table-p raw) (default-pod-spec-object (gethash "spec" raw)))
    (multiple-value-bind (admitted attributes)
        (admit-pod-input store "CREATE" namespace
                         (let ((metadata (gethash "metadata" raw))) (and (hash-table-p metadata) (gethash "name" metadata)))
                         raw nil)
      (let* ((input (request-pod-in-namespace admitted namespace :allow-generate-name t))
             (final (progn
                      (when (plusp (length (pod-ephemeral-containers input)))
                        (invalid-pod "spec.ephemeralContainers: Forbidden: cannot be set on create"))
                      (admit-pod-result store attributes (admit-in-cluster-pod store input)))))
        (if (core-resource-dry-run-p)
            (progn
              (with-store-lock (store)
                (enforce-resource-quotas-unlocked store "pods" namespace (pod-to-object final)))
              (json-response (pod-response-object (default-created-pod final) (pod-status "Pending")) 201))
            (let* ((pod (create-pod store final))
                   (status (reconcile-written-pod reconciler pod)))
              (json-response (pod-response-object pod status) 201)))))))

(defun pod-list-observed-object (store reconciler snapshot)
  "Skip vanished snapshot identities and never attach a replacement Pod's status to an old UID."
  (handler-case
      (let ((status (reconcile-pod reconciler (pod-namespace snapshot) (pod-name snapshot))))
        (with-store-lock (store)
          (let ((current (gethash (pod-key (pod-namespace snapshot) (pod-name snapshot)) (pod-store-pods store))))
            (when (and current (equal (pod-uid snapshot) (pod-uid current)))
              (pod-response-object current status)))))
    (kubernetes-error (condition)
      (unless (= 404 (kubernetes-error-status-code condition)) (error condition)))))

(defun list-pods-response (store reconciler &optional (namespace "default"))
  "Answer a GET on the Pod collection in NAMESPACE. With ?watch, stream changes
   via pod-watch-response. Otherwise return a PodList: items in namespace/name
   order, each reconciled to its current status and kept only if it passes the
   request's label and field selectors, with the list's resourceVersion read
   before the items so a following watch never misses a change."
  (when (true-parameter-p (hunchentoot:parameter "watch"))
    (return-from list-pods-response (pod-watch-response store namespace)))
  (let ((labels (core-selector-predicate (hunchentoot:parameter "labelSelector")))
        (fields (core-selector-predicate (hunchentoot:parameter "fieldSelector") :fields t
                                         :field-paths (pod-selector-field-paths)))
        ;; Read before gathering items: a watch from here may repeat a change
        ;; already in the list, which clients tolerate, but can never miss one.
        (revision (with-store-lock (store) (pod-store-pod-revision store))))
    (json-response
     (json-object "apiVersion" "v1" "kind" "PodList"
                  "metadata" (json-object "resourceVersion" (write-to-string revision))
                  "items" (coerce
                           ;; In key order, as etcd returns a list. Clients index into it.
                           (loop for pod in (sort (list-pods store namespace) #'string<
                                                  :key (lambda (pod) (format nil "~A/~A" (pod-namespace pod) (pod-name pod))))
                                 for object = (pod-list-observed-object store reconciler pod)
                                 when (and object (funcall labels object) (funcall fields object))
                                   collect object) 'vector)))))

(defun get-pod-response (store reconciler name &optional (namespace "default"))
  "Answer a GET on one Pod: its object with the status a fresh reconcile reports.
   Signals a 404 (via get-pod) when NAME is absent in NAMESPACE."
  (let ((pod (get-pod store namespace name)))
    (json-response
     (pod-response-object pod (reconcile-pod reconciler namespace name)))))

(defun pod-dry-run-object (store replacement existing &optional reconciler)
  "Return what a Pod write would store, with EXISTING's identity, having stored nothing.
With RECONCILER, an existing Pod shows the status and revision a read of it would."
  (let* ((object (copy-json-object (pod-to-object replacement)))
         (metadata (gethash "metadata" object))
         (current (and existing reconciler
                       (pod-response-object existing (reconcile-pod reconciler (pod-namespace existing) (pod-name existing))))))
    (when existing
      (let ((old (gethash "metadata" (or current (pod-to-object existing)))))
        (dolist (field '("uid" "creationTimestamp" "resourceVersion" "generation"))
          (setf (gethash field metadata) (gethash field old)))))
    (when (or (null existing) (pod-spec-defaulted-p (gethash "spec" (pod-to-object existing))))
      (default-pod-spec-object (gethash "spec" object)))
    (setf (gethash "status" object)
          (cond (current (gethash "status" current))
                (existing (copy-json-object (or (pod-observed-status store existing) (pod-status "Pending"))))
                (t (pod-status "Pending"))))
    object))

(defun apply-pod-response (store reconciler name &optional (namespace "default"))
  "Serve a PATCH (or server-side apply) on NAME in NAMESPACE. Decodes the body by
   content type -- JSON Patch, strategic merge, or apply-patch+yaml, else a JSON
   merge patch -- runs admission, and on a dry run returns the would-be object
   without storing. Otherwise updates an existing Pod or creates one from an
   apply, returning the stored Pod with 200 (updated) or 201 (created)."
  (let* ((content-type (first (uiop:split-string (or (hunchentoot:header-in* :content-type) "") :separator '(#\;))))
         (applied (equal content-type "application/apply-patch+yaml"))
         (structured (member content-type '("application/json-patch+json" "application/strategic-merge-patch+json" "application/apply-patch+yaml")
                             :test #'equal))
         (patch (unless structured (request-json-object)))
         ;; A patch comes to own the fields it changes; an apply records its own ownership.
         (*apply-update-manager* (unless applied (list (apply-default-manager) nil)))
         (existing (handler-case (get-pod store namespace name)
                     (kubernetes-error (error)
                       (if (= 404 (kubernetes-error-status-code error))
                           nil
                           (error error))))))
    (multiple-value-bind (admitted attributes)
        (admit-pod-input store (if existing "UPDATE" "CREATE") namespace name
                         (cond ((and existing structured) (pod-patched-object (pod-to-object existing) content-type))
                               (existing (merge-json-object (copy-json-object (pod-to-object existing)) patch))
                               (applied (apply-pod-created-object namespace name))
                               (structured (core-resource-error 404 "NotFound" "pods ~S not found" name))
                               (t patch))
                         existing)
      (let ((replacement (request-pod-in-namespace admitted namespace)))
        (unless (string= name (pod-name replacement))
          (invalid-pod "request name does not match metadata.name"))
        (admit-pod-result store attributes replacement)
        (when (core-resource-dry-run-p)
          (return-from apply-pod-response
            (json-response (pod-dry-run-object store replacement existing reconciler) (if existing 200 201))))
        (let ((pod (if existing
                       (update-pod store replacement
                                   (pod-resource-version existing))
                       (create-pod store (admit-in-cluster-pod store replacement)))))
          (json-response
           (pod-response-object pod (reconcile-written-pod reconciler pod))
           (if existing 200 201)))))))

(defun replace-pod-response (store reconciler name &optional (namespace "default"))
  "Serve a PUT replacing NAME in NAMESPACE. Defaults and admits the request as an
   UPDATE, requires metadata.name to match NAME, and on a dry run returns the
   would-be object without storing. An omitted resourceVersion is an
   unconditional update. Returns the stored Pod."
  (let ((raw (core-resource-request-object "Pod"))
        (*apply-update-manager* (list (apply-default-manager) nil)))
    ;; The API server defaults a request as it decodes it, so admission sees the defaults.
    (when (hash-table-p raw) (default-pod-spec-object (gethash "spec" raw)))
    (multiple-value-bind (admitted attributes)
        (admit-pod-input store "UPDATE" namespace name raw (get-pod store namespace name))
      (let ((replacement (request-pod-in-namespace admitted namespace)))
        (unless (string= name (pod-name replacement))
          (invalid-pod "request name does not match metadata.name"))
        (admit-pod-result store attributes replacement)
        (when (core-resource-dry-run-p)
          (return-from replace-pod-response
            (json-response (pod-dry-run-object store replacement (get-pod store namespace name) reconciler))))
        ;; An omitted revision is an unconditional update.
        (let ((pod (update-pod store replacement
                               (or (pod-resource-version replacement)
                                   (pod-resource-version (get-pod store namespace name))))))
          (json-response
           (pod-response-object pod (reconcile-written-pod reconciler pod))))))))

(defun pod-delete-request-arguments ()
  "Decode JSON/protobuf DeleteOptions and query options without mutating desired state."
  (let* ((body (hunchentoot:raw-post-data :force-binary t))
         (options (if (and body (plusp (length body)))
                      (core-resource-request-object "DeleteOptions") (json-object)))
         (preconditions (gethash "preconditions" options))
         (preview (gethash "dryRun" options))
         (query-grace (hunchentoot:parameter "gracePeriodSeconds"))
         (arguments nil) (foreground nil))
    (when preconditions
      (require-object preconditions "preconditions")
      (dolist (key '("uid" "resourceVersion"))
        (when (gethash key preconditions)
          (require-nonempty-string (gethash key preconditions) key))))
    (when (and preview (not (eq preview 'null)))
      (unless (and (vectorp preview) (not (stringp preview))
                   (every (lambda (value) (equal value "All")) preview))
        (core-resource-error 400 "BadRequest" "DeleteOptions.dryRun must contain only All")))
    (let ((policy (or (gethash "propagationPolicy" options)
                      (hunchentoot:parameter "propagationPolicy"))))
      (when (and policy (not (eq policy 'null)) (not (member policy '("Background" "Foreground") :test #'equal)))
        (invalid-pod "Pod deletion supports Background and Foreground propagation only"))
      (when (equal policy "Foreground") (setf foreground t)))
    (when (eq t (gethash "orphanDependents" options))
      (invalid-pod "Orphan propagation is not supported"))
    (multiple-value-bind (grace supplied) (gethash "gracePeriodSeconds" options)
      (when (eq grace 'null) (setf supplied nil))
      (when (and query-grace (not supplied))
        (setf grace (handler-case (parse-integer query-grace)
                      (error () (core-resource-error 400 "BadRequest" "Invalid gracePeriodSeconds")))
              supplied t))
      (when supplied (setf arguments (list :grace-period grace))))
    (values
     (append arguments
             (list :uid (and preconditions (gethash "uid" preconditions))
                   :resource-version (and preconditions (gethash "resourceVersion" preconditions))
                   :dry-run (or (core-resource-dry-run-p)
                                (and (vectorp preview) (not (stringp preview)) (plusp (length preview))))))
     foreground)))

(defun delete-pod-response (store reconciler name &optional (namespace "default"))
  "Start or shorten Pod shutdown and return promptly while its agent stops containers."
  (let ((body (hunchentoot:raw-post-data :force-binary t)))
    (admit-pod-delete store namespace name
                      (when (and body (plusp (length body))) (core-resource-request-object "DeleteOptions"))))
  (multiple-value-bind (status pod)
      (multiple-value-bind (arguments foreground) (pod-delete-request-arguments)
        ;; A Pod with blocking dependents stops now, and its object stays until they are gone.
        (when (and foreground (not (getf arguments :dry-run)))
          (hold-pod-for-foreground-deletion store namespace name (getf arguments :uid)))
        (apply #'delete-reconciled-pod reconciler namespace name arguments))
    (if (equal "Deleted" (and status (gethash "reason" status)))
        (status-response "Success" "Deleted" (format nil "Pod ~A deleted" name) 200)
        (json-response (pod-response-object pod (or status (pod-status "Running" :reason "Terminating")))))))

(defun pod-logs-response (store reconciler name &optional (namespace "default"))
  "Answer GET pods/NAME/log in NAMESPACE. Defaults the container to the Pod's
   first, and signals 400 for an unknown container or one still waiting to start.
   Returns the log text as text/plain, streams it over WebSocket for an upgrade
   request, or follows it live for ?follow (except with ?previous)."
  (let* ((pod (get-pod store namespace name))
         (container (or (hunchentoot:parameter "container")
                        (container-spec-name (aref (pod-containers pod) 0)))))
    (unless (find container (pod-all-containers pod)
                  :key #'container-spec-name :test #'string=)
      (error 'kubernetes-error
             :status-code 400
             :reason "BadRequest"
             :message (format nil "container ~A is not valid for pod ~A"
                              container name)))
    (let* ((status (pod-observed-status store pod))
           (observed (and status (find container (gethash "containerStatuses" status #()) :test #'equal
                                       :key (lambda (entry) (gethash "name" entry))))))
      (when (and observed (container-status-never-started-p observed))
        (error 'kubernetes-error :status-code 400 :reason "BadRequest"
               :message (format nil "container ~S in pod ~S is waiting to start: ~A" container name
                                (gethash "reason" (gethash "waiting" (gethash "state" observed)) "ContainerCreating")))))
    (let* ((previous (true-parameter-p (hunchentoot:parameter "previous")))
           (raw (or (reconciler-logs reconciler (pod-uid pod) container :previous previous) ""))
           (text (format-pod-logs-for-request raw)))
      (cond
        ((upgrade-request-p) (serve-pod-logs-websocket text))
        ((and (true-parameter-p (hunchentoot:parameter "follow")) (not previous))
         (serve-followed-pod-logs store reconciler pod container text (length raw)))
        (t
         (setf (hunchentoot:content-type*) "text/plain; charset=utf-8")
         text)))))

(defstruct exec-options
  command
  container
  stdin
  stdout
  stderr
  tty)

(defun true-parameter-p (value)
  "Read a boolean query parameter as Go's strconv.ParseBool does for true values."
  (and value (member value '("1" "t" "T" "true" "TRUE" "True") :test #'string=) t))

(defun exec-options-from-parameters (parameters)
  "Build an EXEC-OPTIONS from the request's query PARAMETERS: every \"command\"
   value in order, the container, and the stdin/stdout/stderr/tty booleans."
  (make-exec-options
   :command (loop for (name . value) in parameters
                  when (string= name "command") collect value)
   :container (cdr (assoc "container" parameters :test #'string=))
   :stdin (true-parameter-p
           (cdr (assoc "stdin" parameters :test #'string=)))
   :stdout (true-parameter-p
            (cdr (assoc "stdout" parameters :test #'string=)))
   :stderr (true-parameter-p
            (cdr (assoc "stderr" parameters :test #'string=)))
   :tty (true-parameter-p
         (cdr (assoc "tty" parameters :test #'string=)))))

(defparameter *runtime-upgrade-request-headers*
  '(:connection :upgrade :sec-websocket-key :sec-websocket-version
    :sec-websocket-protocol :x-stream-protocol-version :origin :user-agent))

(defun header-name (keyword)
  "Render a header KEYWORD as its capitalized HTTP spelling
   (e.g. :user-agent -> \"User-Agent\")."
  (string-capitalize (symbol-name keyword)))

(defun runtime-upgrade-request (target host port headers)
  "Format the HTTP/1.1 POST request that forwards a client's stream upgrade to
   containerd at HOST:PORT for TARGET, copying only the upgrade-relevant headers
   (*runtime-upgrade-request-headers*) from HEADERS."
  (with-output-to-string (output)
    (format output "POST ~A HTTP/1.1~C~CHost: ~A:~D~C~C"
            target #\Return #\Linefeed host port #\Return #\Linefeed)
    (dolist (header headers)
      (when (member (car header) *runtime-upgrade-request-headers*)
        (format output "~A: ~A~C~C"
                (header-name (car header)) (cdr header)
                #\Return #\Linefeed)))
    (format output "~C~C" #\Return #\Linefeed)))

(defparameter *runtime-upgrade-response-headers*
  '(:connection :upgrade :sec-websocket-accept :sec-websocket-protocol
    :x-stream-protocol-version))

(defun upgrade-request-p ()
  "True when the current request asks to upgrade the connection: it carries an
   Upgrade header and \"upgrade\" among its Connection tokens."
  (let ((connection (hunchentoot:header-in* :connection))
        (upgrade (hunchentoot:header-in* :upgrade)))
    (and connection upgrade
         (find "upgrade"
               (uiop:split-string connection :separator '(#\, #\Space #\Tab))
               :test #'string-equal))))

(defun copy-binary-stream (input output)
  "Copy bytes from INPUT to OUTPUT until INPUT reaches end of file, flushing
   OUTPUT after each batch. Blocks on the first byte of each batch, so it forwards
   data as soon as it arrives."
  (let ((buffer (make-array 16384 :element-type '(unsigned-byte 8))))
    (loop for first = (read-byte input nil nil)
          while first
          do (setf (aref buffer 0) first)
             (let ((count 1))
               (loop while (and (< count (length buffer)) (listen input))
                     do (setf (aref buffer count) (read-byte input))
                        (incf count))
               (write-sequence buffer output :end count)
               (finish-output output)))))

(defun relay-runtime-stream (client upstream socket)
  "Copy both ways until the runtime ends the stream. The other direction's thread can outlive
this: it ends with the client's connection, by which time SOCKET's descriptor number may
belong to another connection, so it must not shut SOCKET down after it has been closed."
  (let ((lock (bt:make-lock "gr8s exec relay socket"))
        (closed nil))
    (bt:make-thread
     (lambda ()
       (unwind-protect
            (ignore-errors (copy-binary-stream client upstream))
         (bt:with-lock-held (lock)
           (unless closed
             (ignore-errors (usocket:socket-shutdown socket :io))))))
     :name "gr8s exec client-to-runtime")
    (unwind-protect
         (copy-binary-stream upstream client)
      (bt:with-lock-held (lock)
        (setf closed t)
        (ignore-errors (usocket:socket-close socket))))))

(defun proxy-runtime-stream (url)
  "Bridge the client's upgraded connection to containerd's streaming server at
   URL: connect, replay the upgrade request, require a 101 response, forward the
   accepted upgrade headers back to the client, then relay the two streams until
   either side ends. Signals a RUNTIME-ERROR on any failure, closing the upstream
   socket."
  (multiple-value-bind (host port target)
      (parse-runtime-stream-url url)
    (let* ((socket (usocket:socket-connect
                    host port :element-type '(unsigned-byte 8)))
           (upstream (usocket:socket-stream socket)))
      (handler-case
          (progn
            (write-sequence
             (ascii-octets
              (runtime-upgrade-request
               target host port (hunchentoot:headers-in*)))
             upstream)
            (finish-output upstream)
            (multiple-value-bind (status headers)
                (parse-http-response-head
                 (read-http-response-head upstream))
              (unless (= status 101)
                (error 'runtime-error
                       :message
                       (format nil
                               "containerd rejected the exec upgrade with HTTP ~D"
                               status)))
              (setf (hunchentoot:return-code*) 101
                    (hunchentoot:content-type*) nil)
              (dolist (header headers)
                (when (member (car header)
                              *runtime-upgrade-response-headers*)
                  (setf (hunchentoot:header-out (car header))
                        (cdr header))))
              ;; SEND-HEADERS treats an unknown-length response as a chunked
              ;; body.  An upgraded connection has no HTTP body: its following
              ;; octets belong to WebSocket/SPDY and must remain untouched.
              (let ((client (hunchentoot::start-output 101 nil)))
                (finish-output client)
                (extend-api-connection-idle-timeout)
                (relay-runtime-stream client upstream socket))))
        (error (condition)
          (ignore-errors (usocket:socket-close socket))
          (if (typep condition 'runtime-error)
              (error condition)
              (error 'runtime-error :message (princ-to-string condition))))))))

(defparameter *kubernetes-websocket-protocols*
  '("v5.channel.k8s.io" "v4.channel.k8s.io" "channel.k8s.io"))

(defun requested-kubernetes-websocket-protocol ()
  "Return the Kubernetes channel subprotocol to use for the current request: the
   most preferred of *kubernetes-websocket-protocols* that the client offered in
   Sec-WebSocket-Protocol, or NIL if none match."
  (let ((requested
          (uiop:split-string
           (or (hunchentoot:header-in* :sec-websocket-protocol) "")
           :separator '(#\, #\Space #\Tab))))
    (find-if (lambda (protocol)
               (find protocol requested :test #'string-equal))
             *kubernetes-websocket-protocols*)))

(defun websocket-accept-value (key)
  "Compute the Sec-WebSocket-Accept value for a client's Sec-WebSocket-KEY: base64
   of its SHA-1 with the WebSocket GUID appended."
  (ag-grpc:base64-encode
   (ironclad:digest-sequence
    :sha1
    (trivial-utf-8:string-to-utf-8-bytes
     (concatenate 'string key "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))))

(defun write-kubernetes-channel-frame (stream channel data)
  "Write DATA to STREAM as one binary WebSocket frame on the Kubernetes
   remotecommand CHANNEL, the channel number prefixed as the first payload byte."
  (let ((payload (make-array (1+ (length data))
                             :element-type '(unsigned-byte 8))))
    (setf (aref payload 0) channel)
    (replace payload data :start1 1)
    (write-websocket-frame stream 2 payload)))

(defun exec-exit-status-bytes (exit-code)
  "Return the UTF-8 bytes of the Kubernetes Status that reports an exec's
   EXIT-CODE: a Success status when zero, otherwise a Failure carrying reason
   NonZeroExitCode and the code in its causes."
  (when (zerop exit-code)
    (return-from exec-exit-status-bytes
      (trivial-utf-8:string-to-utf-8-bytes
       (com.inuoe.jzon:stringify
        (json-object "apiVersion" "v1" "kind" "Status" "status" "Success")))))
  (trivial-utf-8:string-to-utf-8-bytes
   (with-output-to-string (output)
     (com.inuoe.jzon:stringify
      (let ((status (make-hash-table :test #'equal))
            (details (make-hash-table :test #'equal))
            (cause (make-hash-table :test #'equal)))
        (setf (gethash "apiVersion" status) "v1"
              (gethash "kind" status) "Status"
              (gethash "status" status) "Failure"
              (gethash "message" status)
              (format nil "command terminated with exit code ~D" exit-code)
              (gethash "reason" status) "NonZeroExitCode"
              (gethash "code" status) 500
              (gethash "reason" cause) "ExitCode"
              (gethash "message" cause) (princ-to-string exit-code)
              (gethash "causes" details) (list cause)
              (gethash "details" status) details)
        status)
      :stream output))))

(defun exec-status-frame-bytes (exit-code)
  "Return the status channel's payload for EXIT-CODE, or NIL when none is sent.
The unversioned protocol predates structured status: it has no success frame, and
its clients treat any other multi-byte frame as an error message."
  (cond ((not (equal "channel.k8s.io" (requested-kubernetes-websocket-protocol)))
         (exec-exit-status-bytes exit-code))
        ((zerop exit-code) nil)
        (t (trivial-utf-8:string-to-utf-8-bytes
            (format nil "command terminated with exit code ~D" exit-code)))))

(defun exec-failure-frame-bytes (message)
  "Return the status channel's payload for a stream that could not be served, with MESSAGE."
  (format *error-output* "gr8s Pod stream failed: ~A~%" message)
  (trivial-utf-8:string-to-utf-8-bytes
   (if (equal "channel.k8s.io" (requested-kubernetes-websocket-protocol))
       message
       (com.inuoe.jzon:stringify
        (json-object "apiVersion" "v1" "kind" "Status" "status" "Failure" "message" message
                     "reason" "InternalError" "code" 500)))))

(defvar *exec-input-reader-tag* nil
  "The catch tag of this thread's exec input reader, set only while its catch is established.")

(defmacro with-exec-input-reader-stop (&body body)
  "Run BODY until STOP-EXEC-INPUT-READER throws out of it.
A throw needs no handler: an error signalled from an interrupt can land while the thread is
already signalling, with its handlers unbound for the handler tests, and then finds none."
  (let ((tag (gensym "EXEC-INPUT")))
    `(let ((,tag (list :exec-input)))
       (catch ,tag
         (let ((*exec-input-reader-tag* ,tag))
           ,@body)))))

(defun stop-exec-input-reader (thread)
  "Unwind THREAD's exec input reader. An interrupt that arrives after its catch has gone does nothing."
  (when (bt:thread-alive-p thread)
    (ignore-errors
     (bt:interrupt-thread
      thread
      (lambda ()
        (when *exec-input-reader-tag*
          (throw *exec-input-reader-tag* nil)))))))

(defun begin-kubernetes-websocket ()
  "Complete the WebSocket upgrade handshake for a Pod stream and return the client
   octet stream, having set the chosen channel subprotocol. Signals a 400
   (bad-exec-request) when the request lacks a Sec-WebSocket-Key or offers no
   supported protocol."
  (let ((key (hunchentoot:header-in* :sec-websocket-key))
        (protocol (requested-kubernetes-websocket-protocol)))
    (unless (and key (plusp (length key)))
      (bad-exec-request "Pod exec requires Sec-WebSocket-Key"))
    (unless protocol
      (bad-exec-request "Pod exec requires a supported channel protocol"))
    (setf (hunchentoot:return-code*) 101
          (hunchentoot:content-type*) nil
          (hunchentoot:header-out :connection) "Upgrade"
          (hunchentoot:header-out :upgrade) "websocket"
          (hunchentoot:header-out :sec-websocket-accept)
          (websocket-accept-value key)
          (hunchentoot:header-out :sec-websocket-protocol) protocol)
    (let ((client (hunchentoot::start-output 101 nil)))
      (finish-output client)
      client)))

(defun terminal-size-from-channel-data (data)
  "Parse a terminal-resize payload (JSON with height and width) into
   (values HEIGHT WIDTH), each defaulting to 0 when absent."
  (let ((size
          (com.inuoe.jzon:parse
           (trivial-utf-8:utf-8-bytes-to-string data))))
    (values (gethash "height" size 0)
            (gethash "width" size 0))))

(defun forward-kubernetes-exec-input
    (reconciler session stream write-lock finished-p)
  "Read client WebSocket frames from STREAM and drive the exec SESSION until
   FINISHED-P returns true or the client closes. Binary frames carry stdin
   (channel 0), terminal resize (channel 4), and close-stdin (channel 255) to the
   node; pings are answered with pongs under WRITE-LOCK. Runs under
   with-exec-input-reader-stop, and on a close frame or any error cancels the
   session unless it has already finished."
  (handler-case
      (with-exec-input-reader-stop
       (loop until (funcall finished-p)
            do (multiple-value-bind (opcode payload fin-p masked-p)
                   (read-websocket-frame stream)
                 (declare (ignore fin-p))
                 (case opcode
                   (2
                    (unless masked-p
                      (error 'runtime-error
                             :message "WebSocket client frames must be masked"))
                    (when (zerop (length payload))
                      (error 'runtime-error
                             :message "Empty remotecommand input frame"))
                    (case (aref payload 0)
                      (0
                       (reconciler-send-exec-session-input
                        reconciler session
                        gr8s.node.v1::+streamchannel-stream_channel_stdin+
                        (subseq payload 1)))
                      (4
                       (multiple-value-bind (rows columns)
                           (terminal-size-from-channel-data (subseq payload 1))
                         (reconciler-send-exec-session-input
                          reconciler session
                          gr8s.node.v1::+streamchannel-stream_channel_terminal_resize+
                          (make-array 0 :element-type '(unsigned-byte 8))
                          :rows rows :columns columns)))
                      (255
                       (when (and (> (length payload) 1)
                                  (= 0 (aref payload 1)))
                         (reconciler-send-exec-session-input
                          reconciler session
                          gr8s.node.v1::+streamchannel-stream_channel_stdin+
                          (make-array 0 :element-type '(unsigned-byte 8))
                          :eof t)))
                      (otherwise
                       (error 'runtime-error
                              :message "Unsupported remotecommand input channel"))))
                   (8
                    (unless (funcall finished-p)
                      (reconciler-cancel-exec-session
                       reconciler session "WebSocket client closed"))
                    (return))
                   (9
                    (bt:with-lock-held (write-lock)
                      (write-websocket-frame stream 10 payload)))
                   (10)
                   (otherwise
                    (error 'runtime-error
                           :message "Unsupported WebSocket input frame"))))))
    (error (condition)
      (unless (funcall finished-p)
        (ignore-errors
          (reconciler-cancel-exec-session
           reconciler session (princ-to-string condition)))))))

(defun operation-stream-wire-channel (message)
  "Map a node stream MESSAGE's channel to its Kubernetes wire channel number: 1
   for stdout, 2 for stderr, NIL for anything else."
  (case (slot-value message 'gr8s.node.v1::channel)
    (#.gr8s.node.v1::+streamchannel-stream_channel_stdout+ 1)
    (#.gr8s.node.v1::+streamchannel-stream_channel_stderr+ 2)))

(defun serve-agent-exec-session (reconciler uid container options &key attach)
  "Bridge the client's WebSocket to a node exec, or with ATTACH to the container's own process.
A client that asks for SPDY instead is served as a kubelet's streaming server serves it."
  (when (spdy-remotecommand-requested-p)
    (return-from serve-agent-exec-session
      (serve-spdy-exec-session reconciler uid container options :attach attach)))
  (let* ((session
           (if attach
               (reconciler-start-attach-session
                reconciler uid container
                :stdin (exec-options-stdin options)
                :stdout (exec-options-stdout options)
                :stderr (exec-options-stderr options)
                :tty (exec-options-tty options))
               (reconciler-start-exec-session
                reconciler uid container (exec-options-command options)
                :stdin (exec-options-stdin options)
                :stdout (exec-options-stdout options)
                :stderr (exec-options-stderr options)
                :tty (exec-options-tty options))))
         (client (prog1 (begin-kubernetes-websocket) (extend-api-connection-idle-timeout)))
         (write-lock (bt:make-lock "gr8s kubectl exec websocket writer"))
         (finished-lock (bt:make-lock "gr8s kubectl exec finished"))
         (finished-p nil)
         (completed-p nil)
         (input-thread nil))
    (labels ((finished-p ()
               (bt:with-lock-held (finished-lock) finished-p))
             (mark-finished ()
               (bt:with-lock-held (finished-lock) (setf finished-p t))))
      (unwind-protect
           (progn
             (setf input-thread
                   (bt:make-thread
                    (lambda ()
                      (forward-kubernetes-exec-input
                       reconciler session client write-lock #'finished-p))
                    :name "gr8s kubectl exec input"))
             (loop with cursor = 0
                   do (multiple-value-bind (message next-cursor done-p)
                          (reconciler-next-exec-session-output
                           reconciler session cursor)
                        (setf cursor next-cursor)
                        (when message
                          (let ((channel
                                  (operation-stream-wire-channel message)))
                            (when channel
                              (bt:with-lock-held (write-lock)
                                (write-kubernetes-channel-frame
                                 client channel
                                 (slot-value message 'gr8s.node.v1::data))))))
                        (when done-p
                          (setf completed-p t)
                          (loop-finish))))
             ;; A failure on the node reaches the client as its message, not as a dropped connection.
             (let ((status (handler-case
                               (exec-status-frame-bytes (reconciler-exec-session-exit-code reconciler session))
                             (runtime-error (condition)
                               (exec-failure-frame-bytes (runtime-error-message condition))))))
               (when status
                 (bt:with-lock-held (write-lock)
                   (write-kubernetes-channel-frame client 3 status))))
             (mark-finished)
             (bt:with-lock-held (write-lock)
               (write-websocket-frame
                client 8 (make-array 2 :element-type '(unsigned-byte 8)
                                     :initial-contents '(3 232)))))
        (mark-finished)
        (unless completed-p
          (ignore-errors
            (reconciler-cancel-exec-session
             reconciler session "API exec stream ended")))
        (reconciler-release-exec-session reconciler session)
        (when input-thread (stop-exec-input-reader input-thread))
        (when input-thread
          (ignore-errors (bt:join-thread input-thread)))))))

(defun bad-exec-request (message)
  "Signal a 400 BadRequest kubernetes-error carrying MESSAGE."
  (error 'kubernetes-error :status-code 400 :reason "BadRequest"
         :message message))

(defun pod-exec-response (store reconciler name &optional (namespace "default"))
  "Serve a Pod exec on NAME in NAMESPACE over an upgraded connection. Signals 400
   unless the request upgrades, names a command, asks for at least one of
   stdin/stdout/stderr, and names a valid container. After admission, bridges to
   the node's exec session on a control-plane runtime, or proxies the local
   runtime's streaming server otherwise."
  (unless (upgrade-request-p)
    (bad-exec-request "Pod exec requires an upgraded connection"))
  (let* ((pod (get-pod store namespace name))
         (options
           (exec-options-from-parameters (hunchentoot:get-parameters*)))
         (container
           (or (exec-options-container options)
               (container-spec-name (aref (pod-containers pod) 0)))))
    (unless (exec-options-command options)
      (bad-exec-request "Pod exec requires at least one command argument"))
    ;; kubelet's remotecommand.NewOptions refuses a stream with nothing to carry.
    (unless (or (exec-options-stdin options) (exec-options-stdout options) (exec-options-stderr options))
      (bad-exec-request "you must specify at least 1 of stdin, stdout, stderr"))
    (admit-pod-exec store namespace name options)
    (unless (find container (pod-all-containers pod)
                  :key #'container-spec-name :test #'string=)
      (bad-exec-request
       (format nil "container ~A is not valid for pod ~A" container name)))
    ;; kubelet streams every exec, with or without input or a terminal, through the runtime's
    ;; streaming server: output arrives as it is written and the command has no deadline.
    (if (typep (reconciler-runtime reconciler) 'control-plane-runtime)
        (serve-agent-exec-session
         reconciler (pod-uid pod) container options)
        (proxy-runtime-stream
         (reconciler-exec-url
          reconciler (pod-uid pod) container (exec-options-command options)
          :stdin (exec-options-stdin options)
          :stdout (exec-options-stdout options)
          :stderr (exec-options-stderr options)
          :tty (exec-options-tty options))))))

(defun attach-container-tty-p (pod container)
  "Return the TTY the container was created with, which an attach cannot change."
  (let ((spec (find container (pod-all-containers pod) :key #'container-spec-name :test #'string=)))
    (and (gethash "tty" (pod-runtime-container-object pod spec)) t)))

(defun pod-attach-response (store reconciler name &optional (namespace "default"))
  "Offer a Pod attach to the webhooks, then stream the container's own process."
  (let* ((pod (get-pod store namespace name))
         (options (exec-options-from-parameters (hunchentoot:get-parameters*)))
         (container (or (exec-options-container options)
                        (container-spec-name (aref (pod-containers pod) 0)))))
    (admit-pod-attach store namespace name options)
    (unless (upgrade-request-p)
      (bad-exec-request "Pod attach requires an upgraded connection"))
    (unless (or (exec-options-stdin options) (exec-options-stdout options) (exec-options-stderr options))
      (bad-exec-request "you must specify at least one of stdin, stdout, stderr"))
    (unless (find container (pod-all-containers pod) :key #'container-spec-name :test #'string=)
      (bad-exec-request (format nil "container ~A is not valid for pod ~A" container name)))
    ;; A terminal merges stderr into stdout, and containerd refuses both together.
    (let ((tty (attach-container-tty-p pod container)))
      (setf (exec-options-tty options) tty)
      (when tty (setf (exec-options-stderr options) nil)))
    (if (typep (reconciler-runtime reconciler) 'control-plane-runtime)
        (serve-agent-exec-session reconciler (pod-uid pod) container options :attach t)
        (proxy-runtime-stream
         (reconciler-attach-url
          reconciler (pod-uid pod) container
          :stdin (exec-options-stdin options)
          :stdout (exec-options-stdout options)
          :stderr (exec-options-stderr options)
          :tty (exec-options-tty options))))))

(defun pod-route-parts (path)
  "Return Pod subresource parts, namespace, and a route match indicator."
  (let ((parts (uiop:split-string path :separator '(#\/))))
    (when (and (<= 6 (length parts))
               (equal (subseq parts 0 4) '("" "api" "v1" "namespaces"))
               (dns-label-p (fifth parts)) (equal "pods" (sixth parts))
               (every (lambda (part) (plusp (length part))) (nthcdr 6 parts)))
      (values (nthcdr 6 parts) (fifth parts) t))))

(defun dispatch-pod-request (store runtime reconciler path method)
  "Route a Pod request PATH and METHOD to the matching handler -- the collection,
   a named Pod, or a subresource (status, resize, ephemeralcontainers, log, exec,
   eviction, attach, portforward, binding) -- answering a 404 Status when nothing
   matches. RUNTIME is unused."
  (declare (ignore runtime))
  (multiple-value-bind (parts namespace matched) (pod-route-parts path)
    (declare (ignore matched))
    (cond
      ((and (null parts) (eq method :post))
       (create-pod-response store reconciler namespace))
      ((and (null parts) (eq method :get))
       (list-pods-response store reconciler namespace))
      ((and (null parts) (eq method :delete))
       (delete-pod-collection-response store reconciler namespace))
      ((and (= 2 (length parts)) (string= "status" (second parts)) (eq method :get))
       (get-pod-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "status" (second parts)) (member method '(:put :patch)))
       (write-pod-status-response store reconciler (first parts) namespace method))
      ((and (= 1 (length parts)) (eq method :get))
       (get-pod-response store reconciler (first parts) namespace))
      ((and (= 1 (length parts)) (eq method :patch))
       (apply-pod-response store reconciler (first parts) namespace))
      ((and (= 1 (length parts)) (eq method :put))
       (replace-pod-response store reconciler (first parts) namespace))
      ((and (= 1 (length parts)) (eq method :delete))
       (delete-pod-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "resize" (second parts)) (eq method :get))
       (get-pod-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "resize" (second parts)) (member method '(:put :patch)))
       (write-pod-resize-response store reconciler (first parts) namespace method))
      ((and (= 2 (length parts)) (string= "ephemeralcontainers" (second parts)) (eq method :get))
       (get-pod-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "ephemeralcontainers" (second parts)) (member method '(:put :patch)))
       (write-pod-ephemeral-containers-response store reconciler (first parts) namespace method))
      ((and (= 2 (length parts)) (string= "log" (second parts)) (eq method :get))
       (pod-logs-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "exec" (second parts)) (member method '(:get :post)))
       (pod-exec-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "eviction" (second parts)) (eq method :post))
       (pod-eviction-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "attach" (second parts)) (member method '(:get :post)))
       (pod-attach-response store reconciler (first parts) namespace))
      ((and (= 2 (length parts)) (string= "portforward" (second parts)) (member method '(:get :post)))
       (pod-port-forward-response store reconciler (first parts) namespace))
            ((and (= 2 (length parts)) (string= "binding" (second parts)) (eq method :post))
       (pod-binding-response store (first parts) namespace))
      (t (status-response "Failure" "NotFound"
                          (format nil "No route for ~A ~A" method path) 404)))))

(defun read-complete-body (stream content-length)
  "Read a whole request body, of CONTENT-LENGTH octets or else until end of file.
A single read is not enough: pure-tls returns what one TLS record holds rather
than wait for the next, which truncates any body that spans records in flight."
  (let ((buffer (make-array (or content-length 65536) :element-type '(unsigned-byte 8))) (filled 0))
    (loop
      (when (= filled (length buffer))
        (when content-length (return))
        (setf buffer (let ((larger (make-array (* 2 (length buffer)) :element-type '(unsigned-byte 8))))
                       (replace larger buffer))))
      (let ((next (read-sequence buffer stream :start filled)))
        ;; A chunked stream past its last chunk answers 0 whatever START was.
        (when (<= next filled)
          (when content-length
            (core-resource-error 400 "BadRequest" "Request body ended after ~D of ~D octets" filled content-length))
          (return))
        (setf filled next)))
    (if (= filled (length buffer)) buffer (subseq buffer 0 filled))))

(defun read-request-body (request)
  "Hold the current request's entire body before any handler parses it."
  (let* ((header (hunchentoot:header-in :content-length request))
         (content-length (and header (parse-integer header :junk-allowed t)))
         (chunked (hunchentoot::input-chunking-p))
         (form (uiop:string-prefix-p "application/x-www-form-urlencoded" (or (hunchentoot:header-in :content-type request) ""))))
    (when (and (or chunked (and content-length (plusp content-length)))
               (not form)
               (not (uiop:string-prefix-p "multipart/form-data" (or (hunchentoot:header-in :content-type request) ""))))
      (let ((stream (hunchentoot::content-stream request)))
        ;; Otherwise the last chunk doesn't end the read, which then waits for the
        ;; connection's timeout and fails the request: kubectl chunks a body from stdin.
        (when (and chunked (typep stream 'chunga:chunked-input-stream))
          (setf (chunga:chunked-input-stream-eof-after-last-chunk stream) t))
        (setf (slot-value request 'hunchentoot::raw-post-data)
              (read-complete-body stream (unless chunked content-length)))))))

(defun request-media-type ()
  "Return the request's media type without parameters, or an empty string when it has none."
  (string-trim " " (subseq (or (hunchentoot:header-in* :content-type) "")
                           0 (position #\; (or (hunchentoot:header-in* :content-type) "")))))

(defun request-route-path (path)
  "Treat /api/ as /api, as Kubernetes' path recorder does for every API route."
  (let ((trimmed (string-right-trim "/" path)))
    (if (plusp (length trimmed)) trimmed path)))

(defun accept-media-ranges ()
  "Split the current Accept header into media ranges, each a list of its parts."
  (loop for range in (uiop:split-string (or (hunchentoot:header-in* :accept) "") :separator '(#\,))
        for parts = (mapcar (lambda (part) (string-trim " " part)) (uiop:split-string range :separator '(#\;)))
        when (plusp (length (first parts))) collect parts))

(defun check-request-timeout-parameter ()
  "Refuse a timeout query parameter that is not a Go duration, as upstream's request deadline filter does.
Watches are long-running requests, which that filter leaves alone."
  (let ((timeout (hunchentoot:get-parameter "timeout")))
    (when (and timeout (plusp (length timeout))
               (not (true-parameter-p (hunchentoot:get-parameter "watch")))
               (null (cel-parse-duration timeout)))
      (core-resource-error 400 "BadRequest" "invalid timeout specified in the request URL: time: invalid duration ~S"
                           timeout))))

(defun handle-http-request (store runtime reconciler request)
  "Answer the current API request, recording it for the API server's request metrics."
  (call-recording-apiserver-request
   (request-route-path (hunchentoot:script-name request)) (hunchentoot:request-method request)
   (lambda () (answer-http-request store runtime reconciler request))))

(defun answer-http-request (store runtime reconciler request)
  "Route the current request and turn its failure into a Kubernetes Status response."
  (handler-case
      (let ((path (progn (read-request-body request) (request-route-path (hunchentoot:script-name request))))
            (method (hunchentoot:request-method request))
            (*crd-field-validation* (crd-request-field-validation)))
        (let ((*flowcontrol-request-level*
                (if (and store (not *authenticated-api-identity*))
                    (flowcontrol-note-request store (request-api-identity) path method)
                    *flowcontrol-request-level*)))
          (check-request-timeout-parameter)
          (multiple-value-bind (*table-request* *table-api-version*) (negotiate-table-request)
            (if store
                (flowcontrol-call-with-seat store path method
                                            (lambda () (route-http-request store runtime reconciler path method)))
                (route-http-request store runtime reconciler path method)))))
    (kubernetes-error (error)
      (kubernetes-error-response error))
    (com.inuoe.jzon:json-parse-error (error)
      (status-response "Failure" "BadRequest" (princ-to-string error) 400))
    (runtime-error (error)
      (status-response "Failure" "RuntimeError"
                       (runtime-error-message error) 500))))

(defun route-http-request (store runtime reconciler path method)
  "Answer the current request from whichever API handler serves PATH."
  (progn
        (cond
          ((string= path "/gr8s/v1/network/explain")
           (unless (eq method :get)
             (core-resource-error 405 "MethodNotAllowed" "network explain requires GET"))
           (unless (typep runtime 'gr8s.controllers::control-plane-runtime)
             (core-resource-error 503 "ServiceUnavailable" "node operation routing is unavailable"))
           (let ((node (hunchentoot:get-parameter "node"))
                 (peer (hunchentoot:get-parameter "peer")))
             (unless (and node peer (dns-label-p node) (dns-label-p peer))
               (core-resource-error 400 "BadRequest" "valid node and peer are required"))
             (let* ((operation
                      (request-node-operation
                       (gr8s.controllers::control-plane-runtime-node-server runtime)
                       node
                       (make-instance 'gr8s.node.v1::operation-request
                                      :operation-id (generate-uid)
                                      :kind gr8s.node.v1::+operationkind-operation_kind_network_explain+
                                      :peer-id peer)
                       :timeout 5))
                    (bytes (gr8s.controllers::node-operation-channel-data
                            operation gr8s.node.v1::+streamchannel-stream_channel_stdout+)))
               (setf (hunchentoot:content-type*) "application/json")
               (trivial-utf-8:utf-8-bytes-to-string
                (coerce bytes '(vector (unsigned-byte 8)))))))
          ((and (uiop:string-prefix-p "/openapi/v3/" path) (not *openapi-v3-completing*))
           (openapi-v3-complete-response store runtime reconciler path))
          ((nth-value 1 (aggregated-api-route store path))
           ;; The aggregator's proxy is no resource route of this server's.
           (setf *apiserver-request-routed* nil)
           (aggregated-api-response store path method))
          ((string= path "/metrics")
           (setf (hunchentoot:content-type*) "text/plain; version=0.0.4; charset=utf-8")
           (concatenate 'string (apiserver-request-metrics-text) (process-metrics-text)
                        (if store (scheduler-metrics-text store) "")
                        (runtime-network-metrics runtime) (gateway-metrics-text) (volume-reclaim-metrics-text)
                        (if store (flowcontrol-metrics-text store) "")))
          ((string= path "/version") (version-response))
          ((nth-value 1 (component-status-route path))
           (component-status-response (component-status-route path) method))
          ((string= path "/api")
           (if (aggregated-discovery-requested-p)
               (aggregated-discovery-response store runtime reconciler "/api")
               (api-versions-response)))
          ((string= path "/apis")
           (if (aggregated-discovery-requested-p)
               (aggregated-discovery-response store runtime reconciler "/apis")
               (api-groups-response store)))
          ((string= path "/apis/metrics.k8s.io")
           (json-response (resource-metrics-api-group)))
          ((string= path "/apis/metrics.k8s.io/v1beta1")
           (json-response (resource-metrics-discovery-object)))
          ((uiop:string-prefix-p "/apis/metrics.k8s.io/v1beta1/" path)
           (json-response
            (resource-metrics-object
             store (runtime-resource-metrics runtime) path method
             :label-selector (hunchentoot:get-parameter "labelSelector")
             :field-selector (hunchentoot:get-parameter "fieldSelector"))))
          ((string= path "/apis/admissionregistration.k8s.io") (json-response (admission-api-group-object)))
          ((string= path "/apis/admissionregistration.k8s.io/v1") (admission-discovery-response))
          ((string= path "/openapi/v3/apis/admissionregistration.k8s.io/v1") (openapi-v3-response +admission-api-version+))
          ((string= path "/apis/certificates.k8s.io") (json-response (csr-api-group)))
          ((string= path "/apis/certificates.k8s.io/v1") (csr-discovery-response))
          ((string= path "/apis/certificates.k8s.io/v1beta1") (csr-v1beta1-discovery-response))
          ((string= path "/openapi/v3/apis/certificates.k8s.io/v1") (openapi-v3-response "certificates.k8s.io/v1"))
          ((csr-subresource-route path) (dispatch-csr-subresource store path method))
          ((string= path "/apis/discovery.k8s.io") (json-response (endpointslice-api-group)))
          ((string= path "/apis/discovery.k8s.io/v1") (endpointslice-discovery-response))
          ((string= path "/openapi/v3/apis/discovery.k8s.io/v1") (openapi-v3-response "discovery.k8s.io/v1"))
          ((string= path "/apis/networking.k8s.io") (json-response (networking-api-group)))
          ((string= path "/apis/networking.k8s.io/v1") (networking-discovery-response))
          ((string= path "/openapi/v3/apis/networking.k8s.io/v1") (openapi-v3-response "networking.k8s.io/v1"))
          ((networking-status-route path) (dispatch-networking-status-request store path method))
          ((string= path "/apis/storage.k8s.io") (json-response (storage-api-group)))
          ((string= path "/apis/storage.k8s.io/v1") (storage-discovery-response))
          ((string= path "/openapi/v3/apis/storage.k8s.io/v1") (openapi-v3-response "storage.k8s.io/v1"))
          ((storage-status-route path) (dispatch-storage-status-request store path method))
          ((typed-status-route path) (dispatch-typed-status-request store path method))
          ((namespace-finalize-route path) (dispatch-namespace-finalize-request store path method))
          ((equal path "/.well-known/openid-configuration") (openid-configuration-response))
          ((equal path "/openid/v1/jwks") (openid-jwks-response store))
          ((auth-review-group-route path)
           (multiple-value-bind (group version-document) (auth-review-group-route path)
             (if version-document (auth-review-discovery-response group) (json-response (typed-api-group group)))))
          ((auth-review-route path) (dispatch-auth-review-request store path method))
          ((nth-value 1 (service-account-token-route path)) (service-account-token-response store path method))
          ((typed-api-group-route path)
           (multiple-value-bind (group version-document) (typed-api-group-route path)
             (if version-document (typed-api-discovery-response group) (json-response (typed-api-group group)))))
          ((string= path "/apis/node.k8s.io") (json-response (policy-api-group "node.k8s.io")))
          ((string= path "/apis/node.k8s.io/v1") (policy-discovery-response "node.k8s.io"))
          ((string= path "/openapi/v3/apis/node.k8s.io/v1") (openapi-v3-response "node.k8s.io/v1"))
          ((string= path "/apis/scheduling.k8s.io") (json-response (policy-api-group "scheduling.k8s.io")))
          ((string= path "/apis/scheduling.k8s.io/v1") (policy-discovery-response "scheduling.k8s.io"))
          ((string= path "/openapi/v3/apis/scheduling.k8s.io/v1") (openapi-v3-response "scheduling.k8s.io/v1"))
          ((policy-status-route path) (dispatch-policy-status-request store path method))
          ((string= path "/apis/events.k8s.io") (json-response (event-api-group)))
          ((string= path "/apis/events.k8s.io/v1") (event-discovery-response))
          ((string= path "/apis/rbac.authorization.k8s.io") (json-response (rbac-api-group)))
          ((string= path "/apis/rbac.authorization.k8s.io/v1") (rbac-resources-response))
          ((string= path "/apis/gateway.networking.k8s.io") (json-response (gateway-api-group)))
          ((string= path "/apis/gateway.networking.k8s.io/v1") (gateway-discovery-response))
          ((string= path "/apis/cert-manager.io") (json-response (cert-manager-api-group)))
          ((string= path "/apis/cert-manager.io/v1") (cert-manager-discovery-response))
          ((string= path "/apis/autoscaling") (json-response (autoscaling-api-group)))
          ((string= path "/apis/autoscaling/v1") (autoscaling-discovery-response "v1"))
          ((string= path "/apis/autoscaling/v2") (autoscaling-discovery-response "v2"))
          ((hpa-status-route path) (dispatch-hpa-status-request store path method))
          ((string= path "/apis/apiregistration.k8s.io") (json-response (apiservice-api-group)))
          ((string= path "/apis/apiregistration.k8s.io/v1") (apiservice-discovery-response))
          ((and (nth-value 1 (apiservice-route path))
                (or (eq method :get) (builtin-apiservice-p store (apiservice-route path))))
           (apiservice-response store (apiservice-route path) method))
          ((string= path "/apis/apps") (json-response (workload-api-group)))
          ((string= path "/apis/batch") (json-response (batch-api-group)))
          ((string= path "/apis/batch/v1") (batch-resources-response))
          ((string= path "/apis/policy") (json-response (budget-api-group)))
          ((string= path "/apis/policy/v1") (budget-resources-response))
          ((string= path "/openapi/v3/apis/policy/v1") (openapi-v3-response "policy/v1"))
          ((string= path "/apis/apps/v1") (workload-resources-response))
          ((string= path "/openapi/v2") (openapi-v2-response store))
          ((string= path "/openapi/v3") (crd-openapi-discovery-response store))
          ((string= path "/openapi/v3/apis/events.k8s.io/v1") (openapi-v3-response "events.k8s.io/v1"))
          ((string= path "/openapi/v3/apis/apps/v1") (openapi-v3-response "apps/v1"))
          ((string= path "/openapi/v3/api/v1") (openapi-v3-response))
          ((string= path "/api/v1") (api-resources-response))
          ((nth-value 3 (node-http-proxy-route path))
           ;; Route on the trimmed path, but forward the path as sent: /logs/ is not /logs.
           (multiple-value-bind (name port suffix)
               (node-http-proxy-route (or (ignore-errors (hunchentoot:script-name*)) path))
             (node-http-proxy-response store reconciler name suffix method port)))
          ((node-status-route path) (dispatch-node-status-request store path method))
          ((and (eq method :get) (string= path "/api/v1/nodes"))
           (nodes-api-response store))
          ((and (eq method :get) (uiop:string-prefix-p "/api/v1/nodes/" path)
                (dns-subdomain-p (subseq path (length "/api/v1/nodes/"))))
           (nodes-api-response store (subseq path (length "/api/v1/nodes/"))))
          ((and (member method '(:put :patch)) (uiop:string-prefix-p "/api/v1/nodes/" path)
                (dns-subdomain-p (subseq path (length "/api/v1/nodes/"))))
           (write-node-response store (subseq path (length "/api/v1/nodes/")) method))
          ((and (eq method :post) (string= path "/api/v1/nodes")) (create-node-response store))
          ((and (eq method :delete) (string= path "/api/v1/nodes")) (delete-node-collection-response store))
          ((and (eq method :delete) (uiop:string-prefix-p "/api/v1/nodes/" path)
                (dns-subdomain-p (subseq path (length "/api/v1/nodes/"))))
           (delete-node-response store (subseq path (length "/api/v1/nodes/"))))
          ((crd-special-route store path) (dispatch-crd-request store path method))
          ((workload-subresource-route path) (dispatch-workload-subresource store path method))
          ((core-resource-route path)
           (dispatch-core-resource-request store path method))
          ((and (string= path "/api/v1/pods") (eq method :get))
           (list-pods-response store reconciler nil))
          ((nth-value 2 (service-http-proxy-route path))
           (multiple-value-bind (namespace id) (service-http-proxy-route path)
             (service-http-proxy-response store namespace id method)))
          ((nth-value 2 (pod-http-proxy-route path))
           (multiple-value-bind (namespace id) (pod-http-proxy-route path)
             (pod-http-proxy-response store namespace id method)))
          ((nth-value 2 (pod-route-parts path))
           (dispatch-pod-request store runtime reconciler path method))
          (t (setf *apiserver-request-routed* nil)
             (status-response "Failure" "NotFound" "route not found" 404)))))
