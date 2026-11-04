;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Validate durable Namespace, ServiceAccount and RBAC API objects used to
;;;; bootstrap in-cluster clients. Storage transactions, optimistic revisions
;;;; and HTTP patch semantics are shared with the core resource implementation.

(in-package #:gr8s)

(defun bootstrap-string-array (value context &key nonempty)
  "Validate a JSON array of strings and optionally require at least one item."
  (unless (and (vectorp value) (not (stringp value))
               (or (not nonempty) (plusp (length value)))
               (every (lambda (item) (and (stringp item) (plusp (length item)))) value))
    (core-resource-error 422 "Invalid" "~A must be an array of nonempty strings" context))
  value)

(defun validate-rbac-rules (rules cluster-p)
  "Validate resource and nonresource RBAC policy rule shapes."
  (unless (and (vectorp rules) (not (stringp rules)))
    (core-resource-error 422 "Invalid" "rules must be an array"))
  (loop for rule across rules
        do (require-object rule "rule")
           (reject-unsupported-fields rule '("verbs" "apiGroups" "resources" "resourceNames" "nonResourceURLs") "rule")
           (bootstrap-string-array (gethash "verbs" rule) "rule.verbs" :nonempty t)
           (if (gethash "nonResourceURLs" rule)
               (progn
                 (unless cluster-p (core-resource-error 422 "Invalid" "Roles cannot grant nonResourceURLs"))
                 (when (or (gethash "resources" rule) (gethash "apiGroups" rule) (gethash "resourceNames" rule))
                   (core-resource-error 422 "Invalid" "Nonresource rules cannot contain resource fields"))
                 (bootstrap-string-array (gethash "nonResourceURLs" rule) "rule.nonResourceURLs" :nonempty t)
                 (loop for url across (gethash "nonResourceURLs" rule)
                       unless (char= #\/ (char url 0))
                         do (core-resource-error 422 "Invalid" "nonResourceURLs must begin with /")))
               (progn
                 (bootstrap-string-array (gethash "resources" rule) "rule.resources" :nonempty t)
                 (let ((groups (gethash "apiGroups" rule)))
                   (unless (and (vectorp groups) (not (stringp groups)) (plusp (length groups))
                                (every #'stringp groups))
                     (core-resource-error 422 "Invalid" "rule.apiGroups must be a nonempty string array")))
                 (when (gethash "resourceNames" rule)
                   (bootstrap-string-array (gethash "resourceNames" rule) "rule.resourceNames"))))))

(defun default-rbac-api-group (object group)
  "Apply Kubernetes string defaulting without treating a supplied nonstring as empty."
  (multiple-value-bind (value present) (gethash "apiGroup" object)
    (when (or (not present) (eq value 'null) (equal value ""))
      (setf (gethash "apiGroup" object) group))))

(defun validate-rbac-binding (object cluster-p)
  "Validate binding role references and subject identities."
  (let* ((ref (require-object (gethash "roleRef" object) "roleRef"))
         (subjects (gethash "subjects" object #())))
    (default-rbac-api-group ref "rbac.authorization.k8s.io")
    (unless (and (equal "rbac.authorization.k8s.io" (gethash "apiGroup" ref))
                 (member (gethash "kind" ref) (if cluster-p '("ClusterRole") '("Role" "ClusterRole")) :test #'equal)
                 (dns-subdomain-p (gethash "name" ref)))
      (core-resource-error 422 "Invalid" "Invalid roleRef"))
    (unless (and (vectorp subjects) (not (stringp subjects)))
      (core-resource-error 422 "Invalid" "subjects must be an array"))
    (loop for subject across subjects
          for kind = (gethash "kind" (require-object subject "subject"))
          do (unless (member kind '("User" "Group" "ServiceAccount") :test #'equal)
               (core-resource-error 422 "Invalid" "Invalid subject kind"))
             (require-nonempty-string (gethash "name" subject) "subject.name")
             (default-rbac-api-group subject (if (equal kind "ServiceAccount") "" "rbac.authorization.k8s.io"))
             (if (equal kind "ServiceAccount")
                 (unless (and (dns-subdomain-p (gethash "name" subject))
                              (or (not cluster-p) (dns-label-p (gethash "namespace" subject)))
                              (equal "" (gethash "apiGroup" subject "")))
                   (core-resource-error 422 "Invalid" "Invalid ServiceAccount subject"))
                 (unless (equal "rbac.authorization.k8s.io" (gethash "apiGroup" subject))
                   (core-resource-error 422 "Invalid" "User and Group subjects require the RBAC apiGroup"))))))

(defun normalize-bootstrap-resource (resource input namespace name &optional store)
  "Copy, validate and default an implemented bootstrap API object."
  (when (workload-resource-p resource)
    (return-from normalize-bootstrap-resource (normalize-workload-resource resource input namespace name)))
  (when (equal resource "controllerrevisions")
    (return-from normalize-bootstrap-resource (normalize-controller-revision input namespace name)))
  (when (equal resource "events")
    (return-from normalize-bootstrap-resource (normalize-event-resource input namespace name)))
  (when (equal resource "services")
    (return-from normalize-bootstrap-resource (normalize-service-resource input namespace name store)))
  (when (equal resource "podtemplates")
    (return-from normalize-bootstrap-resource (normalize-podtemplate input namespace name)))
  (let* ((object (copy-core-object (require-object input "resource")))
         (kind (core-resource-kind resource))
         (version (core-resource-api-version resource))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (fields (cond ((equal resource "namespaces") '("spec" "status"))
                       ((equal resource "serviceaccounts") '("secrets" "imagePullSecrets" "automountServiceAccountToken"))
                       ((member resource '("roles" "clusterroles") :test #'equal) '("rules"))
                       (t '("roleRef" "subjects")))))
    (unless (and (equal version (gethash "apiVersion" object version))
                 (equal kind (gethash "kind" object kind)))
      (core-resource-error 400 "BadRequest" "Expected ~A ~A" version kind))
    (reject-unsupported-fields object (append '("apiVersion" "kind" "metadata") fields) kind)
    (validate-core-metadata metadata namespace name)
    (setf (gethash "kind" object) kind (gethash "apiVersion" object) version)
    (if namespace (setf (gethash "namespace" metadata) namespace) (remhash "namespace" metadata))
    (cond
      ((equal resource "namespaces")
       (unless (dns-label-p (gethash "name" metadata))
         (core-resource-error 422 "Invalid" "Namespace name must be a DNS label"))
       (let ((spec (gethash "spec" object (core-object))))
         (reject-unsupported-fields spec '("finalizers") "Namespace.spec")
         (when (gethash "finalizers" spec)
           (bootstrap-string-array (gethash "finalizers" spec) "spec.finalizers"))
         (setf (gethash "spec" object) spec
               (gethash "status" object) (core-object "phase" "Active"))))
      ((equal resource "serviceaccounts")
       (multiple-value-bind (automount present) (gethash "automountServiceAccountToken" object)
         (when (and present (not (member automount '(t nil))))
           (core-resource-error 422 "Invalid" "automountServiceAccountToken must be boolean")))
       (dolist (field '("secrets" "imagePullSecrets"))
         (let ((refs (gethash field object #())))
           (unless (and (vectorp refs) (not (stringp refs)))
             (core-resource-error 422 "Invalid" "~A must be an array" field))
           (loop for ref across refs
                 unless (dns-subdomain-p (gethash "name" (require-object ref field)))
                   do (core-resource-error 422 "Invalid" "~A references require valid names" field)))))
      ((member resource '("roles" "clusterroles") :test #'equal)
       (validate-rbac-rules (gethash "rules" object #()) (equal resource "clusterroles")))
      (t (validate-rbac-binding object (equal resource "clusterrolebindings"))))
    object))

(defun stored-resource-discovery (version)
  "Describe implemented durable collections in API VERSION for discovery."
  (coerce
   (loop for (resource kind api-version namespaced) in *stored-resource-types*
         when (equal api-version version)
           collect (core-object "name" resource "singularName" (string-downcase kind)
                                "namespaced" namespaced "kind" kind
                                "shortNames" (cond ((equal resource "certificatesigningrequests") #("csr"))
                                                   ((equal resource "configmaps") #("cm"))
                                                   ((equal resource "services") #("svc"))
                                                   ((equal resource "replicationcontrollers") #("rc"))
                                                   ((equal resource "events") #("ev"))
                                                   ((equal resource "customresourcedefinitions") #("crd" "crds"))
                                                   ((equal resource "persistentvolumes") #("pv"))
                                                   ((equal resource "persistentvolumeclaims") #("pvc"))
                                                   ((equal resource "storageclasses") #("sc")) (t #()))
                                "verbs" (if (or (csr-resource-p resource) (storage-resource-p resource) (endpointslice-resource-p resource)
                                                (member resource '("podtemplates" "events" "deployments" "replicasets" "replicationcontrollers" "daemonsets" "controllerrevisions" "customresourcedefinitions") :test #'equal))
                                            #("create" "delete" "deletecollection" "get" "list" "patch" "update" "watch")
                                            #("create" "delete" "get" "list" "patch" "update" "watch"))))
   'vector))

(defun rbac-resources-response ()
  "Return discovery for the supported RBAC v1 resource collections."
  (json-response
   (core-object "apiVersion" "v1" "kind" "APIResourceList"
                "groupVersion" "rbac.authorization.k8s.io/v1"
                "resources" (stored-resource-discovery "rbac.authorization.k8s.io/v1"))))

(defun native-node-architecture ()
  "Return the Kubernetes architecture name of this native executable."
  (cond ((member :x86-64 *features*) "amd64")
        ((member :arm64 *features*) "arm64")
        (t (string-downcase (machine-type)))))

(defun node-api-object (node)
  "Serialize a registered worker with readiness taken from its live lease."
  (let ((address (node-reported-address node)))
    (core-object
     "apiVersion" "v1" "kind" "Node"
     "metadata" (let ((metadata (core-object "name" (node-record-name node) "uid" (node-record-id node)
                                             "resourceVersion" (node-record-resource-version node)
                                             "labels" (node-labels node))))
                  (when (node-record-annotations node)
                    (setf (gethash "annotations" metadata) (copy-core-object (node-record-annotations node))))
                  metadata)
     "spec" (core-object "unschedulable" nil "podCIDR" (node-record-pod-cidr node)
                         "podCIDRs" (vector (node-record-pod-cidr node)))
     "status" (core-object
               "conditions" (vector (core-object "type" "Ready"
                                                  "status" (if (node-record-ready-p node) "True" "False")
                                                  "reason" (if (node-record-ready-p node) "AgentReady" "AgentNotReady")
                                                  "message" "Readiness follows the gr8s node session lease"))
               "addresses" (if (and address (plusp (length address)))
                               (vector (core-object "type" "InternalIP" "address" address)) #())
               "nodeInfo" (core-object "operatingSystem" "linux" "architecture" (native-node-architecture)
                                        "kubeletVersion" "v1.36.0-gr8s.0")))))

(defun node-write-input (node method)
  "Return the requested Node object from a typed or JSON PUT, or a patch applied to NODE's view."
  (if (eq method :put)
      (core-resource-request-object "Node")
      (let* ((content-type (first (uiop:split-string (or (hunchentoot:header-in* :content-type) "") :separator '(#\;))))
             (patch (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t)))
             (current (node-api-object node)))
        (cond ((equal content-type "application/json-patch+json") (apply-core-json-patch current patch))
              ((member content-type '("application/merge-patch+json" "application/strategic-merge-patch+json") :test #'equal)
               (merge-json-object current (require-object patch "patch")))
              (t (core-resource-error 415 "UnsupportedMediaType" "Unsupported Node patch format"))))))

(defun decode-node-protobuf (bytes)
  "Decode the writable parts of a typed Node, keeping unenforceable spec fields visible to admission."
  (let* ((fields (core-protobuf-fields bytes))
         (metadata (core-protobuf-value fields 1))
         (spec-bytes (core-protobuf-value fields 2))
         (spec (core-object)))
    (when spec-bytes
      (let ((spec-fields (core-protobuf-fields spec-bytes)))
        (let ((cidr (core-protobuf-string spec-fields 1)))
          (when (plusp (length cidr)) (setf (gethash "podCIDR" spec) cidr)))
        (setf (gethash "unschedulable" spec) (eql 1 (core-protobuf-value spec-fields 4 0)))
        (when (find 5 spec-fields :key #'first) (setf (gethash "taints" spec) (vector (core-object))))))
    (core-object "apiVersion" "v1" "kind" "Node" "spec" spec
                 "metadata" (if metadata (core-protobuf-metadata metadata) (core-object)))))

(defun validate-node-write (input node)
  "Refuse Node changes gr8s could not enforce, and return the requested labels and annotations."
  (let* ((metadata (require-object (gethash "metadata" input) "metadata"))
         (spec (gethash "spec" input (core-object)))
         (labels (gethash "labels" metadata))
         (annotations (gethash "annotations" metadata))
         (builtin (node-builtin-labels node))
         (custom (core-object)))
    (unless (equal "Node" (gethash "kind" input "Node")) (core-resource-error 400 "BadRequest" "Expected v1 Node"))
    (when (and (gethash "name" metadata) (not (equal (node-record-name node) (gethash "name" metadata))))
      (core-resource-error 400 "BadRequest" "metadata.name does not match the request name"))
    (when (and (gethash "uid" metadata) (not (equal (node-record-id node) (gethash "uid" metadata))))
      (core-resource-error 409 "Conflict" "metadata.uid does not match the stored Node"))
    (when (eq t (gethash "unschedulable" spec))
      (core-resource-error 422 "Invalid" "gr8s does not support cordoning: spec.unschedulable cannot be set"))
    (let ((taints (gethash "taints" spec)))
      (when (and taints (not (eq taints 'null)) (plusp (length taints)))
        (core-resource-error 422 "Invalid" "gr8s does not enforce taints: spec.taints cannot be set")))
    (when (and (gethash "podCIDR" spec) (not (equal (gethash "podCIDR" spec) (node-record-pod-cidr node))))
      (core-resource-error 422 "Invalid" "spec.podCIDR is immutable"))
    (when (member labels '(nil null)) (setf labels (core-object)))
    (when (member annotations '(nil null)) (setf annotations (core-object)))
    (validate-core-metadata (core-object "name" "node" "labels" labels "annotations" annotations) nil nil)
    (maphash (lambda (key value)
               (unless (equal value (gethash key labels))
                 (core-resource-error 422 "Invalid" "Node label ~A is derived from the node and cannot change" key)))
             builtin)
    (maphash (lambda (key value) (unless (nth-value 1 (gethash key builtin)) (setf (gethash key custom) value))) labels)
    (values custom annotations)))

(defun write-node-response (store name method)
  "Apply a Node update or patch to its durable labels and annotations."
  (let* ((node (get-node store name)) (input (require-object (node-write-input node method) "Node"))
         (expected (gethash "resourceVersion" (require-object (gethash "metadata" input) "metadata")))
         (dry-run (core-resource-dry-run-p)))
    (multiple-value-bind (labels annotations) (validate-node-write input node)
      (json-response
       (node-api-object
        (with-store-lock (store)
          (let ((current (get-node-unlocked store name)))
            (unless (and current (equal (node-record-id current) (node-record-id node)))
              (core-resource-error 409 "Conflict" "The Node was replaced"))
            (when (and (stringp expected) (plusp (length expected))
                       (not (equal expected (node-record-resource-version current))))
              (core-resource-error 409 "Conflict" "The Node was modified; apply your changes to the latest version"))
            (let ((updated (copy-node-record current)))
              (setf (node-record-labels updated) (copy-core-object labels)
                    (node-record-annotations updated) (copy-core-object annotations))
              (cond
                ((and (workload-equal-p labels (or (node-record-labels current) (core-object)))
                      (workload-equal-p annotations (or (node-record-annotations current) (core-object))))
                 current)
                (dry-run updated)
                (t
                 ;; A fresh store's counter can trail a record's initial version.
                 (setf (node-record-resource-version updated)
                       (write-to-string (max (next-pod-revision-unlocked store)
                                             (1+ (parse-integer (node-record-resource-version current))))))
                 (persist-node store updated)
                 ;; Other holders keep this record, as with readiness updates.
                 (setf (node-record-labels current) (node-record-labels updated)
                       (node-record-annotations current) (node-record-annotations updated)
                       (node-record-resource-version current) (node-record-resource-version updated))
                 current))))))))))

(defun nodes-api-response (store &optional name)
  "Return the actual registered worker list or one node by NAME."
  (if name
      (json-response (node-api-object (get-node store name)))
      (let ((labels (core-selector-predicate (hunchentoot:parameter "labelSelector")))
            (fields (core-selector-predicate (hunchentoot:parameter "fieldSelector") :fields t
                                         :field-paths '("metadata.name" "spec.unschedulable"))))
        (json-response
         (core-object "apiVersion" "v1" "kind" "NodeList"
                      "metadata" (core-object "resourceVersion" "0")
                      "items" (coerce (remove-if-not
                                       (lambda (node) (and (funcall labels node) (funcall fields node)))
                                       (mapcar #'node-api-object (list-nodes store))) 'vector))))))
