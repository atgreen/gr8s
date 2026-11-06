;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve the API objects whose consumers are other API clients: Leases, flow
;;;; control, dynamic resource allocation, storage version migrations and
;;;; admission policies.
;;;; They share the durable store, so this file holds what differs per type: its
;;;; schema, defaults, immutable fields, status subresource and finalizer lifecycle.

(in-package #:gr8s)

(defparameter *typed-api-schema*
  (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/typed-apis-v1.json"))
  "Pinned wire and structural definitions for the typed API objects and reviews.")

(defparameter *typed-api-resources*
  '(("leases" "Lease" "coordination.k8s.io/v1" t "coordination")
    ("prioritylevelconfigurations" "PriorityLevelConfiguration" "flowcontrol.apiserver.k8s.io/v1" nil "flowcontrol" :status :generation)
    ("flowschemas" "FlowSchema" "flowcontrol.apiserver.k8s.io/v1" nil "flowcontrol" :status :generation)
    ("deviceclasses" "DeviceClass" "resource.k8s.io/v1" nil "resource" :generation)
    ("resourceclaims" "ResourceClaim" "resource.k8s.io/v1" t "resource" :status)
    ("resourceclaimtemplates" "ResourceClaimTemplate" "resource.k8s.io/v1" t "resource")
    ("resourceslices" "ResourceSlice" "resource.k8s.io/v1" nil "resource" :generation)
    ;; GA in Kubernetes 1.37 (DRADeviceTaintRules, StorageVersionMigrator).
    ("devicetaintrules" "DeviceTaintRule" "resource.k8s.io/v1" nil "resource" :status :generation)
    ("storageversionmigrations" "StorageVersionMigration" "storagemigration.k8s.io/v1" nil "storagemigration" :status)
    ("validatingadmissionpolicies" "ValidatingAdmissionPolicy" "admissionregistration.k8s.io/v1" nil "admissionregistration" :status :generation)
    ("validatingadmissionpolicybindings" "ValidatingAdmissionPolicyBinding" "admissionregistration.k8s.io/v1" nil "admissionregistration" :generation)
    ("mutatingadmissionpolicies" "MutatingAdmissionPolicy" "admissionregistration.k8s.io/v1" nil "admissionregistration" :generation)
    ("mutatingadmissionpolicybindings" "MutatingAdmissionPolicyBinding" "admissionregistration.k8s.io/v1" nil "admissionregistration" :generation)
    ("apiservices" "APIService" "apiregistration.k8s.io/v1" nil "kube-aggregator" :status :generation))
  "Each entry: resource, kind, version, namespaced, proto package segment, then its traits.")

(defparameter *typed-api-groups*
  '("coordination.k8s.io" "flowcontrol.apiserver.k8s.io" "resource.k8s.io" "storagemigration.k8s.io")
  "Groups served only through this file. Admission keeps its own group document.")

(eval-when (:load-toplevel :execute)
  (dolist (entry *typed-api-resources*)
    (destructuring-bind (resource kind version namespaced &rest ignored) entry
      (declare (ignore ignored))
      (setf *stored-resource-types*
            (append (remove resource *stored-resource-types* :key #'first :test #'equal)
                    (list (list resource kind version namespaced))))))
  (dolist (section '("definitions" "messages"))
    (maphash (lambda (name value) (setf (gethash name (gethash section *podtemplate-schema*)) value))
             (gethash section *typed-api-schema*))))

(defun typed-api-resource-p (resource)
  "Return whether RESOURCE is served by this file."
  (assoc resource *typed-api-resources* :test #'equal))

(defun typed-api-trait-p (resource trait)
  "Return whether RESOURCE declares TRAIT in its table entry."
  (member trait (nthcdr 5 (typed-api-resource-p resource))))

(defun typed-api-schema-name (resource)
  "Return the pinned structural definition for a typed RESOURCE."
  (destructuring-bind (name kind version namespaced package &rest traits) (typed-api-resource-p resource)
    (declare (ignore name version namespaced traits))
    (if (equal package "kube-aggregator")
        (format nil "io.k8s.kube-aggregator.pkg.apis.apiregistration.v1.~A" kind)
        (format nil "io.k8s.api.~A.v1.~A" package kind))))

(defun typed-api-kind-p (kind)
  "Return the table entry of a typed object KIND."
  (find kind *typed-api-resources* :key #'second :test #'equal))

(defun decode-typed-api-protobuf (raw kind version)
  "Decode a typed object from its pinned wire schema."
  (let* ((package (fifth (typed-api-kind-p kind)))
         (object (template-protobuf-message
                  (if (equal package "kube-aggregator")
                      (format nil "k8s.io.kube_aggregator.pkg.apis.apiregistration.v1.~A" kind)
                      (format nil "k8s.io.api.~A.v1.~A" package kind))
                  raw))
         (metadata (core-protobuf-value (core-protobuf-fields raw) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) version (gethash "kind" object) kind)
    object))

(defun typed-api-default (object key value)
  "Set KEY in OBJECT to VALUE unless the client chose one."
  (multiple-value-bind (current present) (gethash key object)
    (when (or (not present) (eq current 'null))
      (setf (gethash key object) value))))

(defun typed-api-require (object key context)
  "Require a nonempty string at KEY of OBJECT."
  (let ((value (gethash key object)))
    (unless (and (stringp value) (plusp (length value)))
      (core-resource-error 422 "Invalid" "~A.~A is required" context key))
    value))

(defun typed-api-object-field (object key)
  "Return the object at KEY, creating an empty one when it is absent."
  (let ((value (gethash key object)))
    (if (hash-table-p value) value (setf (gethash key object) (core-object)))))

(defun typed-api-array (object key)
  "Return the array at KEY of OBJECT, treating an absent or null field as empty."
  (let ((value (gethash key object)))
    (if (member value '(nil null)) #() value)))

(defun default-admission-match-constraints (spec)
  "Apply the upstream defaults of a policy's matchConstraints."
  (let ((match (gethash "matchConstraints" spec)))
    (when (hash-table-p match)
      (typed-api-default match "matchPolicy" "Equivalent")
      (typed-api-object-field match "namespaceSelector")
      (typed-api-object-field match "objectSelector"))))

(defun validate-admission-policy-binding (spec actions)
  "Require a named policy and, when ACTIONS, a valid unique set of validation actions."
  (typed-api-require spec "policyName" "spec")
  (when actions
    (let ((values (typed-api-array spec "validationActions")))
      (unless (and (plusp (length values))
                   (every (lambda (value) (member value '("Deny" "Warn" "Audit") :test #'equal)) values)
                   (= (length values) (length (remove-duplicates values :test #'equal))))
        (core-resource-error 422 "Invalid" "spec.validationActions must be a unique subset of Deny, Warn and Audit"))))
  (let ((match (gethash "matchResources" spec)))
    (when (hash-table-p match) (default-admission-match-constraints (core-object "matchConstraints" match)))))

(defun default-flow-priority-level (spec)
  "Validate a priority level's mode and apply the upstream Limited defaults."
  (let ((type (gethash "type" spec)))
    (unless (member type '("Limited" "Exempt") :test #'equal)
      (core-resource-error 422 "Invalid" "spec.type must be Limited or Exempt"))
    (cond
      ((equal type "Exempt")
       (when (hash-table-p (gethash "limited" spec))
         (core-resource-error 422 "Invalid" "spec.limited must be empty when spec.type is Exempt")))
      ((not (hash-table-p (gethash "limited" spec)))
       (core-resource-error 422 "Invalid" "spec.limited must not be empty when spec.type is Limited"))
      (t
       (let* ((limited (gethash "limited" spec))
              (response (typed-api-object-field limited "limitResponse")))
         (typed-api-default limited "nominalConcurrencyShares" 30)
         (typed-api-default limited "lendablePercent" 0)
         (unless (member (gethash "type" response) '("Queue" "Reject") :test #'equal)
           (core-resource-error 422 "Invalid" "limitResponse.type must be Queue or Reject"))
         (when (equal "Queue" (gethash "type" response))
           (let ((queuing (typed-api-object-field response "queuing")))
             (typed-api-default queuing "queues" 64)
             (typed-api-default queuing "handSize" 8)
             (typed-api-default queuing "queueLengthLimit" 50))))))))

(defun fill-required-arrays (value schema &optional (depth 0))
  "Materialize required arrays the wire form cannot represent when empty, so a protobuf and JSON write agree."
  (when (< depth 32)
    (let ((schema (resolve-template-schema schema)))
      (cond
        ((and (hash-table-p value) (equal "object" (gethash "type" schema)))
         (let ((properties (gethash "properties" schema)))
           (loop for required across (gethash "required" schema #())
                 for child = (and properties (gethash required properties))
                 when (and child (equal "array" (gethash "type" (resolve-template-schema child)))
                           (member (gethash required value) '(nil null)))
                   do (setf (gethash required value) (vector)))
           (when properties
             (maphash (lambda (key item)
                        (let ((child (gethash key properties)))
                          (when child (fill-required-arrays item child (1+ depth)))))
                      value))))
        ((and (vectorp value) (not (stringp value)) (gethash "items" schema))
         (loop for item across value do (fill-required-arrays item (gethash "items" schema) (1+ depth)))))))
  value)

(defun validate-device-taint-rule-spec (spec)
  "Check a DeviceTaintRule's taint as upstream's validation does: a label-name key,
   a label value and one of the effects a rule may set."
  (let ((taint (require-object (gethash "taint" spec) "spec.taint")))
    (unless (core-qualified-key-p (typed-api-require taint "key" "spec.taint"))
      (core-resource-error 422 "Invalid" "spec.taint.key: Invalid value: ~S: must be a label name" (gethash "key" taint)))
    (let ((value (gethash "value" taint)))
      (unless (or (member value '(nil null "") :test #'equal) (core-label-name-p value :empty t))
        (core-resource-error 422 "Invalid" "spec.taint.value: Invalid value: ~S: must be a label value" value)))
    (unless (member (gethash "effect" taint) '("None" "NoSchedule" "NoExecute") :test #'equal)
      (core-resource-error 422 "Invalid" "spec.taint.effect: Unsupported value: ~S: supported values: \"NoExecute\", \"NoSchedule\", \"None\""
                           (gethash "effect" taint)))))

(defun stamp-device-taint-time (object existing)
  "Set a DeviceTaintRule's taint.timeAdded as upstream's strategy does: on create or
   update when the client set none, and to now when an update changes the effect but
   carries the old time over."
  (let* ((taint (gethash "taint" (gethash "spec" object)))
         (old (and existing (gethash "taint" (gethash "spec" existing (core-object)))))
         (time (gethash "timeAdded" taint)))
    (when (or (member time '(nil null))
              (and (hash-table-p old)
                   (not (equal (gethash "effect" old) (gethash "effect" taint)))
                   (equal time (gethash "timeAdded" old))))
      (setf (gethash "timeAdded" taint) (current-timestamp)))))

(defun normalize-typed-api-spec (resource object)
  "Apply RESOURCE's defaults and the validation its clients rely on."
  (let ((spec (gethash "spec" object)))
    (cond
      ((equal resource "apiservices") (validate-apiservice object))
      ((equal resource "leases")
       (when (hash-table-p spec)
         (let ((duration (gethash "leaseDurationSeconds" spec)) (transitions (gethash "leaseTransitions" spec)))
           (when (and (integerp duration) (<= duration 0))
             (core-resource-error 422 "Invalid" "spec.leaseDurationSeconds must be greater than 0"))
           (when (and (integerp transitions) (minusp transitions))
             (core-resource-error 422 "Invalid" "spec.leaseTransitions must be greater than or equal to 0")))))
      ((equal resource "prioritylevelconfigurations") (default-flow-priority-level (require-object spec "spec")))
      ((equal resource "flowschemas")
       (typed-api-require (require-object (gethash "priorityLevelConfiguration" (require-object spec "spec")) "spec.priorityLevelConfiguration")
                          "name" "spec.priorityLevelConfiguration")
       (typed-api-default spec "matchingPrecedence" 1000))
      ((equal resource "deviceclasses")
       (loop for selector across (typed-api-array (require-object spec "spec") "selectors")
             do (typed-api-require (require-object (gethash "cel" selector) "selector.cel") "expression" "selector.cel")))
      ((member resource '("resourceclaims" "resourceclaimtemplates") :test #'equal)
       (let* ((claim (if (equal resource "resourceclaims") spec (gethash "spec" (require-object spec "spec"))))
              (devices (gethash "devices" (or claim (core-object)))))
         (when (hash-table-p devices)
           (let ((seen nil))
             (loop for request across (typed-api-array devices "requests")
                   for name = (gethash "name" request)
                   do (unless (dns-label-p name)
                        (core-resource-error 422 "Invalid" "Device request name must be a DNS label"))
                      (when (member name seen :test #'equal)
                        (core-resource-error 422 "Invalid" "Duplicate device request name ~A" name))
                      (push name seen)
                      (when (eq (hash-table-p (gethash "exactly" request))
                                        (plusp (length (typed-api-array request "firstAvailable"))))
                        (core-resource-error 422 "Invalid" "A device request needs exactly one of exactly or firstAvailable"))
                      (let ((exact (gethash "exactly" request)))
                        (when (hash-table-p exact)
                          (typed-api-require exact "deviceClassName" "exactly")
                          (typed-api-default exact "allocationMode" "ExactCount")
                          (when (equal "ExactCount" (gethash "allocationMode" exact))
                            (typed-api-default exact "count" 1)))))))))
      ((equal resource "resourceslices")
       (let ((spec (require-object spec "spec")))
         (typed-api-require spec "driver" "spec")
         (let ((pool (require-object (gethash "pool" spec) "spec.pool")))
           (typed-api-require pool "name" "spec.pool")
           (unless (and (integerp (gethash "generation" pool)) (<= 0 (gethash "generation" pool)))
             (core-resource-error 422 "Invalid" "spec.pool.generation must be nonnegative"))
           (unless (and (integerp (gethash "resourceSliceCount" pool)) (< 0 (gethash "resourceSliceCount" pool)))
             (core-resource-error 422 "Invalid" "spec.pool.resourceSliceCount must be positive")))
         (unless (= 1 (count-if (lambda (field)
                                  (let ((value (gethash field spec)))
                                    (and value (not (eq value 'null)) (not (equal value "")))))
                                '("nodeName" "nodeSelector" "allNodes" "perDeviceNodeSelection")))
           (core-resource-error 422 "Invalid" "ResourceSlice needs exactly one of nodeName, nodeSelector, allNodes or perDeviceNodeSelection"))))
      ((equal resource "devicetaintrules") (validate-device-taint-rule-spec (require-object spec "spec")))
      ((equal resource "storageversionmigrations")
       (let ((target (require-object (gethash "resource" (require-object spec "spec")) "spec.resource")))
         (typed-api-require target "resource" "spec.resource")))
      ((equal resource "validatingadmissionpolicies")
       (let ((spec (require-object spec "spec")))
         (typed-api-default spec "failurePolicy" "Fail")
         (default-admission-match-constraints spec)
         (unless (hash-table-p (gethash "matchConstraints" spec))
           (core-resource-error 422 "Invalid" "spec.matchConstraints is required"))
         (loop for validation across (typed-api-array spec "validations")
               do (typed-api-require validation "expression" "validation"))
         (let ((seen nil))
           (loop for annotation across (typed-api-array spec "auditAnnotations")
                 do (typed-api-require annotation "key" "auditAnnotation")
                    (typed-api-require annotation "valueExpression" "auditAnnotation")
                    (let ((key (gethash "key" annotation)))
                      (unless (and (stringp key) (core-qualified-key-p (format nil "x.example.com/~A" key)))
                        (core-resource-error 422 "Invalid" "spec.auditAnnotations.key ~S must be a qualified name" key))
                      (when (member key seen :test #'equal)
                        (core-resource-error 422 "Invalid" "spec.auditAnnotations.key: Duplicate value: ~S" key))
                      (push key seen))))
         (unless (or (plusp (length (typed-api-array spec "validations")))
                     (plusp (length (typed-api-array spec "auditAnnotations"))))
           (core-resource-error 422 "Invalid" "spec needs validations or auditAnnotations"))))
      ((equal resource "validatingadmissionpolicybindings")
       (validate-admission-policy-binding (require-object spec "spec") t))
      ((equal resource "mutatingadmissionpolicies")
       (let ((spec (require-object spec "spec")))
         (typed-api-default spec "failurePolicy" "Fail")
         (typed-api-default spec "reinvocationPolicy" "Never")
         (default-admission-match-constraints spec)
         (unless (member (gethash "reinvocationPolicy" spec) '("Never" "IfNeeded") :test #'equal)
           (core-resource-error 422 "Invalid" "spec.reinvocationPolicy must be Never or IfNeeded"))
         (unless (hash-table-p (gethash "matchConstraints" spec))
           (core-resource-error 422 "Invalid" "spec.matchConstraints is required"))
         (unless (plusp (length (typed-api-array spec "mutations")))
           (core-resource-error 422 "Invalid" "spec.mutations is required"))
         (loop for mutation across (gethash "mutations" spec)
               for type = (gethash "patchType" mutation)
               do (cond ((equal type "ApplyConfiguration")
                         (typed-api-require (require-object (gethash "applyConfiguration" mutation) "applyConfiguration")
                                            "expression" "applyConfiguration"))
                        ((equal type "JSONPatch")
                         (typed-api-require (require-object (gethash "jsonPatch" mutation) "jsonPatch")
                                            "expression" "jsonPatch"))
                        (t (core-resource-error 422 "Invalid" "mutation.patchType must be ApplyConfiguration or JSONPatch"))))))
      ((equal resource "mutatingadmissionpolicybindings")
       (validate-admission-policy-binding (require-object spec "spec") nil)))
    object))

(defun typed-api-immutable-paths (resource)
  "Return the top-level fields of RESOURCE that an update may not change."
  (when (member resource '("resourceclaims" "resourceclaimtemplates" "storageversionmigrations") :test #'equal) '("spec")))

(defun validate-typed-api-update (resource before after)
  "Reject changes to fields RESOURCE fixes at creation."
  (dolist (field (typed-api-immutable-paths resource))
    (unless (core-json-equal-p (gethash field before) (gethash field after))
      (core-resource-error 422 "Invalid" "~A.~A is immutable" (core-resource-kind resource) field))))

(defun normalize-typed-api-resource (resource input namespace name store)
  "Copy, validate and default one typed object, keeping server-owned status and lifecycle fields."
  (let* ((object (copy-core-object (require-object input (core-resource-kind resource))))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (kind (core-resource-kind resource))
         (version (core-resource-api-version resource))
         (existing (and name store
                        (gethash (core-resource-key resource namespace name) (pod-store-resources store)))))
    (unless (and (equal version (gethash "apiVersion" object version))
                 (equal kind (gethash "kind" object kind)))
      (core-resource-error 400 "BadRequest" "Expected ~A ~A" version kind))
    (validate-core-metadata metadata namespace name :allow-finalizers t)
    (setf (gethash "kind" object) kind (gethash "apiVersion" object) version)
    (if namespace (setf (gethash "namespace" metadata) namespace) (remhash "namespace" metadata))
    ;; A write to the main resource keeps the stored status, so a status it carries is
    ;; dropped before validation, as upstream's strategies reset it first.
    (when (typed-api-trait-p resource :status)
      (unless *typed-api-status-write*
        (let ((status (and existing (gethash "status" existing))))
          (if status (setf (gethash "status" object) (copy-core-object status)) (remhash "status" object)))))
    (fill-required-arrays object (template-schema (typed-api-schema-name resource)))
    (validate-template-shape object (template-schema (typed-api-schema-name resource)) kind)
    (normalize-typed-api-spec resource object)
    (when (and (equal resource "devicetaintrules") (not *typed-api-status-write*))
      (stamp-device-taint-time object existing))
    (when (and (equal resource "apiservices") (not existing))
      (refuse-builtin-apiservice (gethash "name" metadata))
      (default-local-apiservice-status object))
    (remhash "deletionTimestamp" metadata)
    (remhash "generation" metadata)
    (when existing
      (let ((deleted (gethash "deletionTimestamp" (gethash "metadata" existing))))
        (when deleted (setf (gethash "deletionTimestamp" metadata) deleted))))
    (when (typed-api-trait-p resource :generation)
      (let ((before (and existing (gethash "generation" (gethash "metadata" existing)))))
        (setf (gethash "generation" metadata)
              (cond ((null before) 1)
                    ((core-json-equal-p (gethash "spec" existing) (gethash "spec" object)) before)
                    (t (1+ before))))))
    ;; Upstream's policy controller checks each generation once; here that happens with the write.
    (when (and (equal resource "validatingadmissionpolicies") store (not *typed-api-status-write*)
               (not (equal (gethash "generation" metadata)
                           (let ((status (gethash "status" object)))
                             (and (hash-table-p status) (gethash "observedGeneration" status))))))
      (setf (gethash "status" object) (admission-policy-status-after-check store object)))
    object))

(defun delete-typed-api-resource-unlocked (store resource existing dry-run)
  "Remove an object, or hold it as deleting while its finalizers remain. Caller holds the store lock."
  (let* ((metadata (gethash "metadata" existing))
         (namespace (gethash "namespace" metadata))
         (key (core-resource-key resource namespace (gethash "name" metadata)))
         (resources (copy-core-resource-index store))
         (revision (1+ (pod-store-resource-revision store))))
    (if (plusp (length (typed-api-array metadata "finalizers")))
        (let* ((updated (copy-core-object existing)) (updated-metadata (gethash "metadata" updated)))
          (unless (gethash "deletionTimestamp" updated-metadata)
            (setf (gethash "deletionTimestamp" updated-metadata) (current-timestamp)
                  (gethash "resourceVersion" updated-metadata) (write-to-string revision)
                  (gethash key resources) updated)
            (unless dry-run (commit-core-resources store resources revision)))
          (copy-core-object updated))
        (progn
          (remhash key resources)
          (unless dry-run (commit-core-resources store resources revision))
          (copy-core-object existing)))))

;;; Discovery

(defun typed-api-group (group)
  "Describe the served v1 version of a typed API GROUP."
  (let ((version (format nil "~A/v1" group)))
    (core-object "apiVersion" "v1" "kind" "APIGroup" "name" group
                 "versions" (vector (core-object "groupVersion" version "version" "v1"))
                 "preferredVersion" (core-object "groupVersion" version "version" "v1"))))

(defun typed-api-groups ()
  "Describe every group served only through this file."
  (map 'vector #'typed-api-group *typed-api-groups*))

(defun typed-status-discovery (version)
  "Advertise the status subresources of the typed collections in API VERSION."
  (coerce (loop for (resource kind entry-version namespaced) in *typed-api-resources*
                when (and (equal entry-version version) (typed-api-trait-p resource :status))
                  collect (core-object "name" (concatenate 'string resource "/status") "singularName" ""
                                       "namespaced" namespaced "kind" kind
                                       "verbs" #("get" "patch" "update")))
          'vector))

(defun typed-api-discovery-response (group)
  "Describe the collections and status subresources served in GROUP's v1 version."
  (let ((version (format nil "~A/v1" group)))
    (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" version
                                "resources" (concatenate 'vector (stored-resource-discovery version)
                                                         (typed-status-discovery version))))))

(defun typed-api-group-route (path)
  "Return the group and whether PATH names a typed group's version document."
  (dolist (group *typed-api-groups*)
    (let ((root (concatenate 'string "/apis/" group)))
      (cond ((equal path root) (return (values group nil)))
            ((equal path (concatenate 'string root "/v1")) (return (values group t)))))))

;;; Status subresource

(defun typed-status-route (path)
  "Resolve a named typed object's status URL to its collection, namespace and name."
  (when (uiop:string-suffix-p path "/status")
    (let ((route (core-resource-route (subseq path 0 (- (length path) 7)))))
      (when (and route (third route)
                 (or (equal "namespaces" (first route))
                     ;; PodCertificateRequest is a loosely-validated stored
                     ;; resource whose status (certificateChain) the external
                     ;; signer writes via /status (KEP-4317).
                     (equal "podcertificaterequests" (first route))
                     (and (typed-api-resource-p (first route)) (typed-api-trait-p (first route) :status))))
        route))))

(defun typed-status-from-request (resource name namespace old method content-type input)
  "Return OLD with only the status and metadata a status write may change taken from the request."
  (let* ((requested (cond ((eq method :put) input)
                          ((equal content-type "application/json-patch+json")
                           ;; Clients see an unset status as an empty object, so patches can add into it.
                           (let ((view (copy-core-object old)))
                             (unless (hash-table-p (gethash "status" view)) (setf (gethash "status" view) (core-object)))
                             (apply-core-json-patch view input)))
                          (t (merge-json-object (copy-core-object old) (require-object input "patch")))))
         (metadata (require-object (gethash "metadata" requested) "metadata")))
    (unless (and (equal name (gethash "name" metadata))
                 (member (gethash "namespace" metadata namespace) (list namespace "") :test #'equal))
      (core-resource-error 400 "BadRequest" "~A status metadata does not match its URL" (core-resource-kind resource)))
    (setf (gethash "status" old) (copy-core-object (require-object (gethash "status" requested (core-object)) "status")))
    ;; Status writes reset only the spec, so a request's labels and annotations still apply.
    (dolist (field '("labels" "annotations"))
      (multiple-value-bind (value present) (gethash field metadata)
        (if present
            (setf (gethash field (gethash "metadata" old)) (copy-core-object value))
            (remhash field (gethash "metadata" old)))))
    (unless (member (gethash "resourceVersion" metadata) '(nil "") :test #'equal)
      (setf (gethash "resourceVersion" (gethash "metadata" old)) (gethash "resourceVersion" metadata)))
    old))

(defun dispatch-typed-status-request (store path method)
  "Read or replace only a typed object's status, never its spec."
  (destructuring-bind (resource namespace name) (typed-status-route path)
    (when (eq method :get)
      (return-from dispatch-typed-status-request
        (json-response (if (equal resource "apiservices")
                           (apiservice-by-name store name)
                           (get-core-resource store resource namespace name)))))
    (unless (member method '(:put :patch))
      (core-resource-error 405 "MethodNotAllowed" "Unsupported status method"))
    (let* ((*typed-api-status-write* t)
           ;; Field validation finds a request's schema by version: core has its own ResourceClaim.
           (*core-resource-view-version* (core-resource-api-version resource))
           (dry-run (core-resource-dry-run-p))
           (content-type (first (uiop:split-string (or (hunchentoot:header-in* :content-type) "") :separator '(#\;))))
           (input (if (eq method :put)
                      (core-resource-request-object (core-resource-kind resource))
                      (progn
                        (unless (member content-type '("application/merge-patch+json" "application/strategic-merge-patch+json"
                                                       "application/json-patch+json" "application/apply-patch+yaml")
                                        :test #'equal)
                          (core-resource-error 415 "UnsupportedMediaType" "Unsupported status patch type"))
                        (if (equal content-type "application/apply-patch+yaml")
                            (values (yaml-parse (hunchentoot:raw-post-data :force-text t)))
                            (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t)))))))
      ;; Webhooks cannot run inside the update's transaction, so settle a selected write first.
      (when (admission-active-p store (admission-attributes-for store "UPDATE" resource namespace name :subresource "status"))
        (let ((old (get-core-resource store resource namespace name)))
          (setf input (admit-subresource-write
                       store resource "status" namespace name
                       (typed-status-from-request resource name namespace (copy-core-object old) method content-type input)
                       old :dry-run dry-run)
                method :put)))
      (json-response
       (update-core-resource
        store resource namespace name
        (lambda (old) (typed-status-from-request resource name namespace old method content-type input))
        :dry-run dry-run)))))
