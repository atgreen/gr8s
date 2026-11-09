;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate and default stored ResourceQuota, LimitRange, RuntimeClass and
;;;; PriorityClass objects through pinned Kubernetes schemas. Admission, usage
;;;; accounting and scheduling consume these objects from separate files, so
;;;; every accepted field here has an enforcing reader elsewhere.

(in-package #:gr8s.resources)

(defparameter *policy-schema*
  (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/policy-v1.json"))
  "Pinned wire and structural definitions for the policy API objects.")

(defvar *policy-status-write* nil
  "True only while a ResourceQuota status write replaces the server-owned status.")

(eval-when (:load-toplevel :execute)
  (dolist (type '(("resourcequotas" "ResourceQuota" "v1" t)
                  ("limitranges" "LimitRange" "v1" t)
                  ("runtimeclasses" "RuntimeClass" "node.k8s.io/v1" nil)
                  ("priorityclasses" "PriorityClass" "scheduling.k8s.io/v1" nil)))
    (setf *stored-resource-types*
          (append (remove (first type) *stored-resource-types* :key #'first :test #'equal) (list type))))
  (dolist (section '("definitions" "messages"))
    (maphash (lambda (name value) (setf (gethash name (gethash section *podtemplate-schema*)) value))
             (gethash section *policy-schema*))))

(defparameter +highest-user-priority+ 1000000000
  "The largest PriorityClass value a user-named class may declare.")

(defparameter +system-priority-classes+
  '(("system-node-critical" 2000001000 "Used for system critical pods that must not be moved from their current node.")
    ("system-cluster-critical" 2000000000 "Used for system critical pods that must run in the cluster, but can be moved to another node if necessary."))
  "The built-in classes with their fixed values and upstream descriptions.")

(defparameter +standard-quota-resources+
  '("pods" "services" "replicationcontrollers" "resourcequotas" "secrets" "configmaps"
    "persistentvolumeclaims" "services.nodeports" "services.loadbalancers"
    "cpu" "memory" "ephemeral-storage" "storage" "requests.cpu" "requests.memory"
    "requests.ephemeral-storage" "requests.storage" "limits.cpu" "limits.memory"
    "limits.ephemeral-storage")
  "Unqualified names the quota API accepts in a hard resource list.")

(defparameter +integer-quota-resources+
  '("pods" "services" "replicationcontrollers" "resourcequotas" "secrets" "configmaps"
    "persistentvolumeclaims" "services.nodeports" "services.loadbalancers")
  "Quota resources counted in whole objects.")

(defparameter +quota-compute-resources+
  '("pods" "count/pods" "cpu" "memory" "requests.cpu" "requests.memory" "limits.cpu" "limits.memory")
  "Resources a Terminating, NotTerminating or NotBestEffort quota scope can track.")

(defun policy-resource-p (resource)
  "Return whether RESOURCE is one of the quota, limit, runtime or priority collections."
  (member resource '("resourcequotas" "limitranges" "runtimeclasses" "priorityclasses") :test #'equal))

(defun policy-resource-schema-name (resource)
  "Return the pinned structural definition for a policy RESOURCE."
  (format nil "io.k8s.api.~A.~A"
          (cond ((equal resource "runtimeclasses") "node.v1")
                ((equal resource "priorityclasses") "scheduling.v1")
                (t "core.v1"))
          (core-resource-kind resource)))

(defun policy-quantity (value context)
  "Parse VALUE as a quantity small enough to add exactly, rejecting absurd exponents."
  (let ((quantity (parse-container-quantity value context)))
    (unless (<= -30 (container-quantity-scale quantity) 30)
      (core-resource-error 422 "Invalid" "~A is outside the supported quantity range" context))
    quantity))

(defun policy-quantity-value (quantity)
  "Return a parsed QUANTITY as an exact rational."
  (* (container-quantity-coefficient quantity) (expt 10 (container-quantity-scale quantity))))

(defun policy-value (text)
  "Return the exact rational of a stored canonical quantity TEXT."
  (policy-quantity-value (parse-container-quantity text)))

(defun policy-value-string (value &optional (format :decimal))
  "Render exact nonnegative rational VALUE as a canonical quantity in FORMAT."
  (container-quantity-string
   (normalize-container-quantity
    (make-container-quantity :coefficient (ceiling (* value (expt 10 9))) :scale -9 :format format))))

(defun normalize-policy-resource-list (object key context &key nonnegative)
  "Canonicalize the optional resource list at KEY of OBJECT, dropping an explicit null."
  (when (eq (gethash key object) 'null) (remhash key object))
  (let ((values (gethash key object)))
    (when values
      (require-object values context)
      (dolist (name (loop for name being the hash-keys of values collect name))
        (let ((quantity (policy-quantity (gethash name values) (format nil "~A[~A]" context name))))
          (unless (core-qualified-key-p name)
            (core-resource-error 422 "Invalid" "~A has an invalid resource name ~S" context name))
          (when (and nonnegative (minusp (container-quantity-coefficient quantity)))
            (core-resource-error 422 "Invalid" "~A[~A] must be nonnegative" context name))
          (setf (gethash name values) (container-quantity-string quantity)))))
    values))

(defun quota-count-resource-name-p (name)
  "Return whether NAME is the count/<resource>[.<group>] generic object count form."
  (uiop:string-prefix-p "count/" name))

(defun quota-extended-request-name-p (name)
  "Return whether NAME quotas the requests of an extended Pod resource."
  (and (uiop:string-prefix-p "requests." name)
       (position #\/ name)
       (extended-resource-name-p (subseq name (length "requests.")))))

(defun quota-hugepage-resource-name (name)
  "Return the hugepage resource counted by a bare or requests-prefixed quota."
  (let ((resource (if (uiop:string-prefix-p "requests." name) (subseq name 9) name)))
    (when (hugepage-size resource) resource)))

(defun quota-storage-class-resource (name)
  "Return the storage class and its bare resource when NAME is a per-class PVC quota."
  (let* ((marker ".storageclass.storage.k8s.io/") (position (search marker name)))
    (when position
      (let ((resource (subseq name (+ position (length marker)))))
        (when (member resource '("requests.storage" "persistentvolumeclaims") :test #'equal)
          (values (subseq name 0 position) resource))))))

(defun validate-quota-hard-names (hard)
  "Require standard or qualified names, and whole numbers for the counted ones."
  (maphash
   (lambda (name value)
     (unless (or (position #\/ name) (member name +standard-quota-resources+ :test #'equal)
                 (quota-hugepage-resource-name name))
       (core-resource-error 422 "Invalid" "spec.hard[~A] must be a standard resource for quota" name))
     (when (or (member name +integer-quota-resources+ :test #'equal)
               (quota-count-resource-name-p name)
               (equal "persistentvolumeclaims" (nth-value 1 (quota-storage-class-resource name))))
       (unless (integerp (policy-value value))
         (core-resource-error 422 "Invalid" "spec.hard[~A] must be an integer" name))))
   hard))

(defun quota-scope-valid-for-resource-p (scope name)
  "Return whether a quota SCOPE can meaningfully track the hard resource NAME."
  (cond ((equal scope "BestEffort") (member name '("pods" "count/pods") :test #'equal))
        ((equal scope "PriorityClass")
         (or (member name +quota-compute-resources+ :test #'equal)
             (member name '("ephemeral-storage" "requests.ephemeral-storage" "limits.ephemeral-storage") :test #'equal)
             (quota-extended-request-name-p name)))
        (t (member name +quota-compute-resources+ :test #'equal))))

(defun quota-spec-scopes (spec)
  "Return every scope name in SPEC, combining scopes and the scope selector."
  (append (coerce (gethash "scopes" spec #()) 'list)
          (let ((selector (gethash "scopeSelector" spec)))
            (when selector
              (map 'list (lambda (term) (gethash "scopeName" term))
                   (gethash "matchExpressions" selector #()))))))

(defun validate-quota-scope-selector (selector)
  "Validate implemented scope expressions and their operator and value shapes."
  (reject-unsupported-fields selector '("matchExpressions") "spec.scopeSelector")
  (loop for term across (optional-vector selector "matchExpressions" "spec.scopeSelector")
        do (drop-null-fields term)
           (reject-unsupported-fields term '("scopeName" "operator" "values") "scopeSelector expression")
           (let ((scope (gethash "scopeName" term)) (operator (gethash "operator" term))
                 (values (gethash "values" term #())))
             (unless (member operator '("In" "NotIn" "Exists" "DoesNotExist") :test #'equal)
               (core-resource-error 422 "Invalid" "Invalid scopeSelector operator ~S" operator))
             (if (equal scope "PriorityClass")
                 (if (member operator '("In" "NotIn") :test #'equal)
                     (when (zerop (length values))
                       (core-resource-error 422 "Invalid" "scopeSelector values are required for operator ~A" operator))
                     (when (plusp (length values))
                       (core-resource-error 422 "Invalid" "scopeSelector values must be empty for operator ~A" operator)))
                 (progn
                   (unless (equal operator "Exists")
                     (core-resource-error 422 "Invalid" "scope ~A only supports the Exists operator" scope))
                   (when (plusp (length values))
                     (core-resource-error 422 "Invalid" "scopeSelector values must be empty for operator Exists")))))))

(defun normalize-resource-quota-status (status)
  "Canonicalize a client-written ResourceQuota status."
  (drop-null-fields status)
  (reject-unsupported-fields status '("hard" "used") "ResourceQuota.status")
  (normalize-policy-resource-list status "hard" "status.hard" :nonnegative t)
  (normalize-policy-resource-list status "used" "status.used" :nonnegative t)
  status)

(defun normalize-resource-quota (object existing)
  "Validate quota hard limits and scopes; only a status write may change status."
  (let ((spec (gethash "spec" object)))
    (when (member spec '(nil null)) (setf spec (core-object) (gethash "spec" object) spec))
    (drop-null-fields (require-object spec "spec"))
    (reject-unsupported-fields spec '("hard" "scopes" "scopeSelector") "ResourceQuota.spec")
    (normalize-policy-resource-list spec "hard" "spec.hard" :nonnegative t)
    (when (gethash "hard" spec) (validate-quota-hard-names (gethash "hard" spec)))
    (when (gethash "scopeSelector" spec) (validate-quota-scope-selector (gethash "scopeSelector" spec)))
    (let ((scopes (quota-spec-scopes spec)))
      (dolist (scope scopes)
        (unless (member scope '("Terminating" "NotTerminating" "BestEffort" "NotBestEffort" "PriorityClass"
                                "CrossNamespacePodAffinity")
                        :test #'equal)
          (core-resource-error 422 "Invalid" "ResourceQuota scope ~S is not implemented" scope))
        (when (gethash "hard" spec)
          (maphash (lambda (name value)
                     (declare (ignore value))
                     (unless (quota-scope-valid-for-resource-p scope name)
                       (core-resource-error 422 "Invalid" "unsupported scope ~A applied to resource ~A" scope name)))
                   (gethash "hard" spec))))
      (loop for (left right) in '(("Terminating" "NotTerminating") ("BestEffort" "NotBestEffort"))
            do (when (and (member left scopes :test #'equal) (member right scopes :test #'equal))
                 (core-resource-error 422 "Invalid" "conflicting quota scopes ~A and ~A" left right))))
    (if *policy-status-write*
        (setf (gethash "status" object)
              (normalize-resource-quota-status (require-object (gethash "status" object (core-object)) "status")))
        (setf (gethash "status" object)
              (if existing (copy-core-object (gethash "status" existing (core-object))) (core-object))))
    object))

(defun limit-range-default-from (item target source)
  "Copy SOURCE entries missing from TARGET within a LimitRange ITEM, as API defaulting does."
  (let ((values (gethash source item)))
    (when values
      (unless (gethash target item) (setf (gethash target item) (core-object)))
      (maphash (lambda (name value)
                 (unless (nth-value 1 (gethash name (gethash target item)))
                   (setf (gethash name (gethash target item)) value)))
               values))))

(defun validate-limit-range-order (item name)
  "Enforce min <= defaultRequest <= default <= max for resource NAME of a LimitRange ITEM."
  (flet ((amount (key)
           (let ((text (and (gethash key item) (gethash name (gethash key item)))))
             (and text (policy-value text)))))
    (let ((minimum (amount "min")) (maximum (amount "max"))
          (default (amount "default")) (request (amount "defaultRequest")))
      (flet ((ordered (low high low-name high-name)
               (when (and low high (> low high))
                 (core-resource-error 422 "Invalid" "~A value of ~A must not exceed ~A" low-name name high-name))))
        (ordered minimum maximum "min" "max")
        (ordered minimum request "min" "defaultRequest")
        (ordered request default "defaultRequest" "default")
        (ordered default maximum "default" "max")
        (ordered request maximum "defaultRequest" "max")
        (ordered minimum default "min" "default")))))

(defun normalize-limit-range (object)
  "Validate LimitRange items and apply the Container defaulting upstream performs."
  (let* ((spec (require-object (gethash "spec" object) "spec"))
         (limits (optional-vector (drop-null-fields spec) "limits" "spec")))
    (reject-unsupported-fields spec '("limits") "LimitRange.spec")
    (when (zerop (length limits)) (core-resource-error 422 "Invalid" "LimitRange.spec.limits is required"))
    (loop for item across limits
          do (drop-null-fields (require-object item "LimitRange item"))
             (reject-unsupported-fields item '("type" "max" "min" "default" "defaultRequest" "maxLimitRequestRatio") "LimitRange item")
             (let ((type (gethash "type" item)))
               (unless (member type '("Pod" "Container" "PersistentVolumeClaim") :test #'equal)
                 (core-resource-error 422 "Invalid" "LimitRange type ~S is not implemented" type))
               (dolist (key '("max" "min" "default" "defaultRequest" "maxLimitRequestRatio"))
                 (normalize-policy-resource-list item key (concatenate 'string "limits." key) :nonnegative t))
               (when (equal type "Container")
                 (limit-range-default-from item "default" "max")
                 (limit-range-default-from item "defaultRequest" "default")
                 (limit-range-default-from item "defaultRequest" "min"))
               (unless (equal type "Container")
                 (dolist (key '("default" "defaultRequest"))
                   (when (and (gethash key item) (plusp (hash-table-count (gethash key item))))
                     (core-resource-error 422 "Invalid" "~A may not be specified for a ~A limit" key type))))
               (when (equal type "PersistentVolumeClaim")
                 (flet ((storage-only (key)
                          (when (gethash key item)
                            (maphash (lambda (name value)
                                       (declare (ignore value))
                                       (unless (equal name "storage")
                                         (core-resource-error 422 "Invalid" "PersistentVolumeClaim limits only support storage")))
                                     (gethash key item)))))
                   (storage-only "min") (storage-only "max") (storage-only "maxLimitRequestRatio"))
                 (unless (or (and (gethash "min" item) (gethash "storage" (gethash "min" item)))
                             (and (gethash "max" item) (gethash "storage" (gethash "max" item))))
                   (core-resource-error 422 "Invalid" "PersistentVolumeClaim limits require min or max storage")))
               (let ((names nil))
                 (dolist (key '("max" "min" "default" "defaultRequest"))
                   (when (gethash key item)
                     (maphash (lambda (name value) (declare (ignore value)) (pushnew name names :test #'equal))
                              (gethash key item))))
                 (dolist (name names) (validate-limit-range-order item name)))
               (when (gethash "maxLimitRequestRatio" item)
                 (maphash (lambda (name value)
                            (when (< (policy-value value) 1)
                              (core-resource-error 422 "Invalid" "maxLimitRequestRatio[~A] must be at least 1" name)))
                          (gethash "maxLimitRequestRatio" item)))))
    object))

(defun normalize-runtime-class (object)
  "Validate a RuntimeClass handler, Pod overhead and scheduling constraints."
  (let ((handler (gethash "handler" object)))
    (unless (dns-label-p handler)
      (core-resource-error 422 "Invalid" "RuntimeClass handler must be a DNS label")))
  (dolist (field '("overhead" "scheduling"))
    (when (eq (gethash field object) 'null) (remhash field object)))
  (let ((overhead (gethash "overhead" object)))
    (when overhead
      (drop-null-fields (require-object overhead "overhead"))
      (reject-unsupported-fields overhead '("podFixed") "RuntimeClass.overhead")
      (normalize-policy-resource-list overhead "podFixed" "overhead.podFixed" :nonnegative t)
      (when (gethash "podFixed" overhead)
        (maphash (lambda (name value)
                   (declare (ignore value))
                   ;; Extended resources are counted by the scheduler alone, as for containers.
                   (unless (or (member name '("cpu" "memory") :test #'equal) (extended-resource-name-p name))
                     (core-resource-error 422 "Invalid" "overhead.podFixed[~A] has no implemented accounting" name)))
                 (gethash "podFixed" overhead)))))
  (let ((scheduling (gethash "scheduling" object)))
    (when scheduling
      (drop-null-fields (require-object scheduling "scheduling"))
      (reject-unsupported-fields scheduling '("nodeSelector" "tolerations") "RuntimeClass.scheduling")
      (when (gethash "nodeSelector" scheduling) (validate-pod-node-selector (gethash "nodeSelector" scheduling)))
      (validate-pod-tolerations scheduling)))
  object)

(defun normalize-priority-class (object store existing)
  "Validate a PriorityClass value, its reserved names and the single global default."
  (let ((value (gethash "value" object)) (name (gethash "name" (gethash "metadata" object))))
    (unless (typep value '(signed-byte 32))
      (core-resource-error 422 "Invalid" "PriorityClass value must be an int32"))
    (if (uiop:string-prefix-p "system-" name)
        (let ((known (assoc name +system-priority-classes+ :test #'equal)))
          (unless (and known (= (second known) value) (not (eq t (gethash "globalDefault" object))))
            (core-resource-error 403 "Forbidden" "priority class names with 'system-' prefix are reserved for system use only")))
        (when (> value +highest-user-priority+)
          (core-resource-error 403 "Forbidden" "maximum allowed value of a user defined priority is ~D" +highest-user-priority+)))
    (when (member (gethash "preemptionPolicy" object) '(nil null) :test #'equal)
      (setf (gethash "preemptionPolicy" object) "PreemptLowerPriority"))
    (unless (member (gethash "preemptionPolicy" object) '("PreemptLowerPriority" "Never") :test #'equal)
      (core-resource-error 422 "Invalid" "Invalid PriorityClass preemptionPolicy"))
    (multiple-value-bind (global present) (gethash "globalDefault" object)
      (when (and present (not (member global '(t nil null))))
        (core-resource-error 422 "Invalid" "PriorityClass globalDefault must be boolean"))
      (when (eq global 'null) (remhash "globalDefault" object))
      (when (and (eq global t) store)
        (loop for key being the hash-keys of (pod-store-resources store) using (hash-value other)
              do (when (and (equal "priorityclasses" (first key))
                            (eq t (gethash "globalDefault" other))
                            (not (and existing (equal (third key) name))))
                   (core-resource-error 409 "Conflict" "PriorityClass ~A is already marked as default; only one default can exist"
                                        (third key))))))
    (when (eq (gethash "description" object) 'null) (remhash "description" object))
    object))

(defun normalize-policy-resource (resource input namespace name store)
  "Copy, validate and default one policy API object, preserving server-owned status."
  (let* ((object (copy-core-object (require-object input (core-resource-kind resource))))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (kind (core-resource-kind resource))
         (version (core-resource-api-version resource))
         (existing (and name store
                        (gethash (core-resource-key resource namespace name) (pod-store-resources store)))))
    (unless (and (equal version (gethash "apiVersion" object version))
                 (equal kind (gethash "kind" object kind)))
      (core-resource-error 400 "BadRequest" "Expected ~A ~A" version kind))
    (validate-core-metadata metadata namespace name)
    (setf (gethash "kind" object) kind (gethash "apiVersion" object) version)
    (if namespace (setf (gethash "namespace" metadata) namespace) (remhash "namespace" metadata))
    (validate-template-shape object (template-schema (policy-resource-schema-name resource)) kind)
    (cond ((equal resource "resourcequotas") (normalize-resource-quota object existing))
          ((equal resource "limitranges") (normalize-limit-range object))
          ((equal resource "runtimeclasses") (normalize-runtime-class object))
          (t (normalize-priority-class object store existing)))))

(defun validate-policy-update (resource before after)
  "Reject changes to the immutable identity fields of policy objects."
  (flet ((immutable (object-before object-after field context)
           (unless (core-json-equal-p (gethash field object-before) (gethash field object-after))
             (core-resource-error 422 "Invalid" "~A.~A is immutable" context field))))
    (cond ((equal resource "priorityclasses")
           (immutable before after "value" "PriorityClass")
           (immutable before after "preemptionPolicy" "PriorityClass"))
          ((equal resource "runtimeclasses")
           (immutable before after "handler" "RuntimeClass"))
          ((equal resource "resourcequotas")
           (let ((old (gethash "spec" before)) (new (gethash "spec" after)))
             (immutable old new "scopes" "ResourceQuota.spec")
             (immutable old new "scopeSelector" "ResourceQuota.spec"))))))

(defun validate-policy-delete (resource existing)
  "Protect built-in PriorityClasses, whose values admission and scheduling rely on."
  (when (and (equal resource "priorityclasses")
             (assoc (gethash "name" (gethash "metadata" existing)) +system-priority-classes+ :test #'equal))
    (core-resource-error 403 "Forbidden" "builtin PriorityClass ~A cannot be deleted"
                         (gethash "name" (gethash "metadata" existing)))))

(defun ensure-system-priority-classes (store)
  "Create the two built-in PriorityClasses without replacing existing identities."
  (dolist (entry +system-priority-classes+)
    (handler-case
        (create-core-resource store "priorityclasses"
         (core-object "metadata" (core-object "name" (first entry))
                      "value" (second entry) "description" (third entry)) nil)
      (kubernetes-error (condition)
        (unless (= 409 (kubernetes-error-status-code condition)) (error condition))))))

(defun decode-policy-protobuf (bytes kind version)
  "Decode one typed policy object through its pinned wire schema."
  (let* ((message (format nil "k8s.io.api.~A.~A"
                          (cond ((equal kind "RuntimeClass") "node.v1")
                                ((equal kind "PriorityClass") "scheduling.v1")
                                (t "core.v1"))
                          kind))
         (object (template-protobuf-message message bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) version (gethash "kind" object) kind)
    object))
