;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Enforce ValidatingAdmissionPolicy and MutatingAdmissionPolicy objects on the
;;;; admission path: select policy and binding pairs by their match rules, bind
;;;; parameters, compute variables, and evaluate CEL. A CEL failure follows the
;;;; policy's failurePolicy. Applied configurations merge objects and replace lists.

(in-package #:gr8s)

(defparameter +admission-policy-variables+
  '("object" "oldObject" "request" "params" "namespaceObject" "variables" "authorizer")
  "Variables the admission policy CEL environment declares.")

(defun compile-admission-policy-condition (expression)
  "Compile a policy's condition. Variables are dynamically typed here, so a dyn result is checked when evaluated."
  (let ((*cel-declared-variables* +admission-policy-variables+))
    (multiple-value-bind (program type) (compile-cel-expression expression)
      (unless (member (cel-type-head type) '(:bool :dyn))
        (cel-check-error "must evaluate to bool, found ~A" (cel-type-name type)))
      program)))

(defun admission-policy-rule-matches-p (rule attributes)
  "Test one NamedRuleWithOperations, including its resourceNames."
  (and (admission-rule-matches-p rule attributes (admission-group attributes) (admission-version attributes))
       (let ((names (gethash "resourceNames" rule)))
         (or (member names '(nil null)) (zerop (length names))
             (find (admission-name attributes) names :test #'equal)))))

(defun admission-match-resources-p (store match attributes &key require-rules)
  "Apply a MatchResources: its rules unless excluded, then its namespace and object selectors."
  (flet ((rules (key) (let ((value (gethash key match))) (if (member value '(nil null)) #() value))))
    (and (or (and (not require-rules) (zerop (length (rules "resourceRules"))))
             (some (lambda (rule) (admission-policy-rule-matches-p rule attributes)) (rules "resourceRules")))
         (notany (lambda (rule) (admission-policy-rule-matches-p rule attributes)) (rules "excludeResourceRules"))
         (admission-namespace-selected-p store (admission-defaulted-selectors match) attributes)
         (admission-object-selected-p (admission-defaulted-selectors match) attributes))))

(defun admission-defaulted-selectors (match)
  "Return MATCH with the absent selectors that match everything filled in."
  (let ((selectors (core-object "namespaceSelector" (core-object) "objectSelector" (core-object))))
    (dolist (key '("namespaceSelector" "objectSelector") selectors)
      (when (hash-table-p (gethash key match))
        (setf (gethash key selectors) (gethash key match))))))

(defun admission-policy-candidates (store policies attributes)
  "Return (policy . bindings) for every policy in collection POLICIES whose rules select this operation.
Admission configuration resources are exempt, so a bad policy can always be removed."
  (unless (equal +admission-api-group+ (admission-group attributes))
    (let ((stored (list-core-resources store policies)))
      (when stored
        (let ((bindings (list-core-resources store (if (equal policies "mutatingadmissionpolicies")
                                                       "mutatingadmissionpolicybindings"
                                                       "validatingadmissionpolicybindings"))))
          (loop for policy in (sort (copy-list stored) #'string< :key #'object-name)
                for selected = (remove (gethash "name" (gethash "metadata" policy)) bindings
                                       :test-not #'equal
                                       :key (lambda (binding) (gethash "policyName" (gethash "spec" binding))))
                when (and selected
                          (let ((rules (gethash "resourceRules" (gethash "matchConstraints" (gethash "spec" policy) (core-object)))))
                            (and (hash-table-p (gethash "matchConstraints" (gethash "spec" policy)))
                                 (not (member rules '(nil null)))
                                 (some (lambda (rule) (admission-policy-rule-matches-p rule attributes)) rules))))
                  collect (cons policy selected)))))))

(defun object-name (object)
  "Return a stored OBJECT's name."
  (gethash "name" (gethash "metadata" object)))

(defun admission-policy-namespace-object (store attributes)
  "Return the object bound to namespaceObject, or null for cluster-scoped requests."
  (let ((name (or (admission-namespace attributes)
                  (and (equal "namespaces" (admission-plural attributes)) (admission-name attributes)))))
    (or (and name (handler-case (get-core-resource store "namespaces" nil name)
                    (kubernetes-error () nil)))
        'null)))

(defun admission-policy-parameters (store policy binding attributes)
  "Return the parameter objects BINDING selects for POLICY, or (null) when POLICY takes none.
A second value of T means parameters are required, absent, and the binding denies that."
  (let* ((kind (gethash "paramKind" (gethash "spec" policy)))
         (reference (gethash "paramRef" (gethash "spec" binding))))
    (unless (and (hash-table-p kind) (hash-table-p reference))
      (return-from admission-policy-parameters (list 'null)))
    (let* ((type (find-if (lambda (entry)
                            (and (equal (second entry) (gethash "kind" kind))
                                 (equal (third entry) (gethash "apiVersion" kind))))
                          *stored-resource-types*))
           (namespace (and type (fourth type)
                           (let ((named (gethash "namespace" reference)))
                             (if (and (stringp named) (plusp (length named))) named (admission-namespace attributes)))))
           (name (gethash "name" reference))
           (found
             (when type
               (if (and (stringp name) (plusp (length name)))
                   (let ((object (handler-case (get-core-resource store (first type) namespace name)
                                   (kubernetes-error () nil))))
                     (and object (list object)))
                   (let ((selector (gethash "selector" reference)))
                     (remove-if-not (lambda (object)
                                      (workload-selector-matches-p (if (hash-table-p selector) selector (core-object))
                                                                   (admission-object-labels object)))
                                    (list-core-resources store (first type) namespace)))))))
      (if found
          found
          (values nil (equal "Deny" (gethash "parameterNotFoundAction" reference "Deny")))))))

(defun admission-policy-bindings (store policy parameter attributes)
  "Build the CEL environment for POLICY, computing its variables in order."
  (let* ((request (admission-review-request
                   (make-admission-hook :version (admission-version attributes)) attributes))
         (variables (core-object))
         (bindings (list (cons "object" (gethash "object" request))
                         (cons "oldObject" (gethash "oldObject" request))
                         (cons "request" request)
                         (cons "params" parameter)
                         (cons "namespaceObject" (admission-policy-namespace-object store attributes))
                         (cons "variables" variables)
                         (cons "authorizer" (cel-opaque :authorizer nil)))))
    (loop for variable across (let ((value (gethash "variables" (gethash "spec" policy))))
                                (if (member value '(nil null)) #() value))
          ;; A failing variable fails only the expressions that read it, as "no such key".
          do (handler-case
                 (let ((*cel-declared-variables* +admission-policy-variables+))
                   (setf (gethash (gethash "name" variable) variables)
                         (evaluate-cel-value (compile-cel-expression (gethash "expression" variable)) bindings)))
               ((or cel-compile-error cel-evaluation-error) (condition)
                 (format *error-output* "~&Admission policy variable ~A: ~A~%" (gethash "name" variable) condition))))
    bindings))

(defun admission-policy-conditions-pass-p (policy bindings)
  "Evaluate POLICY's matchConditions, whose errors reach the caller for its failurePolicy."
  (let ((*cel-declared-variables* +admission-policy-variables+))
    (every (lambda (condition)
             (evaluate-cel-condition (compile-admission-policy-condition (gethash "expression" condition)) bindings))
           (let ((value (gethash "matchConditions" (gethash "spec" policy))))
             (if (member value '(nil null)) #() value)))))

(defun admission-policy-failure (policy binding attributes condition)
  "Apply POLICY's failurePolicy to a CEL CONDITION: refuse under Fail, otherwise log."
  (let ((kind (gethash "kind" policy)) (name (object-name policy)))
    (if (equal "Ignore" (gethash "failurePolicy" (gethash "spec" policy) "Fail"))
        (format *error-output* "~&Ignoring failed ~A ~A: ~A~%" kind name condition)
        (core-resource-error 403 "Forbidden" "~A ~S is forbidden: ~A '~A' with binding '~A' denied request: ~A"
                             (admission-plural attributes) (or (admission-name attributes) "")
                             kind name (object-name binding) condition))))

(defun admission-policy-pairs (store policies attributes)
  "Return (policy binding parameter denied) for each selected pair and parameter in order."
  (loop for (policy . bindings) in (admission-policy-candidates store policies attributes)
        when (admission-match-resources-p store (gethash "matchConstraints" (gethash "spec" policy)) attributes)
          nconc (loop for binding in (sort (copy-list bindings) #'string< :key #'object-name)
                      for match = (gethash "matchResources" (gethash "spec" binding))
                      when (or (not (hash-table-p match)) (admission-match-resources-p store match attributes))
                        nconc (multiple-value-bind (parameters denied)
                                  (admission-policy-parameters store policy binding attributes)
                                (if parameters
                                    (mapcar (lambda (parameter) (list policy binding parameter nil)) parameters)
                                    (when denied (list (list policy binding 'null t))))))))

;;; Validation

(defun admission-record-audit-annotations (policy binding bindings)
  "Evaluate POLICY's audit annotations, whose failures follow failurePolicy; a null value omits one.
No audit backend exists to carry the values, so they go to the server log."
  (loop for annotation across (let ((value (gethash "auditAnnotations" (gethash "spec" policy))))
                                (if (member value '(nil null)) #() value))
        do (let* ((*cel-declared-variables* +admission-policy-variables+)
                  (value (evaluate-cel-value (compile-cel-expression (gethash "valueExpression" annotation)) bindings)))
             (cond ((eq value 'null) nil)
                   ((stringp value)
                    (format *error-output* "~&Audit annotation ~A/~A from binding ~A: ~A~%"
                            (object-name policy) (gethash "key" annotation) (object-name binding) value))
                   (t (cel-fail "valueExpression must evaluate to a string or null"))))))

(defun admission-policy-denial-code (reason)
  "Map a Validation's reason to its HTTP status, defaulting as upstream does."
  (cond ((equal reason "Unauthorized") (values 401 "Unauthorized"))
        ((equal reason "Forbidden") (values 403 "Forbidden"))
        ((equal reason "RequestEntityTooLarge") (values 413 "RequestEntityTooLarge"))
        ((equal reason "Invalid") (values 422 "Invalid"))
        (t (values 422 "Invalid"))))

(defun admission-validation-message (validation bindings)
  "Choose a failed VALIDATION's message: messageExpression, then message, then the expression."
  (or (let ((expression (gethash "messageExpression" validation)))
        (when (and (stringp expression) (plusp (length expression)))
          (handler-case
              (let* ((*cel-declared-variables* +admission-policy-variables+)
                     (value (evaluate-cel-value (compile-cel-expression expression) bindings)))
                (and (stringp value) (plusp (length value)) value))
            ((or cel-compile-error cel-evaluation-error) () nil))))
      (let ((message (gethash "message" validation)))
        (and (stringp message) (plusp (length message)) message))
      (format nil "failed expression: ~A" (gethash "expression" validation))))

(defun admission-apply-validation-failure (policy binding validation bindings attributes)
  "Carry out BINDING's validationActions for one failed VALIDATION."
  (let ((actions (gethash "validationActions" (gethash "spec" binding) #()))
        (message (admission-validation-message validation bindings)))
    (when (find "Warn" actions :test #'equal)
      (push (format nil "Validation failed for ~A '~A' with binding '~A': ~A"
                    (gethash "kind" policy) (object-name policy) (object-name binding) message)
            (admission-warnings attributes)))
    (when (find "Deny" actions :test #'equal)
      (multiple-value-bind (code reason) (admission-policy-denial-code (gethash "reason" validation))
        (core-resource-error code reason "~A ~S is forbidden: ~A '~A' with binding '~A' denied request: ~A"
                             (admission-plural attributes) (or (admission-name attributes) "")
                             (gethash "kind" policy) (object-name policy) (object-name binding) message)))))

(defun admission-run-validating-policies (store attributes)
  "Evaluate every selected validating policy and binding, refusing on a denial."
  (loop for (policy binding parameter denied) in (admission-policy-pairs store "validatingadmissionpolicies" attributes)
        do (when denied
             (admission-policy-failure policy binding attributes "no params found for policy binding"))
           (unless denied
             (handler-case
                 ;; Validations, their messages, audit annotations and variables share one runtime
                 ;; budget per binding; matchConditions have their own, as upstream's do.
                 (let* ((*cel-shared-budget* (list +cel-runtime-budget+))
                        (bindings (admission-policy-bindings store policy parameter attributes)))
                   (when (with-cel-budget (+cel-match-conditions-budget+)
                           (admission-policy-conditions-pass-p policy bindings))
                     (loop for validation across (let ((value (gethash "validations" (gethash "spec" policy))))
                                                   (if (member value '(nil null)) #() value))
                           unless (let ((*cel-declared-variables* +admission-policy-variables+))
                                    (evaluate-cel-condition (compile-admission-policy-condition (gethash "expression" validation)) bindings))
                             do (admission-apply-validation-failure policy binding validation bindings attributes))
                     (admission-record-audit-annotations policy binding bindings)))
               ((or cel-compile-error cel-evaluation-error) (condition)
                 (admission-policy-failure policy binding attributes condition))))))

;;; Mutation

(defun admission-mutation-result (mutation bindings object)
  "Evaluate one MUTATION, returning OBJECT with its patch applied."
  (let* ((*cel-declared-variables* +admission-policy-variables+)
         (type (gethash "patchType" mutation))
         (apply-configuration (equal type "ApplyConfiguration"))
         (*cel-construction-types* (list (if apply-configuration "Object" "JSONPatch")))
         (source (gethash (if apply-configuration "applyConfiguration" "jsonPatch") mutation))
         (value (evaluate-cel-value (compile-cel-expression (gethash "expression" source)) bindings)))
    (if apply-configuration
        (progn
          (unless (hash-table-p value)
            (cel-fail "an applyConfiguration expression must produce an Object"))
          (merge-json-object (copy-core-object object) value))
        (progn
          (unless (cel-list-p value)
            (cel-fail "a jsonPatch expression must produce a list of JSONPatch"))
          (apply-core-json-patch (copy-core-object object) value)))))

(defun admission-run-mutating-policies (store attributes)
  "Apply every selected mutating policy to the attributes' object, in policy and binding name order."
  (when (member (admission-operation attributes) '("CREATE" "UPDATE") :test #'equal)
    (loop for (policy binding parameter denied) in (admission-policy-pairs store "mutatingadmissionpolicies" attributes)
          do (when denied
               (admission-policy-failure policy binding attributes "no params found for policy binding"))
             (unless denied
               (handler-case
                   (let* ((*cel-shared-budget* (list +cel-runtime-budget+))
                          (bindings (admission-policy-bindings store policy parameter attributes)))
                     (when (with-cel-budget (+cel-match-conditions-budget+)
                             (admission-policy-conditions-pass-p policy bindings))
                       (loop for mutation across (gethash "mutations" (gethash "spec" policy))
                             do (setf (admission-object attributes)
                                      (admission-mutation-result mutation bindings (admission-object attributes)))
                                ;; Later mutations read the object the earlier ones produced.
                                (setf (cdr (assoc "object" bindings :test #'equal)) (admission-object attributes)))))
                 ((or cel-compile-error cel-evaluation-error) (condition)
                   (admission-policy-failure policy binding attributes condition))
                 (kubernetes-error (condition)
                   (admission-policy-failure policy binding attributes (kubernetes-error-message condition))))))))

;;; Authorizer

(defun admission-authorizer-check (store)
  "Return the function that answers authorizer checks with the same RBAC a real request meets."
  (let ((requester (request-api-identity)))
    (lambda (attributes verb)
      (let* ((user (getf attributes :user))
             (identity (if user
                           (make-api-user-identity :username user :groups (coerce (getf attributes :groups) 'vector))
                           requester))
             (spec (if (getf attributes :path)
                       (core-object "nonResourceAttributes"
                                    (core-object "path" (getf attributes :path) "verb" verb))
                       (core-object "resourceAttributes"
                                    (core-object "group" (or (getf attributes :group) "") "verb" verb
                                                 "resource" (or (getf attributes :resource) "")
                                                 "subresource" (or (getf attributes :subresource) "")
                                                 "namespace" (or (getf attributes :namespace) "")
                                                 "name" (or (getf attributes :name) "")))))
             (status (access-review-status store identity spec)))
        (values (eq t (gethash "allowed" status)) (gethash "reason" status) nil)))))

(defun admission-request-resource (attributes)
  "Describe the request's resource as authorizer.requestResource starts from."
  (list :group (admission-group attributes) :resource (admission-plural attributes)
        :subresource (admission-subresource attributes)
        :namespace (admission-namespace attributes) :name (admission-name attributes)))

;;; Type checking, as upstream's policy status reports it

(defun admission-policy-schema-name (group version kind)
  "Name the pinned definition of a built-in kind."
  (format nil "io.k8s.api.~A.~A.~A"
          (if (plusp (length group)) (subseq group 0 (or (position #\. group) (length group))) "core")
          version kind))

(defun admission-policy-built-in-type (group version resource)
  "Return the static type and GVK text of a built-in RESOURCE, or NIL."
  (let* ((api-version (if (plusp (length group)) (format nil "~A/~A" group version) version))
         (entry (if (equal resource "pods")
                    '("pods" "Pod" "v1" t)
                    (find-if (lambda (candidate)
                               (and (equal resource (first candidate)) (equal api-version (third candidate))))
                             *stored-resource-types*))))
    (when entry
      (let ((schema (gethash (admission-policy-schema-name group version (second entry))
                             (gethash "definitions" *podtemplate-schema*))))
        (when schema
          (values (cel-schema-type schema)
                  (format nil "~A, Kind=~A" api-version (second entry))))))))

(defun admission-policy-custom-type (store group version resource)
  "Return the static type and GVK text of a custom RESOURCE established in STORE, or NIL."
  (let ((definition
          (loop for key being the hash-keys of (pod-store-resources store) using (hash-value candidate)
                when (and (equal "customresourcedefinitions" (first key))
                          (equal group (gethash "group" (gethash "spec" candidate)))
                          (equal resource (gethash "plural" (gethash "names" (gethash "spec" candidate)))))
                  return candidate)))
    (when definition
      (let ((entry (crd-version definition version)))
        (when entry
          (values (cel-custom-object-type (crd-schema entry))
                  (format nil "~A/~A, Kind=~A" group version (gethash "kind" (gethash "names" (gethash "spec" definition))))))))))

(defun cel-custom-object-type (schema)
  "Type a custom object for a policy: its schema plus type fields and untyped metadata."
  (list :object
        (lambda (field)
          (cond ((member field '("apiVersion" "kind") :test #'equal) '(:string nil))
                ((equal field "metadata") :dyn)
                (t (let ((child (cel-escape-field-candidates schema field)))
                     (and child (cel-schema-type child))))))))

(defun admission-policy-object-types (store policy)
  "List (gvk-text . type) for every exact resource POLICY's rules name; wildcards stay untyped."
  (let ((types nil) (rules (gethash "resourceRules" (gethash "matchConstraints" (gethash "spec" policy) (core-object)))))
    (loop for rule across (if (crd-array-p rules) rules #())
          do (loop for group across (gethash "apiGroups" rule #())
                   do (loop for version across (gethash "apiVersions" rule #())
                            do (loop for resource across (gethash "resources" rule #())
                                     do (unless (or (equal group "*") (equal version "*") (find #\* resource) (find #\/ resource))
                                          (multiple-value-bind (type text)
                                              (admission-policy-built-in-type group version resource)
                                            (unless type
                                              (multiple-value-setq (type text)
                                                (admission-policy-custom-type store group version resource)))
                                            (when type (pushnew (cons text type) types :key #'car :test #'equal))))))))
    (nreverse types)))

(defun admission-policy-parameter-type (store policy)
  "Type POLICY's params from its paramKind when that names a known kind."
  (let ((kind (gethash "paramKind" (gethash "spec" policy))))
    (or (when (hash-table-p kind)
          (let* ((api-version (gethash "apiVersion" kind))
                 (slash (and (stringp api-version) (position #\/ api-version)))
                 (group (if slash (subseq api-version 0 slash) ""))
                 (version (if slash (subseq api-version (1+ slash)) api-version))
                 (schema (and (stringp version) (stringp (gethash "kind" kind))
                              (gethash (admission-policy-schema-name group version (gethash "kind" kind))
                                       (gethash "definitions" *podtemplate-schema*)))))
            (and schema (cel-schema-type schema))))
        :dyn)))

(defun admission-policy-check-expression (store policy expression text object-type parameter-type)
  "Check EXPRESSION for one object type, returning its warning text or NIL."
  (declare (ignore store))
  (let* ((variable-types (make-hash-table :test #'equal))
         (*cel-declared-variables* +admission-policy-variables+)
         (*cel-variable-types*
           (list (cons "object" object-type) (cons "oldObject" object-type)
                 (cons "params" parameter-type)
                 (cons "authorizer" '(:opaque :authorizer))
                 (cons "variables" (list :object (lambda (field) (gethash field variable-types)))))))
    (loop for variable across (let ((value (gethash "variables" (gethash "spec" policy))))
                                (if (member value '(nil null)) #() value))
          do (setf (gethash (gethash "name" variable) variable-types)
                   (handler-case (nth-value 1 (compile-cel-expression (gethash "expression" variable)))
                     (cel-compile-error () :dyn))))
    (handler-case (progn (compile-cel-expression expression) nil)
      (cel-compile-error (condition)
        (format nil "~@[~A: ~]~A" text (cel-error-message condition))))))

(defun admission-policy-type-warnings (store policy)
  "Type check POLICY's validations against the kinds its rules name, as ExpressionWarnings."
  (let* ((types (or (admission-policy-object-types store policy) (list (cons nil :dyn))))
         (parameter-type (admission-policy-parameter-type store policy))
         (warnings nil))
    (flet ((check (expression field)
             (let ((problems (remove nil (mapcar (lambda (entry)
                                                   (admission-policy-check-expression store policy expression (car entry) (cdr entry) parameter-type))
                                                 types))))
               (when problems
                 (push (core-object "fieldRef" field "warning" (format nil "~{~A~^~%~}" problems)) warnings)))))
      (loop for validation across (let ((value (gethash "validations" (gethash "spec" policy))))
                                    (if (member value '(nil null)) #() value))
            for index from 0
            do (when (stringp (gethash "expression" validation))
                 (check (gethash "expression" validation) (format nil "spec.validations[~D].expression" index)))
               (let ((message (gethash "messageExpression" validation)))
                 (when (and (stringp message) (plusp (length message)))
                   (check message (format nil "spec.validations[~D].messageExpression" index))))))
    (coerce (nreverse warnings) 'vector)))

(defun admission-policy-status-after-check (store policy)
  "Return POLICY's status with the current generation's type check recorded."
  (let* ((status (let ((value (gethash "status" policy))) (if (hash-table-p value) (copy-core-object value) (core-object))))
         (warnings (admission-policy-type-warnings store policy))
         (checking (core-object)))
    (when (plusp (length warnings)) (setf (gethash "expressionWarnings" checking) warnings))
    (setf (gethash "typeChecking" status) checking
          (gethash "observedGeneration" status) (gethash "generation" (gethash "metadata" policy)))
    status))
