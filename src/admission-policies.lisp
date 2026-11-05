;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Enforce ValidatingAdmissionPolicy and MutatingAdmissionPolicy objects on the
;;;; admission path: select policy and binding pairs by their match rules, bind
;;;; parameters, compute variables, and evaluate CEL. A CEL failure follows the
;;;; policy's failurePolicy. Applied configurations merge objects and replace lists.

(in-package #:gr8s)

(defparameter +admission-policy-variables+
  '("object" "oldObject" "request" "params" "namespaceObject" "variables")
  "Variables the admission policy CEL environment declares. The authorizer is not available.")

(defun compile-admission-policy-condition (expression)
  "Compile a policy's condition. Variables are dynamically typed here, so a dyn result is checked when evaluated."
  (let ((*cel-declared-variables* +admission-policy-variables+))
    (multiple-value-bind (program type) (compile-cel-expression expression)
      (unless (member type '(:bool :dyn))
        (cel-check-error "must evaluate to bool, found ~(~A~)" type))
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
                         (cons "variables" variables))))
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
                 (let ((bindings (admission-policy-bindings store policy parameter attributes)))
                   (when (admission-policy-conditions-pass-p policy bindings)
                     (loop for validation across (let ((value (gethash "validations" (gethash "spec" policy))))
                                                   (if (member value '(nil null)) #() value))
                           unless (let ((*cel-declared-variables* +admission-policy-variables+))
                                    (evaluate-cel-condition (compile-admission-policy-condition (gethash "expression" validation)) bindings))
                             do (admission-apply-validation-failure policy binding validation bindings attributes))))
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
                   (let ((bindings (admission-policy-bindings store policy parameter attributes)))
                     (when (admission-policy-conditions-pass-p policy bindings)
                       (loop for mutation across (gethash "mutations" (gethash "spec" policy))
                             do (setf (admission-object attributes)
                                      (admission-mutation-result mutation bindings (admission-object attributes)))
                                ;; Later mutations read the object the earlier ones produced.
                                (setf (cdr (assoc "object" bindings :test #'equal)) (admission-object attributes)))))
                 ((or cel-compile-error cel-evaluation-error) (condition)
                   (admission-policy-failure policy binding attributes condition))
                 (kubernetes-error (condition)
                   (admission-policy-failure policy binding attributes (kubernetes-error-message condition))))))))
