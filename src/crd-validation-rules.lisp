;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Admit and enforce x-kubernetes-validations. A definition's rules are typed
;;;; against its schema and refused when they do not compile or their estimated cost
;;;; is too high; each write runs them with self and oldSelf under the per-rule and
;;;; per-request cost limits, correlating old values through maps and map lists.

(in-package #:gr8s)

(defparameter +crd-rule-cost-limit+ 10000000 "Upstream's StaticEstimatedCostLimit, per rule.")
(defparameter +crd-total-rule-cost-limit+ 100000000 "Upstream's StaticEstimatedCRDCostLimit, per definition.")
(defparameter +crd-runtime-cost-budget+ 10000000 "Upstream's RuntimeCELCostBudget, per request.")
(defparameter +crd-maximum-request-bytes+ (* 3 1024 1024) "Upstream's MaxRequestSizeBytes.")
(defparameter +crd-supported-rule-reasons+
  '("FieldValueInvalid" "FieldValueForbidden" "FieldValueRequired" "FieldValueDuplicate"))

;;; Types from schemas

(defun cel-schema-min-size (schema)
  "Return the fewest JSON bytes a value of SCHEMA serializes to, after apiserver's estimators."
  (let ((type (gethash "type" schema)))
    (cond
      ((gethash "x-kubernetes-int-or-string" schema) 2)
      ((equal type "array")
       (let ((items (gethash "items" schema)))
         (if (and (hash-table-p items) (typep (gethash "minItems" schema) '(integer 1 *)))
             (+ 2 (* (gethash "minItems" schema) (1+ (cel-schema-min-size items))))
             2)))
      ((equal type "object")
       (let ((properties (gethash "properties" schema)) (total 2))
         (when (hash-table-p properties)
           (loop for name across (gethash "required" schema #())
                 for child = (gethash name properties)
                 do (when (and child (not (nth-value 1 (gethash "default" child))))
                      (incf total (+ (length name) 4 (cel-schema-min-size child))))))
         total))
      ((equal type "string")
       (let ((format (gethash "format" schema)))
         (cond ((equal format "duration") 3)
               ((equal format "date") 12)
               ((equal format "date-time") 21)
               ((typep (gethash "minLength" schema) '(integer 1 *)) (+ 2 (gethash "minLength" schema)))
               (t 2))))
      ((equal type "boolean") 4)
      (t 1))))

(defun cel-schema-string-bound (schema)
  "Return the most characters a string of SCHEMA can have."
  (let ((format (gethash "format" schema)) (maximum (gethash "maxLength" schema)) (enum (gethash "enum" schema)))
    (cond ((typep maximum '(integer 0 *))
           ;; Base64 holds three bytes in four characters.
           maximum)
          ((equal format "duration") 32)
          ((equal format "date") 12)
          ((equal format "date-time") 32)
          ((and (crd-array-p enum) (plusp (length enum)) (every #'stringp enum))
           (reduce #'max (map 'list #'length enum)))
          (t (- +crd-maximum-request-bytes+ 2)))))

(defun cel-schema-items-bound (schema)
  "Return the most elements an array of SCHEMA can have."
  (let ((maximum (gethash "maxItems" schema)))
    (if (typep maximum '(integer 0 *))
        maximum
        (floor (- +crd-maximum-request-bytes+ 2) (1+ (cel-schema-min-size (gethash "items" schema)))))))

(defun cel-schema-properties-bound (schema value-schema)
  "Return the most entries a map of SCHEMA can have."
  (let ((maximum (gethash "maxProperties" schema)))
    (if (typep maximum '(integer 0 *))
        maximum
        (floor (- +crd-maximum-request-bytes+ 2) (+ 6 (cel-schema-min-size value-schema))))))

(defun cel-escape-field-candidates (schema name)
  "Find the property of SCHEMA a CEL field NAME refers to, spelled directly or escaped."
  (let ((properties (gethash "properties" schema)))
    (when (hash-table-p properties)
      (or (gethash name properties)
          (and (search "__" name) (gethash (cel-unescape-field name) properties))))))

(defun cel-schema-object-type (schema root)
  "Build the object type of SCHEMA, with a resource root's type and object metadata."
  (list :object
        (lambda (field)
          (cond
            ((and root (member field '("apiVersion" "kind") :test #'equal)) '(:string nil))
            ((and root (equal field "metadata"))
             (list :object
                   (lambda (metadata-field)
                     (and (member metadata-field '("name" "generateName") :test #'equal)
                          (list :string 253)))))
            (t (let ((child (cel-escape-field-candidates schema field)))
                 (and child (cel-schema-type child))))))))

(defun cel-schema-type (schema &optional root)
  "Translate a structural SCHEMA into a CEL type carrying its size bounds."
  (let ((type (gethash "type" schema)))
    (cond
      ((gethash "x-kubernetes-int-or-string" schema) :dyn)
      ((and (gethash "x-kubernetes-preserve-unknown-fields" schema)
            (not (gethash "x-kubernetes-embedded-resource" schema))
            (not (hash-table-p (gethash "properties" schema))))
       :dyn)
      ((equal type "object")
       (let ((additional (gethash "additionalProperties" schema)))
         (if (hash-table-p additional)
             (list :map '(:string 253) (cel-schema-type additional) (cel-schema-properties-bound schema additional))
             (cel-schema-object-type schema (or root (gethash "x-kubernetes-embedded-resource" schema))))))
      ((equal type "array")
       (list :list (cel-schema-type (gethash "items" schema)) (cel-schema-items-bound schema)))
      ((equal type "string")
       (let ((format (gethash "format" schema)))
         (cond ((equal format "byte") (list :bytes (cel-schema-string-bound schema)))
               ((equal format "duration") :duration)
               ((member format '("date" "date-time") :test #'equal) :timestamp)
               (t (list :string (cel-schema-string-bound schema))))))
      ((equal type "boolean") :bool)
      ((equal type "integer") :int)
      ((equal type "number") :double)
      (t :dyn))))

;;; Admission of rules

(defun crd-compile-rule-expression (expression schema root optional-old-self)
  "Compile EXPRESSION against SCHEMA, returning its program, result type and estimated cost."
  (let* ((self (cel-schema-type schema root))
         (*cel-node-types* (make-hash-table :test #'eq))
         (*cel-declared-variables* '("self" "oldSelf"))
         (*cel-variable-types* (list (cons "self" self)
                                     (cons "oldSelf" (if optional-old-self (list :optional self) self)))))
    (multiple-value-bind (program type) (compile-cel-expression expression)
      (values program type (cel-estimated-cost program)))))

(defun crd-cost-error-message (name cost limit)
  "Phrase an estimated cost over LIMIT as upstream's getCostErrorMessage does."
  (let ((factor (/ cost limit)))
    (format nil "~A exceeds budget by factor of ~A (try simplifying the rule, or adding maxItems, maxProperties, and maxLength where arrays, maps, and strings are declared)"
            name
            (if (> factor 100) "more than 100x" (format nil "~,1Fx" (coerce factor 'double-float))))))

(defun crd-rule-field-path-valid-p (schema path)
  "Test whether PATH names a field of SCHEMA, by the simple .a.b['c'] forms fieldPath allows."
  (let ((node schema) (position 0) (size (length path)))
    (loop while (< position size)
          do (multiple-value-bind (name next)
                 (cond
                   ((char= #\. (char path position))
                    (let ((end (or (position-if (lambda (character) (find character ".[")) path :start (1+ position)) size)))
                      (values (subseq path (1+ position) end) end)))
                   ((and (char= #\[ (char path position)) (< (1+ position) size) (char= #\' (char path (1+ position))))
                    (let ((end (search "']" path :start2 (+ position 2))))
                      (unless end (return-from crd-rule-field-path-valid-p nil))
                      (values (subseq path (+ position 2) end) (+ end 2))))
                   (t (return-from crd-rule-field-path-valid-p nil)))
               (when (zerop (length name)) (return-from crd-rule-field-path-valid-p nil))
               (let ((properties (gethash "properties" node)) (additional (gethash "additionalProperties" node)))
                 (setf node (cond ((and (hash-table-p properties) (gethash name properties)))
                                  ((hash-table-p additional) additional)
                                  (t (return-from crd-rule-field-path-valid-p nil)))))
               (setf position next)))
    t))

(defun crd-check-rule-fields (rule path schema)
  "Refuse a rule with empty or malformed text fields, before compiling it."
  (require-object rule path)
  (admission-drop-nulls rule)
  (reject-unsupported-fields rule '("rule" "message" "messageExpression" "reason" "fieldPath" "optionalOldSelf") "validation rule")
  (let ((text (gethash "rule" rule)) (message (gethash "message" rule)) (expression (gethash "messageExpression" rule))
        (reason (gethash "reason" rule)) (field-path (gethash "fieldPath" rule)))
    (flet ((blank (value) (zerop (length (string-trim '(#\Space #\Tab #\Newline #\Return) value))))
           (line-breaks (value) (or (find #\Newline value) (find #\Return value))))
      (unless (and (stringp text) (not (blank text)))
        (crd-schema-error (format nil "~A.rule" path) "Required value: rule is not specified"))
      (when message
        (unless (stringp message) (crd-schema-error (format nil "~A.message" path) "must be a string"))
        (when (blank message) (crd-schema-error (format nil "~A.message" path) "must be non-empty if specified"))
        (when (line-breaks (string-trim '(#\Space #\Tab #\Newline #\Return) message))
          (crd-schema-error (format nil "~A.message" path) "must not contain line breaks")))
      (when (and (line-breaks (string-trim '(#\Space #\Tab #\Newline #\Return) text)) (not message))
        (crd-schema-error (format nil "~A.message" path) "Required value: message must be specified if rule contains line breaks"))
      (when (and expression (or (not (stringp expression)) (blank expression)))
        (crd-schema-error (format nil "~A.messageExpression" path) "must be non-empty if specified"))
      (when (and reason (not (member reason +crd-supported-rule-reasons+ :test #'equal)))
        (crd-schema-error (format nil "~A.reason" path) "Unsupported value: ~S" reason))
      (when field-path
        (unless (and (stringp field-path) (not (blank field-path))) (crd-schema-error (format nil "~A.fieldPath" path) "must be non-empty if specified"))
        (when (line-breaks field-path) (crd-schema-error (format nil "~A.fieldPath" path) "must not contain line breaks"))
        (unless (crd-rule-field-path-valid-p schema field-path)
          (crd-schema-error (format nil "~A.fieldPath" path) "must be a valid path"))))))

(defun crd-check-rules-at (schema path root cardinality uncorrelatable total)
  "Compile and cost the rules directly on SCHEMA, adding their cost to the cell TOTAL."
  (let ((rules (gethash "x-kubernetes-validations" schema)))
    (unless (or (null rules) (crd-array-p rules))
      (crd-schema-error path "x-kubernetes-validations must be an array"))
    (loop for rule across (or rules #())
          for index from 0
          for rule-path = (format nil "~A.x-kubernetes-validations[~D]" path index)
          do (crd-check-rule-fields rule rule-path schema)
             (let* ((optional (eq t (gethash "optionalOldSelf" rule)))
                    (text (gethash "rule" rule)))
               (multiple-value-bind (program type cost)
                   (handler-case (crd-compile-rule-expression text schema root optional)
                     (cel-compile-error (condition)
                       (crd-schema-error (format nil "~A.rule" rule-path) "Invalid value: ~S: compilation failed: ~A"
                                         text (cel-error-message condition))))
                 (unless (eq :bool (cel-type-head type))
                   (crd-schema-error (format nil "~A.rule" rule-path) "Invalid value: ~S: cel expression must evaluate to a bool" text))
                 (let ((scaled (* cost cardinality)))
                   (when (> scaled +crd-rule-cost-limit+)
                     (crd-schema-error (format nil "~A.rule" rule-path) "Forbidden: ~A"
                                       (crd-cost-error-message "estimated rule cost" scaled +crd-rule-cost-limit+)))
                   (incf (car total) scaled))
                 (if (cel-references-variable-p program "oldSelf")
                     (when uncorrelatable
                       (crd-schema-error (format nil "~A.rule" rule-path)
                                         "Invalid value: ~S: oldSelf cannot be used on the uncorrelatable portion of the schema within ~A"
                                         text uncorrelatable))
                     (when (nth-value 1 (gethash "optionalOldSelf" rule))
                       (crd-schema-error (format nil "~A.optionalOldSelf" rule-path) "may not be set if oldSelf is not used in rule"))))
               (when (gethash "messageExpression" rule)
                 (multiple-value-bind (program type cost)
                     (handler-case (crd-compile-rule-expression (gethash "messageExpression" rule) schema root optional)
                       (cel-compile-error (condition)
                         (crd-schema-error (format nil "~A.messageExpression" rule-path) "messageExpression compilation failed: ~A"
                                           (cel-error-message condition))))
                   (declare (ignore program))
                   (unless (eq :string (cel-type-head type))
                     (crd-schema-error (format nil "~A.messageExpression" rule-path) "messageExpression must evaluate to a string"))
                   (when (> cost +crd-rule-cost-limit+)
                     (crd-schema-error (format nil "~A.messageExpression" rule-path) "Forbidden: ~A"
                                       (crd-cost-error-message "estimated messageExpression cost" cost +crd-rule-cost-limit+)))
                   (incf (car total) (* cost cardinality))))))))

(defun crd-check-schema-rules (schema &optional (path "openAPIV3Schema") root (cardinality 1) uncorrelatable (total (list 0)))
  "Admit the rules throughout SCHEMA, refusing the definition when they overrun the total budget."
  (crd-check-rules-at schema path root cardinality uncorrelatable total)
  (loop for branch across (gethash "allOf" schema #())
        do (let ((merged (copy-core-object schema)))
             (remhash "allOf" merged)
             (setf (gethash "x-kubernetes-validations" merged) (gethash "x-kubernetes-validations" branch #()))
             (crd-check-rules-at merged path root cardinality uncorrelatable total)))
  (let ((properties (gethash "properties" schema)) (additional (gethash "additionalProperties" schema))
        (items (gethash "items" schema)))
    (when (hash-table-p properties)
      (maphash (lambda (name child)
                 (crd-check-schema-rules child (format nil "~A.properties[~A]" path name) nil cardinality uncorrelatable total))
               properties))
    (when (hash-table-p additional)
      (crd-check-schema-rules additional (concatenate 'string path ".additionalProperties") nil
                              (* cardinality (cel-schema-properties-bound schema additional)) uncorrelatable total))
    (when (hash-table-p items)
      (crd-check-schema-rules items (concatenate 'string path ".items") nil
                              (* cardinality (cel-schema-items-bound schema))
                              (or uncorrelatable
                                  (and (not (equal "map" (gethash "x-kubernetes-list-type" schema)))
                                       path))
                              total)))
  (when (and (equal path "openAPIV3Schema") (> (car total) +crd-total-rule-cost-limit+))
    (crd-schema-error path "Forbidden: ~A"
                      (crd-cost-error-message "x-kubernetes-validations estimated rule cost total for entire OpenAPIv3 schema"
                                              (car total) +crd-total-rule-cost-limit+))))

;;; Enforcement

(defvar *crd-rule-programs* (make-hash-table :test #'equal :synchronized t)
  "Parsed rule text, which admission has already type checked.")

(defun crd-rule-program (expression)
  "Parse rule EXPRESSION once, remembering the program for later writes."
  (or (gethash expression *crd-rule-programs*)
      (let ((parser (make-cel-parser (cel-tokenize expression))))
        (when (> (hash-table-count *crd-rule-programs*) 8192) (clrhash *crd-rule-programs*))
        (setf (gethash expression *crd-rule-programs*) (cel-parse-expression parser)))))

(defun crd-schema-needs-values-p (schema)
  "Test whether JSON values of SCHEMA read differently in CEL: numbers and formatted strings."
  (let ((type (gethash "type" schema)))
    (or (equal type "number")
        (and (equal type "string") (member (gethash "format" schema) '("byte" "duration" "date" "date-time") :test #'equal))
        (let ((properties (gethash "properties" schema)))
          (and (hash-table-p properties)
               (loop for child being the hash-values of properties thereis (crd-schema-needs-values-p child))))
        (let ((additional (gethash "additionalProperties" schema)))
          (and (hash-table-p additional) (crd-schema-needs-values-p additional)))
        (let ((items (gethash "items" schema)))
          (and (hash-table-p items) (crd-schema-needs-values-p items))))))

(defun crd-cel-value (value schema)
  "Convert the JSON VALUE of SCHEMA to what CEL sees: doubles, timestamps, durations and bytes."
  (cond
    ((eq value 'null) value)
    ((not (crd-schema-needs-values-p schema)) value)
    ((hash-table-p value)
     (let ((copy (make-hash-table :test #'equal))
           (properties (gethash "properties" schema))
           (additional (gethash "additionalProperties" schema)))
       (maphash (lambda (key child)
                  (let ((child-schema (or (and (hash-table-p properties) (gethash key properties))
                                          (and (hash-table-p additional) additional))))
                    (setf (gethash key copy) (if child-schema (crd-cel-value child child-schema) child))))
                value)
       copy))
    ((crd-array-p value)
     (let ((items (gethash "items" schema)))
       (if (hash-table-p items)
           (map 'vector (lambda (child) (crd-cel-value child items)) value)
           value)))
    ((and (realp value) (equal "number" (gethash "type" schema))) (coerce value 'double-float))
    ((stringp value)
     (let ((format (gethash "format" schema)))
       (handler-case
           (cond ((equal format "byte") (coerce (ag-grpc:base64-decode value) '(vector (unsigned-byte 8))))
                 ((equal format "duration") (make-cel-duration :nanos (or (cel-parse-duration value) 0)))
                 ((equal format "date-time") (make-cel-timestamp :nanos (or (cel-parse-rfc3339 value) 0)))
                 ((equal format "date")
                  (make-cel-timestamp :nanos (or (cel-parse-rfc3339 (concatenate 'string value "T00:00:00Z")) 0)))
                 (t value))
         (error () value))))
    (t value)))

(defvar *crd-rule-errors* nil "Failures collected by the current validation walk, newest first.")
(defvar *crd-rule-budget* 0 "Cost left for the current request's validation rules.")

(define-condition crd-rules-stopped (condition) ()
  (:documentation "No further validation rules run, after the budget or a rule's call limit ran out."))

(defun crd-rule-error-text (path type-name reason message)
  "Spell one failure as upstream's field.Error does."
  (cond ((equal reason "FieldValueRequired") (format nil "~A: Required value: ~A" path message))
        ((equal reason "FieldValueForbidden") (format nil "~A: Forbidden: ~A" path message))
        ((equal reason "FieldValueDuplicate") (format nil "~A: Duplicate value: ~A" path message))
        (t (format nil "~A: Invalid value: ~S: ~A" path type-name message))))

(defun crd-rule-charged (function)
  "Run the program FUNCTION within the request budget and per-call limit, charging what it used."
  (let* ((limit (min *crd-rule-budget* +cel-evaluation-budget+))
         (*cel-remaining-steps* limit))
    (unwind-protect (funcall function)
      (decf *crd-rule-budget* (- limit (max 0 *cel-remaining-steps*))))))

(defun crd-rule-message (rule bindings)
  "Choose a failure's message: an evaluated messageExpression, then message, then the rule."
  (let ((expression (gethash "messageExpression" rule)))
    (or (and expression
             (handler-case
                 (let ((value (crd-rule-charged (lambda () (cel-evaluate (crd-rule-program expression) bindings)))))
                   (and (stringp value)
                        (plusp (length (string-trim '(#\Space #\Tab #\Newline) value)))
                        (not (find #\Newline value))
                        value))
               (cel-evaluation-error () nil)))
        (gethash "message" rule)
        (format nil "failed rule: ~A" (gethash "rule" rule)))))

(defun crd-run-rule (rule schema value old has-old path ratchet)
  "Run one rule on VALUE, recording any failure."
  (let* ((text (gethash "rule" rule))
         (program (crd-rule-program text))
         (uses-old (cel-references-variable-p program "oldSelf"))
         (optional (eq t (gethash "optionalOldSelf" rule)))
         (type-name (or (gethash "type" schema) "object")))
    ;; A transition rule has nothing to compare on create, unless it opted into an optional oldSelf.
    (when (or (not uses-old) has-old optional)
      (let* ((self (crd-cel-value value schema))
             (old-value (and has-old (crd-cel-value old schema)))
             (bindings (list (cons "self" self)
                             (cons "oldSelf" (if optional
                                                 (make-cel-optional :value old-value :present has-old)
                                                 old-value)))))
        (flet ((note (message reason)
                 (unless (and ratchet (not uses-old))
                   (push (crd-rule-error-text (crd-rule-failure-path path rule) type-name reason message)
                         *crd-rule-errors*))))
          (when (<= *crd-rule-budget* 0)
            (push (crd-rule-error-text path type-name nil
                                       "validation failed due to running out of cost budget, no further validation rules will be run")
                  *crd-rule-errors*)
            (signal 'crd-rules-stopped))
          (handler-case
              (let ((result (crd-rule-charged (lambda () (cel-evaluate program bindings)))))
                (unless (eq t result)
                  (if (null result)
                      (note (crd-rule-message rule bindings) (gethash "reason" rule))
                      (note (format nil "rule did not evaluate to bool: ~A" text) nil))))
            (cel-cost-exceeded (condition)
              (if (<= *crd-rule-budget* 0)
                  (push (crd-rule-error-text path type-name nil
                                             "validation failed due to running out of cost budget, no further validation rules will be run")
                        *crd-rule-errors*)
                  (push (crd-rule-error-text path type-name nil
                                             (format nil "'~A': no further validation rules will be run due to call cost exceeds limit for rule: ~A"
                                                     (cel-error-message condition) text))
                        *crd-rule-errors*))
              (signal 'crd-rules-stopped))
            (cel-evaluation-error (condition)
              (note (format nil "~A evaluating rule: ~A" (cel-error-message condition) text) nil))))))))

(defun crd-rule-failure-path (path rule)
  "Add a rule's fieldPath to the path of its failure."
  (let ((field-path (gethash "fieldPath" rule)))
    (if field-path (concatenate 'string path field-path) path)))

(defun crd-walk-rules (schema value old has-old path)
  "Run the rules on VALUE and everything below it, correlating OLD when HAS-OLD."
  (when (and (eq value 'null)) (return-from crd-walk-rules nil))
  (let ((ratchet (and has-old (crd-json-equal-p value old))))
    (loop for rule across (gethash "x-kubernetes-validations" schema #())
          do (crd-run-rule rule schema value old has-old path ratchet))
    (loop for branch across (gethash "allOf" schema #())
          do (loop for rule across (gethash "x-kubernetes-validations" branch #())
                   do (crd-run-rule rule schema value old has-old path ratchet))))
  (cond
    ((hash-table-p value)
     (let ((properties (gethash "properties" schema))
           (additional (gethash "additionalProperties" schema)))
       (maphash
        (lambda (key child)
          (let ((child-schema (or (and (hash-table-p properties) (gethash key properties))
                                  (and (hash-table-p additional) additional))))
            (when (and child-schema (crd-schema-has-rules-p child-schema))
              (multiple-value-bind (old-child present)
                  (if (and has-old (hash-table-p old)) (gethash key old) (values nil nil))
                (crd-walk-rules child-schema child old-child (and present t)
                                (if (hash-table-p additional)
                                    (format nil "~A[~A]" path key)
                                    (format nil "~A.~A" path key)))))))
        value)))
    ((crd-array-p value)
     (let ((items (gethash "items" schema)))
       (when (and (hash-table-p items) (crd-schema-has-rules-p items))
         (let ((keys (and (equal "map" (gethash "x-kubernetes-list-type" schema))
                          (coerce (gethash "x-kubernetes-list-map-keys" schema #()) 'list))))
           (loop for child across value
                 for index from 0
                 do (let ((old-child (and keys has-old (and (crd-array-p old) (crd-map-list-entry old keys child)))))
                      (crd-walk-rules items child old-child (and old-child t) (format nil "~A[~D]" path index))))))))))

(defun crd-schema-has-rules-p (schema)
  "Test whether SCHEMA or anything below it carries validation rules."
  (or (plusp (length (gethash "x-kubernetes-validations" schema #())))
      (some (lambda (branch) (plusp (length (gethash "x-kubernetes-validations" branch #()))))
            (gethash "allOf" schema #()))
      (let ((properties (gethash "properties" schema)))
        (and (hash-table-p properties)
             (loop for child being the hash-values of properties thereis (crd-schema-has-rules-p child))))
      (let ((additional (gethash "additionalProperties" schema)))
        (and (hash-table-p additional) (crd-schema-has-rules-p additional)))
      (let ((items (gethash "items" schema)))
        (and (hash-table-p items) (crd-schema-has-rules-p items)))))

(defun crd-enforce-validation-rules (schema object old kind name)
  "Run SCHEMA's rules on OBJECT against OLD, or NIL on create, refusing the write on any failure."
  (when (crd-schema-has-rules-p schema)
    (let ((*crd-rule-errors* nil) (*crd-rule-budget* +crd-runtime-cost-budget+))
      (handler-case (crd-walk-rules schema object old (and old t) "")
        (crd-rules-stopped () nil))
      (when *crd-rule-errors*
        (core-resource-error
         422 "Invalid" "~A ~S is invalid: ~{~A~^, ~}"
         kind (or name "")
         (mapcar (lambda (text) (string-left-trim ": " text)) (reverse *crd-rule-errors*)))))))
