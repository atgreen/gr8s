(in-package #:gr8s/tests)
(def-suite openapi :in gr8s)
(in-suite openapi)

;;; kubectl validates a List's items on the client against /openapi/v2 (kube-openapi's
;;; pkg/util/proto/validation), and explains kinds from /openapi/v3. These tests check what
;;; gr8s serves against the Kubernetes v1.37.2 schemas and validate a real manifest of every
;;; built-in kind as kubectl does. scripts/test-kubectl-validation.py runs real kubectl.

(defun openapi-fixture-manifests ()
  "The real manifests, one per built-in kind, that kubectl must accept."
  (coerce (gethash "items" (com.inuoe.jzon:parse
                            (asdf:system-relative-pathname :gr8s "tests/fixtures/builtin-manifests.json")))
          'list))

(defun json-equal (a b)
  "Compare parsed JSON values regardless of object key order."
  (cond ((and (hash-table-p a) (hash-table-p b))
         (and (= (hash-table-count a) (hash-table-count b))
              (loop for key being the hash-keys of a using (hash-value value)
                    always (multiple-value-bind (other found) (gethash key b)
                             (and found (json-equal value other))))))
        ((and (vectorp a) (vectorp b) (not (stringp a)) (not (stringp b)))
         (and (= (length a) (length b)) (every #'json-equal a b)))
        (t (equal a b))))

(defun openapi-reference-name (reference)
  (car (last (uiop:split-string reference :separator '(#\/)))))

(defun openapi-gvk-index (definitions)
  "Map group/version/kind -> the names of the definitions that declare it."
  (let ((index (make-hash-table :test #'equal)))
    (maphash (lambda (name schema)
               (loop for gvk across (gethash "x-kubernetes-group-version-kind" schema #())
                     do (push name (gethash (list (gethash "group" gvk) (gethash "version" gvk) (gethash "kind" gvk))
                                            index))))
             definitions)
    index))

(defun openapi-dangling-references (definitions)
  "Return every $ref in DEFINITIONS that names no definition."
  (let ((missing '()))
    (maphash (lambda (name schema)
               (declare (ignore name))
               (dolist (reference (gr8s.apiserver::openapi-schema-references schema))
                 (unless (gethash reference definitions) (pushnew reference missing :test #'equal))))
             definitions)
    missing))

(defun kubectl-validation-errors (definitions schema value path)
  "Validate VALUE against v2 SCHEMA as kube-openapi's proto validation does for kubectl:
fields a kind does not declare and missing required fields are errors, an integer or number
must be numeric, a boolean boolean, and a string accepts any scalar."
  (let ((reference (gethash "$ref" schema)))
    (when reference
      (return-from kubectl-validation-errors
        (kubectl-validation-errors definitions (gethash (openapi-reference-name reference) definitions) value path))))
  (let ((type (gethash "type" schema)) (properties (gethash "properties" schema))
        (additional (gethash "additionalProperties" schema)) (errors '()))
    (flet ((problem (control &rest arguments) (push (format nil "~A: ~?" path control arguments) errors)))
      (cond ((eq value 'null))
            ((hash-table-p properties)
             (if (not (hash-table-p value))
                 (problem "expected an object")
                 (progn
                   (loop for field across (gethash "required" schema #())
                         unless (nth-value 1 (gethash field value)) do (problem "missing required field ~S" field))
                   (maphash (lambda (field child)
                              (let ((declared (gethash field properties)))
                                (if declared
                                    (setf errors (append (kubectl-validation-errors definitions declared child
                                                                                    (format nil "~A.~A" path field))
                                                         errors))
                                    (problem "unknown field ~S" field))))
                            value))))
            ((hash-table-p additional)
             (if (hash-table-p value)
                 (maphash (lambda (key child)
                            (setf errors (append (kubectl-validation-errors definitions additional child
                                                                            (format nil "~A[~A]" path key))
                                                 errors)))
                          value)
                 (problem "expected a map")))
            ((equal type "array")
             (if (and (vectorp value) (not (stringp value)))
                 (loop for child across value for index from 0
                       do (setf errors (append (kubectl-validation-errors definitions (gethash "items" schema) child
                                                                          (format nil "~A[~D]" path index))
                                               errors)))
                 (problem "expected an array")))
            ((member type '("integer" "number") :test #'equal)
             (unless (realp value) (problem "expected ~A, got ~S" type value)))
            ((equal type "boolean")
             (unless (member value '(t nil)) (problem "expected boolean, got ~S" value)))
            ((equal type "string")
             (when (or (hash-table-p value) (and (vectorp value) (not (stringp value))))
               (problem "expected a string")))))
    errors))

(defun kubectl-validate-manifest (definitions index object)
  "Validate OBJECT as kubectl does: the definition its apiVersion and kind name, or nothing."
  (let* ((api-version (gethash "apiVersion" object)) (slash (position #\/ api-version))
         (key (list (if slash (subseq api-version 0 slash) "") (if slash (subseq api-version (1+ slash)) api-version)
                    (gethash "kind" object)))
         (names (gethash key index)))
    (values (and names (kubectl-validation-errors definitions (gethash (first names) definitions) object
                                                  (gethash "kind" object)))
            names)))

(test openapi-v2-validates-a-real-manifest-of-every-built-in-kind
  (with-core-api (store path)
    (values store path)
    (let* ((definitions (gethash "definitions" (check-core-status 200 "/openapi/v2")))
           (index (openapi-gvk-index definitions)))
      (is (null (openapi-dangling-references definitions)))
      (maphash (lambda (gvk names) (is (= 1 (length names)) "~A is declared by ~A" gvk names)) index)
      (dolist (manifest (openapi-fixture-manifests))
        (multiple-value-bind (errors names) (kubectl-validate-manifest definitions index manifest)
          (is (consp names) "no definition for ~A ~A" (gethash "apiVersion" manifest) (gethash "kind" manifest))
          (is (null errors) "~A" errors)))
      ;; The report that found this: a Pod's imagePullPolicy and readinessProbe inside a List.
      (let ((pod (find "Pod" (openapi-fixture-manifests) :test #'equal :key (lambda (item) (gethash "kind" item)))))
        (let ((container (aref (gethash "containers" (gethash "spec" pod)) 0)))
          (is (gethash "imagePullPolicy" container))
          (is (gethash "readinessProbe" container))
          ;; The validator is not vacuous: an undeclared field and a wrong type are errors.
          (setf (gethash "imagePullPolicyy" container) "Always"
                (gethash "terminationGracePeriodSeconds" (gethash "spec" pod)) "thirty")
          (let ((errors (kubectl-validate-manifest definitions index pod)))
            (is (find-if (lambda (error) (search "unknown field \"imagePullPolicyy\"" error)) errors))
            (is (find-if (lambda (error) (search "terminationGracePeriodSeconds: expected integer" error)) errors))))))))

(test openapi-v3-documents-publish-the-upstream-schemas-of-their-version
  (with-core-api (store path)
    (values store path)
    (let ((urls (gethash "paths" (check-core-status 200 "/openapi/v3")))
          (upstream (gethash "schemas" gr8s.apiserver::*upstream-openapi*)))
      (maphash
       (lambda (key names)
         (let ((url (gethash key urls)))
           (is (hash-table-p url) "/openapi/v3 does not list ~A" key)
           (when url
             (is (search gr8s.apiserver::+openapi-schema-hash+ (gethash "serverRelativeURL" url)))
             (let* ((schemas (gethash "schemas" (gethash "components" (check-core-status 200 (format nil "/openapi/v3/~A" key)))))
                    (index (openapi-gvk-index schemas)))
               (is (null (openapi-dangling-references schemas)) "~A has dangling references" key)
               (maphash (lambda (gvk names) (is (= 1 (length names)) "~A declares ~A as ~A" key gvk names)) index)
               (loop for name across names
                     for served = (gethash name schemas)
                     do (is (hash-table-p served) "~A does not publish ~A" key name)
                        (unless (member name gr8s.apiserver::+openapi-registered-everywhere+ :test #'equal)
                          (is (json-equal (gethash name upstream) served)
                              "~A publishes a different ~A" key name)))))))
       (gethash "documents" gr8s.apiserver::*upstream-openapi*))
      ;; Every manifest's kind is described in its version's document, as kubectl explain needs.
      (dolist (manifest (openapi-fixture-manifests))
        (let* ((api-version (gethash "apiVersion" manifest))
               (key (if (find #\/ api-version) (format nil "apis/~A" api-version) (format nil "api/~A" api-version)))
               (schemas (gethash "schemas" (gethash "components" (check-core-status 200 (format nil "/openapi/v3/~A" key)))))
               (group (if (find #\/ api-version) (subseq api-version 0 (position #\/ api-version)) ""))
               (version (subseq api-version (1+ (or (position #\/ api-version) -1)))))
          (is (gethash (list group version (gethash "kind" manifest)) (openapi-gvk-index schemas))
              "~A does not describe ~A" key (gethash "kind" manifest)))))))

(test openapi-v2-schemas-are-written-as-kube-openapi-writes-them
  (let ((schema (com.inuoe.jzon:parse "{\"type\":\"object\",\"properties\":{\"default\":{\"type\":\"string\"},
     \"probe\":{\"allOf\":[{\"$ref\":\"#/components/schemas/io.k8s.api.core.v1.Probe\"}],\"default\":{},\"description\":\"d\"},
     \"port\":{\"oneOf\":[{\"type\":\"integer\"},{\"type\":\"string\"}],\"x-kubernetes-int-or-string\":true},
     \"items\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/components/schemas/X\"}},
     \"map\":{\"type\":\"object\",\"additionalProperties\":{\"oneOf\":[{\"type\":\"string\"},{\"type\":\"number\"}]}}}}")))
    (is (json-equal
                (com.inuoe.jzon:parse "{\"type\":\"object\",\"properties\":{\"default\":{\"type\":\"string\"},
     \"probe\":{\"description\":\"d\",\"$ref\":\"#/definitions/io.k8s.api.core.v1.Probe\"},
     \"port\":{\"x-kubernetes-int-or-string\":true,\"type\":\"string\"},
     \"items\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/definitions/X\"}},
     \"map\":{\"type\":\"object\",\"additionalProperties\":{\"type\":\"string\"}}}}")
                (gr8s.apiserver::openapi-v2-schema schema)))))
