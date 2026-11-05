;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify x-kubernetes-validations: compile and cost checks when a definition is
;;;; admitted, self and oldSelf at write time, runtime cost limits, ratcheting and
;;;; the CEL libraries rules use.

(in-package #:gr8s/tests)
(def-suite crd-validation-rules :in gr8s)
(in-suite crd-validation-rules)

(defun rule-schema (text)
  "Parse a JSON schema."
  (com.inuoe.jzon:parse text))

(defun rule-definition (schema-text &key (plural "rulers"))
  "Build a definition whose single version uses the JSON schema SCHEMA-TEXT."
  (gr8s::core-object
   "apiVersion" "apiextensions.k8s.io/v1" "kind" "CustomResourceDefinition"
   "metadata" (gr8s::core-object "name" (format nil "~A.rules.example.test" plural))
   "spec" (gr8s::core-object
           "group" "rules.example.test" "scope" "Namespaced"
           "names" (gr8s::core-object "plural" plural "kind" "Ruler")
           "versions" (vector (gr8s::core-object "name" "v1" "served" t "storage" t
                                                 "schema" (gr8s::core-object "openAPIV3Schema" (rule-schema schema-text)))))))

(defparameter +rule-spec-schema+
  "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-validations\":[
     {\"rule\":\"self.x + self.y > 0\"},
     {\"rule\":\"self.firstArray.isSorted() && self.secondArray.isSorted() && ((self.firstArray.sum() + self.secondArray.sum()) % 2 == 0)\"},
     {\"rule\":\"self.largeArray.all(x, self.largeArray.all(y, y == x))\"}],
     \"properties\":{\"x\":{\"type\":\"integer\"},\"y\":{\"type\":\"integer\"},
       \"firstArray\":{\"type\":\"array\",\"maxItems\":1000,\"items\":{\"type\":\"integer\"}},
       \"secondArray\":{\"type\":\"array\",\"maxItems\":1000,\"items\":{\"type\":\"integer\"}},
       \"largeArray\":{\"type\":\"array\",\"maxItems\":725,\"items\":{\"type\":\"integer\"}}}},
     \"status\":{\"type\":\"object\",\"x-kubernetes-validations\":[{\"rule\":\"self.health == 'ok' || self.health == 'unhealthy'\"}],
       \"properties\":{\"health\":{\"type\":\"string\"}}}}}")

(defun rule-object (name &rest fields)
  "Build a Ruler in namespace default with FIELDS at its top level."
  (let ((object (gr8s::core-object "apiVersion" "rules.example.test/v1" "kind" "Ruler"
                                   "metadata" (gr8s::core-object "name" name "namespace" "default"))))
    (loop for (key value) on fields by #'cddr do (setf (gethash key object) value))
    object))

(defparameter +rule-path+ "/apis/rules.example.test/v1/namespaces/default/rulers")
(defparameter +rule-crd-path+ "/apis/apiextensions.k8s.io/v1/customresourcedefinitions")

(defun rule-refused-message (expected schema-text)
  "Require the definition to be refused with EXPECTED in its message."
  (let ((status (check-core-status 422 +rule-crd-path+ :method :post :object (rule-definition schema-text))))
    (is (search expected (gethash "message" status)) "~A" (gethash "message" status))))

(defun rule-spec (&rest fields)
  "Build a spec object from FIELDS."
  (apply #'gr8s::core-object fields))

(test rules-are-compiled-when-a-definition-is-admitted
  (with-core-api (store path)
    (values store path)
    (rule-refused-message
     "undefined field 'z'"
     "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-validations\":[{\"rule\":\"self.z == 100\"}],\"properties\":{\"x\":{\"type\":\"integer\"}}}}}")
    (rule-refused-message
     "Syntax error"
     "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-validations\":[{\"rule\":\"self = 42\"}]}}}")
    (rule-refused-message
     "exceeds budget"
     "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"array\",\"items\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"x-kubernetes-validations\":[{\"rule\":\"self.all(s, s == 'string constant')\"}]}}}}}}")
    (rule-refused-message
     "must evaluate to a bool"
     "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-validations\":[{\"rule\":\"self.x\"}],\"properties\":{\"x\":{\"type\":\"integer\"}}}}}")
    (rule-refused-message
     "oldSelf cannot be used on the uncorrelatable"
     "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"x-kubernetes-validations\":[{\"rule\":\"self > oldSelf\"}]}}}}")
    (rule-refused-message
     "may not be set if oldSelf is not used"
     "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-validations\":[{\"rule\":\"self.x > 0\",\"optionalOldSelf\":true}],\"properties\":{\"x\":{\"type\":\"integer\"}}}}}")
    (rule-refused-message
     "messageExpression must evaluate to a string"
     "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-validations\":[{\"rule\":\"self.x > 0\",\"messageExpression\":\"self.x\"}],\"properties\":{\"x\":{\"type\":\"integer\"}}}}}")
    (rule-refused-message
     "Unsupported value"
     "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-validations\":[{\"rule\":\"self.x > 0\",\"reason\":\"Nope\"}],\"properties\":{\"x\":{\"type\":\"integer\"}}}}}")
    (rule-refused-message
     "must be a valid path"
     "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"x-kubernetes-validations\":[{\"rule\":\"self.x > 0\",\"fieldPath\":\".nope\"}],\"properties\":{\"x\":{\"type\":\"integer\"}}}}}")))

(test rules-run-with-their-costs-on-writes
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/api/v1/namespaces" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "default")))
    (check-core-status 201 +rule-crd-path+ :method :post :object (rule-definition +rule-spec-schema+))
    (check-core-status 201 +rule-path+ :method :post
      :object (rule-object "ok" "spec" (rule-spec "x" 1 "y" 0 "firstArray" #(3 4) "secondArray" #(5 10) "largeArray" #(2 2))))
    (let ((status (check-core-status 422 +rule-path+ :method :post
                    :object (rule-object "bad" "spec" (rule-spec "x" 0 "y" 0 "firstArray" #(1) "secondArray" #(1) "largeArray" #())))))
      (is (search "failed rule" (gethash "message" status)) "~A" (gethash "message" status)))
    ;; An absent field is an error that names the rule, not a pass.
    (let ((status (check-core-status 422 +rule-path+ :method :post :object (rule-object "missing" "spec" (rule-spec "y" 1)))))
      (is (search "no such key" (gethash "message" status)) "~A" (gethash "message" status)))
    (let ((status (check-core-status 422 +rule-path+ :method :post
                    :object (rule-object "costly" "spec" (rule-spec "largeArray" (make-array 725 :initial-element 20))))))
      (is (search "call cost exceeds limit" (gethash "message" status)) "~A" (gethash "message" status)))))

(defun rule-simple-definition (rule-json &optional (property "{\"type\":\"integer\"}"))
  "Establish a definition whose spec.num carries RULE-JSON."
  (let ((schema (format nil "{\"type\":\"object\",\"properties\":{\"spec\":{\"type\":\"object\",\"properties\":{\"num\":~A}}}}"
                        (format nil "{~A,\"x-kubernetes-validations\":[~A]}"
                                (subseq property 1 (1- (length property))) rule-json))))
    (check-core-status 201 "/api/v1/namespaces" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "default")))
    (check-core-status 201 +rule-crd-path+ :method :post :object (rule-definition schema))))

(test transition-rules-compare-with-the-old-object
  (with-core-api (store path)
    (values store path)
    (rule-simple-definition "{\"rule\":\"self > oldSelf\"}")
    (let ((created (check-core-status 201 +rule-path+ :method :post :object (rule-object "one" "spec" (rule-spec "num" 10)))))
      (let ((lower (gr8s::copy-core-object created)))
        (setf (gethash "num" (gethash "spec" lower)) 9)
        (let ((status (check-core-status 422 (concatenate 'string +rule-path+ "/one") :method :put :object lower)))
          (is (search "failed rule" (gethash "message" status)) "~A" (gethash "message" status))))
      (let ((higher (gr8s::copy-core-object created)))
        (setf (gethash "num" (gethash "spec" higher)) 11)
        (check-core-status 200 (concatenate 'string +rule-path+ "/one") :method :put :object higher)))))

(test rules-honor-message-fields-and-ratchet-unchanged-values
  (with-core-api (store path)
    (values store path)
    ;; Empty strings mean unset, which is how Go's protobuf encodes them.
    (rule-simple-definition
     "{\"rule\":\"self != 8\",\"message\":\"\",\"messageExpression\":\"\",\"fieldPath\":\"\"},{\"rule\":\"self < 5\",\"message\":\"too big\",\"reason\":\"FieldValueForbidden\"},{\"rule\":\"self != 7\",\"messageExpression\":\"'seven is ' + 'out'\"}")
    (let ((status (check-core-status 422 +rule-path+ :method :post :object (rule-object "one" "spec" (rule-spec "num" 6)))))
      (is (search "Forbidden: too big" (gethash "message" status)) "~A" (gethash "message" status)))
    (let ((status (check-core-status 422 +rule-path+ :method :post :object (rule-object "one" "spec" (rule-spec "num" 7)))))
      (is (search "seven is out" (gethash "message" status)) "~A" (gethash "message" status)))))

(defun rule-cel (expression &rest bindings)
  "Evaluate EXPRESSION with library functions enabled."
  (let ((gr8s::*cel-declared-variables* '("self")))
    (gr8s::evaluate-cel-value (gr8s::compile-cel-expression expression)
                              (loop for (name value) on bindings by #'cddr collect (cons name value)))))

(test cel-libraries-behave-as-kubernetes-documents
  ;; Strings
  (is (equal "b" (rule-cel "'abc'.charAt(1)")))
  (is (= 1 (rule-cel "'abcb'.indexOf('b')")))
  (is (= 3 (rule-cel "'abcb'.lastIndexOf('b')")))
  (is (equal "bc" (rule-cel "'abc'.substring(1)")))
  (is (equal "b" (rule-cel "'abc'.substring(1,2)")))
  (is (equal "aXc" (rule-cel "'abc'.replace('b','X')")))
  (is (equal "Xba" (rule-cel "'aba'.replace('a','X',1)")))
  (is (equalp #("a" "b,c") (rule-cel "'a,b,c'.split(',',2)")))
  (is (equal "a-b" (rule-cel "['a','b'].join('-')")))
  (is (equal "hi 1 true" (rule-cel "'hi %d %s'.format([dyn(1), dyn(true)])")))
  (is (eq t (rule-cel "'abc'.matches('^a.c$')")))
  (is (equal "12" (rule-cel "'a12b'.find('[0-9]+')")))
  (is (equalp #("1" "2") (rule-cel "'1a2'.findAll('[0-9]')")))
  ;; Lists
  (is (eq t (rule-cel "[1,2,3].isSorted()")))
  (is (= 6 (rule-cel "[1,2,3].sum()")))
  (is (= 1 (rule-cel "[3,1].min()")))
  (is (= 3 (rule-cel "[3,1].max()")))
  (is (= 1 (rule-cel "[3,1].indexOf(1)")))
  (is (equalp #(2 3) (rule-cel "[1,2,3].slice(1,3)")))
  (is (equalp #(1 2) (rule-cel "[1,2,1].distinct()")))
  (is (equalp #(1 2) (rule-cel "[2,1].sort()")))
  ;; Sets
  (is (eq t (rule-cel "sets.contains([1,2],[2])")))
  (is (eq t (rule-cel "sets.equivalent([1,2],[2,1])")))
  (is (eq t (rule-cel "sets.intersects([1,2],[2,3])")))
  ;; Uint, bytes, time
  (is (eq t (rule-cel "1u == 1")))
  (is (eq t (rule-cel "b'ab'.size() == 2")))
  (is (equal "ab" (rule-cel "string(b'ab')")))
  (is (eq t (rule-cel "timestamp('2024-01-02T03:04:05Z') < timestamp('2024-01-02T03:04:06Z')")))
  (is (= 2024 (rule-cel "timestamp('2024-01-02T03:04:05Z').getFullYear()")))
  (is (= 0 (rule-cel "timestamp('2024-01-02T03:04:05Z').getMonth()")))
  (is (= 2 (rule-cel "timestamp('2024-01-02T03:04:05Z').getDate()")))
  (is (equal "2024-01-02T03:04:06Z" (rule-cel "string(timestamp('2024-01-02T03:04:05Z') + duration('1s'))")))
  (is (= 5400 (rule-cel "duration('1h30m').getSeconds()")))
  ;; Two-variable comprehensions and optionals
  (is (eq t (rule-cel "[1,2].all(i, v, v == i + 1)")))
  (is (equalp #(0 2) (rule-cel "[1,2].transformList(i, v, i * v)")))
  (is (eq t (rule-cel "{'a': 1}.?a.hasValue()")))
  (is (= 7 (rule-cel "{'a': 1}.?b.orValue(7)")))
  (is (= 2 (rule-cel "optional.of(1).optMap(x, x + 1).value()")))
  (is (= 3 (rule-cel "cel.bind(x, 1, x + 2)")))
  ;; Quantity, URL, IP, CIDR, semver
  (is (eq t (rule-cel "quantity('1Gi').isGreaterThan(quantity('1M'))")))
  (is (= 1024 (rule-cel "quantity('1Ki').asInteger()")))
  (is (eq t (rule-cel "quantity('1').add(1).isLessThan(quantity('3'))")))
  (is (equal "https" (rule-cel "url('https://example.com:8/a?b=c').getScheme()")))
  (is (equal "8" (rule-cel "url('https://example.com:8/a').getPort()")))
  (is (eq t (rule-cel "isIP('1.2.3.4') && !isIP('1.2.3')")))
  (is (= 6 (rule-cel "ip('::1').family()")))
  (is (eq t (rule-cel "ip('::1').isLoopback()")))
  (is (eq t (rule-cel "cidr('10.0.0.0/8').containsIP('10.1.1.1')")))
  (is (eq t (rule-cel "cidr('10.0.0.0/8').containsCIDR('10.1.0.0/16')")))
  (is (= 8 (rule-cel "cidr('10.0.0.0/8').prefixLength()")))
  (is (eq t (rule-cel "semver('1.2.3').isGreaterThan(semver('1.2.3-rc1'))")))
  (is (= 1 (rule-cel "semver('v1', true).major()")))
  ;; Formats and JSON patch keys
  (is (eq t (rule-cel "!format.dns1123Label().validate('ok').hasValue()")))
  (is (eq t (rule-cel "format.dns1123Label().validate('NOT OK').hasValue()")))
  (is (equal "a~1b~0c" (rule-cel "jsonpatch.escapeKey('a/b~c')"))))

(test custom-resource-formats-and-patterns-are-enforced
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/api/v1/namespaces" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "default")))
    (check-core-status 201 +rule-crd-path+ :method :post
      :object (rule-definition
               "{\"type\":\"object\",\"properties\":{
                 \"ip\":{\"type\":\"string\",\"format\":\"ipv4\"},
                 \"uuid\":{\"type\":\"string\",\"format\":\"uuid\"},
                 \"odd\":{\"type\":\"string\",\"format\":\"not-a-registered-format\"},
                 \"word\":{\"type\":\"string\",\"pattern\":\"^\\\\p{Lu}[[:lower:]]+$\"}}}"))
    (flet ((attempt (expected name &rest fields)
             (check-core-status expected +rule-path+ :method :post :object (apply #'rule-object name fields))))
      (attempt 201 "one" "ip" "1.2.3.4" "uuid" "123e4567-e89b-12d3-a456-426614174000" "odd" "anything" "word" "Hello")
      (attempt 422 "two" "ip" "1.2.3")
      (attempt 422 "three" "uuid" "nope")
      (attempt 422 "four" "word" "hello"))
    (check-core-status 422 +rule-crd-path+ :method :post
      :object (rule-definition "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"pattern\":\"(?=x)\"}}}" :plural "others"))))

(test policies-report-type-checking-in-status
  (with-core-api (store path)
    (values store path)
    (flet ((policy (name &rest validations)
             (check-core-status 201 "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies" :method :post
               :object (gr8s::core-object
                        "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicy"
                        "metadata" (gr8s::core-object "name" name)
                        "spec" (gr8s::core-object
                                "matchConstraints"
                                (gr8s::core-object
                                 "resourceRules"
                                 (vector (gr8s::core-object "apiGroups" #("apps") "apiVersions" #("v1")
                                                            "operations" #("CREATE") "resources" #("deployments"))))
                                "validations" (coerce validations 'vector))))))
      (let* ((good (policy "good" (gr8s::core-object "expression" "object.spec.replicas > 1")))
             (status (gethash "status" good)))
        (is (= 1 (gethash "observedGeneration" status)))
        (is (hash-table-p (gethash "typeChecking" status)))
        (is (not (gethash "expressionWarnings" (gethash "typeChecking" status)))))
      (let* ((bad (policy "bad" (gr8s::core-object "expression" "object.spec.replicas > '1'"
                                                   "messageExpression" "'wants replicas > 1, got ' + object.spec.replicas")
                          (gr8s::core-object "expression" "object.spec.maxRetries < 10")))
             (warnings (gethash "expressionWarnings" (gethash "typeChecking" (gethash "status" bad)))))
        (is (= 3 (length warnings)))
        (is (equal "spec.validations[0].expression" (gethash "fieldRef" (aref warnings 0))))
        (is (search "found no matching overload for '_>_' applied to '(int, string)'" (gethash "warning" (aref warnings 0))))
        (is (equal "spec.validations[0].messageExpression" (gethash "fieldRef" (aref warnings 1))))
        (is (search "found no matching overload for '_+_' applied to '(string, int)'" (gethash "warning" (aref warnings 1))))
        (is (search "undefined field 'maxRetries'" (gethash "warning" (aref warnings 2))))))))

(test policies-use-the-authorizer-escape-key-and-audit-annotations
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/api/v1/namespaces" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "alpha")))
    (check-core-status 201 "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies" :method :post
      :object (gr8s::core-object
               "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicy"
               "metadata" (gr8s::core-object "name" "authz")
               "spec" (gr8s::core-object
                       "matchConstraints"
                       (gr8s::core-object
                        "resourceRules"
                        (vector (gr8s::core-object "apiGroups" #("") "apiVersions" #("v1")
                                                   "operations" #("CREATE") "resources" #("configmaps"))))
                       "validations"
                       (vector (gr8s::core-object
                                "expression"
                                "authorizer.group('').resource('secrets').namespace('alpha').check('get').allowed() && authorizer.requestResource.check('create').allowed() && jsonpatch.escapeKey('a/b') == 'a~1b'"
                                "message" "denied by authorizer"))
                       "auditAnnotations" (vector (gr8s::core-object "key" "seen" "valueExpression" "object.metadata.name")))))
    (check-core-status 201 "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings" :method :post
      :object (gr8s::core-object
               "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicyBinding"
               "metadata" (gr8s::core-object "name" "authz")
               "spec" (gr8s::core-object "policyName" "authz" "validationActions" #("Deny"))))
    ;; The local listener acts as a cluster administrator, so every check passes.
    (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post :object (core-fixture "ConfigMap" "one"))
    (check-core-status 422 "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies" :method :post
      :object (gr8s::core-object
               "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingAdmissionPolicy"
               "metadata" (gr8s::core-object "name" "bad-key")
               "spec" (gr8s::core-object
                       "matchConstraints" (gr8s::core-object "resourceRules" #())
                       "auditAnnotations" (vector (gr8s::core-object "key" "NOT OK" "valueExpression" "'x'")))))))

(test requests-classify-by-flow-schema-and-report-it
  (with-core-api (store path)
    (values store path)
    (gr8s::reconcile-flowcontrol store)
    (let* ((admin (gr8s::make-api-user-identity :username "system:admin" :groups #("system:masters" "system:authenticated")))
           (user (gr8s::make-api-user-identity :username "noxu" :groups #("system:authenticated")))
           (other (gr8s::make-api-user-identity :username "foo" :groups #("system:authenticated")))
           (exempt (gethash "uid" (gethash "metadata" (gr8s::get-core-resource store "flowschemas" nil "exempt"))))
           (catch-all (gethash "uid" (gethash "metadata" (gr8s::get-core-resource store "flowschemas" nil "catch-all")))))
      (is (equal exempt (gr8s::flowcontrol-classify store admin "/api/v1/pods" :get)))
      (is (equal catch-all (gr8s::flowcontrol-classify store other "/healthz" :get)))
      (check-core-status 201 "/apis/flowcontrol.apiserver.k8s.io/v1/prioritylevelconfigurations" :method :post
        :object (gr8s::core-object "apiVersion" "flowcontrol.apiserver.k8s.io/v1" "kind" "PriorityLevelConfiguration"
                                   "metadata" (gr8s::core-object "name" "test-level")
                                   "spec" (gr8s::core-object "type" "Limited"
                                                             "limited" (gr8s::core-object "nominalConcurrencyShares" 1
                                                                                          "limitResponse" (gr8s::core-object "type" "Reject")))))
      (let* ((schema (check-core-status 201 "/apis/flowcontrol.apiserver.k8s.io/v1/flowschemas" :method :post
                       :object (gr8s::core-object
                                "apiVersion" "flowcontrol.apiserver.k8s.io/v1" "kind" "FlowSchema"
                                "metadata" (gr8s::core-object "name" "test-schema")
                                "spec" (gr8s::core-object
                                        "matchingPrecedence" 1000
                                        "priorityLevelConfiguration" (gr8s::core-object "name" "test-level")
                                        "rules" (vector (gr8s::core-object
                                                         "subjects" (vector (gr8s::core-object "kind" "User" "user" (gr8s::core-object "name" "noxu")))
                                                         "nonResourceRules" (vector (gr8s::core-object "verbs" #("*") "nonResourceURLs" #("*")))))))))
             (uid (gethash "uid" (gethash "metadata" schema))))
        (setf gr8s::*flowcontrol-snapshot* nil)
        (is (equal uid (gr8s::flowcontrol-classify store user "/healthz" :get)))
        (is (equal catch-all (gr8s::flowcontrol-classify store user "/api/v1/pods" :get)))
        (is (equal catch-all (gr8s::flowcontrol-classify store other "/healthz" :get)))
        (gr8s::reconcile-flowcontrol store)
        (let ((condition (aref (gethash "conditions" (gethash "status" (gr8s::get-core-resource store "flowschemas" nil "test-schema"))) 0)))
          (is (equal "Dangling" (gethash "type" condition)))
          (is (equal "False" (gethash "status" condition))))
        (is (search "apiserver_flowcontrol_nominal_limit_seats{priority_level=\"test-level\"} 100"
                    (gr8s::flowcontrol-metrics-text store)))))
    (multiple-value-bind (body status headers) (drakma:http-request "http://127.0.0.1:18089/version")
      (declare (ignore body))
      (is (= 200 status))
      (is (plusp (length (cdr (assoc :x-kubernetes-pf-flowschema-uid headers)))))
      (is (plusp (length (cdr (assoc :x-kubernetes-pf-prioritylevel-uid headers))))))))

(test custom-resource-failures-are-reported-together
  (with-core-api (store path)
    (values store path)
    (check-core-status 201 "/api/v1/namespaces" :method :post
      :object (gr8s::core-object "apiVersion" "v1" "kind" "Namespace" "metadata" (gr8s::core-object "name" "default")))
    (check-core-status 201 +rule-crd-path+ :method :post
      :object (rule-definition "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"enum\":[\"sentinel-a\"]},\"b\":{\"type\":\"string\",\"enum\":[\"sentinel-b\"]}}}"))
    (let* ((object (rule-object "one" "a" "x" "b" "y"))
           (metadata (gethash "metadata" object)))
      (setf (gethash "labels" metadata) (gr8s::core-object "#inv/($%)/alid" ">htt$://"))
      (let* ((status (check-core-status 422 +rule-path+ :method :post :object object))
             (message (gethash "message" status)))
        (is (search "sentinel-a" message) "~A" message)
        (is (search "sentinel-b" message) "~A" message)))))

(test oneof-still-judges-branches-while-collecting
  (let ((schema (gr8s::core-object "type" "object" "properties"
                  (gr8s::core-object "x" (gr8s::core-object "type" "integer" "anyOf"
                                            (vector (gr8s::core-object "minimum" 5) (gr8s::core-object "maximum" 1)))))))
    (is (hash-table-p (gr8s::crd-validate-all (gr8s::core-object "x" 7) schema "resource")))
    (signals kubernetes-error (gr8s::crd-validate-all (gr8s::core-object "x" 3) schema "resource"))))
