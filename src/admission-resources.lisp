;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Admit admissionregistration.k8s.io/v1 webhook configurations through the
;;;; pinned wire schema, upstream validation rules and defaults, including CEL
;;;; compilation of matchConditions and parsing of caBundle certificates, and
;;;; expose the group's discovery documents and OpenAPI paths.

(in-package #:gr8s)

(let ((addition (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/admissionregistration-v1.json"))))
  (dolist (section '("messages" "definitions"))
    (maphash (lambda (name value) (setf (gethash name (gethash section *podtemplate-schema*)) value))
             (gethash section addition))))

(defparameter +admission-api-group+ "admissionregistration.k8s.io"
  "The API group whose resources configure admission and are exempt from it.")

(defparameter +admission-api-version+ "admissionregistration.k8s.io/v1"
  "The served version of the webhook configuration resources.")

(defun admission-config-resource-p (resource)
  "Recognize the two webhook configuration collections."
  (and (member resource '("mutatingwebhookconfigurations" "validatingwebhookconfigurations") :test #'equal) t))

(defun admission-invalid (kind name field control &rest arguments)
  "Signal an upstream-shaped field validation failure for a webhook configuration."
  (core-resource-error 422 "Invalid" "~A ~S is invalid: ~A: ~?" kind name field control arguments))

(defun admission-string-array (value)
  "Return VALUE when it is a JSON array of strings, else NIL."
  (and (vectorp value) (not (stringp value)) (every #'stringp value) value))

(defun admission-drop-nulls (object)
  "Treat explicit nulls as the omitted optional pointers they encode."
  (let ((nulls (loop for key being the hash-keys of object using (hash-value value)
                     when (eq value 'null) collect key)))
    (dolist (key nulls) (remhash key object)))
  object)

(defun admission-fully-qualified-name-p (name)
  "Apply upstream IsFullyQualifiedName: a DNS subdomain of at least three segments."
  (and (stringp name) (plusp (length name)) (dns-subdomain-p name)
       (>= (count #\. name) 2)))

(defun admission-ca-certificates (bytes)
  "Parse every PEM certificate in BYTES, signaling when none can be used."
  (let* ((text (trivial-utf-8:utf-8-bytes-to-string bytes))
         (begin "-----BEGIN CERTIFICATE-----") (end "-----END CERTIFICATE-----")
         (certificates
           (loop with cursor = 0
                 for start = (search begin text :start2 cursor)
                 while start
                 collect (let ((stop (or (search end text :start2 start)
                                         (error "Unterminated PEM certificate block"))))
                           (setf cursor (+ stop (length end)))
                           (pure-tls:parse-certificate
                            (ag-grpc:base64-decode
                             (remove-if (lambda (character)
                                          (member character '(#\Space #\Tab #\Newline #\Return)))
                                        (subseq text (+ start (length begin)) stop))))))))
    (unless certificates (error "no PEM certificates found"))
    certificates))

(defun validate-admission-url (kind name field url)
  "Apply upstream ValidateWebhookURL, which requires https and a bare host."
  (let ((uri (handler-case (puri:parse-uri url)
               (error () (admission-invalid kind name field "url must be a valid URL")))))
    (unless (eq :https (puri:uri-scheme uri))
      (admission-invalid kind name field "'https' is the only allowed URL scheme"))
    (unless (plusp (length (puri:uri-host uri)))
      (admission-invalid kind name field "host must be specified"))
    (when (find #\@ url) (admission-invalid kind name field "user information is not permitted in the URL"))
    (when (puri:uri-fragment uri) (admission-invalid kind name field "fragments are not permitted in the URL"))
    (when (puri:uri-query uri) (admission-invalid kind name field "query parameters are not permitted in the URL"))))

(defun validate-admission-service-path (kind name field path)
  "Apply upstream ValidateWebhookService path rules: DNS subdomain segments."
  (unless (member path '("" "/") :test #'equal)
    (unless (char= #\/ (char path 0)) (admission-invalid kind name field "must start with a '/'"))
    (let* ((rest (subseq path 1))
           (trimmed (if (uiop:string-suffix-p rest "/") (subseq rest 0 (1- (length rest))) rest)))
      (loop for segment in (uiop:split-string trimmed :separator '(#\/))
            for index from 0
            do (when (zerop (length segment))
                 (admission-invalid kind name field "segment[~D] may not be empty" index))
               (unless (dns-subdomain-p segment)
                 (admission-invalid kind name field "segment[~D] must be a DNS subdomain" index))))))

(defun normalize-admission-client-config (kind name field config)
  "Validate clientConfig, requiring exactly one target and a parseable caBundle."
  (require-object config field)
  (admission-drop-nulls config)
  (reject-unsupported-fields config '("url" "service" "caBundle") field)
  (let ((url (gethash "url" config)) (service (gethash "service" config)) (bundle (gethash "caBundle" config)))
    (when (eq (null url) (null service))
      (admission-invalid kind name field "exactly one of url or service is required"))
    (when url
      (unless (stringp url) (admission-invalid kind name (concatenate 'string field ".url") "must be a string"))
      (validate-admission-url kind name (concatenate 'string field ".url") url))
    (when service
      (let ((context (concatenate 'string field ".service")))
        (require-object service context)
        (admission-drop-nulls service)
        (reject-unsupported-fields service '("namespace" "name" "path" "port") context)
        (unless (dns-label-p (gethash "name" service))
          (admission-invalid kind name (concatenate 'string context ".name") "must be a DNS label"))
        (unless (dns-label-p (gethash "namespace" service))
          (admission-invalid kind name (concatenate 'string context ".namespace") "must be a DNS label"))
        (let ((path (gethash "path" service)))
          (when path
            (unless (stringp path) (admission-invalid kind name (concatenate 'string context ".path") "must be a string"))
            (validate-admission-service-path kind name (concatenate 'string context ".path") path)))
        (let ((port (gethash "port" service 443)))
          (unless (typep port '(integer 1 65535))
            (admission-invalid kind name (concatenate 'string context ".port") "must be between 1 and 65535"))
          (setf (gethash "port" service) port))))
    (when (and bundle (not (equal bundle "")))
      (let ((bytes (core-base64-bytes bundle (concatenate 'string field ".caBundle"))))
        (handler-case (admission-ca-certificates bytes)
          (error (condition)
            (admission-invalid kind name (concatenate 'string field ".caBundle")
                               "could not parse certificates: ~A" condition)))))
    (when (equal bundle "") (remhash "caBundle" config))
    config))

(defun validate-admission-resources (kind name field resources)
  "Apply upstream validateResources wildcard rules to a rule's resources."
  (unless (and (admission-string-array resources) (plusp (length resources)))
    (admission-invalid kind name field "Required value"))
  (let ((any-subresource nil) (any-resource nil) (double nil) (single nil) (plain nil))
    (loop for entry across resources for index from 0
          do (when (zerop (length entry))
               (admission-invalid kind name (format nil "~A[~D]" field index) "Required value"))
             (when (equal entry "*/*") (setf double t))
             (when (equal entry "*") (setf single t))
             (let ((slash (position #\/ entry)))
               (if (null slash)
                   (setf plain (not (equal entry "*")))
                   (let ((resource (subseq entry 0 slash)) (subresource (subseq entry (1+ slash))))
                     (when (member resource any-subresource :test #'equal)
                       (admission-invalid kind name (format nil "~A[~D]" field index)
                                          "if '~A/*' is present, must not specify ~A" resource entry))
                     (when (member subresource any-resource :test #'equal)
                       (admission-invalid kind name (format nil "~A[~D]" field index)
                                          "if '*/~A' is present, must not specify ~A" subresource entry))
                     (when (equal subresource "*") (push resource any-subresource))
                     (when (equal resource "*") (push subresource any-resource))))))
    (when (and double (> (length resources) 1))
      (admission-invalid kind name field "if '*/*' is present, must not specify other resources"))
    (when (and single plain)
      (admission-invalid kind name field "if '*' is present, must not specify other resources without subresources"))))

(defun normalize-admission-rule (kind name field rule)
  "Validate one RuleWithOperations and default its scope."
  (require-object rule field)
  (admission-drop-nulls rule)
  (reject-unsupported-fields rule '("operations" "apiGroups" "apiVersions" "resources" "scope") field)
  (flet ((wildcard-alone (key)
           (let ((values (gethash key rule)))
             (unless (and (admission-string-array values) (plusp (length values)))
               (admission-invalid kind name (format nil "~A.~A" field key) "Required value"))
             (when (and (> (length values) 1) (find "*" values :test #'equal))
               (admission-invalid kind name (format nil "~A.~A" field key)
                                  "if '*' is present, must not specify other values"))
             values)))
    (loop for operation across (wildcard-alone "operations")
          unless (member operation '("*" "CREATE" "UPDATE" "DELETE" "CONNECT") :test #'equal)
            do (admission-invalid kind name (format nil "~A.operations" field)
                                  "Unsupported value: ~S" operation))
    (wildcard-alone "apiGroups")
    (when (find "" (wildcard-alone "apiVersions") :test #'equal)
      (admission-invalid kind name (format nil "~A.apiVersions" field) "Required value"))
    (validate-admission-resources kind name (format nil "~A.resources" field) (gethash "resources" rule))
    (let ((scope (gethash "scope" rule "*")))
      (unless (member scope '("*" "Cluster" "Namespaced") :test #'equal)
        (admission-invalid kind name (format nil "~A.scope" field) "Unsupported value: ~S" scope))
      (setf (gethash "scope" rule) scope)))
  rule)

(defun normalize-admission-match-conditions (kind name field conditions)
  "Validate names and compile every matchConditions expression."
  (unless (and (vectorp conditions) (not (stringp conditions)))
    (admission-invalid kind name field "must be an array"))
  (when (> (length conditions) 64)
    (admission-invalid kind name field "Too many: ~D: must have at most 64 items" (length conditions)))
  (let ((seen nil))
    (loop for condition across conditions for index from 0
          for context = (format nil "~A[~D]" field index)
          do (require-object condition context)
             (reject-unsupported-fields condition '("name" "expression") context)
             (let ((condition-name (gethash "name" condition)) (expression (gethash "expression" condition)))
               (unless (and (stringp expression)
                            (plusp (length (string-trim '(#\Space #\Tab #\Newline #\Return) expression))))
                 (admission-invalid kind name (concatenate 'string context ".expression") "Required value"))
               (handler-case (compile-cel-condition expression)
                 (cel-compile-error (failure)
                   (admission-invalid kind name (concatenate 'string context ".expression")
                                      "Invalid value: ~S: compilation failed: ~A" expression failure)))
               (unless (and (stringp condition-name) (plusp (length condition-name)))
                 (admission-invalid kind name (concatenate 'string context ".name") "Required value"))
               (unless (core-qualified-key-p condition-name)
                 (admission-invalid kind name (concatenate 'string context ".name") "must be a qualified name"))
               (when (member condition-name seen :test #'equal)
                 (admission-invalid kind name (concatenate 'string context ".name") "Duplicate value: ~S" condition-name))
               (push condition-name seen)))))

(defun normalize-admission-webhook (kind name field webhook mutating)
  "Validate one webhook against upstream rules and apply the v1 defaults."
  (require-object webhook field)
  (admission-drop-nulls webhook)
  (reject-unsupported-fields webhook
                             (append '("name" "clientConfig" "rules" "failurePolicy" "matchPolicy" "namespaceSelector"
                                       "objectSelector" "sideEffects" "timeoutSeconds" "admissionReviewVersions" "matchConditions")
                                     (when mutating '("reinvocationPolicy")))
                             field)
  (unless (admission-fully-qualified-name-p (gethash "name" webhook))
    (admission-invalid kind name (concatenate 'string field ".name")
                       "should be a domain with at least three segments separated by dots"))
  (flet ((enumerated (key default allowed)
           (let ((value (gethash key webhook default)))
             (unless (member value allowed :test #'equal)
               (admission-invalid kind name (format nil "~A.~A" field key) "Unsupported value: ~S: supported values: ~{~S~^, ~}" value allowed))
             (setf (gethash key webhook) value))))
    (enumerated "failurePolicy" "Fail" '("Fail" "Ignore"))
    (enumerated "matchPolicy" "Equivalent" '("Exact" "Equivalent"))
    (when mutating (enumerated "reinvocationPolicy" "Never" '("Never" "IfNeeded"))))
  (let ((side-effects (gethash "sideEffects" webhook)))
    (unless side-effects
      (admission-invalid kind name (concatenate 'string field ".sideEffects") "Required value: must specify one of None, NoneOnDryRun"))
    (unless (member side-effects '("None" "NoneOnDryRun") :test #'equal)
      (admission-invalid kind name (concatenate 'string field ".sideEffects") "Unsupported value: ~S: supported values: \"None\", \"NoneOnDryRun\"" side-effects)))
  (let ((timeout (gethash "timeoutSeconds" webhook 10)))
    (unless (typep timeout '(integer 1 30))
      (admission-invalid kind name (concatenate 'string field ".timeoutSeconds") "the timeout value must be between 1 and 30 seconds"))
    (setf (gethash "timeoutSeconds" webhook) timeout))
  (let ((versions (gethash "admissionReviewVersions" webhook)))
    (unless (and (admission-string-array versions) (plusp (length versions)))
      (admission-invalid kind name (concatenate 'string field ".admissionReviewVersions") "Required value: must specify one of v1, v1beta1"))
    (unless (= (length versions) (length (remove-duplicates versions :test #'equal)))
      (admission-invalid kind name (concatenate 'string field ".admissionReviewVersions") "duplicate version"))
    (unless (every (lambda (version) (dns-label-p version)) versions)
      (admission-invalid kind name (concatenate 'string field ".admissionReviewVersions") "must contain DNS labels"))
    (unless (or (find "v1" versions :test #'equal) (find "v1beta1" versions :test #'equal))
      (admission-invalid kind name (concatenate 'string field ".admissionReviewVersions") "must include at least one of v1, v1beta1")))
  (dolist (key '("namespaceSelector" "objectSelector"))
    (let ((selector (gethash key webhook)))
      (if selector
          (progn (admission-drop-nulls (require-object selector key))
                 (validate-workload-selector selector :allow-empty t))
          (setf (gethash key webhook) (core-object)))))
  (normalize-admission-client-config kind name (concatenate 'string field ".clientConfig") (gethash "clientConfig" webhook (core-object)))
  (let ((rules (gethash "rules" webhook #())))
    (unless (and (vectorp rules) (not (stringp rules)))
      (admission-invalid kind name (concatenate 'string field ".rules") "must be an array"))
    (loop for rule across rules for index from 0
          do (normalize-admission-rule kind name (format nil "~A.rules[~D]" field index) rule))
    (setf (gethash "rules" webhook) rules))
  (when (gethash "matchConditions" webhook)
    (normalize-admission-match-conditions kind name (concatenate 'string field ".matchConditions")
                                          (gethash "matchConditions" webhook))
    (when (zerop (length (gethash "matchConditions" webhook))) (remhash "matchConditions" webhook)))
  webhook)

(defun normalize-admission-config (resource input name)
  "Validate a webhook configuration and fill in its server-side defaults."
  (let* ((kind (core-resource-kind resource))
         (object (copy-core-object (require-object input kind)))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (mutating (equal resource "mutatingwebhookconfigurations")))
    (admission-drop-nulls object)
    (unless (and (equal +admission-api-version+ (gethash "apiVersion" object +admission-api-version+))
                 (equal kind (gethash "kind" object kind)))
      (core-resource-error 400 "BadRequest" "Expected ~A ~A" +admission-api-version+ kind))
    (reject-unsupported-fields object '("apiVersion" "kind" "metadata" "webhooks") kind)
    (validate-core-metadata metadata nil name)
    (remhash "namespace" metadata)
    (setf (gethash "apiVersion" object) +admission-api-version+ (gethash "kind" object) kind)
    (let ((webhooks (gethash "webhooks" object #())) (seen nil) (config-name (gethash "name" metadata)))
      (unless (and (vectorp webhooks) (not (stringp webhooks)))
        (admission-invalid kind config-name "webhooks" "must be an array"))
      (loop for webhook across webhooks for index from 0
            for field = (format nil "webhooks[~D]" index)
            do (normalize-admission-webhook kind config-name field webhook mutating)
               (when (member (gethash "name" webhook) seen :test #'equal)
                 (admission-invalid kind config-name (concatenate 'string field ".name") "Duplicate value: ~S" (gethash "name" webhook)))
               (push (gethash "name" webhook) seen))
      (setf (gethash "webhooks" object) webhooks))
    object))

(defun prepare-admission-config-write (object existing)
  "Assign metadata.generation, which advances only when the webhooks change."
  (setf (gethash "generation" (gethash "metadata" object))
        (if existing
            (+ (gethash "generation" (gethash "metadata" existing) 1)
               (if (core-json-equal-p (gethash "webhooks" object) (gethash "webhooks" existing)) 0 1))
            1))
  object)

(defun decode-admission-protobuf (bytes kind)
  "Decode a typed webhook configuration with the pinned field numbers."
  (let* ((object (template-protobuf-message (concatenate 'string "k8s.io.api.admissionregistration.v1." kind) bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) +admission-api-version+ (gethash "kind" object) kind)
    object))

(defun admission-api-group-object ()
  "Describe the served admissionregistration.k8s.io API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" +admission-api-group+
               "versions" (vector (core-object "groupVersion" +admission-api-version+ "version" "v1"))
               "preferredVersion" (core-object "groupVersion" +admission-api-version+ "version" "v1")))

(defun admission-discovery-response ()
  "Advertise the webhook configuration collections."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" +admission-api-version+
                              "resources" (concatenate 'vector (stored-resource-discovery +admission-api-version+)
                                                       (typed-status-discovery +admission-api-version+)))))

(defun add-admission-openapi-paths (paths)
  "Describe webhook configuration CRUD from the pinned structural schemas."
  (dolist (resource '("mutatingwebhookconfigurations" "validatingwebhookconfigurations"))
    (let* ((kind (core-resource-kind resource))
           (schema (concatenate 'string "io.k8s.api.admissionregistration.v1." kind))
           (collection (format nil "/apis/~A/~A" +admission-api-version+ resource))
           (item (concatenate 'string collection "/{name}")))
      (flet ((operation (action &optional body)
               (let ((value (core-object "operationId" (format nil "~AAdmissionregistrationV1~A" action kind)
                                         "x-kubernetes-group-version-kind"
                                         (core-object "group" +admission-api-group+ "version" "v1" "kind" kind)
                                         "responses" (core-object "200" (core-object "description" "Success")))))
                 (when body
                   (setf (gethash "parameters" value)
                         (vector (core-object "name" "fieldValidation" "in" "query" "schema" (core-object "type" "string")))
                         (gethash "requestBody" value)
                         (core-object "required" t "content"
                                      (core-object "application/json" (core-object "schema" (reference-schema schema))))))
                 value)))
        (setf (gethash collection paths)
              (core-object "get" (operation "list") "post" (operation "create" t) "delete" (operation "deleteCollection"))
              (gethash item paths)
              (core-object "parameters" (vector (core-object "name" "name" "in" "path" "required" t "schema" (core-object "type" "string")))
                           "get" (operation "read") "put" (operation "replace" t) "patch" (operation "patch" t)
                           "delete" (operation "delete"))))))
  paths)
