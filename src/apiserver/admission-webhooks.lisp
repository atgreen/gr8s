;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Invoke configured admission webhooks: select them by rule, selector and
;;;; matchConditions, call them with AdmissionReview over verified TLS within
;;;; their timeouts, apply failurePolicy, chain and reinvoke mutating JSON patches
;;;; in order, and run validating webhooks concurrently. No store lock is held
;;;; while a webhook runs, so a slow backend delays only its own request.

(in-package #:gr8s.apiserver)

(defstruct (admission-attributes (:conc-name admission-))
  "Describe one API operation as webhooks see it."
  operation resource group version plural subresource kind-group kind-version kind
  namespace name object old-object options dry-run user-info (uid (generate-uid))
  equivalent-versions warnings)

(defstruct (admission-hook (:conc-name hook-))
  "One webhook selected by its rules, with the version it will be called at."
  config spec version)

(define-condition admission-call-failure (error)
  ((message :initarg :message :reader admission-call-failure-message))
  (:report (lambda (condition stream) (write-string (admission-call-failure-message condition) stream)))
  (:documentation "A webhook could not give a usable answer, which failurePolicy governs."))

(defvar *admission-controller* nil
  "Service account name of the in-process controller making this write, outside any HTTP request.")

(defun admission-group-version (api-version)
  "Split an apiVersion into its group, empty for the core group, and version."
  (let ((slash (position #\/ api-version)))
    (if slash
        (values (subseq api-version 0 slash) (subseq api-version (1+ slash)))
        (values "" api-version))))

(defun admission-attributes-for (store operation resource namespace name
                                 &key subresource kind kind-api-version options dry-run object old-object)
  "Build the attributes of an operation in the current request on RESOURCE."
  (multiple-value-bind (group version plural resource-kind equivalent)
      (cond
        ((equal resource "pods") (values "" "v1" "pods" "Pod" nil))
        ((custom-resource-key-p resource)
         (let* ((spec (gethash "spec" *crd-view-definition*)) (names (gethash "names" spec)))
           (values (gethash "group" spec) *crd-request-version* (gethash "plural" names) (gethash "kind" names)
                   (loop for entry across (gethash "versions" spec)
                         when (gethash "served" entry) collect (gethash "name" entry)))))
        (t
         (multiple-value-bind (group version)
             (admission-group-version (if (and (equal resource "events") *core-resource-view-version*)
                                          *core-resource-view-version*
                                          (core-resource-api-version resource)))
           (values group version resource (core-resource-kind resource) nil))))
    (multiple-value-bind (kind-group kind-version)
        (if kind-api-version (admission-group-version kind-api-version) (values group version))
      (make-admission-attributes
       :operation operation :resource resource :group group :version version :plural plural
       :subresource subresource :kind-group kind-group :kind-version kind-version
       :kind (or kind resource-kind) :namespace namespace :name name :object object :old-object old-object
       :options options :dry-run dry-run :equivalent-versions equivalent
       :user-info (if *admission-controller*
                      (core-object "username" (format nil "system:serviceaccount:kube-system:~A" *admission-controller*)
                                   "groups" #("system:serviceaccounts" "system:serviceaccounts:kube-system" "system:authenticated"))
                      (csr-http-request-actor store))))))

(defun admission-stamp-object (attributes object)
  "Give OBJECT the type and namespace metadata a decoded Kubernetes object carries."
  (when (hash-table-p object)
    (setf (gethash "apiVersion" object)
          (if (equal "" (admission-kind-group attributes))
              (admission-kind-version attributes)
              (format nil "~A/~A" (admission-kind-group attributes) (admission-kind-version attributes)))
          (gethash "kind" object) (admission-kind attributes))
    (let ((metadata (gethash "metadata" object)))
      (when (and (hash-table-p metadata) (admission-namespace attributes))
        (setf (gethash "namespace" metadata) (admission-namespace attributes)))))
  object)

;;; Matching

(defun admission-rule-resource-p (rule plural subresource)
  "Apply upstream resource matching, where a bare * excludes subresources and x/* includes the resource."
  (loop for entry across (gethash "resources" rule)
        for slash = (position #\/ entry)
        for resource = (subseq entry 0 slash)
        for wanted-subresource = (if slash (subseq entry (1+ slash)) "")
        thereis (and (or (equal resource "*") (equal resource plural))
                     (or (equal wanted-subresource "*") (equal wanted-subresource (or subresource ""))))))

(defun admission-rule-scope-p (rule attributes)
  "Apply a rule's scope, where Namespace objects count as cluster scoped."
  (let ((scope (gethash "scope" rule "*"))
        (namespace-object (equal "namespaces" (admission-plural attributes)))
        (namespaced (and (admission-namespace attributes) t)))
    (cond ((equal scope "Namespaced") (and namespaced (not namespace-object)))
          ((equal scope "Cluster") (or namespace-object (not namespaced)))
          (t t))))

(defun admission-rule-matches-p (rule attributes group version)
  "Test one RuleWithOperations against the operation at GROUP and VERSION."
  (flet ((listed (key value)
           (let ((entries (gethash key rule)))
             (or (find "*" entries :test #'equal) (find value entries :test #'equal)))))
    (and (listed "operations" (admission-operation attributes))
         (listed "apiGroups" group)
         (listed "apiVersions" version)
         (admission-rule-resource-p rule (admission-plural attributes) (admission-subresource attributes))
         (admission-rule-scope-p rule attributes))))

(defun admission-hook-version (webhook attributes)
  "Choose the version to call WEBHOOK at, or NIL when its rules do not match.
The request's own version wins; matchPolicy Equivalent also accepts another served
version of the same custom resource, which the object is converted to for the call."
  (let ((group (admission-group attributes)) (version (admission-version attributes)) (rules (gethash "rules" webhook)))
    (flet ((matches (candidate)
             (some (lambda (rule) (admission-rule-matches-p rule attributes group candidate)) rules)))
      (cond ((matches version) version)
            ((equal "Equivalent" (gethash "matchPolicy" webhook))
             (find-if #'matches (admission-equivalent-versions attributes)))))))

(defun admission-hooks (store resource attributes)
  "Select RESOURCE's webhooks by rule, ordered by configuration name then position.
Configuration resources are exempt so a bad webhook can always be removed."
  (unless (equal +admission-api-group+ (admission-group attributes))
    (loop for config in (list-core-resources store resource)
          nconc (loop for webhook across (gethash "webhooks" config #())
                      for version = (admission-hook-version webhook attributes)
                      when version
                        collect (make-admission-hook :config (gethash "name" (gethash "metadata" config))
                                                     :spec webhook :version version)))))

(defun admission-active-p (store attributes)
  "Test whether any webhook's or admission policy's rules select this operation."
  (or (admission-hooks store "mutatingwebhookconfigurations" attributes)
      (admission-hooks store "validatingwebhookconfigurations" attributes)
      (admission-policy-candidates store "mutatingadmissionpolicies" attributes)
      (admission-policy-candidates store "validatingadmissionpolicies" attributes)))

(defun admission-object-labels (object)
  "Return OBJECT's labels when it is an object with metadata."
  (let ((metadata (and (hash-table-p object) (gethash "metadata" object))))
    (and (hash-table-p metadata)
         (let ((labels (gethash "labels" metadata))) (and (hash-table-p labels) labels)))))

(defun admission-selector-empty-p (selector)
  "Test for the selector that matches everything."
  (and (zerop (hash-table-count (gethash "matchLabels" selector (core-object))))
       (zerop (length (gethash "matchExpressions" selector #())))))

(defun admission-namespace-selected-p (store webhook attributes)
  "Apply namespaceSelector, which never exempts cluster-scoped objects other than Namespaces."
  (let ((selector (gethash "namespaceSelector" webhook))
        (namespace-object (and (equal "namespaces" (admission-plural attributes))
                               (null (admission-subresource attributes)))))
    (cond
      ((admission-selector-empty-p selector) t)
      ((and namespace-object (member (admission-operation attributes) '("CREATE" "UPDATE") :test #'equal))
       (workload-selector-matches-p selector (admission-object-labels (admission-object attributes))))
      ((and (null (admission-namespace attributes)) (not namespace-object)) t)
      (t
       (let* ((name (or (admission-namespace attributes) (admission-name attributes)))
              (namespace (handler-case (get-core-resource store "namespaces" nil name)
                           (kubernetes-error (condition)
                             (unless (= 404 (kubernetes-error-status-code condition)) (error condition))
                             nil))))
         (workload-selector-matches-p selector (and namespace (admission-object-labels namespace))))))))

(defun admission-object-selected-p (webhook attributes)
  "Apply objectSelector to both the new and old object."
  (let ((selector (gethash "objectSelector" webhook)))
    (or (admission-selector-empty-p selector)
        (flet ((selected (object)
                 (and (hash-table-p object) (hash-table-p (gethash "metadata" object))
                      (workload-selector-matches-p selector (admission-object-labels object)))))
          (or (selected (admission-object attributes))
              (selected (admission-old-object attributes)))))))

(defun admission-review-request (hook attributes)
  "Build the AdmissionRequest sent to HOOK, converting a custom object's version when needed."
  (let* ((version (hook-version hook))
         (requested (admission-version attributes))
         (converted (not (equal version requested)))
         (request-version (lambda (object)
                            (if (and converted (hash-table-p object))
                                (crd-object-at-version *crd-view-definition* object version)
                                object)))
         (resource (core-object "group" (admission-group attributes) "version" version
                                "resource" (admission-plural attributes)))
         (kind (core-object "group" (admission-kind-group attributes)
                            "version" (if converted version (admission-kind-version attributes))
                            "kind" (admission-kind attributes)))
         (namespace (or (admission-namespace attributes)
                        (and (equal "namespaces" (admission-plural attributes)) (admission-name attributes))))
         (request (core-object "uid" (admission-uid attributes) "kind" kind "resource" resource
                               "requestKind" (core-object "group" (admission-kind-group attributes)
                                                          "version" (admission-kind-version attributes)
                                                          "kind" (admission-kind attributes))
                               "requestResource" (core-object "group" (admission-group attributes) "version" requested
                                                              "resource" (admission-plural attributes))
                               "operation" (admission-operation attributes)
                               "userInfo" (admission-user-info attributes)
                               "dryRun" (and (admission-dry-run attributes) t))))
    (when (admission-subresource attributes)
      (setf (gethash "subResource" request) (admission-subresource attributes)
            (gethash "requestSubResource" request) (admission-subresource attributes)))
    (when (admission-name attributes) (setf (gethash "name" request) (admission-name attributes)))
    (when namespace (setf (gethash "namespace" request) namespace))
    (when (admission-options attributes) (setf (gethash "options" request) (admission-options attributes)))
    (setf (gethash "object" request)
          (let ((object (admission-object attributes)))
            (if object (funcall request-version object) 'null))
          (gethash "oldObject" request)
          (let ((object (admission-old-object attributes)))
            (if object (funcall request-version object) 'null)))
    request))

(defun admission-conditions-result (hook attributes)
  "Evaluate matchConditions: any false skips the webhook, otherwise any error is returned."
  (let* ((conditions (gethash "matchConditions" (hook-spec hook) #()))
         (errors nil))
    (when (zerop (length conditions)) (return-from admission-conditions-result (values t nil)))
    (let* ((request (admission-review-request hook attributes))
           (bindings (list (cons "object" (gethash "object" request))
                           (cons "oldObject" (gethash "oldObject" request))
                           (cons "request" request)
                           (cons "authorizer" (cel-opaque :authorizer nil)))))
      (with-cel-budget (+cel-match-conditions-budget+)
        (loop for condition across conditions
              do (handler-case
                     (unless (evaluate-cel-condition (compile-cel-condition (gethash "expression" condition)) bindings)
                       (return-from admission-conditions-result (values nil nil)))
                   ;; Once the shared budget is gone no further condition runs, and that is the error.
                   (cel-budget-exhausted (failure)
                     (return-from admission-conditions-result (values nil (princ-to-string failure))))
                   ((or cel-compile-error cel-evaluation-error) (failure)
                     (push (format nil "failed to evaluate matchCondition ~S: ~A" (gethash "name" condition) failure)
                           errors))))))
    (if errors (values nil (format nil "~{~A~^; ~}" (nreverse errors))) (values t nil))))

(defun admission-hook-selected-p (store hook attributes)
  "Apply selectors and matchConditions, honoring failurePolicy for condition errors."
  (let ((webhook (hook-spec hook)))
    (and (admission-namespace-selected-p store webhook attributes)
         (admission-object-selected-p webhook attributes)
         (multiple-value-bind (matches failure) (admission-conditions-result hook attributes)
           (when (and failure (equal "Fail" (gethash "failurePolicy" webhook)))
             (core-resource-error 403 "Forbidden" "~A ~S is forbidden: ~A"
                                  (admission-plural attributes) (or (admission-name attributes) "") failure))
           matches))))

;;; Transport

(defun admission-review-version (webhook)
  "Pick the first AdmissionReview version this server speaks from the webhook's preference."
  (or (find-if (lambda (version) (member version '("v1" "v1beta1") :test #'equal))
               (gethash "admissionReviewVersions" webhook))
      (error 'admission-call-failure :message "webhook does not accept known AdmissionReview versions")))

(defun admission-review-body (hook attributes)
  "Serialize the AdmissionReview request for HOOK."
  (com.inuoe.jzon:stringify
   (core-object "apiVersion" (format nil "admission.k8s.io/~A" (admission-review-version (hook-spec hook)))
                "kind" "AdmissionReview"
                "request" (admission-review-request hook attributes))))

(defun admission-service-endpoint (store service)
  "Route to a ready endpoint of SERVICE, returning its address, port and node, if known."
  (let* ((namespace (gethash "namespace" service)) (name (gethash "name" service))
         (port (gethash "port" service 443))
         (object (handler-case (get-core-resource store "services" namespace name)
                   (kubernetes-error ()
                     (error 'admission-call-failure :message (format nil "service \"~A/~A\" not found" namespace name)))))
         (spec (gethash "spec" object)))
    (when (equal "ExternalName" (gethash "type" spec))
      (return-from admission-service-endpoint (values (gethash "externalName" spec) port)))
    (let* ((service-port (or (find port (gethash "ports" spec #()) :key (lambda (entry) (gethash "port" entry)))
                             (error 'admission-call-failure
                                    :message (format nil "service \"~A/~A\" has no port ~D" namespace name port))))
           (port-name (let ((value (gethash "name" service-port ""))) (if (stringp value) value "")))
           (candidates nil))
      (dolist (slice (list-core-resources store "endpointslices" namespace))
        (let ((labels (admission-object-labels slice)))
          (when (and labels (equal name (gethash "kubernetes.io/service-name" labels)))
            (let ((slice-port (find-if (lambda (entry)
                                         (let ((value (gethash "name" entry "")))
                                           (equal port-name (if (stringp value) value ""))))
                                       (gethash "ports" slice #()))))
              (when slice-port
                (loop for endpoint across (gethash "endpoints" slice #())
                      for ready = (let ((conditions (gethash "conditions" endpoint)))
                                    (if (hash-table-p conditions)
                                        (multiple-value-bind (value present) (gethash "ready" conditions)
                                          (or (not present) (eq value 'null) value))
                                        t))
                      when ready
                        do (loop for address across (gethash "addresses" endpoint #())
                                 do (push (list address (gethash "port" slice-port)
                                                (let ((node (gethash "nodeName" endpoint)))
                                                  (and (stringp node) (plusp (length node)) node)))
                                          candidates))))))))
      (unless candidates
        (error 'admission-call-failure
               :message (format nil "no endpoints available for service \"~A/~A\"" namespace name)))
      (values-list (nth (random (length candidates)) candidates)))))

(defun admission-read-line (stream)
  "Read one CRLF-terminated ASCII header line."
  (let ((line (make-string-output-stream)) (count 0))
    (loop
      (let ((octet (read-byte stream nil nil)))
        (unless octet (error "connection closed during response headers"))
        (when (> (incf count) 65536) (error "oversized response header line"))
        (case octet
          (10 (return (string-right-trim '(#\Return) (get-output-stream-string line))))
          (t (write-char (code-char octet) line)))))))

(defparameter +admission-maximum-response+ (* 16 1024 1024)
  "Largest webhook response body accepted.")

;; admission-read-line and admission-read-exactly remain as the wire-reading
;; primitives the API aggregator's response parser and the test fixtures' request
;; readers share; admission-read-http-response is gone now that its callers go
;; through gr8s.http-client.
(defun admission-read-exactly (stream count)
  "Read COUNT octets from STREAM."
  (let ((buffer (make-array count :element-type '(unsigned-byte 8))) (filled 0))
    (loop while (< filled count)
          do (let ((next (read-sequence buffer stream :start filled)))
               (when (= next filled) (error "connection closed during response body"))
               (setf filled next)))
    buffer))

(defun admission-tls-context (bundle)
  "Trust exactly the certificates in the base64 BUNDLE, or the system roots without one."
  (let ((context (pure-tls:make-tls-context :verify-mode pure-tls:+verify-required+
                                            :auto-load-system-ca (null bundle))))
    (when bundle
      (setf (pure-tls::tls-context-trust-store context)
            (pure-tls::make-trust-store
             :certificates (admission-ca-certificates (core-base64-bytes bundle "caBundle")))))
    context))

(defun admission-https-post (&key address port server-name host-header target body bundle timeout dial)
  "POST BODY over verified TLS to SERVER-NAME at ADDRESS, through DIAL when given, within TIMEOUT seconds,
returning the status code and body octets.  A thin wrapper over the shared HTTP
client: it trusts exactly the webhook's caBundle (or the system roots without one)
and caps the response at +ADMISSION-MAXIMUM-RESPONSE+.  The private session-ticket
cache, address/verify-name split and socket-close-on-deadline live in the client."
  (multiple-value-bind (code headers response)
      (gr8s.http-client:https-request
       :host address :port port :server-name server-name :host-header host-header
       :method :post :target target
       :headers '(("Content-Type" . "application/json") ("Accept" . "application/json"))
       :body (trivial-utf-8:string-to-utf-8-bytes body)
       :trust-certificates (and bundle (admission-ca-certificates (core-base64-bytes bundle "caBundle")))
       :auto-load-system-ca (null bundle)
       ;; Admission calls the same webhook backend on every matching request;
       ;; reuse the connection instead of a fresh TLS handshake each time.
       :reuse t
       ;; A rolling webhook backend that refuses or resets a fresh connection is
       ;; retried, matching upstream's transport resilience, rather than
       ;; hard-failing on the first reset.  Each attempt is bounded by TIMEOUT, and
       ;; only fast transport failures (refused/reset/EOF) retry, so a hung backend
       ;; still fails once at the deadline rather than multiplying it.
       :max-attempts 3 :retry-interval 1/4
       :dial dial
       :timeout timeout
       :body-limit +admission-maximum-response+)
    (declare (ignore headers))
    (values code response)))

(defun admission-call-webhook (store webhook body)
  "POST BODY to WEBHOOK's backend, returning the parsed AdmissionReview or signaling a call failure."
  (let* ((config (gethash "clientConfig" webhook))
         (service (gethash "service" config))
         (timeout (gethash "timeoutSeconds" webhook))
         (url-string (gethash "url" config))
         (uri (and url-string (puri:parse-uri url-string)))
         (server-name (if service
                          (format nil "~A.~A.svc" (gethash "name" service) (gethash "namespace" service))
                          (puri:uri-host uri)))
         (visible-port (if service (gethash "port" service 443) (or (puri:uri-port uri) 443)))
         (path (let ((value (if service (gethash "path" service "") (or (puri:uri-path uri) ""))))
                 (if (equal value "") "/" value)))
         (target (format nil "~A?timeout=~Ds" path timeout))
         (location (format nil "https://~A:~D~A" server-name visible-port target)))
    (flet ((failure (reason)
             (error 'admission-call-failure
                    :message (format nil "failed to call webhook: Post ~S: ~A" location reason))))
      (multiple-value-bind (code response)
          (handler-case
              (multiple-value-bind (address port node)
                  (if service (admission-service-endpoint store service) (values server-name visible-port))
                (admission-https-post :address address :port port :server-name server-name :target target
                                      :host-header (format nil "~A:~D" server-name visible-port)
                                      :body body :bundle (gethash "caBundle" config) :timeout timeout
                                      :dial (pod-network-dial node store address)))
            (admission-call-failure (condition) (failure (admission-call-failure-message condition)))
            (cl-cancel:deadline-exceeded () (failure "context deadline exceeded"))
            (sb-sys:deadline-timeout () (failure "context deadline exceeded"))
            (usocket:timeout-error () (failure "context deadline exceeded"))
            ;; The socket's own read timeout can fire first. It is the same
            ;; deadline, and its report names a Lisp stream (podster-0o5).
            (sb-sys:io-timeout () (failure "context deadline exceeded"))
            (error (condition) (failure (remove #\Newline (princ-to-string condition)))))
        (unless (<= 200 code 299) (failure (format nil "unexpected status ~D" code)))
        (handler-case (com.inuoe.jzon:parse response
                                            :max-string-length +admission-maximum-response+)
          (error (condition)
            (error 'admission-call-failure
                   :message (format nil "received invalid webhook response: ~A" condition))))))))

(defun admission-verified-response (review webhook expected-uid mutating)
  "Apply upstream VerifyAdmissionResponse to REVIEW, returning its response object."
  (flet ((invalid (control &rest arguments)
           (error 'admission-call-failure
                  :message (format nil "received invalid webhook response: ~?" control arguments))))
    (unless (hash-table-p review) (invalid "response is not an object"))
    (let ((version (admission-review-version webhook)) (response (gethash "response" review)))
      (when (equal version "v1")
        (unless (and (equal "admission.k8s.io/v1" (gethash "apiVersion" review))
                     (equal "AdmissionReview" (gethash "kind" review)))
          (invalid "expected webhook response of admission.k8s.io/v1, Kind=AdmissionReview, got ~A, Kind=~A"
                   (gethash "apiVersion" review) (gethash "kind" review))))
      (unless (hash-table-p response) (invalid "webhook response was absent"))
      (when (equal version "v1")
        (unless (equal expected-uid (gethash "uid" response))
          (invalid "expected response.uid ~S, got ~S" expected-uid (gethash "uid" response))))
      (let ((patch (gethash "patch" response)) (patch-type (gethash "patchType" response)))
        (when (eq patch 'null) (setf patch nil))
        (when (eq patch-type 'null) (setf patch-type nil))
        (if mutating
            (cond ((and patch (null patch-type) (equal version "v1"))
                   (invalid "webhook returned response.patch but not response.patchType"))
                  ((and patch-type (null patch))
                   (invalid "webhook returned response.patchType but not response.patch"))
                  ((and patch-type (not (equal "JSONPatch" patch-type)))
                   (invalid "webhook returned invalid response.patchType of ~S" patch-type)))
            (when (or patch patch-type)
              (invalid "validating webhook may not return response.patch or response.patchType"))))
      response)))

(defun admission-denial (name response)
  "Build the API error for a webhook's explicit denial, as upstream ToStatusErr does."
  (let* ((status (let ((value (gethash "status" response))) (if (hash-table-p value) value (core-object))))
         (code (let ((value (gethash "code" status))) (if (and (integerp value) (<= 400 value 599)) value 400)))
         (message (let ((value (gethash "message" status))) (and (stringp value) (plusp (length value)) value)))
         (reason (let ((value (gethash "reason" status))) (if (stringp value) value ""))))
    (error 'kubernetes-error
           :status-code code :reason reason
           :message (cond (message (format nil "admission webhook ~S denied the request: ~A" name message))
                          ((plusp (length reason)) (format nil "admission webhook ~S denied the request: ~A" name reason))
                          (t (format nil "admission webhook ~S denied the request without explanation" name))))))

(defun admission-internal-error (name reason)
  "Signal the 500 InternalError that a failing Fail-policy webhook produces."
  (core-resource-error 500 "InternalError" "Internal error occurred: failed calling webhook ~S: ~A" name reason))

(defun admission-note-warnings (attributes response)
  "Record warnings a webhook returned for the eventual API response."
  (let ((warnings (gethash "warnings" response)))
    (when (and (vectorp warnings) (not (stringp warnings)))
      (loop for warning across warnings
            when (stringp warning) do (push warning (admission-warnings attributes))))))

(defun admission-emit-warnings (attributes)
  "Publish recorded webhook warnings as Warning headers on the current response."
  (when (and (boundp 'hunchentoot:*reply*) hunchentoot:*reply*)
    (dolist (warning (reverse (admission-warnings attributes)))
      (push (cons :warning (format nil "299 - \"~A\""
                                   (substitute #\Space #\Newline
                                               (cl-ppcre:regex-replace-all "[\\\\\"]" warning "\\\\\\&"))))
            (slot-value hunchentoot:*reply* 'hunchentoot::headers-out))))
  (setf (admission-warnings attributes) nil))

;;; Mutating chain

(defun admission-apply-patch (name object response)
  "Apply RESPONSE's base64 JSON patch to a copy of OBJECT, which is an internal error if malformed."
  (handler-case
      (let ((patch (com.inuoe.jzon:parse
                    (trivial-utf-8:utf-8-bytes-to-string (ag-grpc:base64-decode (gethash "patch" response)))
                    :max-string-length +admission-maximum-response+)))
        (let ((result (apply-core-json-patch (copy-core-object object) patch)))
          (unless (hash-table-p result) (error "patch did not produce an object"))
          result))
    (error (condition)
      (core-resource-error 500 "InternalError" "Internal error occurred: admission webhook ~S returned an unusable patch: ~A"
                           name (if (typep condition 'kubernetes-error) (kubernetes-error-message condition) condition)))))

(defvar *admission-webhook-fail-open-counts* (make-hash-table :test #'equal)
  "Counts, keyed by (webhook-name . type), of webhooks whose call failed and whose
failurePolicy: Ignore let the request through -- apiserver_admission_webhook_fail_open_count.")
(defvar *admission-webhook-fail-open-lock* (bt:make-lock "gr8s admission fail-open metric"))

(defun note-webhook-fail-open (name type)
  "Record that webhook NAME of TYPE (\"validating\" or \"mutating\") failed open.  The
failure is already logged; this is the signal kube-apiserver emits as a metric."
  (bt:with-lock-held (*admission-webhook-fail-open-lock*)
    (incf (gethash (cons name type) *admission-webhook-fail-open-counts* 0))))

(defun admission-webhook-fail-open-metrics-text ()
  "Prometheus exposition of apiserver_admission_webhook_fail_open_count, emitted,
as upstream does, once per webhook that failurePolicy: Ignore lets through."
  (let ((rows (bt:with-lock-held (*admission-webhook-fail-open-lock*)
                (loop for key being the hash-keys of *admission-webhook-fail-open-counts*
                        using (hash-value count)
                      collect (list (car key) (cdr key) count)))))
    (if (null rows)
        ""
        (with-output-to-string (out)
          (format out "# HELP apiserver_admission_webhook_fail_open_count Admission webhook fail open count.~%")
          (format out "# TYPE apiserver_admission_webhook_fail_open_count counter~%")
          (loop for (name type count) in rows
                do (format out "apiserver_admission_webhook_fail_open_count{name=~S,type=~S} ~D~%"
                           name type count))))))

(defun admission-invoke-mutating (store hook attributes)
  "Call one mutating webhook when selected, returning whether it changed the object."
  (when (admission-hook-selected-p store hook attributes)
    (let* ((webhook (hook-spec hook)) (name (gethash "name" webhook))
           (response
             (handler-case
                 (admission-verified-response
                  (admission-call-webhook store webhook (admission-review-body hook attributes))
                  webhook (admission-uid attributes) t)
               (admission-call-failure (condition)
                 (when (equal "Fail" (gethash "failurePolicy" webhook))
                   (admission-internal-error name (admission-call-failure-message condition)))
                 (note-webhook-fail-open name "mutating")
                 (format *error-output* "~&Ignoring failed webhook ~A: ~A~%" name condition)
                 (return-from admission-invoke-mutating nil)))))
      (unless (eq t (gethash "allowed" response)) (admission-denial name response))
      (admission-note-warnings attributes response)
      ;; A DELETE or CONNECT has no object for a patch to change.
      (when (and (gethash "patch" response) (not (eq 'null (gethash "patch" response)))
                 (member (admission-operation attributes) '("CREATE" "UPDATE") :test #'equal))
        (let* ((object (admission-object attributes))
               (patched (admission-apply-patch name object response))
               (changed (not (core-json-equal-p object patched))))
          (setf (admission-object attributes) patched)
          changed)))))

(defun admission-mutate (store attributes)
  "Run the mutating webhooks over the attributes' object and return the result.
Each IfNeeded webhook runs once more when a later webhook changed the object.
This single reinvocation pass is deliberate and matches upstream: Kubernetes'
reinvocationHandler re-dispatches at most once (round 0 then round 1), so a
mutating webhook is invoked at most twice and the object is not iterated to a
fixed point -- changes made during the reinvocation pass are not re-reviewed."
  (let ((hooks (admission-hooks store "mutatingwebhookconfigurations" attributes))
        (invoked nil) (pending nil)
        (*cel-authorizer-check* (admission-authorizer-check store))
        (*cel-request-resource* (admission-request-resource attributes)))
    ;; As upstream's plugin order has it, mutating policies run ahead of mutating webhooks.
    (admission-run-mutating-policies store attributes)
    (dolist (hook hooks)
      (let ((changed (admission-invoke-mutating store hook attributes)))
        (when changed (setf pending (union pending invoked)))
        (when (equal "IfNeeded" (gethash "reinvocationPolicy" (hook-spec hook)))
          (push hook invoked))))
    (dolist (hook hooks)
      (when (member hook pending) (admission-invoke-mutating store hook attributes)))
    (admission-emit-warnings attributes)
    (admission-object attributes)))

;;; Validating fan-out

(defun admission-validating-outcome (store webhook body uid)
  "Call one validating webhook without signaling, for use on a worker thread."
  (handler-case
      (let ((response (admission-verified-response (admission-call-webhook store webhook body) webhook uid nil)))
        (if (eq t (gethash "allowed" response))
            (list :allowed response)
            (list :denied response)))
    (admission-call-failure (condition)
      (list :failed (admission-call-failure-message condition)))
    (serious-condition (condition)
      (list :failed (remove #\Newline (princ-to-string condition))))))

(defun admission-validate (store attributes)
  "Run validating policies, then the selected validating webhooks concurrently, refusing on any denial or Fail-policy failure."
  (let* ((*cel-authorizer-check* (admission-authorizer-check store))
         (*cel-request-resource* (admission-request-resource attributes))
         (hooks (progn
                  (admission-run-validating-policies store attributes)
                  (remove-if-not (lambda (hook) (admission-hook-selected-p store hook attributes))
                                 (admission-hooks store "validatingwebhookconfigurations" attributes))))
         (uid (admission-uid attributes))
         (calls (mapcar (lambda (hook) (cons (hook-spec hook) (admission-review-body hook attributes))) hooks))
         (outcomes
           (if (<= (length calls) 1)
               (mapcar (lambda (call) (admission-validating-outcome store (car call) (cdr call) uid)) calls)
               (mapcar #'bt:join-thread
                       (mapcar (lambda (call)
                                 (bt:make-thread
                                  (lambda () (admission-validating-outcome store (car call) (cdr call) uid))
                                  :name "gr8s admission webhook"))
                               calls)))))
    (loop for (webhook) in calls
          for (state detail) in outcomes
          do (when (eq state :allowed) (admission-note-warnings attributes detail))
             (when (eq state :denied) (admission-denial (gethash "name" webhook) detail)))
    (loop for (webhook) in calls
          for (state detail) in outcomes
          do (when (eq state :failed)
               (if (equal "Fail" (gethash "failurePolicy" webhook))
                   (admission-internal-error (gethash "name" webhook) detail)
                   (progn
                     (note-webhook-fail-open (gethash "name" webhook) "validating")
                     (format *error-output* "~&Ignoring failed webhook ~A: ~A~%" (gethash "name" webhook) detail)))))
    (admission-emit-warnings attributes)))
