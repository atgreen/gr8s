;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify the webhook configuration API, the matchConditions CEL subset and
;;;; real AdmissionReview calls against a local TLS backend: rules, selectors,
;;;; failure policy, timeouts, ordered mutation, reinvocation and every write path.

(in-package #:gr8s/tests)
(def-suite admission-webhooks :in gr8s)
(in-suite admission-webhooks)

;;; CEL

(defun admission-test-cel (expression &rest bindings)
  "Compile and evaluate EXPRESSION with BINDINGS given as a name/value plist."
  (cl-cel::evaluate-cel-condition
   (cl-cel::compile-cel-condition expression)
   (loop for (name value) on bindings by #'cddr collect (cons name value))))

(defun admission-test-compile-message (expression)
  "Return the compile failure of EXPRESSION, or NIL if it compiles."
  (handler-case (progn (cl-cel::compile-cel-condition expression) nil)
    (cl-cel::cel-compile-error (condition) (princ-to-string condition))))

(test cel-evaluates-admission-conditions
  (let ((object (com.inuoe.jzon:parse "{\"metadata\":{\"name\":\"skip-me\",\"labels\":{\"a\":\"b\"}},\"spec\":{\"items\":[1,2,3],\"on\":false}}")))
    (is-false (admission-test-cel "object.metadata.name != 'skip-me'" "object" object))
    (is-true (admission-test-cel "object.metadata.name == \"skip-me\"" "object" object))
    (signals cl-cel::cel-evaluation-error (admission-test-cel "object.metadata.namespace == 'production'" "object" object))
    (is-true (admission-test-cel "has(object.metadata.labels) && !has(object.metadata.other)" "object" object))
    (is-true (admission-test-cel "'a' in object.metadata.labels && 2 in object.spec.items" "object" object))
    (is-true (admission-test-cel "object.spec.items.all(x, x > 0) && object.spec.items.exists_one(x, x == 2)" "object" object))
    (is-true (admission-test-cel "object.spec.items.filter(x, x > 1).size() == 2" "object" object))
    (is-true (admission-test-cel "object.spec.items.map(x, x * 2)[2] == 6" "object" object))
    (is-true (admission-test-cel "object.spec.on ? false : size(object.metadata.name) == 7" "object" object))
    (is-true (admission-test-cel "object.metadata.name.startsWith('skip') && object.metadata.name.upperAscii() == 'SKIP-ME'" "object" object))
    (is-true (admission-test-cel "1 == 1.0 && 7 / 2 == 3 && -7 % 3 == -1 && 'a' + 'b' == 'ab' && [1] + [2] == [1, 2]"))
    (is-true (admission-test-cel "{'k': 1}.k == 1 && {'k': 1}['k'] == 1 && 0x10 == 16 && 1e1 == 10.0"))))

(test cel-errors-follow-its-logic-and-budget
  (let ((object (com.inuoe.jzon:parse "{\"metadata\":{}}")))
    ;; A missing field is an error, which only an absorbing operand can hide.
    (signals cl-cel::cel-evaluation-error (admission-test-cel "object.metadata.name == 'x'" "object" object))
    (is-false (admission-test-cel "object.metadata.name == 'x' && false" "object" object))
    (is-true (admission-test-cel "true || object.metadata.name == 'x'" "object" object))
    (signals cl-cel::cel-evaluation-error (admission-test-cel "object.metadata.name == 'x' || false" "object" object))
    (signals cl-cel::cel-evaluation-error (admission-test-cel "1 / 0 == 1"))
    (signals cl-cel::cel-evaluation-error (admission-test-cel "9223372036854775807 + 1 == 0"))
    (signals cl-cel::cel-evaluation-error (admission-test-cel "dyn('a') < dyn(1)"))
    ;; Doubling the list at each level would otherwise run for far too long.
    (let ((cl-cel::+cel-evaluation-budget+ 1000))
      (signals cl-cel::cel-evaluation-error
        (admission-test-cel "[1,2,3,4,5,6,7,8,9,10].all(a, [1,2,3,4,5,6,7,8,9,10].all(b, [1,2,3,4,5,6,7,8,9,10].all(c, a + b + c > 0)))")))))

(test cel-refuses-what-it-cannot-compile-or-evaluate
  (is (search "Syntax error" (admission-test-compile-message "... [] bad expression")))
  (is (search "Syntax error" (admission-test-compile-message "object.metadata.")))
  (is (search "Syntax error" (admission-test-compile-message "true true")))
  (is (search "Syntax error" (admission-test-compile-message "let == 1")))
  (is (search "Syntax error" (admission-test-compile-message "namespace == 1")))
  (is (null (admission-test-compile-message "object.metadata.namespace == 'production'")))
  (is (search "must evaluate to bool" (admission-test-compile-message "object.metadata.name")))
  (is (search "must evaluate to bool" (admission-test-compile-message "1 + 1")))
  (is (search "undeclared reference" (admission-test-compile-message "params.x == 1")))
  (is (search "no matching overload" (admission-test-compile-message "timestamp('2020') == 1")))
  (is (search "undefined field" (admission-test-compile-message "request.nothing == 1")))
  (is (search "no matching overload" (admission-test-compile-message "1 == 'a'")))
  (is (search "no matching overload" (admission-test-compile-message "1 + 'a' == 'a'")))
  (is (null (admission-test-compile-message "authorizer.path('/').check('get').allowed()")))
  (is (null (admission-test-compile-message "object.a.matches('b')")))
  (is (null (admission-test-compile-message "1u == 1u")))
  (is (null (admission-test-compile-message "b'x' == b'x'")))
  (is (search "not supported" (admission-test-compile-message "Foo{a: 1} == null")))
  (is (search "nesting" (admission-test-compile-message
                         (format nil "~A1 == 1~A" (make-string 200 :initial-element #\()
                                 (make-string 200 :initial-element #\))))))
  (is (null (admission-test-compile-message "request.operation == 'CREATE'")))
  (is (null (admission-test-compile-message "object == null"))))

;;; Local TLS backend

(defun admission-test-respond (stream response &key chunked)
  "Write RESPONSE as JSON over STREAM, with chunked framing on request."
  (let* ((body (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify response)))
         (head (if chunked
                   (format nil "HTTP/1.1 200 OK~C~CContent-Type: application/json~C~CTransfer-Encoding: chunked~C~C~C~C~X~C~C"
                           #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed
                           (length body) #\Return #\Linefeed)
                   (format nil "HTTP/1.1 200 OK~C~CContent-Type: application/json~C~CContent-Length: ~D~C~C~C~C"
                           #\Return #\Linefeed #\Return #\Linefeed (length body) #\Return #\Linefeed #\Return #\Linefeed))))
    (write-sequence (trivial-utf-8:string-to-utf-8-bytes head) stream)
    (write-sequence body stream)
    (when chunked
      (write-sequence (trivial-utf-8:string-to-utf-8-bytes
                       (format nil "~C~C0~C~C~C~C" #\Return #\Linefeed #\Return #\Linefeed #\Return #\Linefeed))
                      stream))
    (force-output stream)))

(defun admission-test-serve (stream handler &optional first-octet)
  "Answer one AdmissionReview on STREAM with the response HANDLER builds from its path and request.
FIRST-OCTET, when given, is the request line's already-read first byte."
  (let* ((request-line (concatenate 'string
                                    (if first-octet (string (code-char first-octet)) "")
                                    (gr8s.apiserver::admission-read-line stream)))
         (length (loop for line = (gr8s.apiserver::admission-read-line stream)
                       until (zerop (length line))
                       when (uiop:string-prefix-p "content-length:" (string-downcase line))
                         collect (parse-integer line :start 15 :junk-allowed nil) into lengths
                       finally (return (first lengths))))
         (review (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string (gr8s.apiserver::admission-read-exactly stream length))
                                       :max-string-length (* 2 1024 1024)))
         (request (gethash "request" review))
         (path (second (uiop:split-string request-line :separator " ")))
         (response (funcall handler path request)))
    (when response
      (setf (gethash "uid" response) (gethash "uid" request))
      (admission-test-respond stream
                              (if (gethash "desiredAPIVersion" request)
                                  (gr8s.resources::core-object "apiVersion" "apiextensions.k8s.io/v1" "kind" "ConversionReview" "response" response)
                                  (gr8s.resources::core-object "apiVersion" "admission.k8s.io/v1" "kind" "AdmissionReview" "response" response))
                              :chunked (search "chunked" path)))))

(defun admission-test-backend (certificate key handler)
  "Serve HANDLER over TLS on a free port, returning the listener and a function that stops it."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (stopping nil)
         (thread
           (bt:make-thread
            (lambda ()
              (loop
                (let ((client (usocket:socket-accept listener :element-type '(unsigned-byte 8))))
                  (when stopping
                    (usocket:socket-close client)
                    (return))
                  (bt:make-thread
                   (lambda ()
                     (unwind-protect
                          (handler-case
                              ;; The production webhook client reuses connections,
                              ;; so serve keep-alive requests until the peer closes.
                              (let ((tls (pure-tls:make-tls-server-stream
                                          (usocket:socket-stream client)
                                          :certificate certificate :key key)))
                                (loop for first = (read-byte tls nil nil)
                                      while first
                                      do (admission-test-serve tls handler first)))
                            (error (condition)
                              (format *error-output* "~&Admission test backend: ~A~%" condition)))
                       (ignore-errors (usocket:socket-close client))))
                   :name "admission test connection"))))
            :name "admission test backend")))
    (values listener
            (lambda ()
              ;; Closing a listener under a blocked accept would leave that thread
              ;; holding a file descriptor number the next socket reuses.
              (setf stopping t)
              (usocket:socket-close (usocket:socket-connect "127.0.0.1" port))
              (bt:join-thread thread)
              (usocket:socket-close listener)))))

(defun admission-test-allow (&rest fields)
  "Build an allowing AdmissionResponse with FIELDS."
  (apply #'gr8s.resources::core-object "allowed" t fields))

(defun admission-test-deny (message &rest fields)
  "Build a denying AdmissionResponse carrying MESSAGE."
  (apply #'gr8s.resources::core-object "allowed" nil "status" (gr8s.resources::core-object "message" message) fields))

(defun admission-test-patch (&rest operations)
  "Encode JSON patch OPERATIONS for an AdmissionResponse."
  (list "patchType" "JSONPatch"
        "patch" (ag-grpc:base64-encode
                 (trivial-utf-8:string-to-utf-8-bytes
                  (com.inuoe.jzon:stringify (coerce operations 'vector))))))

(defun admission-test-add (path value)
  "Build a JSON patch add operation."
  (gr8s.resources::core-object "op" "add" "path" path "value" value))

(defun admission-test-credentials (pki)
  "Issue a server certificate for the test names, returning its chain and key paths."
  (let ((certificate (merge-pathnames "hook.crt" (gr8s.security::cluster-pki-root pki)))
        (key (merge-pathnames "hook.key" (gr8s.security::cluster-pki-root pki))))
    (multiple-value-bind (private public) (ironclad:generate-key-pair :secp256r1)
      (let ((der (gr8s.security::certificate-der
                  (pure-tls/acme::encode-subject gr8s.security::+pki-ca-common-name+)
                  (pure-tls/acme::encode-subject "hook")
                  (pure-tls/acme::encode-ec-public-key public)
                  (list (pure-tls/acme::encode-extension
                         pure-tls/acme::*oid-subject-alt-name*
                         (pure-tls/acme::encode-san-extension (list "hook.alpha.svc" "localhost"))))
                  (gr8s.security::cluster-pki-ca-private-key pki))))
        (gr8s.security::write-private-text-exclusively key (pure-tls/acme::encode-ec-private-key-pem private))
        (gr8s.security::write-private-text-exclusively
         certificate
         (concatenate 'string (pure-tls/acme::wrap-pem "CERTIFICATE" der)
                      (uiop:read-file-string (gr8s.security::cluster-pki-ca-certificate-path pki))))))
    (values certificate key)))

(defvar *admission-test-port* nil "Port of the running local TLS backend.")
(defvar *admission-test-bundle* nil "Base64 CA bundle that trusts the local TLS backend.")
(defvar *admission-test-global-handler* nil
  "Function from path and request to the backend's response, in a global cell because bindings do not cross threads.")

(defmacro with-admission-api ((store) &body body)
  "Run BODY against an API server and a local TLS webhook backend, with namespaces alpha and beta."
  (let ((path (gensym "PATH")) (pki (gensym "PKI")) (root (gensym "ROOT")) (listener (gensym "LISTENER"))
        (stop (gensym "STOP")) (certificate (gensym "CERTIFICATE")) (key (gensym "KEY")))
    `(with-core-api (,store ,path)
       (let* ((,root (uiop:ensure-directory-pathname
                      (sb-posix:mkdtemp (namestring (merge-pathnames "gr8s-admission-XXXXXX" (uiop:temporary-directory))))))
              (,pki (gr8s.security::ensure-cluster-pki (merge-pathnames "pki/" ,root)))
              (*admission-test-bundle*
                (ag-grpc:base64-encode
                 (trivial-utf-8:string-to-utf-8-bytes
                  (uiop:read-file-string (gr8s.security::cluster-pki-ca-certificate-path ,pki))))))
         (multiple-value-bind (,certificate ,key) (admission-test-credentials ,pki)
           (progn
             (setf *admission-test-global-handler*
                   (lambda (path request) (declare (ignore path request)) (admission-test-allow)))
             (multiple-value-bind (,listener ,stop)
                 (admission-test-backend ,certificate ,key
                                         (lambda (path request) (funcall *admission-test-global-handler* path request)))
               (let ((*admission-test-port* (usocket:get-local-port ,listener)))
                 (unwind-protect
                      (progn
                        (dolist (namespace '("alpha" "beta"))
                          (check-core-status 201 "/api/v1/namespaces" :method :post
                            :object (gr8s.resources::core-object "apiVersion" "v1" "kind" "Namespace"
                                                       "metadata" (gr8s.resources::core-object "name" namespace "labels" (gr8s.resources::core-object "team" namespace)))))
                        ,@body)
                   (funcall ,stop)
                   (uiop:delete-directory-tree ,root :validate t :if-does-not-exist :ignore))))))))))

(defun admission-test-webhook (name path &rest fields)
  "Build a webhook on ConfigMap writes that calls the local backend at PATH."
  (let ((webhook (gr8s.resources::core-object
                  "name" name "sideEffects" "None" "admissionReviewVersions" #("v1")
                  "clientConfig" (gr8s.resources::core-object "url" (format nil "https://localhost:~D~A" *admission-test-port* path)
                                                    "caBundle" *admission-test-bundle*)
                  "rules" (vector (gr8s.resources::core-object "operations" #("CREATE" "UPDATE" "DELETE") "apiGroups" #("")
                                                     "apiVersions" #("v1") "resources" #("configmaps")))
                  "timeoutSeconds" 5)))
    (loop for (key value) on fields by #'cddr do (setf (gethash key webhook) value))
    webhook))

(defun admission-test-config (kind name &rest webhooks)
  "Create a webhook configuration of KIND through the API."
  (check-core-status 201 (format nil "/apis/admissionregistration.k8s.io/v1/~(~A~)s" kind) :method :post
    :object (gr8s.resources::core-object "apiVersion" "admissionregistration.k8s.io/v1" "kind" kind
                               "metadata" (gr8s.resources::core-object "name" name)
                               "webhooks" (coerce webhooks 'vector))))

(defmacro with-admission-handler ((path request) &body body)
  "Set the backend's response function for the rest of the test."
  `(setf *admission-test-global-handler* (lambda (,path ,request) (declare (ignorable ,path ,request)) ,@body)))

(defun admission-test-configmap (name &rest data)
  "Build a ConfigMap with DATA given as a key/value plist."
  (core-fixture "ConfigMap" name "data" (apply #'gr8s.resources::core-object data)))

(defclass admission-test-trickle-stream (trivial-gray-streams:fundamental-binary-input-stream)
  ((octets :initarg :octets :accessor admission-test-trickle-octets)
   (position :initform 0 :accessor admission-test-trickle-position))
  (:documentation "Answer each read with at most three octets, as a stream between TLS records does."))

(defmethod trivial-gray-streams:stream-read-sequence
    ((stream admission-test-trickle-stream) sequence start end &key)
  "Copy at most three octets into SEQUENCE and report the new fill position."
  (let* ((from (admission-test-trickle-position stream))
         (count (min 3 (- end start) (- (length (admission-test-trickle-octets stream)) from))))
    (replace sequence (admission-test-trickle-octets stream) :start1 start :start2 from :end2 (+ from count))
    (incf (admission-test-trickle-position stream) count)
    (+ start count)))

(test request-bodies-survive-short-reads
  (let ((octets (coerce (loop for index below 200000 collect (mod index 251)) '(vector (unsigned-byte 8)))))
    (flet ((trickle () (make-instance 'admission-test-trickle-stream :octets octets)))
      (is (equalp octets (gr8s.apiserver::read-complete-body (trickle) (length octets))) "known length")
      (is (equalp octets (gr8s.apiserver::read-complete-body (trickle) nil)) "chunked, until end of file")
      (signals kubernetes-error (gr8s.apiserver::read-complete-body (trickle) (1+ (length octets)))))))

;;; Configuration API

(test webhook-configurations-are-served-discovered-and-defaulted
  (with-admission-api (store)
    (values store)
    (let ((groups (check-core-status 200 "/apis")))
      (is (find "admissionregistration.k8s.io" (gethash "groups" groups) :test #'equal
                :key (lambda (group) (gethash "name" group)))))
    (is (equal "admissionregistration.k8s.io"
               (gethash "name" (check-core-status 200 "/apis/admissionregistration.k8s.io"))))
    (let ((names (map 'list (lambda (entry) (gethash "name" entry))
                      (gethash "resources" (check-core-status 200 "/apis/admissionregistration.k8s.io/v1")))))
      (is (member "mutatingwebhookconfigurations" names :test #'equal))
      (is (member "validatingwebhookconfigurations" names :test #'equal)))
    (is (gethash "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/{name}"
                 (gethash "paths" (check-core-status 200 "/openapi/v3/apis/admissionregistration.k8s.io/v1"))))
    (let* ((created (admission-test-config "MutatingWebhookConfiguration" "defaults" (admission-test-webhook "a.b.c" "/x")))
           (hook (aref (gethash "webhooks" created) 0))
           (rule (aref (gethash "rules" hook) 0))
           (item "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/defaults"))
      (is (equal "Fail" (gethash "failurePolicy" hook)))
      (is (equal "Equivalent" (gethash "matchPolicy" hook)))
      (is (equal "Never" (gethash "reinvocationPolicy" hook)))
      (is (equal "*" (gethash "scope" rule)))
      (is (hash-table-p (gethash "namespaceSelector" hook)))
      (is (hash-table-p (gethash "objectSelector" hook)))
      (is (= 1 (gethash "generation" (gethash "metadata" created))))
      (let ((patched (check-core-status 200 item :method :patch :content-type "application/json-patch+json"
                       :object (vector (gr8s.resources::core-object "op" "replace" "path" "/webhooks/0/rules/0/operations"
                                                          "value" #("UPDATE"))))))
        (is (= 2 (gethash "generation" (gethash "metadata" patched))))
        (is (< (parse-integer (gethash "resourceVersion" (gethash "metadata" created)))
               (parse-integer (gethash "resourceVersion" (gethash "metadata" patched))))))
      (check-core-status 200 item :method :delete)
      (check-core-status 404 item))))

(test mutating-webhook-configurations-reject-an-invalid-reinvocation-policy
  (with-admission-api (store)
    (values store)
    (let ((body (check-core-status 422 "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations"
                  :method :post
                  :object (gr8s.resources::core-object
                           "apiVersion" "admissionregistration.k8s.io/v1" "kind" "MutatingWebhookConfiguration"
                           "metadata" (gr8s.resources::core-object "name" "bad")
                           "webhooks" (vector (admission-test-webhook "a.b.c" "/x" "reinvocationPolicy" "Sometimes"))))))
      (is (search "reinvocationPolicy" (gethash "message" body))))))

(test validating-webhooks-ignore-the-field-only-mutating-webhooks-declare
  (with-admission-api (store)
    (values store)
    (let ((created (check-core-status 201 "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations"
                     :method :post
                     :object (gr8s.resources::core-object
                              "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingWebhookConfiguration"
                              "metadata" (gr8s.resources::core-object "name" "lenient")
                              "webhooks" (vector (admission-test-webhook "a.b.c" "/x" "reinvocationPolicy" "Never"))))))
      (is (not (nth-value 1 (gethash "reinvocationPolicy" (aref (gethash "webhooks" created) 0))))))))

(test webhook-configurations-reject-invalid-fields
  (with-admission-api (store)
    (values store)
    (flet ((rejected (expected &rest fields)
             (let* ((object (gr8s.resources::core-object
                             "apiVersion" "admissionregistration.k8s.io/v1" "kind" "ValidatingWebhookConfiguration"
                             "metadata" (gr8s.resources::core-object "name" "bad")
                             "webhooks" (vector (apply #'admission-test-webhook "a.b.c" "/x" fields))))
                    (body (check-core-status 422 "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations"
                            :method :post :object object)))
               (is (search expected (gethash "message" body)) "~A not in ~A" expected (gethash "message" body)))))
      (rejected "at least three segments" "name" "tooshort.com")
      (rejected "sideEffects" "sideEffects" "Some")
      (rejected "timeout value" "timeoutSeconds" 31)
      (rejected "failurePolicy" "failurePolicy" "Sometimes")
      (rejected "matchPolicy" "matchPolicy" "Maybe")
      (rejected "admissionReviewVersions" "admissionReviewVersions" #("v2"))
      (rejected "clientConfig" "clientConfig" (gr8s.resources::core-object))
      (rejected "https" "clientConfig" (gr8s.resources::core-object "url" "http://example.com/"))
      (rejected "caBundle" "clientConfig" (gr8s.resources::core-object "url" "https://example.com/" "caBundle" "bm90IGEgY2VydA=="))
      (rejected "segment[0]" "clientConfig" (gr8s.resources::core-object "service" (gr8s.resources::core-object "namespace" "a" "name" "b" "path" "/Upper_Case")))
      (rejected "operations" "rules" (vector (gr8s.resources::core-object "operations" #("GET") "apiGroups" #("") "apiVersions" #("v1") "resources" #("pods"))))
      (rejected "if '*/*' is present" "rules" (vector (gr8s.resources::core-object "operations" #("*") "apiGroups" #("") "apiVersions" #("v1") "resources" #("*/*" "pods"))))
      (rejected "compilation failed" "matchConditions" (vector (gr8s.resources::core-object "name" "bad" "expression" "... [] bad expression")))
      (rejected "Duplicate" "matchConditions" (vector (gr8s.resources::core-object "name" "same" "expression" "true")
                                                      (gr8s.resources::core-object "name" "same" "expression" "true"))))))

(defun admission-test-protobuf-field (number wire value)
  "Encode one protobuf field, where VALUE is octets for wire type 2 or an integer for 0."
  (let ((tag (list (logior (ash number 3) wire))))
    (concatenate '(vector (unsigned-byte 8)) tag
                 (if (= wire 2)
                     (concatenate '(vector (unsigned-byte 8))
                                  (loop with size = (length value)
                                        while (> size 127) collect (logior 128 (logand size 127)) into prefix
                                                           do (setf size (ash size -7))
                                        finally (return (append prefix (list size))))
                                  value)
                     (list value)))))

(defun admission-test-protobuf-string (number text)
  "Encode a protobuf string field."
  (admission-test-protobuf-field number 2 (trivial-utf-8:string-to-utf-8-bytes text)))

(test webhook-configuration-protobuf-round-trips-the-typed-client-fields
  (let* ((rule (concatenate '(vector (unsigned-byte 8))
                            (admission-test-protobuf-string 1 "") (admission-test-protobuf-string 2 "v1")
                            (admission-test-protobuf-string 3 "configmaps")))
         (rule-with-operations (concatenate '(vector (unsigned-byte 8))
                                            (admission-test-protobuf-string 1 "CREATE")
                                            (admission-test-protobuf-field 2 2 rule)))
         (service (concatenate '(vector (unsigned-byte 8))
                               (admission-test-protobuf-string 1 "ns") (admission-test-protobuf-string 2 "svc")
                               (admission-test-protobuf-string 3 "") (admission-test-protobuf-field 4 0 80)))
         (client (concatenate '(vector (unsigned-byte 8))
                              (admission-test-protobuf-field 1 2 service)
                              (admission-test-protobuf-field 2 2 (trivial-utf-8:string-to-utf-8-bytes "pem"))))
         (selector (concatenate '(vector (unsigned-byte 8))
                                (admission-test-protobuf-field 1 2 (concatenate '(vector (unsigned-byte 8))
                                                                                (admission-test-protobuf-string 1 "k")
                                                                                (admission-test-protobuf-string 2 "v")))))
         (condition (concatenate '(vector (unsigned-byte 8))
                                 (admission-test-protobuf-string 1 "c") (admission-test-protobuf-string 2 "true")))
         (webhook (concatenate '(vector (unsigned-byte 8))
                               (admission-test-protobuf-string 1 "a.b.c")
                               (admission-test-protobuf-field 2 2 client)
                               (admission-test-protobuf-field 3 2 rule-with-operations)
                               (admission-test-protobuf-string 4 "Ignore")
                               (admission-test-protobuf-field 5 2 selector)
                               (admission-test-protobuf-string 6 "None")
                               (admission-test-protobuf-field 7 0 7)
                               (admission-test-protobuf-string 8 "v1")
                               (admission-test-protobuf-field 11 2 condition)))
         (object (gr8s.resources::decode-admission-protobuf
                  (coerce (concatenate '(vector (unsigned-byte 8))
                                       (admission-test-protobuf-field 1 2 (admission-test-protobuf-string 1 "hook"))
                                       (admission-test-protobuf-field 2 2 webhook))
                          '(simple-array (unsigned-byte 8) (*)))
                  "ValidatingWebhookConfiguration"))
         (decoded (aref (gethash "webhooks" object) 0))
         (decoded-rule (aref (gethash "rules" decoded) 0))
         (decoded-service (gethash "service" (gethash "clientConfig" decoded))))
    (is (equal "hook" (gethash "name" (gethash "metadata" object))))
    (is (equal "a.b.c" (gethash "name" decoded)))
    (is (equalp #("CREATE") (gethash "operations" decoded-rule)))
    (is (equalp #("") (gethash "apiGroups" decoded-rule)))
    (is (equalp #("configmaps") (gethash "resources" decoded-rule)))
    (is (equal "ns" (gethash "namespace" decoded-service)))
    (is (= 80 (gethash "port" decoded-service)))
    (is (equal "" (gethash "path" decoded-service)))
    (is (equal (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes "pem"))
               (gethash "caBundle" (gethash "clientConfig" decoded))))
    (is (= 7 (gethash "timeoutSeconds" decoded)))
    (is (equal "v" (gethash "k" (gethash "matchLabels" (gethash "namespaceSelector" decoded)))))
    (is (equal "true" (gethash "expression" (aref (gethash "matchConditions" decoded) 0))))))

;;; Invocation

(test validating-webhook-denies-with-its-message-and-sees-the-review
  (with-admission-api (store)
    (values store)
    (let ((seen nil))
      (with-admission-handler (path request)
        (push (cons path request) seen)
        (let ((object (gethash "object" request)))
          (if (and (hash-table-p object) (equal "bad" (gethash "name" (gethash "metadata" object))))
              (admission-test-deny "the configmap is bad")
              (admission-test-allow))))
      (admission-test-config "ValidatingWebhookConfiguration" "deny" (admission-test-webhook "deny.example.com" "/deny"))
      (let ((body (check-core-status 400 "/api/v1/namespaces/alpha/configmaps" :method :post
                    :object (admission-test-configmap "bad" "k" "v"))))
        (is (equal "admission webhook \"deny.example.com\" denied the request: the configmap is bad" (gethash "message" body))))
      (check-core-status 404 "/api/v1/namespaces/alpha/configmaps/bad")
      (let ((created (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post
                       :object (admission-test-configmap "good" "k" "v"))))
        (destructuring-bind (path . request) (first seen)
          (is (equal "/deny?timeout=5s" path))
          (is (equal "CREATE" (gethash "operation" request)))
          (is (equal "alpha" (gethash "namespace" request)))
          (is (equal "good" (gethash "name" request)))
          (is (equal "configmaps" (gethash "resource" (gethash "resource" request))))
          (is (equal "ConfigMap" (gethash "kind" (gethash "kind" request))))
          (is (equal "CreateOptions" (gethash "kind" (gethash "options" request))))
          (is (eq nil (gethash "dryRun" request)))
          (is (stringp (gethash "username" (gethash "userInfo" request))))
          ;; Validating webhooks see the object that is actually stored.
          (is (equal (gethash "uid" (gethash "metadata" created))
                     (gethash "uid" (gethash "metadata" (gethash "object" request)))))
          (is (eq 'null (gethash "oldObject" request)))))
      (let ((updated (check-core-status 200 "/api/v1/namespaces/alpha/configmaps/good" :method :patch
                       :content-type "application/merge-patch+json"
                       :object (gr8s.resources::core-object "data" (gr8s.resources::core-object "k" "w")))))
        (is (equal "w" (gethash "k" (gethash "data" updated))))
        (let ((request (cdr (first seen))))
          (is (equal "UPDATE" (gethash "operation" request)))
          (is (equal "v" (gethash "k" (gethash "data" (gethash "oldObject" request)))))
          (is (equal "w" (gethash "k" (gethash "data" (gethash "object" request)))))))
      (check-core-status 200 "/api/v1/namespaces/alpha/configmaps/good" :method :delete)
      (let ((request (cdr (first seen))))
        (is (equal "DELETE" (gethash "operation" request)))
        (is (eq 'null (gethash "object" request)))
        (is (equal "w" (gethash "k" (gethash "data" (gethash "oldObject" request)))))
        (is (equal "DeleteOptions" (gethash "kind" (gethash "options" request))))))))

(test webhook-denial-blocks-updates-and-deletes
  (with-admission-api (store)
    (values store)
    (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post
      :object (admission-test-configmap "keep" "k" "v"))
    (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post
      :object (admission-test-configmap "other" "k" "v"))
    (with-admission-handler (path request)
      (if (member (gethash "operation" request) '("UPDATE" "DELETE") :test #'equal)
          (admission-test-deny "no")
          (admission-test-allow)))
    (admission-test-config "ValidatingWebhookConfiguration" "deny" (admission-test-webhook "deny.example.com" "/deny"))
    (let ((item "/api/v1/namespaces/alpha/configmaps/keep"))
      (check-core-status 400 item :method :put :object (admission-test-configmap "keep" "k" "w"))
      (check-core-status 400 item :method :patch :content-type "application/strategic-merge-patch+json"
        :object (gr8s.resources::core-object "data" (gr8s.resources::core-object "k" "w")))
      (check-core-status 400 item :method :delete)
      (is (equal "v" (gethash "k" (gethash "data" (check-core-status 200 item))))))))

(test mutating-webhooks-chain-patches-in-order
  (with-admission-api (store)
    (values store)
    (with-admission-handler (path request)
      (let ((data (gethash "data" (gethash "object" request))))
        (cond ((search "/first" path)
               (if (gethash "start" data)
                   (apply #'admission-test-allow (admission-test-patch (admission-test-add "/data/stage-1" "yes")))
                   (admission-test-allow)))
              ((gethash "stage-1" data)
               (apply #'admission-test-allow (admission-test-patch (admission-test-add "/data/stage-2" "yes"))))
              (t (admission-test-allow)))))
    (admission-test-config "MutatingWebhookConfiguration" "chain"
                           (admission-test-webhook "first.example.com" "/first")
                           (admission-test-webhook "second.example.com" "/second-chunked"))
    (let* ((created (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post
                      :object (admission-test-configmap "mutated" "start" "yes")))
           (data (gethash "data" created)))
      (is (equal "yes" (gethash "stage-1" data)))
      (is (equal "yes" (gethash "stage-2" data)))
      (is (gr8s.apiserver::core-json-equal-p data (gethash "data" (check-core-status 200 "/api/v1/namespaces/alpha/configmaps/mutated")))
          "the mutated object is what was stored")
      ;; A mutation that leaves the object invalid is refused by normal validation.
      (with-admission-handler (path request)
        (apply #'admission-test-allow (admission-test-patch (admission-test-add "/data/bad key" "yes"))))
      (check-core-status 422 "/api/v1/namespaces/alpha/configmaps" :method :post
        :object (admission-test-configmap "invalid" "k" "v"))
      ;; A malformed patch is an internal error even though it is the webhook's fault.
      (with-admission-handler (path request)
        (admission-test-allow "patchType" "JSONPatch" "patch" "!!!"))
      (check-core-status 500 "/api/v1/namespaces/alpha/configmaps" :method :post
        :object (admission-test-configmap "broken" "k" "v")))))

(test if-needed-webhooks-run-again-after-a-later-change
  (with-admission-api (store)
    (values store)
    (let ((calls nil))
      (with-admission-handler (path request)
        (let ((data (gethash "data" (gethash "object" request))) (name (subseq path 1 (position #\? path))))
          (push (cons name (and (gethash "added" data) t)) calls)
          (if (and (equal name "adder") (not (gethash "added" data)))
              (apply #'admission-test-allow (admission-test-patch (admission-test-add "/data/added" "yes")))
              (admission-test-allow))))
      (admission-test-config "MutatingWebhookConfiguration" "reinvoke"
                             (admission-test-webhook "again.example.com" "/again" "reinvocationPolicy" "IfNeeded")
                             (admission-test-webhook "once.example.com" "/once")
                             (admission-test-webhook "adder.example.com" "/adder"))
      (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post
        :object (admission-test-configmap "x" "k" "v"))
      (is (equal '(("again" . nil) ("once" . nil) ("adder" . nil) ("again" . t)) (reverse calls))))))

(test selectors-and-rules-limit-which-webhooks-run
  (with-admission-api (store)
    (values store)
    (with-admission-handler (path request) (admission-test-deny "selected"))
    (admission-test-config
     "ValidatingWebhookConfiguration" "selective"
     (admission-test-webhook "namespace.example.com" "/n"
                             "namespaceSelector" (gr8s.resources::core-object "matchLabels" (gr8s.resources::core-object "team" "alpha"))
                             "rules" (vector (gr8s.resources::core-object "operations" #("CREATE") "apiGroups" #("") "apiVersions" #("v1") "resources" #("configmaps"))))
     (admission-test-webhook "object.example.com" "/o"
                             "objectSelector" (gr8s.resources::core-object "matchExpressions"
                                                                 (vector (gr8s.resources::core-object "key" "hooked" "operator" "Exists")))
                             "namespaceSelector" (gr8s.resources::core-object "matchLabels" (gr8s.resources::core-object "team" "beta"))
                             "rules" (vector (gr8s.resources::core-object "operations" #("CREATE") "apiGroups" #("") "apiVersions" #("v1") "resources" #("secrets")))))
    (check-core-status 400 "/api/v1/namespaces/alpha/configmaps" :method :post :object (admission-test-configmap "a"))
    (check-core-status 201 "/api/v1/namespaces/beta/configmaps" :method :post :object (admission-test-configmap "a"))
    (check-core-status 201 "/api/v1/namespaces/beta/secrets" :method :post :object (core-fixture "Secret" "plain"))
    (check-core-status 400 "/api/v1/namespaces/beta/secrets" :method :post
      :object (gr8s.resources::core-object "apiVersion" "v1" "kind" "Secret"
                                 "metadata" (gr8s.resources::core-object "name" "labelled" "labels" (gr8s.resources::core-object "hooked" "yes"))))
    ;; An operation outside the rules is untouched.
    (check-core-status 200 "/api/v1/namespaces/beta/configmaps/a" :method :delete)))

(test rule-matching-follows-upstream-resources-and-scope
  (flet ((matches (resources &key scope (plural "pods") subresource (namespace "alpha"))
           (let ((rule (gr8s.resources::core-object "operations" #("*") "apiGroups" #("*") "apiVersions" #("*")
                                          "resources" (coerce resources 'vector) "scope" (or scope "*"))))
             (and (gr8s.apiserver::admission-rule-matches-p
                   rule (gr8s.apiserver::make-admission-attributes :operation "CREATE" :plural plural :subresource subresource :namespace namespace)
                   "" "v1")
                  t))))
    (is-true (matches '("pods")))
    (is-false (matches '("pods") :subresource "status"))
    (is-true (matches '("pods/status") :subresource "status"))
    (is-false (matches '("pods/status")))
    (is-true (matches '("pods/*") :subresource "attach"))
    (is-true (matches '("pods/*")))
    (is-true (matches '("*")))
    (is-false (matches '("*") :subresource "status"))
    (is-true (matches '("*/*") :subresource "status"))
    (is-true (matches '("*/status") :subresource "status"))
    (is-true (matches '("pods") :scope "Namespaced"))
    (is-false (matches '("pods") :scope "Cluster"))
    (is-true (matches '("nodes") :plural "nodes" :namespace nil :scope "Cluster"))
    (is-true (matches '("namespaces") :plural "namespaces" :namespace "alpha" :scope "Cluster"))
    (is-false (matches '("namespaces") :plural "namespaces" :namespace "alpha" :scope "Namespaced"))))

(test failure-policy-governs-unreachable-and-untrusted-backends
  (with-admission-api (store)
    (values store)
    (let ((untrusted (gr8s.resources::core-object "url" (format nil "https://localhost:~D/x" *admission-test-port*))))
      ;; A trusted call to the same host first must not vouch for the untrusted ones through TLS resumption.
      (admission-test-config "ValidatingWebhookConfiguration" "trusted" (admission-test-webhook "trusted.example.com" "/x"))
      (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post :object (admission-test-configmap "first"))
      (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post :object (admission-test-configmap "second"))
      (admission-test-config "ValidatingWebhookConfiguration" "ignored"
                             (admission-test-webhook "ignored.example.com" "/x" "clientConfig" untrusted "failurePolicy" "Ignore"))
      (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post :object (admission-test-configmap "a"))
      (admission-test-config "ValidatingWebhookConfiguration" "closed"
                             (admission-test-webhook "closed.example.com" "/x" "clientConfig" untrusted))
      (let ((body (check-core-status 500 "/api/v1/namespaces/alpha/configmaps" :method :post :object (admission-test-configmap "b"))))
        (is (equal "InternalError" (gethash "reason" body)))
        (is (search "failed calling webhook \"closed.example.com\"" (gethash "message" body)))))))

(test fail-open-webhooks-are-counted-in-the-fail-open-metric
  (with-admission-api (store)
    (values store)
    (let ((unreachable (gr8s.resources::core-object "url" (format nil "https://localhost:~D/x" *admission-test-port*))))
      ;; Untrusted backend + failurePolicy Ignore -> the call fails and the request
      ;; is let through; each fail-open must register in the metric, by name and type.
      (admission-test-config "ValidatingWebhookConfiguration" "vopen"
                             (admission-test-webhook "vopen.example.com" "/x" "clientConfig" unreachable "failurePolicy" "Ignore"))
      (admission-test-config "MutatingWebhookConfiguration" "mopen"
                             (admission-test-webhook "mopen.example.com" "/x" "clientConfig" unreachable "failurePolicy" "Ignore"))
      (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post :object (admission-test-configmap "open"))
      (let* ((raw (drakma:http-request (core-api-url "/metrics") :proxy nil :redirect nil))
             (text (if (stringp raw) raw (trivial-utf-8:utf-8-bytes-to-string raw))))
        (is (search "# TYPE apiserver_admission_webhook_fail_open_count counter" text))
        (is (search "apiserver_admission_webhook_fail_open_count{name=\"vopen.example.com\",type=\"validating\"}" text))
        (is (search "apiserver_admission_webhook_fail_open_count{name=\"mopen.example.com\",type=\"mutating\"}" text))))))

(test webhook-configurations-are-exempt-from-admission
  (with-admission-api (store)
    (values store)
    (with-admission-handler (path request) (admission-test-deny "never"))
    (admission-test-config "ValidatingWebhookConfiguration" "everything"
                           (admission-test-webhook "all.example.com" "/x"
                             "rules" (vector (gr8s.resources::core-object "operations" #("*") "apiGroups" #("admissionregistration.k8s.io")
                                                                "apiVersions" #("*") "resources" #("*")))))
    (admission-test-config "MutatingWebhookConfiguration" "second" (admission-test-webhook "a.b.c" "/x"))
    (check-core-status 200 "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/second" :method :delete)
    (check-core-status 200 "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/everything" :method :delete)))

(test webhook-timeout-is-enforced-and-reported
  (with-admission-api (store)
    (values store)
    (with-admission-handler (path request) (sleep 4) (admission-test-allow))
    (admission-test-config "ValidatingWebhookConfiguration" "slow"
                           (admission-test-webhook "slow.example.com" "/slow" "timeoutSeconds" 1))
    (let* ((started (get-internal-real-time))
           (body (check-core-status 500 "/api/v1/namespaces/alpha/configmaps" :method :post :object (admission-test-configmap "a")))
           (elapsed (/ (- (get-internal-real-time) started) internal-time-units-per-second)))
      (is (< elapsed 3) "the call took ~F seconds" elapsed)
      (is (search "/slow?timeout=1s" (gethash "message" body)))
      (is (search "context deadline exceeded" (gethash "message" body))))))

(test service-webhooks-route-to-ready-endpoints
  (with-admission-api (store)
    (values store)
    (with-admission-handler (path request) (admission-test-deny (format nil "reached ~A" path)))
    (check-core-status 201 "/api/v1/namespaces/alpha/services" :method :post
      :object (gr8s.resources::core-object "apiVersion" "v1" "kind" "Service" "metadata" (gr8s.resources::core-object "name" "hook")
                                 "spec" (gr8s.resources::core-object "ports" (vector (gr8s.resources::core-object "port" 8443 "targetPort" *admission-test-port*)))))
    (admission-test-config "ValidatingWebhookConfiguration" "service"
                           (admission-test-webhook "service.example.com" "/s"
                             "clientConfig" (gr8s.resources::core-object "service" (gr8s.resources::core-object "namespace" "alpha" "name" "hook" "port" 8443 "path" "/via-service")
                                                               "caBundle" *admission-test-bundle*)))
    ;; No endpoints yet: a call failure under the default Fail policy.
    (let ((body (check-core-status 500 "/api/v1/namespaces/beta/configmaps" :method :post :object (admission-test-configmap "a"))))
      (is (search "no endpoints available" (gethash "message" body)))
      (is (search "https://hook.alpha.svc:8443/via-service?timeout=5s" (gethash "message" body))))
    ;; The API refuses a loopback endpoint, which is the only address this backend has.
    (gr8s.store::with-store-lock (store)
      (setf (gethash (gr8s.resources::core-resource-key "endpointslices" "alpha" "hook-1") (gr8s.store::pod-store-resources store))
            (gr8s.resources::core-object "apiVersion" "discovery.k8s.io/v1" "kind" "EndpointSlice" "addressType" "IPv4"
                               "metadata" (gr8s.resources::core-object "name" "hook-1" "namespace" "alpha"
                                                             "labels" (gr8s.resources::core-object "kubernetes.io/service-name" "hook"))
                               "ports" (vector (gr8s.resources::core-object "port" *admission-test-port* "protocol" "TCP"))
                               "endpoints" (vector (gr8s.resources::core-object "addresses" #("127.0.0.1"))))))
    (let ((body (check-core-status 400 "/api/v1/namespaces/beta/configmaps" :method :post :object (admission-test-configmap "a"))))
      (is (search "reached /via-service?timeout=5s" (gethash "message" body))))))

(test match-conditions-select-and-failure-policy-governs-their-errors
  (with-admission-api (store)
    (values store)
    (let ((calls 0))
      (with-admission-handler (path request)
        (incf calls)
        (apply #'admission-test-allow (admission-test-patch (admission-test-add "/data/hit" "yes"))))
      (admission-test-config "MutatingWebhookConfiguration" "conditions"
                             (admission-test-webhook "conditional.example.com" "/m"
                               "matchConditions" (vector (gr8s.resources::core-object "name" "skip-me" "expression" "object.metadata.name != 'skip-me'"))))
      (is-false (gethash "hit" (gethash "data" (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post
                                                 :object (admission-test-configmap "skip-me" "k" "v")))))
      (is (= 0 calls))
      (is (equal "yes" (gethash "hit" (gethash "data" (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post
                                                        :object (admission-test-configmap "other" "k" "v"))))))
      (is (= 1 calls)))
    ;; A condition's runtime error refuses under Fail and skips under Ignore.
    (admission-test-config "ValidatingWebhookConfiguration" "erroring"
                           (admission-test-webhook "fail.example.com" "/e"
                             "rules" (vector (gr8s.resources::core-object "operations" #("CREATE") "apiGroups" #("") "apiVersions" #("v1") "resources" #("secrets")))
                             "matchConditions" (vector (gr8s.resources::core-object "name" "missing" "expression" "object.nothing == 'x'"))))
    (let ((body (check-core-status 403 "/api/v1/namespaces/alpha/secrets" :method :post :object (core-fixture "Secret" "a"))))
      (is (search "no such key" (gethash "message" body))))
    (check-core-status 200 "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/erroring" :method :delete)
    (with-admission-handler (path request) (admission-test-deny "reached"))
    (admission-test-config "ValidatingWebhookConfiguration" "erroring"
                           (admission-test-webhook "ignore.example.com" "/e" "failurePolicy" "Ignore"
                             "rules" (vector (gr8s.resources::core-object "operations" #("CREATE") "apiGroups" #("") "apiVersions" #("v1") "resources" #("secrets")))
                             "matchConditions" (vector (gr8s.resources::core-object "name" "missing" "expression" "object.nothing == 'x'"))))
    (check-core-status 201 "/api/v1/namespaces/alpha/secrets" :method :post :object (core-fixture "Secret" "a"))))

(test bad-admission-responses-are-call-failures
  (with-admission-api (store)
    (values store)
    (admission-test-config "ValidatingWebhookConfiguration" "bad"
                           (admission-test-webhook "bad.example.com" "/x"))
    (flet ((failure (response expected)
             (with-admission-handler (path request)
               (let ((copy (gr8s.resources::copy-core-object response)))
                 (when (eq :wrong-uid (gethash "uid" copy)) (setf (gethash "uid" copy) "other"))
                 copy))
             (let ((body (check-core-status 500 "/api/v1/namespaces/alpha/configmaps" :method :post :object (admission-test-configmap "a"))))
               (is (search expected (gethash "message" body)) "~A not in ~A" expected (gethash "message" body)))))
      (failure (apply #'admission-test-allow (admission-test-patch (admission-test-add "/x" "y")))
               "validating webhook may not return"))))

(defun admission-test-labels (object)
  "Return OBJECT's metadata labels."
  (gethash "labels" (gethash "metadata" object)))

(defun admission-test-pod-object (name &rest fields)
  "Build a minimal Pod manifest named NAME."
  (let ((pod (gr8s.resources::copy-core-object (pod-to-object (parse-pod *valid-pod-json*)))))
    (setf (gethash "metadata" pod) (gr8s.resources::core-object "name" name))
    (loop for (key value) on fields by #'cddr
          do (setf (gethash key (gethash "metadata" pod)) value))
    pod))

(defun admission-test-pod-webhook (name path resources operations)
  "Build a webhook on the Pod RESOURCES and OPERATIONS."
  (admission-test-webhook name path
    "rules" (vector (gr8s.resources::core-object "operations" (coerce operations 'vector) "apiGroups" #("")
                                       "apiVersions" #("v1") "resources" (coerce resources 'vector)))))

(test pod-writes-pass-through-webhooks
  (with-admission-api (store)
    (values store)
    (let ((seen nil))
      (with-admission-handler (path request)
        (push request seen)
        (cond ((search "/mutate" path)
               (apply #'admission-test-allow
                      (admission-test-patch
                       (admission-test-add "/spec/initContainers"
                                           (vector (gr8s.resources::core-object "name" "added" "image" "added-image" "resources" (gr8s.resources::core-object)))))))
              ((let* ((object (gethash "object" request))
                      (labels (admission-test-labels (if (hash-table-p object) object (gethash "oldObject" request)))))
                 (and labels (gethash "denied" labels)))
               (admission-test-deny "the pod is denied"))
              (t (admission-test-allow))))
      (admission-test-config "ValidatingWebhookConfiguration" "pods-validate"
                             (admission-test-pod-webhook "validate.example.com" "/validate" '("pods") '("CREATE" "UPDATE" "DELETE")))
      (let ((body (check-core-status 400 "/api/v1/namespaces/alpha/pods" :method :post
                    :object (admission-test-pod-object "refused" "labels" (gr8s.resources::core-object "denied" "yes")))))
        (is (search "the pod is denied" (gethash "message" body))))
      (check-core-status 404 "/api/v1/namespaces/alpha/pods/refused")
      (admission-test-config "MutatingWebhookConfiguration" "pods-mutate"
                             (admission-test-pod-webhook "mutate.example.com" "/mutate" '("pods") '("CREATE")))
      (let* ((created (check-core-status 201 "/api/v1/namespaces/alpha/pods" :method :post
                        :object (admission-test-pod-object "mutated")))
             (init (aref (gethash "initContainers" (gethash "spec" created)) 0)))
        (is (equal "added" (gethash "name" init)))
        (is (equal "File" (gethash "terminationMessagePolicy" init)) "defaults apply after the mutation")
        (is (equal "/dev/termination-log" (gethash "terminationMessagePath" init)))
        (is (equal "File" (gethash "terminationMessagePolicy" (aref (gethash "containers" (gethash "spec" created)) 0)))))
      (check-core-status 400 "/api/v1/namespaces/alpha/pods/mutated" :method :patch
        :content-type "application/merge-patch+json"
        :object (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "labels" (gr8s.resources::core-object "denied" "yes"))))
      (is-false (gethash "labels" (gethash "metadata" (check-core-status 200 "/api/v1/namespaces/alpha/pods/mutated"))))
      (check-core-status 200 "/api/v1/namespaces/alpha/pods/mutated" :method :delete)
      (let ((request (first seen)))
        (is (equal "DELETE" (gethash "operation" request)))
        (is (equal "mutated" (gethash "name" request)))
        (is (equal "Pod" (gethash "kind" (gethash "oldObject" request))))))))

(test pod-connections-offer-their-options-to-webhooks
  (with-admission-api (store)
    (values store)
    (let ((seen nil))
      (with-admission-handler (path request)
        (push request seen)
        (let ((object (gethash "object" request)))
          (if (and (gethash "stdin" object) (equal "first" (gethash "container" object)))
              (admission-test-deny "attaching to pod 'held' is not allowed")
              (admission-test-allow))))
      (check-core-status 201 "/api/v1/namespaces/alpha/pods" :method :post :object (admission-test-pod-object "held"))
      (admission-test-config "ValidatingWebhookConfiguration" "attach"
                             (admission-test-pod-webhook "attach.example.com" "/attach" '("pods/attach") '("CONNECT")))
      (let ((body (check-core-status 400 "/api/v1/namespaces/alpha/pods/held/attach?container=first&stdin=true" :method :post)))
        (is (search "attaching to pod 'held' is not allowed" (gethash "message" body))))
      (let ((request (first seen)))
        (is (equal "CONNECT" (gethash "operation" request)))
        (is (equal "attach" (gethash "subResource" request)))
        (is (equal "pods" (gethash "resource" (gethash "resource" request))))
        (is (equal "PodAttachOptions" (gethash "kind" (gethash "kind" request))))
        (is (equal "held" (gethash "name" request)))
        (is (equal "PodAttachOptions" (gethash "kind" (gethash "object" request)))))
      ;; An allowed request still has to be a stream, which runs after admission.
      (let ((body (check-core-status 400 "/api/v1/namespaces/alpha/pods/held/attach?container=other&stdin=true" :method :post)))
        (is (search "upgraded connection" (gethash "message" body)))))))

(test containers-validate-termination-message-settings
  (flet ((pod-with (field value)
           (let* ((object (gr8s.resources::copy-core-object (pod-to-object (parse-pod *valid-pod-json*))))
                  (container (aref (gethash "containers" (gethash "spec" object)) 0)))
             (setf (gethash field container) value)
             object)))
    (is (gr8s.model::pod-name (parse-pod (pod-with "terminationMessagePolicy" "File"))))
    (is (gr8s.model::pod-name (parse-pod (pod-with "terminationMessagePolicy" "FallbackToLogsOnError"))))
    (is (gr8s.model::pod-name (parse-pod (pod-with "terminationMessagePath" "/elsewhere"))))
    (signals kubernetes-error (parse-pod (pod-with "terminationMessagePolicy" "Sometimes")))
    (signals kubernetes-error (parse-pod (pod-with "terminationMessagePath" "relative/path")))
    (signals kubernetes-error (parse-pod (pod-with "terminationMessagePath" "/a/../b")))))

(test webhook-configurations-accept-hyphenated-custom-kinds
  (with-admission-api (store)
    (values store)
    (with-admission-handler (path request) (admission-test-deny "the crd contains unwanted label"))
    (admission-test-config "ValidatingWebhookConfiguration" "crd"
                           (admission-test-webhook "crd.example.com" "/crd"
                             "rules" (vector (gr8s.resources::core-object "operations" #("CREATE") "apiGroups" #("apiextensions.k8s.io")
                                                                "apiVersions" #("*") "resources" #("customresourcedefinitions")))))
    (let ((body (check-core-status 400 "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" :method :post
                  :object (gr8s.resources::core-object
                           "apiVersion" "apiextensions.k8s.io/v1" "kind" "CustomResourceDefinition"
                           "metadata" (gr8s.resources::core-object "name" "e2e-deny-crds.webhook.example.com")
                           "spec" (gr8s.resources::core-object
                                   "group" "webhook.example.com" "scope" "Namespaced"
                                   "names" (gr8s.resources::core-object "plural" "e2e-deny-crds" "singular" "e2e-deny-crd"
                                                              "kind" "E2e-deny-crd" "listKind" "E2e-deny-crdList")
                                   "versions" (vector (gr8s.resources::core-object
                                                       "name" "v1" "served" t "storage" t
                                                       "schema" (gr8s.resources::core-object
                                                                 "openAPIV3Schema" (gr8s.resources::core-object
                                                                                    "type" "object"
                                                                                    "x-kubernetes-preserve-unknown-fields" t)))))))))
      (is (search "the crd contains unwanted label" (gethash "message" body))))))

(test workload-scale-subresource-passes-through-webhooks
  (with-admission-api (store)
    (values store)
    (let ((seen nil) (deployment (gr8s.resources::core-object
                                  "apiVersion" "apps/v1" "kind" "Deployment"
                                  "metadata" (gr8s.resources::core-object "name" "web")
                                  "spec" (gr8s.resources::core-object
                                          "replicas" 1
                                          "selector" (gr8s.resources::core-object "matchLabels" (gr8s.resources::core-object "app" "web"))
                                          "template" (gr8s.resources::core-object
                                                      "metadata" (gr8s.resources::core-object "labels" (gr8s.resources::core-object "app" "web"))
                                                      "spec" (gethash "spec" (pod-to-object (parse-pod *valid-pod-json*))))))))
      (check-core-status 201 "/apis/apps/v1/namespaces/alpha/deployments" :method :post :object deployment)
      (with-admission-handler (path request)
        (push request seen)
        (if (> (gethash "replicas" (gethash "spec" (gethash "object" request))) 5)
            (admission-test-deny "too many")
            (admission-test-allow)))
      (admission-test-config "ValidatingWebhookConfiguration" "scale"
                             (admission-test-webhook "scale.example.com" "/scale"
                               "rules" (vector (gr8s.resources::core-object "operations" #("UPDATE") "apiGroups" #("apps")
                                                                  "apiVersions" #("v1") "resources" #("deployments/scale")))))
      (let ((item "/apis/apps/v1/namespaces/alpha/deployments/web/scale"))
        (check-core-status 400 item :method :patch :content-type "application/merge-patch+json"
          :object (gr8s.resources::core-object "spec" (gr8s.resources::core-object "replicas" 9)))
        (check-core-status 200 item :method :patch :content-type "application/merge-patch+json"
          :object (gr8s.resources::core-object "spec" (gr8s.resources::core-object "replicas" 3)))
        (let ((request (first seen)))
          (is (equal "scale" (gethash "subResource" request)))
          (is (equal "Scale" (gethash "kind" (gethash "kind" request))))
          (is (equal "autoscaling" (gethash "group" (gethash "kind" request))))
          (is (equal "deployments" (gethash "resource" (gethash "resource" request)))))))))

(test collection-deletion-offers-each-object
  (with-admission-api (store)
    (values store)
    (let ((names nil) (template (lambda (name)
                                  (gr8s.resources::core-object "apiVersion" "v1" "kind" "PodTemplate"
                                                     "metadata" (gr8s.resources::core-object "name" name)
                                                     "template" (gr8s.resources::core-object "metadata" (gr8s.resources::core-object)
                                                                                   "spec" (gethash "spec" (pod-to-object (parse-pod *valid-pod-json*))))))))
      (dolist (name '("one" "two"))
        (check-core-status 201 "/api/v1/namespaces/alpha/podtemplates" :method :post :object (funcall template name)))
      (with-admission-handler (path request)
        (push (gethash "name" request) names)
        (if (equal "two" (gethash "name" request)) (admission-test-deny "keep two") (admission-test-allow)))
      (admission-test-config "ValidatingWebhookConfiguration" "collection"
                             (admission-test-webhook "collection.example.com" "/c"
                               "rules" (vector (gr8s.resources::core-object "operations" #("DELETE") "apiGroups" #("")
                                                                  "apiVersions" #("v1") "resources" #("podtemplates")))))
      (check-core-status 400 "/api/v1/namespaces/alpha/podtemplates" :method :delete)
      (is (equal '("one" "two") (sort (copy-list names) #'string<)))
      (check-core-status 200 "/api/v1/namespaces/alpha/podtemplates/one"))))

(test dry-run-reaches-webhooks-without-storing
  (with-admission-api (store)
    (values store)
    (let ((seen nil))
      (with-admission-handler (path request)
        (push request seen)
        (admission-test-allow))
      (admission-test-config "ValidatingWebhookConfiguration" "dry" (admission-test-webhook "dry.example.com" "/d"))
      (check-core-status 201 "/api/v1/namespaces/alpha/configmaps?dryRun=All" :method :post :object (admission-test-configmap "a"))
      (is (eq t (gethash "dryRun" (first seen))))
      (check-core-status 404 "/api/v1/namespaces/alpha/configmaps/a"))))

(test lost-update-races-restart-through-the-webhooks
  (with-admission-api (store)
    (let ((raced nil))
      (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post :object (admission-test-configmap "shared" "a" "1"))
      (with-admission-handler (path request)
        ;; Another writer lands while the first attempt is inside the webhook.
        (unless raced
          (setf raced t)
          (gr8s.resources::update-core-resource store "configmaps" "alpha" "shared"
                                      (lambda (old) (setf (gethash "other" (gethash "data" old)) "2") old)))
        (admission-test-allow))
      (admission-test-config "ValidatingWebhookConfiguration" "race" (admission-test-webhook "race.example.com" "/r"))
      (let ((body (check-core-status 200 "/api/v1/namespaces/alpha/configmaps/shared" :method :patch
                    :content-type "application/merge-patch+json"
                    :object (gr8s.resources::core-object "data" (gr8s.resources::core-object "mine" "3")))))
        (is (equal "2" (gethash "other" (gethash "data" body))) "the concurrent write survives")
        (is (equal "3" (gethash "mine" (gethash "data" body))))))))

(test controller-writes-pass-through-webhooks
  (with-admission-api (store)
    (let ((seen nil) (deny-create nil) (deny-delete nil)
          (reconciler (make-reconciler store (make-fake-runtime))))
      (flet ((pods () (list-pods store "alpha"))
             (scale (replicas)
               (check-core-status 200 "/api/v1/namespaces/alpha/replicationcontrollers/rc" :method :patch
                 :content-type "application/merge-patch+json"
                 :object (gr8s.resources::core-object "spec" (gr8s.resources::core-object "replicas" replicas)))))
        (with-admission-handler (path request)
          (push request seen)
          (cond ((search "/mutate" path)
                 (apply #'admission-test-allow
                        (admission-test-patch (admission-test-add "/metadata/annotations" (gr8s.resources::core-object "mutated" "yes")))))
                ((and deny-create (equal "CREATE" (gethash "operation" request)))
                 (admission-test-deny "no more pods"))
                ((and deny-delete (equal "DELETE" (gethash "operation" request)))
                 (admission-test-deny "keep this pod"))
                (t (admission-test-allow))))
        (admission-test-config "MutatingWebhookConfiguration" "pods"
                               (admission-test-pod-webhook "mutate.example.com" "/mutate" '("pods") '("CREATE")))
        (admission-test-config "ValidatingWebhookConfiguration" "pods"
                               (admission-test-pod-webhook "validate.example.com" "/validate" '("pods") '("CREATE" "DELETE")))
        (let ((fixture (rc-fixture "rc" 1)))
          (check-core-status 201 "/api/v1/namespaces/alpha/replicationcontrollers" :method :post :object fixture))
        (gr8s.controllers::reconcile-workloads reconciler)
        ;; A mutating webhook's change reaches the Pod the controller creates.
        (is (= 1 (length (pods))))
        (is (equal "yes" (gethash "mutated" (gethash "annotations" (gethash "metadata" (pod-to-object (first (pods))))))))
        (let ((request (find-if (lambda (entry) (equal "CREATE" (gethash "operation" entry))) seen)))
          (is (equal "system:serviceaccount:kube-system:replication-controller"
                     (gethash "username" (gethash "userInfo" request))))
          (is (equal "alpha" (gethash "namespace" request))))
        ;; A refusal leaves the Pod uncreated and reports it on the owner.
        (setf deny-create t)
        (scale 2)
        (gr8s.controllers::reconcile-workloads reconciler)
        (is (= 1 (length (pods))))
        (let ((status (gethash "status" (gr8s.resources::get-core-resource store "replicationcontrollers" "alpha" "rc"))))
          (is (search "no more pods" (gethash "message" (aref (gethash "conditions" status) 0)))))
        (setf deny-create nil)
        (gr8s.controllers::reconcile-workloads reconciler)
        (is (= 2 (length (pods))))
        ;; A refused deletion leaves the Pod alone until the webhook allows it.
        (setf deny-delete t seen nil)
        (scale 1)
        (gr8s.controllers::reconcile-workloads reconciler)
        (is (notany #'gr8s.kubelet::deletion-requested-p (pods)))
        (is-true (find "DELETE" seen :test #'equal :key (lambda (entry) (gethash "operation" entry))))
        (setf deny-delete nil)
        (gr8s.controllers::reconcile-workloads reconciler)
        (is (= 1 (length (pods))))))))

(test garbage-collection-offers-its-deletions-to-webhooks
  (with-admission-api (store)
    (let ((seen nil) (deny t) (reconciler (make-reconciler store (make-fake-runtime))))
      (with-admission-handler (path request)
        (push request seen)
        (if deny (admission-test-deny "keep this configmap") (admission-test-allow)))
      (let ((orphan (admission-test-configmap "orphan")))
        (setf (gethash "ownerReferences" (gethash "metadata" orphan))
              (vector (gr8s.resources::core-object "apiVersion" "v1" "kind" "ConfigMap" "name" "absent" "uid" "absent-uid")))
        (check-core-status 201 "/api/v1/namespaces/alpha/configmaps" :method :post :object orphan))
      (admission-test-config "ValidatingWebhookConfiguration" "configmaps"
                             (admission-test-webhook "validate.example.com" "/validate"))
      (gr8s.controllers::collect-orphaned-api-objects reconciler)
      (is-true (gr8s.resources::get-core-resource store "configmaps" "alpha" "orphan"))
      (let ((request (first seen)))
        (is (equal "DELETE" (gethash "operation" request)))
        (is (equal "system:serviceaccount:kube-system:generic-garbage-collector"
                   (gethash "username" (gethash "userInfo" request)))))
      (setf deny nil)
      (gr8s.controllers::collect-orphaned-api-objects reconciler)
      (signals kubernetes-error (gr8s.resources::get-core-resource store "configmaps" "alpha" "orphan")))))

(test a-webhook-that-is-too-slow-is-reported-the-same-whichever-timer-ends-the-call
  ;; The request's deadline and the socket's own read timeout are both the
  ;; webhook's timeoutSeconds. The second, when it came first, was reported as an
  ;; I/O timeout on a Lisp stream (podster-0o5).
  (let ((original (symbol-function 'gr8s.apiserver::admission-https-post))
        (webhook (gr8s.resources::core-object
                  "name" "slow.example.com" "timeoutSeconds" 1
                  "clientConfig" (gr8s.resources::core-object "url" "https://localhost:9/slow"))))
    (unwind-protect
         (dolist (signal-it (list (lambda () (error 'sb-sys:io-timeout :stream *standard-input* :direction :input :seconds 1))
                                  (lambda () (error 'usocket:timeout-error))
                                  (lambda () (error 'cl-cancel:deadline-exceeded))))
           (setf (symbol-function 'gr8s.apiserver::admission-https-post)
                 (lambda (&rest arguments) (declare (ignore arguments)) (funcall signal-it)))
           (handler-case
               (progn (gr8s.apiserver::admission-call-webhook nil webhook "{}")
                      (fail "the call returned"))
             (gr8s.apiserver::admission-call-failure (condition)
               (is (equal "failed to call webhook: Post \"https://localhost:9/slow?timeout=1s\": context deadline exceeded"
                          (gr8s.apiserver::admission-call-failure-message condition))))))
      (setf (symbol-function 'gr8s.apiserver::admission-https-post) original))))
