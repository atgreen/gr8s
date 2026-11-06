;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Exercise the typed API objects through HTTP: discovery, defaults, immutable
;;;; fields, status isolation, finalizers, server-side apply, Namespace termination
;;;; and the authentication and authorization review endpoints.

(in-package #:gr8s/tests)
(def-suite typed-apis :in gr8s)
(in-suite typed-apis)

(defvar *typed-test-port* nil "The kernel-assigned port of the current WITH-TYPED-HTTP server.")

(defun typed-http (path &key (method :get) object (content-type "application/json") parameters)
  "Make one request to the typed API test server, returning its parsed body and code."
  (multiple-value-bind (body code)
      (drakma:http-request (format nil "http://127.0.0.1:~D~A" *typed-test-port* path)
                           :method method :content-type content-type :parameters parameters
                           :content (when object (com.inuoe.jzon:stringify object)))
    (values (com.inuoe.jzon:parse (if (stringp body) body (trivial-utf-8:utf-8-bytes-to-string body))) code)))

(defun typed-check (expected path &rest options)
  "Assert a status code, returning the response object."
  (multiple-value-bind (body code) (apply #'typed-http path options)
    (is (= expected code) "~A: ~A" path (com.inuoe.jzon:stringify body))
    body))

(defmacro with-typed-http ((store) &body body)
  "Run an API-only test against a fresh store."
  (let ((path (gensym "PATH")))
    `(with-temporary-store (,store ,path)
       (let* ((server (start-server :address "127.0.0.1" :port 0 :store ,store
                                    :runtime (make-fake-runtime)))
              (*typed-test-port* (hunchentoot:acceptor-port server)))
         (unwind-protect (progn ,path ,@body) (stop-server server))))))

(defun typed-discovery-names (path)
  "List the resource names a discovery document advertises."
  (map 'list (lambda (entry) (gethash "name" entry)) (gethash "resources" (typed-check 200 path))))

(defun typed-namespace (name)
  "Create Namespace NAME."
  (typed-check 201 "/api/v1/namespaces" :method :post
               :object (gr8s::core-object "metadata" (gr8s::core-object "name" name))))

(test typed-api-groups-are-discoverable
  (with-typed-http (store)
    (values store)
    (let ((groups (map 'list (lambda (group) (gethash "name" group)) (gethash "groups" (typed-check 200 "/apis")))))
      (dolist (group '("coordination.k8s.io" "flowcontrol.apiserver.k8s.io" "resource.k8s.io"
                       "storagemigration.k8s.io" "authorization.k8s.io" "authentication.k8s.io"))
        (is-true (member group groups :test #'equal))
        (is (equal group (gethash "name" (typed-check 200 (concatenate 'string "/apis/" group)))))))
    (dolist (name '("prioritylevelconfigurations" "prioritylevelconfigurations/status" "flowschemas"))
      (is-true (member name (typed-discovery-names "/apis/flowcontrol.apiserver.k8s.io/v1") :test #'equal)))
    (dolist (name '("validatingadmissionpolicies" "validatingadmissionpolicies/status" "mutatingadmissionpolicybindings"))
      (is-true (member name (typed-discovery-names "/apis/admissionregistration.k8s.io/v1") :test #'equal)))))

(test leases-support-the-api-lifecycle
  (with-typed-http (store)
    (values store)
    (typed-namespace "leases")
    (let* ((collection "/apis/coordination.k8s.io/v1/namespaces/leases/leases")
           (created (typed-check 201 collection :method :post
                      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "one" "labels" (gr8s::core-object "drop" "true"))
                                                 "spec" (gr8s::core-object "holderIdentity" "holder" "leaseDurationSeconds" 30
                                                                           "acquireTime" "0001-01-01T00:00:02.000000Z")))))
      (is (equal "Lease" (gethash "kind" created)))
      (is (equal "0001-01-01T00:00:02.000000Z" (gethash "acquireTime" (gethash "spec" created))))
      (typed-check 422 collection :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "name" "bad")
                                   "spec" (gr8s::core-object "leaseDurationSeconds" 0)))
      (typed-check 200 (concatenate 'string collection "?labelSelector=drop=true") :method :delete)
      (typed-check 404 (concatenate 'string collection "/one"))
      (is (zerop (length (gethash "items" (typed-check 200 "/apis/coordination.k8s.io/v1/leases"))))))))

(test protobuf-timestamps-cover-go-zero-time
  (is (equal '(1 1 1 0 0 2) (multiple-value-list (gr8s::protobuf-timestamp-fields -62135596798))))
  (is (equal '(1970 1 1 0 0 0) (multiple-value-list (gr8s::protobuf-timestamp-fields 0))))
  (is (equal '(2024 2 29 12 30 45) (multiple-value-list (gr8s::protobuf-timestamp-fields 1709209845)))))

(test priority-levels-default-and-isolate-status
  (with-typed-http (store)
    (values store)
    (let* ((collection "/apis/flowcontrol.apiserver.k8s.io/v1/prioritylevelconfigurations")
           (created (typed-check 201 collection :method :post
                      :object (gr8s::core-object "metadata" (gr8s::core-object "generateName" "pl-")
                                                 "spec" (gr8s::core-object "type" "Limited"
                                                          "limited" (gr8s::core-object "limitResponse" (gr8s::core-object "type" "Reject"))))))
           (name (gethash "name" (gethash "metadata" created)))
           (item (format nil "~A/~A" collection name)))
      (is (= 30 (gethash "nominalConcurrencyShares" (gethash "limited" (gethash "spec" created)))))
      (is (= 1 (gethash "generation" (gethash "metadata" created))))
      (let ((patched (typed-check 200 item :method :patch :content-type "application/merge-patch+json"
                       :object (gr8s::core-object "spec" (gr8s::core-object "limited" (gr8s::core-object "nominalConcurrencyShares" 4))
                                                  "status" (gr8s::core-object "conditions" (vector (gr8s::core-object "type" "Ignored")))))))
        (is (= 2 (gethash "generation" (gethash "metadata" patched))))
        (is (null (gethash "status" patched))))
      (let ((status (typed-check 200 (concatenate 'string item "/status") :method :patch :content-type "application/merge-patch+json"
                      :object (gr8s::core-object "spec" (gr8s::core-object "type" "Exempt")
                                                 "status" (gr8s::core-object "conditions" (vector (gr8s::core-object "type" "Kept")))))))
        (is (equal "Limited" (gethash "type" (gethash "spec" status))))
        (is (equal "Kept" (gethash "type" (aref (gethash "conditions" (gethash "status" status)) 0))))
        (is (= 2 (gethash "generation" (gethash "metadata" status)))))
      (typed-check 422 collection :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "name" "unset")
                                   "spec" (gr8s::core-object "type" "Limited"))))))

(test resource-claims-keep-their-spec-immutable-and-honor-finalizers
  (with-typed-http (store)
    (values store)
    (typed-namespace "claims")
    (let* ((collection "/apis/resource.k8s.io/v1/namespaces/claims/resourceclaims")
           (request (gr8s::core-object "name" "req-0" "exactly" (gr8s::core-object "deviceClassName" "example")))
           (created (typed-check 201 collection :method :post
                      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "claim" "finalizers" #("example.com/hold"))
                                                 "spec" (gr8s::core-object "devices" (gr8s::core-object "requests" (vector request))))))
           (item (concatenate 'string collection "/claim")))
      (is (equal "ExactCount" (gethash "allocationMode" (gethash "exactly" (aref (gethash "requests" (gethash "devices" (gethash "spec" created))) 0)))))
      (let ((changed (gr8s::copy-core-object created)))
        (setf (gethash "deviceClassName" (gethash "exactly" (aref (gethash "requests" (gethash "devices" (gethash "spec" changed))) 0))) "other")
        (typed-check 422 item :method :put :object changed))
      (typed-check 200 item :method :delete)
      (let ((held (typed-check 200 item)))
        (is-true (gethash "deletionTimestamp" (gethash "metadata" held)))
        (setf (gethash "finalizers" (gethash "metadata" held)) #())
        (typed-check 200 item :method :put :object held))
      (typed-check 404 item))))

(test server-side-apply-tracks-ownership
  (with-typed-http (store)
    (values store)
    (typed-namespace "applied")
    (let* ((item "/apis/coordination.k8s.io/v1/namespaces/applied/leases/one")
           (config (lambda (&rest labels)
                     (gr8s::core-object "apiVersion" "coordination.k8s.io/v1" "kind" "Lease"
                                        "metadata" (gr8s::core-object "name" "one" "labels" (apply #'gr8s::core-object labels))
                                        "spec" (gr8s::core-object "holderIdentity" "first"))))
           (apply-type "application/apply-patch+yaml"))
      (typed-check 400 item :method :patch :content-type apply-type :object (funcall config "a" "1"))
      (let ((created (typed-check 201 item :method :patch :content-type apply-type :object (funcall config "a" "1" "b" "2")
                                  :parameters '(("fieldManager" . "first")))))
        (is (equal "first" (gethash "manager" (aref (gethash "managedFields" (gethash "metadata" created)) 0)))))
      ;; A field the manager stops applying goes away.
      (let ((updated (typed-check 200 item :method :patch :content-type apply-type :object (funcall config "a" "1")
                                  :parameters '(("fieldManager" . "first")))))
        (is (null (gethash "b" (gethash "labels" (gethash "metadata" updated))))))
      ;; Another manager conflicts on a differing value unless it forces.
      (typed-check 409 item :method :patch :content-type apply-type :object (funcall config "a" "changed")
                   :parameters '(("fieldManager" . "second")))
      (let ((forced (typed-check 200 item :method :patch :content-type apply-type :object (funcall config "a" "changed")
                                 :parameters '(("fieldManager" . "second") ("force" . "true")))))
        (is (equal "changed" (gethash "a" (gethash "labels" (gethash "metadata" forced)))))))))

(test namespaces-terminate-through-their-finalizer
  (with-typed-http (store)
    (let* ((namespace (typed-namespace "ending"))
           (reconciler (gr8s::make-reconciler store (make-fake-runtime))))
      (is (equalp #("kubernetes") (gethash "finalizers" (gethash "spec" namespace))))
      (is (equal "Active" (gethash "phase" (gethash "status" namespace))))
      (typed-check 201 "/api/v1/namespaces/ending/configmaps" :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "name" "kept")))
      (typed-check 200 "/api/v1/namespaces/ending" :method :delete)
      (let ((terminating (typed-check 200 "/api/v1/namespaces/ending")))
        (is (equal "Terminating" (gethash "phase" (gethash "status" terminating))))
        (is-true (gethash "deletionTimestamp" (gethash "metadata" terminating))))
      (typed-check 403 "/api/v1/namespaces/ending/configmaps" :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "name" "refused")))
      (gr8s::reconcile-namespace-deletions reconciler)
      (typed-check 404 "/api/v1/namespaces/ending/configmaps/kept")
      (typed-check 404 "/api/v1/namespaces/ending"))))

(test namespace-status-and-finalize-subresources-write-only-their-fields
  (with-typed-http (store)
    (values store)
    (typed-namespace "subresources")
    (let ((patched (typed-check 200 "/api/v1/namespaces/subresources/status" :method :patch
                     :content-type "application/merge-patch+json"
                     :object (gr8s::core-object "metadata" (gr8s::core-object "annotations" (gr8s::core-object "seen" "true"))
                                                "spec" (gr8s::core-object "finalizers" #())
                                                "status" (gr8s::core-object "conditions" (vector (gr8s::core-object "type" "StatusPatch" "status" "True")))))))
      (is (equal "true" (gethash "seen" (gethash "annotations" (gethash "metadata" patched)))))
      (is (equalp #("kubernetes") (gethash "finalizers" (gethash "spec" patched))))
      (is (equal "StatusPatch" (gethash "type" (aref (gethash "conditions" (gethash "status" patched)) 0)))))
    (let* ((current (typed-check 200 "/api/v1/namespaces/subresources"))
           (changed (gr8s::copy-core-object current)))
      (setf (gethash "finalizers" (gethash "spec" changed)) #("kubernetes" "example.com/held"))
      (is (equalp #("kubernetes" "example.com/held")
                  (gethash "finalizers" (gethash "spec" (typed-check 200 "/api/v1/namespaces/subresources/finalize" :method :put :object changed))))))
    ;; An ordinary update cannot release a finalizer.
    (let ((changed (typed-check 200 "/api/v1/namespaces/subresources")))
      (setf (gethash "finalizers" (gethash "spec" changed)) #())
      (is (= 2 (length (gethash "finalizers" (gethash "spec" (typed-check 200 "/api/v1/namespaces/subresources" :method :put :object changed)))))))))

(test subject-access-reviews-evaluate-live-rbac
  (with-typed-http (store)
    (values store)
    (typed-namespace "rbac")
    (typed-check 201 "/apis/rbac.authorization.k8s.io/v1/namespaces/rbac/roles" :method :post
      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "reader")
                                 "rules" (vector (gr8s::core-object "apiGroups" #("") "resources" #("configmaps") "verbs" #("list")))))
    (typed-check 201 "/apis/rbac.authorization.k8s.io/v1/namespaces/rbac/rolebindings" :method :post
      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "reader")
                                 "roleRef" (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "Role" "name" "reader")
                                 "subjects" (vector (gr8s::core-object "kind" "User" "name" "alice" "apiGroup" "rbac.authorization.k8s.io"))))
    (flet ((review (user verb)
             (gethash "allowed"
                      (gethash "status"
                               (typed-check 201 "/apis/authorization.k8s.io/v1/subjectaccessreviews" :method :post
                                 :object (gr8s::core-object "spec" (gr8s::core-object "user" user
                                            "resourceAttributes" (gr8s::core-object "namespace" "rbac" "verb" verb "resource" "configmaps"))))))))
      (is (eq t (review "alice" "list")))
      (is (null (review "alice" "delete")))
      (is (null (review "bob" "list"))))
    (is (eq t (gethash "allowed" (gethash "status"
      (typed-check 201 "/apis/authorization.k8s.io/v1/namespaces/rbac/localsubjectaccessreviews" :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "namespace" "rbac")
                  "spec" (gr8s::core-object "user" "alice"
                           "resourceAttributes" (gr8s::core-object "namespace" "rbac" "verb" "list" "resource" "configmaps"))))))))
    (typed-check 422 "/apis/authorization.k8s.io/v1/namespaces/rbac/localsubjectaccessreviews" :method :post
      :object (gr8s::core-object "metadata" (gr8s::core-object "namespace" "rbac")
                "spec" (gr8s::core-object "user" "alice"
                         "resourceAttributes" (gr8s::core-object "namespace" "other" "verb" "list" "resource" "configmaps"))))
    (typed-check 422 "/apis/authorization.k8s.io/v1/subjectaccessreviews" :method :post
      :object (gr8s::core-object "spec" (gr8s::core-object "resourceAttributes" (gr8s::core-object "verb" "list"))))))

(test self-subject-rules-reviews-answer-as-kubectl-asks
  (with-typed-http (store)
    ;; kubectl auth can-i --list sends the empty status that Go renders with null lists.
    (let* ((status (gethash "status"
                            (typed-check 201 "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" :method :post
                              :object (gr8s::core-object "spec" (gr8s::core-object "namespace" "default")
                                        "status" (gr8s::core-object "resourceRules" 'null "nonResourceRules" 'null
                                                                    "incomplete" nil)))))
           (rule (aref (gethash "resourceRules" status) 0)))
      ;; The local listener is a cluster administrator, as access reviews already answer.
      (is (equalp #("*") (gethash "verbs" rule)))
      (is (equalp #("*") (gethash "resources" rule)))
      (is (equalp #("*") (gethash "nonResourceURLs" (aref (gethash "nonResourceRules" status) 0)))))
    (let ((status (gr8s::self-subject-rules-status
                   store (gr8s::make-api-user-identity :username "bob" :groups #("system:authenticated")) "default")))
      (is (zerop (length (gethash "resourceRules" status)))))))

(test service-account-tokens-are-signed-bound-and-reviewable
  (with-typed-http (store)
    (typed-namespace "tokens")
    (typed-check 201 "/api/v1/namespaces/tokens/serviceaccounts" :method :post
      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "robot")))
    (let* ((response (typed-check 201 "/api/v1/namespaces/tokens/serviceaccounts/robot/token" :method :post
                       :object (gr8s::core-object "apiVersion" "authentication.k8s.io/v1" "kind" "TokenRequest" "spec" (gr8s::core-object))))
           (token (gethash "token" (gethash "status" response)))
           (parts (uiop:split-string token :separator '(#\.)))
           (claims (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string (gr8s::base64url-decode (second parts)))))
           (review (lambda (value &optional audiences)
                     (let ((spec (gr8s::core-object "token" value)))
                       (when audiences (setf (gethash "audiences" spec) audiences))
                       (gethash "status" (typed-check 201 "/apis/authentication.k8s.io/v1/tokenreviews" :method :post
                                                      :object (gr8s::core-object "spec" spec)))))))
      (is (= 3 (length parts)))
      (is (equal "system:serviceaccount:tokens:robot" (gethash "sub" claims)))
      (is (equal gr8s::+service-account-issuer+ (gethash "iss" claims)))
      (let ((status (funcall review token)))
        (is (eq t (gethash "authenticated" status)))
        (is (equal "system:serviceaccount:tokens:robot" (gethash "username" (gethash "user" status))))
        (is-true (find "system:authenticated" (gethash "groups" (gethash "user" status)) :test #'equal)))
      ;; Tampering with the payload breaks the signature.
      (let ((forged (format nil "~A.~A.~A" (first parts)
                            (gr8s::base64url-encode (trivial-utf-8:string-to-utf-8-bytes
                                                     (substitute #\x #\r (com.inuoe.jzon:stringify claims))))
                            (third parts))))
        (is (null (gethash "authenticated" (funcall review forged)))))
      ;; A token only authenticates for its own audiences.
      (is (null (gethash "authenticated" (funcall review token #("somewhere-else")))))
      ;; It stops working when its account goes away, even if recreated with the same name.
      (typed-check 200 "/api/v1/namespaces/tokens/serviceaccounts/robot" :method :delete)
      (typed-check 201 "/api/v1/namespaces/tokens/serviceaccounts" :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "name" "robot")))
      (is (null (gethash "authenticated" (funcall review token))))
      (is-true store))
    (typed-check 422 "/api/v1/namespaces/tokens/serviceaccounts/robot/token" :method :post
      :object (gr8s::core-object "spec" (gr8s::core-object "expirationSeconds" 5)))
    (typed-check 404 "/api/v1/namespaces/tokens/serviceaccounts/absent/token" :method :post
      :object (gr8s::core-object "spec" (gr8s::core-object)))))

(test oidc-discovery-publishes-the-signing-key
  (with-typed-http (store)
    (let* ((configuration (typed-check 200 "/.well-known/openid-configuration"))
           (keys (gethash "keys" (typed-check 200 "/openid/v1/jwks")))
           (key (aref keys 0))
           (signing (gr8s::load-service-account-signing-key store)))
      (is (equal gr8s::+service-account-issuer+ (gethash "issuer" configuration)))
      (is (uiop:string-suffix-p (gethash "jwks_uri" configuration) "/openid/v1/jwks"))
      (is (equal "EC" (gethash "kty" key)))
      (is (equal (gr8s::service-account-key-id signing) (gethash "kid" key)))
      (is (equalp (subseq (gr8s::service-account-public-point signing) 1 33)
                  (gr8s::base64url-decode (gethash "x" key)))))))

(test signing-key-survives-a-restart
  (with-typed-http (store)
    (let* ((key (gr8s::load-service-account-signing-key store))
           (id (gr8s::service-account-key-id key)))
      (setf (gr8s::pod-store-service-account-signing-key store) nil)
      (is (equal id (gr8s::service-account-key-id (gr8s::load-service-account-signing-key store)))))))

(defun typed-policy-rule (&rest resources)
  "Build a NamedRuleWithOperations for core RESOURCES on CREATE and UPDATE."
  (gr8s::core-object "operations" #("CREATE" "UPDATE") "apiGroups" #("") "apiVersions" #("v1")
                     "resources" (coerce resources 'vector)))

(defun typed-policy (collection name binding-collection binding-spec &rest spec)
  "Create policy NAME in COLLECTION selecting labeled Namespaces, and its binding."
  (let ((body (apply #'gr8s::core-object spec)))
    (setf (gethash "matchConstraints" body)
          (gr8s::core-object "resourceRules" (vector (typed-policy-rule "configmaps"))
                             "namespaceSelector" (gr8s::core-object "matchLabels" (gr8s::core-object "policed" "true"))))
    (typed-check 201 (concatenate 'string "/apis/admissionregistration.k8s.io/v1/" collection) :method :post
      :object (gr8s::core-object "metadata" (gr8s::core-object "name" name) "spec" body))
    (setf (gethash "policyName" binding-spec) name)
    (typed-check 201 (concatenate 'string "/apis/admissionregistration.k8s.io/v1/" binding-collection) :method :post
      :object (gr8s::core-object "metadata" (gr8s::core-object "name" name) "spec" binding-spec))))

(defun typed-policed-namespaces ()
  "Create one Namespace policies select and one they do not."
  (typed-check 201 "/api/v1/namespaces" :method :post
    :object (gr8s::core-object "metadata" (gr8s::core-object "name" "policed" "labels" (gr8s::core-object "policed" "true"))))
  (typed-namespace "free"))

(defun typed-configmap (name &rest data)
  "Build a ConfigMap body named NAME holding DATA."
  (gr8s::core-object "metadata" (gr8s::core-object "name" name) "data" (apply #'gr8s::core-object data)))

(test validating-admission-policy-denies-selected-writes
  (with-typed-http (store)
    (values store)
    (typed-policed-namespaces)
    (typed-policy "validatingadmissionpolicies" "limit" "validatingadmissionpolicybindings"
                  (gr8s::core-object "validationActions" #("Deny"))
                  "variables" (vector (gr8s::core-object "name" "allowed" "expression" "object.data.mode == 'on'"))
                  "validations" (vector (gr8s::core-object "expression" "variables.allowed"
                                                           "messageExpression" "'mode must be on, got ' + object.data.mode")
                                        (gr8s::core-object "expression" "namespaceObject.metadata.name == 'policed'")))
    (let ((denied (typed-check 422 "/api/v1/namespaces/policed/configmaps" :method :post
                    :object (typed-configmap "off" "mode" "off"))))
      (is (equal "Invalid" (gethash "reason" denied)))
      (is-true (search "mode must be on, got off" (gethash "message" denied))))
    (typed-check 201 "/api/v1/namespaces/policed/configmaps" :method :post :object (typed-configmap "on" "mode" "on"))
    ;; An unselected Namespace is untouched, and a broken read follows failurePolicy Fail.
    (typed-check 201 "/api/v1/namespaces/free/configmaps" :method :post :object (typed-configmap "off" "mode" "off"))
    (typed-check 403 "/api/v1/namespaces/policed/configmaps" :method :post :object (typed-configmap "missing"))))

(test validating-admission-policy-honors-failure-policy-and-warn
  (with-typed-http (store)
    (values store)
    (typed-policed-namespaces)
    (typed-policy "validatingadmissionpolicies" "lenient" "validatingadmissionpolicybindings"
                  (gr8s::core-object "validationActions" #("Deny"))
                  "failurePolicy" "Ignore"
                  "validations" (vector (gr8s::core-object "expression" "object.data.absent == 'x'")))
    (typed-policy "validatingadmissionpolicies" "warning" "validatingadmissionpolicybindings"
                  (gr8s::core-object "validationActions" #("Warn"))
                  "validations" (vector (gr8s::core-object "expression" "false")))
    (typed-check 201 "/api/v1/namespaces/policed/configmaps" :method :post :object (typed-configmap "kept" "mode" "on"))))

(test mutating-admission-policy-applies-configurations
  (with-typed-http (store)
    (values store)
    (typed-policed-namespaces)
    (typed-policy "mutatingadmissionpolicies" "mark" "mutatingadmissionpolicybindings" (gr8s::core-object)
                  "mutations" (vector (gr8s::core-object
                                       "patchType" "ApplyConfiguration"
                                       "applyConfiguration" (gr8s::core-object
                                                             "expression" "Object{ metadata: Object.metadata{ annotations: {'mutated-by': 'policy'} } }"))
                                      (gr8s::core-object
                                       "patchType" "JSONPatch"
                                       "jsonPatch" (gr8s::core-object
                                                    "expression" "[JSONPatch{op: 'add', path: '/data/seen', value: object.metadata.annotations['mutated-by']}]"))))
    (let ((mutated (typed-check 201 "/api/v1/namespaces/policed/configmaps" :method :post
                     :object (typed-configmap "first" "mode" "on"))))
      (is (equal "policy" (gethash "mutated-by" (gethash "annotations" (gethash "metadata" mutated)))))
      (is (equal "policy" (gethash "seen" (gethash "data" mutated))))
      (is (equal "on" (gethash "mode" (gethash "data" mutated)))))
    (is (null (gethash "annotations"
                       (gethash "metadata" (typed-check 201 "/api/v1/namespaces/free/configmaps" :method :post
                                             :object (typed-configmap "first" "mode" "on"))))))))

(test object-construction-stays-out-of-other-cel-environments
  (signals gr8s::cel-compile-error (gr8s::compile-cel-expression "Object{spec: 1}")))

(test json-patches-can-add-into-an-unset-status
  (with-typed-http (store)
    (values store)
    (typed-namespace "patched")
    (let ((collection "/apis/resource.k8s.io/v1/namespaces/patched/resourceclaims"))
      (typed-check 201 collection :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "name" "claim")
                  "spec" (gr8s::core-object "devices" (gr8s::core-object "requests"
                    (vector (gr8s::core-object "name" "req-0" "exactly" (gr8s::core-object "deviceClassName" "example")))))))
      (let ((patched (typed-check 200 (concatenate 'string collection "/claim/status") :method :patch
                       :content-type "application/json-patch+json"
                       :object (vector (gr8s::core-object "op" "add" "path" "/status/allocation" "value" (gr8s::core-object))))))
        (is-true (hash-table-p (gethash "allocation" (gethash "status" patched))))
        ;; A whole object sent to status is checked against this ResourceClaim, not core's namesake.
        (setf (gethash "reservedFor" (gethash "status" patched)) #())
        (let ((updated (typed-check 200 (concatenate 'string collection "/claim/status") :method :put :object patched)))
          (is (equal "claim" (gethash "name" (gethash "metadata" updated))))
          (is (equal "req-0" (gethash "name" (aref (gethash "requests" (gethash "devices" (gethash "spec" updated))) 0)))))))))

(test bootstrap-cluster-roles-grant-oidc-discovery-when-bound
  (with-typed-http (store)
    (gr8s::ensure-system-cluster-roles store)
    (gr8s::ensure-system-cluster-roles store)
    (typed-check 201 "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" :method :post
      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "discover")
                "roleRef" (gr8s::core-object "apiGroup" "rbac.authorization.k8s.io" "kind" "ClusterRole"
                                             "name" "system:service-account-issuer-discovery")
                "subjects" (vector (gr8s::core-object "kind" "ServiceAccount" "name" "default" "namespace" "seen"))))
    ;; RBAC objects keep their colons on the wire as well.
    (typed-check 200 "/apis/rbac.authorization.k8s.io/v1/clusterroles/system:service-account-issuer-discovery")
    (typed-check 400 "/apis/rbac.authorization.k8s.io/v1/clusterroles/a%25b")
    (flet ((allowed (namespace)
             (gr8s::service-account-authorized-p
              store (gr8s::make-api-service-account-identity :namespace namespace :name "default" :uid "uid")
              "get" nil nil nil nil "/openid/v1/jwks")))
      (is-true (allowed "seen"))
      (is-false (allowed "unseen")))))

(test impersonation-names-the-identity-only-when-authorized
  (with-typed-http (store)
    (let ((admin (gr8s::make-api-user-identity :username "admin" :groups (vector "system:masters")))
          (nobody (gr8s::make-api-user-identity :username "nobody" :groups (vector "system:authenticated"))))
      (is (eq :allowed (if (gr8s::impersonation-allowed-p store admin "users" "" "someone") :allowed :denied)))
      (is (eq :denied (if (gr8s::impersonation-allowed-p store nobody "users" "" "someone") :allowed :denied)))
      (is (equal '("ns" "sa") (multiple-value-list (gr8s::service-account-username-parts "system:serviceaccount:ns:sa"))))
      (is (null (gr8s::service-account-username-parts "alice"))))))

(test projected-tokens-are-bound-to-their-pod-and-renewed-when-due
  (with-typed-http (store)
    (typed-namespace "projected")
    (let* ((account (typed-check 201 "/api/v1/namespaces/projected/serviceaccounts" :method :post
                      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "robot"))))
           (pod (gr8s::create-pod
                 store
                 (parse-pod "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"holder\",\"namespace\":\"projected\"},\"spec\":{\"serviceAccountName\":\"robot\",\"containers\":[{\"name\":\"c\",\"image\":\"example\"}],\"volumes\":[{\"name\":\"v\",\"projected\":{\"sources\":[{\"serviceAccountToken\":{\"path\":\"token\",\"audience\":\"reader\",\"expirationSeconds\":3600}}]}}]}}")))
           (source (first (gr8s::pod-projected-token-sources pod)))
           (delivery (gr8s::pod-projected-token-object store pod))
           (encoded (gethash (gr8s::projected-token-data-key source) (gethash "data" delivery)))
           (token (trivial-utf-8:utf-8-bytes-to-string (ag-grpc:base64-decode encoded))))
      (is (equal (gr8s::projected-token-secret-name pod) (gethash "name" (gethash "metadata" delivery))))
      ;; The agent normalizes what it receives, so the delivery must be a valid Secret.
      (is (hash-table-p (gr8s::normalize-core-resource "secrets" delivery "projected" (gr8s::projected-token-secret-name pod))))
      (multiple-value-bind (identity audiences) (gr8s::verify-service-account-jwt store token '("reader"))
        (is (equal "system:serviceaccount:projected:robot" (gr8s::api-identity-username identity)))
        (is (equal (gethash "uid" (gethash "metadata" account)) (gr8s::api-service-account-identity-uid identity)))
        (is (equal '("reader") audiences)))
      ;; Its audience is not the API's, so it cannot be used as an API credential.
      (is (null (gr8s::authenticate-service-account-token store token)))
      ;; The same token is handed out until 80% of its lifetime has passed.
      (is (equal token (gr8s::cached-projected-token store pod source)))
      (let ((entry (first (loop for value being the hash-values of (gr8s::pod-store-projected-tokens store) collect value))))
        (is (< (- 2880 10) (- (getf entry :refresh) (gr8s::unix-time-now)) (+ 2880 10))))
      (loop for key being the hash-keys of (gr8s::pod-store-projected-tokens store) using (hash-value entry)
            do (setf (getf (gethash key (gr8s::pod-store-projected-tokens store)) :refresh) 0))
      (sleep 1)
      (is (not (equal token (gr8s::cached-projected-token store pod source))))
      ;; Deleting the Pod revokes the token.
      (gr8s::remove-pod store "projected" "holder" :uid (gr8s::pod-uid pod))
      (is (null (gr8s::verify-service-account-jwt store token '("reader"))))
      (gr8s::prune-projected-tokens store)
      (is (zerop (hash-table-count (gr8s::pod-store-projected-tokens store)))))))

(test token-reviews-report-what-a-pod-bound-token-proves
  (with-typed-http (store)
    (typed-namespace "bound")
    (let* ((account (typed-check 201 "/api/v1/namespaces/bound/serviceaccounts" :method :post
                      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "robot"))))
           (token (gr8s::mint-service-account-token store account :binding (list "pod" "holder" "pod-uid")
                                                    :node (list "worker" "node-uid"))))
      ;; The Pod it names does not exist, so the binding fails closed.
      (is (null (gr8s::verify-service-account-jwt store token (list gr8s::+service-account-issuer+))))
      (let* ((free (gr8s::mint-service-account-token store account :node (list "worker" "node-uid")))
             (status (gethash "status" (typed-check 201 "/apis/authentication.k8s.io/v1/tokenreviews" :method :post
                                         :object (gr8s::core-object "spec" (gr8s::core-object "token" free)))))
             (extra (gethash "extra" (gethash "user" status))))
        (is (uiop:string-prefix-p "JTI=" (aref (gethash "authentication.kubernetes.io/credential-id" extra) 0)))
        (is (equalp #("worker") (gethash "authentication.kubernetes.io/node-name" extra)))
        (is (equalp #("node-uid") (gethash "authentication.kubernetes.io/node-uid" extra)))))))

(test watches-without-a-resource-version-start-with-the-current-state
  (with-typed-http (store)
    (values store)
    (typed-namespace "watched")
    (typed-check 201 "/api/v1/namespaces/watched/serviceaccounts" :method :post
      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "seen")))
    (multiple-value-bind (stream code)
        (drakma:http-request (format nil "http://127.0.0.1:~D/api/v1/namespaces/watched/serviceaccounts" *typed-test-port*)
                             :want-stream t :parameters '(("watch" . "true") ("timeoutSeconds" . "2")))
      (unwind-protect
           (progn
             (is (= 200 code))
             (let ((event (com.inuoe.jzon:parse (read-line stream))))
               (is (equal "ADDED" (gethash "type" event)))
               (is (equal "seen" (gethash "name" (gethash "metadata" (gethash "object" event)))))))
        (close stream)))))

(test device-taint-rules-follow-the-v1-lifecycle
  ;; GA at resource.k8s.io/v1 in Kubernetes 1.37 (DRADeviceTaintRules), with a status
  ;; subresource, generation and a server-set taint.timeAdded.
  (with-typed-http (store)
    (values store)
    (is-true (member "devicetaintrules" (typed-discovery-names "/apis/resource.k8s.io/v1") :test #'equal))
    (is-true (member "devicetaintrules/status" (typed-discovery-names "/apis/resource.k8s.io/v1") :test #'equal))
    (let* ((collection "/apis/resource.k8s.io/v1/devicetaintrules")
           (item (concatenate 'string collection "/rule"))
           (created (typed-check 201 collection :method :post
                      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "rule" "labels" (gr8s::core-object "e2e" "x"))
                                                 "spec" (gr8s::core-object "taint" (gr8s::core-object "key" "testing" "effect" "None")))))
           (added (gethash "timeAdded" (gethash "taint" (gethash "spec" created)))))
      (is (stringp added))
      (is (= 1 (gethash "generation" (gethash "metadata" created))))
      (typed-check 422 collection :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "name" "bad")
                                   "spec" (gr8s::core-object "taint" (gr8s::core-object "key" "testing" "effect" "PreferNoSchedule"))))
      (typed-check 422 collection :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "name" "bad")
                                   "spec" (gr8s::core-object "taint" (gr8s::core-object "key" "not a key" "effect" "None"))))
      ;; Changing the effect bumps the generation; the status is not writable here.
      (let ((patched (typed-check 200 item :method :patch :content-type "application/strategic-merge-patch+json"
                       :object (gr8s::core-object "spec" (gr8s::core-object "taint" (gr8s::core-object "effect" "NoExecute"))
                                                  "status" (gr8s::core-object "conditions" (vector (gr8s::core-object "type" "Ignored")))))))
        (is (= 2 (gethash "generation" (gethash "metadata" patched))))
        (is (equal "NoExecute" (gethash "effect" (gethash "taint" (gethash "spec" patched)))))
        (is (null (gethash "status" patched))))
      (let ((status (typed-check 200 (concatenate 'string item "/status") :method :patch
                      :content-type "application/strategic-merge-patch+json"
                      :object (gr8s::core-object "status" (gr8s::core-object "conditions"
                                (vector (gr8s::core-object "type" "Testing" "status" "True" "reason" "E2E"
                                                           "message" "m" "lastTransitionTime" "2026-01-01T00:00:00Z")))))))
        (is (equal "Testing" (gethash "type" (aref (gethash "conditions" (gethash "status" status)) 0))))
        (is (= 2 (gethash "generation" (gethash "metadata" status)))))
      (typed-check 200 (concatenate 'string collection "?labelSelector=e2e=x") :method :delete)
      (typed-check 404 item))))

(test storage-version-migrations-keep-their-spec-immutable
  ;; GA at storagemigration.k8s.io/v1 in Kubernetes 1.37 (StorageVersionMigrator).
  (with-typed-http (store)
    (values store)
    (is (equal "storagemigration.k8s.io" (gethash "name" (typed-check 200 "/apis/storagemigration.k8s.io"))))
    (is-true (member "storageversionmigrations/status"
                     (typed-discovery-names "/apis/storagemigration.k8s.io/v1") :test #'equal))
    (let* ((collection "/apis/storagemigration.k8s.io/v1/storageversionmigrations")
           (item (concatenate 'string collection "/migrate"))
           (created (typed-check 201 collection :method :post
                      :object (gr8s::core-object "metadata" (gr8s::core-object "name" "migrate")
                                                 "spec" (gr8s::core-object "resource" (gr8s::core-object "group" "" "resource" "foo"))))))
      (typed-check 422 collection :method :post
        :object (gr8s::core-object "metadata" (gr8s::core-object "name" "empty")
                                   "spec" (gr8s::core-object "resource" (gr8s::core-object "group" "apps"))))
      (let ((changed (gr8s::copy-core-object created)))
        (setf (gethash "resource" (gethash "resource" (gethash "spec" changed))) "bar")
        (typed-check 422 item :method :put :object changed))
      (let ((labelled (typed-check 200 item :method :patch :content-type "application/json-patch+json"
                        :object (vector (gr8s::core-object "op" "add" "path" "/metadata/labels"
                                                           "value" (gr8s::core-object "test" "test"))))))
        (is (equal "test" (gethash "test" (gethash "labels" (gethash "metadata" labelled))))))
      (let ((status (typed-check 200 (concatenate 'string item "/status") :method :patch
                      :content-type "application/merge-patch+json"
                      :object (gr8s::core-object "status" (gr8s::core-object "conditions"
                                (vector (gr8s::core-object "type" "TestCondition" "status" "True" "reason" "TestReason"
                                                           "message" "m" "lastTransitionTime" "2026-01-01T00:00:00Z")))))))
        (is (equal "TestCondition" (gethash "type" (aref (gethash "conditions" (gethash "status" status)) 0)))))
      (typed-check 200 item :method :delete)
      (typed-check 404 item))))
