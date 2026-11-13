;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate durable Namespace, ServiceAccount and RBAC API objects used to
;;;; bootstrap in-cluster clients. Storage transactions, optimistic revisions
;;;; and HTTP patch semantics are shared with the core resource implementation.

(in-package #:gr8s.resources)

(defun bootstrap-string-array (value context &key nonempty)
  "Validate a JSON array of strings and optionally require at least one item."
  (unless (and (vectorp value) (not (stringp value))
               (or (not nonempty) (plusp (length value)))
               (every (lambda (item) (and (stringp item) (plusp (length item)))) value))
    (core-resource-error 422 "Invalid" "~A must be an array of nonempty strings" context))
  value)

(defun validate-rbac-rules (rules cluster-p)
  "Validate resource and nonresource RBAC policy rule shapes."
  (unless (and (vectorp rules) (not (stringp rules)))
    (core-resource-error 422 "Invalid" "rules must be an array"))
  (loop for rule across rules
        do (require-object rule "rule")
           (reject-unsupported-fields rule '("verbs" "apiGroups" "resources" "resourceNames" "nonResourceURLs") "rule")
           (bootstrap-string-array (gethash "verbs" rule) "rule.verbs" :nonempty t)
           (if (gethash "nonResourceURLs" rule)
               (progn
                 (unless cluster-p (core-resource-error 422 "Invalid" "Roles cannot grant nonResourceURLs"))
                 (when (or (gethash "resources" rule) (gethash "apiGroups" rule) (gethash "resourceNames" rule))
                   (core-resource-error 422 "Invalid" "Nonresource rules cannot contain resource fields"))
                 (bootstrap-string-array (gethash "nonResourceURLs" rule) "rule.nonResourceURLs" :nonempty t)
                 (loop for url across (gethash "nonResourceURLs" rule)
                       ;; A lone * is how upstream's cluster-admin grants every URL.
                       unless (or (equal url "*") (and (plusp (length url)) (char= #\/ (char url 0))))
                         do (core-resource-error 422 "Invalid" "nonResourceURLs must begin with /")))
               (progn
                 (bootstrap-string-array (gethash "resources" rule) "rule.resources" :nonempty t)
                 (let ((groups (gethash "apiGroups" rule)))
                   (unless (and (vectorp groups) (not (stringp groups)) (plusp (length groups))
                                (every #'stringp groups))
                     (core-resource-error 422 "Invalid" "rule.apiGroups must be a nonempty string array")))
                 (when (gethash "resourceNames" rule)
                   (bootstrap-string-array (gethash "resourceNames" rule) "rule.resourceNames"))))))

(defun default-rbac-api-group (object group)
  "Apply Kubernetes string defaulting without treating a supplied nonstring as empty."
  (multiple-value-bind (value present) (gethash "apiGroup" object)
    (when (or (not present) (eq value 'null) (equal value ""))
      (setf (gethash "apiGroup" object) group))))

(defun validate-rbac-binding (object cluster-p)
  "Validate binding role references and subject identities."
  (let* ((ref (require-object (gethash "roleRef" object) "roleRef"))
         (subjects (gethash "subjects" object #())))
    (default-rbac-api-group ref "rbac.authorization.k8s.io")
    (unless (and (equal "rbac.authorization.k8s.io" (gethash "apiGroup" ref))
                 (member (gethash "kind" ref) (if cluster-p '("ClusterRole") '("Role" "ClusterRole")) :test #'equal)
                 (path-segment-name-p (gethash "name" ref)))
      (core-resource-error 422 "Invalid" "Invalid roleRef"))
    (unless (and (vectorp subjects) (not (stringp subjects)))
      (core-resource-error 422 "Invalid" "subjects must be an array"))
    (loop for subject across subjects
          for kind = (gethash "kind" (require-object subject "subject"))
          do (unless (member kind '("User" "Group" "ServiceAccount") :test #'equal)
               (core-resource-error 422 "Invalid" "Invalid subject kind"))
             (require-nonempty-string (gethash "name" subject) "subject.name")
             (default-rbac-api-group subject (if (equal kind "ServiceAccount") "" "rbac.authorization.k8s.io"))
             (if (equal kind "ServiceAccount")
                 (unless (and (dns-subdomain-p (gethash "name" subject))
                              (or (not cluster-p) (dns-label-p (gethash "namespace" subject)))
                              (equal "" (gethash "apiGroup" subject "")))
                   (core-resource-error 422 "Invalid" "Invalid ServiceAccount subject"))
                 (unless (equal "rbac.authorization.k8s.io" (gethash "apiGroup" subject))
                   (core-resource-error 422 "Invalid" "User and Group subjects require the RBAC apiGroup"))))))

(defun validate-gateway-port (value context)
  "Validate a Gateway listener/port number is an integer in 1..65535."
  (unless (and (integerp value) (<= 1 value 65535))
    (core-resource-error 422 "Invalid" "~A must be a port number in 1..65535" context)))

(defun validate-gateway-resource (resource object)
  "Validate a gateway.networking.k8s.io/v1 object's spec against the subset of
   the Gateway API gr8s implements. Fails closed (422) on missing required
   fields or malformed shapes; the spec is otherwise stored as supplied."
  (let ((spec (gethash "spec" object)))
    (unless (hash-table-p spec)
      (core-resource-error 422 "Invalid" "~A spec must be an object"
                           (core-resource-kind resource)))
    (cond
      ((equal resource "gatewayclasses")
       (require-nonempty-string (gethash "controllerName" spec) "spec.controllerName"))
      ((equal resource "gateways")
       (require-nonempty-string (gethash "gatewayClassName" spec) "spec.gatewayClassName")
       (let ((listeners (gethash "listeners" spec)))
         (unless (and (vectorp listeners) (not (stringp listeners)) (plusp (length listeners)))
           (core-resource-error 422 "Invalid" "spec.listeners must be a nonempty array"))
         (loop for listener across listeners
               do (require-object listener "listener")
                  (require-nonempty-string (gethash "name" listener) "listener.name")
                  (require-nonempty-string (gethash "protocol" listener) "listener.protocol")
                  (validate-gateway-port (gethash "port" listener) "listener.port"))))
      ((member resource '("httproutes" "tcproutes" "tlsroutes" "grpcroutes") :test #'equal)
       (let ((rules (gethash "rules" spec)))
         (when rules
           (unless (and (vectorp rules) (not (stringp rules)))
             (core-resource-error 422 "Invalid" "spec.rules must be an array"))
           (loop for rule across rules do (require-object rule "rule"))))
       (let ((hostnames (gethash "hostnames" spec)))
         (when hostnames
           (bootstrap-string-array hostnames "spec.hostnames")))))))

(defun validate-cert-manager-resource (resource object)
  "Validate a cert-manager.io/v1 object against the subset gr8s implements. Fails
   closed (422) on unsupported issuer types or missing required fields."
  (let ((spec (gethash "spec" object)))
    (unless (hash-table-p spec)
      (core-resource-error 422 "Invalid" "~A spec must be an object"
                           (core-resource-kind resource)))
    (cond
      ((member resource '("issuers" "clusterissuers") :test #'equal)
       (let ((configured (loop for key in '("selfSigned" "ca" "acme" "vault" "venafi")
                               when (nth-value 1 (gethash key spec)) collect key)))
         (unless (= 1 (length configured))
           (core-resource-error 422 "Invalid" "Issuer spec must configure exactly one issuer type"))
         (let ((type (first configured)))
           (cond
             ((equal type "selfSigned")
              (require-object (gethash "selfSigned" spec) "spec.selfSigned"))
             ((equal type "ca")
              (let ((ca (require-object (gethash "ca" spec) "spec.ca")))
                (require-nonempty-string (gethash "secretName" ca) "spec.ca.secretName")))
             (t (core-resource-error 422 "Invalid" "Issuer type ~A is not implemented" type))))))
      ((equal resource "certificates")
       (require-nonempty-string (gethash "secretName" spec) "spec.secretName")
       (let ((ref (require-object (gethash "issuerRef" spec) "spec.issuerRef")))
         (require-nonempty-string (gethash "name" ref) "spec.issuerRef.name"))
       (let ((dns-names (gethash "dnsNames" spec))
             (common-name (gethash "commonName" spec)))
         (when dns-names (bootstrap-string-array dns-names "spec.dnsNames"))
         (unless (or (and dns-names (plusp (length dns-names)))
                     (and (stringp common-name) (plusp (length common-name))))
           (core-resource-error 422 "Invalid"
                                "Certificate requires spec.commonName or a nonempty spec.dnsNames"))))
      ((equal resource "certificaterequests")
       (let ((ref (require-object (gethash "issuerRef" spec) "spec.issuerRef")))
         (require-nonempty-string (gethash "name" ref) "spec.issuerRef.name"))))))

;;; ClusterTrustBundle validation, as pkg/apis/certificates/validation does it at v1.37.

(defconstant +cluster-trust-bundle-max-size+ (* 1024 1024)
  "certificates.MaxTrustBundleSize: the largest spec.trustBundle accepted.")

(defun cluster-trust-bundle-invalid (control &rest arguments)
  "Reject a ClusterTrustBundle with upstream's wording."
  (core-resource-error 422 "Invalid" "ClusterTrustBundle ~?" control arguments))

(defun validate-cluster-trust-bundle-name (name signer)
  "ValidateClusterTrustBundleName: a signer-linked bundle is named <signerName with
   / as :>:<DNS subdomain>; any other has no colon and is a DNS subdomain."
  (if (zerop (length signer))
      (progn
        (when (find #\: name)
          (cluster-trust-bundle-invalid "metadata.name: Invalid value: ~S: ClusterTrustBundle without signer name must not have \":\" in its name" name))
        (unless (dns-subdomain-p name)
          (cluster-trust-bundle-invalid "metadata.name: Invalid value: ~S: must be a DNS subdomain" name)))
      (let ((prefix (concatenate 'string (substitute #\: #\/ signer) ":")))
        (unless (uiop:string-prefix-p prefix name)
          (cluster-trust-bundle-invalid "metadata.name: Invalid value: ~S: ClusterTrustBundle for signerName ~A must be named with prefix ~A"
                                        name signer prefix))
        (unless (dns-subdomain-p (subseq name (length prefix)))
          (cluster-trust-bundle-invalid "metadata.name: Invalid value: ~S: the part after ~A must be a DNS subdomain" name prefix)))))

(defun validate-cluster-trust-bundle-anchors (bundle)
  "validateTrustBundle: only header-free CERTIFICATE blocks that parse as X.509 CA
   certificates, at least one of them and none twice."
  (unless (stringp bundle)
    (cluster-trust-bundle-invalid "spec.trustBundle: Required value"))
  (when (> (length (trivial-utf-8:string-to-utf-8-bytes bundle)) +cluster-trust-bundle-max-size+)
    (cluster-trust-bundle-invalid "spec.trustBundle: Too long: may not be more than ~D bytes" +cluster-trust-bundle-max-size+))
  (let ((blocks (handler-case (csr-pem-blocks (trivial-utf-8:string-to-utf-8-bytes bundle))
                  (kubernetes-error (condition)
                    (cluster-trust-bundle-invalid "spec.trustBundle: Invalid value: \"<value omitted>\": ~A"
                                                  (kubernetes-error-message condition)))))
        (seen nil))
    (loop for (label . der) in blocks for index from 0
          do (unless (equal label "CERTIFICATE")
               (cluster-trust-bundle-invalid "spec.trustBundle: Invalid value: \"<value omitted>\": entry ~D has bad block type: ~A" index label))
             (let ((certificate (handler-case (if (der-well-formed-p der)
                                                  (pure-tls::parse-certificate der)
                                                  (error "Malformed DER"))
                                  (error () (cluster-trust-bundle-invalid "spec.trustBundle: Invalid value: \"<value omitted>\": entry ~D does not parse as X.509" index)))))
               (unless (pure-tls::certificate-is-ca-p certificate)
                 (cluster-trust-bundle-invalid "spec.trustBundle: Invalid value: \"<value omitted>\": entry ~D does not have the CA bit set" index)))
             (when (member der seen :test #'equalp)
               (cluster-trust-bundle-invalid "spec.trustBundle: Invalid value: \"<value omitted>\": duplicate trust anchor (entry ~D)" index))
             (push der seen))
    (unless seen
      (cluster-trust-bundle-invalid "spec.trustBundle: Invalid value: \"<value omitted>\": at least one trust anchor must be provided"))))

(defun validate-cluster-trust-bundle (object existing)
  "ValidateClusterTrustBundle and, for an update, ValidateClusterTrustBundleUpdate:
   the name matches the signer, the signer is well formed and immutable, and the
   bundle holds only CA certificates (reparsed only when an update changes it)."
  (let* ((spec (or (gethash "spec" object) (core-object)))
         (signer (let ((value (gethash "signerName" spec))) (if (stringp value) value "")))
         (old-spec (and existing (gethash "spec" existing (core-object)))))
    (let ((name (gethash "name" (gethash "metadata" object))))
      ;; A generated name is checked once it exists.
      (when (and (stringp name) (plusp (length name)))
        (validate-cluster-trust-bundle-name name signer)))
    (when (plusp (length signer))
      (handler-case (validate-csr-signer-name signer)
        (kubernetes-error ()
          (cluster-trust-bundle-invalid "spec.signerName: Invalid value: ~S: must be a fully qualified domain and path of the form 'example.com/signer-name'" signer))))
    (when old-spec
      (unless (equal signer (let ((value (gethash "signerName" old-spec))) (if (stringp value) value "")))
        (cluster-trust-bundle-invalid "spec.signerName: Invalid value: ~S: field is immutable" signer)))
    (unless (and old-spec (equal (gethash "trustBundle" spec) (gethash "trustBundle" old-spec)))
      (validate-cluster-trust-bundle-anchors (gethash "trustBundle" spec)))))

(defun normalize-bootstrap-resource (resource input namespace name &optional store)
  "Copy, validate and default an implemented bootstrap API object."
  (when (workload-resource-p resource)
    (return-from normalize-bootstrap-resource (normalize-workload-resource resource input namespace name)))
  (when (equal resource "controllerrevisions")
    (return-from normalize-bootstrap-resource (normalize-controller-revision input namespace name)))
  (when (equal resource "events")
    (return-from normalize-bootstrap-resource (normalize-event-resource input namespace name)))
  (when (equal resource "services")
    (return-from normalize-bootstrap-resource (normalize-service-resource input namespace name store)))
  (when (equal resource "podtemplates")
    (return-from normalize-bootstrap-resource (normalize-podtemplate input namespace name)))
  (when (equal resource "podcertificaterequests")
    (return-from normalize-bootstrap-resource (normalize-pod-certificate-request input namespace name store)))
  (let* ((object (copy-core-object (require-object input "resource")))
         (kind (core-resource-kind resource))
         (version (core-resource-api-version resource))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (fields (cond ((equal resource "namespaces") '("spec" "status"))
                       ((equal resource "serviceaccounts") '("secrets" "imagePullSecrets" "automountServiceAccountToken"))
                       ((equal resource "roles") '("rules"))
                       ((equal resource "clusterroles") '("rules" "aggregationRule"))
                       ((equal resource "networkpolicies") '("spec"))
                       ((equal resource "gatewayclasses") '("spec" "status"))
                       ((member resource '("gateways" "httproutes"
                                           "tcproutes" "tlsroutes" "grpcroutes") :test #'equal)
                        '("spec" "status"))
                       ((member resource '("issuers" "clusterissuers"
                                           "certificates" "certificaterequests") :test #'equal)
                        '("spec" "status"))
                       ;; ClusterTrustBundle carries only a spec (signerName +
                       ;; trustBundle PEM); it has no status subresource.
                       ((equal resource "clustertrustbundles") '("spec"))
                       ;; PodCertificateRequest: spec from the node, status
                       ;; (certificateChain + conditions) from the signer.
                       ((equal resource "podcertificaterequests") '("spec" "status"))
                       (t '("roleRef" "subjects")))))
    (unless (and (equal version (gethash "apiVersion" object version))
                 (equal kind (gethash "kind" object kind)))
      (core-resource-error 400 "BadRequest" "Expected ~A ~A" version kind))
    (reject-unsupported-fields object (append '("apiVersion" "kind" "metadata") fields) kind)
    (validate-core-metadata metadata namespace name :allow-finalizers t
                            :name-test (when (or (rbac-resource-p resource)
                                                 ;; KEP-3257 signer-linked names carry colons.
                                                 (equal resource "clustertrustbundles"))
                                         #'path-segment-name-p))
    (setf (gethash "kind" object) kind (gethash "apiVersion" object) version)
    (if namespace (setf (gethash "namespace" metadata) namespace) (remhash "namespace" metadata))
    (cond
      ((equal resource "namespaces")
       (unless (dns-label-p (gethash "name" metadata))
         (core-resource-error 422 "Invalid" "Namespace name must be a DNS label"))
       (let ((spec (gethash "spec" object (core-object))))
         (reject-unsupported-fields spec '("finalizers") "Namespace.spec")
         (when (gethash "finalizers" spec)
           (bootstrap-string-array (gethash "finalizers" spec) "spec.finalizers"))
         (setf (gethash "spec" object) spec)
         (normalize-namespace-lifecycle
          object (and name store (gethash (core-resource-key "namespaces" nil name) (pod-store-resources store))))))
      ((equal resource "serviceaccounts")
       (multiple-value-bind (automount present) (gethash "automountServiceAccountToken" object)
         (when (and present (not (member automount '(t nil))))
           (core-resource-error 422 "Invalid" "automountServiceAccountToken must be boolean")))
       (dolist (field '("secrets" "imagePullSecrets"))
         (let ((refs (gethash field object #())))
           (unless (and (vectorp refs) (not (stringp refs)))
             (core-resource-error 422 "Invalid" "~A must be an array" field))
           (loop for ref across refs
                 unless (dns-subdomain-p (gethash "name" (require-object ref field)))
                   do (core-resource-error 422 "Invalid" "~A references require valid names" field)))))
      ((member resource '("roles" "clusterroles") :test #'equal)
       (when (eq 'null (gethash "rules" object)) (remhash "rules" object))
       (validate-rbac-rules (gethash "rules" object #()) (equal resource "clusterroles"))
       (confirm-rbac-role-grant-authorized store *authenticated-api-identity*
                                           (gethash "rules" object #())
                                           (equal resource "clusterroles") name namespace)
       (when (equal resource "clusterroles") (validate-cluster-role-aggregation-rule object)))
      ((equal resource "networkpolicies")
       ;; Validated as upstream's API does; the agent parses what it enforces into an np-spec.
       (let ((spec (gethash "spec" object)))
         (when (and spec (not (hash-table-p spec)))
           (core-resource-error 422 "Invalid" "NetworkPolicy spec must be an object"))
         ;; Upstream defaults a request as it decodes it, before validating it.
         (when spec
           (default-network-policy-spec spec)
           (validate-network-policy-spec spec))))
      ((member resource '("gatewayclasses" "gateways" "httproutes"
                          "tcproutes" "tlsroutes" "grpcroutes") :test #'equal)
       (validate-gateway-resource resource object))
      ((member resource '("issuers" "clusterissuers" "certificates" "certificaterequests")
               :test #'equal)
       (validate-cert-manager-resource resource object))
      ((equal resource "clustertrustbundles")
       (let ((spec (gethash "spec" object)))
         (when (and spec (not (hash-table-p spec)))
           (core-resource-error 422 "Invalid" "ClusterTrustBundle spec must be an object"))
         (validate-cluster-trust-bundle
          object (and name store (gethash (core-resource-key "clustertrustbundles" nil name)
                                          (pod-store-resources store))))))
      ((equal resource "podcertificaterequests")
       (let ((spec (gethash "spec" object)))
         (unless (hash-table-p spec)
           (core-resource-error 422 "Invalid" "PodCertificateRequest spec must be an object"))
         (unless (and (stringp (gethash "signerName" spec)) (plusp (length (gethash "signerName" spec))))
           (core-resource-error 422 "Invalid" "PodCertificateRequest spec.signerName is required"))))
      (t (validate-rbac-binding object (equal resource "clusterrolebindings"))
         (confirm-rbac-binding-authorized store *authenticated-api-identity*
                                          object (equal resource "clusterrolebindings") namespace)))
    object))

(defparameter *resource-discovery-names*
  '(("pods" ("po") ("all"))
    ("nodes" ("no"))
    ("namespaces" ("ns"))
    ("serviceaccounts" ("sa"))
    ("configmaps" ("cm"))
    ("services" ("svc") ("all"))
    ("endpoints" ("ep"))
    ("events" ("ev"))
    ("limitranges" ("limits"))
    ("persistentvolumes" ("pv"))
    ("persistentvolumeclaims" ("pvc"))
    ("replicationcontrollers" ("rc") ("all"))
    ("resourcequotas" ("quota"))
    ("deployments" ("deploy") ("all"))
    ("replicasets" ("rs") ("all"))
    ("daemonsets" ("ds") ("all"))
    ("statefulsets" ("sts") ("all"))
    ("jobs" () ("all"))
    ("cronjobs" ("cj") ("all"))
    ("componentstatuses" ("cs") ())
    ("horizontalpodautoscalers" ("hpa") ("all"))
    ("poddisruptionbudgets" ("pdb"))
    ("certificatesigningrequests" ("csr"))
    ("ingresses" ("ing"))
    ("ipaddresses" ("ip"))
    ("networkpolicies" ("netpol"))
    ("storageclasses" ("sc"))
    ("volumeattributesclasses" ("vac"))
    ("priorityclasses" ("pc"))
    ("customresourcedefinitions" ("crd" "crds") ("api-extensions"))
    ("apiservices" () ("api-extensions"))
    ("mutatingwebhookconfigurations" () ("api-extensions"))
    ("validatingwebhookconfigurations" () ("api-extensions"))
    ("validatingadmissionpolicies" () ("api-extensions"))
    ("validatingadmissionpolicybindings" () ("api-extensions"))
    ("mutatingadmissionpolicies" () ("api-extensions"))
    ("mutatingadmissionpolicybindings" () ("api-extensions"))
    ;; These two projects install as CRDs elsewhere; the names come from their manifests.
    ("gatewayclasses" ("gc") ("gateway-api"))
    ("gateways" ("gtw") ("gateway-api"))
    ("httproutes" () ("gateway-api"))
    ("tcproutes" () ("gateway-api"))
    ("tlsroutes" () ("gateway-api"))
    ("grpcroutes" () ("gateway-api"))
    ("issuers" () ("cert-manager"))
    ("clusterissuers" () ("cert-manager"))
    ("certificates" ("cert" "certs") ("cert-manager"))
    ("certificaterequests" ("cr" "crs") ("cert-manager")))
  "Each entry: resource, short names, categories, as Kubernetes v1.36 publishes them in
api/discovery. Clients resolve `kubectl get ns` and `kubectl get all` through these alone.")

(defun resource-discovery-entry (resource singular namespaced kind verbs)
  "Describe a top-level collection, leaving out empty short names and categories as upstream does."
  (let ((entry (core-object "name" resource "singularName" singular "namespaced" namespaced "kind" kind "verbs" verbs)))
    (destructuring-bind (&optional short-names categories) (rest (assoc resource *resource-discovery-names* :test #'equal))
      (when short-names (setf (gethash "shortNames" entry) (coerce short-names 'vector)))
      (when categories (setf (gethash "categories" entry) (coerce categories 'vector))))
    entry))

(defun core-resource-delete-collection-p (resource)
  "Report whether DELETE on RESOURCE's collection URL is served."
  (or (csr-resource-p resource) (storage-resource-p resource) (endpointslice-resource-p resource)
      (batch-resource-p resource) (budget-resource-p resource) (admission-config-resource-p resource)
      (policy-resource-p resource) (typed-api-resource-p resource) (networking-resource-p resource)
      (member resource '("configmaps" "secrets" "serviceaccounts" "roles" "rolebindings" "clusterroles" "clusterrolebindings"
                         "networkpolicies" "services" "podtemplates" "events" "horizontalpodautoscalers" "deployments"
                         "replicasets" "replicationcontrollers" "daemonsets" "statefulsets" "controllerrevisions"
                         "customresourcedefinitions" "clustertrustbundles" "podcertificaterequests")
              :test #'equal)))

(defun stored-resource-discovery (version)
  "Describe implemented durable collections in API VERSION for discovery."
  (coerce
   (loop for (resource kind api-version namespaced) in *stored-resource-types*
         when (equal api-version version)
           collect (resource-discovery-entry
                    resource (string-downcase kind) namespaced kind
                    (if (core-resource-delete-collection-p resource)
                        #("create" "delete" "deletecollection" "get" "list" "patch" "update" "watch")
                        #("create" "delete" "get" "list" "patch" "update" "watch"))))
   'vector))

(defun rbac-api-group ()
  "Describe the implemented rbac.authorization.k8s.io API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "rbac.authorization.k8s.io"
               "versions" (vector (core-object "groupVersion" "rbac.authorization.k8s.io/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "rbac.authorization.k8s.io/v1" "version" "v1")))

(defun rbac-resources-response ()
  "Return discovery for the supported RBAC v1 resource collections."
  (json-response
   (core-object "apiVersion" "v1" "kind" "APIResourceList"
                "groupVersion" "rbac.authorization.k8s.io/v1"
                "resources" (stored-resource-discovery "rbac.authorization.k8s.io/v1"))))

(defun native-node-architecture ()
  "Return the Kubernetes architecture name of this native executable."
  (cond ((member :x86-64 *features*) "amd64")
        ((member :arm64 *features*) "arm64")
        (t (string-downcase (machine-type)))))

(defun node-resource-list (node &key allocatable)
  "Return a fresh list of NODE's measured and advertised resources."
  (let ((list (core-object)))
    (dolist (source (list (if allocatable (or (node-record-allocatable node) (node-record-capacity node))
                             (node-record-capacity node)) (node-record-extended-resources node)))
      (when source
        (maphash (lambda (name value) (setf (gethash name list) value)) source)))
    list))

(defun node-pressure-condition (type pressured true-reason false-reason)
  "A kubelet node-pressure condition (MemoryPressure/DiskPressure/PIDPressure):
True with TRUE-REASON when the agent reports PRESSURED, False with FALSE-REASON
otherwise, matching the reasons upstream kubelet uses."
  (core-object "type" type
               "status" (if pressured "True" "False")
               "reason" (if pressured true-reason false-reason)))

(defun node-api-object (node)
  "Serialize a registered worker with readiness taken from its live lease."
  (let ((address (node-reported-address node)))
    (core-object
     "apiVersion" "v1" "kind" "Node"
     "metadata" (let ((metadata (core-object "name" (node-record-name node) "uid" (node-record-id node)
                                             "resourceVersion" (node-record-resource-version node)
                                             "labels" (node-labels node))))
                  (when (node-record-creation-timestamp node)
                    (setf (gethash "creationTimestamp" metadata) (node-record-creation-timestamp node)))
                  (when (node-record-annotations node)
                    (setf (gethash "annotations" metadata) (copy-core-object (node-record-annotations node))))
                  metadata)
     "spec" (let ((spec (core-object "unschedulable" (not (null (node-record-unschedulable node))))))
              (when (plusp (length (node-record-pod-cidr node)))
                (setf (gethash "podCIDR" spec) (node-record-pod-cidr node)
                      (gethash "podCIDRs" spec) (copy-seq (node-record-all-pod-cidrs node))))
              (when (plusp (length (node-record-taints node)))
                (setf (gethash "taints" spec) (copy-core-object (node-record-taints node))))
              spec)
     "status" (or
               (and (node-record-api-only node)
                    (copy-core-object (or (node-record-api-status node) (core-object))))
               (core-object
               "conditions" (vector (if (and (node-record-ready-p node) (node-record-runtime-down-message node))
                                        (core-object "type" "Ready" "status" "False" "reason" "KubeletNotReady"
                                                     "message" (node-record-runtime-down-message node))
                                        (core-object "type" "Ready"
                                                     "status" (if (node-record-ready-p node) "True" "False")
                                                     "reason" (if (node-record-ready-p node) "AgentReady" "AgentNotReady")
                                                     "message" "Readiness follows the gr8s node session lease"))
                                    ;; The standard kubelet pressure conditions, driven by the
                                    ;; agent's last heartbeat so a pressured node is visible and
                                    ;; avoidable rather than silently Ready.
                                    (node-pressure-condition "MemoryPressure" (node-record-memory-pressure node)
                                                             "KubeletHasInsufficientMemory" "KubeletHasSufficientMemory")
                                    (node-pressure-condition "DiskPressure" (node-record-disk-pressure node)
                                                             "KubeletHasDiskPressure" "KubeletHasNoDiskPressure")
                                    (node-pressure-condition "PIDPressure" (node-record-pid-pressure node)
                                                             "KubeletHasInsufficientPID" "KubeletHasSufficientPID"))
               "addresses" (if (and address (plusp (length address)))
                               (vector (core-object "type" "InternalIP" "address" address)) #())
               "daemonEndpoints" (core-object "kubeletEndpoint" (core-object "Port" (node-record-kubelet-port node)))
               "capacity" (node-resource-list node)
               "allocatable" (node-resource-list node :allocatable t)
               "nodeInfo" (core-object "operatingSystem" "linux" "architecture" (native-node-architecture)
                                        "kubeletVersion" (kubernetes-git-version)))))))

(defun node-write-input (node method)
  "Return the requested Node object from a typed or JSON PUT, or a patch applied to NODE's view."
  (if (eq method :put)
      (core-resource-request-object "Node")
      (let* ((content-type (request-media-type))
             (apply-patch (equal content-type "application/apply-patch+yaml"))
             (patch (unless apply-patch (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t))))
             (current (node-api-object node)))
        (cond (apply-patch
               (let ((*apply-update-manager* nil))
                 (apply-merge current (apply-read-configuration "nodes" nil (gethash "name" (gethash "metadata" current)))
                              "nodes" (apply-field-manager) (apply-force-p))))
              ((equal content-type "application/json-patch+json") (apply-core-json-patch current patch))
              ((member content-type '("application/merge-patch+json" "application/strategic-merge-patch+json") :test #'equal)
               (merge-json-object current (require-object patch "patch")))
              (t (core-resource-error 415 "UnsupportedMediaType" "Unsupported Node patch format"))))))

(defun validate-node-write (input node)
  "Refuse Node changes gr8s could not enforce, and return the requested labels and annotations."
  (let* ((metadata (require-object (gethash "metadata" input) "metadata"))
         (spec (gethash "spec" input (core-object)))
         (labels (gethash "labels" metadata))
         (annotations (gethash "annotations" metadata))
         (builtin (node-builtin-labels node))
         (custom (core-object)))
    (unless (equal "Node" (gethash "kind" input "Node")) (core-resource-error 400 "BadRequest" "Expected v1 Node"))
    (when (and (gethash "name" metadata) (not (equal (node-record-name node) (gethash "name" metadata))))
      (core-resource-error 400 "BadRequest" "metadata.name does not match the request name"))
    (when (and (gethash "uid" metadata) (not (equal (node-record-id node) (gethash "uid" metadata))))
      (core-resource-error 409 "Conflict" "metadata.uid does not match the stored Node"))
    (validate-node-taints spec)
    (when (and (gethash "podCIDR" spec) (not (equal (gethash "podCIDR" spec) (node-record-pod-cidr node))))
      (core-resource-error 422 "Invalid" "spec.podCIDR is immutable"))
    (when (member labels '(nil null)) (setf labels (core-object)))
    (when (member annotations '(nil null)) (setf annotations (core-object)))
    (validate-core-metadata (core-object "name" "node" "labels" labels "annotations" annotations) nil nil)
    (maphash (lambda (key value)
               (unless (equal value (gethash key labels))
                 (core-resource-error 422 "Invalid" "Node label ~A is derived from the node and cannot change" key)))
             builtin)
    (maphash (lambda (key value) (unless (nth-value 1 (gethash key builtin)) (setf (gethash key custom) value))) labels)
    (values custom annotations)))

(defun node-write-taints (input current)
  "Return INPUT's taints as stored, keeping the time a surviving taint was added."
  (let* ((spec (gethash "spec" input (core-object)))
         (requested (let ((value (gethash "taints" spec))) (if (member value '(nil null)) #() value))))
    (map 'vector
         (lambda (taint)
           (let ((copy (copy-core-object taint))
                 (old (find-if (lambda (existing)
                                 (and (equal (gethash "key" existing) (gethash "key" taint))
                                      (equal (gethash "effect" existing) (gethash "effect" taint))))
                               (node-record-taints current))))
             (when (and old (gethash "timeAdded" old)) (setf (gethash "timeAdded" copy) (gethash "timeAdded" old)))
             (when (and (equal "NoExecute" (gethash "effect" copy)) (not (gethash "timeAdded" copy)))
               (setf (gethash "timeAdded" copy) (current-timestamp)))
             copy))
         requested)))

(defun write-node-response (store name method)
  "Apply a Node update or patch to its durable labels and annotations."
  (let* ((node (get-node store name)) (input (require-object (node-write-input node method) "Node"))
         (expected (gethash "resourceVersion" (require-object (gethash "metadata" input) "metadata")))
         (dry-run (core-resource-dry-run-p)))
    (multiple-value-bind (labels annotations) (validate-node-write input node)
      (json-response
       (node-api-object
        (with-store-lock (store)
          (let ((current (get-node-unlocked store name)))
            (unless (and current (equal (node-record-id current) (node-record-id node)))
              (core-resource-error 409 "Conflict" "The Node was replaced"))
            (when (and (stringp expected) (plusp (length expected))
                       (not (equal expected (node-record-resource-version current))))
              (core-resource-error 409 "Conflict" "The Node was modified; apply your changes to the latest version"))
            (let ((updated (copy-node-record current)))
              (setf (node-record-labels updated) (copy-core-object labels)
                    (node-record-annotations updated) (copy-core-object annotations)
                    (node-record-taints updated) (node-write-taints input current)
                    (node-record-unschedulable updated)
                    (eq t (gethash "unschedulable" (gethash "spec" input (core-object)))))
              (cond
                ((and (workload-equal-p labels (or (node-record-labels current) (core-object)))
                      (workload-equal-p annotations (or (node-record-annotations current) (core-object)))
                      (workload-equal-p (node-record-taints updated) (node-record-taints current))
                      (eq (node-record-unschedulable updated) (node-record-unschedulable current)))
                 current)
                (dry-run updated)
                (t
                 (let ((old (node-api-object current)))
                   (persist-node store updated)
                   ;; Other holders keep this record, as with readiness updates.
                   (setf (node-record-labels current) (node-record-labels updated)
                         (node-record-annotations current) (node-record-annotations updated)
                         (node-record-taints current) (node-record-taints updated)
                         (node-record-unschedulable current) (node-record-unschedulable updated))
                   (publish-node-change-unlocked store old current)
                   (note-node-desired-change store current)   ; desired API write (8ia.4)
                   current)))))))))))

(defun nodes-api-response (store &optional name)
  "Return the actual registered worker list, a watch of it, or one node by NAME."
  (cond
    (name (json-response (node-api-object (get-node store name))))
    ((true-parameter-p (hunchentoot:parameter "watch")) (node-watch-response store))
    (t (json-response (node-list-page store (hunchentoot:parameter "labelSelector")
                                      (hunchentoot:parameter "fieldSelector"))))))
