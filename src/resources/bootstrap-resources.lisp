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

(defun ipv4-literal-octets (string)
  "The four octets of dotted-quad STRING, or NIL. Strict like Go's net.ParseIP:
   no leading zeros, no fewer or more than four parts."
  (let ((parts (uiop:split-string string :separator ".")))
    (when (and (= 4 (length parts))
               (every (lambda (part)
                        (and (<= 1 (length part) 3) (every #'digit-char-p part)
                             (or (= 1 (length part)) (char/= #\0 (char part 0)))
                             (<= (parse-integer part) 255)))
                      parts))
      (coerce (mapcar #'parse-integer parts) '(simple-array (unsigned-byte 8) (4))))))

(defun ipv6-literal-octets (string)
  "The sixteen octets of IPv6 literal STRING, or NIL. Accepts one \"::\" and a
   trailing embedded dotted quad; rejects zones and groups over four hex digits."
  (labels ((groups (text allow-ipv4)
             ;; TEXT's 16-bit groups as a list, or :invalid.
             (if (zerop (length text))
                 '()
                 (loop with parts = (uiop:split-string text :separator ":")
                       for (part . more) on parts
                       for ipv4 = (and allow-ipv4 (null more) (find #\. part)
                                       (ipv4-literal-octets part))
                       if ipv4
                         append (list (logior (ash (aref ipv4 0) 8) (aref ipv4 1))
                                      (logior (ash (aref ipv4 2) 8) (aref ipv4 3)))
                       else if (and (<= 1 (length part) 4)
                                    (every (lambda (c) (digit-char-p c 16)) part))
                              collect (parse-integer part :radix 16)
                       else do (return :invalid)))))
    (let* ((double (search "::" string))
           (head (groups (if double (subseq string 0 double) string) (not double)))
           (tail (and double (groups (subseq string (+ double 2)) t))))
      (when (and (listp head) (listp tail)
                 (not (and double (search "::" string :start2 (1+ double))))
                 (if double
                     (<= (+ (length head) (length tail)) 7)
                     (= 8 (length head))))
        (let ((all (append head (make-list (- 8 (length head) (length tail)) :initial-element 0) tail))
              (octets (make-array 16 :element-type '(unsigned-byte 8))))
          (loop for group in all
                for index from 0 by 2
                do (setf (aref octets index) (ldb (byte 8 8) group)
                         (aref octets (1+ index)) (ldb (byte 8 0) group)))
          octets)))))

(defun certificate-ip-address-octets (address)
  "The octets a certificate's iPAddress SAN carries for ADDRESS (4 for IPv4, 16
   for IPv6), or NIL when ADDRESS is not an IP literal."
  (and (stringp address)
       (if (find #\: address)
           (ipv6-literal-octets address)
           (ipv4-literal-octets address))))

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

(defun gateway-status-resource-p (resource)
  "True for Gateway API collections with controller-owned status."
  (member resource '("gateways" "gatewayclasses") :test #'equal))

(defun normalize-gateway-status (resource object name namespace store)
  "Keep status writes separate from desired state and stamp spec generations."
  (let* ((metadata (gethash "metadata" object))
         (old (and name store
                   (gethash (core-resource-key resource namespace name) (pod-store-resources store))))
         (generation (if old (gethash "generation" (gethash "metadata" old) 1) 1)))
    (unless *typed-api-status-write*
      (if (and old (gethash "status" old))
          (setf (gethash "status" object) (copy-core-object (gethash "status" old)))
          (remhash "status" object)))
    (setf (gethash "generation" metadata)
          (if (and old (not (core-json-equal-p (gethash "spec" old) (gethash "spec" object))))
              (1+ generation) generation)))
  object)

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

(defun validate-acme-issuer-spec (acme)
  "The ACME issuer gr8s implements: an https directory, an account key Secret and
   HTTP-01 solvers answered by the Gateway. DNS-01, Ingress solvers and external
   account binding fail closed rather than being silently ignored."
  (let ((server (require-nonempty-string (gethash "server" acme) "spec.acme.server")))
    (unless (uiop:string-prefix-p "https://" server)
      (core-resource-error 422 "Invalid" "spec.acme.server must be an https:// URL")))
  ;; Optional upstream; the pure-tls client always registers a contact address.
  (require-nonempty-string (gethash "email" acme) "spec.acme.email")
  (let ((profile (gethash "profile" acme)))
    (when profile (require-nonempty-string profile "spec.acme.profile")))
  (let ((skip (gethash "skipTLSVerify" acme)))
    (unless (member skip '(nil t))
      (core-resource-error 422 "Invalid" "spec.acme.skipTLSVerify must be a boolean")))
  (when (gethash "externalAccountBinding" acme)
    (core-resource-error 422 "Invalid" "spec.acme.externalAccountBinding is not implemented"))
  (require-nonempty-string (gethash "name" (require-object (gethash "privateKeySecretRef" acme)
                                                           "spec.acme.privateKeySecretRef"))
                           "spec.acme.privateKeySecretRef.name")
  (let ((solvers (gethash "solvers" acme)))
    (unless (and (vectorp solvers) (not (stringp solvers)) (plusp (length solvers)))
      (core-resource-error 422 "Invalid" "spec.acme.solvers must be a nonempty array"))
    (loop for solver across solvers
          for http01 = (gethash "http01" (require-object solver "spec.acme.solvers[]"))
          do (when (gethash "dns01" solver)
               (core-resource-error 422 "Invalid" "spec.acme.solvers[].dns01 is not implemented"))
             (unless (and (hash-table-p http01) (hash-table-p (gethash "gatewayHTTPRoute" http01)))
               (core-resource-error 422 "Invalid"
                                    "spec.acme.solvers[] must configure http01.gatewayHTTPRoute; other solvers are not implemented")))))

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
             ((equal type "acme")
              (validate-acme-issuer-spec (require-object (gethash "acme" spec) "spec.acme")))
             (t (core-resource-error 422 "Invalid" "Issuer type ~A is not implemented" type))))))
      ((equal resource "challenges")
       (dolist (field '("url" "authorizationURL" "dnsName" "type" "token" "key"))
         (require-nonempty-string (gethash field spec) (format nil "spec.~A" field)))
       (unless (equal (gethash "type" spec) "HTTP-01")
         (core-resource-error 422 "Invalid" "spec.type: only HTTP-01 challenges are implemented")))
      ((equal resource "certificates")
       (require-nonempty-string (gethash "secretName" spec) "spec.secretName")
       (let ((ref (require-object (gethash "issuerRef" spec) "spec.issuerRef")))
         (require-nonempty-string (gethash "name" ref) "spec.issuerRef.name"))
       (let ((common-name (gethash "commonName" spec))
             (alt-names 0))
         (dolist (field '("dnsNames" "ipAddresses" "uris" "emailAddresses"))
           (let ((names (gethash field spec)))
             (when names
               (bootstrap-string-array names (format nil "spec.~A" field))
               (incf alt-names (length names)))))
         (loop for address across (or (gethash "ipAddresses" spec) #())
               unless (certificate-ip-address-octets address)
                 do (core-resource-error 422 "Invalid"
                                         "spec.ipAddresses: ~S is not a valid IP address" address))
         (unless (or (plusp alt-names)
                     (and (stringp common-name) (plusp (length common-name))))
           (core-resource-error 422 "Invalid"
                                "Certificate requires spec.commonName or one of spec.dnsNames, spec.ipAddresses, spec.uris or spec.emailAddresses"))))
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
      (validate-cluster-trust-bundle-anchors (gethash "trustBundle" spec)))
    (let ((registries (gethash gr8s.image-distribution::+registry-trust-annotation+
                               (gethash "annotations" (gethash "metadata" object) (core-object)))))
      (when registries
        (handler-case (if (stringp registries)
                          (gr8s.image-distribution::registry-trust-annotation-hosts registries)
                          (error "must be a string"))
          (error (condition)
            (cluster-trust-bundle-invalid "metadata.annotations[~A]: Invalid value: ~S: ~A"
                                          gr8s.image-distribution::+registry-trust-annotation+
                                          registries condition)))))))

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
                       ((member resource '("clusternetworkpolicies" "securityprofiles") :test #'equal)
                        '("spec" "status"))
                       ((equal resource "sandboxprofiles") '("spec"))
                       ((equal resource "gatewayclasses") '("spec" "status"))
                       ((member resource '("gateways" "httproutes"
                                           "tcproutes" "tlsroutes" "grpcroutes") :test #'equal)
                        '("spec" "status"))
                       ((member resource '("issuers" "clusterissuers"
                                           "certificates" "certificaterequests" "challenges") :test #'equal)
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
      ((equal resource "clusternetworkpolicies")
       (validate-cluster-network-policy object))
      ((equal resource "securityprofiles")
       (validate-security-profile object))
      ((equal resource "sandboxprofiles")
       (validate-sandbox-profile object))
      ((member resource '("gatewayclasses" "gateways" "httproutes"
                          "tcproutes" "tlsroutes" "grpcroutes") :test #'equal)
       (validate-gateway-resource resource object)
       (when (gateway-status-resource-p resource)
         (normalize-gateway-status resource object name namespace store)))
      ((member resource '("issuers" "clusterissuers" "certificates" "certificaterequests" "challenges")
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
    ("certificaterequests" ("cr" "crs") ("cert-manager"))
    ("challenges" () ("cert-manager" "cert-manager-acme")))
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
                         "customresourcedefinitions" "clustertrustbundles" "podcertificaterequests"
                         "clusternetworkpolicies" "securityprofiles" "sandboxprofiles")
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

(defparameter +node-pressure-messages+
  '(("KubeletHasInsufficientMemory" . "kubelet has insufficient memory available")
    ("KubeletHasSufficientMemory" . "kubelet has sufficient memory available")
    ("KubeletHasDiskPressure" . "kubelet has disk pressure")
    ("KubeletHasNoDiskPressure" . "kubelet has no disk pressure")
    ("KubeletHasInsufficientPID" . "kubelet has insufficient PID available")
    ("KubeletHasSufficientPID" . "kubelet has sufficient PID available"))
  "The message a kubelet gives each node-pressure reason.")

(defun node-pressure-condition (type pressured true-reason false-reason)
  "A kubelet node-pressure condition (MemoryPressure/DiskPressure/PIDPressure):
True with TRUE-REASON when the agent reports PRESSURED, False with FALSE-REASON
otherwise, with the reasons and messages upstream kubelet uses."
  (let ((reason (if pressured true-reason false-reason)))
    (core-object "type" type
                 "status" (if pressured "True" "False")
                 "reason" reason
                 "message" (cdr (assoc reason +node-pressure-messages+ :test #'equal)))))

(defun node-ready-condition (node)
  "NODE's Ready condition, following its session lease. Its lastTransitionTime,
from which clients such as Headlamp derive uptime, is when the ready lease began,
or for a node that is not ready the last time it was heard from. There is no
lastHeartbeatTime: renewing the lease must not change the object clients see."
  (let* ((ready (node-record-ready-p node))
         (condition (core-object "type" "Ready"
                                 "status" (if ready "True" "False")
                                 "reason" (if ready "AgentReady" "AgentNotReady")
                                 "message" "Readiness follows the gr8s node session lease"))
         (since (if ready (node-record-ready-since node) (node-record-last-heartbeat node))))
    (when since
      (setf (gethash "lastTransitionTime" condition) (current-timestamp since)))
    condition))

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
                                        (node-ready-condition node))
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
               ;; What the node's agent reported. An agent too old to report its version
               ;; shows none, rather than the control plane's: a node that hasn't been
               ;; upgraded must not look as if it had (podster-igs).
               "nodeInfo" (core-object "operatingSystem" "linux"
                                       "architecture" (or (node-record-agent-architecture node) (native-node-architecture))
                                       "kubeletVersion" (or (node-record-agent-version node) "v0.0.0-unknown")))))))

(defun node-write-input (node method)
  "Return the requested Node object from a typed or JSON PUT, or a patch applied to NODE's view."
  (if (eq method :put)
      (core-resource-request-object "Node")
      (let* ((content-type (request-media-type))
             (apply-patch (equal content-type "application/apply-patch+yaml"))
             (patch (unless apply-patch (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-binary t))))
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

;;; A Node the server itself operates, such as a browser node (podster-57fv), gets
;;; its labels and taints from the server rather than through the API.
(defun set-node-labels-and-taints (store name labels taints)
  "Merge LABELS (a hash of key -> value; derived labels are left alone) into NAME's
labels and replace its taints with TAINTS (a vector of taint objects), as an API write
would: persisted, published, and replicated. Signals NotFound when NAME isn't
registered. Returns the node record."
  (with-store-lock (store)
    (let ((current (get-node-unlocked store name)))
      (unless current (core-resource-error 404 "NotFound" "nodes \"~A\" not found" name))
      (let ((updated (copy-node-record current))
            (merged (copy-core-object (or (node-record-labels current) (core-object))))
            (builtin (node-builtin-labels current)))
        (when labels
          (maphash (lambda (key value)
                     (unless (nth-value 1 (gethash key builtin)) (setf (gethash key merged) value)))
                   labels))
        (setf (node-record-labels updated) merged
              (node-record-taints updated) (copy-core-object (or taints #())))
        (let ((old (node-api-object current)))
          (persist-node store updated)
          (setf (node-record-labels current) (node-record-labels updated)
                (node-record-taints current) (node-record-taints updated))
          (publish-node-change-unlocked store old current)
          (note-node-desired-change store current)
          current)))))

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
