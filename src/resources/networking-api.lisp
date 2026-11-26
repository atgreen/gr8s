;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Validate durable core Endpoints and the networking.k8s.io/v1 Ingress,
;;;; IngressClass, ServiceCIDR and IPAddress objects through pinned Kubernetes
;;;; schemas, and publish their discovery, OpenAPI and status routes. Ingress is an
;;;; API contract only: no Ingress controller runs here, as on any cluster that has
;;;; not installed one. Service status shares the status route.

(in-package #:gr8s.resources)

(defparameter *networking-schema*
  (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/networking-v1.json"))
  "Pinned wire and structural definitions for Endpoints and the networking API objects.")

(defparameter +default-service-cidr-name+ "kubernetes"
  "The name upstream gives the ServiceCIDR that describes the cluster's own service range.")

(defparameter +default-service-cidr+ "10.96.0.0/16"
  "The default range normalize-service-resource allocates ClusterIPs from, besides other ServiceCIDRs.")

(defvar *networking-status-write* nil
  "True only while a status subresource write may replace an object's server-owned status.")

(eval-when (:load-toplevel :execute)
  (dolist (type '(("endpoints" "Endpoints" "v1" t)
                  ("ingresses" "Ingress" "networking.k8s.io/v1" t)
                  ("ingressclasses" "IngressClass" "networking.k8s.io/v1" nil)
                  ("servicecidrs" "ServiceCIDR" "networking.k8s.io/v1" nil)
                  ("ipaddresses" "IPAddress" "networking.k8s.io/v1" nil)))
    (setf *stored-resource-types*
          (append (remove (first type) *stored-resource-types* :key #'first :test #'equal) (list type))))
  (dolist (section '("definitions" "messages"))
    (maphash (lambda (name value) (setf (gethash name (gethash section *podtemplate-schema*)) value))
             (gethash section *networking-schema*))))

(defun networking-resource-p (resource)
  "Return whether RESOURCE is Endpoints or one of the schema-validated networking collections."
  (member resource '("endpoints" "ingresses" "ingressclasses" "servicecidrs" "ipaddresses") :test #'equal))

(defun networking-resource-schema-name (resource)
  "Return the pinned structural definition for a networking RESOURCE."
  (format nil "io.k8s.api.~A.~A" (if (equal resource "endpoints") "core.v1" "networking.v1")
          (core-resource-kind resource)))

(defun networking-canonical-ip-p (text)
  "Recognize the canonical spelling of an IPv4 or IPv6 address, as an IPAddress name must be."
  (and (stringp text)
       (handler-case
           (if (find #\: text)
               (and (not (find #\% text)) (string= text (string-downcase text))
                    (0conf:parse-ipv6 text) t)
               (let ((parts (uiop:split-string text :separator '(#\.))))
                 (and (= 4 (length parts))
                      (every (lambda (part)
                               (and (plusp (length part)) (every #'digit-char-p part)
                                    (<= (parse-integer part) 255)
                                    (equal part (write-to-string (parse-integer part)))))
                             parts))))
         (error () nil))))

(defun networking-cidr-p (text)
  "Recognize an IPv4 or IPv6 prefix whose host bits are clear."
  (let ((slash (and (stringp text) (position #\/ text))))
    (when slash
      (let* ((address (subseq text 0 slash)) (digits (subseq text (1+ slash)))
             (prefix (and (plusp (length digits)) (every #'digit-char-p digits) (parse-integer digits))))
        (when (and prefix (networking-canonical-ip-p address))
          (if (find #\: address)
              (and (<= prefix 128)
                   (let ((bytes (0conf:parse-ipv6 address)))
                     (loop for index from 0 below 16
                           for keep = (min 8 (max 0 (- prefix (* index 8))))
                           always (zerop (logand (aref bytes index) (- 255 (- 256 (ash 1 (- 8 keep)))))))))
              (and (<= prefix 32)
                   (zerop (logand (parse-ipv4-integer address) (1- (ash 1 (- 32 prefix))))))))))))

(defun normalize-endpoints-subsets (object)
  "Validate Endpoints subsets and apply the protocol default."
  (when (member (gethash "subsets" object) '(null) :test #'eq) (remhash "subsets" object))
  (loop for subset across (optional-vector object "subsets" "Endpoints")
        do (require-object subset "Endpoints subset")
           (dolist (field '("addresses" "notReadyAddresses"))
             (when (eq 'null (gethash field subset)) (remhash field subset))
             (loop for address across (optional-vector subset field "Endpoints subset")
                   do (require-object address "Endpoints address")
                      (unless (or (endpointslice-address-p (gethash "ip" address) "IPv4")
                                  (endpointslice-address-p (gethash "ip" address) "IPv6"))
                        (core-resource-error 422 "Invalid" "Endpoints address ~S is not a usable IP" (gethash "ip" address)))
                      (let ((hostname (gethash "hostname" address)))
                        (when (and hostname (not (eq hostname 'null)) (not (equal hostname ""))
                                   (not (dns-label-p hostname)))
                          (core-resource-error 422 "Invalid" "Endpoints address hostname must be a DNS label")))))
           (when (eq 'null (gethash "ports" subset)) (remhash "ports" subset))
           (progn
             (loop for port across (optional-vector subset "ports" "Endpoints subset")
                   for name = (gethash "name" (require-object port "Endpoints port") "")
                   do (unless (typep (gethash "port" port) '(integer 1 65535))
                        (core-resource-error 422 "Invalid" "Endpoints port must be in 1..65535"))
                      (unless (or (equal name "") (dns-label-p name))
                        (core-resource-error 422 "Invalid" "Endpoints port names must be DNS labels"))
                      (when (member (gethash "protocol" port) '(nil null ""))
                        (setf (gethash "protocol" port) "TCP"))
                      (unless (member (gethash "protocol" port) '("TCP" "UDP" "SCTP") :test #'equal)
                        (core-resource-error 422 "Invalid" "Endpoints port protocol is invalid")))))
  object)

(defun normalize-ingress (object existing)
  "Check an Ingress names a backend for every path and keep its generation and status server-owned."
  (let ((spec (gethash "spec" object)))
    (when (eq 'null spec) (setf spec nil))
    (unless spec (setf spec (core-object) (gethash "spec" object) spec))
    (require-object spec "Ingress.spec")
    (let ((rules (optional-vector spec "rules" "Ingress.spec")))
      (unless (or (plusp (length rules)) (hash-table-p (gethash "defaultBackend" spec)))
        (core-resource-error 422 "Invalid" "Ingress.spec requires rules or a defaultBackend"))
      (loop for rule across rules
            for http = (gethash "http" (require-object rule "Ingress rule"))
            when (hash-table-p http)
              do (let ((paths (optional-vector http "paths" "Ingress rule")))
                   (unless (plusp (length paths))
                     (core-resource-error 422 "Invalid" "Ingress http rule requires paths"))
                   (loop for path across paths
                         do (require-object path "Ingress path")
                            (unless (member (gethash "pathType" path) '("Exact" "Prefix" "ImplementationSpecific") :test #'equal)
                              (core-resource-error 422 "Invalid" "Ingress pathType is invalid"))
                            (unless (hash-table-p (gethash "backend" path))
                              (core-resource-error 422 "Invalid" "Ingress path requires a backend"))))))
    (setf (gethash "generation" (gethash "metadata" object))
          (cond ((null existing) 1)
                ((equal (endpointslice-canonical-json spec) (endpointslice-canonical-json (gethash "spec" existing)))
                 (gethash "generation" (gethash "metadata" existing) 1))
                (t (1+ (gethash "generation" (gethash "metadata" existing) 1)))))
    (networking-keep-status object existing (core-object "loadBalancer" (core-object)))))

(defun default-ingress-class-name (store)
  "Return the IngressClass the DefaultIngressClass admission plugin assigns: of those annotated
ingressclass.kubernetes.io/is-default-class true, the newest, the lower name on a tie. NIL if none."
  (let ((best nil))
    (loop for object being the hash-values of (pod-store-resources store)
          for metadata = (gethash "metadata" object)
          when (and (equal "IngressClass" (gethash "kind" object))
                    (hash-table-p (gethash "annotations" metadata))
                    (equal "true" (gethash "ingressclass.kubernetes.io/is-default-class" (gethash "annotations" metadata))))
            do (let ((created (gethash "creationTimestamp" metadata "")) (name (gethash "name" metadata)))
                 (when (or (null best) (string> created (first best))
                           (and (string= created (first best)) (string< name (second best))))
                   (setf best (list created name)))))
    (second best)))

(defun apply-default-ingress-class (object store)
  "As upstream's DefaultIngressClass admission plugin does on create: give an Ingress that names
no class, by field or by the legacy kubernetes.io/ingress.class annotation, the default class."
  (let ((spec (gethash "spec" object)) (annotations (gethash "annotations" (gethash "metadata" object))))
    (when (and (hash-table-p spec)
               (member (gethash "ingressClassName" spec) '(nil null) :test #'eq)
               (not (and (hash-table-p annotations) (nth-value 1 (gethash "kubernetes.io/ingress.class" annotations)))))
      (let ((name (default-ingress-class-name store)))
        (when name (setf (gethash "ingressClassName" spec) name)))))
  object)

(defun networking-keep-status (object existing default)
  "Accept OBJECT's status only on a status write; otherwise keep the stored one or DEFAULT."
  (unless (and *networking-status-write* (hash-table-p (gethash "status" object)))
    (setf (gethash "status" object)
          (if existing (copy-core-object (gethash "status" existing default)) default)))
  object)

(defun service-cidr-ready-status (cidrs)
  "Report Ready for every validated range the dual-stack allocator serves."
  (declare (ignore cidrs))
  (core-object "conditions"
               (vector (core-object "type" "Ready" "status" "True"
                                    "reason" ""
                                    "message" "Kubernetes Service CIDR is ready"
                                    "lastTransitionTime" (current-timestamp)))))

(defparameter +egress-synthetic-cidr+ "198.18.0.0/15"
  "The node egress proxy's synthetic address range (gr8s.network, podster-wv1w.8), which
no ServiceCIDR may overlap.")

(defun networking-ipv4-cidrs-overlap-p (left right)
  "True when the IPv4 prefixes LEFT and RIGHT share an address; NIL for IPv6."
  (flet ((parse (cidr)
           (let ((slash (position #\/ cidr)))
             (values (reduce (lambda (acc octet) (+ (* acc 256) (parse-integer octet)))
                             (uiop:split-string (subseq cidr 0 slash) :separator ".")
                             :initial-value 0)
                     (parse-integer cidr :start (1+ slash))))))
    (unless (or (find #\: left) (find #\: right))
      (multiple-value-bind (a a-prefix) (parse left)
        (multiple-value-bind (b b-prefix) (parse right)
          (let ((shift (- 32 (min a-prefix b-prefix))))
            (= (ash a (- shift)) (ash b (- shift)))))))))

(defun normalize-service-cidr (object existing)
  "Validate one or two distinct-family prefixes that never change once set."
  (let* ((spec (require-object (gethash "spec" object) "ServiceCIDR.spec"))
         (cidrs (optional-vector spec "cidrs" "ServiceCIDR.spec")))
    (unless (<= 1 (length cidrs) 2)
      (core-resource-error 422 "Invalid" "ServiceCIDR.spec.cidrs requires one or two prefixes"))
    (unless (every #'networking-cidr-p cidrs)
      (core-resource-error 422 "Invalid" "ServiceCIDR.spec.cidrs must contain canonical prefixes"))
    (when (and (= 2 (length cidrs)) (eq (null (find #\: (aref cidrs 0))) (null (find #\: (aref cidrs 1)))))
      (core-resource-error 422 "Invalid" "ServiceCIDR.spec.cidrs must have one prefix per address family"))
    (when (and existing (not (equalp cidrs (gethash "cidrs" (gethash "spec" existing)))))
      (core-resource-error 422 "Invalid" "ServiceCIDR.spec.cidrs is immutable"))
    (when (some (lambda (cidr) (networking-ipv4-cidrs-overlap-p cidr +egress-synthetic-cidr+)) cidrs)
      (core-resource-error 422 "Invalid" "ServiceCIDR.spec.cidrs may not overlap ~A, where synthetic egress addresses come from"
                           +egress-synthetic-cidr+))
    (networking-keep-status object existing (service-cidr-ready-status cidrs))))

(defun normalize-ip-address (object existing)
  "Require a canonical address as the name and an immutable, complete parent reference."
  (let* ((spec (require-object (gethash "spec" object) "IPAddress.spec"))
         (parent (require-object (gethash "parentRef" spec) "IPAddress.spec.parentRef")))
    (unless (and (stringp (gethash "resource" parent)) (plusp (length (gethash "resource" parent)))
                 (stringp (gethash "name" parent)) (plusp (length (gethash "name" parent))))
      (core-resource-error 422 "Invalid" "IPAddress.spec.parentRef requires resource and name"))
    (when (and existing (not (equal (endpointslice-canonical-json parent)
                                    (endpointslice-canonical-json (gethash "parentRef" (gethash "spec" existing))))))
      (core-resource-error 422 "Invalid" "IPAddress.spec.parentRef is immutable"))
    object))

(defun normalize-ingress-class (object)
  "Require the controller name an IngressClass exists to declare."
  (let ((spec (require-object (gethash "spec" object) "IngressClass.spec")))
    (unless (and (core-qualified-key-p (gethash "controller" spec)) (position #\/ (gethash "controller" spec)))
      (core-resource-error 422 "Invalid" "IngressClass.spec.controller must be a domain-prefixed path"))
    ;; SetDefaults_IngressClass: parameters are cluster-scoped unless they say otherwise.
    (let ((parameters (gethash "parameters" spec)))
      (when (and (hash-table-p parameters) (member (gethash "scope" parameters) '(nil null)))
        (setf (gethash "scope" parameters) "Cluster")))
    object))

(defun normalize-networking-resource (resource input namespace name store)
  "Copy, validate and default one networking API object, preserving server-owned status."
  (let* ((object (copy-core-object (require-object input (core-resource-kind resource))))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (kind (core-resource-kind resource))
         (version (core-resource-api-version resource))
         (existing (and name store
                        (gethash (core-resource-key resource namespace name) (pod-store-resources store)))))
    (unless (and (equal version (gethash "apiVersion" object version))
                 (equal kind (gethash "kind" object kind)))
      (core-resource-error 400 "BadRequest" "Expected ~A ~A" version kind))
    (validate-core-metadata metadata namespace name
                            :name-test (when (equal resource "ipaddresses") #'networking-canonical-ip-p))
    (setf (gethash "kind" object) kind (gethash "apiVersion" object) version)
    (if namespace (setf (gethash "namespace" metadata) namespace) (remhash "namespace" metadata))
    (validate-template-shape object (template-schema (networking-resource-schema-name resource)) kind)
    (cond ((equal resource "endpoints") (normalize-endpoints-subsets object))
          ((equal resource "ingresses")
           (when (and store (null existing)) (apply-default-ingress-class object store))
           (normalize-ingress object existing))
          ((equal resource "ingressclasses") (normalize-ingress-class object))
          ((equal resource "servicecidrs") (normalize-service-cidr object existing))
          (t (normalize-ip-address object existing)))))

(defun decode-networking-protobuf (bytes kind version)
  "Decode one typed Endpoints or networking object through its pinned wire schema."
  (let* ((message (format nil "k8s.io.api.~A.~A" (if (equal kind "Endpoints") "core.v1" "networking.v1") kind))
         (object (template-protobuf-message message bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) version (gethash "kind" object) kind)
    object))

(defun ensure-default-service-cidr (store)
  "Publish the cluster's own service range, as the upstream default ServiceCIDR controller does."
  (handler-case
      (create-core-resource store "servicecidrs"
                            (core-object "metadata" (core-object "name" +default-service-cidr-name+)
                                         "spec" (core-object "cidrs" (vector +default-service-cidr+)))
                            nil)
    (kubernetes-error (condition)
      (unless (= 409 (kubernetes-error-status-code condition)) (error condition)))))

;;; Discovery and OpenAPI

(defun networking-api-group ()
  "Describe the served networking.k8s.io API group."
  (policy-api-group "networking.k8s.io"))

(defun networking-discovery-response ()
  "Describe the networking.k8s.io/v1 collections and their status subresources."
  (json-response
   (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "networking.k8s.io/v1"
                "resources"
                (concatenate 'vector (stored-resource-discovery "networking.k8s.io/v1")
                             (vector (core-object "name" "ingresses/status" "singularName" "" "namespaced" t
                                                  "kind" "Ingress" "verbs" #("get" "patch" "update"))
                                     (core-object "name" "servicecidrs/status" "singularName" "" "namespaced" nil
                                                  "kind" "ServiceCIDR" "verbs" #("get" "patch" "update")))))))

(defun service-subresource-discovery ()
  "Advertise the core Service and Node subresources implemented here."
  (vector (core-object "name" "services/status" "singularName" "" "namespaced" t
                       "kind" "Service" "verbs" #("get" "patch" "update"))
          (core-object "name" "services/proxy" "singularName" "" "namespaced" t "kind" "ServiceProxyOptions"
                       "verbs" #("create" "delete" "get" "patch" "update"))
          (core-object "name" "nodes/proxy" "singularName" "" "namespaced" nil "kind" "NodeProxyOptions"
                       "verbs" #("create" "delete" "get" "patch" "update"))))

(defun add-networking-openapi-paths (paths)
  "Describe the schema-validated networking.k8s.io/v1 collections from their pinned definitions."
  (dolist (resource '("ingresses" "ingressclasses" "servicecidrs" "ipaddresses"))
    (let* ((namespaced (core-resource-namespaced-p resource)) (kind (core-resource-kind resource))
           (prefix "/apis/networking.k8s.io/v1")
           (collection (concatenate 'string prefix (if namespaced "/namespaces/{namespace}/" "/") resource))
           (item (concatenate 'string collection "/{name}")))
      (labels ((parameter (name)
                 (core-object "name" name "in" "path" "required" t "schema" (core-object "type" "string")))
               (operation (method)
                 (let ((operation (core-object "x-kubernetes-action" method
                                               "x-kubernetes-group-version-kind"
                                               (core-object "group" "networking.k8s.io" "version" "v1" "kind" kind)
                                               "responses" (core-object "200" (core-object "description" "Success")))))
                   (when (member method '("post" "put" "patch") :test #'equal)
                     (setf (gethash "requestBody" operation)
                           (core-object "required" t "content"
                                        (core-object "application/json"
                                                     (core-object "schema" (reference-schema (networking-resource-schema-name resource)))))))
                   operation)))
        (setf (gethash collection paths)
              (core-object "parameters" (if namespaced (vector (parameter "namespace")) #())
                           "get" (operation "list") "post" (operation "post") "delete" (operation "deletecollection"))
              (gethash item paths)
              (core-object "parameters" (if namespaced (vector (parameter "namespace") (parameter "name")) (vector (parameter "name")))
                           "get" (operation "get") "put" (operation "put") "patch" (operation "patch") "delete" (operation "delete"))))))
  paths)

;;; Status subresources

(defun networking-status-route (path)
  "Resolve a named Service, Ingress or ServiceCIDR status URL to its collection, namespace and name."
  (when (uiop:string-suffix-p path "/status")
    (let ((route (core-resource-route (subseq path 0 (- (length path) 7)))))
      (when (and route (third route) (member (first route) '("services" "ingresses" "servicecidrs") :test #'equal))
        route))))

(defun dispatch-networking-status-request (store path method)
  "Read an object through its status subresource, or write only its status and metadata."
  (destructuring-bind (resource namespace name) (networking-status-route path)
    (when (eq method :get)
      (return-from dispatch-networking-status-request (json-response (get-core-resource store resource namespace name))))
    (unless (member method '(:put :patch))
      (core-resource-error 405 "MethodNotAllowed" "Unsupported status subresource method"))
    (let* ((*networking-status-write* t)
           (dry-run (core-resource-dry-run-p))
           (content-type (first (uiop:split-string (or (hunchentoot:header-in* :content-type) "") :separator '(#\;))))
           (applied (and (eq method :patch) (equal content-type "application/apply-patch+yaml")))
           ;; An apply records its own ownership; any other status write's manager owns what it changed.
           (*apply-update-manager* (unless applied (list (apply-default-manager) "status")))
           (input (cond ((eq method :put) (core-resource-request-object (core-resource-kind resource)))
                        (applied (apply-read-configuration resource namespace name))
                        (t
                         (unless (member content-type '("application/merge-patch+json" "application/strategic-merge-patch+json"
                                                        "application/json-patch+json")
                                         :test #'equal)
                           (core-resource-error 415 "UnsupportedMediaType" "Unsupported status patch type"))
                         (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-binary t))))))
      (json-response
       (update-core-resource
        store resource namespace name
        (lambda (old)
          (let* ((requested (cond ((eq method :put) input)
                                  (applied (apply-status-configuration (copy-core-object old) input resource))
                                  ((equal content-type "application/json-patch+json")
                                   (apply-core-json-patch (copy-core-object old) input))
                                  (t (merge-json-object (copy-core-object old) (require-object input "patch")))))
                 (metadata (require-object (gethash "metadata" requested) "metadata")))
            (unless (equal name (gethash "name" metadata))
              (core-resource-error 400 "BadRequest" "Status metadata does not match its URL"))
            (setf (gethash "status" old) (copy-core-object (require-object (gethash "status" requested (core-object)) "status")))
            (dolist (field '("labels" "annotations"))
              (multiple-value-bind (value present) (gethash field metadata)
                (when present (setf (gethash field (gethash "metadata" old)) value))))
            ;; A subresource write cannot set managedFields; an apply brings what it recorded.
            (when applied
              (if (gethash "managedFields" metadata)
                  (setf (gethash "managedFields" (gethash "metadata" old)) (gethash "managedFields" metadata))
                  (remhash "managedFields" (gethash "metadata" old))))
            (unless (member (gethash "resourceVersion" metadata) '(nil "") :test #'equal)
              (setf (gethash "resourceVersion" (gethash "metadata" old)) (gethash "resourceVersion" metadata)))
            old))
        :dry-run dry-run)))))
