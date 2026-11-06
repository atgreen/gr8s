;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve actual certificate-request discovery and separately authorized status
;;;; and approval endpoints. Resolve actors only from verified request credentials,
;;;; share durable ordinary CRUD/watches, and publish typed OpenAPI paths.

(in-package #:gr8s)

(defun csr-api-group ()
  "Describe the implemented stable certificates API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "certificates.k8s.io"
               "versions" (vector (core-object "groupVersion" "certificates.k8s.io/v1" "version" "v1")
                                  (core-object "groupVersion" "certificates.k8s.io/v1beta1" "version" "v1beta1"))
               ;; CertificateSigningRequest and ClusterTrustBundle are GA at v1
               ;; (the preferred version); the v1beta1 version carries
               ;; PodCertificateRequest (KEP-4317).
               "preferredVersion" (core-object "groupVersion" "certificates.k8s.io/v1" "version" "v1")))

(defun csr-v1beta1-discovery-response ()
  "Advertise certificates.k8s.io/v1beta1 resources (PodCertificateRequest + its
   signer-written status subresource)."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList"
                              "groupVersion" "certificates.k8s.io/v1beta1"
                              "resources"
                              (concatenate 'vector
                                (stored-resource-discovery "certificates.k8s.io/v1beta1")
                                (vector (core-object "name" "podcertificaterequests/status"
                                                     "singularName" "" "namespaced" t
                                                     "kind" "PodCertificateRequest"
                                                     "verbs" #("get" "patch" "update")))))))

(defun csr-discovery-response ()
  "Advertise only actual collection, status and approval operations."
  (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "certificates.k8s.io/v1"
                "resources" (concatenate 'vector (stored-resource-discovery "certificates.k8s.io/v1")
                  (map 'vector (lambda (subresource)
                                 (core-object "name" (concatenate 'string "certificatesigningrequests/" subresource)
                                              "singularName" "" "namespaced" nil "kind" "CertificateSigningRequest"
                                              "verbs" #("get" "patch" "update"))) '("approval" "status"))))))

(defun csr-http-request-actor (store)
  "Derive immutable request actor fields from verified TLS or token identity, never headers claiming a username."
  (let* ((header (hunchentoot:header-in* :authorization))
         (token (and header (uiop:string-prefix-p "Bearer " header) (subseq header 7)))
         (identity (or *authenticated-api-identity* (and token (authenticate-service-account-token store token)))))
    (if identity (api-identity-actor identity)
        (core-object "username" "system:anonymous" "groups" #("system:unauthenticated")))))

(defun decode-csr-protobuf (bytes)
  "Decode the pinned CSR wire schema, including the ExtraValue array alias."
  (let* ((object (template-protobuf-message "k8s.io.api.certificates.v1.CertificateSigningRequest" bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1))
         (extra (gethash "extra" (gethash "spec" object (core-object)))))
    (when extra
      (maphash (lambda (key value) (setf (gethash key extra) (gethash "items" value #()))) extra))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) "certificates.k8s.io/v1" (gethash "kind" object) "CertificateSigningRequest")
    object))

(defun csr-subresource-route (path)
  "Resolve only named cluster-scoped v1 CSR approval and status paths."
  (let ((parts (uiop:split-string path :separator '(#\/))))
    (when (and (= 7 (length parts)) (equal (subseq parts 0 5) '("" "apis" "certificates.k8s.io" "v1" "certificatesigningrequests"))
               (csr-path-name-p (sixth parts)) (member (seventh parts) '("approval" "status") :test #'equal))
      (list (sixth parts) (if (equal (seventh parts) "approval") :approval :status)))))

(defun csr-subresource-input (old method)
  "Read typed replacement or actual schema-aware JSON patch once per request."
  (if (eq method :put) (core-resource-request-object "CertificateSigningRequest")
      (let* ((type (request-media-type))
             (patch (crd-parse-json-content (hunchentoot:raw-post-data :force-text t))))
        (cond ((equal type "application/json-patch+json") (apply-core-json-patch (copy-core-object old) patch))
              ((equal type "application/merge-patch+json") (merge-json-object (copy-core-object old) (require-object patch "patch")))
              ((equal type "application/strategic-merge-patch+json")
               (template-strategic-merge (copy-core-object old) (require-object patch "patch") (template-schema *csr-schema-name*)))
              (t (core-resource-error 415 "UnsupportedMediaType" "Unsupported CSR patch format"))))))

(defun csr-authorize-signer (store identity signer verb)
  "Require real signer-specific RBAC, including the upstream domain wildcard name."
  (let ((domain (first (uiop:split-string signer :separator '(#\/)))))
    (unless (or (service-account-authorized-p store identity verb "certificates.k8s.io" "signers" signer nil nil)
                (service-account-authorized-p store identity verb "certificates.k8s.io" "signers" (concatenate 'string domain "/*") nil nil))
      (core-resource-error 403 "Forbidden" "The authenticated account may not ~A this signer" verb))))

(defun csr-authorize-subresource (store old requested path)
  "Apply signer approval/signing admission on the existing authenticated TLS listener."
  (when (typep hunchentoot:*acceptor* 'gr8s-in-cluster-acceptor)
    (let* ((header (hunchentoot:header-in* :authorization))
           (identity (or *authenticated-api-identity*
                         (and header (uiop:string-prefix-p "Bearer " header) (authenticate-service-account-token store (subseq header 7)))))
           (signer (gethash "signerName" (gethash "spec" old))))
      (unless identity (core-resource-error 401 "Unauthorized" "A verified API identity is required"))
      (cond ((eq path :approval) (csr-authorize-signer store identity signer "approve"))
            ((not (equal (gethash "certificate" (gethash "status" old) "")
                         (gethash "certificate" (gethash "status" requested (core-object)) "")))
             (csr-authorize-signer store identity signer "sign"))))))

(defun dispatch-csr-subresource (store path method)
  "Read or atomically apply upstream status/approval strategy and signer authorization."
  (destructuring-bind (name *csr-write-path*) (csr-subresource-route path)
    (let* ((*core-resource-view-version* "certificates.k8s.io/v1")
           (old (get-core-resource store "certificatesigningrequests" nil name)))
      (when (eq method :get) (return-from dispatch-csr-subresource (json-response old)))
      (unless (member method '(:put :patch)) (core-resource-error 405 "MethodNotAllowed" "Unsupported CSR subresource method"))
      (let* ((dry-run (core-resource-dry-run-p))
             (requested (admit-subresource-write store "certificatesigningrequests"
                                                 (string-downcase *csr-write-path*) nil name
                                                 (csr-subresource-input old method) old :dry-run dry-run)))
        (csr-authorize-subresource store old requested *csr-write-path*)
        (json-response
         (update-core-resource store "certificatesigningrequests" nil name
           (lambda (current)
             (unless (equal (gethash "uid" (gethash "metadata" old)) (gethash "uid" (gethash "metadata" current)))
               (core-resource-error 409 "Conflict" "CSR was deleted and recreated during the request"))
             requested)
           :dry-run dry-run))))))

(defun delete-csr-collection (store labels fields &key dry-run)
  "Delete selector-matched exact CSR UIDs while respecting durable user finalizers."
  (let ((label-test (core-selector-predicate labels))
        (field-test (core-selector-predicate fields :fields t :field-paths (core-resource-field-paths "certificatesigningrequests"))))
    (dolist (object (list-core-resources store "certificatesigningrequests"))
      (when (and (funcall label-test object) (funcall field-test object))
        (let ((metadata (gethash "metadata" object)))
          (delete-core-resource store "certificatesigningrequests" nil (gethash "name" metadata) :uid (gethash "uid" metadata) :dry-run dry-run))))))

(defun add-csr-openapi-paths (paths)
  "Describe actual stable CSR collection and approval/status paths."
  (let* ((collection "/apis/certificates.k8s.io/v1/certificatesigningrequests")
         (item (concatenate 'string collection "/{name}")))
    (labels ((operation (action &optional body)
               (let ((value (core-object "operationId" (concatenate 'string action "CertificatesV1CertificateSigningRequest")
                                         "x-kubernetes-group-version-kind" (core-object "group" "certificates.k8s.io" "version" "v1" "kind" "CertificateSigningRequest")
                                         "responses" (core-object "200" (core-object "description" "Success")))))
                 (when body
                   (setf (gethash "parameters" value) (vector (core-object "name" "fieldValidation" "in" "query" "schema" (core-object "type" "string")))
                         (gethash "requestBody" value) (core-object "required" t "content" (core-object "application/json" (core-object "schema" (reference-schema *csr-schema-name*))))))
                 value)))
      (setf (gethash collection paths) (core-object "get" (operation "list") "post" (operation "create" t) "delete" (operation "deleteCollection"))
            (gethash item paths) (core-object "parameters" (vector (core-object "name" "name" "in" "path" "required" t "schema" (core-object "type" "string")))
                                            "get" (operation "read") "put" (operation "replace" t) "patch" (operation "patch" t) "delete" (operation "delete")))
      (dolist (subresource '("approval" "status"))
        (setf (gethash (concatenate 'string item "/" subresource) paths)
              (core-object "parameters" (gethash "parameters" (gethash item paths)) "get" (operation (concatenate 'string "read" subresource))
                           "put" (operation (concatenate 'string "replace" subresource) t) "patch" (operation (concatenate 'string "patch" subresource) t))))))
  paths)

(defun add-csr-openapi-v2-paths (paths)
  "Translate actual CSR operations to genuine Swagger v2 body/query parameters."
  (add-csr-openapi-paths paths)
  (labels ((parameters (array)
             (map 'vector (lambda (parameter)
                            (let ((schema (gethash "schema" parameter)))
                              (when schema
                                (setf (gethash "type" parameter) (gethash "type" schema))
                                (remhash "schema" parameter))) parameter) array)))
    (maphash (lambda (path item)
               (declare (ignore path))
               (when (gethash "parameters" item) (setf (gethash "parameters" item) (parameters (gethash "parameters" item))))
               (dolist (verb '("get" "post" "put" "patch" "delete"))
                 (let ((operation (gethash verb item)))
                   (when operation
                     (let* ((body (gethash "requestBody" operation))
                            (input (and body (gethash "schema" (gethash "application/json" (gethash "content" body))))))
                       (when (gethash "parameters" operation)
                         (setf (gethash "parameters" operation) (parameters (gethash "parameters" operation))))
                       (when input
                         (setf (gethash "parameters" operation)
                               (concatenate 'vector (gethash "parameters" operation #())
                                 (vector (core-object "name" "body" "in" "body" "required" t "schema" input)))))
                       (remhash "requestBody" operation)))))) paths))
  paths)
