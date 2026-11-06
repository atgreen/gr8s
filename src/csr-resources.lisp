;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Admit certificates.k8s.io/v1 requests with pinned schemas, actual signature
;;;; checks, immutable actor/spec state and distinct approval/status strategies.
;;;; Ordinary writes preserve spec/status; only authorized subresource handlers
;;;; may change conditions or the immutable issued certificate chain.

(in-package #:gr8s)

(defvar *csr-write-path* nil)
(defvar *csr-request-actor* (core-object))
(defparameter *csr-schema-name* "io.k8s.api.certificates.v1.CertificateSigningRequest")
(defparameter *csr-known-usages*
  '("signing" "digital signature" "content commitment" "key encipherment" "key agreement" "data encipherment"
    "cert sign" "crl sign" "encipher only" "decipher only" "any" "server auth" "client auth" "code signing"
    "email protection" "s/mime" "ipsec end system" "ipsec tunnel" "ipsec user" "timestamping" "ocsp signing" "microsoft sgc" "netscape sgc"))

(let ((addition (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/certificates-v1.json"))))
  (setf *stored-resource-types*
        (append (remove "certificatesigningrequests" *stored-resource-types* :key #'first :test #'equal)
                '(("certificatesigningrequests" "CertificateSigningRequest" "certificates.k8s.io/v1" nil))))
  (dolist (section '("messages" "definitions"))
    (maphash (lambda (name value)
               (unless (gethash name (gethash section *podtemplate-schema*))
                 (setf (gethash name (gethash section *podtemplate-schema*)) value)))
             (gethash section addition))))

(defun csr-resource-p (resource)
  "Recognize the stable cluster-scoped certificate request collection."
  (equal resource "certificatesigningrequests"))

(defun csr-path-name-p (name)
  "Allow Kubernetes CSR names while excluding unsafe REST path segment names."
  (and (stringp name) (plusp (length name)) (not (member name '("." "..") :test #'equal))
       (notany (lambda (character) (find character "/%")) name)))

(defun validate-csr-metadata (metadata name)
  "Validate ordinary object metadata while preserving the CSR name validator."
  (dolist (field '("labels" "annotations" "finalizers" "ownerReferences"))
    (when (eq (gethash field metadata) 'null) (remhash field metadata)))
  (let ((actual (gethash "name" metadata)) (copy (copy-core-object metadata)))
    (unless (csr-path-name-p actual) (csr-invalid "Invalid CSR metadata.name"))
    (when (and name (not (equal name actual))) (core-resource-error 400 "BadRequest" "metadata.name does not match request URL"))
    (setf (gethash "name" copy) "csr-metadata-validation")
    (validate-core-metadata copy nil nil :allow-finalizers t)
    (dolist (field '("labels" "annotations" "ownerReferences" "finalizers"))
      (when (gethash field copy) (setf (gethash field metadata) (gethash field copy))))))

(defun assign-generated-csr-name-unlocked (store input)
  "Allocate a Kubernetes bounded random name before the shared create strategy."
  (let* ((metadata (require-object (gethash "metadata" input) "metadata"))
         (name (gethash "name" metadata)) (prefix (gethash "generateName" metadata)))
    (when (and (member name '(nil null "") :test #'equal) prefix)
      (unless (csr-path-name-p prefix) (csr-invalid "Invalid CSR metadata.generateName"))
      (loop repeat 8 for candidate = (generate-pod-name prefix)
            unless (gethash (core-resource-key "certificatesigningrequests" nil candidate) (pod-store-resources store))
              do (setf (gethash "name" metadata) candidate) (return)
            finally (core-resource-error 409 "AlreadyExists" "Could not allocate a unique CSR name")))))

(defun validate-csr-signer-name (signer)
  "Apply the pinned core signer domain/path validation, including its 571 byte bound."
  (unless (and (stringp signer) (<= (length signer) 571)) (csr-invalid "Invalid spec.signerName"))
  (let ((parts (uiop:split-string signer :separator '(#\/))))
    (unless (and (= 2 (length parts)) (<= (length (first parts)) 253)
                 (find #\. (first parts)) (every #'dns-label-p (uiop:split-string (first parts) :separator '(#\.)))
                 (every #'dns-subdomain-p (uiop:split-string (second parts) :separator '(#\.)))
                 (not (equal signer "kubernetes.io/legacy-unknown")))
      (csr-invalid "spec.signerName must be a supported domain/path identifier"))))

(defun validate-csr-spec (spec)
  "Validate actual CSR contents, known unique usages and requested certificate lifetime."
  (require-object spec "spec")
  (let ((usages (bootstrap-string-array (gethash "usages" spec) "spec.usages" :nonempty t))
        (seen (make-hash-table :test #'equal)))
    (loop for usage across usages
          do (unless (member usage *csr-known-usages* :test #'equal) (csr-invalid "Unknown certificate usage ~A" usage))
             (when (gethash usage seen) (csr-invalid "Duplicate certificate usage ~A" usage))
             (setf (gethash usage seen) t)))
  (validate-csr-signer-name (gethash "signerName" spec))
  (when (eq (gethash "expirationSeconds" spec) 'null) (remhash "expirationSeconds" spec))
  (when (gethash "expirationSeconds" spec)
    (unless (typep (gethash "expirationSeconds" spec) '(integer 600 2147483647))
      (csr-invalid "spec.expirationSeconds must be at least 600 and within int32")))
  (let ((parsed (parse-and-verify-certificate-request (core-base64-bytes (gethash "request" spec) "spec.request"))))
    (when (and (equal "kubernetes.io/kube-apiserver-client" (gethash "signerName" spec))
               (member "system:masters" (loop for (oid . value) in (pure-tls::x509-name-rdns (parsed-certificate-request-subject parsed))
                                             when (eq oid :organization-name) collect value) :test #'equal))
      (core-resource-error 403 "Forbidden" "Client signer requests may not use the system:masters organization"))
    parsed))

(defun csr-condition (status type)
  "Find the unique condition of TYPE in CSR STATUS."
  (find type (gethash "conditions" status #()) :test #'equal :key (lambda (condition) (gethash "type" condition))))

(defun prepare-csr-status (status old path)
  "Apply approval/status reset fields and preserve irreversible decision conditions."
  (let ((conditions (let ((value (gethash "conditions" status #()))) (if (eq value 'null) #() value))) (previous (gethash "status" old (core-object)))
        (seen (make-hash-table :test #'equal)) (now (current-timestamp)))
    (unless (and (vectorp conditions) (not (stringp conditions))) (csr-invalid "status.conditions must be an array"))
    (loop for condition across conditions for type = (gethash "type" (require-object condition "condition"))
          do (unless (and (stringp type) (plusp (length type))) (csr-invalid "condition.type is required"))
             (when (gethash type seen) (csr-invalid "Duplicate condition type ~A" type))
             (setf (gethash type seen) t)
             (unless (member (gethash "status" condition)
                             (if (member type '("Approved" "Denied" "Failed") :test #'equal) '("True") '("True" "False" "Unknown")) :test #'equal)
               (csr-invalid "Invalid CSR condition status")))
    (when (and (gethash "Approved" seen) (gethash "Denied" seen)) (csr-invalid "Approved and Denied are mutually exclusive"))
    (dolist (type '("Approved" "Denied" "Failed"))
      (let ((before (csr-condition previous type)) (after (csr-condition status type)))
        (when (and before (not after)) (csr-invalid "May not remove condition ~A" type))
        (when (and (eq path :status) (member type '("Approved" "Denied") :test #'equal))
          (when (and after (not before)) (csr-invalid "Approval decisions require the approval subresource"))
          (when before (setf (aref conditions (position after conditions :test #'eq)) (copy-core-object before))))))
    (loop for condition across conditions
          for before = (csr-condition previous (gethash "type" condition))
          do (dolist (field '("lastUpdateTime" "lastTransitionTime"))
               (when (member (gethash field condition) '(nil null "") :test #'equal)
                 (setf (gethash field condition)
                       (if (and (equal field "lastTransitionTime") before
                                (equal (gethash "status" condition) (gethash "status" before)) (gethash field before))
                           (gethash field before) now)))
               (setf (gethash field condition) (normalize-event-time (gethash field condition)))))
    (setf (gethash "conditions" status) conditions)
    (when (eq path :approval)
      (if (gethash "certificate" previous) (setf (gethash "certificate" status) (gethash "certificate" previous))
          (remhash "certificate" status)))
    (let* ((certificate (let ((value (gethash "certificate" status ""))) (if (eq value 'null) "" value))) (old-certificate (gethash "certificate" previous ""))
           (bytes (core-base64-bytes certificate "status.certificate")))
      (when (and (plusp (length old-certificate)) (not (equal certificate old-certificate)))
        (csr-invalid "Issued certificate content is immutable"))
      (validate-csr-certificate-chain bytes)
      (if (zerop (length bytes)) (remhash "certificate" status)
          (setf (gethash "certificate" status) (ag-grpc:base64-encode bytes))))
    status))

(defun prune-csr-unknown-fields (value schema &optional (path "") (depth 0))
  "Apply typed-schema pruning with real Strict/Warn diagnostics before strategy resets."
  (when (> depth 64) (csr-invalid "CSR input nesting exceeds 64"))
  (let* ((schema (resolve-template-schema schema)) (properties (gethash "properties" schema))
         (extra (gethash "additionalProperties" schema)) (unknown nil))
    (cond
      ((hash-table-p value)
       (maphash (lambda (key item)
                  (let ((child (or (and properties (gethash key properties)) (and (hash-table-p extra) extra)))
                        (location (if (equal path "") key (concatenate 'string path "." key))))
                    (cond (child (setf unknown (nconc (prune-csr-unknown-fields item child location (1+ depth)) unknown)))
                          ((eq extra t) nil)
                          ((and properties (not child)) (push location unknown) (remhash key value))))) value))
      ((and (vectorp value) (not (stringp value)) (gethash "items" schema))
       (loop for item across value for index from 0
             do (setf unknown (nconc (prune-csr-unknown-fields item (gethash "items" schema) (format nil "~A[~D]" path index) (1+ depth)) unknown)))))
    unknown))

(defun normalize-csr-resource (input name store)
  "Apply pinned create/main/approval/status strategies before durable publication."
  (let* ((object (copy-core-object (require-object input "CertificateSigningRequest")))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (old (and name store (get-core-resource-unlocked store "certificatesigningrequests" nil name))))
    (unless (and (equal (gethash "apiVersion" object "certificates.k8s.io/v1") "certificates.k8s.io/v1")
                 (equal (gethash "kind" object "CertificateSigningRequest") "CertificateSigningRequest"))
      (core-resource-error 400 "BadRequest" "Expected certificates.k8s.io/v1 CertificateSigningRequest"))
    (let ((unknown (prune-csr-unknown-fields object (template-schema *csr-schema-name*))))
      (when unknown (crd-report-pruned-fields unknown)))
    (validate-csr-metadata metadata name)
    (when (gethash "generateName" metadata)
      (unless (csr-path-name-p (gethash "generateName" metadata)) (csr-invalid "Invalid generateName")))
    (setf (gethash "apiVersion" object) "certificates.k8s.io/v1" (gethash "kind" object) "CertificateSigningRequest")
    (remhash "namespace" metadata)
    (cond
      ((null old)
       (let ((spec (require-object (gethash "spec" object) "spec")))
         (dolist (key '("username" "uid" "groups" "extra")) (remhash key spec))
         (setf (gethash "username" spec) (gethash "username" *csr-request-actor* "system:anonymous")
               (gethash "groups" spec) (gethash "groups" *csr-request-actor* #("system:unauthenticated")))
         (dolist (key '("uid" "extra"))
           (when (gethash key *csr-request-actor*) (setf (gethash key spec) (copy-core-object (gethash key *csr-request-actor*))))))
       (setf (gethash "status" object) (core-object "conditions" #())))
      (t
       (setf (gethash "spec" object) (copy-core-object (gethash "spec" old)))
       (when (member (gethash "resourceVersion" metadata) '(nil "") :test #'equal)
         (setf (gethash "resourceVersion" metadata) (gethash "resourceVersion" (gethash "metadata" old))))
       (let ((deleting (gethash "deletionTimestamp" (gethash "metadata" old))))
         (when deleting
           (setf (gethash "deletionTimestamp" metadata) deleting)
           (loop for finalizer across (gethash "finalizers" metadata #())
                 unless (find finalizer (gethash "finalizers" (gethash "metadata" old) #()) :test #'equal)
                   do (csr-invalid "Cannot add finalizers to a deleting CSR"))))
       (setf (gethash "status" object)
             (if *csr-write-path*
                 (prepare-csr-status (require-object (gethash "status" object (core-object)) "status") old *csr-write-path*)
                 (copy-core-object (gethash "status" old))))))
    (validate-template-shape object (template-schema *csr-schema-name*) "CertificateSigningRequest")
    (validate-csr-spec (gethash "spec" object))
    object))

(defun prepare-csr-write (object existing)
  "Preserve server generation semantics and prevent client deletion-intent injection."
  (let ((metadata (gethash "metadata" object)))
    (remhash "generation" metadata)
    (unless (and existing (gethash "deletionTimestamp" (gethash "metadata" existing)))
      (remhash "deletionTimestamp" metadata) (remhash "deletionGracePeriodSeconds" metadata))))

(defun csr-finalized-p (object)
  "Identify a deleting CSR whose finalizers have actually completed."
  (let ((metadata (gethash "metadata" object)))
    (and (gethash "deletionTimestamp" metadata) (zerop (length (gethash "finalizers" metadata #()))))))

(defun delete-csr-unlocked (store existing dry-run)
  "Durably honor CSR finalizers; caller has checked UID/RV delete preconditions."
  (let* ((object (copy-core-object existing)) (metadata (gethash "metadata" object))
         (index (copy-core-resource-index store)) (revision (1+ (pod-store-resource-revision store)))
         (key (core-resource-key "certificatesigningrequests" nil (gethash "name" metadata))))
    (if (plusp (length (gethash "finalizers" metadata #())))
        (unless (gethash "deletionTimestamp" metadata)
          (setf (gethash "deletionTimestamp" metadata) (current-timestamp))
          (prepare-core-resource-metadata object existing revision) (prepare-csr-write object existing)
          (setf (gethash "deletionTimestamp" metadata) (current-timestamp) (gethash key index) object)
          (unless dry-run (commit-core-resources store index revision)))
        (progn (remhash key index) (unless dry-run (commit-core-resources store index revision))))
    object))
