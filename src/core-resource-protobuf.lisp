;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Decode Kubernetes client protobuf request bodies into gr8s's hash-table object
;;;; form, so kubectl and client-go callers sending
;;;; application/vnd.kubernetes.protobuf are served alongside JSON ones.
;;;;
;;;; A hand-written reader walks the protobuf wire format field by field, bounding
;;;; everything it reads off the wire: the body is capped at 16 MiB, the field count
;;;; at 65536, every length prefix is checked against the buffer, and any malformed
;;;; or unsupported shape is an error rather than an over-read. It strips the four-
;;;; byte "k8s\0" magic envelope, reads the shared TypeMeta/ObjectMeta, and
;;;; dispatches on kind to the matching per-group decoder; full message decoding of
;;;; the richer kinds leans on checksum-pinned Kubernetes v1.36 wire schemas.
;;;; Responses are always serialized back as JSON (kubectl advertises JSON as
;;;; acceptable), so this is a one-way request path, and a malformed body becomes a
;;;; 400 BadRequest, never a crash.

(in-package #:gr8s)

;; Kubernetes request envelopes and scalar/metadata helpers. Full core/RBAC
;; message decoding uses checksum-pinned Kubernetes v1.36 wire schemas.
;; Responses remain JSON; kubectl advertises JSON as an acceptable response.
(defvar *core-protobuf-field-count* 0)

(defun core-protobuf-fields (bytes)
  "Parse BYTES as a protobuf message and return its fields, in order, as a list of
   (FIELD-NUMBER WIRE-TYPE VALUE). Varints become integers; length-delimited, 64-,
   and 32-bit fields become byte vectors displaced over BYTES. Signals on a varint
   overflow, an out-of-range field number, a truncated field, or an unsupported
   wire type, and a 413 once the dynamic *core-protobuf-field-count* passes 65536."
  (let ((position 0) (end (length bytes)) (fields nil))
    (labels ((varint ()
               (multiple-value-bind (value count) (ag-proto::decode-varint bytes position)
                 (when (> value #xffffffffffffffff) (error "Protobuf varint overflow"))
                 (incf position count)
                 value)))
      (loop while (< position end)
            for tag = (varint)
            for number = (ash tag -3)
            for wire = (logand tag 7)
            do (unless (<= 1 number #x1fffffff) (error "Invalid protobuf field number"))
               (when (> (incf *core-protobuf-field-count*) 65536)
                 (core-resource-error 413 "RequestEntityTooLarge" "Too many protobuf fields"))
               (let ((value
                       (case wire
                         (0 (varint))
                         ((1 2 5)
                          (let* ((size (case wire (1 8) (5 4) (t (varint))))
                                 (next (+ position size)))
                            (unless (<= next end) (error "Truncated protobuf field"))
                            (prog1 (make-array size :element-type '(unsigned-byte 8)
                                                  :displaced-to bytes :displaced-index-offset position)
                              (setf position next))))
                         (otherwise (error "Unsupported protobuf wire type")))))
                 (push (list number wire value) fields))))
    (nreverse fields)))

(defun core-protobuf-value (fields number &optional (wire 2) default)
  "Return the value of the last field numbered NUMBER in FIELDS, or DEFAULT when
   none is present. Signals when a matching field's wire type is not WIRE (default 2)."
  (let ((value default))
    (dolist (field fields value)
      (when (= number (first field))
        (unless (= wire (second field)) (error "Incorrect protobuf wire type"))
        (setf value (third field))))))

(defun core-protobuf-string (fields number &optional (default ""))
  "Return field NUMBER of FIELDS decoded as a UTF-8 string, or DEFAULT when absent."
  (let ((bytes (core-protobuf-value fields number)))
    (if bytes (trivial-utf-8:utf-8-bytes-to-string bytes) default)))

(defun core-protobuf-map (fields number &key binary)
  "Return a string-keyed table built from the repeated protobuf map entries numbered
   NUMBER in FIELDS, each a { key (1), value (2) } submessage. Values decode as
   UTF-8 strings, or as base64-encoded strings when BINARY."
  (let ((map (make-hash-table :test #'equal)))
    (dolist (field fields map)
      (when (= number (first field))
        (unless (= 2 (second field)) (error "Invalid protobuf map entry"))
        (let* ((entry (core-protobuf-fields (third field)))
               (key (core-protobuf-string entry 1))
               (value (core-protobuf-value entry 2 2 (make-array 0 :element-type '(unsigned-byte 8)))))
          (setf (gethash key map) (if binary (ag-grpc:base64-encode value)
                                     (trivial-utf-8:utf-8-bytes-to-string value))))))))

(defun core-protobuf-metadata (bytes)
  "Decode a Kubernetes ObjectMeta from its protobuf BYTES into gr8s's metadata
   object: name, generateName, namespace, uid, and resourceVersion (empty strings
   dropped), labels and annotations, owner references, and finalizers. Validates the
   owner references and Pod finalizers before returning the metadata."
  (let ((fields (core-protobuf-fields bytes)) (metadata (make-hash-table :test #'equal)))
    (loop for (number name) in '((1 "name") (2 "generateName") (3 "namespace") (5 "uid") (6 "resourceVersion"))
          for value = (core-protobuf-string fields number)
          when (plusp (length value)) do (setf (gethash name metadata) value))
    (loop for (number name) in '((11 "labels") (12 "annotations"))
          for map = (core-protobuf-map fields number)
          when (plusp (hash-table-count map)) do (setf (gethash name metadata) map))
    (let ((owners nil) (finalizers nil))
      (dolist (field fields)
        (when (= 13 (first field))
          (unless (= 2 (second field)) (error "Invalid owner reference wire type"))
          (let* ((owner-fields (core-protobuf-fields (third field))) (owner (core-object)))
            (loop for (number key) in '((5 "apiVersion") (1 "kind") (3 "name") (4 "uid"))
                  do (setf (gethash key owner) (core-protobuf-string owner-fields number)))
            (loop for (number key) in '((6 "controller") (7 "blockOwnerDeletion"))
                  for value = (core-protobuf-value owner-fields number 0 :absent)
                  unless (eq value :absent)
                    do (unless (member value '(0 1)) (error "Invalid owner reference boolean"))
                       (setf (gethash key owner) (= value 1)))
            (push owner owners)))
        (when (= 14 (first field))
          (unless (= 2 (second field)) (error "Invalid finalizer wire type"))
          (push (trivial-utf-8:utf-8-bytes-to-string (third field)) finalizers)))
      (when owners (setf (gethash "ownerReferences" metadata) (coerce (nreverse owners) 'vector)))
      (when finalizers (setf (gethash "finalizers" metadata) (coerce (nreverse finalizers) 'vector))))
    (validate-owner-references metadata)
    (validate-pod-finalizers metadata)
    metadata))

(defun core-protobuf-time (bytes)
  "Decode a metav1.Time { seconds (1), nanos (2) } as an RFC3339 string."
  (let ((seconds (core-protobuf-value (core-protobuf-fields bytes) 1 0)))
    (if seconds (rfc3339-from-unix seconds) "")))

(defun core-protobuf-condition (bytes)
  "Decode a metav1.Condition from protobuf into gr8s's object form."
  (let* ((f (core-protobuf-fields bytes))
         (c (core-object "type" (core-protobuf-string f 1) "status" (core-protobuf-string f 2)
                         "reason" (core-protobuf-string f 5) "message" (core-protobuf-string f 6)))
         (lt (core-protobuf-value f 4)) (og (core-protobuf-value f 3 0)))
    (when lt (setf (gethash "lastTransitionTime" c) (core-protobuf-time lt)))
    (when (and og (plusp og)) (setf (gethash "observedGeneration" c) og))
    c))

(defun decode-pod-certificate-request-protobuf (raw version)
  "Decode a PodCertificateRequest (certificates.k8s.io/v1beta1) create or status
   body from client-go protobuf: metadata (1), spec (2), status (3). The signer
   writes status.certificateChain and conditions here over protobuf."
  (let* ((fields (core-protobuf-fields raw))
         (metadata (core-protobuf-value fields 1))
         (spec-bytes (core-protobuf-value fields 2))
         (status-bytes (core-protobuf-value fields 3))
         (object (core-object "apiVersion" version "kind" "PodCertificateRequest"
                              "metadata" (if metadata (core-protobuf-metadata metadata) (core-object)))))
    (when spec-bytes
      (let ((sf (core-protobuf-fields spec-bytes)) (spec (core-object)))
        (loop for (number key) in '((1 "signerName") (2 "podName") (3 "podUID") (4 "serviceAccountName")
                                    (5 "serviceAccountUID") (6 "nodeName") (7 "nodeUID"))
              do (setf (gethash key spec) (core-protobuf-string sf number)))
        (let ((max (core-protobuf-value sf 8 0))) (when max (setf (gethash "maxExpirationSeconds" spec) max)))
        (loop for (number key) in '((9 "pkixPublicKey") (10 "proofOfPossession") (12 "stubPKCS10Request"))
              for v = (core-protobuf-value sf number)
              when v do (setf (gethash key spec) (ag-grpc:base64-encode v)))
        (let ((ann (core-protobuf-map sf 11)))
          (when (plusp (hash-table-count ann)) (setf (gethash "unverifiedUserAnnotations" spec) ann)))
        (setf (gethash "spec" object) spec)))
    (when status-bytes
      (let ((sf (core-protobuf-fields status-bytes)) (status (core-object)) (conditions nil))
        (dolist (field sf)
          (when (and (= 1 (first field)) (= 2 (second field)))
            (push (core-protobuf-condition (third field)) conditions)))
        (when conditions (setf (gethash "conditions" status) (coerce (nreverse conditions) 'vector)))
        (let ((chain (core-protobuf-string sf 2)))
          (when (plusp (length chain)) (setf (gethash "certificateChain" status) chain)))
        (loop for (number key) in '((4 "notBefore") (5 "beginRefreshAt") (6 "notAfter"))
              for tb = (core-protobuf-value sf number)
              when tb do (setf (gethash key status) (core-protobuf-time tb)))
        (setf (gethash "status" object) status)))
    object))

(defun core-protobuf-delete-options (bytes)
  "Decode a Kubernetes DeleteOptions from protobuf BYTES into an options object:
   gracePeriodSeconds (as a signed int64), propagationPolicy, orphanDependents, the
   uid/resourceVersion preconditions, and the dryRun list. Signals on a malformed
   grace int64 or orphan flag."
  (let* ((fields (core-protobuf-fields bytes))
         (options (make-hash-table :test #'equal))
         (preconditions (core-protobuf-value fields 2))
         (dry-run nil))
    (let ((grace (core-protobuf-value fields 1 0 :absent)))
      (unless (eq grace :absent)
        (when (> grace #xffffffffffffffff) (error "Invalid DeleteOptions grace int64"))
        (setf (gethash "gracePeriodSeconds" options)
              (if (logbitp 63 grace) (- grace (expt 2 64)) grace))))
    (let ((policy (core-protobuf-value fields 4)))
      (when policy
        (setf (gethash "propagationPolicy" options) (trivial-utf-8:utf-8-bytes-to-string policy))))
    (let ((orphan (core-protobuf-value fields 3 0 :absent)))
      (unless (eq orphan :absent)
        (unless (member orphan '(0 1)) (error "Invalid DeleteOptions orphan flag"))
        (setf (gethash "orphanDependents" options) (= 1 orphan))))
    (when preconditions
      (let ((pre-fields (core-protobuf-fields preconditions)))
        (setf (gethash "preconditions" options) (make-hash-table :test #'equal))
        (loop for (number name) in '((1 "uid") (2 "resourceVersion"))
              for value = (core-protobuf-string pre-fields number)
              when (plusp (length value))
                do (setf (gethash name (gethash "preconditions" options)) value))))
    (dolist (field fields)
      (when (= 5 (first field))
        (unless (= 2 (second field)) (error "Invalid DeleteOptions.dryRun"))
        (push (trivial-utf-8:utf-8-bytes-to-string (third field)) dry-run)))
    (when dry-run (setf (gethash "dryRun" options) (coerce (nreverse dry-run) 'vector)))
    options))

(defun decode-core-resource-protobuf (bytes expected-kind &optional version-override)
  "Decode a Kubernetes client protobuf request body (BYTES) into gr8s's object form,
   dispatching on kind. Requires the four-byte \"k8s\\0\" magic prefix and a well-
   formed envelope whose kind equals EXPECTED-KIND and whose version matches the
   kind's expected version (or VERSION-OVERRIDE); a body over 16 MiB is a 413. Each
   kind is routed to its group's decoder (DeleteOptions, CSR, CRD, typed-API,
   networking, policy, batch, workload, storage, bootstrap, and the rest), with
   ConfigMap and Secret decoded inline. Any malformed or unsupported input becomes a
   400 BadRequest; a KUBERNETES-ERROR raised while decoding is re-signalled as is."
  (handler-case
      (let ((*core-protobuf-field-count* 0))
        (when (> (length bytes) (* 16 1024 1024))
          (core-resource-error 413 "RequestEntityTooLarge" "Protobuf request exceeds 16 MiB"))
        (unless (and (>= (length bytes) 4) (equalp (subseq bytes 0 4) #(107 56 115 0)))
          (error "Missing Kubernetes protobuf prefix"))
        (let* ((descriptor (find expected-kind *stored-resource-types* :key #'second :test #'equal))
               (expected-version (or version-override (if descriptor (third descriptor) (or (auth-review-kind-version expected-kind) "v1"))))
               (envelope (core-protobuf-fields (subseq bytes 4)))
               (type-meta (core-protobuf-fields (or (core-protobuf-value envelope 1)
                                                   (make-array 0 :element-type '(unsigned-byte 8)))))
               (kind (core-protobuf-string type-meta 2 expected-kind))
               (version (core-protobuf-string type-meta 1 expected-version))
               (raw (core-protobuf-value envelope 2)))
          (unless (and raw (equal kind expected-kind) (or (equal version expected-version)
                           (and (equal kind "DeleteOptions") (equal version "v1")))
                       (string= "" (core-protobuf-string envelope 3))
                       (member (core-protobuf-string envelope 4) '("" "application/vnd.kubernetes.protobuf") :test #'equal))
            (error "Invalid Kubernetes protobuf envelope"))
          (when (string= kind "DeleteOptions") (return-from decode-core-resource-protobuf (core-protobuf-delete-options raw)))
          (when (equal kind "CertificateSigningRequest")
            (return-from decode-core-resource-protobuf (decode-csr-protobuf raw)))
          (when (equal kind "CustomResourceDefinition")
            (return-from decode-core-resource-protobuf (decode-crd-protobuf raw)))
          (when (typed-api-kind-p kind)
            (return-from decode-core-resource-protobuf (decode-typed-api-protobuf raw kind version)))
          (when (equal kind "Binding")
            (let ((object (template-protobuf-message "k8s.io.api.core.v1.Binding" raw))
                  (metadata (core-protobuf-value (core-protobuf-fields raw) 1)))
              (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object)))
              (return-from decode-core-resource-protobuf object)))
          (when (equal kind "HorizontalPodAutoscaler")
            (let ((object (template-protobuf-message
                           (format nil "k8s.io.api.autoscaling.~A.HorizontalPodAutoscaler"
                                   (if (equal version "autoscaling/v1") "v1" "v2"))
                           raw))
                  (metadata (core-protobuf-value (core-protobuf-fields raw) 1)))
              (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
                    (gethash "apiVersion" object) version (gethash "kind" object) kind)
              (return-from decode-core-resource-protobuf object)))
          (when (auth-review-kind-version kind)
            (return-from decode-core-resource-protobuf (decode-auth-review-protobuf raw kind version)))
          (when (member kind '("Endpoints" "Ingress" "IngressClass" "ServiceCIDR" "IPAddress" "NetworkPolicy") :test #'equal)
            (return-from decode-core-resource-protobuf (decode-networking-protobuf raw kind version)))
          (when (member kind '("ResourceQuota" "LimitRange" "RuntimeClass" "PriorityClass") :test #'equal)
            (return-from decode-core-resource-protobuf (decode-policy-protobuf raw kind version)))
          (when (string= kind "Node")
            (let ((object (template-protobuf-message "k8s.io.api.core.v1.Node" raw))
                  (metadata (core-protobuf-value (core-protobuf-fields raw) 1)))
              (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
                    (gethash "apiVersion" object) "v1" (gethash "kind" object) "Node")
              (return-from decode-core-resource-protobuf object)))
          (when (member kind '("Job" "CronJob") :test #'string=)
            (return-from decode-core-resource-protobuf (decode-batch-protobuf raw kind)))
          (when (member kind '("MutatingWebhookConfiguration" "ValidatingWebhookConfiguration") :test #'equal)
            (return-from decode-core-resource-protobuf (decode-admission-protobuf raw kind)))
          (when (equal kind "PodDisruptionBudget")
            (return-from decode-core-resource-protobuf (decode-budget-protobuf raw)))
          (when (member kind '("Deployment" "ReplicaSet" "DaemonSet" "StatefulSet" "ControllerRevision" "ReplicationController" "Scale") :test #'equal)
            (return-from decode-core-resource-protobuf (decode-workload-protobuf raw kind)))

          (when (equal kind "EndpointSlice")
            (let ((object (template-protobuf-message "k8s.io.api.discovery.v1.EndpointSlice" raw)))
              (setf (gethash "apiVersion" object) version (gethash "kind" object) kind)
              (return-from decode-core-resource-protobuf object)))
          (when (member kind '("PersistentVolume" "PersistentVolumeClaim" "StorageClass" "CSIDriver" "CSINode"
                               "VolumeAttachment" "CSIStorageCapacity" "VolumeAttributesClass") :test #'equal)
            ;; Go always sends metadata.name, empty when generateName is meant, so
            ;; metadata goes through the decoder that drops empty request fields.
            (let ((object (template-protobuf-message
                           (concatenate 'string (if (equal version "storage.k8s.io/v1") "k8s.io.api.storage.v1." "k8s.io.api.core.v1.") kind) raw))
                  (metadata (core-protobuf-value (core-protobuf-fields raw) 1)))
              (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
                    (gethash "apiVersion" object) version (gethash "kind" object) kind)
              (return-from decode-core-resource-protobuf object)))
          (when (equal kind "Event")
            (return-from decode-core-resource-protobuf
              (let* ((package (if (equal version "events.k8s.io/v1") "k8s.io.api.events.v1.Event" "k8s.io.api.core.v1.Event"))
                     (object (template-protobuf-message package raw))
                     (metadata (core-protobuf-value (core-protobuf-fields raw) 1)))
                (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
                      (gethash "apiVersion" object) version (gethash "kind" object) kind)
                object)))
          (when (member kind '("ServiceAccount" "Role" "RoleBinding" "ClusterRole" "ClusterRoleBinding") :test #'equal)
            (return-from decode-core-resource-protobuf (decode-bootstrap-protobuf raw kind version)))
          (when (string= kind "Service")
            (return-from decode-core-resource-protobuf (decode-service-protobuf raw)))
          (when (string= kind "Pod")
            (return-from decode-core-resource-protobuf (decode-pod-protobuf raw)))
          (when (string= kind "PodTemplate")
            (return-from decode-core-resource-protobuf (decode-podtemplate-protobuf raw)))
          (when (string= kind "Namespace")
            (let* ((fields (core-protobuf-fields raw))
                   (metadata (core-protobuf-value fields 1))
                   (spec-bytes (core-protobuf-value fields 2))
                   (finalizers nil)
                   (spec (core-object)))
              (when spec-bytes
                (dolist (field (core-protobuf-fields spec-bytes))
                  (when (= 1 (first field))
                    (unless (= 2 (second field)) (error "Invalid Namespace finalizer"))
                    (push (trivial-utf-8:utf-8-bytes-to-string (third field)) finalizers))))
              (when finalizers (setf (gethash "finalizers" spec) (coerce (nreverse finalizers) 'vector)))
              ;; Namespace status is server-owned unless this is its status subresource.
              (let ((object (core-object "apiVersion" "v1" "kind" kind "spec" spec
                                         "metadata" (if metadata (core-protobuf-metadata metadata) (core-object))))
                    (status (core-protobuf-value fields 3)))
                (when (and status *typed-api-status-write*)
                  (setf (gethash "status" object) (template-protobuf-message "k8s.io.api.core.v1.NamespaceStatus" status)))
                (return-from decode-core-resource-protobuf object))))
          (when (equal kind "PodCertificateRequest")
            (return-from decode-core-resource-protobuf
              (decode-pod-certificate-request-protobuf raw version)))
          (when (equal kind "ClusterTrustBundle")
            ;; metadata (1) + spec (2) { signerName (1), trustBundle (2) }. Agent
            ;; Substrate's podcertcontroller creates these over client-go protobuf.
            (let* ((fields (core-protobuf-fields raw))
                   (metadata (core-protobuf-value fields 1))
                   (spec-bytes (core-protobuf-value fields 2))
                   (spec (core-object)))
              (when spec-bytes
                (let* ((sf (core-protobuf-fields spec-bytes))
                       (signer (core-protobuf-string sf 1 ""))
                       (bundle (core-protobuf-string sf 2 "")))
                  (when (plusp (length signer)) (setf (gethash "signerName" spec) signer))
                  (when (plusp (length bundle)) (setf (gethash "trustBundle" spec) bundle))))
              (return-from decode-core-resource-protobuf
                (core-object "apiVersion" version "kind" kind
                             "metadata" (if metadata (core-protobuf-metadata metadata) (core-object))
                             "spec" spec))))
          (unless (member kind '("ConfigMap" "Secret") :test #'equal) (error "Unsupported protobuf kind"))
          (let* ((fields (core-protobuf-fields raw))
                 (metadata (core-protobuf-value fields 1))
                 (secret (string= kind "Secret"))
                 (immutable (core-protobuf-value fields (if secret 5 4) 0 :absent))
                 (object (core-object "apiVersion" "v1" "kind" kind
                                      "metadata" (if metadata (core-protobuf-metadata metadata) (core-object)))))
            (loop for (number name binary) in (if secret '((2 "data" t) (4 "stringData" nil))
                                                  '((2 "data" nil) (3 "binaryData" t)))
                  for map = (core-protobuf-map fields number :binary binary)
                  when (plusp (hash-table-count map)) do (setf (gethash name object) map))
            (when secret (setf (gethash "type" object) (core-protobuf-string fields 3 "Opaque")))
            (unless (eq immutable :absent) (setf (gethash "immutable" object) (not (zerop immutable))))
            object)))
    (kubernetes-error (condition) (error condition))
    (error () (core-resource-error 400 "BadRequest" "Malformed Kubernetes protobuf request"))))
