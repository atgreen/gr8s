;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; The HTTP surface for Kubernetes "core" durable resources: turn a REST
;;;; request into a store mutation and a wire response.
;;;;
;;;; CORE-RESOURCE-ROUTE parses /api/v1/... and /apis/<group>/<version>/... paths
;;;; into (collection namespace name), consulting *STORED-RESOURCE-TYPES* so only
;;;; registered kinds (and their group/version) resolve. DISPATCH-CORE-RESOURCE-
;;;; REQUEST is the verb switch -- list/watch, get, create, replace, patch,
;;;; delete and delete-collection -- validating names and namespaces and honouring
;;;; dryRun. Request bodies arrive as JSON or Kubernetes protobuf; label and field
;;;; selectors compile to predicates (CORE-SELECTOR-PREDICATE); PATCH is served
;;;; for JSON merge, strategic-merge, JSON Patch (RFC 6902) and server-side apply.
;;;; The JSON-pointer and JSON-patch helpers implement RFC 6901 and RFC 6902 over
;;;; the jzon object model (hash-tables and vectors). Admission, storage and the
;;;; schemas live elsewhere; this file is the protocol edge.

(in-package #:gr8s.apiserver)

(defvar *crd-route* nil)

(defun core-resource-route (path)
  "Resolve a durable resource URL to its collection, namespace and name."
  (when *crd-route* (return-from core-resource-route *crd-route*))
  (let* ((parts (uiop:split-string path :separator '(#\/)))
         (version (cond ((equal (subseq parts 0 (min 3 (length parts))) '("" "api" "v1")) "v1")
                        ((and (>= (length parts) 4) (equal (second parts) "apis"))
                         (format nil "~A/~A" (third parts) (fourth parts)))))
         (tail (and version (nthcdr (if (equal version "v1") 3 4) parts))))
    (when tail
      (let* ((namespaced (and (>= (length tail) 3) (equal (first tail) "namespaces")))
             (namespace (and namespaced (second tail)))
             (remaining (if namespaced (cddr tail) tail))
             (type (assoc (first remaining) *stored-resource-types* :test #'equal)))
        (when (and type (or (equal version (third type))
                                  (and (equal "events" (first type)) (equal version "events.k8s.io/v1"))
                                  (and (equal "horizontalpodautoscalers" (first type)) (equal version "autoscaling/v1"))
                                  (and (equal "podcertificaterequests" (first type))
                                       (equal version +pod-certificate-request-beta-version+)))
                   (<= 1 (length remaining) 2)
                   (every (lambda (part) (plusp (length part))) remaining)
                   (or (not namespaced) (fourth type))
                   (or (fourth type) (not namespaced)))
          (list (first type) namespace (second remaining)))))))

(defun core-resource-dry-run-p ()
  "True when the request carries a ?dryRun parameter. Signals a 400 unless its
   value is exactly \"All\" (the only mode supported)."
  (let ((value (hunchentoot:parameter "dryRun")))
    (when (and value (not (string= value "All")))
      (core-resource-error 400 "BadRequest" "dryRun must be All"))
    (not (null value))))

(defun core-resource-request-object (expected-kind)
  "Decode the request body into a resource object for EXPECTED-KIND. Accepts
   Kubernetes protobuf and JSON (an empty content type is treated as JSON);
   CRD/CSR bodies and CRD views parse through the CRD reader, other JSON gets
   typed field validation. Signals a 415 for any other content type."
  (when (and *crd-view-definition* (not (equal expected-kind "DeleteOptions"))) (return-from core-resource-request-object (crd-read-json)))
  (let ((content-type (request-media-type)))
    (cond
      ((string= content-type "application/vnd.kubernetes.protobuf")
       (decode-core-resource-protobuf (hunchentoot:raw-post-data :force-binary t) expected-kind
                                      (if (equal expected-kind "Scale") "autoscaling/v1"
                                          (when (member expected-kind '("Event" "DeleteOptions" "PodCertificateRequest") :test #'equal)
                                            *core-resource-view-version*))))
      ((member content-type '("" "application/json") :test #'string=)
       (let ((text (hunchentoot:raw-post-data :force-text t)))
         (if (member expected-kind '("CustomResourceDefinition" "CertificateSigningRequest") :test #'equal)
             (require-object (crd-parse-json-content text) "request")
             (apply-typed-field-validation
              (require-object (com.inuoe.jzon:parse text :max-string-length (* 2 1024 1024)) "request")
              text expected-kind))))
      (t (core-resource-error 415 "UnsupportedMediaType" "Supported resource request formats are JSON and Kubernetes protobuf")))))

(defun core-selector-terms (selector)
  "Split a label/field SELECTOR into its comma-separated terms, ignoring commas
   inside parentheses (set-based value lists). Each term is whitespace-trimmed.
   Signals a 400 on unbalanced parentheses."
  (let ((depth 0) (start 0) (terms nil))
    (loop for character across selector for position from 0
          do (case character
               (#\( (incf depth))
               (#\) (decf depth))
               (#\, (when (zerop depth)
                       (push (string-trim " " (subseq selector start position)) terms)
                       (setf start (1+ position)))))
             (when (minusp depth) (core-resource-error 400 "BadRequest" "Invalid selector")))
    (unless (zerop depth) (core-resource-error 400 "BadRequest" "Invalid selector"))
    (push (string-trim " " (subseq selector start)) terms)
    (nreverse terms)))

(defun core-selector-field-value (object path)
  "Read a supported scalar field path using Kubernetes selector string values."
  (when (equal "Event" (gethash "kind" object))
    (cond ((equal path "source")
           (return-from core-selector-field-value
             (or (let ((component (gethash "component" (gethash "source" object))))
                   (and component (plusp (length component)) component))
                 (gethash "reportingComponent" object ""))))
          ((equal path "reportingController") (setf path "reportingComponent"))
          ((uiop:string-prefix-p "regarding." path)
           (setf path (concatenate 'string "involvedObject." (subseq path 10))))))
  (let ((value object))
    (dolist (key (uiop:split-string path :separator '(#\.)))
      (unless (hash-table-p value) (return-from core-selector-field-value ""))
      (multiple-value-bind (next present) (gethash key value)
        (unless present (return-from core-selector-field-value ""))
        (setf value next)))
    (cond ((stringp value) value) ((eq value t) "true") ((null value) "false")
          ((eq value 'null) "") ((numberp value) (write-to-string value)) (t ""))))

(defun core-selector-predicate (selector &key fields (field-paths '("metadata.name" "metadata.namespace")))
  "Compile a label SELECTOR (or, with FIELDS true, a field selector over
   FIELD-PATHS) into a predicate of one object that is true when every term
   matches. Supports =, ==, !=, set-based in/notin, and presence/absence; a
   field selector allows only =/!= on the whitelisted FIELD-PATHS. Signals a 400
   on an empty key or an unsupported term or operator. A NIL or empty selector
   yields a predicate that is always true."
  (let ((predicates nil))
    (unless (or (null selector) (string= "" selector))
      (dolist (term (core-selector-terms selector))
        (let* ((not-in (search " notin " term)) (in (search " in " term))
               (not-equal (search "!=" term)) (equal-sign (position #\= term))
               (set-position (or not-in in))
               (key (string-trim " " (cond (set-position (subseq term 0 set-position))
                                           (not-equal (subseq term 0 not-equal))
                                           (equal-sign (subseq term 0 equal-sign))
                                           ((and (plusp (length term)) (char= #\! (char term 0))) (subseq term 1))
                                           (t term))))
               (operation (cond (not-in :not-in) (in :in) (not-equal :not-equal)
                                (equal-sign :equal) ((and (plusp (length term)) (char= #\! (char term 0))) :absent)
                                (t :present)))
               (values
                 (cond
                   (set-position
                    (let* ((offset (+ set-position (if not-in 7 4)))
                           (value (string-trim " " (subseq term offset))))
                      (unless (and (>= (length value) 2) (char= #\( (char value 0))
                                   (char= #\) (char value (1- (length value)))))
                        (core-resource-error 400 "BadRequest" "Invalid set selector"))
                      (mapcar (lambda (item) (string-trim " " item))
                              (uiop:split-string (subseq value 1 (1- (length value))) :separator '(#\,)))))
                   ((or not-equal equal-sign)
                    (list (subseq term (+ (or not-equal equal-sign)
                                         (if (or not-equal (search "==" term)) 2 1)))))
                   (t nil))))
          (when (or (zerop (length key))
                    (and fields (or (not (member key field-paths :test #'string=))
                                    (not (member operation '(:equal :not-equal))))))
            (core-resource-error 400 "BadRequest" "Unsupported selector ~S" term))
          (push (let ((key key) (operation operation) (values values))
                  (lambda (object)
                    (let* ((metadata (gethash "metadata" object))
                           (labels (gethash "labels" metadata))
                           (value (if fields
                                      (core-selector-field-value object key)
                                      (and labels (gethash key labels))))
                           (matches (and value (member value values :test #'string=))))
                      (case operation
                        ((:equal :in) matches)
                        ((:not-equal :not-in) (not matches))
                        (:present (not (null value)))
                        (:absent (null value)))))) predicates))))
    (lambda (object) (every (lambda (predicate) (funcall predicate object)) predicates))))

(defun core-resource-list-response (store resource namespace)
  "Serve revision-consistent durable lists and mutation-backed watch streams."
  (if (true-parameter-p (hunchentoot:parameter "watch"))
      (podtemplate-watch-response store namespace resource)
      (let* ((text (hunchentoot:parameter "limit"))
             (limit (when text (ignore-errors (parse-integer text :junk-allowed nil)))))
        (when (and text (null limit)) (core-resource-error 400 "BadRequest" "Invalid limit"))
        (multiple-value-bind (page code)
            (template-list-page store namespace (or (hunchentoot:parameter "labelSelector") "")
                                (or (hunchentoot:parameter "fieldSelector") "")
                                :resource resource :limit limit :continuation (hunchentoot:parameter "continue")
                                :resource-version (hunchentoot:parameter "resourceVersion")
                                :match (hunchentoot:parameter "resourceVersionMatch"))
          (json-response page code)))))

(defun core-json-pointer (path)
  "Parse an RFC 6901 JSON Pointer PATH into a list of decoded reference tokens
   (~1 -> /, ~0 -> ~). The empty pointer yields NIL (the whole document).
   Signals a 400 when PATH is not a string, lacks a leading \"/\", or has a bad
   escape."
  (unless (and (stringp path) (or (zerop (length path)) (char= #\/ (char path 0))))
    (core-resource-error 400 "BadRequest" "Invalid JSON patch path"))
  (unless (zerop (length path))
    (mapcar (lambda (part)
              (with-output-to-string (out)
                (loop for position from 0 below (length part)
                      for character = (char part position)
                      do (if (char= character #\~)
                             (progn
                               (incf position)
                               (unless (and (< position (length part)) (find (char part position) "01"))
                                 (core-resource-error 400 "BadRequest" "Invalid JSON pointer escape"))
                               (write-char (if (char= (char part position) #\0) #\~ #\/) out))
                             (write-char character out)))))
            (uiop:split-string (subseq path 1) :separator '(#\/)))))

(defun core-json-array-index (part size &key add)
  "Parse PART as an index into an array of SIZE: a canonical non-negative integer
   (no leading zeros), or \"-\" meaning the end position when ADD is true. The
   valid range is 0..SIZE for an add and 0..SIZE-1 otherwise. Signals a 422 when
   PART is not a valid in-range index."
  (let ((index (if (and add (string= part "-")) size
                   (and (plusp (length part))
                        (or (string= part "0") (not (char= #\0 (char part 0))))
                        (every #'digit-char-p part) (parse-integer part)))))
    (unless (and index (<= 0 index) (if add (<= index size) (< index size)))
      (core-resource-error 422 "Invalid" "JSON patch array index is out of range"))
    index))

(defun core-json-at (object path)
  "Follow pointer PATH (a token list) into OBJECT and return the value there,
   descending hash-tables by key and vectors by index. Signals a 422 when any
   step is missing or lands on a non-container."
  (dolist (part path object)
    (setf object
          (cond ((hash-table-p object)
                 (multiple-value-bind (value present) (gethash part object)
                   (unless present (core-resource-error 422 "Invalid" "JSON patch path does not exist")) value))
                ((and (vectorp object) (not (stringp object)))
                 (aref object (core-json-array-index part (length object))))
                (t (core-resource-error 422 "Invalid" "JSON patch path does not exist"))))))

(defun core-json-write (object path value operation)
  "Return OBJECT with VALUE applied at pointer PATH under OPERATION (:add,
   :replace or :remove). Hash-tables are mutated in place; vectors return a fresh
   vector (:add inserts, :remove drops, :replace overwrites). An empty PATH
   targets the whole document, returning VALUE, or 'NULL for :remove. Signals a
   422 when the parent is missing or a :remove target does not exist. Object
   :replace may create a member, matching Kubernetes' json-patch.v4 behavior;
   array replacement still requires an existing index."
  (if (null path)
      (if (eq operation :remove) 'null value)
      (let ((part (first path)))
        (cond
          ((cdr path)
           (let ((child (core-json-at object (list part))))
             (core-json-write object (list part)
                              (core-json-write child (cdr path) value operation) :replace)))
          ((hash-table-p object)
           (unless (or (member operation '(:add :replace)) (nth-value 1 (gethash part object)))
             (core-resource-error 422 "Invalid" "JSON patch path does not exist"))
           (if (eq operation :remove) (remhash part object) (setf (gethash part object) value)) object)
          ((and (vectorp object) (not (stringp object)))
           (let ((index (core-json-array-index part (length object) :add (eq operation :add))))
             (case operation
               (:replace (setf (aref object index) value) object)
               (:add (concatenate 'vector (subseq object 0 index) (vector value) (subseq object index)))
               (:remove (concatenate 'vector (subseq object 0 index) (subseq object (1+ index)))))))
          (t (core-resource-error 422 "Invalid" "JSON patch parent does not exist"))))))

(defun core-json-equal-p (left right)
  "Deep structural equality of two jzon values: hash-tables by matching keys and
   values, vectors elementwise, strings by EQUAL, numbers by =, else EQL. Used
   by the JSON Patch \"test\" operation."
  (cond
    ((and (hash-table-p left) (hash-table-p right))
     (and (= (hash-table-count left) (hash-table-count right))
          (loop for key being the hash-keys of left using (hash-value value)
                always (and (nth-value 1 (gethash key right))
                            (core-json-equal-p value (gethash key right))))))
    ((or (stringp left) (stringp right)) (equal left right))
    ((and (vectorp left) (vectorp right))
     (and (= (length left) (length right)) (every #'core-json-equal-p left right)))
    ((and (numberp left) (numberp right)) (= left right))
    (t (eql left right))))

(defun apply-core-json-patch (object patch)
  "Apply an RFC 6902 JSON Patch (a JSON array) to OBJECT and return the result.
   Supports test, add, replace, remove, copy and move; \"test\" signals a 409 on
   mismatch, and a move into its own descendant is a 422. Signals a 400 when the
   patch is not an array, an operation lacks a required value, or the op is
   unsupported."
  (unless (and (vectorp patch) (not (stringp patch)))
    (core-resource-error 400 "BadRequest" "JSON patch must be an array"))
  (loop for operation across patch
        do (require-object operation "JSON patch operation")
           (let* ((op (gethash "op" operation))
                  (path (core-json-pointer (gethash "path" operation))))
             (cond
               ((equal op "test")
                (unless (nth-value 1 (gethash "value" operation))
                  (core-resource-error 400 "BadRequest" "JSON patch test requires value"))
                ;; json-patch.v4, used by Kubernetes, treats an absent object
                ;; member as null for test. Controllers use this to install a
                ;; first finalizer atomically. Missing parents still fail.
                (let* ((parent (and path (core-json-at object (butlast path))))
                       (actual (if (hash-table-p parent)
                                   (gethash (car (last path)) parent 'null)
                                   (core-json-at object path))))
                  (unless (core-json-equal-p actual (gethash "value" operation))
                    (core-resource-error 409 "Conflict" "JSON patch test failed"))))
               ((member op '("add" "replace" "remove") :test #'equal)
                (unless (or (equal op "remove") (nth-value 1 (gethash "value" operation)))
                  (core-resource-error 400 "BadRequest" "JSON patch operation requires value"))
                (setf object (core-json-write object path (gethash "value" operation)
                                              (cond ((equal op "add") :add) ((equal op "replace") :replace) (t :remove)))))
               ((member op '("copy" "move") :test #'equal)
                (let* ((from (core-json-pointer (gethash "from" operation)))
                       (value (copy-core-object (core-json-at object from))))
                  (when (and (equal op "move") (> (length path) (length from))
                             (equal from (subseq path 0 (length from))))
                    (core-resource-error 422 "Invalid" "Cannot move a value into its own descendant"))
                  (when (equal op "move") (setf object (core-json-write object from nil :remove)))
                  (setf object (core-json-write object path value :add))))
               (t (core-resource-error 400 "BadRequest" "Unsupported JSON patch operation"))))
        finally (return object)))

(defun core-resource-patch-response (store resource namespace name dry-run)
  "Serve a PATCH on RESOURCE/NAMESPACE/NAME: dispatch by Content-Type to
   server-side apply, JSON Patch, strategic-merge or JSON merge, run the result
   through admitted update (honouring DRY-RUN), and return the stored object as a
   JSON response. Signals a 415 for any other patch media type."
  (let* ((content-type (request-media-type))
         (patch nil))
    (when (string= content-type "application/apply-patch+yaml")
      (return-from core-resource-patch-response (apply-patch-response store resource namespace name dry-run)))
    (unless (member content-type '("application/merge-patch+json" "application/strategic-merge-patch+json"
                                   "application/json-patch+json") :test #'string=)
      (core-resource-error 415 "UnsupportedMediaType" "Supported patch types are JSON merge, strategic merge, JSON patch and apply"))
    (setf patch (if (or (equal resource "customresourcedefinitions") (custom-resource-key-p resource))
                    (crd-parse-json-content (hunchentoot:raw-post-data :force-text t))
                    (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-binary t) :max-string-length (* 2 1024 1024))))
    (json-response
     (admitted-update-core-resource
      store resource namespace name
      (lambda (old)
        (workload-drop-unknown-patched-fields resource
         (if (string= content-type "application/json-patch+json")
            (apply-core-json-patch old patch)
            (if (and (or (csr-resource-p resource) (storage-resource-p resource) (endpointslice-resource-p resource)
                         (budget-resource-p resource)
                         (policy-resource-p resource) (typed-api-resource-p resource) (networking-resource-p resource)
                         (member resource '("podtemplates" "deployments" "replicasets" "replicationcontrollers" "daemonsets" "statefulsets" "controllerrevisions") :test #'equal))
                     (equal content-type "application/strategic-merge-patch+json"))
                (template-strategic-merge old (require-object patch "patch")
                  (template-schema (cond ((csr-resource-p resource) *csr-schema-name*)
                                         ((storage-resource-p resource) (storage-resource-schema-name resource))
                                         ((policy-resource-p resource) (policy-resource-schema-name resource))
                                         ((typed-api-resource-p resource) (typed-api-schema-name resource))
                                         ((networking-resource-p resource) (networking-resource-schema-name resource))
                                         ((endpointslice-resource-p resource) "io.k8s.api.discovery.v1.EndpointSlice")
                                         ((budget-resource-p resource) "io.k8s.api.policy.v1.PodDisruptionBudget")
                                         ((equal resource "podtemplates") "io.k8s.api.core.v1.PodTemplate")
                                         (t (workload-schema-name resource "")))))
                (merge-json-object old (require-object patch "patch"))))))
      :dry-run dry-run))))

(defun dispatch-core-resource-request (store path method)
  "Route and serve one core-resource request. Resolves PATH to (resource
   namespace name), validates the namespace and name for the resource kind,
   binds the per-request actor, apply manager, view version and dryRun, then
   dispatches METHOD: list or watch, get, create (201), replace, patch, delete
   and delete-collection. Signals a 400 for an invalid namespace or name and a
   405 for an unsupported method on the endpoint."
  (destructuring-bind (resource namespace name) (core-resource-route path)
    (when (and namespace (not (dns-label-p namespace)))
      (core-resource-error 400 "BadRequest" "Invalid request namespace"))
    (when (and name (not (cond ((csr-resource-p resource) (csr-path-name-p name))
                               ((rbac-resource-p resource) (path-segment-name-p name))
                               ;; A signer-linked ClusterTrustBundle is named
                               ;; <signerName with the final / as :>:<suffix>
                               ;; (KEP-3257), so its name carries colons.
                               ((equal resource "clustertrustbundles") (path-segment-name-p name))
                               ((equal resource "ipaddresses") (networking-canonical-ip-p name))
                               (t (dns-subdomain-p name)))))
      (core-resource-error 400 "BadRequest" "Invalid request name"))
    (let ((*csr-request-actor* (if (csr-resource-p resource) (csr-http-request-actor store) (core-object)))
          (*apply-update-manager* (and (member method '(:post :put :patch)) (list (apply-default-manager) nil)))
          (*core-resource-view-version* (cond ((and (equal resource "events") (uiop:string-prefix-p "/apis/" path)) "events.k8s.io/v1")
                                              ((uiop:string-prefix-p "/apis/autoscaling/v1/" path) "autoscaling/v1")
                                              ((equal resource "podcertificaterequests") (pod-certificate-request-path-version path))
                                              (t (core-resource-api-version resource))))
          (dry-run (core-resource-dry-run-p))
          (writable-scope (or namespace (not (core-resource-namespaced-p resource)))))
      (cond
        ((and (eq method :get) (null name)) (core-resource-list-response store resource namespace))
        ((and writable-scope name (eq method :get)) (json-response (get-core-resource store resource namespace name)))
        ((and writable-scope (null name) (eq method :post))
         (json-response
          (complete-created-bootstrap-resource
           store resource
           (admitted-create-core-resource store resource (core-resource-request-object (core-resource-kind resource)) namespace :dry-run dry-run)
           dry-run) 201))
        ((and writable-scope name (eq method :put))
         (let ((replacement (core-resource-request-object (core-resource-kind resource))))
           (json-response (admitted-update-core-resource store resource namespace name
                                                        (lambda (old) (declare (ignore old)) replacement) :dry-run dry-run))))
        ((and writable-scope name (eq method :patch)) (core-resource-patch-response store resource namespace name dry-run))
        ((and writable-scope (null name)
              (core-resource-delete-collection-p resource)
              (eq method :delete))
         (let* ((body (hunchentoot:raw-post-data :force-binary t))
                (options (when (and body (plusp (length body))) (core-resource-request-object "DeleteOptions")))
                (preview (gethash "dryRun" (or options (core-object)))))
           (when (and preview (not (equalp preview #("All")))) (core-resource-error 400 "BadRequest" "Invalid dryRun"))
           (when (gethash "preconditions" (or options (core-object)))
             (core-resource-error 400 "BadRequest" "DeleteCollection does not support preconditions"))
           (admit-core-delete-collection store resource namespace options (or dry-run preview))
           (cond ((equal resource "customresourcedefinitions")
                  (delete-crd-definition-collection store (or (hunchentoot:parameter "labelSelector") "")
                                                     (or (hunchentoot:parameter "fieldSelector") "") (or dry-run preview)))
                 ((csr-resource-p resource)
                  (delete-csr-collection store (or (hunchentoot:parameter "labelSelector") "") (or (hunchentoot:parameter "fieldSelector") "") :dry-run (or dry-run preview)))
                 ((or (workload-resource-p resource) (batch-resource-p resource))
                  (delete-workload-collection store resource namespace options (or dry-run preview)))
                 ((or (storage-resource-p resource) (endpointslice-resource-p resource) (policy-resource-p resource)
                      (typed-api-resource-p resource)
                      (networking-resource-p resource) (member resource '("services" "networkpolicies") :test #'equal))
                  (delete-storage-collection store resource namespace (or (hunchentoot:parameter "labelSelector") "")
                                             (or (hunchentoot:parameter "fieldSelector") "") :dry-run (or dry-run preview)))
                 (t (delete-template-collection store namespace (or (hunchentoot:parameter "labelSelector") "")
                                                (or (hunchentoot:parameter "fieldSelector") "") :dry-run (or dry-run preview) :resource resource)))
           (status-response "Success" "Deleted" "Resource collection deleted" 200)))
        ((and writable-scope name (eq method :delete))
         (let* ((body (hunchentoot:raw-post-data :force-binary t))
                (options (if (and body (plusp (length body))) (core-resource-request-object "DeleteOptions")
                             (make-hash-table :test #'equal)))
                (preconditions (gethash "preconditions" options))
                (body-dry-run (gethash "dryRun" options)))
           (when body-dry-run
             (unless (and (vectorp body-dry-run) (not (stringp body-dry-run))
                          (every (lambda (value) (equal value "All")) body-dry-run))
               (core-resource-error 400 "BadRequest" "DeleteOptions.dryRun must contain only All")))
           (when preconditions (require-object preconditions "preconditions"))
           (admit-core-delete store resource namespace name options (or dry-run (and body-dry-run (plusp (length body-dry-run)))))
           (if (or (workload-resource-p resource) (batch-resource-p resource)
                   (core-deletion-held-p store resource namespace name (workload-deletion-policy options resource)))
               (delete-workload-resource store resource namespace name :dry-run (or dry-run (and body-dry-run (plusp (length body-dry-run))))
                    :uid (and preconditions (gethash "uid" preconditions))
                    :resource-version (and preconditions (gethash "resourceVersion" preconditions))
                    :policy (workload-deletion-policy options resource))
               (delete-core-resource store resource namespace name :dry-run (or dry-run (and body-dry-run (plusp (length body-dry-run))))
                                 :uid (and preconditions (gethash "uid" preconditions))
                                 :resource-version (and preconditions (gethash "resourceVersion" preconditions))))
           (status-response "Success" "Deleted" (format nil "~A ~A deleted" (core-resource-kind resource) name) 200)))
        (t (core-resource-error 405 "MethodNotAllowed" "Method is not supported for this resource endpoint"))))))

(defun add-core-resource-openapi-paths (paths)
  "Add the OpenAPI path and operation entries for the core v1 resources served
   here (configmaps, secrets, podtemplates, replicationcontrollers -- plus their
   delete-collection and the replicationcontroller status and scale
   subresources) into PATHS, along with the Event paths. Returns PATHS."
  (dolist (resource '("configmaps" "secrets" "podtemplates" "replicationcontrollers"))
    (let* ((kind (core-resource-kind resource))
           (schema (concatenate 'string "io.k8s.api.core.v1." kind))
           (gvk (json-object "group" "" "version" "v1" "kind" kind))
           (collection (format nil "/api/v1/namespaces/{namespace}/~A" resource))
           (item (concatenate 'string collection "/{name}")))
      (labels ((parameter (name)
                 (json-object "name" name "in" "path" "required" t "schema" (json-object "type" "string")))
               (operation (verb action &key body)
                 (let ((operation
                         (json-object "operationId" (format nil "~ACoreV1Namespaced~A" action kind)
                                      "x-kubernetes-action" verb "x-kubernetes-group-version-kind" gvk
                                      "responses" (json-object "200" (json-object "description" "Success")))))
                   (when body
                     (setf (gethash "parameters" operation)
                           (vector (json-object "name" "fieldValidation" "in" "query"
                                                "schema" (json-object "type" "string"))))
                     (setf (gethash "requestBody" operation)
                           (json-object "required" t "content"
                                        (if (string= verb "patch")
                                            (json-object "application/strategic-merge-patch+json"
                                                         (json-object "schema" (reference-schema schema))
                                                         "application/merge-patch+json"
                                                         (json-object "schema" (reference-schema schema))
                                                         "application/json-patch+json"
                                                         (json-object "schema" (json-object "type" "array" "items" (json-object "type" "object"))))
                                            (json-object "application/json" (json-object "schema" (reference-schema schema)))))))
                   operation)))
        (setf (gethash collection paths)
              (json-object "parameters" (vector (parameter "namespace"))
                           "post" (operation "post" "create" :body t)
                           "get" (operation "list" "list"))
              (gethash item paths)
              (json-object "parameters" (vector (parameter "namespace") (parameter "name"))
                           "get" (operation "get" "read")
                           "put" (operation "put" "replace" :body t)
                           "patch" (operation "patch" "patch" :body t)
                           "delete" (operation "delete" "delete")))
        (when (member resource '("podtemplates" "replicationcontrollers") :test #'equal)
          (setf (gethash "delete" (gethash collection paths)) (operation "deletecollection" "deleteCollection")))
        (when (equal resource "replicationcontrollers")
          (dolist (subresource '("status" "scale"))
            (let ((schema (if (equal subresource "scale") "io.k8s.api.autoscaling.v1.Scale" schema)))
              (setf (gethash (concatenate 'string item "/" subresource) paths)
                    (json-object "parameters" (vector (parameter "namespace") (parameter "name"))
                                 "get" (operation "get" (concatenate 'string "read" subresource))
                                 "put" (operation "put" (concatenate 'string "replace" subresource) :body t)
                                 "patch" (operation "patch" (concatenate 'string "patch" subresource) :body t))))))))) 
  (add-event-openapi-paths paths nil)
  (when (equal *schema-reference-prefix* "#/definitions/") (add-event-openapi-paths paths t))
  paths)
