;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Store PodTemplates independently of the executable Pod subset. Pinned
;;;; Kubernetes schemas describe all nested PodSpec fields for protobuf input,
;;;; structural validation, OpenAPI discovery and strategic merge patching.
;;;; The wire decoder is also shared by executable Pods and Services.

(in-package #:gr8s.resources)

(defparameter *podtemplate-schema*
  (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "schema/podtemplate-v1.json")))

(defun template-schema (name)
  "Return a pinned Kubernetes structural definition by NAME."
  (or (gethash name (gethash "definitions" *podtemplate-schema*))
      (error "Unknown template schema ~A" name)))

(defun resolve-template-schema (schema)
  "Resolve a structural schema reference without changing shared definitions."
  (if (gethash "$ref" schema)
      (template-schema (car (last (uiop:split-string (gethash "$ref" schema) :separator '(#\/))))) schema))

(defun template-protobuf-scalar (type field depth)
  "Decode a scalar or nested message with its declared wire type."
  (destructuring-bind (number wire value) field
    (declare (ignore number))
    (cond
      ((member type '("double" "float") :test #'equal)
       (unless (and (= wire (if (equal type "double") 1 5)) (= (length value) (if (equal type "double") 8 4)))
         (error "Incorrect floating-point protobuf wire type"))
       (let* ((bits (loop for byte across value for shift from 0 by 8 sum (ash byte shift)))
              (high (if (equal type "double") (ldb (byte 32 32) bits) bits))
              (signed (if (logbitp 31 high) (- high #x100000000) high))
              (number (if (equal type "double") (sb-kernel:make-double-float signed (ldb (byte 32 0) bits))
                          (sb-kernel:make-single-float signed))))
         (when (or (sb-ext:float-nan-p number) (sb-ext:float-infinity-p number)) (error "Non-finite protobuf number"))
         number))
      ((member type '("bool" "int32" "int64") :test #'equal)
       (unless (= wire 0) (error "Incorrect template scalar wire type"))
       (cond ((equal type "bool") (unless (member value '(0 1)) (error "Invalid protobuf boolean")) (= value 1))
             (t (let* ((bits (if (equal type "int32") 32 64)) (value (ldb (byte bits 0) value)))
                  (if (logbitp (1- bits) value) (- value (ash 1 bits)) value)))))
      (t
       (unless (= wire 2) (error "Incorrect template message wire type"))
       (cond ((equal type "string") (trivial-utf-8:utf-8-bytes-to-string value))
             ((equal type "bytes") (ag-grpc:base64-encode value))
             (t (template-protobuf-message type value (1+ depth))))))))

(defun protobuf-timestamp-fields (seconds)
  "Split Unix SECONDS into proleptic Gregorian UTC fields, covering Go's zero time in year 1."
  (multiple-value-bind (days second-of-day) (floor seconds 86400)
    ;; Days-to-civil over 400-year eras, shifted so each computed year starts in March.
    (let* ((shifted (+ days 719468)) (era (floor shifted 146097)) (day-of-era (- shifted (* era 146097)))
           (year-of-era (floor (- day-of-era (floor day-of-era 1460) (- (floor day-of-era 36524)) (floor day-of-era 146096)) 365))
           (day-of-year (- day-of-era (- (+ (* 365 year-of-era) (floor year-of-era 4)) (floor year-of-era 100))))
           (shifted-month (floor (+ (* 5 day-of-year) 2) 153))
           (day (1+ (- day-of-year (floor (+ (* 153 shifted-month) 2) 5))))
           (month (if (< shifted-month 10) (+ shifted-month 3) (- shifted-month 9)))
           (year (+ year-of-era (* era 400) (if (<= month 2) 1 0))))
      (values year month day (floor second-of-day 3600) (floor (mod second-of-day 3600) 60) (mod second-of-day 60)))))

(defun template-protobuf-message (name bytes &optional (depth 0))
  "Decode all declared PodTemplate message fields, including maps and repeated messages."
  (when (> depth 64) (error "Template protobuf nesting exceeds 64"))
  (let ((descriptor (gethash name (gethash "messages" *podtemplate-schema*)))
        (object (core-object)))
    (unless descriptor (error "Unknown template protobuf message ~A" name))
    (dolist (field
             (loop for field in (core-protobuf-fields bytes)
                   for definition = (gethash (write-to-string (first field)) descriptor)
                   append (if (and definition (gethash "repeated" definition) (= 2 (second field))
                                   (member (gethash "type" definition) '("int32" "int64" "bool") :test #'equal))
                              (let* ((data (third field)) (source (cons data 0)))
                                (loop while (< (cdr source) (length data))
                                      do (when (> (incf *core-protobuf-field-count*) 65536) (error "Too many packed values"))
                                      collect (list (first field) 0 (ag-proto::read-varint source))))
                              (list field))))
      (let ((definition (gethash (write-to-string (first field)) descriptor)))
        (when definition
          (let* ((key (gethash "name" definition)) (type (gethash "type" definition))
                 (value
                   (if (gethash "mapKey" definition)
                       (progn
                         (unless (= 2 (second field)) (error "Incorrect map wire type"))
                         (let* ((entry (core-protobuf-fields (third field)))
                                (map-key (core-protobuf-string entry 1))
                                (map-value (find 2 entry :key #'first))
                                (map (or (gethash key object) (setf (gethash key object) (core-object)))))
                           (setf (gethash map-key map)
                                 (if map-value (template-protobuf-scalar type map-value depth)
                                     (if (equal type "string") "" (template-protobuf-message type #() (1+ depth)))))
                           map))
                       (template-protobuf-scalar type field depth))))
            (cond ((and (gethash "omitEmpty" definition)
                        (or (null value) (equal value "") (and (numberp value) (zerop value)))) nil)
                  ((gethash "inline" definition) (maphash (lambda (key value) (setf (gethash key object) value)) value))
                  ((gethash "repeated" definition) (push value (gethash key object)))
                  (t (setf (gethash key object) value)))))))
    (maphash (lambda (number definition)
               (declare (ignore number))
               (let ((key (gethash "name" definition)))
                 (when (and (gethash "repeated" definition) (gethash key object))
                   (setf (gethash key object) (coerce (nreverse (gethash key object)) 'vector))))) descriptor)
    (cond
      ((uiop:string-prefix-p "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1." name)
       (crd-protobuf-json-value name object))
      ((equal name "k8s.io.apimachinery.pkg.api.resource.Quantity") (gethash "string" object "0"))
      ((equal name "k8s.io.apimachinery.pkg.util.intstr.IntOrString")
       (if (= 1 (gethash "type" object 0)) (gethash "strVal" object "") (gethash "intVal" object 0)))
      ((equal name "k8s.io.apimachinery.pkg.runtime.RawExtension")
       ;; Keep the client's key order: a revision's data is compared byte for byte.
       (let ((raw (gethash "raw" object)))
         (if raw (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string (ag-grpc:base64-decode raw))) (core-object))))
      ((member name '("k8s.io.api.authorization.v1.ExtraValue" "k8s.io.api.authentication.v1.ExtraValue") :test #'equal)
       (gethash "items" object #()))
      ((equal name "k8s.io.apimachinery.pkg.apis.meta.v1.FieldsV1")
       (let ((raw (gethash "Raw" object)))
         (if raw (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string (ag-grpc:base64-decode raw))) (core-object))))
      ((member name '("k8s.io.apimachinery.pkg.apis.meta.v1.Time" "k8s.io.apimachinery.pkg.apis.meta.v1.MicroTime") :test #'equal)
       (if (zerop (hash-table-count object)) 'null
           (multiple-value-bind (year month day hour minute second)
               (protobuf-timestamp-fields (gethash "seconds" object 0))
             (let ((nanos (gethash "nanos" object 0)))
               (unless (<= 0 nanos 999999999) (error "Invalid protobuf timestamp nanoseconds"))
               (concatenate 'string (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0D" year month day hour minute second)
                            (cond ((equal name "k8s.io.apimachinery.pkg.apis.meta.v1.MicroTime") (format nil ".~6,'0D" (floor nanos 1000)))
                                  ((zerop nanos) "") (t (format nil ".~9,'0D" nanos))) "Z")))))
      (t object))))

(defun decode-podtemplate-protobuf (bytes)
  "Decode PodTemplate input while preserving nested PodSpec fields outside the runtime subset."
  (let* ((object (template-protobuf-message "k8s.io.api.core.v1.PodTemplate" bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1)))
    ;; Request ObjectMeta has optional zero-valued Go fields; reuse admission's
    ;; metadata decoder for the outer resource identity and preconditions.
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) "v1" (gethash "kind" object) "PodTemplate")
    object))

(defvar *pod-status-write* nil
  "True while decoding a status write, the only request whose client status counts.")

(defun decode-pod-protobuf (bytes)
  "Decode typed Pod input using the pinned core schema and server-owned status."
  (let* ((object (template-protobuf-message "k8s.io.api.core.v1.Pod" bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) "v1" (gethash "kind" object) "Pod")
    ;; The Pod creation strategy owns status; client status never drives runtime.
    (remhash "status" object)
    (when *pod-status-write*
      (let ((status (core-protobuf-value (core-protobuf-fields bytes) 3)))
        (setf (gethash "status" object) (if status (decode-pod-status-protobuf status) (core-object)))))
    object))

(defun decode-service-protobuf (bytes)
  "Decode Service wire fields before applying normal allocation and runtime admission."
  (let* ((object (template-protobuf-message "k8s.io.api.core.v1.Service" bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) "v1" (gethash "kind" object) "Service")
    object))

(defun decode-bootstrap-protobuf (bytes kind version)
  "Decode typed ServiceAccounts and RBAC resources through their pinned schemas."
  (let* ((package (if (equal kind "ServiceAccount") "k8s.io.api.core.v1." "k8s.io.api.rbac.v1."))
         (object (template-protobuf-message (concatenate 'string package kind) bytes))
         (metadata (core-protobuf-value (core-protobuf-fields bytes) 1)))
    (setf (gethash "metadata" object) (if metadata (core-protobuf-metadata metadata) (core-object))
          (gethash "apiVersion" object) version (gethash "kind" object) kind)
    object))

(defun strategic-merge-order (server-only patched order key)
  "Interleave list entries as Kubernetes does: a server entry stays ahead of a patched one only
when both were on the server and it came first, so entries new to the list lead the rest."
  (let ((result nil))
    (flet ((position-of (item) (position (gethash key item) order :test #'equal)))
      (loop while (or server-only patched)
            do (let ((left (first server-only)) (right (first patched)))
                 (if (and left (or (null right)
                                   (and (position-of left) (position-of right)
                                        (< (position-of left) (position-of right)))))
                     (push (pop server-only) result)
                     (push (pop patched) result)))))
    (coerce (nreverse result) 'vector)))

(defun template-strategic-merge (old patch schema)
  "Apply schema-declared merge keys instead of replacing named container and volume lists."
  (setf schema (resolve-template-schema schema))
  (cond
    ((hash-table-p patch)
     (when (equal "delete" (gethash "$patch" patch)) (return-from template-strategic-merge 'null))
     (when (equal "replace" (gethash "$patch" patch))
       (let ((copy (copy-core-object patch))) (remhash "$patch" copy) (return-from template-strategic-merge copy)))
     (let ((result (if (hash-table-p old) old (core-object))) (properties (gethash "properties" schema)))
       (maphash (lambda (key value)
                  (unless (or (equal key "$patch") (uiop:string-prefix-p "$setElementOrder/" key))
                    (if (eq value 'null) (remhash key result)
                        (let ((merged (template-strategic-merge (gethash key result) value
                                                               (or (and properties (gethash key properties)) (core-object)))))
                          (if (eq merged 'null) (remhash key result) (setf (gethash key result) merged)))))) patch)
       (maphash (lambda (directive order)
                  (when (uiop:string-prefix-p "$setElementOrder/" directive)
                    (let* ((field (subseq directive (length "$setElementOrder/")))
                           (child (and properties (gethash field properties)))
                           (merge-key (and child (gethash "x-kubernetes-patch-merge-key" child)))
                           (items (gethash field result)))
                      (unless (and merge-key (vectorp order) (not (stringp order))
                                   (vectorp items) (not (stringp items)))
                        (core-resource-error 422 "Invalid" "Invalid strategic list ordering"))
                      (let ((ordered nil))
                        (loop for entry across order
                              for item = (and (hash-table-p entry)
                                              (find (gethash merge-key entry) items
                                                    :key (lambda (item) (gethash merge-key item)) :test #'equal))
                              do (unless (and item (not (member item ordered :test #'eq)))
                                   (core-resource-error 422 "Invalid" "Invalid strategic list ordering key"))
                                 (push item ordered))
                        (setf ordered (nreverse ordered))
                        (setf (gethash field result)
                              (coerce (append ordered (remove-if (lambda (item) (member item ordered :test #'eq)) (coerce items 'list)))
                                      'vector)))))) patch)
       result))
    ((and (vectorp patch) (not (stringp patch))
          (search "merge" (gethash "x-kubernetes-patch-strategy" schema "")))
     (let* ((key (gethash "x-kubernetes-patch-merge-key" schema))
            (items (coerce (or old #()) 'list)))
       (when (and (plusp (length patch)) (hash-table-p (aref patch 0)) (gethash "$patch" (aref patch 0)))
         (let ((directive (gethash "$patch" (aref patch 0))))
           ;; A delete naming an entry removes that entry, in the loop below; a bare one the whole list.
           (when (or (equal directive "replace")
                     (and (equal directive "delete") (not (and key (gethash key (aref patch 0))))))
             (return-from template-strategic-merge (if (equal directive "delete") #() (copy-core-object (subseq patch 1)))))))
       (if key
           (let ((order (mapcar (lambda (item) (gethash key item)) items)) (patched nil))
             (loop for item across patch
                   do (let ((before (find (gethash key item) items :key (lambda (entry) (gethash key entry)) :test #'equal)))
                        (cond ((equal "delete" (gethash "$patch" item)) (setf items (remove before items :test #'eq)))
                              (before (setf items (remove before items :test #'eq))
                                      (push (template-strategic-merge before item (gethash "items" schema)) patched))
                              (t (push (copy-core-object item) patched)))))
             (strategic-merge-order items (nreverse patched) order key))
           (progn
             (loop for item across patch
                   do (unless (find item items :test #'core-json-equal-p) (setf items (append items (list item)))))
             (coerce items 'vector)))))
    (t (copy-core-object patch))))

(defun delete-template-collection (store namespace labels fields &key dry-run (resource "podtemplates"))
  "Delete selector-matched stored objects in one atomic durable transaction."
  (let ((label-test (core-selector-predicate labels))
        (field-test (core-selector-predicate fields :fields t :field-paths (core-resource-field-paths resource)))
        (*local-plane-write* (local-plane-resource-p resource)))
    (with-store-lock (store)
      (let ((index (copy-core-resource-index store)) (changed nil))
        (maphash (lambda (key object)
                   (when (and (equal resource (first key)) (equal namespace (second key))
                              (funcall label-test object) (funcall field-test object))
                     (remhash key index) (setf changed t))) (pod-store-resources store))
        (when (and changed (not dry-run)) (commit-core-resources store index (1+ (pod-store-resource-revision store))))))))

(defun validate-template-shape (value schema path &optional (depth 0))
  "Validate Kubernetes structural types and list identities without applying runtime limitations."
  (when (> depth 64) (core-resource-error 422 "Invalid" "Template nesting exceeds 64"))
  (when (eq value 'null) (return-from validate-template-shape value))
  (when (and (gethash "$ref" schema) (search "resource.Quantity" (gethash "$ref" schema)) (numberp value))
    (return-from validate-template-shape value))
  (setf schema (resolve-template-schema schema))
  (let ((type (gethash "type" schema)))
    (cond
      ((or (gethash "x-kubernetes-int-or-string" schema) (equal "int-or-string" (gethash "format" schema)))
       (unless (or (integerp value) (stringp value)) (core-resource-error 422 "Invalid" "~A requires a string or integer" path)))
      ((equal type "object")
       (require-object value path)
       (let ((properties (gethash "properties" schema)) (extra (gethash "additionalProperties" schema)))
         (loop for required across (gethash "required" schema #())
               unless (and (nth-value 1 (gethash required value)) (not (eq 'null (gethash required value))))
                 do (core-resource-error 422 "Invalid" "~A.~A is required" path required))
         (maphash (lambda (key item)
                    (let ((child (and properties (gethash key properties))))
                      (cond (child (validate-template-shape item child (format nil "~A.~A" path key) (1+ depth)))
                            ((hash-table-p extra) (validate-template-shape item extra path (1+ depth)))
                            ((or (eq extra t) (null properties)) nil)
                            (t (core-resource-error 422 "Invalid" "Unsupported field ~A.~A" path key))))) value)))
      ((equal type "array")
       (unless (and (vectorp value) (not (stringp value))) (core-resource-error 422 "Invalid" "~A must be an array" path))
       (loop for item across value do (validate-template-shape item (gethash "items" schema) path (1+ depth)))
       (let ((keys (gethash "x-kubernetes-list-map-keys" schema)) (seen (make-hash-table :test #'equal)))
         (when keys
           (loop for item across value for key = (loop for field across keys collect (gethash field item))
                 do (when (gethash key seen) (core-resource-error 422 "Invalid" "Duplicate entry in ~A" path))
                    (setf (gethash key seen) t)))))
      ((equal type "string") (unless (stringp value) (core-resource-error 422 "Invalid" "~A must be a string" path)))
      ((equal type "boolean") (unless (member value '(nil t)) (core-resource-error 422 "Invalid" "~A must be boolean" path)))
      ((equal type "integer")
       (unless (and (integerp value)
                    (if (equal "int32" (gethash "format" schema)) (typep value '(signed-byte 32)) (typep value '(signed-byte 64))))
         (core-resource-error 422 "Invalid" "~A must be an integer of the declared width" path)))
      ((equal type "number") (unless (numberp value) (core-resource-error 422 "Invalid" "~A must be numeric" path)))))
  value)

(defun normalize-podtemplate (input namespace name)
  "Validate and default a stored PodTemplate without creating or scheduling any Pods."
  (let* ((object (copy-core-object (require-object input "PodTemplate")))
         (metadata (require-object (gethash "metadata" object) "metadata"))
         (template (require-object (gethash "template" object) "template"))
         (spec (require-object (gethash "spec" template) "template.spec")))
    (unless (and (equal "PodTemplate" (gethash "kind" object "PodTemplate"))
                 (equal "v1" (gethash "apiVersion" object "v1")))
      (core-resource-error 400 "BadRequest" "Expected v1 PodTemplate"))
    (validate-core-metadata metadata namespace name)
    (setf (gethash "apiVersion" object) "v1" (gethash "kind" object) "PodTemplate"
          (gethash "namespace" metadata) namespace)
    (validate-template-shape object (template-schema "io.k8s.api.core.v1.PodTemplate") "PodTemplate")
    (let* ((embedded (gethash "metadata" template (core-object))) (check (copy-core-object embedded)))
      (unless (gethash "name" check) (setf (gethash "name" check) "template"))
      (when (equal "" (gethash "name" check)) (setf (gethash "name" check) "template"))
      (when (equal "" (gethash "namespace" check)) (remhash "namespace" check))
      (validate-core-metadata check (gethash "namespace" check) nil))
    (loop for (key default) in '(("restartPolicy" "Always") ("dnsPolicy" "ClusterFirst") ("schedulerName" "default-scheduler"))
          when (member (gethash key spec) '(nil null "") :test #'equal) do (setf (gethash key spec) default))
    (unless (nth-value 1 (gethash "terminationGracePeriodSeconds" spec)) (setf (gethash "terminationGracePeriodSeconds" spec) 30))
    (unless (gethash "securityContext" spec) (setf (gethash "securityContext" spec) (core-object)))
    ;; SetObjectDefaults_PodTemplate applies SetDefaults_PodSpec and the nested defaults, but not
    ;; SetDefaults_Pod's: a template has no enableServiceLinks default.
    (default-pod-template-spec-object spec)
    (unless (member (gethash "restartPolicy" spec) '("Always" "OnFailure" "Never") :test #'equal)
      (core-resource-error 422 "Invalid" "Invalid template restartPolicy"))
    (unless (member (gethash "dnsPolicy" spec) '("ClusterFirst" "ClusterFirstWithHostNet" "Default" "None") :test #'equal)
      (core-resource-error 422 "Invalid" "Invalid template dnsPolicy"))
    (let ((names (make-hash-table :test #'equal)))
      (dolist (key '("containers" "initContainers" "ephemeralContainers"))
        (let ((containers (gethash key spec #())))
          (unless (and (vectorp containers) (not (stringp containers))) (core-resource-error 422 "Invalid" "~A must be an array" key))
          (when (and (equal key "containers") (zerop (length containers))) (core-resource-error 422 "Invalid" "template requires containers"))
          (loop for container across containers
                do (require-object container "container")
                   (require-dns-label (gethash "name" container) "container name")
                   (when (gethash (gethash "name" container) names) (core-resource-error 422 "Invalid" "Duplicate template container name"))
                   (setf (gethash (gethash "name" container) names) t)
                   (unless (and (stringp (gethash "image" container)) (plusp (length (gethash "image" container))))
                     (core-resource-error 422 "Invalid" "Container image is required"))
                   (loop for (field default) in '(("terminationMessagePath" "/dev/termination-log") ("terminationMessagePolicy" "File"))
                         when (member (gethash field container) '(nil null "") :test #'equal) do (setf (gethash field container) default))
                   (when (member (gethash "imagePullPolicy" container) '(nil null "") :test #'equal)
                     (setf (gethash "imagePullPolicy" container) (default-image-pull-policy (gethash "image" container))))
                   (unless (member (gethash "imagePullPolicy" container) '("Always" "IfNotPresent" "Never") :test #'equal)
                     (core-resource-error 422 "Invalid" "Invalid imagePullPolicy"))
                   (loop for port across (gethash "ports" container #())
                         do (unless (<= 1 (gethash "containerPort" port) 65535) (core-resource-error 422 "Invalid" "Invalid container port"))
                            (when (member (gethash "protocol" port) '(nil "") :test #'equal) (setf (gethash "protocol" port) "TCP"))
                            (unless (member (gethash "protocol" port) '("TCP" "UDP" "SCTP") :test #'equal)
                              (core-resource-error 422 "Invalid" "Invalid port protocol")))))))
    (validate-template-shape object (template-schema "io.k8s.api.core.v1.PodTemplate") "PodTemplate")
    ;; Keep protobuf's larger transport budget from admitting strings that
    ;; cannot be read back by the durable JSON store's 2 MiB string limit.
    (when (> (length (trivial-utf-8:string-to-utf-8-bytes (com.inuoe.jzon:stringify object))) (* 2 1024 1024))
      (core-resource-error 413 "RequestEntityTooLarge" "PodTemplate exceeds the 2 MiB storage limit"))
    object))
