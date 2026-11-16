;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Store one canonical Event behind the core and events.k8s.io APIs, preserving
;;;; identity, revisions and watch history across conversions. Events expire one
;;;; hour after their last write; expiry is a real journaled deletion.

(in-package #:gr8s.resources)

(defparameter *event-clock* #'get-universal-time)
(defparameter *event-ttl-seconds* 3600)
(defparameter *event-version-fields*
  '(("involvedObject" . "regarding") ("message" . "note")
    ("reportingComponent" . "reportingController") ("source" . "deprecatedSource")
    ("firstTimestamp" . "deprecatedFirstTimestamp") ("lastTimestamp" . "deprecatedLastTimestamp")
    ("count" . "deprecatedCount")))

(defun convert-event-fields (input modern-p)
  "Rename versioned Event fields without losing zero values or mutating INPUT."
  (let ((object (copy-core-object input)))
    (dolist (pair *event-version-fields*)
      (let ((from (if modern-p (car pair) (cdr pair))) (to (if modern-p (cdr pair) (car pair))))
        (multiple-value-bind (value present) (gethash from object)
          (when present (setf (gethash to object) value) (remhash from object)))))
    (setf (gethash "apiVersion" object) (if modern-p "events.k8s.io/v1" "v1"))
    object))

(defun event-api-view (input &optional (version *core-resource-view-version*))
  "Project Event objects, lists and watch envelopes into the requested API version."
  (when (equal version "autoscaling/v1") (return-from event-api-view (hpa-api-view input)))
  (when (member version '("certificates.k8s.io/v1" "certificates.k8s.io/v1beta1") :test #'equal)
    (return-from event-api-view (pod-certificate-request-api-view input version)))
  (if (not (and (hash-table-p input) (equal version "events.k8s.io/v1"))) input
      (cond
        ((equal "Event" (gethash "kind" input)) (convert-event-fields input t))
        ((equal "EventList" (gethash "kind" input))
         (let ((object (copy-core-object input)))
           (setf (gethash "apiVersion" object) version
                 (gethash "items" object) (map 'vector (lambda (item) (event-api-view item version)) (gethash "items" object)))
           object))
        ((gethash "object" input)
         (let ((object (copy-core-object input)))
           (setf (gethash "object" object) (event-api-view (gethash "object" input) version)) object))
        (t input))))

(defun normalize-event-time (value &key micro)
  "Validate RFC3339 timestamps and normalize offsets and MicroTime precision."
  (when (eq value 'null) (return-from normalize-event-time 'null))
  (unless (stringp value) (core-resource-error 422 "Invalid" "Event timestamps must be RFC3339 strings"))
  (let ((result nil))
    (cl-ppcre:register-groups-bind (year-text month-text day-text hour-text minute-text second-text fraction zone)
        ("^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:[.]([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$" value)
      (handler-case
          (let* ((parts (mapcar #'parse-integer (list second-text minute-text hour-text day-text month-text year-text)))
                 (second (first parts)) (minute (second parts)) (hour (third parts))
                 (day (fourth parts)) (month (fifth parts)) (year (sixth parts))
                 (offset-hour (if (equal zone "Z") 0 (parse-integer zone :start 1 :end 3)))
                 (offset-minute (if (equal zone "Z") 0 (parse-integer zone :start 4 :end 6)))
                 (nanos (if fraction (parse-integer (concatenate 'string fraction (make-string (- 9 (length fraction)) :initial-element #\0))) 0)))
            (unless (and (<= 0 second 59) (<= 0 minute 59) (<= 0 hour 23) (<= 1 day 31) (<= 1 month 12)
                         (<= offset-hour 23) (<= offset-minute 59)) (error "Invalid timestamp component"))
            (let ((local (encode-universal-time second minute hour day month year 0)))
              (unless (equal parts (subseq (multiple-value-list (decode-universal-time local 0)) 0 6)) (error "Invalid calendar date"))
              (let ((utc (- local (* (if (and (plusp (length zone)) (char= (char zone 0) #\-)) -1 1)
                                      (+ (* 3600 offset-hour) (* 60 offset-minute))))))
                (multiple-value-bind (sec min hr date mon yr) (decode-universal-time utc 0)
                  (setf result (concatenate 'string
                                (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0D" yr mon date hr min sec)
                                (cond (micro (format nil ".~6,'0D" (floor nanos 1000)))
                                      ((plusp nanos) (format nil ".~9,'0D" nanos)) (t "")) "Z"))))))
        (error () (setf result nil))))
    (or result (core-resource-error 422 "Invalid" "Invalid Event timestamp ~S" value))))

(defun normalize-event-resource (input namespace name)
  "Validate either version, then store a canonical core Event with stable semantics."
  (let* ((object (copy-core-object (require-object input "Event")))
         (version (gethash "apiVersion" object (or *core-resource-view-version* "v1")))
         (modern (equal version "events.k8s.io/v1"))
         (metadata (require-object (gethash "metadata" object) "metadata")))
    (unless (and (member version '("v1" "events.k8s.io/v1") :test #'equal)
                 (or (null *core-resource-view-version*) (equal version *core-resource-view-version*))
                 (equal "Event" (gethash "kind" object "Event")))
      (core-resource-error 400 "BadRequest" "Expected an Event in the requested API version"))
    (validate-core-metadata metadata namespace name)
    (setf (gethash "apiVersion" object) version (gethash "kind" object) "Event"
          (gethash "namespace" metadata) namespace)
    (validate-template-shape object (template-schema (if modern "io.k8s.api.events.v1.Event" "io.k8s.api.core.v1.Event")) "Event")
    (when modern (setf object (convert-event-fields object nil)))
    (unless (gethash "involvedObject" object) (setf (gethash "involvedObject" object) (core-object)))
    (let* ((reference (require-object (gethash "involvedObject" object) "involvedObject"))
           (target-namespace (gethash "namespace" reference "")))
      (unless (or (equal target-namespace "") (equal namespace "default") (equal namespace target-namespace))
        (core-resource-error 422 "Invalid" "Event object reference must be in the Event namespace")))
    (dolist (field '("eventTime" "firstTimestamp" "lastTimestamp"))
      (setf (gethash field object) (normalize-event-time (gethash field object 'null) :micro (equal field "eventTime"))))
    (when (member (gethash "source" object) '(nil null)) (setf (gethash "source" object) (core-object)))
    (dolist (field '("reason" "action" "reportingComponent" "reportingInstance" "type" "message"))
      (let ((value (gethash field object "")) (bound (if (equal field "message") 1024 128)))
        (unless (and (stringp value) (<= (length (trivial-utf-8:string-to-utf-8-bytes value)) bound))
          (core-resource-error 422 "Invalid" "Invalid Event ~A" field))
        (when (and modern (member field '("reason" "action" "reportingComponent" "reportingInstance") :test #'equal) (zerop (length value)))
          (core-resource-error 422 "Invalid" "Event ~A is required" field))))
    (when (and modern (or (eq 'null (gethash "eventTime" object))
                         (not (member (gethash "type" object) '("Normal" "Warning") :test #'equal))))
      (core-resource-error 422 "Invalid" "Modern Events require eventTime and a Normal or Warning type"))
    (when (nth-value 1 (gethash "count" object))
      (unless (typep (gethash "count" object) '(integer 0 2147483647)) (core-resource-error 422 "Invalid" "Invalid Event count")))
    (let ((series (gethash "series" object)))
      (unless (or (null series) (eq series 'null))
        (require-object series "series")
        (unless (typep (gethash "count" series) '(integer 2 2147483647)) (core-resource-error 422 "Invalid" "Event series count must be at least 2"))
        (when (eq 'null (gethash "lastObservedTime" series 'null)) (core-resource-error 422 "Invalid" "Event series requires lastObservedTime"))
        (setf (gethash "lastObservedTime" series) (normalize-event-time (gethash "lastObservedTime" series) :micro t))))
    (validate-template-shape object (template-schema "io.k8s.api.core.v1.Event") "Event")
    object))

(defun validate-event-update (before after)
  "Keep the identity and reporting fields of an Event immutable while permitting series updates."
  (dolist (field '("involvedObject" "related" "eventTime" "reason" "type" "action" "reportingComponent" "reportingInstance" "source"))
    (unless (core-json-equal-p (gethash field before 'null) (gethash field after 'null))
      (core-resource-error 422 "Invalid" "Event ~A is immutable" field))))

(defun next-event-expirations (store resources)
  "Compute TTLs for a transaction without publishing state before its durable write."
  (let ((expirations (make-hash-table :test #'equal)))
    (maphash (lambda (key object)
               (when (equal "events" (first key))
                 (let* ((uid (gethash "uid" (gethash "metadata" object)))
                        (old (gethash key (pod-store-resources store)))
                        (old-expiry (gethash uid (pod-store-event-expirations store))))
                   (setf (gethash uid expirations)
                         (if (and (eq old object) old-expiry) old-expiry (+ (funcall *event-clock*) *event-ttl-seconds*)))))) resources)
    expirations))

(defun expire-core-events-unlocked (store)
  "Delete expired Events atomically, preserving actual DELETED watch events."
  (let ((now (funcall *event-clock*)) (index nil)
        ;; Event expiry is local-plane: publish locally, never replicate (8ia.3).
        (*local-plane-write* t))
    (unless (loop for expiry being the hash-values of (pod-store-event-expirations store)
                  thereis (and expiry (<= expiry now)))
      (return-from expire-core-events-unlocked nil))
    (maphash (lambda (key object)
               (when (and (equal "events" (first key))
                          (let ((expiry (gethash (gethash "uid" (gethash "metadata" object)) (pod-store-event-expirations store))))
                            (and expiry (<= expiry now))))
                 (unless index (setf index (copy-core-resource-index store)))
                 (remhash key index))) (pod-store-resources store))
    (when index (commit-core-resources store index (1+ (pod-store-resource-revision store))))))

(defun core-resource-field-paths (resource)
  "Return field selectors backed by actual attributes of this resource."
  (append '("metadata.name" "metadata.namespace")
          (when (and (custom-resource-key-p resource) *crd-view-definition*)
            (crd-selectable-field-paths *crd-view-definition* *crd-request-version*))
          (when (or (csr-resource-p resource) (equal resource "clustertrustbundles")) '("spec.signerName"))
          (when (equal resource "resourceslices") '("spec.driver" "spec.nodeName"))
          ;; pkg/apis/certificates/v1 field label conversions; signers watch by signerName.
          (when (equal resource "podcertificaterequests") '("spec.signerName" "spec.podName" "spec.nodeName"))
          (when (equal resource "events")
            '("involvedObject.kind" "involvedObject.namespace" "involvedObject.name" "involvedObject.uid"
              "involvedObject.apiVersion" "involvedObject.resourceVersion" "involvedObject.fieldPath"
              "regarding.kind" "regarding.namespace" "regarding.name" "regarding.uid"
              "regarding.apiVersion" "regarding.resourceVersion" "regarding.fieldPath"
              "reason" "type" "source" "reportingComponent" "reportingController" "reportingInstance"))))

(defun event-api-group ()
  "Describe the served modern Event API group."
  (core-object "apiVersion" "v1" "kind" "APIGroup" "name" "events.k8s.io"
               "versions" (vector (core-object "groupVersion" "events.k8s.io/v1" "version" "v1"))
               "preferredVersion" (core-object "groupVersion" "events.k8s.io/v1" "version" "v1")))

(defun event-discovery-response ()
  "Advertise the actual versioned Event CRUD, list and watch operations."
  (json-response
   (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" "events.k8s.io/v1"
                "resources" (vector (resource-discovery-entry "events" "event" t "Event"
                                                              #("create" "delete" "deletecollection" "get" "list" "patch" "update" "watch"))))))

(defun add-event-openapi-paths (paths modern-p)
  "Describe both Event API versions with their actual schemas and operations."
  (let* ((base (if modern-p "/apis/events.k8s.io/v1" "/api/v1"))
         (schema (if modern-p "io.k8s.api.events.v1.Event" "io.k8s.api.core.v1.Event"))
         (gvk (core-object "group" (if modern-p "events.k8s.io" "") "version" "v1" "kind" "Event"))
         (collection (concatenate 'string base "/namespaces/{namespace}/events"))
         (item (concatenate 'string collection "/{name}")))
    (labels ((parameter (name) (core-object "name" name "in" "path" "required" t "schema" (core-object "type" "string")))
             (operation (action &optional body)
               (let ((object (core-object "x-kubernetes-action" action "x-kubernetes-group-version-kind" gvk
                                          "responses" (core-object "200" (core-object "description" "Success")))))
                 (when body
                   (setf (gethash "parameters" object)
                         (vector (core-object "name" "fieldValidation" "in" "query"
                                              "schema" (core-object "type" "string"))))
                   (setf (gethash "requestBody" object)
                         (core-object "required" t "content"
                                      (core-object "application/json" (core-object "schema" (reference-schema schema))))))
                 object)))
      (setf (gethash collection paths)
            (core-object "parameters" (vector (parameter "namespace"))
                         "get" (operation "list") "post" (operation "post" t) "delete" (operation "deletecollection"))
            (gethash item paths)
            (core-object "parameters" (vector (parameter "namespace") (parameter "name"))
                         "get" (operation "get") "put" (operation "put" t)
                         "patch" (operation "patch" t) "delete" (operation "delete"))
            (gethash (concatenate 'string base "/events") paths) (core-object "get" (operation "list")))))
  paths)
