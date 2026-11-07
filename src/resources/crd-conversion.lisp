;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Convert custom objects between a definition's versions. Strategy None only
;;;; relabels an object; strategy Webhook sends a ConversionReview over the
;;;; admission transport. A webhook never runs under the store lock: code in a
;;;; store transaction signals CRD-CONVERSION-NEEDED, the enclosing
;;;; WITH-CRD-DEFERRED-CONVERSIONS unwinds out of the lock, converts, remembers the
;;;; answer for the request and runs the transaction again.

(in-package #:gr8s.resources)

(defparameter +crd-conversion-timeout-seconds+ 30
  "Upstream's fixed conversion webhook timeout.")

(defparameter +crd-conversion-memo-limit+ 4096
  "Remembered conversions a long-running request keeps before starting over.")

(defun crd-conversion-webhook (definition)
  "Return DEFINITION's webhook settings when it converts through one."
  (let ((conversion (gethash "conversion" (gethash "spec" definition))))
    (and (hash-table-p conversion) (equal "Webhook" (gethash "strategy" conversion))
         (gethash "webhook" conversion))))

(defun crd-conversion-memo-key (object target)
  "Identify OBJECT's exact content on its way to the TARGET apiVersion."
  (concatenate 'string target " " (com.inuoe.jzon:stringify object)))

(defun crd-conversion-failure (kind control &rest arguments)
  "Fail the request the way upstream reports a conversion webhook failure."
  (core-resource-error 500 "InternalError" "conversion webhook for ~A failed: ~?" kind control arguments))

(defun crd-review-version (webhook)
  "Pick the first ConversionReview version this server speaks from the webhook's preference."
  (or (find-if (lambda (version) (member version '("v1" "v1beta1") :test #'equal))
               (gethash "conversionReviewVersions" webhook))
      "v1"))

(defun crd-converted-objects (review version uid kind)
  "Check a ConversionReview response as upstream does and return its converted objects."
  (unless (hash-table-p review) (crd-conversion-failure kind "response is not an object"))
  (when (equal version "v1")
    (unless (and (equal "apiextensions.k8s.io/v1" (gethash "apiVersion" review))
                 (equal "ConversionReview" (gethash "kind" review)))
      (crd-conversion-failure kind "expected webhook response of apiextensions.k8s.io/v1, Kind=ConversionReview, got ~A, Kind=~A"
                              (gethash "apiVersion" review) (gethash "kind" review))))
  (let ((response (gethash "response" review)))
    (unless (hash-table-p response) (crd-conversion-failure kind "no response provided"))
    (unless (equal uid (gethash "uid" response))
      (crd-conversion-failure kind "expected response.uid=~S, got ~S" uid (gethash "uid" response)))
    (let* ((result (let ((value (gethash "result" response))) (if (hash-table-p value) value (core-object))))
           (status (gethash "status" result)))
      (cond ((equal version "v1")
             (unless (equal "Success" status)
               (let ((message (gethash "message" result)))
                 (if (and (stringp message) (plusp (length message)))
                     (crd-conversion-failure kind "response.result.status was ~S: ~A" status message)
                     (crd-conversion-failure kind "response.result.status was ~S, not 'Success'" status)))))
            ((equal "Failure" status)
             (crd-conversion-failure kind "~A" (gethash "message" result "webhook reported failure")))))
    (let ((objects (gethash "convertedObjects" response)))
      (if (crd-array-p objects) objects #()))))

(defun crd-restore-converted-metadata (original converted kind)
  "Keep only the labels and annotations a webhook returned, as upstream restoreObjectMeta does."
  (let ((before (gethash "metadata" original)) (after (gethash "metadata" converted)))
    (unless (hash-table-p after) (crd-conversion-failure kind "missing metadata in converted object"))
    (dolist (field '("name" "namespace" "uid"))
      (unless (equal (gethash field before "") (gethash field after ""))
        (crd-conversion-failure kind "converted object must have the same ~A: ~A != ~A"
                                field (gethash field before "") (gethash field after ""))))
    (let ((metadata (copy-core-object before)))
      (dolist (field '("labels" "annotations"))
        (multiple-value-bind (value present) (gethash field after)
          (cond ((or (not present) (eq value 'null)) (remhash field metadata))
                ((not (hash-table-p value))
                 (crd-conversion-failure kind "invalid metadata.~A in converted object" field))
                (t (setf (gethash field metadata) value)))))
      (handler-case (validate-core-metadata (copy-core-object metadata) (gethash "namespace" metadata) (gethash "name" metadata))
        (kubernetes-error (condition)
          (crd-conversion-failure kind "invalid metadata in converted object: ~A" (kubernetes-error-message condition))))
      (setf (gethash "metadata" converted) metadata)
      converted)))

(defun crd-webhook-convert (definition objects target)
  "Ask DEFINITION's webhook to convert OBJECTS to TARGET, remembering each answer."
  (let* ((webhook (crd-conversion-webhook definition))
         (kind (format nil "~A, Kind=~A" target (gethash "kind" (gethash "names" (gethash "spec" definition)))))
         (version (crd-review-version webhook))
         (uid (generate-uid))
         (body (com.inuoe.jzon:stringify
                (core-object "apiVersion" (format nil "apiextensions.k8s.io/~A" version) "kind" "ConversionReview"
                             "request" (core-object "uid" uid "desiredAPIVersion" target
                                                    "objects" (coerce objects 'vector)))))
         (review (handler-case
                     (admission-call-webhook *crd-view-store*
                                             (core-object "clientConfig" (gethash "clientConfig" webhook)
                                                          "timeoutSeconds" +crd-conversion-timeout-seconds+)
                                             body)
                   (admission-call-failure (condition)
                     (crd-conversion-failure kind "~A" (admission-call-failure-message condition)))))
         (converted (crd-converted-objects review version uid kind)))
    (unless (= (length converted) (length objects))
      (core-resource-error 500 "InternalError" "conversion webhook for ~A returned ~D objects, expected ~D"
                           kind (length converted) (length objects)))
    (loop for original in objects
          for object across converted
          for index from 0
          do (unless (hash-table-p object)
               (crd-conversion-failure kind "returned invalid converted object at index ~D" index))
             (unless (equal target (gethash "apiVersion" object))
               (crd-conversion-failure kind "returned invalid converted object at index ~D: invalid groupVersion (expected ~A, received ~A)"
                                       index target (gethash "apiVersion" object)))
             (unless (equal (gethash "kind" original) (gethash "kind" object))
               (crd-conversion-failure kind "returned invalid converted object at index ~D: invalid kind (expected ~A, received ~A)"
                                       index (gethash "kind" original) (gethash "kind" object)))
             (setf (gethash (crd-conversion-memo-key original target) *crd-conversion-memo*)
                   (crd-restore-converted-metadata original object kind)))))

(defun crd-perform-deferred-conversion (condition)
  "Run the conversion a store transaction asked for, now that it has released the lock."
  (let ((*crd-conversion-deferred* nil))
    (unless *crd-conversion-memo* (setf *crd-conversion-memo* (make-hash-table :test #'equal)))
    (crd-webhook-convert (crd-conversion-needed-definition condition)
                         (crd-conversion-needed-objects condition)
                         (crd-conversion-needed-target condition))))

(defun crd-convert-objects (definition objects version)
  "Return copies of the list OBJECTS at VERSION of DEFINITION, in order."
  (let* ((group (gethash "group" (gethash "spec" definition)))
         (target (format nil "~A/~A" group version)))
    (flet ((current-p (object) (equal target (gethash "apiVersion" object))))
      (if (not (crd-conversion-webhook definition))
          (mapcar (lambda (object)
                    (let ((copy (copy-core-object object)))
                      (setf (gethash "apiVersion" copy) target)
                      copy))
                  objects)
          (let ((memo *crd-conversion-memo*))
            (when (and memo (> (hash-table-count memo) +crd-conversion-memo-limit+)) (clrhash memo))
            (let ((pending (let ((seen (make-hash-table :test #'equal)))
                             (loop for object in objects
                                   for key = (and (not (current-p object)) (crd-conversion-memo-key object target))
                                   when (and key (not (gethash key seen)) (not (and memo (gethash key memo))))
                                     do (setf (gethash key seen) t) and collect object))))
              (when pending
                (when *crd-conversion-deferred*
                  (error 'crd-conversion-needed :definition definition :objects pending :target target))
                (let ((*crd-conversion-memo* (or memo (make-hash-table :test #'equal))))
                  (crd-webhook-convert definition pending target)
                  (setf memo *crd-conversion-memo*))))
            (mapcar (lambda (object)
                      (copy-core-object
                       (if (current-p object) object (gethash (crd-conversion-memo-key object target) memo))))
                    objects))))))

(defun crd-object-at-version (definition object version)
  "Return a copy of OBJECT at VERSION of DEFINITION."
  (first (crd-convert-objects definition (list object) version)))

(defun crd-selector-needs-view-p (fields)
  "Test whether a field selector reads anything besides metadata, which conversion cannot change."
  (and (stringp fields) (plusp (length fields))
       (notevery (lambda (term) (uiop:string-prefix-p "metadata." term)) (core-selector-terms fields))))

(defun crd-field-selector-test (resource fields)
  "Build the field selector for RESOURCE, reading custom objects at the requested version."
  (let ((test (core-selector-predicate fields :fields t :field-paths (core-resource-field-paths resource))))
    (if (and (custom-resource-key-p resource) *crd-view-definition* (crd-selector-needs-view-p fields))
        (lambda (object) (funcall test (crd-api-view object)))
        test)))

(defun crd-prepare-selector-views (store resource namespace fields)
  "Convert a collection in one review before selecting from it, instead of one object per retry."
  (when (and (custom-resource-key-p resource) *crd-view-definition* (crd-selector-needs-view-p fields)
             (crd-conversion-webhook *crd-view-definition*))
    (crd-convert-objects *crd-view-definition* (list-core-resources store resource namespace) *crd-request-version*)))

(defun crd-selectable-field-paths (definition version)
  "Name the field selector paths VERSION of DEFINITION declares."
  (let ((entry (crd-version definition version)))
    (when entry
      (loop for field across (gethash "selectableFields" entry #())
            collect (string-left-trim "." (gethash "jsonPath" field))))))
