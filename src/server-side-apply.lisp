;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve application/apply-patch+yaml: declare fields for a named manager,
;;;; record ownership in metadata.managedFields, report conflicts with other
;;;; appliers and drop what a manager stops declaring. Lists are atomic, and
;;;; only Apply managers own fields; Update operations do not yet record any.

(in-package #:gr8s)

(defparameter +apply-owned-metadata+ '("labels" "annotations" "finalizers" "ownerReferences")
  "Metadata fields an applier may own; the rest belong to the server or the request.")

(defun apply-field-set (object)
  "Describe OBJECT's fields in FieldsV1 form, treating lists and scalars as leaves."
  (let ((set (core-object)))
    (maphash (lambda (key value)
               (setf (gethash (concatenate 'string "f:" key) set)
                     (if (and (hash-table-p value) (plusp (hash-table-count value)))
                         (apply-field-set value)
                         (core-object))))
             object)
    set))

(defun apply-field-paths (set &optional prefix)
  "Flatten a FieldsV1 set into its leaf paths, each a list of field names."
  (loop for key being the hash-keys of set using (hash-value child)
        for path = (append prefix (list (if (uiop:string-prefix-p "f:" key) (subseq key 2) key)))
        if (and (hash-table-p child) (plusp (hash-table-count child)))
          append (apply-field-paths child path)
        else collect path))

(defun apply-path-prefix-p (left right)
  "Report whether field path LEFT contains RIGHT or equals it."
  (and (<= (length left) (length right)) (equal left (subseq right 0 (length left)))))

(defun apply-path-text (path)
  "Format a field path as Kubernetes reports it in conflicts, such as .spec.foo."
  (format nil "~{.~A~}" path))

(defun apply-value-at (object path)
  "Return the value at PATH and whether it is present."
  (let ((value object))
    (dolist (key path (values value t))
      (unless (hash-table-p value) (return (values nil nil)))
      (multiple-value-bind (child present) (gethash key value)
        (unless present (return (values nil nil)))
        (setf value child)))))

(defun apply-remove-path (object path)
  "Delete the field at PATH and any parent map the deletion leaves empty."
  (when (hash-table-p object)
    (let ((key (first path)))
      (if (rest path)
          (let ((child (gethash key object)))
            (when (hash-table-p child)
              (apply-remove-path child (rest path))
              (when (zerop (hash-table-count child)) (remhash key object))))
          (remhash key object)))))

(defun apply-overlay (target applied)
  "Write APPLIED over TARGET, merging maps; a declared null removes the field."
  (maphash (lambda (key value)
             (cond ((eq value 'null) (remhash key target))
                   ((and (hash-table-p value) (hash-table-p (gethash key target)))
                    (apply-overlay (gethash key target) value))
                   (t (setf (gethash key target) (copy-core-object value)))))
           applied)
  target)

(defun apply-owned-configuration (configuration resource)
  "Reduce CONFIGURATION to the fields a manager comes to own by declaring them."
  (let ((owned (copy-core-object configuration)))
    (remhash "apiVersion" owned)
    (remhash "kind" owned)
    (when (or (not (custom-resource-key-p resource)) (apply-status-subresource-p))
      (remhash "status" owned))
    (let ((metadata (gethash "metadata" owned)))
      (when (hash-table-p metadata)
        (dolist (key (loop for key being the hash-keys of metadata collect key))
          (unless (member key +apply-owned-metadata+ :test #'equal) (remhash key metadata)))
        (when (zerop (hash-table-count metadata)) (remhash "metadata" owned))))
    owned))

(defun apply-status-subresource-p ()
  "Report whether the requested custom version serves status separately."
  (let ((version (and *crd-view-definition* (crd-version *crd-view-definition* *crd-request-version*))))
    (and version (nth-value 1 (gethash "status" (gethash "subresources" version (core-object)))))))

(defun apply-field-manager ()
  "Read the mandatory manager name; Apply has no user agent fallback."
  (let ((manager (hunchentoot:parameter "fieldManager")))
    (unless (and manager (plusp (length manager)))
      (core-resource-error 400 "BadRequest" "fieldManager is required for apply patch"))
    (when (or (> (length manager) 128) (some (lambda (character) (not (graphic-char-p character))) manager))
      (core-resource-error 422 "Invalid" "fieldManager: must be printable and at most 128 characters"))
    manager))

(defun apply-managed-entries (object)
  "Return OBJECT's managed field entries as a list."
  (let ((entries (gethash "managedFields" (gethash "metadata" object))))
    (when (crd-array-p entries) (coerce entries 'list))))

(defun apply-entry (manager api-version set)
  "Build the ownership record of one apply."
  (core-object "manager" manager "operation" "Apply" "apiVersion" api-version
               "time" (current-timestamp) "fieldsType" "FieldsV1" "fieldsV1" set))

(defun apply-applier-p (entry manager)
  "Recognize the record of MANAGER's own previous apply."
  (and (equal manager (gethash "manager" entry)) (equal "Apply" (gethash "operation" entry))))

(defun apply-conflicts (live applied paths manager)
  "List (manager . path) for fields other appliers own that this apply would change."
  (let ((conflicts nil))
    (dolist (entry (apply-managed-entries live))
      (when (and (equal "Apply" (gethash "operation" entry)) (not (equal manager (gethash "manager" entry))))
        (dolist (theirs (apply-field-paths (gethash "fieldsV1" entry (core-object))))
          (dolist (mine paths)
            (when (or (apply-path-prefix-p theirs mine) (apply-path-prefix-p mine theirs))
              (let ((shared (if (< (length theirs) (length mine)) theirs mine)))
                (multiple-value-bind (current present) (apply-value-at live shared)
                  (unless (and present (crd-json-equal-p current (apply-value-at applied shared)))
                    (pushnew (cons (gethash "manager" entry) shared) conflicts :test #'equal)))))))))
    (reverse conflicts)))

(defun apply-conflict-error (conflicts)
  "Fail with the Status upstream reports, naming every contested field."
  (error 'kubernetes-error
         :status-code 409 :reason "Conflict"
         :message (format nil "Apply failed with ~D conflict~:P: ~{~A~^, ~}" (length conflicts)
                          (loop for (manager . path) in conflicts
                                collect (format nil "conflict with ~S: ~A" manager (apply-path-text path))))
         :details (core-object "causes"
                               (coerce (loop for (manager . path) in conflicts
                                             collect (core-object "reason" "FieldManagerConflict"
                                                                  "message" (format nil "conflict with ~S" manager)
                                                                  "field" (apply-path-text path)))
                                       'vector))))

(defun apply-drop-paths (set paths)
  "Return a copy of FieldsV1 SET without the fields PATHS take over."
  (let ((copy (copy-core-object set)))
    (dolist (path paths copy)
      (apply-remove-path copy (mapcar (lambda (key) (concatenate 'string "f:" key)) path)))))

(defun apply-merge (live configuration resource manager force)
  "Return LIVE with CONFIGURATION applied for MANAGER, updating field ownership."
  (let* ((owned (apply-owned-configuration configuration resource))
         (set (apply-field-set owned))
         (paths (apply-field-paths set))
         (entries (apply-managed-entries live))
         (previous (find-if (lambda (entry) (apply-applier-p entry manager)) entries))
         (conflicts (apply-conflicts live configuration paths manager)))
    (when (and conflicts (not force)) (apply-conflict-error conflicts))
    (let* ((others (loop for entry in entries
                         unless (apply-applier-p entry manager)
                           collect (if (and force (equal "Apply" (gethash "operation" entry)))
                                       (let ((copy (copy-core-object entry)))
                                         (setf (gethash "fieldsV1" copy)
                                               (apply-drop-paths (gethash "fieldsV1" entry (core-object))
                                                                 (loop for (who . path) in conflicts
                                                                       when (equal who (gethash "manager" entry)) collect path)))
                                         copy)
                                       entry)))
           (others (remove-if (lambda (entry) (and (equal "Apply" (gethash "operation" entry))
                                                   (zerop (hash-table-count (gethash "fieldsV1" entry (core-object))))))
                              others))
           (held (loop for entry in others append (apply-field-paths (gethash "fieldsV1" entry (core-object)))))
           (merged (copy-core-object live)))
      (when previous
        (dolist (path (apply-field-paths (gethash "fieldsV1" previous (core-object))))
          (unless (or (some (lambda (mine) (apply-path-prefix-p path mine)) paths)
                      (some (lambda (mine) (apply-path-prefix-p mine path)) paths)
                      (member path held :test #'equal))
            (apply-remove-path merged path))))
      (let ((applied (copy-core-object owned)) (metadata (gethash "metadata" merged)))
        (let ((request-metadata (gethash "metadata" configuration)))
          (when (hash-table-p request-metadata)
            ;; A declared revision or UID is a precondition, compared by the store.
            (dolist (key '("resourceVersion" "uid"))
              (when (nth-value 1 (gethash key request-metadata))
                (setf (gethash key metadata) (gethash key request-metadata))))))
        (apply-overlay merged applied)
        (setf metadata (gethash "metadata" merged))
        (setf (gethash "apiVersion" merged) (gethash "apiVersion" configuration)
              (gethash "kind" merged) (gethash "kind" configuration)
              (gethash "managedFields" metadata)
              (coerce (sort (cons (if (and previous (crd-json-equal-p set (gethash "fieldsV1" previous)))
                                      previous
                                      (apply-entry manager (gethash "apiVersion" configuration) set))
                                  others)
                            #'string< :key (lambda (entry) (gethash "manager" entry)))
                      'vector)))
      merged)))

(defun apply-undeclared-fields (configuration resource)
  "Name fields the object's schema does not declare, which Apply rejects in every mode."
  (let ((probe (copy-core-object configuration)))
    (cond
      ((custom-resource-key-p resource)
       (crd-undeclared-fields probe (crd-schema (crd-version *crd-view-definition* *crd-request-version*))))
      (t (let ((schema (typed-request-schema (core-resource-kind resource))))
           (when schema (mapcar (lambda (path) (concatenate 'string "." path)) (prune-typed-unknown-fields probe schema))))))))

(defun apply-read-configuration (resource namespace name)
  "Decode and check the applied YAML, honoring Strict duplicate-key rejection."
  (multiple-value-bind (configuration duplicates)
      (yaml-parse (hunchentoot:raw-post-data :force-text t))
    (when (and duplicates (equal "Strict" *crd-field-validation*))
      (core-resource-error 400 "BadRequest" "error strict decoding YAML: yaml: unmarshal errors:~%~{  ~A~^~%~}" duplicates))
    (unless (hash-table-p configuration)
      (core-resource-error 400 "BadRequest" "error decoding YAML: the applied configuration must be an object"))
    (unless (and (stringp (gethash "apiVersion" configuration)) (stringp (gethash "kind" configuration)))
      (core-resource-error 400 "BadRequest" "Apply requires apiVersion and kind"))
    (let ((metadata (gethash "metadata" configuration)))
      (unless (hash-table-p metadata)
        (setf metadata (core-object) (gethash "metadata" configuration) metadata))
      (unless (equal name (gethash "name" metadata name))
        (core-resource-error 400 "BadRequest" "the name of the object (~A) does not match the name on the URL (~A)"
                             (gethash "name" metadata) name))
      (setf (gethash "name" metadata) name)
      (when (and namespace (member (gethash "namespace" metadata namespace) '("" null) :test #'equal))
        (remhash "namespace" metadata))
      (when (hash-table-p (gethash "managedFields" metadata))
        (core-resource-error 400 "BadRequest" "metadata.managedFields must be nil")))
    (when (nth-value 1 (gethash "managedFields" (gethash "metadata" configuration)))
      (core-resource-error 400 "BadRequest" "metadata.managedFields must be nil"))
    (let ((undeclared (apply-undeclared-fields configuration resource)))
      (when undeclared
        (core-resource-error 400 "BadRequest" "failed to create typed patch object (~@[~A/~]~A; ~A): ~{~A: field not declared in schema~^, ~}"
                             namespace name (gethash "kind" configuration) undeclared)))
    configuration))

(defun apply-force-p ()
  "Read the force option, accepted only as Kubernetes' boolean spellings."
  (let ((force (hunchentoot:parameter "force")))
    (cond ((member force '(nil "" "false" "0") :test #'equal) nil)
          ((member force '("true" "1") :test #'equal) t)
          (t (core-resource-error 400 "BadRequest" "force must be a boolean")))))

(defun apply-patch-response (store resource namespace name dry-run)
  "Create or update the named object from an applied configuration."
  (let* ((manager (apply-field-manager)) (force (apply-force-p))
         (configuration (apply-read-configuration resource namespace name))
         (exists (handler-case (get-core-resource store resource namespace name)
                   (kubernetes-error (condition)
                     (unless (= 404 (kubernetes-error-status-code condition)) (error condition))
                     nil))))
    (if exists
        (json-response
         (admitted-update-core-resource
          store resource namespace name
          (lambda (old) (apply-merge old configuration resource manager force))
          :dry-run dry-run))
        (let ((input (copy-core-object configuration)))
          (setf (gethash "managedFields" (gethash "metadata" input))
                (vector (apply-entry manager (gethash "apiVersion" configuration)
                                     (apply-field-set (apply-owned-configuration configuration resource)))))
          (json-response
           (complete-created-bootstrap-resource
            store resource
            (admitted-create-core-resource store resource input namespace :dry-run dry-run)
            dry-run)
           201)))))
