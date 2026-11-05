;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve application/apply-patch+yaml: declare fields for a named manager,
;;;; record ownership in metadata.managedFields, report conflicts with other
;;;; managers and drop what a manager stops declaring. Associative lists merge item
;;;; by item, and plain writes come to own the fields they change as Update managers.

(in-package #:gr8s)

;;; A path is a list of FieldsV1 keys: f:name, k:{"name":"x"}, v:"x" and "." for a list item itself.

(defparameter +apply-owned-metadata+ '("labels" "annotations" "finalizers" "ownerReferences")
  "Metadata fields an applier may own; the rest belong to the server or the request.")

(defvar *apply-schema* nil "Schema of the object being applied, for its associative lists.")
(defvar *apply-update-manager* nil
  "Manager and subresource of the plain write in progress, whose changed fields it comes to own.")

(defun apply-metadata-schema ()
  "Describe metadata's lists, which schemas here do not always carry."
  (core-object "properties"
               (core-object "finalizers" (core-object "type" "array" "x-kubernetes-list-type" "set"
                                                      "items" (core-object "type" "string"))
                            "ownerReferences" (core-object "type" "array" "x-kubernetes-list-type" "map"
                                                           "x-kubernetes-list-map-keys" #("uid")
                                                           "items" (core-object "type" "object")))))

(defun apply-child-schema (schema key)
  "Return the schema of field KEY under SCHEMA, or NIL."
  (when (hash-table-p schema)
    (let* ((schema (resolve-template-schema schema))
           (properties (gethash "properties" schema))
           (additional (gethash "additionalProperties" schema)))
      (or (and (hash-table-p properties) (gethash key properties))
          (and (hash-table-p additional) additional)))))

(defun apply-list-kind (schema)
  "Return :map with its keys, :set, or NIL for the atomic list SCHEMA describes."
  (when (hash-table-p schema)
    (let* ((schema (resolve-template-schema schema))
           (type (gethash "x-kubernetes-list-type" schema)))
      (cond ((equal type "map") (values :map (coerce (gethash "x-kubernetes-list-map-keys" schema #()) 'list)))
            ((equal type "set") :set)))))

(defun apply-items-schema (schema)
  "Return the element schema of a list SCHEMA."
  (when (hash-table-p schema)
    (gethash "items" (resolve-template-schema schema))))

(defun apply-atomic-map-p (schema)
  "Test whether SCHEMA declares a map to be owned as a whole."
  (and (hash-table-p schema) (equal "atomic" (gethash "x-kubernetes-map-type" (resolve-template-schema schema)))))

(defun apply-item-key-value (item key)
  "Read a map list key of ITEM, with the default a key field has in upstream's schemas."
  (multiple-value-bind (value present) (gethash key item)
    (cond (present value)
          ((equal key "protocol") "TCP")
          (t 'null))))

(defun apply-item-key (item keys)
  "Spell a map list ITEM's identity as a FieldsV1 k: key, with its key fields sorted."
  (format nil "k:{~{~A~^,~}}"
          (loop for key in (sort (copy-list keys) #'string<)
                collect (format nil "~A:~A" (com.inuoe.jzon:stringify key)
                                (com.inuoe.jzon:stringify (apply-item-key-value item key))))))

(defun apply-set-key (value)
  "Spell a set element as a FieldsV1 v: key."
  (concatenate 'string "v:" (com.inuoe.jzon:stringify value)))

(defun apply-field-set (object &optional (schema *apply-schema*))
  "Describe OBJECT's fields in FieldsV1 form, with associative lists item by item."
  (let ((set (core-object)))
    (maphash
     (lambda (key value)
       (let ((child (if (and (eq schema *apply-schema*) (equal key "metadata"))
                        (apply-metadata-schema)
                        (apply-child-schema schema key)))
             (field (concatenate 'string "f:" key)))
         (setf (gethash field set)
               (cond
                 ((and (hash-table-p value) (plusp (hash-table-count value)) (not (apply-atomic-map-p child)))
                  (apply-field-set value child))
                 ((crd-array-p value)
                  (multiple-value-bind (kind keys) (apply-list-kind child)
                    (let ((items (core-object)) (element (apply-items-schema child)))
                      (case kind
                        (:map
                         (loop for item across value
                               do (when (hash-table-p item)
                                    (let ((fields (apply-field-set item element)))
                                      (setf (gethash "." fields) (core-object)
                                            (gethash (apply-item-key item keys) items) fields)))))
                        (:set
                         (loop for item across value
                               do (setf (gethash (apply-set-key item) items) (core-object)))))
                      items)))
                 (t (core-object))))))
     object)
    set))

(defun apply-field-paths (set &optional prefix)
  "Flatten a FieldsV1 set into its leaf paths, each a list of its keys."
  (loop for key being the hash-keys of set using (hash-value child)
        for path = (append prefix (list key))
        if (and (hash-table-p child) (plusp (hash-table-count child)))
          append (apply-field-paths child path)
        else collect path))

(defun apply-path-prefix-p (left right)
  "Report whether field path LEFT contains RIGHT or equals it."
  (and (<= (length left) (length right)) (equal left (subseq right 0 (length left)))))

(defun apply-path-related-p (left right)
  "Report whether two paths name the same field or one contains the other."
  (let ((item-left (if (equal "." (car (last left))) (butlast left) left))
        (item-right (if (equal "." (car (last right))) (butlast right) right)))
    (or (apply-path-prefix-p item-left item-right) (apply-path-prefix-p item-right item-left))))

(defun apply-path-text (path)
  "Format a field path as Kubernetes reports it in conflicts, such as .spec.foo."
  (format nil "~{~A~}"
          (loop for key in path
                unless (equal key ".")
                  collect (cond ((uiop:string-prefix-p "f:" key) (concatenate 'string "." (subseq key 2)))
                                ((uiop:string-prefix-p "k:" key) (format nil "[~A]" (subseq key 2)))
                                ((uiop:string-prefix-p "v:" key) (format nil "[=~A]" (subseq key 2)))
                                (t (concatenate 'string "." key))))))

(defun apply-key-item (items key)
  "Find the element of a list ITEMS that a k: or v: KEY names, returning it and its position."
  (when (crd-array-p items)
    (let ((position
            (if (uiop:string-prefix-p "v:" key)
                (let ((wanted (com.inuoe.jzon:parse (subseq key 2))))
                  (position wanted items :test #'crd-json-equal-p))
                (let ((wanted (com.inuoe.jzon:parse (subseq key 2))))
                  (position-if (lambda (item)
                                 (and (hash-table-p item)
                                      (loop for field being the hash-keys of wanted using (hash-value value)
                                            always (crd-json-equal-p value (apply-item-key-value item field)))))
                               items)))))
      (and position (values (aref items position) position)))))

(defun apply-step (value key)
  "Follow one path KEY from VALUE, returning the next value and whether it is present."
  (cond ((equal key ".") (values value t))
        ((uiop:string-prefix-p "f:" key)
         (if (hash-table-p value) (gethash (subseq key 2) value) (values nil nil)))
        ((or (uiop:string-prefix-p "k:" key) (uiop:string-prefix-p "v:" key))
         (multiple-value-bind (item position) (apply-key-item value key)
           (values item (and position t))))
        (t (values nil nil))))

(defun apply-value-at (object path)
  "Return the value at PATH and whether it is present."
  (let ((value object))
    (dolist (key path (values value t))
      (multiple-value-bind (child present) (apply-step value key)
        (unless present (return (values nil nil)))
        (setf value child)))))

(defun apply-remove-from-list (items position)
  "Copy the list ITEMS without the element at POSITION."
  (concatenate 'vector (subseq items 0 position) (subseq items (1+ position))))

(defun apply-remove-path (object path)
  "Delete the field at PATH and any parent map the deletion leaves empty, returning OBJECT."
  (let ((key (first path)))
    (cond
      ((not (uiop:string-prefix-p "f:" key)) object)
      ((not (hash-table-p object)) object)
      (t
       (let ((name (subseq key 2)))
         (if (rest path)
             (let ((child (gethash name object)) (next (second path)))
               (cond
                 ((hash-table-p child)
                  (apply-remove-path child (rest path))
                  (when (zerop (hash-table-count child)) (remhash name object)))
                 ((and (crd-array-p child) (or (uiop:string-prefix-p "k:" next) (uiop:string-prefix-p "v:" next)))
                  (multiple-value-bind (item position) (apply-key-item child next)
                    (when position
                      (if (or (uiop:string-prefix-p "v:" next) (equal "." (third path)))
                          (let ((remaining (apply-remove-from-list child position)))
                            (if (zerop (length remaining)) (remhash name object) (setf (gethash name object) remaining)))
                          (apply-remove-path item (cddr path))))))))
             (remhash name object)))
       object))))

(defun apply-overlay (target applied &optional (schema *apply-schema*))
  "Write APPLIED over TARGET, merging maps and associative lists; a declared null removes the field."
  (maphash
   (lambda (key value)
     (let ((child (if (and (eq schema *apply-schema*) (equal key "metadata"))
                      (apply-metadata-schema)
                      (apply-child-schema schema key))))
       (cond
         ((eq value 'null) (remhash key target))
         ((and (hash-table-p value) (hash-table-p (gethash key target)) (not (apply-atomic-map-p child)))
          (apply-overlay (gethash key target) value child))
         ((and (crd-array-p value) (crd-array-p (gethash key target)))
          (multiple-value-bind (kind keys) (apply-list-kind child)
            (setf (gethash key target)
                  (case kind
                    (:map (apply-overlay-map-list (gethash key target) value keys (apply-items-schema child)))
                    (:set (apply-overlay-set (gethash key target) value))
                    (t (copy-core-object value))))))
         (t (setf (gethash key target) (copy-core-object value))))))
   applied)
  target)

(defun apply-overlay-map-list (live applied keys element)
  "Merge a map list: entries with a known key overlay in place and new ones follow."
  (let ((result (coerce live 'list)))
    (loop for item across applied
          do (if (hash-table-p item)
                 (let ((existing (find-if (lambda (candidate)
                                            (and (hash-table-p candidate)
                                                 (every (lambda (key)
                                                          (crd-json-equal-p (apply-item-key-value candidate key)
                                                                            (apply-item-key-value item key)))
                                                        keys)))
                                          result)))
                   (if existing
                       (apply-overlay existing item element)
                       (setf result (append result (list (copy-core-object item))))))
                 (setf result (append result (list (copy-core-object item))))))
    (coerce result 'vector)))

(defun apply-overlay-set (live applied)
  "Union two set lists, keeping the live order."
  (let ((result (coerce live 'list)))
    (loop for item across applied
          do (unless (member item result :test #'crd-json-equal-p)
               (setf result (append result (list (copy-core-object item))))))
    (coerce result 'vector)))

(defun apply-owned-configuration (configuration resource &optional subresource)
  "Reduce CONFIGURATION to the fields a manager comes to own by declaring them."
  (let ((owned (copy-core-object configuration)))
    (remhash "apiVersion" owned)
    (remhash "kind" owned)
    (if subresource
        ;; A subresource endpoint takes only what it serves, and metadata.
        (dolist (key (loop for key being the hash-keys of owned collect key))
          (unless (member key (list subresource "metadata") :test #'equal) (remhash key owned)))
        (when (or (not (custom-resource-key-p resource)) (apply-status-subresource-p))
          (remhash "status" owned)))
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

(defun apply-entry (manager api-version set &key (operation "Apply") subresource)
  "Build the ownership record of one write."
  (let ((entry (core-object "manager" manager "operation" operation "apiVersion" api-version
                            "time" (current-timestamp) "fieldsType" "FieldsV1" "fieldsV1" set)))
    (when subresource (setf (gethash "subresource" entry) subresource))
    entry))

(defun apply-applier-p (entry manager &optional subresource)
  "Recognize the record of MANAGER's own previous apply at this endpoint."
  (and (equal manager (gethash "manager" entry)) (equal "Apply" (gethash "operation" entry))
       (equal subresource (gethash "subresource" entry))))

(defun apply-conflicts (live applied paths manager &optional subresource)
  "List (manager . path) for fields other managers own that this apply would change."
  (let ((conflicts nil))
    (dolist (entry (apply-managed-entries live))
      (unless (apply-applier-p entry manager subresource)
        (dolist (theirs (apply-field-paths (gethash "fieldsV1" entry (core-object))))
          (dolist (mine paths)
            ;; Two managers may both hold a list item; only the fields inside can conflict.
            (when (and (apply-path-related-p theirs mine)
                       (not (equal "." (car (last theirs)))) (not (equal "." (car (last mine)))))
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

(defun apply-set-remove-path (set path)
  "Delete PATH from the FieldsV1 SET, dropping maps it leaves empty."
  (let ((key (first path)))
    (if (rest path)
        (let ((child (gethash key set)))
          (when (hash-table-p child)
            (apply-set-remove-path child (rest path))
            (when (zerop (hash-table-count child)) (remhash key set))))
        (remhash key set))))

(defun apply-drop-paths (set paths)
  "Return a copy of FieldsV1 SET without the fields PATHS take over."
  (let ((copy (copy-core-object set)))
    (dolist (path paths copy)
      (dolist (held (apply-field-paths copy))
        (when (and (apply-path-related-p held path) (not (equal "." (car (last held)))))
          (apply-set-remove-path copy held))))))

(defun apply-merge (live configuration resource manager force &optional subresource)
  "Return LIVE with CONFIGURATION applied for MANAGER, updating field ownership."
  (let* ((owned (apply-owned-configuration configuration resource subresource))
         (set (apply-field-set owned))
         (paths (apply-field-paths set))
         (entries (apply-managed-entries live))
         (previous (find-if (lambda (entry) (apply-applier-p entry manager subresource)) entries))
         (conflicts (apply-conflicts live configuration paths manager subresource)))
    (when (and conflicts (not force)) (apply-conflict-error conflicts))
    (let* ((others (loop for entry in entries
                         unless (apply-applier-p entry manager subresource)
                           collect (if force
                                       (let ((copy (copy-core-object entry)))
                                         (setf (gethash "fieldsV1" copy)
                                               (apply-drop-paths (gethash "fieldsV1" entry (core-object))
                                                                 (loop for (who . path) in conflicts
                                                                       when (equal who (gethash "manager" entry)) collect path)))
                                         copy)
                                       entry)))
           (others (remove-if (lambda (entry) (zerop (hash-table-count (gethash "fieldsV1" entry (core-object)))))
                              others))
           (held (loop for entry in others append (apply-field-paths (gethash "fieldsV1" entry (core-object)))))
           (merged (copy-core-object live)))
      (when previous
        ;; An item's "." comes first: its key fields must still be there to find it by.
        (dolist (path (stable-sort (apply-field-paths (gethash "fieldsV1" previous (core-object)))
                                   (lambda (left right)
                                     (and (equal "." (car (last left))) (not (equal "." (car (last right))))))))
          (unless (or (some (lambda (mine) (apply-path-related-p path mine)) paths)
                      (some (lambda (other) (apply-path-related-p other path)) held))
            ;; An item's "." goes with the item: remove it only once nobody holds anything in it.
            (setf merged (apply-remove-path merged path)))))
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
              (apply-sorted-entries
               (cons (if (and previous (crd-json-equal-p set (gethash "fieldsV1" previous)))
                         previous
                         (apply-entry manager (gethash "apiVersion" configuration) set :subresource subresource))
                     others))))
      merged)))

(defun apply-sorted-entries (entries)
  "Order managedFields as upstream does: Apply operations first, then by time and manager."
  (coerce (stable-sort (copy-list entries)
                       (lambda (left right)
                         (let ((a (equal "Apply" (gethash "operation" left)))
                               (b (equal "Apply" (gethash "operation" right))))
                           (cond ((and a (not b)) t)
                                 ((and b (not a)) nil)
                                 (t (string< (gethash "manager" left "") (gethash "manager" right "")))))))
          'vector))

;;; Update managers

(defun apply-changed-set (old new &optional (schema *apply-schema*) (set (core-object)))
  "Return in SET the FieldsV1 leaves NEW sets differently from OLD."
  (maphash
   (lambda (key value)
     (let ((field (concatenate 'string "f:" key))
           (child (if (and (eq schema *apply-schema*) (equal key "metadata"))
                      (apply-metadata-schema)
                      (apply-child-schema schema key))))
       (multiple-value-bind (before present) (if (hash-table-p old) (gethash key old) (values nil nil))
         (unless (and present (crd-json-equal-p before value))
           (cond
             ((and (hash-table-p value) (plusp (hash-table-count value)) (not (apply-atomic-map-p child)))
              (let ((inner (apply-changed-set (and (hash-table-p before) before) value child)))
                (when (plusp (hash-table-count inner)) (setf (gethash field set) inner))))
             ((crd-array-p value)
              (multiple-value-bind (kind keys) (apply-list-kind child)
                (let ((inner (core-object)) (element (apply-items-schema child)))
                  (case kind
                    (:map
                     (loop for item across value
                           do (when (hash-table-p item)
                                (let* ((item-key (apply-item-key item keys))
                                       (old-item (and (crd-array-p before) (apply-key-item before item-key))))
                                  (unless (and old-item (crd-json-equal-p old-item item))
                                    (let ((fields (apply-changed-set old-item item element)))
                                      (setf (gethash "." fields) (core-object)
                                            (gethash item-key inner) fields)))))))
                    (:set
                     (loop for item across value
                           do (unless (and (crd-array-p before) (find item before :test #'crd-json-equal-p))
                                (setf (gethash (apply-set-key item) inner) (core-object))))))
                  (setf (gethash field set) inner))))
             (t (setf (gethash field set) (core-object))))))))
   new)
  set)

(defun apply-removed-paths (old new &optional prefix (schema *apply-schema*))
  "List the paths of fields OLD had that NEW lacks."
  (when (hash-table-p old)
    (loop for key being the hash-keys of old using (hash-value before)
          for path = (append prefix (list (concatenate 'string "f:" key)))
          for child = (apply-child-schema schema key)
          append (multiple-value-bind (after present) (gethash key new)
                   (cond ((not present) (list path))
                         ((and (hash-table-p before) (hash-table-p after))
                          (apply-removed-paths before after path child)))))))

(defun apply-set-merge (target source)
  "Add every leaf of the FieldsV1 SOURCE to TARGET."
  (maphash (lambda (key child)
             (let ((existing (gethash key target)))
               (if (and (hash-table-p existing) (hash-table-p child) (plusp (hash-table-count child)))
                   (apply-set-merge existing child)
                   (setf (gethash key target) (copy-core-object child)))))
           source)
  target)

(defun apply-trackable-view (object)
  "Reduce OBJECT to what ownership tracks: its content and owned metadata."
  (let ((view (copy-core-object object)))
    (remhash "apiVersion" view)
    (remhash "kind" view)
    (let ((metadata (gethash "metadata" view)))
      (when (hash-table-p metadata)
        (dolist (key (loop for key being the hash-keys of metadata collect key))
          (unless (member key +apply-owned-metadata+ :test #'equal) (remhash key metadata)))
        (when (zerop (hash-table-count metadata)) (remhash "metadata" view))))
    view))

(defun apply-track-write (old new resource)
  "Give the manager of a plain write the fields it changed from OLD, taking them from the others."
  (when (and *apply-update-manager* (hash-table-p new) (hash-table-p (gethash "metadata" new)))
    (destructuring-bind (manager subresource) *apply-update-manager*
      (let* ((*apply-schema* (apply-resource-schema resource))
             (metadata (gethash "metadata" new))
             (submitted (multiple-value-list (gethash "managedFields" metadata)))
             (entries (cond
                        ;; An explicit empty list resets tracking, as upstream documents.
                        ((and (second submitted) (crd-array-p (first submitted)) (zerop (length (first submitted))))
                         nil)
                        ((and (second submitted) (crd-array-p (first submitted))) (coerce (first submitted) 'list))
                        (old (apply-managed-entries old))))
             (before (and old (apply-trackable-view old)))
             (after (apply-trackable-view new))
             (changed (apply-changed-set before after))
             (removed (and before (apply-removed-paths before after)))
             (taken (append removed (apply-field-paths changed)))
             (api-version (gethash "apiVersion" new)))
        (let* ((others
                 (loop for entry in entries
                       unless (and (equal manager (gethash "manager" entry))
                                   (equal "Update" (gethash "operation" entry))
                                   (equal api-version (gethash "apiVersion" entry))
                                   (equal subresource (gethash "subresource" entry)))
                         collect (if taken
                                     (let ((copy (copy-core-object entry)))
                                       (setf (gethash "fieldsV1" copy)
                                             (apply-drop-paths (gethash "fieldsV1" entry (core-object)) taken))
                                       copy)
                                     entry)))
               (others (remove-if (lambda (entry) (zerop (hash-table-count (gethash "fieldsV1" entry (core-object))))) others))
               (mine (find-if (lambda (entry)
                                (and (equal manager (gethash "manager" entry))
                                     (equal "Update" (gethash "operation" entry))
                                     (equal api-version (gethash "apiVersion" entry))
                                     (equal subresource (gethash "subresource" entry))))
                              entries))
               (result
                 (cond
                   ((and mine (plusp (hash-table-count changed)))
                    (let ((fields (copy-core-object (gethash "fieldsV1" mine (core-object)))))
                      (apply-set-merge fields changed)
                      (dolist (path removed) (apply-set-remove-path fields path))
                      (cons (apply-entry manager api-version fields :operation "Update" :subresource subresource) others)))
                   (mine (cons mine others))
                   ((plusp (hash-table-count changed))
                    (cons (apply-entry manager api-version changed :operation "Update" :subresource subresource) others))
                   (t others))))
          (if result
              (setf (gethash "managedFields" metadata) (apply-sorted-entries result))
              (remhash "managedFields" metadata))))))
  new)

(defun apply-resource-schema (resource)
  "Return the schema whose list types govern RESOURCE, when one is known."
  (cond ((custom-resource-key-p resource)
         (and *crd-view-definition*
              (crd-schema (crd-version *crd-view-definition* *crd-request-version*))))
        ((equal resource "pods")
         (core-object "properties"
                      (core-object "spec" (core-object "$ref" "#/definitions/io.k8s.api.core.v1.PodSpec")
                                   "status" (core-object
                                             "properties"
                                             (core-object "conditions"
                                                          (core-object "type" "array" "x-kubernetes-list-type" "map"
                                                                       "x-kubernetes-list-map-keys" #("type")
                                                                       "items" (core-object "type" "object")))))))
        ((equal resource "nodes") nil)
        (t (let ((*core-resource-view-version* (core-resource-api-version resource)))
             (typed-request-schema (core-resource-kind resource))))))

(defun apply-default-manager ()
  "Name the manager of a plain write: fieldManager, or the client's name from its User-Agent."
  (let ((named (hunchentoot:parameter "fieldManager")))
    (cond
      ((and named (plusp (length named)))
       (when (or (> (length named) 128) (some (lambda (character) (not (graphic-char-p character))) named))
         (core-resource-error 422 "Invalid" "fieldManager: must be printable and at most 128 characters"))
       named)
      (t
       (let* ((agent (or (hunchentoot:header-in* :user-agent) "unknown"))
              (name (subseq agent 0 (or (position #\/ agent) (length agent)))))
         (subseq name 0 (min 128 (length name))))))))

(defun apply-undeclared-fields (configuration resource)
  "Name fields the object's schema does not declare, which Apply rejects in every mode."
  (let ((probe (copy-core-object configuration)))
    (cond
      ;; Pods and Nodes are served apart from the stored kinds and parse their own writes.
      ((member resource '("pods" "nodes") :test #'equal) nil)
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
         (*apply-schema* (apply-resource-schema resource))
         (*apply-update-manager* nil)
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

(defun apply-pod-patched-object (current subresource)
  "Apply the request's configuration to the Pod object CURRENT at SUBRESOURCE, or NIL for the Pod itself."
  (let* ((*apply-schema* (apply-resource-schema "pods")) (*apply-update-manager* nil)
         (name (gethash "name" (gethash "metadata" current)))
         (namespace (gethash "namespace" (gethash "metadata" current)))
         (configuration (apply-read-configuration "pods" namespace name)))
    (apply-merge current configuration "pods" (apply-field-manager) (apply-force-p) subresource)))

(defun apply-pod-created-object (namespace name)
  "Return the object that creates a Pod from the request's configuration, recording its manager."
  (let* ((*apply-schema* (apply-resource-schema "pods")) (*apply-update-manager* nil)
         (configuration (apply-read-configuration "pods" namespace name))
         (input (copy-core-object configuration)))
    (setf (gethash "managedFields" (gethash "metadata" input))
          (vector (apply-entry (apply-field-manager) (gethash "apiVersion" configuration)
                               (apply-field-set (apply-owned-configuration configuration "pods")))))
    input))
