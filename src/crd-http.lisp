;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve admitted custom-resource routes, versions, discovery and status using
;;;; the shared durable journal. Responses convert to the requested version and
;;;; apply its schema.

(in-package #:gr8s)

(defvar *crd-route* nil)

(defun crd-request-field-validation ()
  "Validate the actual supported field-validation query option."
  (let ((mode (hunchentoot:parameter "fieldValidation")))
    (unless (member mode '(nil "" "Strict" "Warn" "Ignore") :test #'equal)
      (core-resource-error 400 "BadRequest" "fieldValidation must be Strict, Warn or Ignore"))
    (if (member mode '(nil "") :test #'equal) "Warn" mode)))

(defun crd-report-pruned-fields (fields)
  "Reject strict unknown fields or emit a real warning while retaining pruning."
  (report-field-problems (mapcar #'unknown-field-problem (reverse fields))))

(defun crd-version-rank (version)
  "Rank recognized Kubernetes versions by stability, numeric major and prerelease."
  (cl-ppcre:register-groups-bind (major stage minor)
      ("^v([0-9]+)(?:(alpha|beta)([0-9]+))?$" version)
    (let ((major (parse-integer major)) (minor (if minor (parse-integer minor) 0)))
      (when (and (<= major #x7fffffffffffffff) (<= minor #x7fffffffffffffff))
        (list (cond ((equal stage "alpha") 0) ((equal stage "beta") 1) (t 2)) major minor)))))

(defun crd-version-preferred-p (left right)
  "Follow kube-aware ordering, placing arbitrary versions after recognized forms."
  (let ((a (crd-version-rank left)) (b (crd-version-rank right)))
    (cond ((and a b) (loop for x in a for y in b when (/= x y) return (> x y)))
          (a t) (b nil) (t (string< left right)))))

(defun crd-watch-definition-current-p (store definition version)
  "Keep a watch bound to its actual definition UID and served version."
  (with-store-lock (store)
    (let* ((metadata (gethash "metadata" definition))
           (current (gethash (core-resource-key "customresourcedefinitions" nil (gethash "name" metadata)) (pod-store-resources store))))
      (and current (equal (gethash "uid" metadata) (gethash "uid" (gethash "metadata" current)))
           (crd-version current version :served t)))))

(defun crd-api-group (group versions)
  "Describe actual served versions with a deterministic preferred version."
  (let ((values (sort (copy-list versions) #'crd-version-preferred-p)))
    (core-object "apiVersion" "v1" "kind" "APIGroup" "name" group
                 "versions" (coerce (mapcar (lambda (version) (core-object "groupVersion" (format nil "~A/~A" group version) "version" version)) values) 'vector)
                 "preferredVersion" (core-object "groupVersion" (format nil "~A/~A" group (first values)) "version" (first values)))))

(defun crd-api-groups (store)
  "Advertise only versions backed by established definitions in this store."
  (let ((groups (make-hash-table :test #'equal)))
    (with-store-lock (store)
      (loop for key being the hash-keys of (pod-store-resources store) using (hash-value definition)
            when (equal "customresourcedefinitions" (first key))
              do (loop for version across (gethash "versions" (gethash "spec" definition))
                       when (gethash "served" version)
                         do (pushnew (gethash "name" version) (gethash (gethash "group" (gethash "spec" definition)) groups) :test #'equal))))
    (cons (crd-api-group "apiextensions.k8s.io" '("v1"))
          (loop for group in (sort (loop for group being the hash-keys of groups collect group) #'string<)
                collect (crd-api-group group (gethash group groups))))))

(defun crd-api-view (input)
  "Project custom objects, lists and watch events into the actual requested version."
  (if (not (and *crd-view-definition* (hash-table-p input))) input
      (let* ((definition *crd-view-definition*) (spec (gethash "spec" definition)) (names (gethash "names" spec))
             (kind (gethash "kind" input)) (group (gethash "group" spec))
             (version (crd-version definition *crd-request-version*)) (object (copy-core-object input)))
        (cond
          ((and (equal kind (gethash "kind" names))
                (uiop:string-prefix-p (concatenate 'string group "/") (gethash "apiVersion" object "")))
           (setf object (crd-prepare-value (crd-object-at-version definition object *crd-request-version*)
                                           (crd-schema version) t))
           object)
          ((and (equal kind (concatenate 'string (gethash "kind" names) "List"))
                (gethash "items" object))
           ;; One review converts the whole page, which the per-item views then find remembered.
           (when (crd-conversion-webhook definition)
             (crd-convert-objects definition (coerce (gethash "items" object) 'list) *crd-request-version*))
           (setf (gethash "apiVersion" object) (format nil "~A/~A" group *crd-request-version*)
                 (gethash "kind" object) (gethash "listKind" names)
                 (gethash "items" object) (map 'vector #'crd-api-view (gethash "items" object))) object)
          ((gethash "object" object) (setf (gethash "object" object) (crd-api-view (gethash "object" object))) object)
          (t input)))))

(defun crd-special-route (store path)
  "Resolve CRD discovery or a custom collection without plural-only ambiguity."
  (let* ((parts (uiop:split-string path :separator '(#\/)))
         (openapi (equal (subseq parts 0 (min 4 (length parts))) '("" "openapi" "v3" "apis")))
         (parts (if openapi (cons "" (cons "apis" (nthcdr 4 parts))) parts)))
    (when (and (>= (length parts) 3) (equal (subseq parts 0 2) '("" "apis")))
      (let* ((group (third parts)) (version (fourth parts)) (tail (nthcdr 4 parts))
             (namespace (and (equal "namespaces" (first tail)) (third tail) (second tail)))
             (rest (if namespace (cddr tail) tail)))
        (cond
          ((and (equal "apiextensions.k8s.io" group) (equal version "v1") (= 7 (length parts))
                (equal (fifth parts) "customresourcedefinitions") (equal (seventh parts) "status")
                (dns-subdomain-p (sixth parts)))
           (list :definition-status (sixth parts)))
          ((and (equal "apiextensions.k8s.io" group) (member (length parts) '(3 4)) (member version '(nil "v1") :test #'equal))
           (list :discovery group version openapi))
          (t
           (with-store-lock (store)
             (let ((definitions (loop for key being the hash-keys of (pod-store-resources store) using (hash-value definition)
                                      when (and (equal "customresourcedefinitions" (first key))
                                                (equal group (gethash "group" (gethash "spec" definition)))
                                                (or (null version) (crd-version definition version :served t)))
                                        collect definition)))
               (when definitions
                 (if (null tail) (list :discovery group version openapi)
                     (let ((definition (find (first rest) definitions :test #'equal
                                            :key (lambda (value) (gethash "plural" (gethash "names" (gethash "spec" value)))))))
                       (when (and definition (<= 1 (length rest) 3)
                                  (or (not namespace) (equal "Namespaced" (gethash "scope" (gethash "spec" definition))))
                                  (or (/= (length rest) 3)
                                      (and (member (third rest) '("status" "scale") :test #'equal)
                                           (nth-value 1 (gethash (third rest) (gethash "subresources" (crd-version definition version) (core-object)))))))
                         (list :resource (copy-core-object definition) version namespace (second rest) (third rest))))))))))))))

(defun crd-discovery-resources (store group version)
  "Return collections and real status subresources for one served group/version."
  (if (equal group "apiextensions.k8s.io")
      (let ((resources (stored-resource-discovery +crd-api-version+)))
        (concatenate 'vector resources
          (vector (core-object "name" "customresourcedefinitions/status" "namespaced" nil "kind" "CustomResourceDefinition" "verbs" #("get" "patch" "update")))))
      (with-store-lock (store)
        (coerce (loop for key being the hash-keys of (pod-store-resources store) using (hash-value definition)
                      for spec = (gethash "spec" definition)
                      for entry = (and (equal "customresourcedefinitions" (first key))
                                       (equal group (gethash "group" spec)) (crd-version definition version :served t))
                      when entry
                        append (let* ((names (gethash "names" spec))
                                      (resource (core-object "name" (gethash "plural" names) "singularName" (gethash "singular" names)
                                                            "namespaced" (equal "Namespaced" (gethash "scope" spec)) "kind" (gethash "kind" names)
                                                            "verbs" #("create" "delete" "deletecollection" "get" "list" "patch" "update" "watch"))))
                                 (dolist (field '("shortNames" "categories")) (when (gethash field names) (setf (gethash field resource) (copy-core-object (gethash field names)))))
                                 (cons resource
                                       (append
                                        (when (nth-value 1 (gethash "status" (gethash "subresources" entry (core-object))))
                                          (list (core-object "name" (concatenate 'string (gethash "plural" names) "/status")
                                                             "namespaced" (equal "Namespaced" (gethash "scope" spec)) "kind" (gethash "kind" names)
                                                             "verbs" #("get" "patch" "update"))))
                                        (when (nth-value 1 (gethash "scale" (gethash "subresources" entry (core-object))))
                                          (list (core-object "name" (concatenate 'string (gethash "plural" names) "/scale")
                                                             "namespaced" (equal "Namespaced" (gethash "scope" spec)) "kind" "Scale"
                                                             "group" "autoscaling" "version" "v1"
                                                             "verbs" #("get" "patch" "update")))))))) 'vector))))

(defun crd-json-duplicate-fields (text)
  "Find repeated decoded keys without conflating equal keys in different objects."
  (let ((position 0) (size (length text)) (duplicates nil))
    (labels ((whitespace () (loop while (and (< position size) (find (char text position) '(#\Space #\Tab #\Return #\Newline))) do (incf position)))
             (string-end ()
               (incf position)
               (loop while (< position size)
                     for character = (char text position)
                     do (incf position)
                        (cond ((char= character #\\) (incf position)) ((char= character #\") (return)))))
             (value (path)
               (whitespace)
               (case (char text position)
                 (#\{ (incf position) (whitespace)
                  (let ((keys (make-hash-table :test #'equal)))
                    (unless (char= #\} (char text position))
                      (loop
                        (whitespace)
                        (let ((start position))
                          (string-end)
                          (let* ((key (com.inuoe.jzon:parse (subseq text start position)))
                                 (child-path (concatenate 'string path "." key)))
                            (when (gethash key keys) (push child-path duplicates))
                            (setf (gethash key keys) t)
                            (whitespace) (incf position) (value child-path)))
                        (whitespace)
                        (unless (char= #\, (char text position)) (return)) (incf position)))
                    (incf position)))
                 (#\[ (incf position) (whitespace)
                  (unless (char= #\] (char text position))
                    (loop (value (concatenate 'string path "[]")) (whitespace)
                          (unless (char= #\, (char text position)) (return)) (incf position)))
                  (incf position))
                 (#\" (string-end))
                 (t (loop while (and (< position size) (not (find (char text position) '(#\Space #\Tab #\Return #\Newline #\, #\} #\])))) do (incf position))))))
      (value "resource"))
    duplicates))

(defun crd-parse-json-content (text)
  "Parse bounded JSON and enforce real Strict/Warn duplicate-field behavior."
  (let ((object (com.inuoe.jzon:parse text :max-string-length (* 2 1024 1024))))
    (when (member *crd-field-validation* '("Strict" "Warn") :test #'equal)
      (let ((duplicates (crd-json-duplicate-fields text)))
        (report-field-problems (mapcar #'duplicate-field-problem (reverse duplicates)))))
    object))

(defun crd-read-json ()
  "Reject protobuf for unstructured custom objects; read actual JSON requests."
  (let ((type (request-media-type)))
    (unless (member type '("" "application/json") :test #'equal) (core-resource-error 415 "UnsupportedMediaType" "Custom resources require JSON"))
    (require-object (crd-parse-json-content (hunchentoot:raw-post-data :force-text t)) "request")))

(defun dispatch-crd-status (store resource namespace name method)
  "Serve status writes without modifying spec or bypassing optimistic metadata checks."
  (let ((existing (get-core-resource store resource namespace name)))
    (cond ((eq method :get) (json-response existing))
          ((member method '(:put :patch))
           (let* ((view (crd-api-view existing))
                  (type (request-media-type))
                  (*apply-update-manager* (list (apply-default-manager) "status"))
                  (input (if (eq method :put) (crd-read-json)
                             (let ((patch (if (equal type "application/apply-patch+yaml")
                                              nil
                                              (crd-parse-json-content (hunchentoot:raw-post-data :force-text t)))))
                               (cond ((equal type "application/apply-patch+yaml")
                                      (let ((*apply-schema* (apply-resource-schema resource)) (*apply-update-manager* nil))
                                        (apply-merge view (apply-read-configuration resource namespace name) resource
                                                     (apply-field-manager) (apply-force-p) "status")))
                                     ((equal type "application/merge-patch+json") (merge-json-object view patch))
                                     ((equal type "application/json-patch+json") (apply-core-json-patch view patch))
                                     (t (core-resource-error 415 "UnsupportedMediaType" "Custom status supports JSON/merge patches and apply"))))))
                  (input (admit-subresource-write store resource "status" namespace name input view
                                                  :dry-run (core-resource-dry-run-p)))
                  (*crd-status-write* t))
             (json-response
               (update-core-resource store resource namespace name (lambda (old) (declare (ignore old)) input)
                                     :dry-run (core-resource-dry-run-p)))))
          (t (core-resource-error 405 "MethodNotAllowed" "Unsupported custom status method")))))

(defun crd-json-path-parts (path)
  "Split a simple JSONPath into its field names."
  (mapcar (lambda (match) (string-trim ".[]'" match))
          (cl-ppcre:all-matches-as-strings "\\.[A-Za-z0-9_-]+|\\['[^']+'\\]" path)))

(defun crd-read-json-path (object path)
  "Read a simple JSONPath from OBJECT, giving NIL when any part is absent."
  (let ((value object))
    (dolist (part (crd-json-path-parts path) value)
      (setf value (and (hash-table-p value) (gethash part value))))))

(defun crd-write-json-path (object path value)
  "Write VALUE at a simple JSONPath in OBJECT, creating the objects along the way."
  (let ((parts (crd-json-path-parts path)) (node object))
    (loop for (part . more) on parts
          do (if more
                 (let ((next (gethash part node)))
                   (unless (hash-table-p next)
                     (setf next (core-object) (gethash part node) next))
                   (setf node next))
                 (setf (gethash part node) value)))
    object))

(defun crd-scale-view (object definition)
  "Build the autoscaling/v1 Scale of a custom OBJECT from its version's scale paths."
  (let* ((scale (gethash "scale" (gethash "subresources" (crd-version definition *crd-request-version*))))
         (selector (and (gethash "labelSelectorPath" scale)
                        (crd-read-json-path object (gethash "labelSelectorPath" scale))))
         (replicas (crd-read-json-path object (gethash "specReplicasPath" scale)))
         (status-replicas (crd-read-json-path object (gethash "statusReplicasPath" scale)))
         (metadata (gethash "metadata" object))
         (status (core-object "replicas" (if (integerp status-replicas) status-replicas 0))))
    (when (stringp selector) (setf (gethash "selector" status) selector))
    (core-object "apiVersion" "autoscaling/v1" "kind" "Scale"
                 "metadata" (core-object "name" (gethash "name" metadata) "namespace" (gethash "namespace" metadata)
                                         "uid" (gethash "uid" metadata) "resourceVersion" (gethash "resourceVersion" metadata)
                                         "creationTimestamp" (gethash "creationTimestamp" metadata))
                 "spec" (core-object "replicas" (if (integerp replicas) replicas 0))
                 "status" status)))

(defun dispatch-crd-scale (store resource namespace name method)
  "Read and write replicas through the scale subresource with its optimistic metadata."
  (let* ((definition *crd-view-definition*)
         (scale (gethash "scale" (gethash "subresources" (crd-version definition *crd-request-version*))))
         (current (crd-api-view (get-core-resource store resource namespace name)))
         (view (crd-scale-view current definition))
         (dry-run (core-resource-dry-run-p)))
    (flet ((scale-response (object)
             (let ((*crd-view-definition* nil))
               (json-response object))))
      (ecase method
        (:get (scale-response view))
        ((:put :patch)
         (let* ((text (hunchentoot:raw-post-data :force-text t))
                (type (request-media-type))
                (input (if (eq method :put)
                           (require-object (com.inuoe.jzon:parse text) "Scale")
                           (let ((patch (com.inuoe.jzon:parse text)))
                             (cond ((equal type "application/merge-patch+json") (merge-json-object (copy-core-object view) patch))
                                   ((equal type "application/json-patch+json") (apply-core-json-patch (copy-core-object view) patch))
                                   (t (core-resource-error 415 "UnsupportedMediaType" "Scale supports JSON and merge patches")))))))
           (unless (and (equal "Scale" (gethash "kind" input "Scale")) (hash-table-p (gethash "spec" input)))
             (core-resource-error 400 "BadRequest" "Expected an autoscaling/v1 Scale"))
           (let ((replicas (gethash "replicas" (gethash "spec" input)))
                 (expected (let ((metadata (gethash "metadata" input)))
                             (and (hash-table-p metadata) (gethash "resourceVersion" metadata))))
                 (uid (let ((metadata (gethash "metadata" input)))
                        (and (hash-table-p metadata) (gethash "uid" metadata)))))
             (unless (typep replicas '(integer 0 *))
               (crd-schema-error "spec.replicas" "must be greater than or equal to 0"))
             (let* ((input (admit-subresource-write store resource "scale" namespace name input view
                                                    :kind "Scale" :kind-api-version "autoscaling/v1" :dry-run dry-run))
                    (replicas (let ((spec (gethash "spec" input))) (if (hash-table-p spec) (gethash "replicas" spec replicas) replicas)))
                    (updated
                      (update-core-resource
                       store resource namespace name
                       (lambda (old)
                         (when (and (stringp expected) (plusp (length expected))
                                    (not (equal expected (gethash "resourceVersion" (gethash "metadata" old)))))
                           (core-resource-error 409 "Conflict" "The resource was modified; apply your changes to the latest version"))
                         (when (and (stringp uid) (plusp (length uid))
                                    (not (equal uid (gethash "uid" (gethash "metadata" old)))))
                           (core-resource-error 409 "Conflict" "metadata.uid does not match the stored object"))
                         (crd-write-json-path old (gethash "specReplicasPath" scale) replicas))
                       :dry-run dry-run)))
               (scale-response (crd-scale-view (crd-api-view updated) definition))))))))))

(defun dispatch-crd-request (store path method)
  "Handle one real served route using a store-scoped descriptor and version context."
  (let ((route (crd-special-route store path)))
    (ecase (first route)
      (:definition-status (dispatch-crd-definition-status store (second route) method))
      (:discovery
       (unless (eq method :get) (core-resource-error 405 "MethodNotAllowed" "Discovery requires GET"))
       (destructuring-bind (tag group version openapi) route
         (declare (ignore tag))
         (cond (openapi (json-response (crd-openapi-document store group version t)))
               (version (json-response (core-object "apiVersion" "v1" "kind" "APIResourceList" "groupVersion" (format nil "~A/~A" group version)
                                                   "resources" (crd-discovery-resources store group version))))
               (t (json-response (find group (crd-api-groups store) :test #'equal :key (lambda (value) (gethash "name" value))))))))
      (:resource
       (destructuring-bind (tag definition version namespace name subresource) route
         (declare (ignore tag))
         (let* ((*stored-resource-types* (append *stored-resource-types* (crd-resource-types store)))
                (*crd-view-definition* definition) (*crd-request-version* version)
                (*crd-view-store* store) (*crd-conversion-memo* (make-hash-table :test #'equal))
                (resource (crd-custom-key definition)) (*crd-route* (list resource namespace name)))
           (when (and (equal "Namespaced" (gethash "scope" (gethash "spec" definition))) (null namespace)
                      (or name (not (eq method :get))))
             (core-resource-error 405 "MethodNotAllowed" "Namespaced writes require a namespace"))
           (when (and namespace (not (dns-label-p namespace))) (core-resource-error 400 "BadRequest" "Invalid namespace"))
           (when (and name (not (dns-subdomain-p name))) (core-resource-error 400 "BadRequest" "Invalid name"))
           (cond
             ((equal subresource "scale") (dispatch-crd-scale store resource namespace name method))
             (subresource (dispatch-crd-status store resource namespace name method))
             ((and (eq method :patch) (equal "application/strategic-merge-patch+json" (hunchentoot:header-in* :content-type)))
              (core-resource-error 415 "UnsupportedMediaType" "Custom resources do not support strategic merge"))
             ((and (eq method :delete) (null name))
              (let* ((data (hunchentoot:raw-post-data :force-text t))
                     (options (when (and data (plusp (length data))) (com.inuoe.jzon:parse data)))
                     (dry-run (or (core-resource-dry-run-p) (equalp #("All") (gethash "dryRun" (or options (core-object))))))
                     (label-test (core-selector-predicate (hunchentoot:parameter "labelSelector")))
                     (field-test (crd-field-selector-test resource (hunchentoot:parameter "fieldSelector"))))
                (crd-prepare-selector-views store resource namespace (hunchentoot:parameter "fieldSelector"))
                (dolist (object (list-core-resources store resource namespace))
                  (when (and (funcall label-test object) (funcall field-test object))
                    (let ((metadata (gethash "metadata" object)))
                      (admit-core-delete store resource (gethash "namespace" metadata) (gethash "name" metadata) options dry-run)
                      (delete-core-resource store resource (gethash "namespace" metadata) (gethash "name" metadata) :uid (gethash "uid" metadata) :dry-run dry-run))))
                (status-response "Success" "Deleted" "Custom resource collection deleted" 200)))
             (t (dispatch-core-resource-request store path method)))))))))
