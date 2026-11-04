;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve admitted custom-resource routes, versions, discovery and status using
;;;; the shared durable journal. Conversion strategy None changes API identity
;;;; without inventing conversions, and every response applies its version schema.

(in-package #:gr8s)

(defvar *crd-route* nil)

(defun crd-api-group (group versions)
  "Describe actual served versions with a deterministic preferred version."
  (let ((values (sort (copy-list versions) #'string>)))
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
           (setf object (crd-prepare-value object (crd-schema version) t)
                 (gethash "apiVersion" object) (format nil "~A/~A" group *crd-request-version*)) object)
          ((and (equal kind (concatenate 'string (gethash "kind" names) "List"))
                (gethash "items" object))
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
                                      (and (equal "status" (third rest))
                                           (nth-value 1 (gethash "status" (gethash "subresources" (crd-version definition version) (core-object)))))))
                         (list :resource (copy-core-object definition) version namespace (second rest) (third rest))))))))))))))

(defun crd-discovery-resources (store group version)
  "Return collections and real status subresources for one served group/version."
  (if (equal group "apiextensions.k8s.io")
      (stored-resource-discovery +crd-api-version+)
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
                                 (cons resource (when (nth-value 1 (gethash "status" (gethash "subresources" entry (core-object))))
                                                  (list (core-object "name" (concatenate 'string (gethash "plural" names) "/status")
                                                                     "namespaced" (equal "Namespaced" (gethash "scope" spec)) "kind" (gethash "kind" names)
                                                                     "verbs" #("get" "patch" "update"))))))) 'vector))))

(defun crd-read-json ()
  "Reject protobuf for unstructured custom objects; read actual JSON requests."
  (let ((type (first (uiop:split-string (or (hunchentoot:header-in* :content-type) "") :separator '(#\;)))))
    (unless (member type '("" "application/json") :test #'equal) (core-resource-error 415 "UnsupportedMediaType" "Custom resources require JSON"))
    (require-object (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t) :max-string-length (* 2 1024 1024)) "request")))

(defun dispatch-crd-status (store resource namespace name method)
  "Serve status writes without modifying spec or bypassing optimistic metadata checks."
  (let ((existing (get-core-resource store resource namespace name)))
    (cond ((eq method :get) (json-response existing))
          ((member method '(:put :patch))
           (let* ((view (crd-api-view existing))
                  (type (first (uiop:split-string (or (hunchentoot:header-in* :content-type) "") :separator '(#\;))))
                  (input (if (eq method :put) (crd-read-json)
                             (let ((patch (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t))))
                               (cond ((equal type "application/merge-patch+json") (merge-json-object view patch))
                                     ((equal type "application/json-patch+json") (apply-core-json-patch view patch))
                                     (t (core-resource-error 415 "UnsupportedMediaType" "Custom status supports JSON/merge patches"))))))
                  (*crd-status-write* t))
             (json-response
               (update-core-resource store resource namespace name (lambda (old) (declare (ignore old)) input)
                                     :dry-run (core-resource-dry-run-p)))))
          (t (core-resource-error 405 "MethodNotAllowed" "Unsupported custom status method")))))

(defun dispatch-crd-request (store path method)
  "Handle one real served route using a store-scoped descriptor and version context."
  (let ((route (crd-special-route store path)))
    (ecase (first route)
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
                (resource (crd-custom-key definition)) (*crd-route* (list resource namespace name)))
           (when (and (equal "Namespaced" (gethash "scope" (gethash "spec" definition))) (null namespace)
                      (or name (not (eq method :get))))
             (core-resource-error 405 "MethodNotAllowed" "Namespaced writes require a namespace"))
           (when (and namespace (not (dns-label-p namespace))) (core-resource-error 400 "BadRequest" "Invalid namespace"))
           (when (and name (not (dns-subdomain-p name))) (core-resource-error 400 "BadRequest" "Invalid name"))
           (cond
             (subresource (dispatch-crd-status store resource namespace name method))
             ((and (eq method :patch) (equal "application/strategic-merge-patch+json" (hunchentoot:header-in* :content-type)))
              (core-resource-error 415 "UnsupportedMediaType" "Custom resources do not support strategic merge"))
             ((and (eq method :delete) (null name))
              (let* ((data (hunchentoot:raw-post-data :force-text t))
                     (options (when (and data (plusp (length data))) (com.inuoe.jzon:parse data)))
                     (dry-run (or (core-resource-dry-run-p) (equalp #("All") (gethash "dryRun" (or options (core-object))))))
                     (label-test (core-selector-predicate (hunchentoot:parameter "labelSelector")))
                     (field-test (core-selector-predicate (hunchentoot:parameter "fieldSelector") :fields t)))
                (dolist (object (list-core-resources store resource namespace))
                  (when (and (funcall label-test object) (funcall field-test object))
                    (let ((metadata (gethash "metadata" object)))
                      (delete-core-resource store resource (gethash "namespace" metadata) (gethash "name" metadata) :uid (gethash "uid" metadata) :dry-run dry-run))))
                (status-response "Success" "Deleted" "Custom resource collection deleted" 200)))
             (t (dispatch-core-resource-request store path method)))))))))
