;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Serve the apidiscovery.k8s.io/v2 document on /api and /apis, which clients
;;;; request by media type to learn every group and resource in one call. It is
;;;; assembled from the same per-version documents legacy discovery serves, so
;;;; the two cannot disagree about what exists.

(in-package #:gr8s)

(defparameter +aggregated-discovery-media-type+ "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList"
  "The representation served, which client-go recognizes by its exact Content-Type.")

(defun aggregated-discovery-requested-p ()
  "Report whether the client accepts aggregated discovery in JSON."
  (some (lambda (parts)
          (and (member (first parts) '("application/json" "application/vnd.kubernetes.protobuf") :test #'string=)
               (member "as=APIGroupDiscoveryList" (rest parts) :test #'string=)
               (member "g=apidiscovery.k8s.io" (rest parts) :test #'string=)
               (member "v=v2" (rest parts) :test #'string=)))
        (accept-media-ranges)))

(defun aggregated-response-kind (resource group version)
  "Describe the kind RESOURCE returns, which may name another group or version."
  (core-object "group" (gethash "group" resource group)
               "version" (gethash "version" resource version)
               "kind" (gethash "kind" resource "")))

(defun aggregated-version-resources (resources group version)
  "Group a legacy APIResource list into top-level resources and their subresources."
  (let* ((parents (remove-if (lambda (resource) (find #\/ (gethash "name" resource))) resources))
         (children (remove-if-not (lambda (resource) (find #\/ (gethash "name" resource))) resources))
         (parent-names (map 'list (lambda (resource) (gethash "name" resource)) parents))
         (orphans (remove-duplicates
                   (loop for child across children
                         for parent = (subseq (gethash "name" child) 0 (position #\/ (gethash "name" child)))
                         unless (member parent parent-names :test #'equal) collect parent)
                   :test #'equal)))
    (coerce
     (loop for resource in (append (coerce parents 'list) (mapcar (lambda (name) (core-object "name" name)) orphans))
           for name = (gethash "name" resource)
           collect
           (let ((entry (core-object
                         "resource" name
                         "scope" (if (loop for candidate across resources
                                           thereis (and (or (string= name (gethash "name" candidate))
                                                            (uiop:string-prefix-p (concatenate 'string name "/") (gethash "name" candidate)))
                                                        (gethash "namespaced" candidate)))
                                     "Namespaced" "Cluster")
                         "singularResource" (let ((singular (gethash "singularName" resource "")))
                                              (if (plusp (length singular)) singular (string-downcase (gethash "kind" resource ""))))
                         "verbs" (gethash "verbs" resource #())))
                 (subresources
                   (loop for child across children
                         for child-name = (gethash "name" child)
                         for slash = (position #\/ child-name)
                         when (string= name (subseq child-name 0 slash))
                           collect (core-object "subresource" (subseq child-name (1+ slash))
                                                "responseKind" (aggregated-response-kind child group version)
                                                "verbs" (gethash "verbs" child #())))))
             (when (gethash "kind" resource)
               (setf (gethash "responseKind" entry) (aggregated-response-kind resource group version)))
             (dolist (field '("shortNames" "categories"))
               (when (gethash field resource) (setf (gethash field entry) (gethash field resource))))
             (when subresources (setf (gethash "subresources" entry) (coerce subresources 'vector)))
             entry))
     'vector)))

(defun aggregated-version-entry (store runtime reconciler path group version)
  "Describe one served version from its legacy discovery document at PATH."
  (let* ((document (com.inuoe.jzon:parse (route-http-request store runtime reconciler path :get)))
         (resources (gethash "resources" document #())))
    (core-object "version" version "freshness" "Current"
                 "resources" (aggregated-version-resources resources group version))))

(defun aggregated-external-version-entry (store group version)
  "Describe an external version from its server's last good document, or NIL before it has passed."
  (let ((document (aggregated-version-document store group version)))
    (when document
      (core-object "version" version "freshness" "Current"
                   "resources" (aggregated-version-resources (gethash "resources" document #()) group version)))))

(defun aggregated-discovery-response (store runtime reconciler root)
  "Answer the aggregated document for the legacy /api or named /apis root."
  (let* ((groups (if (string= root "/api")
                     (list (cons "" '("v1")))
                     (let ((document (com.inuoe.jzon:parse (api-groups-response store))))
                       (map 'list (lambda (group)
                                    (cons (gethash "name" group)
                                          (map 'list (lambda (version) (gethash "version" version)) (gethash "versions" group))))
                            (gethash "groups" document)))))
         (items (loop for (group . versions) in groups
                      for entries = (loop for version in versions
                                          for entry = (if (and (string/= root "/api")
                                                               (aggregated-apiservice store group version))
                                                          (aggregated-external-version-entry store group version)
                                                          (aggregated-version-entry
                                                           store runtime reconciler
                                                           (if (string= root "/api")
                                                               (format nil "/api/~A" version)
                                                               (format nil "/apis/~A/~A" group version))
                                                           group version))
                                          when entry collect entry)
                      when entries
                        collect (core-object
                                 "metadata" (if (string= root "/api") (core-object) (core-object "name" group))
                                 "versions" (coerce entries 'vector))))
         (body (com.inuoe.jzon:stringify
                (core-object "apiVersion" "apidiscovery.k8s.io/v2" "kind" "APIGroupDiscoveryList"
                             "metadata" (core-object) "items" (coerce items 'vector)))))
    (setf (hunchentoot:return-code*) 200
          (hunchentoot:content-type*) +aggregated-discovery-media-type+)
    body))
