;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Snapshot-wide validation retains identity metadata, never application payloads.
(in-package #:gr8s.resources)

(defstruct snapshot-validation-index
  (identities (make-hash-table :test #'equal))
  (cidrs (make-hash-table :test #'equal))
  (cidr-descendants (make-hash-table :test #'equal))
  (definitions (make-hash-table :test #'equal))
  (custom-shapes (make-hash-table :test #'equal)))

(defun snapshot-claim-identity (index category value)
  (let ((key (list category value)))
    (when (gethash key (snapshot-validation-index-identities index))
      (error "Duplicate snapshot identity in ~A" category))
    (setf (gethash key (snapshot-validation-index-identities index)) t)))

(defun snapshot-claim-cidr (index text)
  "Detect overlaps in O(address width), including differently spelled networks."
  (let ((cidr (and (stringp text) (cel-parse-cidr text))))
    (unless cidr (error "Invalid snapshot Node Pod CIDR"))
    (let* ((address (car cidr)) (prefix (cdr cidr))
           (network (cel-masked-address address prefix))
           (key (list network prefix)))
      (when (or (gethash key (snapshot-validation-index-cidr-descendants index))
                (loop for ancestor from 0 to prefix
                      thereis (gethash (list (cel-masked-address address ancestor) ancestor)
                                       (snapshot-validation-index-cidrs index))))
        (error "Overlapping snapshot Node Pod CIDRs"))
      (setf (gethash key (snapshot-validation-index-cidrs index)) t)
      (loop for ancestor from 0 to prefix do
        (incf (gethash (list (cel-masked-address address ancestor) ancestor)
                      (snapshot-validation-index-cidr-descendants index) 0))))))

(defun snapshot-crd-shape (object)
  "Extract only the descriptor needed to validate durable custom objects."
  (let* ((spec (gethash "spec" object)) (names (and (hash-table-p spec) (gethash "names" spec)))
         (group (and spec (gethash "group" spec)))
         (plural (and (hash-table-p names) (gethash "plural" names)))
         (kind (and names (gethash "kind" names)))
         (scope (and spec (gethash "scope" spec)))
         (versions (and spec (gethash "versions" spec)))
         (seen (make-hash-table :test #'equal)) (storage 0) (apis nil))
    (unless (and (snapshot-string-p group) (snapshot-string-p plural)
                 (snapshot-string-p kind) (member scope '("Namespaced" "Cluster") :test #'equal)
                 (vectorp versions) (not (stringp versions)) (plusp (length versions)))
      (error "Invalid snapshot CRD descriptor"))
    (loop for version across versions do
      (let ((name (and (hash-table-p version) (gethash "name" version))))
        (unless (and (snapshot-string-p name) (not (gethash name seen)))
          (error "Invalid or duplicate snapshot CRD version"))
        (setf (gethash name seen) t)
        (when (eq t (gethash "storage" version)) (incf storage))
        ;; Existing objects can use a version that is no longer served.
        (push (format nil "~A/~A" group name) apis)))
    (unless (= 1 storage) (error "Snapshot CRD must have one storage version"))
    (unless (equal (format nil "~A.~A" plural group)
                   (gethash "name" (gethash "metadata" object)))
      (error "Snapshot CRD name does not match its collection"))
    (values (format nil "custom:~A/~A" group plural) (list kind scope apis))))

(defun index-store-snapshot-record (index record)
  (let ((kind (gethash "kind" record)) (object (gethash "object" record)))
    (cond
      ((equal kind "resource")
       (let* ((resource (gethash "resource" record))
              (namespace (unless (eq 'null (gethash "namespace" record)) (gethash "namespace" record)))
              (name (gethash "name" record)))
         (snapshot-claim-identity index :resource (list resource namespace name))
         (cond
           ((equal resource "customresourcedefinitions")
            (when namespace (error "Snapshot CRD cannot have a namespace"))
            (multiple-value-bind (collection shape) (snapshot-crd-shape object)
              (snapshot-claim-identity index :crd-collection collection)
              (setf (gethash collection (snapshot-validation-index-definitions index)) shape)))
           ((custom-resource-key-p resource)
            (unless (and (snapshot-string-p (gethash "kind" object))
                         (snapshot-string-p (gethash "apiVersion" object)))
              (error "Invalid snapshot custom object kind/version"))
            ;; Deduplicate shapes, not payloads or one descriptor per instance.
            (setf (gethash (list resource (gethash "kind" object) (gethash "apiVersion" object)
                                 (not (null namespace)))
                           (snapshot-validation-index-custom-shapes index)) t)))))
      ((equal kind "pod")
       (let ((metadata (gethash "metadata" object)))
         (snapshot-claim-identity index :pod-uid (gethash "uid" metadata))
         (snapshot-claim-identity index :pod-name (list (gethash "namespace" metadata) (gethash "name" metadata)))))
      ((equal kind "node")
       (snapshot-claim-identity index :node-id (gethash "id" object))
       (snapshot-claim-identity index :node-name (gethash "name" object))
       (let ((underlay (gethash "underlayAddress" object))
             (key (gethash "wireguardPublicKey" object))
             (cidrs (gethash "podCIDRs" object)))
         (when (and underlay (not (eq underlay 'null)) (not (equal underlay "")))
           (let ((address (and (stringp underlay) (cel-parse-ip underlay))))
             (unless address (error "Invalid snapshot Node underlay address"))
             (snapshot-claim-identity index :node-underlay address)))
         (when (and key (not (eq key 'null)) (not (equal key "")))
           (let ((bytes (and (stringp key) (ag-grpc:base64-decode key))))
             (unless (and bytes (= 32 (length bytes)) (equal key (ag-grpc:base64-encode bytes)))
               (error "Invalid snapshot Node WireGuard identity"))
             (snapshot-claim-identity index :node-wireguard key)))
         (unless (or (null cidrs) (eq cidrs 'null) (and (vectorp cidrs) (not (stringp cidrs))))
           (error "Invalid snapshot Node Pod CIDRs"))
         (let ((primary (gethash "podCIDR" object)))
           (dolist (cidr (remove-duplicates
                         (append (when (and primary (not (eq primary 'null)) (not (equal primary "")))
                                   (list primary))
                                 (when (and (vectorp cidrs) (not (stringp cidrs))) (coerce cidrs 'list)))
                         :test #'equal))
             (snapshot-claim-cidr index cidr)))))
      ((member kind '("workloadDeletion" "jobControllerState") :test #'equal)
       (snapshot-claim-identity index kind (gethash "key" record)))))
  index)

(defun finish-store-snapshot-index (index)
  (maphash
   (lambda (shape ignored)
     (declare (ignore ignored))
     (destructuring-bind (collection kind api namespaced) shape
       (let ((definition (gethash collection (snapshot-validation-index-definitions index))))
         (unless (and definition (equal kind (first definition))
                      (eq namespaced (equal "Namespaced" (second definition)))
                      (member api (third definition) :test #'equal))
           (error "Snapshot custom object has no matching definition/version/scope")))))
   (snapshot-validation-index-custom-shapes index))
  index)

(defun validate-store-snapshot (path &key expected-index expected-term function
                                        (max-record-bytes *store-snapshot-max-record-bytes*))
  "Validate a complete artifact, including cross-record identities and CRD relationships.
FUNCTION receives provisional records for a staging destination. END is delivered only
after all validation succeeds. Returns header/clocks/count like MAP-STORE-SNAPSHOT-RECORDS.
Identity indexes grow with object count; payload memory is bounded by a single record."
  (let ((index (make-snapshot-validation-index)) (end nil))
    (multiple-value-bind (header clocks count)
        (map-store-snapshot-records
         path (lambda (record)
                (if (equal "end" (gethash "kind" record)) (setf end record)
                    (progn (index-store-snapshot-record index record)
                           (when function (funcall function record)))))
         :expected-index expected-index :expected-term expected-term :max-record-bytes max-record-bytes)
      (finish-store-snapshot-index index)
      (when function (funcall function end))
      (values header clocks count))))
