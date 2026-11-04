;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Delete genuine custom resources and CRD routes using durable finalizer
;;;; semantics. Definition cleanup and dependent removals share one transaction;
;;;; user finalizers block deletion until their actual controllers release them.

(in-package #:gr8s)

(defun crd-deletion-copy (object revision)
  "Mark a copied object as deleting without rewriting a stable deletion intent."
  (let ((copy (copy-core-object object)))
    (unless (gethash "deletionTimestamp" (gethash "metadata" copy))
      (setf (gethash "deletionTimestamp" (gethash "metadata" copy)) (current-timestamp)))
    (unless (crd-json-equal-p copy object) (prepare-core-resource-metadata copy object revision))
    copy))

(defun crd-cleanup-index (index definition revision)
  "Remove unprotected custom instances, marking protected ones for actual cleanup."
  (let ((resource (crd-custom-key definition)) (remaining nil))
    (maphash (lambda (key object)
               (when (equal resource (first key))
                 (if (plusp (length (gethash "finalizers" (gethash "metadata" object) #())))
                     (progn (setf remaining t (gethash key index) (crd-deletion-copy object revision)))
                     (remhash key index)))) index)
    (let* ((copy (crd-deletion-copy definition revision)) (metadata (gethash "metadata" copy))
           (conditions (gethash "conditions" (gethash "status" copy))))
      (unless (find "Terminating" conditions :test #'equal :key (lambda (condition) (gethash "type" condition)))
        (setf (gethash "conditions" (gethash "status" copy))
              (concatenate 'vector conditions
                (vector (crd-condition "Terminating" "True" "InstanceDeletionInProgress" "Custom resources are being deleted")))))
      (unless remaining
        (setf (gethash "finalizers" metadata)
              (remove "customresourcecleanup.apiextensions.k8s.io" (gethash "finalizers" metadata #()) :test #'equal)))
      (let ((key (core-resource-key "customresourcedefinitions" nil (gethash "name" metadata))))
        (if (plusp (length (gethash "finalizers" metadata #())))
            (progn
              (unless (crd-json-equal-p copy definition) (prepare-core-resource-metadata copy definition revision))
              (setf (gethash key index) copy))
            (remhash key index)))
      copy)))

(defun delete-crd-object-unlocked (store resource object dry-run)
  "Commit deletion/finalization atomically after caller verifies UID and revision."
  (let* ((index (copy-core-resource-index store)) (revision (1+ (pod-store-resource-revision store)))
         (metadata (gethash "metadata" object)) (copy object))
    (cond ((equal resource "customresourcedefinitions") (setf copy (crd-cleanup-index index object revision)))
          ((plusp (length (gethash "finalizers" metadata #())))
           (setf copy (crd-deletion-copy object revision)
                 (gethash (core-resource-key resource (gethash "namespace" metadata) (gethash "name" metadata)) index) copy))
          (t (remhash (core-resource-key resource (gethash "namespace" metadata) (gethash "name" metadata)) index)))
    (maphash (lambda (key value)
               (let ((before (gethash key (pod-store-resources store))))
                 (when (and before (crd-json-equal-p before value)) (setf (gethash key index) before)))) index)
    (unless (or dry-run
                (and (= (hash-table-count index) (hash-table-count (pod-store-resources store)))
                     (loop for key being the hash-keys of index using (hash-value value)
                           always (eq value (gethash key (pod-store-resources store))))))
      (commit-core-resources store index revision))
    (copy-core-object copy)))

(defun reconcile-crd-deletions (store)
  "Resume actual custom-instance cleanup after restart, without expiring finalizers."
  (with-store-lock (store)
    (dolist (definition (loop for key being the hash-keys of (pod-store-resources store) using (hash-value object)
                             when (and (equal "customresourcedefinitions" (first key))
                                       (gethash "deletionTimestamp" (gethash "metadata" object))) collect object))
      (delete-crd-object-unlocked store "customresourcedefinitions" definition nil))))
