;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Persist foreground/orphan workload deletion intent alongside the API
;;;; transaction. Foreground deletion waits for exact-UID dependents, and
;;;; orphaning detaches ownership before the parent disappears, across restart.

(in-package #:gr8s)

(defun workload-deletion-policy (options)
  "Validate modern and deprecated DeleteOptions propagation choices."
  (multiple-value-bind (policy specified) (gethash "propagationPolicy" (or options (core-object)) "Background")
    (multiple-value-bind (orphan orphan-specified) (gethash "orphanDependents" (or options (core-object)))
      (when (and specified orphan-specified)
        (core-resource-error 422 "Invalid" "orphanDependents and propagationPolicy are mutually exclusive"))
      (when orphan-specified
        (unless (member orphan '(t nil)) (core-resource-error 422 "Invalid" "orphanDependents must be boolean"))
        (setf policy (if orphan "Orphan" "Background")))
      (when (eq policy 'null) (setf policy "Background"))
      (unless (member policy '("Background" "Foreground" "Orphan") :test #'equal)
        (core-resource-error 422 "Invalid" "Invalid workload deletion propagation policy"))
      policy)))

(defun delete-workload-resource (store resource namespace name &key uid resource-version dry-run (policy "Background"))
  "Delete immediately in background mode or atomically checkpoint an irreversible deletion."
  (unless (member policy '("Background" "Foreground" "Orphan") :test #'equal)
    (core-resource-error 422 "Invalid" "Invalid workload deletion propagation policy"))
  (with-store-lock (store)
    (let* ((existing (get-core-resource-unlocked store resource namespace name)) (metadata (workload-metadata existing))
           (actual-uid (gethash "uid" metadata)) (key (core-resource-key resource namespace name))
           (resources (copy-core-resource-index store)) (deletions (copy-core-object (pod-store-workload-deletions store)))
           (revision (1+ (pod-store-resource-revision store))) (pending (gethash actual-uid deletions)))
      (when (or (and uid (not (equal uid actual-uid)))
                (and resource-version (not (equal resource-version (gethash "resourceVersion" metadata)))))
        (core-resource-error 409 "Conflict" "Workload deletion precondition does not match"))
      (when (and pending (not (equal policy (gethash "policy" pending))))
        (core-resource-error 409 "Conflict" "A workload deletion's propagation policy cannot be changed"))
      (cond
        (pending (copy-core-object existing))
        ((equal policy "Background")
         (remhash key resources)
         (unless dry-run (commit-core-resources store resources revision :workload-deletions deletions))
         (copy-core-object existing))
        (t
         (let ((copy (copy-core-object existing)))
           (setf (gethash "deletionTimestamp" (workload-metadata copy)) (current-timestamp)
                 (gethash actual-uid deletions) (core-object "resource" resource "namespace" namespace "name" name
                                                           "uid" actual-uid "policy" policy))
           (prepare-core-resource-metadata copy existing revision)
           (setf (gethash key resources) copy)
           (unless dry-run (commit-core-resources store resources revision :workload-deletions deletions))
           copy))))))

(defun delete-workload-collection (store resource namespace options dry-run)
  "Apply propagation independently to all objects matching a real collection snapshot."
  (let* ((page (template-list-page store namespace (or (hunchentoot:parameter "labelSelector") "")
                                   (or (hunchentoot:parameter "fieldSelector") "") :resource resource))
         (policy (workload-deletion-policy options)))
    (loop for object across (gethash "items" page) for metadata = (workload-metadata object)
          do (delete-workload-resource store resource (gethash "namespace" metadata) (gethash "name" metadata)
                                       :uid (gethash "uid" metadata) :policy policy :dry-run dry-run))))

(defun finish-workload-deletion (store record)
  "Atomically forget a completed intent without deleting a same-name replacement."
  (with-store-lock (store)
    (let* ((resources (copy-core-resource-index store)) (deletions (copy-core-object (pod-store-workload-deletions store)))
           (key (core-resource-key (gethash "resource" record) (gethash "namespace" record) (gethash "name" record)))
           (current (gethash key resources)))
      (when (gethash (gethash "uid" record) deletions)
        (when (and current (equal (gethash "uid" record) (gethash "uid" (workload-metadata current))))
          (remhash key resources))
        (remhash (gethash "uid" record) deletions)
        (commit-core-resources store resources (1+ (pod-store-resource-revision store)) :workload-deletions deletions)))))

(defun detach-workload-dependent (store resource owner child &optional (owner-resource "deployments"))
  "Remove one exact controller reference while retaining unrelated owners and immutable state."
  (with-store-lock (store)
    (let* ((metadata (workload-metadata child))
           (current (gethash (core-resource-key resource (gethash "namespace" metadata) (gethash "name" metadata))
                             (pod-store-resources store))))
      (when (and (workload-current-unlocked store owner-resource owner :allow-deleting t)
                 current (equal (gethash "uid" metadata) (gethash "uid" (workload-metadata current)))
                 (workload-owned-p current owner))
        (let* ((copy (copy-core-object current)) (resources (copy-core-resource-index store))
               (revision (1+ (pod-store-resource-revision store))))
          (setf (gethash "ownerReferences" (workload-metadata copy))
                (remove-if (lambda (reference) (equal (gethash "uid" reference) (gethash "uid" (workload-metadata owner))))
                           (gethash "ownerReferences" (workload-metadata copy) #())))
          (prepare-core-resource-metadata copy current revision)
          (setf (gethash (core-resource-key resource (gethash "namespace" metadata) (gethash "name" metadata)) resources) copy)
          (commit-core-resources store resources revision))))))

(defun process-workload-deletion (reconciler record)
  "Advance one durable deletion, retaining foreground owners until dependents disappear."
  (let* ((store (reconciler-store reconciler)) (resource (gethash "resource" record))
         (namespace (gethash "namespace" record)) (name (gethash "name" record))
         (owner (handler-case (get-core-resource store resource namespace name)
                  (kubernetes-error (condition) (unless (= 404 (kubernetes-error-status-code condition)) (error condition)))))
         (orphan (equal "Orphan" (gethash "policy" record))))
    (unless (and owner (equal (gethash "uid" record) (gethash "uid" (workload-metadata owner))))
      (finish-workload-deletion store record)
      (return-from process-workload-deletion nil))
    (if (member resource '("deployments" "cronjobs") :test #'equal)
        (let* ((dependents (if (equal resource "cronjobs") "jobs" "replicasets"))
               (children (remove-if-not (lambda (child) (workload-owned-p child owner))
                                        (list-core-resources store dependents namespace))))
          (dolist (child children)
            (if orphan (detach-workload-dependent store dependents owner child resource)
                (let ((metadata (workload-metadata child)))
                  (delete-workload-resource store dependents namespace (gethash "name" metadata)
                                            :uid (gethash "uid" metadata) :policy "Foreground"))))
          (unless (some (lambda (child) (workload-owned-p child owner)) (list-core-resources store dependents namespace))
            (finish-workload-deletion store record)))
        (let ((children (remove-if-not (lambda (pod) (workload-owned-p (pod-to-object pod) owner)) (list-pods store namespace))))
          (dolist (pod children)
            (if orphan (change-controller-pod-owner store owner pod nil :resource resource)
                (delete-reconciled-pod reconciler namespace (pod-name pod) :uid (pod-uid pod))))
          (unless (some (lambda (pod) (workload-owned-p (pod-to-object pod) owner)) (list-pods store namespace))
            (finish-workload-deletion store record))))))

(defun process-workload-deletions (reconciler)
  "Resume pending intents after a process restart before reconciling new desired replicas."
  (let ((store (reconciler-store reconciler)))
    (dolist (record (with-store-lock (store)
                     (loop for record being the hash-values of (pod-store-workload-deletions store)
                           collect (copy-core-object record))))
      (handler-case (process-workload-deletion reconciler record)
        (kubernetes-error (condition)
          (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))))
