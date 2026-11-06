;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Persist foreground/orphan workload deletion intent alongside the API
;;;; transaction. Foreground deletion waits for exact-UID dependents, and
;;;; orphaning detaches ownership before the parent disappears, across restart.

(in-package #:gr8s)

(defun workload-deletion-policy (options &optional resource)
  "Validate modern and deprecated DeleteOptions propagation choices.
Unspecified, core/v1 ReplicationControllers orphan for compatibility, as in Kubernetes."
  (multiple-value-bind (policy specified)
      (gethash "propagationPolicy" (or options (core-object))
               (if (equal resource "replicationcontrollers") "Orphan" "Background"))
    (multiple-value-bind (orphan orphan-specified) (gethash "orphanDependents" (or options (core-object)))
      (when (and specified orphan-specified)
        (core-resource-error 422 "Invalid" "orphanDependents and propagationPolicy are mutually exclusive"))
      (when orphan-specified
        (unless (member orphan '(t nil)) (core-resource-error 422 "Invalid" "orphanDependents must be boolean"))
        (setf policy (if orphan "Orphan" "Background")))
      (when (eq policy 'null) (setf policy (if (equal resource "replicationcontrollers") "Orphan" "Background")))
      (unless (member policy '("Background" "Foreground" "Orphan") :test #'equal)
        (core-resource-error 422 "Invalid" "Invalid workload deletion propagation policy"))
      policy)))

(defun deletion-policy-finalizers (metadata policy)
  "Return METADATA's finalizers with the one Kubernetes shows while POLICY holds an object."
  (let ((name (if (equal policy "Orphan") "orphan" "foregroundDeletion"))
        (finalizers (gethash "finalizers" metadata #())))
    (if (find name finalizers :test #'equal)
        finalizers
        (concatenate 'vector finalizers (vector name)))))

(defun core-deletion-held-p (store resource namespace name policy)
  "Return whether an object deleted with POLICY waits for its dependents, as all but kinds
with their own deletion lifecycle do."
  (and (member policy '("Foreground" "Orphan") :test #'equal)
       (not (member resource '("namespaces" "customresourcedefinitions" "persistentvolumes" "persistentvolumeclaims")
                    :test #'equal))
       (let ((*stored-resource-types* (append *stored-resource-types* (crd-resource-types store))))
         (workload-deletion-blocked-p store namespace
                                      (gethash "uid" (gethash "metadata" (get-core-resource store resource namespace name)))
                                      policy))))

(defun deletion-held-by-finalizers-p (metadata)
  "Return whether METADATA names finalizers besides the ones a propagation policy adds."
  (find-if-not (lambda (name) (member name '("foregroundDeletion" "orphan") :test #'equal))
               (gethash "finalizers" metadata #())))

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
        ;; A user finalizer holds the object, deleting, until a client removes it.
        ((and (equal policy "Background") (deletion-held-by-finalizers-p metadata))
         (if (gethash "deletionTimestamp" metadata)
             (copy-core-object existing)
             (let ((copy (copy-core-object existing)))
               (setf (gethash "deletionTimestamp" (workload-metadata copy)) (current-timestamp))
               (prepare-core-resource-metadata copy existing revision)
               (setf (gethash key resources) copy)
               (unless dry-run (commit-core-resources store resources revision))
               copy)))
        ((equal policy "Background")
         (remhash key resources)
         (unless dry-run (commit-core-resources store resources revision :workload-deletions deletions))
         (copy-core-object existing))
        (t
         (let ((copy (copy-core-object existing)))
           (setf (gethash "deletionTimestamp" (workload-metadata copy)) (current-timestamp)
                 (gethash "finalizers" (workload-metadata copy))
                 (deletion-policy-finalizers (workload-metadata copy) policy)
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
         (policy (workload-deletion-policy options resource)))
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
          ;; A selector Service owns its Endpoints, however the Service came to be deleted.
          (when (and (equal "services" (gethash "resource" record))
                     (plusp (hash-table-count (gethash "selector" (gethash "spec" current) (core-object)))))
            (remhash (core-resource-key "endpoints" (gethash "namespace" record) (gethash "name" record)) resources))
          ;; An object's own finalizers go on holding it after the policy's has done its work.
          (let ((remaining (remove-if (lambda (name) (member name '("foregroundDeletion" "orphan") :test #'equal))
                                      (gethash "finalizers" (workload-metadata current) #()))))
            (if (plusp (length remaining))
                (let ((copy (copy-core-object current)) (revision (1+ (pod-store-resource-revision store))))
                  (setf (gethash "finalizers" (workload-metadata copy)) remaining)
                  (prepare-core-resource-metadata copy current revision)
                  (setf (gethash key resources) copy))
                (remhash key resources))))
        (remhash (gethash "uid" record) deletions)
        (commit-core-resources store resources (1+ (pod-store-resource-revision store)) :workload-deletions deletions)))))

(defun detach-workload-dependent (store resource owner child &optional (owner-resource (workload-owner-resource owner)))
  "Remove OWNER's reference from CHILD, an exact stored object, retaining unrelated owners."
  (with-store-lock (store)
    (let* ((metadata (workload-metadata child))
           (current (gethash (core-resource-key resource (gethash "namespace" metadata) (gethash "name" metadata))
                             (pod-store-resources store))))
      (when (and (workload-current-unlocked store owner-resource owner :allow-deleting t)
                 current (equal (gethash "uid" metadata) (gethash "uid" (workload-metadata current)))
                 (dependent-owner-reference (workload-metadata current) (gethash "uid" (workload-metadata owner))))
        (let* ((copy (copy-core-object current)) (resources (copy-core-resource-index store))
               (revision (1+ (pod-store-resource-revision store))))
          (setf (gethash "ownerReferences" (workload-metadata copy))
                (remove-if (lambda (reference) (equal (gethash "uid" reference) (gethash "uid" (workload-metadata owner))))
                           (gethash "ownerReferences" (workload-metadata copy) #())))
          (prepare-core-resource-metadata copy current revision)
          (setf (gethash (core-resource-key resource (gethash "namespace" metadata) (gethash "name" metadata)) resources) copy)
          (commit-core-resources store resources revision))))))

(defun dependent-owner-reference (metadata uid)
  "Return the reference in dependent METADATA to the owner with UID, if any."
  (find uid (gethash "ownerReferences" metadata #()) :test #'equal :key (lambda (reference) (gethash "uid" reference))))

(defun remove-pod-owner-reference (store pod uid)
  "Remove one exact owner from POD, retaining the others and every other Pod field."
  (with-store-lock (store)
    (let ((current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store))))
      (when (and current (equal (pod-uid current) (pod-uid pod))
                 (dependent-owner-reference (workload-metadata (pod-to-object current)) uid))
        (let* ((object (copy-core-object (pod-to-object current))) (metadata (workload-metadata object)))
          (setf (gethash "ownerReferences" metadata)
                (remove uid (gethash "ownerReferences" metadata) :test #'equal
                        :key (lambda (reference) (gethash "uid" reference))))
          (update-pod-unlocked store (parse-pod object) (pod-resource-version current)))))))

(defun dependent-has-solid-owner-p (store namespace metadata uid)
  "Return whether a dependent has another owner that exists and is not itself deleting in the foreground."
  (some (lambda (reference)
          (and (not (equal uid (gethash "uid" reference)))
               (not (eq :absent (referenced-owner-state store namespace reference)))
               (not (let ((pending (with-store-lock (store)
                                     (gethash (gethash "uid" reference) (pod-store-workload-deletions store)))))
                      (and pending (equal "Foreground" (gethash "policy" pending)))))))
        (gethash "ownerReferences" metadata #())))

(defun workload-stored-dependents (store namespace uid)
  "List (resource . object) for every stored object that names the owner UID.
A namespaced owner has dependents only in its namespace; only a cluster-scoped one has cluster-scoped dependents."
  (loop for (resource nil nil namespaced) in *stored-resource-types*
        when (or namespaced (null namespace))
          append (loop for object in (list-core-resources store resource namespace)
                       when (dependent-owner-reference (workload-metadata object) uid)
                         collect (cons resource object))))

(defun workload-deletion-blocked-p (store namespace uid policy)
  "Return whether a dependent still prevents the owner with UID from disappearing.
Orphaning waits for every reference to go; foreground waits for blockOwnerDeletion ones."
  (flet ((blocking-p (metadata)
           (let ((reference (dependent-owner-reference metadata uid)))
             (and reference (or (equal policy "Orphan") (eq t (gethash "blockOwnerDeletion" reference)))))))
    (or (some (lambda (pod) (blocking-p (workload-metadata (pod-to-object pod)))) (list-pods store namespace))
        (some (lambda (entry) (blocking-p (workload-metadata (cdr entry))))
              (workload-stored-dependents store namespace uid)))))

(defun advance-foreground-pod-dependent (reconciler pod uid)
  "Delete one dependent Pod, or only drop the owner reference when another owner keeps it alive."
  (let ((store (reconciler-store reconciler)) (namespace (pod-namespace pod)))
    (if (dependent-has-solid-owner-p store namespace (workload-metadata (pod-to-object pod)) uid)
        (remove-pod-owner-reference store pod uid)
        (delete-controller-pod reconciler namespace (pod-name pod) "generic-garbage-collector" :uid (pod-uid pod)))))

(defun advance-foreground-stored-dependent (store owner resource object)
  "Delete one dependent stored object in the foreground, or drop the reference if another owner keeps it."
  (let* ((metadata (workload-metadata object)) (namespace (gethash "namespace" metadata))
         (uid (gethash "uid" (workload-metadata owner))))
    (cond ((dependent-has-solid-owner-p store namespace metadata uid)
           (detach-workload-dependent store resource owner object))
          ((not (controller-delete-allowed-p store resource namespace (gethash "name" metadata) "generic-garbage-collector"))
           nil)
          ((or (workload-resource-p resource) (batch-resource-p resource))
           (delete-workload-resource store resource namespace (gethash "name" metadata)
                                     :uid (gethash "uid" metadata) :policy "Foreground"))
          (t (delete-core-resource store resource namespace (gethash "name" metadata) :uid (gethash "uid" metadata))))))

(defun release-orphaned-pod-dependent (store owner pod resource)
  "Detach POD from OWNER for an orphaning deletion, whichever kind of reference it holds."
  (let ((uid (gethash "uid" (workload-metadata owner))))
    (if (and (or (workload-resource-p resource) (batch-resource-p resource))
             (workload-owned-p (pod-to-object pod) owner))
        (change-controller-pod-owner store owner pod nil :resource resource
                                     :tracking-finalizer (when (batch-resource-p resource) +job-tracking-finalizer+))
        (remove-pod-owner-reference store pod uid))))

(defun process-workload-deletion (reconciler record)
  "Advance one durable deletion, retaining foreground owners until blocking dependents disappear."
  (let* ((store (reconciler-store reconciler)) (resource (gethash "resource" record))
         (namespace (gethash "namespace" record)) (name (gethash "name" record))
         (policy (gethash "policy" record)) (uid (gethash "uid" record))
         (*stored-resource-types* (append *stored-resource-types* (crd-resource-types store))))
    (when (equal resource "pods")
      (return-from process-workload-deletion (process-pod-foreground-deletion reconciler record)))
    ;; Reading a custom owner takes its definition, which the request that deleted it has gone with.
    (multiple-value-bind (*crd-view-definition* *crd-request-version*) (custom-resource-storage-view store resource)
      (let ((owner (handler-case (get-core-resource store resource namespace name)
                     ;; A 410 means the definition itself went away, taking the object with it.
                     (kubernetes-error (condition)
                       (unless (member (kubernetes-error-status-code condition) '(404 410)) (error condition))))))
        (unless (and owner (equal uid (gethash "uid" (workload-metadata owner))))
          (finish-workload-deletion store record)
          (return-from process-workload-deletion nil))
        (dolist (pod (list-pods store namespace))
          (when (dependent-owner-reference (workload-metadata (pod-to-object pod)) uid)
            (if (equal policy "Orphan")
                (release-orphaned-pod-dependent store owner pod resource)
                (advance-foreground-pod-dependent reconciler pod uid))))
        (dolist (entry (workload-stored-dependents store namespace uid))
          (if (equal policy "Orphan")
              (detach-workload-dependent store (car entry) owner (cdr entry) resource)
              (advance-foreground-stored-dependent store owner (car entry) (cdr entry))))
        (unless (workload-deletion-blocked-p store namespace uid policy)
          (finish-workload-deletion store record))))))

(defun hold-pod-for-foreground-deletion (store namespace name uid)
  "Keep a Pod with blocking dependents through a foregroundDeletion finalizer and a durable intent.
Return it when held. The caller then deletes it as usual: as with Kubernetes, its containers
stop at once and only the API object waits for the dependents."
  (let* ((pod (get-pod store namespace name)) (actual (pod-uid pod)))
    (when (and uid (not (equal uid actual)))
      (core-resource-error 409 "Conflict" "Pod deletion precondition does not match"))
    (when (and (not (deletion-requested-p pod))
               (workload-deletion-blocked-p store namespace actual "Foreground"))
      (with-store-lock (store)
        (let ((current (get-pod-unlocked store namespace name))
              (deletions (copy-core-object (pod-store-workload-deletions store))))
          (setf (gethash actual deletions)
                (core-object "resource" "pods" "namespace" namespace "name" name "uid" actual "policy" "Foreground"))
          (commit-core-resources store (copy-core-resource-index store) (1+ (pod-store-resource-revision store))
                                 :workload-deletions deletions)
          (let* ((object (copy-core-object (pod-to-object current))) (metadata (workload-metadata object)))
            (setf (gethash "finalizers" metadata) (deletion-policy-finalizers metadata "Foreground"))
            (update-pod-unlocked store (parse-pod object) (pod-resource-version current)))))
      pod)))

(defun release-foreground-pod (store namespace name uid)
  "Drop the foregroundDeletion finalizer of the exact Pod, which lets its deletion finish."
  (with-store-lock (store)
    (let ((current (gethash (pod-key namespace name) (pod-store-pods store))))
      (when (and current (equal uid (pod-uid current)))
        (let* ((object (copy-core-object (pod-to-object current))) (metadata (workload-metadata object)))
          (setf (gethash "finalizers" metadata)
                (remove "foregroundDeletion" (gethash "finalizers" metadata #()) :test #'equal))
          (update-pod-unlocked store (parse-pod object) (pod-resource-version current)))))))

(defun forget-workload-deletion (store uid)
  "Durably drop the deletion intent for an owner with UID, leaving its object alone."
  (with-store-lock (store)
    (let ((deletions (copy-core-object (pod-store-workload-deletions store))))
      (when (gethash uid deletions)
        (remhash uid deletions)
        (commit-core-resources store (copy-core-resource-index store) (1+ (pod-store-resource-revision store))
                               :workload-deletions deletions)))))

(defun process-pod-foreground-deletion (reconciler record)
  "Delete a held Pod's dependents, then the Pod. A dependent's own dependents go in the background,
which is what breaks a dependency cycle."
  (let* ((store (reconciler-store reconciler)) (namespace (gethash "namespace" record))
         (name (gethash "name" record)) (uid (gethash "uid" record))
         (owner (handler-case (get-pod store namespace name)
                  (kubernetes-error (condition) (unless (= 404 (kubernetes-error-status-code condition)) (error condition))))))
    (if (and owner (equal uid (pod-uid owner)))
        (progn
          (dolist (pod (list-pods store namespace))
            (when (dependent-owner-reference (workload-metadata (pod-to-object pod)) uid)
              (advance-foreground-pod-dependent reconciler pod uid)))
          (loop for (resource . object) in (workload-stored-dependents store namespace uid)
                for metadata = (workload-metadata object)
                do (if (dependent-has-solid-owner-p store namespace metadata uid)
                       (update-owned-workload store resource object
                         (lambda (current)
                           (setf (gethash "ownerReferences" (workload-metadata current))
                                 (remove uid (gethash "ownerReferences" (workload-metadata current) #()) :test #'equal
                                         :key (lambda (reference) (gethash "uid" reference))))
                           current))
                       (when (controller-delete-allowed-p store resource namespace (gethash "name" metadata) "generic-garbage-collector")
                         (delete-core-resource store resource namespace (gethash "name" metadata) :uid (gethash "uid" metadata)))))
          (unless (workload-deletion-blocked-p store namespace uid "Foreground")
            (release-foreground-pod store namespace name uid)
            (forget-workload-deletion store uid)))
        (forget-workload-deletion store uid))))

(defun process-workload-deletions (reconciler)
  "Resume pending intents after a process restart before reconciling new desired replicas."
  (let ((store (reconciler-store reconciler)))
    (dolist (record (with-store-lock (store)
                     (loop for record being the hash-values of (pod-store-workload-deletions store)
                           collect (copy-core-object record))))
      (handler-case (process-workload-deletion reconciler record)
        (kubernetes-error (condition)
          (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))))
