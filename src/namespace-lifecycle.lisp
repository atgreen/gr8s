;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Delete Namespaces the way upstream's controller does. A deleted Namespace turns
;;;; Terminating and refuses new content while its Pods drain first, then its other
;;;; objects, and it disappears only when every finalizer has been released.

(in-package #:gr8s)

(defparameter +namespace-controller-finalizer+ "kubernetes"
  "The spec finalizer the namespace controller itself holds until content is gone.")

(defparameter +undeletable-namespaces+ '("default" "kube-system" "kube-public")
  "Namespaces the cluster cannot run without.")

(defvar *namespace-finalize-write* nil
  "True only while the finalize subresource replaces a Namespace's spec.finalizers.")

(defun namespace-terminating-p (namespace)
  "Return whether stored NAMESPACE has been deleted but still holds finalizers."
  (not (null (gethash "deletionTimestamp" (gethash "metadata" namespace)))))

(defun namespace-object-finalizers (namespace)
  "Return the union of NAMESPACE's spec and metadata finalizers as a list."
  (flet ((names (object key)
           (let ((value (and (hash-table-p object) (gethash key object))))
             (if (member value '(nil null)) nil (coerce value 'list)))))
    (append (names (gethash "spec" namespace) "finalizers")
            (names (gethash "metadata" namespace) "finalizers"))))

(defun require-namespace-accepts-content (store namespace)
  "Refuse new objects in a Namespace being deleted, with the cause clients check for."
  (when namespace
    (let ((object (gethash (core-resource-key "namespaces" nil namespace) (pod-store-resources store))))
      (when (and object (namespace-terminating-p object))
        (error 'kubernetes-error :status-code 403 :reason "Forbidden"
               :message (format nil "unable to create new content in namespace ~A because it is being terminated" namespace))))))

(defun normalize-namespace-lifecycle (object existing)
  "Apply a Namespace write's strategy: its controller-owned fields survive ordinary updates."
  (let ((spec (gethash "spec" object)) (metadata (gethash "metadata" object)))
    (cond
      ((null existing)
       (unless (plusp (length (let ((value (gethash "finalizers" spec))) (if (member value '(nil null)) #() value))))
         (setf (gethash "finalizers" spec) (vector +namespace-controller-finalizer+)))
       (setf (gethash "status" object) (core-object "phase" "Active")))
      (t
       (let ((old-metadata (gethash "metadata" existing)) (old-spec (gethash "spec" existing (core-object))))
         (unless *namespace-finalize-write*
           (if (nth-value 1 (gethash "finalizers" old-spec))
               (setf (gethash "finalizers" spec) (gethash "finalizers" old-spec))
               (remhash "finalizers" spec)))
         (when *namespace-finalize-write*
           (loop for finalizer across (let ((value (gethash "finalizers" spec))) (if (member value '(nil null)) #() value))
                 unless (or (equal finalizer +namespace-controller-finalizer+) (core-qualified-key-p finalizer))
                   do (core-resource-error 422 "Invalid" "Invalid finalizer name ~S" finalizer)))
         (cond (*typed-api-status-write* nil)
               (t (setf (gethash "status" object) (copy-core-object (gethash "status" existing (core-object "phase" "Active"))))))
         (let ((deleted (gethash "deletionTimestamp" old-metadata)))
           (if deleted (setf (gethash "deletionTimestamp" metadata) deleted) (remhash "deletionTimestamp" metadata))))))
    object))

(defun delete-namespace-unlocked (store existing dry-run)
  "Begin deleting Namespace EXISTING, removing it at once only when nothing holds it. Caller holds the store lock."
  (let* ((metadata (gethash "metadata" existing)) (name (gethash "name" metadata))
         (key (core-resource-key "namespaces" nil name))
         (resources (copy-core-resource-index store))
         (revision (1+ (pod-store-resource-revision store))))
    (when (member name +undeletable-namespaces+ :test #'equal)
      (core-resource-error 403 "Forbidden" "this namespace may not be deleted"))
    (cond
      ((namespace-terminating-p existing) (copy-core-object existing))
      ((namespace-object-finalizers existing)
       (let* ((updated (copy-core-object existing)) (updated-metadata (gethash "metadata" updated)))
         (setf (gethash "deletionTimestamp" updated-metadata) (current-timestamp)
               (gethash "resourceVersion" updated-metadata) (write-to-string revision)
               (gethash "status" updated) (core-object "phase" "Terminating")
               (gethash key resources) updated)
         (unless dry-run (commit-core-resources store resources revision))
         (copy-core-object updated)))
      (t
       (remhash key resources)
       (unless dry-run (commit-core-resources store resources revision))
       (copy-core-object existing)))))

(defun namespace-deletion-condition (type status reason message)
  "Build one Namespace deletion condition."
  (core-object "type" type "status" status "reason" reason "message" message))

(defun namespace-deletion-conditions (pods objects finalizers failure)
  "Report what still blocks a Namespace, as upstream's controller does."
  (vector
   (namespace-deletion-condition "NamespaceDeletionDiscoveryFailure" "False" "ResourcesDiscovered" "All resources successfully discovered")
   (namespace-deletion-condition "NamespaceDeletionGroupVersionParsingFailure" "False" "ParsedGroupVersions" "All legacy kube types successfully parsed")
   (if failure
       (namespace-deletion-condition "NamespaceDeletionContentFailure" "True" "ContentDeletionFailed" failure)
       (namespace-deletion-condition "NamespaceDeletionContentFailure" "False" "ContentDeleted" "All content successfully deleted, may be waiting on finalization"))
   (if (or (plusp pods) (plusp objects))
       (namespace-deletion-condition "NamespaceContentRemaining" "True" "SomeResourcesRemain"
                                     (format nil "Some resources are remaining: ~D pods and ~D other objects" pods objects))
       (namespace-deletion-condition "NamespaceContentRemaining" "False" "ContentRemoved" "All content successfully removed"))
   (if finalizers
       (namespace-deletion-condition "NamespaceFinalizersRemaining" "True" "SomeFinalizersRemain"
                                     (format nil "Some content has finalizers remaining: ~{~A~^, ~}" finalizers))
       (namespace-deletion-condition "NamespaceFinalizersRemaining" "False" "ContentHasNoFinalizers" "All content-preserving finalizers finished"))))

(defun publish-namespace-conditions (store name conditions)
  "Record CONDITIONS on Namespace NAME, stamping transitions and skipping unchanged writes."
  (let* ((namespace (get-core-resource store "namespaces" nil name))
         (status (gethash "status" namespace (core-object)))
         (old (let ((value (gethash "conditions" status))) (if (member value '(nil null)) #() value)))
         (changed nil))
    (loop for condition across conditions
          for previous = (find (gethash "type" condition) old :key (lambda (entry) (gethash "type" entry)) :test #'equal)
          do (if (and previous (equal (gethash "status" previous) (gethash "status" condition))
                      (equal (gethash "reason" previous) (gethash "reason" condition))
                      (equal (gethash "message" previous) (gethash "message" condition)))
                 (setf (gethash "lastTransitionTime" condition) (gethash "lastTransitionTime" previous))
                 (setf changed t
                       (gethash "lastTransitionTime" condition) (current-timestamp))))
    (when changed
      (let ((*typed-api-status-write* t))
        (update-core-resource store "namespaces" nil name
                              (lambda (object)
                                (setf (gethash "conditions" (gethash "status" object)) conditions)
                                object))))))

(defun delete-namespace-pods (reconciler namespace)
  "Ask every remaining Pod of NAMESPACE to terminate, returning how many remain."
  (let ((pods (remove namespace (list-pods (reconciler-store reconciler)) :key #'pod-namespace :test-not #'equal)))
    (dolist (pod pods)
      (unless (deletion-requested-p pod)
        (handler-case (delete-controller-pod reconciler namespace (pod-name pod) "namespace-controller" :uid (pod-uid pod))
          (kubernetes-error (condition)
            (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition))))))
    (length pods)))

(defun delete-namespace-objects (store namespace)
  "Delete NAMESPACE's stored objects, returning how many remain, what failed and the finalizers holding them."
  (let ((remaining 0) (failure nil) (finalizers nil)
        (*stored-resource-types* (append *stored-resource-types* (crd-resource-types store))))
    (dolist (type *stored-resource-types*)
      (when (fourth type)
        (dolist (object (list-core-resources store (first type) namespace))
          (let* ((metadata (gethash "metadata" object)) (name (gethash "name" metadata))
                 (held (let ((value (gethash "finalizers" metadata))) (if (member value '(nil null)) nil (coerce value 'list)))))
            (handler-case
                (if (controller-delete-allowed-p store (first type) namespace name "namespace-controller")
                    (progn
                      (delete-core-resource store (first type) namespace name :uid (gethash "uid" metadata))
                      (when held
                        (incf remaining)
                        (setf finalizers (union held finalizers :test #'equal))))
                    ;; A webhook refused, so the namespace waits and the next pass asks again.
                    (incf remaining))
              (kubernetes-error (condition)
                (unless (member (kubernetes-error-status-code condition) '(404 409))
                  (incf remaining)
                  (setf failure (princ-to-string condition)))))))))
    (values remaining failure finalizers)))

(defun remove-namespace-controller-finalizer (store name)
  "Release the controller's hold, removing the Namespace when no other finalizer holds it."
  (let ((namespace (get-core-resource store "namespaces" nil name)))
    (when (member +namespace-controller-finalizer+ (coerce (gethash "finalizers" (gethash "spec" namespace) #()) 'list) :test #'equal)
      (let ((*namespace-finalize-write* t) (*typed-api-status-write* t))
        (update-core-resource store "namespaces" nil name
                              (lambda (object)
                                (setf (gethash "finalizers" (gethash "spec" object))
                                      (remove +namespace-controller-finalizer+ (gethash "finalizers" (gethash "spec" object)) :test #'equal))
                                object))))))

(defun remove-released-namespace (store name)
  "Remove Terminating Namespace NAME once nothing holds it."
  (with-store-lock (store)
    (let ((namespace (gethash (core-resource-key "namespaces" nil name) (pod-store-resources store))))
      (when (and namespace (namespace-terminating-p namespace) (null (namespace-object-finalizers namespace)))
        (let ((resources (copy-core-resource-index store)))
          (remhash (core-resource-key "namespaces" nil name) resources)
          (commit-core-resources store resources (1+ (pod-store-resource-revision store))))))))

(defun reconcile-namespace-deletion (reconciler namespace)
  "Advance one Terminating Namespace: Pods go first, then other objects, then its finalizer."
  (let* ((store (reconciler-store reconciler))
         (name (gethash "name" (gethash "metadata" namespace)))
         (pods (delete-namespace-pods reconciler name)))
    (if (plusp pods)
        (publish-namespace-conditions store name (namespace-deletion-conditions pods 0 nil nil))
        (multiple-value-bind (remaining failure finalizers) (delete-namespace-objects store name)
          (publish-namespace-conditions store name (namespace-deletion-conditions 0 remaining finalizers failure))
          (when (and (zerop remaining) (null failure))
            (remove-namespace-controller-finalizer store name)
            (remove-released-namespace store name))))))

(defun reconcile-namespace-deletions (reconciler)
  "Advance every Terminating Namespace, isolating one's failure from the others."
  (dolist (namespace (list-core-resources (reconciler-store reconciler) "namespaces"))
    (when (namespace-terminating-p namespace)
      (handler-case (reconcile-namespace-deletion reconciler namespace)
        (kubernetes-error (condition)
          (format *error-output* "gr8s namespace ~A deletion: ~A~%"
                  (gethash "name" (gethash "metadata" namespace)) condition))))))

(defun reconcile-namespace-defaults (store)
  "Restore each live Namespace's default ServiceAccount and root CA, as upstream's controllers do."
  (when (pod-store-in-cluster-config store)
    (dolist (namespace (list-core-resources store "namespaces"))
      (unless (namespace-terminating-p namespace)
        (let ((name (gethash "name" (gethash "metadata" namespace))))
          (unless (gethash (core-resource-key "serviceaccounts" name "default") (pod-store-resources store))
            (ensure-default-service-account store name))
          (ensure-namespace-root-ca store name))))))

;;; Subresources

(defun namespace-finalize-route (path)
  "Return the Namespace named by a /api/v1/namespaces/NAME/finalize URL."
  (let ((parts (uiop:split-string path :separator '(#\/))))
    (when (and (= 6 (length parts)) (equal (subseq parts 0 4) '("" "api" "v1" "namespaces"))
               (equal "finalize" (sixth parts)) (dns-label-p (fifth parts)))
      (fifth parts))))

(defun dispatch-namespace-finalize-request (store path method)
  "Replace only a Namespace's spec.finalizers."
  (unless (eq method :put)
    (core-resource-error 405 "MethodNotAllowed" "The finalize subresource only supports update"))
  (let* ((name (namespace-finalize-route path))
         (*namespace-finalize-write* t)
         (input (core-resource-request-object "Namespace"))
         (metadata (require-object (gethash "metadata" input) "metadata")))
    (unless (equal name (gethash "name" metadata))
      (core-resource-error 400 "BadRequest" "Namespace metadata does not match its URL"))
    (json-response
     (update-core-resource
      store "namespaces" nil name
      (lambda (old)
        (setf (gethash "spec" old) (copy-core-object (gethash "spec" input (core-object))))
        (unless (member (gethash "resourceVersion" metadata) '(nil "") :test #'equal)
          (setf (gethash "resourceVersion" (gethash "metadata" old)) (gethash "resourceVersion" metadata)))
        old)))))
