;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Collect supported background owner-reference dependents and resources in
;;;; deleted namespaces. Only the authoritative control plane runs this pass;
;;;; node resource projections must never infer owner existence from local state.

(in-package #:gr8s)

(defun referenced-owner-state (store namespace owner)
  "Return :LIVE, :ABSENT or :UNKNOWN for an exact, namespace-correct owner UID."
  (let ((custom (crd-referenced-owner-state store namespace owner)))
    (when custom (return-from referenced-owner-state custom)))
  (let* ((kind (gethash "kind" owner)) (version (gethash "apiVersion" owner))
         (type (find-if (lambda (type) (and (equal kind (second type)) (equal version (third type))))
                        *stored-resource-types*))
         (object
           (handler-case
               (cond ((and (equal version "v1") (equal kind "Pod"))
                      (pod-to-object (get-pod store namespace (gethash "name" owner))))
                     (type (get-core-resource store (first type) (when (fourth type) namespace)
                                              (gethash "name" owner)))
                     (t (return-from referenced-owner-state :unknown)))
             (kubernetes-error (condition)
               (if (= 404 (kubernetes-error-status-code condition)) nil (error condition))))))
    (if (and object (equal (gethash "uid" owner) (gethash "uid" (gethash "metadata" object))))
        :live :absent)))

(defun api-object-orphaned-p (store object)
  "Recognize deleted namespaces and dependents whose every known owner is absent."
  (let* ((metadata (gethash "metadata" object)) (namespace (gethash "namespace" metadata))
         (owners (gethash "ownerReferences" metadata)))
    (or (and namespace (pod-store-in-cluster-config store)
             (handler-case (progn (get-core-resource store "namespaces" nil namespace) nil)
               (kubernetes-error (condition)
                 (if (= 404 (kubernetes-error-status-code condition)) t (error condition)))))
        (and owners (not (eq owners 'null)) (plusp (length owners))
             (every (lambda (owner) (eq :absent (referenced-owner-state store namespace owner))) owners)))))

(defun dangling-owner-uids (store metadata)
  "Return the UIDs of absent owners in METADATA when a solid owner keeps the dependent alive."
  (let* ((namespace (gethash "namespace" metadata))
         (owners (let ((value (gethash "ownerReferences" metadata #()))) (if (eq value 'null) #() value)))
         (absent (and (> (length owners) 1)
                      (remove-if-not (lambda (owner) (eq :absent (referenced-owner-state store namespace owner)))
                                     (coerce owners 'list)))))
    ;; A dependent every owner of which is absent is collected whole, not patched.
    (when (and absent (dependent-has-solid-owner-p store namespace metadata (gethash "uid" (first absent)))
               (< (length absent) (length owners)))
      (mapcar (lambda (owner) (gethash "uid" owner)) absent))))

(defun drop-dangling-owner-references (store resource object)
  "Remove references to absent owners from OBJECT, as the upstream collector patches them out."
  (let ((uids (dangling-owner-uids store (gethash "metadata" object))))
    (when uids
      (handler-case
          (update-owned-workload store resource object
            (lambda (current)
              (setf (gethash "ownerReferences" (gethash "metadata" current))
                    (remove-if (lambda (reference) (member (gethash "uid" reference) uids :test #'equal))
                               (gethash "ownerReferences" (gethash "metadata" current) #())))
              current))
        (kubernetes-error (condition)
          (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))))

(defun collect-orphaned-api-objects (reconciler)
  "Converge background deletion for supported dependents in the control-plane store."
  (let ((store (reconciler-store reconciler)))
    (dolist (pod (list-pods store))
      (dolist (uid (dangling-owner-uids store (gethash "metadata" (pod-to-object pod))))
        (remove-pod-owner-reference store pod uid))
      (when (api-object-orphaned-p store (pod-to-object pod))
        (handler-case (delete-controller-pod reconciler (pod-namespace pod) (pod-name pod) "generic-garbage-collector" :uid (pod-uid pod))
          (kubernetes-error (condition)
            (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition))))))
    (dolist (type *stored-resource-types*)
      (let ((resource (first type)))
        (dolist (object (list-core-resources store resource))
          (drop-dangling-owner-references store resource object)
          (when (api-object-orphaned-p store object)
            (let* ((metadata (gethash "metadata" object)) (name (gethash "name" metadata))
                   (namespace (gethash "namespace" metadata)))
              (handler-case (when (controller-delete-allowed-p store resource namespace name "generic-garbage-collector")
                              (delete-core-resource store resource namespace name :uid (gethash "uid" metadata)))
                (kubernetes-error (condition)
                  (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))))))))
