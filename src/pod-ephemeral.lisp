;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Implement ephemeral containers: the pods/ephemeralcontainers subresource,
;;;; through which a list may only grow, the rules that keep their declarations
;;;; apart from the Pod's workload, and their separate status. They share the
;;;; sandbox, run once and never decide a Pod's phase, readiness or restarts.

(in-package #:gr8s)

(defparameter *pod-ephemeral-update* nil
  "True while the ephemeralcontainers subresource writes, the only way to change that list.")

(defun preserve-pod-ephemeral-containers (existing replacement)
  "Keep the stored ephemeral containers through any write but the dedicated subresource."
  (unless *pod-ephemeral-update*
    (let ((old (gethash "ephemeralContainers" (gethash "spec" (pod-to-object existing))))
          (new (gethash "spec" (pod-to-object replacement))))
      (if old
          (setf (gethash "ephemeralContainers" new) (copy-core-object old))
          (remhash "ephemeralContainers" new))
      (setf (pod-ephemeral-containers replacement) (pod-ephemeral-containers existing)))))

(defun canonical-container-declaration (value)
  "Return VALUE without unset fields, which typed clients and stored JSON represent differently."
  (cond
    ((hash-table-p value)
     (let ((result (core-object)))
       (maphash (lambda (key item)
                  (let ((canonical (canonical-container-declaration item)))
                    (unless (or (member canonical '(nil null "") :test #'equal)
                                (and (hash-table-p canonical) (zerop (hash-table-count canonical)))
                                (and (vectorp canonical) (zerop (length canonical))))
                      (setf (gethash key result) canonical))))
                value)
       result))
    ((and (vectorp value) (not (stringp value))) (map 'vector #'canonical-container-declaration value))
    (t value)))

(defun validate-pod-ephemeral-update (existing replacement)
  "Require the new list to keep every existing declaration exactly and only add to it."
  (let ((old (gethash "ephemeralContainers" (gethash "spec" (pod-to-object existing)) #()))
        (new (gethash "ephemeralContainers" (gethash "spec" (pod-to-object replacement)) #())))
    (loop for before across old
          for after = (find (gethash "name" before) new :test #'equal
                            :key (lambda (container) (gethash "name" container)))
          do (unless after
               (invalid-pod "existing ephemeral containers ~S may not be removed" (gethash "name" before)))
             (unless (core-json-equal-p (canonical-container-declaration before)
                                        (canonical-container-declaration after))
               (invalid-pod "existing ephemeral containers ~S may not be changed" (gethash "name" before))))))

(defun pod-ephemeral-write-input (current method)
  "Return the Pod a client wrote through the subresource, for PUT or any PATCH form."
  (if (eq method :put)
      (core-resource-request-object "Pod")
      (let ((content-type (first (uiop:split-string (or (hunchentoot:header-in* :content-type) "") :separator '(#\;)))))
        (pod-patched-object current content-type))))

(defvar *pod-patch-subresource* nil "The Pod subresource a patch of the current request targets.")

(defun pod-patched-object (current content-type)
  "Apply the current request's patch of CONTENT-TYPE to a copy of Pod object CURRENT."
  (when (equal content-type "application/apply-patch+yaml")
    (return-from pod-patched-object (apply-pod-patched-object current *pod-patch-subresource*)))
  (let ((patch (com.inuoe.jzon:parse (hunchentoot:raw-post-data :force-text t) :max-string-length (* 2 1024 1024))))
    (cond ((equal content-type "application/json-patch+json")
           (apply-core-json-patch (copy-json-object current) patch))
          ((equal content-type "application/merge-patch+json")
           (merge-json-object (copy-json-object current) (require-object patch "patch")))
          ((equal content-type "application/strategic-merge-patch+json")
           (template-strategic-merge (copy-json-object current) (require-object patch "patch")
                                     (template-schema "io.k8s.api.core.v1.PodTemplateSpec")))
          (t (core-resource-error 415 "UnsupportedMediaType"
                                  "Supported patch types are JSON merge, strategic merge, and JSON patch")))))

(defun write-pod-ephemeral-containers-response (store reconciler name namespace method)
  "Add to a Pod's ephemeral containers, leaving every other part of it untouched."
  (let* ((pod (get-pod store namespace name))
         (input (admit-subresource-write
                 store "pods" "ephemeralcontainers" namespace name
                 (require-object (pod-ephemeral-write-input (pod-to-object pod) method) "Pod")
                 (pod-to-object pod) :dry-run (core-resource-dry-run-p)))
         (metadata (require-object (gethash "metadata" input) "metadata"))
         (expected (gethash "resourceVersion" metadata)))
    (when (and (gethash "name" metadata) (not (equal name (gethash "name" metadata))))
      (core-resource-error 400 "BadRequest" "metadata.name does not match request name"))
    (when (and (gethash "uid" metadata) (not (equal (gethash "uid" metadata) (pod-uid pod))))
      (core-resource-error 409 "Conflict" "UID precondition does not match"))
    (when (and (stringp expected) (plusp (length expected))
               (not (pod-revision-satisfied-p store expected (pod-resource-version pod))))
      (core-resource-error 409 "Conflict" "Pod resourceVersion has changed"))
    (let* ((object (copy-json-object (pod-to-object pod)))
           (requested (gethash "ephemeralContainers" (require-object (gethash "spec" input) "spec") #())))
      (setf (gethash "ephemeralContainers" (gethash "spec" object)) requested)
      (let ((replacement (parse-pod object)))
        (validate-pod-ephemeral-update pod replacement)
        (if (core-resource-dry-run-p)
            (json-response (pod-response-object replacement (reconcile-pod reconciler namespace name)))
            (let ((updated (let ((*pod-ephemeral-update* t))
                             (update-pod store replacement (pod-resource-version pod)))))
              (json-response (pod-response-object updated (reconcile-written-pod reconciler updated)))))))))

(defun remember-pod-ephemeral-declarations (state pod)
  "Checkpoint which names are ephemeral, since an observation of them knows only a UID."
  (let ((names (map 'vector #'container-spec-name (pod-ephemeral-containers pod))))
    (if (plusp (length names))
        (setf (gethash "ephemeralNames" state) names)
        (remhash "ephemeralNames" state)))
  state)

(defun separate-ephemeral-statuses (statuses state)
  "Split STATUSES into the workload's and the ephemeral containers', as two vectors."
  (let ((names (gethash "ephemeralNames" state #())))
    (flet ((ephemeral-p (status) (find (gethash "name" status) names :test #'equal)))
      (values (remove-if #'ephemeral-p statuses) (remove-if-not #'ephemeral-p statuses)))))

(defun pod-ephemeral-progress-required-p (pod status)
  "Return whether a declared ephemeral container has yet to be started."
  (let ((reported (gethash "ephemeralContainerStatuses" status #())))
    (loop for spec across (pod-ephemeral-containers pod)
          thereis (not (find (container-spec-name spec) reported :test #'equal
                             :key (lambda (item) (gethash "name" item)))))))
