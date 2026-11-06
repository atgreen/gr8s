;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve pods/binding, with which a scheduler assigns a Pod to a Node, and the
;;;; deprecated read-only componentstatuses, which kubectl get cs reads.

(in-package #:gr8s)

(defun pod-binding-response (store name namespace)
  "Bind a Pod to the Node its Binding names, as a scheduler does."
  (let* ((binding (core-resource-request-object "Binding"))
         (metadata (gethash "metadata" binding))
         (target (gethash "target" binding)))
    (unless (and (hash-table-p target) (stringp (gethash "name" target)) (plusp (length (gethash "name" target))))
      (core-resource-error 422 "Invalid" "Binding.target.name is required"))
    (unless (member (gethash "kind" target "Node") '("" "Node") :test #'equal)
      (core-resource-error 422 "Invalid" "Binding.target.kind must be Node"))
    (when (and (hash-table-p metadata) (gethash "name" metadata)
               (not (equal name (gethash "name" metadata))))
      (core-resource-error 400 "BadRequest" "Binding name does not match its URL"))
    (let ((uid (and (hash-table-p metadata) (gethash "uid" metadata))))
      (with-store-lock (store)
        (let ((pod (get-pod-unlocked store namespace name)))
          (when (and uid (not (equal uid (pod-uid pod))))
            (core-resource-error 409 "Conflict" "Binding UID does not match Pod ~A" name))
          (when (deletion-requested-p pod)
            (core-resource-error 409 "Conflict" "Pod ~A is being deleted" name))
          (when (pod-node-name pod)
            (core-resource-error 409 "Conflict" "pod ~A is already assigned to node ~S" name (pod-node-name pod)))
          (when (pod-scheduling-gated-p pod)
            (core-resource-error 409 "Conflict" "pod ~A/~A has non-empty .spec.schedulingGates" namespace name))
          (unless (get-node-unlocked store (gethash "name" target))
            (core-resource-error 404 "NotFound" "Node ~S was not found" (gethash "name" target)))
          (persist-pod-assignment store pod (gethash "name" target)))))
    (json-response (core-object "kind" "Status" "apiVersion" "v1" "metadata" (core-object)
                                "status" "Success" "code" 201)
                   201)))

(defun component-status (name)
  "Describe a control-plane component. They all run in this process, so answering shows it is healthy."
  (core-object "kind" "ComponentStatus" "apiVersion" "v1"
               "metadata" (core-object "name" name)
               "conditions" (vector (core-object "type" "Healthy" "status" "True" "message" "ok"))))

(defparameter +component-status-names+ '("controller-manager" "etcd-0" "scheduler")
  "The components upstream reports, which clients look for by name.")

(defun component-status-route (path)
  "Recognize the componentstatuses collection and items, returning the name if any and T."
  (let ((prefix "/api/v1/componentstatuses"))
    (cond ((equal path prefix) (values nil t))
          ((uiop:string-prefix-p (concatenate 'string prefix "/") path)
           (values (subseq path (1+ (length prefix))) t)))))

(defun component-status-response (name method)
  "Serve componentstatuses, which can only be read."
  (unless (member method '(:get :head))
    (core-resource-error 405 "MethodNotAllowed" "componentstatuses are read-only"))
  (cond
    ((null name)
     (json-response (core-object "kind" "ComponentStatusList" "apiVersion" "v1" "metadata" (core-object)
                                 "items" (map 'vector #'component-status +component-status-names+))))
    ((member name +component-status-names+ :test #'equal) (json-response (component-status name)))
    (t (core-resource-error 404 "NotFound" "componentstatuses ~S not found" name))))
