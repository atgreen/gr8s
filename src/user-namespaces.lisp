;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; spec.hostUsers: false (UserNamespacesSupport, GA in v1.36) runs a Pod in a user
;;;; namespace of its own. As the kubelet's userns manager does, each such Pod on a
;;;; node gets a distinct block of 65536 host IDs, mapped to IDs 0-65535 inside, and
;;;; keeps it for its lifetime; the runtime maps the volumes it mounts with idmapped
;;;; mounts, so files stay owned by the IDs they have inside the Pod.

(in-package #:gr8s)

(defparameter +user-namespace-length+ 65536
  "The IDs each Pod's user namespace maps, as the kubelet's default userNamespaces.idsPerPod.")

(defparameter +user-namespace-blocks+ 65535
  "How many blocks of host IDs Pods may use, starting from the second: ID 0 is never mapped.")

(defvar *user-namespace-lock* (bt:make-lock "Pod user namespace allocation")
  "Serializes choosing a block, so two Pods starting together can't take the same one.")

(defun pod-host-users-p (pod)
  "Return whether POD shares the node's user namespace, as it does unless hostUsers is false."
  (multiple-value-bind (value present) (gethash "hostUsers" (gethash "spec" (pod-to-object pod)))
    (not (and present (null value)))))

(defun validate-pod-host-users (spec)
  "Validate spec.hostUsers as the API server does: a Pod with its own user namespace can't share the
node's network, PID or IPC namespaces."
  (multiple-value-bind (value present) (gethash "hostUsers" spec)
    (when present
      (when (eq value 'null) (remhash "hostUsers" spec) (return-from validate-pod-host-users nil))
      (unless (member value '(t nil)) (invalid-pod "spec.hostUsers must be boolean"))
      (unless value
        (dolist (field '("hostNetwork" "hostPID" "hostIPC"))
          (when (eq t (gethash field spec))
            (invalid-pod "spec.~A: Forbidden: when `hostUsers` is false" field)))))))

(defun containerd-user-namespace-path (runtime uid)
  "Return where UID's host ID block is recorded, beside its logs, which outlive container restarts.
It has a file type, since an atomic rename merges a missing one from the temporary file."
  (merge-pathnames "user-namespace.id" (containerd-pod-log-directory runtime uid)))

(defun containerd-user-namespace-host-id (runtime uid)
  "Return the first host ID of UID's user namespace, choosing the lowest free block the first time.
A block is taken while any Pod directory under the log root records it."
  (bt:with-lock-held (*user-namespace-lock*)
    (let ((path (containerd-user-namespace-path runtime uid)))
      (or (ignore-errors (parse-integer (uiop:read-file-string path)))
          (let* ((used (loop for file in (directory (merge-pathnames "*/user-namespace.id" (containerd-runtime-log-root runtime)))
                             for value = (ignore-errors (parse-integer (uiop:read-file-string file)))
                             when value collect value))
                 (block (loop for index from 1 to +user-namespace-blocks+
                              for first = (* index +user-namespace-length+)
                              unless (member first used) return first)))
            (unless block (error 'runtime-error :message "No user namespace block is free on this node"))
            (ensure-directories-exist path)
            (write-private-text-atomically path (write-to-string block))
            block)))))

(defun containerd-pod-user-namespace (runtime pod)
  "Return the CRI UserNamespace for POD: its own mapping when hostUsers is false, else the node's."
  (if (pod-host-users-p pod)
      nil
      (let ((first (containerd-user-namespace-host-id runtime (pod-uid pod))))
        (flet ((mapping () (make-instance 'gr8s.cri.v1::id-mapping :host-id first :container-id 0
                                                                   :length +user-namespace-length+)))
          (make-instance 'gr8s.cri.v1::user-namespace :mode gr8s.cri.v1::+namespacemode-pod+
                                                      :uids (list (mapping)) :gids (list (mapping)))))))

(defun release-containerd-user-namespace (runtime uid)
  "Free UID's host ID block for another Pod; its containers and sandbox are gone."
  (bt:with-lock-held (*user-namespace-lock*)
    (let ((path (containerd-user-namespace-path runtime uid)))
      (when (probe-file path) (delete-file path)))))
