;;;; SPDX-FileCopyrightText: 2026 gr8s contributors
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Transfer only referenced core objects in authenticated Pod assignments and
;;;; materialize ConfigMap, Secret and emptyDir mounts in agent-owned directories.
;;;; Resource data stays scoped to the Pod namespace; relative paths are validated
;;;; before touching the filesystem and fsGroup controls mounted data access.

(in-package #:gr8s)

(defun pod-volume-resource-reference (volume)
  "Return the referenced collection, object name and optional flag for VOLUME."
  (cond ((gethash "configMap" volume)
         (let ((source (gethash "configMap" volume)))
           (values "configmaps" (gethash "name" source) (eq t (gethash "optional" source)))))
        ((gethash "secret" volume)
         (let ((source (gethash "secret" volume)))
           (values "secrets" (gethash "secretName" source) (eq t (gethash "optional" source)))))))

(defun pod-referenced-resource-objects (store pod)
  "Copy only POD's referenced volume resources from its own namespace."
  (let ((result nil))
    (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
          do (multiple-value-bind (resource name optional) (pod-volume-resource-reference volume)
               (when resource
                 (handler-case
                     (push (get-core-resource store resource (pod-namespace pod) name) result)
                   (kubernetes-error (condition)
                     (unless (and optional (= 404 (kubernetes-error-status-code condition)))
                       (error condition)))))))
    (remove-duplicates result :test #'equalp)))

(defun install-assigned-resource-objects (store assignments)
  "Replace the agent's resource projection with objects referenced by its assignments."
  (let ((resources (make-hash-table :test #'equal)))
    (dolist (assignment assignments)
      (let ((pod (assignment-pod assignment)))
        (dolist (bytes (slot-value assignment 'gr8s.node.v1::resource-objects-json))
          (let* ((object (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string bytes)
                                             :max-string-length (* 2 1024 1024)))
                 (metadata (require-object (gethash "metadata" object) "metadata"))
                 (namespace (gethash "namespace" metadata))
                 (name (gethash "name" metadata))
                 (resource (cond ((equal "ConfigMap" (gethash "kind" object)) "configmaps")
                                 ((equal "Secret" (gethash "kind" object)) "secrets")
                                 (t (invalid-pod "assignment resources must be ConfigMaps or Secrets")))))
            (unless (and (equal namespace (pod-namespace pod))
                         (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
                               thereis (multiple-value-bind (referenced-resource referenced-name)
                                           (pod-volume-resource-reference volume)
                                         (and (equal resource referenced-resource) (equal name referenced-name)))))
              (invalid-pod "assignment contains an unreferenced or cross-namespace resource"))
            (setf (gethash (core-resource-key resource namespace name) resources)
                  (normalize-core-resource resource object namespace name))))))
    (with-store-lock (store)
      (unless (equalp resources (pod-store-resources store))
        (commit-core-resources store resources (1+ (pod-store-resource-revision store)))))))

(defun pod-volume-directory (runtime pod name)
  "Return the agent-owned directory for POD's named volume."
  (merge-pathnames (format nil "volumes/~A/" name) (containerd-pod-log-directory runtime (pod-uid pod))))

(defun pod-fs-group (pod)
  "Return POD's requested filesystem group, if any."
  (let ((context (gethash "securityContext" (gethash "spec" (pod-to-object pod)))))
    (and context (gethash "fsGroup" context))))

(defun set-pod-volume-permissions (path mode group)
  "Set MODE and optional filesystem GROUP on an agent-owned volume path."
  (when group (sb-posix:chown (namestring path) #xffffffff group))
  (sb-posix:chmod (namestring path) mode))

(defun pod-volume-data (resource object)
  "Decode a ConfigMap or Secret's supported file data into a fresh byte map."
  (let ((data (make-hash-table :test #'equal)))
    (when object
      (dolist (field (if (equal resource "secrets") '("data") '("data" "binaryData")))
        (let ((values (gethash field object)))
          (when values
            (maphash (lambda (key value)
                       (setf (gethash key data)
                             (if (and (equal resource "configmaps") (equal field "data"))
                                 (trivial-utf-8:string-to-utf-8-bytes value)
                                 (core-base64-bytes value field)))) values)))))
    data))

(defun write-projected-volume-file (target bytes mode group)
  "Atomically publish BYTES with final permissions, starting with a private file."
  (let ((temporary (private-temporary-path target)))
    (ensure-directories-exist target)
    (unwind-protect
         (progn
           (let* ((descriptor (sb-posix:open (namestring temporary)
                                              (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl)
                                              #o600))
                  (stream (sb-sys:make-fd-stream descriptor :output t
                                               :element-type '(unsigned-byte 8) :auto-close t)))
             (unwind-protect (write-sequence bytes stream) (close stream)))
           (set-pod-volume-permissions temporary mode group)
           (sb-posix:rename (namestring temporary) (namestring target)))
      (when (probe-file temporary) (delete-file temporary)))))

(defun materialize-pod-volume (runtime pod volume)
  "Create a volume's directories and projected files with enforced fsGroup access."
  (let* ((directory (pod-volume-directory runtime pod (gethash "name" volume)))
         (group (pod-fs-group pod)))
    (ensure-directories-exist directory)
    ;; The final directory is bind-mounted into the container. Its parent stays
    ;; private on the host even when Kubernetes requests world-readable files.
    (sb-posix:chmod (namestring (containerd-pod-log-directory runtime (pod-uid pod))) #o700)
    (set-pod-volume-permissions directory (if group #o2770 #o777) group)
    (multiple-value-bind (resource name optional) (pod-volume-resource-reference volume)
      (when resource
        (let* ((source (or (gethash "configMap" volume) (gethash "secret" volume)))
               (object (handler-case (get-core-resource (containerd-runtime-resource-store runtime)
                                                        resource (pod-namespace pod) name)
                         (kubernetes-error (condition)
                           (unless (and optional (= 404 (kubernetes-error-status-code condition))) (error condition)))))
               (data (pod-volume-data resource object))
               (items (gethash "items" source))
               (files (if items (coerce items 'list)
                          (loop for key being the hash-keys of data
                                collect (core-object "key" key "path" key)))))
          (dolist (item files)
            (let* ((key (gethash "key" item)) (relative (gethash "path" item))
                   (mode (gethash "mode" item (gethash "defaultMode" source #o644)))
                   (bytes (gethash key data)))
              (unless (safe-volume-relative-path-p relative) (invalid-pod "unsafe volume projection path"))
              (unless (or bytes optional)
                (error 'runtime-error :message (format nil "Volume ~A lacks key ~A" name key)))
              (when bytes
                (let ((target (merge-pathnames relative directory)))
                  (write-projected-volume-file target bytes (if group (logior mode #o440) mode) group))))))))
    directory))

(defun containerd-pod-mounts (runtime pod container)
  "Build CRI bind mounts from validated, materialized Pod volume declarations."
  (let ((volumes (gethash "volumes" (gethash "spec" (pod-to-object pod)) #()))
        (object (pod-runtime-container-object pod container)))
    (loop for mount across (gethash "volumeMounts" object #())
          for volume = (find (gethash "name" mount) volumes :test #'equal
                             :key (lambda (volume) (gethash "name" volume)))
          collect (make-instance 'gr8s.cri.v1::mount
                                 :container-path (gethash "mountPath" mount)
                                 :host-path (namestring (materialize-pod-volume runtime pod volume))
                                 :readonly (or (not (null (gethash "configMap" volume)))
                                               (not (null (gethash "secret" volume)))
                                               (eq t (gethash "readOnly" mount)))))))

(defun containerd-pod-environment (runtime pod container sandbox-id)
  "Resolve environment values in declaration order after sandbox allocation."
  (let* ((object (pod-runtime-container-object pod container)) (pod-ip nil))
    (loop for variable across (gethash "env" object #())
          for from = (gethash "valueFrom" variable)
          collect
          (cons (gethash "name" variable)
                (if (null from)
                    (gethash "value" variable "")
                    (let ((field (gethash "fieldPath" (gethash "fieldRef" from))))
                      (cond ((equal field "metadata.name") (pod-name pod))
                            ((equal field "metadata.namespace") (pod-namespace pod))
                            ((equal field "metadata.uid") (pod-uid pod))
                            ((equal field "spec.nodeName") (or (pod-node-name pod) ""))
                            ((equal field "status.podIP")
                             (or pod-ip (setf pod-ip (cri-pod-sandbox-ip
                                                     (containerd-runtime-socket-path runtime) sandbox-id)))))))))))

(defun containerd-pod-security-context (pod container)
  "Map effective Pod/container Linux identities and privileges to the CRI API."
  (let* ((pod-context (gethash "securityContext" (gethash "spec" (pod-to-object pod))))
         (container-context (gethash "securityContext" (pod-runtime-container-object pod container)))
         (effective (core-object)))
    (dolist (context (list pod-context container-context))
      (when context (maphash (lambda (key value) (setf (gethash key effective) value)) context)))
    (let ((user (gethash "runAsUser" effective)) (group (gethash "runAsGroup" effective)))
      (when (and (eq t (gethash "runAsNonRoot" effective))
                 (not (and user (plusp user))))
        (error 'runtime-error :message "runAsNonRoot requires a verified nonzero runAsUser"))
      (make-instance
       'gr8s.cri.v1::linux-container-security-context
       :run-as-user (when user (make-instance 'gr8s.cri.v1::int64value :value user))
       :run-as-group (when group (make-instance 'gr8s.cri.v1::int64value :value group))
       :supplemental-groups (when (pod-fs-group pod) (list (pod-fs-group pod)))
       :privileged (eq t (gethash "privileged" effective))
       :readonly-rootfs (eq t (gethash "readOnlyRootFilesystem" effective))
       :no-new-privs (and (nth-value 1 (gethash "allowPrivilegeEscalation" effective))
                          (null (gethash "allowPrivilegeEscalation" effective)))))))
