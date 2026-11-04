;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Install authenticated Pod references and public Service discovery together;
;;;; materialize ConfigMap, Secret and emptyDir mounts in agent-owned directories.
;;;; Private resource data stays scoped to the Pod namespace; paths are validated
;;;; before touching the filesystem and fsGroup controls mounted data access.
;;;; Memory emptyDirs are real tmpfs mounts that live until the Pod terminates.

(in-package #:gr8s)

(defun pod-volume-resource-reference (volume)
  "Return the referenced collection, object name and optional flag for VOLUME."
  (cond ((gethash "configMap" volume)
         (let ((source (gethash "configMap" volume)))
           (values "configmaps" (gethash "name" source) (eq t (gethash "optional" source)))))
        ((gethash "secret" volume)
         (let ((source (gethash "secret" volume)))
           (values "secrets" (gethash "secretName" source) (eq t (gethash "optional" source)))))))

(defun pod-resource-reference-declarations (pod)
  "Collect namespace-local resource declarations from volumes and environment sources."
  (let* ((spec (gethash "spec" (pod-to-object pod))) (references nil))
    (loop for volume across (gethash "volumes" spec #())
          do (multiple-value-bind (resource name optional) (pod-volume-resource-reference volume)
               (when resource (push (list resource name optional) references))))
    (loop for container across (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec))
          do (loop for variable across (gethash "env" container #())
                   for from = (gethash "valueFrom" variable)
                   when from
                     do (dolist (source '(("secretKeyRef" "secrets") ("configMapKeyRef" "configmaps")))
                          (let ((ref (gethash (first source) from)))
                            (when ref (push (list (second source) (gethash "name" ref)
                                                 (eq t (gethash "optional" ref))) references)))))
             (loop for source across (gethash "envFrom" container #())
                   do (dolist (kind '(("secretRef" "secrets") ("configMapRef" "configmaps")))
                        (let ((ref (gethash (first kind) source)))
                          (when ref (push (list (second kind) (gethash "name" ref)
                                               (eq t (gethash "optional" ref))) references))))))
    references))

(defun pod-referenced-resource-objects (store pod)
  "Copy only POD's referenced volume and environment resources from its namespace."
  (let ((result nil))
    (dolist (reference (pod-resource-reference-declarations pod))
      (destructuring-bind (resource name optional) reference
        (handler-case (push (get-core-resource store resource (pod-namespace pod) name) result)
          (kubernetes-error (condition)
            (unless (and optional (= 404 (kubernetes-error-status-code condition))) (error condition))))))
    (remove-duplicates (append result (pod-persistent-resource-objects store pod)) :test #'equalp)))

(defun install-assigned-resource-objects (store assignments &optional service-discovery)
  "Atomically install Pod-scoped references, exact PVC/PV bindings and public Service discovery."
  (let ((resources (make-hash-table :test #'equal)))
    (dolist (assignment assignments)
      (let* ((pod (assignment-pod assignment))
             (projected (mapcar (lambda (bytes)
                                  (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string bytes)
                                                       :max-string-length (* 2 1024 1024)))
                                (slot-value assignment 'gr8s.node.v1::resource-objects-json))))
        (dolist (object projected)
          (let* ((metadata (require-object (gethash "metadata" object) "metadata"))
                 (namespace (gethash "namespace" metadata)) (name (gethash "name" metadata))
                 (resource (cond ((equal "ConfigMap" (gethash "kind" object)) "configmaps")
                                 ((equal "Secret" (gethash "kind" object)) "secrets")
                                 ((equal "PersistentVolumeClaim" (gethash "kind" object)) "persistentvolumeclaims")
                                 ((equal "PersistentVolume" (gethash "kind" object)) "persistentvolumes")
                                 (t (invalid-pod "assignment contains an unsupported resource kind")))))
            (unless (if (storage-resource-p resource)
                        (assigned-storage-resource-p object pod projected)
                        (and (equal namespace (pod-namespace pod))
                             (some (lambda (reference) (and (equal resource (first reference)) (equal name (second reference))))
                                   (pod-resource-reference-declarations pod))))
              (invalid-pod "assignment contains an unreferenced, cross-namespace or incorrectly bound resource"))
            ;; This status came from the authenticated control plane, rather than
            ;; an API create request. Preserve its real binding observation.
            (let ((*storage-status-write* (not (null (storage-resource-p resource)))))
              (setf (gethash (core-resource-key resource namespace name) resources)
                    (normalize-core-resource resource object namespace name)))))))
    (install-service-discovery-projection resources service-discovery)
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

(defparameter *pod-tmpfs-mount* (lambda (target options) (%linux-mount "gr8s-pod-volume" target "tmpfs" #x6 options))
  "Mount a MS_NOSUID|MS_NODEV tmpfs, returning the libc status.")
(defparameter *pod-tmpfs-unmount* (lambda (target) (%linux-umount target 0))
  "Unmount one Pod volume, returning the libc status.")
(defparameter *pod-mount-table-path* #P"/proc/self/mountinfo"
  "The kernel's authoritative view of mounts in the agent's namespace.")

(defun decode-mountinfo-path (encoded)
  "Decode the octal escapes Linux applies to mountinfo pathnames."
  (cl-ppcre:regex-replace-all
   "\\\\([0-7]{3})" encoded
   (lambda (match code) (declare (ignore match)) (string (code-char (parse-integer code :radix 8))))
   :simple-calls t))

(defun pod-volume-mount-targets (directory)
  "Return mount points at or beneath existing DIRECTORY, deepest first."
  (let ((root (namestring (truename directory))))
    (sort (loop for line in (uiop:read-file-lines *pod-mount-table-path*)
                for fields = (uiop:split-string line :separator '(#\Space))
                for target = (and (>= (length fields) 5) (decode-mountinfo-path (nth 4 fields)))
                when (and target (uiop:string-prefix-p root (concatenate 'string target "/")))
                  collect target)
          #'> :key #'length)))

(defun pod-volume-system-error (operation target)
  "Signal a runtime error naming the failed mount OPERATION and the current errno."
  (error 'runtime-error :message (format nil "Could not ~A Pod volume ~A: ~A" operation target
                                         (sb-int:strerror (sb-alien:get-errno)))))

(defun ensure-pod-memory-volume (directory source)
  "Mount a tmpfs at DIRECTORY once, so restarted containers keep the volume's contents."
  (unless (pod-volume-mount-targets directory)
    (let* ((target (namestring (truename directory)))
           (limit (gethash "sizeLimit" source))
           (options (if (member limit '(nil 0 "0") :test #'equal) ""
                        (format nil "size=~D" (ceiling (storage-quantity limit "emptyDir.sizeLimit"))))))
      (unless (zerop (funcall *pod-tmpfs-mount* target options))
        (pod-volume-system-error "mount" target)))))

(defun cleanup-pod-volumes (runtime uid)
  "Unmount and delete a terminated Pod's volumes; a failed unmount leaves data for retry."
  (let ((directory (merge-pathnames "volumes/" (containerd-pod-log-directory runtime uid))))
    (when (probe-file directory)
      (dolist (target (pod-volume-mount-targets directory))
        (unless (zerop (funcall *pod-tmpfs-unmount* target))
          (pod-volume-system-error "unmount" target)))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(defun materialize-pod-volume (runtime pod volume)
  "Create a volume's directories and projected files with enforced fsGroup access."
  (when (gethash "hostPath" volume)
    (return-from materialize-pod-volume (materialize-host-storage-source (gethash "hostPath" volume))))
  (when (gethash "persistentVolumeClaim" volume)
    (return-from materialize-pod-volume (materialize-persistent-claim-volume runtime pod (gethash "persistentVolumeClaim" volume))))
  (let* ((directory (pod-volume-directory runtime pod (gethash "name" volume)))
         (group (pod-fs-group pod)))
    (ensure-directories-exist directory)
    ;; The final directory is bind-mounted into the container. Its parent stays
    ;; private on the host even when Kubernetes requests world-readable files.
    (sb-posix:chmod (namestring (containerd-pod-log-directory runtime (pod-uid pod))) #o700)
    (let ((source (gethash "emptyDir" volume)))
      (when (and source (equal "Memory" (gethash "medium" source)))
        (ensure-pod-memory-volume directory source)))
    ;; Applied after mounting because the tmpfs root replaces the directory's mode.
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

(defun containerd-pod-mounts (runtime pod container &optional environment)
  "Build CRI bind mounts from validated, materialized Pod volume declarations."
  (let ((volumes (gethash "volumes" (gethash "spec" (pod-to-object pod)) #()))
        (object (pod-runtime-container-object pod container)))
    (loop for mount across (gethash "volumeMounts" object #()) for index from 0
          for volume = (find (gethash "name" mount) volumes :test #'equal
                             :key (lambda (volume) (gethash "name" volume)))
          collect (multiple-value-bind (path forced-readonly) (materialize-pod-volume runtime pod volume)
                    (let ((relative (container-mount-subpath mount environment)))
                      (when (plusp (length relative))
                        (setf path (stage-container-volume-subpath runtime pod container mount index path relative))))
                    (make-instance 'gr8s.cri.v1::mount
                                   :container-path (gethash "mountPath" mount) :host-path (namestring path)
                                   :readonly (or forced-readonly (not (null (gethash "configMap" volume)))
                                                 (not (null (gethash "secret" volume)))
                                                 (eq t (gethash "readOnly" mount))))))))

(defun containerd-key-environment-value (runtime pod resource reference)
  "Resolve a required or optional environment key without exposing Secret data in errors."
  (let* ((name (gethash "name" reference)) (key (gethash "key" reference))
         (optional (eq t (gethash "optional" reference)))
         (object (handler-case (get-core-resource (containerd-runtime-resource-store runtime) resource (pod-namespace pod) name)
                   (kubernetes-error (condition)
                     (unless (and optional (= 404 (kubernetes-error-status-code condition)))
                       (error 'runtime-error :message (format nil "Missing environment source ~A/~A" resource name))))))
         (data (and object (gethash "data" object))))
    (multiple-value-bind (value present) (if data (gethash key data) (values nil nil))
      (unless present
        (if optional (return-from containerd-key-environment-value (values nil nil))
            (error 'runtime-error :message (format nil "Environment source ~A/~A lacks key ~A" resource name key))))
      (let ((text (if (equal resource "secrets")
                      (handler-case (trivial-utf-8:utf-8-bytes-to-string (core-base64-bytes value "Secret environment"))
                        (error () (error 'runtime-error :message "Secret environment value is not valid UTF-8"))) value)))
        (when (find #\Null text) (error 'runtime-error :message "Environment values cannot contain NUL"))
        (values text t)))))

(defun environment-source-pairs (runtime pod source)
  "Return (name . value) pairs from one envFrom entry, prefixing every key."
  (let* ((secret (gethash "secretRef" source))
         (reference (or secret (gethash "configMapRef" source)))
         (resource (if secret "secrets" "configmaps"))
         (name (gethash "name" reference))
         (object (handler-case (get-core-resource (containerd-runtime-resource-store runtime)
                                                  resource (pod-namespace pod) name)
                   (kubernetes-error (condition)
                     (unless (and (eq t (gethash "optional" reference))
                                  (= 404 (kubernetes-error-status-code condition)))
                       (error 'runtime-error
                              :message (format nil "Missing environment source ~A/~A" resource name))))))
         (data (and object (gethash "data" object))))
    (when data
      (loop for key being the hash-keys of data using (hash-value value)
            for variable = (concatenate 'string (gethash "prefix" source "") key)
            ;; As in Kubernetes, a key that cannot name a variable is skipped.
            unless (find #\= variable)
              collect (cons variable
                            (if secret
                                (handler-case (trivial-utf-8:utf-8-bytes-to-string
                                               (core-base64-bytes value "Secret environment"))
                                  (error () (error 'runtime-error :message "Secret environment value is not valid UTF-8")))
                                value))))))

(defun service-environment-name (name)
  "Convert a Service or port name to its environment variable spelling."
  (substitute #\_ #\- (string-upcase name)))

(defun service-environment-pairs (service)
  "Return a ClusterIP Service's variables, including the legacy Docker link form."
  (let* ((spec (gethash "spec" service))
         (address (gethash "clusterIP" spec))
         (ports (coerce (gethash "ports" spec #()) 'list))
         (prefix (service-environment-name (gethash "name" (gethash "metadata" service)))))
    (when (and (stringp address) (plusp (length address)) (not (equal address "None")) ports)
      (flet ((variable (control &rest arguments)
               (concatenate 'string prefix (apply #'format nil control arguments))))
        (let* ((first-port (first ports))
               (first-number (gethash "port" first-port))
               (first-protocol (string-downcase (gethash "protocol" first-port "TCP"))))
          (append
           (list (cons (variable "_SERVICE_HOST") address)
                 (cons (variable "_SERVICE_PORT") (write-to-string first-number))
                 (cons (variable "_PORT") (format nil "~A://~A:~D" first-protocol address first-number)))
           (loop for port in ports
                 for number = (gethash "port" port)
                 for protocol = (gethash "protocol" port "TCP")
                 for lower = (string-downcase protocol)
                 for base = (variable "_PORT_~D_~A" number (string-upcase protocol))
                 append (append
                         (when (plusp (length (gethash "name" port "")))
                           (list (cons (variable "_SERVICE_PORT_~A" (service-environment-name (gethash "name" port)))
                                       (write-to-string number))))
                         (list (cons base (format nil "~A://~A:~D" lower address number))
                               (cons (concatenate 'string base "_PROTO") lower)
                               (cons (concatenate 'string base "_PORT") (write-to-string number))
                               (cons (concatenate 'string base "_ADDR") address))))))))))

(defun pod-service-environment (runtime pod)
  "Return variables for the API Service and, unless disabled, Services in POD's namespace."
  (let* ((store (containerd-runtime-resource-store runtime))
         (links (gethash "enableServiceLinks" (gethash "spec" (pod-to-object pod)) t))
         (services (remove-duplicates
                    (append (when (eq t links) (list-core-resources store "services" (pod-namespace pod)))
                            (remove-if-not (lambda (service)
                                             (equal "kubernetes" (gethash "name" (gethash "metadata" service))))
                                           (list-core-resources store "services" "default")))
                    :key (lambda (service) (gethash "uid" (gethash "metadata" service))) :test #'equal)))
    (mapcan #'service-environment-pairs services)))

(defun merge-environment (&rest layers)
  "Combine (name . value) LAYERS in order, each later definition replacing an earlier one."
  (let ((result nil))
    (dolist (layer layers (nreverse result))
      (dolist (pair layer)
        (let ((existing (assoc (car pair) result :test #'equal)))
          (if existing
              (setf (cdr existing) (cdr pair))
              (push (cons (car pair) (cdr pair)) result)))))))

(defun containerd-pod-environment (runtime pod container sandbox-id)
  "Resolve a container's variables: Services, then envFrom in order, then explicit env."
  (let* ((object (pod-runtime-container-object pod container)) (pod-ip nil))
    (merge-environment
     (when (and runtime (containerd-runtime-resource-store runtime)) (pod-service-environment runtime pod))
     (loop for source across (gethash "envFrom" object #())
           append (environment-source-pairs runtime pod source))
     (loop for variable across (gethash "env" object #())
           for from = (gethash "valueFrom" variable)
           append
           (multiple-value-bind (value include)
               (cond
                 ((null from) (values (gethash "value" variable "") t))
                 ((gethash "secretKeyRef" from)
                  (containerd-key-environment-value runtime pod "secrets" (gethash "secretKeyRef" from)))
                 ((gethash "configMapKeyRef" from)
                  (containerd-key-environment-value runtime pod "configmaps" (gethash "configMapKeyRef" from)))
                 (t (let* ((field (gethash "fieldPath" (gethash "fieldRef" from)))
                           (reference (pod-metadata-subscript-reference field)))
                      (values
                       (cond ((equal field "metadata.name") (pod-name pod))
                             ((equal field "metadata.namespace") (pod-namespace pod))
                             ((equal field "metadata.uid") (pod-uid pod))
                             ((equal field "spec.nodeName") (or (pod-node-name pod) ""))
                             (reference
                              (let ((metadata (gethash "metadata" (pod-to-object pod))))
                                (gethash (cdr reference) (gethash (car reference) metadata (core-object)) "")))
                             ((equal field "status.podIP")
                              (or pod-ip (setf pod-ip (cri-pod-sandbox-ip
                                                      (containerd-runtime-socket-path runtime) sandbox-id))))) t))))
             (when include (list (cons (gethash "name" variable) value))))))))

(defun cri-seccomp-profile (context)
  "Map a validated seccompProfile to CRI, leaving an unset profile to mean Unconfined."
  (let ((profile (and context (gethash "seccompProfile" context))))
    (when profile
      (make-instance 'gr8s.cri.v1::security-profile
                     :profile-type (if (equal "RuntimeDefault" (gethash "type" profile))
                                       gr8s.cri.v1::|+PROFILETYPE-RuntimeDefault+|
                                       gr8s.cri.v1::|+PROFILETYPE-Unconfined+|)))))

(defun cri-selinux-options (context)
  "Map validated seLinuxOptions to the CRI label; enforcement belongs to the runtime."
  (let ((options (and context (gethash "seLinuxOptions" context))))
    (when options
      (make-instance 'gr8s.cri.v1::se-linux-option
                     :user (gethash "user" options "") :role (gethash "role" options "")
                     :type (gethash "type" options "") :level (gethash "level" options "")))))

(defun pod-supplemental-groups (pod)
  "Return POD's declared supplemental groups joined with its fsGroup."
  (let* ((context (gethash "securityContext" (gethash "spec" (pod-to-object pod))))
         (declared (and context (coerce (gethash "supplementalGroups" context #()) 'list))))
    (remove-duplicates (append declared (when (pod-fs-group pod) (list (pod-fs-group pod))))
                       :from-end t)))

(defun containerd-pod-sandbox-security (pod)
  "Return Pod-level confinement initargs; containers derive their SELinux context from these."
  (let ((context (gethash "securityContext" (gethash "spec" (pod-to-object pod)))))
    (list :seccomp (cri-seccomp-profile context)
          :selinux-options (cri-selinux-options context)
          :supplemental-groups (pod-supplemental-groups pod))))

(defun containerd-pod-security-context (pod container)
  "Map effective Pod/container Linux identities, confinement and privileges to the CRI API."
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
       :supplemental-groups (pod-supplemental-groups pod)
       :seccomp (cri-seccomp-profile effective)
       :selinux-options (cri-selinux-options effective)
       :capabilities (let ((capabilities (gethash "capabilities" effective)))
                       (when capabilities
                         (make-instance 'gr8s.cri.v1::capability
                                        :add-capabilities (coerce (gethash "add" capabilities #()) 'list)
                                        :drop-capabilities (coerce (gethash "drop" capabilities #()) 'list))))
       :privileged (eq t (gethash "privileged" effective))
       :readonly-rootfs (eq t (gethash "readOnlyRootFilesystem" effective))
       :no-new-privs (and (nth-value 1 (gethash "allowPrivilegeEscalation" effective))
                          (null (gethash "allowPrivilegeEscalation" effective)))))))
