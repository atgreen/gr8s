;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Install authenticated Pod references and public Service discovery together;
;;;; materialize ConfigMap, Secret and emptyDir mounts in agent-owned directories.
;;;; Private resource data stays scoped to the Pod namespace; paths are validated
;;;; before touching the filesystem and fsGroup controls mounted data access.
;;;; Memory emptyDirs and NFS volumes are real mounts that live until the Pod terminates.

(in-package #:gr8s)

(defun pod-volume-resource-references (volume)
  "Return (collection name optional) for each object VOLUME reads, including projected sources."
  (flet ((reference (resource source name-field)
           (list resource (gethash name-field source) (eq t (gethash "optional" source)))))
    (append
     (when (gethash "configMap" volume) (list (reference "configmaps" (gethash "configMap" volume) "name")))
     (when (gethash "secret" volume) (list (reference "secrets" (gethash "secret" volume) "secretName")))
     (let ((source (gethash "csi" volume)))
       (when (and source (gethash "nodePublishSecretRef" source))
         (list (reference "secrets" (gethash "nodePublishSecretRef" source) "name"))))
     (when (gethash "projected" volume)
       (loop for source across (gethash "sources" (gethash "projected" volume) #())
             when (gethash "configMap" source)
               collect (reference "configmaps" (gethash "configMap" source) "name")
             when (gethash "secret" source)
               collect (reference "secrets" (gethash "secret" source) "name"))))))

(defun pod-resource-reference-declarations (pod)
  "Collect namespace-local resource declarations from volumes, environment sources and pull secrets."
  (let* ((spec (gethash "spec" (pod-to-object pod))) (references nil))
    (loop for volume across (gethash "volumes" spec #())
          do (setf references (append (pod-volume-resource-references volume) references)))
    ;; A missing pull secret is optional because the kubelet pulls without it.
    (loop for reference across (gethash "imagePullSecrets" spec #())
          when (plusp (length (gethash "name" reference "")))
            do (push (list "secrets" (gethash "name" reference) t) references))
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
        (declare (ignore optional))
        (handler-case (push (get-core-resource store resource (pod-namespace pod) name) result)
          ;; Every snapshot carries every Pod on the node, so signalling here would
          ;; stop them all. The agent reports a required object's absence on this Pod.
          (kubernetes-error (condition)
            (unless (= 404 (kubernetes-error-status-code condition)) (error condition))))))
    (let ((token-object (handler-case (pod-projected-token-object store pod)
                          ;; A missing account delays only this Pod, as its unready volume reports.
                          (kubernetes-error () nil))))
      (when token-object (push token-object result)))
    (remove-duplicates (append result (pod-persistent-resource-objects store pod)) :test #'equalp)))

(defun assignment-resource-objects (assignment)
  "Return ASSIGNMENT's validated objects as (KEY . OBJECT), or signal if any is not acceptable."
  (let* ((pod (assignment-pod assignment))
         (projected (mapcar (lambda (bytes)
                              (com.inuoe.jzon:parse (trivial-utf-8:utf-8-bytes-to-string bytes)
                                                   :max-string-length (* 2 1024 1024)))
                            (slot-value assignment 'gr8s.node.v1::resource-objects-json))))
    (loop for object in projected
          collect
          (let* ((metadata (require-object (gethash "metadata" object) "metadata"))
                 (namespace (gethash "namespace" metadata)) (name (gethash "name" metadata))
                 (resource (cond ((equal "ConfigMap" (gethash "kind" object)) "configmaps")
                                 ((equal "Secret" (gethash "kind" object)) "secrets")
                                 ((equal "PersistentVolumeClaim" (gethash "kind" object)) "persistentvolumeclaims")
                                 ((equal "PersistentVolume" (gethash "kind" object)) "persistentvolumes")
                                 ((equal "CSIDriver" (gethash "kind" object)) "csidrivers")
                                 ((equal "VolumeAttachment" (gethash "kind" object)) "volumeattachments")
                                 (t (invalid-pod "assignment contains an unsupported resource kind")))))
            (unless (if (storage-resource-p resource)
                        (assigned-storage-resource-p object pod projected)
                        (or (and (equal namespace (pod-namespace pod))
                                 (or (and (equal resource "secrets") (equal name (projected-token-secret-name pod))
                                          (pod-projected-token-sources pod))
                                     (some (lambda (reference) (and (equal resource (first reference)) (equal name (second reference))))
                                           (pod-resource-reference-declarations pod))))
                            (and (equal resource "secrets") (csi-volume-secret-reference-p object projected))))
              (invalid-pod "assignment contains an unreferenced, cross-namespace or incorrectly bound resource"))
            ;; This status came from the authenticated control plane, rather than
            ;; an API create request. Preserve its real binding observation.
            (let ((*storage-status-write* (not (null (storage-resource-p resource)))))
              (cons (core-resource-key resource namespace name)
                    (normalize-core-resource resource object namespace name)))))))

(defun install-assigned-resource-objects (store assignments &optional service-discovery)
  "Atomically install Pod-scoped references, exact PVC/PV bindings and public Service discovery."
  (let ((resources (make-hash-table :test #'equal)))
    (dolist (assignment assignments)
      ;; Every snapshot carries every Pod, so failing the whole of it would stop
      ;; all Pods on this node. One Pod's bad object delays only that Pod, whose
      ;; volumes then report the missing resource.
      (handler-case
          (loop for (key . object) in (assignment-resource-objects assignment)
                do (setf (gethash key resources) object))
        (error (condition)
          (format *error-output* "gr8s Pod ~A/~A assignment rejected: ~A~%"
                  (slot-value assignment 'gr8s.node.v1::namespace)
                  (slot-value assignment 'gr8s.node.v1::name) condition))))
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

(defun write-projected-volume-file (target bytes mode group &optional owner)
  "Atomically publish BYTES with final permissions and optional OWNER, starting with a private file."
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
           (when owner (sb-posix:chown (namestring temporary) owner #xffffffff))
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

(defun pod-volume-nfs-mount-p (target)
  "Return whether the kernel reports an NFS filesystem mounted at TARGET."
  (loop for line in (uiop:read-file-lines *pod-mount-table-path*)
        for fields = (uiop:split-string line :separator '(#\Space))
        for separator = (position "-" fields :test #'equal)
        thereis (and separator (>= (length fields) 5) (< (1+ separator) (length fields))
                     (equal (string-right-trim "/" target) (decode-mountinfo-path (nth 4 fields)))
                     (member (nth (1+ separator) fields) '("nfs" "nfs4") :test #'equal))))

(defun materialize-pod-nfs-volume (runtime pod name source mount-options &key share)
  "Mount SOURCE for POD once and return the path, without touching the mount itself.
SHARE names a provisioned volume's export, whose own directory is created on first use."
  (let* ((pod-directory (containerd-pod-log-directory runtime (pod-uid pod)))
         (volumes (merge-pathnames "volumes/" pod-directory)))
    (ensure-directories-exist volumes)
    (sb-posix:chmod (namestring pod-directory) #o700)
    (let* ((root (namestring (truename volumes)))
           (target (concatenate 'string root name))
           (server (gethash "server" source))
           (path (gethash "path" source))
           (tokens (append (nfs-mount-option-tokens mount-options)
                           (when (eq t (gethash "readOnly" source)) (list "ro")))))
      (unless (nfs-target-mounted-p target)
        (ensure-directories-exist (uiop:ensure-directory-pathname target))
        (handler-case (mount-nfs-filesystem server path target tokens)
          (nfs-mount-error (condition)
            (unless (and share (= sb-posix:enoent (nfs-mount-error-errno condition)))
              (error condition))
            (ensure-provisioned-nfs-directory server share (subseq path (1+ (position #\/ path :from-end t)))
                                              (concatenate 'string root "." name "-share")
                                              (remove "ro" tokens :test #'equal))
            (mount-nfs-filesystem server path target tokens))))
      (uiop:ensure-directory-pathname target))))

(defun pod-memory-volume-bytes (pod source)
  "Size a Memory emptyDir by its limit and the Pod's memory limit, whichever is smaller, as a kubelet does."
  (let* ((limit (gethash "sizeLimit" source))
         (size (unless (member limit '(nil 0 "0") :test #'equal) (storage-quantity limit "emptyDir.sizeLimit")))
         (memory (and pod (gethash "memory" (nth-value 1 (pod-spec-resource-totals (gethash "spec" (pod-to-object pod))))))))
    (if (and size memory) (min size memory) (or size memory))))

(defun ensure-pod-memory-volume (directory source &optional pod)
  "Mount a tmpfs at DIRECTORY once, so restarted containers keep the volume's contents."
  (unless (pod-volume-mount-targets directory)
    (let* ((target (namestring (truename directory)))
           (bytes (pod-memory-volume-bytes pod source))
           (options (if bytes (format nil "size=~D" (ceiling bytes)) "")))
      (unless (zerop (funcall *pod-tmpfs-mount* target options))
        (pod-volume-system-error "mount" target)))))

(defun pod-claim-volume-record (runtime uid volume-name)
  "Return where UID's record of the claim behind VOLUME-NAME is kept. It sits beside the
Pod's volume directories, which no container mounts, so it outlives an agent restart and
goes with them when the Pod's volumes are cleaned up."
  (merge-pathnames (format nil "volumes/.claims/~A" volume-name) (containerd-pod-log-directory runtime uid)))

(defun record-pod-claim-volume (runtime pod volume-name claim-name path)
  "Record that POD's VOLUME-NAME mounts CLAIM-NAME from PATH, for the kubelet's volume
statistics, and return PATH."
  (when path
    (let ((record (pod-claim-volume-record runtime (pod-uid pod) volume-name)))
      (ensure-directories-exist record)
      (with-open-file (stream record :direction :output :if-exists :supersede)
        (write-string (com.inuoe.jzon:stringify (vector (pod-namespace pod) claim-name (namestring path))) stream))))
  path)

(defun cleanup-pod-volumes (runtime uid)
  "Unmount and delete a terminated Pod's volumes; a failed unmount leaves data for retry.
The Pod's user namespace block is free again once nothing it owns remains."
  (cleanup-pod-csi-volumes uid)
  (release-containerd-user-namespace runtime uid)
  (let ((directory (merge-pathnames "volumes/" (containerd-pod-log-directory runtime uid))))
    (when (probe-file directory)
      (dolist (target (pod-volume-mount-targets directory))
        (if (pod-volume-nfs-mount-p target)
            (unmount-nfs-filesystem target)
            (unless (zerop (funcall *pod-tmpfs-unmount* target))
              (pod-volume-system-error "unmount" target))))
      ;; The tree deletion below must never reach into a share that is still mounted.
      (when (pod-volume-mount-targets directory)
        (error 'runtime-error :message (format nil "Pod volumes under ~A are still mounted" directory)))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(defun materialize-pod-volume (runtime pod volume)
  "Create a volume's directories and projected files with enforced fsGroup access."
  (when (gethash "hostPath" volume)
    (return-from materialize-pod-volume (materialize-host-storage-source (gethash "hostPath" volume))))
  (when (or (gethash "persistentVolumeClaim" volume) (gethash "ephemeral" volume))
    (let* ((ephemeral (gethash "ephemeral" volume))
           (source (if ephemeral
                       (core-object "claimName" (ephemeral-claim-name (pod-name pod) (gethash "name" volume)))
                       (gethash "persistentVolumeClaim" volume))))
      (multiple-value-bind (path readonly)
          (materialize-persistent-claim-volume runtime pod source (gethash "name" volume) ephemeral)
        (return-from materialize-pod-volume
          (values (record-pod-claim-volume runtime pod (gethash "name" volume) (gethash "claimName" source) path)
                  readonly)))))
  (when (gethash "csi" volume)
    (return-from materialize-pod-volume
      (materialize-inline-csi-volume (containerd-runtime-resource-store runtime) pod volume)))
  (when (gethash "nfs" volume)
    (return-from materialize-pod-volume
      (values (materialize-pod-nfs-volume runtime pod (gethash "name" volume) (gethash "nfs" volume) nil)
              (eq t (gethash "readOnly" (gethash "nfs" volume))))))
  (let* ((directory (pod-volume-directory runtime pod (gethash "name" volume)))
         (group (pod-fs-group pod)))
    (ensure-directories-exist directory)
    ;; The final directory is bind-mounted into the container. Its parent stays
    ;; private on the host even when Kubernetes requests world-readable files.
    (sb-posix:chmod (namestring (containerd-pod-log-directory runtime (pod-uid pod))) #o700)
    (let ((source (gethash "emptyDir" volume)))
      (when (and source (equal "Memory" (gethash "medium" source)))
        (ensure-pod-memory-volume directory source pod)))
    ;; Applied after mounting because the tmpfs root replaces the directory's mode. As the
    ;; kubelet does, the permission bits become 0777 and special bits such as a tmpfs root's
    ;; sticky bit stay; SetVolumeOwnership then ORs in group rwx and setgid for fsGroup.
    ;; So a disk emptyDir under fsGroup is 02777 and a tmpfs one 03777.
    (let ((special (logand #o7000 (sb-posix:stat-mode (sb-posix:stat (namestring directory))))))
      (set-pod-volume-permissions directory (logior special #o777 (if group #o2770 0)) group))
    (multiple-value-bind (files projection) (pod-volume-desired-files runtime pod volume)
      (when projection (publish-pod-volume-files directory files group)))
    directory))

(defun container-mount-propagation (mount)
  "Map a volumeMount's mountPropagation to its CRI mode; drivers publish volumes through Bidirectional."
  (let ((mode (gethash "mountPropagation" mount "None")))
    (cond ((equal mode "Bidirectional") gr8s.cri.v1::+mountpropagation-propagation_bidirectional+)
          ((equal mode "HostToContainer") gr8s.cri.v1::+mountpropagation-propagation_host_to_container+)
          (t gr8s.cri.v1::+mountpropagation-propagation_private+))))

(defun container-image-volume-mount (runtime pod container mount source environment)
  "Return the CRI mount of image volume SOURCE, once its image may be used under its pull policy.
The runtime mounts the image itself, and it fails the container if a subPath isn't in the image."
  (let ((reference (gethash "reference" source)))
    (ensure-container-image runtime reference
                            (gethash "pullPolicy" source (default-image-pull-policy reference))
                            (lambda ()
                              (pod-image-pull-credentials runtime pod (container-spec-name container) reference)))
    (make-instance 'gr8s.cri.v1::mount
                   :container-path (gethash "mountPath" mount)
                   :image (make-instance
                           'gr8s.cri.v1::image-spec
                           :image (or (cri-image-id (containerd-runtime-socket-path runtime) reference) reference))
                   :image-sub-path (container-mount-subpath mount environment)
                   :propagation (container-mount-propagation mount)
                   :readonly t)))

(defun recursive-read-only-mounts-supported-p ()
  "Return whether this kernel has mount_setattr(2), which recursive read-only mounts need (Linux 5.12)."
  (let* ((release (ignore-errors (string-trim '(#\Newline #\Space) (uiop:read-file-string "/proc/sys/kernel/osrelease"))))
         (parts (and release (uiop:split-string release :separator '(#\. #\-))))
         (major (and parts (parse-integer (first parts) :junk-allowed t)))
         (minor (and (second parts) (parse-integer (second parts) :junk-allowed t))))
    (and major minor (or (> major 5) (and (= major 5) (>= minor 12))))))

(defun container-mount-recursive-read-only-p (mount)
  "Return whether MOUNT is made read-only recursively: Enabled always, IfPossible where the kernel can.
A runtime that cannot honour Enabled then fails the container, as a kubelet would."
  (let ((mode (gethash "recursiveReadOnly" mount "Disabled")))
    (and (eq t (gethash "readOnly" mount))
         (or (equal mode "Enabled")
             (and (equal mode "IfPossible") (recursive-read-only-mounts-supported-p))))))

(defun containerd-pod-mounts (runtime pod container &optional environment)
  "Build CRI mounts from validated Pod volume declarations, materializing those the node provides."
  (let ((volumes (gethash "volumes" (gethash "spec" (pod-to-object pod)) #()))
        (object (pod-runtime-container-object pod container)))
    (loop for mount across (gethash "volumeMounts" object #()) for index from 0
          for volume = (find (gethash "name" mount) volumes :test #'equal
                             :key (lambda (volume) (gethash "name" volume)))
          collect (if (gethash "image" volume)
                      (container-image-volume-mount runtime pod container mount (gethash "image" volume) environment)
                      (multiple-value-bind (path forced-readonly) (materialize-pod-volume runtime pod volume)
                        (let ((relative (container-mount-subpath mount environment)))
                          (when (plusp (length relative))
                            (setf path (stage-container-volume-subpath runtime pod container mount index path relative))))
                        (make-instance 'gr8s.cri.v1::mount
                                       :container-path (gethash "mountPath" mount) :host-path (namestring path)
                                       :propagation (container-mount-propagation mount)
                                       :recursive-read-only (container-mount-recursive-read-only-p mount)
                                       :readonly (or forced-readonly (not (null (gethash "configMap" volume)))
                                                     (not (null (gethash "secret" volume)))
                                                     (not (null (gethash "downwardAPI" volume)))
                                                     (not (null (gethash "projected" volume)))
                                                     (eq t (gethash "readOnly" mount)))))))))

(defun containerd-key-environment-value (runtime pod resource reference)
  "Resolve a required or optional environment key without exposing Secret data in errors."
  (let* ((name (gethash "name" reference)) (key (gethash "key" reference))
         (optional (eq t (gethash "optional" reference)))
         (object (handler-case (get-core-resource (containerd-runtime-resource-store runtime) resource (pod-namespace pod) name)
                   (kubernetes-error (condition)
                     (unless (and optional (= 404 (kubernetes-error-status-code condition)))
                       (container-config-error "Missing environment source ~A/~A" resource name)))))
         (data (and object (gethash "data" object))))
    (multiple-value-bind (value present) (if data (gethash key data) (values nil nil))
      (unless present
        (if optional (return-from containerd-key-environment-value (values nil nil))
            (container-config-error "Environment source ~A/~A lacks key ~A" resource name key)))
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
                       (container-config-error "Missing environment source ~A/~A" resource name)))))
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

(defun containerd-sandbox-address (runtime pod sandbox-id)
  "Return POD's own address: its sandbox's, or its node's when it shares the node's network."
  (if (containerd-pod-host-network-p runtime pod)
      (containerd-node-address runtime)
      (cri-pod-sandbox-ip (containerd-runtime-socket-path runtime) sandbox-id)))

(defun containerd-pod-environment (runtime pod container sandbox-id)
  "Resolve a container's variables: Services, then envFrom in order, then explicit env.
A literal value may refer to any variable defined before it, as $(NAME)."
  (let* ((object (pod-runtime-container-object pod container)) (pod-ip nil)
         (environment
           (merge-environment
            (when (and runtime (containerd-runtime-resource-store runtime)) (pod-service-environment runtime pod))
            (loop for source across (gethash "envFrom" object #())
                  append (environment-source-pairs runtime pod source)))))
    (merge-environment
     environment
     (loop for variable across (gethash "env" object #())
           for from = (gethash "valueFrom" variable)
           append
           (multiple-value-bind (value include)
               (cond
                 ((null from)
                  (values (expand-container-command-argument (gethash "value" variable "") environment) t))
                 ((gethash "secretKeyRef" from)
                  (containerd-key-environment-value runtime pod "secrets" (gethash "secretKeyRef" from)))
                 ((gethash "configMapKeyRef" from)
                  (containerd-key-environment-value runtime pod "configmaps" (gethash "configMapKeyRef" from)))
                 ((gethash "fileKeyRef" from)
                  (containerd-file-key-environment-value runtime pod (gethash "fileKeyRef" from)))
                 ((gethash "resourceFieldRef" from)
                  (let ((reference (copy-core-object (gethash "resourceFieldRef" from))))
                    (when (member (gethash "containerName" reference) '(nil "") :test #'equal)
                      (setf (gethash "containerName" reference) (gethash "name" object)))
                    (values (downward-resource-value pod reference) t)))
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
                             ((equal field "spec.serviceAccountName")
                              (gethash "serviceAccountName" (gethash "spec" (pod-to-object pod)) ""))
                             ((member field '("status.hostIP" "status.hostIPs") :test #'equal)
                              (containerd-node-address runtime))
                             ((member field '("status.podIP" "status.podIPs") :test #'equal)
                              (or pod-ip (setf pod-ip (containerd-sandbox-address runtime pod sandbox-id))))) t))))
             (when include
               (setf environment (merge-environment environment (list (cons (gethash "name" variable) value))))
               (list (cons (gethash "name" variable) value))))))))

(defun cri-seccomp-profile (context)
  "Map a validated seccompProfile to CRI, leaving an unset profile to mean Unconfined."
  (let ((profile (and context (gethash "seccompProfile" context))))
    (when profile
      (let ((type (gethash "type" profile)))
        (if (equal type "Localhost")
            (make-instance 'gr8s.cri.v1::security-profile
                           :profile-type gr8s.cri.v1::|+PROFILETYPE-Localhost+|
                           :localhost-ref (namestring (merge-pathnames (gethash "localhostProfile" profile)
                                                                       *seccomp-profile-root*)))
            (make-instance 'gr8s.cri.v1::security-profile
                           :profile-type (if (equal "RuntimeDefault" type)
                                             gr8s.cri.v1::|+PROFILETYPE-RuntimeDefault+|
                                             gr8s.cri.v1::|+PROFILETYPE-Unconfined+|)))))))

(defun cri-apparmor-profile (context)
  "Map a validated appArmorProfile to CRI. Unset leaves the runtime's default, which a node
without AppArmor never reaches: admission refuses any other profile there."
  (let ((profile (and context (gethash "appArmorProfile" context))))
    (when (and profile (host-apparmor-enabled-p))
      (let ((type (gethash "type" profile)))
        (make-instance 'gr8s.cri.v1::security-profile
                       :profile-type (cond ((equal type "RuntimeDefault") gr8s.cri.v1::|+PROFILETYPE-RuntimeDefault+|)
                                           ((equal type "Localhost") gr8s.cri.v1::|+PROFILETYPE-Localhost+|)
                                           (t gr8s.cri.v1::|+PROFILETYPE-Unconfined+|))
                       :localhost-ref (gethash "localhostProfile" profile ""))))))

(defun cri-supplemental-groups-policy (context)
  "Map supplementalGroupsPolicy to CRI: Strict leaves out the groups the image declares for the user."
  (if (equal "Strict" (and context (gethash "supplementalGroupsPolicy" context)))
      gr8s.cri.v1::|+SUPPLEMENTALGROUPSPOLICY-Strict+|
      gr8s.cri.v1::|+SUPPLEMENTALGROUPSPOLICY-Merge+|))

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
          :apparmor (cri-apparmor-profile context)
          :selinux-options (cri-selinux-options context)
          :supplemental-groups (pod-supplemental-groups pod)
          :supplemental-groups-policy (cri-supplemental-groups-policy context))))

(defun verify-run-as-non-root (pod container effective image-user)
  "Refuse to create CONTAINER when runAsNonRoot holds and it would run as root, as a kubelet does.
IMAGE-USER returns the image's numeric user (or NIL) and its user name; an image naming neither runs as root."
  (when (eq t (gethash "runAsNonRoot" effective))
    (let ((user (gethash "runAsUser" effective))
          (where (format nil "(pod: ~S, container: ~A)"
                         (format nil "~A_~A(~A)" (pod-name pod) (pod-namespace pod) (pod-uid pod))
                         (container-spec-name container))))
      (cond
        (user
         (when (eql 0 user) (container-config-error "container's runAsUser breaks non-root policy ~A" where)))
        (t
         (multiple-value-bind (uid username) (if image-user (funcall image-user) (values nil ""))
           (cond ((and (null uid) (plusp (length username)))
                  (container-config-error "container has runAsNonRoot and image has non-numeric user (~A), cannot verify user is non-root ~A"
                                          username where))
                 ((or (null uid) (eql 0 uid))
                  (container-config-error "container has runAsNonRoot and image will run as root ~A" where))
                 ((not (<= 1 uid 2147483647))
                  (container-config-error "container has runAsNonRoot and image has an invalid user id (~D). (Must be 1-(2147483647)) ~A"
                                          uid where)))))))))

(defun containerd-pod-security-context (pod container &key target-id image-user userns)
  "Map effective Pod/container Linux identities, confinement and privileges to the CRI API.
TARGET-ID names the running container whose PID namespace an ephemeral container joins;
IMAGE-USER reports the user the container's image runs as, for runAsNonRoot."
  (let* ((pod-context (gethash "securityContext" (gethash "spec" (pod-to-object pod))))
         (container-context (gethash "securityContext" (pod-runtime-container-object pod container)))
         (effective (core-object)))
    (dolist (context (list pod-context container-context))
      (when context (maphash (lambda (key value) (setf (gethash key effective) value)) context)))
    (let ((user (gethash "runAsUser" effective)) (group (gethash "runAsGroup" effective)))
      (verify-run-as-non-root pod container effective image-user)
      (make-instance
       'gr8s.cri.v1::linux-container-security-context
       :run-as-user (when user (make-instance 'gr8s.cri.v1::int64value :value user))
       :run-as-group (when group (make-instance 'gr8s.cri.v1::int64value :value group))
       :supplemental-groups (pod-supplemental-groups pod)
       :supplemental-groups-policy (cri-supplemental-groups-policy pod-context)
       :seccomp (cri-seccomp-profile effective)
       :apparmor (cri-apparmor-profile effective)
       :selinux-options (cri-selinux-options effective)
       :namespace-options (make-instance
                           'gr8s.cri.v1::namespace-option
                           :pid (if (and target-id (= (pod-pid-namespace-mode pod)
                                                      gr8s.cri.v1::+namespacemode-container+))
                                    gr8s.cri.v1::+namespacemode-target+
                                    (pod-pid-namespace-mode pod))
                           :target-id (or target-id "")
                           :ipc (if (pod-spec-flag-p pod "hostIPC") gr8s.cri.v1::+namespacemode-node+ gr8s.cri.v1::+namespacemode-pod+)
                           :network (if (pod-host-network-p pod) gr8s.cri.v1::+namespacemode-node+ gr8s.cri.v1::+namespacemode-pod+)
                           ;; A container must name its sandbox's user namespace, as the kubelet passes it to both.
                           :userns-options userns)
       :capabilities (let ((capabilities (gethash "capabilities" effective)))
                       (when capabilities
                         (make-instance 'gr8s.cri.v1::capability
                                        :add-capabilities (coerce (gethash "add" capabilities #()) 'list)
                                        :drop-capabilities (coerce (gethash "drop" capabilities #()) 'list))))
       :privileged (eq t (gethash "privileged" effective))
       :readonly-rootfs (eq t (gethash "readOnlyRootFilesystem" effective))
       :no-new-privs (and (nth-value 1 (gethash "allowPrivilegeEscalation" effective))
                          (null (gethash "allowPrivilegeEscalation" effective)))))))
