;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Do a kubelet's half of CSI: find drivers through the plugin registry, then stage
;;;; and publish their volumes for a node's Pods, and undo that when each Pod ends.
;;;; Paths match the kubelet's, because driver manifests mount them by that name.

(in-package #:gr8s)

(defparameter *csi-kubelet-root* "/var/lib/kubelet/"
  "Where drivers expect the kubelet's plugin registry, staging and Pod directories.")

(defparameter *csi-rpc-timeout-seconds* 120)

(defstruct csi-plugin
  name endpoint socket socket-inode node-id max-volumes topology stage-unstage-p)

(defvar *csi-plugins* (make-hash-table :test #'equal)
  "Registered drivers on this agent, by name.")
(defvar *csi-plugins-lock* (bt:make-lock "gr8s CSI plugins"))

(defun %call-csi-endpoint (socket operation request)
  "Make one CSI or registration RPC on the Unix SOCKET, returning its response."
  (let ((channel (make-unix-grpc-channel socket :timeout *csi-rpc-timeout-seconds*)))
    (unwind-protect
         (multiple-value-bind (response status)
             (let ((timeout *csi-rpc-timeout-seconds*))
               (flet ((node (function)
                        (funcall function (gr8s.csi.v1::make-node-stub channel) request :timeout timeout))
                      (registration (function)
                        (funcall function (gr8s.pluginregistration.v1::make-registration-stub channel)
                                 request :timeout timeout)))
                 (ecase operation
                   (:get-info (registration #'gr8s.pluginregistration.v1::registration-get-info))
                   (:notify (registration #'gr8s.pluginregistration.v1::registration-notify-registration-status))
                   (:node-get-info (node #'gr8s.csi.v1::node-node-get-info))
                   (:node-capabilities (node #'gr8s.csi.v1::node-node-get-capabilities))
                   (:stage (node #'gr8s.csi.v1::node-node-stage-volume))
                   (:unstage (node #'gr8s.csi.v1::node-node-unstage-volume))
                   (:publish (node #'gr8s.csi.v1::node-node-publish-volume))
                   (:unpublish (node #'gr8s.csi.v1::node-node-unpublish-volume)))))
           (unless (= status ag-grpc:+grpc-status-ok+)
             (error 'runtime-error
                    :message (format nil "CSI ~(~A~) failed with gRPC status ~D (~A)"
                                     operation status (ag-grpc:grpc-status-name status))))
           response)
      (ag-grpc:channel-close channel))))

(defparameter *csi-call* #'%call-csi-endpoint
  "Make a CSI RPC, taking the socket, an operation keyword and the request.")

(defun csi-kubelet-path (control &rest arguments)
  (concatenate 'string *csi-kubelet-root* (apply #'format nil control arguments)))

(defun csi-registry-sockets ()
  "Return (PATH . INODE) for each socket node-driver-registrar has placed in the registry."
  (let ((directory (csi-kubelet-path "plugins_registry")))
    (when (ignore-errors (sb-posix:stat directory))
      (let ((handle (sb-posix:opendir directory)))
        (unwind-protect
             (loop for entry = (sb-posix:readdir handle)
                   until (sb-alien:null-alien entry)
                   for name = (sb-posix:dirent-name entry)
                   for path = (format nil "~A/~A" directory name)
                   for stat = (ignore-errors (sb-posix:lstat path))
                   when (and stat (= sb-posix:s-ifsock (logand (sb-posix:stat-mode stat) sb-posix:s-ifmt)))
                     collect (cons path (sb-posix:stat-ino stat)))
          (sb-posix:closedir handle))))))

(defun csi-plugin-version-supported-p (versions)
  (some (lambda (version) (uiop:string-prefix-p "1." version)) versions))

(defun register-csi-plugin (socket inode)
  "Register the driver behind one registry SOCKET, telling it whether that worked."
  (let ((info (funcall *csi-call* socket :get-info (make-instance 'gr8s.pluginregistration.v1::info-request))))
    (flet ((notify (registered &optional (message ""))
             (funcall *csi-call* socket :notify
                      (make-instance 'gr8s.pluginregistration.v1::registration-status
                                     :plugin-registered registered :error message))))
      (handler-case
          (let ((name (gr8s.pluginregistration.v1::name info))
                (endpoint (gr8s.pluginregistration.v1::endpoint info)))
            (unless (equal "CSIPlugin" (gr8s.pluginregistration.v1::proto-plugin-info-type info))
              (error 'runtime-error :message "Plugin type is not CSIPlugin"))
            (unless (csi-driver-name-valid-p name)
              (error 'runtime-error :message "Plugin has an invalid driver name"))
            (unless (csi-plugin-version-supported-p (gr8s.pluginregistration.v1::supported-versions info))
              (error 'runtime-error :message "Plugin supports no CSI 1.x version"))
            (unless (storage-absolute-path-p endpoint)
              (error 'runtime-error :message "Plugin endpoint must be an absolute path"))
            (let* ((node-info (funcall *csi-call* endpoint :node-get-info
                                       (make-instance 'gr8s.csi.v1::node-get-info-request)))
                   (capabilities (funcall *csi-call* endpoint :node-capabilities
                                          (make-instance 'gr8s.csi.v1::node-get-capabilities-request)))
                   (topology (gr8s.csi.v1::accessible-topology node-info))
                   (plugin (make-csi-plugin
                            :name name :endpoint endpoint :socket socket :socket-inode inode
                            :node-id (gr8s.csi.v1::node-id node-info)
                            :max-volumes (gr8s.csi.v1::max-volumes-per-node node-info)
                            :topology (and topology (gr8s.csi.v1::segments topology))
                            :stage-unstage-p
                            (some (lambda (capability)
                                    (let ((rpc (gr8s.csi.v1::rpc capability)))
                                      (and rpc (eql 1 (gr8s.csi.v1::proto-rpc-type rpc)))))
                                  (gr8s.csi.v1::capabilities capabilities)))))
              (bt:with-lock-held (*csi-plugins-lock*)
                (setf (gethash name *csi-plugins*) plugin))
              (notify t)
              plugin))
        (error (condition)
          (notify nil (princ-to-string condition))
          (error condition))))))

(defun scan-csi-plugin-registry ()
  "Register new or restarted drivers and forget those whose registry socket has gone."
  (let ((sockets (csi-registry-sockets)))
    (bt:with-lock-held (*csi-plugins-lock*)
      (loop for plugin being the hash-values of *csi-plugins* using (hash-key name)
            unless (assoc (csi-plugin-socket plugin) sockets :test #'equal)
              collect name into gone
            finally (dolist (entry gone) (remhash entry *csi-plugins*))))
    (loop for (socket . inode) in sockets
          unless (bt:with-lock-held (*csi-plugins-lock*)
                   (loop for plugin being the hash-values of *csi-plugins*
                         thereis (and (equal socket (csi-plugin-socket plugin))
                                      (eql inode (csi-plugin-socket-inode plugin)))))
            do (handler-case (register-csi-plugin socket inode)
                 (error (condition)
                   (format *error-output* "gr8s CSI plugin at ~A did not register: ~A~%" socket condition))))))

(defun csi-driver-registrations ()
  "Describe registered drivers for the agent's report to the control plane."
  (bt:with-lock-held (*csi-plugins-lock*)
    (sort (loop for plugin being the hash-values of *csi-plugins*
                collect (make-instance 'gr8s.node.v1::csi-driver-registration
                                       :name (csi-plugin-name plugin)
                                       :node-id (csi-plugin-node-id plugin)
                                       :max-volumes (or (csi-plugin-max-volumes plugin) 0)
                                       :topology (csi-plugin-topology plugin)))
          #'string< :key (lambda (registration) (slot-value registration 'gr8s.node.v1::name)))))

(defun csi-plugin-for (driver)
  (or (bt:with-lock-held (*csi-plugins-lock*) (gethash driver *csi-plugins*))
      (error 'runtime-error :message (format nil "CSI driver ~A is not registered on this node" driver))))

(defun csi-volume-directory (uid name)
  (csi-kubelet-path "pods/~A/volumes/kubernetes.io~~csi/~A/" uid name))

(defun csi-staging-path (driver handle)
  "Return the one staging path all of a node's Pods share for a volume."
  (csi-kubelet-path "plugins/kubernetes.io/csi/~A/~A/globalmount" driver
                    (string-downcase
                     (octets-to-hex
                      (ironclad:digest-sequence :sha256 (trivial-utf-8:string-to-utf-8-bytes handle))))))

(defun csi-access-mode (modes)
  "Map Kubernetes access modes to the CSI mode that promises the most sharing asked for."
  (flet ((has (mode) (find mode modes :test #'equal)))
    (cond ((has "ReadWriteMany") 5)
          ((has "ReadOnlyMany") 3)
          (t 1))))

(defun csi-volume-capability (fs-type mount-flags access-mode)
  (let ((capability
          (make-instance 'gr8s.csi.v1::volume-capability
                         :mount (make-instance 'gr8s.csi.v1::mount-volume
                                               :fs-type (or fs-type "")
                                               :mount-flags (coerce (or mount-flags #()) 'list))
                         :access-mode (make-instance 'gr8s.csi.v1::access-mode :mode access-mode))))
    (setf (gr8s.csi.v1::access-type-case capability) :mount)
    capability))

(defun csi-hash-alist (table)
  "Convert a JSON string map into the alist the generated CSI messages use."
  (when table (loop for key being the hash-keys of table using (hash-value value) collect (cons key value))))

(defun csi-secret-data (store reference namespace)
  "Decode a Secret named by a CSI secret reference, as drivers expect."
  (when reference
    (let* ((secret (handler-case
                       (get-core-resource store "secrets" (gethash "namespace" reference namespace) (gethash "name" reference))
                     (kubernetes-error ()
                       (error 'runtime-error :message "A CSI volume's Secret is not available to this node"))))
           (data (gethash "data" secret)))
      (when data
        (loop for key being the hash-keys of data using (hash-value value)
              collect (cons key (trivial-utf-8:utf-8-bytes-to-string (core-base64-bytes value "CSI secret"))))))))

(defun csi-pod-context (pod)
  "Describe the consuming Pod, as a kubelet does for drivers that ask."
  (list (cons "csi.storage.k8s.io/pod.name" (pod-name pod))
        (cons "csi.storage.k8s.io/pod.namespace" (pod-namespace pod))
        (cons "csi.storage.k8s.io/pod.uid" (pod-uid pod))
        (cons "csi.storage.k8s.io/serviceAccount.name"
              (gethash "serviceAccountName" (gethash "spec" (pod-to-object pod)) "default"))))

(defun write-csi-volume-record (directory record)
  "Record a published volume durably first, so a crash can't lose how to undo it."
  (ensure-directories-exist directory)
  (with-open-file (stream (concatenate 'string directory "vol_data.json")
                          :direction :output :if-exists :supersede)
    (com.inuoe.jzon:stringify record :stream stream)))

(defun publish-csi-volume (pod name &key driver handle fs-type mount-flags access-mode attributes
                                      publish-context stage-secrets publish-secrets readonly)
  "Stage and publish one volume for POD, returning the path to bind into its containers."
  (let* ((plugin (csi-plugin-for driver))
         (directory (csi-volume-directory (pod-uid pod) name))
         (target (concatenate 'string directory "mount"))
         (capability (csi-volume-capability fs-type mount-flags access-mode))
         (staging (and (csi-plugin-stage-unstage-p plugin) (csi-staging-path driver handle))))
    (unless (nfs-target-mounted-p target)
      (write-csi-volume-record directory (core-object "driver" driver "volumeHandle" handle
                                                      "targetPath" target "stagingPath" (or staging "")))
      (when staging
        (ensure-directories-exist (uiop:ensure-directory-pathname staging))
        (funcall *csi-call* (csi-plugin-endpoint plugin) :stage
                 (make-instance 'gr8s.csi.v1::node-stage-volume-request
                                :volume-id handle :publish-context publish-context
                                :staging-target-path staging :volume-capability capability
                                :secrets stage-secrets :volume-context attributes)))
      (funcall *csi-call* (csi-plugin-endpoint plugin) :publish
               (make-instance 'gr8s.csi.v1::node-publish-volume-request
                              :volume-id handle :publish-context publish-context
                              :staging-target-path (or staging "") :target-path target
                              :volume-capability capability :readonly (not (null readonly))
                              :secrets publish-secrets :volume-context attributes)))
    (uiop:ensure-directory-pathname target)))

(defun materialize-persistent-csi-volume (store pod name volume)
  "Publish a bound CSI PV once its required attachment has succeeded."
  (let* ((spec (gethash "spec" volume)) (source (gethash "csi" spec))
         (driver (gethash "driver" source)) (handle (gethash "volumeHandle" source))
         (driver-object (handler-case (get-core-resource store "csidrivers" nil driver)
                          (kubernetes-error () nil)))
         (attach-required (or (null driver-object)
                              (not (eq nil (gethash "attachRequired" (gethash "spec" driver-object) t)))))
         (attachment (when attach-required
                       (handler-case
                           (get-core-resource store "volumeattachments" nil
                                              (volume-attachment-name driver handle (or (pod-node-name pod) "")))
                         (kubernetes-error () nil))))
         (status (and attachment (gethash "status" attachment))))
    (when (and attach-required (not (and status (eq t (gethash "attached" status)))))
      (error 'runtime-error :message (format nil "CSI volume ~A is not attached to this node yet" handle)))
    (let ((readonly (eq t (gethash "readOnly" source))))
      (values
       (publish-csi-volume
        pod name :driver driver :handle handle :fs-type (gethash "fsType" source)
        :mount-flags (gethash "mountOptions" spec)
        :access-mode (csi-access-mode (gethash "accessModes" spec))
        :attributes (append (csi-hash-alist (gethash "volumeAttributes" source)) (csi-pod-context pod)
                            (list (cons "csi.storage.k8s.io/ephemeral" "false")))
        :publish-context (and status (csi-hash-alist (gethash "attachmentMetadata" status)))
        :stage-secrets (csi-secret-data store (gethash "nodeStageSecretRef" source) nil)
        :publish-secrets (csi-secret-data store (gethash "nodePublishSecretRef" source) nil)
        :readonly readonly)
       readonly))))

(defun materialize-inline-csi-volume (store pod volume)
  "Publish a Pod's inline volume, which lives exactly as long as that Pod."
  (let* ((name (gethash "name" volume)) (source (gethash "csi" volume))
         (driver (gethash "driver" source))
         (driver-object (handler-case (get-core-resource store "csidrivers" nil driver)
                          (kubernetes-error ()
                            (error 'runtime-error :message (format nil "CSIDriver ~A does not exist" driver))))))
    (unless (find "Ephemeral" (gethash "volumeLifecycleModes" (gethash "spec" driver-object) #()) :test #'equal)
      (error 'runtime-error :message (format nil "CSIDriver ~A does not support inline volumes" driver)))
    (let ((readonly (eq t (gethash "readOnly" source))))
      (values
       (publish-csi-volume
        pod name :driver driver
        :handle (format nil "csi-~A"
                        (string-downcase
                         (octets-to-hex
                          (ironclad:digest-sequence
                           :sha256 (trivial-utf-8:string-to-utf-8-bytes
                                    (format nil "~A~A" (pod-uid pod) name))))))
        :fs-type (gethash "fsType" source) :access-mode 1
        :attributes (append (csi-hash-alist (gethash "volumeAttributes" source)) (csi-pod-context pod)
                            (list (cons "csi.storage.k8s.io/ephemeral" "true")))
        :publish-secrets (csi-secret-data store (gethash "nodePublishSecretRef" source) (pod-namespace pod))
        :readonly readonly)
       readonly))))

(defun csi-volume-records ()
  "Return (DIRECTORY . RECORD) for every volume this node has published, across all Pods."
  (loop for path in (ignore-errors (directory (csi-kubelet-path "pods/*/volumes/kubernetes.io~~csi/*/vol_data.json")))
        for record = (ignore-errors (com.inuoe.jzon:parse path))
        when record
          collect (cons (namestring (uiop:pathname-directory-pathname path)) record)))

(defun cleanup-pod-csi-volumes (uid)
  "Unpublish UID's CSI volumes, unstaging each one no other Pod still uses.
A failure leaves the record behind, so the Pod's deletion retries it."
  (let* ((prefix (csi-kubelet-path "pods/~A/" uid))
         (records (csi-volume-records))
         (own (remove-if-not (lambda (entry) (uiop:string-prefix-p prefix (car entry))) records)))
    (loop for (directory . record) in own
          do (let* ((plugin (csi-plugin-for (gethash "driver" record)))
                    (handle (gethash "volumeHandle" record))
                    (staging (gethash "stagingPath" record "")))
               (funcall *csi-call* (csi-plugin-endpoint plugin) :unpublish
                        (make-instance 'gr8s.csi.v1::node-unpublish-volume-request
                                       :volume-id handle :target-path (gethash "targetPath" record)))
               (when (and (plusp (length staging))
                          (notany (lambda (entry)
                                    (and (not (equal directory (car entry)))
                                         (not (uiop:string-prefix-p prefix (car entry)))
                                         (equal staging (gethash "stagingPath" (cdr entry)))))
                                  records))
                 (funcall *csi-call* (csi-plugin-endpoint plugin) :unstage
                          (make-instance 'gr8s.csi.v1::node-unstage-volume-request
                                         :volume-id handle :staging-target-path staging)))
               (delete-file (concatenate 'string directory "vol_data.json"))
               ;; rmdir only: anything still inside belongs to the driver, not to us.
               (ignore-errors (sb-posix:rmdir (concatenate 'string directory "mount")))
               (ignore-errors (sb-posix:rmdir directory))))
    (dolist (relative '("volumes/kubernetes.io~csi/" "volumes/" ""))
      (ignore-errors (sb-posix:rmdir (concatenate 'string prefix relative))))))
