;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Discover kubelet DRA plugins through the shared node plugin registry.

(in-package #:gr8s.kubelet)

(defstruct dra-plugin name endpoint socket socket-inode)

(defstruct dra-prepared-claim
  namespace name uid
  (pod-uids (make-hash-table :test #'equal))
  (driver-devices (make-hash-table :test #'equal)))

(defstruct (dra-manager (:constructor %make-dra-manager))
  store state-directory
  (claims (make-hash-table :test #'equal))
  (lock (bt:make-lock "gr8s DRA manager")))

(defvar *dra-plugins* (make-hash-table :test #'equal)
  "Registered DRA drivers on this agent, by driver name.")
(defvar *dra-plugins-lock* (bt:make-lock "gr8s DRA plugins"))

(defparameter *dra-rpc-timeout-seconds* 120)

(defun %call-dra-endpoint (plugin operation request)
  "Call OPERATION on PLUGIN's kubelet DRA endpoint."
  (let ((channel (make-unix-grpc-channel (dra-plugin-endpoint plugin)
                                         :timeout *dra-rpc-timeout-seconds*)))
    (unwind-protect
         (multiple-value-bind (response status)
             (let ((stub (gr8s.dra.v1::make-dra-plugin-stub channel))
                   (timeout *dra-rpc-timeout-seconds*))
               (ecase operation
                 (:prepare
                  (gr8s.dra.v1::dra-plugin-node-prepare-resources
                   stub request :timeout timeout))
                 (:unprepare
                  (gr8s.dra.v1::dra-plugin-node-unprepare-resources
                   stub request :timeout timeout))))
           (unless (= status ag-grpc:+grpc-status-ok+)
             (error 'runtime-error
                    :message (format nil "DRA ~(~A~) failed with gRPC status ~D (~A)"
                                     operation status (ag-grpc:grpc-status-name status))))
           response)
      (ag-grpc:channel-close channel))))

(defparameter *dra-call* #'%call-dra-endpoint
  "Make a DRA RPC, taking a plugin, operation keyword and request.")

(defun dra-plugin-version-supported-p (versions)
  "Return whether VERSIONS advertises the kubelet DRA v1 protocol."
  (find "v1.DRAPlugin" versions :test #'equal))

(defun register-dra-plugin (socket inode info)
  "Register the DRA driver described by INFO and notify its registrar."
  (flet ((notify (registered &optional (message ""))
           (funcall *csi-call* socket :notify
                    (make-instance 'gr8s.pluginregistration.v1::registration-status
                                   :plugin-registered registered :error message))))
    (handler-case
        (let ((name (gr8s.pluginregistration.v1::name info))
              (endpoint (gr8s.pluginregistration.v1::endpoint info)))
          (unless (equal "DRAPlugin" (gr8s.pluginregistration.v1::proto-plugin-info-type info))
            (error 'runtime-error :message "Plugin type is not DRAPlugin"))
          (unless (csi-driver-name-valid-p name)
            (error 'runtime-error :message "Plugin has an invalid driver name"))
          (unless (dra-plugin-version-supported-p
                   (gr8s.pluginregistration.v1::supported-versions info))
            (error 'runtime-error :message "Plugin supports no DRA v1 version"))
          (unless (storage-absolute-path-p endpoint)
            (error 'runtime-error :message "Plugin endpoint must be an absolute path"))
          (let ((plugin (make-dra-plugin :name name :endpoint endpoint
                                         :socket socket :socket-inode inode)))
            (bt:with-lock-held (*dra-plugins-lock*)
              (setf (gethash name *dra-plugins*) plugin))
            (notify t)
            plugin))
      (error (condition)
        (notify nil (princ-to-string condition))
        (error condition)))))

(defun prune-dra-plugins (sockets)
  "Forget DRA registrations whose registrar socket is absent from SOCKETS."
  (bt:with-lock-held (*dra-plugins-lock*)
    (loop for plugin being the hash-values of *dra-plugins* using (hash-key name)
          unless (assoc (dra-plugin-socket plugin) sockets :test #'equal)
            collect name into gone
          finally (dolist (entry gone) (remhash entry *dra-plugins*)))))

(defun dra-plugin-socket-known-p (socket inode)
  "Return whether SOCKET and INODE identify an unchanged DRA registration."
  (bt:with-lock-held (*dra-plugins-lock*)
    (loop for plugin being the hash-values of *dra-plugins*
          thereis (and (equal socket (dra-plugin-socket plugin))
                       (eql inode (dra-plugin-socket-inode plugin))))))

(register-kubelet-plugin-handler "DRAPlugin" #'register-dra-plugin
                                 #'prune-dra-plugins #'dra-plugin-socket-known-p)

(defun dra-checkpoint-path (state-directory)
  "Return the durable prepared-claim checkpoint below STATE-DIRECTORY."
  (merge-pathnames "dra/prepared-claims.json"
                   (uiop:ensure-directory-pathname state-directory)))

(defun dra-device-checkpoint-object (device)
  "Encode a driver-returned DRA DEVICE for the node checkpoint."
  (core-object "requestNames" (coerce (gr8s.dra.v1::request-names device) 'vector)
               "poolName" (gr8s.dra.v1::pool-name device)
               "deviceName" (gr8s.dra.v1::device-name device)
               "cdiDeviceIDs" (coerce (gr8s.dra.v1::cdi-device-ids device) 'vector)
               "shareID" (gr8s.dra.v1::share-id device)))

(defun dra-prepared-claim-checkpoint-object (prepared)
  "Encode PREPARED without depending on live API objects or plugin sockets."
  (let ((drivers (core-object)))
    (loop for driver being the hash-keys of (dra-prepared-claim-driver-devices prepared)
            using (hash-value devices)
          do (setf (gethash driver drivers)
                   (coerce (mapcar #'dra-device-checkpoint-object devices) 'vector)))
    (core-object
     "namespace" (dra-prepared-claim-namespace prepared)
     "name" (dra-prepared-claim-name prepared)
     "uid" (dra-prepared-claim-uid prepared)
     "podUIDs" (coerce (loop for uid being the hash-keys of
                               (dra-prepared-claim-pod-uids prepared)
                             collect uid)
                        'vector)
     "drivers" drivers)))

(defun save-dra-checkpoint (manager)
  "Atomically checkpoint MANAGER while its lock is held."
  (let* ((path (dra-checkpoint-path (dra-manager-state-directory manager)))
         (temporary
           (make-pathname :name (format nil "prepared-claims-~36R" (random (expt 36 10)))
                          :type "tmp" :defaults path))
         (root
           (core-object
            "version" 1
            "claims" (coerce
                      (loop for prepared being the hash-values of
                              (dra-manager-claims manager)
                            collect (dra-prepared-claim-checkpoint-object prepared))
                      'vector))))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (with-open-file (out temporary :direction :output :if-exists :supersede
                                          :if-does-not-exist :create)
             (com.inuoe.jzon:stringify root :stream out))
           (uiop:rename-file-overwriting-target temporary path))
      (when (probe-file temporary) (delete-file temporary)))))

(defun dra-device-from-checkpoint (object)
  "Decode one driver-returned DRA device from OBJECT."
  (make-instance 'gr8s.dra.v1::device
                 :request-names (coerce (gethash "requestNames" object #()) 'list)
                 :pool-name (gethash "poolName" object "")
                 :device-name (gethash "deviceName" object "")
                 :cdi-device-ids (coerce (gethash "cdiDeviceIDs" object #()) 'list)
                 :share-id (gethash "shareID" object "")))

(defun dra-prepared-claim-from-checkpoint (object)
  "Decode one prepared claim, rejecting checkpoint entries without identity."
  (let* ((namespace (gethash "namespace" object))
         (name (gethash "name" object))
         (uid (gethash "uid" object))
         (prepared (make-dra-prepared-claim :namespace namespace :name name :uid uid)))
    (unless (and (stringp namespace) (stringp name) (stringp uid)
                 (hash-table-p (gethash "drivers" object)))
      (error 'runtime-error :message "Invalid DRA prepared-claim checkpoint"))
    (loop for pod-uid across (gethash "podUIDs" object #())
          do (setf (gethash pod-uid (dra-prepared-claim-pod-uids prepared)) t))
    (loop for driver being the hash-keys of (gethash "drivers" object)
            using (hash-value devices)
          do (setf (gethash driver (dra-prepared-claim-driver-devices prepared))
                   (loop for device across devices
                         collect (dra-device-from-checkpoint device))))
    prepared))

(defun load-dra-checkpoint (state-directory)
  "Load prepared claims from STATE-DIRECTORY, or return an empty registry."
  (let ((claims (make-hash-table :test #'equal))
        (path (dra-checkpoint-path state-directory)))
    (when (probe-file path)
      (let ((root (com.inuoe.jzon:parse path)))
        (unless (and (hash-table-p root) (eql 1 (gethash "version" root))
                     (vectorp (gethash "claims" root)))
          (error 'runtime-error :message "Invalid DRA checkpoint"))
        (loop for object across (gethash "claims" root)
              for prepared = (dra-prepared-claim-from-checkpoint object)
              do (setf (gethash
                         (core-resource-key "resourceclaims"
                                            (dra-prepared-claim-namespace prepared)
                                            (dra-prepared-claim-name prepared))
                         claims)
                       prepared))))
    claims))

(defun make-dra-manager (store state-directory)
  "Create a node DRA manager for STORE with checkpoint state under STATE-DIRECTORY."
  (%make-dra-manager :store store
                     :state-directory (uiop:ensure-directory-pathname state-directory)
                     :claims (load-dra-checkpoint state-directory)))

(defun dra-plugin-for (driver)
  "Return DRIVER's registered DRA plugin or signal a runtime error."
  (or (bt:with-lock-held (*dra-plugins-lock*) (gethash driver *dra-plugins*))
      (error 'runtime-error
             :message (format nil "DRA driver ~A is not registered on this node" driver))))

(defun pod-resource-claim-name (pod pod-claim)
  "Resolve POD-CLAIM's direct or template-generated ResourceClaim name."
  (or (gethash "resourceClaimName" pod-claim)
      (let* ((status (gethash "status" (pod-to-object pod)))
             (entries (and status (gethash "resourceClaimStatuses" status #())))
             (entry (and entries
                         (find (gethash "name" pod-claim) entries :test #'equal
                               :key (lambda (candidate) (gethash "name" candidate))))))
        (and entry (gethash "resourceClaimName" entry)))))

(defun pod-resource-claim-pairs (pod)
  "Return (logical-name . ResourceClaim-name) pairs resolved for POD."
  (loop for pod-claim across (gethash "resourceClaims" (gethash "spec" (pod-to-object pod)) #())
        for claim-name = (pod-resource-claim-name pod pod-claim)
        when claim-name
          collect (cons (gethash "name" pod-claim) claim-name)))

(defun dra-claim-reserved-for-pod-p (claim pod)
  "Return whether CLAIM's status reserves it for POD's exact UID."
  (some (lambda (reference)
          (and (equal "pods" (gethash "resource" reference))
               (equal (pod-name pod) (gethash "name" reference))
               (equal (pod-uid pod) (gethash "uid" reference))))
        (gethash "reservedFor" (gethash "status" claim (core-object)) #())))

(defun dra-claim-allocation-results (claim)
  "Return CLAIM's allocated device results, or NIL when it is unallocated."
  (let ((allocation (gethash "allocation" (gethash "status" claim (core-object)))))
    (and allocation
         (gethash "results" (gethash "devices" allocation (core-object)) #()))))

(defun dra-rpc-claim (claim)
  "Build a kubelet DRA Claim message for CLAIM."
  (let ((metadata (gethash "metadata" claim)))
    (make-instance 'gr8s.dra.v1::claim
                   :namespace (gethash "namespace" metadata)
                   :name (gethash "name" metadata)
                   :uid (gethash "uid" metadata))))

(defun prepare-dra-claim (manager pod claim)
  "Prepare CLAIM for POD and cache the driver's authoritative CDI devices."
  (let* ((metadata (gethash "metadata" claim))
         (namespace (gethash "namespace" metadata))
         (name (gethash "name" metadata))
         (uid (gethash "uid" metadata))
         (results (dra-claim-allocation-results claim))
         (drivers (remove-duplicates
                   (loop for result across results collect (gethash "driver" result))
                   :test #'equal))
         (key (core-resource-key "resourceclaims" namespace name)))
    (unless (and uid results)
      (error 'runtime-error :message (format nil "ResourceClaim ~A is not allocated" name)))
    (unless (dra-claim-reserved-for-pod-p claim pod)
      (error 'runtime-error
             :message (format nil "ResourceClaim ~A is not reserved for Pod ~A"
                              name (pod-name pod))))
    (let ((cached nil))
      (bt:with-lock-held ((dra-manager-lock manager))
        (setf cached (gethash key (dra-manager-claims manager)))
        (when cached
          (unless (equal uid (dra-prepared-claim-uid cached))
            (error 'runtime-error
                   :message (format nil "ResourceClaim ~A was replaced with a different UID" name)))
          (setf (gethash (pod-uid pod) (dra-prepared-claim-pod-uids cached)) t)
          (save-dra-checkpoint manager)))
      (when cached
        (return-from prepare-dra-claim cached)))
    (let ((prepared (make-dra-prepared-claim :namespace namespace :name name :uid uid)))
      (dolist (driver drivers)
        (let* ((plugin (dra-plugin-for driver))
               (response
                 (funcall *dra-call* plugin :prepare
                          (make-instance 'gr8s.dra.v1::node-prepare-resources-request
                                         :claims (list (dra-rpc-claim claim)))))
               (entry (assoc uid (gr8s.dra.v1::claims response) :test #'equal)))
          (unless entry
            (error 'runtime-error
                   :message (format nil "DRA driver ~A skipped ResourceClaim ~A" driver name)))
          (let ((result (cdr entry)))
            (when (plusp (length (slot-value result 'gr8s.dra.v1::proto-error)))
              (error 'runtime-error :message (slot-value result 'gr8s.dra.v1::proto-error)))
            (setf (gethash driver (dra-prepared-claim-driver-devices prepared))
                  (copy-list (gr8s.dra.v1::devices result))))))
      (setf (gethash (pod-uid pod) (dra-prepared-claim-pod-uids prepared)) t)
      (bt:with-lock-held ((dra-manager-lock manager))
        (setf (gethash key (dra-manager-claims manager)) prepared)
        (save-dra-checkpoint manager))
      prepared)))

(defun prepare-pod-dynamic-resources (manager pod)
  "Prepare all allocated ResourceClaims referenced by POD."
  (dolist (pair (pod-resource-claim-pairs pod))
    (prepare-dra-claim
     manager pod
     (get-core-resource (dra-manager-store manager) "resourceclaims"
                        (pod-namespace pod) (cdr pair))))
  t)

(defun dra-rpc-prepared-claim (prepared)
  "Build a kubelet DRA Claim message from PREPARED's checkpointed identity."
  (make-instance 'gr8s.dra.v1::claim
                 :namespace (dra-prepared-claim-namespace prepared)
                 :name (dra-prepared-claim-name prepared)
                 :uid (dra-prepared-claim-uid prepared)))

(defun unprepare-dra-claim (manager key prepared pod-uid)
  "Release POD-UID's reference to PREPARED, unpreparing its last reference."
  (let ((pod-uids (dra-prepared-claim-pod-uids prepared)))
    (when (gethash pod-uid pod-uids)
      (if (> (hash-table-count pod-uids) 1)
          (progn
            (remhash pod-uid pod-uids)
            (save-dra-checkpoint manager))
          (progn
            (loop for driver being the hash-keys of
                    (dra-prepared-claim-driver-devices prepared)
                  for response =
                    (funcall *dra-call* (dra-plugin-for driver) :unprepare
                             (make-instance
                              'gr8s.dra.v1::node-unprepare-resources-request
                              :claims (list (dra-rpc-prepared-claim prepared))))
                  for entry = (assoc (dra-prepared-claim-uid prepared)
                                     (gr8s.dra.v1::claims response) :test #'equal)
                  do (unless entry
                       (error 'runtime-error
                              :message
                              (format nil "DRA driver ~A skipped ResourceClaim ~A"
                                      driver (dra-prepared-claim-name prepared))))
                     (let ((message
                             (slot-value
                              (cdr entry)
                              'gr8s.dra.v1::proto-error)))
                       (when (plusp (length message))
                         (error 'runtime-error :message message))))
            (remhash key (dra-manager-claims manager))
            (save-dra-checkpoint manager))))))

(defun unprepare-pod-dynamic-resources (manager pod)
  "Release POD's prepared claims and notify each driver after the last user."
  (bt:with-lock-held ((dra-manager-lock manager))
    (let ((pod-uid (pod-uid pod))
          (claims
            (loop for prepared being the hash-values of (dra-manager-claims manager)
                    using (hash-key key)
                  when (gethash (pod-uid pod)
                                (dra-prepared-claim-pod-uids prepared))
                    collect (cons key prepared))))
      (dolist (entry claims)
        (unprepare-dra-claim manager (car entry) (cdr entry) pod-uid))))
  t)

(defun dra-request-matches-p (configured prepared)
  "Return whether PREPARED request name satisfies CONFIGURED's scope."
  (or (null configured)
      (equal configured "")
      (equal configured prepared)
      (uiop:string-prefix-p (format nil "~A/" configured) prepared)))

(defun container-dra-cdi-device-ids (manager pod container)
  "Return CDI device IDs prepared for CONTAINER's ResourceClaim requests."
  (let ((claim-names (pod-resource-claim-pairs pod)) (result nil))
    (loop for reference across (gethash "claims" (gethash "resources" container (core-object)) #())
          for claim-name = (cdr (assoc (gethash "name" reference) claim-names :test #'equal))
          for prepared = (and claim-name
                              (bt:with-lock-held ((dra-manager-lock manager))
                                (gethash (core-resource-key "resourceclaims" (pod-namespace pod)
                                                           claim-name)
                                         (dra-manager-claims manager))))
          do (unless prepared
               (error 'runtime-error
                      :message (format nil "ResourceClaim ~A is not prepared" claim-name)))
             (loop for devices being the hash-values of (dra-prepared-claim-driver-devices prepared)
                   do (dolist (device devices)
                        (let ((requests (gr8s.dra.v1::request-names device)))
                          (when (or (null requests)
                                    (some (lambda (name)
                                            (dra-request-matches-p (gethash "request" reference) name))
                                          requests))
                            (setf result (append result
                                                 (gr8s.dra.v1::cdi-device-ids device))))))))
    (remove-duplicates result :test #'equal)))
