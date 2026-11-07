;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Serve the storage.k8s.io objects CSI drivers and their sidecars read and write.
;;;; Their leader-election Leases are served with the other typed APIs.

(in-package #:gr8s)

(eval-when (:load-toplevel :execute)
  (dolist (type '(("csidrivers" "CSIDriver" "storage.k8s.io/v1" nil)
                  ("csinodes" "CSINode" "storage.k8s.io/v1" nil)
                  ("volumeattachments" "VolumeAttachment" "storage.k8s.io/v1" nil)
                  ("csistoragecapacities" "CSIStorageCapacity" "storage.k8s.io/v1" t)))
    (setf *stored-resource-types*
          (append (remove (first type) *stored-resource-types* :key #'first :test #'equal) (list type)))))

(defun csi-storage-resource-p (resource)
  "Return whether RESOURCE is a storage.k8s.io object that describes CSI state."
  (member resource '("csidrivers" "csinodes" "volumeattachments" "csistoragecapacities") :test #'equal))

(defun csi-driver-name-valid-p (name)
  "Accept a CSI driver name: a DNS subdomain of at most 63 characters."
  (and (stringp name) (<= 1 (length name) 63) (dns-subdomain-p name)))

(defun require-csi-driver-name (name context)
  "Signal a 422 Invalid error naming CONTEXT unless NAME is a valid CSI driver
   name (a DNS subdomain of at most 63 characters). Returns NIL when it accepts."
  (unless (csi-driver-name-valid-p name)
    (core-resource-error 422 "Invalid" "~A must be a CSI driver name" context)))

(defun normalize-csi-driver-spec (spec)
  "Apply CSIDriver defaults, including the attach requirement Kubernetes assumes."
  (multiple-value-bind (value present) (gethash "attachRequired" spec)
    (declare (ignore value))
    (unless present (setf (gethash "attachRequired" spec) t)))
  (multiple-value-bind (value present) (gethash "podInfoOnMount" spec)
    (declare (ignore value))
    (unless present (setf (gethash "podInfoOnMount" spec) nil)))
  (unless (gethash "fsGroupPolicy" spec) (setf (gethash "fsGroupPolicy" spec) "ReadWriteOnceWithFSType"))
  (storage-string-enum (gethash "fsGroupPolicy" spec) '("ReadWriteOnceWithFSType" "File" "None") "spec.fsGroupPolicy")
  (when (zerop (length (gethash "volumeLifecycleModes" spec #())))
    (setf (gethash "volumeLifecycleModes" spec) (vector "Persistent")))
  (loop for mode across (gethash "volumeLifecycleModes" spec)
        do (storage-string-enum mode '("Persistent" "Ephemeral") "spec.volumeLifecycleModes")))

(defun normalize-csi-storage-object (resource object existing)
  "Validate and default one CSI object, keeping controller-owned attachment status."
  (cond
    ((equal resource "csidrivers")
     (require-csi-driver-name (gethash "name" (gethash "metadata" object)) "metadata.name")
     (normalize-csi-driver-spec (require-object (gethash "spec" object) "spec")))
    ((equal resource "csinodes")
     (loop for driver across (gethash "drivers" (require-object (gethash "spec" object) "spec") #())
           do (require-csi-driver-name (gethash "name" driver) "spec.drivers.name")
              (require-nonempty-string (gethash "nodeID" driver) "spec.drivers.nodeID"))
     (normalize-csi-node-status object existing))
    ((equal resource "volumeattachments")
     (let ((spec (require-object (gethash "spec" object) "spec")))
       (require-csi-driver-name (gethash "attacher" spec) "spec.attacher")
       (require-nonempty-string (gethash "nodeName" spec) "spec.nodeName")
       (let ((source (require-object (gethash "source" spec) "spec.source")))
         (unless (= 1 (count-if (lambda (field) (gethash field source))
                                '("persistentVolumeName" "inlineVolumeSpec")))
           (core-resource-error 422 "Invalid" "spec.source requires exactly one volume source"))))
     (unless *storage-status-write*
       (if (and existing (gethash "status" existing))
           (setf (gethash "status" object) (copy-core-object (gethash "status" existing)))
           (remhash "status" object))))
    ((equal resource "csistoragecapacities")
     (require-nonempty-string (gethash "storageClassName" object) "storageClassName"))))

(defun normalize-csi-node-status (object existing)
  "Keep CSINode status server-owned outside its subresource. storageHealth needs the
alpha CSIVolumeHealth gate, which Kubernetes leaves off, so like Kubernetes it is
dropped unless the stored object already reports some."
  (let ((old (and existing (gethash "status" existing))))
    (if *storage-status-write*
        (let ((status (gethash "status" object)))
          (when (hash-table-p status)
            (when (zerop (length (gethash "storageHealth" (or old (core-object)) #())))
              (remhash "storageHealth" status))
            (when (zerop (hash-table-count status)) (remhash "status" object))))
        (if (and old (plusp (hash-table-count old)))
            (setf (gethash "status" object) (copy-core-object old))
            (remhash "status" object)))))

(defun validate-csi-storage-update (resource before after)
  "Enforce the fields Kubernetes makes immutable on CSI objects."
  (unless *storage-status-write*
    (cond
      ((equal resource "volumeattachments")
       (unless (core-json-equal-p (gethash "spec" before) (gethash "spec" after))
         (core-resource-error 422 "Invalid" "VolumeAttachment spec is immutable")))
      ((equal resource "csidrivers")
       (dolist (field '("attachRequired" "volumeLifecycleModes" "fsGroupPolicy"))
         (unless (core-json-equal-p (gethash field (gethash "spec" before)) (gethash field (gethash "spec" after)))
           (core-resource-error 422 "Invalid" "CSIDriver spec.~A is immutable" field))))
      ((equal resource "csistoragecapacities")
       (unless (equal (gethash "storageClassName" before) (gethash "storageClassName" after))
         (core-resource-error 422 "Invalid" "CSIStorageCapacity storageClassName is immutable"))))))

;;; Provisioning through a driver's external-provisioner sidecar

(defparameter +external-provisioner-annotation+ "volume.kubernetes.io/storage-provisioner")
(defparameter +external-provisioner-beta-annotation+ "volume.beta.kubernetes.io/storage-provisioner")
(defparameter +selected-node-annotation+ "volume.kubernetes.io/selected-node")

(defun storage-class-external-p (class)
  "Return whether a driver's sidecar, not gr8s, provisions volumes for CLASS."
  (let ((provisioner (storage-class-provisioner class)))
    (and provisioner
         (not (builtin-provisioner-p provisioner))
         (not (equal provisioner +no-provisioner+)))))

(defun storage-claim-awaits-external-provisioner-p (class claim)
  "Return whether a sidecar can still satisfy CLAIM under CLASS."
  (and (storage-class-external-p class)
       (not (gethash "volumeName" (gethash "spec" claim)))))

(defun annotate-claim-for-external-provisioner (claim class node)
  "Return a copy of CLAIM carrying what external-provisioner watches for.
A changed copy is committed by the caller; an unchanged claim is returned as is."
  (let* ((metadata (gethash "metadata" claim))
         (annotations (gethash "annotations" metadata (core-object)))
         (provisioner (storage-class-provisioner class)))
    (if (and (equal provisioner (gethash +external-provisioner-annotation+ annotations))
             (or (null node)
                 (equal (node-record-name node) (gethash +selected-node-annotation+ annotations))))
        claim
        (let* ((copy (copy-core-object claim))
               (new (gethash "annotations" (gethash "metadata" copy) (core-object))))
          (setf (gethash +external-provisioner-annotation+ new) provisioner
                (gethash +external-provisioner-beta-annotation+ new) provisioner
                (gethash "annotations" (gethash "metadata" copy)) new)
          (when node (setf (gethash +selected-node-annotation+ new) (node-record-name node)))
          copy))))

;;; Attachment

(defun volume-attachment-name (driver handle node-name)
  "Name an attachment the way the kubelet does, so a repeated pass finds it."
  (format nil "csi-~A"
          (string-downcase
           (octets-to-hex
            (ironclad:digest-sequence
             :sha256 (trivial-utf-8:string-to-utf-8-bytes
                      (concatenate 'string handle driver node-name)))))))

(defun csi-driver-attach-required-p (store driver)
  "Return whether DRIVER needs attaching: Kubernetes assumes so without a CSIDriver object."
  (let ((object (gethash (core-resource-key "csidrivers" nil driver) (pod-store-resources store))))
    (or (null object) (not (eq nil (gethash "attachRequired" (gethash "spec" object) t))))))

(defun desired-volume-attachments-unlocked (store)
  "Return the attachments that running consumers need, keyed by name."
  (let ((desired (make-hash-table :test #'equal)) (index (pod-store-resources store)))
    (loop for pod being the hash-values of (pod-store-pods store)
          when (and (pod-node-name pod) (storage-pod-active-p store pod))
            do (dolist (claim-name (storage-pod-claim-names pod))
                 (let* ((claim (gethash (core-resource-key "persistentvolumeclaims" (pod-namespace pod) claim-name) index))
                        (volume (and claim (storage-bound-volume index claim)))
                        (source (and volume (gethash "csi" (gethash "spec" volume)))))
                   (when (and source (csi-driver-attach-required-p store (gethash "driver" source)))
                     (let ((driver (gethash "driver" source)))
                       (setf (gethash (volume-attachment-name driver (gethash "volumeHandle" source) (pod-node-name pod)) desired)
                             (core-object "apiVersion" "storage.k8s.io/v1" "kind" "VolumeAttachment"
                                          "metadata" (core-object "name" (volume-attachment-name driver (gethash "volumeHandle" source) (pod-node-name pod)))
                                          "spec" (core-object
                                                  "attacher" driver "nodeName" (pod-node-name pod)
                                                  "source" (core-object "persistentVolumeName" (storage-resource-name volume))))))))))
    desired))

(defun gr8s-volume-attachment-name-p (name)
  "Return whether NAME has the form VOLUME-ATTACHMENT-NAME gives the attachments gr8s creates."
  (and (= (length name) 68) (uiop:string-prefix-p "csi-" name)
       (every (lambda (char) (digit-char-p char 16)) (subseq name 4))
       (string= name (string-downcase name))))

(defun reconcile-volume-attachments (store)
  "Create attachments consumers need and delete those of ours no consumer holds any more.
Attachments others created, such as a driver's tooling or a test's, are left alone, as
Kubernetes' attach/detach controller leaves them."
  (let ((desired (with-store-lock (store) (desired-volume-attachments-unlocked store))))
    (flet ((tolerating-races (thunk)
             (handler-case (funcall thunk)
               (kubernetes-error (condition)
                 (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition))))))
      (maphash (lambda (name object)
                 (unless (gethash (core-resource-key "volumeattachments" nil name) (pod-store-resources store))
                   (tolerating-races (lambda () (create-core-resource store "volumeattachments" object nil)))))
               desired)
      (dolist (attachment (list-core-resources store "volumeattachments"))
        (let ((metadata (gethash "metadata" attachment)))
          (unless (or (gethash (gethash "name" metadata) desired) (gethash "deletionTimestamp" metadata)
                      (not (gr8s-volume-attachment-name-p (gethash "name" metadata))))
            (tolerating-races
             (lambda () (delete-core-resource store "volumeattachments" nil (gethash "name" metadata))))))))))

;;; Node registrations

(defun csi-node-driver-entry (registration)
  "Turn one agent's driver registration into a CSINode driver entry."
  (let ((entry (core-object "name" (slot-value registration 'gr8s.node.v1::name)
                            "nodeID" (slot-value registration 'gr8s.node.v1::node-id)
                            "topologyKeys" (coerce (mapcar #'car (slot-value registration 'gr8s.node.v1::topology)) 'vector)))
        (limit (slot-value registration 'gr8s.node.v1::max-volumes)))
    (when (and limit (plusp limit))
      (setf (gethash "allocatable" entry) (core-object "count" limit)))
    entry))

(defun add-csi-topology-node-labels (store node-name registrations)
  "Label NODE-NAME with the topology segments its drivers report, as a kubelet does when it
registers a driver, so that external-provisioner finds the keys on a node. A label already
holding a different value is left alone and reported, as the kubelet refuses a collision."
  (let ((segments (loop for registration in registrations
                        append (slot-value registration 'gr8s.node.v1::topology))))
    (when segments
      (with-store-lock (store)
        (let* ((current (get-node-unlocked store node-name))
               (labels (copy-core-object (or (and current (node-record-labels current)) (core-object))))
               (changed nil))
          (when current
            (loop for (key . value) in segments
                  for existing = (gethash key labels)
                  do (cond ((null existing) (setf (gethash key labels) value changed t))
                           ((not (equal existing value))
                            (format *error-output* "gr8s CSI topology ~A=~A collides with Node ~A's label ~A=~A~%"
                                    key value node-name key existing))))
            (when changed
              (let ((old (node-api-object current)) (updated (copy-node-record current)))
                (setf (node-record-labels updated) labels)
                (persist-node store updated)
                (setf (node-record-labels current) labels)
                (publish-node-change-unlocked store old current)
                (note-node-desired-change store)))))))))

(defun update-node-csi-registrations (store node-name registrations)
  "Publish the drivers NODE-NAME reports, writing only when they have changed."
  (add-csi-topology-node-labels store node-name registrations)
  (let* ((drivers (coerce (sort (mapcar #'csi-node-driver-entry registrations) #'string<
                                :key (lambda (entry) (gethash "name" entry)))
                          'vector))
         (existing (gethash (core-resource-key "csinodes" nil node-name) (pod-store-resources store))))
    (cond
      ((and (null existing) (zerop (length drivers))) nil)
      ((null existing)
       (create-core-resource store "csinodes"
                             (core-object "apiVersion" "storage.k8s.io/v1" "kind" "CSINode"
                                          "metadata" (core-object "name" node-name)
                                          "spec" (core-object "drivers" drivers))
                             nil))
      ((not (core-json-equal-p (gethash "drivers" (gethash "spec" existing)) drivers))
       (update-core-resource store "csinodes" nil node-name
                             (lambda (old)
                               (let ((copy (copy-core-object old)))
                                 (setf (gethash "drivers" (gethash "spec" copy)) drivers)
                                 copy)))))))
