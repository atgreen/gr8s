;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Reserve static and dynamically provisioned volumes in a durable two-sided
;;;; transaction. Claims never become Bound without an exclusive PV claimRef UID;
;;;; installing a binding never claims a volume plugin successfully mounted it.

(in-package #:gr8s.resources)

(defun storage-resource-name (object)
  "Return a validated API object's metadata name."
  (gethash "name" (gethash "metadata" object)))

(defun ephemeral-claim-name (pod-name volume-name)
  "Name the claim a generic ephemeral volume owns, as Kubernetes does."
  (format nil "~A-~A" pod-name volume-name))

(defun storage-pod-claim-names (pod)
  "Return PVC names POD references, including those of its generic ephemeral volumes."
  (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
        for source = (gethash "persistentVolumeClaim" volume)
        when source collect (gethash "claimName" source)
        when (gethash "ephemeral" volume)
          collect (ephemeral-claim-name (pod-name pod) (gethash "name" volume))))

(defun storage-ephemeral-claim (store pod volume)
  "Build the admitted claim a generic ephemeral VOLUME asks for, owned by POD."
  (let* ((template (gethash "volumeClaimTemplate" (gethash "ephemeral" volume)))
         (name (ephemeral-claim-name (pod-name pod) (gethash "name" volume)))
         (metadata (copy-core-object (gethash "metadata" template (core-object)))))
    (setf (gethash "name" metadata) name
          (gethash "namespace" metadata) (pod-namespace pod)
          (gethash "ownerReferences" metadata)
          (vector (core-object "apiVersion" "v1" "kind" "Pod" "name" (pod-name pod) "uid" (pod-uid pod)
                               "controller" t "blockOwnerDeletion" t)))
    (normalize-storage-resource
     "persistentvolumeclaims"
     (core-object "apiVersion" "v1" "kind" "PersistentVolumeClaim" "metadata" metadata
                  "spec" (copy-core-object (gethash "spec" template)))
     (pod-namespace pod) name store)))

(defun storage-ensure-ephemeral-claims (store index)
  "Add each missing generic ephemeral claim to INDEX; an existing claim is never adopted."
  (loop for pod being the hash-values of (pod-store-pods store)
        unless (gethash "deletionTimestamp" (gethash "metadata" (pod-to-object pod)))
          do (loop for volume across (gethash "volumes" (gethash "spec" (pod-to-object pod)) #())
                   when (gethash "ephemeral" volume)
                     do (let ((key (core-resource-key "persistentvolumeclaims" (pod-namespace pod)
                                                      (ephemeral-claim-name (pod-name pod) (gethash "name" volume)))))
                          (unless (gethash key index)
                            (handler-case (setf (gethash key index) (storage-ephemeral-claim store pod volume))
                              (kubernetes-error (condition)
                                (format *error-output* "gr8s Pod ~A/~A ephemeral volume rejected: ~A~%"
                                        (pod-namespace pod) (pod-name pod) condition))))))))

(defun storage-pod-active-p (store pod)
  "Keep storage protected until a Pod is terminal or actually removed."
  (not (terminal-pod-phase-p (gethash (pod-uid pod) (pod-store-pod-observed-phases store)))))

(defun storage-claim-consumers-unlocked (store claim &optional exclude-uid)
  "Find live Pods referencing this exact namespace/name while STORE is locked."
  (let ((metadata (gethash "metadata" claim)))
    (loop for pod being the hash-values of (pod-store-pods store)
          when (and (not (equal exclude-uid (pod-uid pod))) (storage-pod-active-p store pod)
                    (equal (gethash "namespace" metadata) (pod-namespace pod))
                    (member (gethash "name" metadata) (storage-pod-claim-names pod) :test #'equal)) collect pod)))

(defun storage-claim-ref-matches-p (volume claim &key allow-unbound)
  "Match PV reservation namespace/name and optionally its unfilled UID."
  (let* ((ref (gethash "claimRef" (gethash "spec" volume)))
         (metadata (gethash "metadata" claim))
         (uid (and ref (gethash "uid" ref))))
    (and ref (equal (gethash "name" ref) (gethash "name" metadata))
         (equal (gethash "namespace" ref) (gethash "namespace" metadata))
         (or (equal uid (gethash "uid" metadata)) (and allow-unbound (member uid '(nil "") :test #'equal))))))

(defun storage-bound-volume (index claim)
  "Return the PV with the exact two-sided binding identity, ignoring mutable phase text."
  (let* ((name (gethash "volumeName" (gethash "spec" claim)))
         (volume (and name (gethash (core-resource-key "persistentvolumes" nil name) index))))
    (and volume (storage-claim-ref-matches-p volume claim) volume)))

(defun storage-native-volume-p (volume)
  "Return true only for sources and volume modes the native agent can mount."
  (let ((spec (gethash "spec" volume)))
    (and (equal "Filesystem" (gethash "volumeMode" spec "Filesystem"))
         (member (storage-source-kind spec) '("hostPath" "local" "nfs" "csi") :test #'equal)
         (or (member (storage-source-kind spec) '("nfs" "csi") :test #'equal)
             (zerop (length (gethash "mountOptions" spec #())))))))

(defun storage-requirement-matches-p (requirement value)
  "Evaluate Kubernetes set/existence/integer node and label requirements."
  (let ((op (gethash "operator" requirement)) (values (gethash "values" requirement #())))
    (cond ((equal op "In") (and value (find value values :test #'equal)))
          ((equal op "NotIn") (not (and value (find value values :test #'equal))))
          ((equal op "Exists") (not (null value)))
          ((equal op "DoesNotExist") (null value))
          ((member op '("Gt" "Lt") :test #'equal)
           (let ((left (and value (ignore-errors (parse-integer value :junk-allowed nil))))
                 (right (ignore-errors (parse-integer (aref values 0) :junk-allowed nil))))
             (and left right (if (equal op "Gt") (> left right) (< left right))))))))

(defun storage-label-selector-matches-p (selector labels)
  "Apply a PVC selector to persisted PV labels."
  (or (null selector)
      (and (loop for key being the hash-keys of (gethash "matchLabels" selector (core-object))
                   using (hash-value expected)
                 always (equal expected (and labels (gethash key labels))))
           (loop for requirement across (gethash "matchExpressions" selector #())
                 always (storage-requirement-matches-p requirement (and labels (gethash (gethash "key" requirement) labels)))))))

(defun storage-node-labels (node)
  "Use the same actual node labels exposed by the API."
  (gethash "labels" (gethash "metadata" (node-api-object node))))

(defun storage-node-affinity-matches-p (volume node)
  "Evaluate PV required affinity on NODE; no node means binding has not selected one."
  (let ((required (gethash "required" (gethash "nodeAffinity" (gethash "spec" volume) (core-object)))))
    (or (null required) (null node)
        (let ((labels (storage-node-labels node)))
          (loop for term across (gethash "nodeSelectorTerms" required #())
                thereis (and (or (plusp (length (gethash "matchExpressions" term #())))
                                 (plusp (length (gethash "matchFields" term #()))))
                             (loop for requirement across (gethash "matchExpressions" term #())
                                   always (storage-requirement-matches-p requirement (gethash (gethash "key" requirement) labels)))
                             (loop for requirement across (gethash "matchFields" term #())
                                   always (storage-requirement-matches-p requirement (node-record-name node)))))))))

(defun storage-node-affinity-excludes-node-name-p (volume name)
  "Return whether VOLUME's affinity rules out the node called NAME, judging only its name.
An agent doesn't hold its own Node labels; the control plane already matched those."
  (let ((required (gethash "required" (gethash "nodeAffinity" (gethash "spec" volume) (core-object)))))
    (and required
         (notany (lambda (term)
                   (and (every (lambda (requirement)
                                 (or (not (equal "kubernetes.io/hostname" (gethash "key" requirement)))
                                     (storage-requirement-matches-p requirement name)))
                               (gethash "matchExpressions" term #()))
                        (every (lambda (requirement) (storage-requirement-matches-p requirement name))
                               (gethash "matchFields" term #()))))
                 (gethash "nodeSelectorTerms" required #())))))

(defun storage-class-topology-matches-p (class node)
  "Honor a selected StorageClass's allowed node topology."
  (let ((terms (and class (gethash "allowedTopologies" class))))
    (or (null terms) (zerop (length terms)) (null node)
        (let ((labels (storage-node-labels node)))
          (loop for term across terms
                thereis (and (plusp (length (gethash "matchLabelExpressions" term #())))
                             (loop for expression across (gethash "matchLabelExpressions" term #())
                                   always (find (gethash (gethash "key" expression) labels)
                                                (gethash "values" expression) :test #'equal))))))))

(defun storage-prebound-pair-p (volume claim)
  "Return whether CLAIM names VOLUME and VOLUME's claimRef names CLAIM. Kubernetes binds such a
pair as given, without comparing class, size or modes, as e2epv's pre-bound pairs require."
  (and (equal (gethash "volumeName" (gethash "spec" claim)) (storage-resource-name volume))
       (storage-claim-ref-matches-p volume claim :allow-unbound t)))

(defun storage-volume-matches-claim-p (volume claim &optional node)
  "Check capacity, class, modes, reservation UID and affinity before allocating a PV."
  (let* ((spec (gethash "spec" volume)) (wanted (gethash "spec" claim))
         (ref (gethash "claimRef" spec)) (requested-name (gethash "volumeName" wanted)))
    (when (storage-prebound-pair-p volume claim)
      (return-from storage-volume-matches-claim-p
        (and (not (gethash "deletionTimestamp" (gethash "metadata" volume)))
             (storage-node-affinity-matches-p volume node))))
    (and (not (gethash "deletionTimestamp" (gethash "metadata" volume)))
         ;; Only a sidecar that was asked to clone or restore can have filled this volume.
         (or (not (or (gethash "dataSource" wanted) (gethash "dataSourceRef" wanted)))
             (storage-claim-ref-matches-p volume claim))
         (or (not ref) (storage-claim-ref-matches-p volume claim :allow-unbound t))
         (or (not requested-name) (equal requested-name (storage-resource-name volume)))
         (equal (gethash "storageClassName" spec "") (gethash "storageClassName" wanted ""))
         (equal (gethash "volumeMode" spec "Filesystem") (gethash "volumeMode" wanted "Filesystem"))
         (<= (storage-quantity (gethash "storage" (gethash "requests" (gethash "resources" wanted))) "claim capacity")
             (storage-quantity (gethash "storage" (gethash "capacity" spec)) "volume capacity"))
         (every (lambda (mode) (find mode (gethash "accessModes" spec) :test #'equal)) (gethash "accessModes" wanted))
         (or requested-name (storage-claim-ref-matches-p volume claim :allow-unbound t)
             (storage-label-selector-matches-p (gethash "selector" wanted) (gethash "labels" (gethash "metadata" volume))))
         (storage-node-affinity-matches-p volume node))))

(defun storage-claim-class (index claim)
  "Return the claim's StorageClass if one exists; static class names need no class object."
  (gethash (core-resource-key "storageclasses" nil (gethash "storageClassName" (gethash "spec" claim) "")) index))

(defun storage-claim-delayed-p (index claim)
  "Wait for a scheduled consumer for delayed classes and storage that exists on one node."
  (let ((class (storage-claim-class index claim)))
    (and class (or (equal "WaitForFirstConsumer" (gethash "volumeBindingMode" class))
                   (storage-class-node-bound-p class))
         (not (gethash "volumeName" (gethash "spec" claim))))))

(defun storage-candidate-volume (index claim &optional node used)
  "Choose a matching reservation first, then the smallest available fitting volume."
  (first
   (sort (loop for key being the hash-keys of index using (hash-value volume)
               when (and (equal "persistentvolumes" (first key))
                         (not (member (storage-resource-name volume) used :test #'equal))
                         (storage-volume-matches-claim-p volume claim node)) collect volume)
         (lambda (left right)
           (let ((a (storage-claim-ref-matches-p left claim :allow-unbound t))
                 (b (storage-claim-ref-matches-p right claim :allow-unbound t))
                 (ac (storage-quantity (gethash "storage" (gethash "capacity" (gethash "spec" left))) "capacity"))
                 (bc (storage-quantity (gethash "storage" (gethash "capacity" (gethash "spec" right))) "capacity")))
             (cond ((and a (not b)) t) ((and b (not a)) nil) ((/= ac bc) (< ac bc))
                   (t (string< (storage-resource-name left) (storage-resource-name right)))))))))

(defun pod-node-storage-failure (store pod node)
  "Return why POD's claims rule out NODE, in the scheduler's VolumeBinding and VolumeRestrictions
wording, or NIL when they allow it. Call with STORE locked."
  (let ((index (pod-store-resources store)) (used nil))
    (dolist (name (storage-pod-claim-names pod) nil)
      (let* ((claim (gethash (core-resource-key "persistentvolumeclaims" (pod-namespace pod) name) index))
             (delayed (and claim (storage-claim-delayed-p index claim)))
             (requested (and claim (gethash "volumeName" (gethash "spec" claim))))
             (bound (and claim (storage-bound-volume index claim)))
             (candidate (or bound (and delayed (storage-candidate-volume index claim node used))))
             (provisionable (and claim (not candidate) delayed
                                 (or (storage-claim-provisionable-p (storage-claim-class index claim) claim)
                                     (storage-claim-awaits-external-provisioner-p (storage-claim-class index claim) claim)))))
        (cond
          ((null claim) (return (format nil "persistentvolumeclaim ~S not found" name)))
          ((gethash "deletionTimestamp" (gethash "metadata" claim))
           (return (format nil "persistentvolumeclaim ~S is being deleted" name)))
          ((and requested (not (gethash (core-resource-key "persistentvolumes" nil requested) index)))
           (return "node(s) unavailable due to one or more pvc(s) bound to non-existent pv(s)"))
          ((and (not candidate) (not delayed)) (return "pod has unbound immediate PersistentVolumeClaims"))
          ((not (or candidate provisionable)) (return "node(s) didn't find available persistent volumes to bind"))
          ((not (or provisionable (storage-node-affinity-matches-p candidate node)))
           (return "node(s) had volume node affinity conflict"))
          ((not (storage-class-topology-matches-p (storage-claim-class index claim) node))
           (return "node(s) didn't find available persistent volumes to bind")))
        (let* ((modes (gethash "accessModes" (gethash "spec" claim)))
               (others (storage-claim-consumers-unlocked store claim (pod-uid pod))))
          (when (and (find "ReadWriteOncePod" modes :test #'equal) others)
            (return "node has pod using PersistentVolumeClaim with the same name and ReadWriteOncePod access mode"))
          ;; Kubernetes leaves this to attachment; gr8s refuses the node up front.
          (when (and (find "ReadWriteOnce" modes :test #'equal)
                     (some (lambda (other) (and (pod-node-name other) (not (equal (pod-node-name other) (node-record-name node))))) others))
            (return "node(s) unavailable due to a ReadWriteOnce PersistentVolumeClaim in use on another node")))
        (when candidate (push (storage-resource-name candidate) used))))))

(defun pod-node-storage-compatible-p (store pod node)
  "Filter scheduler candidates using real claim/PV state while STORE is locked."
  (null (pod-node-storage-failure store pod node)))

(defun storage-attributes-class-in-use-p (index name)
  "Return whether a PV or PVC in INDEX names the VolumeAttributesClass NAME, as current,
requested or target class, which Kubernetes' vac-protection controller also checks."
  (loop for key being the hash-keys of index using (hash-value object)
          thereis (let ((spec (gethash "spec" object (core-object))) (status (gethash "status" object (core-object))))
                    (cond ((equal "persistentvolumes" (first key))
                           (equal name (gethash "volumeAttributesClassName" spec)))
                          ((equal "persistentvolumeclaims" (first key))
                           (or (equal name (gethash "volumeAttributesClassName" spec))
                               (equal name (gethash "currentVolumeAttributesClassName" status))
                               (equal name (gethash "targetVolumeAttributesClassName"
                                                    (gethash "modifyVolumeStatus" status (core-object))))))))))

(defun storage-object-in-use-unlocked (store resource object)
  "Enforce implemented PV and PVC protection using exact persisted references."
  (cond ((equal resource "persistentvolumeclaims") (not (null (storage-claim-consumers-unlocked store object))))
        ((equal resource "volumeattributesclasses")
         (storage-attributes-class-in-use-p (pod-store-resources store) (storage-resource-name object)))
        ((equal resource "persistentvolumes")
         (let* ((ref (gethash "claimRef" (gethash "spec" object)))
                (claim (and ref (gethash (core-resource-key "persistentvolumeclaims" (gethash "namespace" ref) (gethash "name" ref))
                                         (pod-store-resources store)))))
           (and claim (storage-claim-ref-matches-p object claim))))))

(defun storage-protection-finalizer (resource)
  "Return the storage controller's own protection finalizer for RESOURCE."
  (cond ((equal resource "persistentvolumes") "kubernetes.io/pv-protection")
        ((equal resource "persistentvolumeclaims") "kubernetes.io/pvc-protection")
        ((equal resource "volumeattributesclasses") "kubernetes.io/vac-protection")))

(defun prepare-storage-deletion-unlocked (store resource object)
  "Mark deletion and drop our finalizer only when the underlying reservation is unused."
  (let* ((copy (copy-core-object object)) (metadata (gethash "metadata" copy))
         (own (storage-protection-finalizer resource)))
    (unless (gethash "deletionTimestamp" metadata)
      (setf (gethash "deletionTimestamp" metadata) (current-timestamp)
            (gethash "deletionGracePeriodSeconds" metadata) 0))
    (when (and own (not (storage-object-in-use-unlocked store resource object)))
      (setf (gethash "finalizers" metadata) (remove own (gethash "finalizers" metadata #()) :test #'equal)))
    copy))

(defun delete-storage-resource-unlocked (store resource existing dry-run)
  "Perform a storage deletion transaction, preserving objects protected by live users."
  (let* ((object (prepare-storage-deletion-unlocked store resource existing))
         (metadata (gethash "metadata" object)) (index (copy-core-resource-index store))
         (revision (1+ (pod-store-resource-revision store)))
         (key (core-resource-key resource (gethash "namespace" metadata) (gethash "name" metadata))))
    (when (and (plusp (length (gethash "finalizers" metadata #()))) (core-json-equal-p existing object))
      (return-from delete-storage-resource-unlocked object))
    (if (plusp (length (gethash "finalizers" metadata #())))
        (progn (prepare-core-resource-metadata object existing revision) (setf (gethash key index) object))
        (remhash key index))
    (unless (or dry-run (and (gethash key index) (core-json-equal-p existing object)))
      (commit-core-resources store index revision))
    (copy-core-object object)))

(defun storage-status (object phase &optional reason message)
  "Set a genuine controller phase and preserve the PV phase transition timestamp."
  (let* ((previous (gethash "status" object))
         (status (core-object "phase" phase)))
    (when (equal "PersistentVolume" (gethash "kind" object))
      (setf (gethash "lastPhaseTransitionTime" status)
            (if (and previous (equal phase (gethash "phase" previous)) (gethash "lastPhaseTransitionTime" previous))
                (gethash "lastPhaseTransitionTime" previous) (current-timestamp))))
    (when reason (setf (gethash "reason" status) reason))
    (when message (setf (gethash "message" status) message))
    (setf (gethash "status" object) status)))

(defun storage-bind-pair (volume claim)
  "Create a two-sided UID reservation before publishing either object's Bound status."
  (let* ((pv (copy-core-object volume)) (pvc (copy-core-object claim))
         (metadata (gethash "metadata" pvc)) (spec (gethash "spec" pv)))
    (setf (gethash "claimRef" spec) (core-object "apiVersion" "v1" "kind" "PersistentVolumeClaim"
                                               "namespace" (gethash "namespace" metadata) "name" (gethash "name" metadata)
                                               "uid" (gethash "uid" metadata))
          (gethash "volumeName" (gethash "spec" pvc)) (storage-resource-name pv))
    (dolist (object (list pv pvc))
      (let* ((meta (gethash "metadata" object)) (annotations (gethash "annotations" meta (core-object))))
        (setf (gethash "pv.kubernetes.io/bind-completed" annotations) "yes"
              (gethash "annotations" meta) annotations)))
    ;; A built-in provisioner's capacity is advisory, so growing needs no node work.
    (when (and (builtin-provisioner-p (gethash +provisioned-by-annotation+ (gethash "annotations" (gethash "metadata" pv) (core-object))))
               (> (storage-quantity (gethash "storage" (gethash "requests" (gethash "resources" (gethash "spec" pvc)))) "claim capacity")
                  (storage-quantity (gethash "storage" (gethash "capacity" spec)) "volume capacity")))
      (setf (gethash "storage" (gethash "capacity" spec))
            (gethash "storage" (gethash "requests" (gethash "resources" (gethash "spec" pvc))))))
    (storage-status pv "Bound")
    (storage-status pvc "Bound")
    (setf (gethash "capacity" (gethash "status" pvc)) (copy-core-object (gethash "capacity" spec))
          (gethash "accessModes" (gethash "status" pvc)) (copy-core-object (gethash "accessModes" spec)))
    (values pv pvc)))

(defun reconcile-storage-bindings (store)
  "Publish real static reservations, releases and protected deletions atomically."
  (with-store-lock (store)
    (let* ((original (pod-store-resources store))
           (index (let ((copy (copy-core-resource-index store)))
                    (storage-ensure-ephemeral-claims store copy)
                    copy))
           (claims (sort (loop for key being the hash-keys of index using (hash-value object)
                              when (equal "persistentvolumeclaims" (first key)) collect object)
                         #'string< :key (lambda (object) (format nil "~A/~A" (gethash "namespace" (gethash "metadata" object)) (storage-resource-name object)))))
           (changed nil))
      ;; Protection runs before allocation: old claimant UIDs remain reserved
      ;; until their actual consumers disappear. Retained data is never recycled.
      (maphash (lambda (key object)
                 (when (and (storage-resource-p (first key)) (gethash "deletionTimestamp" (gethash "metadata" object)))
                   (let* ((copy (prepare-storage-deletion-unlocked store (first key) object))
                          (finalizers (gethash "finalizers" (gethash "metadata" copy) #())))
                     (if (zerop (length finalizers)) (remhash key index) (setf (gethash key index) copy))))) original)
      (dolist (claim claims)
        (let* ((metadata (gethash "metadata" claim))
               (key (core-resource-key "persistentvolumeclaims" (gethash "namespace" metadata) (gethash "name" metadata))))
          ;; A claim created in this pass has no UID to bind against until it commits.
          (when (and (gethash key index) (gethash "uid" metadata) (not (gethash "deletionTimestamp" metadata)))
            (unless (or (gethash "volumeName" (gethash "spec" claim))
                        (nth-value 1 (gethash "storageClassName" (gethash "spec" claim))))
              (let ((class (storage-default-class-unlocked store)))
                (when class
                  (setf claim (copy-core-object claim)
                        (gethash "storageClassName" (gethash "spec" claim)) (storage-resource-name class)
                        (gethash key index) claim))))
            (let* ((bound (storage-bound-volume index claim))
                   (consumer (find-if #'pod-node-name (storage-claim-consumers-unlocked store claim)))
                   (node (and consumer (gethash (pod-node-name consumer) (pod-store-nodes store))))
                   (delayed (storage-claim-delayed-p index claim))
                   (candidate (or bound (and (or (not delayed) node)
                                            (storage-class-topology-matches-p (storage-claim-class index claim) node)
                                            (or (storage-candidate-volume index claim node)
                                                (storage-provisioned-volume store (storage-claim-class index claim) claim node))))))
              (if candidate
                  (multiple-value-bind (pv pvc) (storage-bind-pair candidate claim)
                    (setf (gethash (core-resource-key "persistentvolumes" nil (storage-resource-name pv)) index) pv
                          (gethash key index) pvc))
                  (let ((copy (let ((class (storage-claim-class index claim)))
                                (copy-core-object
                                 (if (and (storage-claim-awaits-external-provisioner-p class claim)
                                          (or (not delayed) node))
                                     (annotate-claim-for-external-provisioner claim class node)
                                     claim)))))
                    (if (and (gethash "volumeName" (gethash "spec" claim))
                             (equal "yes" (gethash "pv.kubernetes.io/bind-completed" (gethash "annotations" metadata (core-object)))))
                        (storage-status copy "Lost")
                        (storage-status copy "Pending"))
                    (setf (gethash key index) copy)))))))
      (maphash
       (lambda (key volume)
         (when (equal "persistentvolumes" (first key))
           (let* ((ref (gethash "claimRef" (gethash "spec" volume)))
                  (claim (and ref (gethash (core-resource-key "persistentvolumeclaims" (gethash "namespace" ref) (gethash "name" ref)) index)))
                  (copy (copy-core-object volume)))
             (cond ((and claim (storage-claim-ref-matches-p volume claim) (equal (storage-resource-name volume) (gethash "volumeName" (gethash "spec" claim))))
                    (storage-status copy "Bound"))
                   ((and ref (gethash "uid" ref) (plusp (length (gethash "uid" ref))))
                    (if (or (equal "Retain" (gethash "persistentVolumeReclaimPolicy" (gethash "spec" volume)))
                            (gethash +provisioned-by-annotation+ (gethash "annotations" (gethash "metadata" volume) (core-object))))
                        (storage-status copy "Released")
                        (storage-status copy "Failed" "ReclaimUnsupported" "No native deleter or recycler is installed; backing storage was retained")))
                   (t (storage-status copy "Available")))
             (setf (gethash key index) copy)))) index)
      (let ((revision (1+ (pod-store-resource-revision store))))
        (maphash (lambda (key object)
                   (let ((before (gethash key original)))
                     (unless (core-json-equal-p before object)
                       (prepare-core-resource-metadata object before revision)
                       (setf changed t))
                     (when (and before (core-json-equal-p before object)) (setf (gethash key index) before)))) index)
        (when (/= (hash-table-count index) (hash-table-count original)) (setf changed t))
        (when changed (commit-core-resources store index revision)))
      changed)))
