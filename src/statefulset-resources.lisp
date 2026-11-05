;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Default and validate the fields only a StatefulSet has, on top of the admission
;;;; all workloads share. A template that cannot run and a claim template storage
;;;; would refuse are refused here, and fields the controller does not perform,
;;;; such as a rolling update's maxUnavailable, are refused rather than ignored.

(in-package #:gr8s)

(defparameter +statefulset-name-limit+ 52
  "Longest StatefulSet name: a Pod's revision label holds the name, a hyphen and a ten-digit hash.")

(defparameter +statefulset-mutable-fields+
  '("replicas" "ordinals" "template" "updateStrategy" "persistentVolumeClaimRetentionPolicy"
    "minReadySeconds" "revisionHistoryLimit")
  "The spec fields upstream lets an update change.")

(defun statefulset-object-field (object field)
  "Return OBJECT's FIELD as an object, treating an absent or null one as empty."
  (let ((value (gethash field object)))
    (if (member value '(nil null)) (core-object) (require-object value field))))

(defun normalize-statefulset-update-strategy (spec)
  "Default and validate updateStrategy, refusing a maxUnavailable above the one Pod gr8s replaces at a time."
  (let* ((strategy (statefulset-object-field spec "updateStrategy"))
         (type (let ((value (gethash "type" strategy))) (if (member value '(nil null "") :test #'equal) "RollingUpdate" value))))
    (unless (member type '("RollingUpdate" "OnDelete") :test #'equal)
      (core-resource-error 422 "Invalid" "spec.updateStrategy.type must be RollingUpdate or OnDelete"))
    (setf (gethash "type" strategy) type (gethash "updateStrategy" spec) strategy)
    (if (equal type "OnDelete")
        (if (member (gethash "rollingUpdate" strategy) '(nil null))
            (remhash "rollingUpdate" strategy)
            (core-resource-error 422 "Invalid" "spec.updateStrategy.rollingUpdate is only allowed with type RollingUpdate"))
        (let ((rolling (statefulset-object-field strategy "rollingUpdate")))
          (setf (gethash "partition" rolling) (workload-int (gethash "partition" rolling) "spec.updateStrategy.rollingUpdate.partition")
                (gethash "rollingUpdate" strategy) rolling)
          (let ((maximum (gethash "maxUnavailable" rolling)))
            (cond ((eq maximum 'null) (remhash "maxUnavailable" rolling))
                  ((and maximum (not (eql maximum 1)))
                   (core-resource-error 422 "Invalid" "gr8s replaces one StatefulSet Pod at a time: spec.updateStrategy.rollingUpdate.maxUnavailable must be 1"))))))))

(defun normalize-statefulset-claim-templates (spec object namespace)
  "Reduce each claim template to what a claim uses, after real claim admission accepts it."
  (let ((templates (let ((value (gethash "volumeClaimTemplates" spec))) (if (member value '(nil null)) #() value)))
        (seen nil))
    (setf (gethash "volumeClaimTemplates" spec)
          (map 'vector
               (lambda (template)
                 (let* ((metadata (statefulset-object-field template "metadata")) (name (gethash "name" metadata))
                        (kept (core-object "name" name)))
                   (require-dns-label name "volumeClaimTemplates name")
                   (when (member name seen :test #'equal)
                     (core-resource-error 422 "Invalid" "Duplicate volumeClaimTemplates name ~A" name))
                   (push name seen)
                   (dolist (field '("labels" "annotations"))
                     (when (hash-table-p (gethash field metadata)) (setf (gethash field kept) (gethash field metadata))))
                   (let* ((reduced (core-object "metadata" kept "spec" (statefulset-object-field template "spec")))
                          (claim (normalize-storage-resource "persistentvolumeclaims"
                                                             (statefulset-claim-object object reduced 0) namespace nil nil)))
                     (setf (gethash "spec" reduced) (gethash "spec" claim))
                     reduced)))
               templates))))

(defun normalize-statefulset-spec (object namespace)
  "Default and validate OBJECT's StatefulSet fields, and refuse a template no Pod could run."
  (let* ((spec (gethash "spec" object)) (name (gethash "name" (workload-metadata object)))
         (policy (let ((value (gethash "podManagementPolicy" spec))) (if (member value '(nil null "") :test #'equal) "OrderedReady" value)))
         (service (gethash "serviceName" spec))
         (retention (statefulset-object-field spec "persistentVolumeClaimRetentionPolicy")))
    (unless (and (dns-label-p name) (<= (length name) +statefulset-name-limit+))
      (core-resource-error 422 "Invalid" "StatefulSet name must be a DNS label of at most ~D characters" +statefulset-name-limit+))
    (unless (member policy '("OrderedReady" "Parallel") :test #'equal)
      (core-resource-error 422 "Invalid" "spec.podManagementPolicy must be OrderedReady or Parallel"))
    (setf (gethash "podManagementPolicy" spec) policy
          (gethash "revisionHistoryLimit" spec) (workload-int (gethash "revisionHistoryLimit" spec) "spec.revisionHistoryLimit" 10))
    (if (member service '(nil null ""))
        (remhash "serviceName" spec)
        (require-dns-label service "spec.serviceName"))
    (dolist (field '("whenDeleted" "whenScaled"))
      (let ((value (let ((given (gethash field retention))) (if (member given '(nil null "") :test #'equal) "Retain" given))))
        (unless (member value '("Retain" "Delete") :test #'equal)
          (core-resource-error 422 "Invalid" "spec.persistentVolumeClaimRetentionPolicy.~A must be Retain or Delete" field))
        (setf (gethash field retention) value)))
    (setf (gethash "persistentVolumeClaimRetentionPolicy" spec) retention)
    (let ((ordinals (gethash "ordinals" spec)))
      (if (member ordinals '(nil null))
          (remhash "ordinals" spec)
          (setf (gethash "start" (require-object ordinals "spec.ordinals"))
                (workload-int (gethash "start" ordinals) "spec.ordinals.start"))))
    (normalize-statefulset-update-strategy spec)
    (normalize-statefulset-claim-templates spec object namespace)
    ;; The owner has no identity yet, and this Pod is only ever parsed.
    (parse-pod (statefulset-pod-object object (gethash "template" spec) (statefulset-start-ordinal spec)
                                       (format nil "~A-0000000000" name)))
    object))

(defun validate-statefulset-update (existing object)
  "Refuse an update to any spec field upstream fixes at creation."
  (flet ((fixed (candidate)
           (let ((copy (copy-core-object (gethash "spec" candidate))))
             (dolist (field +statefulset-mutable-fields+) (remhash field copy))
             copy)))
    (unless (workload-equal-p (fixed existing) (fixed object))
      (core-resource-error 422 "Invalid" "updates to statefulset spec for fields other than ~{'~A'~^, ~} are forbidden"
                           +statefulset-mutable-fields+))))
